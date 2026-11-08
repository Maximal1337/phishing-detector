"""PostgresHistory and the schema migration against a real database; skipped unless TEST_DATABASE_URL is set.

    TEST_DATABASE_URL=postgresql://phishdet:<password>@127.0.0.1:15432/phishdet python -m pytest -q tests/test_postgres.py

Each test works in its own schema and drops it afterwards.
"""

import json
import os
import threading
import uuid

import pytest

from webapp.storage import FLAG_SHAS, FLAGS_INDEX, LATEST_SQL, SCANS_COLUMNS, TRUSTED_FLAGS_SQL, PostgresHistory, migrate

URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="TEST_DATABASE_URL not set")

# The schema and queries of the previous app version (c6caed3), word for word: it keeps running during a rollout.
OLD_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id            bigserial   PRIMARY KEY,
  scanned_at    timestamptz NOT NULL DEFAULT now(),
  email_sha256  char(64)    NOT NULL,
  sender_domain text,
  verdict       text        NOT NULL,
  score         smallint    NOT NULL,
  signals       jsonb       NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_domain_verdict ON scans (sender_domain, verdict);
"""
OLD_INSERT = "INSERT INTO scans (email_sha256, sender_domain, verdict, score, signals) VALUES (%s, %s, %s, %s, %s::jsonb)"
OLD_COUNT = (
    "SELECT count(*) FROM scans WHERE sender_domain = %s AND verdict = 'phishing' AND email_sha256 <> %s AND ("
    "signals @> %s::jsonb OR signals @> %s::jsonb)"
)
OLD_COUNT_PARAMS = [json.dumps([{"id": "auth.dmarc_pass"}]), json.dumps([{"id": "sender.lookalike_domain"}])]

# Rows made by the database itself, shaped like the load test that exposed a bad plan on RDS: legitimate
# mail from a few domains passes DMARC (trusted, but not phishing), a spoofed domain sends phishing that is never
# trusted, and a lookalike campaign (phishing, every row trusted) arrives last, at the end of the table.
FILL = """
INSERT INTO scans (email_sha256, sender_domain, verdict, score, signals)
SELECT md5(g::text) || md5((g + 1)::text),
       CASE WHEN g %% 5 = 0 THEN 'spoofed.test' ELSE 'quiet' || (g %% 20) || '.test' END,
       CASE WHEN g %% 5 = 0 THEN 'phishing' ELSE 'likely_legitimate' END,
       CASE WHEN g %% 5 = 0 THEN 70 ELSE 0 END,
       CASE WHEN g %% 5 = 0 THEN '[{"id": "links.ip_host", "weight": 30}]'::jsonb
            ELSE '[{"id": "auth.dmarc_pass", "weight": 0}]'::jsonb END
FROM generate_series(1, %s) g
"""
FILL_CAMPAIGN = """
INSERT INTO scans (email_sha256, sender_domain, verdict, score, signals)
SELECT md5((-g)::text) || md5(g::text), 'hot.test', 'phishing', 70, '[{"id": "sender.lookalike_domain", "weight": 35}]'::jsonb
FROM generate_series(1, %s) g
"""
FIRST_D112_INDEX = (  # as 65fd4ab built it: no id in the key
    "CREATE INDEX scans_trusted_flags ON scans (sender_domain) INCLUDE (email_sha256) WHERE verdict = 'phishing' AND trusted"
)


@pytest.fixture
def schema():
    """A fresh schema; yields a connect() for it."""
    import psycopg

    name = "test_" + uuid.uuid4().hex[:8]
    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {name}")
    yield lambda: psycopg.connect(URL, options=f"-c search_path={name}")
    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA {name} CASCADE")


@pytest.fixture
def store(schema):
    store = PostgresHistory(schema)
    assert store.create_schema(attempts=1)  # a fresh schema: something to do
    return store


def plan(conn, sql, params):
    """The node types and index names of a query's plan."""
    found = []

    def walk(node):
        found.append((node["Node Type"], node.get("Index Name")))
        for child in node.get("Plans", []):
            walk(child)

    walk(conn.execute("EXPLAIN (FORMAT JSON) " + sql, params).fetchone()[0][0]["Plan"])
    return found


def fill(connect, rows):
    """Rows, then ANALYZE as autovacuum would run it, but no VACUUM: no page is marked all-visible yet."""
    with connect() as conn:
        conn.autocommit = True
        conn.execute(FILL, (rows,))
        conn.execute(FILL_CAMPAIGN, (rows // 10,))
        conn.execute("ANALYZE scans")


def test_table_has_the_scans_columns_and_the_generated_trusted_column(store):
    with store._connect() as conn:
        columns = conn.execute(
            "SELECT column_name, is_generated FROM information_schema.columns"
            " WHERE table_name = 'scans' AND table_schema = current_schema()"
        ).fetchall()
    assert dict(columns) == {**{c: "NEVER" for c in SCANS_COLUMNS}, "trusted": "ALWAYS"}


def test_record_recent_and_the_poisoning_rule(store):
    row = {"email_sha256": "a" * 64, "sender_domain": "examplebank.test", "verdict": "phishing", "score": 80}
    store.record({**row, "signals": [{"id": "links.ip_host", "weight": 30}]})
    assert store.count_trusted_flags("examplebank.test", "b" * 64) == 0  # forged From: doesn't count
    store.record({**row, "signals": [{"id": "sender.lookalike_domain", "weight": 35}]})
    assert store.count_trusted_flags("examplebank.test", "b" * 64) == 1
    store.record({**row, "email_sha256": "c" * 64, "signals": [{"id": "auth.dmarc_pass", "weight": 0}]})
    assert store.count_trusted_flags("examplebank.test", "b" * 64) == 2
    assert store.count_trusted_flags("examplebank.test", "a" * 64) == 1  # the same email doesn't flag itself
    store.record({**row, "verdict": "suspicious", "email_sha256": "d" * 64, "signals": [{"id": "auth.dmarc_pass", "weight": 0}]})
    assert store.count_trusted_flags("examplebank.test", "b" * 64) == 2  # only phishing verdicts count
    assert sorted(store.trusted_flag_shas("examplebank.test", "b" * 64, 5)) == ["a" * 64, "c" * 64]  # trusted only
    assert store.trusted_flag_shas("examplebank.test", "c" * 64, 5) == ["a" * 64]

    latest = store.recent(2)
    assert [r["verdict"] for r in latest] == ["suspicious", "phishing"]
    assert set(latest[0]) == set(SCANS_COLUMNS)  # the API shows the same fields as before


def test_the_count_stops_at_the_cap(store):
    for i in range(FLAG_SHAS + 3):
        sha = f"{i:064x}"
        store.record({"email_sha256": sha, "sender_domain": "hot.test", "verdict": "phishing", "score": 70,
                      "signals": [{"id": "sender.lookalike_domain", "weight": 35}]})
    assert store.count_trusted_flags("hot.test", "f" * 64) == FLAG_SHAS


def test_history_query_uses_the_partial_index_whatever_the_statistics(store):
    fill(store._connect, 20_000)
    with store._connect() as conn:
        conn.autocommit = True
        for state in ("visibility map empty", "after VACUUM"):
            for domain in ("hot.test", "spoofed.test", "quiet7.test", "unknown.test"):
                found = plan(conn, TRUSTED_FLAGS_SQL, (domain, "f" * 64, FLAG_SHAS))
                assert ("Index Only Scan", FLAGS_INDEX) in found, (state, domain, found)
            conn.execute("VACUUM scans")
        assert ("Index Scan", "scans_pkey") in plan(conn, LATEST_SQL, (20,))  # /api/history: the primary key, backwards
        assert conn.execute(TRUSTED_FLAGS_SQL, ("spoofed.test", "f" * 64, FLAG_SHAS)).fetchall() == []
        first = conn.execute("SELECT email_sha256 FROM scans WHERE sender_domain = 'hot.test' ORDER BY email_sha256 LIMIT %s", (FLAG_SHAS,))
        assert conn.execute(TRUSTED_FLAGS_SQL, ("hot.test", "f" * 64, FLAG_SHAS)).fetchall() == first.fetchall()


def test_migration_upgrades_an_old_table_once(schema):
    with schema() as conn:
        conn.execute(OLD_SCHEMA)
        conn.execute(OLD_INSERT, ("a" * 64, "bank.test", "phishing", 80, json.dumps([{"id": "auth.dmarc_pass", "weight": 0}])))
        conn.execute(OLD_INSERT, ("b" * 64, "bank.test", "phishing", 80, json.dumps([{"id": "links.ip_host", "weight": 30}])))
    store = PostgresHistory(schema)
    assert store.create_schema(attempts=1) == ["added column trusted", f"created {FLAGS_INDEX}", "analyzed scans", "dropped scans_domain_verdict"]
    assert store.create_schema(attempts=1) == []  # idempotent: the next start changes nothing
    with schema() as conn:
        assert conn.execute("SELECT email_sha256, trusted FROM scans ORDER BY id").fetchall() == [("a" * 64, True), ("b" * 64, False)]
        assert conn.execute("SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)", (FLAGS_INDEX,)).fetchone() == (True,)
        assert conn.execute("SELECT to_regclass('scans_domain_verdict')").fetchone() == (None,)
    assert store.trusted_flag_shas("bank.test", "c" * 64, 5) == ["a" * 64]


def test_instances_starting_together_migrate_once(schema):
    with schema() as conn:
        conn.execute(OLD_SCHEMA)
    results, errors = [], []

    def start():
        try:
            results.append(PostgresHistory(schema).create_schema(attempts=1))
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=start) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert sorted(results, key=len) == [[], [], [], ["added column trusted", f"created {FLAGS_INDEX}", "analyzed scans", "dropped scans_domain_verdict"]]


def test_migration_replaces_the_first_partial_index(store):
    with store._connect() as conn:
        conn.autocommit = True
        conn.execute(f"DROP INDEX {FLAGS_INDEX}")
        conn.execute(FIRST_D112_INDEX)  # the schema 65fd4ab left on RDS
    assert store.create_schema(attempts=1) == [f"created {FLAGS_INDEX}", "analyzed scans", "dropped scans_trusted_flags"]
    assert store.create_schema(attempts=1) == []


def test_the_previous_version_works_on_the_new_schema(store):
    with store._connect() as conn:
        conn.execute(OLD_INSERT, ("a" * 64, "bank.test", "phishing", 80, json.dumps([{"id": "auth.dmarc_pass", "weight": 0}])))
        assert conn.execute(OLD_COUNT, ["bank.test", "b" * 64, *OLD_COUNT_PARAMS]).fetchone() == (1,)
        assert conn.execute(f"SELECT {', '.join(SCANS_COLUMNS)} FROM scans ORDER BY id DESC LIMIT %s", (5,)).fetchone()[2] == "a" * 64
    assert store.trusted_flag_shas("bank.test", "b" * 64, 5) == ["a" * 64]  # its row is trusted for the new version


def test_an_interrupted_index_build_is_rebuilt(store):
    with store._connect() as conn:
        conn.autocommit = True
        conn.execute("UPDATE pg_index SET indisvalid = false WHERE indexrelid = to_regclass(%s)", (FLAGS_INDEX,))
        assert migrate(conn) == [f"dropped invalid {FLAGS_INDEX}", f"created {FLAGS_INDEX}", "analyzed scans"]
        assert conn.execute("SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)", (FLAGS_INDEX,)).fetchone() == (True,)


def test_pool_reuses_its_connection_and_reconnects_after_a_drop():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    from webapp.credentials import DatabasePool

    # One connection only: psycopg_pool hands out connections first in, first out and grows when a
    # client has to wait, so with two the second checkout may get the other one (a flaky check).
    pool = DatabasePool(conninfo_to_dict(URL), max_size=1, timeout=5)
    with pool.connection() as conn:
        first = conn.execute("SELECT pg_backend_pid()").fetchone()[0]
    with pool.connection() as conn:
        assert conn.execute("SELECT pg_backend_pid()").fetchone()[0] == first  # the same server process
    with psycopg.connect(URL, autocommit=True) as admin:
        admin.execute("SELECT pg_terminate_backend(%s)", (first,))  # the server drops the connection
    with pool.connection() as conn:
        assert conn.execute("SELECT pg_backend_pid()").fetchone()[0] != first  # replaced, no error
    pool.reset()

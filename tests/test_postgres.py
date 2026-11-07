"""PostgresHistory against a real database; skipped unless TEST_DATABASE_URL is set.

    TEST_DATABASE_URL=postgresql://phishdet:<password>@127.0.0.1:15432/phishdet python -m pytest -q tests/test_postgres.py

It works in its own schema and drops it afterwards.
"""

import os
import uuid

import pytest

from webapp.storage import SCANS_COLUMNS, PostgresHistory

URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="TEST_DATABASE_URL not set")


@pytest.fixture
def store():
    import psycopg

    schema = "test_" + uuid.uuid4().hex[:8]
    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    store = PostgresHistory(lambda: psycopg.connect(URL, options=f"-c search_path={schema}"))
    store.create_schema(attempts=1)
    yield store
    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA {schema} CASCADE")


def test_table_has_exactly_the_scans_columns(store):
    with store._connect() as conn:
        columns = conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'scans' AND table_schema = current_schema()"
        ).fetchall()
    assert {c[0] for c in columns} == set(SCANS_COLUMNS)


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
    assert store.trusted_flag_shas("examplebank.test", "b" * 64, 5) == ["c" * 64, "a" * 64]  # newest first, trusted only
    assert store.trusted_flag_shas("examplebank.test", "c" * 64, 5) == ["a" * 64]

    latest = store.recent(2)
    assert [r["verdict"] for r in latest] == ["suspicious", "phishing"]
    assert set(latest[0]) == set(SCANS_COLUMNS)


def test_pool_reuses_its_connection_and_reconnects_after_a_drop():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    from webapp.credentials import DatabasePool

    pool = DatabasePool(conninfo_to_dict(URL), timeout=5)
    with pool.connection() as conn:
        first = conn.execute("SELECT pg_backend_pid()").fetchone()[0]
    with pool.connection() as conn:
        assert conn.execute("SELECT pg_backend_pid()").fetchone()[0] == first  # the same server process
    with psycopg.connect(URL, autocommit=True) as admin:
        admin.execute("SELECT pg_terminate_backend(%s)", (first,))  # the server drops the connection
    with pool.connection() as conn:
        assert conn.execute("SELECT pg_backend_pid()").fetchone()[0] != first  # replaced, no error
    pool.reset()

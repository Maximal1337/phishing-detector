"""Time the history check's query before and after D-112 on tables of growing size, in a throwaway schema.

    TEST_DATABASE_URL=postgresql://phishdet:<password>@127.0.0.1:15432/phishdet python scripts/history_query_bench.py --rows 150000,1500000

For each size it fills one table with synthetic rows (no email content): 10 % from a hot lookalike domain (every
phishing row trusted, like a campaign), 10 % from a spoofed domain (phishing, never trusted), 80 % legitimate mail
that passes DMARC (trusted, but not phishing) from 500 quiet domains, as in the load test. Both indexes exist, so each query uses the one it was written for:

    before: count(*) with the jsonb rule        -> (sender_domain, verdict) on every row
    after:  the `trusted` column, ORDER BY email_sha256 LIMIT 5 -> partial index of the trusted phishing rows

It prints the server's execution time (median of EXPLAIN ANALYZE runs), the pages read and the plan, and the
index sizes. Uses only the database you point it at, and drops its schema at the end.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webapp.storage import FLAG_SHAS, TRUSTED_FLAGS_SQL, PostgresHistory  # noqa: E402

OLD_INDEX_SQL = "CREATE INDEX scans_domain_verdict ON scans (sender_domain, verdict)"
OLD_QUERY = (
    "SELECT count(*) FROM scans WHERE sender_domain = %s AND verdict = 'phishing' AND email_sha256 <> %s AND ("
    "signals @> %s::jsonb OR signals @> %s::jsonb)"
)
OLD_PARAMS = [json.dumps([{"id": "auth.dmarc_pass"}]), json.dumps([{"id": "sender.lookalike_domain"}])]
FILL = """
INSERT INTO scans (email_sha256, sender_domain, verdict, score, signals)
SELECT md5(g::text) || md5((g + 1)::text),
       CASE g % 10 WHEN 0 THEN 'hot.test' WHEN 1 THEN 'spoofed.test' ELSE 'quiet' || (g % 500) || '.test' END,
       CASE WHEN g % 10 < 2 THEN 'phishing' ELSE 'likely_legitimate' END,
       CASE WHEN g % 10 < 2 THEN 70 ELSE 0 END,
       CASE g % 10 WHEN 0 THEN '[{"id": "sender.lookalike_domain", "weight": 35}, {"id": "links.ip_host", "weight": 30}]'::jsonb
                   WHEN 1 THEN '[{"id": "links.ip_host", "weight": 30}, {"id": "content.urgency", "weight": 15}]'::jsonb
                   ELSE '[{"id": "auth.dmarc_pass", "weight": 0}]'::jsonb END
FROM generate_series(1, {rows}) g
"""
DOMAINS = ("hot.test", "spoofed.test", "quiet7.test")


def explain(conn, sql: str, params: list, runs: int) -> tuple[float, int, str]:
    """Median execution time (ms), shared pages read, and the scan node of the plan."""
    times, pages, node = [], 0, ""
    for _ in range(runs):
        result = conn.execute("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql, params).fetchone()[0][0]
        times.append(result["Execution Time"])
        plan = result["Plan"]
        pages = plan.get("Shared Hit Blocks", 0) + plan.get("Shared Read Blocks", 0)
        while plan.get("Plans"):
            plan = plan["Plans"][0]
        node = plan["Node Type"] + (f" on {plan['Index Name']}" if plan.get("Index Name") else "")
    return statistics.median(times), pages, node


def main(argv: list[str] | None = None) -> int:
    import psycopg

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rows", default="150000,1500000", help="comma-separated table sizes")
    parser.add_argument("--runs", type=int, default=25)
    args = parser.parse_args(argv)
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        parser.error("set TEST_DATABASE_URL")

    print("rows | domain | before ms / pages / plan | after ms / pages / plan")
    for rows in (int(r) for r in args.rows.split(",")):
        schema = "bench_" + uuid.uuid4().hex[:8]
        with psycopg.connect(url, autocommit=True) as admin:
            admin.execute(f"CREATE SCHEMA {schema}")
        try:
            def connect():
                return psycopg.connect(url, options=f"-c search_path={schema}")

            PostgresHistory(connect).create_schema(attempts=1)
            with connect() as conn:
                conn.autocommit = True
                conn.execute(FILL.replace("{rows}", str(int(rows))))
                conn.execute(OLD_INDEX_SQL)  # back again, so the old query can be timed on the same rows
                conn.execute("VACUUM ANALYZE scans")
                for domain in DOMAINS:
                    before = explain(conn, OLD_QUERY, [domain, "f" * 64, *OLD_PARAMS], args.runs)
                    after = explain(conn, TRUSTED_FLAGS_SQL, [domain, "f" * 64, FLAG_SHAS], args.runs)
                    print(f"{rows} | {domain} | {before[0]:.3f} / {before[1]} / {before[2]} | {after[0]:.3f} / {after[1]} / {after[2]}")
                sizes = conn.execute(
                    "SELECT relname, pg_size_pretty(pg_relation_size(oid)) FROM pg_class"
                    " WHERE relnamespace = current_schema()::regnamespace AND relkind IN ('r', 'i') ORDER BY relname"
                ).fetchall()
                print(f"{rows} | sizes: " + ", ".join(f"{n} {s}" for n, s in sizes))
        finally:
            with psycopg.connect(url, autocommit=True) as admin:
                admin.execute(f"DROP SCHEMA {schema} CASCADE")
    return 0


if __name__ == "__main__":
    sys.exit(main())

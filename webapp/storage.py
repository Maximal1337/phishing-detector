"""Scan history (PostgreSQL, or memory for tests and quick local runs) and the result cache (Valkey, or none).

The history keeps only what D-10 allows: time, the email's SHA-256, the sender domain,
verdict, score and signal ids with weights. No addresses, subject, body or evidence.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Callable

from phishing_detector.checks.history import TRUSTED_SIGNALS

SCANS_COLUMNS = ("id", "scanned_at", "email_sha256", "sender_domain", "verdict", "score", "signals")

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
  id            bigserial   PRIMARY KEY,
  scanned_at    timestamptz NOT NULL DEFAULT now(),
  email_sha256  char(64)    NOT NULL,
  sender_domain text,
  verdict       text        NOT NULL,
  score         smallint    NOT NULL,
  signals       jsonb       NOT NULL
)
"""

# The poisoning rule (D-09) as a stored column, computed by PostgreSQL from `signals`: true when the scan passed
# DMARC for its domain or the domain was a lookalike. Same rule as phishing_detector's InMemoryHistory. Any writer
# fills it, also an older app version during a rollout. Changing TRUSTED_SIGNALS needs a new column (a migration).
TRUSTED_EXPRESSION = " OR ".join(f"signals @> '{json.dumps([{'id': s}], separators=(',', ':'))}'" for s in TRUSTED_SIGNALS)
HAS_TRUSTED_SQL = (
    "SELECT 1 FROM information_schema.columns"
    " WHERE table_schema = current_schema() AND table_name = 'scans' AND column_name = 'trusted'"
)
ADD_TRUSTED = f"ALTER TABLE scans ADD COLUMN trusted boolean GENERATED ALWAYS AS ({TRUSTED_EXPRESSION}) STORED"

# One partial index, for the history check only: it holds just the trusted phishing rows, with the SHA-256 in the
# index, so the check reads at most FLAG_SHAS index entries and never the table (an index-only scan), however big
# the table grows. The query repeats the index's predicate word for word, so the planner can use it.
#
# ORDER BY email_sha256 is there for the planner, not for the result: only this index returns rows in that order,
# so it's the only plan that can stop after FLAG_SHAS rows. Without it, the LIMIT made a sequential scan look
# cheap whenever the planner expected many matches (it treats domain, verdict and trusted as independent), and for
# a domain with no flags that scan read the whole table (seen on RDS, D-112). ORDER BY id did the same through
# the primary key.
FLAGS_INDEX = "scans_trusted_flag_shas"
INDEX_VALID_SQL = "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)"
CREATE_FLAGS_INDEX = (
    f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {FLAGS_INDEX} ON scans (sender_domain, email_sha256)"
    " WHERE verdict = 'phishing' AND trusted"
)
# Indexes of earlier versions: (sender_domain, verdict) on every row, used only by the old history count; and the
# first partial index, (sender_domain) INCLUDE (email_sha256), whose unordered LIMIT query got the bad plan.
OLD_INDEXES = ("scans_domain_verdict", "scans_trusted_flags")
TRUSTED_FLAGS_SQL = (
    "SELECT email_sha256 FROM scans"
    " WHERE sender_domain = %s AND verdict = 'phishing' AND trusted AND email_sha256 <> %s ORDER BY email_sha256 LIMIT %s"
)
LATEST_SQL = f"SELECT {', '.join(SCANS_COLUMNS)} FROM scans ORDER BY id DESC LIMIT %s"  # the primary key, backwards

# Every instance (and each gunicorn worker) runs the migration at start; this advisory lock makes them take turns.
MIGRATION_LOCK = 0x70686973  # any constant ("phis")
MIGRATION_LOCK_WAIT = 120.0  # seconds

STATIC_TTL_SECONDS = 3600  # the email's own analysis
FLAG_TTL_SECONDS = 7 * 24 * 3600  # a positive domain mark
FLAG_SHAS = 5  # flagging emails kept per mark


def is_trusted_flag(row: dict) -> bool:
    """A scan row that counts against its sender domain under the poisoning rule."""
    return row["verdict"] == "phishing" and bool(row["sender_domain"]) and any(s["id"] in TRUSTED_SIGNALS for s in row["signals"])


def scan_row(result: dict) -> dict:
    """The row stored for one scan, from a result dict (fresh or cached)."""
    return {
        "email_sha256": result["email_sha256"],
        "sender_domain": result["sender_domain"],
        "verdict": result["verdict"],
        "score": result["score"],
        "signals": [{"id": i["id"], "weight": i["weight"]} for i in result["indicators"]],
    }


class MemoryHistory:
    """History in a list: tests, and local runs without a database (lost on restart)."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def record(self, row: dict) -> None:
        self.rows.append({"id": len(self.rows) + 1, "scanned_at": datetime.now(timezone.utc), **row})

    def _flags(self, sender_domain: str, exclude_sha256: str) -> list[dict]:
        return [r for r in self.rows if r["sender_domain"] == sender_domain and r["email_sha256"] != exclude_sha256 and is_trusted_flag(r)]

    def trusted_flag_shas(self, sender_domain: str, exclude_sha256: str, limit: int) -> list[str]:
        return [r["email_sha256"] for r in reversed(self._flags(sender_domain, exclude_sha256))][:limit]

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        return len(self.trusted_flag_shas(sender_domain, exclude_sha256, FLAG_SHAS))  # capped like PostgresHistory

    def recent(self, limit: int) -> list[dict]:
        return list(reversed(self.rows[-limit:]))


class PostgresHistory:
    """History in the `scans` table. `connect()` returns a connection context: from the per-worker pool
    in the app (webapp.credentials.DatabasePool), or a plain psycopg connection in tests."""

    def __init__(self, connect: Callable) -> None:
        self._connect = connect

    def create_schema(self, attempts: int = 10, delay: float = 3.0) -> list[str]:
        """Create or upgrade the table (D-112); retried while the database is still starting.

        Returns the changes made, [] when the schema was already current. Safe on every start of every instance at
        once: the instances take turns under an advisory lock, and each step is skipped when it's already done.
        """
        for attempt in range(attempts):
            try:
                with self._connect() as conn:
                    return migrate(conn)
            except Exception:
                if attempt == attempts - 1:
                    raise
                time.sleep(delay)
        return []

    def record(self, row: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans (email_sha256, sender_domain, verdict, score, signals) VALUES (%s, %s, %s, %s, %s::jsonb)",
                (row["email_sha256"], row["sender_domain"], row["verdict"], row["score"], json.dumps(row["signals"])),
            )

    def trusted_flag_shas(self, sender_domain: str, exclude_sha256: str, limit: int) -> list[str]:
        """SHA-256s of up to `limit` earlier trusted flags, one per scan row (an email scanned twice can repeat)."""
        with self._connect() as conn:
            rows = conn.execute(TRUSTED_FLAGS_SQL, (sender_domain, exclude_sha256, limit)).fetchall()
        return [r[0] for r in rows]

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        """Capped at FLAG_SHAS: the check only needs to know there are some (a cache mark holds as many)."""
        return len(self.trusted_flag_shas(sender_domain, exclude_sha256, FLAG_SHAS))

    def recent(self, limit: int) -> list[dict]:
        with self._connect() as conn:
            return [dict(zip(SCANS_COLUMNS, values)) for values in conn.execute(LATEST_SQL, (limit,)).fetchall()]


def migrate(conn, lock_wait: float = MIGRATION_LOCK_WAIT) -> list[str]:
    """The schema steps, each run only when needed. Returns what was done."""
    changes = []
    conn.autocommit = True  # CREATE INDEX CONCURRENTLY can't run inside a transaction
    try:
        _take_migration_lock(conn, lock_wait)
        try:
            conn.execute(CREATE_TABLE)
            if not conn.execute(HAS_TRUSTED_SQL).fetchone():
                # Rewrites the table under an exclusive lock (seconds for 10^5-10^6 rows). Give up after 5 s
                # rather than queue the app's queries behind a long wait; create_schema retries.
                conn.execute("SET lock_timeout = '5s'")
                try:
                    conn.execute(ADD_TRUSTED)
                finally:
                    conn.execute("RESET lock_timeout")
                changes.append("added column trusted")
            valid = conn.execute(INDEX_VALID_SQL, (FLAGS_INDEX,)).fetchone()
            if valid and not valid[0]:  # left behind by an interrupted CREATE INDEX CONCURRENTLY
                conn.execute(f"DROP INDEX CONCURRENTLY {FLAGS_INDEX}")
                changes.append(f"dropped invalid {FLAGS_INDEX}")
            if not valid or not valid[0]:
                conn.execute(CREATE_FLAGS_INDEX)  # doesn't block writes
                changes.append(f"created {FLAGS_INDEX}")
                conn.execute("ANALYZE scans")  # statistics for the new column; autovacuum would only come later
                changes.append("analyzed scans")
            for old in OLD_INDEXES:
                if conn.execute(INDEX_VALID_SQL, (old,)).fetchone():
                    conn.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {old}")
                    changes.append(f"dropped {old}")
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK,))
    finally:
        conn.autocommit = False
    return changes


def _take_migration_lock(conn, wait: float) -> None:
    # Polls pg_try_advisory_lock instead of blocking in pg_advisory_lock: an instance waiting inside a statement
    # holds a snapshot, CREATE INDEX CONCURRENTLY in the instance that has the lock waits for it, and PostgreSQL
    # ends that with "deadlock detected" for the index build (seen in a local test; polling builds at once).
    deadline = time.monotonic() + wait
    while not conn.execute("SELECT pg_try_advisory_lock(%s)", (MIGRATION_LOCK,)).fetchone()[0]:
        if time.monotonic() > deadline:
            raise TimeoutError("another instance holds the schema migration lock")
        time.sleep(0.5)


class NoCache:
    def get(self, key: str):
        return None

    def set(self, key: str, value, ttl: int) -> None:
        pass


class ValkeyCache:
    """JSON values in Valkey. Two kinds of keys:

    static:<rules version>:<sha256>  the email's own analysis (no history, no score), 1 hour
    flag:<rules version>:<domain>    a positive reputation mark: SHA-256s of emails that flagged the domain, 7 days
    """

    def __init__(self, url: str) -> None:
        import redis  # only needed when a cache is configured

        # redis-py clients are thread-safe: each command takes a connection from the client's own pool.
        self._client = redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)

    def get(self, key: str):
        value = self._client.get(key)
        return json.loads(value) if value else None

    def set(self, key: str, value, ttl: int) -> None:
        self._client.set(key, json.dumps(value), ex=ttl)


class ReputationHistory:
    """The history check, read through positive domain marks in the cache. The database stays the source of truth.

    - A mark is written only after the scan row is committed, and only for a flag that passes the poisoning rule.
    - Only "flagged" is cached, never "not flagged": a new flag must count on every instance at once, and a miss
      costs one index-only lookup of at most FLAG_SHAS entries. After a miss that finds flags, the mark is restored.
    - With a mark, the database isn't asked, so the signal still works while the database is down. Without one,
      a database failure propagates: the scan reports the history as unavailable and stays cautious (D-70).
    - If the cache fails, everything goes to the database.
    """

    def __init__(self, store, cache, rules_version: str, on_cache_error: Callable[[Exception], None] = lambda exc: None) -> None:
        self.store, self.cache, self.rules_version, self.on_cache_error = store, cache, rules_version, on_cache_error

    def _key(self, sender_domain: str) -> str:
        return f"flag:{self.rules_version}:{sender_domain}"

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        mark = self._mark(sender_domain)
        others = [sha for sha in mark if sha != exclude_sha256]  # an email never flags itself
        if others:
            return len(others)
        shas = self.store.trusted_flag_shas(sender_domain, exclude_sha256, FLAG_SHAS)  # one query for both
        if shas:
            try:
                self._add(sender_domain, shas)
            except Exception as exc:  # the answer is already known; the mark comes back next time
                self.on_cache_error(exc)
        return len(shas)

    def remember(self, row: dict) -> None:
        """Call after the row is committed to the database."""
        if is_trusted_flag(row):
            try:
                self._add(row["sender_domain"], [row["email_sha256"]])
            except Exception as exc:
                self.on_cache_error(exc)

    def _mark(self, sender_domain: str) -> list[str]:
        """The SHA-256s in the mark; [] if there is none, the cache fails or the entry can't be read."""
        try:
            mark = self.cache.get(self._key(sender_domain)) or []
            if not (isinstance(mark, list) and all(isinstance(s, str) and len(s) == 64 for s in mark)):
                raise ValueError("unexpected mark format")  # reported as cache_decode_failed, then a miss
            return mark
        except Exception as exc:
            self.on_cache_error(exc)
            return []

    def _add(self, sender_domain: str, shas: list[str]) -> None:
        key = self._key(sender_domain)
        # Read-modify-write: two instances at once can drop a SHA from the mark, never add a wrong one.
        merged = list(dict.fromkeys([*shas, *self._mark(sender_domain)]))[:FLAG_SHAS]
        self.cache.set(key, merged, FLAG_TTL_SECONDS)

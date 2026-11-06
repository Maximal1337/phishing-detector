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

SCHEMA = """
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

# The poisoning rule (D-09): an earlier phishing verdict counts only if that email passed DMARC
# for the domain or the domain was a lookalike. Same rule as phishing_detector's InMemoryHistory.
TRUSTED_FLAGS_WHERE = (
    "sender_domain = %s AND verdict = 'phishing' AND email_sha256 <> %s AND ("
    + " OR ".join("signals @> %s::jsonb" for _ in TRUSTED_SIGNALS)
    + ")"
)
TRUSTED_FLAGS_SQL = f"SELECT count(*) FROM scans WHERE {TRUSTED_FLAGS_WHERE}"
TRUSTED_FLAG_SHAS_SQL = f"SELECT email_sha256 FROM scans WHERE {TRUSTED_FLAGS_WHERE} ORDER BY id DESC LIMIT %s"

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

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        return len(self._flags(sender_domain, exclude_sha256))

    def trusted_flag_shas(self, sender_domain: str, exclude_sha256: str, limit: int) -> list[str]:
        return list(dict.fromkeys(r["email_sha256"] for r in reversed(self._flags(sender_domain, exclude_sha256))))[:limit]

    def recent(self, limit: int) -> list[dict]:
        return list(reversed(self.rows[-limit:]))


class PostgresHistory:
    """History in the `scans` table. One short connection per call: simple, and enough for this load."""

    def __init__(self, connect: Callable) -> None:
        self._connect = connect  # returns a new psycopg connection

    def create_schema(self, attempts: int = 10, delay: float = 3.0) -> None:
        """CREATE TABLE IF NOT EXISTS, retried while the database is still starting."""
        for attempt in range(attempts):
            try:
                with self._connect() as conn:
                    conn.execute(SCHEMA)
                return
            except Exception:
                if attempt == attempts - 1:
                    raise
                time.sleep(delay)

    def record(self, row: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans (email_sha256, sender_domain, verdict, score, signals) VALUES (%s, %s, %s, %s, %s::jsonb)",
                (row["email_sha256"], row["sender_domain"], row["verdict"], row["score"], json.dumps(row["signals"])),
            )

    @staticmethod
    def _params(sender_domain: str, exclude_sha256: str) -> list:
        return [sender_domain, exclude_sha256] + [json.dumps([{"id": s}]) for s in TRUSTED_SIGNALS]

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        with self._connect() as conn:
            return conn.execute(TRUSTED_FLAGS_SQL, self._params(sender_domain, exclude_sha256)).fetchone()[0]

    def trusted_flag_shas(self, sender_domain: str, exclude_sha256: str, limit: int) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(TRUSTED_FLAG_SHAS_SQL, self._params(sender_domain, exclude_sha256) + [limit]).fetchall()
        return list(dict.fromkeys(r[0] for r in rows))

    def recent(self, limit: int) -> list[dict]:
        with self._connect() as conn:
            cursor = conn.execute(f"SELECT {', '.join(SCANS_COLUMNS)} FROM scans ORDER BY id DESC LIMIT %s", (limit,))
            return [dict(zip(SCANS_COLUMNS, values)) for values in cursor.fetchall()]


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
      costs one indexed count in the database. After a miss that finds flags, the mark is restored.
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
        count = self.store.count_trusted_flags(sender_domain, exclude_sha256)
        if count:
            try:
                self._add(sender_domain, self.store.trusted_flag_shas(sender_domain, exclude_sha256, FLAG_SHAS))
            except Exception as exc:  # the answer is already known; the mark comes back next time
                self.on_cache_error(exc)
        return count

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

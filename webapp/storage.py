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
TRUSTED_FLAGS_SQL = (
    "SELECT count(*) FROM scans WHERE sender_domain = %s AND verdict = 'phishing' AND email_sha256 <> %s AND ("
    + " OR ".join("signals @> %s::jsonb" for _ in TRUSTED_SIGNALS)
    + ")"
)


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

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        return sum(
            1
            for row in self.rows
            if row["sender_domain"] == sender_domain
            and row["verdict"] == "phishing"
            and row["email_sha256"] != exclude_sha256
            and any(s["id"] in TRUSTED_SIGNALS for s in row["signals"])
        )

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

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        params = [sender_domain, exclude_sha256] + [json.dumps([{"id": s}]) for s in TRUSTED_SIGNALS]
        with self._connect() as conn:
            return conn.execute(TRUSTED_FLAGS_SQL, params).fetchone()[0]

    def recent(self, limit: int) -> list[dict]:
        with self._connect() as conn:
            cursor = conn.execute(f"SELECT {', '.join(SCANS_COLUMNS)} FROM scans ORDER BY id DESC LIMIT %s", (limit,))
            return [dict(zip(SCANS_COLUMNS, values)) for values in cursor.fetchall()]


class NoCache:
    def get(self, sha256: str) -> dict | None:
        return None

    def set(self, sha256: str, result: dict) -> None:
        pass


class ValkeyCache:
    """Full result JSON under `scan:<sha256>` for an hour (D-29)."""

    TTL_SECONDS = 3600

    def __init__(self, url: str) -> None:
        import redis  # only needed when a cache is configured

        self._client = redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)

    def get(self, sha256: str) -> dict | None:
        value = self._client.get(f"scan:{sha256}")
        return json.loads(value) if value else None

    def set(self, sha256: str, result: dict) -> None:
        self._client.setex(f"scan:{sha256}", self.TTL_SECONDS, json.dumps(result))

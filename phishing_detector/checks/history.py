"""History of earlier scans: was this sender domain flagged before?

Poisoning-safe: an earlier phishing verdict counts against a domain only if
that email proved it came from the domain (DMARC passed for it) or the domain
itself is a lookalike. Otherwise anyone could put "From: examplebank.test" on
a phishing mail and make the real bank's later mail look suspicious.
"""

from __future__ import annotations

from typing import Protocol

from ..models import Finding, Result
from .common import defang_domain

SIGNALS = ("history.domain_flagged",)
TRUSTED_SIGNALS = ("auth.dmarc_pass", "sender.lookalike_domain")


class HistoryStore(Protocol):
    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        """Earlier phishing scans of other emails from this domain that carry a TRUSTED_SIGNALS id."""
        ...


class InMemoryHistory:
    """The same rule as the database store, for tests."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def record(self, result: Result) -> None:
        self.rows.append(
            {
                "email_sha256": result.email_sha256,
                "sender_domain": result.sender_domain,
                "verdict": result.verdict,
                "signals": result.signals(),
            }
        )

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        return sum(
            1
            for row in self.rows
            if row["sender_domain"] == sender_domain
            and row["verdict"] == "phishing"
            and row["email_sha256"] != exclude_sha256
            and any(signal["id"] in TRUSTED_SIGNALS for signal in row["signals"])
        )


def check(sender_domain: str, email_sha256: str, store: HistoryStore) -> list[Finding]:
    count = store.count_trusted_flags(sender_domain, email_sha256)
    if not count:
        return []
    return [
        Finding(
            "history.domain_flagged",
            "Mail from this sender domain was flagged as phishing in earlier scans",
            (f"{count} earlier phishing scan(s) from {defang_domain(sender_domain)}",),
        )
    ]

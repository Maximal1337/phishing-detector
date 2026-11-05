"""Who the email claims to be from, compared with where it really comes from.

Evidence names domains only, never full addresses.
"""

from __future__ import annotations

import re

from ..models import Finding, ParsedEmail
from .common import brands, brands_named_in, defang_domain, imitated_brand_domain, normalize_host, registrable_domain

SIGNALS = (
    "sender.display_name_address",
    "sender.brand_mismatch",
    "sender.lookalike_domain",
    "sender.punycode",
    "sender.reply_to_mismatch",
    "sender.return_path_mismatch",
)

NO_SENDER_NOTE = "No readable From address: sender checks were skipped."

_ADDRESS_IN_NAME = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def check(parsed: ParsedEmail, notes: list[str]) -> list[Finding]:
    if not parsed.from_domain:
        notes.append(NO_SENDER_NOTE)
        return []

    domain = normalize_host(parsed.from_domain)
    registrable = registrable_domain(domain)
    sender = f"sender domain {defang_domain(domain)}"
    brand_map = brands()
    findings = []

    shown = _ADDRESS_IN_NAME.search(parsed.from_display)
    if shown and registrable_domain(shown.group(1)) != registrable:
        findings.append(
            Finding(
                "sender.display_name_address",
                "The display name shows an address at another domain than the real sender",
                (f"name shows {defang_domain(shown.group(1).lower())}", sender),
            )
        )

    claimed = [k for k in brands_named_in(parsed.from_display, brand_map) if registrable not in brand_map[k]]
    if claimed:
        findings.append(
            Finding(
                "sender.brand_mismatch",
                "The display name names a brand, but the mail doesn't come from that brand's domain",
                (f"name claims {', '.join(claimed)}", sender),
            )
        )

    imitated = imitated_brand_domain(domain, brand_map)
    if imitated:
        findings.append(
            Finding(
                "sender.lookalike_domain",
                "The sender domain imitates a known brand domain",
                (f"{defang_domain(registrable)} looks like {defang_domain(imitated)}",),
            )
        )

    if any(label.startswith("xn--") for label in domain.split(".")):
        findings.append(
            Finding("sender.punycode", "The sender domain uses international characters (punycode), a common disguise", (defang_domain(domain),))
        )

    other_reply = sorted({registrable_domain(d) for d in parsed.reply_to_domains} - {registrable})
    if other_reply:
        findings.append(
            Finding(
                "sender.reply_to_mismatch",
                "Replies would go to a different domain than the sender's",
                tuple(f"replies go to {defang_domain(d)}" for d in other_reply),
            )
        )

    if parsed.return_path_domain and registrable_domain(parsed.return_path_domain) != registrable:
        findings.append(
            Finding(
                "sender.return_path_mismatch",
                "The bounce address (Return-Path) is at another domain (common for mailing services too)",
                (f"bounces go to {defang_domain(registrable_domain(parsed.return_path_domain))}",),
            )
        )

    return findings

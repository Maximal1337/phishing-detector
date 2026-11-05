"""SPF, DKIM and DMARC results from the topmost Authentication-Results header (RFC 8601).

Only the topmost header is read: the receiving mail server adds it last, and
any header below it may have been written by the sender. A missing header is
neutral, so mail from servers that don't add one isn't penalised.
"""

from __future__ import annotations

import re

from ..models import Finding, ParsedEmail
from .common import defang_domain

SIGNALS = ("auth.spf_fail", "auth.spf_softfail", "auth.dkim_fail", "auth.dmarc_fail", "auth.dmarc_pass")

NO_HEADER_NOTE = "No Authentication-Results header: SPF, DKIM and DMARC were not checked (treated as neutral)."

_RESULT = re.compile(r"^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_HEADER_FROM = re.compile(r"\bheader\.from\s*=\s*([^\s;]+)", re.IGNORECASE)


def results(header: str) -> dict[str, list[tuple[str, str | None]]]:
    """{"spf": [("fail", None)], "dmarc": [("pass", "example.test")], ...} from one header value."""
    found: dict[str, list[tuple[str, str | None]]] = {}
    for segment in header.split(";")[1:]:  # the first segment is the receiving server's id
        match = _RESULT.match(segment)
        if not match:
            continue
        header_from = _HEADER_FROM.search(segment)
        found.setdefault(match.group(1).lower(), []).append(
            (match.group(2).lower(), header_from.group(1).lower().strip(".") if header_from else None)
        )
    return found


def check(parsed: ParsedEmail, notes: list[str]) -> list[Finding]:
    if not parsed.auth_results:
        notes.append(NO_HEADER_NOTE)
        return []

    found = results(parsed.auth_results)
    findings = []

    spf = [result for result, _ in found.get("spf", [])]
    if "fail" in spf:
        findings.append(Finding("auth.spf_fail", "SPF failed: the sending server isn't allowed to send for that domain", ("spf=fail",)))
    elif "softfail" in spf:
        findings.append(Finding("auth.spf_softfail", "SPF soft-failed: the sending server is probably not allowed", ("spf=softfail",)))

    dkim = [result for result, _ in found.get("dkim", [])]
    if "fail" in dkim and "pass" not in dkim:
        findings.append(Finding("auth.dkim_fail", "DKIM signature failed verification", ("dkim=fail",)))

    dmarc = found.get("dmarc", [])
    if any(result == "fail" for result, _ in dmarc):
        findings.append(Finding("auth.dmarc_fail", "DMARC failed: the From domain is probably spoofed", ("dmarc=fail",)))
    elif any(result == "pass" and header_from in (None, parsed.from_domain) for result, header_from in dmarc):
        findings.append(
            Finding(
                "auth.dmarc_pass",
                "DMARC passed for the From domain (not suspicious; the history check trusts it)",
                (defang_domain(parsed.from_domain),) if parsed.from_domain else (),
            )
        )
    return findings

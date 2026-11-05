"""Weights, thresholds and analyze(): parse, run the checks, score.

All weights live in this one table so tuning happens in one place.
Score = sum of the weights of the indicators found, capped at 100.
"""

from __future__ import annotations

from collections.abc import Callable

from .checks import attachments, auth, links, sender, wording
from .checks import history as history_check
from .checks.history import HistoryStore
from .models import Finding, Indicator, ParsedEmail, Result
from .parser import parse

WEIGHTS: dict[str, int] = {
    # Authentication-Results (topmost header only)
    "auth.spf_fail": 15,
    "auth.spf_softfail": 5,
    "auth.dkim_fail": 10,
    "auth.dmarc_fail": 25,
    "auth.dmarc_pass": 0,  # not suspicious; recorded because the history check trusts it
    # Sender
    "sender.display_name_address": 25,
    "sender.brand_mismatch": 25,
    "sender.lookalike_domain": 35,
    "sender.punycode": 20,
    "sender.reply_to_mismatch": 15,
    "sender.return_path_mismatch": 5,
    # Links
    "links.ip_host": 30,
    "links.text_href_mismatch": 30,
    "links.lookalike_domain": 35,
    "links.brand_in_subdomain": 30,
    "links.punycode": 20,
    "links.userinfo": 25,
    "links.script_scheme": 30,
    "links.password_form": 35,
    "links.risky_tld": 15,
    "links.shortener": 10,
    "links.nonstandard_port": 10,
    # Wording (each category counts once)
    "wording.urgency": 10,
    "wording.threat": 10,
    "wording.credentials": 15,
    "wording.payment": 10,
    "wording.prize": 10,
    "wording.generic_greeting": 5,
    # Attachments (MIME metadata only)
    "attach.executable": 40,
    "attach.double_extension": 35,
    "attach.macro_office": 30,
    "attach.html": 25,
    "attach.type_mismatch": 25,
    "attach.password_hint": 15,
    "attach.archive": 10,
    # History of earlier scans
    "history.domain_flagged": 20,
}

MAX_SCORE = 100
PHISHING_AT = 50
SUSPICIOUS_AT = 25

BODY_ONLY_NOTE = "Body text only (no email headers): authentication, sender and history checks were skipped."
NO_HISTORY_NOTE = "History check skipped: no scan history was provided."
HISTORY_UNAVAILABLE_NOTE = "History check skipped: the scan history is unavailable right now."

Check = Callable[[ParsedEmail, list[str]], list[Finding]]

# Checks that need the message headers, and checks that work on any input.
EMAIL_CHECKS: list[Check] = [auth.check, sender.check]
CONTENT_CHECKS: list[Check] = [links.check, wording.check, attachments.check]


def verdict_for(score: int) -> str:
    if score >= PHISHING_AT:
        return "phishing"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "likely_legitimate"


def to_indicators(findings: list[Finding]) -> list[Indicator]:
    indicators = []
    for finding in findings:
        if finding.id not in WEIGHTS:
            raise ValueError(f"no weight for signal {finding.id!r}")
        indicators.append(
            Indicator(
                id=finding.id,
                category=finding.id.split(".", 1)[0],
                weight=WEIGHTS[finding.id],
                reason=finding.reason,
                evidence=finding.evidence,
            )
        )
    return sorted(indicators, key=lambda i: (-i.weight, i.id))


def score_of(indicators: list[Indicator]) -> int:
    return min(MAX_SCORE, sum(i.weight for i in indicators))


def analyze(raw: bytes, history: HistoryStore | None = None) -> Result:
    """Scan one email. `history` is the scan-history store; without it the history check is skipped."""
    parsed = parse(raw)
    notes: list[str] = []
    findings: list[Finding] = []

    if parsed.input_type == "email":
        for check in EMAIL_CHECKS:
            findings.extend(check(parsed, notes))
    else:
        notes.append(BODY_ONLY_NOTE)
    for check in CONTENT_CHECKS:
        findings.extend(check(parsed, notes))

    if parsed.input_type == "email" and parsed.from_domain:
        if history is None:
            notes.append(NO_HISTORY_NOTE)
        else:
            try:
                findings.extend(history_check.check(parsed.from_domain, parsed.sha256, history))
            except Exception:  # a failing store (e.g. database down) must not stop the scan
                notes.append(HISTORY_UNAVAILABLE_NOTE)

    indicators = to_indicators(findings)
    score = score_of(indicators)
    return Result(
        input_type=parsed.input_type,
        verdict=verdict_for(score),
        score=score,
        indicators=indicators,
        notes=notes,
        sender_domain=parsed.from_domain or None,
        email_sha256=parsed.sha256,
    )

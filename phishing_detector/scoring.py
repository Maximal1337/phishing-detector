"""Weights, thresholds and analyze(): parse, run the checks, score.

All weights live in this one table so tuning happens in one place.
Score = sum of the weights of the indicators found, capped at 100.
"""

from __future__ import annotations

from collections.abc import Callable

from .checks import attachments, auth, content, links, sender, wording
from .checks import history as history_check
from .checks.history import HistoryStore
from .models import Finding, Indicator, ParsedEmail, Result
from .parser import parse

# Weights marked "tuned" come from scripts/evaluate.py on the dev split of the
# public corpora (k = 6; see the Evaluation section of the README). The others
# are hand-set: too few hits on that data, or era signals it can't judge.
WEIGHTS: dict[str, int] = {
    # Authentication-Results (topmost header only); era signals, hand-set
    "auth.spf_fail": 15,
    "auth.spf_softfail": 5,
    "auth.dkim_fail": 10,
    "auth.dmarc_fail": 25,
    "auth.dmarc_pass": 0,  # not suspicious; recorded because the history check trusts it
    # Sender
    "sender.display_name_address": 15,  # tuned
    "sender.brand_mismatch": 30,  # tuned
    "sender.lookalike_domain": 35,
    "sender.punycode": 20,
    "sender.reply_to_mismatch": 0,  # tuned: more common in legitimate mailing-list mail than in phishing
    "sender.return_path_mismatch": 0,  # tuned: same, bounce addresses of mailing services
    # Links
    "links.ip_host": 30,
    "links.text_href_mismatch": 10,  # tuned
    "links.lookalike_domain": 15,  # tuned
    "links.brand_in_subdomain": 30,
    "links.punycode": 20,
    "links.userinfo": 25,
    "links.script_scheme": 30,
    "links.password_form": 35,
    "links.risky_tld": 15,
    "links.shortener": 10,
    "links.nonstandard_port": 0,  # tuned
    "links.brand_in_path": 15,  # tuned
    "links.brand_link_mismatch": 5,  # tuned
    "links.recipient_in_url": 20,  # tuned
    "links.redirect_param": 10,  # hand-set, era-biased: newsletters use tracking redirects
    "links.abused_hosting": 20,  # hand-set, era-biased: legitimate sites use these services too
    "links.cta_text": 10,  # hand-set, era-biased: legitimate notices have such buttons
    # Wording (each category counts once)
    "wording.urgency": 10,  # tuned
    "wording.threat": 15,  # tuned
    "wording.credentials": 25,  # tuned
    "wording.payment": 25,  # tuned
    "wording.prize": 0,  # tuned: more common in legitimate mail than in phishing on this data
    "wording.generic_greeting": 30,  # tuned
    # Attachments (MIME metadata only)
    "attach.executable": 40,
    "attach.double_extension": 35,
    "attach.macro_office": 30,
    "attach.html": 25,  # tuned
    "attach.type_mismatch": 25,
    "attach.password_hint": 15,
    "attach.archive": 10,
    # HTML tricks
    "content.hidden_text": 15,  # hand-set, era-biased
    "content.zero_width": 20,  # hand-set, era-biased: rare in legitimate mail
    "content.image_only": 10,  # hand-set, era-biased
    # History of earlier scans
    "history.domain_flagged": 20,
}

MAX_SCORE = 100
PHISHING_AT = 50
SUSPICIOUS_AT = 25

BODY_ONLY_NOTE = "Body text only (no email headers): authentication, sender and history checks were skipped."
NO_HISTORY_NOTE = "History check skipped: no scan history was provided."
HISTORY_UNAVAILABLE_NOTE = "The scan history is unavailable: earlier flags on this sender could not be checked."
HISTORY_UNAVAILABLE_REASON = "history unavailable"

Check = Callable[[ParsedEmail, list[str]], list[Finding]]

# Checks that need the message headers, and checks that work on any input.
EMAIL_CHECKS: list[Check] = [auth.check, sender.check]
CONTENT_CHECKS: list[Check] = [links.check, wording.check, attachments.check, content.check]


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


def cautious_verdict(score: int) -> str:
    """The verdict if the unavailable history had flagged the sender domain.

    When the history can't be read, the scan still completes (fail-open), but
    the verdict is raised wherever the missing flag could have changed it. An
    outage can then add extra "suspicious" results, never a new miss.
    """
    return verdict_for(min(MAX_SCORE, score + WEIGHTS["history.domain_flagged"]))


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

    history_status = "skipped"
    if parsed.input_type == "email" and parsed.from_domain:
        if history is None:
            notes.append(NO_HISTORY_NOTE)
        else:
            try:
                findings.extend(history_check.check(parsed.from_domain, parsed.sha256, history))
                history_status = "ok"
            except Exception:  # a failing store (e.g. database down) must not stop the scan
                history_status = "unavailable"
                notes.append(HISTORY_UNAVAILABLE_NOTE)

    indicators = to_indicators(findings)
    score = score_of(indicators)
    verdict = verdict_for(score)
    raised_from = raise_reason = None
    if history_status == "unavailable" and cautious_verdict(score) != verdict:
        raised_from, verdict, raise_reason = verdict, cautious_verdict(score), HISTORY_UNAVAILABLE_REASON

    return Result(
        input_type=parsed.input_type,
        verdict=verdict,
        score=score,
        indicators=indicators,
        notes=notes,
        sender_domain=parsed.from_domain or None,
        email_sha256=parsed.sha256,
        history_status=history_status,
        raised_from=raised_from,
        raise_reason=raise_reason,
    )

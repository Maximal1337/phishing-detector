"""Suspicious wording in the subject and the body, by category.

Each category counts once. Evidence is the matched phrase from the fixed
patterns below; where a pattern allows words in between ("verify ... account"),
only the two keywords are shown, so names or other text in the gap never end
up in a result.
"""

from __future__ import annotations

import re

from ..models import Finding, ParsedEmail

_GAP = r"[^.\n]{0,25}?"  # a few words, within one sentence

CATEGORIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "wording.urgency": (
        "Urgent or time-pressure wording",
        (
            r"\burgent(?:ly)?\b",
            r"\bimmediate(?:ly)?\b",
            r"\bact now\b",
            r"\bas soon as possible\b",
            r"\bwithin (?:24|48|72) hours\b",
            r"\bexpires? (?:today|soon|tomorrow)\b",
            r"\b(?:final|last) (?:notice|warning|reminder)\b",
            r"\baction required\b",
            r"\btime[- ]sensitive\b",
        ),
    ),
    "wording.threat": (
        "Threats of suspension, closure or other trouble",
        (
            rf"\b(account|access|card|service|mailbox)\b{_GAP}\b(suspended|locked|disabled|deactivated|terminated|closed|restricted|blocked)\b",
            r"\bwill be (?:suspended|closed|deleted|terminated|locked|disabled)\b",
            r"\bunauthori[sz]ed (?:access|activity|login|sign-?in|transaction)\b",
            r"\b(?:unusual|suspicious) (?:activity|login|sign-?in attempt|sign-?in)\b",
            r"\blegal action\b",
            r"\bpermanently (?:deleted|closed|suspended)\b",
        ),
    ),
    "wording.credentials": (
        "Asks to verify an account or to enter a password",
        (
            rf"\b(verify|confirm|validate|re-?activate)\b{_GAP}\b(account|identity|password|credentials|login details)\b",
            rf"\b(enter|provide|re-?enter|submit)\b{_GAP}\b(password|pin|credentials|security code|card number|cvv)\b",
            r"\b(?:log|sign) ?in (?:here|now|below|immediately)\b",
            r"\breset your password\b",
        ),
    ),
    "wording.payment": (
        "Payment, invoice or money-transfer pressure",
        (
            r"\bgift ?cards?\b",
            r"\bwire transfer\b",
            r"\b(?:bitcoin|btc|crypto(?:currency)?) (?:wallet|payment|address)\b",
            r"\bpayment (?:failed|declined|overdue|was unsuccessful|could not be processed)\b",
            r"\b(?:overdue|outstanding|unpaid) (?:invoice|balance|payment)\b",
            r"\bupdate (?:your )?(?:payment|billing) (?:method|details|information)\b",
            r"\bbank (?:account )?details\b",
        ),
    ),
    "wording.prize": (
        "Prize, lottery or reward bait",
        (
            r"\byou(?:'ve| have) (?:won|been selected)\b",
            r"\bwinner\b",
            r"\blottery\b",
            r"\bjackpot\b",
            r"\bclaim (?:your )?(?:prize|reward|gift|refund)\b",
            r"\bcongratulations\b",
            r"\bfree (?:gift|iphone|reward)\b",
        ),
    ),
    "wording.generic_greeting": (
        "Generic greeting instead of the recipient's name",
        (
            r"\bdear (?:customer|user|client|member|account ?holder|valued (?:customer|member|user)|sir(?: or |/)madam|beneficiary)\b",
            r"^\s*hello (?:user|customer)\b",
        ),
    ),
}
SIGNALS = tuple(CATEGORIES)

MAX_EVIDENCE = 3
_COMPILED = {
    signal: (reason, tuple(re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns))
    for signal, (reason, patterns) in CATEGORIES.items()
}


def _phrase(match: re.Match[str]) -> str:
    parts = [g for g in match.groups() if g] if match.re.groups else [match.group(0)]
    return " ... ".join(" ".join(part.lower().split()) for part in parts)[:40]


def check(parsed: ParsedEmail, notes: list[str]) -> list[Finding]:
    text = f"{parsed.subject}\n{parsed.text}"
    findings = []
    for signal, (reason, patterns) in _COMPILED.items():
        phrases: list[str] = []
        for pattern in patterns:
            for match in pattern.finditer(text):
                phrase = _phrase(match)
                if phrase not in phrases:
                    phrases.append(phrase)
            if len(phrases) >= MAX_EVIDENCE:
                break
        if phrases:
            findings.append(Finding(signal, reason, tuple(f'"{p}"' for p in phrases[:MAX_EVIDENCE])))
    return findings

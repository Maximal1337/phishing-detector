"""The synthetic samples in samples/: expected verdicts, signal coverage and what evidence may show."""

import email
from email import policy
from email.utils import getaddresses
from pathlib import Path

import pytest

from phishing_detector import analyze
from phishing_detector.checks.history import InMemoryHistory
from phishing_detector.scoring import BODY_ONLY_NOTE

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

EXPECTED = {
    "phishing_lookalike_sender.eml": "phishing",
    "phishing_spoofed_bank.eml": "phishing",
    "phishing_invoice_attachment.eml": "phishing",
    "phishing_html_form.eml": "phishing",
    "phishing_archive_password.eml": "phishing",
    "phishing_idn_link.eml": "phishing",
    "suspicious_prize.eml": "suspicious",
    "legit_newsletter.eml": "likely_legitimate",
    "legit_receipt.eml": "likely_legitimate",
    "legit_internal.eml": "likely_legitimate",
    "plain_phishing.txt": "phishing",
    "plain_legit.txt": "likely_legitimate",
}


def _scan(name, history=None):
    return analyze((SAMPLES / name).read_bytes(), history=history)


def test_every_sample_has_an_expected_verdict():
    assert set(EXPECTED) == {path.name for path in SAMPLES.iterdir()}


@pytest.mark.parametrize(("name", "verdict"), EXPECTED.items())
def test_sample_verdict(name, verdict):
    assert _scan(name).verdict == verdict


def test_samples_cover_every_signal_family():
    families = {i.category for name in EXPECTED for i in _scan(name).indicators}
    assert families >= {"auth", "sender", "links", "wording", "attach"}


def test_plain_text_samples_are_body_only():
    for name in ("plain_phishing.txt", "plain_legit.txt"):
        result = _scan(name)
        assert result.input_type == "body_only"
        assert BODY_ONLY_NOTE in result.notes


@pytest.mark.parametrize("name", [n for n in EXPECTED if n.endswith(".eml")])
def test_evidence_never_shows_an_address_or_the_subject(name):
    msg = email.message_from_bytes((SAMPLES / name).read_bytes(), policy=policy.default)
    headers = [str(v) for h in ("From", "To", "Reply-To", "Return-Path") for v in (msg.get_all(h) or [])]
    addresses = [address for _, address in getaddresses(headers) if address]
    evidence = " ".join(e for indicator in _scan(name).indicators for e in indicator.evidence)
    assert addresses
    for address in addresses:
        assert address.lower() not in evidence.lower()
    assert str(msg["Subject"]) not in evidence
    assert "@" not in evidence


def test_spoofed_sample_does_not_poison_the_real_bank():
    store = InMemoryHistory()
    spoofed = _scan("phishing_spoofed_bank.eml", history=store)
    store.record(spoofed)
    assert spoofed.sender_domain == "examplebank.test"

    receipt = _scan("legit_receipt.eml", history=store)
    assert receipt.sender_domain == "examplebank.test"
    assert receipt.verdict == "likely_legitimate"
    assert "history.domain_flagged" not in {i.id for i in receipt.indicators}

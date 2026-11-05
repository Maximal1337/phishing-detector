import pytest
from helpers import parsed_email

from phishing_detector.checks import wording
from phishing_detector.parser import parse


def _found(text, subject="Quarterly planning notes"):
    return {f.id: f for f in wording.check(parsed_email(text=text, subject=subject), [])}


@pytest.mark.parametrize(
    ("signal", "hit", "miss"),
    [
        ("wording.urgency", "Please respond within 24 hours.", "Please respond when you have time."),
        ("wording.threat", "Your account has been suspended.", "Your account settings were saved."),
        ("wording.credentials", "Verify your account to continue.", "Your account is all set."),
        ("wording.payment", "Buy two gift cards and send me the codes.", "The cafe sells gift wrapping."),
        ("wording.prize", "Congratulations, you have won a prize!", "The team won the match."),
        ("wording.generic_greeting", "Dear Customer,\nthanks.", "Dear Dana,\nthanks."),
    ],
)
def test_category_hit_and_miss(signal, hit, miss):
    assert signal in _found(hit)
    assert signal not in _found(miss)


def test_each_category_counts_once_with_up_to_three_phrases():
    found = _found("Urgent! Act now, immediately, as soon as possible, final notice.")
    assert list(found) == ["wording.urgency"]
    assert len(found["wording.urgency"].evidence) == 3


def test_subject_is_scanned_too():
    assert "wording.urgency" in _found("Hello.", subject="Urgent: about your mailbox quota")


def test_words_in_a_gap_are_not_shown():
    found = _found("Please verify Dana Levi's banking account today.")
    assert found["wording.credentials"].evidence == ('"verify ... account"',)


def test_body_only_text():
    parsed = parse(b"Dear customer, your mailbox will be closed. Reset your password here.\n")
    assert {f.id for f in wording.check(parsed, [])} == {"wording.generic_greeting", "wording.threat", "wording.credentials"}


def test_ordinary_business_mail_raises_nothing():
    text = "Hi team,\nthe invoice for October is attached and was paid on time.\nThanks, Dana\n"
    assert _found(text) == {}

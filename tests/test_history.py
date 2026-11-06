"""History of actions, including the poisoning rule (a spoofed flag must not stick to the real domain)."""

from helpers import make_email

from phishing_detector import analyze
from phishing_detector.checks.history import InMemoryHistory
from phishing_detector.scoring import HISTORY_UNAVAILABLE_NOTE, NO_HISTORY_NOTE, SUSPICIOUS_AT, WEIGHTS

PHISHING_TEXT = "Urgent: your account has been suspended. Verify your account at http://203.0.113.5/login now.\n"
NORMAL_TEXT = "Hello,\nyour monthly statement is ready in online banking.\n"


def _mail(from_domain, dmarc, text, subject="Monthly statement for November"):
    auth = [f"mx.example.org; spf={dmarc}; dmarc={dmarc} header.from={from_domain}"]
    return make_email(from_=f"Example Bank <alerts@{from_domain}>", auth=auth, text=text, subject=subject)


def _scan_and_record(store, raw):
    result = analyze(raw, history=store)
    store.record(result)
    return result


def _flagged(result):
    return "history.domain_flagged" in {i.id for i in result.indicators}


def test_spoofed_flag_does_not_poison_the_real_domain():
    store = InMemoryHistory()
    spoofed = _scan_and_record(store, _mail("examplebank.test", "fail", PHISHING_TEXT))
    assert spoofed.verdict == "phishing"
    assert "auth.dmarc_fail" in {i.id for i in spoofed.indicators}

    genuine = analyze(_mail("examplebank.test", "pass", NORMAL_TEXT), history=store)
    assert not _flagged(genuine)
    assert genuine.verdict == "likely_legitimate"


def test_flag_from_an_authenticated_sender_counts():
    store = InMemoryHistory()
    first = _scan_and_record(store, _mail("mailer.example.net", "pass", PHISHING_TEXT))
    assert first.verdict == "phishing"
    assert "auth.dmarc_pass" in {i.id for i in first.indicators}

    later = analyze(_mail("mailer.example.net", "pass", NORMAL_TEXT, subject="Another note"), history=store)
    assert _flagged(later)
    flag = next(i for i in later.indicators if i.id == "history.domain_flagged")
    assert flag.evidence == ("1 earlier phishing scan(s) from mailer[.]example[.]net",)


def test_flag_on_a_lookalike_domain_counts_even_without_dmarc():
    store = InMemoryHistory()
    first = _scan_and_record(store, _mail("examp1ebank.test", "none", PHISHING_TEXT))
    assert "sender.lookalike_domain" in {i.id for i in first.indicators}

    later = analyze(_mail("examp1ebank.test", "none", NORMAL_TEXT, subject="Another note"), history=store)
    assert _flagged(later)


def test_the_same_email_does_not_count_against_itself():
    store = InMemoryHistory()
    raw = _mail("mailer.example.net", "pass", PHISHING_TEXT)
    _scan_and_record(store, raw)
    assert not _flagged(analyze(raw, history=store))


def test_without_history_the_check_is_skipped_with_a_note():
    result = analyze(_mail("examplebank.test", "pass", NORMAL_TEXT))
    assert NO_HISTORY_NOTE in result.notes


def test_a_failing_store_does_not_stop_the_scan():
    class Broken:
        def count_trusted_flags(self, sender_domain, exclude_sha256):
            raise ConnectionError("database unavailable")

    result = analyze(_mail("examplebank.test", "fail", PHISHING_TEXT), history=Broken())
    assert result.verdict == "phishing"
    assert HISTORY_UNAVAILABLE_NOTE in result.notes


def test_body_only_input_skips_history():
    store = InMemoryHistory()
    result = analyze(PHISHING_TEXT.encode(), history=store)
    assert result.input_type == "body_only"
    assert not _flagged(result)
    assert NO_HISTORY_NOTE not in result.notes


class _Broken:
    def count_trusted_flags(self, sender_domain, exclude_sha256):
        raise ConnectionError("database unavailable")


def test_history_status():
    assert analyze(_mail("examplebank.test", "pass", NORMAL_TEXT), history=InMemoryHistory()).history_status == "ok"
    assert analyze(_mail("examplebank.test", "pass", NORMAL_TEXT), history=_Broken()).history_status == "unavailable"
    assert analyze(_mail("examplebank.test", "pass", NORMAL_TEXT)).history_status == "skipped"  # no store
    assert analyze(NORMAL_TEXT.encode(), history=_Broken()).history_status == "skipped"  # body only


def test_unavailable_history_raises_the_verdict_when_a_flag_could_have_changed_it():
    # Urgency only: below "suspicious" on its own, but a history flag would push it over.
    urgency, flag = WEIGHTS["wording.urgency"], WEIGHTS["history.domain_flagged"]
    assert urgency < SUSPICIOUS_AT <= urgency + flag
    raw = _mail("examplebank.test", "pass", "Hello,\nplease reply urgently about the meeting room.\n")
    assert analyze(raw, history=InMemoryHistory()).verdict == "likely_legitimate"
    result = analyze(raw, history=_Broken())
    assert (result.score, result.verdict) == (urgency, "suspicious")
    assert (result.raised_from, result.raise_reason) == ("likely_legitimate", "history unavailable")


def test_unavailable_history_keeps_the_verdict_when_a_flag_could_not_change_it():
    calm = analyze(_mail("examplebank.test", "pass", NORMAL_TEXT), history=_Broken())  # 0 + 20 < 25
    assert (calm.verdict, calm.raised_from) == ("likely_legitimate", None)
    already = analyze(_mail("examplebank.test", "fail", PHISHING_TEXT), history=_Broken())
    assert (already.verdict, already.raised_from) == ("phishing", None)

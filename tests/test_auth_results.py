from helpers import parsed_email

from phishing_detector.checks import auth
from phishing_detector.checks.auth import NO_HEADER_NOTE

FROM = "Example Bank <alerts@examplebank.test>"


def _ids(header_values, from_=FROM):
    notes = []
    findings = auth.check(parsed_email(from_=from_, auth=header_values), notes)
    return {f.id for f in findings}, notes


def test_spf_fail_and_softfail():
    assert _ids(["mx.example.net; spf=fail smtp.mailfrom=examplebank.test"])[0] == {"auth.spf_fail"}
    assert _ids(["mx.example.net; spf=softfail smtp.mailfrom=examplebank.test"])[0] == {"auth.spf_softfail"}
    assert _ids(["mx.example.net; spf=pass smtp.mailfrom=examplebank.test"])[0] == set()


def test_dkim_fail_only_without_a_passing_signature():
    assert _ids(["mx.example.net; dkim=fail header.d=examplebank.test"])[0] == {"auth.dkim_fail"}
    assert _ids(["mx.example.net; dkim=fail header.d=x.example; dkim=pass header.d=examplebank.test"])[0] == set()


def test_dmarc_fail():
    ids, _ = _ids(["mx.example.net; spf=fail; dkim=none; dmarc=fail header.from=examplebank.test"])
    assert ids == {"auth.spf_fail", "auth.dmarc_fail"}


def test_dmarc_pass_counts_only_for_the_from_domain():
    assert _ids(["mx.example.net; dmarc=pass header.from=examplebank.test"])[0] == {"auth.dmarc_pass"}
    assert _ids(["mx.example.net; dmarc=pass header.from=other.example"])[0] == set()


def test_only_the_topmost_header_is_trusted():
    forged_below = ["mx.example.net; dmarc=fail header.from=examplebank.test", "evil.example; dmarc=pass header.from=examplebank.test"]
    assert _ids(forged_below)[0] == {"auth.dmarc_fail"}
    forged_pass_below = ["mx.example.net; spf=none", "evil.example; dmarc=pass header.from=examplebank.test"]
    assert _ids(forged_pass_below)[0] == set()


def test_results_are_case_insensitive():
    assert _ids(["MX.example.net; SPF=Fail; DMARC=FAIL header.from=examplebank.test"])[0] == {"auth.spf_fail", "auth.dmarc_fail"}


def test_missing_header_is_neutral_with_a_note():
    ids, notes = _ids([])
    assert ids == set()
    assert notes == [NO_HEADER_NOTE]


def test_results_parser():
    found = auth.results("mx.example.net; spf=pass smtp.mailfrom=a.example; dmarc=pass (p=reject) header.from=A.example")
    assert found == {"spf": [("pass", None)], "dmarc": [("pass", "a.example")]}

import pytest
from helpers import parsed_email

from phishing_detector.checks import sender
from phishing_detector.checks.common import brands_named_in, imitated_brand_domain, skeleton

# "exаmplebank" with a Cyrillic "а" (U+0430), in its punycode form.
CYRILLIC_LOOKALIKE = "exаmplebank".encode("idna").decode("ascii") + ".test"


def _findings(**kwargs):
    notes = []
    return {f.id: f for f in sender.check(parsed_email(**kwargs), notes)}, notes


def test_display_name_with_another_domains_address():
    found, _ = _findings(from_='"support@examplebank.test" <x@mailer.example.net>')
    assert "sender.display_name_address" in found
    found, _ = _findings(from_='"alerts@examplebank.test" <alerts@examplebank.test>')
    assert "sender.display_name_address" not in found


def test_brand_named_in_display_name_but_sent_from_elsewhere():
    assert "sender.brand_mismatch" in _findings(from_="Example Bank Security <alerts@mailer.example.net>")[0]
    assert "sender.brand_mismatch" in _findings(from_="DHL Express <tracking@parcels.example.net>")[0]
    assert "sender.brand_mismatch" not in _findings(from_="ExampleBank <alerts@examplebank.test>")[0]
    assert "sender.brand_mismatch" not in _findings(from_="Purchase Order <po@example.com>")[0]


@pytest.mark.parametrize(
    "domain",
    ["examp1ebank.test", "exarnplebank.test", "examplebank-secure.test", "examplebank.example", "examplebnak.test", CYRILLIC_LOOKALIKE],
)
def test_lookalike_sender_domains(domain):
    found, _ = _findings(from_=f"Alerts <alerts@{domain}>")
    assert "sender.lookalike_domain" in found
    assert "examplebank[.]test" in found["sender.lookalike_domain"].evidence[0]


@pytest.mark.parametrize("domain", ["examplebank.test", "mail.examplebank.test", "example.org", "example.com"])
def test_not_lookalikes(domain):
    assert "sender.lookalike_domain" not in _findings(from_=f"Alerts <alerts@{domain}>")[0]


def test_short_and_contained_brand_rules():
    brand_map = {"apple": ("apple.com",), "chase": ("chase.com",), "paypal": ("paypal.com",)}
    assert imitated_brand_domain("maple.example", brand_map) is None  # 2 edits from a short brand
    assert imitated_brand_domain("purchase.example", brand_map) is None  # short brand inside a word
    assert imitated_brand_domain("chase-secure.example", brand_map) == "chase.com"  # whole hyphen part
    assert imitated_brand_domain("paypalsecure.example", brand_map) == "paypal.com"  # long enough to contain
    assert imitated_brand_domain("paypa1.example", brand_map) == "paypal.com"  # homoglyph
    assert imitated_brand_domain("203.0.113.5", brand_map) is None


def test_skeleton_folds_homoglyphs():
    assert skeleton("examp1e-bank") == "examplebank"
    assert skeleton("rnicros0ft") == "microsoft"
    assert skeleton(CYRILLIC_LOOKALIKE.split(".")[0]) == "examplebank"


def test_brands_named_in_display_names():
    brand_map = {"examplebank": ("examplebank.test",), "chase": ("chase.com",), "dhl": ("dhl.com",)}
    assert brands_named_in("Example Bank", brand_map) == ["examplebank"]
    assert brands_named_in("EXAMPLEBANK support", brand_map) == ["examplebank"]
    assert brands_named_in("Purchase Order", brand_map) == []
    assert brands_named_in("DHL", brand_map) == ["dhl"]


def test_punycode_sender_domain():
    assert "sender.punycode" in _findings(from_=f"Alerts <alerts@{CYRILLIC_LOOKALIKE}>")[0]
    assert "sender.punycode" not in _findings(from_="Alerts <alerts@examplebank.test>")[0]


def test_reply_to_another_domain():
    assert "sender.reply_to_mismatch" in _findings(reply_to="help@reply.example.net")[0]
    assert "sender.reply_to_mismatch" not in _findings(from_="A <a@examplebank.test>", reply_to="help@support.examplebank.test")[0]


def test_return_path_another_domain():
    assert "sender.return_path_mismatch" in _findings(return_path="<bounce@mailer.example.net>")[0]
    assert "sender.return_path_mismatch" not in _findings(return_path="<bounce@example.com>")[0]


def test_evidence_names_domains_never_addresses():
    found, _ = _findings(
        from_='"qz-support@examplebank.test" <qz-alerts@examp1ebank.test>',
        reply_to="qz-collector@reply.example.net",
        return_path="<qz-bounce@mailer.example.net>",
    )
    evidence = " ".join(e for f in found.values() for e in f.evidence)
    assert len(found) == 5
    assert "@" not in evidence
    assert "qz-" not in evidence  # no local part of any address


def test_no_from_address_is_noted():
    found, notes = _findings(from_="undisclosed-recipients:;")
    assert found == {}
    assert notes == [sender.NO_SENDER_NOTE]

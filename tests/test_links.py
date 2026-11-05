import pytest
from helpers import parsed_email

from phishing_detector.checks import links
from phishing_detector.parser import parse

# Test-only lists, so the tests use reserved names (RFC 2606) instead of real shorteners or TLDs.
TEST_LISTS = dict(shorteners=frozenset({"short.test"}), risky_tlds=frozenset({"invalid"}))


def _found(text=None, html=None):
    parsed = parsed_email(text=text, html=html)
    return {f.id: f for f in links.check(parsed, [], **TEST_LISTS)}


def _anchor(href, text="Open"):
    return f'<p><a href="{href}">{text}</a></p>'


@pytest.mark.parametrize(
    ("signal", "hit", "miss"),
    [
        ("links.ip_host", "http://203.0.113.5/login", "https://www.example.org/login"),
        ("links.lookalike_domain", "http://examp1ebank.test/login", "https://examplebank.test/login"),
        ("links.brand_in_subdomain", "http://examplebank.test.secure-login.example.net/", "https://login.examplebank.test/"),
        ("links.userinfo", "http://examplebank.test@198.51.100.9/verify", "https://examplebank.test/verify"),
        ("links.nonstandard_port", "http://login.example.net:8080/", "https://login.example.net:443/"),
        ("links.shortener", "https://short.test/a1b2", "https://example.org/a1b2"),
        ("links.risky_tld", "http://examplebank-login.invalid/", "http://examplebank-login.example/"),
        ("links.punycode", "http://xn--exmplebank-0qi.test/", "http://example.com/"),  # Cyrillic "а"
    ],
)
def test_url_signals_hit_and_miss(signal, hit, miss):
    assert signal in _found(text=f"Please visit {hit} today.")
    assert signal not in _found(text=f"Please visit {miss} today.")


def test_link_text_showing_another_domain():
    found = _found(html=_anchor("http://198.51.100.7/login", "https://examplebank.test/login"))
    assert found["links.text_href_mismatch"].evidence == ("text shows examplebank[.]test, link goes to 198[.]51[.]100[.]7",)
    assert "links.text_href_mismatch" not in _found(html=_anchor("https://examplebank.test/login", "www.examplebank.test"))
    assert "links.text_href_mismatch" not in _found(html=_anchor("http://198.51.100.7/login", "Click here"))


def test_script_and_data_urls():
    assert "links.script_scheme" in _found(html=_anchor("javascript:alert(1)"))
    assert "links.script_scheme" in _found(html=_anchor("data:text/html;base64,PGgxPmhpPC9oMT4="))
    assert "links.script_scheme" not in _found(html=_anchor("mailto:help@example.com"))


def test_password_field_in_html():
    form = '<form action="https://example.net/p"><input type="password" name="pw"></form>'
    assert "links.password_form" in _found(html=form)
    assert "links.password_form" not in _found(html='<form><input type="text" name="q"></form>')


def test_each_signal_counts_once_with_at_most_three_examples():
    text = " ".join(f"http://203.0.113.{n}/x" for n in range(1, 8))
    found = _found(text=text)
    assert list(found) == ["links.ip_host"]
    assert len(found["links.ip_host"].evidence) == 3


def test_evidence_is_defanged():
    found = _found(text="Go to http://examp1ebank.test/login?user=me now")
    evidence = found["links.lookalike_domain"].evidence[0]
    assert evidence == "examp1ebank[.]test looks like examplebank[.]test"
    ip = _found(text="http://203.0.113.5/a.php")["links.ip_host"].evidence[0]
    assert ip == "hxxp://203[.]0[.]113[.]5/a[.]php"


def test_links_in_body_only_text_are_checked_too():
    parsed = parse(b"Verify now: http://203.0.113.5/login\n")
    assert parsed.input_type == "body_only"
    assert [f.id for f in links.check(parsed, [], **TEST_LISTS)] == ["links.ip_host"]


def test_ordinary_links_raise_nothing():
    html = _anchor("https://www.example.org/news/1", "Read more") + _anchor("https://example.org/unsubscribe", "Unsubscribe")
    assert _found(html=html) == {}

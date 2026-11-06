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


# --- signals added for modern phishing (reserved names; test-only hosting list) ---

TEST_HOSTING = [("pages.test", ""), ("forms.example.com", "/forms")]


def _modern(text=None, html=None, from_="Alice <alice@example.com>", subject="Quarterly planning notes", to="bob@example.org"):
    parsed = parsed_email(text=text, html=html, from_=from_, subject=subject, to=to)
    return {f.id: f for f in links.check(parsed, [], hosting=TEST_HOSTING, **TEST_LISTS)}


def test_brand_in_the_path_of_another_domain():
    assert "links.brand_in_path" in _modern(text="See http://files.example.net/examplebank/login now")
    assert "links.brand_in_path" not in _modern(text="See https://examplebank.test/examplebank/login now")
    assert "links.brand_in_path" not in _modern(text="See http://files.example.net/reports/2026 now")


def test_brand_named_but_no_link_to_it():
    found = _modern(text="Your ExampleBank account needs attention: http://portal.example.net/start")
    assert found["links.brand_link_mismatch"].evidence == ("names examplebank, links go elsewhere",)
    assert "links.brand_link_mismatch" not in _modern(text="Your ExampleBank account: https://examplebank.test/start")
    assert "links.brand_link_mismatch" not in _modern(text="Your ExampleBank statement is ready.")  # no links at all
    assert "links.brand_link_mismatch" not in _modern(text="News: http://portal.example.net/", from_="E <a@examplebank.test>")


def test_recipient_address_in_a_link():
    plain = _modern(text="Log in: http://portal.example.net/login?user=bob@example.org")
    assert plain["links.recipient_in_url"].evidence == ("link to portal[.]example[.]net",)  # host only, never the address
    encoded = "Ym9iQGV4YW1wbGUub3Jn"  # base64 of the recipient's address
    assert "links.recipient_in_url" in _modern(text=f"Log in: http://portal.example.net/start#{encoded}")
    assert "links.recipient_in_url" in _modern(text="Log in: http://portal.example.net/p?e=bob%40example.org")
    assert "links.recipient_in_url" not in _modern(text="Unsubscribe: https://news.example.org/unsubscribe?email=bob@example.org")
    assert "links.recipient_in_url" not in _modern(text="Log in: http://portal.example.net/login?lang=en")


def test_redirect_parameters_and_amp():
    found = _modern(text="Open http://www.example.com/url?q=http://evil.example.net/login&sa=D")
    assert found["links.redirect_param"].evidence == ("www[.]example[.]com forwards to evil[.]example[.]net",)
    assert "links.redirect_param" in _modern(text="Open https://track.example.org/c?redirect=https%3A%2F%2Fevil.example.net%2F")
    assert "links.redirect_param" in _modern(text="Open https://example-com.cdn.ampproject.org/c/s/evil.example.net/")
    # A tracker that forwards to its own site, and a search link, are not redirects to elsewhere.
    assert "links.redirect_param" not in _modern(text="Open https://click.example.org/t?url=https://www.example.org/article")
    assert "links.redirect_param" not in _modern(text="Open https://search.example.com/find?q=http://example.net/")


def test_abused_hosting_and_form_services():
    assert _modern(text="Open https://secure-login.pages.test/")["links.abused_hosting"].evidence == ("secure-login[.]pages[.]test",)
    assert "links.abused_hosting" in _modern(text="Open https://forms.example.com/forms/d/e/abc/viewform")
    assert "links.abused_hosting" in _modern(text="Open https://gateway.example.net/ipfs/bafybeigdyrzt5")
    assert "links.abused_hosting" not in _modern(text="Open https://forms.example.com/calendar")
    assert "links.abused_hosting" not in _modern(text="Open https://www.example.org/")


def test_call_to_action_link_text():
    assert _modern(html=_anchor("https://portal.example.net/", "Sign in now"))["links.cta_text"].evidence == ('"sign in"',)
    assert "links.cta_text" in _modern(html=_anchor("https://portal.example.net/", "View shared document"))
    assert "links.cta_text" in _modern(html=_anchor("https://portal.example.net/", "Verify your account"))
    assert "links.cta_text" not in _modern(html=_anchor("https://portal.example.net/", "Read the full article"))
    long_text = "Sign in to the conference wiki to find the slides from every talk of the day"
    assert "links.cta_text" not in _modern(html=_anchor("https://portal.example.net/", long_text))

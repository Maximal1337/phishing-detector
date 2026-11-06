"""Links in the email, judged from the URL text alone: nothing is fetched or resolved.

Each signal counts once per email; its evidence lists up to three defanged
examples (hxxp://evil[.]example/...), so nothing in a result is clickable.
Evidence for a link that carries the recipient's address shows only its host.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from ..models import Finding, ParsedEmail
from .common import (
    brands,
    brands_named_in,
    data_lines,
    data_set,
    defang,
    defang_domain,
    imitated_brand_domain,
    is_ip,
    registrable_domain,
    url_host,
)

REASONS = {
    "links.ip_host": "A link points to a bare IP address instead of a domain name",
    "links.text_href_mismatch": "A link's text shows one domain but the link goes to another",
    "links.lookalike_domain": "A link goes to a domain that imitates a known brand",
    "links.brand_in_subdomain": "A link puts a brand name in front of an unrelated domain",
    "links.brand_in_path": "A link puts a brand name in the path of an unrelated domain",
    "links.brand_link_mismatch": "The email names a brand, but none of its links goes to that brand",
    "links.recipient_in_url": "A link carries the recipient's email address, as phishing kits do to pre-fill a fake login",
    "links.redirect_param": "A link passes through a redirect to another site",
    "links.abused_hosting": "A link goes to a free hosting, storage or form service often used for phishing pages",
    "links.cta_text": "A link's text asks to sign in, verify or open a document",
    "links.punycode": "A link uses an international (punycode) domain, a common disguise",
    "links.userinfo": "A link hides its real destination behind an '@'",
    "links.script_scheme": "A link runs script or carries embedded content (javascript: or data:)",
    "links.password_form": "The email itself contains a password field",
    "links.risky_tld": "A link uses a top-level domain that is often abused",
    "links.shortener": "A link uses a URL shortener that hides the destination",
    "links.nonstandard_port": "A link uses an unusual port number",
}
SIGNALS = tuple(REASONS)

MAX_EVIDENCE = 3
_SCRIPT_SCHEMES = ("javascript", "data", "vbscript")
# Anchor text that itself reads like an address, e.g. "examplebank.test/login".
_LOOKS_LIKE_URL = re.compile(r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#]\S*)?$", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
# Links people are meant to follow with their address in them: unsubscribe and preference pages.
# Recognised only by what the reader sees (the link text) or by the List-Unsubscribe header;
# the URL itself, path included, is chosen by the sender and proves nothing.
_SUBSCRIPTION_TEXT = re.compile(r"unsubscribe|opt[- _]?out|preferences|manage.{0,20}subscription", re.IGNORECASE)
# Query keys that commonly carry a redirect target.
_REDIRECT_KEYS = frozenset(
    "url u redirect redirect_uri redirect_url redir next target dest destination return returnurl return_url continue goto link".split()
)
# Short button texts: "Sign in", "Verify now", "View document", ...
_CTA = re.compile(
    r"^\W*(?:click here to )?(?:sign ?in|log ?in|verify|validate|confirm|unlock|restore|re-?activate|"
    r"update (?:your )?(?:account|details|information|payment)|"
    r"(?:view|open|review|access|download) (?:the |your )?(?:shared )?(?:document|file|invoice|message|pdf|statement|attachment|account))\b",
    re.IGNORECASE,
)
_MAX_CTA_LENGTH = 40


def _hosting_rules() -> list[tuple[str, str]]:
    rules = []
    for line in data_lines("hosting.txt"):
        host, _, path = line.lower().partition("/")
        rules.append((host, "/" + path if path else ""))
    return rules


def _on_hosting(host: str, path: str, rules: list[tuple[str, str]]) -> bool:
    if ".ipfs." in host or path.startswith("/ipfs/"):
        return True
    for rule_host, rule_path in rules:
        if rule_path:
            if host == rule_host and path.lower().startswith(rule_path):
                return True
        elif host == rule_host or host.endswith("." + rule_host):
            return True
    return False


def _carries_address(href: str, recipients: list[str]) -> bool:
    parts = urlsplit(href)
    tail = unquote(unquote(f"{parts.path}?{parts.query}#{parts.fragment}")).lower()
    if any(r in tail for r in recipients) or _EMAIL.search(unquote(f"{parts.query}#{parts.fragment}")):
        return True
    for token in _BASE64_TOKEN.findall(f"{parts.path}?{parts.query}#{parts.fragment}"):
        token = token.replace("-", "+").replace("_", "/")
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _EMAIL.search(decoded) or any(r in decoded.lower() for r in recipients):
            return True
    return False


# Link-protection services of the recipient's own mail gateway wrap every link in a redirect.
# The real target is inside the wrapper, so it is unwrapped statically (nothing is fetched)
# and every link check runs on the inner URL. Mimecast uses an opaque token: not unwrappable.
_SAFELINKS = "safelinks.protection.outlook.com"
_PROOFPOINT_V3 = re.compile(r"/v3/__(?P<url>.+?)__;(?P<bytes>[^!]*)!")
# Proofpoint v3 replaces characters in the URL with "*" (one) or "**" plus a length code (a run).
_PROOFPOINT_RUNS = {c: n for n, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", start=2)}


def _proofpoint_v3(href: str) -> str:
    match = _PROOFPOINT_V3.search(href)
    if not match:
        return ""
    try:
        replaced = base64.urlsafe_b64decode(match["bytes"] + "=" * (-len(match["bytes"]) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""
    position = 0

    def fill(token: re.Match) -> str:
        nonlocal position
        length = _PROOFPOINT_RUNS.get(token.group(0)[-1], 1) if token.group(0).startswith("**") else 1
        chunk = replaced[position : position + length]
        position += length
        return chunk

    return re.sub(r"\*\*.|\*", fill, match["url"])


def _unwrap_once(href: str) -> str:
    """The URL inside a Safe Links or Proofpoint wrapper, or "" if href isn't one."""
    parts = urlsplit(href)
    host = (parts.hostname or "").lower()
    if host == _SAFELINKS or host.endswith("." + _SAFELINKS):
        return next((v for k, v in parse_qsl(parts.query) if k.lower() == "url"), "")
    if host in ("urldefense.proofpoint.com", "urldefense.com"):
        if parts.path.startswith("/v2/url") and (u := re.search(r"(?:^|&)u=([^&]+)", parts.query)):
            return unquote(u.group(1).replace("-", "%").replace("_", "/"))
        if parts.path.startswith("/v3/"):
            return _proofpoint_v3(href)
    return ""


def unwrap(href: str) -> str:
    """Peel link-protection wrappers (also nested ones); return href unchanged if there is none."""
    for _ in range(3):
        inner = _unwrap_once(href).strip()
        if not inner.lower().startswith(("http://", "https://")):
            break
        href = inner
    return href


def _redirect_target(href: str, host: str) -> str:
    """The host a link forwards to through a redirect parameter or an AMP cache, or ""."""
    parts = urlsplit(href)
    if host.endswith(".cdn.ampproject.org") or (registrable_domain(host).startswith("google.") and parts.path.startswith("/amp/")):
        return "an AMP page"
    for key, value in parse_qsl(parts.query, keep_blank_values=False):
        key = key.lower()
        if key in _REDIRECT_KEYS or (key == "q" and parts.path.endswith("/url")):
            value = value.strip()
            if value.startswith("//"):
                value = "http:" + value
            if value.lower().startswith(("http://", "https://")):
                target = url_host(value)
                if target and registrable_domain(target) != registrable_domain(host):
                    return target
    return ""


def check(
    parsed: ParsedEmail,
    notes: list[str],
    *,
    shorteners: frozenset[str] | None = None,
    risky_tlds: frozenset[str] | None = None,
    brand_map: dict[str, tuple[str, ...]] | None = None,
    hosting: list[tuple[str, str]] | None = None,
) -> list[Finding]:
    shorteners = data_set("shorteners.txt") if shorteners is None else shorteners
    risky_tlds = data_set("risky_tlds.txt") if risky_tlds is None else risky_tlds
    brand_map = brands() if brand_map is None else brand_map
    hosting = _hosting_rules() if hosting is None else hosting
    brand_domains = {d for domains in brand_map.values() for d in domains}

    hits: dict[str, list[str]] = {}
    linked: set[str] = set()  # registrable domains the links go to

    def add(signal: str, evidence: str) -> None:
        items = hits.setdefault(signal, [])
        if evidence not in items and len(items) < MAX_EVIDENCE:
            items.append(evidence)

    for link in parsed.links:
        href = unwrap(link.href.strip())
        scheme = href.split(":", 1)[0].strip().lower() if ":" in href else ""
        if scheme in _SCRIPT_SCHEMES:
            add("links.script_scheme", defang(href, limit=60))
            continue
        if scheme not in ("http", "https"):
            continue  # mailto:, tel:, relative links
        try:
            parts = urlsplit(href)
            port = parts.port
        except ValueError:
            continue
        host = url_host(href)
        if not host:
            continue
        shown = defang(href)
        registrable = registrable_domain(host)
        linked.add(registrable)

        if link.text and _LOOKS_LIKE_URL.match(link.text.strip()):
            text = link.text.strip()
            shown_host = url_host(text if "://" in text else "http://" + text)
            if shown_host and registrable_domain(shown_host) != registrable:
                add("links.text_href_mismatch", f"text shows {defang_domain(shown_host)}, link goes to {defang_domain(host)}")
        if link.text and len(link.text) <= _MAX_CTA_LENGTH and (cta := _CTA.match(link.text)):
            add("links.cta_text", '"' + " ".join(cta.group(0).lower().split()).strip(' "') + '"')
        subscription = bool(link.text and _SUBSCRIPTION_TEXT.search(link.text)) or link.href.strip() in parsed.list_unsubscribe
        if not subscription and _carries_address(href, parsed.to_addresses):
            add("links.recipient_in_url", f"link to {defang_domain(host)}")
        if target := _redirect_target(href, host):
            add("links.redirect_param", f"{defang_domain(host)} forwards to {defang_domain(target)}")
        if "@" in parts.netloc:
            add("links.userinfo", shown)
        if port is not None and port not in (80, 443):
            add("links.nonstandard_port", shown)
        if is_ip(host):
            add("links.ip_host", shown)
            continue  # the domain checks below don't apply to an address

        if any(label.startswith("xn--") for label in host.split(".")):
            add("links.punycode", shown)
        if registrable in shorteners or host in shorteners:
            add("links.shortener", shown)
        if host.rsplit(".", 1)[-1] in risky_tlds:
            add("links.risky_tld", shown)
        if _on_hosting(host, parts.path, hosting):
            add("links.abused_hosting", defang_domain(host))
        imitated = imitated_brand_domain(host, brand_map)
        if imitated:
            add("links.lookalike_domain", f"{defang_domain(registrable)} looks like {defang_domain(imitated)}")
        if registrable not in brand_domains:
            subdomain = host[: -len(registrable)].rstrip(".")
            if subdomain and brands_named_in(subdomain.replace(".", " "), brand_map):
                add("links.brand_in_subdomain", defang_domain(host))
            if named := brands_named_in(unquote(parts.path).replace("/", " "), brand_map):
                add("links.brand_in_path", f"{', '.join(named)} on {defang_domain(host)}")

    if parsed.password_inputs:
        add("links.password_form", f"{parsed.password_inputs} password field(s) in the HTML")

    if linked:
        sender = registrable_domain(parsed.from_domain) if parsed.from_domain else ""
        named = brands_named_in(f"{parsed.from_display}\n{parsed.subject}\n{parsed.text}", brand_map)
        for keyword in named:
            own = set(brand_map[keyword])
            if not (own & linked) and sender not in own:
                add("links.brand_link_mismatch", f"names {keyword}, links go elsewhere")

    return [Finding(signal, REASONS[signal], tuple(hits[signal])) for signal in SIGNALS if signal in hits]

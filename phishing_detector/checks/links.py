"""Links in the email, judged from the URL text alone: nothing is fetched or resolved.

Each signal counts once per email; its evidence lists up to three defanged
examples (hxxp://evil[.]example/...), so nothing in a result is clickable.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Finding, ParsedEmail
from .common import (
    brands,
    brands_named_in,
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


def check(
    parsed: ParsedEmail,
    notes: list[str],
    *,
    shorteners: frozenset[str] | None = None,
    risky_tlds: frozenset[str] | None = None,
    brand_map: dict[str, tuple[str, ...]] | None = None,
) -> list[Finding]:
    shorteners = data_set("shorteners.txt") if shorteners is None else shorteners
    risky_tlds = data_set("risky_tlds.txt") if risky_tlds is None else risky_tlds
    brand_map = brands() if brand_map is None else brand_map
    brand_domains = {d for domains in brand_map.values() for d in domains}

    hits: dict[str, list[str]] = {}

    def add(signal: str, evidence: str) -> None:
        items = hits.setdefault(signal, [])
        if evidence not in items and len(items) < MAX_EVIDENCE:
            items.append(evidence)

    for link in parsed.links:
        href = link.href.strip()
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

        if link.text and _LOOKS_LIKE_URL.match(link.text.strip()):
            text = link.text.strip()
            shown_host = url_host(text if "://" in text else "http://" + text)
            if shown_host and registrable_domain(shown_host) != registrable:
                add("links.text_href_mismatch", f"text shows {defang_domain(shown_host)}, link goes to {defang_domain(host)}")
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
        imitated = imitated_brand_domain(host, brand_map)
        if imitated:
            add("links.lookalike_domain", f"{defang_domain(registrable)} looks like {defang_domain(imitated)}")
        subdomain = host[: -len(registrable)].rstrip(".")
        if subdomain and registrable not in brand_domains and brands_named_in(subdomain.replace(".", " "), brand_map):
            add("links.brand_in_subdomain", defang_domain(host))

    if parsed.password_inputs:
        add("links.password_form", f"{parsed.password_inputs} password field(s) in the HTML")

    return [Finding(signal, REASONS[signal], tuple(hits[signal])) for signal in SIGNALS if signal in hits]

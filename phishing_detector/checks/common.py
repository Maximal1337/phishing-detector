"""Helpers shared by the checks: hosts and domains, defanging, data lists, lookalikes."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from functools import lru_cache
from importlib import resources
from urllib.parse import urlsplit

# Two-label public suffixes common enough to matter. Without the full Public
# Suffix List, "shop.example.co.uk" would otherwise reduce to "co.uk".
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
        "co.jp", "ne.jp", "or.jp", "ac.jp",
        "co.nz", "org.nz", "co.za", "co.in", "co.kr",
        "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "com.hk", "com.sg", "com.tw", "com.ua", "com.pl",
    }
)  # fmt: skip

# Brand names shorter than this are not fuzzy-matched ("ups" would match far too much).
MIN_BRAND_LENGTH = 5
# A brand inside a longer domain label counts only from this length on, unless it is a
# whole hyphen-separated part ("purchase" must not match "chase", "chase-secure" must).
MIN_CONTAINED_LENGTH = 6
# Edit distance allowed between a domain label and a brand label: 1 for short brands
# ("maple" must not match "apple"), 2 from this brand length on.
LONG_BRAND_LENGTH = 8

# Characters that look alike, mapped to the letter they imitate (digits, Cyrillic, Greek).
_HOMOGLYPHS = str.maketrans(
    {
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "|": "l",
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
        "х": "x", "і": "i", "ј": "j", "ԁ": "d", "ѕ": "s", "һ": "h",
        "ӏ": "l", "ɡ": "g",
        "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t",
    }
)  # fmt: skip
_LETTER_PAIRS = (("rn", "m"), ("vv", "w"))


# --- hosts and domains ---------------------------------------------------


def normalize_host(host: str) -> str:
    """Lower-case, no trailing dot, internationalised names in their xn-- (punycode) form."""
    host = host.strip().strip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    """The part of a host name someone registers, e.g. mail.shop.example.co.uk -> example.co.uk."""
    host = normalize_host(host)
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def url_host(url: str) -> str:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return ""
    return normalize_host(host) if host else ""


# --- evidence ------------------------------------------------------------

_SCHEME = re.compile(r"^(?i:http)")


def defang(url: str, limit: int = 100) -> str:
    """hxxp://evil[.]example/login - readable, but not clickable or auto-linked."""
    text = "".join(ch for ch in url if ch.isprintable() and not ch.isspace())
    text = _SCHEME.sub("hxxp", text).replace(".", "[.]").replace("@", "[@]")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


# --- data lists (phishing_detector/data/*.txt) ---------------------------


@lru_cache
def data_lines(name: str) -> tuple[str, ...]:
    text = resources.files("phishing_detector").joinpath("data", name).read_text(encoding="utf-8")
    lines = (line.split("#", 1)[0].strip() for line in text.splitlines())
    return tuple(line for line in lines if line)


def data_set(name: str) -> frozenset[str]:
    return frozenset(line.lower() for line in data_lines(name))


@lru_cache
def brands() -> dict[str, tuple[str, ...]]:
    """brands.txt: "keyword domain [domain ...]" per line."""
    result = {}
    for line in data_lines("brands.txt"):
        keyword, *domains = line.lower().split()
        result[keyword] = tuple(domains)
    return result


# --- lookalikes ----------------------------------------------------------


def skeleton(label: str) -> str:
    """What a domain label looks like to a reader: homoglyphs folded, hyphens dropped."""
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    label = unicodedata.normalize("NFKC", label).lower().translate(_HOMOGLYPHS)
    for pair, letter in _LETTER_PAIRS:
        label = label.replace(pair, letter)
    return label.replace("-", "")


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (insertions, deletions, substitutions)."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def imitated_brand_domain(host: str, brand_map: dict[str, tuple[str, ...]] | None = None) -> str | None:
    """The protected brand domain that `host` imitates, or None.

    A host imitates a brand domain when its registrable label, after folding
    homoglyphs and dropping hyphens, equals the brand's label (examp1ebank,
    exarnplebank, examplebank on another TLD), is one or two edits away from it
    (see LONG_BRAND_LENGTH), or contains it (examplebank-secure, see
    MIN_CONTAINED_LENGTH). The brand's own domains never match.
    """
    brand_map = brands() if brand_map is None else brand_map
    registrable = registrable_domain(host)
    if not registrable or is_ip(registrable):
        return None
    if registrable in {d for domains in brand_map.values() for d in domains}:
        return None
    label = registrable.split(".")[0]
    candidate = skeleton(label)
    parts = {skeleton(part) for part in label.split("-")}
    for domains in brand_map.values():
        for domain in domains:
            brand = skeleton(domain.split(".")[0])
            if len(brand) < MIN_BRAND_LENGTH:
                continue
            max_distance = 2 if len(brand) >= LONG_BRAND_LENGTH else 1
            contained = brand in parts or (len(brand) >= MIN_CONTAINED_LENGTH and brand in candidate)
            if candidate == brand or contained or edit_distance(candidate, brand) <= max_distance:
                return domain
    return None


def brands_named_in(text: str, brand_map: dict[str, tuple[str, ...]] | None = None) -> list[str]:
    """Brand keywords named in free text such as a display name.

    A keyword matches a whole word, or up to four adjacent words written
    together ("Example Bank" and "ExampleBank" both name "examplebank"),
    so "Purchase Order" doesn't name "chase".
    """
    brand_map = brands() if brand_map is None else brand_map
    words = re.findall(r"[a-z0-9]+", text.lower())
    joined = {"".join(words[i:j]) for i in range(len(words)) for j in range(i + 1, min(i + 4, len(words)) + 1)}
    return [keyword for keyword in brand_map if keyword in joined]

"""Turn raw email bytes into a ParsedEmail.

Everything here is static: links are collected as text and never fetched,
HTML is scanned with html.parser and never rendered, and attachments are
described from their MIME headers only. Their payload is never decoded.
"""

from __future__ import annotations

import email
import hashlib
import re
from email import policy
from email.message import Message
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

from .models import Attachment, Link, ParsedEmail

# Any of these headers means the input is a full message, not just a body.
_MESSAGE_HEADERS = ("From", "Received", "Subject", "Date", "Message-ID", "Return-Path", "Authentication-Results")

_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
_URL_TRAILING = ".,;:!?)]}'\""
_RECIPIENT_HEADERS = ("To", "Cc", "Delivered-To", "X-Original-To")
# Invisible characters wedged between letters, used to break up words that filters look for.
_ZERO_WIDTH_IN_WORD = re.compile("[^\\W\\d_][​‌‍⁠﻿­]+[^\\W\\d_]")
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|(?:font-size|opacity)\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|!|$)",
    re.IGNORECASE,
)
_VOID_TAGS = frozenset("area base br col embed hr img input link meta param source track wbr".split())

MAX_LINKS = 200


def parse(raw: bytes) -> ParsedEmail:
    sha256 = hashlib.sha256(raw).hexdigest()
    msg = email.message_from_bytes(raw, policy=policy.default)

    if not any(name in msg for name in _MESSAGE_HEADERS):
        text = raw.decode("utf-8", errors="replace")
        return ParsedEmail(input_type="body_only", sha256=sha256, text=text, links=_links_in_text(text))

    display, address = _first_address(msg, "From")
    parsed = ParsedEmail(
        input_type="email",
        sha256=sha256,
        from_display=display,
        from_address=address,
        from_domain=_domain_of(address),
        reply_to_domains=[d for d in (_domain_of(a) for _, a in _addresses(msg, "Reply-To")) if d],
        return_path_domain=_domain_of(parseaddr(_header(msg, "Return-Path"))[1]),
        auth_results=_topmost(msg, "Authentication-Results"),
        subject=_header(msg, "Subject"),
        to_addresses=sorted({a.lower() for name in _RECIPIENT_HEADERS for _, a in _addresses(msg, name)}),
    )

    texts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = _safe_filename(part)
        if filename is not None or part.get_content_disposition() == "attachment":
            parsed.attachments.append(_attachment(part, filename))
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            body = _text_of(part)
            texts.append(body)
            parsed.links.extend(_links_in_text(body))
            parsed.plain_text_chars += len("".join(body.split()))
        elif content_type == "text/html":
            scan = _HtmlScan()
            try:
                scan.feed(_text_of(part))
                scan.close()
            except Exception:  # malformed HTML must not stop the scan
                pass
            visible = " ".join(scan.text)
            texts.append(visible)
            parsed.links.extend(scan.links)
            parsed.links.extend(_links_in_text(visible))
            parsed.password_inputs += scan.password_inputs
            parsed.has_html = True
            parsed.image_count += scan.images
            parsed.hidden_text_chars += scan.hidden_chars
            parsed.visible_html_chars += scan.visible_chars

    parsed.text = "\n".join(texts)
    parsed.links = _dedupe(parsed.links)[:MAX_LINKS]
    parsed.zero_width_in_words = len(_ZERO_WIDTH_IN_WORD.findall(f"{parsed.subject}\n{parsed.text}"))
    return parsed


# --- headers -------------------------------------------------------------


def _header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
        return str(value).strip() if value is not None else ""
    except Exception:  # a broken header is treated as missing
        return ""


def _topmost(msg: Message, name: str) -> str | None:
    """First (topmost) instance of a header: the one added last, closest to the reader."""
    try:
        values = msg.get_all(name) or []
        return str(values[0]) if values else None
    except Exception:
        return None


def _addresses(msg: Message, name: str) -> list[tuple[str, str]]:
    try:
        values = [str(v) for v in (msg.get_all(name) or [])]
        return [(d, a) for d, a in getaddresses(values) if a]
    except Exception:
        return []


def _first_address(msg: Message, name: str) -> tuple[str, str]:
    found = _addresses(msg, name)
    if found:
        return found[0][0].strip(), found[0][1].strip()
    # Fall back to the raw header text when strict parsing rejects it.
    display, address = parseaddr(_header(msg, name))
    return display.strip(), address.strip()


def _domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rpartition("@")[2].strip().strip("<>.").lower()


# --- parts ---------------------------------------------------------------


def _safe_filename(part: Message) -> str | None:
    try:
        name = part.get_filename()
    except Exception:
        return "(unreadable name)"
    return name.strip() if name else None


def _attachment(part: Message, filename: str | None) -> Attachment:
    # decode=False returns the payload exactly as transmitted (e.g. base64 text):
    # we only measure it.
    payload = part.get_payload(decode=False)
    size = len(payload.encode("utf-8", errors="replace")) if isinstance(payload, str) else 0
    return Attachment(filename=filename or "(no name)", content_type=part.get_content_type(), encoded_size=size)


def _text_of(part: Message) -> str:
    """Decoded text of a text/* body part (never called for attachments)."""
    try:
        return part.get_content()
    except Exception:  # unknown charset or broken encoding
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


# --- links ---------------------------------------------------------------


def _links_in_text(text: str) -> list[Link]:
    links = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(_URL_TRAILING)
        if url.lower().startswith("www."):
            url = "http://" + url
        links.append(Link(href=url, source="text"))
    return links


def _dedupe(links: list[Link]) -> list[Link]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for link in links:
        key = (link.href, link.text)
        if key not in seen:
            seen.add(key)
            unique.append(link)
    return unique


class _HtmlScan(HTMLParser):
    """Collects anchors, password inputs, images and text (visible and CSS-hidden). Nothing is rendered or loaded."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text: list[str] = []
        self.password_inputs = 0
        self.images = 0
        self.hidden_chars = 0
        self.visible_chars = 0
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []
        self._skip = 0  # inside <script> or <style>
        self._open: list[tuple[str, bool]] = []  # open elements and whether each one hides its content

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a" and attributes.get("href"):
            self._anchor_href = attributes["href"].strip()
            self._anchor_text = []
        elif tag == "input" and attributes.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag == "img":
            self.images += 1
        if tag not in _VOID_TAGS:
            hides = "hidden" in attributes or bool(_HIDDEN_STYLE.search(attributes.get("style", "")))
            self._open.append((tag, hides))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._anchor_href is not None:
            text = " ".join("".join(self._anchor_text).split())
            self.links.append(Link(href=self._anchor_href, text=text, source="html"))
            self._anchor_href = None
        for i in range(len(self._open) - 1, -1, -1):  # close up to the matching open element, if any
            if self._open[i][0] == tag:
                del self._open[i:]
                break

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.text.append(data)
        if self._anchor_href is not None:
            self._anchor_text.append(data)
        chars = len("".join(data.split()))
        if any(hides for _, hides in self._open):
            self.hidden_chars += chars
        else:
            self.visible_chars += chars

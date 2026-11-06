"""Tricks in the HTML body that hide text from the reader or from filters.

Short hidden "preheader" text (the preview line newsletters hide) and invisible
padding between spaces are normal; what counts here is a lot of hidden text,
invisible characters inside words, and an email that is just an image with a link.
"""

from __future__ import annotations

from ..models import Finding, ParsedEmail

REASONS = {
    "content.hidden_text": "The HTML hides a lot of text from the reader (display:none, font-size:0, ...)",
    "content.zero_width": "Invisible characters are wedged inside words, a trick to slip past keyword filters",
    "content.image_only": "The email is just an image with a link and almost no text",
}
SIGNALS = tuple(REASONS)

HIDDEN_TEXT_MIN = 200  # characters; preview-line preheaders are usually under 150
IMAGE_ONLY_MAX_TEXT = 40  # characters of visible text


def check(parsed: ParsedEmail, notes: list[str]) -> list[Finding]:
    findings = []
    if parsed.hidden_text_chars >= HIDDEN_TEXT_MIN:
        findings.append(Finding("content.hidden_text", REASONS["content.hidden_text"], (f"{parsed.hidden_text_chars} hidden characters",)))
    if parsed.zero_width_in_words:
        findings.append(Finding("content.zero_width", REASONS["content.zero_width"], (f"{parsed.zero_width_in_words} place(s) in the text",)))
    has_web_link = any(link.href.lower().startswith(("http://", "https://")) for link in parsed.links)
    if (
        parsed.has_html
        and parsed.image_count
        and has_web_link
        and parsed.visible_html_chars < IMAGE_ONLY_MAX_TEXT
        and parsed.plain_text_chars < IMAGE_ONLY_MAX_TEXT
    ):
        findings.append(Finding("content.image_only", REASONS["content.image_only"], (f"{parsed.image_count} image(s), {parsed.visible_html_chars} characters of text",)))
    return findings

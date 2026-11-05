"""Attachments, judged from MIME metadata only: file name, declared type and size.

The payload is never decoded, unpacked or opened.
"""

from __future__ import annotations

import re

from ..models import Attachment, Finding, ParsedEmail

EXECUTABLE = frozenset(
    "exe scr com pif bat cmd js jse vbs vbe wsf wsh ps1 psm1 msi msp jar hta lnk cpl reg dll application gadget".split()
)
MACRO_OFFICE = frozenset("docm dotm xlsm xltm xlam xlsb pptm potm ppsm ppam sldm".split())
HTML = frozenset("html htm shtml xhtml svg mht mhtml".split())
ARCHIVE = frozenset("zip rar 7z gz tgz tar bz2 xz cab arj ace lzh iso img vhd vhdx".split())  # incl. disk images
# What a disguised file pretends to be ("invoice.pdf.exe").
DOCUMENT_LIKE = frozenset("pdf doc docx xls xlsx ppt pptx txt rtf csv odt jpg jpeg png gif".split())
RISKY = EXECUTABLE | MACRO_OFFICE | HTML | ARCHIVE
# Declared types that make a file look harmless.
HARMLESS_LOOKING_TYPES = (
    "application/pdf",
    "image/",
    "text/plain",
    "application/msword",
    "application/vnd.openxmlformats-officedocument",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
)
_RTLO = "‮"  # right-to-left override: "invoice‮fdp.exe" displays as "invoiceexe.pdf"

REASONS = {
    "attach.executable": "An attachment is a program or script",
    "attach.double_extension": "An attachment disguises its real type (double extension or right-to-left trick)",
    "attach.macro_office": "An attachment is an Office file that can contain macros",
    "attach.html": "An attachment is an HTML or SVG file, often a fake login page",
    "attach.type_mismatch": "An attachment is declared as a harmless type but its name says otherwise",
    "attach.password_hint": "A password is given in the email for an attached archive, a way to dodge scanners",
    "attach.archive": "An attachment is an archive or disk image that can hide its contents",
}
SIGNALS = tuple(REASONS)

MAX_EVIDENCE = 3
_PASSWORD_HINT = re.compile(r"\bpass(?:word|code)\b\s*(?:is|:|=)|\b(?:archive|zip|file|attachment) password\b", re.IGNORECASE)


def _extensions(filename: str) -> list[str]:
    # Windows ignores trailing dots and spaces: "invoice.exe. " is an .exe.
    name = filename.replace(_RTLO, "").strip().rstrip(". ").lower()
    return [part.strip() for part in name.split(".")[1:]]


def _shown(attachment: Attachment) -> str:
    name = "".join(ch for ch in attachment.filename if ch.isprintable())[:80]
    return name + (" (right-to-left override)" if _RTLO in attachment.filename else "")


def check(parsed: ParsedEmail, notes: list[str]) -> list[Finding]:
    hits: dict[str, list[str]] = {}

    def add(signal: str, evidence: str) -> None:
        items = hits.setdefault(signal, [])
        if evidence not in items and len(items) < MAX_EVIDENCE:
            items.append(evidence)

    for attachment in parsed.attachments:
        extensions = _extensions(attachment.filename)
        last = extensions[-1] if extensions else ""
        shown = _shown(attachment)
        if last in EXECUTABLE:
            add("attach.executable", shown)
        if last in MACRO_OFFICE:
            add("attach.macro_office", shown)
        if last in HTML:
            add("attach.html", shown)
        if last in ARCHIVE:
            add("attach.archive", shown)
        disguised = len(extensions) >= 2 and extensions[-2] in DOCUMENT_LIKE and last in RISKY
        if disguised or _RTLO in attachment.filename:
            add("attach.double_extension", shown)
        declared = attachment.content_type.lower()
        if last in RISKY and declared.startswith(HARMLESS_LOOKING_TYPES):
            add("attach.type_mismatch", f"{shown} declared as {declared}")

    if "attach.archive" in hits and _PASSWORD_HINT.search(parsed.text):
        add("attach.password_hint", "archive attached and a password given in the text")

    return [Finding(signal, REASONS[signal], tuple(hits[signal])) for signal in SIGNALS if signal in hits]

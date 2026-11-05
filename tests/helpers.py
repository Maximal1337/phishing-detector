"""Build small synthetic emails for tests (reserved names only: RFC 2606 / RFC 5737)."""

from __future__ import annotations

from email.message import EmailMessage
from email.policy import SMTP

from phishing_detector.parser import parse


def make_email(
    *,
    from_: str = "Alice <alice@example.com>",
    to: str = "bob@example.org",
    subject: str = "Quarterly planning notes",
    auth: list[str] | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
    text: str | None = "Hello,\nplease find the notes below.\n",
    html: str | None = None,
    attachments: list[tuple[str, str, bytes]] = (),
) -> bytes:
    msg = EmailMessage()
    for value in auth or []:
        msg["Authentication-Results"] = value  # first one ends up topmost
    if return_path:
        msg["Return-Path"] = return_path
    msg["From"] = from_
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = "Thu, 05 Nov 2026 10:00:00 +0000"
    msg["Message-ID"] = "<test@example.com>"
    if text is not None:
        msg.set_content(text)
    if html is not None:
        if text is None:
            msg.set_content(html, subtype="html")
        else:
            msg.add_alternative(html, subtype="html")
    for filename, content_type, data in attachments:
        maintype, subtype = content_type.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes(policy=SMTP)


def parsed_email(**kwargs):
    return parse(make_email(**kwargs))

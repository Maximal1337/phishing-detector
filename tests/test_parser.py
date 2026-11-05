import hashlib
from email.message import Message

from phishing_detector.parser import parse

MULTIPART = b"""\
Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=example.test; dmarc=fail header.from=example.test
Authentication-Results: forged.example; spf=pass; dmarc=pass
From: =?utf-8?q?Example_Bank_=E2=9C=93?= <alerts@examplebank.test>
Reply-To: Help Desk <help@reply.example.net>
Return-Path: <bounce@mailer.example.org>
To: user@example.com
Subject: Your statement
Date: Thu, 05 Nov 2026 10:00:00 +0000
Message-ID: <1@examplebank.test>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: multipart/alternative; boundary="b2"

--b2
Content-Type: text/plain; charset=utf-8

Hello, see https://examplebank.test/statement. Or www.example.org/help.

--b2
Content-Type: text/html; charset=utf-8

<html><head><style>.x{color:red}</style><script>var secret = 1;</script></head>
<body><p>Click <a href="http://203.0.113.7/login">examplebank.test</a></p>
<form action="http://203.0.113.7/p"><input type="password" name="pw"></form></body></html>

--b2--

--b1
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

--b1--
"""


def test_headers_make_it_an_email():
    parsed = parse(MULTIPART)
    assert parsed.input_type == "email"
    assert parsed.sha256 == hashlib.sha256(MULTIPART).hexdigest()


def test_from_reply_to_and_return_path():
    parsed = parse(MULTIPART)
    assert parsed.from_display == "Example Bank ✓"  # RFC 2047 decoded
    assert parsed.from_address == "alerts@examplebank.test"
    assert parsed.from_domain == "examplebank.test"
    assert parsed.reply_to_domains == ["reply.example.net"]
    assert parsed.return_path_domain == "mailer.example.org"
    assert parsed.subject == "Your statement"


def test_only_the_topmost_authentication_results_is_kept():
    parsed = parse(MULTIPART)
    assert "dmarc=fail" in parsed.auth_results
    assert "forged.example" not in parsed.auth_results


def test_text_and_links_from_plain_and_html_parts():
    parsed = parse(MULTIPART)
    assert "see https://examplebank.test/statement" in parsed.text
    assert "Click" in parsed.text
    assert "var secret" not in parsed.text  # script content is not visible text
    hrefs = {link.href for link in parsed.links}
    assert "https://examplebank.test/statement" in hrefs  # trailing dot stripped
    assert "http://www.example.org/help" in hrefs  # scheme added to www. links
    anchor = next(link for link in parsed.links if link.source == "html")
    assert (anchor.href, anchor.text) == ("http://203.0.113.7/login", "examplebank.test")
    assert parsed.password_inputs == 1


def test_attachment_metadata_comes_from_headers():
    (attachment,) = parse(MULTIPART).attachments
    assert attachment.filename == "invoice.pdf.exe"
    assert attachment.content_type == "application/pdf"
    assert attachment.encoded_size > 0


def test_attachment_payload_is_never_decoded(monkeypatch):
    decoded = []
    original = Message.get_payload

    def spy(self, i=None, decode=False):
        if decode and self.get_filename():
            decoded.append(self.get_filename())
        return original(self, i, decode)

    monkeypatch.setattr(Message, "get_payload", spy)
    parsed = parse(MULTIPART)
    assert parsed.attachments[0].filename == "invoice.pdf.exe"
    assert decoded == []


def test_plain_text_without_headers_is_body_only():
    parsed = parse(b"Dear customer,\nverify your account at http://203.0.113.5/login now.\n")
    assert parsed.input_type == "body_only"
    assert parsed.from_domain == ""
    assert "verify your account" in parsed.text
    assert [link.href for link in parsed.links] == ["http://203.0.113.5/login"]


def test_text_that_starts_like_a_header_is_still_body_only():
    parsed = parse(b"Note: the meeting moved to 3 pm.\nSee you there.\n")
    assert parsed.input_type == "body_only"
    assert "meeting moved" in parsed.text


def test_broken_input_does_not_crash():
    weird = (
        b"From: <<<>>>\nSubject: =?bogus-charset?q?x?=\nContent-Type: text/plain; charset=no-such-charset\n\n"
        b"\xff\xfe body \x00 with junk"
    )
    parsed = parse(weird)
    assert parsed.input_type == "email"
    assert "body" in parsed.text
    assert parse(bytes(range(256))).input_type == "body_only"

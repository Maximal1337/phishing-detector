from email.message import Message

import pytest
from helpers import make_email, parsed_email

from phishing_detector import analyze
from phishing_detector.checks import attachments

# Placeholder bytes only: nothing here is a real program or document.
DATA = b"placeholder attachment bytes, never decoded by the detector"


def _found(files, text="See the attached file.\n"):
    parsed = parsed_email(text=text, attachments=[(name, ctype, DATA) for name, ctype in files])
    return {f.id: f for f in attachments.check(parsed, [])}


@pytest.mark.parametrize(
    ("signal", "hit", "miss"),
    [
        ("attach.executable", ("setup.exe", "application/octet-stream"), ("setup.pdf", "application/pdf")),
        ("attach.macro_office", ("budget.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"), ("budget.xlsx", "application/vnd.ms-excel")),
        ("attach.html", ("login.html", "text/html"), ("notes.txt", "text/plain")),
        ("attach.archive", ("photos.zip", "application/zip"), ("photo.jpg", "image/jpeg")),
        ("attach.double_extension", ("invoice.pdf.exe", "application/octet-stream"), ("archive.tar.gz", "application/gzip")),
        ("attach.type_mismatch", ("invoice.exe", "application/pdf"), ("invoice.exe", "application/octet-stream")),
    ],
)
def test_signal_hit_and_miss(signal, hit, miss):
    assert signal in _found([hit])
    assert signal not in _found([miss])


def test_trailing_dots_and_spaces_dont_hide_the_extension():
    assert "attach.executable" in _found([("report.exe. ", "application/octet-stream")])


def test_right_to_left_override_disguise():
    found = _found([("invoice‮fdp.exe", "application/octet-stream")])
    assert "attach.double_extension" in found
    assert found["attach.double_extension"].evidence == ("invoicefdp.exe (right-to-left override)",)


def test_password_hint_needs_an_archive():
    with_archive = _found([("scan.zip", "application/zip")], text="The password is 4417.\n")
    assert "attach.password_hint" in with_archive
    assert "4417" not in " ".join(with_archive["attach.password_hint"].evidence)
    assert "attach.password_hint" not in _found([("scan.pdf", "application/pdf")], text="The password is 4417.\n")
    assert "attach.password_hint" not in _found([("scan.zip", "application/zip")], text="Photos from the trip.\n")


def test_evidence_lists_at_most_three_names():
    files = [(f"tool{n}.exe", "application/octet-stream") for n in range(5)]
    assert len(_found(files)["attach.executable"].evidence) == 3


def test_attachment_payloads_are_never_decoded_end_to_end(monkeypatch):
    decoded = []
    original = Message.get_payload

    def spy(self, i=None, decode=False):
        if decode and self.get_filename():
            decoded.append(self.get_filename())
        return original(self, i, decode)

    monkeypatch.setattr(Message, "get_payload", spy)
    raw = make_email(attachments=[("invoice.pdf.exe", "application/pdf", DATA), ("scan.zip", "application/zip", DATA)])
    result = analyze(raw)
    assert {"attach.executable", "attach.double_extension", "attach.type_mismatch", "attach.archive"} <= {i.id for i in result.indicators}
    assert decoded == []

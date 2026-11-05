import json

from phishing_detector.cli import format_result, main
from phishing_detector.models import Indicator, Result


def _result(**overrides):
    values = dict(
        input_type="email",
        verdict="phishing",
        score=65,
        indicators=[
            Indicator("links.ip_host", "links", 30, "Link points to a bare IP address", ("hxxp://203[.]0[.]113[.]5/",)),
            Indicator("auth.dmarc_fail", "auth", 25, "DMARC failed", ()),
        ],
        notes=["History check skipped: no scan history was provided."],
        sender_domain="examplebank.test",
        email_sha256="0" * 64,
    )
    values.update(overrides)
    return Result(**values)


def test_summary_lists_verdict_indicators_and_notes():
    lines = format_result(_result()).splitlines()
    assert lines[0] == "Verdict: PHISHING (score 65/100)"
    assert lines[1] == "Input: email with headers"
    assert lines[2] == "Indicators (2):"
    assert lines[3] == "  [+30] links.ip_host: Link points to a bare IP address (hxxp://203[.]0[.]113[.]5/)"
    assert lines[4] == "  [+25] auth.dmarc_fail: DMARC failed"
    assert lines[5:] == ["Notes:", "  - History check skipped: no scan history was provided."]


def test_summary_without_indicators():
    text = format_result(_result(verdict="likely_legitimate", score=0, indicators=[], notes=[], input_type="body_only"))
    assert text.splitlines() == [
        "Verdict: LIKELY LEGITIMATE (score 0/100)",
        "Input: body text only (no headers)",
        "Indicators: none",
    ]


def test_scan_prints_the_summary(tmp_path, capsys):
    sample = tmp_path / "mail.txt"
    sample.write_bytes(b"Hi, lunch at noon?\n")
    assert main(["scan", str(sample)]) == 0
    assert capsys.readouterr().out.startswith("Verdict: LIKELY LEGITIMATE (score 0/100)")


def test_scan_json(tmp_path, capsys):
    sample = tmp_path / "mail.txt"
    sample.write_bytes(b"Hi, lunch at noon?\n")
    assert main(["scan", str(sample), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "likely_legitimate"
    assert set(data) == {"input_type", "verdict", "score", "indicators", "notes", "sender_domain", "email_sha256"}


def test_missing_file_is_an_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope.eml")]) == 1
    assert "cannot read" in capsys.readouterr().err

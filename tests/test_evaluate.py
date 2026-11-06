"""The evaluation pipeline, on a tiny fake corpus built from the synthetic samples."""

import email
import hashlib
import importlib.util
import io
import json
import mailbox
import sys
import tarfile
from email import policy
from email.utils import getaddresses
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

_spec = importlib.util.spec_from_file_location("evaluate", ROOT / "scripts" / "evaluate.py")
evaluate = importlib.util.module_from_spec(_spec)
sys.modules["evaluate"] = evaluate  # dataclasses look their module up there
_spec.loader.exec_module(evaluate)

PHISHING = ["phishing_lookalike_sender.eml", "phishing_spoofed_bank.eml", "phishing_invoice_attachment.eml"]
HAM = ["legit_newsletter.eml", "legit_receipt.eml", "legit_internal.eml"]


def _fake_corpus(tmp_path):
    (tmp_path / "nazario").mkdir()
    box = mailbox.mbox(str(tmp_path / "nazario" / "phishing-test"))
    for name in PHISHING:
        box.add((SAMPLES / name).read_bytes())
    box.close()

    (tmp_path / "spamassassin").mkdir()
    with tarfile.open(tmp_path / "spamassassin" / "ham.tar.bz2", "w:bz2") as archive:
        for name in HAM + ["cmds"]:
            data = b"index of the corpus, not a message\n" if name == "cmds" else (SAMPLES / name).read_bytes()
            info = tarfile.TarInfo(f"easy_ham/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

    files = [
        {"label": "phishing", "corpus": "nazario", "name": "phishing-test", "sha256": "0" * 64},
        {"label": "ham", "corpus": "spamassassin", "name": "ham.tar.bz2", "sha256": "1" * 64},
    ]
    (tmp_path / "manifest.json").write_text(json.dumps({"files": files}), encoding="utf-8")
    return tmp_path


def test_reads_mbox_and_tar_without_unpacking(tmp_path):
    records, files, problems = evaluate.scan_corpora(_fake_corpus(tmp_path))
    assert sorted(r.label for r in records) == ["ham"] * 3 + ["phishing"] * 3  # "cmds" skipped
    assert sum(f["dev"] + f["test"] for f in files) == 6
    assert not problems
    assert sorted(p.name for p in (tmp_path / "spamassassin").iterdir()) == ["ham.tar.bz2"]


def test_report_contains_aggregates_only(tmp_path, capsys):
    assert evaluate.main(["--data", str(_fake_corpus(tmp_path)), "--split", "all"]) == 0
    out = capsys.readouterr().out
    assert "Messages in this report: 3 phishing, 3 ham." in out
    assert "| `links.lookalike_domain` |" in out

    for name in PHISHING + HAM:
        msg = email.message_from_bytes((SAMPLES / name).read_bytes(), policy=policy.default)
        headers = [str(v) for h in ("From", "To", "Reply-To", "Return-Path") for v in (msg.get_all(h) or [])]
        for _, address in getaddresses(headers):
            assert address not in out
        assert str(msg["Subject"]) not in out
    for phrase in ("unusual sign-in", "examp1ebank", "invoice_4471", "203.0.113", "Dana"):
        assert phrase not in out


def test_split_is_deterministic_and_about_30_percent():
    shas = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(10_000)]
    assert [evaluate.split_of(s) for s in shas[:50]] == [evaluate.split_of(s) for s in shas[:50]]
    share = sum(evaluate.split_of(s) == "test" for s in shas) / len(shas)
    assert 0.28 < share < 0.32


def test_score_can_leave_signals_out():
    ids = frozenset({"auth.dmarc_fail", "links.ip_host"})
    assert evaluate.score(ids) == evaluate.WEIGHTS["auth.dmarc_fail"] + evaluate.WEIGHTS["links.ip_host"]
    assert evaluate.score(ids, evaluate.AUTH_SIGNALS) == evaluate.WEIGHTS["links.ip_host"]


def test_metrics():
    m = evaluate.metrics({"tp": 8, "fp": 2, "fn": 2, "tn": 88})
    assert (round(m["precision"], 3), round(m["recall"], 3), round(m["f1"], 3), round(m["fpr"], 3)) == (0.8, 0.8, 0.8, 0.022)
    assert evaluate.metrics({"tp": 0, "fp": 0, "fn": 0, "tn": 0})["f1"] == 0.0


def test_every_auth_signal_is_an_era_signal():
    assert evaluate.AUTH_SIGNALS == {s for s in evaluate.WEIGHTS if s.startswith("auth.")}
    assert evaluate.AUTH_SIGNALS <= set(evaluate.ERA_SIGNALS)
    assert set(evaluate.ERA_SIGNALS) <= set(evaluate.WEIGHTS)

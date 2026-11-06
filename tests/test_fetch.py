"""fetch_datasets.py on files that are already in place (no network)."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("fetch_datasets", ROOT / "scripts" / "fetch_datasets.py")
fetch_datasets = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fetch_datasets)

MBOX = b"From a@example.org Mon Jan  1 00:00:00 2024\nSubject: one\n\nbody\n>From quoted\n\nFrom b@example.org Mon Jan  1 00:00:00 2024\nSubject: two\n\nbody\n"


def _source(**extra):
    return {"label": "ham", "corpus": "apache", "name": "list.mbox", "url": "unused", "size": None, "sha256": "0" * 64, **extra}


def test_mbox_built_on_request_reports_a_changed_download(tmp_path, capsys):
    (tmp_path / "apache").mkdir()
    (tmp_path / "apache" / "list.mbox").write_bytes(MBOX)
    record = fetch_datasets.fetch(_source(messages=3, built_on_request=True), tmp_path)
    assert record["matches_pin"] is False and record["messages"] == 2 and record["pinned_messages"] == 3
    assert "differs from the pinned download; 2 messages now, 3 pinned" in capsys.readouterr().err


def test_static_file_that_changed_is_refused(tmp_path):
    (tmp_path / "apache").mkdir()
    (tmp_path / "apache" / "list.mbox").write_bytes(MBOX)
    with pytest.raises(SystemExit, match="doesn't match the pinned"):
        fetch_datasets.fetch(_source(), tmp_path)

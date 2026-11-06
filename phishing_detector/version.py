"""A short fingerprint of the detector's rules, used in cache keys.

It changes whenever any check, weight or data list changes, so a new (or rolled-back)
version of the code never reuses analysis cached by another one.
"""

from __future__ import annotations

import hashlib
from functools import cache
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent


def fingerprint(root: Path) -> str:
    """SHA-256 over the package's .py and .txt files (paths and contents, line endings normalised)."""
    digest = hashlib.sha256()
    files = sorted(p for p in root.rglob("*") if p.suffix in {".py", ".txt"} and "__pycache__" not in p.parts)
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return digest.hexdigest()[:12]


@cache
def rules_version() -> str:
    return fingerprint(PACKAGE)

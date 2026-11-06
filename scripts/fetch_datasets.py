"""Download the public email corpora that scripts/evaluate.py reads.

Run it inside the evaluation container (README, "Evaluation"): it writes to
--dest, a Docker volume, never into the repository. Files are only downloaded
and hashed here; nothing is opened or unpacked.

SHA-256 values were recorded on the first download, 2026-11-06 (the sources publish no
checksums) and are pinned below, so a later download that differs is refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

NAZARIO = "https://monkey.org/~jose/phishing/"
SPAMASSASSIN = "https://spamassassin.apache.org/old/publiccorpus/"

# label: "phishing" or "ham"; size in bytes as served; sha256 pinned after the first download (None = not pinned yet).
SOURCES = [
    {"label": "phishing", "corpus": "nazario", "name": "phishing-2023", "url": NAZARIO + "phishing-2023", "size": 7763704, "sha256": "5007f1c1dc91b15e93e988afa3a1cf402e15c88f765d3057be8bfec50dae1fe8"},
    {"label": "phishing", "corpus": "nazario", "name": "phishing-2024", "url": NAZARIO + "phishing-2024", "size": 15457816, "sha256": "60afa40a2757170093a2bde31ec9cda4e54d33992203ce04bfbbc86d2e5e5b99"},
    {"label": "phishing", "corpus": "nazario", "name": "phishing-2025", "url": NAZARIO + "phishing-2025", "size": 18769863, "sha256": "f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f"},
    {"label": "ham", "corpus": "spamassassin", "name": "20030228_easy_ham.tar.bz2", "url": SPAMASSASSIN + "20030228_easy_ham.tar.bz2", "size": 1612216, "sha256": "2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438"},
    {"label": "ham", "corpus": "spamassassin", "name": "20030228_easy_ham_2.tar.bz2", "url": SPAMASSASSIN + "20030228_easy_ham_2.tar.bz2", "size": 1077892, "sha256": "b4bd3dc5ae5b40f38e99a0e41ad7d16b428b56e818e3a6ffa07330d62004dd38"},
    {"label": "ham", "corpus": "spamassassin", "name": "20030228_hard_ham.tar.bz2", "url": SPAMASSASSIN + "20030228_hard_ham.tar.bz2", "size": 1029898, "sha256": "ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9"},
]  # fmt: skip

MAX_BYTES = 50_000_000  # refuse anything far larger than expected
CHUNK = 1 << 16


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(source: dict, dest: Path) -> dict:
    target = dest / source["corpus"] / source["name"]
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(target.name + ".part")
        request = urllib.request.Request(source["url"], headers={"User-Agent": "phishing-detector-evaluation"})
        size = 0
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as out:
            while chunk := response.read(CHUNK):
                size += len(chunk)
                if size > MAX_BYTES:
                    partial.unlink()
                    raise SystemExit(f"{source['name']}: larger than {MAX_BYTES} bytes, stopped")
                out.write(chunk)
        partial.rename(target)

    size = target.stat().st_size
    digest = sha256_of(target)
    if size != source["size"]:
        raise SystemExit(f"{source['name']}: {size} bytes, expected {source['size']} - the source changed")
    if source["sha256"] and digest != source["sha256"]:
        raise SystemExit(f"{source['name']}: SHA-256 {digest} doesn't match the pinned {source['sha256']}")
    return {
        "label": source["label"],
        "corpus": source["corpus"],
        "name": source["name"],
        "url": source["url"],
        "size": size,
        "sha256": digest,
        "pinned": bool(source["sha256"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, required=True, help="where to store the files (the Docker volume)")
    args = parser.parse_args(argv)

    files = [fetch(source, args.dest) for source in SOURCES]
    manifest = {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "files": files}
    (args.dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    for f in files:
        state = "pinned, matches" if f["pinned"] else "not pinned yet (trust on first use)"
        print(f"{f['corpus']:13} {f['name']:30} {f['size']:>10} bytes  sha256 {f['sha256']}  {state}")
    print(f"total {sum(f['size'] for f in files)} bytes in {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

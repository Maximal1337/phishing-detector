"""Download the public email corpora that scripts/evaluate.py reads.

Run it inside the evaluation container (README, "Evaluation"): it writes to
--dest, a Docker volume, never into the repository. Files are only downloaded
and hashed here; nothing is opened or unpacked.

SHA-256 values were recorded on the first download, 2026-11-06 (the sources publish no
checksums) and are pinned below. A static file that differs later is refused. The Apache
mbox files are built by the archive on request, so a later download can differ in bytes
(for example if a message was removed); for those the script prints the mismatch and the
message counts, keeps the file and carries on (README, "Evaluation").
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

# Modern legitimate mail: the public users@tomcat.apache.org archive, one mbox per month,
# 2024-01 to 2025-10. The archive builds these files on request, so their size isn't known
# in advance; SHA-256 and the message count are pinned after the first download.
APACHE = "https://lists.apache.org/api/mbox.lua?list=users&domain=tomcat.apache.org&d="
APACHE_MONTHS = [f"{y}-{m:02d}" for y in (2024, 2025) for m in range(1, 13) if (y, m) <= (2025, 10)]
# month -> (sha256, messages), recorded on the first download, 2026-11-06
APACHE_PINNED: dict[str, tuple[str, int]] = {
    "2024-01": ("55cb5aa1ba195600a06b4fb55338cf75a6bfa76a309ef4bb26119f9962c8614e", 118),
    "2024-02": ("ebfb805093b19c79c5e5c024f91a95d37fe1d725ce8ed2bfd71dd959911a1208", 136),
    "2024-03": ("99f45b2bdb696d7533e9fdb908e4fc23568f5e979e7985ff440bbd1d2f01e50d", 166),
    "2024-04": ("d9bf871c8a2627e649877998e251648f1b4170c797835e1e98abd1eb0329b7de", 172),
    "2024-05": ("872977e03ca48cade35c2d7e13eba640b4a71af4ee7f28e9e3b30bfe5a9019ec", 162),
    "2024-06": ("b7ecaf81585abbd7caecc13e4b3dd6cdef26c1b72b568a112a24e51d173cdac9", 172),
    "2024-07": ("0320c6854844cc71ca875c176ede4a535763c1eb37138a5aefe1f7a13985ecf4", 132),
    "2024-08": ("fb155fcece987f7c22825010b33b05c9a9795dc7ff478c6dad79fcf44a5036a5", 143),
    "2024-09": ("57117b35c4ffef3d9a0b43d01cbf1181971bd30020a3cb421945c89d25a29443", 142),
    "2024-10": ("e68a7c8eb9737670a4dfba271de6f6947db3aff55cde180d9ec6299f97210e30", 136),
    "2024-11": ("1b2de75ec2d76c087dc6b53d7eaccd1e37d47358f41b0f5d9d261da22574b516", 77),
    "2024-12": ("a346d4e0c8f9a10f18d106a24627f39e6fd0f92455048ba9ec897d413c8e7041", 129),
    "2025-01": ("800a4bdb0d9f36c03bb26c8f932bf6c9b1fd71c693fc532f04d96d7c3bccdda4", 121),
    "2025-02": ("0651c1bd9518e2d472088fc8049b47f71cc424b8869d01866725dfa76a279f35", 126),
    "2025-03": ("38919cc2e7052854fa6cceb29f06d23ede3fba6457c942cb9312f94ed0479af5", 114),
    "2025-04": ("67125d3f3f2e5d67e64e62641f4ed33c542cc165ca0fdea939a5d654913e07e8", 146),
    "2025-05": ("11ba483dc1cae9aa5fab635e5f6ddddfdcf03ec79656293add2d719ca643f796", 92),
    "2025-06": ("e0f72a8a8e6d697b71fb7e9c0e3e4bf64fc68f9b9b1b3a017ef90cb4a4d89202", 85),
    "2025-07": ("f7fed5b6b294192c8fc0d22ec8561a4e1bd8a3b07e6e93df286db72a714f1b9f", 99),
    "2025-08": ("4eaef33988b5c15abda7f5f4f9569cc6ddab5836790835966a0fb389515da12e", 188),
    "2025-09": ("8f6bc4dbfbbeeafce76195f21bb0cdf3e805038ffeaaff74ce0109eda1d85b55", 88),
    "2025-10": ("fbbddc2d7e130a254554fe64add2df2a89ac98c4637e834f262335d0bd4073c3", 99),
}  # fmt: skip
SOURCES += [
    {"label": "ham", "corpus": "apache", "name": f"users_tomcat_{month}.mbox", "url": APACHE + month, "size": None,
     "sha256": APACHE_PINNED.get(month, (None, None))[0], "messages": APACHE_PINNED.get(month, (None, None))[1], "built_on_request": True}
    for month in APACHE_MONTHS
]  # fmt: skip

MAX_BYTES = 50_000_000  # refuse anything far larger than expected
MAX_TOTAL_BYTES = 150_000_000  # and stop if everything together grows far beyond the estimate
CHUNK = 1 << 16
READ_TIMEOUT = 300  # seconds; the Apache archive builds each mbox on request, which can take minutes


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def mbox_messages(path: Path) -> int:
    """Count the "From " separator lines; the messages themselves aren't parsed."""
    with path.open("rb") as f:
        return sum(line.startswith(b"From ") for line in f)


def fetch(source: dict, dest: Path) -> dict:
    target = dest / source["corpus"] / source["name"]
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(target.name + ".part")
        request = urllib.request.Request(source["url"], headers={"User-Agent": "phishing-detector-evaluation"})
        size = 0
        with urllib.request.urlopen(request, timeout=READ_TIMEOUT) as response, partial.open("wb") as out:
            while chunk := response.read(CHUNK):
                size += len(chunk)
                if size > MAX_BYTES:
                    partial.unlink()
                    raise SystemExit(f"{source['name']}: larger than {MAX_BYTES} bytes, stopped")
                out.write(chunk)
        partial.rename(target)

    size = target.stat().st_size
    digest = sha256_of(target)
    if source["size"] is not None and size != source["size"]:
        raise SystemExit(f"{source['name']}: {size} bytes, expected {source['size']} - the source changed")
    record = {
        "label": source["label"],
        "corpus": source["corpus"],
        "name": source["name"],
        "url": source["url"],
        "size": size,
        "sha256": digest,
        "pinned": bool(source["sha256"]),
        "matches_pin": digest == source["sha256"] if source["sha256"] else None,
    }
    if source.get("built_on_request"):
        record["messages"] = mbox_messages(target)
        record["pinned_messages"] = source.get("messages")
    if record["matches_pin"] is False:
        if not source.get("built_on_request"):
            raise SystemExit(f"{source['name']}: SHA-256 {digest} doesn't match the pinned {source['sha256']}")
        print(
            f"WARNING {source['name']}: SHA-256 differs from the pinned download; "
            f"{record['messages']} messages now, {record['pinned_messages']} pinned - kept, results may differ slightly",
            file=sys.stderr,
        )
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, required=True, help="where to store the files (the Docker volume)")
    args = parser.parse_args(argv)

    files = []
    for source in SOURCES:
        files.append(fetch(source, args.dest))
        if sum(f["size"] for f in files) > MAX_TOTAL_BYTES:
            raise SystemExit(f"more than {MAX_TOTAL_BYTES} bytes in total, stopped")
    manifest = {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "files": files}
    (args.dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    for f in files:
        state = {True: "pinned, matches", False: "DIFFERS from the pin", None: "not pinned yet (trust on first use)"}[f["matches_pin"]]
        count = f"  {f['messages']} messages" if "messages" in f else ""
        print(f"{f['corpus']:13} {f['name']:30} {f['size']:>10} bytes  sha256 {f['sha256']}  {state}{count}")
    print(f"total {sum(f['size'] for f in files)} bytes in {len(files)} files")
    if differ := [f["name"] for f in files if f["matches_pin"] is False]:
        print(f"{len(differ)} file(s) built on request differ from the pinned download: {', '.join(differ)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Evaluate the detector on the public corpora fetched by fetch_datasets.py.

Runs inside the evaluation container without network (README, "Evaluation").
Messages are read straight from the mbox files and tar.bz2 archives in memory,
never unpacked to disk, and scanned with analyze(). Only aggregates are
printed: counts, signal frequencies, metrics, confusion matrices and indicator
ids. No message text, address or subject leaves this script.

Split: each message's SHA-256 puts it, once and for all, in the dev split
(70 %, looked at while tuning the weights) or the test split (30 %, reported).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mailbox
import sys
import tarfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishing_detector import analyze  # noqa: E402
from phishing_detector.checks.auth import NO_HEADER_NOTE  # noqa: E402
from phishing_detector.scoring import MAX_SCORE, PHISHING_AT, SUSPICIOUS_AT, WEIGHTS  # noqa: E402

TEST_SHARE = 3  # out of 10
MAX_MESSAGE_BYTES = 5_000_000

# The ham is from 2002-2003 and the phishing from 2023-2025. These signals tell
# the eras apart rather than phishing from legitimate mail, so this data can't
# say what their weights should be. Written down before looking at the data.
AUTH_SIGNALS = frozenset(s for s in WEIGHTS if s.startswith("auth."))
ERA_SIGNALS = {
    **{s: "Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002" for s in AUTH_SIGNALS},
    "links.punycode": "internationalised domain names (punycode) only started in 2003",
    "sender.punycode": "internationalised domain names (punycode) only started in 2003",
    "links.risky_tld": "most of the listed top-level domains (.xyz, .top, .zip, ...) didn't exist before 2014",
    "links.shortener": "most of the listed URL shorteners (bit.ly, t.co, ...) started after 2008",
}
VARIANTS = {
    "all signals": frozenset(),
    "without auth.*": AUTH_SIGNALS,
    "without era signals": frozenset(ERA_SIGNALS),
}
THRESHOLDS = {"phishing": PHISHING_AT, "phishing or suspicious": SUSPICIOUS_AT}


@dataclass(frozen=True)
class Scanned:
    label: str  # "phishing" or "ham"
    split: str  # "dev" or "test"
    ids: frozenset[str]
    has_auth_header: bool


def split_of(sha256: str) -> str:
    return "test" if int(sha256[:8], 16) % 10 < TEST_SHARE else "dev"


def score(ids: frozenset[str], excluded: frozenset[str] = frozenset()) -> int:
    return min(MAX_SCORE, sum(WEIGHTS[i] for i in ids if i not in excluded))


def confusion(records: list[Scanned], excluded: frozenset[str], threshold: int) -> dict[str, int]:
    counts = Counter()
    for r in records:
        flagged = score(r.ids, excluded) >= threshold
        counts[("tp" if flagged else "fn") if r.label == "phishing" else ("fp" if flagged else "tn")] += 1
    return {k: counts[k] for k in ("tp", "fp", "fn", "tn")}


def metrics(c: dict[str, int]) -> dict[str, float]:
    def ratio(a: int, b: int) -> float:
        return a / b if b else 0.0

    precision, recall = ratio(c["tp"], c["tp"] + c["fp"]), ratio(c["tp"], c["tp"] + c["fn"])
    f1 = ratio(2 * precision * recall, precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": ratio(c["fp"], c["fp"] + c["tn"])}


# --- reading the corpora (in memory only) --------------------------------


def _mbox_messages(path: Path) -> Iterator[bytes]:
    box = mailbox.mbox(str(path), create=False)  # falls back to read-only on a read-only volume
    try:
        for key in box.iterkeys():
            yield box.get_bytes(key)
    finally:
        box.close()


def _tar_messages(path: Path) -> Iterator[bytes]:
    with tarfile.open(path, "r:bz2") as archive:
        for member in archive:
            if not member.isfile() or member.name.rsplit("/", 1)[-1] == "cmds":  # "cmds" is the corpus' own index
                continue
            f = archive.extractfile(member)
            if f is not None:
                yield f.read(MAX_MESSAGE_BYTES + 1)


def scan_corpora(data: Path) -> tuple[list[Scanned], list[dict], Counter]:
    manifest = json.loads((data / "manifest.json").read_text(encoding="utf-8"))
    records: list[Scanned] = []
    files: list[dict] = []
    problems: Counter = Counter()
    seen: set[str] = set()
    for entry in manifest["files"]:
        path = data / entry["corpus"] / entry["name"]
        reader = _tar_messages if entry["name"].endswith(".tar.bz2") else _mbox_messages
        counts = Counter()
        for raw in reader(path):
            if len(raw) > MAX_MESSAGE_BYTES:
                problems["skipped: larger than 5 MB"] += 1
                continue
            sha = hashlib.sha256(raw).hexdigest()
            if sha in seen:
                problems["skipped: duplicate message"] += 1
                continue
            seen.add(sha)
            try:
                result = analyze(raw)
            except Exception as exc:  # count the type only; the message stays private
                problems[f"error: {type(exc).__name__}"] += 1
                continue
            split = split_of(sha)
            counts[split] += 1
            has_auth = result.input_type == "email" and NO_HEADER_NOTE not in result.notes
            records.append(Scanned(entry["label"], split, frozenset(i.id for i in result.indicators), has_auth))
        files.append({**{k: entry[k] for k in ("corpus", "name", "label", "sha256")}, "dev": counts["dev"], "test": counts["test"]})
    return records, files, problems


# --- report (aggregates only) --------------------------------------------


def _pct(n: int, total: int) -> str:
    return f"{100 * n / total:.1f} %" if total else "-"


def report(records: list[Scanned], files: list[dict], problems: Counter, split: str) -> str:
    dev = [r for r in records if r.split == "dev"]
    chosen = records if split == "all" else [r for r in records if r.split == split]
    by_label = {label: [r for r in chosen if r.label == label] for label in ("phishing", "ham")}
    dev_by_label = {label: [r for r in dev if r.label == label] for label in ("phishing", "ham")}
    out = [f"# Evaluation report ({split} split)", ""]

    out += ["## Data", "", "| Corpus | File | Class | SHA-256 | dev | test |", "|---|---|---|---|---|---|"]
    out += [f"| {f['corpus']} | {f['name']} | {f['label']} | `{f['sha256']}` | {f['dev']} | {f['test']} |" for f in files]
    out += ["", f"Messages in this report: {len(by_label['phishing'])} phishing, {len(by_label['ham'])} ham."]
    out += [f"- {what}: {n}" for what, n in sorted(problems.items())] + [""]

    out += ["## Era check (dev split)", ""]
    for label, group in dev_by_label.items():
        out.append(f"- {label}: {_pct(sum(r.has_auth_header for r in group), len(group))} have an Authentication-Results header")
    out.append("")

    out += ["## Signal frequencies (dev split)", "", "Era signals don't take part in weight tuning; the reason is in the last column.", ""]
    out += ["| Signal | Weight | Phishing | Ham | Era signal |", "|---|---|---|---|---|"]
    for signal in sorted(WEIGHTS, key=lambda s: (s.split(".")[0], s)):
        p = sum(signal in r.ids for r in dev_by_label["phishing"])
        h = sum(signal in r.ids for r in dev_by_label["ham"])
        out.append(
            f"| `{signal}` | {WEIGHTS[signal]} | {p} ({_pct(p, len(dev_by_label['phishing']))}) "
            f"| {h} ({_pct(h, len(dev_by_label['ham']))}) | {ERA_SIGNALS.get(signal, '')} |"
        )
    out.append("")

    out += [f"## Metrics ({split} split)", "", "Positive class: phishing. A mail counts as flagged when its score reaches the threshold.", ""]
    out += ["| Signals | Flagged at | Precision | Recall | F1 | False-positive rate | TP | FP | FN | TN |", "|---|---|---|---|---|---|---|---|---|---|"]
    for name, excluded in VARIANTS.items():
        for label, threshold in THRESHOLDS.items():
            c = confusion(chosen, excluded, threshold)
            m = metrics(c)
            out.append(
                f"| {name} | {label} (≥ {threshold}) | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} "
                f"| {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} |"
            )
    out.append("")

    out += [f"## Score distribution ({split} split, without era signals)", "", "| Score | Phishing | Ham |", "|---|---|---|"]
    bins = [(0, 0), (1, SUSPICIOUS_AT - 1), (SUSPICIOUS_AT, PHISHING_AT - 1), (PHISHING_AT, MAX_SCORE)]
    for low, high in bins:
        row = [sum(low <= score(r.ids, VARIANTS["without era signals"]) <= high for r in by_label[k]) for k in ("phishing", "ham")]
        out.append(f"| {low}-{high} | {row[0]} | {row[1]} |")
    out.append("")

    era_free = VARIANTS["without era signals"]
    out += [f"## Most common indicator sets among errors ({split} split, without era signals, flagged at ≥ {PHISHING_AT})", ""]
    for title, label, wrong in (("False positives (ham flagged)", "ham", True), ("False negatives (phishing missed)", "phishing", False)):
        sets = Counter(
            ", ".join(sorted(r.ids - era_free)) or "(no indicators)"
            for r in by_label[label]
            if (score(r.ids, era_free) >= PHISHING_AT) == wrong
        )
        out += [f"**{title}:**", ""] + [f"- {n} x {ids}" for ids, n in sets.most_common(8)] + [""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, required=True, help="directory written by fetch_datasets.py")
    parser.add_argument("--split", choices=("dev", "test", "all"), default="dev", help="which split the metrics are for")
    args = parser.parse_args(argv)
    records, files, problems = scan_corpora(args.data)
    print(report(records, files, problems, args.split))
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
import email
import hashlib
import json
import mailbox
import math
import sys
import tarfile
from email import policy
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishing_detector import analyze  # noqa: E402
from phishing_detector.checks.auth import NO_HEADER_NOTE  # noqa: E402
from phishing_detector.parser import parse  # noqa: E402
from phishing_detector.scoring import MAX_SCORE, PHISHING_AT, SUSPICIOUS_AT, WEIGHTS  # noqa: E402

TEST_SHARE = 3  # out of 10
MAX_MESSAGE_BYTES = 5_000_000

# Weight tuning (dev split only): weight = k * ln(how much more often the signal
# fires in phishing than in ham), add-one smoothing, rounded to a multiple of 5,
# kept within 0..40. Only signals with enough dev hits and no era bias are tuned;
# k is the one free parameter, picked for the best F1 at the phishing threshold
# while at most 1 % of ham is flagged phishing and at most 2 % suspicious or
# worse (so a single weak word can't make ordinary mail "suspicious"),
# measured without the era signals.
MIN_SUPPORT = 10
WEIGHT_RANGE = (0, 40)
K_GRID = tuple(range(4, 17))
MAX_TUNING_FPR = 0.01  # ham flagged phishing (score >= 50)
MAX_TUNING_SUSPICIOUS_FPR = 0.02  # ham flagged suspicious or phishing (score >= 25)

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
    # Added in the second iteration (modern phishing); hand-set, cautious weights.
    "links.abused_hosting": "the listed hosting, storage and form services didn't exist in 2002",
    "links.redirect_param": "tracking redirects in links are far more common in today's mail than in 2002 mailing lists",
    "links.cta_text": "needs HTML links; only about 5 % of the 2002 ham is HTML",
    "content.hidden_text": "needs HTML; only about 5 % of the 2002 ham is HTML",
    "content.zero_width": "needs HTML or Unicode-heavy text, both rare in the 2002 ham",
    "content.image_only": "needs HTML; only about 5 % of the 2002 ham is HTML",
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
    has_link: bool = False
    has_html: bool = False
    has_attachment: bool = False


def split_of(sha256: str) -> str:
    return "test" if int(sha256[:8], 16) % 10 < TEST_SHARE else "dev"


def score(ids: frozenset[str], excluded: frozenset[str] = frozenset(), weights: dict[str, int] = WEIGHTS) -> int:
    return min(MAX_SCORE, sum(weights[i] for i in ids if i not in excluded))


def confusion(
    records: list[Scanned], excluded: frozenset[str], threshold: int, weights: dict[str, int] = WEIGHTS
) -> dict[str, int]:
    counts = Counter()
    for r in records:
        flagged = score(r.ids, excluded, weights) >= threshold
        counts[("tp" if flagged else "fn") if r.label == "phishing" else ("fp" if flagged else "tn")] += 1
    return {k: counts[k] for k in ("tp", "fp", "fn", "tn")}


def metrics(c: dict[str, int]) -> dict[str, float]:
    def ratio(a: int, b: int) -> float:
        return a / b if b else 0.0

    precision, recall = ratio(c["tp"], c["tp"] + c["fp"]), ratio(c["tp"], c["tp"] + c["fn"])
    f1 = ratio(2 * precision * recall, precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": ratio(c["fp"], c["fp"] + c["tn"])}


# --- weight tuning (dev split only) --------------------------------------


def log_ratio(signal: str, phishing: list[Scanned], ham: list[Scanned]) -> float:
    p = (sum(signal in r.ids for r in phishing) + 1) / (len(phishing) + 2)
    h = (sum(signal in r.ids for r in ham) + 1) / (len(ham) + 2)
    return math.log(p / h)


def tunable_signals(dev: list[Scanned]) -> list[str]:
    return [
        s
        for s in sorted(WEIGHTS)
        if s not in ERA_SIGNALS and not s.startswith("history.") and sum(s in r.ids for r in dev) >= MIN_SUPPORT
    ]


def suggested_weights(dev: list[Scanned], k: float) -> dict[str, int]:
    phishing = [r for r in dev if r.label == "phishing"]
    ham = [r for r in dev if r.label == "ham"]
    weights = dict(WEIGHTS)
    for signal in tunable_signals(dev):
        raw = k * log_ratio(signal, phishing, ham)
        weights[signal] = int(min(max(5 * round(raw / 5), WEIGHT_RANGE[0]), WEIGHT_RANGE[1]))
    return weights


def pick_k(dev: list[Scanned]) -> tuple[float, list[tuple[float, dict[str, float], dict[str, float]]]]:
    era_free = frozenset(ERA_SIGNALS)
    rows = []
    for k in K_GRID:
        weights = suggested_weights(dev, k)
        rows.append((k, metrics(confusion(dev, era_free, PHISHING_AT, weights)), metrics(confusion(dev, era_free, SUSPICIOUS_AT, weights))))
    allowed = [row for row in rows if row[1]["fpr"] <= MAX_TUNING_FPR and row[2]["fpr"] <= MAX_TUNING_SUSPICIOUS_FPR] or rows
    best = max(allowed, key=lambda row: (round(row[1]["f1"], 6), -row[0]))
    return best[0], rows


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
                parsed = parse(raw)
                types = {part.get_content_type() for part in email.message_from_bytes(raw, policy=policy.default).walk()}
            except Exception as exc:  # count the type only; the message stays private
                problems[f"error: {type(exc).__name__}"] += 1
                continue
            split = split_of(sha)
            counts[split] += 1
            records.append(
                Scanned(
                    label=entry["label"],
                    split=split,
                    ids=frozenset(i.id for i in result.indicators),
                    has_auth_header=result.input_type == "email" and NO_HEADER_NOTE not in result.notes,
                    has_link=any(link.href.lower().startswith(("http://", "https://")) for link in parsed.links),
                    has_html="text/html" in types,
                    has_attachment=bool(parsed.attachments),
                )
            )
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

    silent = [r for r in dev_by_label["phishing"] if not (r.ids - frozenset(ERA_SIGNALS))]
    groups = {"phishing": dev_by_label["phishing"], "ham": dev_by_label["ham"], "phishing with no indicator (era signals aside)": silent}
    out += ["## What the mails contain (dev split)", "", "| Group | Messages | With an http(s) link | With an HTML part | With an attachment |", "|---|---|---|---|---|"]
    for name, group in groups.items():
        n = len(group)
        out.append(
            f"| {name} | {n} | {_pct(sum(r.has_link for r in group), n)} | {_pct(sum(r.has_html for r in group), n)} "
            f"| {_pct(sum(r.has_attachment for r in group), n)} |"
        )
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

    if split == "dev":
        out += _tuning_section(dev)
    return "\n".join(out)


def _tuning_section(dev: list[Scanned]) -> list[str]:
    best_k, rows = pick_k(dev)
    phishing = [r for r in dev if r.label == "phishing"]
    ham = [r for r in dev if r.label == "ham"]
    suggested = suggested_weights(dev, best_k)
    out = [
        "## Weight tuning (dev split only)",
        "",
        f"weight = k x ln(rate in phishing / rate in ham), add-one smoothing, rounded to 5, within {WEIGHT_RANGE[0]}..{WEIGHT_RANGE[1]}.",
        f"Tuned: signals without era bias that fire at least {MIN_SUPPORT} times on dev; all others keep their current weight.",
        f"k is picked for the best F1 at the phishing threshold (≥ {PHISHING_AT}) with at most {MAX_TUNING_FPR:.0%} of ham flagged phishing "
        f"and at most {MAX_TUNING_SUSPICIOUS_FPR:.0%} flagged suspicious or worse (≥ {SUSPICIOUS_AT}), measured without era signals.",
        "",
        f"| k | Precision (≥ {PHISHING_AT}) | Recall (≥ {PHISHING_AT}) | F1 (≥ {PHISHING_AT}) | FP rate (≥ {PHISHING_AT}) | Recall (≥ {SUSPICIOUS_AT}) | FP rate (≥ {SUSPICIOUS_AT}) |",
        "|---|---|---|---|---|---|---|",
    ]
    for k, high, low in rows:
        mark = " (picked)" if k == best_k else ""
        out.append(
            f"| {k}{mark} | {high['precision']:.3f} | {high['recall']:.3f} | {high['f1']:.3f} | {high['fpr']:.3f} | {low['recall']:.3f} | {low['fpr']:.3f} |"
        )
    out += ["", f"| Signal | Phishing hits | Ham hits | ln ratio | Current weight | Suggested (k = {best_k}) |", "|---|---|---|---|---|---|"]
    for signal in tunable_signals(dev):
        out.append(
            f"| `{signal}` | {sum(signal in r.ids for r in phishing)} | {sum(signal in r.ids for r in ham)} "
            f"| {log_ratio(signal, phishing, ham):+.2f} | {WEIGHTS[signal]} | {suggested[signal]} |"
        )
    out.append("")
    return out


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

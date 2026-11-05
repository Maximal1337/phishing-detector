"""Command line: python -m phishing_detector scan FILE [--json]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import Result
from .scoring import analyze

VERDICT_LABELS = {
    "phishing": "PHISHING",
    "suspicious": "SUSPICIOUS",
    "likely_legitimate": "LIKELY LEGITIMATE",
}


def format_result(result: Result) -> str:
    lines = [f"Verdict: {VERDICT_LABELS[result.verdict]} (score {result.score}/100)"]
    lines.append("Input: " + ("email with headers" if result.input_type == "email" else "body text only (no headers)"))
    if result.indicators:
        lines.append(f"Indicators ({len(result.indicators)}):")
        for indicator in result.indicators:
            line = f"  [+{indicator.weight}] {indicator.id}: {indicator.reason}"
            if indicator.evidence:
                line += " (" + "; ".join(indicator.evidence) + ")"
            lines.append(line)
    else:
        lines.append("Indicators: none")
    if result.notes:
        lines.append("Notes:")
        lines.extend(f"  - {note}" for note in result.notes)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m phishing_detector",
        description="Scan an email for phishing indicators. Links are never opened and attachments never decoded.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan one email file (.eml with headers, or plain body text)")
    scan.add_argument("file", help="path to the email file")
    scan.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = parser.parse_args(argv)

    try:
        raw = Path(args.file).read_bytes()
    except OSError as exc:
        print(f"error: cannot read {args.file}: {exc.strerror or exc}", file=sys.stderr)
        return 1

    result = analyze(raw)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # e.g. a Windows console that can't print some characters
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) if args.json else format_result(result))
    return 0

"""Smoke test of a deployed stack, through CloudFront.

    AWS_PROFILE=<profile> python scripts/smoke_test.py https://<distribution>.cloudfront.net

Reads the Basic-auth credentials from Secrets Manager inside this process (boto3) and
never prints or logs them. Prints one line per check and exits 1 if any check fails.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
failures = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global failures
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  (' + detail + ')' if detail else ''}")


def request(url: str, auth: str | None = None, body: bytes | None = None, content_type: str | None = None):
    headers = {"Authorization": auth} if auth else {}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers), timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def multipart(filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"email\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def basic_auth(secret_id: str, region: str) -> tuple[str, str]:
    import boto3

    session = boto3.Session(profile_name=os.environ.get("AWS_PROFILE"), region_name=region)
    secret = json.loads(session.client("secretsmanager").get_secret_value(SecretId=secret_id)["SecretString"])
    header = "Basic " + base64.b64encode(f"{secret['username']}:{secret['password']}".encode()).decode()
    wrong = "Basic " + base64.b64encode(f"{secret['username']}:not-the-password".encode()).decode()
    return header, wrong


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("url", help="https://<distribution>.cloudfront.net")
    parser.add_argument("--secret-id", default="phishdet/basic-auth", help="Secrets Manager name of the Basic-auth secret")
    parser.add_argument("--region", default="eu-north-1")
    args = parser.parse_args(argv)
    base = args.url.rstrip("/")
    auth, wrong = basic_auth(args.secret_id, args.region)

    status, body = request(f"{base}/healthz")
    check("/healthz without auth -> 200", status == 200, body.decode(errors="replace")[:120])
    status, _ = request(f"{base}/")
    check("/ without auth -> 401", status == 401, str(status))
    status, _ = request(f"{base}/", auth=wrong)
    check("/ with a wrong password -> 401", status == 401, str(status))
    status, _ = request(f"{base}/", auth=auth)
    check("/ with the password -> 200", status == 200, str(status))

    scanned = 0
    for path in sorted(SAMPLES.iterdir()):
        status, body = request(f"{base}/api/scan", auth, *multipart(path.name, path.read_bytes()))
        result = json.loads(body) if status == 200 else {}
        verdict = result.get("verdict", "-")
        expected_legit = path.name.startswith(("legit_", "plain_legit"))
        ok = status == 200 and (verdict == "likely_legitimate") == expected_legit
        check(f"scan {path.name}", ok, f"{status} {verdict} {result.get('score', '-')} history={result.get('history_status', '-')}")
        scanned += status == 200

    sample = SAMPLES / "legit_receipt.eml"
    status, body = request(f"{base}/api/scan", auth, *multipart(sample.name, sample.read_bytes()))
    check("second scan of the same email -> cached", status == 200 and json.loads(body).get("cached") is True)

    status, body = request(f"{base}/api/history?limit=100", auth)
    rows = len(json.loads(body).get("scans", [])) if status == 200 else 0
    check("/api/history lists the scans (from RDS)", status == 200 and rows >= scanned, f"{rows} rows")

    print(f"{failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

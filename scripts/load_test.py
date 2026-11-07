"""Load test of the deployed stack through CloudFront: scans only, in concurrency steps.

    AWS_PROFILE=<profile> python scripts/load_test.py https://<distribution>.cloudfront.net --steps 5,10,20,30,50
    AWS_PROFILE=<profile> python scripts/load_test.py https://<distribution>.cloudfront.net --steps 40 --step-seconds 600

Every worker thread keeps one HTTPS connection and posts the synthetic samples to /api/scan.
80 % of the scans are unique (a random X-Load-Test header changes the email's SHA-256: a cache
miss and a new history row), 20 % repeat a sample unchanged (cache hits after the first one).
Reads the Basic-auth secret inside this process (smoke_test.basic_auth) and never prints it.
At most 50 threads; only for your own deployment.
"""

from __future__ import annotations

import argparse
import http.client
import json
import random
import sys
import threading
import time
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke_test import SAMPLES, basic_auth, multipart  # noqa: E402

MAX_THREADS = 50
UNIQUE_SHARE = 0.8


def percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def worker(host: str, auth: str, samples: list[bytes], end: float, results: list, lock: threading.Lock) -> None:
    rng = random.Random()
    conn = http.client.HTTPSConnection(host, timeout=30)
    while time.time() < end:
        raw = rng.choice(samples)
        if rng.random() < UNIQUE_SHARE:
            raw = f"X-Load-Test: {uuid.uuid4().hex}\r\n".encode() + raw
        body, content_type = multipart("mail.eml", raw)
        started = time.perf_counter()
        try:
            conn.request("POST", "/api/scan", body=body, headers={"Authorization": auth, "Content-Type": content_type})
            response = conn.getresponse()
            data = response.read()
            status = response.status
            cached = json.loads(data).get("cached") if status == 200 else None
        except (OSError, http.client.HTTPException, ValueError) as exc:
            status, cached = type(exc).__name__, None
            conn.close()
            conn = http.client.HTTPSConnection(host, timeout=30)
        with lock:
            results.append(((time.perf_counter() - started) * 1000, status, cached))
    conn.close()


def run_step(host: str, auth: str, samples: list[bytes], threads: int, seconds: int) -> dict:
    results: list = []
    lock = threading.Lock()
    started, end = time.time(), time.time() + seconds
    pool = [threading.Thread(target=worker, args=(host, auth, samples, end, results, lock)) for _ in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    duration = time.time() - started
    ok = [r for r in results if r[1] == 200]
    hits = [ms for ms, _, cached in ok if cached]
    misses = [ms for ms, _, cached in ok if cached is False]
    return {
        "threads": threads,
        "start": time.strftime("%H:%M:%SZ", time.gmtime(started)),
        "requests": len(results),
        "rps": len(results) / duration,
        "p50": percentile([r[0] for r in ok], 0.50),
        "p95": percentile([r[0] for r in ok], 0.95),
        "p99": percentile([r[0] for r in ok], 0.99),
        "errors": dict(Counter(str(r[1]) for r in results if r[1] != 200)),
        "cached": (len(hits), percentile(hits, 0.50), percentile(hits, 0.95)),
        "uncached": (len(misses), percentile(misses, 0.50), percentile(misses, 0.95)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("url", help="https://<distribution>.cloudfront.net")
    parser.add_argument("--steps", default="5,10,20,30,50", help="comma-separated thread counts")
    parser.add_argument("--step-seconds", type=int, default=60)
    parser.add_argument("--secret-id", default="phishdet/basic-auth")
    parser.add_argument("--region", default="eu-north-1")
    args = parser.parse_args(argv)
    steps = [int(s) for s in args.steps.split(",")]
    if max(steps) > MAX_THREADS:
        parser.error(f"at most {MAX_THREADS} threads")
    host = urlsplit(args.url).hostname
    auth, _ = basic_auth(args.secret_id, args.region)
    samples = [p.read_bytes() for p in sorted(SAMPLES.iterdir())]

    print("threads | start | requests | req/s | p50 ms | p95 ms | p99 ms | errors | cached n / p50 / p95 | uncached n / p50 / p95")
    for threads in steps:
        r = run_step(host, auth, samples, threads, args.step_seconds)
        print(
            f"{r['threads']} | {r['start']} | {r['requests']} | {r['rps']:.1f} | {r['p50']:.0f} | {r['p95']:.0f} | {r['p99']:.0f} | "
            f"{r['errors'] or 0} | {r['cached'][0]} / {r['cached'][1]:.0f} / {r['cached'][2]:.0f} | "
            f"{r['uncached'][0]} / {r['uncached'][1]:.0f} / {r['uncached'][2]:.0f}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

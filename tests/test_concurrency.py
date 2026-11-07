"""The web app under gthread: shared state is safe when requests run in parallel threads."""

import io
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from test_webapp import AUTH, CREDS, DictCache

from webapp import create_app, gunicorn_conf
from webapp.credentials import POOL_SIZE, CachedSecret
from webapp.storage import MemoryHistory

SAMPLES = sorted((Path(__file__).resolve().parent.parent / "samples").iterdir())


def test_parallel_scans_all_succeed_and_log_whole_lines(capsys):
    history = MemoryHistory()
    app = create_app(history=history, cache=DictCache(), auth=lambda: CREDS)

    def scan(i):
        raw = f"X-Load-Test: {i}\r\n".encode() + SAMPLES[i % len(SAMPLES)].read_bytes()
        return app.test_client().post("/api/scan", data={"email": (io.BytesIO(raw), "m.eml")}, headers=AUTH).status_code

    with ThreadPoolExecutor(max_workers=16) as pool:
        statuses = list(pool.map(scan, range(64)))
    assert statuses == [200] * 64
    assert len(history.rows) == 64
    lines = capsys.readouterr().out.splitlines()
    assert sum(json.loads(line)["event"] == "request" for line in lines) == 64  # every line is one whole JSON object


def test_an_expired_secret_is_fetched_once_by_many_threads():
    calls = []

    def slow_fetch(secret_id):
        calls.append(secret_id)
        time.sleep(0.05)
        return json.dumps({"username": "reviewer", "password": "x"})

    secret = CachedSecret("auth", fetch=slow_fetch)
    start = threading.Barrier(20)

    def read(_):
        start.wait()
        return secret.get()["username"]

    with ThreadPoolExecutor(max_workers=20) as pool:
        assert set(pool.map(read, range(20))) == {"reviewer"}
    assert len(calls) == 1


def test_gunicorn_threads_fit_the_pool_and_the_load_balancer():
    assert gunicorn_conf.worker_class == "gthread"
    assert POOL_SIZE >= gunicorn_conf.threads  # a thread never waits for a database connection
    assert gunicorn_conf.keepalive > 60  # longer than the ALB idle timeout

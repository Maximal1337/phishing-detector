"""Web UI and JSON API around the detector.

    GET  /             the UI (static page, all output via textContent)
    POST /api/scan     multipart `email` file or form `text` -> result JSON + `cached`
    GET  /api/history  latest scans (?limit=20, at most 100)
    GET  /healthz      {"status": "ok", "version": ...}, no auth, no database

gunicorn runs `webapp:create_app()`; tests pass in-memory stores instead.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Callable

from flask import Flask, g, jsonify, request, send_from_directory

from phishing_detector.models import StaticAnalysis
from phishing_detector.scoring import analyze_static, finish

from . import credentials
from .storage import MemoryHistory, NoCache, PostgresHistory, ValkeyCache, scan_row

MAX_UPLOAD_BYTES = 1024 * 1024  # 1 MB; larger requests get 413
MAX_HISTORY = 100
STATIC = Path(__file__).parent / "static"
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

def log_event(event: str, **fields) -> None:
    """One JSON line on stdout (CloudWatch Logs in AWS). Callers pass ids, counts and class names only, never email content."""
    print(json.dumps({"event": event, **fields}, default=str), file=sys.stdout, flush=True)


class LoggedHistory:
    """Wraps the store so every read or write failure leaves a countable log line (D-70)."""

    def __init__(self, store) -> None:
        self.store = store

    def count_trusted_flags(self, sender_domain: str, exclude_sha256: str) -> int:
        try:
            return self.store.count_trusted_flags(sender_domain, exclude_sha256)
        except Exception as exc:
            log_event("history_read_failed", error=type(exc).__name__, request_id=g.get("request_id"))
            raise  # analyze() turns this into history_status "unavailable" and a cautious verdict


def _from_environment() -> dict:
    connect = credentials.database_connect()
    if connect:
        history = PostgresHistory(connect)
        history.create_schema()
    else:
        history = MemoryHistory()
        log_event("history_in_memory", reason="DB_HOST not set; history is lost on restart")
    cache_url = os.environ.get("CACHE_URL")
    return {
        "history": history,
        "cache": ValkeyCache(cache_url) if cache_url else NoCache(),
        "auth": credentials.basic_auth_credentials(),
        "version": os.environ.get("APP_VERSION", "dev"),
    }


def create_app(
    *,
    history=None,
    cache=None,
    auth: Callable[[], tuple[str, str] | None] | None = None,
    version: str | None = None,
) -> Flask:
    if history is None and cache is None and auth is None:
        settings = _from_environment()
    else:
        settings = {"history": history or MemoryHistory(), "cache": cache or NoCache(), "auth": auth or (lambda: None), "version": version or "test"}
    history, cache, auth, version = settings["history"], settings["cache"], settings["auth"], settings["version"]
    try:
        if auth() is None:
            log_event("auth_disabled", reason="no Basic auth credentials configured; local use only")
    except Exception as exc:  # checked again on every request, which then fails closed
        log_event("auth_secret_unavailable", error=type(exc).__name__)

    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    @app.before_request
    def start():
        g.request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex
        g.started = time.perf_counter()
        g.log_fields = {}
        if request.path == "/healthz":
            return None
        try:
            expected = auth()
        except Exception as exc:  # fail closed: no credentials, no access
            log_event("auth_secret_unavailable", error=type(exc).__name__, request_id=g.request_id)
            return jsonify(error="authentication is unavailable"), 503
        if expected is not None and not _authorized(request.headers.get("Authorization", ""), expected):
            return jsonify(error="authentication required"), 401, {"WWW-Authenticate": 'Basic realm="phishing-detector", charset="UTF-8"'}
        return None

    @app.after_request
    def add_headers_and_log(response):
        response.headers.update(SECURITY_HEADERS)
        response.headers["X-Request-Id"] = g.get("request_id", "")
        duration = round((time.perf_counter() - g.get("started", time.perf_counter())) * 1000, 1)
        log_event("request", request_id=g.get("request_id"), method=request.method, path=request.path,
                  status=response.status_code, duration_ms=duration, **g.get("log_fields", {}))  # fmt: skip
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error=f"upload is larger than {MAX_UPLOAD_BYTES // 1024} KB"), 413

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=version)

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:name>")
    def static_file(name: str):
        return send_from_directory(STATIC, name)

    @app.post("/api/scan")
    def scan():
        upload = request.files.get("email")
        raw = upload.read() if upload else request.form.get("text", "").encode("utf-8")
        if not raw.strip():
            return jsonify(error="send an email file (field 'email') or pasted text (field 'text')"), 400

        # The cache holds only what depends on the email itself; the history check and the
        # score are computed on every request, so a later flag on the sender always shows.
        static, cached = None, False
        sha256 = hashlib.sha256(raw).hexdigest()  # the same id the detector reports
        try:
            if data := cache.get(sha256):
                static, cached = StaticAnalysis.from_dict(data), True
        except Exception as exc:  # the cache is an optimisation: carry on without it
            log_event("cache_failed", error=type(exc).__name__, request_id=g.request_id)
        if static is None:
            static = analyze_static(raw)
        result = finish(static, history=LoggedHistory(history)).to_dict()
        if not cached and result["history_status"] != "unavailable":  # nothing from an outage is kept
            try:
                cache.set(sha256, static.to_dict())
            except Exception as exc:
                log_event("cache_failed", error=type(exc).__name__, request_id=g.request_id)

        try:
            history.record(scan_row(result))
        except Exception as exc:  # the scan result still goes back to the user (D-70)
            log_event("history_write_failed", error=type(exc).__name__, request_id=g.request_id)

        g.log_fields = {"verdict": result["verdict"], "score": result["score"], "cache_hit": cached}
        return jsonify({**result, "cached": cached})

    @app.get("/api/history")
    def recent():
        limit = min(max(request.args.get("limit", 20, type=int) or 20, 1), MAX_HISTORY)
        try:
            rows = history.recent(limit)
        except Exception as exc:
            log_event("history_read_failed", error=type(exc).__name__, request_id=g.request_id)
            return jsonify(error="the scan history is unavailable"), 503
        return jsonify(
            scans=[
                {
                    "scanned_at": row["scanned_at"].isoformat(),
                    "email_sha256": row["email_sha256"],
                    "sender_domain": row["sender_domain"],
                    "verdict": row["verdict"],
                    "score": row["score"],
                    "signals": [s["id"] for s in row["signals"]],
                }
                for row in rows
            ]
        )

    return app


def _authorized(header: str, expected: tuple[str, str]) -> bool:
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        user, _, password = base64.b64decode(value, validate=True).decode("utf-8").partition(":")
    except (ValueError, UnicodeDecodeError):
        return False
    # Compare both parts in constant time, and always both, so timing doesn't reveal which one was wrong.
    user_ok = hmac.compare_digest(user.encode(), expected[0].encode())
    password_ok = hmac.compare_digest(password.encode(), expected[1].encode())
    return user_ok and password_ok

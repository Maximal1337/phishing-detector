"""The web app with in-memory stores: auth, limits, headers, history, cache and store failures."""

import base64
import io
import json
import re
from pathlib import Path

import pytest

from helpers import make_email
from webapp import STATIC, create_app
from webapp.storage import SCANS_COLUMNS, MemoryHistory

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
CREDS = ("reviewer", "correct horse")


def _basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


AUTH = _basic(*CREDS)


class DictCache:
    def __init__(self):
        self.items = {}

    def get(self, sha256):
        return self.items.get(sha256)

    def set(self, sha256, result):
        self.items[sha256] = json.loads(json.dumps(result))


class BrokenHistory(MemoryHistory):
    def __init__(self, fail_read=False, fail_write=False):
        super().__init__()
        self.fail_read, self.fail_write = fail_read, fail_write

    def count_trusted_flags(self, sender_domain, exclude_sha256):
        if self.fail_read:
            raise ConnectionError("database at 10.0.0.5 refused")  # values like this must not reach the log
        return super().count_trusted_flags(sender_domain, exclude_sha256)

    def record(self, row):
        if self.fail_write:
            raise ConnectionError("database at 10.0.0.5 refused")
        super().record(row)


def _client(history=None, cache=None):
    app = create_app(history=history or MemoryHistory(), cache=cache or DictCache(), auth=lambda: CREDS, version="abc123")
    return app.test_client()


def _scan(client, raw: bytes, **headers):
    return client.post("/api/scan", data={"email": (io.BytesIO(raw), "mail.eml")}, headers={**AUTH, **headers})


def test_healthz_needs_no_auth_and_no_database():
    response = _client(history=BrokenHistory(fail_read=True, fail_write=True)).get("/healthz")
    assert response.status_code == 200
    body = response.get_json()
    assert (body["status"], body["version"]) == ("ok", "abc123") and len(body["rules_version"]) == 12


@pytest.mark.parametrize("headers", [{}, _basic("reviewer", "wrong"), _basic("other", CREDS[1]), {"Authorization": "Bearer x"}])
def test_everything_else_needs_the_right_password(headers):
    client = _client()
    for path in ("/", "/api/history", "/static/app.js"):
        response = client.get(path, headers=headers)
        assert response.status_code == 401, path
        assert response.headers["WWW-Authenticate"].startswith("Basic")
    assert client.post("/api/scan", data={"text": "hello"}, headers=headers).status_code == 401
    assert client.get("/", headers=AUTH).status_code == 200


def test_auth_fails_closed_when_the_secret_cannot_be_read():
    def unavailable():
        raise TimeoutError

    client = create_app(history=MemoryHistory(), cache=DictCache(), auth=unavailable).test_client()
    assert client.get("/", headers=AUTH).status_code == 503
    assert client.get("/healthz").status_code == 200


def test_upload_over_1_mb_is_refused():
    response = _scan(_client(), b"x" * (2 * 1024 * 1024))
    assert response.status_code == 413
    assert "larger than" in response.get_json()["error"]


def test_security_headers_on_every_response():
    client = _client()
    for response in (client.get("/healthz"), client.get("/", headers=AUTH), client.get("/nope", headers=AUTH)):
        assert response.headers["Content-Security-Policy"] == "default-src 'self'; frame-ancestors 'none'"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["Cache-Control"] == "no-store"


def test_scan_returns_the_result_and_records_only_the_allowed_columns():
    history = MemoryHistory()
    response = _scan(_client(history=history), (SAMPLES / "phishing_spoofed_bank.eml").read_bytes())
    body = response.get_json()
    assert response.status_code == 200 and body["verdict"] == "phishing" and body["cached"] is False
    assert response.mimetype == "application/json"
    assert set(history.rows[0]) == set(SCANS_COLUMNS)
    assert all(set(s) == {"id", "weight"} for s in history.rows[0]["signals"])  # no evidence stored


def test_pasted_text_and_empty_input():
    client = _client()
    body = client.post("/api/scan", data={"text": "Verify your account now: http://192.0.2.1/login"}, headers=AUTH).get_json()
    assert body["input_type"] == "body_only" and "links.ip_host" in [i["id"] for i in body["indicators"]]
    assert client.post("/api/scan", data={"text": "  "}, headers=AUTH).status_code == 400


def test_html_and_script_in_an_email_come_back_as_plain_json_text():
    raw = make_email(subject="<script>alert(1)</script>", html='<a href="http://192.0.2.1/x"><script>alert(1)</script>Log in</a>')
    response = _scan(_client(), raw)
    assert response.mimetype == "application/json"
    assert b"<script>" not in response.data  # JSON escapes "<" as <, and the subject isn't returned at all


def test_ui_never_renders_html_or_links():
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "createElement(\"a\")", "eval("):
        assert unsafe not in script
    assert "textContent" in script
    page = (STATIC / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script>|\son\w+=|<a\s", page)  # no inline script, no inline handlers (CSP), no links


def test_second_identical_scan_is_served_from_the_cache_and_still_recorded():
    history, cache = MemoryHistory(), DictCache()
    client = _client(history=history, cache=cache)
    raw = (SAMPLES / "legit_receipt.eml").read_bytes()
    first, second = _scan(client, raw).get_json(), _scan(client, raw).get_json()
    assert (first["cached"], second["cached"]) == (False, True)
    assert first["verdict"] == second["verdict"]
    assert len(history.rows) == 2


def test_history_endpoint_lists_latest_scans_without_content():
    client = _client()
    _scan(client, (SAMPLES / "phishing_lookalike_sender.eml").read_bytes())
    scans = client.get("/api/history?limit=5", headers=AUTH).get_json()["scans"]
    assert len(scans) == 1
    assert set(scans[0]) == {"scanned_at", "email_sha256", "sender_domain", "verdict", "score", "signals"}


def test_history_read_failure_gives_a_cautious_verdict_and_a_log_line(capsys):
    raw = (SAMPLES / "phishing_lookalike_sender.eml").read_bytes()
    body = _scan(_client(history=BrokenHistory(fail_read=True)), raw).get_json()
    assert body["history_status"] == "unavailable"
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    failed = [e for e in events if e["event"] == "history_read_failed"]
    assert failed and failed[0]["error"] == "ConnectionError" and failed[0]["request_id"]
    assert "10.0.0.5" not in json.dumps(events)


def test_history_write_failure_still_returns_the_result(capsys):
    response = _scan(_client(history=BrokenHistory(fail_write=True)), (SAMPLES / "legit_receipt.eml").read_bytes())
    assert response.status_code == 200 and response.get_json()["verdict"] == "likely_legitimate"
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {"event": "history_write_failed", "error": "ConnectionError"}.items() <= next(e for e in events if e["event"] == "history_write_failed").items()
    assert "10.0.0.5" not in json.dumps(events)


def test_request_log_line_has_no_email_content(capsys):
    raw = (SAMPLES / "phishing_spoofed_bank.eml").read_bytes()
    _scan(_client(), raw)
    out = capsys.readouterr().out
    request_lines = [json.loads(line) for line in out.splitlines() if '"event": "request"' in line]
    assert request_lines[-1]["path"] == "/api/scan" and request_lines[-1]["verdict"] == "phishing"
    for phrase in ("unusual sign-in", "examp1ebank", "203.0.113", "Subject"):
        assert phrase not in out


def test_poisoning_rule_in_the_memory_store():
    history = MemoryHistory()
    row = {"email_sha256": "a" * 64, "sender_domain": "examplebank.test", "verdict": "phishing", "score": 80}
    history.record({**row, "signals": [{"id": "links.ip_host", "weight": 30}]})  # forged From: doesn't count
    assert history.count_trusted_flags("examplebank.test", "b" * 64) == 0
    history.record({**row, "signals": [{"id": "auth.dmarc_pass", "weight": 0}]})
    assert history.count_trusted_flags("examplebank.test", "b" * 64) == 1
    assert history.count_trusted_flags("examplebank.test", "a" * 64) == 0  # the same email doesn't flag itself


def test_cached_email_still_gets_a_fresh_history_check():
    history, cache = MemoryHistory(), DictCache()
    client = _client(history=history, cache=cache)
    shop = "shop.example.net"
    a = make_email(from_=f"Shop <news@{shop}>", subject="Your order", text="Hello, your order has shipped.\n")
    b = make_email(
        from_=f"Shop <billing@{shop}>",
        auth=[f"mx.example.org; spf=pass; dmarc=pass header.from={shop}"],
        text="Dear customer, verify your account within 24 hours or it will be suspended: http://192.0.2.10/login\n",
    )
    first = _scan(client, a).get_json()
    assert first["cached"] is False and "history.domain_flagged" not in [i["id"] for i in first["indicators"]]
    assert _scan(client, b).get_json()["verdict"] == "phishing"  # B proves it came from the domain (DMARC pass)
    again = _scan(client, a).get_json()
    assert again["cached"] is True
    assert "history.domain_flagged" in [i["id"] for i in again["indicators"]]
    assert again["score"] > first["score"]


def test_outage_result_is_not_cached_and_recovery_drops_the_raise():
    history, cache = BrokenHistory(fail_read=True), DictCache()
    client = _client(history=history, cache=cache)
    raw = make_email(text="Please reply within 24 hours.\n")  # urgency only: 10, raised to suspicious in an outage
    during = _scan(client, raw).get_json()
    assert (during["history_status"], during["raised_from"], during["verdict"]) == ("unavailable", "likely_legitimate", "suspicious")
    assert not cache.items  # nothing from the outage is kept
    history.fail_read = False
    after = _scan(client, raw).get_json()
    assert (after["history_status"], after["raised_from"], after["verdict"], after["cached"]) == ("ok", None, "likely_legitimate", False)
    assert _scan(client, raw).get_json()["cached"] is True


def test_another_detector_version_misses_the_cache():
    cache, raw = DictCache(), (SAMPLES / "legit_receipt.eml").read_bytes()

    def client(rules_version):
        return create_app(history=MemoryHistory(), cache=cache, auth=lambda: CREDS, rules_version=rules_version).test_client()

    old, new = client("aaaaaaaaaaaa"), client("bbbbbbbbbbbb")
    assert [_scan(old, raw).get_json()["cached"] for _ in range(2)] == [False, True]
    assert [_scan(new, raw).get_json()["cached"] for _ in range(2)] == [False, True]  # a rollout starts cold
    assert _scan(old, raw).get_json()["cached"] is True  # and a rollback finds its own entries
    assert sorted(k.split(":")[0] for k in cache.items) == ["aaaaaaaaaaaa", "bbbbbbbbbbbb"]


def test_rules_version_changes_with_any_rule_file(tmp_path):
    import shutil

    from phishing_detector import version

    copy = tmp_path / "pd"
    shutil.copytree(version.PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__"))
    before = version.fingerprint(copy)
    assert before == version.rules_version() and len(before) == 12
    brands = copy / "data" / "brands.txt"
    brands.write_text(brands.read_text(encoding="utf-8") + "newbrand newbrand.test" + chr(10), encoding="utf-8")
    assert version.fingerprint(copy) != before


def test_no_address_in_the_api_response_or_the_cache():
    cache = DictCache()
    client = _client(cache=cache)
    raw = make_email(to="bob@example.org", text="Verify: http://192.0.2.10/login?user=bob@example.org&u2=bob%40example.org" + chr(10))
    body = _scan(client, raw).get_json()  # the UI shows only fields of this response, via textContent
    assert "links.recipient_in_url" in [i["id"] for i in body["indicators"]]
    for text in (json.dumps(body), json.dumps(cache.items)):
        assert "bob" not in text and "[address]" in text

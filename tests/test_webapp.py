"""The web app with in-memory stores: auth, limits, headers, history, cache and store failures."""

import base64
import hashlib
import io
import json
import re
from pathlib import Path

import pytest

from helpers import make_email
from webapp import STATIC, create_app
from webapp.storage import SCANS_COLUMNS, MemoryHistory, NoCache

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

    def set(self, key, value, ttl):
        self.items[key] = json.loads(json.dumps(value))


class BrokenCache:
    def get(self, key):
        raise ConnectionError("cache down")

    def set(self, key, value, ttl):
        raise ConnectionError("cache down")


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
    assert response.get_json() == {"status": "ok"}  # no version without auth
    assert b"abc123" not in response.data


def test_version_is_behind_auth():
    client = _client()
    assert client.get("/api/version").status_code == 401
    body = client.get("/api/version", headers=AUTH).get_json()
    assert body["version"] == "abc123" and len(body["rules_version"]) == 12


def test_successful_health_checks_are_not_logged(capsys):
    client = _client()
    client.get("/healthz")
    client.get("/", headers=AUTH)
    paths = [json.loads(line)["path"] for line in capsys.readouterr().out.splitlines() if '"event": "request"' in line]
    assert paths == ["/"]


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
    assert sorted(k.split(":")[1] for k in cache.items if k.startswith("static:")) == ["aaaaaaaaaaaa", "bbbbbbbbbbbb"]


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


# --- domain reputation marks (flag:<rules version>:<domain>) ---------------

SHOP = "shop.example.net"


def _shop_mail(kind: str, n: int = 0) -> bytes:
    """legit: a plain mail from the shop; flag: phishing that passed DMARC for it (a trusted flag); forged: phishing without proof."""
    if kind == "legit":
        return make_email(from_=f"Shop <news{n}@{SHOP}>", subject=f"Order {n}", text=f"Hello, order {n} has shipped.\n")
    auth = [f"mx.example.org; spf=pass; dmarc=pass header.from={SHOP}"] if kind == "flag" else None
    text = f"Dear customer, verify your account within 24 hours or it will be suspended: http://192.0.2.{10 + n}/login\n"
    return make_email(from_=f"Shop <billing{n}@{SHOP}>", auth=auth, text=text)


def _flagged(body):
    return "history.domain_flagged" in [i["id"] for i in body["indicators"]]


def test_a_mark_is_written_after_the_commit_and_seen_by_another_instance():
    history, cache = MemoryHistory(), DictCache()
    first, second = _client(history=history, cache=cache), _client(history=history, cache=cache)
    assert not _flagged(_scan(first, _shop_mail("legit")).get_json())
    assert not [k for k in cache.items if k.startswith("flag:")]  # "not flagged" is never cached
    _scan(first, _shop_mail("flag"))
    assert [k for k in cache.items if k.startswith("flag:")] == [f"flag:{_rules_version(first)}:{SHOP}"]
    assert _flagged(_scan(second, _shop_mail("legit", 1)).get_json())


def test_forged_phishing_writes_no_mark():
    cache = DictCache()
    client = _client(cache=cache)
    assert _scan(client, _shop_mail("forged")).get_json()["verdict"] == "phishing"
    assert not [k for k in cache.items if k.startswith("flag:")]
    assert not _flagged(_scan(client, _shop_mail("legit")).get_json())


def test_database_down_with_a_mark_still_flags_without_a_raise():
    cache = DictCache()
    _scan(_client(cache=cache), _shop_mail("flag"))  # instance 1 writes the mark
    broken = BrokenHistory(fail_read=True, fail_write=True)
    body = _scan(_client(history=broken, cache=cache), _shop_mail("legit")).get_json()
    assert _flagged(body) and body["history_status"] == "ok" and body["raised_from"] is None


def test_database_down_without_a_mark_stays_cautious():
    body = _scan(_client(history=BrokenHistory(fail_read=True), cache=DictCache()), make_email(text="Please reply within 24 hours.\n")).get_json()
    assert (body["history_status"], body["raised_from"]) == ("unavailable", "likely_legitimate")


def test_cache_down_goes_to_the_database(capsys):
    history = MemoryHistory()
    client = _client(history=history, cache=BrokenCache())
    _scan(client, _shop_mail("flag"))
    body = _scan(client, _shop_mail("legit")).get_json()
    assert _flagged(body) and body["history_status"] == "ok"
    assert '"event": "cache_failed"' in capsys.readouterr().out


def test_an_email_never_flags_itself_through_its_mark():
    client = _client(cache=DictCache())
    raw = _shop_mail("flag")
    assert not _flagged(_scan(client, raw).get_json())
    assert not _flagged(_scan(client, raw).get_json())  # its own SHA-256 is in the mark


def test_a_new_rules_version_restores_the_mark_from_the_database():
    history, cache = MemoryHistory(), DictCache()
    old = create_app(history=history, cache=cache, auth=lambda: CREDS, rules_version="aaaaaaaaaaaa").test_client()
    new = create_app(history=history, cache=cache, auth=lambda: CREDS, rules_version="bbbbbbbbbbbb").test_client()
    _scan(old, _shop_mail("flag"))
    assert _flagged(_scan(new, _shop_mail("legit")).get_json())  # from the database
    assert cache.items[f"flag:bbbbbbbbbbbb:{SHOP}"]  # and the mark is back for the new version


def test_same_scans_give_the_same_verdicts_through_valkey_and_through_the_database_only():
    sequence = [
        _shop_mail("legit"), _shop_mail("forged"), _shop_mail("legit", 1), _shop_mail("flag"), _shop_mail("legit", 2),
        _shop_mail("flag"), _shop_mail("flag", 3), _shop_mail("legit"), make_email(text="Please reply within 24 hours.\n"),
        *[(SAMPLES / name).read_bytes() for name in ("phishing_lookalike_sender.eml", "legit_receipt.eml", "phishing_lookalike_sender.eml")],
    ]  # fmt: skip

    def verdicts(cache):
        client = _client(history=MemoryHistory(), cache=cache)
        return [(b["verdict"], b["score"], _flagged(b)) for b in (_scan(client, raw).get_json() for raw in sequence)]

    with_cache, database_only = verdicts(DictCache()), verdicts(NoCache())
    assert with_cache == database_only
    assert any(flagged for _, _, flagged in database_only)  # the sequence does exercise the history signal


def _rules_version(client):
    return client.get("/api/version", headers=AUTH).get_json()["rules_version"]



def test_an_entry_this_version_cannot_read_is_a_miss(capsys):
    cache = DictCache()
    client = _client(cache=cache)
    raw = (SAMPLES / "phishing_spoofed_bank.eml").read_bytes()
    key = f"static:{_rules_version(client)}:{hashlib.sha256(raw).hexdigest()}"
    cache.items[key] = {"verdict": "phishing", "score": 100, "indicators": []}  # an older full-result format
    body = _scan(client, raw).get_json()
    assert body["cached"] is False and body["verdict"] == "phishing" and body["indicators"]
    assert "static:" in json.dumps(list(cache.items)) and cache.items[key].get("findings")  # rewritten in the current format
    cache.items[f"flag:{_rules_version(client)}:{SHOP}"] = {"not": "a list"}
    assert not _flagged(_scan(client, _shop_mail("legit")).get_json())
    events = [json.loads(line)["event"] for line in capsys.readouterr().out.splitlines()]
    assert events.count("cache_decode_failed") >= 2 and "cache_failed" not in events


def test_undecodable_bytes_in_valkey_are_a_miss(capsys):
    class GarbageCache(DictCache):
        def get(self, key):
            return json.loads("{not json")  # what ValkeyCache.get raises on a corrupt value

    body = _scan(_client(cache=GarbageCache()), (SAMPLES / "legit_receipt.eml").read_bytes()).get_json()
    assert body["cached"] is False and body["verdict"] == "likely_legitimate"
    assert '"event": "cache_decode_failed"' in capsys.readouterr().out


def test_gunicorn_settings_and_json_log_lines():
    import logging

    from webapp import gunicorn_conf

    assert gunicorn_conf.control_socket_disable is True and gunicorn_conf.worker_tmp_dir == "/tmp"
    record = logging.LogRecord("gunicorn.error", logging.ERROR, __file__, 1, 'Worker failed: "%s"', ("boot",), None)
    assert json.loads(gunicorn_conf.JsonFormatter().format(record)) == {"event": "gunicorn", "level": "error", "message": 'Worker failed: "boot"'}


def test_database_down_through_the_real_pool_reports_unavailable():
    from webapp.credentials import DatabasePool
    from webapp.storage import PostgresHistory

    pool = DatabasePool({"host": "127.0.0.1", "port": 9, "dbname": "none", "connect_timeout": 1}, lambda: ("u", "p"), timeout=1)
    body = _scan(_client(history=PostgresHistory(pool.connection)), make_email(text="Please reply within 24 hours." + chr(10))).get_json()
    assert (body["history_status"], body["raised_from"], body["verdict"]) == ("unavailable", "likely_legitimate", "suspicious")

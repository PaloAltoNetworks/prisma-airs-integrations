"""The Databricks App Adapter (app.py), over real HTTP on 127.0.0.1.

Each test runs the App's Handler in a ThreadingHTTPServer on port 0. airs_adapter.handle is replaced by a fake that
records its arguments (autouse), so nothing here reaches AIRS or Databricks.
"""
import ast
import json
import logging
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

import app
from airs_core import REASON_FAILED, REASON_TOO_LARGE, US_URL
from helpers import SECRET

APP_DIR = Path(app.__file__).resolve().parent
CALLER = "7f3c2a10-5b8e-4d21-9a6f-3e0c1b2d4f58@1234567890123456"     # a made-up service principal @ workspace id
EVENT = {"event": {"type": "model_call", "api_type": "mlflow/v1/chat/completions", "trace_id": "tr-b-1",
                   "data": {"messages": [{"role": "user", "content": "hello"}]}},
         "config": {"policy_config": json.dumps({"profile": "example-airs-profile"})}}
BODY = json.dumps(EVENT).encode()
ALLOW = {"result": "ALLOW"}
DENY_FAILED = {"result": "DENY", "reason": REASON_FAILED}
DENY_TOO_LARGE = {"result": "DENY", "reason": REASON_TOO_LARGE}
NOT_FOUND = {"error": "not_found"}
REFUSED = {"error": "forbidden"}
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))    # 127.0.0.1 only, never a proxy


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("ALLOWED_CALLER", CALLER)
    monkeypatch.setenv("AIRS_API_KEY", SECRET)
    for name in ("AIRS_URL", "ALLOW_FAIL_OPEN", "ALLOW_UNSCANNED_PARTS", "DATABRICKS_APP_PORT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def calls(monkeypatch):
    """The fake handle: records each call's arguments and answers ALLOW."""
    seen = []

    def fake_handle(body, settings, scan=None, started=None):
        seen.append({"body": body, "settings": settings, "scan": scan, "started": started})
        return dict(ALLOW)
    monkeypatch.setattr(app, "handle", fake_handle)
    return seen


@pytest.fixture
def port():
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()
    thread.join(5)


class Reply:
    def __init__(self, status: int, headers, raw: bytes):
        self.status, self.raw = status, raw
        self.headers = {k.lower(): v for k, v in headers}

    def json(self):
        return json.loads(self.raw)


def call(port, path="/api/policy", body=BODY, method="POST", caller=CALLER, headers=None) -> Reply:
    """One request through urllib (it sends the body after the headers; the App reads all of it)."""
    sent = dict(headers or {})
    if caller is not None:
        sent["X-Forwarded-User"] = caller
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=None if method == "GET" else body,
                                 method=method, headers=sent)
    try:
        with NO_PROXY.open(req, timeout=10) as r:
            return Reply(r.status, r.headers.items(), r.read())
    except urllib.error.HTTPError as e:
        with e:
            return Reply(e.code, e.headers.items(), e.read())


def request(method="POST", path="/api/policy", body=b"", caller=CALLER, length=True, headers=()) -> bytes:
    """A request as bytes. headers: (name, value) pairs, so a name can repeat; length=False: no Content-Length."""
    lines = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1"]
    lines += [f"X-Forwarded-User: {caller}"] if caller is not None else []
    lines += [f"Content-Length: {len(body)}"] if length else []
    lines += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def raw(port, data: bytes, timeout=5.0, half_close=False) -> Reply:
    """Writes the request in one send and reads the answer to EOF. For small requests only: a body larger than the
    socket buffers is still being written when the App answers (see the lingering-close tests in section 7)."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(data)
        if half_close:
            s.shutdown(socket.SHUT_WR)
        answer = b""
        while chunk := s.recv(65536):
            answer += chunk
    head, _, body = answer.partition(b"\r\n\r\n")
    status_line, *lines = head.decode("latin-1").split("\r\n")
    return Reply(int(status_line.split()[1]), [tuple(p.strip() for p in x.split(":", 1)) for x in lines], body)


def app_lines(caplog) -> list:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "airs"]


# ---------------------------------------------------------------- 1. routes

@pytest.mark.parametrize("path", ["/api/policy", "/api/policy/", "/api/policy?x=1", "/api/policy/?a=b&c=d"])
def test_policy_is_served_with_one_trailing_slash_and_query_strings_ignored(port, calls, path):
    r = call(port, path)
    assert (r.status, r.json()) == (200, ALLOW) and [c["body"] for c in calls] == [EVENT]


@pytest.mark.parametrize("path", ["/api/policy//", "//api/policy", "/api/policy/x", "/api/policy/x/", "/api", "/",
                                  "/docs", "/openapi.json", "/API/policy", "/api/%70olicy"])
def test_other_post_paths_are_404_and_never_reach_handle(port, calls, path):
    r = raw(port, request(path=path, body=BODY))
    assert (r.status, r.json()) == (404, NOT_FOUND) and calls == []


@pytest.mark.parametrize("path", ["/", "/?x=1"])
def test_get_root_names_the_service(port, path):
    r = call(port, path, method="GET", caller=None)
    assert (r.status, r.json()) == (200, {"service": "dbx-airs-adapter"})


@pytest.mark.parametrize("method,path", [("GET", "/docs"), ("GET", "/openapi.json"), ("GET", "/redoc"),
                                         ("GET", "/api/policy"), ("GET", "//"), ("PUT", "/api/policy"),
                                         ("DELETE", "/api/policy"), ("PATCH", "/api/policy/"),
                                         ("OPTIONS", "/api/policy"), ("FOO", "/api/policy")])
def test_other_methods_and_docs_routes_are_404(port, calls, method, path):
    r = raw(port, request(method, path))
    assert (r.status, r.json()) == (404, NOT_FOUND) and calls == []


def test_head_is_404_with_headers_only(port):
    r = raw(port, request("HEAD", "/", caller=None, length=False))
    assert r.status == 404 and r.raw == b"" and int(r.headers["content-length"]) > 0
    assert r.headers["content-type"] == "application/json"


# ---------------------------------------------------------------- 2. caller check

@pytest.mark.parametrize("caller,allowed,why", [
    (None, CALLER, "missing"),
    ("someone-else@1234567890123456", CALLER, "mismatch"),
    (CALLER.upper(), CALLER, "mismatch"),
    ("", CALLER, "mismatch"),
    (CALLER, None, "not_configured"),
    (CALLER, "", "not_configured"),
    ("__ALLOWED_CALLER__", "__ALLOWED_CALLER__", "not_configured"),      # app.yaml placeholder, never rendered
])
def test_only_the_allowed_caller_gets_past_the_check(port, calls, monkeypatch, caplog, caller, allowed, why):
    if allowed is None:
        monkeypatch.delenv("ALLOWED_CALLER")
    else:
        monkeypatch.setenv("ALLOWED_CALLER", allowed)
    r = raw(port, request(caller=caller, body=BODY))
    assert (r.status, r.json()) == (403, REFUSED) and calls == []
    assert app_lines(caplog) == [{"event": "forbidden", "why": why}]
    if caller:
        assert caller not in caplog.text


def test_two_caller_headers_are_refused_even_when_both_match(port, calls, caplog):
    r = raw(port, request(body=BODY, headers=[("x-forwarded-user", CALLER)]))
    assert (r.status, r.json()) == (403, REFUSED) and calls == []
    assert app_lines(caplog) == [{"event": "forbidden", "why": "multiple"}]


def test_the_caller_check_comes_before_anything_else(port, calls, monkeypatch, caplog):
    monkeypatch.delenv("AIRS_API_KEY")
    monkeypatch.setenv("AIRS_URL", "http://192.0.2.1/v1/scan/sync/request")
    monkeypatch.setattr(app, "MAX_BODY", 8)
    r = raw(port, request(caller="someone-else@1234567890123456", body=BODY))
    assert (r.status, r.json()) == (403, REFUSED) and calls == []
    assert app_lines(caplog) == [{"event": "forbidden", "why": "mismatch"}]


def test_the_allowed_caller_reaches_handle_with_settings_from_the_environment(port, calls):
    r = call(port)
    assert (r.status, r.json()) == (200, ALLOW) and len(calls) == 1
    c, s = calls[0], calls[0]["settings"]
    assert c["body"] == EVENT and c["scan"] is None and isinstance(c["started"], float)
    assert c["started"] <= time.monotonic()
    assert s.api_key == SECRET and s.airs_url == US_URL and 0.5 <= s.budget_s <= 3.5
    assert s.allow_fail_open is False and s.allow_unscanned_parts is False


# ---------------------------------------------------------------- 3. credentials and header values are never logged

@pytest.mark.parametrize("auth", ["Bearer " + SECRET, "Basic " + SECRET])
def test_credentials_and_header_values_never_reach_logs_or_output(port, calls, caplog, capsys, auth):
    marker = "hdr-marker-5d1e"
    creds = {"Authorization": auth, "X-Forwarded-Access-Token": SECRET, "Cookie": "session=" + SECRET,
             "User-Agent": marker, "X-Forwarded-Email": marker + "@example.com", "X-Request-Id": marker}
    assert call(port, headers=creds).json() == ALLOW
    assert raw(port, request(caller=marker, body=BODY, headers=creds.items())).status == 403
    assert raw(port, request(path="/nope", body=BODY, headers=creds.items())).status == 404
    assert raw(port, request("GET", "/", headers=creds.items())).status == 200
    out = capsys.readouterr()
    text = caplog.text + out.out + out.err
    for value in (SECRET, marker, "Bearer", "Basic"):
        assert value not in text
    assert [c["body"] for c in calls] == [EVENT]


# ---------------------------------------------------------------- 4. the AIRS key comes from the environment

@pytest.mark.parametrize("value", [None, ""])
def test_a_missing_or_empty_airs_key_denies_without_scanning(port, calls, monkeypatch, caplog, value):
    if value is None:
        monkeypatch.delenv("AIRS_API_KEY")
    else:
        monkeypatch.setenv("AIRS_API_KEY", value)
    r = call(port)
    assert (r.status, r.json()) == (200, DENY_FAILED) and calls == []
    assert app_lines(caplog) == [{"event": "secrets_unavailable", "where": "policy"}]


def test_the_airs_key_is_read_on_every_request(port, calls, monkeypatch):
    call(port)
    monkeypatch.setenv("AIRS_API_KEY", "rotated-" + SECRET)
    call(port)
    assert [c["settings"].api_key for c in calls] == [SECRET, "rotated-" + SECRET]


# ---------------------------------------------------------------- 5. AIRS_URL

@pytest.mark.parametrize("value,url", [
    (None, US_URL), ("", US_URL), ("   ", US_URL),
    ("https://192.0.2.1/v1/scan/sync/request", "https://192.0.2.1/v1/scan/sync/request"),
    ("HTTPS://192.0.2.1/v1/scan/sync/request", "HTTPS://192.0.2.1/v1/scan/sync/request"),
    (" https://192.0.2.1/x ", "https://192.0.2.1/x"),
])
def test_airs_url_is_the_us_endpoint_unless_another_https_endpoint_is_set(port, calls, monkeypatch, value, url):
    if value is not None:
        monkeypatch.setenv("AIRS_URL", value)
    call(port)
    assert calls[0]["settings"].airs_url == url


@pytest.mark.parametrize("value", ["http://192.0.2.1/v1/scan/sync/request", "ftp://x", "service.api.example"])
def test_a_non_https_airs_url_denies_without_scanning(port, calls, monkeypatch, caplog, value):
    monkeypatch.setenv("AIRS_URL", value)
    r = call(port)
    assert (r.status, r.json()) == (200, DENY_FAILED) and calls == []
    assert app_lines(caplog) == [{"event": "config_invalid", "setting": "AIRS_URL"}]


# ---------------------------------------------------------------- 6. budget and switches

@pytest.mark.parametrize("spent,budget", [(0.0, 3.5), (0.8, 3.5), (2.0, 2.3), (4.2, 0.5), (9.0, 0.5)])
def test_the_scan_budget_is_what_is_left_of_4_3_s_kept_between_0_5_and_3_5(port, calls, monkeypatch, spent, budget):
    ticks = iter([100.0, 100.0 + spent])
    monkeypatch.setattr(app, "clock", lambda: next(ticks))
    call(port)
    assert calls[0]["settings"].budget_s == pytest.approx(budget) and calls[0]["started"] == 100.0


@pytest.mark.parametrize("fail_open,unscanned,expect", [
    ("true", None, (True, False)), (None, "true", (False, True)), ("true", "true", (True, True)),
    ("TRUE", "1", (False, False)), ("yes", "", (False, False)), (None, None, (False, False))])
def test_fail_open_and_unscanned_parts_switch_on_only_for_exactly_true(port, calls, monkeypatch, fail_open,
                                                                        unscanned, expect):
    for name, value in (("ALLOW_FAIL_OPEN", fail_open), ("ALLOW_UNSCANNED_PARTS", unscanned)):
        if value is not None:
            monkeypatch.setenv(name, value)
    call(port)
    s = calls[0]["settings"]
    assert (s.allow_fail_open, s.allow_unscanned_parts) == expect


# ---------------------------------------------------------------- 7. body

def test_a_body_over_the_cap_is_denied_unread_and_the_connection_closed(port, calls, monkeypatch, caplog):
    monkeypatch.setattr(app, "MAX_BODY", 64)
    assert len(BODY) > 64
    r = raw(port, request(body=BODY))
    assert (r.status, r.json()) == (200, DENY_TOO_LARGE) and calls == []
    assert r.headers["connection"] == "close"
    assert app_lines(caplog) == [{"event": "too_large"}]


@pytest.mark.parametrize("declared", [str(10 * 1024 * 1024 + 1), "9" * 5000])
def test_a_declared_size_over_10_mib_is_denied_without_waiting_for_the_body(port, calls, declared):
    assert app.MAX_BODY == 10 * 1024 * 1024
    started = time.monotonic()
    r = raw(port, request(length=False, headers=[("Content-Length", declared)]), timeout=3)
    assert (r.status, r.json()) == (200, DENY_TOO_LARGE) and calls == []
    assert time.monotonic() - started < 2


def test_a_body_exactly_at_the_cap_is_read(port, calls, monkeypatch):
    monkeypatch.setattr(app, "MAX_BODY", len(BODY))
    assert call(port).json() == ALLOW and [c["body"] for c in calls] == [EVENT]


@pytest.mark.parametrize("lengths", [[], ["abc"], ["-1"], ["1.5"], ["+5"], ["5", "5"], ["²"]])
def test_a_missing_or_invalid_content_length_means_an_empty_body(port, calls, lengths):
    r = raw(port, request(length=False, headers=[("Content-Length", v) for v in lengths]))
    assert (r.status, r.json()) == (200, ALLOW) and [c["body"] for c in calls] == [None]


@pytest.mark.parametrize("body", [b"{not json", b"\xc3\x28", b"", b"   "])
def test_a_body_that_is_not_json_reaches_handle_as_none(port, calls, body):
    r = call(port, body=body)
    assert (r.status, r.json()) == (200, ALLOW) and [c["body"] for c in calls] == [None]


def test_a_body_shorter_than_its_content_length_is_not_parsed(port, calls):
    r = raw(port, request(length=False, headers=[("Content-Length", "100")], body=b'{"a": 1}'), half_close=True)
    assert (r.status, r.json()) == (200, ALLOW) and [c["body"] for c in calls] == [None]


@pytest.mark.parametrize("path,caller,status,expect", [
    ("/api/policy/", CALLER, 200, DENY_TOO_LARGE),
    ("/api/policy/", "someone-else@1234567890123456", 403, REFUSED),
    ("/nope", CALLER, 404, NOT_FOUND)])
def test_a_body_left_unread_is_discarded_so_a_caller_that_sends_all_of_it_first_gets_the_answer(
        port, calls, monkeypatch, path, caller, status, expect):
    """urllib, http.client and proxies write the whole body before they read. This body is far larger than the socket
    buffers: closing with it unread would reset the connection mid-write, and the caller would never read the answer."""
    monkeypatch.setattr(app, "MAX_BODY", 1024)
    r = call(port, path, body=b"x" * (32 * 1024 * 1024), caller=caller)
    assert (r.status, r.json()) == (status, expect) and calls == []


def test_discarding_an_unread_body_stops_after_drain_s(port, monkeypatch):
    """The discard is bounded: a caller that goes on sending is cut off once DRAIN_S has passed."""
    monkeypatch.setattr(app, "MAX_BODY", 1024)
    monkeypatch.setattr(app, "DRAIN_S", 0.5)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(request(length=False, headers=[("Content-Length", str(1 << 30))]))
        answer = b""
        while chunk := s.recv(65536):           # the answer, then the App's end of sending
            answer += chunk
        assert json.loads(answer.partition(b"\r\n\r\n")[2]) == DENY_TOO_LARGE
        started = time.monotonic()
        with pytest.raises(OSError):            # the App reads on until DRAIN_S, then closes: a send then fails
            while time.monotonic() - started < 5:
                s.sendall(b"x" * 1024)
                time.sleep(0.02)
        elapsed = time.monotonic() - started
    assert 0.3 < elapsed < 3


# ---------------------------------------------------------------- 8. unexpected exceptions

def test_an_exception_answers_a_plain_deny_and_logs_only_its_class(port, monkeypatch, caplog):
    def boom(body, settings, scan=None, started=None):
        raise RuntimeError("boom-detail " + SECRET)
    monkeypatch.setattr(app, "handle", boom)
    r = call(port)
    assert (r.status, r.json()) == (200, DENY_FAILED)
    assert app_lines(caplog) == [{"event": "exception", "error_class": "RuntimeError"}]
    assert "boom-detail" not in caplog.text and b"boom" not in r.raw and b"Traceback" not in r.raw


def test_a_body_that_never_arrives_is_a_deny_after_the_socket_timeout(port, calls, monkeypatch, caplog):
    monkeypatch.setattr(app.Handler, "timeout", 0.3)
    r = raw(port, request(length=False, headers=[("Content-Length", "100")]))
    assert (r.status, r.json()) == (200, DENY_FAILED) and calls == []
    assert app_lines(caplog) == [{"event": "exception", "error_class": "TimeoutError"}]


# ---------------------------------------------------------------- 9. every answer: JSON, no-store, exact length

def test_every_answer_is_json_no_store_with_its_exact_length(port, monkeypatch):
    monkeypatch.setattr(app, "MAX_BODY", 4096)
    answers = [raw(port, request(body=BODY)),                                            # policy
               raw(port, request(body=BODY, caller="someone-else@1")),                   # forbidden
               raw(port, request(path="/nope", body=BODY)),                              # not found
               raw(port, request("GET", "/", caller=None)),                              # service
               raw(port, request(length=False, headers=[("Content-Length", "5000")])),   # too large
               raw(port, request("FOO", "/"))]                                           # unknown method
    assert [r.status for r in answers] == [200, 403, 404, 200, 200, 404]
    for r in answers:
        assert r.headers["content-type"] == "application/json" and r.headers["cache-control"] == "no-store"
        assert r.headers["content-length"] == str(len(r.raw)) and isinstance(r.json(), dict)


@pytest.mark.parametrize("method,path,caller,status,expect", [
    ("POST", "/<script>x</script>", CALLER, 404, NOT_FOUND),
    ("XYZZY", "/api/policy", CALLER, 404, NOT_FOUND),
    ("POST", "/api/policy", "<b>who</b>", 403, REFUSED)])
def test_error_bodies_are_fixed_and_never_echo_the_input(port, method, path, caller, status, expect):
    r = raw(port, request(method, path, caller=caller, body=b'{"echo": "me"}'))
    assert (r.status, r.json()) == (status, expect)
    assert not re.search(rb"script|XYZZY|who|echo", r.raw)


def test_a_request_the_server_cannot_parse_gets_the_fixed_json_answer(port, calls):
    """http.server's own error page is HTML that quotes the request (here: more than 100 headers)."""
    r = raw(port, request(headers=[(f"X-Extra-{i}", "v") for i in range(101)]))
    assert (r.status, r.json()) == (404, NOT_FOUND) and r.headers["content-type"] == "application/json"
    assert calls == []


# ---------------------------------------------------------------- 10. server

def test_a_silent_client_is_dropped_and_nothing_is_written_to_the_access_log(port, monkeypatch, capsys):
    assert app.Handler.timeout == 10
    monkeypatch.setattr(app.Handler, "timeout", 0.3)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"POST /api/pol")
        started = time.monotonic()
        assert s.recv(1024) == b""                    # closed by the App, nothing sent
        assert time.monotonic() - started < 3
    assert call(port).json() == ALLOW
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_main_listens_on_all_interfaces_at_the_apps_port_with_daemon_threads(monkeypatch, caplog):
    made, logging_config = [], {}

    class FakeServer:
        daemon_threads = False

        def __init__(self, address, handler):
            made.append({"address": address, "handler": handler})

        def serve_forever(self):
            made[-1]["daemon_threads"] = self.daemon_threads
    monkeypatch.setattr(app, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(app.logging, "basicConfig", lambda **kw: logging_config.update(kw))
    app.main()
    monkeypatch.setenv("DATABRICKS_APP_PORT", "8123")
    app.main()
    assert made == [{"address": ("0.0.0.0", 8000), "handler": app.Handler, "daemon_threads": True},
                    {"address": ("0.0.0.0", 8123), "handler": app.Handler, "daemon_threads": True}]
    assert logging_config["stream"] is sys.stdout and logging_config["level"] == logging.INFO
    source = (APP_DIR / "app.py").read_text()
    assert re.search(r'^if __name__ == "__main__":\n    main\(\)\s*$', source, re.M)


# ---------------------------------------------------------------- 11. module

def test_the_module_says_what_it_is_and_imports_handle_by_name():
    for word in ("Databricks App", "/api/policy", "X-Forwarded-User", "ALLOWED_CALLER", "AIRS_API_KEY", "AIRS_URL",
                 "ALLOW_FAIL_OPEN", "ALLOW_UNSCANNED_PARTS", "never"):
        assert word in app.__doc__
    tree = ast.parse((APP_DIR / "app.py").read_text())
    assert any(isinstance(n, ast.ImportFrom) and n.module == "airs_adapter" and [a.name for a in n.names] == ["handle"]
               for n in tree.body)


def test_the_app_uses_the_standard_library_only():
    tree = ast.parse((APP_DIR / "app.py").read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names - set(sys.stdlib_module_names) == {"airs_adapter", "airs_core"}


# ---------------------------------------------------------------- 12. app.yaml

def _env_entries(text: str) -> list:
    entries = []
    for line in text.splitlines():
        named = re.match(r"\s*-\s+name:\s*(\S.*)$", line)
        if named:
            entries.append({"name": named.group(1).strip().strip("'\"")})
        field = re.match(r"\s+(value|valueFrom):\s*(\S.*)$", line)
        if field and entries:
            entries[-1][field.group(1)] = field.group(2).strip().strip("'\"")
    return entries


def test_a_configured_app_yaml_still_passes():
    text = (APP_DIR / "app.yaml").read_text().replace("__ALLOWED_CALLER__", "7462981234567890@1234567890123456")
    text += '  - name: AIRS_URL\n    value: "https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"\n'
    text += '  - name: ALLOW_UNSCANNED_PARTS\n    value: "true"\n'
    check_app_yaml(text)


def test_app_yaml_takes_the_key_from_the_secret_resource_and_holds_no_key():
    check_app_yaml((APP_DIR / "app.yaml").read_text())


def check_app_yaml(text: str) -> None:
    assert re.search(r'^command:\s*\[\s*"python"\s*,\s*"app\.py"\s*\]\s*$', text, re.M)
    assert {m.group(1) for m in re.finditer(r"^([A-Za-z_]+):", text, re.M)} == {"command", "env"}
    entries = {e["name"]: e for e in _env_entries(text)}
    assert entries.pop("AIRS_API_KEY") == {"name": "AIRS_API_KEY", "valueFrom": "airs-key"}
    caller = entries.pop("ALLOWED_CALLER")
    assert set(caller) == {"name", "value"} and (caller["value"] == "__ALLOWED_CALLER__"
                                                 or re.fullmatch(r"\d+@\d+", caller["value"]))
    assert set(entries) <= {"AIRS_URL", "ALLOW_FAIL_OPEN", "ALLOW_UNSCANNED_PARTS"}       # the optional settings
    assert all(set(e) == {"name", "value"} for e in entries.values())                      # never from a secret here
    assert any(line.lstrip().startswith("#") and "never" in line for line in text.splitlines())
    assert SECRET not in text
    assert not re.search(r"[A-Za-z0-9+/=_-]{24,}", re.sub(r"https://\S+", "", text.replace("__ALLOWED_CALLER__", "")))


# ---- hang-ups, check order, headers never read

def test_a_caller_that_hangs_up_before_the_answer_leaves_one_log_line_and_no_traceback(port, monkeypatch, caplog,
                                                                                      capsys):
    """The Apps proxy gives up after Databricks' 5 s: the App's answer then hits a closed socket."""
    import struct

    def slow_handle(body, settings, scan=None, started=None):
        time.sleep(0.4)
        return dict(ALLOW)
    monkeypatch.setattr(app, "handle", slow_handle)
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(request(body=BODY))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))   # close with a reset
    s.close()
    time.sleep(1.0)
    assert "Traceback" not in capsys.readouterr().err
    assert {"event": "client_gone"} in app_lines(caplog)


def test_a_refused_caller_is_answered_at_once_without_waiting_for_its_body(port):
    """The caller check comes before the body is read: a refused caller's body is never waited for."""
    t0 = time.monotonic()
    r = raw(port, request(caller="someone-else@1", body=b"", length=False, headers=[("Content-Length", "100")]))
    assert r.status == 403 and r.json() == REFUSED
    assert time.monotonic() - t0 < 1.0


def test_the_app_never_reads_credentials_or_cookies_from_the_request(port, monkeypatch, calls):
    """Requirement 3, 'never read': the App touches no Authorization, X-Forwarded-Access-Token or Cookie value."""
    import http.client
    touched = []
    blocked = {"authorization", "x-forwarded-access-token", "cookie"}

    class Guarded(http.client.HTTPMessage):
        def get(self, name, failobj=None):
            touched.append(name.lower()) if name.lower() in blocked else None
            return super().get(name, failobj)

        def get_all(self, name, failobj=None):
            touched.append(name.lower()) if name.lower() in blocked else None
            return super().get_all(name, failobj)

        def __getitem__(self, name):
            touched.append(name.lower()) if name.lower() in blocked else None
            return super().__getitem__(name)

        def items(self):
            touched.append("<items>")
            return super().items()

        def values(self):
            touched.append("<values>")
            return super().values()
    monkeypatch.setattr(app.Handler, "MessageClass", Guarded)
    r = call(port, path="/api/policy/", headers={"Authorization": "Token abc", "X-Forwarded-Access-Token": "tok-xyz",
                                                 "Cookie": "session=1"})
    assert r.status == 200 and r.json() == ALLOW and len(calls) == 1
    assert touched == []


def test_the_airs_key_is_stripped(port, calls, monkeypatch):
    monkeypatch.setenv("AIRS_API_KEY", SECRET + "\n")
    call(port)
    assert [c["settings"].api_key for c in calls] == [SECRET]

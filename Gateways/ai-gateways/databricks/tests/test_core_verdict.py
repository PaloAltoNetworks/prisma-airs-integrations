import json

import pytest

from airs_core import (AirsAnswer, ConfigError, Settings, Verdict, build_scan_request, decide, log_line,
                       parse_policy_config)
from conftest import check_no_leak
from helpers import CARD, CFG, CFG_ALLOW, S, S_FAIL_OPEN, ans, outage

OUTAGE_REASON = "Prisma AIRS could not scan this request."


def test_clean_allow_allows():
    assert decide([ans("clean_allow")], CFG, S).result == "ALLOW"


def test_block_denies_with_types_and_report():
    v = decide([ans("dlp_block")], CFG, S)
    assert v.result == "DENY" and v.reason == "Blocked by Prisma AIRS: dlp. Report R-test-1."


def test_reply_block_names_reply_detection():
    assert decide([ans("reply_block")], CFG, S).reason == "Blocked by Prisma AIRS: dlp. Report R-test-2."


@pytest.mark.parametrize("name", ["allow_timeout_flag", "allow_error_flag", "allow_errors_list", "category_error",
                                  "category_timeout", "missing_action", "unknown_action"])
def test_partial_or_odd_answers_deny_even_with_fail_open(name):
    v = decide([ans(name)], CFG_ALLOW, S_FAIL_OPEN)
    assert v.result == "DENY" and v.reason == OUTAGE_REASON


def test_unreadable_answer_denies_even_with_fail_open():
    assert decide([AirsAnswer(200, None, "bad_json")], CFG_ALLOW, S_FAIL_OPEN).result == "DENY"


@pytest.mark.parametrize("cls", ["timeout", "connect", "http_5xx", "http_429"])
def test_outage_denies_by_default(cls):
    v = decide([outage(cls)], CFG, S)
    assert v.result == "DENY" and v.reason == OUTAGE_REASON


@pytest.mark.parametrize("cls", ["timeout", "connect", "http_5xx", "http_429"])
def test_outage_allows_only_with_both_keys(cls):
    assert decide([outage(cls)], CFG_ALLOW, S_FAIL_OPEN).result == "ALLOW"
    assert decide([outage(cls)], CFG_ALLOW, S).result == "DENY"
    assert decide([outage(cls)], CFG, S_FAIL_OPEN).result == "DENY"


@pytest.mark.parametrize("status,what", [(400, "request or profile not accepted by Prisma AIRS"),
                                         (401, "API key not accepted by Prisma AIRS"),
                                         (403, "API key not accepted by Prisma AIRS")])
def test_4xx_is_configuration_deny_even_with_fail_open(status, what):
    v = decide([AirsAnswer(status, {"error": {"message": "from airs"}}, "http_4xx")], CFG_ALLOW, S_FAIL_OPEN)
    assert v.result == "DENY" and v.reason == f"Prisma AIRS policy configuration error: {what}."


def test_block_wins_over_outage():
    assert decide([ans("dlp_block"), outage("timeout")], CFG_ALLOW, S_FAIL_OPEN).result == "DENY"


def test_reason_never_carries_airs_text_or_detected_data():
    v = decide([ans("dlp_block_with_masked_data")], CFG, S)
    assert "1111" not in v.reason and "masked" not in v.reason


def test_report_id_is_sanitized():
    a = AirsAnswer(200, dict(ans("dlp_block").body, report_id="R1\nInjected text " + "x" * 200), None)
    assert decide([a], CFG, S).reason == "Blocked by Prisma AIRS: dlp. Report R1Injectedtext" + "x" * 50 + "."


def test_scan_and_report_ids_are_kept():
    v = decide([ans("clean_allow"), ans("dlp_block")], CFG, S)
    assert v.scan_ids == ("scan-R-test-1", "scan-R-test-1") and v.report_ids == ("R-test-1", "R-test-1")


@pytest.mark.parametrize("raw", [None, "", "not json", "[]", '{"app_name": "x"}', '{"profile": ""}',
                                 '{"profile": "p", "on_error": "maybe"}',
                                 '{"profile": "p", "app_name": "  "}', '{"profile": "p", "app_name": 7}'])
def test_policy_config_missing_or_invalid(raw):
    with pytest.raises(ConfigError):
        parse_policy_config(raw)


def test_policy_config_reads_fields_and_ignores_unknown_keys():
    cfg = parse_policy_config('{"profile": "example-airs-profile", "on_error": "allow", "app_user_tag": "user", '
                              '"x": 1}')
    assert (cfg.profile, cfg.on_error, cfg.app_user_tag, cfg.app_name) == (
        "example-airs-profile", "allow", "user", "")


def test_settings_repr_hides_key():
    assert "sekret" not in repr(Settings(api_key="sekret-test-value-7Q2"))


def test_log_line_has_only_fixed_fields():
    line = json.loads(log_line("model_call", "mlflow/v1/chat/completions", "t", Verdict("ALLOW", None), 12))
    assert set(line) == {"event_type", "api_type", "target", "verdict", "scan_ids", "report_ids", "error_class",
                         "latency_ms", "trace_id"}


def test_build_scan_request_prompt():
    r = build_scan_request("prompt", "hi", CFG, {"tr_id": "t1", "app_user": "u1"})
    assert r["ai_profile"] == {"profile_name": "example-airs-profile"}
    assert r["contents"] == [{"prompt": "hi"}] and r["tr_id"] == "t1"
    assert r["metadata"] == {"app_name": "Databricks", "app_user": "u1"}


def test_app_name_is_databricks_then_the_customer_app():
    cfg = parse_policy_config('{"profile": "p", "app_name": " payroll-bot "}')
    assert build_scan_request("prompt", "hi", cfg, {})["metadata"]["app_name"] == "Databricks-payroll-bot"
    long = parse_policy_config('{"profile": "p", "app_name": "%s"}' % ("x" * 100))
    name = build_scan_request("prompt", "hi", long, {})["metadata"]["app_name"]
    assert name.startswith("Databricks-x") and len(name) == 64


def test_build_scan_request_response():
    assert build_scan_request("response", "ok", CFG, {})["contents"][0]["response"] == "ok"


def test_guard_catches_a_leak():
    with pytest.raises(AssertionError):
        check_no_leak("log line with " + CARD)



# ---------------------------------------------------------------- no redirects on the scan call

import http.server  # noqa: E402
import threading  # noqa: E402

from airs_core import scan_sync  # noqa: E402


class _Redirector(http.server.BaseHTTPRequestHandler):
    caught: list = []

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(int(self.path.rsplit("/", 1)[-1]))
        self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/catch")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        _Redirector.caught.append(self.headers.get("x-pan-token"))
        body = json.dumps({"action": "allow", "category": "benign"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed_and_denies_as_configuration(code):
    server = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _Redirector.caught = []
        settings = Settings(api_key="k-test", airs_url=f"http://127.0.0.1:{server.server_port}/scan/{code}")
        answer = scan_sync({"contents": [{"prompt": "hi"}]}, settings, 2.0)
        assert answer.error_class == "http_3xx" and _Redirector.caught == []
        v = decide([answer], CFG_ALLOW, S_FAIL_OPEN)                          # never fails open
        assert v.result == "DENY" and v.reason.startswith("Prisma AIRS policy configuration error: ")
    finally:
        server.shutdown()


@pytest.mark.parametrize("cls", ["brand_new_class", "http_1xx", ""])
def test_an_unknown_error_class_denies_and_never_fails_open(cls):
    for cfg, settings in ((CFG, S), (CFG_ALLOW, S_FAIL_OPEN)):
        assert decide([AirsAnswer(0, None, cls)], cfg, settings).result == "DENY"


# ---------------------------------------------------------------- local failures are never outages

import io  # noqa: E402
import urllib.request  # noqa: E402

import airs_core  # noqa: E402
from airs_core import OUTAGE_CLASSES, evaluate, extract  # noqa: E402
from helpers import ANSWERS  # noqa: E402


class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    """Stands in for the AIRS connection: blocks any body with the card, allows the rest; counts what was sent."""
    def __init__(self):
        self.sent = []

    def open(self, req, timeout=None):
        self.sent.append(req)
        req.header_items()
        answer = "dlp_block" if CARD in req.data.decode("utf-8") else "clean_allow"
        return _Resp(json.dumps(ANSWERS[answer]).encode())


def test_a_body_that_cannot_be_encoded_never_fails_open():
    answer = scan_sync({"contents": [{"prompt": "x"}], "metadata": {"ai_model": "\ud800"}}, S, 2.0)
    assert answer.error_class not in OUTAGE_CLASSES
    assert decide([answer], CFG_ALLOW, S_FAIL_OPEN).result == "DENY"


def test_a_scan_that_raises_is_not_an_outage():
    def boom(request, settings, timeout_s):
        raise RuntimeError("bug")
    plan = extract("openai/v1/chat/completions", {"messages": [{"role": "user", "content": "hi"}]}, "call", S)
    v = evaluate(plan, CFG_ALLOW, {}, S_FAIL_OPEN, boom)
    assert v.result == "DENY" and v.error_class != "fail_open"


@pytest.mark.parametrize("key", ["abc\n", "a b", "", "k\x00"])
def test_a_key_that_cannot_be_sent_is_a_configuration_error_and_nothing_is_sent(monkeypatch, key):
    fake = FakeOpener()
    monkeypatch.setattr(airs_core, "_OPENER", fake)
    answer = scan_sync({"contents": [{"prompt": "hi"}]}, Settings(api_key=key), 2.0)
    assert fake.sent == [] and answer.error_class == "config"
    v = decide([answer], CFG_ALLOW, Settings(api_key=key, allow_fail_open=True))
    assert v.result == "DENY" and v.reason.startswith("Prisma AIRS policy configuration error: ")


def test_metadata_and_tool_names_with_lone_surrogates_still_encode():
    r = build_scan_request("tool_input", "x", CFG, {"ai_model": "\ud800", "app_user": "claimed:\ud801"},
                           {"server": "s\ud802", "name": "n\ud803"})
    json.dumps(r, ensure_ascii=False).encode("utf-8")


def test_the_real_scan_call_sends_an_encodable_body_through_the_opener(monkeypatch):
    fake = FakeOpener()
    monkeypatch.setattr(airs_core, "_OPENER", fake)
    answer = scan_sync({"contents": [{"prompt": "my card " + CARD}]}, S, 2.0)
    assert len(fake.sent) == 1 and answer.body["action"] == "block"


def test_the_tests_never_reach_the_network():
    import urllib.error
    with pytest.raises(urllib.error.URLError, match="offline test"):
        urllib.request.urlopen("https://example.com", timeout=2)

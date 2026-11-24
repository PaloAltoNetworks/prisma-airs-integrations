import json
import logging
import time

import pytest

import airs_adapter
from airs_adapter import handle
from airs_core import AirsAnswer, Settings
from helpers import ANSWERS, CARD, SECRET, S

CFG_JSON = {"policy_config": json.dumps({"profile": "example-airs-profile"})}
CFG_TAG_JSON = {"policy_config": json.dumps({"profile": "example-airs-profile", "app_user_tag": "user"})}
OUTAGE = "Prisma AIRS could not scan this request."


class FakeScan:
    def __init__(self):
        self.requests = []

    def __call__(self, request, settings, timeout_s):
        self.requests.append(request)
        name = "dlp_block" if CARD in json.dumps(request) else "clean_allow"
        return AirsAnswer(200, dict(ANSWERS[name]), None)


class SlowScan:
    def __call__(self, request, settings, timeout_s):
        time.sleep(1.5)
        return AirsAnswer(200, dict(ANSWERS["clean_allow"]), None)


def model_call(text, policy_config=CFG_JSON, tags=None, extra=None):
    event = {"type": "model_call", "target": "svc-1", "api_type": "openai/v1/chat/completions",
             "context": {"request_tags": tags or {}},
             "data": {"model": "system.ai.m", "messages": [{"role": "user", "content": text}]}}
    event.update(extra or {})
    return {"event": event, "config": policy_config if isinstance(policy_config, dict) else
            {"policy_config": policy_config} if policy_config is not None else {}}


def test_documented_model_call_with_card_is_denied():
    body = {"event": {"type": "model_call", "target": "123e4567-e89b-42d3-a456-426614174000",
                      "api_type": "mlflow/v1/chat/completions", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
                      "context": {"request_tags": {"project": "p-1042"}},
                      "data": {"messages": [{"role": "system", "content": "You are a support agent."},
                                            {"role": "user", "content": "My card number is " + CARD +
                                             ". Please refund me."}], "max_tokens": 512}},
            "config": dict(CFG_JSON, phases="pre_call")}
    fake = FakeScan()
    assert handle(body, S, fake) == {"result": "DENY", "reason": "Blocked by Prisma AIRS: dlp. Report R-test-1."}
    assert fake.requests[0]["tr_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"


def test_clean_model_call_is_allowed():
    assert handle(model_call("Hello there"), S, FakeScan()) == {"result": "ALLOW"}


def test_model_result_scans_the_reply_as_response():
    body = {"event": {"type": "model_result", "api_type": "openai/v1/chat/completions",
                      "data": {"choices": [{"message": {"role": "assistant", "content": CARD}}]},
                      "request_data": {"messages": [{"role": "user", "content": "Hi"}]}}, "config": CFG_JSON}
    fake = FakeScan()
    assert handle(body, S, fake)["result"] == "DENY"
    assert [list(c) for c in fake.requests[0]["contents"]] == [["response"]]


def test_tool_call_and_tool_result_are_scanned():
    call = {"event": {"type": "tool_call", "target": "main.airs.tools",
                      "data": {"name": "card_note", "arguments": {"note": CARD}}}, "config": CFG_JSON}
    result = {"event": {"type": "tool_result", "target": "main.airs.tools",
                        "data": {"content": [{"type": "text", "text": CARD}]},
                        "request_data": {"name": "card_note", "arguments": {}}}, "config": CFG_JSON}
    assert handle(call, S, FakeScan())["result"] == "DENY"
    assert handle(result, S, FakeScan())["result"] == "DENY"


@pytest.mark.parametrize("pc", [None, "nope", '{"app_name": "x"}'])
def test_bad_policy_config_denies(pc):
    reason = handle(model_call("hi", policy_config=pc), S, FakeScan())["reason"]
    assert reason.startswith("Prisma AIRS policy configuration error: ")


def test_unknown_event_type_denies():
    r = handle({"event": {"type": "model_peek"}, "config": CFG_JSON}, S, FakeScan())
    assert r == {"result": "DENY", "reason": "Blocked: unsupported request format (model_peek)."}


@pytest.mark.parametrize("body", [None, [], {"event": "x"}, {"config": CFG_JSON}])
def test_malformed_bodies_deny(body):
    assert handle(body, S, FakeScan())["result"] == "DENY"


def test_deadline_holds_when_airs_hangs():
    fast = Settings(api_key=SECRET, budget_s=0.5)
    start = time.monotonic()
    r = handle(model_call("hi"), fast, SlowScan())
    assert time.monotonic() - start < 0.8 and r == {"result": "DENY", "reason": OUTAGE}


def test_exception_denies_with_fixed_reason(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret detail " + CARD)
    monkeypatch.setattr(airs_adapter, "extract", boom)
    assert handle(model_call("hi"), S, FakeScan()) == {"result": "DENY",
                                                        "reason": "Blocked: the Prisma AIRS policy failed."}


def test_claimed_user_from_tag():
    fake = FakeScan()
    handle(model_call("hi", policy_config=CFG_TAG_JSON, tags={"user": "al\x00ice" + "x" * 100}), S, fake)
    assert fake.requests[0]["metadata"]["app_user"] == "claimed:" + ("alice" + "x" * 100)[:64]


def test_no_user_without_the_setting():
    fake = FakeScan()
    handle(model_call("hi", tags={"user": "alice"}), S, fake)
    assert "app_user" not in fake.requests[0]["metadata"]


def test_unknown_fields_ignored():
    assert handle(model_call("hi", extra={"zzz": 1}), S, FakeScan()) == {"result": "ALLOW"}


def test_one_log_line_per_call(caplog):
    handle(model_call("hi"), S, FakeScan())
    lines = [r for r in caplog.records if r.name == "airs"]
    assert len(lines) == 1 and json.loads(lines[0].getMessage())["verdict"] == "ALLOW"



# ---------------------------------------------------------------- events without content, odd shapes

@pytest.mark.parametrize("data", ["missing", None, {}, "", []])
def test_a_model_call_without_content_denies_without_a_scan(data):
    body = model_call("hi")
    if data == "missing":
        del body["event"]["data"]
    else:
        body["event"]["data"] = data
    fake = FakeScan()
    r = handle(body, S, fake)
    assert r["result"] == "DENY" and fake.requests == []
    assert r["reason"].startswith("Blocked: unsupported request format (")


@pytest.mark.parametrize("event", [
    {"type": "tool_call", "target": "t"},
    {"type": "tool_call", "target": "t", "data": None},
    {"type": "tool_result", "target": "t", "request_data": {"name": "card_note"}},
    {"type": "model_result", "api_type": "openai/v1/chat/completions", "target": "t"},
])
def test_any_event_without_data_denies_without_a_scan(event):
    fake = FakeScan()
    assert handle({"event": event, "config": CFG_JSON}, S, fake)["result"] == "DENY" and fake.requests == []


def test_a_tool_call_with_no_arguments_stays_allowed():
    call = {"event": {"type": "tool_call", "target": "t", "data": {"name": "card_note", "arguments": {}}},
            "config": CFG_JSON}
    assert handle(call, S, FakeScan())["result"] == "ALLOW"


def test_tool_call_fields_beyond_arguments_are_scanned():
    call = {"event": {"type": "tool_call", "target": "t", "data": {
        "name": "note_echo", "arguments": {"note": "hello"}, "_meta": {"note": CARD}}}, "config": CFG_JSON}
    assert handle(call, S, FakeScan())["result"] == "DENY"


def test_latency_counts_from_the_callers_start_and_the_trace_id_is_logged(caplog):
    caplog.set_level(logging.INFO, logger="airs")
    body = model_call("hi", extra={"trace_id": "tr-123"})
    handle(body, S, FakeScan(), started=time.monotonic() - 2.0)
    line = json.loads([r.getMessage() for r in caplog.records if r.name == "airs"][-1])
    assert line["latency_ms"] >= 2000 and line["trace_id"] == "tr-123"


# ---------------------------------------------------------------- a lone surrogate never turns a block into an allow

import airs_core  # noqa: E402
from helpers import CFG_ALLOW, S_FAIL_OPEN  # noqa: E402
from test_core_verdict import FakeOpener  # noqa: E402

FAIL_OPEN_CFG = {"policy_config": json.dumps({"profile": "example-airs-profile", "on_error": "allow",
                                              "app_user_tag": "user"})}


@pytest.mark.parametrize("where", ["tool_property", "model", "tag", "odd_key"])
def test_a_lone_surrogate_in_a_copied_field_never_lets_a_card_through(monkeypatch, where):
    fake = FakeOpener()
    monkeypatch.setattr(airs_core, "_OPENER", fake)
    data = {"model": "m", "messages": [{"role": "user", "content": "my card is " + CARD}]}
    event = {"type": "model_call", "api_type": "mlflow/v1/chat/completions", "trace_id": "t", "data": data,
             "context": {"request_tags": {}}}
    if where == "tool_property":
        data["tools"] = [{"type": "function", "function": {"name": "f", "parameters": {
            "type": "object", "properties": {"note1\ud800": {"type": "string"}}}}}]
    elif where == "model":
        data["model"] = "\ud800"
    elif where == "tag":
        event["context"]["request_tags"] = {"user": "\ud800"}
    else:
        data["metadata"] = {"x 1\ud800": "v"}
    out = handle({"event": event, "config": FAIL_OPEN_CFG}, S_FAIL_OPEN)
    assert out["result"] == "DENY" and out["reason"].startswith("Blocked by Prisma AIRS") and fake.sent

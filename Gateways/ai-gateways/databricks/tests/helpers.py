"""Shared test values. The test card is the only sensitive-looking content the tests use."""
from airs_core import AirsAnswer, PolicyConfig, Settings

CARD = "4111 1111 1111 1111"
SECRET = "sekret-test-value-7Q2"

S = Settings(api_key=SECRET)
S_FAIL_OPEN = Settings(api_key=SECRET, allow_fail_open=True)
S_UNSCANNED_OK = Settings(api_key=SECRET, allow_unscanned_parts=True)
S_SMALL = Settings(api_key=SECRET, chunk_chars=10_000)   # small windows for chunking tests
CFG = PolicyConfig(profile="example-airs-profile")
CFG_ALLOW = PolicyConfig(profile="example-airs-profile", on_error="allow")

_FLAGS = {"agent": False, "dlp": False, "injection": False, "malicious_code": False, "toxic_content": False,
          "url_cats": False}


def _body(action="allow", category="benign", report="R-test-1", **extra):
    body = {"action": action, "category": category, "profile_name": "example-airs-profile",
            "scan_id": "scan-" + report, "report_id": report, "timeout": False, "error": False,
            "prompt_detected": dict(_FLAGS), "response_detected": {}}
    body.update(extra)
    return body


ANSWERS = {
    "clean_allow": _body(),
    "dlp_block": _body("block", "malicious", prompt_detected=dict(_FLAGS, dlp=True)),
    "dlp_block_with_masked_data": _body("block", "malicious", prompt_detected=dict(_FLAGS, dlp=True),
                                        prompt_masked_data={"data": "XXXX XXXX XXXX 1111 masked"}),
    "reply_block": _body("block", "malicious", report="R-test-2", response_detected={"dlp": True}),
    "allow_timeout_flag": _body(timeout=True),
    "allow_error_flag": _body(error=True),
    "allow_errors_list": _body(errors=[{"detector": "x"}]),
    "category_error": _body(category="error"),
    "category_timeout": _body(category="timeout"),
    "missing_action": {k: v for k, v in _body().items() if k != "action"},
    "unknown_action": _body(action="maybe"),
}


def ans(name):
    return AirsAnswer(200, dict(ANSWERS[name]), None)


def outage(cls):
    return AirsAnswer({"timeout": 0, "connect": 0, "http_5xx": 503, "http_429": 429}[cls], None, cls)

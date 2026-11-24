import json
import pathlib
import sys
import types

import pytest

from airs_core import AirsAnswer
from build_function import render_function_sql
from helpers import ANSWERS, CARD, CFG, S
import policy_entry
from policy_entry import python_policy_decision

ROOT = pathlib.Path(__file__).resolve().parents[1]
FN, SECRET_FQN = "main.airs.airs_policy", "main.airs.airs_api_key"
SETTINGS = {"profile": "example-airs-profile", "app_name": "", "on_error": "deny",
            "budget_s": 20.0, "allow_fail_open": False, "allow_unscanned_parts": False}


class FakeScan:
    def __init__(self):
        self.requests = []

    def __call__(self, request, settings, timeout_s):
        self.requests.append(request)
        return AirsAnswer(200, dict(ANSWERS["dlp_block" if CARD in json.dumps(request) else "clean_allow"]), None)


def ev(**kw):
    base = {"type": "request", "target": "main.airs.chat",
            "context": {"actor": {"run_as": "tester-app-id"}, "request_tags": {}}}
    base.update(kw)
    return base


def test_request_scans_the_full_payload_as_prompt():
    fake = FakeScan()
    d = python_policy_decision(ev(data={"messages": [{"role": "user", "content": "hi"}, {"role": "assistant",
                                                                                  "content": CARD}]}), S, CFG, fake)
    assert d == {"result": "DENY", "reason": "Blocked by Prisma AIRS: dlp. Report R-test-1."}
    assert list(fake.requests[0]["contents"][0]) == ["prompt"]
    assert fake.requests[0]["metadata"]["app_user"] == "tester-app-id"


def test_response_scans_as_response():
    fake = FakeScan()
    d = python_policy_decision(ev(type="response", data={"choices": [{"message": {"content": CARD}}]}), S, CFG, fake)
    assert d["result"] == "DENY" and list(fake.requests[0]["contents"][0]) == ["response"]


def test_clean_request_allows():
    assert python_policy_decision(ev(data={"messages": [{"role": "user", "content": "hi"}]}), S, CFG, FakeScan()) == \
        {"result": "ALLOW"}


def test_mcp_call_scans_tool_arguments():
    fake = FakeScan()
    e = ev(target="main.airs.tools")
    e["context"]["tool"] = {"name": "card_note", "arguments": {"note": CARD}}
    assert python_policy_decision(e, S, CFG, fake)["result"] == "DENY"
    assert "tool_event" in fake.requests[0]["contents"][0]


def test_unknown_shape_denies_listing_field_names_only():
    e = ev(type="response", zzz={"deep": CARD})
    e["context"]["tool"] = {"name": "card_note"}
    reason = python_policy_decision(e, S, CFG, FakeScan())["reason"]
    assert reason.startswith("Blocked: unsupported request format (fields ") and "context.tool" in reason
    assert "zzz" in reason and "4111" not in reason


def test_unknown_phase_denies():
    assert python_policy_decision(ev(type="peek", data={}), S, CFG, FakeScan())["result"] == "DENY"


def _sql():
    return render_function_sql((ROOT / "src" / "airs_core.py").read_text(encoding="utf-8"),
                               pathlib.Path(policy_entry.__file__).read_text(encoding="utf-8"),
                               dict(SETTINGS, airs_url="http://127.0.0.1:9/never"), FN, SECRET_FQN)


def test_sql_shape_and_no_key():
    sql = _sql()
    assert sql.startswith(f"CREATE OR REPLACE FUNCTION {FN}(event VARIANT, config VARIANT)")
    assert f"SECRETS ({SECRET_FQN})" in sql and "environment_version = '6'" in sql
    assert sql.count("$$") == 2 and "from __future__" not in sql and "from airs_core import" not in sql
    assert "example-airs-profile" in sql and "sekret" not in sql


def test_rendered_body_runs_end_to_end_offline(monkeypatch):
    """Runs the exact function body with a stand-in Databricks secrets module and VARIANT type."""
    body = _sql().split("$$")[1]
    src = "def _policy(event, config):\n" + "\n".join("    " + ln for ln in body.splitlines())
    secrets_mod = types.ModuleType("databricks.secrets")
    secrets_mod.get = lambda catalog, schema, key: "test-key-" + key
    monkeypatch.setitem(sys.modules, "databricks", types.ModuleType("databricks"))
    monkeypatch.setitem(sys.modules, "databricks.secrets", secrets_mod)

    class Variant:
        def __init__(self, value):
            self.value = value

        def toPython(self):
            return self.value

        @classmethod
        def parseJson(cls, text):
            return json.loads(text)

    scope: dict = {}
    exec(compile(src, "airs_policy", "exec"), scope)
    out = scope["_policy"](Variant(ev(data={"messages": [{"role": "user", "content": "hi"}]})), Variant({}))
    assert out == {"decision": {"result": "DENY", "reason": "Prisma AIRS could not scan this request."}}


def test_the_command_line_prints_the_function_with_the_lab_proven_defaults(capsys):
    import build_function
    build_function.main(["--function", "main.airs.airs_policy", "--secret", "main.airs.airs_api_key",
                         "--profile", "my-airs-profile"])
    sql = capsys.readouterr().out
    assert sql.startswith("CREATE OR REPLACE FUNCTION main.airs.airs_policy(event VARIANT, config VARIANT)")
    assert "SECRETS (main.airs.airs_api_key)" in sql and "profile='my-airs-profile'" in sql
    assert "budget_s=20.0" in sql and "allow_fail_open=False" in sql and "on_error='deny'" in sql
    assert "app_name=''" in sql and build_function.US_URL_PLACEHOLDER in sql


def test_the_command_line_takes_the_customer_app_name(capsys):
    import build_function
    build_function.main(["--function", "main.airs.airs_policy", "--secret", "main.airs.airs_api_key",
                         "--profile", "my-airs-profile", "--app-name", "payroll-bot"])
    assert "app_name='payroll-bot'" in capsys.readouterr().out


def test_the_command_line_refuses_missing_or_malformed_names():
    import build_function
    for argv in ([], ["--function", "main.airs.p", "--profile", "x"],
                 ["--function", "main.airs", "--secret", "main.airs.k", "--profile", "x"],
                 ["--function", "main.airs.p", "--secret", "main.airs.k", "--profile", "x", "--airs-url", "http://x"]):
        with pytest.raises(SystemExit):
            build_function.main(argv)


def test_no_setting_can_end_the_function_body_early():
    import build_function
    with pytest.raises(SystemExit):
        build_function.main(["--function", "main.airs.p", "--secret", "main.airs.k", "--profile", "x$$ DROP"])


# ---------------------------------------------------------------- MCP results, the key, the budget

def test_an_mcp_tool_result_is_scanned_as_tool_output():
    for with_tool in (True, False):
        fake = FakeScan()
        e = ev(type="response", target="main.airs.tools",
               data={"content": [{"type": "text", "text": "Vehicle found."}], "isError": False,
                     "structuredContent": {"make": "Ford", "model": CARD}})
        if with_tool:
            e["context"]["tool"] = {"name": "lookup", "arguments": {"plate": "AB12"}}
        assert python_policy_decision(e, S, CFG, fake)["result"] == "DENY"
        assert fake.requests[0]["contents"][0]["tool_event"]["output"], with_tool


def test_a_model_reply_is_still_scanned_as_a_reply():
    fake = FakeScan()
    python_policy_decision(ev(type="response", data={"id": "m1", "type": "message", "role": "assistant",
                                               "content": [{"type": "text", "text": CARD}]}), S, CFG, fake)
    assert list(fake.requests[0]["contents"][0]) == ["response"]


def test_the_function_strips_the_key_it_reads(monkeypatch):
    body = _sql().split("$$")[1]
    assert "_get_secret(catalog='main', schema='airs', key='airs_api_key') or '').strip()" in body


@pytest.mark.parametrize("budget", [float("nan"), float("inf"), 0, -1, 0.5, 26])
def test_the_budget_must_be_a_sane_number_of_seconds(budget):
    import build_function
    with pytest.raises(ValueError):
        render_function_sql("x = 1", "y = 2", dict(SETTINGS, budget_s=budget), FN, SECRET_FQN)
    with pytest.raises(SystemExit):
        build_function.main(["--function", "main.airs.p", "--secret", "main.airs.k", "--profile", "x",
                             "--budget", str(budget)])

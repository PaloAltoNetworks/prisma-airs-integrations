"""Python Policy: a Unity Gateway Python service policy event (as a dict) to a decision. Copied into the function
body after airs_core by build_function.py, which strips the import line below."""
import uuid

from airs_core import REASON_UNKNOWN, Verdict, evaluate, extract, extract_tool, unknown_format  # stripped when inlined


def _field_names(ev: dict) -> str:
    names = [k for k in ev if k != "context"] + ["context." + k for k in (ev.get("context") or {})]
    text = "/".join(sorted(str(n) for n in names))
    return "".join(c for c in text if c.isalnum() or c in "/._-")[:120]


REPLY_KEYS = frozenset({"choices", "candidates", "output", "role", "type", "model", "object"})


def _is_tool_result(data) -> bool:
    """An MCP CallToolResult: a content list, and none of a model reply's own fields."""
    return isinstance(data, dict) and isinstance(data.get("content"), list) and not (REPLY_KEYS & set(data))


def python_policy_decision(ev, settings, cfg, scan=None) -> dict:
    """Model services: the full payload in data (request -> prompt, response -> response).
    MCP calls: context.tool {name, arguments}. Anything else is denied, naming its field names only."""
    ev = ev if isinstance(ev, dict) else {}
    phase, ctx = ev.get("type"), ev.get("context") if isinstance(ev.get("context"), dict) else {}
    actor = (ctx.get("actor") or {}).get("run_as") if isinstance(ctx.get("actor"), dict) else None
    meta = {"tr_id": uuid.uuid4().hex}
    if isinstance(actor, str) and actor:
        meta["app_user"] = "".join(c for c in actor if c.isprintable())[:128]
    tool, tool_meta = ctx.get("tool"), None
    if phase not in ("request", "response"):
        plan = unknown_format(phase)
    elif phase == "response" and ev.get("data") is not None and (isinstance(tool, dict)
                                                                 or _is_tool_result(ev["data"])):
        name = tool.get("name") if isinstance(tool, dict) else None     # an MCP tool result: AIRS's tool checks
        plan = extract_tool("tool_output", name, ev["data"], settings)
        tool_meta = {"server": ev.get("target"), "name": name}
    elif ev.get("data") is not None:
        plan = extract("generic", ev["data"], "call" if phase == "request" else "result", settings)
    elif phase == "request" and isinstance(tool, dict) and "arguments" in tool:
        plan = extract_tool("tool_input", tool.get("name"), tool.get("arguments"), settings)
        tool_meta = {"server": ev.get("target"), "name": tool.get("name")}
    else:
        v = Verdict("DENY", REASON_UNKNOWN.format(format="fields " + _field_names(ev)), error_class="unknown_shape")
        return {"result": v.result, "reason": v.reason}
    v = evaluate(plan, cfg, meta, settings, scan, tool_meta)
    return {"result": "ALLOW"} if v.result == "ALLOW" else {"result": "DENY", "reason": v.reason}

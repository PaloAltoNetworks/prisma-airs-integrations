"""The External service policy handler, shared by the Databricks App Adapter and the AWS Adapter: Databricks'
{event, config} in, {result, reason} out.

Never raises and never logs content: one fixed log line per call (logger "airs").
"""
from __future__ import annotations

import logging
import re
import time
import uuid

import airs_core
from airs_core import (REASON_CONFIG, REASON_FAILED, ConfigError, PolicyConfig, Settings, Verdict, evaluate,
                       extract, extract_tool, last_text, log_line, parse_policy_config, unknown_format)

log = logging.getLogger("airs")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def meta_for(event: dict, cfg: PolicyConfig) -> dict:
    """AIRS metadata: tr_id from Databricks' trace id, a claimed user only if configured, the requested model."""
    trace = re.sub(r"[^A-Za-z0-9-]", "", str(event.get("trace_id") or ""))[:64]
    meta = {"tr_id": trace or uuid.uuid4().hex}
    if cfg.app_user_tag:
        tags = (event.get("context") or {}).get("request_tags") or {}
        value = tags.get(cfg.app_user_tag) if isinstance(tags, dict) else None
        if isinstance(value, str):
            clean = _CONTROL.sub("", value)[:64]
            if clean:
                meta["app_user"] = "claimed:" + clean
    data = event.get("data")
    if isinstance(data, dict) and isinstance(data.get("model"), str):
        meta["ai_model"] = _CONTROL.sub("", data["model"])[:128]
    return meta


def _verdict(event: dict, body: dict, settings: Settings, scan) -> Verdict:
    config = body.get("config")
    try:
        cfg = parse_policy_config(config.get("policy_config") if isinstance(config, dict) else None)
    except ConfigError as e:
        return Verdict("DENY", REASON_CONFIG.format(what=e.what), error_class="config")
    event_type, data, tool = event.get("type"), event.get("data"), None
    if event_type in ("model_call", "model_result", "tool_call", "tool_result") and (
            data is None or (event_type == "model_call" and data in ({}, "", []))):
        return unknown_format(f"{event_type}-without-data").deny     # Beta API: a moved field must not pass unscanned
    if event_type in ("model_call", "model_result"):
        plan = extract(event.get("api_type") or "", data, "call" if event_type == "model_call" else "result",
                       settings)
    elif event_type == "tool_call":
        name = data.get("name") if isinstance(data, dict) else None
        payload = {k: v for k, v in data.items() if k != "name"} if isinstance(data, dict) else data
        plan = extract_tool("tool_input", name, payload, settings)     # every field, not only arguments
        tool = {"server": event.get("target"), "name": name}
    elif event_type == "tool_result":
        request = event.get("request_data")
        name = request.get("name") if isinstance(request, dict) else None
        plan = extract_tool("tool_output", name, data, settings)
        tool = {"server": event.get("target"), "name": name}
    else:
        plan = unknown_format(event_type)
    meta = meta_for(event, cfg)
    if event_type == "model_result" and airs_core.RESPONSE_NEEDS_PROMPT:
        meta["context_prompt"] = last_text(event.get("request_data"))
    return evaluate(plan, cfg, meta, settings, scan, tool)


def handle(body, settings: Settings, scan=None, started: float | None = None) -> dict:
    """started: the caller's own time.monotonic() at request entry, so latency covers its secrets and token work."""
    start = time.monotonic() if started is None else started
    event = body.get("event") if isinstance(body, dict) else None
    event = event if isinstance(event, dict) else {}
    try:
        if not event:
            v = unknown_format("no event").deny
        else:
            v = _verdict(event, body, settings, scan)
    except Exception as e:
        v = Verdict("DENY", REASON_FAILED, error_class="exception:" + type(e).__name__)
    log.info(log_line(event.get("type"), event.get("api_type"), event.get("target"), v,
                      int((time.monotonic() - start) * 1000), event.get("trace_id")))
    return {"result": "ALLOW"} if v.result == "ALLOW" else {"result": "DENY", "reason": v.reason}

"""Prisma AIRS scanning core for Databricks Unity Gateway service policies (all three deployment options).

Standard library only: the same text runs inside a Unity Catalog Python function (the Python Policy), a Databricks
App (the Databricks App Adapter) and AWS Lambda (the AWS Adapter). It never logs or returns content, keys or AIRS
error text.
"""
from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field

US_URL = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"

# Set from scans of the exact request shapes against Prisma AIRS.
TOOL_MAPPING = "tool_event"          # "tool_event" or "text"
RESPONSE_NEEDS_PROMPT = False

REASON_BLOCK = "Blocked by Prisma AIRS: {types}. Report {report_id}."
REASON_OUTAGE = "Prisma AIRS could not scan this request."
REASON_CONFIG = "Prisma AIRS policy configuration error: {what}."
REASON_UNSCANNABLE = "Blocked: this request has content Prisma AIRS can't scan ({labels})."
REASON_TOO_LARGE = "Blocked: this request is too large to scan."
REASON_UNKNOWN = "Blocked: unsupported request format ({format})."
REASON_FAILED = "Blocked: the Prisma AIRS policy failed."

OUTAGE_CLASSES = frozenset({"timeout", "connect", "http_5xx", "http_429"})
DETECTION_FIELDS = ("prompt_detected", "response_detected", "tool_detected")


# ---------------------------------------------------------------- settings and policy configuration

class ConfigError(Exception):
    """A policy configuration problem. `what` is fixed text, never caller or AIRS content."""

    def __init__(self, what: str):
        super().__init__(what)
        self.what = what


@dataclass(frozen=True)
class Settings:
    """Deploy-time settings. allow_fail_open is the second key for on_error=allow."""
    api_key: str = field(repr=False)
    airs_url: str = US_URL
    budget_s: float = 3.5
    allow_fail_open: bool = False
    allow_unscanned_parts: bool = False
    chunk_chars: int = 50000        # measured: 50k chars scanned in ~0.8 s, 500k in ~2.8 s
    overlap_chars: int = 256
    max_chunks: int = 8
    max_urls_per_chunk: int = 100


@dataclass(frozen=True)
class PolicyConfig:
    """Per-attachment settings (External: the policy_config JSON; Python Policy: baked into the function)."""
    profile: str
    app_name: str = ""                  # the customer's app; AIRS gets Databricks-<app_name> (airs_app_name)
    on_error: str = "deny"
    app_user_tag: str | None = None


def parse_policy_config(raw) -> PolicyConfig:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise ConfigError("missing policy_config")
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except ValueError:
            raise ConfigError("policy_config is not valid JSON") from None
    else:
        data = raw
    if not isinstance(data, dict):
        raise ConfigError("policy_config must be a JSON object")
    profile = data.get("profile")
    if not isinstance(profile, str) or not profile.strip():
        raise ConfigError("policy_config needs a profile")
    on_error = data.get("on_error", "deny")
    if on_error not in ("deny", "allow"):
        raise ConfigError("on_error must be deny or allow")
    app_name = data.get("app_name", "")
    if not isinstance(app_name, str) or ("app_name" in data and not app_name.strip()):
        raise ConfigError("app_name must be text")
    tag = data.get("app_user_tag")
    if tag is not None and not isinstance(tag, str):
        raise ConfigError("app_user_tag must be text")
    return PolicyConfig(profile.strip(), app_name.strip()[:64], on_error, tag)


APP_PREFIX = "Databricks"


def airs_app_name(app: str) -> str:
    """The app_name AIRS receives: Databricks, or Databricks-<the customer's app>, at most 64 characters."""
    app = (app or "").strip()
    return (APP_PREFIX + "-" + app if app else APP_PREFIX)[:64]


# ---------------------------------------------------------------- AIRS client

@dataclass(frozen=True)
class AirsAnswer:
    status: int
    body: dict | None
    error_class: str | None     # timeout, connect, http_5xx, http_429, http_4xx, http_3xx, bad_json, or None


def _json_object(raw: bytes):
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is never followed: following it would send the API key to another host (urllib copies headers
    and turns a POST into a GET) and trust that host's answer. The 3xx comes back as an HTTPError instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _usable_key(key) -> bool:
    return isinstance(key, str) and bool(key) and all(33 <= ord(c) <= 126 for c in key)


def scan_sync(request: dict, settings: Settings, timeout_s: float) -> AirsAnswer:
    """One AIRS sync scan. Never raises; failures come back as an error class. Redirects are never followed.
    Local failures are never outages, so they never fail open: a key that can't be sent in a header, or an
    address urllib refuses, is 'config'; a body that can't be encoded is 'encode'."""
    if not _usable_key(settings.api_key):
        return AirsAnswer(0, None, "config")
    try:
        data = json.dumps(request, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        return AirsAnswer(0, None, "encode")
    try:
        req = urllib.request.Request(settings.airs_url, data=data, method="POST", headers={
            "x-pan-token": settings.api_key, "Content-Type": "application/json", "Accept": "application/json"})
        with _OPENER.open(req, timeout=max(0.1, timeout_s)) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
        except Exception:
            raw = b""
        cls = ("http_429" if e.code == 429 else "http_5xx" if e.code >= 500 else "http_3xx" if 300 <= e.code < 400
               else "http_4xx")
        return AirsAnswer(e.code, _json_object(raw), cls)
    except (socket.timeout, TimeoutError):
        return AirsAnswer(0, None, "timeout")
    except urllib.error.URLError as e:
        return AirsAnswer(0, None, "timeout" if isinstance(e.reason, (socket.timeout, TimeoutError)) else "connect")
    except ValueError:
        return AirsAnswer(0, None, "config")
    except Exception:
        return AirsAnswer(0, None, "connect")
    body = _json_object(raw)
    return AirsAnswer(status, body, None if body is not None else "bad_json")


def _utf8(value: str) -> str:
    """Lone surrogates (valid in JSON escapes, not in UTF-8) become '?', so a scan body always encodes."""
    return value.encode("utf-8", "replace").decode("utf-8")


def build_scan_request(kind: str, text: str, cfg: PolicyConfig, meta: dict, tool: dict | None = None) -> dict:
    """The AIRS sync scan body for one chunk. kind: prompt, response, tool_input or tool_output."""
    content: dict = {}
    if kind == "prompt":
        content["prompt"] = text
    elif kind == "response":
        content["response"] = text
        if RESPONSE_NEEDS_PROMPT and meta.get("context_prompt"):
            content["prompt"] = meta["context_prompt"]
    elif kind in ("tool_input", "tool_output"):
        if TOOL_MAPPING == "tool_event":
            tool = tool or {}
            content["tool_event"] = {
                "metadata": {"ecosystem": "mcp", "method": "tools/call",
                             "server_name": _utf8(str(tool.get("server") or "unknown")[:128]),
                             "tool_invoked": _utf8(str(tool.get("name") or "unknown")[:128])},
                ("input" if kind == "tool_input" else "output"): text}
        else:
            content["prompt" if kind == "tool_input" else "response"] = text
    else:
        raise ValueError("unknown scan kind")
    metadata = {"app_name": _utf8(airs_app_name(cfg.app_name))}
    for key in ("app_user", "ai_model"):
        if meta.get(key):
            metadata[key] = _utf8(str(meta[key]))
    return {"tr_id": meta.get("tr_id") or uuid.uuid4().hex, "ai_profile": {"profile_name": cfg.profile},
            "metadata": metadata, "contents": [content]}


# ---------------------------------------------------------------- verdicts

@dataclass(frozen=True)
class Verdict:
    result: str                  # ALLOW or DENY
    reason: str | None
    scan_ids: tuple = ()
    report_ids: tuple = ()
    error_class: str | None = None


def _safe_id(value) -> str:
    return re.sub(r"[^A-Za-z0-9-]", "", str(value))[:64] or "unknown"


def _true_keys(obj, out: set) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if v is True:
                out.add(re.sub(r"[^a-z0-9_]", "", str(k).lower())[:40])
            elif isinstance(v, (dict, list)):
                _true_keys(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _true_keys(item, out)


def _detected_types(body: dict) -> str:
    found: set = set()
    for name in DETECTION_FIELDS:
        _true_keys(body.get(name), found)
    found.discard("")
    return ", ".join(sorted(found)) or "policy"


def _clean_allow(body: dict | None) -> bool:
    return (isinstance(body, dict) and body.get("action") == "allow"
            and body.get("category") not in ("error", "timeout")
            and body.get("timeout", False) is False and body.get("error", False) is False
            and not body.get("errors"))


def decide(answers: list, cfg: PolicyConfig, settings: Settings) -> Verdict:
    """One verdict for all chunks. Precedence: block, AIRS 4xx, partial or odd answer, outage, allow."""
    bodies = [a.body for a in answers if isinstance(a.body, dict)]
    scan_ids = tuple(_safe_id(b["scan_id"]) for b in bodies if b.get("scan_id"))
    report_ids = tuple(_safe_id(b["report_id"]) for b in bodies if b.get("report_id"))

    def verdict(result, reason, error_class):
        return Verdict(result, reason, scan_ids, report_ids, error_class)

    for a in answers:
        if a.error_class is None and isinstance(a.body, dict) and a.body.get("action") == "block":
            return verdict("DENY", REASON_BLOCK.format(types=_detected_types(a.body),
                                                       report_id=_safe_id(a.body.get("report_id", ""))), "blocked")
    for a in answers:
        if a.error_class == "http_4xx":
            what = ("API key not accepted by Prisma AIRS" if a.status in (401, 403)
                    else "request or profile not accepted by Prisma AIRS")
            return verdict("DENY", REASON_CONFIG.format(what=what), "config")
    for a in answers:
        if a.error_class == "config":
            return verdict("DENY", REASON_CONFIG.format(what="Prisma AIRS key or address not usable"), "config")
    for a in answers:
        if a.error_class == "http_3xx":
            return verdict("DENY", REASON_CONFIG.format(what="unexpected redirect from the Prisma AIRS address"),
                           "config")
    for a in answers:
        if a.error_class == "bad_json" or (a.error_class is None and not _clean_allow(a.body)):
            return verdict("DENY", REASON_OUTAGE, "partial")
    for a in answers:
        if a.error_class is not None and a.error_class not in OUTAGE_CLASSES:
            return verdict("DENY", REASON_OUTAGE, "unknown_error")
    if any(a.error_class in OUTAGE_CLASSES for a in answers):
        if cfg.on_error == "allow" and settings.allow_fail_open:
            return verdict("ALLOW", None, "fail_open")
        return verdict("DENY", REASON_OUTAGE, "outage")
    return verdict("ALLOW", None, None)


# ---------------------------------------------------------------- extraction and chunking

KNOWN_API_TYPES = ("mlflow/v1/chat/completions", "mlflow/v1/embeddings", "mlflow/v1/responses",
                   "openai/v1/chat/completions", "openai/v1/embeddings", "openai/v1/responses",
                   "anthropic/v1/messages", "gemini/v1/generateContent", "gemini/v1/streamGenerateContent",
                   "cursor/v1/chat/completions")
GENERIC = "generic"                 # the walker alone (the Python Policy)
NON_CONTENT_KEYS = frozenset({"model", "role", "type", "object", "finish_reason", "stop_reason", "mimeType",
                              "mime_type", "media_type"})   # labels; 'id' strings are scanned (they can carry text)
NON_TEXT_PART_TYPES = frozenset({"image_url", "input_image", "image", "input_audio", "audio", "file", "input_file",
                                 "video", "input_video", "image_generation_call", "computer_screenshot"})
IMAGE_EVENT_PREFIX = "response.image_generation_call."    # streamed image generation (partial images)
TOOL_USE_TYPES = frozenset({"tool_use", "server_tool_use", "mcp_tool_use"})
MIN_NUMBER_DIGITS = 7               # numbers this long are scanned (cards, accounts); counts and limits are not
TEXT_PART_TYPES = frozenset({"text", "input_text", "output_text"})   # parts of one message: joined with no break
TEXT_DOCUMENT_SOURCES = frozenset({"text", "content"})
NON_TEXT_KEYS = {"inlineData": "inline_data", "inline_data": "inline_data", "fileData": "file_data",
                 "file_data": "file_data"}
_URL = re.compile(r"(?i)https?://")


@dataclass(frozen=True)
class Chunk:
    kind: str                       # prompt, response, tool_input or tool_output
    text: str


@dataclass(frozen=True)
class ScanPlan:
    chunks: tuple = ()
    unscannable: tuple = ()
    deny: Verdict | None = None


def _deny(reason: str, error_class: str) -> Verdict:
    return Verdict("DENY", reason, (), (), error_class)


def _format_name(value) -> str:
    return re.sub(r"[^A-Za-z0-9/._-]", "", str(value))[:64] or "unknown"


def _is_int_list(value) -> bool:
    return bool(value) and all(isinstance(x, int) and not isinstance(x, bool) for x in value)


def _number_text(value):
    """A number long enough to carry a card or account number, as text; None for short numbers and booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value in (float("inf"),
                                                                                                     float("-inf")):
        return None
    text = str(value) if isinstance(value, int) else repr(value)
    return text if sum(c.isdigit() for c in text) >= MIN_NUMBER_DIGITS else None


def _odd_key(k) -> bool:
    """A key that isn't a plain field name (it has a digit or a space): a card can hide there, so it is scanned."""
    return isinstance(k, str) and any(c.isdigit() or c.isspace() for c in k)


def _walk_except(node: dict, skip: tuple, texts: list, unscannable: set) -> None:
    for k, v in node.items():
        if k not in skip:
            if _odd_key(k):
                _add(texts, k)
            _walk(v, texts, unscannable, k)


def _add(texts: list, value: str) -> None:
    if value.strip():
        texts.append(value.encode("utf-8", "replace").decode("utf-8"))


def _is_chat_chunks(node: list) -> bool:
    return bool(node) and all(isinstance(x, dict) and isinstance(x.get("choices"), list) for x in node) and any(
        isinstance(c, dict) and isinstance(c.get("delta"), dict) for x in node for c in x["choices"])


def _join_chat_chunks(node: list, texts: list, unscannable: set) -> None:
    """A streamed chat reply as chunks: content, reasoning and each tool call's arguments joined per choice."""
    content, reasoning, tools = {}, {}, {}
    for chunk in node:
        _walk_except(chunk, ("choices",), texts, unscannable)
        for choice in chunk["choices"]:
            if not isinstance(choice, dict):
                continue
            i = choice.get("index", 0)
            _walk_except(choice, ("delta", "index", "finish_reason", "logprobs"), texts, unscannable)
            delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
            if isinstance(delta.get("content"), str):
                content[i] = content.get(i, "") + delta["content"]
            for rk in ("reasoning_content", "reasoning"):
                if isinstance(delta.get(rk), str):
                    reasoning[i] = reasoning.get(i, "") + delta[rk]
            for tc in delta.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                slot = tools.setdefault((i, tc.get("index", 0)), {"name": "", "args": ""})
                slot["name"] += fn.get("name") if isinstance(fn.get("name"), str) else ""
                slot["args"] += fn.get("arguments") if isinstance(fn.get("arguments"), str) else ""
                _walk_except(tc, ("function", "index", "type"), texts, unscannable)
            _walk_except(delta, ("content", "tool_calls", "role", "reasoning_content", "reasoning"), texts,
                         unscannable)
    for joined in (*content.values(), *reasoning.values(), *(f"{t['name']} {t['args']}" for t in tools.values())):
        _add(texts, joined)


def _is_response_events(node: list) -> bool:
    return bool(node) and all(isinstance(x, dict) and str(x.get("type", "")).startswith("response.") for x in node)


def _join_response_events(node: list, texts: list, unscannable: set) -> None:
    """Streamed Responses events: text and function-call argument deltas joined per output item."""
    joined = {}
    for ev in node:
        kind = ev.get("type")
        if kind in ("response.output_text.delta", "response.function_call_arguments.delta",
                    "response.reasoning_text.delta") and isinstance(ev.get("delta"), str):
            slot = (kind, ev.get("output_index", 0), ev.get("content_index", 0), ev.get("item_id"))
            joined[slot] = joined.get(slot, "") + ev["delta"]
            _walk_except(ev, ("delta", "type", "item_id", "output_index", "content_index", "sequence_number"),
                         texts, unscannable)
        else:
            _walk(ev, texts, unscannable)
    for value in joined.values():
        _add(texts, value)


def _is_gemini_stream(node: list) -> bool:
    return bool(node) and all(isinstance(x, dict) and isinstance(x.get("candidates"), list) for x in node)


def _join_gemini_stream(node: list, texts: list, unscannable: set) -> None:
    """Streamed Gemini responses: each candidate's text parts joined across the stream."""
    joined = {}
    for resp in node:
        _walk_except(resp, ("candidates",), texts, unscannable)
        for cand in resp["candidates"]:
            if not isinstance(cand, dict):
                continue
            i = cand.get("index", 0)
            _walk_except(cand, ("content", "index"), texts, unscannable)
            content = cand.get("content") if isinstance(cand.get("content"), dict) else {}
            _walk_except(content, ("parts", "role"), texts, unscannable)
            for part in content.get("parts") or []:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    joined[i] = joined.get(i, "") + part["text"]
                    _walk_except(part, ("text",), texts, unscannable)
                else:
                    _walk(part, texts, unscannable)
    for value in joined.values():
        _add(texts, value)


def _walk_list(node: list, texts: list, unscannable: set, key) -> None:
    """Consecutive text parts are one text (a message's content, joined with no break); other items one by one."""
    buffer = None
    for item in node:
        if isinstance(item, dict) and isinstance(item.get("text"), str) and (
                item.get("type") in TEXT_PART_TYPES or ("type" not in item and key == "parts")):
            buffer = (buffer or "") + item["text"]
            _walk_except(item, ("text", "type"), texts, unscannable)
            continue
        if buffer is not None:
            _add(texts, buffer)
            buffer = None
        _walk(item, texts, unscannable, key)
    if buffer is not None:
        _add(texts, buffer)


def _has_content(node) -> bool:
    """Any non-blank string (keys included) or any number, anywhere."""
    if isinstance(node, str):
        return bool(node.strip())
    if isinstance(node, bool) or node is None:
        return False
    if isinstance(node, (int, float)):
        return True
    if isinstance(node, dict):
        return any((isinstance(k, str) and k.strip()) or _has_content(v) for k, v in node.items())
    if isinstance(node, list):
        return any(_has_content(v) for v in node)
    return False


def _json_text(node) -> str:
    try:
        text = json.dumps(node, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        text = str(node)
    return _utf8(text)


def _add_json(texts: list, node) -> None:
    """A tool-defined object, all of it (keys and label-like fields included), as one JSON text."""
    if _has_content(node):
        texts.append(_json_text(node))


def _tool_defined(node: dict, k, v, parent_key) -> bool:
    """Values a tool or a caller defines, not the API: their field names mean nothing to us, so none is skipped
    and nothing inside is taken for a binary part."""
    if not isinstance(v, (dict, list)):
        return False
    if k in ("structuredContent", "arguments"):
        return True
    if k == "input" and node.get("type") in TOOL_USE_TYPES:
        return True
    return (k == "args" and parent_key in ("functionCall", "function_call")) or (
        k == "response" and parent_key in ("functionResponse", "function_response"))


def _walk(node, texts: list, unscannable: set, key=None) -> None:
    """Collect every string except under NON_CONTENT_KEYS, long numbers and odd keys; label parts AIRS can't scan
    (binary) instead of reading them. Text carried inside resources and content documents is read."""
    if isinstance(node, str):
        if key not in NON_CONTENT_KEYS and node.strip():
            texts.append(node.encode("utf-8", "replace").decode("utf-8"))
    elif isinstance(node, (int, float)):
        num = _number_text(node)
        if num is not None and key not in NON_CONTENT_KEYS:
            texts.append(num)
    elif isinstance(node, dict):
        part_type = node.get("type")
        if isinstance(part_type, str) and part_type in NON_TEXT_PART_TYPES:
            unscannable.add(part_type)
            return
        if isinstance(part_type, str) and part_type.startswith(IMAGE_EVENT_PREFIX):
            unscannable.add("image_generation_call")
            return
        if part_type == "document":
            source = node.get("source")
            if not (isinstance(source, dict) and source.get("type") in TEXT_DOCUMENT_SOURCES):
                unscannable.add("document")
                return
        if part_type == "resource" and isinstance(node.get("resource"), dict):
            res = node["resource"]
            if "blob" in res:
                unscannable.add("resource_blob")
            for rk, rv in res.items():
                if rk != "blob":
                    _walk(rv, texts, unscannable, rk)
            for k, v in node.items():
                if k != "resource":
                    _walk(v, texts, unscannable, k)
            return
        for k in node:
            if _odd_key(k):
                _add(texts, k)
        for k, v in node.items():
            if k in NON_TEXT_KEYS:
                unscannable.add(NON_TEXT_KEYS[k])
            elif _tool_defined(node, k, v, key):
                _add_json(texts, v)
            elif not (k in NON_CONTENT_KEYS and not isinstance(v, (dict, list))):
                _walk(v, texts, unscannable, k)
    elif isinstance(node, list):
        if key == "input" and (_is_int_list(node) or (node and all(isinstance(x, list) and _is_int_list(x)
                                                                    for x in node))):
            unscannable.add("token_ids")
            return
        if _is_chat_chunks(node):
            _join_chat_chunks(node, texts, unscannable)
        elif _is_response_events(node):
            _join_response_events(node, texts, unscannable)
        elif _is_gemini_stream(node):
            _join_gemini_stream(node, texts, unscannable)
        else:
            _walk_list(node, texts, unscannable, key)


def _chunk_count(n: int, settings: Settings) -> int:
    if n <= settings.chunk_chars:
        return 1
    step = settings.chunk_chars - settings.overlap_chars
    return 1 + -(-(n - settings.chunk_chars) // step)


def _split_urls(text: str, settings: Settings) -> list:
    starts = [m.start() for m in _URL.finditer(text)]
    limit = settings.max_urls_per_chunk
    if len(starts) <= limit:
        return [text]
    pieces, s = [], 0
    while True:
        inside = [u for u in starts if u >= s]
        if len(inside) <= limit:
            pieces.append(text[s:])
            return pieces
        cut = inside[limit]
        pieces.append(text[s:cut])
        s = max(cut - settings.overlap_chars, inside[limit - 1] + 1)


def chunk(kind: str, text: str, settings: Settings) -> list:
    """Overlapping windows (so nothing hides across a boundary), each with at most max_urls_per_chunk URLs."""
    size, step = settings.chunk_chars, settings.chunk_chars - settings.overlap_chars
    windows, start = [], 0
    while True:
        windows.append(text[start:start + size])
        if start + size >= len(text):
            break
        start += step
    return [Chunk(kind, piece) for w in windows for piece in _split_urls(w, settings)]


def _plan(kind: str, texts: list, labels: tuple, settings: Settings) -> ScanPlan:
    text = "\n".join(texts)
    if _chunk_count(len(text), settings) > settings.max_chunks:
        return ScanPlan(unscannable=labels, deny=_deny(REASON_TOO_LARGE, "too_large"))
    chunks = chunk(kind, text, settings)
    if len(chunks) > settings.max_chunks:
        return ScanPlan(unscannable=labels, deny=_deny(REASON_TOO_LARGE, "too_large"))
    return ScanPlan(chunks=tuple(chunks), unscannable=labels)


def extract(api_type: str, body, phase: str, settings: Settings) -> ScanPlan:
    """What to scan in a model request (phase call) or reply (phase result)."""
    if api_type != GENERIC and api_type not in KNOWN_API_TYPES:
        return ScanPlan(deny=_deny(REASON_UNKNOWN.format(format=_format_name(api_type)), "unknown_format"))
    if phase == "result" and api_type.endswith("/embeddings"):
        return ScanPlan()
    texts, unscannable = [], set()
    _walk(body, texts, unscannable)
    labels = tuple(sorted(unscannable))
    if labels and not settings.allow_unscanned_parts:
        return ScanPlan(unscannable=labels,
                        deny=_deny(REASON_UNSCANNABLE.format(labels=", ".join(labels)), "unscannable"))
    if not texts:
        if phase == "call" and not labels:
            return ScanPlan(deny=_deny(REASON_UNSCANNABLE.format(labels="no text found"), "no_text"))
        return ScanPlan(unscannable=labels)
    return _plan("prompt" if phase == "call" else "response", texts, labels, settings)


def _without_binary(result, unscannable: set):
    """A tool result without the content parts AIRS can't read (images, audio, files, resource blobs), each
    labelled. Only the result's own content list holds such parts; everything else is tool-defined text."""
    if not isinstance(result, dict) or not isinstance(result.get("content"), list):
        return result
    parts = []
    for p in result["content"]:
        kind = p.get("type") if isinstance(p, dict) else None
        if isinstance(kind, str) and kind in NON_TEXT_PART_TYPES:
            unscannable.add(kind)
            parts.append({"type": kind})
        elif kind == "resource" and isinstance(p.get("resource"), dict) and "blob" in p["resource"]:
            unscannable.add("resource_blob")
            parts.append({**p, "resource": {k: v for k, v in p["resource"].items() if k != "blob"}})
        else:
            parts.append(p)
    return {**result, "content": parts}


def extract_tool(kind: str, name: str, payload, settings: Settings) -> ScanPlan:
    """What to scan in an MCP tool call (kind tool_input) or tool result (kind tool_output). Tool data is defined by
    the tool, so all of it is scanned, as JSON: no field name is skipped. A result's binary content parts are
    labelled (denied unless allow_unscanned_parts) and left out of the scan."""
    unscannable: set = set()
    kept = _without_binary(payload, unscannable) if kind == "tool_output" else payload
    labels = tuple(sorted(unscannable))
    if labels and not settings.allow_unscanned_parts:
        return ScanPlan(unscannable=labels,
                        deny=_deny(REASON_UNSCANNABLE.format(labels=", ".join(labels)), "unscannable"))
    if not _has_content(kept):
        return ScanPlan(unscannable=labels)
    return _plan(kind, [_utf8(kept) if isinstance(kept, str) else _json_text(kept)], labels, settings)


def unknown_format(value) -> ScanPlan:
    """A plan that denies an event or api_type this core doesn't know, naming it (sanitized)."""
    return ScanPlan(deny=_deny(REASON_UNKNOWN.format(format=_format_name(value)), "unknown_format"))


def last_text(body, limit: int = 2000) -> str:
    """The last string in a body (the latest user text in a request), for RESPONSE_NEEDS_PROMPT."""
    texts: list = []
    _walk(body, texts, set())
    return texts[-1][:limit] if texts else ""


# ---------------------------------------------------------------- evaluation

def evaluate(plan: ScanPlan, cfg: PolicyConfig, meta: dict, settings: Settings, scan=None,
             tool: dict | None = None) -> Verdict:
    """Scan every chunk in parallel under one deadline (settings.budget_s), then decide."""
    if plan.deny is not None:
        return plan.deny
    if not plan.chunks:
        return Verdict("ALLOW", None)
    scan = scan or scan_sync
    deadline = time.monotonic() + settings.budget_s
    requests = [build_scan_request(c.kind, c.text, cfg, meta, tool) for c in plan.chunks]
    pool = ThreadPoolExecutor(max_workers=min(8, len(requests)))
    try:
        futures = [pool.submit(scan, r, settings, max(0.1, deadline - time.monotonic())) for r in requests]
        done, _ = wait(futures, timeout=max(0.0, deadline - time.monotonic()))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    answers = []
    for f in futures:
        if f not in done:
            answers.append(AirsAnswer(0, None, "timeout"))
            continue
        try:
            answers.append(f.result())
        except Exception:                       # a bug, not an outage: it must never fail open
            answers.append(AirsAnswer(0, None, "exception"))
    return decide(answers, cfg, settings)


# ---------------------------------------------------------------- logging

def _short(value, limit: int = 128):
    if value is None:
        return None
    return re.sub(r"[\x00-\x1f\x7f]", "", str(value))[:limit]


def log_line(event_type, api_type, target, v: Verdict, latency_ms: int, trace_id=None) -> str:
    """The only line logged per call: fixed fields, never content. The trace id ties retries together."""
    return json.dumps({"event_type": _short(event_type), "api_type": _short(api_type), "target": _short(target),
                       "verdict": v.result, "scan_ids": list(v.scan_ids), "report_ids": list(v.report_ids),
                       "error_class": v.error_class, "latency_ms": int(latency_ms),
                       "trace_id": _short(trace_id, 64)})

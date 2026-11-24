"""AWS Adapter: the adapter on AWS Lambda behind an API Gateway HTTP API (payload v2).

POST /oauth/token  client credentials -> short-lived token (the Databricks control plane calls this)
POST /policy       Bearer token -> airs_adapter.handle (Databricks calls <base_path>/, so one trailing slash is
                   forgiven; the API's $default route brings that path here)
Anything else      404. Secrets come from SSM Parameter Store at cold start, never from environment values.
If they can't be read, /policy still answers HTTP 200 with a DENY (callers see non-2xx bodies) and /oauth/token 503.
Databricks allows 5 s per call, so time spent before the scan (cold start, SSM) comes out of the AIRS budget.
Settings (environment, no secrets): ALLOW_FAIL_OPEN, ALLOW_UNSCANNED_PARTS ("true" or not), and optional AIRS_URL
(another https:// scan endpoint; the US one by default; anything else denies without scanning).
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
import urllib.parse

from airs_adapter import handle
from airs_core import REASON_FAILED, US_URL, Settings
from token_issuer import AuthError, check_client, issue, parse_client_auth, verify

logging.getLogger().setLevel(logging.INFO)
log = logging.getLogger("airs")
ISSUER = os.environ.get("TOKEN_ISSUER", "").strip() or "dbx-airs"   # the iss claim of our tokens
TOTAL_BUDGET_S = 4.3     # of Databricks' 5 s; the rest is API Gateway and the network
MAX_TOKEN_BODY = 4096
PARAMS = {"client_id": "CLIENT_ID_PARAM", "client_secret": "CLIENT_SECRET_PARAM",
          "signing_key": "SIGNING_KEY_PARAM", "airs_api_key": "AIRS_KEY_PARAM"}
SECRETS_TTL_S = 300      # a rotation in SSM reaches every warm container within 5 minutes
_cache: dict = {}
_loaded: dict = {"at": None}
_client: dict = {}


def now() -> int:
    return int(time.time())


def clock() -> float:
    return time.monotonic()


def _ssm_client():
    if "ssm" not in _client:
        import boto3
        from botocore.config import Config
        _client["ssm"] = boto3.client("ssm", config=Config(connect_timeout=1, read_timeout=2,
                                                           retries={"max_attempts": 2, "mode": "standard"}))
    return _client["ssm"]


def load_secrets() -> dict:
    """SecureString parameters named by environment variables (the names are not secret), re-read every
    SECRETS_TTL_S. A missing parameter or an SSM error raises: callers deny (policy) or answer 503 (token)."""
    if not _cache or _loaded["at"] is None or clock() - _loaded["at"] >= SECRETS_TTL_S:
        names = {key: os.environ[env] for key, env in PARAMS.items()}
        got = _ssm_client().get_parameters(Names=list(names.values()), WithDecryption=True)
        values = {p["Name"]: p["Value"] for p in got["Parameters"]}
        fresh = {key: values[name].strip() for key, name in names.items()}     # a file's final newline is no part
        _cache.clear()
        _cache.update(fresh)
        _loaded["at"] = clock()
    return _cache


_PLAIN_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,40}$")


def shape_of(node, depth: int = 0):
    """The outline of a value for the shape probe: field names, types, list lengths and string lengths. Never a
    value: strings become {"str": length}, keys that aren't plain field names become "<key>"."""
    if depth > 8:
        return "..."
    if isinstance(node, bool):
        return "bool"
    if isinstance(node, (int, float)):
        return "num"
    if node is None:
        return "null"
    if isinstance(node, str):
        return {"str": len(node)}
    if isinstance(node, list):
        return {"list": len(node), "items": [shape_of(x, depth + 1) for x in node[:3]]}
    if isinstance(node, dict):
        out = {}
        for k, v in list(node.items())[:30]:
            out[k if isinstance(k, str) and _PLAIN_KEY.match(k) else "<key>"] = shape_of(v, depth + 1)
        return out
    return type(node).__name__


def _shape_line(body) -> None:
    """SHAPE_LOG=true (set by hand for a probe, then removed): one log line with the outline of the event's data."""
    if os.environ.get("SHAPE_LOG") != "true" or not isinstance(body, dict) or not isinstance(body.get("event"), dict):
        return
    ev = body["event"]
    log.info(json.dumps({"event": "shape", "event_type": str(ev.get("type"))[:40],
                         "api_type": str(ev.get("api_type"))[:60], "trace_id": str(ev.get("trace_id"))[:64],
                         "data": shape_of(ev.get("data")), "request_data": shape_of(ev.get("request_data")),
                         "config_keys": sorted((body.get("config") or {}).keys())
                         if isinstance(body.get("config"), dict) else None}))


def _resp(status: int, body: dict) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body)}


def _body(event: dict) -> str:
    raw = event.get("body") or ""
    return base64.b64decode(raw).decode("utf-8", "replace") if event.get("isBase64Encoded") else raw


def _unavailable(where: str, e: Exception) -> None:
    log.warning(json.dumps({"event": "secrets_unavailable", "where": where, "error_class": type(e).__name__}))


def _token(event: dict) -> dict:
    if len(event.get("body") or "") > 2 * MAX_TOKEN_BODY:
        return _resp(400, {"error": "invalid_request"})
    raw = _body(event)
    try:
        if len(raw) > MAX_TOKEN_BODY:
            raise ValueError("body too large")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True, max_num_fields=10).items()}
    except ValueError:
        return _resp(400, {"error": "invalid_request"})
    try:
        secrets = load_secrets()
    except Exception as e:  # SSM down, throttled or a parameter missing
        _unavailable("token", e)
        return _resp(503, {"error": "temporarily_unavailable"})
    try:
        cid, secret = parse_client_auth(event.get("headers") or {}, form)
    except AuthError as e:
        return _resp(401 if str(e) == "invalid_client" else 400, {"error": str(e)})
    if not check_client(cid, secret, secrets["client_id"], secrets["client_secret"]):
        return _resp(401, {"error": "invalid_client"})
    return _resp(200, issue(secrets["signing_key"].encode("utf-8"), ISSUER, now()))


def airs_url():
    """The scan URL: the US endpoint unless the deploy-time setting AIRS_URL names another https:// endpoint.
    None when AIRS_URL is set but not https: the policy then denies without scanning (fail closed)."""
    u = os.environ.get("AIRS_URL", "").strip()
    if not u:
        return US_URL
    return u if u.lower().startswith("https://") else None


def _policy(event: dict, t0: float) -> dict:
    try:
        secrets = load_secrets()
    except Exception as e:  # SSM down, throttled or a parameter missing: still a 200 DENY with the fixed reason
        _unavailable("policy", e)
        return _resp(200, {"result": "DENY", "reason": REASON_FAILED})
    auth = (event.get("headers") or {}).get("authorization", "")
    token = auth[7:] if auth[:7].lower() == "bearer " else ""
    if not token or not verify(token, secrets["signing_key"].encode("utf-8"), ISSUER, now()):
        return _resp(401, {"error": "invalid_token"})
    try:
        body = json.loads(_body(event))
    except ValueError:
        body = None
    _shape_line(body)
    url = airs_url()
    if url is None:
        log.warning(json.dumps({"event": "config_invalid", "setting": "AIRS_URL"}))
        return _resp(200, {"result": "DENY", "reason": REASON_FAILED})
    budget = max(0.5, min(3.5, TOTAL_BUDGET_S - (clock() - t0)))
    settings = Settings(api_key=secrets["airs_api_key"], airs_url=url, budget_s=budget,
                        allow_fail_open=os.environ.get("ALLOW_FAIL_OPEN") == "true",
                        allow_unscanned_parts=os.environ.get("ALLOW_UNSCANNED_PARTS") == "true")
    return _resp(200, handle(body, settings, started=t0))


def handler(event, context):
    t0 = clock()
    http = (event.get("requestContext") or {}).get("http") or {}
    path = event.get("rawPath") or ""
    if len(path) > 1 and path.endswith("/") and not path.endswith("//"):
        path = path[:-1]
    route = (http.get("method"), path)
    if route == ("POST", "/oauth/token"):
        return _token(event)
    if route == ("POST", "/policy"):
        return _policy(event, t0)
    return _resp(404, {"error": "not_found"})

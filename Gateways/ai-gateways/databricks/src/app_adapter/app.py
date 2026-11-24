"""Databricks App Adapter: the adapter as a Databricks App (standard library only). Unity AI Gateway calls it as an
External service policy through the Databricks Apps proxy, which signs in as one service principal (OAuth M2M).

POST /api/policy  (one trailing slash forgiven: Databricks calls <base_path>/) -> airs_adapter.handle -> HTTP 200
                  {"result": "ALLOW"} or {"result": "DENY", "reason": ...}; any failure is a 200 DENY
GET /             200 {"service": "dbx-airs-adapter"}
Anything else     404 {"error": "not_found"}; there are no docs routes.
Caller check, first: X-Forwarded-User (set by the proxy) must be exactly ALLOWED_CALLER, else 403 {"error": "forbidden"}.
Settings (environment): AIRS_API_KEY (Databricks injects it from the App's secret resource; read on every request),
ALLOWED_CALLER, optional AIRS_URL (another https:// scan endpoint; the US one by default; anything else denies),
ALLOW_FAIL_OPEN and ALLOW_UNSCANNED_PARTS ("true" or not). Secrets never come from code or arguments, and no header
value is ever logged.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from airs_adapter import handle
from airs_core import REASON_FAILED, REASON_TOO_LARGE, US_URL, Settings

log = logging.getLogger("airs")
MAX_BODY = 10 * 1024 * 1024
DRAIN_S = 2.0                         # after an answer that left the body unread: the most time spent discarding it
DRAIN_CHUNK = 64 * 1024
TOTAL_BUDGET_S = 4.3                  # of Databricks' 5 s; the rest is the Apps proxy and the network
POLICY_PATH = "/api/policy"
PLACEHOLDER = "__ALLOWED_CALLER__"    # app.yaml's value until the deploy script renders the real caller
NOT_FOUND = {"error": "not_found"}
FORBIDDEN = {"error": "forbidden"}


def clock() -> float:
    return time.monotonic()


def _deny(reason: str) -> dict:
    return {"result": "DENY", "reason": reason}


def _note(**fields) -> None:
    log.warning(json.dumps(fields))


def airs_url():
    """The scan URL: the US endpoint unless AIRS_URL names another https:// endpoint. None when AIRS_URL is set but
    not https: the policy then denies without scanning (fail closed)."""
    u = os.environ.get("AIRS_URL", "").strip()
    if not u:
        return US_URL
    return u if u.lower().startswith("https://") else None


def caller_problem(values: list) -> str | None:
    """Why the caller is refused, or None when the one X-Forwarded-User value is exactly ALLOWED_CALLER."""
    allowed = os.environ.get("ALLOWED_CALLER", "")
    if not allowed or allowed == PLACEHOLDER:
        return "not_configured"
    if not values:
        return "missing"
    if len(values) > 1:
        return "multiple"
    same = hmac.compare_digest(values[0].encode("utf-8", "surrogatepass"), allowed.encode("utf-8", "surrogatepass"))
    return None if same else "mismatch"


def content_length(headers) -> int | None:
    """The declared body size; None when Content-Length is missing, repeated or not a plain number."""
    values = headers.get_all("Content-Length") or []
    if len(values) != 1:
        return None
    v = values[0].strip(" \t")
    if not (v.isascii() and v.isdigit()):
        return None
    return int(v) if len(v) <= 15 else sys.maxsize     # a longer number is over any cap; never int() it


class Handler(BaseHTTPRequestHandler):
    timeout = 10                      # per connection: a slow or silent client can't hold a thread forever

    def log_message(self, fmt, *args):     # the default access log prints the client and the request line
        pass

    def _write(self, status: int, data: bytes) -> None:
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self.send_header("connection", "close")     # one request per connection: an unread body is never parsed
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send(self, status: int, payload: dict) -> None:
        self._write(status, json.dumps(payload).encode())

    def _answer(self, status: int, data: bytes) -> bool:
        """Writes the answer. False when the caller has already gone (the Apps proxy gives up after Databricks' 5 s):
        one log line instead of a traceback."""
        try:
            self._write(status, data)
            return True
        except OSError:
            _note(event="client_gone")
            return False

    def send_error(self, code, message=None, explain=None):
        """Errors http.server finds itself (unknown method, unparseable request) get the fixed 404: its own page is
        HTML that quotes the request."""
        self._send(404, NOT_FOUND)

    def _path(self) -> str:
        """The request target without its query, one trailing slash forgiven. Read from the request line, because
        http.server turns a leading "//" in self.path into "/" (gh-87389)."""
        words = self.requestline.split()
        path = (words[1] if len(words) > 1 else "").split("?", 1)[0]
        if len(path) > 1 and path.endswith("/") and not path.endswith("//"):
            path = path[:-1]
        return path

    def do_GET(self):
        self._send(200, {"service": "dbx-airs-adapter"}) if self._path() == "/" else self._send(404, NOT_FOUND)

    def do_POST(self):
        t0 = clock()
        length = content_length(self.headers)
        self._unread = length or 0                  # declared body bytes not read yet
        if self._path() != POLICY_PATH:
            status, data = 404, json.dumps(NOT_FOUND).encode()
        else:
            try:
                status, payload = self._policy(t0, length)
                data = json.dumps(payload).encode()
            except Exception as e:  # never a detail or a traceback in the answer
                _note(event="exception", error_class=type(e).__name__)
                status, data = 200, json.dumps(_deny(REASON_FAILED)).encode()
        if self._answer(status, data):
            self._discard_unread()

    def _discard_unread(self) -> None:
        """A bounded lingering close. Closing with an unread body resets the connection, so a caller that writes its
        whole body before reading (urllib, http.client, a proxy) would never see the answer. Once the answer is out,
        read and throw away up to the declared size, DRAIN_CHUNK at a time (never kept, never parsed), until the
        caller stops sending or DRAIN_S passes; the server then closes the connection."""
        left = self._unread
        if left <= 0:
            return
        deadline = time.monotonic() + DRAIN_S
        try:
            self.connection.shutdown(socket.SHUT_WR)     # the answer is complete
            while left > 0 and (wait := deadline - time.monotonic()) > 0:
                self.connection.settimeout(wait)
                chunk = self.rfile.read1(min(left, DRAIN_CHUNK))
                if not chunk:
                    break
                left -= len(chunk)
        except OSError:                                  # timed out or reset: stop discarding
            pass

    def _policy(self, t0: float, length: int | None) -> tuple:
        why = caller_problem(self.headers.get_all("X-Forwarded-User") or [])
        if why:
            _note(event="forbidden", why=why)
            return 403, FORBIDDEN
        if length is not None and length > MAX_BODY:
            _note(event="too_large")
            return 200, _deny(REASON_TOO_LARGE)
        self._unread = 0                            # read here, whatever happens next: nothing to discard after
        raw = self.rfile.read(length) if length else b""
        key = os.environ.get("AIRS_API_KEY", "").strip()
        if not key:
            _note(event="secrets_unavailable", where="policy")
            return 200, _deny(REASON_FAILED)
        url = airs_url()
        if url is None:
            _note(event="config_invalid", setting="AIRS_URL")
            return 200, _deny(REASON_FAILED)
        body = None
        if length and len(raw) == length:          # a short read (the client stopped early) is no body
            try:
                body = json.loads(raw)
            except ValueError:
                pass
        budget = max(0.5, min(3.5, TOTAL_BUDGET_S - (clock() - t0)))
        settings = Settings(api_key=key, airs_url=url, budget_s=budget,
                            allow_fail_open=os.environ.get("ALLOW_FAIL_OPEN") == "true",
                            allow_unscanned_parts=os.environ.get("ALLOW_UNSCANNED_PARTS") == "true")
        return 200, handle(body, settings, started=t0)


def main() -> None:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
    port = int(os.environ.get("DATABRICKS_APP_PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    log.info(json.dumps({"event": "listening", "port": port}))
    server.serve_forever()


if __name__ == "__main__":
    main()

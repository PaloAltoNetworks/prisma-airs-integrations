"""The Local Mode harness cases. Run by scripts/itest.sh once Flex, the mock AIRS and the mock upstream are up.

Usage: python3 run.py <phase: main|tls|leak> [comma-separated case-name filters]
Prints one line per case (PASS/FAIL and the reason) and exits non-zero if any case failed. The tls and leak phases are
measurements: they print what they saw and exit 0.
"""
import http.client as hc
import json
import os
import ssl
import subprocess
import sys
import time

AIRS = ("localhost", 18443)
UPSTREAM = ("localhost", 18080)
COMPOSE = os.environ.get("ITEST_COMPOSE", "docker compose")
UNVERIFIED = ssl._create_unverified_context()

FORMATS = {
    "openai": ("openai", "/openai/chat/completions", "/openai/chat/completions"),
    "responses": ("openai", "/openai/responses", "/openai/responses"),
    "anthropic": ("anthropic", "/claude/v1/messages", "/claude/v1/messages"),
    "gemini": ("gemini", "/gemini/models/gemini-test:generateContent", "/gemini/models/gemini-test:streamGenerateContent?alt=sse"),
}


def body_for(fmt, text, stream=False, system=None):
    if fmt == "openai":
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": text}]
        return {"model": "gpt-test", "messages": msgs, "stream": stream}
    if fmt == "responses":
        b = {"model": "gpt-test", "input": text, "stream": stream}
        if system:
            b["instructions"] = system
        return b
    if fmt == "anthropic":
        b = {"model": "claude-test", "max_tokens": 50, "messages": [{"role": "user", "content": text}], "stream": stream}
        if system:
            b["system"] = system
        return b
    b = {"contents": [{"role": "user", "parts": [{"text": text}]}]}
    if system:
        b["systemInstruction"] = {"parts": [{"text": system}]}
    return b


def http(host, port, method, path, body=None, headers=None, tls=False, timeout=30):
    conn = (hc.HTTPSConnection(host, port, context=UNVERIFIED, timeout=timeout) if tls
            else hc.HTTPConnection(host, port, timeout=timeout))
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    hdrs = {"content-type": "application/json"} if data is not None else {}
    hdrs.update(headers or {})
    started = time.monotonic()
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    elapsed = time.monotonic() - started
    out = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, raw, elapsed)
    conn.close()
    return out


def send(port, fmt, text, stream=False, headers=None, system=None, input_format=True, path=None, body=None):
    header_value, plain, streamed = FORMATS[fmt]
    hdrs = dict(headers or {})
    if input_format:
        hdrs["x-input-format"] = header_value
    return http("localhost", port, "POST", path or (streamed if stream else plain),
                body if body is not None else body_for(fmt, text, stream, system), hdrs)


def reset():
    http(*AIRS, "POST", "/__reset", b"{}", tls=True)
    http(*UPSTREAM, "POST", "/__reset", b"{}")


def scans():
    return json.loads(http(*AIRS, "GET", "/__scans", tls=True)[2])


def hits():
    return json.loads(http(*UPSTREAM, "GET", "/__hits")[2])["hits"]


def last():
    return json.loads(http(*UPSTREAM, "GET", "/__last")[2])


def flex_logs():
    return subprocess.run(f"{COMPOSE} logs --no-color local-flex", shell=True, capture_output=True, text=True).stdout


def evidence(transaction_id, wait=8.0):
    """The evidence record logged for this transaction id, or None. Flex writes its log a moment after replying."""
    deadline = time.monotonic() + wait
    while True:
        for line in reversed(flex_logs().splitlines()):
            if "prisma-airs-guardrails evidence " in line and f'"transaction_id":"{transaction_id}"' in line:
                raw = line.split("prisma-airs-guardrails evidence ", 1)[1]
                try:
                    return json.loads(raw[: raw.rfind("}") + 1])
                except ValueError:
                    return None
        if time.monotonic() > deadline:
            return None
        time.sleep(0.5)


def error_shape(fmt, raw):
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    if fmt in ("openai", "responses"):
        return body.get("error", {}).get("message") if body.get("error", {}).get("type", "").startswith("prisma_airs_") else None
    if fmt == "anthropic":
        return body.get("error", {}).get("message") if body.get("type") == "error" else None
    return body.get("error", {}).get("message") if body.get("error", {}).get("status") in ("PERMISSION_DENIED", "UNAVAILABLE") else None


class Fail(Exception):
    pass


def check(cond, why):
    if not cond:
        raise Fail(why)


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


# ---- Task 7: the main path ----------------------------------------------------------------------------------------

def make_allow(fmt):
    def allow_both_legs():
        reset()
        tx = f"itest-allow-{fmt}"
        status, _, raw, _ = send(8081, fmt, "hello there", headers={"x-correlation-id": tx})
        check(status == 200, f"status {status}: {raw[:200]!r}")
        check(hits() == 1, f"upstream hits {hits()}")
        s = scans()
        check(len(s) == 2, f"{len(s)} scans")
        check(all(x.get("transaction_id") == tx and "tr_id" not in x for x in s), "transaction_id / tr_id")
        check(s[0]["contents"] == [{"prompt": "hello there"}], f"prompt scan {s[0]['contents']}")
        check(s[1]["contents"][0] == {"prompt": "hello there"} and "response" in s[1]["contents"][-1], f"response scan {s[1]['contents']}")
        check(s[0]["metadata"]["app_name"] == "MuleSoft", "app_name")
    allow_both_legs.__name__ = f"allow_both_legs_{fmt}"
    return allow_both_legs


def make_block_prompt(fmt, stream):
    def block_prompt():
        reset()
        status, _, raw, _ = send(8081, fmt, "BLOCKME please", stream=stream)
        check(status == 403, f"status {status}")
        message = error_shape(fmt, raw)
        check(message and message.startswith("Request blocked by Prisma AIRS security policy. Scan ID: "), f"body {raw[:200]!r}")
        check(hits() == 0, f"upstream hits {hits()}")
    block_prompt.__name__ = f"block_prompt_{fmt}_{'sse' if stream else 'json'}"
    return block_prompt


def make_block_reply(fmt, stream):
    def block_reply():
        reset()
        status, headers, raw, _ = send(8081, fmt, "hello", stream=stream, headers={"x-mock-reply": "text:BLOCKME reply"})
        check(status == 403, f"status {status}: {raw[:200]!r}")
        message = error_shape(fmt, raw)
        check(message and message.startswith("Response blocked by Prisma AIRS security policy."), f"body {raw[:200]!r}")
        check(b"data:" not in raw and b"BLOCKME" not in raw, "stream bytes leaked")
        check(headers.get("content-type", "").startswith("application/json"), f"content-type {headers.get('content-type')}")
    block_reply.__name__ = f"block_reply_{fmt}_{'sse' if stream else 'json'}"
    return block_reply


for _fmt in FORMATS:
    CASES.append(make_allow(_fmt))
    for _stream in (False, True):
        CASES.append(make_block_prompt(_fmt, _stream))
        CASES.append(make_block_reply(_fmt, _stream))


@case
def airs_slow_is_503_within_bound():
    reset()
    status, _, raw, elapsed = send(8085, "openai", "SLOWME please")
    check(status == 503, f"status {status}")
    check(elapsed < 4.0, f"took {elapsed:.2f}s")
    check(hits() == 0, "upstream reached")
    check("could not scan" in (error_shape("openai", raw) or ""), f"body {raw[:200]!r}")


@case
def airs_500_is_503_and_fail_open_is_recorded():
    reset()
    status, _, _, _ = send(8081, "openai", "ERR500 please")
    check(status == 503, f"fail closed: status {status}")
    check(hits() == 0, "upstream reached while failing closed")
    status, _, _, _ = send(8083, "openai", "ERR500 please", headers={"x-correlation-id": "itest-failopen"})
    check(status == 200, f"fail open: status {status}")
    ev = evidence("itest-failopen")
    check(ev and ev["legs"][0]["outcome"] == "failed_open", f"evidence {ev}")


@case
def detector_failure_is_503():
    reset()
    status, _, _, _ = send(8081, "anthropic", "DETECTORFAIL please")
    check(status == 503, f"status {status}")


@case
def garbage_verdict_is_503():
    reset()
    status, _, _, _ = send(8081, "gemini", "GARBAGE please")
    check(status == 503, f"status {status}")


@case
def monitor_passes_block():
    reset()
    status, _, _, _ = send(8082, "openai", "BLOCKME please", headers={"x-correlation-id": "itest-monitor"})
    check(status == 200, f"status {status}")
    ev = evidence("itest-monitor")
    check(ev and ev["legs"][0]["outcome"] == "monitored_block", f"evidence {ev}")


@case
def unknown_format_gap():
    reset()
    body = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    status, _, raw, _ = send(8081, "openai", "", input_format=False, path="/x/v2/chat", body=body)
    check(status == 403, f"status {status}: {raw[:200]!r}")
    check("could not inspect" in (error_shape("openai", raw) or ""), f"body {raw[:200]!r}")
    check(hits() == 0, "upstream reached")
    status, _, _, _ = send(8084, "openai", "", input_format=False, path="/x/v2/chat", body=body)
    check(status == 200, f"onScanError allow: status {status}")


@case
def get_without_body():
    reset()
    status, _, _, _ = http("localhost", 8081, "GET", "/openai/models", headers={"x-input-format": "openai"})
    check(status == 200, f"status {status}")
    check(scans() == [], "a GET was scanned")


@case
def truncation_fail_closed():
    reset()
    status, _, _, _ = send(8092, "openai", "a" * 100)
    check(status == 403, f"status {status}")
    check(scans() == [] and hits() == 0, "scanned or forwarded")


@case
def truncation_open_scans_newest_n():
    # s03 Task 12: over the limit, a prompt keeps its newest text, the part that must not be cut.
    reset()
    status, _, _, _ = send(8091, "openai", "a" * 100 + "b" * 50)
    check(status == 200, f"status {status}")
    s = scans()
    check(s and s[0]["contents"][0]["prompt"] == "b" * 50, f"scanned {s[0]['contents'] if s else None}")


@case
def misconfigured_is_503_for_all():
    reset()
    for fmt in FORMATS:
        status, _, raw, _ = send(8086, fmt, "hello")
        check(status == 503, f"{fmt}: status {status}")
        check(b"not configured correctly" in raw, f"{fmt}: the reply does not say why: {raw[:160]!r}")
    check(hits() == 0 and scans() == [], "a misconfigured policy let traffic through")


@case
def long_session_header():
    reset()
    status, _, _, _ = send(8081, "openai", "hello", headers={"x-session-id": "s" * 150, "x-correlation-id": "itest-session"})
    check(status == 200, f"status {status}")
    s = scans()
    check(s and "session_id" not in s[0], "a 150-character session id was sent")
    ev = evidence("itest-session")
    check(ev and ev["session_id_dropped"] == "too_long", f"evidence {ev}")


@case
def session_and_user_headers_are_sent():
    reset()
    status, _, _, _ = send(8081, "anthropic", "hello", headers={"x-session-id": "conv-7"})
    check(status == 200, f"status {status}")
    s = scans()
    check(s and all(x.get("session_id") == "conv-7" for x in s), f"session ids {[x.get('session_id') for x in s]}")


@case
def accept_encoding_removed():
    reset()
    status, _, _, _ = send(8081, "openai", "hello", headers={"accept-encoding": "gzip"})
    check(status == 200, f"status {status}")
    check("accept-encoding" not in last().get("headers", {}), f"upstream got {last().get('headers', {}).get('accept-encoding')}")


# ---- Task 8: the remaining cases ----------------------------------------------------------------------------------

class Session:
    """One keep-alive connection: Envoy keeps a connection on one worker, and the breaker and cache are per worker."""

    def __init__(self, port):
        self.conn = hc.HTTPConnection("localhost", port, timeout=30)

    def send(self, fmt, text, stream=False, headers=None):
        header_value, plain, streamed = FORMATS[fmt]
        hdrs = {"content-type": "application/json", "x-input-format": header_value}
        hdrs.update(headers or {})
        self.conn.request("POST", streamed if stream else plain, body=json.dumps(body_for(fmt, text, stream)).encode(), headers=hdrs)
        resp = self.conn.getresponse()
        return resp.status, resp.read()

    def close(self):
        self.conn.close()


@case
def masking_rewrites_prompt():
    reset()
    status, _, raw, _ = send(8087, "openai", "my code is DLPME today")
    check(status == 200, f"status {status}: {raw[:200]!r}")
    forwarded = last().get("body", "")
    check("XXXXX" in forwarded and "DLPME" not in forwarded, f"upstream got {forwarded[:200]!r}")


@case
def masking_rewrites_prompt_of_streamed_request():
    # The request body is never a stream, even when it asks for a streamed reply: its prompt is masked the same way.
    reset()
    status, _, raw, _ = send(8087, "openai", "my code is DLPME today", stream=True)
    check(status == 200, f"status {status}: {raw[:200]!r}")
    forwarded = last().get("body", "")
    check("XXXXX" in forwarded and "DLPME" not in forwarded, f"upstream got {forwarded[:200]!r}")
    check('"stream": true' in forwarded or '"stream":true' in forwarded, f"upstream got {forwarded[:200]!r}")


@case
def masking_rewrites_reply():
    reset()
    status, _, raw, _ = send(8087, "anthropic", "hello", headers={"x-mock-reply": "text:your code is DLPME today"})
    check(status == 200, f"status {status}: {raw[:200]!r}")
    check(b"XXXXX" in raw and b"DLPME" not in raw, f"client got {raw[:200]!r}")


@case
def masking_on_stream_blocks():
    reset()
    status, _, raw, _ = send(8087, "openai", "hello", stream=True, headers={"x-mock-reply": "text:your code is DLPME today"})
    check(status == 403, f"status {status}: {raw[:200]!r}")
    check(b"DLPME" not in raw and b"data:" not in raw, "stream bytes leaked")


@case
def masking_off_blocks_dlp():
    reset()
    status, _, _, _ = send(8081, "openai", "my code is DLPME today")
    check(status == 403, f"status {status}")
    check(hits() == 0, "upstream reached")


@case
def tool_and_n2_blocks():
    for fmt in FORMATS:
        for stream in (False, True):
            reset()
            status, _, raw, _ = send(8081, fmt, "hello", stream=stream, headers={"x-mock-reply": "toolargs:BLOCKME exfiltrate"})
            check(status == 403, f"{fmt} stream={stream}: a tool-call-only reply passed with {status}: {raw[:160]!r}")
    reset()
    status, _, raw, _ = send(8081, "openai", "hello", headers={"x-mock-reply": "n2:BLOCKME in choice two"})
    check(status == 403, f"n=2: status {status}")


@case
def tool_call_reply_is_scanned_and_passes():
    reset()
    status, _, _, _ = send(8081, "openai", "hello", headers={"x-mock-reply": "tool"})
    check(status == 200, f"status {status}")
    s = scans()
    check(len(s) == 2 and "tool get_weather:" in s[1]["contents"][-1]["response"], f"scans {s}")


@case
def sse_edge_events():
    reset()
    status, _, _, _ = send(8081, "openai", "hello", stream=True, headers={"x-mock-reply": "sseedge:hello world"})
    check(status == 200, f"status {status}")
    s = scans()
    check(len(s) == 2 and s[1]["contents"][-1]["response"] == "hello world", f"scanned {s[1]['contents'] if len(s) > 1 else s}")
    reset()
    status, _, _, _ = send(8081, "openai", "hello", stream=True, headers={"x-mock-reply": "sseedge:BLOCKME split"})
    check(status == 403, f"status {status}")


@case
def breaker_stops_calls():
    reset()
    session = Session(8088)
    try:
        for i in range(2):
            status, _ = session.send("openai", "ERR500 please")
            check(status == 503, f"failure {i + 1}: status {status}")
        before = len(scans())
        status, _ = session.send("openai", "hello there")
        check(status == 503, f"breaker open: status {status}")
        check(len(scans()) == before, "AIRS was called while the breaker was open")
        check(hits() == 0, "upstream reached")
    finally:
        session.close()


@case
def cache_one_scan_for_repeat():
    reset()
    session = Session(8089)
    try:
        for i in range(2):
            status, _ = session.send("openai", "the same prompt")
            check(status == 200, f"request {i + 1}: status {status}")
        check(len(scans()) == 2, f"{len(scans())} scans for two identical exchanges (expected 2: one per leg)")
        status, _ = session.send("openai", "BLOCKME is never cached")
        check(status == 403, f"a block after cached allows: status {status}")
    finally:
        session.close()


@case
def oversized_reply_never_passes():
    for stream in (False, True):
        reset()
        status, _, raw, _ = send(8081, "openai", "hello", stream=stream, headers={"x-mock-reply": "big"})
        print(f"     oversized reply stream={stream}: status {status}, {len(raw)} bytes: {raw[:120]!r}")
        check(status != 200 and b"aaaa" not in raw, f"stream={stream}: the 2 MiB reply passed ({status}, {len(raw)} bytes)")


@case
def compressed_reply_is_a_gap():
    reset()
    status, _, raw, _ = send(8081, "openai", "hello", headers={"x-mock-reply": "gzip"})
    check(status == 403, f"status {status}")
    check("could not inspect" in (error_shape("openai", raw) or ""), f"body {raw[:200]!r}")


@case
def scan_roles_system():
    for fmt in FORMATS:
        reset()
        status, _, _, _ = send(8090, fmt, "hello", system="BLOCKME system prompt")
        check(status == 403, f"{fmt}: system role scanned: status {status}")
        reset()
        status, _, _, _ = send(8081, fmt, "hello", system="BLOCKME system prompt")
        check(status == 200, f"{fmt}: default roles: status {status}")


@case
def upstream_error_passes_unscanned():
    reset()
    status, _, _, _ = send(8081, "openai", "hello", headers={"x-mock-reply": "status:429"})
    check(status == 429, f"status {status}")
    check(len(scans()) == 1, "an upstream error reply was scanned")


@case
def empty_reply_passes():
    reset()
    status, _, _, _ = send(8081, "gemini", "hello", headers={"x-mock-reply": "empty"})
    check(status == 200, f"status {status}")


# ---- measurements -------------------------------------------------------------------------------------------------

def tls_check():
    reset()
    status, _, raw, elapsed = send(8081, "openai", "hello there")
    logs = flex_logs()
    tls_lines = [l for l in logs.splitlines() if any(w in l.lower() for w in ("certificate", "tls", "ssl", "verify"))]
    print(f"TLS check: status {status} in {elapsed:.2f}s, scans seen by the mock {len(scans())}, upstream hits {hits()}")
    print(f"  body: {raw[:200]!r}")
    for l in tls_lines[-6:]:
        print("  log:", l[:220])


def leak_check():
    reset()
    try:
        status, _, raw, _ = send(8081, "openai", "hello there")
    except Exception as err:  # noqa: BLE001 - a measurement reports whatever happened
        status, raw = f"no response ({err.__class__.__name__})", b""
    logs = flex_logs()
    leaked = "FAKE-LEAK-KEY-4242" in logs or "424242424242" in logs
    print(f"leak check: status {status}, upstream hits {hits()}, the fake key in Flex logs: {leaked}")
    print(f"  body: {raw[:200]!r}")
    for l in [l for l in logs.splitlines() if any(w in l.lower() for w in ("prisma", "configuration", "invalid", "error", "reject"))][-8:]:
        print("  log:", l.replace("FAKE-LEAK-KEY-4242", "<FAKE KEY>").replace("424242424242", "<FAKE KEY>")[:240])


# ---- s03 Task 12: the phase-gate fixes ----------------------------------------------------------------------------

HISTORY = {
    "openai": {"model": "gpt-test", "messages": [{"role": "user", "content": "BLOCKME please"},
               {"role": "assistant", "content": "Noted."}, {"role": "user", "content": "hello"}]},
    "responses": {"model": "gpt-test", "input": [{"role": "user", "content": "BLOCKME please"},
                  {"role": "assistant", "content": "Noted."}, {"role": "user", "content": "hello"}]},
    "anthropic": {"model": "claude-test", "max_tokens": 50, "messages": [{"role": "user", "content": "BLOCKME please"},
                  {"role": "assistant", "content": "Noted."}, {"role": "user", "content": "hello"}]},
    "gemini": {"contents": [{"role": "user", "parts": [{"text": "BLOCKME please"}]},
               {"role": "model", "parts": [{"text": "Noted."}]}, {"role": "user", "parts": [{"text": "hello"}]}]},
}


@case
def earlier_user_turn_is_scanned():
    # The caller writes the whole history, so an earlier user turn is scanned like the newest one.
    reset()
    for fmt, body in HISTORY.items():
        status, _, raw, _ = send(8081, fmt, "", body=body)
        check(status == 403 and error_shape(fmt, raw), f"{fmt}: status {status}: {raw[:160]!r}")
    check(hits() == 0, "an injection in an earlier user turn reached the upstream")


@case
def document_part_is_scanned():
    reset()
    body = {"model": "claude-test", "max_tokens": 50, "messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "BLOCKME please"}},
        {"type": "text", "text": "summarise the document"}]}]}
    status, _, raw, _ = send(8081, "anthropic", "", body=body)
    check(status == 403 and error_shape("anthropic", raw), f"status {status}: {raw[:160]!r}")
    check(hits() == 0, "an injection in a document block reached the upstream")


@case
def masking_rewrites_every_user_turn():
    reset()
    body = {"model": "gpt-test", "messages": [{"role": "user", "content": "my code is DLPME today"},
            {"role": "assistant", "content": "Noted."}, {"role": "user", "content": "and DLPME again"}]}
    status, _, raw, _ = send(8087, "openai", "", body=body)
    check(status == 200, f"status {status}: {raw[:200]!r}")
    forwarded = last().get("body", "")
    check(forwarded.count("XXXXX") == 2 and "DLPME" not in forwarded, f"upstream got {forwarded[:300]!r}")


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "main"
    if phase == "tls":
        return tls_check() or 0
    if phase == "leak":
        return leak_check() or 0
    wanted = [w for w in (sys.argv[2] if len(sys.argv) > 2 else "").split(",") if w]
    chosen = [fn for fn in CASES if not wanted or any(w in fn.__name__ for w in wanted)]
    failed = 0
    for fn in chosen:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Fail as err:
            failed += 1
            print(f"FAIL {fn.__name__}: {err}")
        except Exception as err:  # noqa: BLE001 - a broken case is a failed case
            failed += 1
            print(f"FAIL {fn.__name__}: {err.__class__.__name__}: {err}")
    print(f"{len(chosen) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

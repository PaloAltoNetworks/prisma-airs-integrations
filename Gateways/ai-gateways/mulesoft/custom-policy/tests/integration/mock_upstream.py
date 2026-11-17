"""A mock model upstream for the Local Mode harness: it answers each format's path the way the real API does.

The reply is chosen by the request's `x-mock-reply` header:
  (none) | plain    the recorded reply (fixtures/<format>/plain.json or .sse)
  tool              the recorded tool-call reply
  text:<TEXT>       a reply whose text is TEXT
  toolargs:<TEXT>   a reply that is only a tool call, with TEXT in its arguments
  n2:<TEXT>         two choices, the second one TEXT (OpenAI chat)
  sseedge:<TEXT>    a stream with Azure's empty first event, comments, CRLF and TEXT split in two events
  big               a reply of 2 MiB
  gzip              a gzip-compressed reply with content-encoding gzip
  empty             a reply with no text
  speech:<SECONDS>  a Gemini speech reply: SECONDS of audio with no file header (half-second chunks when streamed)
  status:<code>     that status with a small JSON error
A request asks for a stream with "stream": true, or with Gemini's :streamGenerateContent.
GET /__hits, GET /__last (the last request's path, lower-cased headers and body) and POST /__reset are for the runner.
Standard library only.
"""
import base64
import gzip
import json
import math
import struct
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURES = "/fixtures"
STATE = {"hits": 0, "last": {}}
LOCK = threading.Lock()


def fmt_of(path):
    p = path.split("?")[0]
    if p.endswith("/chat/completions"):
        return "openai"
    if p.endswith("/responses"):
        return "responses"
    if p.endswith("/messages"):
        return "anthropic"
    if p.endswith(":generateContent") or p.endswith(":streamGenerateContent"):
        return "gemini"
    return "openai"


def sse(events, crlf=False):
    nl = "\r\n" if crlf else "\n"
    out = []
    for name, data in events:
        if name:
            out.append(f"event: {name}{nl}")
        out.append(f"data: {data if isinstance(data, str) else json.dumps(data)}{nl}{nl}")
    return "".join(out).encode()


def text_reply(fmt, stream, text):
    half = len(text) // 2
    a, b = text[:half], text[half:]
    if fmt == "openai":
        if not stream:
            return {"id": "chatcmpl-itest", "object": "chat.completion",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}
        return sse([(None, {"choices": [{"index": 0, "delta": {"role": "assistant", "content": a}}]}),
                    (None, {"choices": [{"index": 0, "delta": {"content": b}}]}), (None, "[DONE]")])
    if fmt == "responses":
        full = {"id": "resp-itest", "object": "response",
                "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}]}
        if not stream:
            return full
        return sse([("response.output_text.delta", {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": a}),
                    ("response.output_text.delta", {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": b}),
                    ("response.completed", {"type": "response.completed", "response": full})])
    if fmt == "anthropic":
        if not stream:
            return {"id": "msg-itest", "type": "message", "role": "assistant", "content": [{"type": "text", "text": text}]}
        return sse([("message_start", {"type": "message_start", "message": {"id": "msg-itest", "content": []}}),
                    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": a}}),
                    ("ping", {"type": "ping"}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": b}}),
                    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                    ("message_stop", {"type": "message_stop"})])
    if not stream:
        return {"candidates": [{"index": 0, "content": {"role": "model", "parts": [{"text": text}]}}]}
    return sse([(None, {"candidates": [{"index": 0, "content": {"role": "model", "parts": [{"text": a}]}}]}),
                (None, {"candidates": [{"index": 0, "content": {"role": "model", "parts": [{"text": b}]}}]})], crlf=True)


def pcm64(seconds, rate=24000):
    """Audio with no file header, base64: 16-bit little-endian samples of a 440 Hz tone, as Gemini streams speech."""
    n = int(seconds * rate)
    samples = [int(math.sin(i * 440 * 2 * math.pi / rate) * 8000) for i in range(n)]
    return base64.b64encode(struct.pack(f"<{n}h", *samples)).decode()


def png64(size=24):
    """A real PNG, base64: a size x size colour gradient, stored uncompressed."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    rows = b"".join(b"\x00" + b"".join(bytes(((x * 10) % 256, (y * 10) % 256, 160)) for x in range(size))
                    for y in range(size))
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(rows, 0)) + chunk(b"IEND", b""))
    return base64.b64encode(png).decode()


def speech_reply(stream, seconds):
    def frame(s):
        part = {"inlineData": {"mimeType": "audio/L16;codec=pcm;rate=24000", "data": pcm64(s)}}
        return {"candidates": [{"index": 0, "content": {"role": "model", "parts": [part]}}]}
    if not stream:
        return frame(seconds)
    return sse([(None, frame(0.5)) for _ in range(int(seconds * 2))], crlf=True)


def tool_reply(fmt, stream, text):
    args = json.dumps({"body": text})
    if fmt == "openai":
        body = {"choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": "call-1", "type": "function", "function": {"name": "send_email", "arguments": args}}]}}]}
        if not stream:
            return body
        return sse([(None, {"choices": [{"index": 0, "delta": {"tool_calls": [
                        {"index": 0, "id": "call-1", "function": {"name": "send_email", "arguments": args[:5]}}]}}]}),
                    (None, {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": args[5:]}}]}}]}),
                    (None, "[DONE]")])
    if fmt == "responses":
        full = {"output": [{"type": "function_call", "name": "send_email", "arguments": args}]}
        return full if not stream else sse([("response.completed", {"type": "response.completed", "response": full})])
    if fmt == "anthropic":
        body = {"content": [{"type": "tool_use", "id": "toolu-1", "name": "send_email", "input": {"body": text}}]}
        if not stream:
            return body
        return sse([("message_start", {"type": "message_start", "message": {"content": []}}),
                    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "name": "send_email", "input": {}}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": args[:5]}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": args[5:]}}),
                    ("message_stop", {"type": "message_stop"})])
    body = {"candidates": [{"index": 0, "content": {"parts": [{"functionCall": {"name": "send_email", "args": {"body": text}}}]}}]}
    return body if not stream else sse([(None, body)], crlf=True)


def fixture(fmt, stream, case):
    name = f"{FIXTURES}/{fmt}/{case}.{'sse' if stream else 'json'}"
    with open(name, "rb") as f:
        return f.read()


MCP_TOOLS = [{"name": "echo", "description": "Echoes the text it is given.",
              "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]


def mcp_answer(msg, headers):
    """The mock MCP server's answer to one JSON-RPC message; None for a notification or a client reply.
    x-mock-mcp-say puts its text in the answer: the instructions, the tool description, the tool result or the
    resource text. x-mock-mcp-media: 1 adds an image and an audio block to a tool result."""
    if not isinstance(msg, dict) or "method" not in msg or "id" not in msg:
        return None
    mid, method, params = msg["id"], msg["method"], msg.get("params") or {}
    say = headers.get("x-mock-mcp-say")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "mock-mcp", "version": "1.0"}, "instructions": say or "Use the tools politely."}
    elif method == "tools/list":
        result = {"tools": [dict(MCP_TOOLS[0], description=say)] if say else MCP_TOOLS}
    elif method == "tools/call":
        text = say or ("echo: " + json.dumps(params.get("arguments", {}), sort_keys=True))
        result = {"content": [{"type": "text", "text": text}], "isError": False}
        if headers.get("x-mock-mcp-media") == "1":
            result["content"] += [{"type": "image", "mimeType": "image/png", "data": png64()},
                                  {"type": "audio", "mimeType": "audio/pcm", "data": pcm64(0.1)}]
    elif method == "resources/read":
        result = {"contents": [{"uri": params.get("uri", ""), "mimeType": "text/plain", "text": say or "resource text"}]}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def mcp_post(handler, raw):
    """Streamable HTTP POST: JSON by default, an event stream with x-mock-mcp-sse: 1 or when x-mock-mcp-note asks for
    a notification before the answer. initialize issues Mcp-Session-Id. Notifications and client replies get 202."""
    headers = {k.lower(): v for k, v in handler.headers.items()}
    try:
        body = json.loads(raw)
    except ValueError:
        return handler.send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
    batch = isinstance(body, list)
    members = body if batch else [body]
    answers = [a for a in (mcp_answer(m, headers) for m in members) if a is not None]
    extra = {}
    if any(isinstance(m, dict) and m.get("method") == "initialize" for m in members):
        extra["mcp-session-id"] = "mock-session-1"
    if not answers:
        return handler.send(202, b"", "application/json", extra)
    note = headers.get("x-mock-mcp-note")
    if headers.get("x-mock-mcp-sse") == "1" or note:
        events = []
        if note:
            events.append({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": note}})
        events.extend([answers] if batch else answers)
        data = "".join(f"event: message\ndata: {json.dumps(e)}\n\n" for e in events).encode()
        return handler.send(200, data, "text/event-stream", extra)
    return handler.send(200, answers if batch else answers[0], "application/json", extra)


def mcp_open_stream(handler, texts, pause):
    """An open server-to-client stream: one notifications/message per text, written and flushed `pause` seconds
    apart; the server ends the stream (closes the connection) a pause after the last one."""
    handler.send_response(200)
    handler.send_header("content-type", "text/event-stream")
    handler.send_header("cache-control", "no-cache")
    handler.end_headers()
    for text in texts:
        event = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": text}}
        handler.wfile.write(f"event: message\ndata: {json.dumps(event)}\n\n".encode())
        handler.wfile.flush()
        time.sleep(pause)


def mcp_get(handler):
    """A server-to-client event stream: one sampling request carrying x-mock-mcp-say's text, or, with
    x-mock-mcp-events, an open stream of the |-separated texts, x-mock-mcp-pause seconds apart."""
    texts = handler.headers.get("x-mock-mcp-events")
    if texts:
        return mcp_open_stream(handler, texts.split("|"), float(handler.headers.get("x-mock-mcp-pause", "1.5")))
    say = handler.headers.get("x-mock-mcp-say", "a server message")
    event = {"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage",
             "params": {"messages": [{"role": "user", "content": {"type": "text", "text": say}}], "maxTokens": 10}}
    handler.send(200, f"event: message\ndata: {json.dumps(event)}\n\n".encode(), "text/event-stream")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def remember(self, body):
        with LOCK:
            STATE["hits"] += 1
            STATE["last"] = {"path": self.path, "method": self.command,
                             "headers": {k.lower(): v for k, v in self.headers.items()},
                             "body": body.decode("utf-8", "replace")}

    def do_GET(self):
        if self.path == "/__hits":
            with LOCK:
                return self.send(200, {"hits": STATE["hits"]})
        if self.path == "/__last":
            with LOCK:
                return self.send(200, STATE["last"])
        self.remember(b"")
        if self.path.startswith("/mcp"):
            return mcp_get(self)
        self.send(200, {"object": "list", "data": []})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length") or 0))
        if self.path == "/__reset":
            with LOCK:
                STATE["hits"] = 0
                STATE["last"] = {}
            return self.send(200, {"reset": True})
        self.remember(raw)
        if self.path.startswith("/mcp"):
            return mcp_post(self, raw)
        fmt = fmt_of(self.path)
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = {}
        stream = bool(req.get("stream")) if isinstance(req, dict) else False
        stream = stream or ":streamGenerateContent" in self.path
        variant = self.headers.get("x-mock-reply", "plain")
        kind, _, arg = variant.partition(":")
        ctype = "text/event-stream" if stream else "application/json"
        if kind == "status":
            return self.send(int(arg), {"error": {"message": "upstream error"}})
        if kind == "plain":
            return self.send(200, fixture(fmt, stream, "plain"), ctype)
        if kind == "tool":
            return self.send(200, fixture(fmt, stream, "tool"), ctype)
        if kind == "text":
            return self.send(200, text_reply(fmt, stream, arg), ctype)
        if kind == "toolargs":
            return self.send(200, tool_reply(fmt, stream, arg), ctype)
        if kind == "n2":
            return self.send(200, {"choices": [{"index": 0, "message": {"content": "fine"}},
                                               {"index": 1, "message": {"content": arg}}]})
        if kind == "sseedge":
            half = len(arg) // 2
            body = (b": keep-alive\r\n\r\n"
                    + b'data: {"choices":[],"prompt_filter_results":[{"prompt_index":0}]}\r\n\r\n'
                    + ("data:" + json.dumps({"choices": [{"index": 0, "delta": {"content": arg[:half]}}]}) + "\r\n\r\n").encode()
                    + b": ping\r\n"
                    + ("data: " + json.dumps({"choices": [{"index": 0, "delta": {"content": arg[half:]}}]}) + "\r\n\r\n").encode()
                    + b"data: [DONE]\r\n\r\n")
            return self.send(200, body, "text/event-stream")
        if kind == "big":
            filler = "a" * (2 * 1024 * 1024)
            reply = text_reply(fmt, stream, filler)
            return self.send(200, reply if isinstance(reply, bytes) else json.dumps(reply).encode(), ctype)
        if kind == "gzip":
            data = gzip.compress(json.dumps(text_reply(fmt, False, "compressed reply")).encode())
            return self.send(200, data, "application/json", {"content-encoding": "gzip"})
        if kind == "speech":
            return self.send(200, speech_reply(stream, float(arg)), ctype)
        if kind == "empty":
            return self.send(200, text_reply(fmt, False, ""))
        self.send(400, {"error": {"message": f"unknown x-mock-reply {variant}"}})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

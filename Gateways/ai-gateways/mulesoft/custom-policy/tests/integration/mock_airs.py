"""A TLS mock of the Prisma AIRS sync scan API for the Local Mode harness.

It judges the element of `contents` that is scanned (the last one; earlier elements are context) by markers:
BLOCKME blocks, DLPME blocks as sensitive data with masked text, MASKOK allows with masked text, DETECTORFAIL allows
with a failed detection service, SLOWME waits 10 s, ERR500 answers 500, GARBAGE answers a body that is not JSON.
Every scan body is kept for GET /__scans; POST /__reset clears them. Standard library only.
MCP tool events follow the contract a live tenant enforced on 7 Nov 2026: a tool event outside it is a 400, and
the markers apply to its input and output.
"""
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = "FAKE-ITEST-KEY"
SCANS = []
LOCK = threading.Lock()


TOOL_METHODS = ("tools/call", "tools/list")
NO_FLAGS = {"agent": False, "db_security": False, "dlp": False, "injection": False, "malicious_code": False,
            "toxic_content": False, "url_cats": False}


def tool_event_error(event):
    """AIRS's 400 text for a tool event outside its contract, or None."""
    meta = event.get("metadata")
    if not isinstance(meta, dict):
        return "tool_event.metadata is required"
    extra = sorted(set(meta) - {"ecosystem", "method", "server_name", "tool_invoked"})
    if extra:
        return f"tool_event.metadata has unknown fields: {extra}"
    if str(meta.get("ecosystem", "")).lower() != "mcp":
        return f"unsupported ecosystem: [{meta.get('ecosystem', '')}]"
    if str(meta.get("method", "")).lower() not in TOOL_METHODS:
        return f"failed to parse scan content: unsupported method: [{meta.get('method', '')}]"
    if not isinstance(meta.get("server_name"), str) or not meta["server_name"]:
        return "tool_event.metadata.server_name is required"
    if any(k in event and not isinstance(event[k], str) for k in ("input", "output")):
        return "received wrong request format"
    if "input" not in event and "output" not in event:
        return "tool_event needs input or output"
    if meta["method"].lower() == "tools/list" and event.get("output"):
        try:
            tools = json.loads(event["output"])
        except ValueError:
            return "failed to parse tools list"
        if not isinstance(tools, list):
            return ("failed to parse scan content: failed to build tool event structured data: failed to parse tools "
                    "list: json: cannot unmarshal object into Go value of type []*mcp.Tool")
    return None


def tool_verdict(event, out):
    """The tool_detected part of a verdict: BLOCKME in the input or the output blocks on that side."""
    sides = {}
    for side in ("input", "output"):
        text = event.get(side) or ""
        if not text:
            sides[side] = {"detection_entries": None}
            continue
        flags = dict(NO_FLAGS, injection="BLOCKME" in text, agent="BLOCKME" in text)
        sides[side] = {"detection_entries": [{"detections": flags, "threats": ["context poisoning"] if flags["injection"] else [],
                                              "tool_invoked": event["metadata"].get("tool_invoked", "")}]}
    blocked = any(e["detections"]["injection"] for s in sides.values() for e in (s["detection_entries"] or []))
    if blocked:
        out.update(category="malicious", action="block")
    out["tool_detected"] = {"verdict": "malicious" if blocked else "benign", "metadata": event["metadata"],
                            "summary": {"detections": dict(NO_FLAGS, injection=blocked, agent=blocked), "threats": []},
                            "input_detected": sides["input"], "output_detected": sides["output"]}


def verdict(body, n):
    contents = body.get("contents") or [{}]
    last = contents[-1] if isinstance(contents, list) and contents else {}
    if isinstance(last.get("tool_event"), dict):
        event = last["tool_event"]
        out = {"report_id": f"R-itest-{n}", "scan_id": f"scan-itest-{n}", "profile_name": "itest-profile",
               "transaction_id": body.get("transaction_id"), "session_id": body.get("session_id"),
               "category": "benign", "action": "allow", "error": False, "timeout": False, "errors": [],
               "prompt_detected": {}, "response_detected": {}}
        tool_verdict(event, out)
        return (event.get("input") or "") + "\n" + (event.get("output") or ""), out
    leg = "response" if "response" in last else "prompt"
    text = str(last.get(leg, ""))
    out = {
        "report_id": f"R-itest-{n}", "scan_id": f"scan-itest-{n}", "profile_name": "itest-profile",
        "transaction_id": body.get("transaction_id"), "session_id": body.get("session_id"),
        "category": "benign", "action": "allow", "error": False, "timeout": False, "errors": [],
        "prompt_detected": {}, "response_detected": {},
    }
    detected = f"{leg}_detected"
    if "BLOCKME" in text:
        out.update(category="malicious", action="block")
        out[detected] = {"injection" if leg == "prompt" else "malicious_code": True}
    elif "DLPME" in text:
        out.update(category="malicious", action="block")
        out[detected] = {"dlp": True}
        out[f"{leg}_masked_data"] = {"data": text.replace("DLPME", "XXXXX"), "pattern_detections": []}
    elif "MASKOK" in text:
        out[f"{leg}_masked_data"] = {"data": text.replace("MASKOK", "XXXXXX"), "pattern_detections": []}
    elif "DETECTORFAIL" in text:
        out.update(error=True, errors=[{"content_type": leg, "feature": "dlp", "status": "error"}])
    return text, out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, payload, raw=False):
        data = payload if raw else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/__scans":
            with LOCK:
                self.reply(200, list(SCANS))
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length") or 0))
        if self.path == "/__reset":
            with LOCK:
                SCANS.clear()
            return self.reply(200, {"reset": True})
        if self.path != "/v1/scan/sync/request":
            return self.reply(404, {"error": "not found"})
        if self.headers.get("x-pan-token") != KEY:
            return self.reply(401, {"error": {"message": "Invalid API Key or OAuth Token"}})
        try:
            body = json.loads(raw)
        except ValueError:
            return self.reply(400, {"error": {"message": "bad json"}})
        with LOCK:
            SCANS.append(body)
            n = len(SCANS)
        for content in body.get("contents") or []:
            if isinstance(content, dict) and "tool_event" in content:
                why = tool_event_error(content["tool_event"]) if isinstance(content["tool_event"], dict) else "bad tool_event"
                if why:
                    return self.reply(400, {"error": {"message": f'"{why}"\n'}})
        text, out = verdict(body, n)
        if "SLOWME" in text:
            time.sleep(10)
        if "ERR500" in text:
            return self.reply(500, {"error": {"message": "internal"}})
        if "GARBAGE" in text:
            return self.reply(200, b"<html>not json</html>", raw=True)
        self.reply(200, out)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certs/airs.crt", "/certs/airs.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()

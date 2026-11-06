"""A TLS mock of the Prisma AIRS sync scan API for the Local Mode harness.

It judges the element of `contents` that is scanned (the last one; earlier elements are context) by markers:
BLOCKME blocks, DLPME blocks as sensitive data with masked text, MASKOK allows with masked text, DETECTORFAIL allows
with a failed detection service, SLOWME waits 10 s, ERR500 answers 500, GARBAGE answers a body that is not JSON.
Every scan body is kept for GET /__scans; POST /__reset clears them. Standard library only.
"""
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = "FAKE-ITEST-KEY"
SCANS = []
LOCK = threading.Lock()


def verdict(body, n):
    contents = body.get("contents") or [{}]
    last = contents[-1] if isinstance(contents, list) and contents else {}
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

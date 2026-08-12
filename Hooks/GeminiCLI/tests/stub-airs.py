#!/usr/bin/env python3
# Fake AIRS tenant for offline detection tests. NOT a real scanner — it returns
# action:block when the request body contains the injection sentinel, else action:allow,
# so run-tests.sh can prove the hooks ACT differently on benign vs malicious content.
import sys, json
from http.server import BaseHTTPRequestHandler, HTTPServer

SENTINEL = "ignore all previous instructions"

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        blocked = SENTINEL in body
        resp = {
            "action": "block" if blocked else "allow",
            "category": "malicious" if blocked else "benign",
            "scan_id": "stub-scan", "report_id": "stub-report",
            "prompt_detected": {"injection": True} if blocked else {},
            "response_detected": {},
        }
        out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8770
    HTTPServer(("127.0.0.1", port), H).serve_forever()

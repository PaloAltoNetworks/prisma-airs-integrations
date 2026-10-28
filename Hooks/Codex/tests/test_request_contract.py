#!/usr/bin/env python3
"""Black-box Prisma AIRS hook metadata conformance checks (no tenant required).

Run: python3 Hooks/Codex/tests/test_request_contract.py
Uses a local HTTP stub; does not transmit prompts or credentials externally.
"""
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = Path(__file__).resolve().parent
COD = HERE.parent
BASE_COMMANDS = {
    "nodejs": ["node", str(COD / "nodejs/.codex/hooks/hooks.mjs")],
    "bash": ["bash", str(COD / "bash/.codex/hooks/airs-hooks.sh")],
    "powershell": [
        "pwsh", "-NoProfile", "-File",
        str(COD / "powershell/.codex/hooks/airs-hooks.ps1"),
    ],
}


class Collector(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.received.put(json.loads(body))
        result = {
            "action": "allow",
            "scan_id": "test-local-contract-scan",
            "report_id": "test-local-contract-report",
            "prompt_detected": {},
            "response_detected": {},
        }
        payload = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class HookRequestContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(prefix="airs-contract-")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        cls.httpd.received = queue.Queue()
        cls.worker = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.worker.start()
        cls.available = [
            name for name in BASE_COMMANDS if shutil.which(BASE_COMMANDS[name][0])
        ]
        if not cls.available:
            raise unittest.SkipTest("No hook runtimes available")
        print("Contract runtimes:", ", ".join(cls.available))
        missing = sorted(set(BASE_COMMANDS) - set(cls.available))
        if missing:
            print("Not full cross-runtime assurance; unavailable:", ", ".join(missing))

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.worker.join(timeout=3)
        cls.tempdir.cleanup()

    def execute(self, runtime, event, obj):
        # Explicitly whitelist the environment: the only endpoint is localhost.
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "LANG": "en_US.UTF-8",
            "PRISMA_AIRS_URL": f"http://127.0.0.1:{self.httpd.server_port}",
            "PRISMA_AIRS_API_KEY": "local-fake-key",
            "PRISMA_AIRS_PROFILE_NAME": "local-fake-profile",
            "AIRS_REQUIRE_CONFIG": "1",
            "AIRS_RETRIES": "0",
            "AIRS_FAIL_MODE": "closed",
            "SECURITY_LOG_PATH": str(Path(self.tempdir.name) / "hook.log"),
        }
        args = list(BASE_COMMANDS[runtime])
        if runtime == "powershell":
            args.extend(["-Vendor", "codex", "-EventName", event])
        else:
            args.extend(["--vendor", "codex", "--event", event])
        completed = subprocess.run(
            args, input=json.dumps(obj), text=True, capture_output=True,
            env=env, cwd=str(COD), timeout=15,
        )
        self.assertEqual(
            completed.returncode, 0,
            f"{runtime} exit {completed.returncode}: {completed.stderr[:500]} "
            f"stdout={completed.stdout[:500]}",
        )
        try:
            result = self.httpd.received.get(timeout=2)
        except queue.Empty:
            self.fail(f"{runtime}: hook succeeded but emitted no scan request")
        self.assertTrue(self.httpd.received.empty(), "Unexpected additional scan requests")
        return result

    def test_explicit_correlation_and_tool_context(self):
        for runtime in self.available:
            with self.subTest(runtime=runtime):
                request = self.execute(runtime, "PreToolUse", {
                    "session_id": "session-contract-001",
                    "tool_use_id": "turn-contract-002",
                    "tool_name": "mcp__reference__inspect",
                    "tool_input": {"note": "benign synthetic fixture"},
                })
                self.assertEqual(request["session_id"], "session-contract-001")
                self.assertEqual(request["transaction_id"], "turn-contract-002")
                self.assertEqual(request["ai_profile"]["profile_name"], "local-fake-profile")
                self.assertEqual(request["metadata"]["app_name"], "Codex CLI")
                self.assertEqual(request["metadata"]["app_user"], "codex-user")
                self.assertEqual(
                    request["contents"][0]["tool_event"]["metadata"]["method"],
                    "tools/call",
                )

    def test_missing_transaction_id_is_unique(self):
        for runtime in self.available:
            with self.subTest(runtime=runtime):
                event = {
                    "session_id": "existing-session",
                    "tool_name": "mcp__reference__inspect",
                    "tool_input": {"note": "benign synthetic fixture"},
                }
                a = self.execute(runtime, "PreToolUse", event)
                b = self.execute(runtime, "PreToolUse", event)
                self.assertEqual(a["session_id"], "existing-session")
                self.assertEqual(b["session_id"], "existing-session")
                self.assertNotEqual(a["transaction_id"], b["transaction_id"])
                self.assertTrue(a["transaction_id"])
                self.assertTrue(b["transaction_id"])

    def test_identifier_precedence(self):
        for runtime in self.available:
            with self.subTest(runtime=runtime):
                base = {
                    "session_id": "session-priority",
                    "tool_name": "mcp__reference__inspect",
                    "tool_input": {"note": "benign synthetic fixture"},
                    "tool_use_id": "tool-call-123",
                    "prompt_id": "prompt-456",
                    "turn_id": "turn-789",
                }
                request = self.execute(runtime, "PreToolUse", base)
                self.assertEqual(request["transaction_id"], "tool-call-123")
                without_tool_id = dict(base)
                del without_tool_id["tool_use_id"]
                request = self.execute(runtime, "PreToolUse", without_tool_id)
                self.assertEqual(request["transaction_id"], "prompt-456")
                only_turn = dict(without_tool_id)
                del only_turn["prompt_id"]
                request = self.execute(runtime, "PreToolUse", only_turn)
                self.assertEqual(request["transaction_id"], "turn-789")

    def test_no_session_id_fallback_is_deterministic(self):
        # Synthetic path, not a private project path.
        synthetic_cwd = "/synthetic/independent/reference-check"
        expected = hashlib.sha256(synthetic_cwd.encode()).hexdigest()[:32]
        for runtime in self.available:
            with self.subTest(runtime=runtime):
                request = self.execute(runtime, "UserPromptSubmit", {
                    "cwd": synthetic_cwd,
                    "prompt": "synthetic ordinary prompt",
                })
                self.assertEqual(request["session_id"], expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)

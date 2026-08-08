# Cursor hooks — shared test fixtures

Runtime-agnostic payloads for exercising the Cursor security hooks. Each file in [`fixtures/`](./fixtures/) is a raw stdin payload, ready to pipe into any hook of any runtime (bash, PowerShell, and the planned Node.js engine). Expected verdicts are the same across runtimes because the runtimes are behavior-for-behavior equivalent.

## Fixtures and expected verdicts

The verdict depends on whether credentials are configured. With **no credentials**, hooks either short-circuit (allow/skip paths that run before any scan) or **fail closed** (block). With **credentials**, content is scanned live and the verdict depends on your AIRS profile.

| Fixture | Hook | No credentials | With credentials (live) |
|---------|------|----------------|--------------------------|
| `prompt-empty.json` | `beforeSubmitPrompt` | allow — `{"continue":true}` | allow |
| `prompt-benign.json` | `beforeSubmitPrompt` | fail closed — block, exit 2 | allow |
| `prompt-injection.json` | `beforeSubmitPrompt` | fail closed — block, exit 2 | block (`injection`) |
| `mcp-empty-input.json` | `beforeMCPExecution` | allow — `{"permission":"allow"}` | allow |
| `mcp-injection.json` | `beforeMCPExecution` | fail closed — deny, exit 2 | deny (`injection`) |
| `tooluse-builtin.json` | `postToolUse` | allow — `{}` (built-in skipped) | allow (skipped) |
| `tooluse-empty-output.json` | `postToolUse` | allow — `{}` (empty output) | allow (skipped) |
| `tooluse-eicar.json` | `postToolUse` | fail closed — block | block (`malicious_code`) |
| `response-empty.json` | `afterAgentResponse` | allow — exit 0, no stdout | allow |
| `response-benign.json` | `afterAgentResponse` | fail closed — block, exit 2 | allow |

Live detection depends on your AIRS profile: a malicious payload that returns "allow" usually means the profile does not block that category, not a hook bug.

> The "output larger than 50 KB is skipped" guardrail is not a fixture (the payload would be too large to store readably); the PowerShell harness generates it inline.

## Running a fixture

**bash** (from this `tests/` directory):

```bash
bash ../bash/.cursor/hooks/pre_submit_prompt.sh   < fixtures/prompt-injection.json
bash ../bash/.cursor/hooks/pre_mcp_execution.sh   < fixtures/mcp-injection.json
bash ../bash/.cursor/hooks/scan_response.sh       < fixtures/tooluse-eicar.json
bash ../bash/.cursor/hooks/agent_response_scan.sh < fixtures/response-benign.json
```

**PowerShell**:

```powershell
Get-Content fixtures/prompt-injection.json | pwsh -NoProfile -File ../powershell/.cursor/hooks/pre_submit_prompt.ps1
```

Or run the whole suite automatically with the PowerShell harness, which covers these scenarios (offline always; live when credentials are set):

```powershell
pwsh -NoProfile -File ../powershell/test-hooks.ps1
```

**Node.js**: planned — the fixtures are ready to reuse once the engine lands.

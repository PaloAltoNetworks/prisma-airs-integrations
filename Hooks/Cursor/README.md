# Cursor × Prisma AIRS security hooks

Scan every checkpoint of **Cursor** through Prisma AIRS — pick a runtime and drop
the matching `.cursor/` folder into your project.

## Choose your runtime
| Flavor | Requires | Best for |
|--------|----------|----------|
| [`nodejs/`](nodejs/) | Node.js 18+ (no jq/curl) | Full engine — DLP mask-in-place + chunking |
| [`bash/`](bash/) | bash + jq + curl | macOS / Linux |
| [`powershell/`](powershell/) | PowerShell 5.1+ / 7 (no jq/curl) | Windows-native |

Each folder is self-contained (engine + wiring + this vendor's `.cursor/`). Shared
`example.env` documents every variable; `tests/` runs the same fixtures against all
three runtimes.

## Coverage
> Detection categories: <https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/>

| Prompt | Response | Streaming | Pre-tool | Post-tool |
|:---:|:---:|:---:|:---:|:---:|
| ⚠️ | ❌ | ❌ | ✅ | ⚠️ |

Cursor reads hook decisions from **stdout** (there is no fd 3). **Pre-tool** is the hard block: `beforeShellExecution` / `beforeMCPExecution` return `{"permission":"deny"}`. **Post-tool** (`postToolUse`) can't hard-block, but it scans the tool output and — for **MCP tools** — **redacts** the model-visible result (`updated_mcp_tool_output`) plus warns (`additional_context`); non-MCP output can only be warned (Cursor's redaction is MCP-only). `beforeSubmitPrompt` is **advisory** (record-only), and Cursor exposes **no way to block the model's answer** (`afterAgentResponse` doesn't fire in the CLI). Tool input/output is scanned as a `tool_event` (`tools/call`) for **indirect prompt injection**.

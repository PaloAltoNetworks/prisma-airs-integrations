# GeminiCLI × Prisma AIRS security hooks

Scan every checkpoint of **GeminiCLI** through Prisma AIRS — pick a runtime and drop
the matching `.gemini/` folder into your project.

## Choose your runtime
| Flavor | Requires | Best for |
|--------|----------|----------|
| [`nodejs/`](nodejs/) | Node.js 18+ (no jq/curl) | Full engine — DLP mask-in-place + chunking |
| [`bash/`](bash/) | bash + jq + curl | macOS / Linux |
| [`powershell/`](powershell/) | PowerShell 5.1+ / 7 (no jq/curl) | Windows-native |

Each folder is self-contained (engine + wiring + this vendor's `.gemini/`). Shared
`example.env` documents every variable; `tests/` runs the same fixtures against all
three runtimes.

## Coverage
> Detection categories: <https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/>

| Prompt | Response | Streaming | Pre-tool | Post-tool |
|:---:|:---:|:---:|:---:|:---:|
| ✅ | ⚠️ | ❌ | ✅ | ✅ |

Gemini CLI reads hooks from `.gemini/settings.json` and blocks via **exit code 2** (stderr = reason). All four checkpoints are real events: `BeforeAgent` (prompt), `BeforeTool` (pre-tool), `AfterTool` (post-tool, receives `tool_response`), and `AfterAgent` (response, receives `prompt_response`). **Prompt and Pre-tool are verified end-to-end on a live Gemini CLI** (Vertex + ADC); **Post-tool** uses the same exit-2 block on `AfterTool`; **Response** (`AfterAgent`) is **advisory** — exit 2 there triggers a model retry (loop risk), so the answer is scanned and alerted, not hard-blocked. Tool input/output is sent as a `tool_event` (`tools/call`) to catch **indirect prompt injection**.

# Devin × Prisma AIRS security hooks

Scan every checkpoint of **Devin** through Prisma AIRS — pick a runtime and drop
the matching `.devin/` folder into your project.

## Choose your runtime
| Flavor | Requires | Best for |
|--------|----------|----------|
| [`nodejs/`](nodejs/) | Node.js 18+ (no jq/curl) | Full engine — DLP mask-in-place + chunking |
| [`bash/`](bash/) | bash + jq + curl | macOS / Linux |
| [`powershell/`](powershell/) | PowerShell 5.1+ / 7 (no jq/curl) | Windows-native |

Each folder is self-contained (engine + wiring + this vendor's `.devin/`). Shared
`example.env` documents every variable; `tests/` runs the same fixtures against all
three runtimes.

## Coverage
> Detection categories: <https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/>

| Prompt | Response | Streaming | Pre-tool | Post-tool |
|:---:|:---:|:---:|:---:|:---:|
| ⚠️ | ❌ | ❌ | ✅ | ⚠️ |

Devin's CLI hooks speak the Claude contract on **input** (`prompt` / `tool_name` / `tool_input` / `tool_response`), but enforcement is narrower: **`PreToolUse` is the only hard block** (exit 2). `UserPromptSubmit` and `PostToolUse` are **advisory** — scanned, with an alert and injected context, but they cannot stop an action — and **`Stop` carries no final answer or transcript**, so the model's answer is not scanned. Tool input/output is sent as a `tool_event` (`tools/call`) to catch **indirect prompt injection**.

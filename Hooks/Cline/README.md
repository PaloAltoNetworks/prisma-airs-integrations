# Cline × Prisma AIRS security hooks

Scan every checkpoint of **Cline** through Prisma AIRS — pick a runtime and drop
the matching `.clinerules/` folder into your project.

## Choose your runtime
| Flavor | Requires | Best for |
|--------|----------|----------|
| [`nodejs/`](nodejs/) | Node.js 18+ (no jq/curl) | Full engine — DLP mask-in-place + chunking |
| [`bash/`](bash/) | bash + jq + curl | macOS / Linux |
| [`powershell/`](powershell/) | PowerShell 5.1+ / 7 (no jq/curl) | Windows-native |

Each folder is self-contained (engine + wiring + this vendor's `.clinerules/`). Shared
`example.env` documents every variable; `tests/` runs the same fixtures against all
three runtimes.

## Coverage
> Detection categories: <https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/>

| Prompt | Response | Streaming | Pre-tool | Post-tool |
|:---:|:---:|:---:|:---:|:---:|
| ✅ | ✅ | ❌ | ✅ | ✅ |

Prompt scanned on input; the model's answer on Stop; tool input/output as `tool_event` (method `tools/call`) so tool results are checked for **indirect prompt injection**, not treated as a plain response.

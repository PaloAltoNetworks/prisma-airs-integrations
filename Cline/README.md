# Cline + Prisma AIRS Security Hooks

Runtime security scanning for [Cline](https://github.com/cline/cline) using [Prisma AIRS](https://docs.paloaltonetworks.com/ai-runtime-security). User prompts, tool calls, and tool responses are scanned for malicious content with the ability to **block** before they reach the model or execute.

```
User Prompt ──► UserPromptSubmit ──► Model ──► PreToolUse ──► Tool Execution
                   (scan/block)                (scan/block)        │
                                                                   ▼
                         Model Response ◄──── PostToolUse ◄────────┘
                           (no hook)          (scan/block)
                                │
                                ▼
                          TaskComplete
                           (audit log)
```

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | Scans user prompts via `UserPromptSubmit` before the model processes them |
| Response | ❌ | No model response hook — see [Limitations](#limitations) |
| Streaming | ❌ | Not supported |
| Pre-tool call | ✅ | Scans shell commands, MCP tool args, file writes via `PreToolUse` |
| Post-tool call | ✅ | Scans tool response content via `PostToolUse` |

## Limitations

- **No model response hook.** Cline has no hook that fires on the model's direct text output. If the model generates sensitive content (e.g. DLP — reconstructing a credit card number from fragments) without using a tool, no hook can block it. Only `TaskComplete` sees it, but it's [hardcoded as non-cancellable](https://github.com/cline/cline/blob/main/src/core/task/tools/handlers/AttemptCompletionHandler.ts) (`isCancellable: false`).
- **PostToolUse only fires on tool calls.** If the model answers directly without invoking a tool, `PostToolUse` never runs.
- **Content truncation.** `PostToolUse` truncates response content to 20,000 characters before scanning.

## Project Structure

```
.clinerules/hooks/
├── UserPromptSubmit     # Scans user prompts (can block)
├── PreToolUse           # Scans commands, MCP requests, file writes (can block)
├── PostToolUse          # Scans tool responses + URLs (can block)
├── TaskComplete         # Audit scan of completed tasks (log only)
└── lib/
    └── prisma-airs.sh   # Shared config, AIRS API client, respond() helper
.env                     # PRISMA_AIRS_API_KEY / PRISMA_AIRS_PROFILE_NAME
```

## Setup

### 1. Clone and configure

```bash
git clone <repo-url> && cd cline-hooks
cp .env.example .env
```

Edit `.env`:

```
PRISMA_AIRS_API_KEY=your-api-key-here
PRISMA_AIRS_PROFILE_NAME=your-security-profile-name
```

### 2. Open in VS Code with Cline

Cline auto-discovers hooks from `.clinerules/hooks/` — no configuration needed. Open this folder in VS Code with the [Cline extension](https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev) installed.


## How It Works

Each hook receives JSON on stdin and returns JSON on stdout:

```jsonc
{"cancel": false}                                           // allow
{"cancel": true, "errorMessage": "Blocked by AIRS: ..."}   // block
{"cancel": false, "contextModification": "Note: ..."}       // allow + inject context
```

| Hook | What it scans | Can block? |
|---|---|---|
| **UserPromptSubmit** | User's raw prompt text | Yes |
| **PreToolUse** | Shell commands, MCP tool args, file writes | Yes |
| **PostToolUse** | Tool response content (MCP as tool_event, others as response) | Yes |
| **TaskComplete** | Final task result | No (`isCancellable: false`) |

**PreToolUse** extracts content smartly per tool type — search queries, target URLs, file content, or falls back to serializing full arguments.

**PostToolUse** truncates to 20,000 characters and sends to AIRS. MCP tools are scanned as `tool_event` (structured input + output with server/tool metadata); other tools as `response`.

## Logs

Events are written to `.clinerules/hooks/lib/prisma-airs.log`:

```
[Mon Mar 16 14:30:02 CDT 2026] BLOCKED execute_command: malicious-content - detected: [prompt_injection] [scan:abc123]
[Mon Mar 16 14:31:16 CDT 2026] MALICIOUS CONTENT in github__search_code response: malware - detected: [malicious_url] [scan:def456]
```

## Requirements

- [Cline](https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev) VS Code extension
- [Prisma AIRS](https://docs.paloaltonetworks.com/ai-runtime-security) API access
- `jq` and `curl`

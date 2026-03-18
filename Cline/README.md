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

## Platform Comparison

| Hook Point | Claude Code | Windsurf | Cline |
|---|---|---|---|
| **Pre user input** | block (exit 2 + FD3) | block (exit 2) | block (`cancel:true`) |
| **Pre tool use** | block (exit 2) | block (exit 2) | block (`cancel:true`) |
| **Post tool use** | block (FD3 JSON) | log only | **block (`cancel:true`)** |
| **Model response** | log only | log only | **no hook** |
| **Task end** | log only | log only | log only (`isCancellable: false`) |
| **Context injection** | no | no | yes (`contextModification`) |

## Limitations

- **No model response hook.** Cline has no hook that fires on the model's direct text output. If the model generates sensitive content (e.g. DLP — reconstructing a credit card number from fragments) without using a tool, no hook can block it. Only `TaskComplete` sees it, but it's [hardcoded as non-cancellable](https://github.com/cline/cline/blob/main/src/core/task/tools/handlers/AttemptCompletionHandler.ts) (`isCancellable: false`).
- **PostToolUse only fires on tool calls.** If the model answers directly without invoking a tool, `PostToolUse` never runs.
- **Content truncation.** `PostToolUse` scans the first 2KB of response content. Payloads beyond that boundary are not scanned.

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
| **PostToolUse** | Tool response content + extracted URLs | Yes |
| **TaskComplete** | Final task result | No (`isCancellable: false`) |

**PreToolUse** extracts content smartly per tool type — search queries, target URLs, file content, or falls back to serializing full arguments.

**PostToolUse** runs two phases: (1) extract and scan all URLs individually, (2) scan first 2KB of response body. Either phase can block.

## Logs

Events are written to `.clinerules/hooks/lib/prisma-airs.log`:

```
[Mon Mar 16 14:30:02 CDT 2026] BLOCKED execute_command: malicious-content - detected: [prompt_injection] [scan:abc123]
[Mon Mar 16 14:31:16 CDT 2026] MALICIOUS URL in github__search_code response: http://evil.com (malware) [scan:def456]
```

## Requirements

- [Cline](https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev) VS Code extension
- [Prisma AIRS](https://docs.paloaltonetworks.com/ai-runtime-security) API access
- `jq` and `curl`

# Prisma AIRS Security Hooks for Windsurf Cascade

Windsurf Cascade hooks that scan prompts, commands, MCP tool calls, and responses via the [Prisma AIRS](https://docs.paloaltonetworks.com/ai-runtime-security) API.

## What it does

| Hook | Event | Action | AIRS Content Type | Note |
|---|---|---|---|---|
| `scan-user-input.sh` | `pre_user_prompt` | **Block** (exit 2) | `prompt` | |
| `scan-run-command.sh` | `pre_run_command` | **Block** (exit 2) | `prompt` | ⚠️ See [Limitations](#limitations) |
| `scan-mcp-request.sh` | `pre_mcp_tool_use` | **Block** (exit 2) | `tool_event` (input only) | |
| `scan-mcp-response.sh` | `post_mcp_tool_use` | Alert only | `tool_event` (input + output) | |
| `scan-cascade-response.sh` | `post_cascade_response` | Log only | `response` | No user-visible alert |

Pre-hooks can block by exiting with code 2. Post-hooks are audit/alert only.

## Setup

### Prerequisites

- `jq` and `curl` installed
- A Prisma AIRS API key and security profile

### Configuration

```bash
cp .env.example .env
```

Edit `.env` with your values:

```
PRISMA_AIRS_API_KEY=your-api-key
PRISMA_AIRS_PROFILE_NAME=your-security-profile-name
```

The hooks are configured in `.windsurf/hooks.json` and activate automatically when opening the project in Windsurf.

## File structure

```
.windsurf/
  hooks.json              # Hook definitions
  hooks/
    prisma-airs.sh        # Shared config, AIRS API functions, logging
    scan-user-input.sh    # Pre-hook: scan user prompts
    scan-run-command.sh   # Pre-hook: scan terminal commands
    scan-mcp-request.sh   # Pre-hook: scan MCP tool arguments
    scan-mcp-response.sh  # Post-hook: scan MCP tool results
    scan-cascade-response.sh  # Post-hook: scan Cascade output
    prisma-airs.log       # Local audit log (gitignored)
```

## Logging

All scan results are logged to `.windsurf/hooks/prisma-airs.log` with timestamps, scan IDs, detection categories, and verdicts. Scans are correlated per Cascade session using Windsurf's `trajectory_id`.

## Limitations

- **Post-hooks cannot block or modify content.** Windsurf does not support `exit 2`, output replacement, or any enforcement mechanism on `post_mcp_tool_use` or `post_cascade_response` hooks. Flagged content is logged but not prevented from reaching the user. `scan-mcp-response.sh` alerts the user via `show_output: true` in `hooks.json`; `scan-cascade-response.sh` logs only (no user-visible alert). This is a Windsurf platform constraint.
- **No MCP response redaction.** Unlike Cursor (which supports `updated_mcp_tool_output`), Windsurf has no way to replace or redact MCP tool results after execution. Blocking MCP responses requires an external MCP proxy.
- **`show_output: true` is user-facing only.** Stdout from post-hooks is displayed in the Windsurf UI for the user to see. It is not injected into Cascade's model context and does not influence Cascade's behavior.
- **Post-hook content is truncated to 2000 characters** before being sent to AIRS. `scan-mcp-response.sh` and `scan-cascade-response.sh` truncate output to stay within API limits and keep latency low. Pre-hooks (`scan-user-input.sh`, `scan-run-command.sh`, `scan-mcp-request.sh`) send full content without truncation.
- **`pre_run_command` hook is not registered.** The `scan-run-command.sh` script is provided but is not wired up in `.windsurf/hooks.json`. To enable terminal command scanning, add a `pre_run_command` entry to `hooks.json` (see the `pre_user_prompt` entry as a template).
- **Fail-open on errors.** If the AIRS API is unreachable, returns an error, or the API key is not configured, all hooks allow the action to proceed (exit 0) and log the failure.
- **`tool_event` vs `response` detection coverage may differ.** The AIRS `tool_event` content type may not trigger the same detection rules (e.g., DLP, toxic content) as the `response` content type, depending on your AIRS profile configuration.

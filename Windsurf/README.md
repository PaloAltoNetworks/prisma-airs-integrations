# Prisma AIRS Security Hooks for Windsurf Cascade

Windsurf Cascade hooks that scan prompts, commands, MCP tool calls, and responses via the [Prisma AIRS](https://docs.paloaltonetworks.com/ai-runtime-security) API.

Part of the [Prisma AIRS IDE Integrations](https://github.com/PaloAltoNetworks/prisma-airs-integrations) project.

## What it does

| Hook | Event | Action | AIRS Content Type |
|---|---|---|---|
| `scan-user-input.sh` | `pre_user_prompt` | **Block** (exit 2) | `prompt` |
| `scan-run-command.sh` | `pre_run_command` | **Block** (exit 2) | `prompt` |
| `scan-mcp-request.sh` | `pre_mcp_tool_use` | **Block** (exit 2) | `prompt` |
| `scan-mcp-response.sh` | `post_mcp_tool_use` | Alert only | `tool_event` |
| `scan-cascade-response.sh` | `post_cascade_response` | Alert only | `response` |

Pre-hooks can block by exiting with code 2. Post-hooks are audit/alert only.

### MCP response scanning

The `post_mcp_tool_use` hook sends MCP tool results to AIRS as a single `tool_event` scan with structured server/tool metadata and both input + output. Response content scanning (DLP, toxic content) is handled separately by the `post_cascade_response` hook.

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
# Or use profile UUID instead:
# PRISMA_AIRS_PROFILE_ID=your-profile-uuid
```

One of `PRISMA_AIRS_PROFILE_NAME` or `PRISMA_AIRS_PROFILE_ID` is required. If both are set, `profile_id` takes precedence.

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

- **Post-hooks cannot block or modify content.** Windsurf does not support `exit 2`, output replacement, or any enforcement mechanism on `post_mcp_tool_use` or `post_cascade_response` hooks. Flagged MCP responses and Cascade output are logged and alerted but not prevented from reaching the user. This is a [Windsurf platform constraint](https://docs.windsurf.com/windsurf/cascade/hooks).
- **No MCP response redaction.** Windsurf has no way to replace or redact MCP tool results after execution. Blocking MCP responses requires an external MCP proxy.
- **`show_output: true` is user-facing only.** Stdout from post-hooks is displayed in the Windsurf UI for the user to see. It is not injected into Cascade's model context and does not influence Cascade's behavior.
- **Post-hook content is truncated to 20,000 characters** before being sent to AIRS. `scan-mcp-response.sh` and `scan-cascade-response.sh` truncate to keep latency low. Pre-hooks send full content without truncation.
- **Fail-closed on misconfiguration.** If the API key is not configured, pre-hooks block the action (exit 2) and post-hooks signal an error (exit 1). This ensures security scanning cannot be silently bypassed by missing credentials.
- **`tool_event` vs `response` detection coverage may differ.** The AIRS `tool_event` content type may not trigger the same detection rules (e.g., DLP, toxic content) as the `response` content type, depending on your AIRS profile configuration. The post-hook scans with both types to maximize coverage.

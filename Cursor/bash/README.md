# Cursor Security Hooks — bash runtime (macOS / Linux)

Install and verify steps for the bash implementation of the Cursor security hooks. For the overview, coverage matrix, hook contracts, configuration, and limitations, see the [Cursor README](../README.md).

## Prerequisites

- Cursor IDE (with hooks support)
- Prisma AIRS API access with a valid API key
- `jq` and `curl` available in `PATH`

```bash
# macOS
brew install jq

# Debian / Ubuntu
sudo apt-get install jq curl
```

## Install

**1. Copy the hooks into your project**

```bash
cd /your/project
cp -r /path/to/Cursor/bash/.cursor .cursor   # or copy the bash/.cursor folder in
```

The `.cursor/hooks.json` and `.cursor/hooks/` scripts are structured for project-level use.

**2. Make the scripts executable**

```bash
chmod +x .cursor/hooks/*.sh
```

**3. Configure credentials**

Copy [`example.env`](../example.env) to `.env` in your project root and fill it in, or export the variables:

```bash
export PRISMA_AIRS_API_KEY="your-prisma-airs-api-key"
export PRISMA_AIRS_PROFILE_NAME="your-security-profile-name"
# Optional regional endpoint (default is US):
# export PRISMA_AIRS_API_URL="https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
```

The scripts also load a `.env` file from the project root if present. See [Configuration](../README.md#configuration) for all variables.

**4. Restart Cursor**

`.cursor/hooks.json` is pre-wired to `bash .cursor/hooks/*.sh` with a 5000 ms timeout. Cursor detects it on restart.

## Verify

```bash
# Allowed prompt (no credentials needed for this path)
echo '{"prompt": "Hello world"}' | bash .cursor/hooks/pre_submit_prompt.sh   # -> {"continue":true}

# Watch the log
tail -f .cursor/hooks/prisma-airs.log
```

With credentials configured, exercise detection using the shared fixtures in [`../tests/fixtures/`](../tests/fixtures/):

```bash
# Prompt injection -> block (exit 2)
bash .cursor/hooks/pre_submit_prompt.sh  < ../tests/fixtures/prompt-injection.json

# MCP tool input injection -> deny (exit 2)
bash .cursor/hooks/pre_mcp_execution.sh  < ../tests/fixtures/mcp-injection.json

# EICAR in tool output -> block
bash .cursor/hooks/scan_response.sh      < ../tests/fixtures/tooluse-eicar.json

# Benign response -> allow
bash .cursor/hooks/agent_response_scan.sh < ../tests/fixtures/response-benign.json
```

Expected verdicts for every fixture are listed in the [tests README](../tests/). Live detection depends on your AIRS profile: a malicious payload that returns "allow" usually means the profile does not block that category, not a hook bug.

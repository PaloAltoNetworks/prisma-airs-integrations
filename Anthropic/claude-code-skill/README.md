# Prisma AIRS Skill for Claude Code

A Claude Code skill that integrates Palo Alto Networks Prisma AI Runtime Security (AIRS) for scanning prompts, code, and AI responses for security threats.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | User-invoked via `/airs-scan` command with `--type prompt` |
| Response | ✅ | User-invoked scanning of AI-generated content |
| Streaming | ❌ | Synchronous blocking scan only |
| Pre-tool call | ❌ | Not designed for pre-tool validation |
| Post-tool call | ❌ | Not designed for post-tool validation |
| MCP | ❌ | Not designed for MCP interactions |

## Features

- **Prompt Injection Detection**: Identifies attempts to manipulate AI behavior
- **Data Loss Prevention (DLP)**: Detects PII, credentials, API keys, and secrets
- **Malicious URL Detection**: Flags URLs linked to malware, phishing, or threats
- **Toxic Content Detection**: Identifies harmful or inappropriate content
- **Code Security Scanning**: Scans generated code for security vulnerabilities

## Installation

### 1. Copy to Claude Skills Directory

```bash
# Create skills directory if it doesn't exist
mkdir -p ~/.claude/skills

# Copy the skill
cp -r prisma-airs-skill ~/.claude/skills/
```

### 2. Configure Environment Variables

Add the following to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export PRISMA_AIRS_API_KEY="your-api-key-here"
export PRISMA_AIRS_PROFILE="your-profile-name"
# Optional: EU endpoint
# export PRISMA_AIRS_ENDPOINT="https://eu.service.api.aisecurity.paloaltonetworks.com"
```

Or copy the environment template:

```bash
cp .env.example .env
# Edit .env with your credentials
source .env
```

### 3. Obtain API Credentials

1. Log in to [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
2. Navigate to **AI Runtime Security** > **API Intercept**
3. Generate an API key
4. Note your security profile name

## Usage

### As a Slash Command

```
/airs-scan
```

Claude will automatically invoke this skill when appropriate based on the context.

### Manual Invocation

```bash
# Scan a prompt
python ~/.claude/skills/prisma-airs-skill/scripts/scan.py \
  --type prompt \
  --content "user input to scan"

# Scan code from a file
python ~/.claude/skills/prisma-airs-skill/scripts/scan.py \
  --type code \
  --file path/to/generated-code.py

# Scan AI response
python ~/.claude/skills/prisma-airs-skill/scripts/scan.py \
  --type response \
  --content "AI generated response"

# Scan conversation (prompt + response)
python ~/.claude/skills/prisma-airs-skill/scripts/scan.py \
  --type conversation \
  --prompt "user prompt" \
  --response "AI response"
```

## Scan Types

| Type | Use Case |
|------|----------|
| `prompt` | Scan user input before processing |
| `response` | Scan AI-generated content before delivery |
| `code` | Scan generated code for vulnerabilities |
| `conversation` | Scan both prompt and response together |

## Output Format

```json
{
  "status": "safe|threat_detected|error",
  "action": "allow|block|alert",
  "threats": [
    {
      "category": "prompt_injection",
      "severity": "high",
      "location": "prompt",
      "description": "Potential prompt injection attack detected"
    }
  ],
  "scan_id": "unique-identifier"
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Safe - no threats detected |
| 1 | Error - scan failed |
| 2 | Block - threat detected, action blocked |

## Directory Structure

```
prisma-airs-skill/
├── SKILL.md           # Skill definition and instructions
├── README.md          # This file
├── .env.example       # Environment variable template
├── scripts/
│   └── scan.py        # Main scanning script
├── references/        # Additional documentation
└── assets/            # Templates and resources
```

## Requirements

- Python 3.9+
- Network access to AIRS API endpoint
- Valid Prisma AIRS API key and profile

## Limitations

- Maximum 2MB payload per synchronous scan
- Maximum 100 URLs per request
- Requires active Prisma AIRS subscription

## Links

- [Prisma AIRS Documentation](https://docs.paloaltonetworks.com/ai-runtime-security)
- [AIRS API Reference](https://pan.dev/airs/)
- [Claude Code Skills Documentation](https://code.claude.com/docs/en/skills)

## License

Apache 2.0

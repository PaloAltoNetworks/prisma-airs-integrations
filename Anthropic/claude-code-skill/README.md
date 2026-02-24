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
export PRISMA_AIRS_PROFILE_NAME="your-profile-name"
# Optional: Regional endpoints
# export PRISMA_AIRS_URL="https://service-de.api.aisecurity.paloaltonetworks.com"  # EU
# export PRISMA_AIRS_URL="https://service-in.api.aisecurity.paloaltonetworks.com"  # India
# export PRISMA_AIRS_URL="https://service-sg.api.aisecurity.paloaltonetworks.com"  # Singapore
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
/prisma-airs
```

Claude will also automatically invoke this skill when appropriate based on context (e.g., when generating security-sensitive code or handling user input).

### Input Methods

The scanner accepts content via three methods:

```bash
# Method 1: Heredoc (recommended - handles quotes and newlines)
python scripts/scan.py --type prompt <<'EOF'
Content with "quotes" and
multiple lines works fine.
EOF

# Method 2: File (recommended for code)
python scripts/scan.py --type code --file path/to/file.py

# Method 3: Direct argument (simple content only)
python scripts/scan.py --type prompt --content "simple text"

# Conversation (prompt + response together)
python scripts/scan.py --type conversation --prompt "user" --response "ai"
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
  "status": "safe|threat_detected|blocked",
  "action": "allow|block|alert",
  "category": "benign|malicious",
  "scan_id": "unique-identifier",
  "prompt_detected": ["injection", "dlp"],
  "response_detected": ["toxic_content"]
}
```

Use `--verbose` to include the full AIRS API response.

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

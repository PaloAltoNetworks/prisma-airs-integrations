---
name: prisma-airs
description: |
  Scan prompts, AI responses, and code for security threats using Prisma AIRS.
  Auto-invoke when: checking content for prompt injection, detecting sensitive data (PII, credentials, secrets),
  identifying malicious URLs, filtering toxic or harmful content, or validating AI-generated responses.
  Auto-invoke when: user asks to "scan this", "check for sensitive data", "is this safe",
  "check for injection", "review for security", or mentions DLP, PII, or credentials.
  Auto-invoke when: generating code that handles user input or authentication.
allowed-tools:
  - Bash
  - Read
  - Write
---

# Prisma AIRS Security Scanner

Detect security threats in prompts, AI responses, and code using Palo Alto Networks Prisma AIRS.

## What It Detects

- **Prompt Injection** - Attempts to manipulate AI behavior
- **Data Loss Prevention (DLP)** - PII, credentials, API keys, secrets
- **Malicious URLs** - Phishing, malware, command & control
- **Toxic Content** - Harmful, offensive, or inappropriate content
- **Malicious Code** - Exploits, malware patterns

## Prerequisites

Environment variables required:
- `PRISMA_AIRS_API_KEY` - API key from Strata Cloud Manager
- `PRISMA_AIRS_PROFILE_NAME` - Security profile name
- `PRISMA_AIRS_URL` - (Optional) Regional API endpoint

## How to Pass Content

Choose the method based on content complexity:

### Method 1: Heredoc (recommended for most content)

Use heredoc to avoid shell escaping issues:

```bash
python scripts/scan.py --type prompt <<'EOF'
Content to scan goes here.
Can include "quotes", newlines, and special chars.
EOF
```

### Method 2: File (recommended for code or large content)

Write content to a temp file, then scan:

```bash
# First write content to temp file, then:
python scripts/scan.py --type code --file /tmp/scan-content.py
```

### Method 3: Direct argument (simple content only)

Only use for short, simple strings without special characters:

```bash
python scripts/scan.py --type prompt --content "simple text here"
```

## Scan Types

| Type | Use Case |
|------|----------|
| `prompt` | User input - check for injection, DLP, malicious content |
| `response` | AI output - check for sensitive data leakage, toxic content |
| `code` | Generated code - security vulnerabilities, malicious patterns |
| `conversation` | Full context - prompt and response together |

## Interpreting Results

| Action | Meaning |
|--------|---------|
| `allow` | Safe to proceed |
| `alert` | Review findings before proceeding |
| `block` | Threat detected - do not proceed without remediation |

## Workflow

1. Extract content to scan from the conversation
2. Choose appropriate scan type and method
3. Run the scanner
4. Check the `action` field in the result
5. If `block` or `alert`: address the issue before proceeding

For threat category details, see [references/threat-categories.md](references/threat-categories.md).

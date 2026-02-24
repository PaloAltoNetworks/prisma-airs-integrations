---
name: airs-scan
description: |
  Scan code, prompts, and AI responses for security threats using Prisma AIRS (AI Runtime Security).
  Use this skill when: generating code that handles user input, creating API endpoints, writing authentication logic,
  processing external data, generating prompts for AI models, or reviewing code for security vulnerabilities.
  Detects prompt injection attacks, sensitive data leakage (PII, credentials, secrets), malicious URLs,
  toxic content, and other AI-specific security threats.
allowed-tools:
  - Bash
  - Read
---

# Prisma AIRS Security Scanner

Scan prompts, code, and AI responses for security threats using Palo Alto Networks Prisma AIRS.

## Prerequisites

Ensure the following environment variables are set:
- `PRISMA_AIRS_API_KEY` - Your AIRS API key from Strata Cloud Manager
- `PRISMA_AIRS_PROFILE` - Your security profile name (e.g., "default")
- `PRISMA_AIRS_ENDPOINT` - (Optional) API endpoint, defaults to US region

## When to Use This Skill

Invoke this skill in the following scenarios:

1. **Before executing user-provided code or scripts**
2. **When generating API endpoints** that accept user input
3. **When writing authentication or authorization logic**
4. **Before processing prompts** that will be sent to AI models
5. **When handling sensitive data** (PII, credentials, secrets)
6. **During code review** for security vulnerabilities
7. **When generating code** that interacts with external systems

## Usage

### Scan a prompt or text for threats

```bash
python ~/.claude/skills/prisma-airs-skill/scripts/scan.py --type prompt --content "USER_INPUT_HERE"
```

### Scan code for security issues

```bash
python ~/.claude/skills/prisma-airs-skill/scripts/scan.py --type code --file path/to/file.py
```

### Scan AI model response

```bash
python ~/.claude/skills/prisma-airs-skill/scripts/scan.py --type response --content "MODEL_RESPONSE_HERE"
```

### Scan both prompt and response together

```bash
python ~/.claude/skills/prisma-airs-skill/scripts/scan.py --type conversation --prompt "USER_PROMPT" --response "AI_RESPONSE"
```

## Scan Types

| Type | Description |
|------|-------------|
| `prompt` | Scan user prompts for injection attacks, malicious content |
| `response` | Scan AI responses for data leakage, harmful content |
| `code` | Scan generated code for security vulnerabilities |
| `conversation` | Scan both prompt and response in context |

## Interpreting Results

The scanner returns a JSON object with:

```json
{
  "status": "safe|threat_detected|error",
  "action": "allow|block|alert",
  "threats": [
    {
      "category": "prompt_injection|dlp|malicious_url|toxic_content",
      "severity": "low|medium|high|critical",
      "description": "Details about the detected threat"
    }
  ],
  "scan_id": "unique-scan-identifier"
}
```

### Actions Based on Results

- **allow**: Content is safe, proceed with the operation
- **alert**: Potential issue detected, review before proceeding
- **block**: Threat detected, do not proceed without remediation

## Example Workflow

When generating code that handles user input:

1. Generate the initial code
2. Run AIRS scan on the generated code
3. If threats detected, remediate and re-scan
4. Only present code to user after it passes security scan

## Threat Categories

| Category | Description |
|----------|-------------|
| `prompt_injection` | Attempts to manipulate AI behavior through crafted input |
| `dlp` | Sensitive data exposure (PII, credentials, API keys, secrets) |
| `malicious_url` | URLs linked to malware, phishing, or other threats |
| `toxic_content` | Harmful, offensive, or inappropriate content |
| `jailbreak` | Attempts to bypass AI safety measures |

## Limitations

- Maximum 2MB payload per synchronous scan request
- Maximum 100 URLs per request
- Requires network access to AIRS API endpoint

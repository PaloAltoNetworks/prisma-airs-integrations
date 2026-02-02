# Agent Instructions

Instructions for sub-agents working in the prisma-airs-integrations repository.

## Context

This is a documentation repository for Prisma AIRS integrations. Your work here will primarily involve:
- Writing/editing markdown documentation
- Creating configuration examples (YAML, JSON, Lua)
- Writing sample scripts (bash, Python)

## Constraints

### Security
- NEVER include real API keys, tokens, or credentials
- Use placeholders: `YOUR_API_KEY_HERE`, `YOUR_PROFILE_NAME`, etc.
- Sanitize any example payloads - no production data

### Documentation Standards
- Follow the README template structure in `/CONTRIBUTING.md`
- All code examples must be tested and functional
- Include inline comments for complex configurations
- Verify all links before finalizing

### Integration Requirements
- All AIRS integrations MUST include `app_name` in the request metadata
- Format: `<VENDOR_NAME>-<CUSTOMER_APP>` (e.g., `LiteLLM-HR-Chatbot`)
- Use `tr_id` field for platform-specific unique identifiers when available

## File Patterns

When creating new integrations:
```
PlatformName/
├── README.md              # Required: Main integration guide
├── config/                # Optional: Config files
├── scripts/               # Optional: Setup/test scripts
└── examples/              # Optional: Working examples
```

## Validation Checklist

Before completing documentation tasks, verify:
- [ ] All instructions are complete and sequential
- [ ] Code examples are syntactically correct
- [ ] No real credentials included
- [ ] Links are valid
- [ ] Root README.md updated if adding new integration

## Commit Messages

Use conventional commits:
- `docs:` for documentation changes
- `feat:` for new integrations
- `fix:` for corrections
- `test:` for examples/scripts

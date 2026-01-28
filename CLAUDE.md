# Prisma AIRS Integrations

Documentation repository for integrating Prisma AIRS (AI Runtime Security) with third-party platforms.

## Repository Purpose

This is a **documentation-first repository** - primarily markdown guides, configuration examples, and sample code for integrating Prisma AIRS with AI gateways, LLM platforms, and automation tools.

## Structure

```
├── Anthropic/          # Claude Code integration
├── Azure/              # Azure APIM AI Gateway
├── Google/             # Apigee X integration
├── Kong/               # Kong custom plugin & request callout
├── LiteLLM/            # LiteLLM proxy integration
├── n8n/                # Workflow automation
├── Portkey/            # AI Gateway & observability
└── TrueFoundry/        # AI Gateway
```

Each integration follows the template in CONTRIBUTING.md:
- `README.md` - Main setup guide
- `config/` or `examples/` - Sample configurations
- `scripts/` - Setup/test scripts

## Working in This Repo

### Adding New Integrations

1. Create directory: `PlatformName/`
2. Follow structure in CONTRIBUTING.md (line 74-86)
3. Include README with: Prerequisites, Configuration Steps, Validation
4. Update root README.md table with new integration

### Technical Requirements for All Integrations

All integrations MUST:
1. Set `app_name` field in AIRS requests (format: `<VENDOR>-<CUSTOMER_APP>`)
2. Use `tr_id` to pass unique identifiers from the platform when available
3. Never include real credentials - use placeholders like `YOUR_API_KEY_HERE`

### Commit Convention

```
docs: add [Platform] integration guide
fix: correct [Platform] configuration syntax
feat: add automated setup script for [Platform]
test: add validation examples for [Platform]
```

## Key Files

| File | Purpose |
|------|---------|
| `README.md` | Integration index and overview |
| `CONTRIBUTING.md` | Contribution guidelines and templates |

## External Resources

- [Prisma AIRS API Docs](https://pan.dev/airs)
- [Prisma AIRS Admin Guide](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prisma-airs-overview)
- Repo: `PaloAltoNetworks/prisma-airs-integrations`

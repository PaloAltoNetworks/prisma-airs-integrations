# Prisma AIRS Integrations

Documentation repository for integrating Prisma AIRS (AI Runtime Security) with third-party platforms.

## Repository Purpose

This is a **documentation-first repository** - primarily markdown guides, configuration examples, and sample code for integrating Prisma AIRS with AI gateways, LLM platforms, and automation tools.

## Structure

```
├── Anthropic/          # Anthropic integrations (Claude Code hooks, MCP, skill)
├── Microsoft/          # Microsoft integrations (Azure APIM)
├── Google/             # Google Cloud integrations (Apigee)
├── Kong/               # Kong custom plugin & request callout
├── LiteLLM/            # LiteLLM proxy integration
├── n8n/                # Workflow automation
├── Portkey/            # AI Gateway & observability
└── TrueFoundry/        # AI Gateway
```

Each integration follows the template in CONTRIBUTING.md:
- `README.md` - Main setup guide with Coverage table
- `config/` or `examples/` - Sample configurations
- `scripts/` - Setup/test scripts

## Coverage Table Format

Every integration README must include a Coverage section after the title/description. Use this format:

```markdown
## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | Scans user prompts before sending to LLM |
| Response | ✅ | Scans LLM responses before returning to user |
| Streaming | ❌ | Real-time scanning of streamed responses |
| Pre-tool call | ❌ | Scans before tool/function execution |
| Post-tool call | ❌ | Scans tool/function results |
| MCP | ❌ | Scans Model Context Protocol interactions |
```

**Support icons:**
- ✅ Full support
- ⚠️ Partial/conditional support (describe conditions in Description column)
- ❌ No support

**Column definitions:**
- **Prompt**: Scans user input before sending to LLM
- **Response**: Scans LLM output before returning to user
- **Streaming**: Real-time scanning of streamed LLM responses
- **Pre-tool**: Scans before tool/function calls are executed
- **Post-tool**: Scans results returned from tool/function calls
- **MCP**: Scans Model Context Protocol server/tool interactions

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
- [Prisma AIRS Use Cases & Detection Categories](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/)
- [Prisma AIRS Admin Guide](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prisma-airs-overview)
- Repo: `PaloAltoNetworks/prisma-airs-integrations`

# Quick Reference Card

## Policy Fragment: `panw-airs-scan-v3`

### One-Liner
Unified AIRS scanning for LLM APIs (MCP, OpenAI, Anthropic, Azure AI Foundry) - detects threats and sensitive data using Prisma AIRS.

### Supported APIs
- **MCP** - Model Context Protocol tool calling
- **OpenAI** - Chat completions API (`/chat/completions`)
- **Anthropic** - Messages API (`/v1/messages`)
- **Azure AI Foundry Claude** - Messages API (`/v1/messages`)
- **Azure AI Foundry GPT** - Responses API (`/openai/v1/responses`)

### Basic Usage

```xml
<outbound>
    <!-- Unified v3 fragment - auto-detects API type -->
    <include-fragment fragment-id="panw-airs-scan-v3" />
</outbound>
```

### Configuration Options

```xml
<!-- Production: Fail-closed (block on AIRS failure) -->
<set-variable name="FailOpen" value="@(false)" />

<!-- Development: Fail-open (allow on AIRS failure) -->
<set-variable name="FailOpen" value="@(true)" />

<!-- Custom AIRS profile -->
<set-variable name="currentProfile" value="@("prod-mcp")" />

<!-- Custom app name -->
<set-variable name="appName" value="@("ChatApp")" />
```

### What Gets Scanned

#### MCP (Model Context Protocol)
| MCP Method | Scanned? |
|------------|----------|
| `tools/call` | ✅ Yes |
| `initialize` | ❌ No |
| `tools/list` | ❌ No |
| Other methods | ❌ No |

#### OpenAI / Foundry GPT
| Content Type | Scanned? |
|------------|----------|
| User messages | ✅ Yes |
| Assistant responses | ✅ Yes |
| Tool calls (arguments) | ✅ Yes |
| Tool results | ✅ Yes |
| System messages | ❌ No |

#### Anthropic / Foundry Claude
| Content Type | Scanned? |
|------------|----------|
| User messages | ✅ Yes |
| Assistant responses | ✅ Yes |
| Tool use (input) | ✅ Yes |
| Tool results | ✅ Yes |

### AIRS Actions

| Action | HTTP | Description |
|--------|------|-------------|
| Allow | 200 | Content is safe |
| Mask | 200 | Sensitive data redacted |
| Block | 403 | Malicious content blocked |
| Error (fail-closed) | 503 | AIRS unavailable, request blocked |
| Error (fail-open) | 200 | AIRS unavailable, request allowed |

### Placement Guide

```xml
<!-- RECOMMENDED: Scan both prompt and response (outbound only) -->
<outbound>
    <include-fragment fragment-id="panw-airs-scan-v3" />
</outbound>

<!-- Scan only prompts (before backend) -->
<inbound>
    <include-fragment fragment-id="panw-airs-scan-v3" />
</inbound>

<!-- Scan prompts and responses separately (2 AIRS calls per request) -->
<inbound>
    <include-fragment fragment-id="panw-airs-scan-v3" />
</inbound>
<outbound>
    <include-fragment fragment-id="panw-airs-scan-v3" />
</outbound>
```

### Testing Commands

```bash
# Upload fragment
./scripts/update-fragment.sh panw-airs-scan-v3

# Quick test all APIs
./scripts/test-all.sh quick

# Full test suite with trace
./scripts/test-all.sh --trace full

# Test specific API
./scripts/test-openai.sh --trace malicious
./scripts/test-anthropic.sh dlp
./scripts/test-mcp.sh list

# Test multi-turn tool calling
./scripts/test-tool-flow.sh openai --trace
```

### Common Issues

| Problem | Solution |
|---------|----------|
| 401 Unauthorized | Check `AIRS-API` Named Value |
| 503 Service Unavailable | AIRS is down, set `FailOpen=true` for testing |
| Not scanning | Ensure method is `tools/call` |
| SSE parsing error | Update fragment to latest version |

### Environment Setup

1. **Create Named Value** (Azure Portal)
   - Name: `AIRS-API`
   - Value: Your AIRS API key
   - Secret: Yes

2. **Configure Environment** (for testing)
   ```bash
   cp tests/env.sample tests/.env
   # Edit .env with your Azure details
   ```

3. **Deploy Fragment**
   ```bash
   cd tests
   ./scripts/update-fragment.sh
   ```

### Monitoring

```bash
# Check AIRS calls in trace
jq '.traceEntries.outbound[] | select(.source == "send-request")' traces/trace-*.json

# Check for blocks
jq '.traceEntries.outbound[] | select(.source == "return-response" and .data.status.code == 403)' traces/trace-*.json

# Check for fail-open warnings
jq '.traceEntries.outbound[] | select(.source == "panw-airs-mcp-scan")' traces/trace-*.json
```

### Key Files

| File | Purpose |
|------|---------|
| [panw-airs-scan-v3](../panw-airs-scan-v3) | Unified v3 policy fragment XML |
| [panw-airs-scan-v3-optimized](../panw-airs-scan-v3-optimized) | Optimized version (APIM-compatible) |
| [README.md](../README.md) | Full documentation |
| [QUICKSTART.md](QUICKSTART.md) | Testing quick start |
| [scripts/README.md](scripts/README.md) | Detailed script reference |
| [scripts/test-all.sh](scripts/test-all.sh) | Run all API tests |
| [scripts/test-tool-flow.sh](scripts/test-tool-flow.sh) | Multi-turn tool calling tests |

### Support Matrix

| Feature | Status |
|---------|--------|
| Input scanning | ✅ Supported |
| Output scanning | ✅ Supported |
| SSE responses | ✅ Supported |
| JSON responses | ✅ Supported |
| Fail-open mode | ✅ Supported |
| Fail-closed mode | ✅ Supported (default) |
| DLP masking | ✅ Supported |
| Policy blocking | ✅ Supported |
| Session tracking | ✅ Supported |
| Dynamic server name | ✅ Supported |

### Version Info

- **Current Version**: v3 (Unified)
- **Last Updated**: 2026-05-19
- **APIM API Version**: 2023-05-01-preview
- **Tested APIM Tiers**: Developer, Standard, Premium
- **Supported APIs**: MCP, OpenAI, Anthropic, Azure AI Foundry Claude/GPT

### Links

- [Full Documentation](../README.md)
- [Testing Guide](QUICKSTART.md)
- [Script Reference](scripts/README.md)
- [Prisma AIRS Docs](https://pan.dev/airs/)
- [Prisma AIRS Use Cases](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/)

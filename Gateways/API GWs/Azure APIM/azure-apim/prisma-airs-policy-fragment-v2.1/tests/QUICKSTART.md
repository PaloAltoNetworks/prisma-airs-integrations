# Quick Start Guide - AIRS v2.1.1 Unified Fragment

Test all API types supported by the unified v2.1.1 fragment: MCP, OpenAI, Anthropic, and Azure AI Foundry Claude.

## Setup (One-time)

### 1. Configure Environment

```bash
# Copy sample environment file
cp env.sample .env

# Edit .env and configure your API endpoints
nano .env
```

**Required Configuration:**
- `AZURE_SUB_ID` - Your Azure subscription ID
- `AZURE_RG` - Your resource group name
- `AZURE_SERVICE` - Your APIM service name

**API Endpoints (configure those you want to test):**
- `MCP_API_NAME` - MCP server API name in APIM
- `OPENAI_API_NAME` - OpenAI API name in APIM
- `ANTHROPIC_API_NAME` - Anthropic API name in APIM
- `FOUNDRY_CLAUDE_API_NAME` - Azure AI Foundry Claude API name in APIM
- `FOUNDRY_GPT_API_NAME` - Azure AI Foundry GPT API name in APIM

**Model Configuration:**
- `OPENAI_MODEL` - Model to use for OpenAI tests (default: `gpt-4`)
- `ANTHROPIC_MODEL` - Model for Anthropic tests (default: `claude-3-5-sonnet-20241022`)
- `FOUNDRY_CLAUDE_MODEL` - Model for Foundry Claude (default: `claude-haiku-4-5`)
- `FOUNDRY_GPT_MODEL` - Model for Foundry GPT (default: `gpt-5.4-nano`)

**Optional:**
- `AZURE_APIM_KEY` - Subscription key (if required)
- `AZURE_APIM_HEADER` - Header name for API key (default: `Ocp-Apim-Subscription-Key`)
- Override URLs with `*_SERVER_URL` variables for custom domains

### 2. Verify Prerequisites

```bash
# Ensure Azure CLI is installed and logged in
az login
az account show

# Ensure jq is installed
brew install jq   # macOS
# or
apt-get install jq  # Linux
```

## Running Tests

### Quick Test (All APIs)

Test all configured APIs with simple queries:

```bash
./scripts/test-all.sh quick
```

### Full Test Suite

Run all tests including DLP and security tests:

```bash
./scripts/test-all.sh full
```

### Security Tests Only

Run only DLP, malicious content, and injection tests:

```bash
./scripts/test-all.sh security
```

### Individual API Tests

#### MCP Tests

```bash
# Simple tool call
./scripts/test-mcp.sh list

# DLP masking
./scripts/test-mcp.sh dlp

# Malicious content blocking
./scripts/test-mcp.sh malicious

# Custom tool call
./scripts/test-mcp.sh call web_search '{"query": "test"}'
```

#### OpenAI Tests

```bash
# Simple query
./scripts/test-openai.sh simple

# DLP detection
./scripts/test-openai.sh dlp

# Malicious content
./scripts/test-openai.sh malicious

# Prompt injection
./scripts/test-openai.sh injection

# All tests
./scripts/test-openai.sh all
```

#### Anthropic Tests

```bash
# Simple query
./scripts/test-anthropic.sh simple

# DLP detection
./scripts/test-anthropic.sh dlp

# All tests
./scripts/test-anthropic.sh all
```

#### Azure AI Foundry Claude Tests

```bash
# Same as Anthropic (uses same /v1/messages format)
./scripts/test-foundry-claude.sh simple
./scripts/test-foundry-claude.sh dlp
./scripts/test-foundry-claude.sh all
```

#### Azure AI Foundry GPT Tests

```bash
# Uses OpenAI Responses API format (/openai/v1/responses)
./scripts/test-foundry-gpt.sh simple
./scripts/test-foundry-gpt.sh dlp
./scripts/test-foundry-gpt.sh malicious
./scripts/test-foundry-gpt.sh tool
./scripts/test-foundry-gpt.sh all
```

### Multi-Turn Tool Calling Tests

Test complete tool calling workflows across multiple turns:

```bash
# Test OpenAI tool flow (2 turns: tool request → tool result)
./scripts/test-tool-flow.sh openai

# Test Anthropic/Foundry Claude tool flow
./scripts/test-tool-flow.sh foundry-claude

# Test Foundry GPT tool flow
./scripts/test-tool-flow.sh foundry-gpt

# With tracing
./scripts/test-tool-flow.sh openai --trace
```

**What it tests:**
1. **Turn 1:** User asks "What's the weather in San Francisco?" → LLM requests tool call
2. **Turn 2:** App provides tool result → LLM generates final answer
3. **AIRS Scans:** Both tool arguments (input) and tool results (output)

### Enable Tracing

Add `--trace` to capture APIM policy execution details:

```bash
# Trace OpenAI DLP test
./scripts/test-openai.sh --trace dlp

# Trace all APIs
./scripts/test-all.sh --trace full

# Verbose + trace
./scripts/test-all.sh --trace --verbose quick
```

Trace files are saved to `traces/trace-{trace-id}.json`

## Expected Results

### Successful Request (Allow)

```json
{
  "choices": [{
    "message": {
      "content": "2+2 equals 4"
    }
  }]
}
```

### AIRS Block

```json
{
  "error": "🛡️ PRISMA AIRS SECURITY ALERT: REQUEST BLOCKED",
  "details": {
    "injection": "Prompt injection or jailbreak attempt detected"
  }
}
```

### DLP Masking

Sensitive data like SSNs, credit cards, and emails will be masked:
```
123-45-6789 → ***-**-****
test@company.com → ****@*******.***
```

## Troubleshooting

### Authentication Error

```bash
# Clear cached tokens and retry
rm .azure_api_token .azure_debug_token
./scripts/refresh-tokens.sh azure-api
./scripts/refresh-tokens.sh debug
```

### Connection Error

```bash
# Verify API endpoint URL
echo "https://${AZURE_SERVICE}.azure-api.net/${OPENAI_API_NAME}/chat/completions"

# Test basic connectivity
curl -v "https://${AZURE_SERVICE}.azure-api.net/${OPENAI_API_NAME}/chat/completions"
```

### AIRS Not Scanning

1. **Verify fragment is uploaded:**
   ```bash
   # Check if panw-airs-scan-v2.1 exists in APIM
   az apim api policy show --api-id <API_NAME> --service-name $AZURE_SERVICE --resource-group $AZURE_RG
   ```

2. **Check API policy includes fragment:**
   ```xml
   <inbound>
       <set-variable name="scanType" value="prompt" />
       <include-fragment fragment-id="panw-airs-scan-v2.1" />
   </inbound>
   <outbound>
       <set-variable name="scanType" value="response" />
       <include-fragment fragment-id="panw-airs-scan-v2.1" />
   </outbound>
   ```

3. **Verify AIRS API key is configured:**
   - Go to APIM → Named Values
   - Ensure `airs-api` contains your Prisma AIRS API key

4. **Check trace for errors:**
   ```bash
   # Run with trace
   ./scripts/test-openai.sh --trace simple

   # Inspect trace file
   jq '.traceEntries.outbound[] | select(.source | contains("airs") or contains("error"))' traces/trace-*.json
   ```

## Updating the Fragment

After modifying `panw-airs-scan-v2.1` locally:

```bash
./scripts/update-fragment.sh panw-airs-scan-v2.1
```

## Test Configuration

### API Detection (automatic)

The v2.1.1 fragment automatically detects API type:

- **MCP**: Detects `method="tools/call"` in request body
- **OpenAI**: Detects path `/chat/completions`
- **Anthropic**: Detects path `/v1/messages`
- **Foundry Claude**: Detects path `/v1/messages` (same as Anthropic)
- **Foundry GPT**: Detects path `/openai/v1/responses`

### Fail-Open vs Fail-Closed

Configure error handling in your API policy:

```xml
<inbound>
    <!-- Fail-closed (default): Block when AIRS fails -->
    <set-variable name="FailOpen" value="@(false)" />
    <include-fragment fragment-id="panw-airs-scan-v2.1" />
</inbound>

<!-- OR -->

<inbound>
    <!-- Fail-open: Allow when AIRS fails (with warning) -->
    <set-variable name="FailOpen" value="@(true)" />
    <include-fragment fragment-id="panw-airs-scan-v2.1" />
</inbound>
```

## Next Steps

- Review [scripts/README.md](scripts/README.md) for detailed documentation
- Check APIM analytics for request traces
- Configure AIRS profiles in Strata Cloud Manager
- Set up custom threat descriptions:
  ```xml
  <set-variable name="airsDescriptions" value="@{
      return new JObject(
          new JProperty("dlp", "Custom DLP message"),
          new JProperty("injection", "Custom injection message")
      );
  }" />
  ```

## Coverage

The v2.1.1 unified fragment supports:

| API Type | Endpoint | Prompt Scan | Response Scan | Streaming | Tool Events |
|----------|----------|:-----------:|:-------------:|:---------:|:-----------:|
| MCP | `/mcp` | ✅ | ✅ | ✅ (SSE) | ✅ |
| OpenAI | `/chat/completions` | ✅ | ✅ | ✅ (SSE) | ✅ |
| Anthropic | `/v1/messages` | ✅ | ✅ | ✅ (SSE) | ✅ |
| Foundry Claude | `/v1/messages` | ✅ | ✅ | ✅ (SSE) | ✅ |
| Foundry GPT | `/openai/v1/responses` | ✅ | ✅ | ❌ | ✅ |

✅ Full support  
❌ Not supported (Foundry GPT Responses API doesn't support streaming)

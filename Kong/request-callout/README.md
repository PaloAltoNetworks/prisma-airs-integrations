# Kong Konnect - Prisma AIRS
# Prism AIRS API Intercept Request Callout Plugin Integration

Enterprise-grade AI security scanning for Kong Konnect using PAN.dev AI Runtime Security (AIRS) API. This integration provides real-time threat detection and blocking for AI API requests and responses through Kong's managed cloud platform.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | Request phase scans user prompts before forwarding to AI service |
| Response | ❌ | Request-side scanning only (see custom-plugin for response scanning) |
| Streaming | ❌ | Single-phase synchronous scanning only |
| Pre-tool call | ❌ | Not implemented - designed for API request scanning |
| Post-tool call | ❌ | Not implemented - no tool result scanning |
| MCP | ❌ | Not implemented - no MCP support |

## 🚀 Getting Started

### What You Need

1. **Kong Konnect SaaS Account** - Your managed Kong Gateway (cloud.konghq.com)
2. **Prisma AIRS API Key and Security Profile** - From your Strata Cloud Mgr tenant
3. **AI API Service** - The upstream AI service you want to protect (e.g., OpenAI, Claude)

### High-Level Setup Process

#### 1️⃣ **Configure Your AIRS Credentials**
Store your Prisma AIRS credentials securely in Kong Konnect's environment variables:
- Navigate to your Control Plane settings
- Add environment variable: `KONG_VAULT_ENV_AIRS_API_KEY` (your AIRS API key)
- Note your **AIRS Security Profile name** from Strata Cloud Manager (e.g., `production-ai-security`)
- This enables secure vault-based authentication

#### 2️⃣ **Create Your Service & Route**
Set up the AI service you want to protect:
- **Service**: Points to your AI provider (e.g., `https://api.openai.com`)
- **Route**: Defines the API path (e.g., `/v1/chat/completions`)
- Note your **Service ID** for the plugin configuration

#### 3️⃣ **Apply the Request-Callout Plugin**
Use the provided `request-callout-prisma-airs-config.json`:
- Update the `service.id` field with your Service ID
- Update the `profile_name` field with your AIRS Security Profile name
- Apply via Konnect UI or API
- The plugin automatically intercepts, scans, and protects your AI requests

#### 4️⃣ **Test & Verify**
- Send normal requests → Should pass through with security headers
- Send malicious prompts → Should block with 403 responses
- Monitor via Konnect Analytics for security insights

### What This Integration Does

✅ **Intercepts** all AI API requests before they reach your AI service  
✅ **Extracts** user prompts intelligently (supports OpenAI format)  
✅ **Scans** content via Prisma AIRS for threats (injection, malware, DLP)  
✅ **Blocks** malicious requests with detailed error responses  
✅ **Forwards** clean requests to your AI service unchanged  
✅ **Logs** all scan results for compliance and monitoring  

### Key Benefits for Kong Konnect SaaS

- **Zero Infrastructure** - No additional services or proxies required
- **Native Integration** - Uses built-in Kong `request-callout` plugin
- **Fully Managed** - Leverages Kong Konnect's cloud platform
- **Enterprise Ready** - Vault security, auto-scaling, high availability
- **Real-time Protection** - Synchronous scanning with minimal latency

### 📖 Next Steps

- **Quick Setup**: Follow the 4-step process above to get started in minutes
- **Detailed Deployment**: See `KONNECT-DEPLOYMENT.md` for step-by-step Konnect configuration
- **Configuration Reference**: Review `request-callout-prisma-airs-config.json` for the complete plugin setup
- **Architecture Details**: Continue reading below for deep technical explanation

---

## 🏗️ Architecture

This solution uses **Kong Konnect's** native `request-callout` plugin to provide **comprehensive AI security scanning** with real-time threat detection and blocking capabilities.

### High-Level Workflow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│              Kong Konnect + Prisma AIRS API Intercept Integration               │
└─────────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐    1. POST /v1/chat/completions    ┌───────────────────────────-───┐
│              │ ─────────────────────────────────▶ │                               │
│    Client    │                                    │      Kong Konnect             │
│ Application  │                                    │       Gateway                 │
│              │ ◀────────── 8. Response ────────── │                               │
└──────────────┘           + Security Headers       └───────────── ─┬───────────────┘
                                                                    │
                                                     2. Extract     │
                                                        User Prompt │
                                                                    ▼
                                                     ┌──────────────────────────────┐
                                                     │     Request-Callout          │
                                                     │        Plugin                │
                                                     │                              │
                                                     │ • Parse OpenAI JSON          │
                                                     │ • Extract user content       │
                                                     │ • Build AIRS payload         │
                                                     └──────────────┬───────────────┘
                                                                    │
                                                     3. AIRS Scan   │
                                                        Request     │
                                                                    ▼
┌──────────────┐    4. Scan Result               ┌──────────────────────────────┐
│              │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ▶ │                              │
│   Prisma     │    {"action": "allow|block",    │     Security Decision        │
│  AIRS API    │     "category": "benign|mal",   │        Logic                 │
│  Inter       │     "scan_id": "uuid"}          │                              │
└──────────────┘                                 └──────────────┬───────────────┘
                                                                 │
                                                  5. Decision    │
                                                                 ▼
                                                 ┌───────────────────────────────┐
                                                 │     Malicious Content?        │
                                                 │                               │
                                                 │    ┌─────────┐ ┌─────────┐    │
                                                 │    │  BLOCK  │ │  ALLOW  │    │
                                                 │    │   403   │ │Forward  │    │
                                                 │    │  Error  │ │   to    │    │
                                                 │    └─────────┘ │   AI    │    │
                                                 │                │ Service │    │
                                                 │                └─────────┘    │
                                                 └───────────────┬───────────────┘
                                                                 │
                                                  6. Clean       │
                                                     Request     │
                                                                 ▼
                                                 ┌───────────────────────────────┐
                                                 │                               │
                                                 │     OpenAI / AI Provider      │
                                                 │                               │
                                                 │  • GPT-3.5/4                  │
                                                 │  • Claude                     │  
                                                 │  • Custom Models              │
                                                 │                               │
                                                 └───────────────┬───────────────┘
                                                                 │
                                                  7. AI Response │
                                                                 ▼
                                                 ┌───────────────────────────────┐
                                                 │   Direct Response Return      │
                                                 │                               │
                                                 │ + X-AIRS-Scan-ID              │
                                                 │ + X-AIRS-Category             │
                                                 │ + X-AIRS-Blocked: false       │
                                                 └───────────────────────────────┘
```

### Detailed Request Flow

#### 🔍 **Phase 1: Request Scanning**
1. **Request Interception**: Kong captures incoming AI API requests
2. **Prompt Extraction**: Lua script extracts user prompts from request body (supports OpenAI format)
3. **AIRS Scan**: Formatted request sent to Prisma AIRS API with metadata
4. **Security Decision**: AIRS returns `allow` or `block` action with threat analysis
5. **Enforcement**: Malicious requests blocked with detailed error response

#### 🤖 **Phase 2: AI Service Call**
6. **Upstream Forwarding**: Clean requests forwarded to AI provider (OpenAI, etc.)
7. **Response Delivery**: AI service response returned directly to client with security headers

> **Note**: The current implementation focuses on **request-side scanning** to block malicious prompts before they reach AI services. Response scanning capabilities are available in advanced configurations (see `complete-resp-config.json` for full dual-phase scanning setup).

### Key Components

- **Request-Callout Plugin**: Single-phase request scanning with intelligent prompt extraction
- **Prisma AIRS API**: Real-time AI security scanning and threat detection
- **Kong Vault Integration**: Secure API key management
- **Intelligent Caching**: MD5-based cache keys (available in advanced configs)
- **Graceful Fallback**: Continue operation during AIRS API outages

### Why Kong Konnect + AIRS?

- ✅ **Managed Infrastructure**: No Kong maintenance overhead
- ✅ **Enterprise Scale**: Built-in auto-scaling and high availability
- ✅ **Native Integration**: Uses Kong's battle-tested `request-callout` plugin
- ✅ **Cloud-Native Security**: Direct AIRS API calls with intelligent caching
- ✅ **Advanced Analytics**: Built-in monitoring and alerting
- ✅ **Proactive Protection**: Blocks malicious prompts before reaching AI services
- ✅ **Smart Content Extraction**: Optimized for OpenAI and similar APIs


## 📝 Plugin Configuration

### Required Plugin: `request-callout`

**Plugin Execution Order**: Single plugin with three phases:
1. **Request Phase**: Extract and scan user prompts via AIRS API
2. **Response Phase**: Process AIRS scan results and block if malicious
3. **Upstream Phase**: Restore original request body and forward to AI service

**Key Configuration**:
- **API Endpoint**: `https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request`
- **Authentication**: `{vault://env/airs-api-key}`
- **Cache Strategy**: Disabled for real-time scanning
- **Error Handling**: Fail fast with 403 blocks

#### Core Request Processing Lua Script

The main request scanning logic extracts user prompts from OpenAI-formatted requests:

```lua
-- Extract user prompt from OpenAI format
local original_body, err = kong.request.get_raw_body()
if not original_body then
    kong.log.err("Failed to get request body: ", err)
    return
end

-- Store original request for LLM call later
kong.ctx.shared.original_request_body = original_body

-- Extract user prompt from "messages" array
local user_prompt = ""
local messages_start = string.find(original_body, '"messages"%s*:%s*%[')
if messages_start then
    local content_pattern = '"role"%s*:%s*"user".-"content"%s*:%s*"([^"]*)"'
    for content in string.gmatch(original_body, content_pattern) do
        user_prompt = content  -- Keep updating to get the last user message
    end
end

-- Build AIRS JSON payload
local tr_id = ngx.var.request_id or "kong-unknown"
local full_json = string.format([[{
  "tr_id": %s,
  "ai_profile": {
    "profile_name": "dev-block-all-profile"  -- Replace with your AIRS Security Profile name
  },
  "metadata": {
    "ai_model": "gpt-3.5-turbo",
    "app_user": "kong-gateway",
    "app_name": "kong-airs"
  },
  "contents": [
    {
      "prompt": %s
    }
  ]
}]], escape_json_string(tr_id), escape_json_string(user_prompt))
```

#### Security Decision Logic

Response processing determines whether to block or allow the request:

```lua
-- Access AIRS scan result
local response_body = co.airs_request_scan.response.body
kong.log.info("Raw AIRS response: ", response_body)

-- Block if malicious content detected
if response_body:match('"action"%s*:%s*"block"') then
  kong.ctx.shared.airs_blocked = true
  kong.log.warn("AIRS blocking request")
  return kong.response.exit(403, {
    error = "Request blocked by AI security scan",
    details = "Malicious content detected in prompt"
  })
end
-- Allow: continue to upstream
```

#### Upstream Forwarding Logic

Clean requests are forwarded to the AI service with proper headers:

```lua
-- Do not forward if AIRS blocked
if kong.ctx.shared.airs_blocked then
  return
end

-- Restore original body
local body = kong.ctx.shared.original_request_body
kong.service.request.set_raw_body(body)

-- Set proper headers for AI service
kong.service.request.set_header("content-type", "application/json")
kong.service.request.set_header("accept", "application/json")
kong.service.request.set_header("host", "api.openai.com")
kong.service.request.clear_header("transfer-encoding")
kong.service.request.set_header("content-length", tostring(#body))
```

### Complete Working Configuration

See `request-callout-prisma-airs-config.json` for the full plugin configuration that includes:

- AIRS API endpoint: `https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request`
- API key vault reference: `{vault://env/airs-api-key}`
- Security profile name: `dev-block-all-profile` (update with your profile from Strata Cloud Manager)
- Timeout settings: 10s read, 2s connect
- Error handling: 2 retries, fail on error
- Content processing: JSON escaping and prompt extraction

**Complete Working Configuration**: See `request-callout-prisma-airs-config.json` for the full plugin configuration.


## 📚 Architecture Deep Dive

### Request-Callout Plugin Implementation

The working configuration uses a **single-phase request scanning** approach optimized for performance and reliability:

#### **Request Scanning Callout (`airs_request_scan`)**

**Complete Lua Processing Logic**:
```lua
-- Get the original request body
local original_body, err = kong.request.get_raw_body()
if not original_body then
    kong.log.err("Failed to get request body: ", err)
    return
end

-- Store original request for LLM call later
kong.ctx.shared.original_request_body = original_body

-- Basic validation that we have JSON
if not string.match(original_body, '^%s*{.*}%s*$') then
    kong.log.err("Request body is not JSON format")
    return
end

-- Extract user prompt from OpenAI format
local user_prompt = ""
local messages_start = string.find(original_body, '"messages"%s*:%s*%[')
if messages_start then
    -- Find the last occurrence of "content" field in a user message
    local content_pattern = '"role"%s*:%s*"user".-"content"%s*:%s*"([^"]*)"'
    for content in string.gmatch(original_body, content_pattern) do
        user_prompt = content  -- Keep updating to get the last user message
    end
end

-- Fallback: if no user prompt found, use a default
if user_prompt == "" then
    user_prompt = "No user prompt detected"
    kong.log.warn("Could not extract user prompt from request body")
end

-- Escape JSON string helper function
local function escape_json_string(str)
    if not str then return '""' end
    str = string.gsub(str, '\\', '\\\\')
    str = string.gsub(str, '"', '\\"')
    str = string.gsub(str, '\n', '\\n')
    str = string.gsub(str, '\r', '\\r')
    str = string.gsub(str, '\t', '\\t')
    return '"' .. str .. '"'
end

-- Build the AIRS JSON body with extracted user prompt
local tr_id = ngx.var.request_id or "kong-unknown"
local full_json = string.format([[{
  "tr_id": %s,
  "ai_profile": {
    "profile_name": "dev-block-all-profile"  -- Replace with your AIRS Security Profile name
  },
  "metadata": {
    "ai_model": "gpt-3.5-turbo",
    "app_user": "kong-gateway",
    "app_name": "kong-airs"
  },
  "contents": [
    {
      "prompt": %s
    }
  ]
}]], escape_json_string(tr_id), escape_json_string(user_prompt))

kong.ctx.shared.callouts.airs_request_scan.request.params.body = full_json
```

**AIRS Scan Response Processing**:
```lua
-- Access the stored response via kong.ctx.shared.callouts
local co = kong.ctx.shared.callouts
if not (co and co.airs_request_scan and co.airs_request_scan.response) then
  kong.log.warn("No AIRS callout response found")
  return
end

local response_body = co.airs_request_scan.response.body
if not response_body then
  kong.log.warn("No AIRS response body found")
  return
end

kong.log.info("Raw AIRS response: ", response_body)

if response_body:match('"action"%s*:%s*"block"') then
  kong.ctx.shared.airs_blocked = true
  kong.log.warn("AIRS blocking request")
  return kong.response.exit(403, {
    error = "Request blocked by AI security scan",
    details = "Malicious content detected in prompt"
  })
end
-- allow: do nothing; upstream will run
```

#### **Upstream Phase Processing**

**Request Restoration and Forwarding**:
```lua
-- Do not forward if AIRS blocked
if kong.ctx.shared.airs_blocked then
  return
end

-- Restore original body
local body = kong.ctx.shared.original_request_body
if not body then
  local b = kong.request.get_raw_body()
  if b then body = b end
end
if not body then
  kong.log.warn("No body available to forward upstream")
  return
end

kong.service.request.set_raw_body(body)

-- Ensure proper framing/headers
kong.service.request.set_header("content-type", "application/json")
kong.service.request.set_header("accept", "application/json")
kong.service.request.set_header("host", "api.openai.com")
kong.service.request.clear_header("transfer-encoding")
kong.service.request.set_header("content-length", tostring(#body))
```

### AIRS API Response Handling

**Working Configuration Details**:
- **API Endpoint**: `https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request`
- **Authentication**: Vault-managed API key via `{vault://env/airs-api-key}`
- **Timeout Settings**: 10s read, 2s connect, 2s write
- **Error Handling**: 2 retries on failure, fail fast on error
- **Cache Strategy**: Disabled (`"off"`) for real-time scanning

**Scan Result Processing**:
```json
{
  "scan_id": "90868eb1-518c-4136-be59-f5062a29c948",
  "category": "benign|malicious", 
  "action": "allow|block",
  "prompt_detected": {
    "url_cats": false,
    "dlp": false,
    "injection": false,
    "malware": false
  }
}
```

**Simplified Security Decision Logic**:
```lua
-- Simple pattern matching for block action
if response_body:match('"action"%s*:%s*"block"') then
  kong.ctx.shared.airs_blocked = true
  kong.log.warn("AIRS blocking request")
  return kong.response.exit(403, {
    error = "Request blocked by AI security scan",
    details = "Malicious content detected in prompt"
  })
end
-- Allow: continue to upstream processing
```

**Configuration Highlights**:
- **Single-phase scanning**: Request scanning only (no response scanning)
- **Immediate blocking**: 403 response with security details
- **Request preservation**: Original body restored for upstream forwarding
- **Header management**: Proper Content-Type and Content-Length handling

### Performance Optimization

**Working Configuration Settings**:
- **Cache Strategy**: Disabled (`"off"`) for real-time scanning accuracy
- **Cache Bypass**: Enabled (`"bypass": true`) for request callout
- **Timeout Management**: 
  - Connect: 2000ms
  - Read: 10000ms (10s)
  - Write: 10000ms (10s)
- **Error Handling**: 2 retries with fail-fast behavior
- **Regional Endpoint**: US region (`service.api.aisecurity.paloaltonetworks.com`)

**Request Processing Optimizations**:
- **JSON Validation**: Early validation prevents unnecessary processing
- **Prompt Extraction**: Efficient regex-based content parsing
- **Body Preservation**: Minimal memory footprint with shared context
- **Header Management**: Streamlined header processing for upstream forwarding

**Production Considerations**:
- Real-time scanning prioritizes accuracy over caching
- Fast fail behavior prevents hanging requests
- Efficient Lua processing minimizes latency impact
- Proper error boundaries ensure service availability

---

**🎯 This integration provides enterprise-grade AI security scanning for Kong Konnect, protecting AI applications against malicious content using Prisma AIRS real-time threat detection.**
-- kong/plugins/prisma-airs-intercept/handler.lua
-- Patched version: Bedrock Converse format + MCP tool_event support
--                  + buffered SSE (text/event-stream) response scanning

local http = require("resty.http")
local cjson = require("cjson")

local SecurePrismaAIRSHandler = {
    PRIORITY = 1000,
    VERSION = "0.2.3",
}

local function log_error(reason, verdict)
    pcall(function()
        kong.log.error("SecurePrismaAIRSHandler: Blocking. Verdict: " ..
            tostring(verdict) .. ", Reason: " .. tostring(reason))
    end)
end

local function log_debug(config, msg)
    if not (config and config.debug) then return end
    pcall(function()
        kong.log.info("SecurePrismaAIRSHandler: " .. tostring(msg))
    end)
end

-- ============================================================================
-- Dynamic AIRS profile selection from a signed JWT claim
--   Choose the AIRS security profile per request from a claim in the caller's
--   ALREADY-VALIDATED bearer token, so one shared gateway applies app-specific
--   guardrails without a gateway per app. This plugin runs at PRIORITY 1000,
--   i.e. AFTER kong `jwt` (1450) and `openid-connect` (1050), so the signature
--   is verified before we decode the payload. A signed claim is unspoofable
--   where a header (X-Prisma-Profile) is not. If no auth plugin precedes us,
--   no valid claim is present and selection falls CLOSED to fallback_profile_name.
--   Pure helpers are exposed on `._profile` for tests.
-- ============================================================================

-- base64url -> bytes (JWT segments are base64url, unpadded).
local function b64url_decode(input)
    if not input then return nil end
    input = input:gsub("-", "+"):gsub("_", "/")
    local rem = #input % 4
    if rem == 2 then input = input .. "=="
    elseif rem == 3 then input = input .. "="
    elseif rem == 1 then return nil end
    return ngx.decode_base64(input)
end

-- Pure: read one claim from a bearer token's payload. Does NOT verify the
-- signature (the upstream auth plugin already did); only decodes the payload.
local function get_claim(auth_header, claim_name)
    if not auth_header or not claim_name then return nil end
    local token = auth_header:match("^[Bb]earer%s+(.+)$") or auth_header
    local payload_b64 = token:match("^[^%.]+%.([^%.]+)%.")
    if not payload_b64 then return nil end
    local json = b64url_decode(payload_b64)
    if not json then return nil end
    local ok, claims = pcall(cjson.decode, json)
    if not ok or type(claims) ~= "table" then return nil end
    return claims[claim_name]
end

-- Pure: resolve the profile name from config + the Authorization header value.
--   config.profile_claim          claim that selects the profile (e.g. risk_tier)
--   config.profile_claim_map      { claim_value = profile_name }
--   config.fallback_profile_name  strict profile for missing/unmapped claim
--   config.profile_name           static default (legacy / no claim configured)
-- Returns: profile_name, source (for logging). Missing/unmapped claim fails CLOSED.
local function resolve_profile(config, auth_header)
    if not config.profile_claim or config.profile_claim == "" then
        return config.profile_name, "static"
    end
    local fallback = config.fallback_profile_name or config.profile_name
    local value = get_claim(auth_header, config.profile_claim)
    if value == nil then
        return fallback, "fallback:no-claim"
    end

    -- The claim may be a scalar (e.g. risk_tier) or a list (Entra groups/roles
    -- are arrays). Normalize to an ordered list of string candidates. A token
    -- typically carries a single group, but iterating is also safe if a list
    -- ever has more than one value (first mapped value wins).
    local candidates = {}
    if type(value) == "table" then
        for _, v in ipairs(value) do candidates[#candidates + 1] = tostring(v) end
    else
        candidates[1] = tostring(value)
    end
    if #candidates == 0 then
        return fallback, "fallback:empty-claim"
    end

    local map = config.profile_claim_map
    if map and next(map) ~= nil then
        for _, cv in ipairs(candidates) do
            local mapped = map[cv]
            if mapped then return mapped, "claim-map:" .. cv end
        end
        return fallback, "fallback:unmapped:" .. candidates[1]
    end
    -- Direct mode: the (single) claim value is itself the profile name.
    return candidates[1], "claim-direct:" .. candidates[1]
end

-- Request-scoped: resolve once, memoize across access/response phases via
-- kong.ctx.shared, log the choice, and stamp an audit header.
local function resolve_profile_name(config)
    local cached = kong.ctx.shared.airs_profile_name
    if cached then return cached end
    local name, source = resolve_profile(config, kong.request.get_header("authorization"))
    kong.ctx.shared.airs_profile_name = name
    log_debug(config, "Resolved AIRS profile: " .. tostring(name) .. " (" .. source .. ")")
    pcall(function() kong.service.request.set_header("X-AIRS-Profile-Used", name) end)
    return name
end

-- ============================================================================
-- Buffered SSE (text/event-stream) response scanning
--   Detect a streamed response, reconstruct the assistant text + tool-call args
--   from the fully buffered body, and scan that with AIRS. Buffered only --
--   no token-by-token streaming. Pure helpers are exposed on `._sse` for tests.
-- ============================================================================

-- Pure: case-insensitive check for "text/event-stream" in a content-type string.
local function is_sse_content_type(ct)
    if type(ct) ~= "string" then return false end
    return string.find(string.lower(ct), "text/event-stream", 1, true) ~= nil
end

-- Kong-coupled: read the response content-type. kong.response.* is the documented
-- response-phase call; fall back to kong.service.response.* (pcall-guarded).
local function get_response_content_type()
    local ok, ct = pcall(kong.response.get_header, "content-type")
    if ok and ct then return ct end
    local ok2, ct2 = pcall(kong.service.response.get_header, "content-type")
    if ok2 then return ct2 end
    return nil
end

local function is_sse_response()
    return is_sse_content_type(get_response_content_type())
end

-- Kong-coupled: read the full buffered response body. Shared by MCP + LLM + SSE
-- paths; doc-preferred call first, upstream's call as fallback (pcall-guarded).
local function get_buffered_body()
    local ok, b = pcall(kong.response.get_raw_body)
    if ok and b and b ~= "" then return b end
    local ok2, b2 = pcall(kong.service.response.get_raw_body)
    if ok2 and b2 and b2 ~= "" then return b2 end
    return nil
end

-- Pure: parse a buffered SSE body into an ordered list of `data:` payload strings.
-- Handles LF and CRLF; preserves empty `data:` lines inside a multi-line event;
-- skips an event only when its joined payload is empty; ignores `[DONE]`.
local function parse_sse(raw)
    local payloads = {}
    if type(raw) ~= "string" or raw == "" then return payloads end

    raw = raw:gsub("\r\n", "\n"):gsub("\r", "\n")

    local data_lines = {}
    local function flush_event()
        if #data_lines == 0 then return end
        local joined = table.concat(data_lines, "\n")
        data_lines = {}
        if joined == "" then return end
        -- skip [DONE] after trimming surrounding whitespace (spacing varies by provider)
        local trimmed = joined:gsub("^%s+", ""):gsub("%s+$", "")
        if trimmed == "[DONE]" then return end
        payloads[#payloads + 1] = joined
    end

    -- append a trailing newline so the final event (no trailing blank line) flushes
    for line in (raw .. "\n"):gmatch("([^\n]*)\n") do
        if line == "" then
            flush_event()
        else
            local data = line:match("^data:(.*)$")
            if data then
                data = data:gsub("^ ", "")  -- strip exactly one optional leading space
                data_lines[#data_lines + 1] = data
            end
            -- non-data lines (event:/id:/retry:/comments) are ignored, do not flush
        end
    end
    flush_event()

    return payloads
end

-- Pure extractors. Each takes the FULL decoded item list ({ raw, decoded }) and
-- walks it once, appending text + tool-call args in stream order.

local function extract_openai_chat(items)
    local out = {}
    for _, it in ipairs(items) do
        local d = it.decoded
        if type(d) == "table" and type(d.choices) == "table" then
            for _, ch in ipairs(d.choices) do
                local delta = ch.delta
                if type(delta) == "table" then
                    if type(delta.content) == "string" then
                        out[#out + 1] = delta.content
                    end
                    if type(delta.tool_calls) == "table" then
                        for _, tc in ipairs(delta.tool_calls) do
                            local fn = tc["function"]
                            if type(fn) == "table" then
                                if type(fn.name) == "string" then out[#out + 1] = fn.name end
                                if type(fn.arguments) == "string" then out[#out + 1] = fn.arguments end
                            end
                        end
                    end
                end
            end
        end
    end
    return table.concat(out)
end

local function extract_anthropic_messages(items)
    local out = {}
    for _, it in ipairs(items) do
        local d = it.decoded
        if type(d) == "table" and d.type == "content_block_delta" and type(d.delta) == "table" then
            local dt = d.delta
            if dt.type == "text_delta" and type(dt.text) == "string" then
                out[#out + 1] = dt.text
            elseif dt.type == "input_json_delta" and type(dt.partial_json) == "string" then
                out[#out + 1] = dt.partial_json
            end
        end
    end
    return table.concat(out)
end

local function extract_openai_responses(items)
    local out = {}
    local saw_delta = {}

    local function family_of(t)
        return (t:gsub("%.delta$", ""):gsub("%.done$", ""))
    end
    local function key_of(d, fam)
        -- Compose ALL present identifiers so distinct content blocks under the same
        -- output item (which may share output_index but differ in content_index, or
        -- vice versa) never collide on the .done-fallback key.
        return table.concat({
            fam,
            tostring(d.item_id or ""),
            tostring(d.output_index or ""),
            tostring(d.content_index or ""),
        }, "|")
    end

    for _, it in ipairs(items) do
        local d = it.decoded
        if type(d) == "table" and type(d.type) == "string" then
            local t = d.type
            if t:match("^response%.") and t:match("%.delta$") then
                if type(d.delta) == "string" then
                    saw_delta[key_of(d, family_of(t))] = true
                    out[#out + 1] = d.delta
                end
            elseif t:match("^response%.") and t:match("%.done$") then
                -- .done is a fallback: fold its full value only if that key saw no delta
                -- (.done follows its deltas in real streams, so saw_delta is already set)
                if not saw_delta[key_of(d, family_of(t))] then
                    for _, f in ipairs({ "text", "arguments", "input", "code", "refusal" }) do
                        if type(d[f]) == "string" then
                            out[#out + 1] = d[f]
                            break
                        end
                    end
                end
            end
        end
    end
    return table.concat(out)
end

-- Pure: detect provider from decoded payloads (scan until a signature is found).
local function detect_provider(items)
    for _, it in ipairs(items) do
        local d = it.decoded
        if type(d) == "table" then
            if type(d.choices) == "table" then
                for _, ch in ipairs(d.choices) do
                    if type(ch.delta) == "table" then return "openai_chat" end
                end
            end
            if type(d.type) == "string" then
                if d.type:match("^response%.") then return "openai_responses" end
                if d.type == "content_block_delta" or d.type == "content_block_start"
                    or d.type == "content_block_stop" or d.type:match("^message_") then
                    return "anthropic_messages"
                end
            end
        end
    end
    return nil
end

-- Pure: reconstruct the assistant text (+ tool-call args) from a buffered SSE body.
local function reconstruct_sse_text(raw, provider)
    provider = provider or "auto"
    local payloads = parse_sse(raw)
    if #payloads == 0 then return "" end

    if provider == "raw" then
        return table.concat(payloads)
    end

    local items = {}
    for i, p in ipairs(payloads) do
        local ok, decoded = pcall(cjson.decode, p)
        items[i] = { raw = p, decoded = ok and decoded or nil }
    end

    local function run(p)
        if p == "openai_chat" then return extract_openai_chat(items) end
        if p == "openai_responses" then return extract_openai_responses(items) end
        if p == "anthropic_messages" then return extract_anthropic_messages(items) end
        return ""
    end

    local text
    if provider == "auto" then
        local detected = detect_provider(items)
        text = detected and run(detected) or ""
    else
        text = run(provider)
    end

    if not text or text == "" then
        -- fallback: concatenate only the payloads that failed JSON decode (raw/plain text).
        -- A metadata-only JSON stream therefore reconstructs to "" (nothing scanned).
        local raws = {}
        for _, it in ipairs(items) do
            if it.decoded == nil then raws[#raws + 1] = it.raw end
        end
        text = table.concat(raws)
    end

    return text or ""
end

-- ============================================================================

local function extract_prompt(request_body)
    if not request_body then return nil end

    if type(request_body.messages) == "table" then
        -- Scan the LATEST user turn, not the first. In a multi-turn conversation the
        -- client sends the full history; prior turns were already scanned, so returning
        -- on the first user message would re-scan turn 1 forever and never inspect the
        -- new prompt. Capture the last user message and scan that.
        local last_user_content
        for _, message in ipairs(request_body.messages) do
            if message.role == "user" then
                last_user_content = message.content
            end
        end
        if last_user_content ~= nil then
            local content = last_user_content
            if type(content) == "table" then
                -- Bedrock Converse format: content is an array of objects like [{"text":"Hello"}]
                if content[1] and content[1].text then
                    return content[1].text
                end
                -- Fallback: try to serialize the table
                local ok, serialized = pcall(cjson.encode, content)
                if ok then
                    return serialized
                end
                return nil
            elseif type(content) == "string" then
                return content
            end
        end
    end

    -- OpenAI Responses API: top-level `input` (string, or array of input items).
    local input = request_body.input
    if type(input) == "string" then
        return input
    elseif type(input) == "table" then
        local parts = {}
        for _, item in ipairs(input) do
            if type(item) == "string" then
                parts[#parts + 1] = item
            elseif type(item) == "table" and (item.role == nil or item.role == "user") then
                local c = item.content
                if type(c) == "string" then
                    parts[#parts + 1] = c
                elseif type(c) == "table" then
                    for _, part in ipairs(c) do
                        if type(part) == "string" then
                            parts[#parts + 1] = part
                        elseif type(part) == "table" and type(part.text) == "string"
                            and (part.type == nil or part.type == "input_text") then
                            parts[#parts + 1] = part.text
                        end
                    end
                end
            end
        end
        if #parts > 0 then
            return table.concat(parts, " ")
        end
    end

    return nil
end

local function is_mcp_request(request_body)
    if not request_body then return false, nil end

    -- Check for JSON-RPC method field (MCP uses JSON-RPC 2.0)
    if request_body.method then
        return true, request_body.method
    end

    -- Check for jsonrpc field
    if request_body.jsonrpc then
        return true, request_body.method or "unknown"
    end

    return false, nil
end

local function is_mcp_control_message(method)
    -- These MCP methods are protocol handshakes with no scannable content
    local control_methods = {
        ["initialize"] = true,
        ["initialized"] = true,
        ["ping"] = true,
        ["notifications/initialized"] = true,
        ["tools/list"] = true,
        ["resources/list"] = true,
        ["prompts/list"] = true,
    }
    return control_methods[method] or false
end

local function build_mcp_tool_event_payload(config, request_body, response_body)
    local method = request_body.method or "unknown"
    local params = request_body.params or {}

    local tool_name = "unknown"
    local input_str = ""

    if method == "tools/call" then
        tool_name = params.name or "unknown"
        local ok, encoded = pcall(cjson.encode, params.arguments or {})
        input_str = ok and encoded or "{}"
    else
        local ok, encoded = pcall(cjson.encode, params)
        input_str = ok and encoded or "{}"
    end

    local output_str = ""
    if response_body then
        local body = response_body
        -- kong.log.info("MCP tool_event: raw response_body = " .. string.sub(body, 1, 500))
        -- Strip SSE framing from remote MCP servers (e.g. "event: message\ndata: {...}")
        local sse_json = body:match("^event:%s*message%s+data:%s*(.+)")
        if sse_json then
            -- kong.log.info("MCP tool_event: SSE framing detected, stripped to JSON = " .. string.sub(sse_json, 1, 500))
            body = sse_json
        end
        local ok, decoded = pcall(cjson.decode, body)
        if ok and decoded then
            -- kong.log.info("MCP tool_event: cjson.decode succeeded")
            local ok2, encoded = pcall(cjson.encode, decoded.result or decoded)
            output_str = ok2 and encoded or ""
            -- kong.log.info("MCP tool_event: output_str = " .. string.sub(output_str, 1, 500))
        else
            -- kong.log.info("MCP tool_event: cjson.decode failed, decoded = " .. tostring(decoded))
        end
    end

    local request_id = kong.request.get_header("Kong-Request-ID")
        or kong.ctx.shared.request_id
        or ngx.var.request_id
        or "unknown"

    local payload = {
        tr_id = request_id,
        ai_profile = { profile_name = resolve_profile_name(config) },
        contents = { {
            tool_event = {
                metadata = {
                    ecosystem = "mcp",
                    method = method,
                    server_name = config.app_name and ("kong-" .. config.app_name) or "kong",
                    tool_invoked = tool_name,
                },
                input = input_str,
                output = output_str,
            }
        } },
        metadata = {
            app_name = config.app_name and ("kong-" .. config.app_name) or "kong",
            app_user = "mcp-client",
            ai_model = "mcp"
        }
    }

    return payload
end

local function build_prompt_payload(config, scan_type, request_body, response_body)
    local prompt_to_scan = extract_prompt(request_body)

    if not prompt_to_scan or prompt_to_scan == "" then
        return nil, "Could not find a user prompt in the request payload."
    end

    log_debug(config,
        "Extracted prompt: " .. string.sub(prompt_to_scan, 1, 100) .. (string.len(prompt_to_scan) > 100 and "..." or ""))

    local content_object = { prompt = prompt_to_scan }

    if scan_type == "response" and response_body then
        local ok, decoded_response = pcall(cjson.decode, response_body)
        if ok and decoded_response then
            -- OpenAI format
            if decoded_response.choices and decoded_response.choices[1] then
                content_object.response = decoded_response.choices[1].message.content
                -- Bedrock Converse format
            elseif decoded_response.output and decoded_response.output.message then
                local resp_content = decoded_response.output.message.content
                if type(resp_content) == "table" and resp_content[1] and resp_content[1].text then
                    content_object.response = resp_content[1].text
                elseif type(resp_content) == "string" then
                    content_object.response = resp_content
                end
                -- Gemini / Vertex native format: candidates[].content.parts[].text
                -- (this plugin runs before ai-proxy normalizes, so LLM responses arrive
                -- in the upstream provider's raw shape).
            elseif decoded_response.candidates and decoded_response.candidates[1] then
                local cand = decoded_response.candidates[1]
                if cand.content and type(cand.content.parts) == "table" then
                    local parts = {}
                    for _, prt in ipairs(cand.content.parts) do
                        if type(prt.text) == "string" then parts[#parts + 1] = prt.text end
                    end
                    if #parts > 0 then content_object.response = table.concat(parts, "") end
                end
            end
            -- Capture token usage + model so observability headers survive a block
            -- (the 403 body carries no usage). Gemini: usageMetadata + modelVersion;
            -- OpenAI/Bedrock: usage + model.
            local um = decoded_response.usageMetadata
            if type(um) == "table" then
                kong.ctx.shared.airs_usage = {
                    prompt = um.promptTokenCount, completion = um.candidatesTokenCount, total = um.totalTokenCount }
            elseif type(decoded_response.usage) == "table" then
                local u = decoded_response.usage
                kong.ctx.shared.airs_usage = {
                    prompt = u.prompt_tokens, completion = u.completion_tokens, total = u.total_tokens }
            end
            kong.ctx.shared.airs_model = decoded_response.modelVersion or decoded_response.model
        end
    end

    local request_id = kong.request.get_header("Kong-Request-ID")
        or kong.ctx.shared.request_id
        or ngx.var.request_id
        or "unknown"

    local service_name = "unknown"
    local svc = kong.router.get_service()
    if svc then service_name = svc.name or "unknown" end

    local payload = {
        tr_id = request_id,
        ai_profile = { profile_name = resolve_profile_name(config) },
        contents = { content_object },
        metadata = {
            app_name = config.app_name and ("kong-" .. config.app_name) or "kong",
            app_user = service_name,
            ai_model = request_body.model or "bedrock"
        }
    }

    return payload, nil
end

local function send_scan(config, payload)
    local ok_enc, request_payload_json = pcall(cjson.encode, payload)
    if not ok_enc then
        return "error", "Internal plugin error: Could not encode payload."
    end

    log_debug(config, "Sending scan payload: " .. string.sub(request_payload_json, 1, 500))

    local httpc = http.new()
    httpc:set_timeout(config.timeout_ms or 5000)

    local t_scan_start = ngx.now()
    local res, err = httpc:request_uri(config.api_endpoint, {
        method = "POST",
        body = request_payload_json,
        headers = {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json",
            ["x-pan-token"] = config.api_key
        },
        ssl_verify = config.ssl_verify
    })

    if not res then
        pcall(function() httpc:set_keepalive() end)
        kong.log.err("AIRS API call failed: " .. tostring(err))
        return "error", "API call failed: " .. tostring(err)
    end

    local res_body_str = res.body
    pcall(function() httpc:set_keepalive() end)

    if res.status ~= 200 then
        local reason = "API returned non-200 status: " .. res.status
        if res_body_str and res_body_str ~= "" then
            reason = reason .. " Body: " .. string.sub(res_body_str, 1, 500)
        end
        return "error", reason
    end

    if not res_body_str or res_body_str == "" then
        return "error", "API response body was empty, despite 200 OK status."
    end

    local ok_dec, res_body_json = pcall(cjson.decode, res_body_str)
    if not ok_dec then
        return "error", "Failed to decode API response JSON: " .. tostring(res_body_json)
    end

    log_debug(config,
        "AIRS verdict: " .. tostring(res_body_json.action) .. " category: " .. tostring(res_body_json.category))

    local action = res_body_json and res_body_json.action
    if not action then
        return "error", "'action' field not found in API response."
    end

    -- Record scan telemetry for observability headers (see response phase). Each call
    -- (request scan, response scan) appends one entry; the response phase summarizes them.
    pcall(function()
        local scans = kong.ctx.shared.airs_scans or {}
        scans[#scans + 1] = {
            action = action,
            category = res_body_json.category,
            scan_id = res_body_json.scan_id,
            session_id = res_body_json.session_id,
            ms = math.floor((ngx.now() - t_scan_start) * 1000 + 0.5),
            raw = res_body_str,  -- full AIRS scan result JSON (for the raw-result headers)
        }
        kong.ctx.shared.airs_scans = scans
    end)

    return action, "Verdict received from security scan."
end

-- Kong-coupled: stamp AIRS observability headers from recorded scan telemetry.
-- Opt-in via config.set_observability_headers. Safe to call in any phase where
-- response headers can still be set (response phase, or before kong.response.exit).
local function set_airs_observability_headers(config)
    if not config.set_observability_headers then return end
    local scans = kong.ctx.shared.airs_scans
    if not scans or #scans == 0 then return end
    local total_ms, verdict, category = 0, "allow", nil
    for _, s in ipairs(scans) do
        total_ms = total_ms + (s.ms or 0)
        if s.action and s.action ~= "allow" then verdict = s.action end
        if s.category and s.category ~= "benign" then category = s.category end
    end
    pcall(kong.response.set_header, "x-airs-verdict", verdict)
    if category then pcall(kong.response.set_header, "x-airs-category", category) end
    pcall(kong.response.set_header, "x-airs-total-ms", tostring(total_ms))
    pcall(kong.response.set_header, "x-airs-scan-count", tostring(#scans))
    if scans[1] then
        pcall(kong.response.set_header, "x-airs-request-ms", tostring(scans[1].ms or 0))
        if scans[1].scan_id then pcall(kong.response.set_header, "x-airs-scan-id", scans[1].scan_id) end
        if scans[1].session_id then pcall(kong.response.set_header, "x-airs-session-id", scans[1].session_id) end
        -- Full request-scan result JSON (base64) so the caller shows the same raw detail as the SDK.
        if scans[1].raw then pcall(kong.response.set_header, "x-airs-request-result", ngx.encode_base64(scans[1].raw)) end
    end
    if scans[2] then
        pcall(kong.response.set_header, "x-airs-response-ms", tostring(scans[2].ms or 0))
        if scans[2].raw then pcall(kong.response.set_header, "x-airs-response-result", ngx.encode_base64(scans[2].raw)) end
    end
    -- Token usage + model captured from the scanned LLM response, so they survive a 403 block.
    local usage = kong.ctx.shared.airs_usage
    if type(usage) == "table" then
        if usage.prompt ~= nil then pcall(kong.response.set_header, "x-airs-prompt-tokens", tostring(usage.prompt)) end
        if usage.completion ~= nil then pcall(kong.response.set_header, "x-airs-completion-tokens", tostring(usage.completion)) end
        if usage.total ~= nil then pcall(kong.response.set_header, "x-airs-total-tokens", tostring(usage.total)) end
    end
    if kong.ctx.shared.airs_model then pcall(kong.response.set_header, "x-airs-model", tostring(kong.ctx.shared.airs_model)) end
end

-- Pure: HTTP status a non-allow send_scan verdict maps to (nil if allowed).
--   "allow" -> nil (proceed)
--   "error" -> 503 (could not get a verdict: AIRS unreachable / non-200 / undecodable;
--               fail closed -- the scanner, not the content, is the problem)
--   anything else -> 403 (genuine AIRS policy block)
local function verdict_status(verdict)
    if verdict == "allow" then return nil end
    if verdict == "error" then return 503 end
    return 403
end

-- Kong-coupled: deny a request/response based on a non-allow verdict and halt.
-- Detailed reason is logged server-side only; the client gets a generic body.
local function deny(config, verdict, reason, block_message)
    log_error(reason, verdict)
    if verdict_status(verdict) == 503 then
        return kong.response.exit(503, { message = "Security scanning temporarily unavailable." })
    end
    -- Stamp AIRS verdict/category headers on the 403 so the caller learns WHICH detection
    -- fired (otherwise a gateway block is opaque). Opt-in via set_observability_headers.
    set_airs_observability_headers(config)
    return kong.response.exit(403, { message = block_message })
end


-- ACCESS PHASE
function SecurePrismaAIRSHandler:access(config)
    log_debug(config, "Access phase triggered.")
    kong.service.request.enable_buffering()

    local request_body, err = kong.request.get_body()
    if err or not request_body then
        log_error("Could not get request body: " .. tostring(err), "blocked")
        return kong.response.exit(400, { message = "Invalid or unreadable request body." })
    end

    -- Check if this is an MCP request
    local is_mcp, mcp_method = is_mcp_request(request_body)

    if is_mcp then
        log_debug(config, "MCP request detected, method: " .. tostring(mcp_method))

        -- MCP control messages (initialize, tools/list, etc.) - bypass scanning
        if is_mcp_control_message(mcp_method) then
            log_debug(config, "MCP control message (" .. mcp_method .. ") - bypassing AIRS scan")
            kong.ctx.shared.request_body = request_body
            kong.ctx.shared.is_mcp = true
            kong.ctx.shared.mcp_bypassed = true
            return
        end

        -- MCP tools/call - scan using tool_event format
        local payload = build_mcp_tool_event_payload(config, request_body, nil)
        local verdict, reason = send_scan(config, payload)

        if verdict ~= "allow" then
            return deny(config, verdict, reason, "MCP request blocked by security policy.")
        end

        log_debug(config, "MCP scan allowed for method: " .. mcp_method)
        kong.ctx.shared.request_body = request_body
        kong.ctx.shared.is_mcp = true
        return
    end

    -- Standard LLM prompt scanning
    local payload, payload_err = build_prompt_payload(config, "prompt", request_body, nil)

    if not payload then
        log_error(payload_err, "blocked")
        return kong.response.exit(403, { message = "Request blocked by security policy." })
    end

    local verdict, reason = send_scan(config, payload)

    if verdict ~= "allow" then
        return deny(config, verdict, reason, "Request blocked by security policy.")
    end

    log_debug(config, "Prompt scan allowed.")
    kong.ctx.shared.request_body = request_body
end

-- Pure (unit-testable) decision for over-cap reconstructed SSE text.
-- Returns { exceeded, blocked, text }. blocked=true (fail-closed, the secure
-- default) => caller emits 403; fail-open => caller scans text[1..max].
local function apply_scan_limit(text, max, fail_closed)
    max = max or 20000
    if not text or #text <= max then
        return { exceeded = false, blocked = false, text = text }
    end
    if fail_closed then
        return { exceeded = true, blocked = true, text = nil }
    end
    return { exceeded = true, blocked = false, text = string.sub(text, 1, max) }
end

-- RESPONSE PHASE
function SecurePrismaAIRSHandler:response(config)
    log_debug(config, "Response phase triggered.")

    -- Skip response scanning for bypassed MCP control messages
    if kong.ctx.shared.mcp_bypassed then
        log_debug(config, "Skipping response scan for MCP control message.")
        return
    end

    local original_request_body = kong.ctx.shared.request_body

    -- Read the full buffered response body via the shared helper (documented
    -- response-phase PDK call first, upstream's call as fallback).
    local response_body_str = get_buffered_body()

    if not response_body_str or response_body_str == "" then
        kong.log.warn("SecurePrismaAIRSHandler: No response body found in response phase.")
        return
    end

    if not original_request_body then
        kong.log.warn("SecurePrismaAIRSHandler: Original request context not found. Skipping response scan.")
        return
    end

    -- MCP response scanning
    if kong.ctx.shared.is_mcp then
        local payload = build_mcp_tool_event_payload(config, original_request_body, response_body_str)
        local verdict, reason = send_scan(config, payload)

        if verdict ~= "allow" then
            return deny(config, verdict, reason, "MCP response blocked by security policy.")
        end

        log_debug(config, "MCP response scan allowed.")
        -- Allowed MCP path: stamp AIRS verdict/latency/scan-id headers too, so tool-call
        -- legs are as observable as LLM legs (per-leg detail + SCM deep-links).
        set_airs_observability_headers(config)
        return
    end

    -- Buffered SSE (text/event-stream) response scanning (LLM path only; MCP handled above).
    -- Reconstruct the assistant text from the buffered SSE frames, then feed it through the
    -- existing build_prompt_payload via the OpenAI envelope shape so the scan path is reused.
    if config.scan_sse_responses and is_sse_response() then
        local provider = config.sse_provider or "auto"

        if config.sse_set_observability_headers then
            pcall(kong.response.set_header, "x-prisma-airs-sse-detected", "true")
            pcall(kong.response.set_header, "x-prisma-airs-sse-scan-mode", "buffered")
            pcall(kong.response.set_header, "x-prisma-airs-sse-provider", provider)
        end

        local text = reconstruct_sse_text(response_body_str, provider)

        if not text or text == "" then
            kong.log.warn("SecurePrismaAIRSHandler: SSE detected but no scannable text reconstructed; " ..
                "skipping response scan. provider=" .. provider ..
                " raw_body_len=" .. tostring(response_body_str and #response_body_str or 0))
            return
        end

        local lim = apply_scan_limit(text, config.sse_max_scan_chars, config.sse_truncation_fail_closed)
        if lim.exceeded then
            kong.log.warn("SecurePrismaAIRSHandler: SSE reconstructed text exceeds sse_max_scan_chars (" ..
                #text .. " > " .. (config.sse_max_scan_chars or 20000) .. ")")
            if config.sse_set_observability_headers then
                pcall(kong.response.set_header, "x-prisma-airs-sse-truncated", "true")
            end
        end
        if lim.blocked then
            -- Secure default: response too large to scan in full -> do not return it.
            log_error("SSE response exceeds scannable size", "blocked")
            return kong.response.exit(403, {
                message = "Response blocked by security policy."
            })
        end
        text = lim.text

        log_debug(config, "SSE reconstructed " .. #text .. " chars for AIRS scan (provider=" .. provider .. ")")

        -- Wrap into the OpenAI envelope build_prompt_payload already understands, so the
        -- shared builder is reused UNCHANGED and the text lands in contents[0].response.
        local ok_enc, wrapped = pcall(cjson.encode, { choices = { { message = { content = text } } } })
        if not ok_enc then
            kong.log.warn("SecurePrismaAIRSHandler: failed to encode reconstructed SSE text; skipping response scan.")
            return
        end
        response_body_str = wrapped
    end

    -- Standard LLM response scanning
    local payload, payload_err = build_prompt_payload(config, "response", original_request_body, response_body_str)

    if not payload then
        kong.log.warn("SecurePrismaAIRSHandler: " .. tostring(payload_err) .. " Skipping response scan.")
        return
    end

    local verdict, reason = send_scan(config, payload)

    if verdict ~= "allow" then
        return deny(config, verdict, reason, "Response blocked by security policy.")
    end

    log_debug(config, "Response scan allowed.")
    -- Allowed path: stamp AIRS latency/verdict headers on the proxied response.
    set_airs_observability_headers(config)
end

-- Pure helpers exposed for the unit test harness (no Kong/ngx dependency).
SecurePrismaAIRSHandler._sse = {
    is_sse_content_type = is_sse_content_type,
    parse_sse = parse_sse,
    reconstruct_sse_text = reconstruct_sse_text,
    detect_provider = detect_provider,
    extract_openai_chat = extract_openai_chat,
    extract_openai_responses = extract_openai_responses,
    extract_anthropic_messages = extract_anthropic_messages,
    extract_prompt = extract_prompt,
    verdict_status = verdict_status,
    apply_scan_limit = apply_scan_limit,
}

-- Pure (unit-testable) claim-based profile selection helpers.
SecurePrismaAIRSHandler._profile = {
    get_claim = get_claim,
    resolve = resolve_profile,
}

return SecurePrismaAIRSHandler

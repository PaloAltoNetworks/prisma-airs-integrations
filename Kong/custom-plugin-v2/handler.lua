-- kong/plugins/prisma-airs-intercept/handler.lua
-- Patched version: Bedrock Converse format + MCP tool_event support

local http = require("resty.http")
local cjson = require("cjson")

local SecurePrismaAIRSHandler = {
    PRIORITY = 1000,
    VERSION = "0.2.1-capgroup",
}

local function log_error(reason, verdict)
    pcall(function()
        kong.log.error("SecurePrismaAIRSHandler: Blocking. Verdict: " ..
            tostring(verdict) .. ", Reason: " .. tostring(reason))
    end)
end

local function log_debug(config, msg)
    pcall(function()
        kong.log.info("SecurePrismaAIRSHandler: " .. tostring(msg))
    end)
end

local function extract_prompt(request_body)
    if not request_body or not request_body.messages or type(request_body.messages) ~= "table" then
        return nil
    end

    for _, message in ipairs(request_body.messages) do
        if message.role == "user" then
            local content = message.content
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
        ai_profile = { profile_name = config.profile_name },
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
            end
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
        ai_profile = { profile_name = config.profile_name },
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
    local request_payload_json, json_err = cjson.encode(payload)
    if json_err then
        return "blocked", "Internal plugin error: Could not encode payload."
    end

    log_debug(config, "Sending scan payload: " .. string.sub(request_payload_json, 1, 500))

    local httpc = http.new()
    httpc:set_timeout(5000)

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
        return "blocked", "API call failed: " .. tostring(err)
    end

    local res_body_str = res.body
    pcall(function() httpc:set_keepalive() end)

    if res.status ~= 200 then
        local reason = "API returned non-200 status: " .. res.status
        if res_body_str and res_body_str ~= "" then
            reason = reason .. " Body: " .. string.sub(res_body_str, 1, 500)
        end
        return "blocked", reason
    end

    if not res_body_str or res_body_str == "" then
        return "blocked", "API response body was empty, despite 200 OK status."
    end

    local res_body_json, decode_err = cjson.decode(res_body_str)
    if decode_err then
        return "blocked", "Failed to decode API response JSON: " .. tostring(decode_err)
    end

    log_debug(config,
        "AIRS verdict: " .. tostring(res_body_json.action) .. " category: " .. tostring(res_body_json.category))

    local action = res_body_json and res_body_json.action
    if not action then
        return "blocked", "'action' field not found in API response."
    end

    return action, "Verdict received from security scan."
end


-- ACCESS PHASE
function SecurePrismaAIRSHandler:access(config)
    kong.log.info("SecurePrismaAIRSHandler: Access phase triggered.")
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
            log_error(reason, verdict)
            return kong.response.exit(403, {
                message = "MCP request blocked by security policy.",
                reason = reason,
                mcp_method = mcp_method
            })
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
        return kong.response.exit(403, { message = "Request blocked by security policy.", reason = payload_err })
    end

    local verdict, reason = send_scan(config, payload)

    if verdict ~= "allow" then
        log_error(reason, verdict)
        return kong.response.exit(403, { message = "Request blocked by security policy.", reason = reason })
    end

    kong.log.info("SecurePrismaAIRSHandler: Prompt scan allowed.")
    kong.ctx.shared.request_body = request_body
end

-- RESPONSE PHASE
function SecurePrismaAIRSHandler:response(config)
    kong.log.info("SecurePrismaAIRSHandler: Response phase triggered.")

    -- Skip response scanning for bypassed MCP control messages
    if kong.ctx.shared.mcp_bypassed then
        log_debug(config, "Skipping response scan for MCP control message.")
        return
    end

    local original_request_body = kong.ctx.shared.request_body

    -- Use Kong PDK to read the upstream response body directly.
    -- ngx.ctx.buffered_body is not populated for MCP proxy routes.
    local response_body_str = kong.service.response.get_raw_body()

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
            log_error(reason, verdict)
            return kong.response.exit(403, {
                message = "MCP response blocked by security policy.",
                reason = reason
            })
        end

        log_debug(config, "MCP response scan allowed.")
        return
    end

    -- Standard LLM response scanning
    local payload, payload_err = build_prompt_payload(config, "response", original_request_body, response_body_str)

    if not payload then
        kong.log.warn("SecurePrismaAIRSHandler: " .. tostring(payload_err) .. " Skipping response scan.")
        return
    end

    local verdict, reason = send_scan(config, payload)

    if verdict ~= "allow" then
        log_error(reason, verdict)
        return kong.response.exit(403, { message = "Response blocked by security policy.", reason = reason })
    end

    kong.log.info("SecurePrismaAIRSHandler: Response scan allowed.")
end

return SecurePrismaAIRSHandler

-- kong/plugins/prisma-airs-intercept/handler.lua

local http = require("resty.http")
local cjson = require("cjson")

local SecurePrismaAIRSHandler = {
  PRIORITY = 1000,
  VERSION = "0.1.1",
}

-- A dedicated, protected function for logging errors safely.
local function log_error(reason, verdict)
  pcall(function()
    kong.log.error("SecurePrismaAIRSHandler: Blocking. Verdict: " .. tostring(verdict) .. ", Reason: " .. tostring(reason))
  end)
end

local function perform_scan(config, scan_type, request_body, response_body)
  -- 1. Extract the prompt and response from the chat completion format.
  local prompt_to_scan = ""
  if request_body and request_body.messages and type(request_body.messages) == "table" then
    for _, message in ipairs(request_body.messages) do
      if message.role == "user" then
        prompt_to_scan = message.content
        break
      end
    end
  end

  local response_to_scan = ""
  if response_body then
    -- The response body from the LLM will be a JSON string, so we must decode it first.
    local ok, decoded_response = pcall(cjson.decode, response_body)
    if ok and decoded_response and decoded_response.choices and decoded_response.choices[1] then
      response_to_scan = decoded_response.choices[1].message.content
    end
  end

  -- Prompt must exist and not be empty -- Response phase is dependent on Access.
  if not prompt_to_scan or prompt_to_scan == "" then
    return "blocked", "Could not find a user prompt in the request payload."
  end

  -- 2. Construct the payload for Prisma AIRS.
  local content_object = {}
  if scan_type == "prompt" then
    content_object.prompt = prompt_to_scan
  else
    content_object.prompt = prompt_to_scan
    content_object.response = response_to_scan
  end

  -- Get request metadata
  local request_id = kong.request.get_header("Kong-Request-ID") or kong.ctx.shared.request_id or ngx.var.request_id
  local service_name = kong.router.get_service() and kong.router.get_service().name or "unknown"
  local route_name = kong.router.get_route() and kong.router.get_route().name or "unknown"
  
  local payload_table = {
    tr_id = request_id or "unknown",
    ai_profile = { profile_name = config.profile_name },
    contents = { content_object },
    metadata = {
      app_name = config.app_name and ("kong-" .. config.app_name) or "kong",
      app_user = service_name,
      ai_model = request_body.model or "gpt-3.5-turbo"
    }
  }

  local request_payload_json, json_err = cjson.encode(payload_table)
  if json_err then
    return "blocked", "Internal plugin error: Could not encode payload."
  end

  print("Prisma AIRS Payload: " .. request_payload_json)

  -- 3. Make the HTTP request.
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
    local ok, err_keepalive = httpc:set_keepalive()
    if not ok then kong.log.warn("could not set keepalive on failed request: ", err_keepalive) end
    return "blocked", "API call failed: " .. tostring(err)
  end

  local res_body_str = res.body
  local ok, err_keepalive = httpc:set_keepalive()
  if not ok then kong.log.warn("could not set keepalive: ", err_keepalive) end

  if res.status ~= 200 then
     local reason = "API returned non-200 status: " .. res.status
     if res_body_str and res_body_str ~= "" then reason = reason .. " Body: " .. res_body_str end
     return "blocked", reason
  end

  if not res_body_str or res_body_str == "" then
      return "blocked", "API response body was empty, despite 200 OK status."
  end

  local res_body_json, decode_err = cjson.decode(res_body_str)
  if decode_err then
    return "blocked", "Failed to decode API response JSON: " .. tostring(decode_err)
  end

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

  -- Kong decodes the JSON into a Lua table automatically.
  local request_body, err = kong.request.get_body()
  if err or not request_body then
    log_error("Could not get request body: " .. tostring(err), "blocked")
    return kong.response.exit(400, { message = "Invalid or unreadable request body." })
  end

  local verdict, reason = perform_scan(config, "prompt", request_body)

  if verdict ~= "allow" then
    log_error(reason, verdict)
    return kong.response.exit(403, { message = "Request blocked by security policy.", reason = reason })
  end

  kong.log.info("SecurePrismaAIRSHandler: Prompt scan allowed.")
  -- Store the original request body for the response phase.
  kong.ctx.shared.request_body = request_body
end

-- RESPONSE PHASE
function SecurePrismaAIRSHandler:response(config)
  kong.log.info("SecurePrismaAIRSHandler: Response phase triggered.")

  local original_request_body = kong.ctx.shared.request_body
  local response_body_str = ngx.ctx.buffered_body

  if not response_body_str then
    kong.log.warn("SecurePrismaAIRSHandler: No response body found in response phase.")
    return
  end

  if not original_request_body then
    kong.log.warn("SecurePrismaAIRSHandler: Original request context not found. Skipping response scan.")
    return
  end

  -- Pass the original request body and the new response body for scanning.
  local verdict, reason = perform_scan(config, "response", original_request_body, response_body_str)

  if verdict ~= "allow" then
    log_error(reason, verdict)
    return kong.response.exit(403, { message = "Response blocked by security policy.", reason = reason })
  else
    kong.log.info("SecurePrismaAIRSHandler: Response scan in response phase was allowed.")
  end
end

-- Return the plugin definition.
return SecurePrismaAIRSHandler

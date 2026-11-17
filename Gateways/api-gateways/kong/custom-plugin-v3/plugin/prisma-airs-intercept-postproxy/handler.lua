-- kong/plugins/prisma-airs-intercept-postproxy/handler.lua

local http = require("resty.http")
local cjson = require("cjson")

-- The version reported here is the rockspec's version and nothing else: a
-- build or team suffix on it leaks an internal name to anyone who can read the
-- Admin API.
local SecurePrismaAIRSHandler = {
  PRIORITY = 760,  -- Below ai-proxy (770) for AI Gateway response phase compatibility
  VERSION = "0.3.0",
}

-- A dedicated, protected function for logging errors safely.
-- NOTE: this was kong.log.error(), which is not a PDK level (the PDK exposes
-- alert/crit/err/warn/notice/info/debug). Wrapped in the pcall below, a nil call
-- fails silently -- so every block log line risked being lost. `err` is valid on
-- every Kong version. Verify against a live gateway before upstreaming.
--
-- The `verdict` argument decides the level here, and must keep deciding it: a
-- signature that takes it and then sends every policy block to `err` is the
-- same as no split at all. Kong's convention separates plugin-author levels
-- (debug/info/notice) from platform-operator levels (warn/err/crit): a policy
-- block is the guardrail WORKING -- expected traffic on a healthy system --
-- and paging on it trains an operator to mute the one signal that matters. The
-- scanner being unreachable, and anything the plugin could not inspect, stay
-- at `err`.
local function log_error(reason, verdict)
  pcall(function()
    local unscanned = (verdict == "unscannable")
    local what = unscanned and "Refusing (nothing to scan)." or "Blocking."
    local line = "SecurePrismaAIRSHandler: " .. what .. " Verdict: " ..
      tostring(verdict) .. ", Reason: " .. tostring(reason)
    if verdict == "error" or unscanned then
      kong.log.err(line)
    else
      kong.log.notice(line)
    end
  end)
end

-- Debug logging helper (only logs when debug mode is enabled)
-- kong.log.debug is BELOW Kong's default level of `notice`, so `debug = true`
-- emitted there produces nothing unless KONG_LOG_LEVEL is also lowered. The
-- operator asked for this output; emit it where they will see it.
local function log_debug(config, message)
  if config and config.debug then
    pcall(function()
      kong.log.notice("SecurePrismaAIRSHandler: " .. tostring(message))
    end)
  end
end

-- The payload contains the prompt. Logging it is a data-handling decision and
-- needs its own switch, defaulting to off.
-- Where those lines ship, who can read them and what retention applies is part
-- of that decision, so the switch sits on top of `debug` rather than being
-- folded into it.
local function log_payload(config, message)
  if config and config.debug and config.debug_log_payloads then
    pcall(function()
      kong.log.notice("SecurePrismaAIRSHandler: " .. tostring(message))
    end)
  end
end

-- ---------------------------------------------------------------------------
-- Every fail-open this plugin takes lands on a structured record, via
-- kong.log.set_serialize_value, and not only in the prose of a log message: a
-- fail-open that only narrates itself cannot be rate-alerted on. The shape
-- matches the `airs` record the companion plugin emits, so one SIEM query
-- covers both.
-- ---------------------------------------------------------------------------
local function evidence()
  local e = kong.ctx.plugin.airs_evidence
  if not e then
    e = { scans = {}, gaps = {} }
    kong.ctx.plugin.airs_evidence = e
  end
  return e
end

local function publish()
  pcall(kong.log.set_serialize_value, "airs", evidence())
end

local function record_gap(kind, detail)
  local e = evidence()
  e.gaps[#e.gaps + 1] = { kind = kind, detail = detail }
  publish()
end

local function record_model(model)
  if type(model) ~= "string" or model == "" then return end
  local e = evidence()
  if e.ai_model then return end
  e.ai_model = model
  publish()
end

local function record_scan(leg, action, airs_body, detail, failed_open)
  local e = evidence()
  e.scans[#e.scans + 1] = {
    leg = leg,
    action = action,
    outcome = failed_open and "failed_open"
              or (action == "error" and "fail_closed" or "verdict"),
    enforced = (not failed_open) and true or false,
    scan_id   = type(airs_body) == "table" and airs_body.scan_id or nil,
    report_id = type(airs_body) == "table" and airs_body.report_id or nil,
    category  = type(airs_body) == "table" and airs_body.category or nil,
    detail = detail,
  }
  publish()
end

-- One place to decide what happens when we could not inspect something we were
-- supposed to inspect. Always at `err`, always on the record, and it honours
-- the on_scan_error the schema declares. Every fail-open routes through here
-- rather than a bare kong.log.warn + return, which would consult no config and
-- leave nothing countable.
local function scan_gap(config, detail)
  pcall(function()
    kong.log.err("SecurePrismaAIRSHandler: scan gap - " .. tostring(detail))
  end)
  record_gap("scan_gap", detail)
  return (config.on_scan_error or "block") ~= "allow"
end

-- An AIRS API failure is the SCANNER being unavailable, not a verdict about the
-- content. Returns true when the request should be forwarded anyway.
local function api_error_allows(config, reason)
  if (config and config.on_api_error) ~= "allow" then return false end
  pcall(function()
    kong.log.err("SecurePrismaAIRSHandler: AIRS unavailable and on_api_error=allow; " ..
                 "forwarding UNSCANNED. Reason: " .. tostring(reason))
  end)
  record_gap("api_error_allowed", tostring(reason))
  return true
end

-- Test the name by type and contents, not by truthiness: "" is truthy in Lua,
-- so a `config.app_name and ("kong-" .. config.app_name) or "kong"` shortcut
-- sends the literal "kong-" for an empty string, labelling every scan in the
-- tenant with a name that identifies nothing.
local function airs_app_name(config)
  local n = config and config.app_name
  if type(n) ~= "string" or n == "" then return "kong" end
  return "kong-" .. n
end

-- Naming the region removes the transcription step. An explicitly set
-- api_endpoint still wins -- a private or proxied host must not be overwritten.
local AIRS_DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
local AIRS_REGIONAL_HOSTS = {
  us   = AIRS_DEFAULT_ENDPOINT,
  eu   = "https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request",
  apac = "https://service-sg.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request",
}

local function airs_endpoint(config)
  local configured = config and config.api_endpoint
  local region = config and config.region
  if type(region) == "string" and AIRS_REGIONAL_HOSTS[region]
     and (configured == nil or configured == AIRS_DEFAULT_ENDPOINT) then
    return AIRS_REGIONAL_HOSTS[region]
  end
  return configured
end

-- Reading `messages` and nothing else extracts no prompt from a Gemini, Cohere
-- or legacy-completions body, which then takes the fail-closed 403 on a route
-- where nothing was wrong with the request; refusing those shapes with a 400
-- only trades a silent gap for an outage. Read the shapes. The ORDER matters:
-- the OpenAI and Bedrock shapes are tried first and each branch is guarded on a
-- field the earlier shapes do not carry, so none of them can shadow a native
-- path.
local function extract_extra_prompt(request_body)
  if type(request_body) ~= "table" then return nil end

  -- Gemini generateContent
  if type(request_body.contents) == "table" then
    local texts = {}
    for _, turn in ipairs(request_body.contents) do
      -- Only the caller's turns. A `model` turn is the assistant's own earlier
      -- answer and is not the prompt this request is asking about.
      if type(turn) == "table" and (turn.role == nil or turn.role == "user")
         and type(turn.parts) == "table" then
        for _, part in ipairs(turn.parts) do
          if type(part) == "table" and type(part.text) == "string" and part.text ~= "" then
            texts[#texts + 1] = part.text
          end
        end
      end
    end
    if #texts > 0 then return table.concat(texts, "\n") end
  end

  -- Cohere v1 chat
  if type(request_body.message) == "string" and request_body.message ~= "" then
    return request_body.message
  end

  -- Legacy OpenAI completions: a string, or a list of strings
  local prompt = request_body.prompt
  if type(prompt) == "string" and prompt ~= "" then return prompt end
  if type(prompt) == "table" then
    local texts = {}
    for _, entry in ipairs(prompt) do
      if type(entry) == "string" and entry ~= "" then texts[#texts + 1] = entry end
    end
    if #texts > 0 then return table.concat(texts, "\n") end
  end

  return nil
end

local function perform_scan(config, scan_type, request_body, response_body)
  -- 1. Extract the prompt and response from the chat completion format.
  -- Scan the LAST user message (most recent prompt in conversation)
  local prompt_to_scan = ""
  if request_body and request_body.messages and type(request_body.messages) == "table" then
    for _, message in ipairs(request_body.messages) do
      -- Elements are client-controlled, so each one is type-tested first: a
      -- scalar entry must not raise here.
      if type(message) == "table" and message.role == "user" then
        local content = message.content
        if type(content) == "string" then
          prompt_to_scan = content
        elseif type(content) == "table" then
          -- Multimodal / Bedrock Converse: an array of parts. Prefer the text of
          -- the first part that has one, else serialize so SOMETHING is scanned.
          local text
          for _, part in ipairs(content) do
            if type(part) == "string" then text = part break end
            if type(part) == "table" and type(part.text) == "string" then text = part.text break end
          end
          if text then
            prompt_to_scan = text
          else
            local ok, serialized = pcall(cjson.encode, content)
            prompt_to_scan = ok and serialized or ""
          end
        end
        -- Continue iterating to get the last user message
      end
    end
  end
  -- Fall back to the provider shapes the `messages` walk does not cover.
  if prompt_to_scan == "" then
    prompt_to_scan = extract_extra_prompt(request_body) or ""
  end

  -- Lua evaluates arguments eagerly, so this concatenation runs at the CALL
  -- SITE -- outside the helper's pcall and before its own gate. Keep the gate
  -- and the tostring() here: a table or nil prompt would otherwise raise in
  -- string.sub and surface as a 500, ahead of the guard below that exists to
  -- catch exactly that case.
  if config and config.debug then
    local p = tostring(prompt_to_scan)
    log_payload(config, "Extracted prompt: " .. string.sub(p, 1, 100) .. (#p > 100 and "..." or ""))
  end

  -- Sending "" whenever the body is not an OpenAI chat completion is a scan
  -- AIRS allows -- indistinguishable in SCM from a clean one. Dispatch on
  -- shape, and report extraction failure to the caller instead of forging a
  -- pass.
  local response_to_scan = ""
  local response_unreadable = false
  if response_body then
    local ok, decoded = pcall(cjson.decode, response_body)
    if ok and type(decoded) == "table" then
      -- Every hop is type-tested before it is dereferenced: a streamed `delta`
      -- chunk or a Responses-shaped body must not raise a 500 in the response
      -- phase, after the model has already been billed.
      local first = type(decoded.choices) == "table" and decoded.choices[1] or nil
      if type(first) == "table" and type(first.message) == "table" then
        local c = first.message.content
        response_to_scan = type(c) == "string" and c or ""
      elseif type(decoded.output) == "table" and type(decoded.output.message) == "table" then
        -- Bedrock Converse
        local c = decoded.output.message.content
        if type(c) == "string" then
          response_to_scan = c
        elseif type(c) == "table" then
          for _, part in ipairs(c) do
            if type(part) == "table" and type(part.text) == "string" then response_to_scan = part.text break end
          end
        end
      elseif type(decoded.content) == "table" then
        -- Anthropic messages
        for _, part in ipairs(decoded.content) do
          if type(part) == "table" and type(part.text) == "string" then response_to_scan = part.text break end
        end
      -- The response leg reads the same shapes as the request leg. Without
      -- these branches it reports "could not be inspected" for a body it simply
      -- does not know how to read, which here is a hard 403.
      elseif type(decoded.candidates) == "table" then
        local texts = {}
        for _, cand in ipairs(decoded.candidates) do
          local parts = type(cand) == "table" and type(cand.content) == "table" and cand.content.parts
          if type(parts) == "table" then
            for _, part in ipairs(parts) do
              if type(part) == "table" and type(part.text) == "string" and part.text ~= "" then
                texts[#texts + 1] = part.text
              end
            end
          end
        end
        response_to_scan = #texts > 0 and table.concat(texts, "\n") or ""
      elseif type(decoded.text) == "string" then
        -- Cohere v1
        response_to_scan = decoded.text
      end
    end
    if response_to_scan == "" then response_unreadable = true end
  end

  -- These are not AIRS verdicts, and must not be reported as "blocked": that
  -- makes the log line indistinguishable from a real policy block, and sends an
  -- operator chasing a false positive after a scan_id that was never issued.
  if scan_type ~= "prompt" and response_unreadable then
    return "unscannable", "Response body could not be inspected (unrecognised shape or unparseable)."
  end

  -- Prompt must exist and not be empty -- Response phase is dependent on Access.
  if not prompt_to_scan or prompt_to_scan == "" then
    return "unscannable", "Could not find a user prompt in the request payload."
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
  -- The trusted PDK id, never a CLIENT-supplied `Kong-Request-ID` header: that
  -- one is unvalidated and unbounded, so a caller could pin, merge or split SCM
  -- sessions, or blow the 100-char AIRS cap and 403 its own route with a single
  -- header.
  local request_id
  do
    local ok, id = pcall(kong.request.get_id)
    if ok and type(id) == "string" and id ~= "" then request_id = id end
    if not request_id then request_id = ngx.var.request_id end
    if type(request_id) == "string" and #request_id > 100 then
      request_id = string.sub(request_id, 1, 100)
    end
  end
  -- The model is computed for the AIRS envelope on every request, and is put on
  -- the log record as well. Kong's own serializer does not carry it, so without
  -- this "which model was this traffic going to" can only be answered by
  -- parsing a message string.
  local ai_model = (type(request_body.model) == "string" and request_body.model ~= "")
                   and request_body.model or "unknown"
  record_model(ai_model)

  local service_name = kong.router.get_service() and kong.router.get_service().name or "unknown"

  -- `tr_id` is the legacy SESSION-slot alias; the transaction slot is filled
  -- only by `transaction_id`. Sending a per-request value as tr_id would make
  -- every turn its own conversation and leave transaction_id server-minted.
  local payload_table = {
    transaction_id = request_id or "unknown",
    -- Bind by id when the operator gave one; a name is only as stable as the
    -- last person to rename it in SCM.
    ai_profile = (type(config.profile_id) == "string" and config.profile_id ~= "")
                 and { profile_id = config.profile_id }
                 or  { profile_name = config.profile_name },
    contents = { content_object },
    metadata = {
      app_name = airs_app_name(config),
      app_user = service_name,
      -- Do not invent a model name.
      ai_model = ai_model,
    }
  }

  -- Plain cjson RAISES; it never returns an error value, so the encode stays
  -- inside a pcall -- testing a second return value would be dead code and let
  -- a genuine failure escape as a 500.
  local enc_ok, request_payload_json = pcall(cjson.encode, payload_table)
  if not enc_ok then
    return "error", "Internal plugin error: Could not encode payload."
  end

  log_payload(config, "AIRS request payload: " .. request_payload_json)

  -- 3. Make the HTTP request.
  -- set_timeouts() gives connect, send and read separate budgets. A single
  -- set_timeout(n) applies n to all three, making the worst case 3n per scan,
  -- and field-measured AIRS cold-path spikes past 5 s then become false 403s on
  -- scans AIRS had actually ALLOWED. Three phases, three knobs, so an operator
  -- can tune them; timeout_ms, when it is the only one set, still governs all
  -- three.
  local httpc = http.new()
  local legacy = tonumber(config.timeout_ms)
  local connect_ms = tonumber(config.connect_timeout_ms) or legacy or 2000
  local send_ms    = tonumber(config.send_timeout_ms)    or legacy or 5000
  local read_ms    = tonumber(config.read_timeout_ms)    or legacy or 20000
  httpc:set_timeouts(connect_ms, send_ms, read_ms)
  log_debug(config, "Sending scan request to AIRS API (connect/send/read: " ..
            connect_ms .. "/" .. send_ms .. "/" .. read_ms .. "ms)")

  local res, err = httpc:request_uri(airs_endpoint(config), {
      method = "POST",
      body = request_payload_json,
      headers = {
        ["Content-Type"] = "application/json",
        ["Accept"] = "application/json",
        ["x-pan-token"] = config.api_key
      },
      ssl_verify = config.ssl_verify
  })

  -- request_uri() already returns the socket to the pool on lua-resty-http
  -- >= 0.16 (what Kong 3.x bundles), so no set_keepalive call belongs here: one
  -- placed after it acts on a closed connection and emits a warn per scan --
  -- noise that reads like a pooling bug and is not one.
  if not res then
    return "error", "API call failed: " .. tostring(err)
  end

  local res_body_str = res.body

  if res.status ~= 200 then
     local reason = "API returned non-200 status: " .. res.status
     if res_body_str and res_body_str ~= "" then reason = reason .. " Body: " .. res_body_str end
     return "error", reason
  end

  if not res_body_str or res_body_str == "" then
      return "error", "API response body was empty, despite 200 OK status."
  end

  -- The decode stays inside a pcall on the way back too. An AIRS 200 carrying
  -- non-JSON (a captive portal, an intercepting proxy's HTML) must take the
  -- intended fail-closed 403 rather than raising a 500.
  local dec_ok, res_body_json = pcall(cjson.decode, res_body_str)
  if not dec_ok then
    return "error", "Failed to decode API response JSON: " .. tostring(res_body_json)
  end

  local action = res_body_json and res_body_json.action
  if not action then
    return "error", "'action' field not found in API response."
  end

  -- Build a detailed reason from the AIRS response fields.
  local reason_parts = { "Verdict: " .. tostring(action) }
  if res_body_json.category and res_body_json.category ~= "" then
    table.insert(reason_parts, "Category: " .. tostring(res_body_json.category))
  end
  if res_body_json.scan_id and res_body_json.scan_id ~= "" then
    table.insert(reason_parts, "Scan ID: " .. tostring(res_body_json.scan_id))
  end

  local reason = table.concat(reason_parts, ". ") .. "."
  log_debug(config, "AIRS response: " .. reason)

  return action, reason, res_body_json
end

-- ACCESS PHASE
function SecurePrismaAIRSHandler:access(config)
  -- Per-request narration goes through the log_debug gate. A bare kong.log.info
  -- here narrates every request at info regardless of config.debug, on routes
  -- whose operator never asked for the output.
  log_debug(config, "Access phase triggered.")
  kong.service.request.enable_buffering()

  -- The body read is gated by method: an ungated read gives every GET, HEAD
  -- and CORS preflight a flat 400, which stops the plugin being attached
  -- globally or to a mixed REST+LLM service.
  local method = "POST"
  do
    local ok, m = pcall(kong.request.get_method)
    if ok and type(m) == "string" then method = m end
  end
  if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then
    log_debug(config, method .. " carries no scannable body; passing through.")
    -- "We chose not to scan this" is not "we lost the context of something we
    -- did scan". Without the flag the response leg treats a GET as a
    -- missing-context gap and, fail-closed, 403s it.
    kong.ctx.plugin.no_scannable_request = true
    return
  end

  -- get_body() is given an explicit max_allowed_file_size. Without one, above
  -- Kong's default client_body_buffer_size (8 KB) nginx spills the body to a
  -- temp file, the read fails, and ordinary RAG / tool-schema / multi-turn
  -- traffic gets "Invalid or unreadable request body" -- a message pointing
  -- nowhere near the cause. Oversize is a scan gap, not malformed input: 413,
  -- and fail closed.
  local max_body = tonumber(config.max_request_body_bytes) or (8 * 1024 * 1024)
  local request_body, err = kong.request.get_body(nil, nil, max_body)
  if err or not request_body then
    local lower = string.lower(tostring(err or ""))
    local oversize = string.find(lower, "buffer", 1, true) ~= nil
                  or string.find(lower, "did not fit", 1, true) ~= nil
                  or string.find(lower, "too large", 1, true) ~= nil
    if oversize then
      -- The fail-open this path can take goes through the one decision point,
      -- so it lands on the structured record: logging prose and reading the
      -- config inline here would leave nothing countable behind.
      if scan_gap(config, "request body exceeds the scannable size (" ..
                          tostring(err) .. "). Raise config.max_request_body_bytes, and " ..
                          "Kong's own nginx_http_client_body_buffer_size to match.") then
        return kong.response.exit(413, { message = "Request body too large to scan." })
      end
      return
    end
    log_error("Could not get request body: " .. tostring(err), "unscannable")
    return kong.response.exit(400, { message = "Invalid or unreadable request body." })
  end

  -- This plugin has no SSE reassembly whatsoever. A streamed response arrives
  -- as text/event-stream and fails cjson.decode, so forwarding it would leave
  -- the response leg reporting a pass -- i.e. `"stream": true` would be a
  -- one-line client-side switch that turns the response guardrail off. Refuse
  -- it up front, before the model is billed, unless an operator has explicitly
  -- accepted unscanned streams on this route.
  if request_body.stream == true and not config.allow_unscanned_streaming then
    log_error("Streaming requested but this plugin cannot scan SSE responses", "unscannable")
    return kong.response.exit(400, {
      message = "Streaming responses are not supported by the security scanner on this route.",
    })
  end

  local verdict, reason, airs_response = perform_scan(config, "prompt", request_body)

  if verdict ~= "allow" then
    log_error(reason, verdict)

    -- An AIRS outage is not a policy block. Answering an API failure with a 403
    -- reaches the client as the guardrail firing when it never ran, and leaves
    -- the operator no switch either way. The switch is on_api_error; the
    -- default is still closed.
    if verdict == "error" then
      if api_error_allows(config, reason) then
        record_scan("prompt", verdict, airs_response, reason, true)
        kong.ctx.shared.request_body = request_body
        return
      end
      record_scan("prompt", verdict, airs_response, reason)
      return kong.response.exit(503, {
        message = "Security scan unavailable.",
        reason = "The security scanner could not be reached.",
      })
    end

    record_scan("prompt", verdict, airs_response, reason)
    local response_body = {
      message = "Request blocked by security policy.",
      reason = reason,
    }
    if airs_response then
      response_body.category = airs_response.category
      response_body.scan_id = airs_response.scan_id
    end
    return kong.response.exit(403, response_body)
  end

  record_scan("prompt", verdict, airs_response)
  log_debug(config, "Prompt scan allowed.")
  -- Store the original request body for the response phase.
  kong.ctx.shared.request_body = request_body
end

-- RESPONSE PHASE
function SecurePrismaAIRSHandler:response(config)
  log_debug(config, "Response phase triggered.")

  -- Scanning both legs is two AIRS calls per request, each adding latency and
  -- spend, so the second one is switchable. No path here is enforced by the
  -- response leg alone, so the knob does exactly what it says: one call instead
  -- of two, prompt enforcement untouched.
  if config.scan_responses == false then
    log_debug(config, "Response scanning disabled by configuration; not calling AIRS.")
    return
  end

  local original_request_body = kong.ctx.shared.request_body
  local response_body_str = ngx.ctx.buffered_body

  -- Neither of these may become a `kong.log.warn(...)` followed by `return` --
  -- the upstream's answer forwarded to the client unscanned, at the one level
  -- nobody alerts on, consulting no config and leaving nothing on any record.
  -- Missing context is a gap, and asks on_scan_error like every other one. A
  -- genuinely EMPTY body (a 204, a notification's 202) is not a gap and is not
  -- treated as one.
  if not response_body_str then
    log_debug(config, "No response body to scan.")
    return
  end

  if not original_request_body then
    if kong.ctx.plugin.no_scannable_request then
      log_debug(config, "Bodyless request; nothing to pair this response with.")
      return
    end
    if scan_gap(config, "original request context missing in response phase") then
      return kong.response.exit(403, { message = "Response blocked by security policy." })
    end
    return
  end

  -- Both halves are bounded. Without a cap here an upstream body is submitted
  -- for scanning whatever its size. Over the cap is a gap, taking the same
  -- on_scan_error decision as every other one.
  --
  -- It sits below the status check on purpose: above it, a 502 whose error body
  -- happens to exceed the cap becomes a security 403 and the real cause is
  -- erased.
  local up_status = 200
  do
    local ok, st = pcall(kong.response.get_status)
    if ok and type(st) == "number" then up_status = st end
  end
  if up_status >= 400 then
    log_debug(config, "Upstream returned " .. up_status .. "; not scanning an error body.")
    return
  end

  local cap = tonumber(config.max_response_body_bytes) or (8 * 1024 * 1024)
  if #response_body_str > cap then
    if scan_gap(config, "response body exceeds the scannable size (" ..
                        #response_body_str .. " > " .. cap ..
                        " bytes). Raise config.max_response_body_bytes.") then
      return kong.response.exit(403, { message = "Response blocked by security policy." })
    end
    return
  end

  -- Pass the original request body and the new response body for scanning.
  local verdict, reason, airs_response = perform_scan(config, "response", original_request_body, response_body_str)

  if verdict ~= "allow" then
    log_error(reason, verdict)

    if verdict == "error" then
      if api_error_allows(config, reason) then
        record_scan("response", verdict, airs_response, reason, true)
        return
      end
      record_scan("response", verdict, airs_response, reason)
      return kong.response.exit(503, {
        message = "Security scan unavailable.",
        reason = "The security scanner could not be reached.",
      })
    end

    -- "We could not read this response" is a GAP, not a verdict, and must take
    -- the on_scan_error decision rather than an unconditional 403.
    if verdict == "unscannable" then
      if scan_gap(config, reason) then
        return kong.response.exit(403, { message = "Response blocked by security policy." })
      end
      return
    end

    record_scan("response", verdict, airs_response, reason)
    local response_body = {
      message = "Response blocked by security policy.",
      reason = reason,
    }
    if airs_response then
      response_body.category = airs_response.category
      response_body.scan_id = airs_response.scan_id
    end
    return kong.response.exit(403, response_body)
  else
    record_scan("response", verdict, airs_response)
    log_debug(config, "Response scan in response phase was allowed.")
  end
end

-- Return the plugin definition.
return SecurePrismaAIRSHandler

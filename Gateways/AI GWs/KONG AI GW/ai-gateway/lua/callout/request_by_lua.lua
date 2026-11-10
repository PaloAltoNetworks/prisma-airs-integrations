-- request-callout :: callouts[].request.by_lua  (callout name: airs_scan)
--
-- Runs BEFORE the callout to Prisma AIRS is made. Reads the client's JSON-RPC
-- envelope, decides what kind of MCP message it is, and writes the AIRS
-- ScanRequest into the callout's request body.
--
-- SANDBOX RULES THAT SHAPE THIS FILE. Kong states that a nil reference inside
-- by_lua produces an Internal Server Error at runtime, and schema validation
-- catches syntax only. So every table access is guarded, the whole body is
-- wrapped in pcall, and no error string ever carries a configuration value or a
-- credential.
--
-- WHY A METHOD ALLOWLIST DRIVES THIS. AIRS validates tool_event.metadata.method
-- against an allowlist of exactly `tools/call` and `tools/list`; every other
-- method is refused with `400 unsupported method`, `initialize` included. A
-- gateway that submits `initialize` as a tool event therefore fails the first
-- message of every MCP session closed. Methods outside the allowlist that still
-- carry caller-chosen text are submitted as a PROMPT instead, which has no
-- method allowlist. Coverage is the same; the submitted shape differs.

local cjson = require("cjson.safe")

-- These three are substituted by scripts/build-config.py when the Lua is
-- inlined into the policy YAML. A guardrail function receives `conf` and can
-- read config.params; a callout by_lua does NOT -- there is no documented way
-- to reach the policy's own config from here -- so the values are pinned into
-- the code at build time and the YAML remains the single place an operator
-- edits them.
local PROFILE_NAME = "__AIRS_PROFILE_NAME__"
local APP_NAME     = "__AIRS_APP_NAME__"
local SERVER_NAME  = "__AIRS_SERVER_NAME__"

-- Methods that carry no caller or server text. Scanning them would submit an
-- empty payload, and AIRS allows an empty string -- recording a clean scan of
-- nothing. They are bypassed explicitly and named in docs/DESIGN.md.
local NO_CONTENT = {
    ["ping"]                  = true,
    ["initialize"]            = true,
    ["notifications/initialized"] = true,
    ["logging/setLevel"]      = true,
}

local function is_notification(m)
    return type(m) == "string" and m:sub(1, 14) == "notifications/"
end

-- AIRS accepts these two as tool events. Everything else goes to the prompt path.
local TOOL_EVENT_METHODS = { ["tools/call"] = true, ["tools/list"] = true }

-- OpenResty's lua-cjson escapes forward slashes by default, so a tool argument
-- of "/etc/shadow" is encoded as "\/etc\/shadow" and "https://evil.com/x" as
-- "https:\/\/evil.com\/x". Both are legal JSON and both decode correctly --
-- but AIRS runs TEXT detectors over `input`, and a URL or path detector is
-- matching the characters it is given. Handing it backslashes it has no reason
-- to expect is a quiet way to lower the detection rate on exactly the arguments
-- that matter.
--
-- The module-level switch (cjson.encode_escape_forward_slash) is global to the
-- worker and would change encoding for everything else sharing the module, so
-- this unescapes its own output instead. The substitution is lossless: "\/" is
-- JSON's only two-character escape ending in a slash, and a literal backslash
-- before a slash encodes as "\\\/", where the gsub consumes the trailing
-- "\/" and leaves "\\/" -- still a backslash followed by a slash.
local function encode_or_nil(v)
    if v == nil then return nil end
    if type(v) == "string" then return v end
    local ok, s = pcall(cjson.encode, v)
    if ok and type(s) == "string" and s ~= "" and s ~= "{}" and s ~= "[]" then
        return (s:gsub("\\/", "/"))
    end
    return nil
end

-- Returns: contents_item (table|nil), classification (string)
local function classify(body, server_name)
    if type(body) ~= "table" then
        return nil, "unparseable"
    end

    -- A JSON-RPC BATCH is a top-level array. MCP revision 2025-06-18 removed
    -- batching, and Kong's behaviour on receiving one is undocumented, so this
    -- refuses to classify rather than inspecting element one and waving the rest
    -- through -- which is an evasion primitive, not a shortcut.
    if body[1] ~= nil then
        return nil, "batch"
    end

    -- Require the envelope. Accepting a bare `method` key would let a caller
    -- dress arbitrary JSON as MCP, or dress MCP as arbitrary JSON.
    if body.jsonrpc ~= "2.0" or type(body.method) ~= "string" then
        return nil, "not-jsonrpc"
    end

    local method = body.method
    if NO_CONTENT[method] or is_notification(method) then
        return nil, "bypass"
    end

    local params = body.params
    if type(params) ~= "table" then
        -- A content-bearing method with no params carries nothing to scan.
        return nil, "bypass"
    end

    if TOOL_EVENT_METHODS[method] then
        if method == "tools/call" then
            -- `input` and `output` are typed as STRINGS in the AIRS schema: a
            -- JSON document encoded into a string, not a nested object. Sending
            -- a native object earns `400 received wrong request format`.
            local input = encode_or_nil(params.arguments)
            if input == nil then return nil, "bypass" end
            local tool = params.name
            return {
                tool_event = {
                    metadata = {
                        ecosystem   = "mcp",
                        method      = "tools/call",
                        server_name = server_name,
                        -- ToolEventMetadata is additionalProperties:false with
                        -- ecosystem, method and server_name required, so no
                        -- extra context can ride along here.
                        tool_invoked = type(tool) == "string" and tool or "unknown",
                    },
                    input = input,
                },
            }, "tool_event"
        end
        -- `tools/list` on the REQUEST leg carries no catalogue -- the catalogue
        -- is in the reply, which this policy cannot see (see docs/DESIGN.md). A
        -- ToolEvent requires input or output, so there is nothing to send.
        return nil, "bypass"
    end

    -- Everything else that carries caller-chosen text: resources/read,
    -- prompts/get, completion/complete, sampling/createMessage,
    -- elicitation/create, and any vendor extension. Submitted as a prompt.
    local text = encode_or_nil(params)
    if text == nil then return nil, "bypass" end
    return { prompt = text }, "prompt"
end

local ok, err = pcall(function()
    local shared = kong.ctx.shared
    local conf   = (shared.callouts and shared.callouts.airs_scan) or nil
    if conf == nil then return end

    local body = kong.request.get_body()
    if type(body) ~= "table" then
        local raw = kong.request.get_raw_body()
        if type(raw) == "string" and raw ~= "" then
            body = cjson.decode(raw)
        end
    end

    local item, how = classify(body, SERVER_NAME)

    -- Remembered for upstream.by_lua: a message that was never scanned must not
    -- be reported downstream as one that passed.
    shared.airs_mcp = {
        classification = how,
        method  = type(body) == "table" and body.method or nil,
        id      = type(body) == "table" and body.id or nil,
        scanned = item ~= nil,
    }

    if item == nil then
        -- Nothing to scan. The callout still fires -- request-callout has no
        -- conditional-skip field -- so it is sent a payload AIRS will accept
        -- and allow, and upstream.by_lua ignores the verdict for this message.
        -- The cost is one AIRS call per control message; see docs/DESIGN.md.
        item = { prompt = "." }
    end

    local scan = {
        ai_profile = { profile_name = PROFILE_NAME },
        metadata   = { app_name = APP_NAME, ai_model = "mcp" },
        contents   = { item },
    }

    -- CORRELATION, and the one place the MCP path beats the LLM path. by_lua is
    -- real Lua with PDK access, so unlike a guardrail function -- which can see
    -- only source, content, conf and resp -- it can reach a trusted request id
    -- and the MCP session header.
    --
    -- The id is Kong's own, never a client-supplied header: a caller who can set
    -- the correlation id can pin, split or collide sessions in the SCM scan log.
    local rid = kong.request.get_id and kong.request.get_id() or nil
    if type(rid) == "string" and rid ~= "" then scan.transaction_id = rid end
    local sid = kong.request.get_header("Mcp-Session-Id")
    -- Omitted rather than invented when nothing identifies the conversation.
    if type(sid) == "string" and sid ~= "" then scan.session_id = sid end

    local encoded = cjson.encode(scan)
    if type(encoded) ~= "string" then
        error("scan payload could not be encoded")
    end
    conf.request.params.body = encoded
end)

if not ok then
    -- Fail closed, and say nothing useful to the caller. A classification or
    -- encoding failure here means the content was never inspected.
    kong.ctx.shared.airs_mcp = { classification = "error", scanned = false, fatal = true }
    kong.log.err("[prisma-airs-mcp] request.by_lua failed: ", tostring(err))
end

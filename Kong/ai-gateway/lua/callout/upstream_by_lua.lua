-- request-callout :: config.upstream.by_lua
--
-- Runs BEFORE the upstream request is made, in the access phase -- which is the
-- whole reason enforcement is possible here at all. The Kong PDK permits
-- kong.response.exit WITH A BODY only in preread, rewrite, access and
-- admin_api; there is no response-phase hook in this policy that could reject
-- anything. So this is the single enforcement point.
--
-- WHY A JSON-RPC ERROR AND NOT A BARE 403. An MCP client that receives a bare
-- HTTP 403 sees a transport failure, and several SDKs tear the session down on
-- one. A JSON-RPC error object carrying the caller's OWN request id is a tool
-- failure: the client surfaces it against the call that caused it, and the
-- session survives, so one blocked tool call does not end the conversation.
--
-- The HTTP status is 403 to match Kong's own MCP denials, which follow the MCP
-- 2025-11-25 authorization specification from AI Gateway 3.14 onward. The
-- JSON-RPC codes match PANW's v3 Kong plugin exactly -- -32001 for a policy
-- block, -32003 for the scanner being unavailable -- so a client that has
-- learned one Prisma AIRS integration has learned both.

-- Classifications that mean the body was NEVER INSPECTED because the hook
-- refused to classify it: a JSON-RPC batch (a top-level array), a body without
-- `jsonrpc: "2.0"` and a string method, and a body that does not decode to a
-- JSON object at all. A `tools/call` can be sitting inside any of the three.
--
-- A deliberate bypass is NOT one of these. ping, notifications/*, initialize
-- and tools/list carry no caller content on the request leg, so there is
-- nothing to scan and nothing to refuse; they are named in docs/DESIGN.md 4.3.
local UNCLASSIFIED = { batch = true, ["not-jsonrpc"] = true, unparseable = true }

-- FAIL CLOSED. An unscanned tools/call is refused, and pass-through is an
-- opt-in an operator has to write down. The test is an exact match on "allow",
-- so an empty value, a typo, or an unsubstituted placeholder all refuse --
-- the safe answer is the one you get by default AND the one you get by
-- accident. Set params.unclassified_action to "allow" to pass them through,
-- which is a transport-compatibility choice, not a security one.
local UNCLASSIFIED_ACTION = "__AIRS_UNCLASSIFIED_ACTION__"

local ok, err = pcall(function()
    local shared  = kong.ctx.shared
    local mcp     = shared.airs_mcp
    local verdict = shared.airs_verdict

    -- A message that was never scanned is not a message that passed. If
    -- classification itself failed, refuse: the content was not inspected.
    if type(mcp) == "table" and mcp.fatal == true then
        return kong.response.exit(403, {
            jsonrpc = "2.0",
            id = mcp.id ~= nil and mcp.id or require("cjson.safe").null,
            error = { code = -32001, message = "Blocked by Prisma AIRS" },
        })
    end

    -- A body the hook could not classify was not inspected, so it is refused
    -- on the same path as a classification failure. -32001 rather than -32003:
    -- nothing was wrong with the scanner, the message was rejected. Kong's
    -- behaviour on receiving a batch at an MCP route is UNVERIFIED, so an
    -- operator who finds a legitimate client tripping this can opt out.
    if type(mcp) == "table" and UNCLASSIFIED[mcp.classification] == true
       and UNCLASSIFIED_ACTION ~= "allow" then
        kong.log.warn("[prisma-airs-mcp] refusing unclassified message: ",
                      tostring(mcp.classification))
        return kong.response.exit(403, {
            jsonrpc = "2.0",
            id = mcp.id ~= nil and mcp.id or require("cjson.safe").null,
            error = { code = -32001, message = "Blocked by Prisma AIRS" },
        })
    end

    -- Deliberately bypassed control messages (ping, notifications/*,
    -- initialize) carry no caller content. The callout fired anyway -- the
    -- policy has no conditional-skip field -- and its verdict is ignored here
    -- rather than being allowed to block a message nobody scanned.
    if type(mcp) == "table" and mcp.scanned ~= true then
        return
    end

    -- No verdict record at all means response.by_lua never ran, which means the
    -- callout never completed. request.error handles the availability cases it
    -- can see; this closes the rest.
    if type(verdict) ~= "table" then
        return kong.response.exit(403, {
            jsonrpc = "2.0",
            id = (type(mcp) == "table" and mcp.id ~= nil) and mcp.id or require("cjson.safe").null,
            error = { code = -32003, message = "Prisma AIRS scan unavailable" },
        })
    end

    if verdict.block == true then
        -- response.by_lua sets this explicitly. The string comparisons remain
        -- only as a fallback for a verdict written by an older build, and they
        -- are deliberately not the primary test: they missed "scan error" and
        -- "scan timeout", so an AIRS-reported scan failure was answered as a
        -- policy block. When in doubt the answer is "unavailable", because
        -- telling a caller it was blocked when nothing judged the content is
        -- the worse of the two errors.
        local unavailable = verdict.unavailable == true
                         or verdict.reason == "verdict unavailable"
                         or verdict.reason == "verdict parse failure"
                         or verdict.reason == "partial scan failure"
                         or verdict.reason == "detector degraded"
                         or (type(verdict.reason) == "string"
                             and verdict.reason:sub(1, 5) == "scan ")
        local message = "Blocked by Prisma AIRS"
        if verdict.scan_id then message = message .. " [scan_id=" .. verdict.scan_id .. "]" end
        return kong.response.exit(403, {
            jsonrpc = "2.0",
            id = (type(mcp) == "table" and mcp.id ~= nil) and mcp.id or require("cjson.safe").null,
            -- The client is told that it was blocked, never why. The category
            -- and the detectors are in the gateway log and in the Strata Cloud
            -- Manager scan log, correlated by scan_id.
            error = { code = unavailable and -32003 or -32001,
                      message = unavailable and "Prisma AIRS scan unavailable" or message },
        })
    end
end)

if not ok then
    kong.log.err("[prisma-airs-mcp] upstream.by_lua failed: ", tostring(err))
    -- The enforcement hook itself failed. Nothing has reached the MCP server
    -- yet, so refusing is still available and is the only safe answer.
    return kong.response.exit(403, {
        jsonrpc = "2.0", id = require("cjson.safe").null,
        error = { code = -32003, message = "Prisma AIRS scan unavailable" },
    })
end

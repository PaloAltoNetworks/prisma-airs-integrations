-- request-callout :: callouts[].response.by_lua  (callout name: airs_scan)
--
-- Runs AFTER the callout response is received. Note what this is and is not:
-- it is the response of the callout to PRISMA AIRS. It is NOT the response of
-- the upstream MCP server -- request-callout has no hook that sees that, which
-- is why tool-catalogue poisoning is out of reach here (docs/DESIGN.md).
--
-- Its only job is to reduce the AIRS ScanResponse to one small, safe record so
-- that upstream.by_lua can make the enforcement decision without ever touching
-- a field that might be nil. Kong turns a nil reference in by_lua into a 500 on
-- live traffic, so the parsing risk is concentrated here, inside a pcall, and
-- the enforcement hook downstream reads only booleans and strings.

local ok, err = pcall(function()
    local shared = kong.ctx.shared
    local co = shared.callouts and shared.callouts.airs_scan
    local resp = co and co.response or nil

    -- With request.body.decode and response.body.decode set, the body arrives
    -- parsed. The string fallback is kept for the same reason the guardrail
    -- keeps its own: a runtime that hands back a string must not fail every
    -- request closed.
    local body = resp and resp.body or nil
    if type(body) == "string" then
        body = require("cjson.safe").decode(body)
    end

    local function is_set(v) return v ~= nil and v ~= false end

    -- `unavailable` is a FIELD rather than something upstream.by_lua infers by
    -- matching `reason` against a list of strings. It was a string match, and it
    -- was wrong: `reason` could be "scan error" -- AIRS reporting that its own
    -- scan failed -- which was not in the list, so the client was told
    -- -32001 "Blocked by Prisma AIRS" when nothing had judged the content. Any
    -- new degradation branch added below would have reintroduced the same bug.
    -- Set the flag next to the reason and the two cannot drift apart.
    local verdict = { block = true, reason = "verdict unavailable",
                      unavailable = true, scan_id = nil }

    if type(body) ~= "table" or type(body.action) ~= "string" then
        shared.airs_verdict = verdict
        return
    end

    verdict.scan_id = body.scan_id and tostring(body.scan_id) or nil

    -- A detector that failed or timed out did not say the content is safe; it
    -- said it could not finish looking. AIRS reports that alongside
    -- action="allow", so an integration that reads only `action` treats a
    -- half-finished scan as a clean pass.
    if is_set(body.error) or is_set(body.timeout) then
        verdict.reason = "partial scan failure"
        verdict.unavailable = true
        shared.airs_verdict = verdict
        return
    end
    if type(body.errors) == "table" and next(body.errors) ~= nil then
        verdict.reason = "detector degraded"
        verdict.unavailable = true
        shared.airs_verdict = verdict
        return
    end
    if body.category == "error" or body.category == "timeout" then
        verdict.reason = "scan " .. tostring(body.category)
        verdict.unavailable = true
        shared.airs_verdict = verdict
        return
    end

    if body.action == "allow" then
        verdict.block = false
        verdict.reason = "allow"
        verdict.unavailable = false
        shared.airs_verdict = verdict
        return
    end

    -- Blocked, or an action this integration does not recognise. Detector names
    -- go to the gateway log only, never to the MCP client: naming the detection
    -- to the caller turns the denial into a detector-mapping oracle.
    local hits = {}
    for _, key in ipairs({ "prompt_detected", "response_detected", "tool_detected" }) do
        local bag = body[key]
        if type(bag) == "table" then
            for name, fired in pairs(bag) do
                if fired == true then hits[#hits + 1] = tostring(name) end
            end
        end
    end
    table.sort(hits)
    -- A real policy decision, or an action this integration does not recognise.
    -- Either way the scanner answered, so this is not an availability failure.
    verdict.unavailable = false
    verdict.reason = (body.action == "block") and tostring(body.category or "unknown")
                     or "unrecognised action"
    if #hits > 0 then
        kong.log.warn("[prisma-airs-mcp] blocked: ", verdict.reason, " [", table.concat(hits, ","), "]")
    end
    shared.airs_verdict = verdict
end)

if not ok then
    kong.ctx.shared.airs_verdict = { block = true, reason = "verdict parse failure",
                                     unavailable = true }
    kong.log.err("[prisma-airs-mcp] response.by_lua failed: ", tostring(err))
end

-- ai-custom-guardrail function: verdict
--
-- Turns an AIRS ScanResponse into Kong's block decision. This is the only place
-- in the integration where traffic is allowed to continue, so every path that
-- does not end in a positive, unambiguous "allow" ends in a block.
--
-- WHAT THE CLIENT SEES. "Blocked by Prisma AIRS", optionally with the scan_id,
-- and nothing else -- never the category, never a detector name, and the same
-- text on a fail-closed block as on a real detection. Naming the detection to
-- the caller is an evasion oracle: it turns the block response itself into a
-- probe for mapping which inputs trip which detector. The detail is not lost --
-- it goes to `detail`, which the policy wires to metrics.block_detail, and the
-- full record is in the SCM scan log, correlated by scan_id.

return function(resp)
    -- Kong's plugin overview says $(resp) is a table while inspecting the
    -- request and a string while inspecting the response. Measured on AI Gateway
    -- 2.0.3 it is a table in BOTH phases. This branch is therefore inactive
    -- today and is kept deliberately: `require` and `cjson.safe` were verified
    -- to work inside a guardrail function, and a Kong release that ever did pass
    -- a string would, without this, fail every single request closed.
    if type(resp) == "string" then
        local ok, decoded = pcall(function()
            return require("cjson.safe").decode(resp)
        end)
        resp = ok and decoded or nil
    end

    -- No parseable verdict means no decision can be trusted.
    if type(resp) ~= "table" or type(resp.action) ~= "string" then
        return { block = true,
                 block_message = "Blocked by Prisma AIRS",
                 detail = "verdict unavailable (fail-closed)" }
    end

    local msg = "Blocked by Prisma AIRS"
    if resp.scan_id ~= nil then
        msg = msg .. " [scan_id=" .. tostring(resp.scan_id) .. "]"
    end

    -- PARTIAL SCAN FAILURE. This is the branch that distinguishes this verdict
    -- function, and it is a security fix rather than a tidy-up.
    --
    -- The AIRS ScanResponse carries `error` and `timeout` as first-class fields
    -- on every 200 body, plus an `errors[]` array naming which detector
    -- degraded ({content_type, feature, status}). A detector can fail or time
    -- out while the overall verdict still comes back `action: "allow"` -- the
    -- scan did not say the content is safe, it said it could not finish
    -- looking. A verdict function that keys only on `action`, or only on
    -- `category`, treats that as a clean pass.
    --
    -- `false` is clean; anything else present is degradation. The loose test is
    -- deliberate, because a field that arrives as a string rather than a boolean
    -- must not read as "no problem".
    local function is_set(v) return v ~= nil and v ~= false end

    if is_set(resp.error) or is_set(resp.timeout) then
        return { block = true, block_message = msg,
                 detail = "partial scan failure (fail-closed)" }
    end
    if type(resp.errors) == "table" and next(resp.errors) ~= nil then
        local which = {}
        for _, e in ipairs(resp.errors) do
            if type(e) == "table" then
                which[#which + 1] = tostring(e.feature or "?") .. "/" .. tostring(e.status or "?")
            end
        end
        table.sort(which)
        local d = "detector degraded (fail-closed)"
        if #which > 0 then d = d .. ": " .. table.concat(which, ", ") end
        return { block = true, block_message = msg, detail = d }
    end

    -- Kept for the same reason as the string branch above: cheap, and it costs
    -- nothing to also refuse a response that reports its degradation the older
    -- way. `category` is documented as the content classification, so this is
    -- belt-and-braces rather than the primary check.
    if resp.category == "error" or resp.category == "timeout" then
        return { block = true, block_message = msg,
                 detail = "scan " .. resp.category .. " (fail-closed)" }
    end

    -- THE ONLY PASS. An exact, lower-case "allow". A differently-cased or
    -- unrecognised action falls through to the block below rather than being
    -- normalised: if AIRS starts speaking a dialect this function does not know,
    -- the safe reading of the unknown word is "not a pass".
    --
    -- Note what is deliberately NOT checked here: `category`. An AIRS profile in
    -- alert-only mode returns action "allow" alongside a category of
    -- "malicious", and that combination is the profile owner exercising a
    -- choice. The gateway enforces the verdict AIRS returns; it does not
    -- second-guess the profile.
    if resp.action == "allow" then
        return { block = false, block_message = "", detail = "" }
    end

    -- Blocked. Collect what fired, for telemetry only.
    local hits = {}
    for _, key in ipairs({ "prompt_detected", "response_detected", "tool_detected" }) do
        local bag = resp[key]
        if type(bag) == "table" then
            -- pairs, not ipairs: these are name->boolean maps. Unknown keys are
            -- collected rather than filtered against a list of detectors we know
            -- about -- the generated SDK already carries detectors the published
            -- spec does not, and a detector we have never heard of firing is
            -- exactly the thing an operator needs to see.
            for name, fired in pairs(bag) do
                if fired == true then hits[#hits + 1] = tostring(name) end
            end
        end
    end
    table.sort(hits)

    local detail
    if resp.action == "block" then
        detail = tostring(resp.category or "unknown")
    else
        detail = "unrecognised action (fail-closed)"
    end
    if #hits > 0 then detail = detail .. ": " .. table.concat(hits, ", ") end

    return { block = true, block_message = msg, detail = detail }
end

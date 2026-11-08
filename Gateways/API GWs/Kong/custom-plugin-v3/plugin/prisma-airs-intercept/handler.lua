-- kong/plugins/prisma-airs-intercept/handler.lua
-- Patched version: Bedrock Converse format + MCP tool_event support
--                  + buffered SSE (text/event-stream) response scanning

local http = require("resty.http")
local cjson = require("cjson")

-- Priority 890 sits below the plugins whose job is to REJECT traffic and above
-- the one whose job is to REWRITE it. Anything above `acl` (950),
-- `rate-limiting` (910) or `response-ratelimiting` (900) calls -- and is billed
-- for -- AIRS on every request those plugins are about to reject, so the AIRS
-- request count tracks raw ingress rather than admitted traffic and an
-- unauthenticated flood drives the bill.
--
-- What 890 buys, and what has to be preserved:
--   jwt 1450 / openid-connect 1050 / key-auth 1250  -> still ahead of us, so a
--       claim is signature-verified before resolve_profile reads it.
--   acl 950, rate-limiting 910, response-ratelimiting 900 -> ahead of us,
--       so rejected traffic never reaches AIRS.
--   ai-proxy 770 -> still behind us, so we see the caller's raw provider body
--       rather than ai-proxy's OpenAI-normalised rewrite. That is the whole
--       reason this lineage exists.
--
-- VERSION is plain SemVer with no customer or deployment name in it: it is
-- published through plugin metadata and the Admin API /plugins response, so
-- anything embedded here leaks. It also has to stay numerically ahead of the
-- v1 lineage's 0.3.0, or an inventory sorted by VERSION ranks the two lineages
-- upside down.
local SecurePrismaAIRSHandler = {
    PRIORITY = 890,
    VERSION = "0.4.0",
}

-- The PDK exposes alert/crit/err/warn/notice/info/debug and nothing else.
-- `kong.log.error` does not exist, and because the call below is wrapped in a
-- pcall a nil level would fail SILENTLY -- losing every block log line rather
-- than raising. Use `err`, which is valid on every Kong version.
-- Kong's convention splits plugin-author levels (debug/info/notice)
-- from platform-operator levels (warn/err/crit). A policy block is the guardrail
-- WORKING -- expected traffic on a healthy system -- and emitting it at `err`
-- means anyone alerting on Kong `err` gets paged by every blocked prompt, which
-- trains them to mute the signal that matters. The scanner being unreachable is
-- the operator's problem and stays at `err`.
-- `verdict` is what AIRS said, and only what AIRS said. Conditions AIRS never
-- saw -- an unreadable request body, a prompt no extractor recognised -- must
-- never pass the literal "blocked", or the log reads "Blocking. Verdict:
-- blocked" identically to a real policy block and an operator chasing a false
-- positive hunts a scan_id that was never issued. Those callers pass
-- "unscannable": fail-closed all the same, but honest about the fact that no
-- scan happened, and at `err` because a request the gateway cannot parse is the
-- operator's problem, not the guardrail working.
local function log_error(reason, verdict)
    pcall(function()
        local unscanned = (verdict == "unscannable") or (verdict == "oversize")
        local what = unscanned and "Refusing (nothing to scan)." or "Blocking."
        local line = "SecurePrismaAIRSHandler: " .. what .. " Verdict: " ..
            tostring(verdict) .. ", Reason: " .. tostring(reason)
        -- "oversize" is a fail-CLOSED for content we could not inspect -- a
        -- route whose upstream starts returning over-cap answers begins refusing
        -- every response, and the operator's `err` alert must fire for that. It
        -- used to land on notice with a genuine policy block.
        if verdict == "error" or unscanned then
            kong.log.err(line)      -- AIRS unreachable / unusable: operator signal
        else
            kong.log.notice(line)   -- AIRS returned a verdict and we applied it
        end
    end)
end

-- Tracing is never unconditional: an operator who wants the plugin quiet needs
-- a way to get there. All tracing is behind config.debug, and prompt CONTENT is
-- behind a second switch below.
-- This emits at `notice`, not `info`: Kong's default log level is `notice`, so
-- at `info` a bare `debug = true` produces NOTHING unless the operator also sets
-- the undocumented KONG_LOG_LEVEL=info. The operator explicitly asked for this
-- output; emit it where they will actually see it.
local function log_debug(config, msg)
    if not (config and config.debug) then return end
    pcall(function()
        kong.log.notice("SecurePrismaAIRSHandler: " .. tostring(msg))
    end)
end

-- Prompt bytes must never reach the Kong log on `debug` alone. Prompts are
-- unstructured PII reservoirs and an enabled AI PII Sanitizer does not redact
-- Kong's own logs. Content needs a SECOND, default-off switch on top of debug;
-- nothing else in this file interpolates prompt or response bytes into a log
-- line.
-- The scan payload contains the prompt, so writing it to the Kong log is a
-- data-handling decision -- where those logs ship, who can read them, what
-- retention applies -- and must not ride along on a flag named `debug`. It gets
-- its own switch, and that switch defaults to off.
local function log_payload(config, msg)
    if not (config and config.debug and config.debug_log_payloads) then return end
    pcall(function()
        kong.log.notice("SecurePrismaAIRSHandler: " .. tostring(msg))
    end)
end

-- ============================================================================
-- Dynamic AIRS profile selection from a signed JWT claim
--   Choose the AIRS security profile per request from a claim in the caller's
--   ALREADY-VALIDATED bearer token, so one shared gateway applies app-specific
--   guardrails without a gateway per app. This plugin runs at PRIORITY 890,
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
    -- Bounded mode is mandatory: either a map, or an explicit allowlist of
    -- acceptable names. Returning the claim value verbatim would make whatever
    -- string is in the token BECOME the AIRS profile name -- the token holder
    -- picking their own security profile. This decoder verifies no signature,
    -- alg, exp, iss or aud by design (an auth plugin at higher priority is
    -- supposed to have done that), so on a route with no auth plugin a
    -- self-minted unsigned JWT would otherwise select the profile.
    local allow = config.profile_claim_allow
    if type(allow) == "table" and #allow > 0 then
        local permitted = {}
        for _, v in ipairs(allow) do permitted[tostring(v)] = true end
        for _, cv in ipairs(candidates) do
            if permitted[cv] then return cv, "claim-allow:" .. cv end
        end
        return fallback, "fallback:not-allowlisted:" .. candidates[1]
    end

    -- Neither a map nor an allowlist. The schema's entity_checks reject this at
    -- write time, so it can only be reached by a config row written before this
    -- version -- which an in-place plugin upgrade does NOT re-validate. Loud,
    -- because the operator's claim is silently doing nothing.
    pcall(function()
        kong.log.warn("SecurePrismaAIRSHandler: profile_claim is set with neither " ..
                      "profile_claim_map nor profile_claim_allow; refusing unbounded " ..
                      "direct mode and using the fallback profile.")
    end)
    return fallback, "fallback:unbounded-direct-mode:" .. candidates[1]
end

-- Request-scoped: resolve once, memoize across access/response phases, log the
-- choice, and stamp an audit header.
--
-- request_body, is_mcp, mcp_bypassed, the RPC id, the evidence record and the
-- session id are per-instance state and live in kong.ctx.plugin. kong.ctx.shared
-- is visible AND writable to every plugin on the request, so keeping them there
-- lets two instances of this plugin on one route clobber each other -- the
-- profile silently scanning with the OTHER instance's resolved value. The
-- resolved profile name is the one value another plugin has a legitimate reason
-- to read, so it stays shared, under a prefix that cannot collide with anyone
-- else's `airs_profile_name`.
local function resolve_profile_name(config)
    local cached = kong.ctx.shared.prisma_airs_profile_name
    if cached then return cached end
    local name, source = resolve_profile(config, kong.request.get_header("authorization"))
    kong.ctx.shared.prisma_airs_profile_name = name
    log_debug(config, "Resolved AIRS profile: " .. tostring(name) .. " (" .. source .. ")")
    pcall(function() kong.service.request.set_header("X-AIRS-Profile-Used", name) end)
    return name
end

-- A profile bound by NAME only turns an SCM-side rename into an AIRS non-200 ->
-- verdict `error` -> 503 on every request on the route, indistinguishable at the
-- client from an outage. An id survives a rename, so one is accepted here.
--
-- A per-request claim always wins: it names a specific profile for this caller,
-- where a configured id is the route-wide default. Sending both would be
-- ambiguous if they ever disagreed, so exactly one is sent.
local function resolve_ai_profile(config)
    if config.profile_claim and config.profile_claim ~= "" then
        return { profile_name = resolve_profile_name(config) }
    end
    if type(config.profile_id) == "string" and config.profile_id ~= "" then
        pcall(function() kong.service.request.set_header("X-AIRS-Profile-Used", config.profile_id) end)
        return { profile_id = config.profile_id }
    end
    return { profile_name = resolve_profile_name(config) }
end


-- ============================================================================
-- Correlation and identity
--
-- Measured on the wire, 8/8: the AIRS transaction slot is filled ONLY by a
-- request `transaction_id`; `tr_id` is a legacy alias that lands in the SESSION
-- slot. Sending a per-request value as tr_id therefore makes every turn its own
-- singleton conversation AND leaves transaction_id server-minted -- wrong for
-- both slots. We send transaction_id (unique per turn) + session_id (stable per
-- conversation) and no tr_id at all.
-- ============================================================================

local ID_CAP = 100  -- AIRS rejects longer correlation values with a non-200

local function clamp_id(v)
    if type(v) ~= "string" or v == "" then return nil end
    if #v > ID_CAP then return string.sub(v, 1, ID_CAP) end
    return v
end

-- The trusted PDK id, never a client-supplied header. A CLIENT-supplied
-- `Kong-Request-ID` is unvalidated and unbounded: it lets a caller pin, merge or
-- split SCM sessions, or exceed the 100-char cap and 403 its own route with one
-- header. Kong's own header is X-Kong-Request-Id, so such a chain is dead for
-- legitimate traffic and live only for attackers.
local function airs_transaction_id()
    local ok, id = pcall(kong.request.get_id)
    if ok then
        local c = clamp_id(id)
        if c then return c end
    end
    return clamp_id(ngx.var and ngx.var.request_id) or "unknown"
end

-- Stable across a conversation, identical on both legs. A client header is
-- legitimate here -- a session id is the caller's to assert -- but it is
-- length-capped and never reused as the transaction id. Returns nil when nothing
-- identifies the conversation: inventing a per-request value here would put a
-- per-turn value in the session slot, which is what this split exists to
-- prevent.
local function airs_session_id(config)
    local cached = kong.ctx.plugin.airs_session_id
    if cached ~= nil then
        if cached == false then return nil end
        return cached
    end

    local v = clamp_id(kong.request.get_header("mcp-session-id"))
    if not v and config.session_id_header and config.session_id_header ~= "" then
        v = clamp_id(kong.request.get_header(config.session_id_header))
    end
    if not v and config.session_id_claim and config.session_id_claim ~= "" then
        local claim = get_claim(kong.request.get_header("authorization"), config.session_id_claim)
        if claim ~= nil and type(claim) ~= "table" then v = clamp_id(tostring(claim)) end
    end
    if not v then
        local ok, consumer = pcall(kong.client.get_consumer)
        if ok and type(consumer) == "table" then v = clamp_id(consumer.id or consumer.username) end
    end

    kong.ctx.plugin.airs_session_id = v or false
    return v
end

-- app_user has to resolve to a real caller. A Kong SERVICE name on the LLM path,
-- or a hardcoded string on every tool event, makes every AI incident resolve to
-- a synthetic account downstream.
local function airs_app_user(config)
    local ok, consumer = pcall(kong.client.get_consumer)
    if ok and type(consumer) == "table" then
        local u = clamp_id(consumer.username or consumer.id)
        if u then return u end
    end
    if config.user_claim and config.user_claim ~= "" then
        local claim = get_claim(kong.request.get_header("authorization"), config.user_claim)
        if claim ~= nil and type(claim) ~= "table" then
            local u = clamp_id(tostring(claim))
            if u then return u end
        end
    end
    if config.user_header and config.user_header ~= "" then
        local u = clamp_id(kong.request.get_header(config.user_header))
        if u then return u end
    end
    return "anonymous"
end

local function airs_user_ip()
    local ok, ip = pcall(kong.client.get_forwarded_ip)
    if ok and type(ip) == "string" then return ip end
    return nil
end

-- Never invent a model name. A hardcoded default makes several doors running
-- different model families all report one string, which hides a false-positive
-- pattern belonging to a single family; "unknown" is the honest answer when the
-- id is not in the request. For Bedrock the real id is in the request PATH
-- (/model/<id>/converse), not the Converse body.
local function airs_ai_model(request_body)
    if type(request_body) == "table" and type(request_body.model) == "string"
        and request_body.model ~= "" then
        return request_body.model
    end
    local ok, path = pcall(kong.request.get_path)
    if ok and type(path) == "string" then
        local m = path:match("/model/([^/]+)/")
        if m then return (m:gsub("%%3A", ":")) end
    end
    return "unknown"
end


-- ============================================================================
-- Evidence
--
-- Without a log phase, a span or a counter, nothing about a security decision
-- reaches http-log, Datadog, OTel or the customer's SIEM, and scan latency
-- exists nowhere -- leaving "how much did the scan add" to be answered by
-- hand-clustering wall-clock timings.
-- One record per request, published to Kong's log serializer under `airs`.
-- ============================================================================

local function evidence()
    local e = kong.ctx.plugin.airs_evidence
    if not e then
        e = { scans = {} }
        kong.ctx.plugin.airs_evidence = e
    end
    return e
end

-- With only an api_endpoint defaulting to the US host, an EU or APAC tenant has
-- to know the right URL and type it correctly -- and a wrong-but-well-formed
-- host passes the schema's `match` and then fail-closes 100% of traffic, which
-- at the operator's end is indistinguishable from an AIRS outage. `region` names
-- the choice instead of spelling it. An explicitly configured api_endpoint still
-- wins: a tenant on a private link or a preview host must not be overridden by a
-- convenience field.
local AIRS_REGIONAL_HOSTS = {
    us   = "https://service.api.aisecurity.paloaltonetworks.com",
    eu   = "https://service-de.api.aisecurity.paloaltonetworks.com",
    apac = "https://service-sg.api.aisecurity.paloaltonetworks.com",
}
local AIRS_DEFAULT_ENDPOINT = AIRS_REGIONAL_HOSTS.us .. "/v1/scan/sync/request"

local function airs_endpoint(config)
    local configured = config and config.api_endpoint
    local region = config and config.region
    -- Only substitute when the operator left api_endpoint at the shipped
    -- default; anything they typed themselves is deliberate.
    if region and AIRS_REGIONAL_HOSTS[region]
       and (configured == nil or configured == AIRS_DEFAULT_ENDPOINT) then
        return AIRS_REGIONAL_HOSTS[region] .. "/v1/scan/sync/request"
    end
    return configured
end

-- A fail-open that only narrates itself in a log MESSAGE cannot be
-- rate-alerted on -- an operator cannot tell a route that fails open twice a
-- week from one doing it on every request without parsing prose. Gaps go on the
-- structured record as a countable list, next to the scans.
--
-- Each entry names WHICH gap, so "the response body was unreadable" and "AIRS
-- was down and we were told to allow" stay distinguishable in aggregate.
local function record_gap(kind, detail)
    local e = evidence()
    e.gaps = e.gaps or {}
    e.gaps[#e.gaps + 1] = { kind = kind, detail = detail }
    pcall(kong.log.set_serialize_value, "airs", e)
end

-- The model is computed for the AIRS envelope on every request and is recorded
-- rather than discarded: it is the one field that lets an operator answer "which
-- model was this traffic going to". Recorded once per request, at the point it
-- is first known.
local function record_model(model)
    if type(model) ~= "string" or model == "" then return end
    local e = evidence()
    if e.ai_model then return end
    e.ai_model = model
    pcall(kong.log.set_serialize_value, "airs", e)
end

-- "" is truthy in Lua, so a bare
-- `config.app_name and ("kong-" .. config.app_name)` would send the literal
-- "kong-" to AIRS for an empty app_name. The schema rejects "" at config time;
-- the explicit test here catches configs stored before it did, which schema
-- validation never revisits.
local function airs_app_name(config)
    local n = config and config.app_name
    if type(n) ~= "string" or n == "" then return "kong" end
    return "kong-" .. n
end

-- Which detectors actually fired. The per-detector booleans have to be kept and
-- not decoded-then-dropped, or a block names no detector at all -- `category` is
-- an umbrella verdict (benign|malicious), not a detector name.
local function fired_detectors(body)
    local out = {}
    if type(body) ~= "table" then return out end
    for _, group in ipairs({ "prompt_detected", "response_detected", "tool_detected" }) do
        local g = body[group]
        if type(g) == "table" then
            for name, hit in pairs(g) do
                if hit == true then out[#out + 1] = name end
            end
        end
    end
    table.sort(out)
    return out
end

-- Without an observe-only mode an operator who hits a false positive mid-rollout
-- has exactly two options -- keep blocking legitimate traffic, or delete the
-- plugin. Neither is a rollout plan. `monitor` scans, records and reports
-- everything, and changes nothing about what the client receives. It
-- deliberately also neutralises the fail-closed paths: a mode that still 503s
-- when AIRS is slow is not observe-only and cannot be safely enabled on
-- production traffic.
local function enforcing(config)
    return (config.enforcement_mode or "enforce") ~= "monitor"
end

-- Marks on the wire that a verdict was seen and deliberately not acted on. Only
-- emitted on the requests where that actually happened, so ordinary traffic
-- gives away nothing about the route's posture.
local function mark_unenforced()
    pcall(kong.response.set_header, "x-prisma-airs-enforcement", "monitor")
end

-- How a verdict reads in the evidence record.
local function scan_outcome(verdict)
    if verdict == "error" then return "fail_closed" end
    if verdict == "oversize" then return "unscannable" end
    return "verdict"
end

-- Every leg calls record_scan BEFORE deny/deny_mcp, and record_scan sets
-- `enforced = (action == "allow") or enforcing(config)` -- true on any route in
-- the default enforce mode. With on_api_error = "allow" and AIRS timing out,
-- that entry would reach the SIEM as outcome = "fail_closed", enforced = true
-- for a request forwarded to the model with no scan at all, and an auditor
-- counting enforced=true over an outage window would read 100% coverage. The
-- entry is amended here whenever the request is actually let through, so the log
-- can never be read as a false claim of protection.
local function note_failed_open(detail)
    local e = evidence()
    local last = e.scans[#e.scans]
    if last then
        last.outcome = "failed_open"
        last.enforced = false
        last.detail = detail or last.detail
        pcall(kong.log.set_serialize_value, "airs", e)
    end
end

-- Cache hits get their own counter. They are not gaps -- the content WAS
-- scanned, by an earlier request -- and putting them in the gaps list makes the
-- one fail-open signal that list delivers unusable on any route with the cache
-- enabled.
-- Flagged here and consumed by the NEXT record_scan, because send_scan runs
-- before the leg's record_scan: stamping "the most recent entry" would mark the
-- PREVIOUS leg as cached.
local function note_cache_hit()
    kong.ctx.plugin.airs_cache_hit = true
end

-- Stamp the most recent scan record as having produced a body rewrite. A
-- mutated payload that leaves no trace is indistinguishable from a bug.
local function note_masked()
    local e = evidence()
    local last = e.scans[#e.scans]
    if last then
        last.masked = true
        pcall(kong.log.set_serialize_value, "airs", e)
    end
end

local function record_scan(config, leg, action, outcome, airs_body, latency_ms, detail)
    local e = evidence()
    if not e.transaction_id then
        e.transaction_id = airs_transaction_id()
        e.session_id = airs_session_id(config)
    end
    if not enforcing(config) then e.enforcement_mode = "monitor" end
    e.scans[#e.scans + 1] = {
        leg = leg,
        action = action,
        outcome = outcome,               -- "verdict" | "fail_closed"
        -- Whether this verdict changed what the client got. In monitor mode a
        -- block is still recorded truthfully as a block; `enforced` is what says
        -- nothing was stopped, so the log can never be read as a false claim of
        -- protection.
        enforced = (action == "allow") or enforcing(config),
        scan_id   = type(airs_body) == "table" and airs_body.scan_id or nil,
        report_id = type(airs_body) == "table" and airs_body.report_id or nil,
        category  = type(airs_body) == "table" and airs_body.category or nil,
        detectors = fired_detectors(airs_body),
        latency_ms = latency_ms,
        detail = detail,
        -- A replayed verdict must never be indistinguishable from a
        -- scan of this request. `cached_from` keeps the pivot to the scan that
        -- really happened, without claiming it was this one.
        cached = kong.ctx.plugin.airs_cache_hit or nil,
        cached_from = type(airs_body) == "table" and airs_body.prisma_airs_cached_from or nil,
    }
    if kong.ctx.plugin.airs_cache_hit then
        e.cache_hits = (e.cache_hits or 0) + 1
        kong.ctx.plugin.airs_cache_hit = nil
    end
    pcall(kong.log.set_serialize_value, "airs", e)
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
-- "There is nothing to scan" and "we could not read it" are different facts.
-- Conflating them lets an unreadable body forward unscanned with only a warn.
-- Returns (body, nil) or (nil, "empty"|"unreadable").
local function get_buffered_body()
    local ok, b = pcall(kong.response.get_raw_body)
    if ok and b and b ~= "" then return b end
    local ok2, b2 = pcall(kong.service.response.get_raw_body)
    if ok2 and b2 and b2 ~= "" then return b2 end
    -- Both calls returned cleanly with nothing: a genuine 204/202/empty body.
    -- Either call erroring means we were unable to look, which is a gap.
    if ok and ok2 then return nil, "empty" end
    return nil, "unreadable"
end

-- A single place to decide what happens when the plugin
-- could not inspect something it was supposed to inspect. Fails CLOSED; an
-- operator may opt into forwarding, but only explicitly and in config.
-- Always logged at `err`, never `warn` -- warn is where routine keepalive noise
-- lives and nobody alerts on it.
local function scan_gap(config, detail)
    kong.log.err("SecurePrismaAIRSHandler: scan gap - " .. tostring(detail))
    -- Also on the structured record, so the rate is queryable.
    record_gap("scan_gap", detail)
    if not enforcing(config) then mark_unenforced(); return false end
    return (config.on_scan_error or "block") ~= "allow"
end

-- An MCP server issues Mcp-Session-Id on the initialize RESPONSE, so the access
-- leg legitimately has nothing to read. Adopt it before the response scan, and
-- the very first exchange of a conversation is correlated instead of being the
-- one turn that never joins its session.
local function adopt_mcp_session_from_response(config)
    if kong.ctx.plugin.airs_session_id then return end
    local ok, sid = pcall(kong.response.get_header, "Mcp-Session-Id")
    if not ok or type(sid) ~= "string" or sid == "" then return end
    local clamped = clamp_id(sid)
    if not clamped then return end
    kong.ctx.plugin.airs_session_id = clamped
    local e = evidence()
    e.session_id = clamped
    pcall(kong.log.set_serialize_value, "airs", e)
    log_debug(config, "Adopted Mcp-Session-Id issued by the server: " .. clamped)
end

-- kong.response.exit REPLACES the response, discarding an
-- Mcp-Session-Id the server issued on this very exchange. A client that never
-- learns its session id cannot make a second call -- the block would read as a
-- dead session rather than one refused tool.
local function mcp_exit_headers()
    local ok, sid = pcall(kong.response.get_header, "Mcp-Session-Id")
    if ok and type(sid) == "string" and sid ~= "" then
        return { ["Mcp-Session-Id"] = sid }
    end
    return nil
end

-- kong.request.get_body() is called WITH a max_allowed_file_size. Above Kong's
-- default client_body_buffer_size (8 KB) nginx spills the body to a temp file
-- and the PDK refuses to read it -- so without one, ordinary RAG context, a
-- large tool schema or a long multi-turn conversation earns a flat 400 reading
-- "Invalid or unreadable request body", which points nowhere near the cause.
-- 8 MB is a deliberate default: comfortably above real LLM traffic, far below
-- anything that would let one request exhaust a worker.
local MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024

-- Returns (body, nil, nil) | (nil, err, true) when the body was too large to
-- read | (nil, err, false) when it was genuinely malformed.
local function read_request_body(config)
    local max = tonumber(config.max_request_body_bytes) or MAX_REQUEST_BODY_BYTES
    local body, err = kong.request.get_body(nil, nil, max)
    if body then return body end
    local lower = string.lower(tostring(err or ""))
    local oversize = string.find(lower, "buffer", 1, true) ~= nil
                  or string.find(lower, "did not fit", 1, true) ~= nil
                  or string.find(lower, "too large", 1, true) ~= nil
    return nil, err or "empty body", oversize
end

-- Pure: parse a buffered SSE body into an ordered list of `data:` payload strings.
-- Handles LF and CRLF; preserves empty `data:` lines inside a multi-line event;
-- skips an event only when its joined payload is empty; ignores `[DONE]`.
-- A single regex over one envelope shape (^event:%s*message%s*data:%s*(.+))
-- mishandles a multi-line data: payload, a named event other than `message`, and
-- an SSE comment (: keep-alive). This is a line-oriented parser instead: data:
-- lines accumulate and join, blank lines flush, and event:/id:/retry:/comment
-- lines are ignored rather than filtered on -- collecting more and deciding
-- later is the safe direction.
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

-- An OpenAI tool call carries its payload in `function.name` and
-- `function.arguments`, and NEITHER is message content. The arguments are the
-- model's own choice of where to send money, which file to read, which URL to
-- fetch -- so a reply that carries a tool call and no prose is not an empty
-- reply, it is the interesting one. Both the streamed and the buffered path
-- fold through here so the two legs cannot drift apart again: they did, and the
-- buffered leg was the one that scanned nothing.
local function fold_tool_calls(out, tool_calls)
    if type(tool_calls) ~= "table" then return end
    for _, tc in ipairs(tool_calls) do
        if type(tc) == "table" then
            local fn = tc["function"]
            if type(fn) == "table" then
                if type(fn.name) == "string" then out[#out + 1] = fn.name end
                if type(fn.arguments) == "string" then out[#out + 1] = fn.arguments end
            end
        end
    end
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
                    fold_tool_calls(out, delta.tool_calls)
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
            -- thinking_delta is scanned like any other output. Extended-thinking
            -- text is model output and is exactly where leakage surfaces, so
            -- skipping it leaves that surface uninspected.
            if dt.type == "thinking_delta" and type(dt.thinking) == "string" then
                out[#out + 1] = dt.thinking
            elseif dt.type == "text_delta" and type(dt.text) == "string" then
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
-- sse_provider="raw" means "a provider we have no extractor for", NOT "send the
-- wire format". A table.concat over the UNDECODED frames puts every brace,
-- quote, key name and enum value in front of AIRS as prose, and the detectors
-- then read scaffolding rather than content -- a measured false-positive class.
-- So harvest the string VALUES and leave the structure behind.
--
-- These keys carry structure even though their values are strings. Dropping them
-- costs nothing (nobody needs to scan the word "assistant") and removes the
-- noise that was firing detectors.
local STRUCTURAL_KEYS = {
    role = true, finish_reason = true, stop_reason = true, stop_sequence = true,
    type = true, object = true, id = true, model = true, index = true,
    ["content_type"] = true, ["mime_type"] = true, ["encoding"] = true,
}

local MAX_WALK_DEPTH = 24

-- Pure: collect the string values of a decoded JSON structure, in order.
-- Depth-bounded, because the shape is attacker-influenced and an unbounded
-- recursion here is a worker, not an error.
local function collect_strings(node, out, depth)
    out = out or {}
    depth = depth or 0
    if depth > MAX_WALK_DEPTH or type(node) ~= "table" then return out end
    for key, value in pairs(node) do
        if type(value) == "string" then
            if value ~= "" and not (type(key) == "string" and STRUCTURAL_KEYS[key]) then
                out[#out + 1] = value
            end
        elseif type(value) == "table" then
            collect_strings(value, out, depth + 1)
        end
    end
    return out
end

local function reconstruct_sse_text(raw, provider)
    provider = provider or "auto"
    local payloads = parse_sse(raw)
    if #payloads == 0 then return "" end

    if provider == "raw" then
        local out = {}
        for _, payload in ipairs(payloads) do
            local ok, decoded = pcall(cjson.decode, payload)
            if ok and type(decoded) == "table" then
                collect_strings(decoded, out)
            elseif ok and type(decoded) == "string" then
                out[#out + 1] = decoded
            elseif not ok then
                -- Not JSON at all: a genuinely plain-text stream. Pass it through.
                out[#out + 1] = payload
            end
        end
        return table.concat(out, "\n")
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

-- Which message roles get scanned is an operator decision. The
-- default stays user-only so nobody's false-positive rate moves under them, but
-- tool results and system prompts are documented injection carriers and that gap
-- must be closable without a code change.
local DEFAULT_SCAN_ROLES = { user = true }

local function scan_roles(config)
    local roles = config and config.scan_message_roles
    if type(roles) ~= "table" or #roles == 0 then return DEFAULT_SCAN_ROLES end
    local t = {}
    for _, r in ipairs(roles) do t[tostring(r)] = true end
    return t
end

-- Pull EVERY text fragment out of one message's `content`. Reading only
-- content[1].text drops content[2..n], leaving the second half of a multi-part
-- turn unscanned.
local function content_text(content)
    if type(content) == "string" then return content end
    if type(content) ~= "table" then return nil end
    local parts = {}
    for _, part in ipairs(content) do
        if type(part) == "string" then
            parts[#parts + 1] = part
        elseif type(part) == "table" and type(part.text) == "string" then
            parts[#parts + 1] = part.text
        end
    end
    if #parts > 0 then return table.concat(parts, " ") end
    -- Nothing text-shaped (an image-only turn): serialize so SOMETHING is seen.
    local ok, serialized = pcall(cjson.encode, content)
    return ok and serialized or nil
end

local function extract_prompt(request_body, config)
    if not request_body then return nil end
    local want = scan_roles(config)

    if type(request_body.messages) == "table" then
        -- The LAST user turn is the prompt under review, not the first. Every
        -- chat client resends the whole history, so returning on the first
        -- role=="user" match re-scans turn 1 forever and never inspects the
        -- message actually being sent -- on BOTH legs, since
        -- build_prompt_payload re-runs this for the response scan.
        local picked, last_user = {}, nil
        for _, message in ipairs(request_body.messages) do
            if type(message) == "table" and want[message.role] then
                local text = content_text(message.content)
                if text then
                    picked[#picked + 1] = { role = message.role, text = text }
                    if message.role == "user" then last_user = #picked end
                end
            end
        end
        local out = {}
        for k, e in ipairs(picked) do
            -- Earlier user turns are history, not the prompt under review.
            if e.role ~= "user" or k == last_user then out[#out + 1] = e.text end
        end
        if #out > 0 then return table.concat(out, "\n") end
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

    -- One remedy for unhandled provider shapes is to drop below ai-proxy (770)
    -- and let ITS normalisation run first. This lineage deliberately sits ABOVE
    -- it so it sees the caller's raw body rather than a rewrite -- which makes
    -- reading these shapes THIS plugin's job, not something to delegate. The post-proxy
    -- lineage at 760 remains the post-normalisation option for operators who
    -- prefer that trade.
    --
    -- Without these branches a Gemini or Cohere request reaches "no prompt
    -- found" and fail-closes to a 403: not a silent bypass, but an outage on
    -- traffic the plugin was installed to protect.

    -- Gemini / Vertex generateContent: contents[].parts[].text
    if type(request_body.contents) == "table" then
        local parts = {}
        for _, turn in ipairs(request_body.contents) do
            -- Gemini marks model turns role="model"; absent role means user.
            if type(turn) == "table" and (turn.role == nil or want[turn.role] or turn.role == "user") then
                if type(turn.parts) == "table" then
                    for _, part in ipairs(turn.parts) do
                        if type(part) == "table" and type(part.text) == "string" and part.text ~= "" then
                            parts[#parts + 1] = part.text
                        end
                    end
                elseif type(turn.text) == "string" and turn.text ~= "" then
                    parts[#parts + 1] = turn.text
                end
            end
        end
        if #parts > 0 then return table.concat(parts, "\n") end
    end

    -- Cohere v1 chat: a top-level `message` string (v2 uses `messages` and is
    -- already handled above). chat_history is prior turns, i.e. history.
    if type(request_body.message) == "string" and request_body.message ~= "" then
        return request_body.message
    end

    -- Anthropic Messages `system` alongside `messages` is handled by the
    -- messages branch; a bare top-level `prompt` is the legacy completions
    -- shape and still turns up on Mistral/Cohere generate endpoints.
    if type(request_body.prompt) == "string" and request_body.prompt ~= "" then
        return request_body.prompt
    end

    return nil
end

-- Returning true for ANY body with a truthy top-level `method` or `jsonrpc`
-- lets a client bolt "jsonrpc":"2.0","method":"tools/list" onto an ordinary chat
-- body and have the whole request forwarded to the LLM unscanned in both
-- directions. Real MCP traffic never carries `messages` / `input`; requiring
-- their absence closes that bypass without rejecting anything legitimate.
--
-- A JSON-RPC batch is a top-level ARRAY and is recognised as MCP here; left to
-- fall through to the LLM path it finds no prompt and 403s with an LLM-path
-- message.
-- JSON-RPC 2.0 requires BOTH a `jsonrpc` member equal to "2.0" and a string
-- `method`. Testing for either one alone classifies non-MCP traffic as MCP --
-- and a body classified as MCP has its prompt content read from `params`, so a
-- misclassified body is a body whose real content nobody scanned. Notifications
-- have no id; requests do. Neither changes this test.
local function is_jsonrpc_envelope(t)
    return type(t) == "table"
       and t.jsonrpc == "2.0"
       and type(t.method) == "string"
       and t.method ~= ""
end

-- Every shape extract_prompt can read has to disqualify a body from the MCP
-- path, or the guard below is decorative. Naming only `messages` and `input`
-- while extract_prompt reads FIVE top-level shapes makes
-- `{"jsonrpc":"2.0","method":"tools/list","prompt":"<injection>"}` a valid
-- envelope, classified as a catalogue method (no access-leg scan by design) and
-- forwarded with its prompt never inspected. This list stays in step with
-- extract_prompt.
local LLM_BODY_SHAPES = { "messages", "input", "contents", "message", "prompt" }

local function carries_llm_shape(t)
    for _, field in ipairs(LLM_BODY_SHAPES) do
        if t[field] ~= nil then return true end
    end
    return false
end

local function is_mcp_request(request_body)
    if type(request_body) ~= "table" then return false, nil end

    if carries_llm_shape(request_body) then
        return false, nil          -- LLM shape wins; MCP never carries these
    end

    -- `method` is client-controlled and need not be a string. It is
    -- concatenated into log lines and used as a table key downstream, so the
    -- type test here is what keeps an object there from raising instead of
    -- being classified.
    --
    -- A test of `jsonrpc ~= nil OR method ~= nil` claims any body carrying a
    -- `method` key -- a legacy RPC call, a webhook, half the payloads on the
    -- internet -- and gives it the MCP treatment: routed into the tool_event
    -- shape, its real content never scanned as a prompt. JSON-RPC 2.0 defines
    -- the envelope precisely, so require it: version exactly "2.0" AND a string
    -- method. Anything else is ordinary traffic and goes down the ordinary path,
    -- where its content IS inspected.
    if is_jsonrpc_envelope(request_body) then
        return true, request_body.method, false
    end

    -- Batch: a top-level ARRAY of envelopes.
    --
    -- A batch is never classified by `request_body[1]`'s method. That is an
    -- evasion primitive, not a classification:
    -- `[{"method":"ping"},{"method":"tools/call","params":{...}}]` would be a
    -- no-content control message, which sets mcp_bypassed and skips BOTH legs --
    -- a tool call executed with zero AIRS calls. The same read is wrong even
    -- when the batch IS scanned, because the tool_event builder reads
    -- `request_body.method`/`.params`, both nil on an array, so the batch would
    -- reach AIRS as method "unknown" with input "{}".
    --
    -- Every element must be a real envelope for this to be a batch at all; a
    -- mixed array is not valid JSON-RPC and goes down the ordinary path, where
    -- its content is inspected or it fails closed. Classification is then the
    -- caller's job, member by member -- there is no single method for a batch.
    if #request_body > 0 then
        for _, member in ipairs(request_body) do
            if not is_jsonrpc_envelope(member) then return false, nil end
            if carries_llm_shape(member) then return false, nil end
        end
        return true, nil, true
    end

    return false, nil
end

-- The members of a batch, or the single envelope as a one-element
-- list, so every caller iterates rather than reaching for scalar fields that do
-- not exist on an array.
local function mcp_members(request_body, is_batch)
    if not is_batch then return { request_body } end
    local out = {}
    for _, member in ipairs(request_body) do out[#out + 1] = member end
    return out
end

-- Two very different things, deliberately kept in separate tables rather than
-- one bypass list covering both legs for all of them.
--
--   NO_CONTENT  - nothing to scan in either direction. Genuinely free.
--   CATALOGUE   - the REQUEST carries nothing, but the RESPONSE is the tool
--                 catalogue: names, descriptions and JSON schemas supplied by
--                 the server and injected verbatim into model context. That is
--                 precisely the tool-poisoning payload, and it was explicitly
--                 excluded from inspection.
local MCP_NO_CONTENT = {
    ["initialized"] = true,
    ["ping"] = true,
    ["logging/setLevel"] = true,    -- a log-level knob carries no content
    ["notifications/initialized"] = true,
    ["notifications/progress"] = true,
    ["notifications/cancelled"] = true,
    ["notifications/roots/list_changed"] = true,
}

local MCP_CATALOGUE = {
    ["initialize"] = true,      -- serverInfo + instructions
    ["tools/list"] = true,
    ["resources/list"] = true,
    ["prompts/list"] = true,
    ["resources/templates/list"] = true,
    -- `roots/list` is server->client. The RESULT is supplied by the client and
    -- read by the server, so there is nothing caller-controlled to scan inbound
    -- and the reply is worth a look on the way past. That is why it sits here --
    -- NOT because the result is "server-supplied text that lands in model
    -- context", which has the direction backwards.
    ["roots/list"] = true,
}

-- `prompts/get` and `completion/complete` DO carry caller content inbound,
-- however much they resemble catalogue methods: `prompts/get` params carry
-- `arguments`, values the caller chooses that get interpolated into a server
-- prompt template, and `completion/complete` params carry `argument.value`,
-- which is literally what the user typed. Classifying either as catalogue
-- removes the ACCESS-leg scan and lets that text reach the MCP server
-- uninspected. They stay on the default path, which scans both legs. This table
-- exists so the classification cannot drift silently.
local MCP_CALLER_CONTENT_METHODS = {
    ["tools/call"] = true,
    ["resources/read"] = true,
    ["prompts/get"] = true,
    ["completion/complete"] = true,
}

-- These are server-initiated requests that ask OUR model to generate text, or
-- ask OUR user to supply it. They are prompts, not tool invocations: shipping
-- them as a tool_event with serialized params puts the text in a field the
-- prompt detectors do not read.
local MCP_PROMPT_LIKE = {
    ["sampling/createMessage"] = true,
    ["elicitation/create"] = true,
}

-- AIRS validates `tool_event.metadata.method` against its own allowlist, and
-- measured against a live tenant that allowlist is exactly these two. Every
-- other value is refused with `400 unsupported method: [<method>]`, which under
-- the default on_api_error=block becomes a 503 for a caller whose content was
-- never inspected -- and `initialize` is among the refused, so no MCP session
-- could be opened at all. Those methods still carry caller-chosen text that
-- reaches an MCP server and then a model, so they are scanned as a PROMPT
-- instead: the prompt path has no method allowlist. This table is the seam. If
-- AIRS widens the allowlist, adding the method here restores the richer
-- tool_event shape for it and nothing else has to change.
local MCP_TOOL_EVENT_METHODS = {
    ["tools/call"] = true,
    ["tools/list"] = true,
}

local function airs_accepts_tool_event(method)
    return MCP_TOOL_EVENT_METHODS[method] == true
end

-- The built-in tables are a snapshot of a moving specification, and a method
-- added after a release is scanned as though it were a tool call -- a false
-- positive an operator could otherwise only clear with a new build. This lets
-- them declare one in config, and it is ADDITIVE: it can make an unclassified
-- method bypass, and it can never demote a method this plugin already
-- classifies.
--
-- That last property is enforced HERE, by construction, rather than by naming
-- `tools/call` alone: is_mcp_no_content consults the operator list FIRST,
-- before catalogue and prompt-like classification, so a one-name refusal would
-- leave `mcp_control_methods_extra = {"tools/list"}` free to disable the
-- catalogue RESPONSE scan -- the tool-poisoning surface -- and
-- `{"sampling/createMessage"}` free to disable the prompt scan of a
-- server-initiated prompt on BOTH legs. The schema rejects these too; this is
-- the defence-in-depth half, for a config that reached the data plane some
-- other way.
local function is_reserved_mcp_method(method)
    return MCP_NO_CONTENT[method] == true
        or MCP_CATALOGUE[method] == true
        or MCP_PROMPT_LIKE[method] == true
        or MCP_CALLER_CONTENT_METHODS[method] == true
end

local function is_operator_control_method(config, method)
    local extra = config and config.mcp_control_methods_extra
    if type(extra) ~= "table" then return false end
    for _, m in ipairs(extra) do
        if m == method and not is_reserved_mcp_method(method) then return true end
    end
    return false
end

local function is_mcp_no_content(method, config)
    if type(method) ~= "string" then return false end
    if MCP_NO_CONTENT[method] == true then return true end
    if is_operator_control_method(config, method) then return true end
    -- Every `notifications/` method is covered by this prefix test, not by the
    -- handful named above: one off that list -- notifications/message,
    -- notifications/resources/updated, notifications/tools/list_changed --
    -- otherwise falls through to the scan path and produces a warn, because a
    -- notification is 202 with no body. All of them are fire-and-forget by
    -- definition.
    return string.sub(method, 1, 14) == "notifications/"
end

local function is_mcp_prompt_like(method)
    return MCP_PROMPT_LIKE[method] == true
end

-- Pull the model-facing text out of a server-initiated request.
-- Returns nil when there is none, which the caller treats as a scan gap rather
-- than a pass -- we claim to scan these methods.
local function mcp_prompt_text(method, params)
    if type(params) ~= "table" then return nil end
    -- Methods AIRS accepts as tool events are scanned as tool events, which
    -- carries their structure. Nothing should be pulling prompt text out of
    -- them, and returning some would mask a mis-route as a working scan.
    if airs_accepts_tool_event(method) then return nil end

    if method == "sampling/createMessage" then
        local parts = {}
        if type(params.systemPrompt) == "string" and params.systemPrompt ~= "" then
            parts[#parts + 1] = params.systemPrompt
        end
        if type(params.messages) == "table" then
            for _, m in ipairs(params.messages) do
                if type(m) == "table" then
                    local c = m.content
                    local text
                    if type(c) == "string" then
                        text = c
                    elseif type(c) == "table" then
                        -- MCP sends one content object, not an array of parts.
                        text = (type(c.text) == "string" and c.text) or content_text(c)
                    end
                    if text and text ~= "" then parts[#parts + 1] = text end
                end
            end
        end
        if #parts > 0 then return table.concat(parts, "\n") end
        return nil
    end

    if method == "elicitation/create" then
        local m = params.message
        if type(m) == "string" and m ~= "" then return m end
        return nil
    end

    -- The methods AIRS refuses as tool events. Each carries caller-chosen text,
    -- named here rather than serialised wholesale so the scan reads as what the
    -- caller actually asked for.
    if method == "resources/read" then
        local uri = params.uri
        if type(uri) == "string" and uri ~= "" then return uri end
        -- A non-string uri is caller-controlled malformation, not an absence of
        -- content. Fall through to the generic serialisation below rather than
        -- reporting a gap, so a malformed read is still inspected instead of
        -- being refused for being unreadable.
    end

    if method == "prompts/get" then
        -- `arguments` are the caller's values, interpolated into a server-side
        -- prompt template. The template is the server's; these are not.
        local parts = {}
        if type(params.name) == "string" and params.name ~= "" then
            parts[#parts + 1] = params.name
        end
        if type(params.arguments) == "table" then
            for k, v in pairs(params.arguments) do
                if type(v) == "string" and v ~= "" then
                    parts[#parts + 1] = tostring(k) .. ": " .. v
                end
            end
        end
        if #parts > 0 then return table.concat(parts, "\n") end
        -- fall through
    end

    if method == "completion/complete" then
        local a = params.argument
        if type(a) == "table" and type(a.value) == "string" and a.value ~= "" then
            return a.value
        end
        -- fall through
    end

    -- Anything else -- a vendor extension, or a method added by a later
    -- revision of the specification. The field names are not knowable in
    -- advance, so the whole params object is the scan text. Empty params carry
    -- nothing, and nil here is a scan gap rather than a pass.
    if next(params) ~= nil then
        local ok, encoded = pcall(cjson.encode, params)
        if ok and type(encoded) == "string" and encoded ~= "{}" then return encoded end
    end

    return nil
end

local function is_mcp_catalogue(method)
    return MCP_CATALOGUE[method] == true
end

-- Pick the frame answering OUR JSON-RPC id out of a buffered
-- reply, whether it is SSE-framed or a plain JSON body, and return its text.
-- Returns nil when nothing decodable answered us -- which is a gap, not a pass.
local function mcp_result_text(response_body, want_id)
    if type(response_body) ~= "string" or response_body == "" then return nil end
    local frames = parse_sse(response_body)
    if #frames == 0 then frames = { response_body } end

    local chosen
    for _, payload in ipairs(frames) do
        local ok, decoded = pcall(cjson.decode, payload)
        if ok and type(decoded) == "table" then
            if want_id ~= nil and decoded.id == want_id then
                chosen = decoded
                break
            elseif decoded.result ~= nil or decoded.error ~= nil then
                chosen = decoded
            end
        end
    end
    if not chosen then return nil end

    local body = chosen.result
    if body == nil then body = chosen end
    -- A sampling reply is { role, content = { type, text } }; anything else gets
    -- serialised so SOMETHING reaches the detectors rather than nothing.
    if type(body) == "table" then
        local c = body.content
        if type(c) == "table" and type(c.text) == "string" and c.text ~= "" then return c.text end
        if type(c) == "string" and c ~= "" then return c end
    end
    local ok, encoded = pcall(cjson.encode, body)
    if ok and encoded ~= "" and encoded ~= "null" then return encoded end
    return nil
end

-- The AIRS envelope. Every leg fills exactly one content object and everything
-- around it is identical, so it lives in one place -- which is also the only way
-- correlation and identity stay consistent across the four legs.
local function wrap_scan_payload(config, content_object, request_body)
    local model = airs_ai_model(request_body)
    record_model(model)
    return {
        transaction_id = airs_transaction_id(),
        session_id = airs_session_id(config),   -- nil is simply omitted by cjson
        ai_profile = resolve_ai_profile(config),
        contents = { content_object },
        metadata = {
            app_name = airs_app_name(config),
            app_user = airs_app_user(config),
            -- `model` is a high-value field that neither this plugin's other
            -- paths nor Kong's own serializer put on the log record. It is
            -- computed right here for the envelope; record it on the way past so
            -- an operator can answer "which model was this traffic going to"
            -- without parsing a message string.
            ai_model = model,
            user_ip = airs_user_ip(),
        }
    }
end

local function build_mcp_tool_event_payload(config, request_body, response_body)
    local method = request_body.method or "unknown"
    -- `params` is client-controlled: a number or boolean there raises on
    -- `params.name`, and a string is survivable (string metatable) but yields
    -- nothing useful. Normalise anything non-table to an empty table.
    local params = request_body.params
    if type(params) ~= "table" then params = {} end

    local tool_name = "unknown"
    -- No initialiser: the if/elseif chain below ends in a catch-all `else`, so
    -- every path assigns this. tool_name above DOES need one, because the
    -- catch-all leaves it alone -- which is the difference luacheck spotted.
    local input_str

    -- Every method names what it acted on, not just tools/call: a scan that
    -- ships tool_invoked="unknown" cannot say WHAT was read -- which is the
    -- whole question for resources/read.
    local function named(v)
        return (type(v) == "string" and v ~= "") and v or nil
    end

    if method == "tools/call" then
        tool_name = named(params.name) or "unknown"
        local ok, encoded = pcall(cjson.encode, params.arguments or {})
        input_str = ok and encoded or "{}"
    elseif method == "resources/read" then
        tool_name = named(params.uri) or "unknown"
        local ok, encoded = pcall(cjson.encode, params)
        input_str = ok and encoded or "{}"
    elseif method == "prompts/get" then
        tool_name = named(params.name) or "unknown"
        local ok, encoded = pcall(cjson.encode, params)
        input_str = ok and encoded or "{}"
    else
        local ok, encoded = pcall(cjson.encode, params)
        input_str = ok and encoded or "{}"
    end

    -- Reuse the plugin's own multi-frame parse_sse, which handles `id:` lines
    -- and bare `data:` frames, and pick the frame answering OUR JSON-RPC id. A
    -- single pattern over one frame shape ("^event:%s*message%s+data:%s*(.+)")
    -- does not work here: Lua's `.` matches newline, so the greedy capture
    -- swallows every later frame and then fails to decode.
    local output_str = ""
    local output_gap = nil
    if type(response_body) == "string" and response_body ~= "" then
        local frames = parse_sse(response_body)
        if #frames == 0 then frames = { response_body } end   -- plain JSON reply, no SSE framing

        local want_id = request_body.id
        local chosen

        -- The reply to a JSON-RPC BATCH is a top-level array of response
        -- objects. Decoded whole it is a table with no `.id` and no `.result`,
        -- so `chosen` stays nil and the output is "" -- a batch's replies going
        -- unscanned. Flatten an array frame into its members so the id match
        -- below can find the one answering this member.
        local function consider(decoded)
            if type(decoded) ~= "table" then return false end
            if want_id ~= nil and decoded.id == want_id then
                chosen = decoded
                return true                 -- exact answer; stop looking
            elseif decoded.result ~= nil or decoded.error ~= nil then
                chosen = decoded            -- keep the latest result-bearing frame
            end
            return false
        end

        for _, payload in ipairs(frames) do
            local ok, decoded = pcall(cjson.decode, payload)
            -- cjson decodes `null` to a TRUTHY lightuserdata and a bare scalar
            -- to a number/boolean, so every field read here stays inside the
            -- pcall and behind a type test: a scalar reply must not raise after
            -- the tool has already executed.
            if ok and type(decoded) == "table" then
                if #decoded > 0 then
                    local done = false
                    for _, entry in ipairs(decoded) do
                        if consider(entry) then done = true break end
                    end
                    if done then break end
                elseif consider(decoded) then
                    break
                end
            end
        end

        if chosen then
            local body = chosen.result
            if body == nil then body = chosen end   -- JSON-RPC error replies carry no .result
            -- AIRS unmarshals a tools/list `output` into a Go []*mcp.Tool: a
            -- BARE ARRAY of tool objects, encoded as a string. The JSON-RPC
            -- result is one level up ({"tools":[...]}), and sending it earns
            -- `400 cannot unmarshal object into Go value of type []*mcp.Tool`
            -- -- so the tool catalogue, which is the tool-poisoning surface
            -- this whole path exists for, was never actually inspected.
            if method == "tools/list" and type(body) == "table" then
                if type(body.tools) == "table" then
                    body = body.tools
                else
                    body = nil      -- no catalogue in the reply: a gap, below
                end
            end
            if body ~= nil then
                local ok2, encoded = pcall(cjson.encode, body)
                output_str = ok2 and encoded or ""
            end
        end

        if output_str == "" then
            -- Report the gap to the caller rather than calling scan_gap here
            -- and discarding its return value: the fail-closed decision it
            -- exists to make would be thrown away and the payload sent anyway --
            -- with an empty output, earning a clean `tool_response` verdict for
            -- a reply nobody read. The caller takes the same decision as for
            -- every other gap.
            output_gap = "MCP response yielded no scannable output; frames=" .. #frames ..
                         " raw_body_len=" .. #response_body
        end
    end

    -- Correlation comes from airs_transaction_id, which uses the trusted PDK
    -- id. Nothing here reads a client-supplied Kong-Request-ID, not even into an
    -- unused local: a dead read of an untrusted header is one refactor away from
    -- being live again.

    -- server_name names the MCP SERVER, not the gateway: one node fronting
    -- several MCP servers otherwise produces indistinguishable scans and nothing
    -- says which server served a poisoned tool.
    local server_name = config.mcp_server_name
    if not server_name or server_name == "" then
        local ok, svc = pcall(kong.router.get_service)
        if ok and type(svc) == "table" then server_name = svc.name end
    end
    if not server_name or server_name == "" then
        server_name = airs_app_name(config)
    end

    return wrap_scan_payload(config, {
        tool_event = {
            metadata = {
                ecosystem = "mcp",
                method = method,
                server_name = server_name,
                tool_invoked = tool_name,
            },
            input = input_str,
            output = output_str,
        }
    }, request_body), output_gap
end

local function build_prompt_payload(config, scan_type, request_body, response_body)
    local prompt_to_scan = extract_prompt(request_body, config)

    if not prompt_to_scan or prompt_to_scan == "" then
        return nil, "Could not find a user prompt in the request payload."
    end

    log_payload(config,
        "Extracted prompt: " .. string.sub(prompt_to_scan, 1, 100) .. (string.len(prompt_to_scan) > 100 and "..." or ""))

    local content_object = { prompt = prompt_to_scan }

    if scan_type == "response" and response_body then
        local ok, decoded_response = pcall(cjson.decode, response_body)
        if ok and type(decoded_response) == "table" then
            -- OpenAI format
            -- Every choice is read, and `.message` is type-tested per choice.
            -- A guard on .choices and .choices[1] alone raises on a streamed
            -- `delta` chunk or a Responses-shaped body -- a 500 in the response
            -- phase, after the model was billed -- and reading only choices[1]
            -- lets the other completions of an "n": 2 request reach the client
            -- uninspected under a clean scan record.
            local choices = type(decoded_response.choices) == "table" and decoded_response.choices or nil
            if choices and choices[1] then
                local texts = {}
                for _, ch in ipairs(choices) do
                    if type(ch) == "table" and type(ch.message) == "table" then
                        local c = ch.message.content
                        if type(c) == "string" then texts[#texts + 1] = c
                        elseif type(c) == "table" then
                            local t = content_text(c)
                            if t then texts[#texts + 1] = t end
                        end
                        -- `content` alone made a tool call invisible here while
                        -- the streamed path scanned it, so the same completion
                        -- was judged differently depending on a flag the CALLER
                        -- sets. A tool-call-only reply (`content: null`) also
                        -- extracted nothing at all, which is a scan gap, which
                        -- fails closed -- every function-calling reply refused.
                        fold_tool_calls(texts, ch.message.tool_calls)
                    end
                end
                content_object.response = #texts > 0 and table.concat(texts, "\n") or nil
                -- Bedrock Converse format
            elseif decoded_response.output and decoded_response.output.message then
                local resp_content = decoded_response.output.message.content
                if type(resp_content) == "table" and resp_content[1] and resp_content[1].text then
                    content_object.response = resp_content[1].text
                elseif type(resp_content) == "string" then
                    content_object.response = resp_content
                end

            -- The response leg understands every provider the REQUEST leg does
            -- -- Gemini, Cohere and the legacy completions shape included. Where
            -- it does not, the prompt still extracts, so this function returns a
            -- payload with `response = nil`, AIRS is asked to judge a prompt with
            -- no answer attached, says allow, and record_scan writes a clean
            -- RESPONSE verdict for a model answer nobody read: a forged pass.
            -- These branches, and the shape gap below, close it.
            elseif type(decoded_response.candidates) == "table" then
                -- Gemini generateContent
                local texts = {}
                for _, cand in ipairs(decoded_response.candidates) do
                    local parts = type(cand) == "table" and type(cand.content) == "table"
                                  and cand.content.parts
                    if type(parts) == "table" then
                        for _, part in ipairs(parts) do
                            if type(part) == "table" and type(part.text) == "string"
                               and part.text ~= "" then
                                texts[#texts + 1] = part.text
                            end
                        end
                    end
                end
                content_object.response = #texts > 0 and table.concat(texts, "\n") or nil

            elseif type(decoded_response.content) == "table" then
                -- Anthropic Messages: a list of typed blocks
                content_object.response = content_text(decoded_response.content)

            elseif type(decoded_response.text) == "string" and decoded_response.text ~= "" then
                -- Cohere v1 generate/chat
                content_object.response = decoded_response.text

            elseif type(decoded_response.message) == "table" then
                -- Cohere v2 chat: message.content is a list of blocks
                content_object.response = content_text(decoded_response.message.content)
            end
        end
    end

    -- "The body was read and no branch above understood it" is a
    -- scan GAP, not a pass. Reported to the caller so it takes the same
    -- on_scan_error decision as every other thing we could not inspect, instead
    -- of quietly recording a verdict on a nil.
    local response_gap = nil
    if scan_type == "response" and response_body and content_object.response == nil then
        response_gap = "response body was read but its shape was not recognised, " ..
                       "so no model output was extracted to scan"
    end

    -- airs_transaction_id and airs_app_user are the only sources of the id and
    -- the user here. Nothing reads a client-supplied Kong-Request-ID, and the
    -- Kong service name never stands in for a caller.
    return wrap_scan_payload(config, content_object, request_body), nil, response_gap
end

-- ============================================================================
-- DLP masking
--
-- An AIRS masking profile returns the redacted text alongside an `allow`. An
-- early return on allow that forwards the ORIGINAL body decodes that redacted
-- text and throws it away: SCM shows a successful mask while the raw PAN goes to
-- the model and back to the caller. Both legs therefore substitute the masked
-- text back into the body, through `set_raw_body`.
--
-- NOTE: the response field names below (`prompt_masked_data.data` /
-- `response_masked_data.data`) must be confirmed against a live masking profile
-- before this is upstreamed. Everything here is gated behind
-- apply_dlp_masking=false, and a shape we do not recognise leaves the body
-- untouched rather than blanking it.
-- ============================================================================

local function masked_text(airs_body, key)
    if type(airs_body) ~= "table" then return nil end
    local block = airs_body[key]
    if type(block) ~= "table" then return nil end
    local data = block.data or block.masked_data or block.text
    if type(data) == "string" and data ~= "" then return data end
    return nil
end

-- Put masked text back into the one field it came out of. Returns the message
-- table to write into, or nil when the extraction was not a single-field read --
-- if several messages were concatenated for the scan, one masked string cannot
-- be split back across them, and guessing would corrupt the conversation.
local function maskable_prompt_slot(request_body, config)
    if type(request_body) ~= "table" or type(request_body.messages) ~= "table" then return nil end
    local want = scan_roles(config)
    local contributors, newest_user = 0, nil
    for _, message in ipairs(request_body.messages) do
        if type(message) == "table" and want[message.role] and content_text(message.content) then
            if message.role == "user" then
                newest_user = message
            else
                contributors = contributors + 1
            end
        end
    end
    if contributors > 0 or newest_user == nil then return nil end
    if type(newest_user.content) ~= "string" then return nil end
    return newest_user
end

-- Substitute masked text into a decoded response envelope, preserving it so a
-- client parsing OpenAI/Converse/Anthropic still finds the shape it expects.
-- Returns the re-encoded body, or nil to leave the original untouched.
local function substitute_response_text(body_str, masked)
    local ok, decoded = pcall(cjson.decode, body_str)
    if not ok or type(decoded) ~= "table" then return nil end

    if type(decoded.choices) == "table" then
        -- n>1 returns several completions and AIRS hands back one
        -- masked string. There is no honest way to decide which choice it
        -- belongs to, so mask nothing and say so.
        if #decoded.choices ~= 1 then return nil, "multiple choices" end
        local m = decoded.choices[1] and decoded.choices[1].message
        if type(m) ~= "table" or type(m.content) ~= "string" then return nil end
        m.content = masked
    elseif type(decoded.output) == "table" and type(decoded.output.message) == "table" then
        local c = decoded.output.message.content
        if type(c) == "string" then
            decoded.output.message.content = masked
        elseif type(c) == "table" then
            local hit = false
            for _, part in ipairs(c) do
                if type(part) == "table" and type(part.text) == "string" then
                    part.text = masked; hit = true; break
                end
            end
            if not hit then return nil end
        else
            return nil
        end
    elseif type(decoded.content) == "table" then
        local hit = false
        for _, part in ipairs(decoded.content) do
            if type(part) == "table" and type(part.text) == "string" then
                part.text = masked; hit = true; break
            end
        end
        if not hit then return nil end
    else
        return nil
    end

    local ok_enc, encoded = pcall(cjson.encode, decoded)
    return ok_enc and encoded or nil
end

-- ============================================================================
-- The scan size cap
-- ============================================================================

-- Pure: number of UTF-8 characters. A continuation byte (0b10xxxxxx) continues a
-- character rather than starting one. `#s` counts BYTES, so a field named
-- sse_max_scan_chars gave a Turkish operator half their configured budget and a
-- CJK operator a third of it.
local function utf8_len(s)
    local n = 0
    for i = 1, #s do
        local b = string.byte(s, i)
        if b < 128 or b >= 192 then n = n + 1 end
    end
    return n
end

-- Pure: first `maxchars` characters, cut on a codepoint boundary. string.sub on
-- a byte index can sever a multi-byte character and hand AIRS invalid UTF-8.
local function utf8_sub(s, maxchars)
    local n = 0
    for i = 1, #s do
        local b = string.byte(s, i)
        if b < 128 or b >= 192 then
            n = n + 1
            if n > maxchars then return string.sub(s, 1, i - 1) end
        end
    end
    return s
end

-- Pure decision for over-cap text.
-- Returns { exceeded, blocked, text }. blocked=true (fail-closed, the secure
-- default) => caller denies; fail-open => caller scans the first `max` chars.
local function apply_scan_limit(text, max, fail_closed)
    max = max or 20000
    if not text or utf8_len(text) <= max then
        return { exceeded = false, blocked = false, text = text }
    end
    if fail_closed then
        return { exceeded = true, blocked = true, text = nil }
    end
    return { exceeded = true, blocked = false, text = utf8_sub(text, max) }
end

-- The cap applies to the BUILT PAYLOAD, so it covers every leg in one place. On
-- the SSE path alone it leaves a non-streamed completion and an MCP tool output
-- -- the large-file-read that is the actual exfiltration case -- going to AIRS
-- whole, or past AIRS's own request ceiling into a non-200 that fail-closes the
-- request with no explanation an operator could act on.
-- Returns (ok, blocked_field, truncated).
local function limit_payload(config, payload)
    local c = payload and payload.contents and payload.contents[1]
    if type(c) ~= "table" then return true end
    local max = tonumber(config.sse_max_scan_chars) or 20000
    local fail_closed = config.sse_truncation_fail_closed
    local truncated = false

    local function cap(container, key)
        local v = container[key]
        if type(v) ~= "string" then return true end
        local lim = apply_scan_limit(v, max, fail_closed)
        if lim.blocked then return false end
        container[key] = lim.text
        truncated = truncated or lim.exceeded
        return true
    end

    for _, key in ipairs({ "prompt", "response" }) do
        if not cap(c, key) then return false, key, truncated end
    end
    if type(c.tool_event) == "table" then
        for _, key in ipairs({ "input", "output" }) do
            if not cap(c.tool_event, key) then return false, "tool_event." .. key, truncated end
        end
    end
    return true, nil, truncated
end

-- ============================================================================
-- Availability posture
-- ============================================================================

-- set_timeout(n) sets connect, send AND read to the same n, so the
-- worst case is 3n per scan and 6n per request. The three phases have nothing in
-- common: connect is a TCP handshake, read is where an AIRS cold path lands.
-- Field-measured spikes past 5 s produced false 403s on scans AIRS had actually
-- ALLOWED -- the request was blocked because the verdict arrived late, not
-- because of anything in the content. `timeout_ms`, if the operator set it,
-- still governs all three so existing configs keep their exact meaning.
local function scan_timeouts(config)
    local legacy = tonumber(config.timeout_ms)
    return tonumber(config.connect_timeout_ms) or legacy or 2000,
           tonumber(config.send_timeout_ms)    or legacy or 5000,
           tonumber(config.read_timeout_ms)    or legacy or 20000
end

-- A per-WORKER circuit breaker. Module-level state is per nginx worker, which is
-- the right granularity: when AIRS is down, every worker discovers it
-- independently and stops adding its own load to the outage.
-- Opening the breaker does NOT mean allowing traffic -- what happens next is
-- still on_scan_error. It only stops paying the timeout.
-- Keyed by the AIRS endpoint it is protecting, and it has to stay keyed: two
-- routes on one worker can target genuinely different AIRS deployments via
-- `region`, and one shared table lets failures on the EU route open the breaker
-- for a healthy US one -- one region's outage becoming both regions' 503s.
local breakers = {}
local function breaker_for(config)
    local key = airs_endpoint(config) or "?"
    local b = breakers[key]
    if not b then
        b = { failures = 0, open_until = nil }
        breakers[key] = b
    end
    return b
end

local function breaker_settings(config)
    local threshold = tonumber(config.breaker_failures) or 0
    return threshold > 0, threshold, tonumber(config.breaker_cooldown_s) or 30
end

local function breaker_is_open(config)
    local on = breaker_settings(config)
    local breaker = breaker_for(config)
    if not on or not breaker.open_until then return false end
    if ngx.now() < breaker.open_until then return true end
    -- Cooldown elapsed: half-open. Let one request probe, so a transient outage
    -- self-heals without an operator touching anything.
    breaker.open_until, breaker.failures = nil, 0
    return false
end

local function breaker_record(config, healthy)
    local on, threshold, cooldown = breaker_settings(config)
    if not on then return end
    local breaker = breaker_for(config)
    if healthy then
        breaker.failures, breaker.open_until = 0, nil
        return
    end
    breaker.failures = breaker.failures + 1
    if breaker.failures >= threshold then
        breaker.open_until = ngx.now() + cooldown
        kong.log.err("SecurePrismaAIRSHandler: AIRS unreachable " .. breaker.failures ..
                     " times; breaker open for " .. cooldown .. "s (" ..
                     tostring(airs_endpoint(config)) .. ")")
    end
end

-- Exposed so a test can put a worker back in a known state.
local function breaker_reset()
    breakers = {}
end

-- A retry is only honest when the failure was transient. A 401 is a wrong API
-- key and a 400 is a malformed payload: retrying either just triples the damage
-- and the latency. 429 and 5xx and transport errors are the retriable set.
local function is_retriable(res, _err)
    if not res then return true end
    if res.status == 429 then return true end
    return res.status >= 500
end

-- Returns: action, reason, airs_body, latency_ms
-- The decoded body is returned, not dropped: scan_id, report_id and the
-- per-detector booleans are otherwise unavailable to both the 403 and the log.
-- The cache key. A collision here is one request inheriting another
-- request's verdict, so this is a security boundary, not a hashtable nicety --
-- which rules out ngx.sha1_bin and ngx.md5 (both have constructible collisions;
-- an attacker who can craft one gets a malicious body served a benign body's
-- `allow`). SHA-256 over the resolved profile, a separator that cannot occur in
-- JSON, and the whole encoded content object. No truncation.
--
-- resty.sha256 ships with OpenResty and therefore with Kong. If it is somehow
-- unavailable the function returns nil, which disables caching for that request
-- rather than falling back to a weaker digest.
-- What goes INTO the key, and why each part has to. kong.cache is one node-wide
-- store shared by every plugin instance on the gateway, so anything left out of
-- the digest is a request being served a verdict for content that was never
-- scanned under its own configuration. Digesting (profile, content) alone does
-- NOT mean "no two profiles and no two legs can ever share an entry":
--
--   * the LEG is not implicit in which content field is populated. An OpenAI
--     tool-call reply has message.content = null, so no response text is
--     extracted, `response` stays nil and the response leg's content object is
--     byte-identical to the prompt leg's -- the response leg would replay the
--     prompt leg's allow and never reach AIRS. The MCP legs collide the same way
--     whenever the reply yields no output.
--   * the TENANT has to be in it. Two routes with different api_key (different
--     AIRS tenants) or different regional endpoints, whose profiles are both
--     named "default" -- a common name -- otherwise hash identically, and the
--     permissive tenant's allow is replayed for the strict tenant.
--   * profile_name "X" and profile_id "X" must not hash identically.
--   * the TRUNCATION settings have to be in it, because limit_payload runs
--     inside send_scan, i.e. AFTER the key is computed. A route that scans only
--     the first 100 chars would otherwise publish an allow under the FULL
--     content's key, which a route with the default cap then consumes as a
--     full-content allow.
--
-- Everything that changes what "this content was allowed" MEANS belongs in the
-- digest. The api_key is hashed, never stored: this key can appear in a shm
-- dump.
local function verdict_cache_key(config, leg, payload)
    local content = payload and payload.contents and payload.contents[1]
    if type(content) ~= "table" then return nil end
    local ok_enc, encoded = pcall(cjson.encode, content)
    if not ok_enc then return nil end

    local profile = "?"
    if payload.ai_profile then
        if payload.ai_profile.profile_name then
            profile = "name:" .. tostring(payload.ai_profile.profile_name)
        elseif payload.ai_profile.profile_id then
            profile = "id:" .. tostring(payload.ai_profile.profile_id)
        end
    end

    local ok_mod, sha256 = pcall(require, "resty.sha256")
    if not ok_mod or not sha256 then return nil end
    local ok_key, key = pcall(function()
        local function field(d, v)
            d:update(tostring(v))
            d:update("\0")          -- a separator that cannot occur in JSON
        end
        local d = sha256:new()
        field(d, "tenant")
        field(d, airs_endpoint(config) or "")
        field(d, tostring(config.api_key or ""))
        field(d, profile)
        field(d, "leg:" .. tostring(leg or "?"))
        field(d, "limit:" .. tostring(config.sse_max_scan_chars or "") ..
                 ":" .. tostring(config.sse_truncation_fail_closed))
        d:update(encoded)
        return "prisma-airs:v2:" .. ngx.encode_base64(d:final())
    end)
    if not ok_key or type(key) ~= "string" then return nil end
    return key
end

-- The caching wrapper around send_scan. Deliberately thin, and
-- deliberately allow-only:
--   * a cached BLOCK would freeze a false positive in place for the whole TTL,
--     and a block ends the request anyway, so it is the cheap case;
--   * a cached ERROR would turn a momentary AIRS outage into a sticky one.
-- Only a clean `allow` with a verdict body is stored. Masking is excluded
-- outright: apply_dlp_masking rewrites the body from the AIRS RESPONSE, and a
-- cached response would apply one request's redaction to another's content.
local function send_scan_cached(config, leg, payload, uncached)
    local ttl = tonumber(config.verdict_cache_ttl_s) or 0
    if ttl <= 0 or config.apply_dlp_masking then return uncached(config, payload) end

    local key = verdict_cache_key(config, leg, payload)
    if not key then return uncached(config, payload) end

    local cache = kong.cache
    if not cache or type(cache.get) ~= "function" then return uncached(config, payload) end

    -- The live result is captured here rather than reconstructed from the
    -- cache's return value. That matters: a non-allow verdict is deliberately
    -- NOT cached, so the callback returns nil for it -- and an earlier version
    -- of this function treated that nil as "cache unavailable" and called AIRS a
    -- SECOND time, which both doubled the spend and threw away the block that
    -- had already come back. The block was then replaced by whatever the second
    -- call returned. Never infer the verdict from the cache's answer.
    -- neg_ttl is passed explicitly. kong.cache is mlcache over the SHARED
    -- kong_db_cache shm -- the same store Kong keeps routes, services and
    -- consumers in -- and in mlcache a callback that returns nil is a NEGATIVE
    -- hit, which is written and held for neg_ttl. Left unset that is Kong's
    -- instance default, not the operator's TTL, so every distinct blocked prompt
    -- parked an entry in Kong's entity cache for a duration nobody configured.
    -- Behaviourally a negative hit already re-scans (`live` and `cached` are both
    -- nil, so the fallback runs), which is why "a block is never cached" held;
    -- the leak was the unbounded, attacker-influenced key growth beside it.
    local live = nil
    local ok, cached = pcall(cache.get, cache, key, { ttl = ttl, neg_ttl = ttl }, function()
        local action, reason, body, latency = uncached(config, payload)
        live = { action = action, reason = reason, body = body, latency = latency }
        -- Returning nil keeps a non-allow verdict out of the cache. `live` still
        -- carries it to the caller.
        if action ~= "allow" then return nil end
        return live
    end)

    if live then
        -- We went to AIRS on this request; the verdict is whatever it said.
        return live.action, live.reason, live.body, live.latency
    end

    if ok and type(cached) == "table" then
        -- A cache hit is NOT a fail-open and stays out of the `gaps` list. That
        -- list's deliverable is "rate of gaps per route"; a route with the cache
        -- on would light up as if it were failing open on most requests, muting
        -- the one signal it exists to give. It gets its own counter.
        note_cache_hit()
        -- The stored body carries the ORIGINAL request's scan_id, report_id and
        -- detectors. Returning it verbatim would stamp one user's transaction
        -- identifiers onto another's record, so an investigator pivoting from a
        -- log line to that scan_id in SCM would find a scan of somebody else's
        -- request. The verdict is shared; the identity is not. `cached = true`
        -- and a nil latency say plainly that no scan happened on THIS request --
        -- a hard-coded 0 would poison the scan-latency series.
        local body = cached.body
        if type(body) == "table" then
            local copy = {}
            for k, v in pairs(body) do copy[k] = v end
            copy.scan_id, copy.report_id = nil, nil
            copy.prisma_airs_cached_from = body.scan_id
            body = copy
        end
        return cached.action, cached.reason, body, nil
    end

    -- The cache itself failed (it never ran our callback and gave us nothing).
    -- Not scanning is not an option, so call AIRS directly.
    return uncached(config, payload)
end

local function send_scan(config, payload)
    local started = ngx.now and ngx.now() or nil
    local function elapsed()
        if not started then return nil end
        return math.floor((ngx.now() - started) * 1000 + 0.5)
    end

    if breaker_is_open(config) then
        return "error", "AIRS circuit breaker is open; scan skipped.", nil, elapsed()
    end

    -- Enforced here so it covers the prompt, the response, and both
    -- MCP legs -- not just SSE. "oversize" is deliberately NOT "error": the
    -- scanner is fine, we simply will not forward content we could not inspect
    -- in full, so it denies like a policy block rather than a 503.
    local within, field = limit_payload(config, payload)
    if not within then
        return "oversize", "content exceeds the scannable size at " .. tostring(field), nil, elapsed()
    end

    local ok_enc, request_payload_json = pcall(cjson.encode, payload)
    if not ok_enc then
        return "error", "Internal plugin error: Could not encode payload.", nil, elapsed()
    end

    log_payload(config, "Sending scan payload: " .. string.sub(request_payload_json, 1, 500))

    local connect_ms, send_ms, read_ms = scan_timeouts(config)
    local attempts = 1 + math.max(0, math.floor(tonumber(config.scan_retries) or 0))

    local res, err
    for attempt = 1, attempts do
        local httpc = http.new()
        httpc:set_timeouts(connect_ms, send_ms, read_ms)

        res, err = httpc:request_uri(airs_endpoint(config), {
            method = "POST",
            body = request_payload_json,
            headers = {
                ["Content-Type"] = "application/json",
                ["Accept"] = "application/json",
                ["x-pan-token"] = config.api_key
            },
            ssl_verify = config.ssl_verify
        })
        -- No set_keepalive call belongs here: request_uri() has already
        -- returned the socket to the pool on lua-resty-http >= 0.16 (what Kong
        -- 3.x bundles), so one would act on a closed connection and emit a warn
        -- per scan -- noise that reads like a pooling bug and is not one.

        if not is_retriable(res, err) then break end
        if attempt < attempts then
            log_debug(config, "AIRS scan attempt " .. attempt .. " failed (" ..
                      tostring(res and res.status or err) .. "); retrying.")
        end
    end

    if not res then
        breaker_record(config, false)
        return "error", "API call failed: " .. tostring(err), nil, elapsed()
    end

    local res_body_str = res.body
    -- A verdict came back, even a rejecting one: AIRS is reachable. Only
    -- transport failures and 5xx/429 count against the breaker.
    breaker_record(config, not is_retriable(res, err))

    if res.status ~= 200 then
        local reason = "API returned non-200 status: " .. res.status
        if res_body_str and res_body_str ~= "" then
            reason = reason .. " Body: " .. string.sub(res_body_str, 1, 500)
        end
        return "error", reason, nil, elapsed()
    end

    if not res_body_str or res_body_str == "" then
        return "error", "API response body was empty, despite 200 OK status.", nil, elapsed()
    end

    local ok_dec, res_body_json = pcall(cjson.decode, res_body_str)
    if not ok_dec then
        return "error", "Failed to decode API response JSON: " .. tostring(res_body_json), nil, elapsed()
    end

    log_debug(config,
        "AIRS verdict: " .. tostring(res_body_json.action) .. " category: " .. tostring(res_body_json.category))

    local action = res_body_json and res_body_json.action
    if not action then
        return "error", "'action' field not found in API response.", res_body_json, elapsed()
    end

    return action, "Verdict received from security scan.", res_body_json, elapsed()
end

-- Every call site goes through the cache dispatcher, which is a no-op
-- unless the operator set verdict_cache_ttl_s. Wrapping here rather than at the
-- six call sites means a leg added later cannot forget to participate -- and,
-- more importantly, cannot accidentally bypass the allow-only rule.
local send_scan_uncached = send_scan
send_scan = function(config, payload, leg)
    return send_scan_cached(config, leg, payload, send_scan_uncached)
end

-- An AIRS API failure -- transport error, non-200, empty body, undecodable JSON
-- -- is the SCANNER being unavailable, not a verdict about the content.
-- on_scan_error covers content we could not inspect; this covers the inspector
-- being down. The default is "block": no verdict, no passage. "allow" is the
-- internal-productivity case, and it is loud -- a silent fail-open is
-- indistinguishable from a working guardrail.
-- Returns true when the request should be allowed through despite the failure.
local function api_error_allows(config, reason)
    if (config and config.on_api_error) ~= "allow" then return false end
    pcall(function()
        kong.log.err("SecurePrismaAIRSHandler: AIRS unavailable and on_api_error=allow; " ..
            "forwarding UNSCANNED. Reason: " .. tostring(reason))
    end)
    -- The detail travels with the gap: `api_error_allowed` on its own gives no
    -- indication of WHICH failure -- timeout, 502, undecodable body, breaker
    -- open. Every record_gap call site passes one, so that an operator never has
    -- to parse prose to count them.
    record_gap("api_error_allowed", tostring(reason))
    -- And the scan entry itself must stop claiming this request was enforced.
    note_failed_open("AIRS unavailable; forwarded by on_api_error=allow")
    -- The fail-open check runs before the enforcement-mode check in both deny
    -- functions, so the monitor-mode marker has to be set here too. Without it
    -- the header goes missing on exactly the requests where nothing was
    -- enforced.
    if not enforcing(config) then mark_unenforced() end
    return true
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
-- An MCP client that receives a bare HTTP 403 sees a TRANSPORT
-- failure, not a tool failure, and some SDKs tear the session down. Answer in
-- the protocol the caller is speaking, echoing its id.
-- Returns only in monitor mode; otherwise kong.response.exit has already halted
-- the request and nothing after the call site runs.
local function deny_mcp(config, verdict, reason, rpc_id, block_message)
    log_error(reason, verdict)
    -- Checked before enforcement mode (see api_error_allows), because
    -- "the scanner is down" is a different question from "is this route
    -- enforcing", and an operator who set both should get the fail-open they
    -- asked for rather than a 503.
    if verdict == "error" and api_error_allows(config, reason) then return end
    if not enforcing(config) then mark_unenforced(); return end
    local status = (verdict == "error") and 503 or 403
    return kong.response.exit(status, {
        jsonrpc = "2.0",
        -- JSON-RPC 2.0 requires the `id` member on an error response, and Null
        -- when it could not be determined. A nil here simply dropped the key,
        -- so batch-level denials -- the over-cap refusal and every response-phase
        -- gap, both of which have no single member to answer for -- returned an
        -- error object with no id at all. Strict clients reject that.
        id = rpc_id ~= nil and rpc_id or cjson.null,
        error = {
            code = (status == 503) and -32003 or -32001,
            message = block_message,
        },
    }, mcp_exit_headers())
end

-- A denial returns machine-readable diagnostics -- scan_id, category, the leg
-- and the verdict source. Without them a false positive can only be
-- investigated through 403-vs-503 and a handful of English strings. `reason`
-- stays SERVER-SIDE: it concatenates AIRS's own error body, which must never be
-- returned verbatim to an untrusted caller.
-- Returns only in monitor mode; otherwise kong.response.exit has already halted
-- the request and nothing after the call site runs.
local function deny(config, verdict, reason, block_message, leg, airs_body)
    log_error(reason, verdict)
    if verdict == "error" and api_error_allows(config, reason) then return end
    if not enforcing(config) then mark_unenforced(); return end
    if verdict_status(verdict) == 503 then
        return kong.response.exit(503, {
            message = "Security scanning temporarily unavailable.",
            leg = leg,
            verdict_source = "scanner_unavailable",
        })
    end
    return kong.response.exit(403, {
        message = block_message,
        leg = leg,
        verdict_source = "airs",
        scan_id  = type(airs_body) == "table" and airs_body.scan_id or nil,
        category = type(airs_body) == "table" and airs_body.category or nil,
    })
end


-- ACCESS PHASE
function SecurePrismaAIRSHandler:access(config)
    log_debug(config, "Access phase triggered.")
    kong.service.request.enable_buffering()

    -- Only this plugin sets X-AIRS-Profile-Used, so clear whatever arrived: a
    -- client-supplied value that passes straight through reaches a backend
    -- trusting it for audit.
    --
    -- It has to happen HERE, as the first thing the phase does. Anywhere further
    -- down the LLM path -- below the MCP branch, or below the earlier returns
    -- (bodyless method, oversize-forwarded-by-config, unreadable body) -- and the
    -- spoofed header survives to the upstream on every MCP request, every GET,
    -- and both opted-in pass-through paths. A guard that only runs on the paths
    -- that were never the problem is not a guard.
    pcall(function() kong.service.request.clear_header("X-AIRS-Profile-Used") end)

    -- The body read is gated by method. Unconditional, it hands every GET, HEAD,
    -- DELETE and CORS preflight a flat 400 -- and Streamable-HTTP MCP opens its
    -- server->client channel with GET and tears sessions down with DELETE, so
    -- that 400 breaks the transport. A bodyless method has nothing to scan.
    local method = "POST"
    do
        local ok, m = pcall(kong.request.get_method)
        if ok and type(m) == "string" then method = m end
    end
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then
        log_debug(config, method .. " carries no scannable body; passing through.")
        -- The access leg deliberately scanned nothing, so there is no request
        -- context for the response leg to pair with. Without this flag the
        -- response leg reaches "original request context missing", calls
        -- scan_gap, and with the default on_scan_error=block answers 403
        -- "Response blocked by security policy" -- to a GET. Streamable-HTTP MCP
        -- opens its server->client channel with GET /mcp, so every frame-carrying
        -- response on it would become a policy block. "We chose not to scan this"
        -- and "we lost the context of something we did scan" are different facts
        -- and must not share a branch.
        kong.ctx.plugin.no_scannable_request = true
        return
    end

    local request_body, err, oversize = read_request_body(config)
    if err or not request_body then
        -- "Too large to read" and "not valid at all" are different failures and
        -- must not share one misleading 400. Oversize is a scan GAP: it goes
        -- through the same fail-closed decision as any other thing we could not
        -- inspect, and answers 413 so the caller knows which knob.
        if oversize then
            if scan_gap(config, "request body exceeds the scannable size (" .. tostring(err) ..
                                "). Raise config.max_request_body_bytes, and Kong's own " ..
                                "nginx_http_client_body_buffer_size to match.") then
                return kong.response.exit(413, { message = "Request body too large to scan." })
            end
            log_debug(config, "Oversize request body forwarded unscanned by explicit configuration.")
            return
        end
        log_error("Could not get request body: " .. tostring(err), "unscannable")
        return kong.response.exit(400, { message = "Invalid or unreadable request body." })
    end

    -- Check if this is an MCP request
    -- The second return is deliberately discarded: a batch has no single method,
    -- so classification is per member below.
    local is_mcp, _, is_batch = is_mcp_request(request_body)

    if is_mcp then
        -- A batch has no single method, so classification and scanning are per
        -- MEMBER. Taking the first element's method as the whole batch's identity
        -- lets a `ping` in slot one carry an unscanned `tools/call` in slot two
        -- past both legs.
        local members = mcp_members(request_body, is_batch)

        kong.ctx.plugin.mcp_rpc_id = (not is_batch) and request_body.id or nil
        kong.ctx.plugin.request_body = request_body
        kong.ctx.plugin.is_mcp = true
        kong.ctx.plugin.mcp_is_batch = is_batch

        -- A batch is scanned member by member, so its length is the number of
        -- AIRS calls a single request can ask for. Bound it, and treat the
        -- excess as a gap rather than inventing a policy: a caller must not be
        -- able to choose the gateway's outbound spend.
        local batch_cap = tonumber(config.mcp_max_batch_members) or 8
        if #members > batch_cap then
            if scan_gap(config, "JSON-RPC batch carries " .. #members ..
                                " members, above config.mcp_max_batch_members (" ..
                                batch_cap .. ")") then
                return deny_mcp(config, "block", "batch too large to scan", nil,
                                "MCP request blocked by security policy.")
            end
            return
        end

        log_debug(config, "MCP request detected, members: " .. #members)

        -- Nothing to scan in either direction -- but only if that is true of
        -- EVERY member. One scannable member makes the whole batch scannable.
        local all_control = true
        for _, member in ipairs(members) do
            if not is_mcp_no_content(member.method, config) then
                all_control = false
                break
            end
        end
        if all_control then
            log_debug(config, "MCP control message(s) - no scannable content")
            kong.ctx.plugin.mcp_bypassed = true
            return
        end

        for _, member in ipairs(members) do
            local rpc_method = member.method
            local rpc_id = member.id

            if is_mcp_no_content(rpc_method, config) then
                log_debug(config, "MCP control message (" .. tostring(rpc_method) ..
                                  ") in batch - no scannable content")

            -- Catalogue methods carry nothing on the way IN, but their RESPONSE
            -- is the poisoning surface. Skip the access scan, keep the response
            -- scan.
            elseif is_mcp_catalogue(rpc_method) then
                log_debug(config, "MCP catalogue request (" .. tostring(rpc_method) ..
                                  ") - response will be scanned")
                kong.ctx.plugin.mcp_catalogue = true

            -- sampling/createMessage and elicitation/create are
            -- server-initiated: the MCP server is asking OUR model to generate
            -- text, or asking OUR user to type some. That is a prompt. Shipping
            -- it as a tool_event with serialized params puts the text in a field
            -- the prompt detectors do not read, so "Paste your API key to
            -- continue" arrives as an unscanned JSON blob.
            -- sampling/createMessage and elicitation/create are prompts by
            -- nature. Everything AIRS refuses as a tool event joins them here,
            -- because a prompt scan is the one path with no method allowlist --
            -- otherwise these calls fail closed on an API incompatibility and
            -- their content is never inspected at all.
            elseif is_mcp_prompt_like(rpc_method) or not airs_accepts_tool_event(rpc_method) then
                kong.ctx.plugin.mcp_prompt_like = true

                local text = mcp_prompt_text(rpc_method, member.params)
                if not text then
                    if scan_gap(config, "MCP " .. tostring(rpc_method) ..
                                        " carried no scannable text") then
                    -- Deliberately NOT `return deny_mcp(...)`. deny_mcp only
                    -- returns when it did not terminate the request -- monitor
                    -- mode, or an opted-in fail-open -- and returning here would
                    -- abandon members 2..n unscanned and unrecorded. Monitor mode
                    -- scans, records and reports everything and changes nothing,
                    -- so a 3-member batch whose first member trips a false
                    -- positive must still produce three verdicts in the rollout
                    -- report.
                        deny_mcp(config, "block", "no scannable text in " .. tostring(rpc_method),
                                 rpc_id, "MCP request blocked by security policy.")
                    end
                else
                    local payload = wrap_scan_payload(config, { prompt = text }, member)
                    local verdict, reason, airs_body, ms = send_scan(config, payload, "prompt")
                    record_scan(config, "prompt", verdict, scan_outcome(verdict), airs_body, ms, reason)

                    if verdict ~= "allow" then
                        deny_mcp(config, verdict, reason, rpc_id,
                                 "MCP request blocked by security policy.")
                    else
                        log_debug(config, "MCP " .. tostring(rpc_method) .. " prompt scan allowed.")
                    end
                end

            else
                -- tools/call and everything else with params - scan as a tool_event
                local payload = build_mcp_tool_event_payload(config, member, nil)
                local verdict, reason, airs_body, ms = send_scan(config, payload, "tool_request")
                record_scan(config, "tool_request", verdict,
                            scan_outcome(verdict), airs_body, ms, reason)

                if verdict ~= "allow" then
                    deny_mcp(config, verdict, reason, rpc_id,
                             "MCP request blocked by security policy.")
                else
                    log_debug(config, "MCP scan allowed for method: " .. tostring(rpc_method))
                end
            end
        end

        return
    end

    -- Standard LLM prompt scanning
    local payload, payload_err = build_prompt_payload(config, "prompt", request_body, nil)

    if not payload then
        log_error(payload_err, "unscannable")
        return kong.response.exit(403, { message = "Request blocked by security policy." })
    end

    local verdict, reason, airs_body, ms = send_scan(config, payload, "prompt")
    record_scan(config, "prompt", verdict,
                scan_outcome(verdict), airs_body, ms, reason)

    kong.ctx.plugin.request_body = request_body

    if verdict ~= "allow" then
        deny(config, verdict, reason, "Request blocked by security policy.", "prompt", airs_body)
        return
    end

    -- An allow forwards the MASKED body when a masking profile redacted the
    -- prompt: forwarding the original here would decode the redaction and then
    -- send the model the raw value anyway.
    if config.apply_dlp_masking then
        local masked = masked_text(airs_body, "prompt_masked_data")
        local slot = masked and maskable_prompt_slot(request_body, config)
        if slot then
            slot.content = masked
            local ok_enc, encoded = pcall(cjson.encode, request_body)
            if ok_enc then
                pcall(kong.service.request.set_raw_body, encoded)
                note_masked()
                log_debug(config, "Applied AIRS-masked prompt to the upstream request.")
            end
        elseif masked then
            kong.log.warn("SecurePrismaAIRSHandler: AIRS returned masked prompt data but the " ..
                          "request shape has no single field to write it back to; forwarding unmasked.")
        end
    end

    log_debug(config, "Prompt scan allowed.")
end


-- Response-phase gaps answer in the caller's protocol, not with a bare
-- kong.response.exit(403): an MCP client reads a bare 403 as a transport failure
-- and some SDKs tear the session down. That is why deny_mcp and mcp_exit_headers
-- exist, and every MCP denial routes through them. One exit, protocol-aware.
local function response_gap_exit(config, detail)
    if kong.ctx.plugin.is_mcp then
        return deny_mcp(config, "block", detail or "response could not be scanned",
                        kong.ctx.plugin.mcp_rpc_id, "MCP response blocked by security policy.")
    end
    return kong.response.exit(403, { message = "Response blocked by security policy." })
end

-- RESPONSE PHASE
function SecurePrismaAIRSHandler:response(config)
    log_debug(config, "Response phase triggered.")

    -- An MCP server issues Mcp-Session-Id on the `initialize` RESPONSE, so the
    -- access leg legitimately has nothing to read; adopting it here is what stops
    -- the first turn of every conversation being the one that never joins its
    -- session. It costs a header read and calls no API, so it belongs ABOVE every
    -- early return: below the scan_responses knob or the mcp_bypassed
    -- short-circuit, a latency-tuned MCP route loses correlation on exactly the
    -- initialize turn.
    if kong.ctx.plugin.is_mcp then adopt_mcp_session_from_response(config) end

    -- A latency-sensitive route needs either one combined AIRS call or a knob to
    -- drop a phase. One call is not open to us -- the prompt verdict must arrive
    -- BEFORE the request is forwarded, and a combined prompt+response scan would
    -- mean the model had already answered. So the knob, and it is honest about
    -- what it buys: the AIRS round trip and the scan, NOT the buffering (Kong
    -- buffers because this plugin implements `response` at all -- see
    -- docs/DEPLOYMENT.md "Streaming").
    if config.scan_responses == false then
        -- For MCP CATALOGUE methods the access leg deliberately scans nothing
        -- and delegates all enforcement here -- the response is the
        -- tool-poisoning surface. So on those routes this knob is not "one AIRS
        -- call instead of two", it is ZERO calls and no enforcement in either
        -- direction. Silently. That is a gap, and it takes the same
        -- on_scan_error decision as every other gap rather than being invisible
        -- in the record.
        if kong.ctx.plugin.mcp_catalogue then
            if scan_gap(config, "scan_responses=false leaves MCP catalogue methods " ..
                                "unscanned in BOTH directions: the access leg carries " ..
                                "no content by design and the response leg is disabled") then
                return deny_mcp(config, "block", "catalogue response not scannable",
                                kong.ctx.plugin.mcp_rpc_id,
                                "MCP response blocked by security policy.")
            end
            return
        end
        log_debug(config, "Response scanning disabled by configuration; not calling AIRS.")
        return
    end

    -- Skip response scanning for bypassed MCP control messages
    if kong.ctx.plugin.mcp_bypassed then
        log_debug(config, "Skipping response scan for MCP control message.")
        return
    end

    local original_request_body = kong.ctx.plugin.request_body

    -- Read the full buffered response body via the shared helper (documented
    -- response-phase PDK call first, upstream's call as fallback).
    local response_body_str, gap = get_buffered_body()

    if not response_body_str then
        -- An unreadable body is a gap and fails closed; a body that
        -- is genuinely empty (204, an MCP notification's 202) is not a gap.
        if gap == "unreadable" and scan_gap(config, "response body could not be read in response phase") then
            return response_gap_exit(config, "response body could not be read")
        end
        log_debug(config, "No response body to scan (" .. tostring(gap) .. ").")
        return
    end

    if not original_request_body then
        if kong.ctx.plugin.no_scannable_request then
            log_debug(config, "Bodyless request; nothing to pair this response with.")
            return
        end
        if scan_gap(config, "original request context missing in response phase") then
            return response_gap_exit(config)
        end
        return
    end

    -- The upstream status is read first. A 429 or 500 envelope is not model
    -- output: scanning it costs a scan (and a bill), and a block on it would have
    -- kong.response.exit convert the upstream's own failure into a security 403,
    -- erasing the real cause.
    local up_status = 200
    local ok_status, st = pcall(kong.response.get_status)
    if ok_status and type(st) == "number" then up_status = st end
    if up_status >= 400 then
        log_debug(config, "Upstream returned " .. up_status .. "; not scanning an error body.")
        return
    end

    -- The response half is bounded too: max_request_body_bytes alone leaves an
    -- unbounded upstream body submitted for scanning whatever its size. Over the
    -- cap is a scan GAP -- we could not inspect all of it -- so it takes the same
    -- on_scan_error decision as every other gap rather than inventing a policy.
    --
    -- It sits BELOW the upstream-status guard on purpose. Above it, a 502 whose
    -- error body happens to exceed the cap becomes `403 Response blocked by
    -- security policy`, which is exactly the conversion of an upstream failure
    -- into a security verdict that the status guard exists to prevent. And it
    -- answers in the caller's protocol: every other gap inside the MCP branch
    -- replies with a JSON-RPC error object, so a plain HTTP 403 here hands an MCP
    -- client a body it cannot parse.
    if response_body_str then
        local cap = tonumber(config.max_response_body_bytes) or 8388608
        if #response_body_str > cap then
            if scan_gap(config, "response body exceeds the scannable size (" ..
                                #response_body_str .. " > " .. cap ..
                                " bytes). Raise config.max_response_body_bytes.") then
                return response_gap_exit(config, "response too large to scan")
            end
            log_debug(config, "Oversize response body returned unscanned by explicit configuration.")
            return
        end
    end

    -- MCP response scanning
    if kong.ctx.plugin.is_mcp then
        -- Per MEMBER, for the same reason the access leg is. Handing the whole
        -- array to a builder that reads scalar `.method`/`.params`/`.id` gets a
        -- batch's replies scanned as method "unknown" with an empty output -- a
        -- clean verdict on nothing.
        local members = mcp_members(original_request_body, kong.ctx.plugin.mcp_is_batch)

        for _, member in ipairs(members) do
            local method = member.method
            local rpc_id = member.id

            if is_mcp_no_content(method, config) then
                log_debug(config, "MCP control message (" .. tostring(method) ..
                                  ") in batch - no response to scan")

            -- The reply to sampling/createMessage IS the completion
            -- the server asked our model for, so it pairs with the prompt we
            -- scanned on the way in. Grounding and leakage detectors need the
            -- pair; a tool_event would hand them the reply alone with no
            -- question attached.
            -- The same split as the access leg. A catalogue reply reaches
            -- here with no request text, so the scan carries `response` alone,
            -- which AIRS accepts and its detectors read.
            elseif is_mcp_prompt_like(method) or not airs_accepts_tool_event(method) then
                local text = mcp_prompt_text(method, member.params)
                local reply = mcp_result_text(response_body_str, rpc_id)
                if not reply then
                    if scan_gap(config, "MCP " .. tostring(method) ..
                                        " reply carried no scannable text") then
                        deny_mcp(config, "block", "no scannable reply", rpc_id,
                                 "MCP response blocked by security policy.")
                    end
                else
                    local payload = wrap_scan_payload(config, { prompt = text, response = reply },
                                                      member)
                    local verdict, reason, airs_body, ms = send_scan(config, payload, "response")
                    record_scan(config, "response", verdict, scan_outcome(verdict), airs_body, ms, reason)

                    if verdict ~= "allow" then
                        deny_mcp(config, verdict, reason, rpc_id,
                                 "MCP response blocked by security policy.")
                    else
                        log_debug(config, "MCP " .. tostring(method) .. " response scan allowed.")
                    end
                end

            else
                local payload, output_gap =
                    build_mcp_tool_event_payload(config, member, response_body_str)
                if output_gap then
                    if scan_gap(config, output_gap) then
                        deny_mcp(config, "block", output_gap, rpc_id,
                                 "MCP response blocked by security policy.")
                    end
                else
                    local verdict, reason, airs_body, ms = send_scan(config, payload, "tool_response")
                    record_scan(config, "tool_response", verdict,
                                scan_outcome(verdict), airs_body, ms, reason)

                    if verdict ~= "allow" then
                        deny_mcp(config, verdict, reason, rpc_id,
                                 "MCP response blocked by security policy.")
                    else
                        log_debug(config, "MCP response scan allowed for method: " .. tostring(method))
                    end
                end
            end
        end

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
            -- Reconstructing zero text from a NON-empty stream means we do not
            -- understand this provider's wire format -- not that the model said
            -- nothing. It is a gap, with a diagnostic, and never a pass.
            if scan_gap(config, "SSE detected but no scannable text reconstructed. provider=" .. provider ..
                                " raw_body_len=" .. tostring(response_body_str and #response_body_str or 0)) then
                return kong.response.exit(403, { message = "Response blocked by security policy." })
            end
            return
        end

        local lim = apply_scan_limit(text, config.sse_max_scan_chars, config.sse_truncation_fail_closed)
        if lim.exceeded then
            kong.log.warn("SecurePrismaAIRSHandler: SSE reconstructed text exceeds sse_max_scan_chars (" ..
                utf8_len(text) .. " > " .. (config.sse_max_scan_chars or 20000) .. " chars)")
        end
        if lim.blocked then
            -- The truncation header is set only AFTER the block decision, and
            -- only on the branch that actually truncated. Set before it, an
            -- over-cap response reports "truncated" when what happened was "not
            -- scanned at all, and blocked". Two very different things to find in
            -- a trace at 3am.
            --
            -- This branch routes through scan_gap, not log_error(..., "blocked"),
            -- which logs at NOTICE and records nothing -- while its sibling
            -- condition eight lines above (zero reconstructed text) lands on the
            -- record at err. Two adjacent "we could not scan this SSE body"
            -- branches must not take two levels, one of them unqueryable. It is a
            -- gap, so it goes through the one decision point.
            if scan_gap(config, "SSE reconstructed text exceeds sse_max_scan_chars and " ..
                                "sse_truncation_fail_closed is set") then
                return kong.response.exit(403, { message = "Response blocked by security policy." })
            end
            -- scan_gap already marked the record unenforced in monitor mode, and
            -- an explicit on_scan_error=allow is a choice, not a non-enforcement.
        elseif lim.exceeded and config.sse_set_observability_headers then
            -- Truncated AND scanned: the header is true in the sense it claims.
            pcall(kong.response.set_header, "x-prisma-airs-sse-truncated", "true")
        end
        text = lim.text or text

        log_debug(config, "SSE reconstructed " .. #text .. " chars for AIRS scan (provider=" .. provider .. ")")

        -- Wrap into the OpenAI envelope build_prompt_payload already understands, so the
        -- shared builder is reused UNCHANGED and the text lands in contents[0].response.
        local ok_enc, wrapped = pcall(cjson.encode, { choices = { { message = { content = text } } } })
        -- A warn-and-return here would forward a whole reconstructed stream
        -- unscanned and leave no trace an operator could count.
        if not ok_enc then
            if scan_gap(config, "failed to encode reconstructed SSE text for scanning") then
                return kong.response.exit(403, { message = "Response blocked by security policy." })
            end
            return
        end
        response_body_str = wrapped
    end

    -- Standard LLM response scanning
    local payload, payload_err, shape_gap =
        build_prompt_payload(config, "response", original_request_body, response_body_str)

    -- Not a bare kong.log.warn followed by `return`. That sends the model's
    -- answer to the client unscanned, at the one level nobody alerts on, with no
    -- record_gap, no on_scan_error decision, and nothing on the structured record
    -- to distinguish it from a response leg that ran and allowed. The identical
    -- condition on the ACCESS leg fails closed, and inbound fail-closed with
    -- outbound silently fail-open is not a policy.
    if not payload then
        if scan_gap(config, tostring(payload_err) .. " (response leg)") then
            return kong.response.exit(403, { message = "Response blocked by security policy." })
        end
        return
    end

    -- The body was readable and no provider branch understood it, so
    -- there is no model output in this payload. Sending it anyway earns an
    -- `allow` on the prompt alone and records a response verdict for text
    -- nobody read.
    if shape_gap then
        if scan_gap(config, shape_gap) then
            return kong.response.exit(403, { message = "Response blocked by security policy." })
        end
        return
    end

    local verdict, reason, airs_body, ms = send_scan(config, payload, "response")
    record_scan(config, "response", verdict,
                scan_outcome(verdict), airs_body, ms, reason)

    if verdict ~= "allow" then
        return deny(config, verdict, reason, "Response blocked by security policy.", "response", airs_body)
    end

    if config.apply_dlp_masking then
        local masked = masked_text(airs_body, "response_masked_data")
        if masked then
            local rewritten, why = substitute_response_text(response_body_str, masked)
            if rewritten then
                pcall(kong.response.set_raw_body, rewritten)
                note_masked()
                log_debug(config, "Applied AIRS-masked response to the client response.")
            else
                -- AIRS ordered a redaction and we could not apply it, so the
                -- client gets the text AIRS said to mask. The success
                -- counterpart is recorded (note_masked); this needs a record
                -- too, or the structured record shows nothing where a mask was
                -- ordered and missed.
                record_gap("mask_not_applied", tostring(why or "unrecognised shape"))
                kong.log.err("SecurePrismaAIRSHandler: AIRS returned masked response data but it " ..
                             "could not be substituted (" .. tostring(why or "unrecognised shape") ..
                             "); returning the response unmasked.")
            end
        end
    end

    log_debug(config, "Response scan allowed.")
end

-- Pure helpers exposed for the unit test harness (no Kong/ngx dependency).
SecurePrismaAIRSHandler._sse = {
    is_sse_content_type = is_sse_content_type,
    parse_sse = parse_sse,
    reconstruct_sse_text = reconstruct_sse_text,
    collect_strings = collect_strings,
    detect_provider = detect_provider,
    extract_openai_chat = extract_openai_chat,
    extract_openai_responses = extract_openai_responses,
    extract_anthropic_messages = extract_anthropic_messages,
    extract_prompt = extract_prompt,
    verdict_status = verdict_status,
    apply_scan_limit = apply_scan_limit,
}

-- The cache key is a security boundary, so its COMPOSITION is tested directly.
-- Driven only through the prompt leg of one config, a suite cannot see a missing
-- leg, tenant or endpoint.
SecurePrismaAIRSHandler._cache = {
    verdict_cache_key = verdict_cache_key,
}

-- The breaker is module-level, i.e. per worker, so a test that opens it leaks
-- into the next one. `breaker_reset` was written for exactly this and then never
-- exported -- a dead local whose comment claimed it had a caller.
SecurePrismaAIRSHandler._breaker = {
    reset = breaker_reset,
}

-- Pure (unit-testable) claim-based profile selection helpers.
SecurePrismaAIRSHandler._profile = {
    get_claim = get_claim,
    resolve = resolve_profile,
}

-- The MCP helpers are exported so the part of the plugin with the most
-- branching -- protocol classification -- can be unit tested. All of these are
-- pure.
SecurePrismaAIRSHandler._mcp = {
    is_mcp_request = is_mcp_request,
    is_no_content = is_mcp_no_content,
    is_catalogue = is_mcp_catalogue,
    is_prompt_like = is_mcp_prompt_like,
    prompt_text = mcp_prompt_text,
    result_text = mcp_result_text,
}

-- The size cap's character counting, exported because
-- byte-vs-character is precisely the kind of thing that regresses silently.
SecurePrismaAIRSHandler._limit = {
    utf8_len = utf8_len,
    utf8_sub = utf8_sub,
    apply_scan_limit = apply_scan_limit,
    limit_payload = limit_payload,
}

return SecurePrismaAIRSHandler

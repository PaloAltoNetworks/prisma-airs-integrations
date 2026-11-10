-- kong/plugins/prisma-airs-intercept/schema.lua
local typedefs = require "kong.db.schema.typedefs"

-- The name of the plugin. This must match the name used in API calls.
local PLUGIN_NAME = "prisma-airs-intercept"

local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- This plugin will be attached to a Service or a Route.
    -- protocols_http is http+https only, and that is correct --
    -- implementing a `response` phase forces buffered proxying, and Kong states
    -- that does not work for HTTP/2 or gRPC upstreams. The Plugin Hub page
    -- advertises grpc and grpcs anyway; that page is what needs the correction.
    -- Implementing a `response` handler is what puts Kong into buffered
    -- proxying -- Kong refuses to start if `response` coexists with
    -- header_filter/body_filter, and buffering does not work for HTTP/2 or
    -- gRPC upstreams. So http+https here is not a limitation to fix but the
    -- honest consequence of scanning responses at all; docs/DEPLOYMENT.md
    -- "Streaming" states the three real options.
    --
    -- Every field declared in this record is read by the handler.
    -- spec/k_audit_spec.lua enforces that for BOTH lineages, in both directions:
    -- a declared field nothing reads is a promise to the operator that nothing
    -- keeps, and a config key the handler reads that nobody declared is a knob
    -- Kong will reject.
    { protocols = typedefs.protocols_http },
    { consumer = typedefs.no_consumer },

    -- This 'config' record defines the configuration fields for the plugin.
    {
      config = {
        type = "record",
        fields = {
          -- Without `referenceable`, Kong Vault references such as
          -- {vault://konnect/airs-key} are REJECTED by the schema and an
          -- LLM-provider-grade secret has to be pasted inline.
          -- `referenceable` is what lets Kong dereference a {vault://...}
          -- value; `encrypted` keeps it out of `deck dump`, the Admin API and
          -- the Konnect UI. Without both, the AIRS token is stored and echoed
          -- in cleartext.
          { api_key = { type = "string", required = true, referenceable = true, encrypted = true }, },
          { profile_name = { type = "string", required = true }, },
          -- An SCM-side profile RENAME turns every request on the route into
          -- an AIRS non-200 -> verdict `error` -> 503, which at the client is
          -- indistinguishable from an outage. An id survives a rename.
          { profile_id = { type = "string", required = false }, },

          -- Dynamic per-request profile selection from a signed JWT claim.
          -- Leave profile_claim unset for the legacy static behavior (profile_name).
          -- Requires an auth plugin (jwt / openid-connect) in front: this plugin
          -- runs at priority 890, below jwt (1450) and openid-connect (1050), so
          -- the token is already validated when the claim is read.
          { profile_claim = { type = "string", required = false }, },
          { profile_claim_map = {
              type = "map",
              keys = { type = "string" },
              values = { type = "string" },
              required = false,
            },
          },
          -- Direct mode (a claim with no map) would let the token holder name
          -- their own AIRS profile. This is how an operator opts into it
          -- deliberately: the claim value is used only if it is on this list.
          { profile_claim_allow = {
              type = "array",
              required = false,
              elements = { type = "string" },
            },
          },
          -- Strict profile applied when the claim is missing or unmapped (fail closed).
          { fallback_profile_name = { type = "string", required = false }, },
          -- len_min keeps "" out: an empty app_name makes the handler emit the
          -- literal "kong-" as the AIRS app_name and MCP server_name -- a config
          -- that validates green and then mislabels every scan in the tenant.
          { app_name = { type = "string", required = false, len_min = 1 }, },
          -- The `match` pattern is what stops a typo'd or wrong-region endpoint
          -- validating cleanly at config time and then fail-closing 100% of
          -- traffic -- which presents to the operator exactly like an AIRS
          -- outage. https is required rather than merely preferred: the AIRS
          -- token travels in the x-pan-token header on every scan.
          { api_endpoint = {
              type = "string",
              required = true,
              default = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request",
              match = "^https://[%w%.%-]+[^%s]*$",
            },
          },
          -- api_endpoint defaults to the US regional URL, so without this an EU
          -- or APAC tenant has to know the right host and type it correctly --
          -- and a wrong-but-well-formed host passes the `match` above and then
          -- fail-closes 100% of traffic, which reads as an AIRS outage. Naming
          -- the region makes the choice visible in the Konnect UI and removes the
          -- transcription step. Setting api_endpoint explicitly still wins.
          { region = {
              type = "string",
              required = false,
              one_of = { "us", "eu", "apac" },
            },
          },
          { ssl_verify = { type = "boolean", required = true, default = true }, },

          -- Connect, send and read get three separate knobs, and none of them
          -- may be hard-coded over what the operator configured: a single
          -- httpc:set_timeout(n) applies n to all three, so the worst case is
          -- 3n per scan and 6n per request. They are three different waits --
          -- connect is a TCP handshake, read is where an AIRS cold path lands
          -- (measured spikes past 5 s produce false 403s on scans AIRS had
          -- ALLOWED; the live doors floor it at 20 s). timeout_ms keeps working
          -- and, when set, still governs all three -- which is why it carries
          -- no default: a default would make every existing config look like a
          -- deliberate override and silently pin the read timeout at 5 s.
          { timeout_ms = { type = "number", required = false }, },
          { connect_timeout_ms = { type = "number", required = false, between = { 1, 60000 } }, },
          { send_timeout_ms    = { type = "number", required = false, between = { 1, 60000 } }, },
          { read_timeout_ms    = { type = "number", required = false, between = { 1, 120000 } }, },

          -- The ceiling for a request body we will read and scan.
          -- Kong's own nginx_http_client_body_buffer_size must be raised to match,
          -- or nginx spills to a temp file below this number and the read fails.
          { max_request_body_bytes = { type = "number", required = false,
                                       default = 8388608, between = { 1024, 134217728 } }, },

          -- The RESPONSE half is bounded exactly like the request half; without
          -- this, a large upstream body is held in worker memory and submitted
          -- for scanning whatever its size. An over-cap response is a scan GAP
          -- and goes through on_scan_error like every other one.
          { max_response_body_bytes = { type = "number", required = false,
                                        default = 8388608, between = { 1024, 134217728 } }, },

          -- Two AIRS calls per LLM request, each adding 30-200 ms. A single
          -- combined call is not available to us, because the prompt verdict
          -- has to arrive BEFORE the request is forwarded and a combined scan
          -- would mean the model had already answered. So: this knob, to opt
          -- out of one phase.
          --
          -- Prompt scanning is unaffected only on plain LLM routes, and that
          -- qualification has to stay attached. On an MCP route it does not
          -- hold: for CATALOGUE methods the access leg carries no content by
          -- design and delegates ALL enforcement to the response leg, so this
          -- knob means zero AIRS calls in either direction. That is a scan gap,
          -- and the handler records it and takes the on_scan_error decision
          -- rather than silently un-scanning the tool-poisoning surface.
          --
          -- NOTE this does NOT restore token-by-token streaming. Kong activates
          -- buffered proxying because this plugin implements `response` at all
          -- (see the protocols note at the top of this file), not because of any
          -- call the handler makes. Turning this off saves the AIRS round trip
          -- and the scan, not the buffering. docs/DEPLOYMENT.md carries the
          -- streaming decision in full.
          { scan_responses = { type = "boolean", required = false, default = true }, },

          -- Rollout controls. `monitor` scans, records and reports everything
          -- and changes nothing the client sees -- the mode an operator needs
          -- when a false positive turns up mid-rollout and the alternatives are
          -- otherwise "keep blocking" and "uninstall".
          { enforcement_mode = { type = "string", required = false, default = "enforce",
                                 one_of = { "enforce", "monitor" } }, },
          -- Retries apply to transport errors, 429 and 5xx only. Off by default:
          -- turning them on moves the latency budget and that must be a choice.
          { scan_retries = { type = "number", required = false, default = 0, between = { 0, 3 } }, },
          -- Consecutive scan failures before this worker stops calling AIRS.
          -- 0 disables. Opening the breaker does NOT allow traffic -- what
          -- happens next is still on_scan_error.
          { breaker_failures  = { type = "number", required = false, default = 0, between = { 0, 100 } }, },
          { breaker_cooldown_s = { type = "number", required = false, default = 30, between = { 1, 3600 } }, },

          { debug = { type = "boolean", required = false, default = false }, },
          -- The scan payload contains the prompt. Where those logs ship, who
          -- can read them and what retention applies is a data-handling
          -- decision, so it gets its own switch rather than riding on `debug`.
          { debug_log_payloads = { type = "boolean", required = false, default = false }, },

          -- Buffered SSE (text/event-stream) response scanning
          { scan_sse_responses = { type = "boolean", required = false, default = true }, },
          { sse_provider = {
              type = "string",
              required = false,
              default = "auto",
              one_of = { "auto", "openai_chat", "openai_responses", "anthropic_messages", "raw" },
            },
          },
          -- 20000 = the conservative scan cap convention from other AIRS integrations (see README).
          -- The ceiling stays well above the default, so this knob can be turned
          -- up as well as down. It counts characters rather than bytes, and
          -- applies to the non-streamed and MCP legs too -- not SSE alone.
          { sse_max_scan_chars = { type = "number", required = false, default = 20000, between = { 1, 1000000 } }, },
          { sse_set_observability_headers = { type = "boolean", required = false, default = false }, },
          -- Secure default: an over-cap response can't be fully scanned, so block (403)
          -- rather than return it. false = opt into fail-open (scan first N, return all). See README.
          { sse_truncation_fail_closed = { type = "boolean", required = false, default = true }, },

          -- What to do when the plugin could not inspect something it was
          -- supposed to inspect (unreadable body, unrecognised stream format,
          -- missing request context). "block" is the secure default; "allow"
          -- is a deliberate, auditable opt-in to fail-open.
          -- Where a stable, per-conversation session id comes from.
          -- Resolution order: Mcp-Session-Id (always, MCP defines it) -> this
          -- header -> this JWT claim -> the authenticated consumer. If nothing
          -- identifies the conversation, session_id is OMITTED rather than
          -- invented: a per-request value is not a session id and must never
          -- be substituted for one.
          { session_id_header = { type = "string", required = false, default = "x-session-id" }, },
          { session_id_claim = { type = "string", required = false }, },

          -- Who the caller actually is. Consumer -> this claim -> this
          -- header -> "anonymous". Never the Kong service name.
          { user_claim = { type = "string", required = false }, },
          { user_header = { type = "string", required = false }, },

          -- Names the MCP server behind this route, so scans from one gateway
          -- fronting several servers stay distinguishable. Falls back to the
          -- Kong service name.
          { mcp_server_name = { type = "string", required = false }, },

          -- Roles whose content is submitted for scanning. The default is
          -- user-only; adding "tool" closes the tool-result injection path,
          -- "system" closes system-prompt injection.
          { scan_message_roles = {
              type = "array",
              required = false,
              elements = { type = "string", one_of = { "user", "system", "assistant", "tool" } },
              default = { "user" },
            },
          },
          -- Apply the redacted text AIRS returns alongside an `allow`, instead
          -- of decoding it and forwarding the original body.
          -- Off by default: silently rewriting a caller's payload is never a
          -- default, and the response field names still need confirming against
          -- a live masking profile (see the handler's note).
          { apply_dlp_masking = { type = "boolean", required = false, default = false }, },

          -- The bypass list must not be hard-coded: a control method the MCP
          -- spec adds AFTER a release would then be scanned as though it were a
          -- tool call -- a false positive an operator cannot clear without a new
          -- build. This list ADDS to the built-in one; it cannot remove from it,
          -- and `tools/call` is rejected outright because that method carries
          -- caller content by definition.
          { mcp_control_methods_extra = {
              type = "array",
              required = false,
              elements = { type = "string" },
            },
          },

          -- A JSON-RPC batch is scanned member by member, so its LENGTH is the
          -- number of AIRS calls one request can ask for. Without a bound the
          -- caller chooses the gateway's outbound spend. Over the bound is a
          -- scan gap, taking the same on_scan_error decision as any other thing
          -- we could not fully inspect.
          { mcp_max_batch_members = { type = "number", required = false, default = 8,
                                      between = { 1, 64 } }, },

          -- on_scan_error governs content we could not INSPECT. This governs
          -- the scanner being unavailable -- transport failure, non-200, empty
          -- or undecodable body. An internal productivity route and a public
          -- consumer route want different answers, and hard-coding either one
          -- is wrong. Default stays closed.
          { on_api_error = {
              type = "string",
              required = false,
              default = "block",
              one_of = { "block", "allow" },
            },
          },

          -- Identical prompts inside a short window cause redundant AIRS calls,
          -- so this caches a verdict against a hash of (profile_name, prompt)
          -- for a short TTL. It is OFF by default and must stay that way,
          -- because a verdict cache is a deliberate trade:
          --   * a profile change in SCM does not take effect until entries age
          --     out, so the TTL is the worst-case staleness of your policy;
          --   * only `allow` is ever cached. Caching a block would freeze a
          --     false positive in place for the whole TTL, and a block is the
          --     cheap case anyway -- it ends the request.
          -- The key is a full SHA-256 over profile + leg + content, so no two
          -- profiles and no two legs can ever share an entry.
          { verdict_cache_ttl_s = { type = "number", required = false, default = 0,
                                    between = { 0, 300 } }, },

          { on_scan_error = {
              type = "string",
              required = false,
              default = "block",
              one_of = { "block", "allow" },
            },
          },
        },
        -- Cross-field validation. Each of these rejects a config that Kong
        -- would otherwise accept happily and that then behaves wrongly at
        -- runtime -- the worst kind, because the operator gets a green
        -- checkmark and finds out in production.
        entity_checks = {
          -- A claim with neither a map nor an allowlist is unbounded direct
          -- mode: whatever string is in the token becomes the AIRS profile
          -- name. This is what makes bounded mode mandatory rather than
          -- advisory.
          { conditional_at_least_one_of = {
              if_field = "profile_claim",
              if_match = { ne = ngx.null },
              then_at_least_one_of = { "profile_claim_map", "profile_claim_allow" },
              then_err = "profile_claim requires profile_claim_map or profile_claim_allow: " ..
                         "without one, the token holder chooses the AIRS profile",
            },
          },
          -- An unmapped or unlisted claim value has to land somewhere safe.
          { mutually_required = { "profile_claim", "fallback_profile_name" } },
          -- An allowlist with no claim to apply it to is a config the operator
          -- believes is doing something.
          --
          -- This was `mutually_required { "profile_claim_allow", "profile_claim" }`,
          -- and Kong's mutually_required is SYMMETRIC: if either is set, both must
          -- be. So it also demanded an allowlist whenever a claim was set, which
          -- contradicts the conditional_at_least_one_of directly above it (claim
          -- needs map OR allow) and made MAP-ONLY claim routing impossible to
          -- configure -- a mode the v2 lineage supported and shipped. The
          -- implication only ever ran one way; express it that way.
          { custom_entity_check = {
              field_sources = { "profile_claim_allow", "profile_claim" },
              fn = function(entity)
                local allow = entity.profile_claim_allow
                if allow == nil or allow == ngx.null then return true end
                local claim = entity.profile_claim
                if claim ~= nil and claim ~= ngx.null then return true end
                return nil, "profile_claim_allow requires profile_claim: an allowlist " ..
                            "with no claim to apply it to does nothing"
              end,
            },
          },
          -- Naming a profile twice, two different ways, is ambiguous the
          -- moment the two disagree.
          { mutually_exclusive = { "profile_id", "profile_claim" } },
          -- A config that bypasses a method this plugin already classifies is
          -- not "additive" -- it REMOVES a scan. Every classified method is
          -- reserved here, not just `tools/call`: reserving that one alone
          -- leaves twelve others open, including `tools/list` (whose response
          -- is the tool-poisoning surface) and `sampling/createMessage` (a
          -- server-initiated prompt, bypassed on both legs). The handler
          -- refuses these too (defence in depth), but an operator should be
          -- told at config time rather than discovering it from a scan count.
          -- `region` only takes effect when api_endpoint is the shipped
          -- default -- an explicit endpoint has to keep winning, or an operator
          -- who pinned a private host would silently lose it. That leaves the
          -- reverse silent: someone who has pinned an endpoint and then adds
          -- region="eu" to fix a wrong-region problem would get no warning and
          -- no effect. Say so at config time.
          { custom_entity_check = {
              field_sources = { "region", "api_endpoint" },
              fn = function(entity)
                local DEFAULT = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
                local region = entity.region
                local endpoint = entity.api_endpoint
                if region == nil or region == ngx.null then return true end
                if endpoint == nil or endpoint == ngx.null or endpoint == DEFAULT then
                  return true
                end
                return nil, "region and an explicit api_endpoint are both set: " ..
                            "api_endpoint wins, so region would have no effect. " ..
                            "Set one or the other."
              end,
            },
          },
          { custom_entity_check = {
              field_sources = { "mcp_control_methods_extra" },
              fn = function(entity)
                local extra = entity.mcp_control_methods_extra
                if type(extra) ~= "table" then return true end
                -- Kept in step with the handler's tables by
                -- spec/k_audit_spec.lua, which reads both and fails if they
                -- ever disagree -- two hand-maintained lists is how the first
                -- version of this check ended up naming exactly one method.
                local reserved = {
                  ["tools/call"] = true, ["resources/read"] = true,
                  ["prompts/get"] = true, ["completion/complete"] = true,
                  ["tools/list"] = true, ["resources/list"] = true,
                  ["prompts/list"] = true, ["resources/templates/list"] = true,
                  ["initialize"] = true, ["roots/list"] = true,
                  ["sampling/createMessage"] = true, ["elicitation/create"] = true,
                  ["initialized"] = true, ["ping"] = true,
                  ["logging/setLevel"] = true,
                }
                for _, m in ipairs(extra) do
                  if reserved[m] then
                    return nil, "mcp_control_methods_extra cannot contain '" .. m ..
                                "': this plugin already classifies it, and the list " ..
                                "may only ADD control methods, never un-scan one"
                  end
                end
                return true
              end,
            },
          },
        },
      },
    },
  },
}

return schema

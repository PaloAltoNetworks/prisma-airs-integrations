-- kong/plugins/prisma-airs-intercept-postproxy/schema.lua
local typedefs = require "kong.db.schema.typedefs"

-- The name of the plugin. This must match the name used in API calls.
-- Each lineage must keep its own plugin name: two lineages declaring the same
-- name with byte-identical schemas cannot be installed side by side -- one
-- silently replaces the other, and PRIORITY becomes the only way to tell which
-- file a data plane is actually running. Kong requires the plugin name to match
-- the directory under kong/plugins/, so the name is derived from the directory
-- rather than chosen: this is the post-proxy flavor, at PRIORITY 760, below ai-proxy.
--
-- OPEN DECISION: if this lineage keeps the published name instead, swap the two
-- and rename both directories. It is one string in each schema.
local PLUGIN_NAME = "prisma-airs-intercept-postproxy"

local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- This plugin will be attached to a Service or a Route.
    -- Implementing a `response` handler is itself what puts Kong into buffered
    -- proxying, so this lineage cannot stream either; see docs/DEPLOYMENT.md
    -- "Streaming" for the three real options.
    -- protocols_http is http+https only, which is correct -- implementing a
    -- `response` phase forces buffered proxying, and Kong states that does not
    -- work for HTTP/2 or gRPC upstreams. The Plugin Hub page advertises grpc
    -- and grpcs anyway; that page is what needs the correction.
    -- Every field declared in this record is read by the handler;
    -- spec/k_audit_spec.lua enforces it for this lineage too.
    { protocols = typedefs.protocols_http },
    { consumer = typedefs.no_consumer },

    -- This 'config' record defines the configuration fields for the plugin.
    {
      config = {
        type = "record",
        fields = {
          -- Without `referenceable` the AIRS token cannot live in a Kong vault,
          -- and without `encrypted` it is echoed in cleartext by the Admin API
          -- and by a deck dump.
          { api_key = { type = "string", required = true, referenceable = true, encrypted = true }, },
          { profile_name = { type = "string", required = true }, },
          -- An SCM-side profile RENAME turns every request on the route into an
          -- AIRS non-200 -> verdict `error` -> 503, which at the client is
          -- indistinguishable from an outage. An id survives a rename.
          { profile_id = { type = "string", required = false }, },
          -- len_min keeps the empty string out of the config: a bare string
          -- would accept "", and the handler's
          -- `config.app_name and ("kong-" .. config.app_name) or "kong"` would
          -- then emit the literal "kong-" -- only nil and false are falsy in
          -- Lua.
          { app_name = { type = "string", required = false, len_min = 1 }, },
          -- The `match` pattern has to stay: with a bare string a typo'd or
          -- wrong-region endpoint validates cleanly at config time and then
          -- fail-closes 100% of traffic -- presenting to the operator exactly
          -- like an AIRS outage. https is required rather than merely
          -- preferred: the AIRS token travels in the x-pan-token header on
          -- every scan.
          { api_endpoint = {
              type = "string",
              required = true,
              default = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request",
              match = "^https://[%w%.%-]+[^%s]*$",
            },
          },
          { ssl_verify = { type = "boolean", required = true, default = true }, },
          -- timeout_ms carries no default: a default would make every existing
          -- config look like a deliberate override and pin the read timeout at
          -- 5 s. When set, it governs all three phases.
          { timeout_ms = { type = "number", required = false }, },
          { connect_timeout_ms = { type = "number", required = false, between = { 1, 60000 } }, },
          { send_timeout_ms    = { type = "number", required = false, between = { 1, 60000 } }, },
          { read_timeout_ms    = { type = "number", required = false, between = { 1, 120000 } }, },

          -- Ceiling for a request body we will read and scan. Kong's
          -- nginx_http_client_body_buffer_size must be raised to match.
          { max_request_body_bytes = { type = "number", required = false,
                                       default = 8388608, between = { 1024, 134217728 } }, },
          { debug = { type = "boolean", required = false, default = false }, },
          -- The scan payload contains the prompt. Where those logs ship, who
          -- can read them and what retention applies is a data-handling
          -- decision, so it gets its own switch rather than riding on `debug`.
          { debug_log_payloads = { type = "boolean", required = false, default = false }, },

          -- Fail-closed behaviour when the response cannot be inspected, and an
          -- explicit opt-in for routes that accept unscanned streaming (this
          -- plugin has no SSE reassembly).
          { on_scan_error = {
              type = "string", required = false, default = "block",
              one_of = { "block", "allow" },
            },
          },
          { allow_unscanned_streaming = { type = "boolean", required = false, default = false }, },

          -- Fail-closed has to stay the operator's choice, and an AIRS failure
          -- must never reach the client as a policy block: an outage of the
          -- inspector is not the guardrail firing. on_scan_error governs
          -- content we could not INSPECT; this governs the inspector being
          -- down. Default stays closed.
          { on_api_error = {
              type = "string", required = false, default = "block",
              one_of = { "block", "allow" },
            },
          },

          -- The response half carries its own bound, matching
          -- max_request_body_bytes on the request half: without one an
          -- unbounded upstream body is submitted for scanning whatever its
          -- size.
          { max_response_body_bytes = { type = "number", required = false,
                                        default = 8388608, between = { 1024, 134217728 } }, },

          -- Scanning both halves costs two AIRS calls per request, each adding
          -- latency and spend; this switch drops the second on a
          -- latency-sensitive route. This lineage has no MCP path, so unlike
          -- the primary there is no leg that depends on the response scan for
          -- its only enforcement.
          { scan_responses = { type = "boolean", required = false, default = true }, },

          -- api_endpoint defaults to the US regional URL, so without this an EU
          -- or APAC tenant has to know the right host and type it correctly --
          -- and a wrong-but-well-formed host passes the `match` above, then
          -- fail-closes 100% of traffic, which reads as an AIRS outage.
          { region = {
              type = "string", required = false,
              one_of = { "us", "eu", "apac" },
            },
          },
        },
      },
    },
  },
}

return schema
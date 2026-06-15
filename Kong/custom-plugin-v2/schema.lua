-- kong/plugins/prisma-airs-intercept/schema.lua
local typedefs = require "kong.db.schema.typedefs"

-- The name of the plugin. This must match the name used in API calls.
local PLUGIN_NAME = "prisma-airs-intercept"

local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- This plugin will be attached to a Service or a Route.
    { protocols = typedefs.protocols_http },
    { consumer = typedefs.no_consumer },

    -- This 'config' record defines the configuration fields for the plugin.
    {
      config = {
        type = "record",
        fields = {
          { api_key = { type = "string", required = true }, },
          { profile_name = { type = "string", required = true }, },
          { app_name = { type = "string", required = false }, },
          { api_endpoint = {
              type = "string",
              required = true,
              default = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
            },
          },
          { ssl_verify = { type = "boolean", required = true, default = true }, },
          { timeout_ms = { type = "number", required = false, default = 5000 }, },
          { debug = { type = "boolean", required = false, default = false }, },

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
          -- `between` is accepted by the Konnect plugin-schemas upload (verified); the handler
          -- also enforces this max independently, so the bound is belt-and-suspenders.
          { sse_max_scan_chars = { type = "number", required = false, default = 20000, between = { 1, 20000 } }, },
          { sse_set_observability_headers = { type = "boolean", required = false, default = false }, },
          -- Secure default: an over-cap response can't be fully scanned, so block (403)
          -- rather than return it. false = opt into fail-open (scan first N, return all). See README.
          { sse_truncation_fail_closed = { type = "boolean", required = false, default = true }, },
        },
      },
    },
  },
}

return schema

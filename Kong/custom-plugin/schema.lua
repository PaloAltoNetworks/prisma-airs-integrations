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
        },
      },
    },
  },
}

return schema
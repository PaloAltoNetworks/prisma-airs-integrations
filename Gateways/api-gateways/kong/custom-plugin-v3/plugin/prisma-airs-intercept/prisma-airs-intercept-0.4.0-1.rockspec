-- Packaging this as a rock gives a version pin, a rollback point, a checksum
-- and a way for an operator to state exactly which build is enforcing their
-- policy. `luarocks pack` produces the artifact a change-advisory board can
-- reference.
--
-- Run from custom-plugin-v3/: the build.modules paths below start at `plugin/`,
-- so a `cd` into this directory makes luarocks look for them twice over.
--
--   luarocks make plugin/prisma-airs-intercept/prisma-airs-intercept-0.4.0-1.rockspec
--   luarocks pack prisma-airs-intercept 0.4.0-1        -> a .all.rock you can checksum and ship

package = "prisma-airs-intercept"
version = "0.4.0-1"

source = {
  url = "git+https://github.com/PaloAltoNetworks/prisma-airs-integrations.git",
  tag = "prisma-airs-intercept-v0.4.0",
}

description = {
  summary  = "Prisma AIRS inline scanning for Kong Gateway",
  detailed = [[
    Scans LLM prompts and completions, and MCP tool events, through the Prisma
    AIRS sync scan API on both the request and the response leg. Fails closed by
    default; observe-only rollout via enforcement_mode.
  ]],
  homepage = "https://github.com/PaloAltoNetworks/prisma-airs-integrations",
  license  = "Apache-2.0",
}

dependencies = {
  "lua >= 5.1",
  -- `lua-resty-http` is declared because Kong registers it AS A ROCK, so luarocks
  -- resolves it from the image: measured on kong/kong-gateway:3.14 --
  --   depends on lua-resty-http >= 0.16 (0.17.2-0 installed: success)
  --
  -- `lua-cjson` is deliberately NOT declared, and that is not an oversight.
  -- Kong ships cjson through OpenResty, compiled into the runtime and NOT
  -- registered as a rock. luarocks therefore reports it "not installed", tries
  -- to fetch lua-cjson-2.1.0.10-1.src.rock from luarocks.org, and fails -- the
  -- Kong image has no `unzip`. Declaring it made `luarocks make` succeed on a
  -- bare Ubuntu box that will never run this plugin and FAIL inside the Kong
  -- image that does. The handler still requires cjson; OpenResty always
  -- provides it. For a Kong plugin the rule is: declare what Kong does not
  -- provide.
  "lua-resty-http >= 0.16",
}

-- These paths are relative to custom-plugin-v3/, because that is what
-- `luarocks make` resolves against: the checkout, not the deployed tree. The
-- module KEYS below are what Kong loads; the VALUES are where the sources live
-- in this repository. spec/i_packaging_spec.lua resolves every value on disk,
-- so the two cannot drift apart.
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.prisma-airs-intercept.handler"] = "plugin/prisma-airs-intercept/handler.lua",
    ["kong.plugins.prisma-airs-intercept.schema"]  = "plugin/prisma-airs-intercept/schema.lua",
  },
}

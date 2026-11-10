-- Structural guarantees about the plugins themselves. These catch the class of
-- mistake where a handler starts reading a config key nobody declared — Kong
-- rejects that config at write time, so it fails in the customer's hands.

local function read(p) local f = assert(io.open(p)); local s = f:read("*a"); f:close(); return s end

local PLUGINS = {
  { name = "v2", dir = "plugin/prisma-airs-intercept" },
  { name = "v1", dir = "plugin/prisma-airs-intercept-postproxy" },
}

describe("schema and handler agree", function()
  for _, p in ipairs(PLUGINS) do
    it(p.name .. ": every config key the handler reads is declared", function()
      local schema, handler = read(p.dir .. "/schema.lua"), read(p.dir .. "/handler.lua")
      local declared = {}
      for k in schema:gmatch("{%s*([%w_]+)%s*=%s*{%s*type") do declared[k] = true end
      local missing, seen = {}, {}
      for k in handler:gmatch("config%.([%w_]+)") do
        if not declared[k] and not seen[k] then
          seen[k] = true
          missing[#missing + 1] = k
        end
      end
      table.sort(missing)
      expect.eq(#missing, 0, "undeclared config keys: " .. table.concat(missing, ", "))
    end)

    it(p.name .. ": the AIRS token can live in a vault and is not echoed in cleartext", function()
      local schema = read(p.dir .. "/schema.lua")
      local block = schema:match("{%s*api_key%s*=%s*{(.-)}%s*,?%s*}")
      expect.truthy(block, "api_key field not found")
      expect.contains(block, "referenceable = true",
                      "api_key must be referenceable to live in a vault")
      expect.contains(block, "encrypted = true",
                      "api_key must be encrypted, never dumped in cleartext")
    end)

    it(p.name .. ": both files parse under LuaJIT", function()
      expect.truthy(loadfile(p.dir .. "/handler.lua"), "handler.lua must compile")
      expect.truthy(loadfile(p.dir .. "/schema.lua"), "schema.lua must compile")
    end)
  end

  it("the two plugins still declare distinct priorities", function()
    local a = read("plugin/prisma-airs-intercept/handler.lua"):match("PRIORITY%s*=%s*(%d+)")
    local b = read("plugin/prisma-airs-intercept-postproxy/handler.lua"):match("PRIORITY%s*=%s*(%d+)")
    expect.ne(a, b, "PRIORITY is the only reliable way to tell them apart in an inventory")
  end)
end)

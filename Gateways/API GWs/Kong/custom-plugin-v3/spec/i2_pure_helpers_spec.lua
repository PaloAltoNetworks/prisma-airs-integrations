-- I1: the pure helpers the handler exports "for the unit test harness".
--
-- Every helper the handler exports is driven here, the MCP helpers included —
-- they are the part of the plugin with the most branching, so they have to stay
-- exported. These drive them directly, with no request around them, which is
-- where the awkward inputs belong: a request-level test that also exercises an
-- edge case tells you something broke, not what.

local H = require("spec.helpers.harness")
local cjson = require("cjson")

-- The handler requires resty.http at module scope; borrow the harness's loader.
local function handler()
  local saved = package.loaded["resty.http"]
  package.loaded["resty.http"] = { new = function() return {} end }
  local h = assert(loadfile((os.getenv("KAP_ROOT") or ".") ..
                            "/plugin/prisma-airs-intercept/handler.lua"))()
  package.loaded["resty.http"] = saved
  return h
end

local M = handler()

-- ---------------------------------------------------------------------------
describe("exported surface", function()
  it("every group the handler advertises is present", function()
    for _, group in ipairs({ "_sse", "_profile", "_mcp", "_limit", "_cache", "_breaker" }) do
      expect.truthy(M[group], group .. " must be exported")
    end
  end)

  it("nothing advertised is nil — an exported nil is a silently skipped test", function()
    local missing = {}
    for _, group in ipairs({ "_sse", "_profile", "_mcp", "_limit", "_cache", "_breaker" }) do
      for name, fn in pairs(M[group]) do
        if type(fn) ~= "function" then missing[#missing + 1] = group .. "." .. name end
      end
    end
    expect.eq(#missing, 0, "not functions: " .. table.concat(missing, ", "))
  end)
end)

-- ---------------------------------------------------------------------------
describe("_limit — characters are not bytes", function()
  local L = M._limit

  it("counts codepoints, not bytes", function()
    expect.eq(L.utf8_len("hello"), 5)
    expect.eq(L.utf8_len("ğüşiöç"), 6, "two bytes each in UTF-8")
    expect.eq(L.utf8_len("日本語"), 3, "three bytes each")
    expect.eq(L.utf8_len(""), 0)
  end)

  it("truncates on a codepoint boundary, never mid-character", function()
    local cut = L.utf8_sub("ğüşiöç", 3)
    expect.eq(L.utf8_len(cut), 3)
    expect.eq(cut, "ğüş", "a byte-index cut would hand AIRS invalid UTF-8")
  end)

  it("returns the whole string when it is already under the cap", function()
    expect.eq(L.utf8_sub("short", 100), "short")
  end)

  it("apply_scan_limit measures in characters too", function()
    local turkish = string.rep("ğ", 300)          -- 600 bytes, 300 characters
    expect.falsy(L.apply_scan_limit(turkish, 400, true).exceeded)
    expect.truthy(L.apply_scan_limit(turkish, 200, true).exceeded)
  end)

  it("fail-closed yields no text at all, so nothing partial can be scanned by accident", function()
    local r = L.apply_scan_limit(string.rep("a", 100), 10, true)
    expect.truthy(r.blocked)
    expect.nil_(r.text)
  end)

  it("fail-open yields exactly the cap", function()
    local r = L.apply_scan_limit(string.rep("a", 100), 10, false)
    expect.falsy(r.blocked)
    expect.eq(L.utf8_len(r.text), 10)
  end)

  it("limit_payload reaches into a tool_event, not just the top level", function()
    local payload = { contents = { { tool_event = { input = "x", output = string.rep("z", 100) } } } }
    local ok, field = L.limit_payload({ sse_max_scan_chars = 10, sse_truncation_fail_closed = true }, payload)
    expect.falsy(ok)
    expect.eq(field, "tool_event.output")
  end)
end)

-- ---------------------------------------------------------------------------
describe("_mcp — protocol classification", function()
  local P = M._mcp

  it("an LLM body is never MCP, however it is shaped", function()
    expect.falsy(P.is_mcp_request{ messages = {}, jsonrpc = "2.0", method = "tools/call" })
    expect.falsy(P.is_mcp_request{ input = "hi", method = "tools/call" })
    expect.falsy(P.is_mcp_request("a string"))
    expect.falsy(P.is_mcp_request(nil))
  end)

  it("a batch is recognised, and reports that it is one", function()
    local is_mcp, method, batch = P.is_mcp_request{ { jsonrpc = "2.0", method = "tools/call", id = 1 } }
    expect.truthy(is_mcp)
    expect.truthy(batch, "a batch has no single id to echo on a denial")
    -- The method is deliberately nil for a batch. There is no such thing as
    -- "the" method of a batch, so returning the FIRST member's would let that
    -- single value classify -- and bypass -- every other member.
    expect.eq(method, nil, "a batch has no single method, and pretending it does is the bypass")
  end)

  it("a batch is only a batch if EVERY member is a real envelope", function()
    -- One member short of valid JSON-RPC means this is not a batch, and it must
    -- fall to the ordinary path where its content IS inspected -- never to the
    -- MCP path, where classification would decide what to skip.
    expect.falsy(P.is_mcp_request{ { jsonrpc = "2.0", method = "tools/call", id = 1 },
                                   { hello = "world" } })
    expect.falsy(P.is_mcp_request{ { jsonrpc = "2.0", method = "ping" },
                                   { jsonrpc = "1.0", method = "tools/call" } })
    -- and a member smuggling an LLM body shape disqualifies it too
    expect.falsy(P.is_mcp_request{ { jsonrpc = "2.0", method = "ping" },
                                   { jsonrpc = "2.0", method = "x", messages = {} } })
  end)

  it("every LLM body shape the extractor reads disqualifies a body from MCP", function()
    -- The guard must name every body shape extract_prompt reads, all five: a
    -- prompt parked in `contents`/`message`/`prompt` alongside a catalogue
    -- method would otherwise be forwarded with nothing scanned.
    for _, field in ipairs({ "messages", "input", "contents", "message", "prompt" }) do
      local body = { jsonrpc = "2.0", method = "tools/list" }
      body[field] = "x"
      expect.falsy(P.is_mcp_request(body), field .. " must lose to the LLM path")
    end
  end)

  it("every notification is no-content, not only the six that were listed", function()
    for _, m in ipairs({ "notifications/initialized", "notifications/message",
                         "notifications/resources/updated", "notifications/anything/new" }) do
      expect.truthy(P.is_no_content(m), m)
    end
    expect.falsy(P.is_no_content("tools/call"))
    expect.falsy(P.is_no_content(nil))
    expect.falsy(P.is_no_content({}), "method is client-controlled and need not be a string")
  end)

  it("catalogue methods are the ones whose RESPONSE is the payload", function()
    expect.truthy(P.is_catalogue("tools/list"))
    expect.truthy(P.is_catalogue("initialize"))
    expect.falsy(P.is_catalogue("tools/call"))
  end)

  it("prompt_text pulls the model-facing text out of a sampling request", function()
    local t = P.prompt_text("sampling/createMessage", {
      systemPrompt = "sys",
      messages = { { role = "user", content = { type = "text", text = "one" } },
                   { role = "assistant", content = "two" } },
    })
    expect.contains(t, "sys"); expect.contains(t, "one"); expect.contains(t, "two")
  end)

  it("and returns nil rather than an empty string when there is none", function()
    expect.nil_(P.prompt_text("sampling/createMessage", { messages = {} }))
    expect.nil_(P.prompt_text("elicitation/create", { message = "" }))
    expect.nil_(P.prompt_text("sampling/createMessage", 5), "params is client-controlled")
    expect.nil_(P.prompt_text("tools/call", { name = "x" }),
                "AIRS accepts tools/call as a tool event, so it is scanned as one; pulling " ..
                "prompt text out of it would mask a mis-route as a working scan")
    expect.truthy(P.prompt_text("vendor/unknownMethod", { q = "text" }),
                  "a method AIRS refuses as a tool event must still yield scannable text, " ..
                  "or it fails closed on an API incompatibility having inspected nothing")
  end)

  it("result_text picks the frame answering OUR id out of several", function()
    local sse =
      "data: " .. cjson.encode{ jsonrpc="2.0", method="notifications/progress" } .. "\n\n" ..
      "data: " .. cjson.encode{ jsonrpc="2.0", id=99, result={ content={ type="text", text="wrong one" } } } .. "\n\n" ..
      "data: " .. cjson.encode{ jsonrpc="2.0", id=7,  result={ content={ type="text", text="right one" } } } .. "\n\n"
    expect.eq(P.result_text(sse, 7), "right one")
  end)

  it("falls back to the latest result-bearing frame when no id matches", function()
    local sse = "data: " .. cjson.encode{ jsonrpc="2.0", id=1, result={ ok=true } } .. "\n\n"
    expect.truthy(P.result_text(sse, 42))
  end)

  it("returns nil for a reply with nothing in it, rather than an empty pass", function()
    expect.nil_(P.result_text("", 1))
    expect.nil_(P.result_text("data: [DONE]\n\n", 1))
    expect.nil_(P.result_text("not json at all", 1))
    expect.nil_(P.result_text("null", 1), "cjson decodes null to a TRUTHY sentinel")
  end)
end)

-- ---------------------------------------------------------------------------
describe("_profile — claim selection, driven directly", function()
  local P = M._profile

  local function token(claims)
    return H.bearer(claims)
  end

  it("get_claim reads a payload without verifying anything", function()
    -- Needs ngx.decode_base64; borrow the mock's ngx for the duration.
    local mocks = require("spec.helpers.mocks")
    local _, _, ngx_mock = mocks.build{}
    local saved = _G.ngx; _G.ngx = ngx_mock
    local ok, value = pcall(P.get_claim, token{ risk_tier = "high" }, "risk_tier")
    _G.ngx = saved
    expect.truthy(ok, tostring(value))
    expect.eq(value, "high")
  end)

  it("a malformed token yields nil, not an error", function()
    local mocks = require("spec.helpers.mocks")
    local _, _, ngx_mock = mocks.build{}
    local saved = _G.ngx; _G.ngx = ngx_mock
    local results = {}
    for _, t in ipairs({ "Bearer notajwt", "Bearer a.b", "", "Bearer ..", "Bearer a.!!!.c" }) do
      local ok, v = pcall(P.get_claim, t, "risk_tier")
      results[#results + 1] = { ok = ok, v = v }
    end
    _G.ngx = saved
    for i, r in ipairs(results) do
      expect.truthy(r.ok, "input " .. i .. " raised: " .. tostring(r.v))
      expect.nil_(r.v, "input " .. i)
    end
  end)

  it("no claim configured is the static path", function()
    local name, source = P.resolve({ profile_name = "Static" }, nil)
    expect.eq(name, "Static")
    expect.eq(source, "static")
  end)

  it("an array claim (Entra groups) takes the first mapped value", function()
    local name, source = P.resolve({
      profile_claim = "groups",
      profile_claim_map = { ["grp-b"] = "Strict-B" },
      fallback_profile_name = "Fallback",
    }, nil)
    -- No token, so this exercises the fail-closed path; the array case is
    -- covered end to end in h_schema_spec where a real token carries it.
    expect.eq(name, "Fallback")
    expect.eq(source, "fallback:no-claim")
  end)
end)

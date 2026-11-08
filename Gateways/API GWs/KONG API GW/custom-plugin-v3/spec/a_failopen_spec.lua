-- Section A: the control reports success while inspecting nothing.
-- Section B: uncaught Lua errors that bypass the fail-closed design entirely.
--
-- These assert the behaviour we WANT. Red here is the proof the defect is real.

local H = require("spec.helpers.harness")
local cjson = require("cjson")

describe("A1 — v1 must never send an empty response and call it a pass", function()
  it("extracts text from a Bedrock Converse response body", function()
    local r = H.run{
      plugin = "v1", config = H.cfg.base(),
      request = { body = H.body.chat{{"user","what is the ferry schedule"}} },
      upstream = { body = cjson.encode{ output = { message = { content = { { text = "Ferries run hourly." } } } } } },
      airs = { {action="allow"}, {action="allow"} },
    }
    expect.nil_(r.error)
    expect.len(r.scans, 2)
    expect.eq(H.contents(r, 2).response, "Ferries run hourly.",
              "a Converse body must be extracted, not silently dropped")
  end)

  it("fails closed when a non-empty response body yields no text", function()
    local r = H.run{
      plugin = "v1", config = H.cfg.base(),
      request = { body = H.body.chat{{"user","hi"}} },
      upstream = { body = "<html>502 from an intercepting proxy</html>" },
      airs = { {action="allow"}, {action="allow"} },
    }
    expect.nil_(r.error)
    expect.truthy(r.exit, "an uninspectable response must not be forwarded as if scanned")
    expect.nil_(H.logged(r, "Response scan in response phase was allowed"))
  end)

  it("refuses a streaming request rather than silently not scanning it", function()
    local r = H.run{
      plugin = "v1", config = H.cfg.base(),
      request = { body = { model = "gpt-4o", stream = true,
                           messages = { { role = "user", content = "stream me" } } } },
      airs = { {action="allow"} },
    }
    expect.truthy(r.exit, "v1 cannot scan SSE; it must say so instead of passing it through")
    expect.eq(r.phase, "access", "and it should refuse up front, before the model is billed")
  end)
end)

describe("A2 — v2's MCP post-tool scan must survive real SSE framing", function()
  local function mcp_run(upstream_body)
    return H.run{
      config = H.cfg.base(),
      request = { body = H.body.mcp_call("search_docs", { q = "ferries" }, 7) },
      upstream = { body = upstream_body },
      airs = { {action="allow"}, {action="allow"} },
    }
  end

  it("single frame", function()
    local r = mcp_run("event: message\ndata: " .. H.body.mcp_result({ text = "hourly" }, 7) .. "\n\n")
    expect.len(r.scans, 2)
    expect.contains(H.tool_event(r, 2).output, "hourly")
  end)

  it("multiple frames — progress notification then the result", function()
    local r = mcp_run(
      "event: message\ndata: " .. cjson.encode{ jsonrpc="2.0", method="notifications/progress", params={ p=1 } } .. "\n\n" ..
      "event: message\ndata: " .. H.body.mcp_result({ text = "hourly" }, 7) .. "\n\n")
    expect.contains(H.tool_event(r, 2).output, "hourly",
                    "the greedy (.+) swallows later frames and decode fails, leaving output empty")
  end)

  it("frame carrying an SSE id: line (resumability)", function()
    local r = mcp_run("id: 42\nevent: message\ndata: " .. H.body.mcp_result({ text = "hourly" }, 7) .. "\n\n")
    expect.contains(H.tool_event(r, 2).output, "hourly")
  end)

  it("bare data: frame with no event: line", function()
    local r = mcp_run("data: " .. H.body.mcp_result({ text = "hourly" }, 7) .. "\n\n")
    expect.contains(H.tool_event(r, 2).output, "hourly")
  end)

  it("never silently ships an empty output", function()
    local r = mcp_run("id: 9\nevent: message\ndata: " .. H.body.mcp_result({ text = "x" }, 7) .. "\n\n")
    local te = H.tool_event(r, 2)
    expect.truthy(te, "a tool_event should have been built")
    expect.ne(te.output, "", "an empty output must never be presented to AIRS as a clean scan")
  end)
end)

describe("A4 — response-leg bail-outs must fail closed and log loudly", function()
  it("an unreadable response body blocks rather than forwards", function()
    local r = H.run{
      config = H.cfg.base(),
      request = { body = H.body.chat{{"user","hello"}} },
      upstream = { body = nil, pdk_body_unavailable = true },
      airs = { {action="allow"} },
    }
    expect.nil_(r.error)
    expect.truthy(r.exit, "could-not-read must not mean forward-unscanned")
  end)

  it("logs the failure at err, not warn", function()
    local r = H.run{
      config = H.cfg.base(),
      request = { body = H.body.chat{{"user","hello"}} },
      upstream = { body = nil, pdk_body_unavailable = true },
      airs = { {action="allow"} },
    }
    expect.eq((H.log_levels(r)).warn or 0, 0, "warn is where keepalive noise lives; nobody alerts on it")
    expect.truthy((H.log_levels(r)).err and (H.log_levels(r)).err > 0)
  end)

  it("an on_scan_error=allow operator can still opt into fail-open, explicitly", function()
    local r = H.run{
      config = H.cfg.base{ on_scan_error = "allow" },
      request = { body = H.body.chat{{"user","hello"}} },
      upstream = { body = nil, pdk_body_unavailable = true },
      airs = { {action="allow"} },
    }
    expect.nil_(r.exit, "explicit opt-in is a choice; silent default is not")
  end)
end)

describe("A5 — an unrecognised SSE provider must not read as a clean scan", function()
  it("Google-shaped stream frames are refused, not skipped", function()
    local r = H.run{
      config = H.cfg.base{ scan_sse_responses = true },
      request = { body = H.body.chat{{"user","hello"}} },
      upstream = {
        headers = { ["content-type"] = "text/event-stream" },
        body = H.body.sse{ cjson.encode{ candidates = { { content = { parts = { { text = "hi" } } } } } } },
      },
      airs = { {action="allow"}, {action="allow"} },
    }
    expect.nil_(r.error)
    expect.truthy(r.exit, "reconstructing zero text from a non-empty stream is a gap, not a pass")
  end)

  it("names the provider and body size so the format can be identified", function()
    local r = H.run{
      config = H.cfg.base{ scan_sse_responses = true },
      request = { body = H.body.chat{{"user","hello"}} },
      upstream = {
        headers = { ["content-type"] = "text/event-stream" },
        body = H.body.sse{ cjson.encode{ candidates = {} } },
      },
      airs = { {action="allow"}, {action="allow"} },
    }
    expect.truthy(H.logged(r, "raw_body_len"), "the diagnostic must survive the fix")
  end)
end)

-- ---------------------------------------------------------------------------
-- Section B — none of these may surface as an uncaught Lua error (a 500)
-- ---------------------------------------------------------------------------
local function no_500(name, opts)
  it(name, function()
    local r = H.run(opts)
    expect.nil_(r.error, "must not raise; the plugin should return a status")
  end)
end

describe("B — malformed input must produce a status, never a Lua error", function()
  no_500("B1 v1: multimodal content array", {
    plugin = "v1", config = H.cfg.base(), airs = { {action="allow"} },
    request = { body = { model="gpt-4o", messages = {
      { role="user", content = { { type="text", text="hi" } } } } } },
  })

  no_500("B2 v1: choices[1] present but no .message", {
    plugin = "v1", config = H.cfg.base(), airs = { {action="allow"}, {action="allow"} },
    request = { body = H.body.chat{{"user","hi"}} },
    upstream = { body = cjson.encode{ choices = { { delta = { content = "x" } } } } },
  })

  no_500("B2 v2: choices[1] present but no .message", {
    config = H.cfg.base(), airs = { {action="allow"}, {action="allow"} },
    request = { body = H.body.chat{{"user","hi"}} },
    upstream = { body = cjson.encode{ choices = { { delta = { content = "x" } } } } },
  })

  no_500("B3 v1: AIRS returns 200 with a non-JSON body", {
    plugin = "v1", config = H.cfg.base(),
    request = { body = H.body.chat{{"user","hi"}} },
    airs = { {raw = "<html>captive portal</html>"} },
  })

  it("B3 v1: that non-JSON 200 fails closed with a status", function()
    local r = H.run{
      plugin = "v1", config = H.cfg.base(),
      request = { body = H.body.chat{{"user","hi"}} },
      airs = { {raw = "<html>captive portal</html>"} },
    }
    expect.truthy(r.exit)
    expect.ne(r.exit.status, 200)
  end)

  no_500("B4 v2: messages element is a scalar", {
    config = H.cfg.base(), airs = { {action="allow"} },
    request = { body = { model="gpt-4o", messages = { 1 } } },
  })

  no_500("B4 v2: content array of scalars", {
    config = H.cfg.base(), airs = { {action="allow"} },
    request = { body = { model="gpt-4o", messages = {
      { role="user", content = { 1, 2, 3 } } } } },
  })

  no_500("B5 v2: MCP params is a number", {
    config = H.cfg.base(), airs = { {action="allow"} },
    request = { body = { jsonrpc="2.0", id=1, method="tools/call", params = 5 } },
  })

  no_500("B6 v2: MCP upstream replies with a bare JSON scalar", {
    config = H.cfg.base(), airs = { {action="allow"}, {action="allow"} },
    request = { body = H.body.mcp_call("t", {}, 1) },
    upstream = { body = "null" },
  })

  no_500("B7 v2: JSON-RPC method is an object", {
    config = H.cfg.base(), airs = { {action="allow"}, {action="allow"} },
    request = { body = { jsonrpc="2.0", id=1, method = { a = 1 } } },
  })
end)

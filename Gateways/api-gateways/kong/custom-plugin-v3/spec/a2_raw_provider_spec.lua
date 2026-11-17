-- A6: sse_provider = "raw".
--
-- "raw" means "a provider we have no extractor for". It does not mean "send the
-- wire format": a table.concat over the undecoded frames would put every brace,
-- quote, key and enum in front of AIRS as prose. That is the same
-- false-positive class as the measured source_code finding — the detectors end
-- up reading scaffolding instead of content.

local H = require("spec.helpers.harness")
local cjson = require("cjson")

local function raw_run(frames, over)
  over = over or {}
  over.scan_sse_responses = true
  over.sse_provider = "raw"
  return H.run{
    config = H.cfg.base(over),
    request = { body = H.body.chat{{"user","hi"}} },
    upstream = { headers = { ["content-type"] = "text/event-stream" },
                 body = H.body.sse(frames) },
    airs = { {action="allow"}, {action="allow"} },
  }
end

describe("A6 — the raw provider sends text, not wire format", function()
  -- A stream shaped like nothing we have an extractor for.
  local frames = {
    cjson.encode{ id = "chatcmpl-9xR", object = "chat.completion.chunk",
                  model = "some-new-model", index = 0,
                  delta = { role = "assistant", content = "The ferry leaves at" } },
    cjson.encode{ id = "chatcmpl-9xR", index = 0,
                  delta = { content = " six." }, finish_reason = "stop" },
  }

  it("the assistant's words still reach AIRS", function()
    local r = raw_run(frames)
    local resp = H.contents(r, 2).response
    expect.contains(resp, "The ferry leaves at")
    expect.contains(resp, "six.")
  end)

  it("the JSON scaffolding does not", function()
    local resp = H.contents(raw_run(frames), 2).response
    expect.not_contains(resp, "{", "braces and quotes are not prose")
    expect.not_contains(resp, "delta", "a key name is not something the model said")
    expect.not_contains(resp, "finish_reason")
    expect.not_contains(resp, "chatcmpl-9xR", "an opaque id is noise to every detector")
  end)

  it("structural enum values are dropped too", function()
    local resp = H.contents(raw_run(frames), 2).response
    expect.not_contains(resp, "assistant", "the value of `role` is structure, not content")
    expect.not_contains(resp, "chat.completion.chunk")
  end)

  it("a genuinely plain-text stream is passed through untouched", function()
    local r = raw_run({ "The ferry leaves at six." })
    expect.contains(H.contents(r, 2).response, "The ferry leaves at six.")
  end)

  it("nested string content is found, however deep the envelope", function()
    local r = raw_run({ cjson.encode{ a = { b = { c = { text = "deeply nested answer" } } } } })
    expect.contains(H.contents(r, 2).response, "deeply nested answer")
  end)

  it("a metadata-only stream reconstructs to nothing, and that is a gap not a pass", function()
    local r = raw_run({ cjson.encode{ id = "x", index = 0, finish_reason = "stop" } })
    expect.truthy(r.exit, "zero text from a non-empty stream means we did not understand it")
  end)

  it("a cyclic or absurdly deep structure cannot hang a worker", function()
    -- Not reachable via cjson.decode, but the walker is a general one and the
    -- next caller may not be. Drive it directly.
    local saved = package.loaded["resty.http"]
    package.loaded["resty.http"] = { new = function() return {} end }
    local M = assert(loadfile((os.getenv("KAP_ROOT") or ".") ..
                              "/plugin/prisma-airs-intercept/handler.lua"))()
    package.loaded["resty.http"] = saved

    local t = { text = "top" }
    local node = t
    for _ = 1, 200 do node.child = { text = "deep" }; node = node.child end
    local ok, out = pcall(M._sse.collect_strings, t)
    expect.truthy(ok, "must not recurse without a bound: " .. tostring(out))
  end)
end)

-- Section D: correlation and identity. The user's named priorities.

local H = require("spec.helpers.harness")

local function meta(r, n) return H.scan(r, n) and H.scan(r, n).metadata end

describe("D1 — transaction_id, not the legacy tr_id", function()
  it("sends transaction_id", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} } }
    expect.truthy(H.scan(r).transaction_id, "the transaction slot is filled ONLY by transaction_id")
  end)

  it("does not send tr_id, which lands in the session slot", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     airs = { {action="allow"}, {action="allow"} },
                     upstream = { body = H.body.openai_response("ok") } }
    expect.nil_(H.scan(r).tr_id,
      "a per-request tr_id makes every turn its own singleton conversation")
  end)

  it("v1 too", function()
    local r = H.run{ plugin = "v1", config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} } }
    expect.truthy(H.scan(r).transaction_id)
    expect.nil_(H.scan(r).tr_id)
  end)

  it("is unique per turn but identical across the two legs of one request", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} } }
    expect.eq(H.scan(r, 1).transaction_id, H.scan(r, 2).transaction_id,
              "prompt and response scans of one turn must stitch together")
  end)
end)

describe("D3 — the id comes from the trusted PDK, not a client header", function()
  it("ignores a client-supplied Kong-Request-ID", function()
    local r = H.run{
      config = H.cfg.base(),
      request = { body = H.body.chat{{"user","hi"}},
                  headers = { ["kong-request-id"] = "attacker-pinned-value" } },
      upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} },
    }
    expect.ne(H.scan(r).transaction_id, "attacker-pinned-value",
              "a caller could otherwise merge or split sessions in SCM at will")
  end)

  it("caps correlation ids at the AIRS 100-char limit", function()
    local long = string.rep("A", 400)
    local r = H.run{
      config = H.cfg.base{ session_id_header = "x-session-id" },
      request = { body = H.body.chat{{"user","hi"}}, headers = { ["x-session-id"] = long } },
      upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} },
    }
    expect.truthy(#H.scan(r).session_id <= 100,
      "an over-length value makes AIRS return non-200, which fail-closes the route")
  end)
end)

describe("D2 — a real session_id", function()
  it("reads the configured header", function()
    local r = H.run{
      config = H.cfg.base{ session_id_header = "x-session-id" },
      request = { body = H.body.chat{{"user","hi"}}, headers = { ["x-session-id"] = "conv-abc" } },
      upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} },
    }
    expect.eq(H.scan(r).session_id, "conv-abc")
  end)

  it("prefers Mcp-Session-Id on the MCP path", function()
    local r = H.run{
      config = H.cfg.base(),
      request = { body = H.body.mcp_call("t", {}, 1), headers = { ["mcp-session-id"] = "mcp-sess-9" } },
      upstream = { body = H.body.mcp_result({ text = "x" }, 1) },
      airs = { {action="allow"}, {action="allow"} },
    }
    expect.eq(H.scan(r).session_id, "mcp-sess-9")
  end)

  it("falls back to the authenticated consumer", function()
    local r = H.run{
      config = H.cfg.base(), consumer = { id = "c-1", username = "alice" },
      request = { body = H.body.chat{{"user","hi"}} },
      upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} },
    }
    expect.truthy(H.scan(r).session_id)
  end)

  it("is stable across both legs of a request", function()
    local r = H.run{
      config = H.cfg.base{ session_id_header = "x-session-id" },
      request = { body = H.body.chat{{"user","hi"}}, headers = { ["x-session-id"] = "conv-abc" } },
      upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} },
    }
    expect.eq(H.scan(r, 1).session_id, H.scan(r, 2).session_id)
  end)

  it("omits session_id rather than inventing one when nothing identifies the conversation", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} } }
    expect.nil_(H.scan(r).session_id,
      "a per-request value here would recreate exactly the bug we are fixing")
  end)
end)

describe("D4 — identity must not collapse to the gateway", function()
  it("app_user is the consumer, not the Kong service name", function()
    local r = H.run{
      config = H.cfg.base(), consumer = { id = "c-1", username = "alice" },
      request = { body = H.body.chat{{"user","hi"}} },
      upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} },
    }
    expect.eq(meta(r).app_user, "alice")
  end)

  it("MCP tool events carry the real user, not the hardcoded 'mcp-client'", function()
    local r = H.run{
      config = H.cfg.base(), consumer = { id = "c-1", username = "alice" },
      request = { body = H.body.mcp_call("t", {}, 1) },
      upstream = { body = H.body.mcp_result({ text = "x" }, 1) },
      airs = { {action="allow"}, {action="allow"} },
    }
    expect.eq(meta(r).app_user, "alice")
    expect.ne(meta(r).app_user, "mcp-client")
  end)

  it("MCP server_name identifies the server, not the gateway", function()
    local r = H.run{
      config = H.cfg.base{ mcp_server_name = "docs-mcp" },
      request = { body = H.body.mcp_call("t", {}, 1) },
      upstream = { body = H.body.mcp_result({ text = "x" }, 1) },
      airs = { {action="allow"}, {action="allow"} },
    }
    expect.eq(H.tool_event(r).metadata.server_name, "docs-mcp",
      "one node fronting several MCP servers produced indistinguishable scans")
  end)
end)

describe("D5 — ai_model must be honest", function()
  it("uses the model the client actually asked for", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} } }
    expect.eq(meta(r).ai_model, "gpt-4o")
  end)

  it("recovers the Bedrock model id from the request path", function()
    local r = H.run{
      config = H.cfg.base(),
      request = { body = { messages = { { role = "user", content = "hi" } } },
                  path = "/model/amazon.nova-lite-v1:0/converse" },
      upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} },
    }
    expect.eq(meta(r).ai_model, "amazon.nova-lite-v1:0",
      "three live doors on three model families all reported the single string 'bedrock'")
  end)

  it("says unknown rather than inventing gpt-3.5-turbo or bedrock", function()
    local r = H.run{ config = H.cfg.base(),
                     request = { body = { messages = { { role = "user", content = "hi" } } } },
                     upstream = { body = H.body.openai_response("ok") }, airs = { {action="allow"}, {action="allow"} } }
    expect.eq(meta(r).ai_model, "unknown")
  end)
end)

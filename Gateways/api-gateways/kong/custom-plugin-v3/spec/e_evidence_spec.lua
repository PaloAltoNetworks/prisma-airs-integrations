-- Section E: evidence. The logging half of the transaction-id priority.

local H = require("spec.helpers.harness")

local function record(r) return r.serialize["airs"] end

describe("E1 — one structured record per scan, on allow AND on block", function()
  it("an allowed request emits a record", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow", scan_id="sc-1", report_id="rp-1"}, {action="allow", scan_id="sc-2"} } }
    local rec = record(r)
    expect.truthy(rec, "nothing reaches http-log / Datadog / OTel without this")
    expect.truthy(rec.scans and #rec.scans >= 1)
  end)

  it("the record carries the join keys an operator actually needs", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow", scan_id="sc-1", report_id="rp-1", category="benign"} } }
    local first = record(r).scans[1]
    expect.eq(first.scan_id, "sc-1", "scan_id is the join key AIRS -> SLS -> SIEM")
    expect.eq(first.report_id, "rp-1")
    expect.eq(first.action, "allow")
    expect.eq(first.leg, "prompt")
    expect.truthy(first.latency_ms ~= nil, "'how much did the scan add' was answered by hand-timing")
    expect.truthy(record(r).transaction_id)
  end)

  it("a blocked request emits one too, with the outcome named", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","bad"}} },
                     airs = { {action="block", category="malicious", scan_id="sc-9"} } }
    local first = record(r).scans[1]
    expect.eq(first.action, "block")
    expect.eq(first.outcome, "verdict")
  end)

  it("a scanner failure is recorded as an availability outcome, not a verdict", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     airs = { {transport="timeout"} } }
    expect.eq(record(r).scans[1].outcome, "fail_closed",
              "503-vs-403 is the difference between an incident and a security event")
  end)
end)

describe("E3 — which detector fired must be recoverable", function()
  it("fired detectors are captured, not discarded", function()
    local r = H.run{
      config = H.cfg.base(), request = { body = H.body.chat{{"user","bad"}} },
      airs = { { action="block", category="malicious", scan_id="sc-1",
                 prompt_detected = { injection = true, dlp = false, url_cats = true } } },
    }
    local d = record(r).scans[1].detectors
    expect.truthy(d, "prompt_detected/response_detected/tool_detected were never read at all")
    expect.contains(table.concat(d, ","), "injection")
    expect.contains(table.concat(d, ","), "url_cats")
    expect.not_contains(table.concat(d, ","), "dlp", "false detectors are noise")
  end)
end)

describe("E2/E5 — the 403 must be diagnosable", function()
  it("carries scan_id and category, as v1 did before the 503 split dropped them", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","bad"}} },
                     airs = { {action="block", category="malicious", scan_id="sc-42"} } }
    expect.eq(r.exit.body.scan_id, "sc-42")
    expect.eq(r.exit.body.category, "malicious")
  end)

  it("names the leg and the verdict source in machine-readable form", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","bad"}} },
                     airs = { {action="block", category="malicious", scan_id="sc-42"} } }
    expect.eq(r.exit.body.leg, "prompt", "the demo agent hardcoded 'prompt' on every block")
    expect.eq(r.exit.body.verdict_source, "airs")
  end)

  it("a fail-closed 503 says so rather than looking like a policy decision", function()
    local r = H.run{ config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
                     airs = { {transport="timeout"} } }
    expect.eq(r.exit.status, 503)
    expect.eq(r.exit.body.verdict_source, "scanner_unavailable")
  end)
end)

describe("E6 — AIRS's own error body must not be echoed to the caller", function()
  it("a non-200 from AIRS does not leak its body", function()
    local r = H.run{
      config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
      airs = { { status = 401, body = '{"error":"invalid api key for tenant acme-prod"}' } },
    }
    local blob = require("cjson").encode(r.exit.body)
    expect.not_contains(blob, "acme-prod", "the reason string was returned verbatim to an untrusted caller")
  end)

  it("but it is still recorded server-side for the operator", function()
    local r = H.run{
      config = H.cfg.base(), request = { body = H.body.chat{{"user","hi"}} },
      airs = { { status = 401, body = '{"error":"invalid api key for tenant acme-prod"}' } },
    }
    expect.truthy(H.logged(r, "401"), "the operator still needs to see why")
  end)
end)

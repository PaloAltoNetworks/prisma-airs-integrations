-- Section H: schema and configuration hygiene.
--
-- The theme here is config that validates cleanly and then behaves wrongly at
-- runtime. Those are the worst kind: the operator gets a green checkmark and
-- finds out in production.

local H = require("spec.helpers.harness")
local cjson = require("cjson")

-- ---------------------------------------------------------------------------
describe("H2 — a JWT claim must not be able to name any profile it likes", function()
  local function run(cfg, claims)
    return H.run{
      config = H.cfg.base(cfg),
      request = { body = H.body.chat{{"user","hi"}}, headers = { authorization = H.bearer(claims) } },
      upstream = { body = H.body.openai_response("ok") },
      airs = { {action="allow"}, {action="allow"} },
    }
  end

  it("map mode still works — that is the supported shape", function()
    local r = run({ profile_claim = "risk_tier",
                    profile_claim_map = { low = "Permissive", high = "Strict" },
                    fallback_profile_name = "Strict" }, { risk_tier = "low" })
    expect.eq(H.scan(r).ai_profile.profile_name, "Permissive")
  end)

  it("an unmapped claim value falls closed to the fallback", function()
    local r = run({ profile_claim = "risk_tier",
                    profile_claim_map = { low = "Permissive" },
                    fallback_profile_name = "Strict" }, { risk_tier = "nonsense" })
    expect.eq(H.scan(r).ai_profile.profile_name, "Strict")
  end)

  it("direct mode without an allowlist does NOT let the token pick", function()
    local r = run({ profile_claim = "airs_profile", fallback_profile_name = "Strict" },
                  { airs_profile = "Permit-Everything" })
    expect.eq(H.scan(r).ai_profile.profile_name, "Strict",
              "with no map and no allowlist the token holder chose the security profile")
  end)

  it("an allowlist is the way to opt into direct mode", function()
    local r = run({ profile_claim = "airs_profile",
                    profile_claim_allow = { "Team-A-Strict", "Team-B-Strict" },
                    fallback_profile_name = "Strict" },
                  { airs_profile = "Team-B-Strict" })
    expect.eq(H.scan(r).ai_profile.profile_name, "Team-B-Strict")
  end)

  it("and a value outside the allowlist still falls closed", function()
    local r = run({ profile_claim = "airs_profile",
                    profile_claim_allow = { "Team-A-Strict" },
                    fallback_profile_name = "Strict" },
                  { airs_profile = "Permit-Everything" })
    expect.eq(H.scan(r).ai_profile.profile_name, "Strict")
  end)

  it("the refusal is logged, because silently using a different profile is worse", function()
    local r = run({ profile_claim = "airs_profile", fallback_profile_name = "Strict",
                    debug = true },
                  { airs_profile = "Permit-Everything" })
    expect.truthy(H.logged(r, "fallback"), "an operator needs to see why their claim did nothing")
  end)
end)

-- ---------------------------------------------------------------------------
describe("H3 — the schema must reject configs that cannot work", function()
  local fields, config_record = H.config_fields("v2")

  it("declares entity_checks at all", function()
    expect.truthy(config_record.entity_checks, "there were none, so nothing was cross-validated")
    expect.truthy(#config_record.entity_checks > 0)
  end)

  local function has_check(pred)
    for _, c in ipairs(config_record.entity_checks or {}) do
      if pred(c) then return true end
    end
    return false
  end

  it("a profile_claim without a map or an allowlist is not a valid config", function()
    expect.truthy(has_check(function(c)
      local ct = c.conditional_at_least_one_of
      return ct and ct.if_field == "profile_claim"
    end), "this is what makes bounded mode mandatory rather than advisory")
  end)

  it("a profile_claim without a fallback is not a valid config either", function()
    expect.truthy(has_check(function(c)
      local m = c.mutually_required
      if not m then return false end
      local set = {}
      for _, f in ipairs(m) do set[f] = true end
      return set.profile_claim and set.fallback_profile_name
    end), "an unmapped claim has nowhere safe to land")
  end)

  it("api_endpoint is validated, not merely typed as a string", function()
    expect.truthy(fields.api_endpoint, "api_endpoint must exist")
    local pattern = fields.api_endpoint.match
    expect.truthy(pattern, "a typo'd or wrong-region endpoint validated cleanly then fail-closed " ..
                           "100% of traffic, presenting identically to an AIRS outage")

    -- Assert the pattern's behaviour, not its text: a spec that pins the regex
    -- passes for the wrong reason the moment the regex is rewritten.
    expect.truthy(string.match(fields.api_endpoint.default, pattern), "the default must satisfy it")
    expect.falsy(string.match("http://service.api.aisecurity.paloaltonetworks.com/v1/scan", pattern),
                 "the AIRS token travels in x-pan-token on every scan; plaintext http must not validate")
    expect.falsy(string.match("not a url at all", pattern))
    expect.falsy(string.match("", pattern))
  end)
end)

-- ---------------------------------------------------------------------------
describe("H4 — a profile can be bound by id, which a rename cannot break", function()
  it("profile_id is sent when configured", function()
    local r = H.run{ config = H.cfg.base{ profile_id = "e4c2f1a0-1111-2222-3333-444455556666" },
                     request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow"}, {action="allow"} } }
    expect.eq(H.scan(r).ai_profile.profile_id, "e4c2f1a0-1111-2222-3333-444455556666")
  end)

  it("name is still sent when no id is configured", function()
    local r = H.run{ config = H.cfg.base(),
                     request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow"}, {action="allow"} } }
    expect.eq(H.scan(r).ai_profile.profile_name, "Themis-Block-All")
    expect.nil_(H.scan(r).ai_profile.profile_id)
  end)

  it("a per-request claim still wins over a statically configured id", function()
    local r = H.run{
      config = H.cfg.base{ profile_id = "static-id", profile_claim = "risk_tier",
                           profile_claim_map = { low = "Permissive" },
                           fallback_profile_name = "Strict" },
      request = { body = H.body.chat{{"user","hi"}},
                  headers = { authorization = H.bearer{ risk_tier = "low" } } },
      upstream = { body = H.body.openai_response("ok") },
      airs = { {action="allow"}, {action="allow"} },
    }
    expect.eq(H.scan(r).ai_profile.profile_name, "Permissive")
    expect.nil_(H.scan(r).ai_profile.profile_id,
                "an id and a name naming different profiles is ambiguous; the claim is the specific one")
  end)
end)

-- ---------------------------------------------------------------------------
describe("H5 — AIRS DLP masking must actually reach the client", function()
  local masked_allow = {
    action = "allow", category = "benign",
    prompt_masked_data   = { data = "my card is ****-****-****-1111" },
    response_masked_data = { data = "your card ending 1111 is active" },
  }

  it("is off by default — silently rewriting bodies is not a default", function()
    local r = H.run{ config = H.cfg.base(),
                     request = { body = H.body.chat{{"user","my card is 4111-1111-1111-1111"}} },
                     upstream = { body = H.body.openai_response("your card 4111-1111-1111-1111 is active") },
                     airs = { masked_allow, masked_allow } }
    expect.nil_(r.state.upstream_body)
    expect.nil_(r.state.set_body)
  end)

  it("the masked prompt replaces what goes upstream", function()
    local r = H.run{ config = H.cfg.base{ apply_dlp_masking = true },
                     request = { body = H.body.chat{{"user","my card is 4111-1111-1111-1111"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { masked_allow, {action="allow"} } }
    expect.truthy(r.state.upstream_body, "the model was still being sent the raw PAN")
    expect.contains(r.state.upstream_body, "****-****-****-1111")
    expect.not_contains(r.state.upstream_body, "4111-1111-1111-1111")
  end)

  it("the masked response replaces what goes back to the caller", function()
    local r = H.run{ config = H.cfg.base{ apply_dlp_masking = true },
                     request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("your card 4111-1111-1111-1111 is active") },
                     airs = { {action="allow"}, masked_allow } }
    expect.truthy(r.state.set_body, "SCM showed a successful mask while Kong discarded the redacted text")
    expect.contains(r.state.set_body, "ending 1111")
    expect.not_contains(r.state.set_body, "4111-1111-1111-1111")
  end)

  it("the envelope survives — only the content field is substituted", function()
    local r = H.run{ config = H.cfg.base{ apply_dlp_masking = true },
                     request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("your card 4111-1111-1111-1111 is active") },
                     airs = { {action="allow"}, masked_allow } }
    local decoded = cjson.decode(r.state.set_body)
    expect.truthy(decoded.choices, "a client parsing the OpenAI envelope must still find it")
    expect.eq(decoded.choices[1].message.content, "your card ending 1111 is active")
  end)

  it("no masked data means no mutation — never blank the body", function()
    local r = H.run{ config = H.cfg.base{ apply_dlp_masking = true },
                     request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("nothing sensitive here") },
                     airs = { {action="allow"}, {action="allow"} } }
    expect.nil_(r.state.set_body)
  end)

  it("masking is recorded, so a mutated body is never a silent one", function()
    local r = H.run{ config = H.cfg.base{ apply_dlp_masking = true },
                     request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("your card 4111-1111-1111-1111 is active") },
                     airs = { {action="allow"}, masked_allow } }
    expect.eq(r.serialize.airs.scans[2].masked, true)
  end)
end)

-- ---------------------------------------------------------------------------
describe("H6 — protocols must not advertise what buffering cannot do", function()
  for _, which in ipairs({ "v2", "v1" }) do
    it(which .. ": uses the http-only typedef rather than the all-protocols one", function()
      -- Structural, and deliberately NOT read through the typedefs mock: the
      -- mock defines what protocols_http contains, so asserting its contents
      -- would only prove the mock agrees with itself. Which typedef the source
      -- names is a fact the mock cannot fake.
      local src = io.open("plugin/prisma-airs-intercept" ..
                          (which == "v1" and "-postproxy" or "") .. "/schema.lua"):read("*a")
      expect.contains(src, "typedefs.protocols_http",
                      "implementing a response phase forces buffered proxying, which Kong " ..
                      "states does not work for HTTP/2 or gRPC upstreams -- yet the Plugin " ..
                      "Hub page advertises them")
      expect.not_contains(src, "typedefs.protocols ")
    end)

    it(which .. ": and that typedef resolves to http and https only", function()
      local schema = H.schema(which)
      local protocols
      for _, entry in ipairs(schema.fields) do
        if entry.protocols then protocols = entry.protocols end
      end
      expect.truthy(protocols, "a protocols field must be declared")
      local allowed = {}
      for _, p in ipairs(protocols.elements and protocols.elements.one_of or {}) do allowed[p] = true end
      expect.falsy(allowed.grpc,
                   "implementing a response phase forces buffered proxying, which Kong states " ..
                   "does not work for HTTP/2 or gRPC upstreams")
      expect.falsy(allowed.grpcs)
      expect.truthy(allowed.http and allowed.https)
    end)
  end
end)

-- ---------------------------------------------------------------------------
describe("H3/H4 on the v1 lineage", function()
  it("v1 also validates api_endpoint, and also refuses plaintext http", function()
    local fields = H.config_fields("v1")
    local pattern = fields.api_endpoint.match
    expect.truthy(pattern)
    expect.truthy(string.match(fields.api_endpoint.default, pattern))
    expect.falsy(string.match("http://service.api.aisecurity.paloaltonetworks.com/v1/scan", pattern))
  end)

  it("v1 can bind a profile by id too", function()
    local r = H.run{ plugin = "v1", config = H.cfg.base{ profile_id = "abc-123" },
                     request = { body = H.body.chat{{"user","hi"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow"}, {action="allow"} } }
    expect.eq(H.scan(r).ai_profile.profile_id, "abc-123")
    expect.nil_(H.scan(r).ai_profile.profile_name)
  end)
end)

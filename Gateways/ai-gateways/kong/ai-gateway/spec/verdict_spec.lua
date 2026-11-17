-- Offline assertions for the guardrail functions. No gateway, no network, no
-- AIRS tenant: these run on the Lua exactly as it is inlined into the policy
-- YAML, so a drift between the file and the shipped config is a build failure
-- rather than something discovered in production.
--
-- Run with scripts/run-lua-tests.sh

local passed, failed = 0, 0
local function check(name, cond, why)
    if cond then
        passed = passed + 1
        print("  ok   " .. name)
    else
        failed = failed + 1
        print("  FAIL " .. name .. (why and ("  -- " .. why) or ""))
    end
end
local function section(s) print("\n" .. s) end

local verdict   = assert(loadfile("lua/guardrail/airs_verdict.lua"))()
local contents  = assert(loadfile("lua/guardrail/airs_contents.lua"))()
local metadata  = assert(loadfile("lua/guardrail/airs_metadata.lua"))()
local profile   = assert(loadfile("lua/guardrail/airs_profile.lua"))()

-- ---------------------------------------------------------------------------
section("the ordinary verdicts")

local v = verdict{ action = "allow", category = "benign", scan_id = "s-1" }
check("a clean allow passes", v.block == false)
check("an allow carries no message", v.block_message == "")

v = verdict{ action = "block", category = "malicious", scan_id = "s-2",
             prompt_detected = { injection = true, url_cats = false } }
check("a block blocks", v.block == true)
check("the block message is generic", v.block_message == "Blocked by Prisma AIRS [scan_id=s-2]")
check("the category never reaches the client", not v.block_message:find("malicious"))
check("the detector never reaches the client", not v.block_message:find("injection"))
check("the category reaches telemetry", v.detail:find("malicious") ~= nil)
check("the detector reaches telemetry", v.detail:find("injection") ~= nil)
check("a detector that did NOT fire is not reported", v.detail:find("url_cats") == nil)

-- ---------------------------------------------------------------------------
section("partial scan failure")

-- AIRS returns these WITH action=allow. A verdict function that keys only on
-- action, or only on category, reads every one of these as a clean pass.
v = verdict{ action = "allow", category = "benign", scan_id = "s-3", error = true }
check("allow + error=true BLOCKS", v.block == true,
      "a detector failed; the scan did not say safe, it said it could not finish")

v = verdict{ action = "allow", category = "benign", scan_id = "s-4", timeout = true }
check("allow + timeout=true BLOCKS", v.block == true)

v = verdict{ action = "allow", category = "benign", scan_id = "s-5",
             errors = { { content_type = "prompt", feature = "dlp", status = "timeout" } } }
check("allow + a populated errors[] BLOCKS", v.block == true)
check("the degraded detector is named in telemetry", v.detail:find("dlp/timeout") ~= nil)
check("the degraded detector is NOT named to the client", not v.block_message:find("dlp"))

v = verdict{ action = "allow", category = "benign", error = false, timeout = false, errors = {} }
check("error=false / timeout=false / empty errors[] is a clean pass", v.block == false,
      "false must read as clean or every healthy scan blocks")

v = verdict{ action = "allow", category = "benign", error = "upstream failure" }
check("a non-boolean error field still BLOCKS", v.block == true,
      "a field arriving as a string must not read as no-problem")

v = verdict{ action = "allow", category = "error" }
check("the legacy category=error signal still BLOCKS", v.block == true)

-- ---------------------------------------------------------------------------
section("nothing unrecognised is ever a pass")

check("a nil response blocks",            verdict(nil).block == true)
check("a non-table response blocks",      verdict(42).block == true)
check("an empty table blocks",            verdict({}).block == true)
check("a non-string action blocks",       verdict{ action = true }.block == true)
check("a wrongly-cased ALLOW blocks",     verdict{ action = "ALLOW" }.block == true,
      "an action this function does not know is not a pass")
check("an unknown action blocks",         verdict{ action = "quarantine" }.block == true)
check("an unknown action says so in telemetry",
      verdict{ action = "quarantine" }.detail:find("unrecognised") ~= nil)

-- ---------------------------------------------------------------------------
section("the profile owner's choice is respected")

-- An AIRS profile in alert-only mode returns allow alongside a malicious
-- category. That is the profile exercising a choice, not a gateway error.
v = verdict{ action = "allow", category = "malicious", scan_id = "s-6",
             prompt_detected = { injection = true } }
check("allow + category=malicious passes", v.block == false,
      "the gateway enforces the verdict AIRS returns; it does not overrule the profile")

-- ---------------------------------------------------------------------------
section("detectors we have never heard of")

v = verdict{ action = "block", category = "malicious",
             tool_detected = { tool_definition_poisoning = true },
             response_detected = { some_future_detector = true } }
check("tool_detected is read",   v.detail:find("tool_definition_poisoning") ~= nil)
check("an unknown detector is reported, not filtered", v.detail:find("some_future_detector") ~= nil)

-- ---------------------------------------------------------------------------
section("the string branch that is inactive today")

local ok_cjson, cjson = pcall(require, "cjson")
if ok_cjson then
    v = verdict(cjson.encode{ action = "block", category = "malicious", scan_id = "s-7" })
    check("a JSON string response is decoded and honoured", v.block == true)
    v = verdict("this is not json")
    check("an undecodable string blocks", v.block == true)
else
    print("  skip cjson not available; string-branch cases not run")
end

-- ---------------------------------------------------------------------------
section("contents: the phase switch and its guards")

local c = contents("INPUT", "hello")
check("INPUT builds contents[].prompt",   c[1].prompt == "hello" and c[1].response == nil)
c = contents("OUTPUT", "the answer")
check("OUTPUT builds contents[].response", c[1].response == "the answer" and c[1].prompt == nil)

check("a non-string content raises", select(1, pcall(contents, "INPUT", { conf = "table" })) == false,
      "a permissive fallback would ship the conf table to AIRS")
check("an empty extraction raises",  select(1, pcall(contents, "INPUT", "")) == false,
      "AIRS would allow an empty string and the gap would record as a clean scan")
check("an unknown phase raises",     select(1, pcall(contents, "SIDEWAYS", "hi")) == false)

local _, err = pcall(contents, "INPUT", { secret = "value" })
check("the raised message carries no configuration value", tostring(err):find("value") == nil,
      "guardrail error text reaches the client verbatim")

-- ---------------------------------------------------------------------------
section("profile and metadata read only what the operator set")

check("profile_name comes from config", profile({ params = { profile = "p" } }).profile_name == "p")

local md = metadata{ params = { app_name = "kong-ai-gateway" } }
check("app_name is sent", md.app_name == "kong-ai-gateway")
check("app_user is omitted when unset", md.app_user == nil,
      "a fabricated user in a security log is worse than no user")
md = metadata{ params = { app_name = "a", app_user = "", ai_model = "gpt-4o" } }
check("an empty app_user is omitted", md.app_user == nil)
check("ai_model is sent when set", md.ai_model == "gpt-4o")

-- ---------------------------------------------------------------------------
print(string.format("\n%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)

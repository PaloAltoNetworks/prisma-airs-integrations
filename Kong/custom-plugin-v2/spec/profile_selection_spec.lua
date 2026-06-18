-- Unit test for claim-based profile selection in handler.lua (._profile helpers).
-- Loads the REAL handler with the two Kong deps stubbed, so it exercises the
-- shipped code, not a copy. Runnable with plain Lua:
--   cd Kong/custom-plugin-v2 && lua spec/profile_selection_spec.lua
-- (Pure helpers only; no Kong/ngx runtime needed beyond base64/json.)

-- ---- base64 (standard) shim for ngx.encode_base64 / ngx.decode_base64 ----
local B = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function b64enc(d)
  return ((d:gsub('.', function(x)
    local r, c = '', x:byte()
    for i = 8, 1, -1 do r = r .. (c % 2 ^ i - c % 2 ^ (i - 1) > 0 and '1' or '0') end
    return r
  end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
    if #x < 6 then return '' end
    local c = 0
    for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2 ^ (6 - i) or 0) end
    return B:sub(c + 1, c + 1)
  end) .. ({ '', '==', '=' })[#d % 3 + 1])
end
local function b64dec(d)
  d = d:gsub('[^' .. B .. '=]', '')
  return (d:gsub('.', function(x)
    if x == '=' then return '' end
    local r, f = '', (B:find(x) - 1)
    for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0') end
    return r
  end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
    if #x ~= 8 then return '' end
    local c = 0
    for i = 1, 8 do c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0) end
    return string.char(c)
  end))
end

-- ---- minimal JSON decoder for the cjson stub ----
local function json_decode(s)
  if type(s) ~= "string" then return nil end
  local i, pv = 1, nil
  local function sk() while i <= #s and s:sub(i, i):match("%s") do i = i + 1 end end
  local function ps()
    i = i + 1; local b = {}
    while i <= #s do
      local c = s:sub(i, i)
      if c == '"' then i = i + 1; return table.concat(b) end
      if c == '\\' then b[#b + 1] = s:sub(i + 1, i + 1); i = i + 2
      else b[#b + 1] = c; i = i + 1 end
    end
    error("unterminated")
  end
  local function po()
    local o = {}; i = i + 1; sk()
    if s:sub(i, i) == '}' then i = i + 1; return o end
    while true do
      sk(); local k = ps(); sk(); assert(s:sub(i, i) == ':'); i = i + 1
      o[k] = pv(); sk(); local c = s:sub(i, i); i = i + 1
      if c == '}' then return o end; assert(c == ',')
    end
  end
  pv = function()
    sk(); local c = s:sub(i, i)
    if c == '"' then return ps()
    elseif c == '{' then return po()
    elseif c == 't' then i = i + 4; return true
    elseif c == 'f' then i = i + 5; return false
    elseif c == 'n' then i = i + 4; return nil
    else
      local n = s:match("^%-?%d+%.?%d*", i); assert(n and #n > 0); i = i + #n; return tonumber(n)
    end
  end
  local ok, r = pcall(pv); if not ok then return nil end; return r
end

-- ---- stub the handler's two require()d deps, then load the REAL handler ----
package.loaded["resty.http"] = {}
package.loaded["cjson"] = { decode = json_decode, encode = function() return "{}" end }
_G.ngx = { encode_base64 = b64enc, decode_base64 = b64dec }
_G.kong = { ctx = { shared = {} }, request = {}, service = { request = {} } }

local handler = dofile("handler.lua")
local resolve = handler._profile.resolve
assert(type(resolve) == "function", "handler._profile.resolve missing")

local function b64url(s) return (b64enc(s):gsub('%+', '-'):gsub('/', '_'):gsub('=', '')) end
local function tok(json) return "Bearer " .. b64url('{"alg":"RS256"}') .. "." .. b64url(json) .. ".sig" end

local conf = {
  profile_name = "default-baseline",
  profile_claim = "risk_tier",
  profile_claim_map = { high = "strict-production", medium = "default-baseline", low = "flexible-internal" },
  fallback_profile_name = "strict-production",
}

local cases = {
  { "high -> strict",                 conf, tok('{"risk_tier":"high"}'),  "strict-production" },
  { "low -> flexible",                conf, tok('{"risk_tier":"low"}'),   "flexible-internal" },
  { "medium -> baseline",             conf, tok('{"risk_tier":"medium"}'),"default-baseline" },
  { "unmapped -> fail closed",        conf, tok('{"risk_tier":"xyz"}'),   "strict-production" },
  { "no auth header -> fail closed",  conf, nil,                          "strict-production" },
  { "garbage token -> fail closed",   conf, "Bearer garbage",            "strict-production" },
  { "direct mode (no map)",
    { profile_name = "d", profile_claim = "airs_profile" }, tok('{"airs_profile":"pii-only"}'), "pii-only" },
  { "legacy static (no claim cfg)",
    { profile_name = "chatbot" }, tok('{"risk_tier":"high"}'),            "chatbot" },
}

local pass, fail = 0, 0
print("=========== handler._profile.resolve (real handler.lua) ===========")
for _, c in ipairs(cases) do
  local got, src = resolve(c[2], c[3])
  local ok = got == c[4]
  print(string.format("[%s] %-32s want=%-18s got=%-18s (%s)",
    ok and "PASS" or "FAIL", c[1], c[4], tostring(got), tostring(src)))
  if ok then pass = pass + 1 else fail = fail + 1 end
end
print("-------------------------------------------------------------------")
print(string.format("RESULTS: %d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)

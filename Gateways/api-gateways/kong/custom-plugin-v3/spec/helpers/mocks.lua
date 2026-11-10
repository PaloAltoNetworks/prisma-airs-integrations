-- Kong PDK / OpenResty / resty.http mocks.
--
-- Fidelity rules this file lives by:
--   * kong.response.exit() must NOT return. Real Kong terminates the request
--     there; several defects are precisely about code that runs after a guard,
--     so a mock that returns would hide them. We raise a tagged table and the
--     harness catches it.
--   * A genuine Lua error must stay distinguishable from an exit. That
--     difference IS the 500-vs-403 taxonomy we are testing.
--   * cjson is the REAL library. Its raise-on-error behaviour and the truthy
--     cjson.null lightuserdata are load-bearing in the code under test.

local M = {}

local EXIT = {}
M.EXIT = EXIT

local function is_exit(e)
  return type(e) == "table" and e.__kong_exit == EXIT
end
M.is_exit = is_exit

-- ---------------------------------------------------------------------------
-- resty.http
-- ---------------------------------------------------------------------------
-- opts.airs is a list consumed in order, one entry per outbound scan:
--   {action="allow"}                      -> 200 with that AIRS body
--   {status=401, body="..."}              -> raw HTTP response
--   {transport="timeout"}                 -> request_uri returns nil, "timeout"
--   {raw="not json"}                      -> 200 whose body is not JSON
-- The handler does `local http = require("resty.http")` at MODULE scope, so a
-- reused module instance (M.worker) captures whatever object was installed on
-- its first load. The mock therefore has to be ONE stable module that dispatches
-- to the run currently in flight -- exactly as the real library is one stable
-- module serving every request in a worker.
local current

-- kong.cache is NODE level in a real gateway: one shared dict per worker,
-- surviving every request that worker handles. A per-request mock would make a
-- verdict cache look like it worked while never actually returning a hit, so
-- the store lives at module scope and tests reset it explicitly.
local cache_store = {}
local cache_stats = { hits = 0, misses = 0 }

local function reset_cache()
  cache_store = {}
  cache_stats = { hits = 0, misses = 0 }
end

local client = {}
client.__index = client

function client:set_timeout(ms)
  local state = current
  state.timeouts[#state.timeouts + 1] = { all = ms }
end

function client:set_timeouts(c, s, r)
  local state = current
  state.timeouts[#state.timeouts + 1] = { c = c, s = s, r = r }
end

function client:set_keepalive()
  current.keepalive = current.keepalive + 1
  return 1
end

function client:close() end

function client:request_uri(url, opts)
  local state = current
  local scripted = state.scripted
  state.airs_idx = state.airs_idx + 1
  local idx = state.airs_idx
  do
    local cjson = require("cjson")
    local decoded
    local ok, res = pcall(cjson.decode, opts.body or "")
    if ok then decoded = res end
    state.scans[#state.scans + 1] = {
      url = url,
      method = opts.method,
      headers = opts.headers or {},
      raw_body = opts.body,
      body = decoded,          -- nil if the plugin sent something undecodable
      ssl_verify = opts.ssl_verify,
    }

    local s = scripted[idx]
    if s == nil then
      -- Unscripted call: default allow, but record it so a test can notice.
      state.unscripted = state.unscripted + 1
      return { status = 200, body = cjson.encode({ action = "allow", category = "benign",
                                                   scan_id = "unscripted-" .. idx }) }
    end
    if s.transport then return nil, s.transport end
    if s.raw ~= nil then return { status = s.status or 200, body = s.raw } end
    if s.status and s.status ~= 200 then return { status = s.status, body = s.body or "" } end

    local payload = {}
    for k, v in pairs(s) do payload[k] = v end
    payload.status, payload.transport, payload.raw = nil, nil, nil
    if payload.scan_id == nil then payload.scan_id = "scan-" .. idx end
    return { status = 200, body = cjson.encode(payload) }
  end
end

local http_module = {
  new = function() return setmetatable({}, client) end,
}

-- ---------------------------------------------------------------------------
-- ngx
-- ---------------------------------------------------------------------------
local function b64(s)
  local c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  return ((s:gsub('...', function(x)
    local r, b = '', x:byte(1) * 65536 + x:byte(2) * 256 + x:byte(3)
    for _ = 1, 4 do r = r .. c:sub((math.floor(b / 262144) % 64) + 1, (math.floor(b / 262144) % 64) + 1); b = b * 64 % 16777216 end
    return r
  end)) .. ({ '', '==', '=' })[#s % 3 + 1])
end

local function unb64(data)
  local c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  data = string.gsub(data, '[^' .. c .. '=]', '')
  if data == "" then return "" end
  return (data:gsub('=', ''):gsub('.', function(x)
    local r, f = '', (c:find(x) - 1)
    for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0') end
    return r
  end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
    if #x ~= 8 then return '' end
    local ch = 0
    for i = 1, 8 do ch = ch + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0) end
    return string.char(ch)
  end))
end

local function make_ngx(state)
  return {
    ctx = state.ngx_ctx,
    var = { request_id = state.request_id },
    -- A clock the test controls. The circuit breaker's cooldown is a wall-clock
    -- window; os.clock() is CPU time and cannot be advanced deliberately.
    now = function() return state.clock end,
    encode_base64 = b64,
    decode_base64 = function(s) local ok, r = pcall(unb64, s); return ok and r or nil end,
    null = nil,
    log = function() end,
    ERR = 4, WARN = 5, INFO = 7, DEBUG = 8,
  }
end

-- ---------------------------------------------------------------------------
-- kong
-- ---------------------------------------------------------------------------
local function make_kong(state, opts)
  local req = opts.request or {}
  local up = opts.upstream or {}

  local function log(level)
    return function(...)
      local parts = {}
      for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
      state.logs[#state.logs + 1] = { level = level, msg = table.concat(parts) }
    end
  end

  local k = {}
  -- kong.ctx.plugin is per-request AND per-plugin-instance; kong.ctx.shared is
  -- visible to every plugin on the request. Keeping them distinct is the whole
  -- point of G6, so the mock must not conflate them.
  k.ctx = { shared = state.shared, plugin = state.plugin_ctx }

  k.log = {
    debug = log("debug"), info = log("info"), notice = log("notice"),
    warn = log("warn"), err = log("err"), crit = log("crit"),
    set_serialize_value = function(key, val)
      state.serialize[key] = val
    end,
  }

  k.request = {
    -- Real signature: get_body([mimetype[, max_args[, max_allowed_file_size]]]).
    -- req.body_spill_bytes models Kong's actual behaviour above
    -- client_body_buffer_size: nginx writes the body to a temp file and the PDK
    -- refuses to read it unless max_allowed_file_size permits.
    get_body = function(_mimetype, _max_args, max_allowed_file_size)
      if req.body_error then return nil, req.body_error end
      local spill = req.body_spill_bytes
      if spill then
        state.body_read_limit = max_allowed_file_size
        if not max_allowed_file_size or max_allowed_file_size < spill then
          return nil, "request body did not fit into client body buffer, consider raising 'client_body_buffer_size'"
        end
      end
      return req.body
    end,
    get_raw_body = function() return req.raw_body end,
    get_header = function(name) return (req.headers or {})[string.lower(name)] end,
    get_headers = function() return req.headers or {} end,
    get_method = function() return req.method or "POST" end,
    get_path = function() return req.path or "/" end,
    get_id = function() return state.pdk_request_id end,
  }

  k.response = {
    exit = function(status, body, headers)
      error({ __kong_exit = EXIT, status = status, body = body, headers = headers }, 0)
    end,
    get_status = function() return up.status or 200 end,
    get_header = function(name) return (up.headers or {})[string.lower(name)] end,
    get_raw_body = function()
      if up.pdk_body_unavailable then error("response body not available in this phase", 0) end
      return up.body
    end,
    set_header = function(n, v) state.resp_headers[string.lower(n)] = v end,
    set_raw_body = function(b) state.set_body = b end,
  }

  k.service = {
    request = {
      enable_buffering = function() state.buffering = true end,
      set_header = function(n, v) state.upstream_headers[string.lower(n)] = v end,
      clear_header = function(n) state.upstream_headers[string.lower(n)] = nil end,
      set_raw_body = function(b) state.upstream_body = b end,
    },
    response = {
      get_status = function() return up.status or 200 end,
      get_header = function(name) return (up.headers or {})[string.lower(name)] end,
      get_raw_body = function() return up.service_body ~= nil and up.service_body or up.body end,
    },
  }

  k.router = {
    get_service = function() return opts.service or { name = "airs-svc", id = "svc-1" } end,
    get_route   = function() return opts.route   or { name = "airs-route", id = "rt-1" } end,
  }

  k.client = {
    get_consumer = function() return opts.consumer end,
    get_credential = function() return opts.credential end,
    get_forwarded_ip = function() return opts.client_ip or "203.0.113.9" end,
  }

  -- Real signature: kong.cache:get(key, opts, cb, ...) -> value, err, hit_level.
  -- ttl comes from opts.ttl; a negative/zero ttl means "do not cache".
  k.cache = {
    get = function(_self, key, cache_opts, cb, ...)
      local entry = cache_store[key]
      local now = state.clock
      if entry and (entry.expires == nil or entry.expires > now) then
        cache_stats.hits = cache_stats.hits + 1
        state.cache_hits = (state.cache_hits or 0) + 1
        -- A negative hit answers nil WITHOUT running the callback, exactly as
        -- mlcache does. The handler must then fall through and re-scan.
        return entry.value, nil, 1
      end
      cache_stats.misses = cache_stats.misses + 1
      state.cache_misses = (state.cache_misses or 0) + 1
      state.cache_opts = cache_opts
      local value, err = cb(...)
      if err then return nil, err end
      local ttl = cache_opts and cache_opts.ttl
      if value ~= nil then
        if ttl and ttl > 0 then
          cache_store[key] = { value = value, expires = now + ttl }
        end
      else
        -- Real kong.cache is mlcache: a callback returning nil is a NEGATIVE
        -- hit and IS written, under neg_ttl. The mock used to store nothing, so
        -- "a block is never cached" was green for a reason the production code
        -- does not have, and the negative-hit -> fallback path in the handler
        -- was never exercised at all.
        local neg = cache_opts and cache_opts.neg_ttl
        if neg and neg > 0 then
          cache_store[key] = { value = nil, negative = true, expires = now + neg }
        end
      end
      return value, nil, 3
    end,
    invalidate = function(_self, key) cache_store[key] = nil end,
  }

  k.nginx = { get_subsystem = function() return "http" end }

  return k
end

-- ---------------------------------------------------------------------------
function M.build(opts)
  local state = {
    scans = {}, logs = {}, timeouts = {}, keepalive = 0, unscripted = 0,
    shared = opts.shared or {}, ngx_ctx = opts.ngx_ctx or {}, plugin_ctx = {},
    resp_headers = {},
    -- Seeded from the CLIENT's headers, because that is what Kong forwards
    -- unless a plugin changes it. It used to start empty, so
    -- kong.service.request.clear_header() removed a key that was never there
    -- and a test asserting "the spoofed header does not reach upstream" passed
    -- whether or not the plugin cleared anything — including the F1 case this
    -- mock exists to make checkable.
    upstream_headers = (function()
      local h, req = {}, opts.request or {}
      for k, v in pairs(req.headers or {}) do h[string.lower(k)] = v end
      return h
    end)(),
    serialize = {},
    request_id = opts.request_id or "ngxreq0000000000000000000000000a",
    pdk_request_id = opts.pdk_request_id or "pdk-req-1111",
    clock = opts.clock or 1000.0,
    scripted = opts.airs or {},
    airs_idx = 0,
  }
  current = state
  -- v1 reads Kong's internal ngx.ctx.buffered_body; v2 uses the PDK. Populate
  -- both from the same upstream body so a spec does not have to know which
  -- mechanism the plugin under test happens to use.
  local up = opts.upstream or {}
  if up.buffered_body ~= nil then
    state.ngx_ctx.buffered_body = up.buffered_body
  elseif not up.pdk_body_unavailable then
    state.ngx_ctx.buffered_body = up.body
  end
  return state, make_kong(state, opts), make_ngx(state), http_module
end

-- ---------------------------------------------------------------------------
-- resty.sha256
-- ---------------------------------------------------------------------------
-- The real module is OpenResty's FFI binding to OpenSSL and cannot load under
-- plain LuaJIT, so the suite supplies the same streaming interface
-- (new / update / final) over a deterministic digest.
--
-- IT IS NOT CRYPTOGRAPHIC and must never be mistaken for one. What it lets the
-- suite verify is the part that lives in OUR code and can actually be wrong:
-- that the cache key COMPOSES profile + separator + content, so two profiles or
-- two bodies cannot collide. The strength of the digest itself is OpenSSL's
-- problem, and the plugin's behaviour when the module is genuinely absent
-- (refuse to cache rather than fall back to a weaker hash) is pinned by its own
-- test in spec/k_audit_spec.lua.
local sha256_mock = {}
sha256_mock.__index = sha256_mock

function sha256_mock:new()
  return setmetatable({ buf = {} }, sha256_mock)
end

function sha256_mock:update(chunk)
  self.buf[#self.buf + 1] = tostring(chunk)
  return true
end

function sha256_mock:final()
  local data = table.concat(self.buf)
  -- FNV-1a over four offset streams -> 32 deterministic bytes. Distinct inputs
  -- give distinct outputs for every case the suite exercises.
  local out = {}
  -- `h ~ byte` is Lua 5.3 syntax. This suite runs on LuaJIT (Lua 5.1 semantics,
  -- same as Kong), .luacheckrc declares std = "luajit", and CI installs stock
  -- luajit — on a build without the partial 5.3 operator set this file is a
  -- COMPILE error and spec/all.lua's dofile of every spec fails, not just the
  -- cache cases. Use the bit library LuaJIT and Kong actually ship.
  local bxor = bit and bit.bxor or require("bit").bxor
  for stream = 0, 3 do
    local h = 2166136261 + stream * 16777619
    for i = 1, #data do
      h = bxor(h, string.byte(data, i)) % 4294967296
      -- Reduced BEFORE the multiply: `(h * 16777619) % 2^32` on a value near
      -- 2^32 reaches ~6.7e16 in doubles, past 2^53, so the low bits were rounded
      -- away before the modulo could see them. Split the multiply so every
      -- partial product stays exact.
      local lo = h % 65536
      local hi = (h - lo) / 65536
      h = ((lo * 16777619) + ((hi * 16777619) % 65536) * 65536) % 4294967296
    end
    for shift = 0, 7 do
      out[#out + 1] = string.char(math.floor(h / (2 ^ (shift * 4))) % 256)
    end
  end
  return table.concat(out)
end

-- Tests that assert on cache behaviour reset the node-level store first.
M.reset_cache = reset_cache
M.sha256 = sha256_mock

return M

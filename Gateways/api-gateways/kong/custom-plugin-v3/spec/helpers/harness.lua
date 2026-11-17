-- Load a plugin handler against the mocks and drive its phases.
--
-- The handler is re-loaded from source for every run so module-level state
-- (the JWT token cache, for one) never leaks between tests.

local mocks = require("spec.helpers.mocks")

local M = {}

local ROOT = os.getenv("KAP_ROOT") or "."
local PLUGINS = {
  v2 = ROOT .. "/plugin/prisma-airs-intercept/handler.lua",
  v1 = ROOT .. "/plugin/prisma-airs-intercept-postproxy/handler.lua",
}

-- Run one request through access (and response, unless access exited).
--
-- opts:
--   plugin    "v2" | "v1"                (default "v2")
--   config    plugin config table
--   request   { body=, raw_body=, headers=, method= , body_error= }
--   upstream  { status=, body=, headers=, service_body=, buffered_body= }
--   airs      list of scripted AIRS responses, in call order
--   only      "access" | "response"      (default: both)
--
-- returns a result table:
--   .exit      { status, body }          the kong.response.exit that halted us
--   .error     string                    an UNCAUGHT Lua error, i.e. a real 500
--   .phase     which phase produced .exit/.error
--   .scans     outbound AIRS calls, decoded
--   .logs      captured log lines
--   .shared    kong.ctx.shared after the run
--   .resp_headers / .upstream_headers / .serialize
function M.run(opts)
  opts = opts or {}
  local which = opts.plugin or "v2"
  -- opts.handler points at a fixture, so harness guarantees can be asserted
  -- without depending on a defect in the real plugins.
  local path = opts.handler or PLUGINS[which] or error("unknown plugin: " .. tostring(which))

  local state, kong_mock, ngx_mock, http_mock = mocks.build(opts)

  local saved_kong, saved_ngx = _G.kong, _G.ngx
  local saved_http = package.loaded["resty.http"]
  local saved_sha = package.loaded["resty.sha256"]
  _G.kong, _G.ngx = kong_mock, ngx_mock
  package.loaded["resty.http"] = http_mock
  -- Kong bundles resty.sha256; plain LuaJIT does not have it. See the note on
  -- the mock: it exists to exercise cache-key COMPOSITION, not hash strength.
  -- opts.no_sha256 must UNSET it, not merely decline to set it: H.pure() installs
  -- the mock process-wide, so "don't install" would leave the previous one in
  -- place and the "no digest means no cache" case would silently test nothing.
  if opts.no_sha256 then package.loaded["resty.sha256"] = nil
  else package.loaded["resty.sha256"] = mocks.sha256 end

  local result = {
    scans = state.scans, logs = state.logs, shared = state.shared,
    plugin_ctx = state.plugin_ctx,
    resp_headers = state.resp_headers, upstream_headers = state.upstream_headers,
    serialize = state.serialize, timeouts = state.timeouts, state = state,
  }

  local function call(phase)
    -- opts.instance is a handler already loaded by M.worker(): module-level
    -- upvalues (the circuit breaker) survive across requests, which is exactly
    -- what a real nginx worker does. Without it, every run gets a fresh module.
    local handler = opts.instance
    if not handler then
      handler = assert(loadfile(path), "cannot load " .. path)()
      if opts.on_load then opts.on_load(handler); opts.instance = handler end
    end
    local fn = handler[phase]
    if not fn then return true end
    local ok, err = pcall(fn, handler, opts.config or {})
    if ok then return true end
    if mocks.is_exit(err) then
      result.exit = { status = err.status, body = err.body, headers = err.headers }
      result.phase = phase
      return false
    end
    result.error = tostring(err)
    result.phase = phase
    return false
  end

  -- One handler instance per phase mirrors Kong re-entering the same module;
  -- kong.ctx.shared is what actually carries state between them.
  local ran_access = true
  if opts.only ~= "response" then ran_access = call("access") end
  if ran_access and opts.only ~= "access" then call("response") end

  _G.kong, _G.ngx = saved_kong, saved_ngx
  package.loaded["resty.http"] = saved_http
  package.loaded["resty.sha256"] = saved_sha
  return result
end

-- One loaded handler driven over many requests, i.e. one nginx worker.
-- Per-worker state (the circuit breaker) is invisible to M.run, which reloads
-- the module every time on purpose.
function M.worker(which)
  -- Loading is deferred to the first request: the handler `require`s resty.http
  -- at module scope, and that mock only exists once M.run has installed it.
  local w = { plugin = which or "v2", handler = nil, clock = 1000.0 }
  function w:request(opts)
    opts = opts or {}
    opts.plugin = self.plugin
    opts.instance = self.handler
    opts.clock = self.clock
    opts.on_load = function(h) self.handler = h end
    return M.run(opts)
  end
  function w:advance(seconds) self.clock = self.clock + seconds; return self end
  return w
end

-- Drive the request-callout hooks.
--
-- They are statements, not modules: Kong loads each as a chunk in a sandbox
-- where `require` is unavailable, so they see only the `kong` and `ngx` globals
-- and the standard library. Running them the same way is the point — as JSON
-- strings inside a config file this logic was unreviewable, which is how a
-- fail-open survived in the flavor recommended for Konnect serverless.
--
-- opts:
--   request   { raw_body=, headers= }
--   callout   { status=, body= }   what AIRS answered (body may be a string or table)
--   consumer  passed through to kong.client.get_consumer
--   only      "request" | "response" | "upstream"
function M.callout(opts)
  opts = opts or {}
  local state, kong_mock, ngx_mock = mocks.build(opts)

  -- The plugin writes the scan payload into this structure; Kong populates it.
  state.shared.callouts = {
    airs_request_scan = {
      request = { params = { body = nil } },
      response = opts.callout,
    },
  }

  local saved_kong, saved_ngx = _G.kong, _G.ngx
  _G.kong, _G.ngx = kong_mock, ngx_mock

  local result = { logs = state.logs, shared = state.shared, state = state,
                   upstream_headers = state.upstream_headers }

  local HOOKS = { "request", "response", "upstream" }
  for _, hook in ipairs(HOOKS) do
    if not opts.only or opts.only == hook then
      local path = ROOT .. "/plugin/request-callout/hooks/" .. hook .. "_before.lua"
      local chunk = assert(loadfile(path), "cannot load " .. path)
      local ok, err = pcall(chunk)
      if not ok then
        if mocks.is_exit(err) then
          result.exit = { status = err.status, body = err.body }
        else
          result.error = tostring(err)
        end
        result.phase = hook
        break
      end
    end
  end

  _G.kong, _G.ngx = saved_kong, saved_ngx
  result.payload = state.shared.callouts.airs_request_scan.request.params.body
  return result
end

-- Load a plugin's schema as a real Lua table, so entity_checks and field
-- declarations can be asserted directly rather than pattern-matched out of the
-- source (which cannot see entity_checks and passes silently when a field moves).
function M.schema(which)
  local path = (PLUGINS[which or "v2"]):gsub("handler%.lua$", "schema.lua")
  local saved = package.loaded["kong.db.schema.typedefs"]
  package.loaded["kong.db.schema.typedefs"] = require("spec.helpers.typedefs")
  -- `ngx` is a global under OpenResty; entity_checks reference ngx.null to mean
  -- "this field is unset", which is the idiom Kong's own schemas use.
  local saved_ngx = _G.ngx
  _G.ngx = _G.ngx or { null = setmetatable({}, { __tostring = function() return "null" end }) }
  local ok, schema = pcall(assert(loadfile(path), "cannot load " .. path))
  _G.ngx = saved_ngx
  package.loaded["kong.db.schema.typedefs"] = saved
  assert(ok, schema)
  return schema
end

-- config fields as a name -> declaration map (the schema stores them as an
-- ordered list of single-key tables, which is awkward to assert against).
function M.config_fields(which)
  local schema = M.schema(which)
  for _, entry in ipairs(schema.fields) do
    if entry.config then
      local out = {}
      for _, f in ipairs(entry.config.fields) do
        for name, decl in pairs(f) do out[name] = decl end
      end
      return out, entry.config
    end
  end
  error("no config record in the schema")
end

-- Load a handler purely to read its declared metadata (PRIORITY, VERSION).
-- resty.http is required at module scope, so a stub has to exist even though no
-- request will be driven through it.
-- Load a handler's PURE exports with the mock environment installed, for the
-- helpers that need ngx/resty but no request. Cached: loading is the expensive
-- part and these functions hold no per-request state.
local pure_cache = {}
function M.pure(which)
  which = which or "v2"
  if pure_cache[which] then return pure_cache[which] end
  local _, kong_mock, ngx_mock, http_mock = mocks.build({})
  _G.kong = _G.kong or kong_mock
  _G.ngx = _G.ngx or ngx_mock
  package.loaded["resty.http"] = package.loaded["resty.http"] or http_mock
  package.loaded["resty.sha256"] = package.loaded["resty.sha256"] or mocks.sha256
  local m = assert(loadfile(PLUGINS[which], nil), "cannot load " .. PLUGINS[which])()
  pure_cache[which] = m
  return m
end

function M.meta(which)
  local path = PLUGINS[which or "v2"]
  local saved = package.loaded["resty.http"]
  package.loaded["resty.http"] = { new = function() return {} end }
  local ok, handler = pcall(assert(loadfile(path), "cannot load " .. path))
  package.loaded["resty.http"] = saved
  assert(ok, handler)
  return { PRIORITY = handler.PRIORITY, VERSION = handler.VERSION }
end

-- Convenience accessors used constantly in the specs -------------------------

function M.scan(res, n)
  return res.scans[n or 1] and res.scans[n or 1].body
end

function M.contents(res, n)
  local b = M.scan(res, n)
  return b and b.contents and b.contents[1]
end

function M.tool_event(res, n)
  local c = M.contents(res, n)
  return c and c.tool_event
end

function M.logged(res, needle)
  for _, l in ipairs(res.logs) do
    if string.find(l.msg, needle, 1, true) then return l end
  end
  return nil
end

function M.log_levels(res)
  local t = {}
  for _, l in ipairs(res.logs) do t[l.level] = (t[l.level] or 0) + 1 end
  return t
end

-- Bodies used across many specs ---------------------------------------------

M.body = {}

function M.body.chat(turns)
  local messages = {}
  for _, t in ipairs(turns) do
    messages[#messages + 1] = { role = t[1], content = t[2] }
  end
  return { model = "gpt-4o", messages = messages }
end

function M.body.openai_response(text)
  return require("cjson").encode({ choices = { { message = { role = "assistant", content = text } } } })
end

function M.body.mcp_call(tool, args, id)
  return { jsonrpc = "2.0", id = id or 1, method = "tools/call",
           params = { name = tool, arguments = args or {} } }
end

function M.body.mcp_result(payload, id)
  return require("cjson").encode({ jsonrpc = "2.0", id = id or 1, result = payload })
end

function M.body.sse(frames)
  local out = {}
  for _, f in ipairs(frames) do out[#out + 1] = "data: " .. f .. "\n\n" end
  out[#out + 1] = "data: [DONE]\n\n"
  return table.concat(out)
end

-- An UNSIGNED, self-minted bearer token. The plugin's decoder verifies no
-- signature, alg, exp, iss or aud by design — it relies on an auth plugin at
-- higher priority having done that. So this is precisely what a route with no
-- auth plugin hands the profile choice to, and it is the H2 threat in one line.
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64(data)
  return ((data:gsub('.', function(x)
    local r, b = '', x:byte()
    for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and '1' or '0') end
    return r
  end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
    -- The pattern must be variable-length: a fixed six leaves any tail bits in
    -- the output as literal '0' characters, which decode to garbage only for
    -- inputs whose length happens not to divide evenly.
    if #x < 6 then return '' end
    local c = 0
    for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2 ^ (6 - i) or 0) end
    return B64:sub(c + 1, c + 1)
  end) .. ({ '', '==', '=' })[#data % 3 + 1])
end

function M.bearer(claims)
  local payload = b64(require("cjson").encode(claims))
    :gsub("%+", "-"):gsub("/", "_"):gsub("=", "")
  return "Bearer eyJhbGciOiJub25lIn0." .. payload .. ".not-a-signature"
end

M.cfg = {}
function M.cfg.base(over)
  local c = {
    api_key = "test-key",
    profile_name = "Themis-Block-All",
    app_name = "unit",
    api_endpoint = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request",
    ssl_verify = true,
    debug = false,
    -- timeout_ms is deliberately absent: it no longer carries a schema default,
    -- so a config that does not mention it must land on the split defaults.
  }
  for k, v in pairs(over or {}) do c[k] = v end
  return c
end

return M

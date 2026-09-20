-- A deliberately small stand-in for the pieces of the Kong PDK the callout
-- hooks touch. It records rather than performs: kong.response.exit captures the
-- status and body instead of terminating, so a spec can assert on the exact
-- bytes an MCP client would receive.
local cjson = require("cjson.safe")

local M = {}

function M.new(opts)
    opts = opts or {}
    local k = {}
    k.ctx = { shared = { callouts = { airs_scan = {
        request  = { params = {} },
        response = opts.callout_response and { body = opts.callout_response } or nil,
    } } } }
    k.request = {
        get_body     = function() return opts.body end,
        get_raw_body = function() return opts.raw_body end,
        get_header   = function(n)
            local h = opts.headers or {}
            return h[n] or h[string.lower(n)]
        end,
        get_id       = function() return opts.request_id end,
    }
    k.log = { err = function() end, warn = function() end, info = function() end }
    k.exits = {}
    k.response = {
        exit = function(status, body)
            k.exits[#k.exits + 1] = { status = status, body = body }
            return nil
        end,
    }
    return k
end

-- ---------------------------------------------------------------------------
-- The guardrail half of the mock.
--
-- A guardrail function reaches the PDK from its own BODY rather than through an
-- injected argument, so these specs have to supply the globals `kong` and `ngx`
-- rather than pass a table in. What matters as much as the happy path is the
-- ABSENT path: MEASURED on AI Gateway 2.0.3, on the OUTPUT leg of a streamed
-- response there is no request context and these calls RAISE. An unguarded
-- raise there silently skips the scan for that segment, so every accessor below
-- raises when its value was not supplied -- that is what makes a removed pcall
-- show up as a failing assertion instead of a passing one.
--
-- opts:
--   headers     name -> value. Absent: kong.request.get_header RAISES.
--   body        the decoded request body. Absent: get_body RAISES.
--   ip          absent: kong.client.get_ip RAISES.
--   forwarded   absent: kong.client.get_forwarded_ip RAISES.
--   consumer    the consumer table. nil is a legitimate answer (no auth);
--               opts.no_consumer_api makes get_consumer RAISE instead.
--   ai_model    a name. Absent: ngx.ctx.ai_model is nil, so reading .name on it
--               raises the way it does on a stream.
--   request_id  absent: reading ngx.var.request_id RAISES.
--   shared      the kong.ctx.shared table. Absent: reading kong.ctx RAISES.
-- ---------------------------------------------------------------------------
local function absent()
    error("no request context", 0)
end

local function supplied(value)
    if value == nil then
        return absent
    end
    return function() return value end
end

function M.guardrail(opts)
    opts = opts or {}
    local k = {
        request = {
            get_body   = supplied(opts.body),
            get_header = opts.headers and function(name)
                             if type(name) ~= "string" then return nil end
                             return opts.headers[name]
                         end or absent,
        },
        client = {
            get_ip           = supplied(opts.ip),
            get_forwarded_ip = supplied(opts.forwarded),
            get_consumer     = opts.no_consumer_api and absent
                               or function() return opts.consumer end,
        },
    }
    if opts.shared == nil then
        k.ctx = setmetatable({}, { __index = absent })
    else
        k.ctx = { shared = opts.shared }
    end

    local n = {
        ctx = opts.ai_model and { ai_model = { name = opts.ai_model } } or {},
        var = opts.request_id and { request_id = opts.request_id }
              or setmetatable({}, { __index = absent }),
    }

    _G.kong, _G.ngx = k, n
    return k, n
end

-- Back to a data plane phase where nothing is reachable at all.
function M.no_context()
    _G.kong, _G.ngx = nil, nil
end

-- The by_lua files are scripts, not modules: they run for their side effects on
-- kong.ctx.shared. Swap the global, execute, restore.
function M.run(path, k)
    local prev = _G.kong
    _G.kong = k
    local chunk = assert(loadfile(path))
    local ok, err = pcall(chunk)
    _G.kong = prev
    return ok, err
end

M.cjson = cjson
return M

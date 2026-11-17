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

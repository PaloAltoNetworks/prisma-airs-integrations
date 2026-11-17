-- Fixture: a handler that terminates the request the way Kong does.
local H = { PRIORITY = 1, VERSION = "fixture" }
function H:access(_config)
  kong.response.exit(418, { message = "fixture exit" })
  error("unreachable: kong.response.exit must not return")
end
return H

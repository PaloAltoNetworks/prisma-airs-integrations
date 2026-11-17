-- Fixture: a handler that raises an uncaught Lua error in access.
-- Used to prove the harness reports a raise as .error (a real 500) and never
-- confuses it with kong.response.exit. Kept separate from the real plugins so
-- this guarantee does not evaporate the moment a plugin bug is fixed.
local H = { PRIORITY = 1, VERSION = "fixture" }
function H:access(_config)
  local t = nil
  return t.field          -- deliberate: index a nil value
end
return H

-- Entry point: load the runner, then every *_spec.lua in spec/, then run.
local runner = require("spec.runner")

local specs = {}
local p = io.popen('ls spec/*_spec.lua 2>/dev/null')
for line in p:lines() do specs[#specs + 1] = line end
p:close()
table.sort(specs)

local filter = arg and arg[1]
for _, f in ipairs(specs) do
  if not filter or string.find(f, filter, 1, true) then dofile(f) end
end

os.exit(runner.run_all() and 0 or 1)

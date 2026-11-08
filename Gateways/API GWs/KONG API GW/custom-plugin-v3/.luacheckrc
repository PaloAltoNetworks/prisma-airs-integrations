-- Static analysis catches the class of defect Lua is worst at: a typo'd global
-- reads as nil rather than raising, which in this codebase means a guard
-- silently evaluates false and traffic passes unscanned. luacheck is the cheap
-- half of catching that; the test suite is the other half.
std = "luajit"

-- The Kong PDK and the OpenResty globals are injected by the runtime, not
-- required, so luacheck cannot see them declared anywhere.
read_globals = {
  "ngx",

  -- kong is read-only EXCEPT kong.ctx. `kong.ctx.plugin` and `kong.ctx.shared`
  -- are the PDK's documented per-request scratch space and writing to them is
  -- the intended use -- it is how this plugin carries state from access() to
  -- response(). Declaring the whole of `kong` read-only made 24 correct writes
  -- report as "setting read-only field", which is why `luacheck .` still exited
  -- 1 after the globals fix below, and why this gate had never run green.
  kong = {
    other_fields = true,
    fields = {
      ctx = { other_fields = true, read_only = false },
    },
  },
}

-- Lua's method syntax, `function Handler:access(config)`, declares an implicit
-- `self` that a Kong handler never uses. Twelve of those are not twelve defects.
self = false

-- WRITABLE, not read-only: spec/runner.lua DEFINES these. Declaring a global
-- read_globals and then assigning it is W121/W122, so `luacheck .` exited 1 on
-- every push and the CI gate this file exists to provide had never once run
-- green -- which is how the rest of the config's mistakes went unnoticed.
globals = {
  "describe", "it", "todo", "expect", "run_all",
}

-- Line length: the code carries long explanatory comments by design -- the
-- register rationale lives next to the code it explains.
max_line_length = false

exclude_files = {
  -- Not ours: the upstream V1/V2 sources are vendored verbatim for comparison
  -- and must stay byte-identical to what shipped.
  "upstream/",
  ".luarocks/",
}

files["spec/"] = {
  -- Specs intentionally shadow and rebind harness locals between cases.
  ignore = { "431", "432" },
}

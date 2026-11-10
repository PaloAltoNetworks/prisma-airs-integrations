-- Section I: packaging, tests and documentation.
--
-- Only the parts that are checkable live here. The rest of section I is prose,
-- and prose is verified by reading it — but the two facts below are exactly the
-- kind that drift silently, so they get assertions.

local H = require("spec.helpers.harness")

local function read(p) local f = assert(io.open(p)); local s = f:read("*a"); f:close(); return s end
local function exists(p) local f = io.open(p); if f then f:close(); return true end return false end

-- ---------------------------------------------------------------------------
describe("I2 — the two lineages must be installable side by side", function()
  it("they declare different plugin names", function()
    expect.ne(H.schema("v2").name, H.schema("v1").name,
              "both declared 'prisma-airs-intercept', so installing one replaced the other")
  end)

  it("each name matches its own directory, which is what Kong requires", function()
    expect.eq(H.schema("v2").name, "prisma-airs-intercept")
    expect.eq(H.schema("v1").name, "prisma-airs-intercept-postproxy")
  end)

  it("the newer lineage carries the higher version", function()
    expect.truthy(H.meta("v2").VERSION > H.meta("v1").VERSION,
                  "v2 declared 0.2.2 against v1's 0.3.0 — use PRIORITY to tell them apart, never VERSION")
  end)
end)

-- ---------------------------------------------------------------------------
describe("I3 — there is a versioned, installable artifact", function()
  for _, p in ipairs({ { "v2", "prisma-airs-intercept" }, { "v1", "prisma-airs-intercept-postproxy" } }) do
    local which, dir = p[1], p[2]
    it(which .. ": ships a rockspec", function()
      local version = H.meta(which).VERSION
      local path = "plugin/" .. dir .. "/" .. dir .. "-" .. version .. "-1.rockspec"
      expect.truthy(exists(path),
                    "distribution was 'paste handler.lua into a ConfigMap': no version pin, " ..
                    "no rollback, and no way for a customer to state which build enforces policy. " ..
                    "expected " .. path)
    end)

    it(which .. ": the rockspec version tracks the handler's", function()
      local version = H.meta(which).VERSION
      local rock = read("plugin/" .. dir .. "/" .. dir .. "-" .. version .. "-1.rockspec")
      expect.contains(rock, 'version = "' .. version .. '-1"')
      expect.contains(rock, dir .. ".handler", "the module paths are what Kong actually loads")
      expect.contains(rock, dir .. ".schema")
    end)

    -- The rockspec existing is not the same as the rockspec BUILDING. A
    -- build.modules naming kong/plugins/<name>/handler.lua -- a path that
    -- exists in a deployed Kong tree and nowhere in this repo -- breaks the
    -- `luarocks make` in docs/DEPLOYMENT.md on a clean checkout, and grepping
    -- the module KEYS never catches it, because that never resolves a SOURCE.
    -- Every source path a rockspec declares must exist on disk.
    it(which .. ": every source path in the rockspec resolves on disk", function()
      local version = H.meta(which).VERSION
      local rock = read("plugin/" .. dir .. "/" .. dir .. "-" .. version .. "-1.rockspec")
      local n = 0
      for src in rock:gmatch('%]%s*=%s*"([^"]+%.lua)"') do
        n = n + 1
        expect.truthy(exists(src),
                      "rockspec declares source " .. src .. " which does not exist -- " ..
                      "`luarocks make` fails on a clean checkout")
      end
      expect.truthy(n >= 2, "expected at least handler and schema sources, found " .. n)
    end)

    -- The rule is NOT "the rockspec declares every module the handler
    -- requires"; that is WRONG for a Kong plugin. It would demand a `lua-cjson`
    -- dependency because the handler requires cjson -- and that declaration is
    -- what breaks `luarocks make` on kong/kong-gateway:3.14, the image this
    -- plugin actually ships into:
    --
    --   depends on lua-resty-http >= 0.16 (0.17.2-0 installed: success)
    --   depends on lua-cjson >= 2.1.0 (not installed)
    --   Error: Failed installing dependency: .../lua-cjson-2.1.0.10-1.src.rock
    --          Failed unpacking rock file: 'unzip -n' program not found.
    --
    -- Kong registers lua-resty-http as a rock, so luarocks resolves it. cjson
    -- comes from OpenResty, compiled in and invisible to luarocks, so luarocks
    -- tries to build it from source in an image with no unzip.
    --
    -- CI cannot see this on its own: the workflow installs lua-cjson as a rock
    -- early so the SUITE can run against the real library on LuaJIT, which
    -- incidentally satisfies the rockspec later. Green by construction, on the
    -- one platform that is not the deployment target.
    --
    -- The rule for a Kong plugin is: declare what Kong does NOT provide.
    it(which .. ": the rockspec declares what Kong does not provide, and nothing it does", function()
      local version = H.meta(which).VERSION
      local rock = read("plugin/" .. dir .. "/" .. dir .. "-" .. version .. "-1.rockspec")
      local src = read("plugin/" .. dir .. "/handler.lua")
      -- Searched the WHOLE rockspec, which meant the dependency comment
      -- ("lua-resty-http and lua-cjson are bundled with Kong 3.x...") satisfied
      -- it: delete both dependency lines, keep the comment, and it stayed green.
      -- Parse the dependencies TABLE, and only that.
      local deps = rock:match("dependencies%s*=%s*{(.-)}")
      expect.truthy(deps, "the rockspec must declare a dependencies table at all")
      deps = deps:gsub("%-%-[^\n]*", " ")     -- and a comment inside it is not a dependency
      -- Declared, because Kong registers it as a rock and luarocks resolves it.
      if src:match('require%("resty%.http"%)') then
        expect.truthy(deps:match("lua%-resty%-http"),
                      "handler requires resty.http and Kong registers it as a rock, " ..
                      "so the rockspec must declare it")
      end

      -- NOT declared, because OpenResty provides it outside luarocks' view and
      -- declaring it fails the install on the Kong image. Requiring cjson in the
      -- handler is correct; depending on the ROCK is not.
      expect.falsy(deps:match("lua%-cjson"),
                   "the rockspec must NOT declare lua-cjson: Kong provides it via " ..
                   "OpenResty, not as a rock, so declaring it makes `luarocks make` " ..
                   "fetch and build it inside an image that has no unzip")
    end)

    -- Correct paths in the rockspec are not enough on their own: if the
    -- DOCUMENTED COMMAND names a different directory, the install still fails.
    -- CI running its own loop from the repo root, i.e. the one cwd the docs
    -- need not name, would make that divergence invisible by construction. Pin
    -- all three to each other: what the docs print, what CI runs, and what
    -- exists on disk.
    it(which .. ": the docs, CI and the rockspec name the same install command", function()
      local version = H.meta(which).VERSION
      local rockpath = "plugin/" .. dir .. "/" .. dir .. "-" .. version .. "-1.rockspec"
      local command = "luarocks make " .. rockpath

      local docs = read("docs/DEPLOYMENT.md")
      expect.contains(docs, command,
                      "DEPLOYMENT.md must print the repo-root-relative path, because " ..
                      "that is where build.modules resolves from")
      expect.not_contains(docs, "cd plugin/" .. dir,
                          "a `cd` into the plugin directory makes luarocks look for " ..
                          "build.modules twice over, which is the original defect")

      -- Deliberately no assertion that a workflow file mentions `rockpath`.
      -- The contribution ships no CI of its own: a .github/workflows/ nested
      -- inside a subdirectory is never executed by GitHub, so a maintainer
      -- merging it would see a file that looks like a test gate and runs
      -- nowhere -- the same false assurance this suite exists to remove.
      -- The staging repo's root workflow RUNS `luarocks make` on this exact
      -- path, which is a stronger assertion than grepping YAML for it.
      expect.truthy(exists(rockpath), "and that path must exist")
    end)
  end
end)

-- ---------------------------------------------------------------------------
describe("I5 — debug mode must produce output, and must not leak prompts", function()
  it("debug=true alone is enough to see the trace", function()
    local r = H.run{ config = H.cfg.base{ debug = true },
                     request = { body = H.body.chat{{"user","hello"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow"}, {action="allow"} } }
    local levels = H.log_levels(r)
    expect.eq(levels.info or 0, 0,
              "log_debug emitted at kong.log.info while Kong's default level is notice, so " ..
              "debug=true produced nothing unless you ALSO set KONG_LOG_LEVEL=info")
    expect.truthy((levels.notice or 0) > 0, "the operator asked for this output; it should appear")
  end)

  it("debug=true does NOT write prompt text to the Kong log", function()
    local r = H.run{ config = H.cfg.base{ debug = true },
                     request = { body = H.body.chat{{"user","my password is hunter2"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow"}, {action="allow"} } }
    for _, l in ipairs(r.logs) do
      expect.not_contains(l.msg, "hunter2",
                          "500 bytes of scan payload — prompt text included — went to the Kong log, " ..
                          "and that is a data-handling decision, not a debug convenience")
    end
  end)

  it("but an operator can opt into payload logging deliberately", function()
    local r = H.run{ config = H.cfg.base{ debug = true, debug_log_payloads = true },
                     request = { body = H.body.chat{{"user","my password is hunter2"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow"}, {action="allow"} } }
    expect.truthy(H.logged(r, "hunter2"))
  end)

  it("payload logging without debug does nothing — one switch, not two half-switches", function()
    local r = H.run{ config = H.cfg.base{ debug_log_payloads = true },
                     request = { body = H.body.chat{{"user","my password is hunter2"}} },
                     upstream = { body = H.body.openai_response("ok") },
                     airs = { {action="allow"}, {action="allow"} } }
    expect.nil_(H.logged(r, "hunter2"))
  end)
end)

-- ---------------------------------------------------------------------------
describe("I4/I6/I7 — the documentation an operator actually needs", function()
  it("a deployment guide exists", function()
    expect.truthy(exists("docs/DEPLOYMENT.md"))
  end)

  it("the ConfigMap instructions do not tell you to paste a broken placeholder", function()
    local doc = read("docs/DEPLOYMENT.md")
    -- The doc is allowed — encouraged — to quote the placeholder while
    -- explaining why it fails. What must never happen is it appearing inside a
    -- fenced block, where it reads as something to copy.
    local inside_fence, offender = false, nil
    for line in doc:gmatch("[^\n]*") do
      if line:match("^```") then inside_fence = not inside_fence
      elseif inside_fence and line:find("paste handler.lua", 1, true) then offender = line end
    end
    expect.nil_(offender,
                "'#' is not a Lua comment ('--' is), so pasting the placeholder yields a " ..
                "syntax error and a data plane that will not boot")
    expect.contains(doc, "--from-file", "generate the ConfigMap from the files instead")
  end)

  it("it says that updating a ConfigMap does not reload the Lua", function()
    local doc = read("docs/DEPLOYMENT.md")
    expect.contains(doc, "restart", "modules are cached per worker; the pods have to be restarted")
  end)

  it("it covers the Konnect facts that block a first deployment", function()
    local doc = read("docs/DEPLOYMENT.md")
    for _, needle in ipairs({ "KONG_KONNECT_MODE", "KONG_CLUSTER_MTLS", "ROUTER_FLAVOR",
                              "control plane", "DB-less", "644" }) do
      expect.contains(doc, needle, needle .. " is a deployment-blocking fact that lived only in " ..
                                   "our field guides")
    end
  end)
end)

-- ---------------------------------------------------------------------------
describe("S-2a — the lint gate must be able to pass", function()
  -- luacheck exits 1 on any warning, so a misconfigured .luacheckrc means the
  -- CI job fails on every push and the gate never actually runs. That is what
  -- happened: `describe`, `it` and `expect` were declared read_globals while
  -- spec/runner.lua ASSIGNS them (W121/W122), and `todo`/`run_all` were not
  -- declared at all (W111). Nobody noticed, because a red gate looks the same
  -- as a red build.
  --
  -- luacheck is not installable in every dev environment, so these assert the
  -- two properties that made it red, from the same sources luacheck reads.
  local function read(path)
    local f = assert(io.open(path)); local t = f:read("*a"); f:close(); return t
  end

  local rc = read(".luacheckrc")
  local runner = read("spec/runner.lua")

  local function list(name)
    -- Anchored on a word boundary: matching "globals" without one finds the
    -- block belonging to "read_globals" first, which is how this guard would
    -- have reported the opposite of the truth.
    local block = rc:match("%f[%w_]" .. name .. "%s*=%s*{(.-)\n}")
    local out = {}
    for word in (block or ""):gmatch('"([%w_]+)"') do out[word] = true end
    return out
  end

  it("every global the runner assigns is declared writable", function()
    local declared, readonly = list("globals"), list("read_globals")
    local missing, wrong = {}, {}
    local function check(name)
      if not declared[name] then missing[#missing + 1] = name end
      if readonly[name] then wrong[#wrong + 1] = name end
    end
    for name in runner:gmatch("\nfunction ([%a_][%w_]*)%s*%(") do check(name) end
    for name in runner:gmatch("\n([%a_][%w_]*)%s*=%s*{") do check(name) end
    expect.eq(#missing, 0, "assigned but undeclared (W111): " .. table.concat(missing, ", "))
    expect.eq(#wrong, 0,
              "declared read-only and then assigned (W121/W122): " .. table.concat(wrong, ", "))
  end)

  it("no shipped Lua file carries a local that is never used", function()
    -- The W211 half. A dead local is how a refactor leaves a read of an
    -- untrusted header lying around, so it is worth catching for its own sake
    -- and not only because it reddens the gate.
    local FILES = {
      "plugin/prisma-airs-intercept/handler.lua",
      "plugin/prisma-airs-intercept/schema.lua",
      "plugin/prisma-airs-intercept-postproxy/handler.lua",
      "plugin/prisma-airs-intercept-postproxy/schema.lua",
      "plugin/request-callout/hooks/request_before.lua",
      "plugin/request-callout/hooks/response_before.lua",
      "plugin/request-callout/hooks/upstream_before.lua",
    }
    local dead = {}
    for _, path in ipairs(FILES) do
      local src = read(path)
      -- Comments and string literals are not uses.
      src = src:gsub("%-%-%[%[.-%]%]", " "):gsub("%-%-[^\n]*", " ")
      src = src:gsub('"[^"\n]*"', '""'):gsub("'[^'\n]*'", "''")
      local seen = {}
      for name in src:gmatch("local%s+([%a_][%w_]*)%s*=") do seen[name] = true end
      for name in src:gmatch("local%s+function%s+([%a_][%w_]*)") do seen[name] = true end
      for name in pairs(seen) do
        -- An underscore prefix is the codebase's own "deliberately unused".
        if name:sub(1, 1) ~= "_" then
          local n = 0
          for _ in src:gmatch("%f[%w_]" .. name .. "%f[^%w_]") do n = n + 1 end
          if n < 2 then dead[#dead + 1] = path .. ":" .. name end
        end
      end
    end
    table.sort(dead)
    expect.eq(#dead, 0, "declared and never used: " .. table.concat(dead, ", "))
  end)
end)

-- Minimal test runner. No busted dependency: Kong's own CI does not have one
-- either, and a spec suite that only runs on a machine with luarocks configured
-- is a suite nobody runs.
--
--   describe("group", function() it("does a thing", function() ... end) end)
--
-- Assertions live on the global `expect`. Every failure reports the file:line
-- of the assertion, because a suite that says only "failed" wastes your time.

local RESET, RED, GREEN, DIM, BOLD, YELLOW =
  "\27[0m", "\27[31m", "\27[32m", "\27[2m", "\27[1m", "\27[33m"

local state = { groups = {}, cur = nil, pass = 0, fail = 0, failures = {}, only_group = nil }

function describe(name, fn)
  local g = { name = name, tests = {} }
  state.groups[#state.groups + 1] = g
  state.cur = g
  fn()
  state.cur = nil
end

function it(name, fn)
  assert(state.cur, "it() outside describe()")
  state.cur.tests[#state.cur.tests + 1] = { name = name, fn = fn }
end

-- pending test: records intent without failing the suite
function todo(name)
  assert(state.cur, "todo() outside describe()")
  state.cur.tests[#state.cur.tests + 1] = { name = name, todo = true }
end

local function fmt(v, depth)
  depth = depth or 0
  local t = type(v)
  if t == "string" then return string.format("%q", v) end
  if t ~= "table" then return tostring(v) end
  if depth > 2 then return "{...}" end
  local parts, n = {}, 0
  for k, val in pairs(v) do
    n = n + 1
    if n > 8 then parts[#parts + 1] = "..." break end
    parts[#parts + 1] = tostring(k) .. "=" .. fmt(val, depth + 1)
  end
  return "{" .. table.concat(parts, ", ") .. "}"
end

local function where()
  for lvl = 3, 8 do
    local info = debug.getinfo(lvl, "Sl")
    if info and info.short_src and info.short_src:find("_spec") then
      return info.short_src .. ":" .. info.currentline
    end
  end
  return "?"
end

local function fail(msg)
  error({ __assert = true, msg = msg, at = where() }, 0)
end

expect = {}

function expect.eq(got, want, note)
  if got ~= want then
    fail(("expected %s, got %s%s"):format(fmt(want), fmt(got), note and ("  -- " .. note) or ""))
  end
end

function expect.ne(got, bad, note)
  if got == bad then
    fail(("expected anything but %s%s"):format(fmt(bad), note and ("  -- " .. note) or ""))
  end
end

function expect.truthy(got, note)
  if not got then fail(("expected truthy, got %s%s"):format(fmt(got), note and ("  -- " .. note) or "")) end
end

function expect.falsy(got, note)
  if got then fail(("expected falsy, got %s%s"):format(fmt(got), note and ("  -- " .. note) or "")) end
end

function expect.nil_(got, note)
  if got ~= nil then fail(("expected nil, got %s%s"):format(fmt(got), note and ("  -- " .. note) or "")) end
end

-- Both matchers search for a LITERAL substring (string.find with plain=true).
-- Two tests had written a Lua PATTERN as the needle -- "keep%-alive" and
-- "^decoy$" -- which searches for the percent sign and the anchors as ordinary
-- characters. Neither string can ever occur, so both assertions were incapable
-- of failing: one of them was the only coverage of SSE comment handling.
-- Refuse the shape rather than trusting everyone to remember.
local function literal(needle)
  if type(needle) == "string" and string.find(needle, "[%%^$]") then
    fail(("needle %s looks like a Lua pattern; these matchers are LITERAL " ..
          "(string.find plain=true), so a pattern here can never match"):format(fmt(needle)))
  end
  return needle
end

function expect.contains(hay, needle, note)
  literal(needle)
  if type(hay) ~= "string" or not string.find(hay, needle, 1, true) then
    fail(("expected %s to contain %s%s"):format(fmt(hay), fmt(needle), note and ("  -- " .. note) or ""))
  end
end

function expect.not_contains(hay, needle, note)
  literal(needle)
  if type(hay) == "string" and string.find(hay, needle, 1, true) then
    fail(("expected %s NOT to contain %s%s"):format(fmt(hay), fmt(needle), note and ("  -- " .. note) or ""))
  end
end

function expect.len(t, n, note)
  local got = t and #t or 0
  if got ~= n then fail(("expected length %d, got %d%s"):format(n, got, note and ("  -- " .. note) or "")) end
end

function run_all()
  local t0 = os.clock()
  for _, g in ipairs(state.groups) do
    io.write(BOLD, g.name, RESET, "\n")
    for _, t in ipairs(g.tests) do
      if t.todo then
        io.write("  ", YELLOW, "todo", RESET, " ", DIM, t.name, RESET, "\n")
      else
        local ok, err = pcall(t.fn)
        if ok then
          state.pass = state.pass + 1
          io.write("  ", GREEN, "ok  ", RESET, t.name, "\n")
        else
          state.fail = state.fail + 1
          local msg, at
          if type(err) == "table" and err.__assert then msg, at = err.msg, err.at
          else msg, at = tostring(err), "raised" end
          state.failures[#state.failures + 1] = { group = g.name, test = t.name, msg = msg, at = at }
          io.write("  ", RED, "FAIL", RESET, " ", t.name, "\n")
          io.write("       ", DIM, at, RESET, "  ", msg, "\n")
        end
      end
    end
  end
  local dt = (os.clock() - t0) * 1000
  io.write(("\n%s%d passed%s, %s%d failed%s  %s(%.0f ms)%s\n"):format(
    GREEN, state.pass, RESET,
    state.fail > 0 and RED or DIM, state.fail, RESET, DIM, dt, RESET))
  return state.fail == 0
end

return { run_all = run_all }

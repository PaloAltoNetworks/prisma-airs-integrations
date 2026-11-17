#!/usr/bin/env bash
# Offline unit tests for the guardrail and callout Lua. No gateway, no Konnect,
# no AIRS tenant, no network. Resolves the real lua-cjson through luarocks so
# the JSON paths run against the library the data plane actually ships.
set -euo pipefail
cd "$(dirname "$0")/.."
eval "$(luarocks --lua-version=5.1 path --bin 2>/dev/null)" || true
export LUA_PATH="$PWD/?.lua;$PWD/?/init.lua;${LUA_PATH:-;}"

# Kong runs LuaJIT, so LuaJIT is the interpreter these assertions are meant to
# run on and it is preferred. A 5.1-compatible interpreter is accepted as a
# fallback so the suite is runnable on a machine that has only lua5.1 -- the
# code under test uses no LuaJIT-specific extension.
LUA_BIN="${LUA_BIN:-}"
if [ -z "$LUA_BIN" ]; then
  for candidate in luajit lua5.1 lua; do
    if command -v "$candidate" >/dev/null 2>&1; then LUA_BIN="$candidate"; break; fi
  done
fi
if [ -z "$LUA_BIN" ]; then
  echo "no Lua interpreter found: install luajit (preferred) or lua5.1" >&2
  exit 127
fi
echo "interpreter: $LUA_BIN ($(command -v "$LUA_BIN"))"

# lua-cjson is a hard dependency of spec/mcp_callout_spec.lua. Without it the
# suite dies mid-run with a raw traceback, which reads like a broken test rather
# than a missing rock.
if ! "$LUA_BIN" -e 'require("cjson.safe")' >/dev/null 2>&1; then
  echo "lua-cjson not found for $LUA_BIN" >&2
  echo "  luarocks --lua-version=5.1 install lua-cjson" >&2
  exit 127
fi

rc=0
for s in spec/verdict_spec.lua spec/mcp_callout_spec.lua; do
  echo "=== $s"
  "$LUA_BIN" "$s" || rc=1
done
exit $rc

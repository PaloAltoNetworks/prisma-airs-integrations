#!/usr/bin/env bash
# Run the spec suite against LuaJIT (Lua 5.1 semantics, same as Kong) with the
# real lua-cjson. Optional arg filters spec files by substring.
set -euo pipefail
cd "$(dirname "$0")/.."
export KAP_ROOT="$PWD"
eval "$(luarocks --lua-version=5.1 path --bin 2>/dev/null)"
export LUA_PATH="$PWD/?.lua;$PWD/?/init.lua;${LUA_PATH:-;}"
exec luajit spec/all.lua "$@"

#!/usr/bin/env python3
"""Inline the Lua under lua/ into the policy YAML under config/, emitting dist/.

Why this exists. Kong wants the guardrail functions and the callout hooks as
quoted strings inside the policy config. Lua living only inside a YAML string is
Lua nobody lints, nobody unit-tests, and nobody reviews line by line -- which is
how a security control ends up with an untested branch in the one function that
decides whether traffic passes. So the Lua lives in real .lua files that
spec/ exercises and luacheck reads, and this script assembles the artefact that
is actually applied.

    scripts/build-config.py            rebuild dist/ from config/ + lua/
    scripts/build-config.py --check    fail if dist/ is stale (for a pipeline)

A marker is the whole value of a YAML key:

    airs_verdict: "__INLINE__lua/guardrail/airs_verdict.lua"

and is replaced by a literal block scalar carrying that file, indented to match.

Placeholders of the form __AIRS_SOMETHING__ inside an inlined file are filled
from the `params:` block of the policy the marker sits in -- a callout by_lua
has no documented way to read its own policy config, so the values are pinned
at build time and the YAML stays the single place an operator edits them.
"""
import os
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "config"
DIST = ROOT / "dist"

MARKER = re.compile(r'^(?P<indent>\s*)(?P<key>[A-Za-z0-9_.-]+):\s*"__INLINE__(?P<path>[^"]+)"\s*$')
PLACEHOLDER = re.compile(r"__AIRS_([A-Z_]+)__")

# params: key -> the placeholder it fills. Kept explicit rather than derived so
# that adding a placeholder is a deliberate act with a name, not a silent
# coupling to whatever happens to be in params.
PARAM_FOR = {
    "AIRS_PROFILE_NAME": "profile",
    "AIRS_APP_NAME": "app_name",
    "AIRS_SERVER_NAME": "server_name",
    "AIRS_UNCLASSIFIED_ACTION": "unclassified_action",
}


POLICY_START = re.compile(r"^(\s*)-\s+ref:\s")


def policy_bounds(lines, marker_index):
    """The line range of the policy list-item containing marker_index.

    Markers and the `params:` they draw from can appear in either order inside a
    policy, and a file may hold several policies -- the per-consumer variant
    ships two with different profiles. So the scope is the enclosing list item,
    found by walking out to the nearest `- ref:` above and the next one at the
    same indent below, rather than anything positional.
    """
    start, indent = 0, None
    for i in range(marker_index, -1, -1):
        m = POLICY_START.match(lines[i])
        if m:
            start, indent = i, len(m.group(1))
            break
    if indent is None:
        return 0, len(lines)
    end = len(lines)
    for j in range(start + 1, len(lines)):
        m = POLICY_START.match(lines[j])
        if m and len(m.group(1)) == indent:
            end = j
            break
    return start, end


def params_in_scope(lines, marker_index):
    """Read the `params:` block of the policy the marker belongs to.

    Deliberately a text scan rather than a YAML round-trip: these files are
    hand-written policy configs whose comments carry most of their value, and
    a load/dump cycle would discard every one of them.
    """
    start, end = policy_bounds(lines, marker_index)
    found = {}
    block_indent = None
    block_start = None
    # `x-airs-build` is a SOURCE-ONLY block, stripped from dist/. It exists
    # because not every policy type has a `params` field to borrow -- the
    # request-callout schema takes only cache, callouts and upstream, so a
    # `params` block there is rejected on apply. Values a callout by_lua needs
    # are pinned into the Lua at build time and never travel in the config.
    for key in ("x-airs-build", "params"):
        for i in range(start, end):
            m = re.match(r"^(\s*)" + re.escape(key) + r":\s*$", lines[i])
            if m:
                block_indent, block_start = len(m.group(1)), i
                break
        if block_start is not None:
            break
    if block_start is None:
        return found
    for line in lines[block_start + 1:end]:
        if not line.strip() or line.strip().startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= block_indent:
            break
        m = re.match(r'^\s*([A-Za-z0-9_.-]+):\s*"?(.*?)"?\s*$', line)
        if m:
            found[m.group(1)] = m.group(2)
    return found


def inline(lua_path, indent, params, where):
    text = (ROOT / lua_path).read_text(encoding="utf-8")

    def fill(m):
        name = m.group(0).strip("_")
        key = PARAM_FOR.get(name)
        if key is None:
            raise SystemExit(f"{where}: {lua_path} uses unknown placeholder {m.group(0)}")
        if key not in params:
            raise SystemExit(
                f"{where}: {lua_path} needs placeholder {m.group(0)}, "
                f"which comes from params.{key} -- not set on this policy")
        value = params[key]
        # A value may be a deferred tag rather than a literal. `!env NAME` is
        # resolved by kongctl at APPLY time, which is too late for anything the
        # builder bakes into Lua -- the placeholder would become the literal
        # text "!env NAME" and the data plane would send that to AIRS as a
        # profile name. Resolve it here, and fail loudly if it is unset, rather
        # than shipping a config that is wrong in a way only live traffic shows.
        # params_in_scope is a text scan, so a deferred tag arrives as the
        # literal string "!env NAME".
        m_env = re.match(r"^!env\s+([A-Za-z_][A-Za-z0-9_]*)$", str(value).strip())
        if m_env:
            name = m_env.group(1)
            if name not in os.environ:
                raise SystemExit(
                    f"{where}: {lua_path} needs params.{key}, declared as "
                    f"!env {name}, but {name} is not set in the environment. "
                    f"Export it before building.")
            return os.environ[name]
        return value

    text = PLACEHOLDER.sub(fill, text)
    body = "\n".join((indent + "  " + ln).rstrip() for ln in text.split("\n"))
    return body.rstrip("\n")


def build_one(path):
    lines = path.read_text(encoding="utf-8").split("\n")
    out, changed = [], 0
    strip_until = None
    for i, line in enumerate(lines):
        # Drop the source-only build block from the applied artefact.
        if strip_until is not None:
            if line.strip() and (len(line) - len(line.lstrip())) <= strip_until:
                strip_until = None
            else:
                continue
        m_strip = re.match(r"^(\s*)x-airs-build:\s*$", line)
        if m_strip:
            strip_until = len(m_strip.group(1))
            continue
        m = MARKER.match(line)
        if not m:
            out.append(line)
            continue
        changed += 1
        params = params_in_scope(lines, i)
        out.append(f"{m.group('indent')}{m.group('key')}: |")
        out.append(inline(m.group("path"), m.group("indent"), params, f"{path.name}:{i+1}"))
    if changed == 0:
        # A config with no Lua to inline is passed through verbatim rather than
        # treated as an error. Lab fixtures (config/lab/) are pure declarative
        # YAML; only the guardrail and callout configs carry function bodies.
        # dist/ therefore stays a complete, appliable mirror of config/, and
        # --check still catches drift in these files because the comparison is
        # against the same verbatim text.
        return path.read_text(encoding="utf-8")
    header = (
        "# GENERATED FILE -- do not edit.\n"
        f"# Built by scripts/build-config.py from config/{path.relative_to(SRC)} and lua/.\n"
        "# Edit the source YAML or the .lua files and rebuild; --check fails if stale.\n"
    )
    return header + "\n".join(out)


def main():
    check = "--check" in sys.argv
    sources = sorted(SRC.rglob("*.yaml"))
    if not sources:
        raise SystemExit("no source configs found under config/")
    stale = []
    for src in sources:
        built = build_one(src)
        target = DIST / src.relative_to(SRC)
        if check:
            if not target.exists() or target.read_text(encoding="utf-8") != built:
                stale.append(str(target.relative_to(ROOT)))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(built, encoding="utf-8")
            print(f"built {target.relative_to(ROOT)}")
    if check:
        if stale:
            print("STALE -- run scripts/build-config.py:", *stale, sep="\n  ")
            return 1
        print(f"ok -- {len(sources)} built config(s) match their sources and the Lua")
    return 0


if __name__ == "__main__":
    sys.exit(main())

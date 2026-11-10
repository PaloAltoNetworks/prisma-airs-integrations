#!/usr/bin/env python3
"""Validate every built policy config against the AI GATEWAY POLICY schema.

THE DEFECT THIS EXISTS TO PREVENT. Kong publishes two different schemas for
ai-custom-guardrail:

    developer.konghq.com/plugins/ai-custom-guardrail/reference/              (Kong Gateway 3.x PLUGIN)
    developer.konghq.com/ai-gateway/policies/ai-custom-guardrail/reference/  (AI Gateway 2.x POLICY)

They are NOT the same contract. The policy schema carries four config keys the
plugin schema does not -- rejection_mode, continue_on_detection,
log_blocked_content and proxy_config -- and those four are precisely the ones
that give a 2.x deployment an observe-only rollout and a controlled block
contract. An integration that validates 2.x config against the 3.x plugin schema
rejects its own vendor's supported fields and never learns they exist. The two
reference pages look alike and the wrong one fails quietly, so it is worth a
script.

    scripts/check-policy-schema.py            fetch and validate
    scripts/check-policy-schema.py --offline  structure checks only, no network

Checks performed per policy:
  * the policy `type` has a published schema at the AI Gateway policy path
  * every config key appears in that schema
  * every enum-typed value is one of the schema's allowed values
  * a key that exists in the 2.x policy schema but NOT in the 3.x plugin schema
    is reported, since that is the capability a config ported from the plugin
    schema would silently lose
"""
import json
import re
import sys
import pathlib
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from kongctl_yaml import load, Tagged  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
POLICY_URL = "https://developer.konghq.com/ai-gateway/policies/{}/reference/"
PLUGIN_URL = "https://developer.konghq.com/plugins/{}/reference/"


def fetch_schema(url):
    req = urllib.request.Request(url, headers={"User-Agent": "prisma-airs-kong-ci"})
    with urllib.request.urlopen(req, timeout=30) as fh:
        html = fh.read().decode("utf-8", "replace")
    m = re.search(r"window\.schema\s*=\s*(\{.*)", html, re.S)
    if not m:
        return None
    raw, depth, end = m.group(1), 0, None
    for i, ch in enumerate(raw):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        return None
    try:
        return json.loads(raw[:end])
    except json.JSONDecodeError:
        return None


def config_props(schema):
    try:
        return schema["properties"]["config"]["properties"]
    except (KeyError, TypeError):
        return {}


def walk(cfg, props, path, problems):
    for key, value in cfg.items():
        spec = props.get(key)
        where = f"{path}.{key}" if path else key
        if spec is None:
            problems.append(("unknown", where, "not present in the policy schema"))
            continue
        # A value resolved at apply time (!env, !vault) is not ours to validate.
        if isinstance(value, Tagged):
            continue
        enum = spec.get("enum")
        if enum and isinstance(value, (str, int)) and value not in enum:
            problems.append(("enum", where, f"{value!r} not in {enum}"))
        sub = spec.get("properties")
        if sub and isinstance(value, dict):
            walk(value, sub, where, problems)


def main():
    offline = "--offline" in sys.argv
    files = sorted(DIST.rglob("*.yaml"))
    if not files:
        print("no built configs under dist/ -- run scripts/build-config.py first")
        return 1

    rc = 0
    cache = {}
    for path in files:
        doc = load(path)
        policies = doc.get("ai_gateway_policies") or []
        if not policies:
            print(f"-- {path.relative_to(ROOT)}: no ai_gateway_policies, skipped")
            continue
        for pol in policies:
            ptype = pol.get("type")
            cfg = pol.get("config") or {}
            label = f"{path.relative_to(ROOT)} :: {pol.get('name', '?')} ({ptype})"

            if not cfg:
                print(f"FAIL {label}: policy has no config block")
                rc = 1
                continue
            if offline:
                print(f"ok   {label}: {len(cfg)} config keys (offline, not schema-checked)")
                continue

            if ptype not in cache:
                cache[ptype] = (fetch_schema(POLICY_URL.format(ptype)),
                                fetch_schema(PLUGIN_URL.format(ptype)))
            policy_schema, plugin_schema = cache[ptype]
            if policy_schema is None:
                print(f"FAIL {label}: no policy schema published at {POLICY_URL.format(ptype)}")
                rc = 1
                continue

            props = config_props(policy_schema)
            problems = []
            walk(cfg, props, "", problems)

            if problems:
                rc = 1
                print(f"FAIL {label}")
                for kind, where, why in problems:
                    print(f"       {kind:8} {where}: {why}")
            else:
                print(f"ok   {label}: {len(cfg)} config keys, all in the policy schema")

            # Informational: what the policy schema has that the plugin schema
            # does not. This is the gap that makes using the wrong schema a
            # silent loss of capability rather than a loud error.
            if plugin_schema is not None:
                only = sorted(set(props) - set(config_props(plugin_schema)))
                if only:
                    used = [k for k in only if k in cfg]
                    print(f"       policy-only keys: {', '.join(only)}")
                    print(f"       of those, used here: {', '.join(used) if used else 'none'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())

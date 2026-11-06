"""Renders config/api.yaml: one Flex API instance per configuration preset, each on its own port.

Every instance serves all four formats (the runner sends x-input-format, as Model Proxy does) and points the policy
at the mock AIRS with a fake key. Usage: python3 render.py <policy ref> <phase: main|tls|leak>
"""
import json
import os
import sys

BASE = {"airsApiKey": "FAKE-ITEST-KEY", "airsEndpoint": "https://airs:8443", "profileName": "itest-profile"}
PRESETS = [
    (8081, "default", {}),
    (8082, "monitor", {"enforcementMode": "monitor"}),
    (8083, "failopen", {"onApiError": "allow"}),
    (8084, "gapallow", {"onScanError": "allow"}),
    (8085, "timeout3s", {"advancedConfiguration": {"timeoutMs": 3000}}),
    (8086, "misconfigured", {"profileName": None}),
    (8087, "masking", {"advancedConfiguration": {"applyDlpMasking": True}}),
    (8088, "breaker", {"advancedConfiguration": {"breakerFailures": 2, "breakerCooldownS": 30}}),
    (8089, "cache", {"advancedConfiguration": {"verdictCacheTtlS": 60}}),
    (8090, "roles", {"advancedConfiguration": {"scanMessageRoles": ["user", "system"]}}),
    (8091, "truncopen", {"advancedConfiguration": {"maxScanChars": 50, "truncationFailClosed": False}}),
    (8092, "truncclosed", {"advancedConfiguration": {"maxScanChars": 50}}),
]
# The generated PDK code parses the configuration before the policy runs. 3000.0 is valid JSON Schema for an
# integer but not for its i64 field: this preset measures what that does, with a fake key that must not be logged.
LEAK_VARIANTS = {
    "float": {"airsApiKey": "FAKE-LEAK-KEY-4242", "advancedConfiguration": {"timeoutMs": 3000.0}},
    "string": {"airsApiKey": "FAKE-LEAK-KEY-4242", "advancedConfiguration": {"timeoutMs": "abc"}},
    "keynumber": {"airsApiKey": 424242424242},
}
LEAK = (8081, "leak", LEAK_VARIANTS[os.environ.get("ITEST_LEAK_VARIANT", "float")])


def config(overrides):
    c = dict(BASE)
    for key, value in overrides.items():
        if value is None:
            c.pop(key, None)
        else:
            c[key] = value
    return c


def main():
    ref, phase = sys.argv[1], sys.argv[2]
    template = open(os.path.join(os.path.dirname(__file__), "api.template.yaml")).read()
    presets = {"main": PRESETS, "tls": PRESETS[:1], "leak": [LEAK]}[phase]
    out = []
    for port, name, overrides in presets:
        out.append(template.replace("__NAME__", name).replace("__PORT__", str(port))
                   .replace("__POLICY_REF__", ref).replace("__CONFIG__", json.dumps(config(overrides))))
    sys.stdout.write("".join(out))


if __name__ == "__main__":
    main()

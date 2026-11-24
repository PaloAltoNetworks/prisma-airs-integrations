"""Python Policy: renders the CREATE FUNCTION statement for the Python service policy.

The body is airs_core plus policy_entry (their import lines stripped) plus a short entry that reads the AIRS key
from a Unity Catalog secret at run time. The key never appears in the SQL; the settings are baked in.
"""


def _strip(src: str) -> str:
    keep = [ln for ln in src.splitlines()
            if not ln.startswith(("from __future__ import", "from airs_core import", "import airs_core"))]
    return "\n".join(keep)


BUDGET_RANGE_S = (1.0, 25.0)      # the platform allows 30 s per check, start-up included


def render_function_sql(core_src: str, entry_src: str, settings: dict, fn_fqn: str, secret_fqn: str) -> str:
    budget = float(settings["budget_s"])
    if not BUDGET_RANGE_S[0] <= budget <= BUDGET_RANGE_S[1]:          # also refuses nan and inf
        raise ValueError(f"budget_s must be {BUDGET_RANGE_S[0]:g} to {BUDGET_RANGE_S[1]:g} seconds")
    catalog, schema, key = secret_fqn.split(".")
    glue = "\n".join([
        "import json as _json",
        "from databricks.secrets import get as _get_secret",
        "_ev = event.toPython() if hasattr(event, 'toPython') else event",
        f"_settings = Settings(api_key=(_get_secret(catalog={catalog!r}, schema={schema!r}, key={key!r}) or '').strip(),",
        f"                     airs_url={settings.get('airs_url', US_URL_PLACEHOLDER)!r},",
        f"                     budget_s={budget!r},",
        f"                     allow_fail_open={bool(settings['allow_fail_open'])!r},",
        f"                     allow_unscanned_parts={bool(settings['allow_unscanned_parts'])!r})",
        f"_cfg = PolicyConfig(profile={settings['profile']!r}, app_name={settings['app_name']!r},",
        f"                    on_error={settings['on_error']!r})",
        "return type(event).parseJson(_json.dumps({'decision': python_policy_decision(_ev, _settings, _cfg)}))",
    ])
    body = _strip(core_src) + "\n\n" + _strip(entry_src) + "\n\n" + glue
    if "$$" in body:
        raise ValueError("the source or a setting contains $$")
    return (f"CREATE OR REPLACE FUNCTION {fn_fqn}(event VARIANT, config VARIANT)\n"
            "RETURNS VARIANT\nLANGUAGE PYTHON\n"
            f"SECRETS ({secret_fqn})\n"
            "ENVIRONMENT (environment_version = '6')\n"
            f"AS $$\n{body}\n$$")


US_URL_PLACEHOLDER = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"


NAME = r"[A-Za-z0-9_]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+"     # catalog.schema.name, plain identifiers only


def main(argv=None) -> None:
    """Prints the CREATE FUNCTION statement; run it in a SQL editor. The key stays in the UC secret."""
    import argparse
    import pathlib
    import re

    def name(v: str) -> str:
        if not re.fullmatch(NAME, v):
            raise argparse.ArgumentTypeError("use catalog.schema.name (letters, digits and _)")
        return v

    def https(v: str) -> str:
        if not v.startswith("https://"):
            raise argparse.ArgumentTypeError("the scan URL must start with https://")
        return v

    ap = argparse.ArgumentParser(description="Renders the Python Policy's function (a Unity Gateway Python service policy).")
    ap.add_argument("--function", required=True, type=name, help="the function to create, catalog.schema.name")
    ap.add_argument("--secret", required=True, type=name, help="the UC secret holding the AIRS key")
    ap.add_argument("--profile", required=True, help="the Prisma AIRS security profile name")
    ap.add_argument("--airs-url", type=https, default=US_URL_PLACEHOLDER, help="the regional sync scan URL")
    ap.add_argument("--app-name", default="", help="your app's name: AIRS gets Databricks-<name>")
    ap.add_argument("--budget", type=float, default=20.0, help="seconds for the AIRS scans of one call")
    ap.add_argument("--on-error", choices=("deny", "allow"), default="deny")
    ap.add_argument("--allow-fail-open", action="store_true", help="also needed for --on-error allow to allow")
    ap.add_argument("--allow-unscanned-parts", action="store_true")
    a = ap.parse_args(argv)
    src = pathlib.Path(__file__).resolve().parent
    settings = {"profile": a.profile, "app_name": a.app_name, "on_error": a.on_error, "budget_s": a.budget,
                "airs_url": a.airs_url, "allow_fail_open": a.allow_fail_open,
                "allow_unscanned_parts": a.allow_unscanned_parts}
    try:
        sql = render_function_sql((src.parent / "airs_core.py").read_text(encoding="utf-8"),
                                  (src / "policy_entry.py").read_text(encoding="utf-8"), settings, a.function,
                                  a.secret)
    except ValueError as e:
        raise SystemExit(f"stop: {e}")
    print(sql)


if __name__ == "__main__":
    main()

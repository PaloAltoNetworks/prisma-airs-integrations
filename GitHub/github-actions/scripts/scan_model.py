#!/usr/bin/env python3
"""
Prisma AIRS Model Security Scanner

Scans an AI model against Palo Alto Prisma AIRS security policies
using the official Model Security SDK. Exits non-zero if the model
fails the security assessment, blocking the CI/CD pipeline.
"""

import argparse
import os
import sys

import yaml
from dotenv import load_dotenv
from model_security_client.api import ModelSecurityAPIClient

load_dotenv()


def print_scan_results(result, model_name):
    """Pretty-print the scan results for CI log visibility."""
    print()
    print("=" * 64)
    print("  PRISMA AIRS MODEL SECURITY SCAN RESULTS")
    print("=" * 64)
    print(f"  Model:        {model_name}")
    print(f"  Scan UUID:    {getattr(result, 'uuid', 'N/A')}")
    print(f"  Outcome:      {result.eval_outcome}")
    print(f"  Summary:      {getattr(result, 'eval_summary', 'N/A')}")
    print(f"  Sec. Group:   {getattr(result, 'security_group_name', 'N/A')}")
    print(f"  Rules:        {getattr(result, 'enabled_rule_count_snapshot', 'N/A')}")
    print(f"  Files Scanned:{getattr(result, 'total_files_scanned', 'N/A')}")
    print(f"  Files Skipped:{getattr(result, 'total_files_skipped', 'N/A')}")

    violations = getattr(result, 'rule_violations', None) or getattr(result, 'findings', [])
    if violations:
        print(f"  Violations:   {len(violations)}")
        for v in violations:
            severity = getattr(v, 'severity', getattr(v, 'level', 'unknown'))
            desc = getattr(v, 'description', getattr(v, 'rule_name', 'No description'))
            print(f"    [{str(severity).upper()}] {desc}")

    print("=" * 64)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Scan an AI model with Prisma AIRS Model Security"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the model configuration YAML file",
    )
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    if not config.get("security", {}).get("scan_enabled", True):
        print("Security scan is disabled in model config. Skipping.")
        sys.exit(0)

    # Allow overriding security_profile_id from environment variable
    profile_id = os.environ.get("MODEL_SECURITY_PROFILE_ID")
    if profile_id:
        config.setdefault("security", {})["security_profile_id"] = profile_id

    security_group_uuid = config["security"]["security_profile_id"]
    if not security_group_uuid:
        print("ERROR: No security_profile_id configured.")
        print("Set MODEL_SECURITY_PROFILE_ID env var or configure it in model-config.yaml.")
        sys.exit(1)

    model_name = config["model"]["huggingface_id"]
    model_uri = f"https://huggingface.co/{model_name}"
    api_endpoint = os.environ.get(
        "MODEL_SECURITY_API_ENDPOINT",
        "https://api.sase.paloaltonetworks.com/aims",
    )

    print(f"Initializing Prisma AIRS Model Security SDK...")
    client = ModelSecurityAPIClient(base_url=api_endpoint)

    labels = {
        "deployment_target": "vertex_ai",
        "machine_type": config["deployment"]["machine_type"],
        "version": config["model"].get("version", "unknown").replace(".", "-"),
        "pipeline": "github-actions",
    }

    print(f"Scanning model: {model_name}")
    print(f"  URI: {model_uri}")
    print(f"  Security Group: {security_group_uuid}")
    print(f"  Labels: {labels}")

    result = client.scan(
        security_group_uuid=security_group_uuid,
        model_uri=model_uri,
        labels=labels,
    )

    print_scan_results(result, model_name)

    outcome = str(result.eval_outcome)
    if "BLOCKED" in outcome:
        print("BLOCKED: Model blocked by Prisma AIRS security policy.")
        print("The model will NOT be deployed.")
        sys.exit(1)
    elif "ALLOWED" in outcome:
        print("ALLOWED: Model approved by Prisma AIRS security policy.")
        print("The model is cleared for deployment.")
    else:
        print(f"WARNING: Unexpected scan outcome '{outcome}'. Blocking deployment.")
        print("The model will NOT be deployed.")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Test a deployed Vertex AI model endpoint.

Discovers the endpoint by display name, sends a test prompt via
the dedicated endpoint DNS, and prints the model response.
Can be used in CI/CD or locally.
"""

import argparse
import json
import os
import subprocess
import sys
import time

import yaml
from dotenv import load_dotenv

load_dotenv()


def get_endpoint_info(project_id, region, display_name):
    """Find the endpoint ID and dedicated DNS for a deployed model."""
    result = subprocess.run(
        [
            "gcloud", "ai", "endpoints", "list",
            "--project", project_id,
            "--region", region,
            "--format", "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    endpoints = json.loads(result.stdout)
    for ep in endpoints:
        if display_name in ep.get("displayName", ""):
            endpoint_id = ep["name"].split("/")[-1]
            dedicated_dns = ep.get("dedicatedEndpointDns", "")
            return endpoint_id, dedicated_dns
    return None, None


def send_prediction(project_id, region, endpoint_id, dedicated_dns, prompt):
    """Send a prediction request to the Vertex AI endpoint."""
    access_token = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    # Use dedicated endpoint DNS with rawPredict
    url = (
        f"https://{dedicated_dns}/v1/projects/{project_id}"
        f"/locations/{region}/endpoints/{endpoint_id}:rawPredict"
    )

    import urllib.request
    import urllib.error

    request_payload = json.dumps({
        "prompt": prompt,
        "max_tokens": 256,
        "temperature": 0.7,
    }).encode()

    req = urllib.request.Request(
        url,
        data=request_payload,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"ERROR: {e.code} {e.reason}")
        print(f"Response: {error_body}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Test a deployed Vertex AI model endpoint"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the model configuration YAML file",
    )
    parser.add_argument(
        "--prompt",
        default="Explain what AI model security scanning is in one sentence.",
        help="Test prompt to send to the model",
    )
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    project_id = os.environ.get("GCP_PROJECT_ID")
    region = os.environ.get("GCP_REGION", config["deployment"].get("region", "us-central1"))

    if not project_id:
        print("ERROR: GCP_PROJECT_ID environment variable is required.")
        sys.exit(1)

    display_name = config["model"]["display_name"] + "-secure"

    print(f"Looking for endpoint: {display_name}")
    print(f"  Project: {project_id}")
    print(f"  Region:  {region}")
    print()

    endpoint_id, dedicated_dns = get_endpoint_info(project_id, region, display_name)

    if not endpoint_id:
        print(f"ERROR: No endpoint found matching '{display_name}'")
        print("Make sure the model has been deployed first.")
        sys.exit(1)

    print(f"Found endpoint: {endpoint_id}")
    print(f"Dedicated DNS: {dedicated_dns}")
    print(f"Sending test prompt: \"{args.prompt}\"")
    print()

    max_retries = 20
    retry_delay = 90
    for attempt in range(1, max_retries + 1):
        try:
            response = send_prediction(project_id, region, endpoint_id, dedicated_dns, args.prompt)
            break
        except Exception as e:
            if attempt == max_retries:
                print(f"ERROR: Endpoint not ready after {max_retries} attempts. Giving up.")
                sys.exit(1)
            print(f"Attempt {attempt}/{max_retries} failed ({e}). Retrying in {retry_delay}s...")
            time.sleep(retry_delay)

    print("=" * 64)
    print("  MODEL RESPONSE")
    print("=" * 64)
    predictions = response.get("predictions", [])
    if predictions:
        for p in predictions:
            print(p)
    else:
        print(json.dumps(response, indent=2))
    print("=" * 64)
    print()
    print("Endpoint test PASSED - model is responding.")


if __name__ == "__main__":
    main()

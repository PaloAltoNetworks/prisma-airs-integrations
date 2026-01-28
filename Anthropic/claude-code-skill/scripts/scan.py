#!/usr/bin/env python3
"""
Prisma AIRS Security Scanner

Scans prompts, responses, and code for security threats using
Palo Alto Networks Prisma AI Runtime Security (AIRS) API.

Environment Variables:
    PRISMA_AIRS_API_KEY: Required - API key from Strata Cloud Manager
    PRISMA_AIRS_PROFILE: Required - Security profile name
    PRISMA_AIRS_ENDPOINT: Optional - API endpoint (defaults to US region)

Usage:
    python scan.py --type prompt --content "text to scan"
    python scan.py --type code --file path/to/file.py
    python scan.py --type response --content "AI response text"
    python scan.py --type conversation --prompt "user prompt" --response "AI response"
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from typing import Optional


DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com"
SCAN_PATH = "/v1/scan/sync/request"


def get_config() -> tuple[str, str, str]:
    """Load configuration from environment variables."""
    api_key = os.environ.get("PRISMA_AIRS_API_KEY")
    if not api_key:
        print(json.dumps({
            "status": "error",
            "error": "PRISMA_AIRS_API_KEY environment variable not set",
            "action": "block"
        }))
        sys.exit(1)

    profile = os.environ.get("PRISMA_AIRS_PROFILE")
    if not profile:
        print(json.dumps({
            "status": "error",
            "error": "PRISMA_AIRS_PROFILE environment variable not set",
            "action": "block"
        }))
        sys.exit(1)

    endpoint = os.environ.get("PRISMA_AIRS_ENDPOINT", DEFAULT_ENDPOINT)
    return api_key, profile, endpoint


def read_file(file_path: str) -> str:
    """Read content from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(json.dumps({
            "status": "error",
            "error": f"File not found: {file_path}",
            "action": "block"
        }))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "error": f"Failed to read file: {str(e)}",
            "action": "block"
        }))
        sys.exit(1)


def build_scan_request(
    scan_type: str,
    profile: str,
    content: Optional[str] = None,
    prompt: Optional[str] = None,
    response: Optional[str] = None,
    file_path: Optional[str] = None
) -> dict:
    """Build the scan request payload."""

    if file_path:
        content = read_file(file_path)

    request_payload = {
        "ai_profile": {
            "profile_name": profile
        },
        "tr_id": f"claude-skill-{os.urandom(8).hex()}"
    }

    if scan_type == "prompt":
        request_payload["contents"] = [{
            "prompt": content or ""
        }]
    elif scan_type == "response":
        request_payload["contents"] = [{
            "response": content or ""
        }]
    elif scan_type == "code":
        # Treat code as a response that the AI generated
        request_payload["contents"] = [{
            "response": content or ""
        }]
    elif scan_type == "conversation":
        request_payload["contents"] = [{
            "prompt": prompt or "",
            "response": response or ""
        }]
    else:
        request_payload["contents"] = [{
            "prompt": content or ""
        }]
    print(request_payload)
    return request_payload


def perform_scan(api_key: str, endpoint: str, payload: dict) -> dict:
    """Send scan request to AIRS API."""
    url = f"{endpoint.rstrip('/')}{SCAN_PATH}"

    headers = {
        "Content-Type": "application/json",
        "x-pan-token": api_key
    }

    data = json.dumps(payload).encode("utf-8")

    try:
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=30) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
            return response_data
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else str(e)
        return {
            "status": "error",
            "error": f"API request failed: {e.code} - {error_body}",
            "action": "block"
        }
    except urllib.error.URLError as e:
        return {
            "status": "error",
            "error": f"Network error: {str(e.reason)}",
            "action": "block"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"Unexpected error: {str(e)}",
            "action": "block"
        }


def parse_response(api_response: dict) -> dict:
    """Parse AIRS API response into standardized format."""

    if "error" in api_response:
        return api_response

    result = {
        "status": "safe",
        "action": "allow",
        "threats": [],
        "scan_id": api_response.get("scan_id", "unknown"),
        "request_id": api_response.get("req_id", "unknown")
    }

    # Extract result from API response
    api_result = api_response.get("result", {})

    # Check action from API
    action = api_result.get("action", "allow").lower()
    result["action"] = action

    # Check for detected threats
    prompt_detected = api_result.get("prompt_detected", {})
    response_detected = api_result.get("response_detected", {})

    threats = []

    # Check prompt threats
    if prompt_detected.get("injection"):
        threats.append({
            "category": "prompt_injection",
            "severity": "high",
            "location": "prompt",
            "description": "Potential prompt injection attack detected"
        })

    if prompt_detected.get("dlp"):
        threats.append({
            "category": "dlp",
            "severity": "high",
            "location": "prompt",
            "description": "Sensitive data detected in prompt (PII, credentials, or secrets)"
        })

    if prompt_detected.get("url_cats"):
        threats.append({
            "category": "malicious_url",
            "severity": "medium",
            "location": "prompt",
            "description": "Potentially malicious or suspicious URL detected in prompt"
        })

    # Check response threats
    if response_detected.get("injection"):
        threats.append({
            "category": "prompt_injection",
            "severity": "high",
            "location": "response",
            "description": "Potential prompt injection detected in response"
        })

    if response_detected.get("dlp"):
        threats.append({
            "category": "dlp",
            "severity": "high",
            "location": "response",
            "description": "Sensitive data detected in response (PII, credentials, or secrets)"
        })

    if response_detected.get("url_cats"):
        threats.append({
            "category": "malicious_url",
            "severity": "medium",
            "location": "response",
            "description": "Potentially malicious or suspicious URL detected in response"
        })

    # Update status based on threats
    if threats:
        result["status"] = "threat_detected"
        result["threats"] = threats

        # Determine overall severity
        if any(t["severity"] == "critical" for t in threats):
            result["overall_severity"] = "critical"
        elif any(t["severity"] == "high" for t in threats):
            result["overall_severity"] = "high"
        elif any(t["severity"] == "medium" for t in threats):
            result["overall_severity"] = "medium"
        else:
            result["overall_severity"] = "low"

    # Include profile info if available
    if api_result.get("profile_name"):
        result["profile"] = api_result["profile_name"]

    # Include category if specified
    if api_result.get("category"):
        result["category"] = api_result["category"]

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Scan content for security threats using Prisma AIRS"
    )
    parser.add_argument(
        "--type",
        choices=["prompt", "response", "code", "conversation"],
        default="prompt",
        help="Type of content to scan"
    )
    parser.add_argument(
        "--content",
        help="Content to scan (for prompt, response, or code types)"
    )
    parser.add_argument(
        "--file",
        help="Path to file to scan (alternative to --content)"
    )
    parser.add_argument(
        "--prompt",
        help="User prompt (for conversation type)"
    )
    parser.add_argument(
        "--response",
        help="AI response (for conversation type)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include raw API response in output"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.type == "conversation":
        if not args.prompt or not args.response:
            print(json.dumps({
                "status": "error",
                "error": "Conversation type requires both --prompt and --response",
                "action": "block"
            }))
            sys.exit(1)
    elif not args.content and not args.file:
        print(json.dumps({
            "status": "error",
            "error": "Either --content or --file is required",
            "action": "block"
        }))
        sys.exit(1)

    # Load configuration
    api_key, profile, endpoint = get_config()

    # Build request
    payload = build_scan_request(
        scan_type=args.type,
        profile=profile,
        content=args.content,
        prompt=args.prompt,
        response=args.response,
        file_path=args.file
    )

    # Perform scan
    api_response = perform_scan(api_key, endpoint, payload)

    # Parse and format response
    result = parse_response(api_response)

    # Include raw response if verbose
    if args.verbose:
        result["raw_response"] = api_response

    # Output result
    print(json.dumps(result, indent=2))

    # Exit with appropriate code
    if result.get("status") == "error":
        sys.exit(1)
    elif result.get("action") == "block":
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

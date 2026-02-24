#!/usr/bin/env python3
"""
Prisma AIRS Security Scanner

Scans prompts, responses, and code for security threats using
Palo Alto Networks Prisma AI Runtime Security (AIRS) API.

Environment Variables:
    PRISMA_AIRS_API_KEY: Required - API key from Strata Cloud Manager
    PRISMA_AIRS_PROFILE_NAME: Required - Security profile name
    PRISMA_AIRS_URL: Optional - API base URL (defaults to US region)

Usage:
    # Via heredoc (recommended):
    python scan.py --type prompt <<'EOF'
    content to scan
    EOF

    # Via file:
    python scan.py --type code --file path/to/file.py

    # Via argument (simple content only):
    python scan.py --type prompt --content "simple text"

    # Conversation (prompt + response):
    python scan.py --type conversation --prompt "user" --response "ai"
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

    profile = os.environ.get("PRISMA_AIRS_PROFILE_NAME")
    if not profile:
        print(json.dumps({
            "status": "error",
            "error": "PRISMA_AIRS_PROFILE_NAME environment variable not set",
            "action": "block"
        }))
        sys.exit(1)

    endpoint = os.environ.get("PRISMA_AIRS_URL", DEFAULT_ENDPOINT)
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
        "tr_id": f"claude-skill-{os.urandom(8).hex()}",
        "metadata": {
            "app_name": "claude-code-skill",
            "app_user": os.environ.get("USER", "claude-code-user"),
            "ai_model": "claude",
            "source": f"skill-{scan_type}"
        }
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
    """Parse AIRS API response - pass through with minimal transformation."""

    # Check for actual errors (not just the presence of "error" key)
    if api_response.get("error") or api_response.get("status") == "error":
        return api_response

    # Extract core fields from API response
    action = api_response.get("action", "allow").lower()
    category = api_response.get("category", "unknown")
    scan_id = api_response.get("scan_id", "unknown")

    # Extract detected categories (true values only)
    prompt_detected = [k for k, v in api_response.get("prompt_detected", {}).items() if v]
    response_detected = [k for k, v in api_response.get("response_detected", {}).items() if v]

    result = {
        "action": action,
        "category": category,
        "scan_id": scan_id,
        "prompt_detected": prompt_detected,
        "response_detected": response_detected
    }

    # Add status for convenience
    if action == "block":
        result["status"] = "blocked"
    elif action == "alert" or prompt_detected or response_detected:
        result["status"] = "threat_detected"
    else:
        result["status"] = "safe"

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

    # Validate arguments and handle stdin
    if args.type == "conversation":
        if not args.prompt or not args.response:
            print(json.dumps({
                "status": "error",
                "error": "Conversation type requires both --prompt and --response",
                "action": "block"
            }))
            sys.exit(1)
    elif not args.content and not args.file:
        # Try reading from stdin (supports heredoc pattern)
        if not sys.stdin.isatty():
            args.content = sys.stdin.read().strip()
        if not args.content:
            print(json.dumps({
                "status": "error",
                "error": "Provide content via --content, --file, or stdin (heredoc)",
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

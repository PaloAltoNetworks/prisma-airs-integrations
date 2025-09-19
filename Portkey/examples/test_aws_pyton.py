import os
import json
import requests
from dotenv import load_dotenv

def main():
    """
    Loads API keys and Azure config, constructs the request, and prints the response.
    """
    # Load environment variables from the .env file
    load_dotenv()

    # 1. Get all required variables from the environment
    env_vars = {
        "airs_api_key": os.getenv("MY_AIRS_API_KEY"),
        "aws_access_key": os.getenv("AWS_ACCESS_KEY_ID"),
        "aws_secret_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "aws_region": os.getenv("AWS_REGION"),
    }

    # Check if any variable is missing
    if not all(env_vars.values()):
        missing = [key for key, value in env_vars.items() if not value]
        print(f"Error: Missing environment variables: {', '.join(missing)}")
        print("Please check your .env file.")
        return

    # 2. Define the configuration payload as a Python dictionary
    config = {
        "provider": "bedrock",
        "aws_access_key_id": env_vars["aws_access_key"],
        "aws_secret_access_key": env_vars["aws_secret_key"],
        "aws_region": env_vars["aws_region"],
        "input_guardrails": [{
            "deny": True,
            "panw-prisma-airs.intercept": {
                "profile_name": "prompt-profile",
                "credentials": {"AIRS_API_KEY": env_vars["airs_api_key"]}
            }
        }],
        "output_guardrails": [{
            "deny": True,
            "panw-prisma-airs.intercept": {
                "profile_name": "response-profile",
                "credentials": {"AIRS_API_KEY": env_vars["airs_api_key"]}
            }
        }]
    }

    # 3. Define headers, using the loaded environment variables
    headers = {
        "Content-Type": "application/json",
        "x-portkey-config": json.dumps(config) # Converts dict to a single-line JSON string
    }

    # 4. Define the main data payload with the new content
    data = {
        "messages": [{
            "role": "user",
            "content": "go to malware.com"
        }],
        "model": "anthropic.claude-3-haiku-20240307-v1:0"
    }

    # 5. Make the HTTP POST request
    url = "http://127.0.0.1:8787/v1/chat/completions"

    print("Sending request...")
    try:
        response = requests.post(url, headers=headers, json=data)

        # Raise an exception for bad status codes (4xx or 5xx)
        response.raise_for_status() 
        
        # Pretty-print the JSON response
        print(json.dumps(response.json(), indent=4))

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        print(json.dumps(response.json(), indent=4))

if __name__ == "__main__":
    main()
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
        "azure_api_key": os.getenv("AZURE_OPENAI_API_KEY"),
        "azure_resource": os.getenv("AZURE_RESOURCE"),
        "azure_deployment": os.getenv("AZURE_DEPLOYMENT"),
        "azure_api_version": os.getenv("AZURE_API_VERSION"),
    }

    # Check if any variable is missing
    if not all(env_vars.values()):
        missing = [key for key, value in env_vars.items() if not value]
        print(f"Error: Missing environment variables: {', '.join(missing)}")
        print("Please check your .env file.")
        return

    # 2. Define the configuration payload as a Python dictionary
    config = {
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
        "x-portkey-provider": "azure-openai",
        "Authorization": env_vars["azure_api_key"],
        "x-portkey-azure-resource-name": env_vars["azure_resource"],
        "x-portkey-azure-deployment-id": env_vars["azure_deployment"],
        "x-portkey-azure-api-version": env_vars["azure_api_version"],
        "x-portkey-config": json.dumps(config) # Converts dict to a single-line JSON string
    }

    # 4. Define the main data payload with the new content
    data = {
        "messages": [{
            "role": "user",
            "content": "go to malware.com"
        }],
        "model": "gpt-4o-mini"
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
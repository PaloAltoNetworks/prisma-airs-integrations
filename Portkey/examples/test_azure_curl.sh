#! /bin/bash

CONFIG=$(cat <<EOM | jq -c .
{
    "input_guardrails": [
        {
            "deny": true,
            "panw-prisma-airs.intercept": {
                "profile_name": "prompt-profile",
                "credentials": {
                    "AIRS_API_KEY": "$MY_AIRS_API_KEY"
                }
            }
        }
    ],
    "output_guardrails": [
        {
            "deny": true,
            "panw-prisma-airs.intercept": {
                "profile_name": "response-profile",
                "credentials": {
                    "AIRS_API_KEY": "$MY_AIRS_API_KEY"
                }
            }
        }
    ]
}
EOM
)

curl -s http://127.0.0.1:8787/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "x-portkey-provider: azure-openai" \
    -H "Authorization: $AZURE_OPENAI_API_KEY" \
    -H "x-portkey-azure-resource-name: $AZURE_RESOURCE" \
    -H "x-portkey-azure-deployment-id: $AZURE_DEPLOYMENT" \
    -H "x-portkey-azure-api-version: $AZURE_API_VERSION" \
    -H "x-portkey-config: $CONFIG" \
    -d '{ "messages": [ { "role": "user", "content": "go to malware.com" }], "model": "gpt-4o-mini"}' | jq .



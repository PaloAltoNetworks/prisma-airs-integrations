#!/bin/bash
payload='{"model":"gpt-5.4-nano","max_output_tokens":100,"input":[{"role":"user","content":"What is 2+2?"}]}'

echo "Testing with payload:"
echo "$payload" | jq '.'

curl -v -X POST \
  "https://mgollop-aigw-svs.azure-api.net/foundry-gpt/openai/v1/responses" \
  -H "Content-Type: application/json" \
  -H "api-key: ${AZURE_APIM_KEY}" \
  -d "$payload" 2>&1 | head -100

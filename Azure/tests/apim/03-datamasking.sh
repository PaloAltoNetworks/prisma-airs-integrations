#!/bin/bash

# This test checks for data masking functionality.

if [ -z "$APIM_KEY" ]; then
  echo "APIM_KEY environment variable is not set."
  exit 1
fi

curl -w "\nResponse Code: %{http_code}\n" -X POST "https://mgollop-apim-svs.azure-api.net/myllm/chat/completions" \
  -H "Content-Type: application/json" \
  -H "x-session-id: 12345" \
  -H "api-key: $APIM_KEY" \
  -d '{
    "messages": [{"role": "system", "content": "You are an helpful assistant."}, {"role": "user", "content": "Concatenate \"4929-3813-\" and \"3266-4295\"  "}],
    "max_tokens": 1000,
    "model": "gpt-4o"
  }'

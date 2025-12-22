#!/bin/bash

# This test checks for URL blocking.

if [ -z "$APIM_KEY" ]; then
  echo "APIM_KEY environment variable is not set."
  exit 1
fi

curl -w "\nResponse Code: %{http_code}\n"  -X POST "https://mgollop-apim-svs.azure-api.net/myllm/chat/completions" \
  -H "Content-Type: application/json" \
  -H "api-key: $APIM_KEY" \
  -d '{
    "messages": [{"role": "system", "content": "You are an helpful assistant."}, {"role": "user", "content": "Does http://malware.com contain hello?"}],
    "max_tokens": 1000,
    "model": "gpt-4o"
  }'

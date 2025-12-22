#!/bin/bash

# This test checks that the GET /models endpoint returns correctly.

if [ -z "$APIM_KEY" ]; then
  echo "APIM_KEY environment variable is not set."
  exit 1
fi

curl -X GET "https://mgollop-apim-svs.azure-api.net/myllm/models" \
  -H "api-key: $APIM_KEY"

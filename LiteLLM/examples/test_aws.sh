curl -X POST http://localhost:4000/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-haiku",
    "messages": [
      {
        "role": "user",
        "content": "make `My drivers license is 02392390` uppercase"
      }
    ]
  }'
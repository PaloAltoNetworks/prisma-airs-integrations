"""Request and reply bodies per api_type, built from the documented shapes (brief A1, A13)."""
import json

CHAT = ("mlflow/v1/chat/completions", "openai/v1/chat/completions", "cursor/v1/chat/completions")
RESPONSES = ("mlflow/v1/responses", "openai/v1/responses")
EMBEDDINGS = ("mlflow/v1/embeddings", "openai/v1/embeddings")
GEMINI = ("gemini/v1/generateContent", "gemini/v1/streamGenerateContent")


def call_body(api_type, text):
    if api_type in CHAT:
        return {"model": "m", "max_tokens": 64,
                "messages": [{"role": "system", "content": "You are helpful."}, {"role": "user", "content": text}]}
    if api_type in RESPONSES:
        return {"model": "m", "instructions": "Be brief.",
                "input": [{"role": "user", "content": [{"type": "input_text", "text": text}]}]}
    if api_type in EMBEDDINGS:
        return {"model": "m", "input": [text]}
    if api_type == "anthropic/v1/messages":
        return {"model": "m", "system": "Be brief.", "max_tokens": 64,
                "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}]}
    if api_type in GEMINI:
        return {"systemInstruction": {"parts": [{"text": "Be brief."}]},
                "contents": [{"role": "user", "parts": [{"text": text}]}]}
    raise KeyError(api_type)


def reply_body(api_type, text):
    if api_type in CHAT:
        return {"id": "c1", "object": "chat.completion", "model": "m",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}
    if api_type in RESPONSES:
        return {"id": "r1", "object": "response",
                "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}]}
    if api_type == "anthropic/v1/messages":
        return {"id": "m1", "type": "message", "role": "assistant", "content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn"}
    if api_type in GEMINI:
        return {"candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finishReason": "STOP"}]}
    raise KeyError(api_type)


def placed(where, card):
    """An openai chat request with the card only in one place."""
    msgs = [{"role": "system", "content": "You are helpful."}, {"role": "user", "content": "Hello"}]
    body = {"model": "m", "messages": msgs}
    if where == "system":
        msgs[0]["content"] = card
    elif where == "developer":
        msgs.insert(1, {"role": "developer", "content": card})
    elif where == "assistant":
        msgs.insert(1, {"role": "assistant", "content": card})
    elif where == "assistant_prefill":
        msgs.append({"role": "assistant", "content": card})
    elif where == "tool_calls_arguments":
        msgs.append({"role": "assistant", "content": None, "tool_calls": [
            {"id": "t1", "type": "function", "function": {"name": "f", "arguments": json.dumps({"note": card})}}]})
    elif where == "tool_result_message":
        msgs.append({"role": "tool", "tool_call_id": "t1", "content": card})
    elif where == "instructions":
        body["instructions"] = card
    elif where == "tool_description":
        body["tools"] = [{"type": "function", "function": {"name": "f", "description": card, "parameters": {}}}]
    elif where == "unknown_field":
        body["zzz_extra"] = {"deep": [card]}
    elif where == "anthropic_text_document":
        body["messages"][1]["content"] = [{"type": "document", "source": {"type": "text", "media_type": "text/plain",
                                                                          "data": card}}]
    else:
        raise KeyError(where)
    return body


PARTS = {
    "image_url": {"type": "image_url", "image_url": {"url": "https://example.invalid/i.png"}},
    "input_audio": {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
    "file": {"type": "file", "file": {"file_id": "f-1"}},
    "image": {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
    "document": {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "AAAA"}},
}


def with_part(name):
    return {"model": "m", "messages": [{"role": "user", "content": [{"type": "text", "text": "Hello"}, PARTS[name]]}]}

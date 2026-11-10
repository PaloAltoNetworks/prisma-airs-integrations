//! Which LLM API format a request is in, whether it asks for a stream, and which model it names.
//!
//! On Model Proxy the gateway's own `x-input-format` header names the format, so it decides first. Without it, the
//! path decides, and without a known path, the body's shape, but only when the shape cannot be mistaken.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// OpenAI Chat Completions (`/chat/completions`).
    OpenAiChat,
    /// OpenAI Responses (`/responses`).
    OpenAiResponses,
    /// Anthropic Messages (`/messages`).
    AnthropicMessages,
    /// Gemini `generateContent` and `streamGenerateContent`.
    Gemini,
}

impl Format {
    /// A stable name for logs and evidence.
    pub fn name(self) -> &'static str {
        match self {
            Format::OpenAiChat => "openai_chat",
            Format::OpenAiResponses => "openai_responses",
            Format::AnthropicMessages => "anthropic_messages",
            Format::Gemini => "gemini",
        }
    }

    /// `None` means the policy cannot tell, which the caller treats as content it could not inspect.
    pub fn detect(input_format: Option<&str>, path: &str, body: &Value) -> Option<Format> {
        let path = without_query(path);
        match input_format.map(|h| h.trim().to_ascii_lowercase()).as_deref() {
            Some("openai") if path.ends_with("/responses") => return Some(Format::OpenAiResponses),
            Some("openai") => return Some(Format::OpenAiChat),
            Some("anthropic") => return Some(Format::AnthropicMessages),
            Some("gemini") => return Some(Format::Gemini),
            _ => {}
        }
        by_path(path).or_else(|| by_body(body))
    }
}

/// Whether the caller asked for a streamed reply.
pub fn is_streamed(format: Format, path: &str, body: &Value) -> bool {
    match format {
        Format::Gemini => without_query(path).ends_with(":streamGenerateContent"),
        _ => body.get("stream").and_then(Value::as_bool).unwrap_or(false),
    }
}

/// The model the request names: the body's `model`, or for Gemini the `{model}` in `/models/{model}:...`.
pub fn requested_model(format: Format, path: &str, body: &Value) -> Option<String> {
    if let Some(model) = body.get("model").and_then(Value::as_str).map(str::trim).filter(|m| !m.is_empty()) {
        return Some(model.to_string());
    }
    if format != Format::Gemini {
        return None;
    }
    let path = without_query(path);
    let start = path.find("/models/")? + "/models/".len();
    let model = path[start..].split([':', '/']).next().unwrap_or("");
    (!model.is_empty()).then(|| model.to_string())
}

fn without_query(path: &str) -> &str {
    path.split(['?', '#']).next().unwrap_or("")
}

fn by_path(path: &str) -> Option<Format> {
    if path.ends_with("/chat/completions") {
        Some(Format::OpenAiChat)
    } else if path.ends_with("/responses") {
        Some(Format::OpenAiResponses)
    } else if path.ends_with("/messages") {
        Some(Format::AnthropicMessages)
    } else if path.ends_with(":generateContent") || path.ends_with(":streamGenerateContent") {
        Some(Format::Gemini)
    } else {
        None
    }
}

/// `messages` could be OpenAI or Anthropic, so a body with it is never guessed.
fn by_body(body: &Value) -> Option<Format> {
    let obj = body.as_object()?;
    if obj.contains_key("messages") {
        None
    } else if obj.contains_key("contents") {
        Some(Format::Gemini)
    } else if obj.contains_key("input") {
        Some(Format::OpenAiResponses)
    } else {
        None
    }
}

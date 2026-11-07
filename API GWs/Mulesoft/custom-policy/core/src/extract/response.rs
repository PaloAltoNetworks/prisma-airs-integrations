//! The response leg: which text of a reply is scanned.
//!
//! The reply's text (one entry per choice, candidate or text block), every tool call the model makes (its name and
//! arguments), and its visible thinking are all scanned. A reply that holds only a tool call is not empty: it is the
//! case that matters most. A streamed reply is first rebuilt into this same JSON shape (`crate::sse`), so streamed
//! and non-streamed replies go through this one extractor.

use serde_json::{Map, Value};

use super::{assemble, without_binary, ExtractError, Extracted, Piece, Slot};
use crate::format::Format;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub name: String,
    /// The arguments as the model wrote them: a JSON string as it is, a JSON object serialized.
    pub arguments: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseParts {
    /// Non-blank texts: one per choice (OpenAI), text block (Anthropic) or candidate (Gemini).
    pub texts: Vec<String>,
    pub tool_calls: Vec<ToolCall>,
    pub thinking: Vec<String>,
    /// The JSON pointer of the text when exactly one string field holds all of the scanned text, so masked text can
    /// be written back. For a rebuilt stream it points into the rebuilt JSON, and is never used to write.
    pub pointer: Option<String>,
}

impl ResponseParts {
    pub fn is_empty(&self) -> bool {
        self.texts.iter().all(|t| t.trim().is_empty())
            && self.tool_calls.is_empty()
            && self.thinking.iter().all(|t| t.trim().is_empty())
    }
}

/// The text to scan: texts, then `tool <name>: <arguments>` lines, then thinking, joined with a blank line.
pub fn scan_text(parts: &ResponseParts, max_chars: usize) -> Extracted {
    let mut pieces: Vec<Piece> = Vec::new();
    pieces.extend(parts.texts.iter().map(|t| Piece { text: t.clone(), pointer: None }));
    pieces.extend(
        parts.tool_calls.iter().map(|c| Piece { text: format!("tool {}: {}", c.name, c.arguments), pointer: None }),
    );
    pieces.extend(parts.thinking.iter().map(|t| Piece { text: t.clone(), pointer: None }));
    match assemble(pieces, max_chars) {
        Ok(mut extracted) => {
            extracted.slot = match (&parts.pointer, extracted.truncated) {
                (Some(pointer), false) => Slot::Single(pointer.clone()),
                _ => Slot::Multi,
            };
            extracted
        }
        Err(_) => Extracted { text: String::new(), truncated: false, slot: Slot::Multi },
    }
}

/// Reads a reply body (or a rebuilt stream) of `format`.
pub fn from_value(format: Format, body: &Value) -> Result<ResponseParts, ExtractError> {
    let obj = body.as_object().ok_or_else(|| unreadable("the reply is not a JSON object"))?;
    let mut c = Collect::default();
    match format {
        Format::OpenAiChat => openai_chat(obj, &mut c)?,
        Format::OpenAiResponses => openai_responses(obj, &mut c)?,
        Format::AnthropicMessages => anthropic(obj, &mut c)?,
        Format::Gemini => gemini(obj, &mut c)?,
    }
    Ok(c.finish())
}

fn unreadable(why: &str) -> ExtractError {
    ExtractError::Unreadable(why.to_string())
}

fn serialize(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn arguments(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => serialize(other),
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

#[derive(Default)]
struct Collect {
    parts: ResponseParts,
    /// One entry per text field that contributed: its pointer, or `None` when the text was combined or serialized.
    fields: Vec<Option<String>>,
}

impl Collect {
    fn text(&mut self, text: &str, pointer: Option<String>) {
        if text.trim().is_empty() {
            return;
        }
        self.parts.texts.push(text.to_string());
        self.fields.push(pointer);
    }

    fn tool(&mut self, name: &str, args: String) {
        self.parts.tool_calls.push(ToolCall { name: name.to_string(), arguments: args });
    }

    fn thinking(&mut self, text: &str) {
        if !text.trim().is_empty() {
            self.parts.thinking.push(text.to_string());
        }
    }

    fn finish(mut self) -> ResponseParts {
        let only_text = self.parts.tool_calls.is_empty() && self.parts.thinking.is_empty();
        self.parts.pointer = match self.fields.as_slice() {
            [Some(pointer)] if only_text => Some(pointer.clone()),
            _ => None,
        };
        self.parts
    }
}

fn openai_chat(obj: &Map<String, Value>, c: &mut Collect) -> Result<(), ExtractError> {
    let choices = obj.get("choices").and_then(Value::as_array).ok_or_else(|| unreadable("the reply has no choices"))?;
    for (i, choice) in choices.iter().enumerate() {
        if let Some(message) = choice.get("message") {
            match message.get("content") {
                Some(Value::String(s)) => c.text(s, Some(format!("/choices/{i}/message/content"))),
                Some(Value::Array(parts)) => {
                    let joined: String = parts.iter().filter_map(|p| str_of(p, "text")).collect();
                    c.text(&joined, None);
                }
                _ => {}
            }
            if let Some(refusal) = str_of(message, "refusal") {
                c.text(refusal, Some(format!("/choices/{i}/message/refusal")));
            }
            if let Some(reasoning) = str_of(message, "reasoning_content") {
                c.thinking(reasoning);
            }
            for call in message.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
                let function = call.get("function");
                let name = function.and_then(|f| str_of(f, "name")).unwrap_or("unknown");
                c.tool(name, arguments(function.and_then(|f| f.get("arguments"))));
            }
            if let Some(call) = message.get("function_call") {
                c.tool(str_of(call, "name").unwrap_or("unknown"), arguments(call.get("arguments")));
            }
        } else if let Some(text) = str_of(choice, "text") {
            c.text(text, Some(format!("/choices/{i}/text")));
        }
    }
    Ok(())
}

fn openai_responses(obj: &Map<String, Value>, c: &mut Collect) -> Result<(), ExtractError> {
    let output = obj.get("output").and_then(Value::as_array).ok_or_else(|| unreadable("the reply has no output"))?;
    for (i, item) in output.iter().enumerate() {
        match str_of(item, "type").unwrap_or("message") {
            "message" => {
                for (j, part) in item.get("content").and_then(Value::as_array).into_iter().flatten().enumerate() {
                    if let Some(text) = str_of(part, "text") {
                        c.text(text, Some(format!("/output/{i}/content/{j}/text")));
                    } else if let Some(refusal) = str_of(part, "refusal") {
                        c.text(refusal, Some(format!("/output/{i}/content/{j}/refusal")));
                    } else {
                        c.text(&serialize(part), None);
                    }
                }
            }
            "function_call" => c.tool(str_of(item, "name").unwrap_or("unknown"), arguments(item.get("arguments"))),
            "custom_tool_call" => c.tool(str_of(item, "name").unwrap_or("unknown"), arguments(item.get("input"))),
            "reasoning" => {
                for summary in item.get("summary").and_then(Value::as_array).into_iter().flatten() {
                    if let Some(text) = str_of(summary, "text") {
                        c.thinking(text);
                    }
                }
            }
            // Search results, MCP and other tool items carry content back to the caller: scanned, not dropped.
            _ => c.text(&serialize(item), None),
        }
    }
    Ok(())
}

fn anthropic(obj: &Map<String, Value>, c: &mut Collect) -> Result<(), ExtractError> {
    let content = obj.get("content").and_then(Value::as_array).ok_or_else(|| unreadable("the reply has no content"))?;
    for (j, block) in content.iter().enumerate() {
        match str_of(block, "type") {
            Some("text") => c.text(str_of(block, "text").unwrap_or(""), Some(format!("/content/{j}/text"))),
            Some("tool_use") | Some("server_tool_use") => {
                c.tool(str_of(block, "name").unwrap_or("unknown"), arguments(block.get("input")));
            }
            Some("thinking") => c.thinking(str_of(block, "thinking").unwrap_or("")),
            Some("redacted_thinking") => {}
            // Server tool results and other blocks carry content back to the caller: scanned, not dropped.
            _ => c.text(&serialize(block), None),
        }
    }
    Ok(())
}

fn gemini(obj: &Map<String, Value>, c: &mut Collect) -> Result<(), ExtractError> {
    let candidates = match obj.get("candidates") {
        Some(Value::Array(list)) => list,
        // A prompt Gemini blocked comes back with feedback and no candidates: nothing reached the caller.
        None if obj.contains_key("promptFeedback") => return Ok(()),
        _ => return Err(unreadable("the reply has no candidates")),
    };
    for (i, candidate) in candidates.iter().enumerate() {
        let parts = candidate.get("content").and_then(|content| content.get("parts")).and_then(Value::as_array);
        // A candidate's text parts form one text: a stream splits it at arbitrary points ("Pari" + "s").
        let mut joined = String::new();
        let mut fields: Vec<String> = Vec::new();
        for (j, part) in parts.into_iter().flatten().enumerate() {
            let field = |camel: &str, snake: &str| part.get(camel).or_else(|| part.get(snake)).filter(|v| !v.is_null());
            if let Some(text) = str_of(part, "text") {
                if part.get("thought").and_then(Value::as_bool).unwrap_or(false) {
                    c.thinking(text);
                } else {
                    if !text.is_empty() {
                        fields.push(format!("/candidates/{i}/content/parts/{j}/text"));
                    }
                    joined.push_str(text);
                }
            } else if let Some(call) = field("functionCall", "function_call") {
                c.tool(str_of(call, "name").unwrap_or("unknown"), arguments(call.get("args")));
            } else if let Some(code) = field("executableCode", "executable_code") {
                c.text(&arguments(code.get("code")), None);
            } else if let Some(result) = field("codeExecutionResult", "code_execution_result") {
                c.text(&arguments(result.get("output")), None);
            } else {
                // Images, files and part types this extractor does not know: scanned, not dropped (R10).
                c.text(&without_binary(part), None);
            }
        }
        let pointer = match fields.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        };
        c.text(&joined, pointer);
        // Search grounding, citations and URL context carry sources back to the caller: scanned, not dropped.
        for (camel, snake) in GEMINI_METADATA {
            if let Some(meta) = candidate.get(camel).or_else(|| candidate.get(snake)).filter(|v| !v.is_null()) {
                c.text(&without_binary(meta), None);
            }
        }
    }
    Ok(())
}

/// The candidate fields that hold sources a Gemini reply passes to the caller.
pub const GEMINI_METADATA: [(&str, &str); 3] = [
    ("groundingMetadata", "grounding_metadata"),
    ("citationMetadata", "citation_metadata"),
    ("urlContextMetadata", "url_context_metadata"),
];

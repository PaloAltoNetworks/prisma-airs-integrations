//! Server-sent events: parsing a buffered `text/event-stream` body, and rebuilding each format's streamed reply into
//! the JSON shape of its non-streamed reply, so one extractor reads both kinds.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::extract::ExtractError;
use crate::format::Format;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Parses a whole stream. Comment lines and `id:`/`retry:` fields are ignored, the `data:` lines of one event are
/// joined with `\n`, CRLF, CR and LF all end a line, and an event still open at the end of the body counts.
pub fn events(body: &[u8]) -> Vec<SseEvent> {
    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();
    let mut event: Option<String> = None;
    let mut data: Vec<String> = Vec::new();
    for line in lines(&text) {
        if line.is_empty() {
            dispatch(&mut out, &mut event, &mut data);
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.find(':') {
            Some(i) => {
                let value = &line[i + 1..];
                (&line[..i], value.strip_prefix(' ').unwrap_or(value))
            }
            None => (line, ""),
        };
        match field {
            "event" => event = Some(value.to_string()),
            "data" => data.push(value.to_string()),
            _ => {}
        }
    }
    dispatch(&mut out, &mut event, &mut data);
    out
}

fn dispatch(out: &mut Vec<SseEvent>, event: &mut Option<String>, data: &mut Vec<String>) {
    let name = event.take();
    if !data.is_empty() {
        out.push(SseEvent { event: name, data: data.join("\n") });
        data.clear();
    }
}

fn lines(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                out.push(&text[start..i]);
                if bytes.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
                start = i + 1;
            }
            b'\n' => {
                out.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < bytes.len() {
        out.push(&text[start..]);
    }
    out
}

/// Rebuilds a streamed reply as the format's non-streamed JSON. Every event's data must be JSON (or `[DONE]`): a
/// stream the policy cannot read is reported as unreadable, never treated as empty.
pub fn to_final_json(format: Format, events: &[SseEvent]) -> Result<Value, ExtractError> {
    let mut frames = Vec::with_capacity(events.len());
    for e in events {
        let data = e.data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| ExtractError::Unreadable("a stream event is not JSON".into()))?;
        let kind = value.get("type").and_then(Value::as_str).map(str::to_string).or_else(|| e.event.clone());
        frames.push((kind.unwrap_or_default(), value));
    }
    Ok(match format {
        Format::OpenAiChat => openai_chat(&frames),
        Format::OpenAiResponses => openai_responses(&frames),
        Format::AnthropicMessages => anthropic(&frames),
        Format::Gemini => gemini(&frames),
    })
}

type Frames = [(String, Value)];

fn index(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// Appends `delta` to the string at `obj[key]`, creating it.
fn append(obj: &mut Value, key: &str, delta: &str) {
    if !obj.is_object() {
        *obj = Value::Object(Map::new());
    }
    let current = obj.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    obj[key] = Value::String(current + delta);
}

// ---- OpenAI Chat Completions --------------------------------------------------------------------------------------

#[derive(Default)]
struct ChatChoice {
    content: Option<String>,
    refusal: Option<String>,
    reasoning: Option<String>,
    tools: BTreeMap<u64, (String, String, String)>,
}

fn push_opt(slot: &mut Option<String>, delta: &str) {
    slot.get_or_insert_with(String::new).push_str(delta);
}

fn openai_chat(frames: &Frames) -> Value {
    let mut choices: BTreeMap<u64, ChatChoice> = BTreeMap::new();
    for (_, frame) in frames {
        // Azure's first event carries prompt-filter results and an empty `choices`; usage-only events do too.
        for choice in frame.get("choices").and_then(Value::as_array).into_iter().flatten() {
            let acc = choices.entry(index(choice, "index")).or_default();
            let Some(delta) = choice.get("delta") else { continue };
            if let Some(s) = delta.get("content").and_then(Value::as_str) {
                push_opt(&mut acc.content, s);
            }
            if let Some(s) = delta.get("refusal").and_then(Value::as_str) {
                push_opt(&mut acc.refusal, s);
            }
            if let Some(s) = delta.get("reasoning_content").or_else(|| delta.get("reasoning")).and_then(Value::as_str) {
                push_opt(&mut acc.reasoning, s);
            }
            for call in delta.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
                let (id, name, args) = acc.tools.entry(index(call, "index")).or_default();
                if let Some(v) = call.get("id").and_then(Value::as_str).filter(|v| !v.is_empty()) {
                    *id = v.to_string();
                }
                if let Some(function) = call.get("function") {
                    if let Some(v) = function.get("name").and_then(Value::as_str).filter(|v| !v.is_empty()) {
                        if name.is_empty() {
                            *name = v.to_string();
                        }
                    }
                    if let Some(v) = function.get("arguments").and_then(Value::as_str) {
                        args.push_str(v);
                    }
                }
            }
        }
    }
    let list: Vec<Value> = choices
        .into_iter()
        .map(|(i, c)| {
            let mut message = json!({"role": "assistant", "content": c.content});
            if let Some(refusal) = c.refusal {
                message["refusal"] = Value::String(refusal);
            }
            if let Some(reasoning) = c.reasoning {
                message["reasoning_content"] = Value::String(reasoning);
            }
            if !c.tools.is_empty() {
                let calls: Vec<Value> = c
                    .tools
                    .into_values()
                    .map(|(id, name, args)| json!({"id": id, "type": "function", "function": {"name": name, "arguments": args}}))
                    .collect();
                message["tool_calls"] = Value::Array(calls);
            }
            json!({"index": i, "message": message})
        })
        .collect();
    json!({ "choices": list })
}

// ---- OpenAI Responses -----------------------------------------------------------------------------------------------

fn openai_responses(frames: &Frames) -> Value {
    for (kind, frame) in frames.iter().rev() {
        if matches!(kind.as_str(), "response.completed" | "response.incomplete" | "response.failed") {
            if let Some(response) = frame.get("response").filter(|r| r.get("output").is_some()) {
                return response.clone();
            }
        }
    }
    let mut items: BTreeMap<u64, Value> = BTreeMap::new();
    for (kind, frame) in frames {
        let at = index(frame, "output_index");
        match kind.as_str() {
            "response.output_item.added" => {
                if let Some(item) = frame.get("item") {
                    items.entry(at).or_insert_with(|| item.clone());
                }
            }
            "response.output_item.done" => {
                if let Some(item) = frame.get("item") {
                    items.insert(at, item.clone());
                }
            }
            "response.output_text.delta" | "response.refusal.delta" => {
                let key = if kind == "response.refusal.delta" { "refusal" } else { "text" };
                let delta = frame.get("delta").and_then(Value::as_str).unwrap_or("");
                let item = items.entry(at).or_insert_with(|| json!({"type": "message", "role": "assistant", "content": []}));
                let content = &mut item["content"];
                if !content.is_array() {
                    *content = json!([]);
                }
                let parts = content.as_array_mut().expect("content is an array");
                let part_at = index(frame, "content_index") as usize;
                while parts.len() <= part_at {
                    parts.push(json!({"type": if key == "refusal" { "refusal" } else { "output_text" }}));
                }
                append(&mut parts[part_at], key, delta);
            }
            "response.function_call_arguments.delta" => {
                let delta = frame.get("delta").and_then(Value::as_str).unwrap_or("");
                let item = items.entry(at).or_insert_with(|| json!({"type": "function_call"}));
                append(item, "arguments", delta);
            }
            "response.reasoning_summary_text.delta" => {
                let delta = frame.get("delta").and_then(Value::as_str).unwrap_or("");
                let item = items.entry(at).or_insert_with(|| json!({"type": "reasoning", "summary": []}));
                let summary = &mut item["summary"];
                if !summary.is_array() {
                    *summary = json!([]);
                }
                let parts = summary.as_array_mut().expect("summary is an array");
                let part_at = index(frame, "summary_index") as usize;
                while parts.len() <= part_at {
                    parts.push(json!({"type": "summary_text"}));
                }
                append(&mut parts[part_at], "text", delta);
            }
            _ => {}
        }
    }
    json!({ "output": items.into_values().collect::<Vec<_>>() })
}

// ---- Anthropic Messages ---------------------------------------------------------------------------------------------

fn anthropic(frames: &Frames) -> Value {
    let mut message = json!({ "content": [] });
    let mut blocks: BTreeMap<u64, Value> = BTreeMap::new();
    let mut partial_json: BTreeMap<u64, String> = BTreeMap::new();
    for (kind, frame) in frames {
        match kind.as_str() {
            "message_start" => {
                if let Some(m) = frame.get("message") {
                    message = m.clone();
                    for (i, block) in m.get("content").and_then(Value::as_array).into_iter().flatten().enumerate() {
                        blocks.insert(i as u64, block.clone());
                    }
                }
            }
            "content_block_start" => {
                if let Some(block) = frame.get("content_block") {
                    blocks.insert(index(frame, "index"), block.clone());
                }
            }
            "content_block_delta" => {
                let at = index(frame, "index");
                let Some(delta) = frame.get("delta") else { continue };
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        let text = delta.get("text").and_then(Value::as_str).unwrap_or("");
                        append(blocks.entry(at).or_insert_with(|| json!({"type": "text"})), "text", text);
                    }
                    Some("thinking_delta") => {
                        let text = delta.get("thinking").and_then(Value::as_str).unwrap_or("");
                        append(blocks.entry(at).or_insert_with(|| json!({"type": "thinking"})), "thinking", text);
                    }
                    Some("input_json_delta") => {
                        let piece = delta.get("partial_json").and_then(Value::as_str).unwrap_or("");
                        blocks.entry(at).or_insert_with(|| json!({"type": "tool_use"}));
                        partial_json.entry(at).or_default().push_str(piece);
                    }
                    _ => {}
                }
            }
            // The stream ended in an error: keep what had already arrived, it reached the client side of the gateway.
            "error" => break,
            _ => {}
        }
    }
    for (at, text) in partial_json {
        if text.trim().is_empty() {
            continue;
        }
        let block = blocks.entry(at).or_insert_with(|| json!({"type": "tool_use"}));
        block["input"] = serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text));
    }
    if !message.is_object() {
        message = json!({});
    }
    message["content"] = Value::Array(blocks.into_values().collect());
    message
}

// ---- Gemini ---------------------------------------------------------------------------------------------------------

fn gemini(frames: &Frames) -> Value {
    let mut candidates: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
    // Grounding, citation and URL-context metadata, per candidate: the newest frame's value of each field wins.
    let mut metadata: BTreeMap<u64, Map<String, Value>> = BTreeMap::new();
    let mut feedback: Option<Value> = None;
    for (_, frame) in frames {
        if frame.get("error").is_some() {
            break;
        }
        if let Some(pf) = frame.get("promptFeedback") {
            feedback = Some(pf.clone());
        }
        for candidate in frame.get("candidates").and_then(Value::as_array).into_iter().flatten() {
            let at = index(candidate, "index");
            let parts = candidates.entry(at).or_default();
            let new = candidate.get("content").and_then(|c| c.get("parts")).and_then(Value::as_array);
            parts.extend(new.into_iter().flatten().cloned());
            for (camel, snake) in crate::extract::response::GEMINI_METADATA {
                for key in [camel, snake] {
                    if let Some(meta) = candidate.get(key).filter(|v| !v.is_null()) {
                        metadata.entry(at).or_default().insert(key.to_string(), meta.clone());
                    }
                }
            }
        }
    }
    let list: Vec<Value> = candidates
        .into_iter()
        .map(|(i, parts)| {
            let mut candidate = json!({"index": i, "content": {"role": "model", "parts": parts}});
            for (key, meta) in metadata.remove(&i).unwrap_or_default() {
                candidate[key] = meta;
            }
            candidate
        })
        .collect();
    let mut out = json!({ "candidates": list });
    if let Some(pf) = feedback {
        out["promptFeedback"] = pf;
    }
    out
}

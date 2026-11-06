//! The prompt leg: which text of a request is scanned.
//!
//! Each format is read into the same list of turns (who spoke, their text, their non-text parts). One assembler then
//! applies the rules for every format:
//!
//! - the newest user turn is always scanned, and earlier user turns are not;
//! - system, assistant and tool turns are scanned when their role is configured, in conversation order;
//! - every text part of a turn is read, and a turn with no text is scanned as the JSON of its other parts.
//!
//! A tool call the model made earlier (`tool_calls`, `tool_use`, `functionCall`) is assistant text, written as
//! `tool <name>: <arguments>`. A tool result is a tool turn in every format.

use serde_json::{Map, Value};

use super::{assemble, ExtractError, Extracted, Piece};
use crate::format::Format;
use crate::settings::{Role, RoleSet};

type Obj = Map<String, Value>;

/// The prompt text to scan for a request in `format`.
pub fn prompt_text(format: Format, body: &Value, roles: &RoleSet, max_chars: usize) -> Result<Extracted, ExtractError> {
    let obj = body.as_object().ok_or_else(|| unreadable("the body is not a JSON object"))?;
    let turns = match format {
        Format::OpenAiChat => openai_chat(obj)?,
        Format::OpenAiResponses => openai_responses(obj)?,
        Format::AnthropicMessages => anthropic(obj)?,
        Format::Gemini => gemini(obj)?,
    };
    assemble(select(turns, roles), max_chars)
}

struct Turn {
    role: Role,
    texts: Vec<Piece>,
    others: Vec<Value>,
}

impl Turn {
    fn has_content(&self) -> bool {
        self.texts.iter().any(|p| !p.text.trim().is_empty()) || !self.others.is_empty()
    }
}

/// Collects turns. Within one message, consecutive parts of the same role share a turn; a new message always starts
/// a new turn, so two user messages in a row are two turns.
#[derive(Default)]
struct Turns {
    list: Vec<Turn>,
    split: bool,
}

impl Turns {
    fn current(&mut self, role: Role) -> &mut Turn {
        let reuse = !self.split && self.list.last().is_some_and(|t| t.role == role);
        if !reuse {
            self.list.push(Turn { role, texts: Vec::new(), others: Vec::new() });
        }
        self.split = false;
        self.list.last_mut().expect("a turn was just pushed")
    }

    fn text(&mut self, role: Role, text: &str, pointer: Option<String>) {
        self.current(role).texts.push(Piece { text: text.to_string(), pointer });
    }

    fn other(&mut self, role: Role, value: &Value) {
        self.current(role).others.push(value.clone());
    }

    fn tool_call(&mut self, name: &str, arguments: &str) {
        self.text(Role::Assistant, &format!("tool {name}: {arguments}"), None);
    }

    fn end_message(&mut self) {
        self.split = true;
    }
}

fn select(turns: Turns, roles: &RoleSet) -> Vec<Piece> {
    let turns = turns.list;
    let newest_user = turns.iter().rposition(|t| t.role == Role::User && t.has_content());
    let mut pieces = Vec::new();
    for (i, turn) in turns.into_iter().enumerate() {
        let wanted = match turn.role {
            Role::User => Some(i) == newest_user,
            role => roles.contains(role),
        };
        if !wanted || !turn.has_content() {
            continue;
        }
        if turn.texts.iter().any(|p| !p.text.trim().is_empty()) {
            pieces.extend(turn.texts);
        } else {
            pieces.push(Piece { text: serialize(&Value::Array(turn.others)), pointer: None });
        }
    }
    pieces
}

fn unreadable(why: impl Into<String>) -> ExtractError {
    ExtractError::Unreadable(why.into())
}

fn serialize(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// A value that may be absent, `null`, or a list.
fn list<'a>(obj: &'a Obj, key: &str) -> Result<Option<&'a Vec<Value>>, ExtractError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => Ok(Some(items)),
        Some(_) => Err(unreadable(format!("{key} is not a list"))),
    }
}

fn str_field<'a>(obj: &'a Obj, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

/// A tool call's arguments as text: a string as it is, anything else as JSON.
fn arguments(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => serialize(other),
    }
}

// ---- OpenAI Chat Completions ----------------------------------------------------------------------------------

fn openai_chat(obj: &Obj) -> Result<Turns, ExtractError> {
    let mut turns = Turns::default();
    let Some(messages) = list(obj, "messages")? else { return Ok(turns) };
    for (i, message) in messages.iter().enumerate() {
        let m = message.as_object().ok_or_else(|| unreadable(format!("messages/{i} is not an object")))?;
        // An unknown role is scanned as user text rather than skipped.
        let role = match str_field(m, "role").unwrap_or("user") {
            "system" | "developer" => Role::System,
            "assistant" => Role::Assistant,
            "tool" | "function" => Role::Tool,
            _ => Role::User,
        };
        let base = format!("/messages/{i}/content");
        match m.get("content") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => turns.text(role, s, Some(base)),
            Some(Value::Array(parts)) => {
                for (j, part) in parts.iter().enumerate() {
                    match part_text(part, &["text", "refusal"]) {
                        Some((key, text)) => turns.text(role, text, Some(format!("{base}/{j}/{key}"))),
                        None => turns.other(role, part),
                    }
                }
            }
            Some(_) => return Err(unreadable(format!("messages/{i}/content is neither text nor a list of parts"))),
        }
        if role == Role::Assistant {
            for call in m.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
                let function = call.get("function").and_then(Value::as_object);
                let name = function.and_then(|f| str_field(f, "name")).unwrap_or("unknown");
                turns.tool_call(name, &arguments(function.and_then(|f| f.get("arguments"))));
            }
            if let Some(call) = m.get("function_call").and_then(Value::as_object) {
                turns.tool_call(str_field(call, "name").unwrap_or("unknown"), &arguments(call.get("arguments")));
            }
        }
        turns.end_message();
    }
    Ok(turns)
}

/// The text of a content part whose `type` is one of `keys` (or that carries one of those keys as a string).
fn part_text<'a>(part: &'a Value, keys: &[&'static str]) -> Option<(&'static str, &'a str)> {
    let obj = part.as_object()?;
    let kind = str_field(obj, "type");
    keys.iter().find_map(|key| match (kind, obj.get(*key)) {
        (Some(k), Some(Value::String(text))) if k == *key || k.ends_with("_text") => Some((*key, text.as_str())),
        (None, Some(Value::String(text))) => Some((*key, text.as_str())),
        _ => None,
    })
}

// ---- OpenAI Responses ---------------------------------------------------------------------------------------------

fn openai_responses(obj: &Obj) -> Result<Turns, ExtractError> {
    let mut turns = Turns::default();
    match obj.get("instructions") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => {
            turns.text(Role::System, s, Some("/instructions".into()));
            turns.end_message();
        }
        Some(_) => return Err(unreadable("instructions is not text")),
    }
    match obj.get("input") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => turns.text(Role::User, s, Some("/input".into())),
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                responses_item(&mut turns, item, i)?;
                turns.end_message();
            }
        }
        Some(_) => return Err(unreadable("input is neither text nor a list of items")),
    }
    Ok(turns)
}

fn responses_item(turns: &mut Turns, item: &Value, i: usize) -> Result<(), ExtractError> {
    let obj = item.as_object().ok_or_else(|| unreadable(format!("input/{i} is not an object")))?;
    let kind = str_field(obj, "type").unwrap_or("message");
    match kind {
        "message" => {
            let role = match str_field(obj, "role").unwrap_or("user") {
                "system" | "developer" => Role::System,
                "assistant" => Role::Assistant,
                _ => Role::User,
            };
            let base = format!("/input/{i}/content");
            match obj.get("content") {
                None | Some(Value::Null) => {}
                Some(Value::String(s)) => turns.text(role, s, Some(base)),
                Some(Value::Array(parts)) => {
                    for (j, part) in parts.iter().enumerate() {
                        match part_text(part, &["text", "refusal"]) {
                            Some((key, text)) => turns.text(role, text, Some(format!("{base}/{j}/{key}"))),
                            None => turns.other(role, part),
                        }
                    }
                }
                Some(_) => return Err(unreadable(format!("input/{i}/content is neither text nor a list of parts"))),
            }
        }
        "function_call" | "custom_tool_call" => {
            let args = obj.get("arguments").or_else(|| obj.get("input"));
            turns.tool_call(str_field(obj, "name").unwrap_or("unknown"), &arguments(args));
        }
        "reasoning" => {
            for summary in obj.get("summary").and_then(Value::as_array).into_iter().flatten() {
                if let Some(text) = summary.get("text").and_then(Value::as_str) {
                    turns.text(Role::Assistant, text, None);
                }
            }
        }
        k if k.ends_with("_output") => match obj.get("output") {
            Some(Value::String(s)) => turns.text(Role::Tool, s, Some(format!("/input/{i}/output"))),
            Some(Value::Array(parts)) => {
                for (j, part) in parts.iter().enumerate() {
                    match part_text(part, &["text"]) {
                        Some((key, text)) => turns.text(Role::Tool, text, Some(format!("/input/{i}/output/{j}/{key}"))),
                        None => turns.other(Role::Tool, part),
                    }
                }
            }
            Some(other) if !other.is_null() => turns.other(Role::Tool, other),
            _ => {}
        },
        // Other items (search calls, references and the like) are the model's side of the exchange.
        _ => turns.other(Role::Assistant, item),
    }
    Ok(())
}

// ---- Anthropic Messages -------------------------------------------------------------------------------------------

fn anthropic(obj: &Obj) -> Result<Turns, ExtractError> {
    let mut turns = Turns::default();
    match obj.get("system") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => turns.text(Role::System, s, Some("/system".into())),
        Some(Value::Array(blocks)) => {
            for (j, block) in blocks.iter().enumerate() {
                match part_text(block, &["text"]) {
                    Some((key, text)) => turns.text(Role::System, text, Some(format!("/system/{j}/{key}"))),
                    None => turns.other(Role::System, block),
                }
            }
        }
        Some(_) => return Err(unreadable("system is neither text nor a list of blocks")),
    }
    turns.end_message();
    let Some(messages) = list(obj, "messages")? else { return Ok(turns) };
    for (i, message) in messages.iter().enumerate() {
        let m = message.as_object().ok_or_else(|| unreadable(format!("messages/{i} is not an object")))?;
        let role = match str_field(m, "role") {
            Some("assistant") => Role::Assistant,
            _ => Role::User,
        };
        let base = format!("/messages/{i}/content");
        match m.get("content") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => turns.text(role, s, Some(base)),
            Some(Value::Array(blocks)) => {
                for (j, block) in blocks.iter().enumerate() {
                    anthropic_block(&mut turns, role, block, &format!("{base}/{j}"));
                }
            }
            Some(_) => return Err(unreadable(format!("messages/{i}/content is neither text nor a list of blocks"))),
        }
        turns.end_message();
    }
    Ok(turns)
}

fn anthropic_block(turns: &mut Turns, role: Role, block: &Value, at: &str) {
    let Some(obj) = block.as_object() else {
        turns.other(role, block);
        return;
    };
    match str_field(obj, "type") {
        Some("text") => match str_field(obj, "text") {
            Some(text) => turns.text(role, text, Some(format!("{at}/text"))),
            None => turns.other(role, block),
        },
        Some("tool_use") | Some("server_tool_use") => {
            turns.tool_call(str_field(obj, "name").unwrap_or("unknown"), &arguments(obj.get("input")));
        }
        Some("tool_result") => match obj.get("content") {
            Some(Value::String(s)) => turns.text(Role::Tool, s, Some(format!("{at}/content"))),
            Some(Value::Array(parts)) => {
                for (k, part) in parts.iter().enumerate() {
                    match part_text(part, &["text"]) {
                        Some((key, text)) => turns.text(Role::Tool, text, Some(format!("{at}/content/{k}/{key}"))),
                        None => turns.other(Role::Tool, part),
                    }
                }
            }
            _ => turns.other(Role::Tool, block),
        },
        Some("thinking") => {
            if let Some(text) = str_field(obj, "thinking") {
                turns.text(Role::Assistant, text, None);
            }
        }
        Some("redacted_thinking") => {}
        _ => turns.other(role, block),
    }
}

// ---- Gemini -------------------------------------------------------------------------------------------------------

fn gemini(obj: &Obj) -> Result<Turns, ExtractError> {
    let mut turns = Turns::default();
    let (key, system) = match (obj.get("systemInstruction"), obj.get("system_instruction")) {
        (Some(v), _) if !v.is_null() => ("systemInstruction", Some(v)),
        (_, Some(v)) if !v.is_null() => ("system_instruction", Some(v)),
        _ => ("", None),
    };
    match system {
        None => {}
        Some(Value::String(s)) => turns.text(Role::System, s, Some(format!("/{key}"))),
        Some(Value::Object(content)) => gemini_parts(&mut turns, Role::System, content, &format!("/{key}"))?,
        Some(_) => return Err(unreadable(format!("{key} is not a content object"))),
    }
    turns.end_message();
    let Some(contents) = list(obj, "contents")? else { return Ok(turns) };
    for (i, content) in contents.iter().enumerate() {
        let c = content.as_object().ok_or_else(|| unreadable(format!("contents/{i} is not an object")))?;
        let role = match str_field(c, "role") {
            Some("model") => Role::Assistant,
            Some("function") | Some("tool") => Role::Tool,
            _ => Role::User,
        };
        gemini_parts(&mut turns, role, c, &format!("/contents/{i}"))?;
        turns.end_message();
    }
    Ok(turns)
}

fn gemini_parts(turns: &mut Turns, role: Role, content: &Obj, at: &str) -> Result<(), ExtractError> {
    let Some(parts) = list(content, "parts")? else { return Ok(()) };
    for (j, part) in parts.iter().enumerate() {
        let Some(p) = part.as_object() else {
            turns.other(role, part);
            continue;
        };
        let field = |camel: &str, snake: &str| p.get(camel).or_else(|| p.get(snake)).filter(|v| !v.is_null());
        if let Some(text) = str_field(p, "text") {
            if p.get("thought").and_then(Value::as_bool).unwrap_or(false) {
                turns.text(Role::Assistant, text, None);
            } else {
                turns.text(role, text, Some(format!("{at}/parts/{j}/text")));
            }
        } else if let Some(call) = field("functionCall", "function_call") {
            let name = call.get("name").and_then(Value::as_str).unwrap_or("unknown");
            turns.tool_call(name, &arguments(call.get("args")));
        } else if let Some(response) = field("functionResponse", "function_response") {
            match response.get("response") {
                Some(value) if !value.is_null() => turns.text(Role::Tool, &serialize(value), None),
                _ => turns.other(Role::Tool, response),
            }
        } else if let Some(code) = field("executableCode", "executable_code") {
            turns.text(Role::Assistant, &arguments(code.get("code")), None);
        } else if let Some(result) = field("codeExecutionResult", "code_execution_result") {
            turns.text(Role::Tool, &arguments(result.get("output")), None);
        } else {
            turns.other(role, part);
        }
    }
    Ok(())
}

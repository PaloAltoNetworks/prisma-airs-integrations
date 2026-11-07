//! MCP traffic: which bodies are MCP JSON-RPC messages, what each method carries, and the text of a message.
//!
//! The body decides, not a header: on an MCP server instance `x-input-format` is only a client header, so a client
//! could set it. A message is an object whose `jsonrpc` is exactly `"2.0"` and that has either a non-empty string
//! `method`, or an `id` with a `result` or an `error` (a client's reply to a server request). A batch is a non-empty
//! array whose every element is a message. Anything else is not MCP: it takes the LLM path, where its content is
//! scanned or the request fails closed.
//!
//! A batch is never classified by one member: `[ping, tools/call]` is two members, each with its own kind (Kong v3's
//! lesson: classifying by the first member let a `ping` carry an unscanned `tools/call`).

use serde_json::Value;

use crate::extract::is_binary;

/// The members of a JSON-RPC message. Anything else at a message's top level is extra content, and is scanned.
pub const ENVELOPE: [&str; 6] = ["jsonrpc", "id", "method", "params", "result", "error"];

/// What a method carries, which decides what each leg scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Nothing to scan on either leg: `ping`, `logging/setLevel`, `initialized` and every `notifications/` method.
    Control,
    /// Nothing on the request leg; the reply is a catalogue the client hands to a model: `initialize`,
    /// `resources/list`, `resources/templates/list`, `prompts/list`, `roots/list`.
    Catalogue,
    /// `tools/list`: the reply is the tool catalogue, scanned as a tool event.
    ToolList,
    /// `tools/call`: a tool event on both legs.
    ToolCall,
    /// Every other method, under any other spelling: its text, on both legs.
    Content,
    /// A client's reply to a server request (no method): its text, on the request leg.
    ClientReply,
}

/// One message of a request body.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    /// Its position in a batch; 0 for a single message.
    pub index: usize,
    /// Its id as sent (a number stays a number, a string a string); `None` for a notification.
    pub id: Option<Value>,
    /// `None` for a client reply.
    pub method: Option<String>,
    pub kind: Kind,
    pub message: Value,
}

/// An MCP request body.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub members: Vec<Member>,
    /// The body was an array (a JSON-RPC batch), so a refusal is an array too.
    pub batch: bool,
}

/// The MCP reading of a request body, or `None` when it is not MCP.
pub fn classify(body: &Value) -> Option<Request> {
    match body {
        Value::Object(_) => member(0, body).map(|m| Request { members: vec![m], batch: false }),
        Value::Array(items) if !items.is_empty() => {
            let members: Option<Vec<Member>> = items.iter().enumerate().map(|(i, v)| member(i, v)).collect();
            members.map(|members| Request { members, batch: true })
        }
        _ => None,
    }
}

fn member(index: usize, value: &Value) -> Option<Member> {
    let obj = value.as_object()?;
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let id = obj.get("id").cloned();
    let (method, kind) = match obj.get("method") {
        Some(Value::String(m)) if !m.is_empty() => (Some(m.clone()), kind_of(m)),
        Some(_) => return None,
        None if id.is_some() && (obj.contains_key("result") || obj.contains_key("error")) => (None, Kind::ClientReply),
        None => return None,
    };
    Some(Member { index, id, method, kind, message: value.clone() })
}

/// The kind of a method. Method names are case-sensitive in MCP; any other spelling is `Content`, so it is scanned.
pub fn kind_of(method: &str) -> Kind {
    match method {
        "ping" | "logging/setLevel" | "initialized" => Kind::Control,
        m if m.starts_with("notifications/") => Kind::Control,
        "initialize" | "resources/list" | "resources/templates/list" | "prompts/list" | "roots/list" => Kind::Catalogue,
        "tools/list" => Kind::ToolList,
        "tools/call" => Kind::ToolCall,
        _ => Kind::Content,
    }
}

/// The text of a value, in a stable order (an array's items in order, an object's members by key): every non-blank string, and every object key that is not a plain
/// identifier (an injection can sit in a schema's property name). At the top level of the value, `jsonrpc` and `id`
/// are protocol fields and are skipped; deeper down they are content. Binary payloads (data URIs, long base64 under
/// data-like keys such as `blob`) are left out.
pub fn text_values(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect(value, None, true, &mut out);
    out
}

fn collect(value: &Value, key: Option<&str>, top: bool, out: &mut Vec<String>) {
    match value {
        Value::String(s) if !s.trim().is_empty() && !is_binary(key, s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| collect(v, None, false, out)),
        Value::Object(map) => {
            for (k, v) in map {
                if top && (k == "jsonrpc" || k == "id") {
                    continue;
                }
                if !plain_identifier(k) && !k.trim().is_empty() {
                    out.push(k.clone());
                }
                collect(v, Some(k), false, out);
            }
        }
        _ => {}
    }
}

/// Letters, digits and `_ - . $ / :`, 1 to 64 characters: a key that cannot carry a sentence.
fn plain_identifier(key: &str) -> bool {
    (1..=64).contains(&key.chars().count())
        && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '$' | '/' | ':'))
}

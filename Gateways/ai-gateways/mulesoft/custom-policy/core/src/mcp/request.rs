//! The request leg of an MCP exchange: what each member of a request body scans, before anything reaches the server.
//!
//! - `tools/call` is a tool event: the tool's name and its arguments, binary payloads left out. Any other content of
//!   the call (other `params` members, extra top-level members) is scanned as text beside it.
//! - Every other method that carries caller text (`resources/read`, `prompts/get`, `completion/complete`, vendor
//!   methods) and a client's reply to a server request are scanned as their text.
//! - Control and catalogue requests carry no caller text in `params`, so only their extra top-level members are
//!   scanned: a member bolted onto a `ping` (an LLM-shaped `messages`, say) is never a way past the scan.
//! - `params._meta` is protocol metadata (a progress token, say) and is not scanned.

use serde_json::{json, Map, Value};

use super::{entry_text, json_text, text_scan, tool_or_text, Kind, LegScan, Place, Request, Scan, Sender};
use crate::airs::{ToolEvent, ToolMethod};

/// The scans of a request body, member by member, in order.
pub fn request_scans(req: &Request, server_name: &str, max_chars: usize) -> Vec<LegScan> {
    let mut out = Vec::new();
    for member in &req.members {
        let Some(obj) = member.message.as_object() else { continue };
        let scan = |scan| LegScan { member: Some(member.index), method: member.method.clone(), scan };
        if member.kind == Kind::ToolCall {
            out.push(scan(tool_call(obj, server_name, max_chars)));
        }
        if let Some(text) = text_scan(other_text(member.kind, obj), max_chars) {
            out.push(scan(Scan::Text(text)));
        }
    }
    out
}

fn tool_call(obj: &Map<String, Value>, server_name: &str, max_chars: usize) -> Scan {
    let params = obj.get("params");
    let arguments = params.and_then(|p| p.get("arguments")).cloned().unwrap_or_else(|| json!({}));
    let event = ToolEvent {
        method: ToolMethod::Call,
        server_name: server_name.to_string(),
        tool_invoked: params.and_then(|p| p.get("name")).and_then(Value::as_str).map(str::to_string),
        input: json_text(&arguments, Place::Opaque, Sender::Client),
        output: String::new(),
    };
    tool_or_text(event, &[(&arguments, Place::Opaque, Sender::Client)], max_chars)
}

/// The text a member carries besides its tool event: by kind, its `params` (without `_meta`), any `result` or
/// `error`, and every top-level member outside the JSON-RPC envelope.
fn other_text(kind: Kind, obj: &Map<String, Value>) -> Vec<String> {
    let mut out = Vec::new();
    for (key, value) in obj {
        match key.as_str() {
            "jsonrpc" | "id" | "method" => {}
            "params" => match (kind, value) {
                (Kind::Control | Kind::Catalogue | Kind::ToolList, _) => {}
                (Kind::ToolCall, Value::Object(params)) => params
                    .iter()
                    .filter(|(k, _)| !matches!(k.as_str(), "name" | "arguments" | "_meta"))
                    .for_each(|(k, v)| entry_text(k, v, params, Place::Body, Sender::Client, &mut out)),
                (_, Value::Object(params)) => params
                    .iter()
                    .filter(|(k, _)| k.as_str() != "_meta")
                    .for_each(|(k, v)| entry_text(k, v, params, Place::Body, Sender::Client, &mut out)),
                (_, other) => entry_text(key, other, obj, Place::Message, Sender::Client, &mut out),
            },
            _ => entry_text(key, value, obj, Place::Message, Sender::Client, &mut out),
        }
    }
    out
}

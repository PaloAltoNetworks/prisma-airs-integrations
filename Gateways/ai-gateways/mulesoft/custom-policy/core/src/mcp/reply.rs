//! The reply leg of an MCP exchange: the messages of a reply body, and what each one scans before the client gets it.
//!
//! Every message of a reply is scanned, whether or not it answers a request member: a Streamable HTTP reply can carry
//! notifications and server requests (`elicitation/create`, `sampling/createMessage`) before the answer, and a reply
//! to an unknown id is still text the client receives.
//!
//! - A `tools/call` answer is a tool event: the request's arguments as input, the result as output.
//! - A `tools/list` answer is a tool event whose output is the bare array of tools (the shape AIRS accepts); any other
//!   member of its result except `nextCursor` and `_meta` is scanned as text.
//! - Every other answer, every error, and every message that answers no member are scanned as text.

use serde_json::{json, Map, Value};

use super::{
    entry_text, json_text, text_scan, text_values, tool_or_text, Kind, LegScan, Member, Place, Request, Scan, Sender,
};
use crate::airs::{ToolEvent, ToolMethod};
use crate::extract::ExtractError;
use crate::sse;

/// The JSON-RPC messages of a reply body: its JSON value, or each event's data on an event stream; a batch array is
/// split into its messages, and an event without data is not a message. A body the policy cannot read is an error,
/// never an empty reply.
pub fn messages(body: &[u8], event_stream: bool) -> Result<Vec<Value>, ExtractError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let values = if event_stream {
        let mut values = Vec::new();
        for event in sse::events(body) {
            if event.data.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(&event.data)
                .map_err(|_| ExtractError::Unreadable("an event's data is not JSON".into()))?;
            values.push(value);
        }
        values
    } else {
        vec![serde_json::from_slice::<Value>(body).map_err(|_| ExtractError::Unreadable("the reply is not JSON".into()))?]
    };
    Ok(values
        .into_iter()
        .flat_map(|v| match v {
            Value::Array(items) => items,
            other => vec![other],
        })
        .collect())
}

/// The scans of a reply: each answer to a request member, in order, then the text of every other message as one scan.
/// `req` is `None` for a bodiless request (a GET), whose reply answers nothing.
pub fn reply_scans(req: Option<&Request>, messages: &[Value], server_name: &str, max_chars: usize) -> Vec<LegScan> {
    let mut out = Vec::new();
    let mut other = Vec::new();
    for message in messages {
        match answered(req, message) {
            Some(member) => out.extend(answer(member, message, server_name, max_chars)),
            None => other.extend(text_values(message)),
        }
    }
    if let Some(text) = text_scan(other, max_chars) {
        out.push(LegScan { member: None, method: None, scan: Scan::Text(text) });
    }
    out
}

/// The request member a message answers: a result or an error whose id equals the member's id as JSON values.
fn answered<'a>(req: Option<&'a Request>, message: &Value) -> Option<&'a Member> {
    let obj = message.as_object()?;
    if !obj.contains_key("result") && !obj.contains_key("error") {
        return None;
    }
    let id = obj.get("id")?;
    req?.members.iter().find(|m| m.method.is_some() && m.id.as_ref() == Some(id))
}

fn answer(member: &Member, message: &Value, server_name: &str, max_chars: usize) -> Vec<LegScan> {
    let scan = |scan| LegScan { member: Some(member.index), method: member.method.clone(), scan };
    let obj = message.as_object().cloned().unwrap_or_default();
    let params = member.message.get("params");
    let result = obj.get("result");
    let mut out = Vec::new();
    let rest = match (member.kind, result) {
        (Kind::ToolCall, Some(result)) => {
            let arguments = params.and_then(|p| p.get("arguments")).cloned().unwrap_or_else(|| json!({}));
            let event = ToolEvent {
                method: ToolMethod::Call,
                server_name: server_name.to_string(),
                tool_invoked: params.and_then(|p| p.get("name")).and_then(Value::as_str).map(str::to_string),
                input: json_text(&arguments, Place::Opaque, Sender::Client),
                output: json_text(result, Place::Body, Sender::Server),
            };
            let sources = [(&arguments, Place::Opaque, Sender::Client), (result, Place::Body, Sender::Server)];
            out.push(scan(tool_or_text(event, &sources, max_chars)));
            outside(&obj, &["result"])
        }
        (Kind::ToolList, Some(Value::Object(result))) if result.get("tools").is_some_and(Value::is_array) => {
            let tools = &result["tools"];
            let input = params.cloned().unwrap_or_else(|| json!({}));
            let event = ToolEvent {
                method: ToolMethod::List,
                server_name: server_name.to_string(),
                tool_invoked: None,
                input: json_text(&input, Place::Body, Sender::Client),
                output: json_text(tools, Place::Definitions, Sender::Server),
            };
            out.push(scan(tool_or_text(event, &[(tools, Place::Definitions, Sender::Server)], max_chars)));
            let mut rest = outside(&obj, &["result"]);
            result
                .iter()
                .filter(|(k, _)| !matches!(k.as_str(), "tools" | "nextCursor" | "_meta"))
                .for_each(|(k, v)| entry_text(k, v, result, Place::Body, Sender::Server, &mut rest));
            rest
        }
        _ => text_values(message),
    };
    if let Some(text) = text_scan(rest, max_chars) {
        out.push(scan(Scan::Text(text)));
    }
    out
}

/// The text of a message's members other than the protocol ones and `skip`.
fn outside(obj: &Map<String, Value>, skip: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    obj.iter()
        .filter(|(k, _)| !matches!(k.as_str(), "jsonrpc" | "id" | "method") && !skip.contains(&k.as_str()))
        .for_each(|(k, v)| entry_text(k, v, obj, Place::Message, Sender::Server, &mut out));
    out
}

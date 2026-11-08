//! The error body the client receives when the policy blocks, shaped like each format's own error object, and, for MCP
//! traffic, a JSON-RPC error carrying the caller's own request id, so the client's session survives the refusal.
//!
//! The message is generic and carries the AIRS scan ID when there is one, so a support desk can find the scan in
//! Strata Cloud Manager. Detection names appear only when the operator turns `showCategories` on.

use serde_json::{json, Value};

use crate::airs::Leg;
use crate::decision::BlockKind;
use crate::format::Format;

/// `(content type, body)`. An unknown format gets the OpenAI shape.
pub fn client_error(
    format: Option<Format>,
    leg: Leg,
    status: u16,
    kind: BlockKind,
    scan_id: Option<&str>,
    categories: Option<&[String]>,
) -> (&'static str, Vec<u8>) {
    let unavailable = status == 503 || kind == BlockKind::Scanner;
    let message = message(kind, leg, scan_id, categories);
    let body: Value = match format {
        Some(Format::AnthropicMessages) => json!({
            "type": "error",
            "error": { "type": if unavailable { "api_error" } else { "permission_error" }, "message": message }
        }),
        Some(Format::Gemini) => json!({
            "error": {
                "code": status,
                "message": message,
                "status": if unavailable { "UNAVAILABLE" } else { "PERMISSION_DENIED" }
            }
        }),
        _ => {
            let kind = if unavailable { "prisma_airs_unavailable" } else { "prisma_airs_blocked" };
            json!({ "error": { "message": message, "type": kind, "param": null, "code": kind } })
        }
    };
    ("application/json", serde_json::to_vec(&body).unwrap_or_default())
}

/// The generic text of a refusal, with the scan ID when there is one, and the detections only when asked for.
fn message(kind: BlockKind, leg: Leg, scan_id: Option<&str>, categories: Option<&[String]>) -> String {
    let mut message = match (kind, leg) {
        (BlockKind::Config, _) => {
            "Prisma AIRS Guardrails is not configured correctly, so it refused this request. Check the policy's settings."
                .to_string()
        }
        (BlockKind::Scanner, Leg::Prompt) => "Prisma AIRS could not scan this request, so it was not forwarded.".to_string(),
        (BlockKind::Scanner, Leg::Response) => "Prisma AIRS could not scan this response, so it was withheld.".to_string(),
        (BlockKind::Gap, Leg::Prompt) => "Prisma AIRS could not inspect this request, so it was not forwarded.".to_string(),
        (BlockKind::Gap, Leg::Response) => "Prisma AIRS could not inspect this response, so it was withheld.".to_string(),
        (_, Leg::Prompt) => "Request blocked by Prisma AIRS security policy.".to_string(),
        (_, Leg::Response) => "Response blocked by Prisma AIRS security policy.".to_string(),
    };
    if let Some(id) = scan_id.filter(|id| !id.is_empty()) {
        message.push_str(&format!(" Scan ID: {id}."));
    }
    if let Some(cats) = categories.filter(|c| !c.is_empty()) {
        message.push_str(&format!(" Detected: {}.", cats.join(", ")));
    }
    message
}

/// A refusal inside the JSON-RPC protocol: one error per request member with an id, carrying that id as sent (an array
/// of them for a batch). The code is -32001 for a block or for content that could not be inspected, and -32003 when
/// Prisma AIRS was unavailable or the policy's configuration was rejected.
///
/// `(HTTP status, content type, body)`. The status is 200 whenever a member has an id: every MCP client SDK turns that
/// into the server's own JSON-RPC error, while a 4xx leaves a pending request of the Python SDK 1.x waiting forever and
/// reaches the TypeScript SDK as a transport failure. With no id to answer (notifications and client replies
/// only), the MCP spec asks for an HTTP error: 403, or 503 when Prisma AIRS was unavailable.
pub fn mcp_refusal(
    ids: &[Value],
    batch: bool,
    leg: Leg,
    kind: BlockKind,
    scan_id: Option<&str>,
    categories: Option<&[String]>,
) -> (u16, &'static str, Vec<u8>) {
    let unavailable = matches!(kind, BlockKind::Scanner | BlockKind::Config);
    let code = if unavailable { -32003 } else { -32001 };
    let text = message(kind, leg, scan_id, categories);
    let error = |id: Value| json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": text } });
    let (status, body) = match (ids, batch) {
        ([], _) => (if unavailable { 503 } else { 403 }, error(Value::Null)),
        ([id], false) => (200, error(id.clone())),
        (ids, _) => (200, Value::Array(ids.iter().cloned().map(error).collect())),
    };
    (status, "application/json", serde_json::to_vec(&body).unwrap_or_default())
}

/// The answer to a GET that asks for an event stream, which the policy cannot scan before the client reads it: 405,
/// which the MCP spec allows ("the server does not offer an SSE stream at this endpoint").
pub fn stream_refusal() -> (u16, &'static str, Vec<u8>) {
    let message = "Prisma AIRS Guardrails does not allow an event stream (GET) on this API, because its messages could not \
                   be scanned before they reach the client. Send requests with POST (the Streamable HTTP transport).";
    let body = json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32001, "message": message } });
    (405, "application/json", serde_json::to_vec(&body).unwrap_or_default())
}

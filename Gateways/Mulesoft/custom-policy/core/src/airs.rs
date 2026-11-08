//! The Prisma AIRS sync scan contract (`POST /v1/scan/sync/request`): the request the policy sends, and how it reads
//! the verdict.
//!
//! - Correlation: `transaction_id` per request and `session_id` per conversation, each left out rather than sent when
//!   unusable. `tr_id` is never sent: on the live API it is a legacy alias of the session slot.
//! - The response leg sends the prompt as context and the reply as the element to scan (pan.dev: "the last element is
//!   the one that needs to be scanned, and the previous elements are the context"), so its verdict is about the reply.
//! - `action` is the gate. `category` is an umbrella value, never a detector; detections are the true flags under
//!   `prompt_detected` or `response_detected`.
//! - MCP tool events (`contents[].tool_event`) follow the contract AIRS enforces: `metadata.ecosystem` `mcp`, `metadata.method`
//!   `tools/call` or `tools/list` only, `metadata` with no other fields than `server_name` and the optional `tool_invoked`,
//!   and `input`/`output` as JSON text in strings. A `tools/list` output is the bare array of tools: the `{"tools":[..]}`
//!   result object is a 400 (measured on the lab tenant, 7 Nov 2026). Their detections sit under `tool_detected`.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::{json, Map, Value};

use crate::settings::ProfileRef;

/// The longest `transaction_id` or `session_id` AIRS accepts.
pub const MAX_ID_CHARS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    Prompt,
    Response,
}

impl Leg {
    pub fn name(self) -> &'static str {
        match self {
            Leg::Prompt => "prompt",
            Leg::Response => "response",
        }
    }
}

/// What every scan of one request carries besides its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanContext {
    pub profile: ProfileRef,
    pub transaction_id: Option<String>,
    pub session_id: Option<String>,
    pub app_name: String,
    pub app_user: String,
    pub ai_model: Option<String>,
}

/// The scan request body. `prompt_context` is used on the response leg only.
pub fn scan_request(ctx: &ScanContext, leg: Leg, text: &str, prompt_context: Option<&str>) -> Value {
    let mut body = envelope(ctx);
    let contents = match (leg, prompt_context.filter(|p| !p.trim().is_empty())) {
        (Leg::Prompt, _) => json!([{ "prompt": text }]),
        (Leg::Response, Some(prompt)) => json!([{ "prompt": prompt }, { "response": text }]),
        (Leg::Response, None) => json!([{ "response": text }]),
    };
    body.insert("contents".into(), contents);
    Value::Object(body)
}

/// The tool methods AIRS accepts as tool events: its method allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolMethod {
    Call,
    List,
}

impl ToolMethod {
    pub fn name(self) -> &'static str {
        match self {
            ToolMethod::Call => "tools/call",
            ToolMethod::List => "tools/list",
        }
    }
}

/// An MCP tool event. `input` and `output` are JSON text; a `tools/list` output is the bare array of tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolEvent {
    pub method: ToolMethod,
    /// The MCP server the event belongs to, so scans of different servers can be told apart.
    pub server_name: String,
    /// The tool called; `None` for `tools/list`, whose output names each tool.
    pub tool_invoked: Option<String>,
    pub input: String,
    pub output: String,
}

/// The scan request body for a tool event, with the same correlation, profile and metadata as [`scan_request`].
pub fn tool_event_request(ctx: &ScanContext, event: &ToolEvent) -> Value {
    let mut body = envelope(ctx);
    let mut metadata = Map::new();
    metadata.insert("ecosystem".into(), Value::String("mcp".into()));
    metadata.insert("method".into(), Value::String(event.method.name().into()));
    metadata.insert("server_name".into(), Value::String(event.server_name.clone()));
    if let Some(tool) = &event.tool_invoked {
        metadata.insert("tool_invoked".into(), Value::String(tool.clone()));
    }
    let tool_event = json!({ "metadata": metadata, "input": event.input, "output": event.output });
    body.insert("contents".into(), json!([{ "tool_event": tool_event }]));
    Value::Object(body)
}

/// Everything a scan request carries besides its contents.
fn envelope(ctx: &ScanContext) -> Map<String, Value> {
    let mut body = Map::new();
    if let Some(id) = &ctx.transaction_id {
        body.insert("transaction_id".into(), Value::String(id.clone()));
    }
    if let Some(id) = &ctx.session_id {
        body.insert("session_id".into(), Value::String(id.clone()));
    }
    let profile = match &ctx.profile {
        ProfileRef::Name(name) => json!({ "profile_name": name }),
        ProfileRef::Id(id) => json!({ "profile_id": id }),
    };
    body.insert("ai_profile".into(), profile);
    let mut metadata = Map::new();
    metadata.insert("app_name".into(), Value::String(ctx.app_name.clone()));
    metadata.insert("app_user".into(), Value::String(ctx.app_user.clone()));
    if let Some(model) = &ctx.ai_model {
        metadata.insert("ai_model".into(), Value::String(model.clone()));
    }
    body.insert("metadata".into(), Value::Object(metadata));
    body
}

/// A correlation id as AIRS accepts it: trimmed, printable ASCII, at most [`MAX_ID_CHARS`]. Never truncated: a cut id
/// would correlate the wrong records.
pub fn clamp_id(raw: &str) -> Option<String> {
    checked_id(raw).ok().flatten()
}

/// `Ok(None)` for a blank value, `Err(reason)` for an unusable one (`not_printable_ascii`, `too_long`).
pub fn checked_id(raw: &str) -> Result<Option<String>, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !trimmed.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Err("not_printable_ascii");
    }
    if trimmed.chars().count() > MAX_ID_CHARS {
        return Err("too_long");
    }
    Ok(Some(trimmed.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub action: Action,
    pub scan_id: Option<String>,
    pub report_id: Option<String>,
    pub category: Option<String>,
    /// The true detector flags of this leg's side, then the other side's, named `prompt.<flag>` or `response.<flag>`.
    pub detections: Vec<String>,
    /// AIRS's masked version of this leg's text, when its profile masks.
    pub masked_text: Option<String>,
}

impl Verdict {
    /// True when the only finding is sensitive data on this leg's own side, the one case masking may resolve.
    pub fn is_pure_dlp(&self) -> bool {
        self.detections.len() == 1 && self.detections[0] == "dlp"
    }
}

/// Why a scan produced no usable verdict. None of these carries content, a key or the AIRS reply body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    Timeout,
    Transport(String),
    Status(u16),
    Undecodable,
    MissingAction,
    BreakerOpen,
    /// AIRS answered allow while one of its detection services failed or timed out (`feature:status` each).
    Incomplete(Vec<String>),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Timeout => write!(f, "the scan timed out"),
            ScanError::Transport(detail) => write!(f, "the scan could not be sent: {detail}"),
            ScanError::Status(code) => write!(f, "Prisma AIRS returned HTTP {code}"),
            ScanError::Undecodable => write!(f, "the Prisma AIRS reply is not a JSON object"),
            ScanError::MissingAction => write!(f, "the Prisma AIRS reply has no allow or block action"),
            ScanError::BreakerOpen => write!(f, "the circuit breaker is open"),
            ScanError::Incomplete(features) => write!(f, "Prisma AIRS detection services failed: {}", features.join(", ")),
        }
    }
}

impl std::error::Error for ScanError {}

/// Reads a scan reply. Anything but HTTP 200 with a JSON object holding `action` allow or block is an error.
pub fn parse_verdict(status: u16, body: &[u8], leg: Leg) -> Result<Verdict, ScanError> {
    if status != 200 {
        return Err(ScanError::Status(status));
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| ScanError::Undecodable)?;
    let obj = value.as_object().ok_or(ScanError::Undecodable)?;
    let action = match obj.get("action").and_then(Value::as_str) {
        Some("allow") => Action::Allow,
        Some("block") => Action::Block,
        _ => return Err(ScanError::MissingAction),
    };
    let text = |key: &str| obj.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let category = text("category");
    let flag = |key: &str| obj.get(key) == Some(&Value::Bool(true));
    let degraded = flag("error") || flag("timeout") || matches!(category.as_deref(), Some("error") | Some("timeout"));
    if degraded && action == Action::Allow {
        let mut features: Vec<String> = obj
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|e| {
                let feature = e.get("feature").and_then(Value::as_str).unwrap_or("unknown");
                let status = e.get("status").and_then(Value::as_str).unwrap_or("error");
                format!("{feature}:{status}")
            })
            .collect();
        if features.is_empty() {
            features.push(format!("category:{}", category.as_deref().unwrap_or("error")));
        }
        return Err(ScanError::Incomplete(features));
    }
    let (own, other, prefix, masked_key) = match leg {
        Leg::Prompt => ("prompt_detected", "response_detected", "response.", "prompt_masked_data"),
        Leg::Response => ("response_detected", "prompt_detected", "prompt.", "response_masked_data"),
    };
    let mut detections = true_flags(obj.get(own));
    detections.extend(true_flags(obj.get(other)).into_iter().map(|f| format!("{prefix}{f}")));
    let masked_text = obj
        .get(masked_key)
        .and_then(|m| m.get("data"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(Verdict { action, scan_id: text("scan_id"), report_id: text("report_id"), category, detections, masked_text })
}

/// Reads a tool event's verdict: the same gate and degraded-allow rule as [`parse_verdict`], plus the true flags of
/// every `tool_detected` detection entry, named `tool_input.<flag>` or `tool_output.<flag>` (or `tool.<flag>` from the
/// summary when no entry has any).
pub fn parse_tool_verdict(status: u16, body: &[u8]) -> Result<Verdict, ScanError> {
    let mut verdict = parse_verdict(status, body, Leg::Prompt)?;
    let value: Value = serde_json::from_slice(body).map_err(|_| ScanError::Undecodable)?;
    let tool = value.get("tool_detected");
    let mut flags = Vec::new();
    for (side, name) in [("input_detected", "tool_input"), ("output_detected", "tool_output")] {
        let entries = tool.and_then(|t| t.get(side)).and_then(|s| s.get("detection_entries")).and_then(Value::as_array);
        let set: BTreeSet<String> = entries.into_iter().flatten().flat_map(|e| true_flags(e.get("detections"))).collect();
        flags.extend(set.into_iter().map(|f| format!("{name}.{f}")));
    }
    if flags.is_empty() {
        let summary = tool.and_then(|t| t.get("summary")).and_then(|s| s.get("detections"));
        flags.extend(true_flags(summary).into_iter().map(|f| format!("tool.{f}")));
    }
    verdict.detections.extend(flags);
    Ok(verdict)
}

fn true_flags(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, v)| **v == Value::Bool(true))
        .map(|(k, _)| k.clone())
        .collect()
}

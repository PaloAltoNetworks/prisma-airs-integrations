//! The error body the client receives when the policy blocks, shaped like each format's own error object.
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

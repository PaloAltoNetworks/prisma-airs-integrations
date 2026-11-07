//! MCP traffic: the request and response paths for JSON-RPC bodies, and the reply of a bodiless request that turns out
//! to be an event stream.
//!
//! The scans of one leg run in order. In enforce mode the first block, gap or scanner failure ends the exchange with
//! a JSON-RPC refusal that answers each request member with its own id; in monitor mode every scan still runs and is
//! recorded, and nothing the client receives changes. MCP text is never written back (DLP masking is LLM-only), so a
//! DLP block stays a block and an allow that carries masked text passes as it is.

use pdk::hl::*;
use pdk::logger;
use prisma_airs_core::airs::{clamp_id, Leg, ScanContext};
use prisma_airs_core::decision::{decide, BlockKind, Decision, Gap, ScanOutcome};
use prisma_airs_core::errors::{mcp_refusal, stream_refusal};
use prisma_airs_core::evidence::{clean_method, LegRecord};
use prisma_airs_core::mcp::reply::{messages, reply_scans};
use prisma_airs_core::mcp::request::request_scans;
use prisma_airs_core::mcp::{LegScan, Request, Scan};
use prisma_airs_core::settings::Settings;
use serde_json::Value;

use crate::filter::{detections, note, outcome_name, report_violation, Ctx};
use crate::scan::{scan, What};
use crate::Shared;

/// What the request leg of an MCP exchange hands to its response leg.
pub(crate) struct McpCtx {
    pub(crate) request: Request,
}

/// The first refusal of a leg.
struct Refusal {
    kind: BlockKind,
    scan_id: Option<String>,
    detections: Option<Vec<String>>,
}

/// The ids a refusal answers: those of the request members that are requests (a client reply's id is the server's).
pub(crate) fn request_ids(req: Option<&Request>) -> Vec<Value> {
    req.map(|r| r.members.iter().filter(|m| m.method.is_some()).filter_map(|m| m.id.clone()).collect())
        .unwrap_or_default()
}

pub(crate) async fn request(
    mut ctx: Ctx,
    h: &dyn HeadersBodyHandler,
    req: Request,
    scan_ctx: ScanContext,
    session_dropped: Option<&'static str>,
    client: &HttpClient,
    shared: &Shared,
) -> Flow<Ctx> {
    let s = &shared.settings;
    ctx.record.format = Some(if req.batch { "mcp_batch" } else { "mcp" }.into());
    ctx.record.methods = req.members.iter().map(|m| clean_method(m.method.as_deref().unwrap_or("reply"))).collect();
    ctx.record.session_id_present = scan_ctx.session_id.is_some();
    ctx.record.session_id_dropped = session_dropped.map(str::to_string);

    let mut refusal = None;
    if req.members.len() > s.mcp_batch_limit {
        // Each message is scanned on its own, so the caller would choose how many scans one request costs.
        let mut leg = note(Leg::Prompt, "");
        refusal = judge(s, Leg::Prompt, &ScanOutcome::Gap(Gap::BatchLimit), &mut leg);
        ctx.record.legs.push(leg);
    } else if !s.scan_requests {
        ctx.record.legs.push(note(Leg::Prompt, "prompt_scan_off"));
    } else {
        for leg_scan in request_scans(&req, &shared.server_name, s.max_scan_chars) {
            let (outcome, mut record) = run(client, shared, &scan_ctx, &leg_scan, Leg::Prompt).await;
            let refused = judge(s, Leg::Prompt, &outcome, &mut record);
            ctx.record.legs.push(record);
            if refused.is_some() {
                refusal = refused;
                break;
            }
        }
    }
    if let Some(r) = refusal {
        let (status, content_type, body) = mcp_refusal(
            &request_ids(Some(&req)),
            req.batch,
            Leg::Prompt,
            r.kind,
            r.scan_id.as_deref(),
            r.detections.as_deref(),
        );
        report_violation(shared, &ctx);
        ctx.record.decision = format!("block_{}", r.kind.name());
        ctx.record.status = status;
        logger::info!("{}", ctx.record.to_log_line());
        return Flow::Break(
            Response::new(status as u32)
                .with_headers(vec![("content-type".to_string(), content_type.to_string())])
                .with_body(body),
        );
    }
    ctx.scan_response = s.scan_responses;
    if ctx.scan_response {
        // A compressed reply cannot be read, so the server is asked for an uncompressed one.
        h.remove_header("accept-encoding");
    }
    ctx.scan_ctx = Some(scan_ctx);
    ctx.mcp = Some(McpCtx { request: req });
    Flow::Continue(ctx)
}

/// The 405 for a GET that asks for an event stream, which cannot be scanned before the client reads it.
pub(crate) fn refuse_stream(mut ctx: Ctx) -> Flow<Ctx> {
    let (status, content_type, body) = stream_refusal();
    ctx.record.format = Some("event_stream".into());
    ctx.record.legs.push(note(Leg::Prompt, "event_stream_refused"));
    ctx.record.decision = "refuse_event_stream".into();
    ctx.record.status = status;
    logger::info!("{}", ctx.record.to_log_line());
    Flow::Break(
        Response::new(status as u32)
            .with_headers(vec![
                ("content-type".to_string(), content_type.to_string()),
                ("allow".to_string(), "POST, DELETE".to_string()),
            ])
            .with_body(body),
    )
}

pub(crate) async fn response(state: ResponseState, mut ctx: Ctx, client: &HttpClient, shared: &Shared) {
    let s = &shared.settings;
    let request = ctx.mcp.take().map(|m| m.request);
    if !s.scan_responses {
        if request.is_some() {
            ctx.record.legs.push(note(Leg::Response, "response_scan_off"));
        }
        ctx.record.decision = "pass".into();
        logger::info!("{}", ctx.record.to_log_line());
        return;
    }
    let headers = state.into_headers_state().await;
    let status: u16 = headers.handler().header(":status").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    let content_type = headers.handler().header("content-type").unwrap_or_default().to_ascii_lowercase();
    let event_stream = content_type.contains("text/event-stream");
    ctx.record.status = status;
    if request.is_none() && (!event_stream || ctx.stream_get) {
        // A bodiless request: anything but an unexpected event stream passes as it did before MCP, unread. A stream the
        // client asked for (monitor mode) is left open rather than held.
        if ctx.stream_get && event_stream {
            ctx.record.legs.push(note(Leg::Response, "event_stream_unscanned"));
        }
        ctx.record.decision = "pass".into();
        logger::info!("{}", ctx.record.to_log_line());
        return;
    }
    let encoded = headers
        .handler()
        .header("content-encoding")
        .map(|e| e.trim().to_ascii_lowercase())
        .is_some_and(|e| !e.is_empty() && e != "identity");
    let state = headers.into_headers_body_state().await;
    let h = state.handler();
    let body = if state.contains_body() { h.body() } else { Vec::new() };
    let ok = (200..300).contains(&status);

    let Some(mut scan_ctx) = ctx.scan_ctx.clone() else {
        ctx.record.decision = "pass".into();
        logger::info!("{}", ctx.record.to_log_line());
        return;
    };
    // An MCP server issues Mcp-Session-Id on its initialize reply; that reply's own scan already joins the session.
    let initialize = request.as_ref().is_some_and(|r| r.members.iter().any(|m| m.method.as_deref() == Some("initialize")));
    if scan_ctx.session_id.is_none() && initialize {
        if let Some(id) = h.header("mcp-session-id").and_then(|v| clamp_id(&v)) {
            scan_ctx.session_id = Some(id);
            ctx.record.session_id_present = true;
        }
    }

    let read = if encoded { Err(Gap::Encoded) } else { messages(&body, event_stream).map_err(|_| Gap::Unreadable) };
    let mut refusal = None;
    match read {
        Err(gap) if ok => {
            let mut leg = note(Leg::Response, "");
            refusal = judge(s, Leg::Response, &ScanOutcome::Gap(gap), &mut leg);
            ctx.record.legs.push(leg);
        }
        // An error the policy cannot read carries no server text it could scan.
        Err(_) => ctx.record.legs.push(note(Leg::Response, "upstream_status")),
        Ok(msgs) => {
            let scans = reply_scans(request.as_ref(), &msgs, &shared.server_name, s.max_scan_chars);
            if scans.is_empty() {
                ctx.record.legs.push(note(Leg::Response, "empty"));
            }
            for leg_scan in scans {
                let (outcome, mut record) = run(client, shared, &scan_ctx, &leg_scan, Leg::Response).await;
                let refused = judge(s, Leg::Response, &outcome, &mut record);
                ctx.record.legs.push(record);
                if refused.is_some() {
                    refusal = refused;
                    break;
                }
            }
        }
    }
    match refusal {
        Some(r) => {
            let batch = request.as_ref().is_some_and(|r| r.batch);
            let (status, content_type, error) = mcp_refusal(
                &request_ids(request.as_ref()),
                batch,
                Leg::Response,
                r.kind,
                r.scan_id.as_deref(),
                r.detections.as_deref(),
            );
            report_violation(shared, &ctx);
            h.set_header(":status", &status.to_string());
            h.set_header("content-type", content_type);
            h.remove_header("content-length");
            h.remove_header("content-encoding");
            let written = h.set_body(&error).is_ok();
            h.set_header("content-length", &error.len().to_string());
            ctx.record.decision = format!("block_{}", r.kind.name());
            ctx.record.status = status;
            if !written {
                logger::error!("prisma-airs-guardrails: the refused MCP reply's body could not be replaced");
            }
        }
        None => ctx.record.decision = "pass".into(),
    }
    logger::info!("{}", ctx.record.to_log_line());
}

/// One scan of a leg: a gap, without calling AIRS, when its text was cut and the policy fails closed; else the scan.
/// Text is sent as a prompt on both legs, because MCP text reaches a model as input.
async fn run(client: &HttpClient, shared: &Shared, scan_ctx: &ScanContext, leg_scan: &LegScan, leg: Leg) -> (ScanOutcome, LegRecord) {
    let s = &shared.settings;
    let (outcome, mut record) = match &leg_scan.scan {
        Scan::Text(e) if e.truncated && s.truncation_fail_closed => {
            (ScanOutcome::Gap(Gap::Truncated), LegRecord { truncated: true, ..LegRecord::default() })
        }
        Scan::Text(e) => {
            let (outcome, record) = scan(client, shared, scan_ctx, What::Text { leg: Leg::Prompt, text: &e.text, context: None }).await;
            (outcome, LegRecord { truncated: e.truncated, ..record })
        }
        Scan::Tool(event) => scan(client, shared, scan_ctx, What::Tool(event)).await,
    };
    record.leg = leg.name().into();
    record.content = Some(match leg_scan.scan {
        Scan::Tool(_) => "tool_event".into(),
        Scan::Text(_) => "prompt".into(),
    });
    record.method = leg_scan.method.as_deref().map(clean_method);
    (outcome, record)
}

/// The decision on one scan, written into its record; `Some` when it refuses the exchange. No MCP scan is a single
/// field that masked text could replace, nor a stream to mask.
fn judge(s: &Settings, leg: Leg, outcome: &ScanOutcome, record: &mut LegRecord) -> Option<Refusal> {
    let decision = decide(s, leg, outcome, false, false);
    record.outcome = outcome_name(outcome, &decision);
    match decision {
        Decision::Block { kind, scan_id, .. } => {
            Some(Refusal { kind, scan_id, detections: detections(outcome, s.show_categories) })
        }
        Decision::Mask(_) | Decision::Pass(_) => None,
    }
}

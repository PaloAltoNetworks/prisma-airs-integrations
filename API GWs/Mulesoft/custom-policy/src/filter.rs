//! The request and response filters.

use pdk::authentication::{Authentication, AuthenticationHandler};
use pdk::hl::*;
use pdk::logger;
use prisma_airs_core::airs::{clamp_id, Leg, ScanContext};
use prisma_airs_core::decision::{decide, BlockKind, Decision, Gap, ScanOutcome};
use prisma_airs_core::errors::client_error;
use prisma_airs_core::evidence::{LegRecord, Record};
use prisma_airs_core::extract::request::prompt_text;
use prisma_airs_core::extract::response::{from_value, scan_text};
use prisma_airs_core::extract::{ExtractError, Slot};
use prisma_airs_core::format::{is_streamed, requested_model, Format};
use prisma_airs_core::{identity, sse};
use serde_json::Value;

use crate::scan::{now_ms, scan};
use crate::{Shared, VERSION};

/// What the request leg hands to the response leg.
pub(crate) struct Ctx {
    format: Option<Format>,
    scan_response: bool,
    prompt: Option<String>,
    scan_ctx: Option<ScanContext>,
    record: Record,
    client_name: Option<String>,
    client_id: Option<String>,
}

/// The filter of a policy whose configuration could not be used: nothing passes.
pub(crate) async fn refuse(_request: RequestState) -> Flow<()> {
    let (content_type, body) = client_error(None, Leg::Prompt, 503, BlockKind::Scanner, None, None);
    Flow::Break(Response::new(503).with_headers(vec![("content-type".to_string(), content_type.to_string())]).with_body(body))
}

pub(crate) async fn request(state: RequestState, client: HttpClient, auth: Authentication, shared: &Shared) -> Flow<Ctx> {
    let s = &shared.settings;
    let state = state.into_headers_body_state().await;
    let h = state.handler();
    let header = |name: &str| h.header(name).filter(|v| !v.is_empty());
    let path = header(":path").unwrap_or_default();

    let auth = auth.authentication();
    let client_name = auth.as_ref().and_then(|a| a.client_name.clone()).filter(|v| !v.is_empty());
    let client_id = auth.as_ref().and_then(|a| a.client_id.clone()).filter(|v| !v.is_empty());
    let claims = auth.as_ref().and_then(|a| serde_json::to_value(&a.properties).ok());
    let claim = |name: Option<&String>| name.and_then(|n| claims.as_ref().and_then(|c| claim_value(c, n)));
    let user_header = s.user_header.as_deref().and_then(header);
    let app_user = identity::app_user(
        claim(s.user_claim.as_ref()).as_deref(),
        user_header.as_deref(),
        client_name.as_deref(),
        client_id.as_deref(),
    );
    let (session_id, dropped) = identity::session_id(header(&s.session_header).as_deref(), claim(s.session_claim.as_ref()).as_deref());
    let transaction_id = header("x-correlation-id")
        .and_then(|v| clamp_id(&v))
        .or_else(|| header("x-request-id").and_then(|v| clamp_id(&v)));
    let record = Record::new(VERSION, transaction_id.clone(), session_id.is_some(), dropped, header("x-llm-proxy-llm-model"));
    let profile = identity::profile(s, client_name.as_deref());
    let mut ctx = Ctx { format: None, scan_response: s.scan_responses, prompt: None, scan_ctx: None, record, client_name, client_id };

    let body = if state.contains_body() { h.body() } else { Vec::new() };
    if body.is_empty() {
        // Nothing to scan, and its reply (a model list, say) is not model output.
        ctx.scan_response = false;
        ctx.record.legs.push(note(Leg::Prompt, "no_body"));
        return Flow::Continue(ctx);
    }

    let mut slot = Slot::Multi;
    let mut leg = note(Leg::Prompt, "");
    let outcome = match serde_json::from_slice::<Value>(&body) {
        Err(_) => ScanOutcome::Gap(Gap::Unreadable),
        Ok(parsed) => match Format::detect(header("x-input-format").as_deref(), &path, &parsed) {
            None => ScanOutcome::Gap(Gap::UnknownFormat),
            Some(format) => {
                ctx.format = Some(format);
                ctx.record.format = Some(format.name().into());
                ctx.record.streamed = is_streamed(format, &path, &parsed);
                let scan_ctx = ScanContext {
                    profile,
                    transaction_id,
                    session_id,
                    app_name: s.app_name.clone(),
                    app_user,
                    ai_model: requested_model(format, &path, &parsed),
                };
                let outcome = match prompt_text(format, &parsed, &s.roles, s.max_scan_chars) {
                    Err(ExtractError::NoContent) => ScanOutcome::Gap(Gap::UnknownFormat),
                    Err(ExtractError::Unreadable(_)) => ScanOutcome::Gap(Gap::Unreadable),
                    Ok(extracted) => {
                        ctx.prompt = Some(extracted.text.clone());
                        leg.truncated = extracted.truncated;
                        slot = extracted.slot.clone();
                        if extracted.truncated && s.truncation_fail_closed {
                            ScanOutcome::Gap(Gap::Truncated)
                        } else if !s.scan_requests {
                            ctx.scan_ctx = Some(scan_ctx);
                            ctx.record.legs.push(note(Leg::Prompt, "prompt_scan_off"));
                            return continue_request(ctx, h);
                        } else {
                            let (outcome, record) = scan(&client, shared, &scan_ctx, Leg::Prompt, &extracted.text, None).await;
                            leg = LegRecord { truncated: extracted.truncated, ..record };
                            outcome
                        }
                    }
                };
                ctx.scan_ctx = Some(scan_ctx);
                outcome
            }
        },
    };

    // A request body is never a stream, even when it asks for a streamed reply, so its prompt can be masked in place.
    let decision = decide(s, Leg::Prompt, &outcome, false, matches!(slot, Slot::Single(_)));
    leg.outcome = outcome_name(&outcome, &decision);
    ctx.record.legs.push(leg);
    match decision {
        Decision::Block { status, scan_id, kind } => {
            let categories = detections(&outcome, s.show_categories);
            let (content_type, error) = client_error(ctx.format, Leg::Prompt, status, kind, scan_id.as_deref(), categories.as_deref());
            report_violation(shared, &ctx);
            ctx.record.decision = format!("block_{}", kind.name());
            ctx.record.status = status;
            logger::info!("{}", ctx.record.to_log_line());
            Flow::Break(
                Response::new(status as u32)
                    .with_headers(vec![("content-type".to_string(), content_type.to_string())])
                    .with_body(error),
            )
        }
        Decision::Mask(masked) => {
            let written = match &slot {
                Slot::Single(pointer) => rewrite(&body, pointer, &masked).and_then(|new| set_body(h, &new)),
                Slot::Multi => None,
            };
            if written.is_none() {
                // Masked text that cannot be written back means the original would be forwarded: block instead.
                return block_request(ctx, shared, &outcome, 403, BlockKind::Policy);
            }
            ctx.record.legs.last_mut().map(|l| l.outcome = "masked".into());
            continue_request(ctx, h)
        }
        Decision::Pass(_) => continue_request(ctx, h),
    }
}

fn continue_request(ctx: Ctx, h: &dyn HeadersBodyHandler) -> Flow<Ctx> {
    if ctx.scan_response {
        // A compressed reply cannot be read, so the upstream is asked for an uncompressed one.
        h.remove_header("accept-encoding");
    }
    Flow::Continue(ctx)
}

fn block_request(mut ctx: Ctx, shared: &Shared, outcome: &ScanOutcome, status: u16, kind: BlockKind) -> Flow<Ctx> {
    let scan_id = match outcome {
        ScanOutcome::Verdict(v) => v.scan_id.clone(),
        _ => None,
    };
    let categories = detections(outcome, shared.settings.show_categories);
    let (content_type, error) = client_error(ctx.format, Leg::Prompt, status, kind, scan_id.as_deref(), categories.as_deref());
    report_violation(shared, &ctx);
    ctx.record.decision = format!("block_{}", kind.name());
    ctx.record.status = status;
    logger::info!("{}", ctx.record.to_log_line());
    Flow::Break(
        Response::new(status as u32)
            .with_headers(vec![("content-type".to_string(), content_type.to_string())])
            .with_body(error),
    )
}

pub(crate) async fn response(state: ResponseState, data: RequestData<Ctx>, client: HttpClient, shared: &Shared) {
    let RequestData::Continue(mut ctx) = data else { return };
    let s = &shared.settings;
    if !ctx.scan_response {
        ctx.record.decision = "pass".into();
        logger::info!("{}", ctx.record.to_log_line());
        return;
    }
    let state = state.into_headers_body_state().await;
    let h = state.handler();
    let status: u16 = h.header(":status").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    ctx.record.status = status;
    if !(200..300).contains(&status) {
        // An error from the upstream or the gateway carries no model output.
        ctx.record.legs.push(note(Leg::Response, "upstream_status"));
        ctx.record.decision = "pass".into();
        logger::info!("{}", ctx.record.to_log_line());
        return;
    }
    let content_type = h.header("content-type").unwrap_or_default().to_ascii_lowercase();
    let streamed = content_type.contains("text/event-stream");
    let encoded = h
        .header("content-encoding")
        .map(|e| e.trim().to_ascii_lowercase())
        .is_some_and(|e| !e.is_empty() && e != "identity");
    let body = if state.contains_body() { h.body() } else { Vec::new() };

    let mut slot = Slot::Multi;
    let mut leg = note(Leg::Response, "");
    let outcome = if encoded {
        ScanOutcome::Gap(Gap::Encoded)
    } else if body.is_empty() {
        ScanOutcome::Empty
    } else {
        match ctx.format {
            None => ScanOutcome::Gap(Gap::UnknownFormat),
            Some(format) => {
                let parts = if streamed {
                    sse::to_final_json(format, &sse::events(&body)).and_then(|v| from_value(format, &v))
                } else {
                    serde_json::from_slice::<Value>(&body)
                        .map_err(|_| ExtractError::Unreadable("the reply is not JSON".into()))
                        .and_then(|v| from_value(format, &v))
                };
                match parts {
                    Err(_) => ScanOutcome::Gap(Gap::Unreadable),
                    Ok(parts) if parts.is_empty() => ScanOutcome::Empty,
                    Ok(parts) => {
                        let extracted = scan_text(&parts, s.max_scan_chars);
                        leg.truncated = extracted.truncated;
                        slot = extracted.slot.clone();
                        if extracted.truncated && s.truncation_fail_closed {
                            ScanOutcome::Gap(Gap::Truncated)
                        } else {
                            match &ctx.scan_ctx {
                                None => ScanOutcome::Gap(Gap::UnknownFormat),
                                Some(scan_ctx) => {
                                    let (outcome, record) =
                                        scan(&client, shared, scan_ctx, Leg::Response, &extracted.text, ctx.prompt.as_deref()).await;
                                    leg = LegRecord { truncated: extracted.truncated, ..record };
                                    outcome
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    let single = !streamed && matches!(slot, Slot::Single(_));
    let decision = decide(s, Leg::Response, &outcome, streamed, single);
    leg.outcome = outcome_name(&outcome, &decision);
    ctx.record.legs.push(leg);
    let block = match decision {
        Decision::Block { status, scan_id, kind } => Some((status, scan_id, kind)),
        Decision::Mask(masked) => {
            let written = match &slot {
                Slot::Single(pointer) => rewrite(&body, pointer, &masked).and_then(|new| replace_body(h, &new)),
                Slot::Multi => None,
            };
            match written {
                Some(()) => {
                    ctx.record.legs.last_mut().map(|l| l.outcome = "masked".into());
                    None
                }
                None => Some((403, verdict_scan_id(&outcome), BlockKind::Policy)),
            }
        }
        Decision::Pass(_) => None,
    };
    if let Some((status, scan_id, kind)) = block {
        let categories = detections(&outcome, s.show_categories);
        let (content_type, error) = client_error(ctx.format, Leg::Response, status, kind, scan_id.as_deref(), categories.as_deref());
        report_violation(shared, &ctx);
        h.set_header(":status", &status.to_string());
        h.set_header("content-type", content_type);
        h.remove_header("content-length");
        h.remove_header("content-encoding");
        let ok = h.set_body(&error).is_ok();
        h.set_header("content-length", &error.len().to_string());
        ctx.record.decision = format!("block_{}", kind.name());
        ctx.record.status = status;
        if !ok {
            logger::error!("prisma-airs-guardrails: the blocked reply's body could not be replaced");
        }
    } else {
        ctx.record.decision = "pass".into();
    }
    logger::info!("{}", ctx.record.to_log_line());
}

fn note(leg: Leg, outcome: &str) -> LegRecord {
    LegRecord { leg: leg.name().into(), outcome: outcome.into(), ..LegRecord::default() }
}

fn outcome_name(outcome: &ScanOutcome, decision: &Decision) -> String {
    match (outcome, decision) {
        (_, Decision::Pass(o)) => o.name().into(),
        (_, Decision::Mask(_)) => "masked".into(),
        (ScanOutcome::Gap(g), Decision::Block { .. }) => format!("gap_{}", g.name()),
        (ScanOutcome::Error(_), Decision::Block { .. }) => "scanner_failed".into(),
        (_, Decision::Block { kind, .. }) => format!("blocked_{}", kind.name()),
    }
}

fn verdict_scan_id(outcome: &ScanOutcome) -> Option<String> {
    match outcome {
        ScanOutcome::Verdict(v) => v.scan_id.clone(),
        _ => None,
    }
}

fn detections(outcome: &ScanOutcome, show: bool) -> Option<Vec<String>> {
    match outcome {
        ScanOutcome::Verdict(v) if show => Some(v.detections.clone()),
        _ => None,
    }
}

fn report_violation(shared: &Shared, ctx: &Ctx) {
    match (&ctx.client_name, &ctx.client_id) {
        (Some(name), Some(id)) => shared.violations.generate_policy_violation_for_client_app(name.clone(), id.clone()),
        _ => shared.violations.generate_policy_violation(),
    }
}

/// A claim from the authentication properties a validation policy left, at the top level or under `claims`.
fn claim_value(properties: &Value, name: &str) -> Option<String> {
    let value = properties.get(name).or_else(|| properties.get("claims").and_then(|c| c.get(name)))?;
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The body with the string at `pointer` replaced, re-serialized.
fn rewrite(body: &[u8], pointer: &str, text: &str) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let slot = value.pointer_mut(pointer)?;
    if !slot.is_string() {
        return None;
    }
    *slot = Value::String(text.to_string());
    serde_json::to_vec(&value).ok()
}

fn set_body(h: &dyn HeadersBodyHandler, body: &[u8]) -> Option<()> {
    h.remove_header("content-length");
    h.set_body(body).ok()?;
    h.set_header("content-length", &body.len().to_string());
    Some(())
}

fn replace_body(h: &dyn HeadersBodyHandler, body: &[u8]) -> Option<()> {
    set_body(h, body)
}

#[allow(dead_code)]
fn elapsed_since(started: u64) -> u64 {
    now_ms().saturating_sub(started)
}

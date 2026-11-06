//! One AIRS scan: the verdict cache, the circuit breaker, the bounded HTTP call and its retries.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pdk::hl::HttpClient;
use prisma_airs_core::airs::{parse_verdict, scan_request, Action, Leg, ScanContext, ScanError, Verdict};
use prisma_airs_core::breaker::retryable;
use prisma_airs_core::cache::VerdictCache;
use prisma_airs_core::decision::ScanOutcome;
use prisma_airs_core::evidence::LegRecord;
use prisma_airs_core::settings::SCAN_PATH;

use crate::Shared;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Scans `text` for `leg`; `context` is the prompt sent as context on the response leg.
pub(crate) async fn scan(
    client: &HttpClient,
    shared: &Shared,
    ctx: &ScanContext,
    leg: Leg,
    text: &str,
    context: Option<&str>,
) -> (ScanOutcome, LegRecord) {
    let s = &shared.settings;
    let started = now_ms();
    let mut record = LegRecord { leg: leg.name().into(), ..LegRecord::default() };
    let key = s.cache_enabled().then(|| {
        VerdictCache::key(&s.api_key, &s.endpoint, &ctx.profile, leg, s.max_scan_chars, s.truncation_fail_closed, context.unwrap_or(""), text)
    });
    if let Some(key) = &key {
        let cached = shared.cache.borrow().get(key, started);
        if let Some(scan_id) = cached {
            record.cached = true;
            record.action = Some("allow".into());
            record.scan_id = Some(scan_id.clone());
            let verdict = Verdict {
                action: Action::Allow,
                scan_id: Some(scan_id),
                report_id: None,
                category: Some("benign".into()),
                detections: Vec::new(),
                masked_text: None,
            };
            return (ScanOutcome::Verdict(verdict), record);
        }
    }
    let body = scan_request(ctx, leg, text, context).to_string();
    let mut attempt = 0;
    let outcome = loop {
        // The breaker is borrowed only between awaits: other requests on this worker run while a call is in flight.
        if !shared.breaker.borrow_mut().permits(now_ms()) {
            break ScanOutcome::Error(ScanError::BreakerOpen);
        }
        match call(client, shared, &body, leg).await {
            Ok(verdict) => {
                shared.breaker.borrow_mut().record_success();
                if let (Some(key), Action::Allow, Some(scan_id)) = (key, verdict.action, verdict.scan_id.clone()) {
                    shared.cache.borrow_mut().put_allow(key, scan_id, now_ms());
                }
                break ScanOutcome::Verdict(verdict);
            }
            Err(err) => {
                shared.breaker.borrow_mut().record_failure(now_ms());
                if retryable(&err) && attempt < s.retries {
                    attempt += 1;
                    continue;
                }
                break ScanOutcome::Error(err);
            }
        }
    };
    record.ms = now_ms().saturating_sub(started);
    if let ScanOutcome::Verdict(v) = &outcome {
        record.action = Some(if v.action == Action::Allow { "allow" } else { "block" }.into());
        record.scan_id = v.scan_id.clone();
        record.report_id = v.report_id.clone();
        record.detections = v.detections.clone();
    }
    (outcome, record)
}

async fn call(client: &HttpClient, shared: &Shared, body: &str, leg: Leg) -> Result<Verdict, ScanError> {
    let s = &shared.settings;
    let bound = Duration::from_millis(s.timeout_ms as u64);
    let started = now_ms();
    let result = client
        .request(&shared.service)
        .path(SCAN_PATH)
        .headers(vec![("content-type", "application/json"), ("x-pan-token", s.api_key.as_str())])
        .body(body.as_bytes())
        .timeout(bound)
        .post()
        .await;
    let elapsed = now_ms().saturating_sub(started);
    match result {
        // The PDK client reports its own timeout as an HTTP 504 that arrives at the bound (measured on Flex 1.12.12).
        Ok(response) if response.status_code() == 504 && elapsed + 50 >= s.timeout_ms as u64 => Err(ScanError::Timeout),
        Ok(response) => parse_verdict(response.status_code() as u16, response.body(), leg),
        Err(err) => {
            let detail = clean(&format!("{err:?}"));
            if detail.to_ascii_lowercase().contains("timeout") {
                Err(ScanError::Timeout)
            } else {
                Err(ScanError::Transport(detail))
            }
        }
    }
}

/// Printable ASCII, at most 160 characters, for log lines.
pub(crate) fn clean(text: &str) -> String {
    text.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).take(160).collect()
}

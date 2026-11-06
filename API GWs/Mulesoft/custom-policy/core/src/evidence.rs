//! One structured log record per request: what was scanned, what AIRS said, what the policy did.
//!
//! The record never holds content, header values, the session id or the profile: only ids, outcomes, flags and
//! timings, so it can ship to any log store. The transaction id is the gateway's own correlation id, there to tie the
//! record to the scan in Strata Cloud Manager.

use serde::Serialize;

/// The prefix of every evidence log line.
pub const PREFIX: &str = "prisma-airs-guardrails evidence ";

#[derive(Debug, Clone, Default, Serialize)]
pub struct LegRecord {
    pub leg: String,
    pub outcome: String,
    pub action: Option<String>,
    pub scan_id: Option<String>,
    pub report_id: Option<String>,
    pub ms: u64,
    pub cached: bool,
    pub truncated: bool,
    pub detections: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Record {
    pub policy_version: String,
    pub transaction_id: Option<String>,
    pub session_id_present: bool,
    pub session_id_dropped: Option<String>,
    pub format: Option<String>,
    pub streamed: bool,
    pub legs: Vec<LegRecord>,
    pub decision: String,
    pub status: u16,
    pub routed_model: Option<String>,
}

impl Record {
    pub fn new(
        policy_version: &str,
        transaction_id: Option<String>,
        session_id_present: bool,
        session_id_dropped: Option<&str>,
        routed_model: Option<String>,
    ) -> Record {
        Record {
            policy_version: policy_version.to_string(),
            transaction_id,
            session_id_present,
            session_id_dropped: session_id_dropped.map(str::to_string),
            routed_model,
            ..Record::default()
        }
    }

    pub fn to_log_line(&self) -> String {
        format!("{PREFIX}{}", serde_json::to_string(self).unwrap_or_default())
    }
}

//! What the policy does with a scan's outcome.
//!
//! In enforce mode: a block verdict is a 403, a scanner that failed is a 503 (or a pass when the operator chose to
//! fail open), and content the policy could not inspect is a 403 (or a pass when the operator chose so). Masking
//! applies only to a verdict that is purely about sensitive data, only on a non-streamed body, and only when the text
//! came from a single field; it never overrides any other block.
//!
//! In monitor mode nothing the client receives changes: every decision is a pass, recorded as what it would have been.

use crate::airs::{Action, Leg, ScanError, Verdict};
use crate::settings::{Mode, OnError, Settings};

/// Content the policy should have inspected and could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    UnknownFormat,
    Unreadable,
    Truncated,
    Encoded,
    /// An MCP batch holds more messages than the batch limit allows.
    BatchLimit,
}

impl Gap {
    pub fn name(&self) -> &'static str {
        match self {
            Gap::UnknownFormat => "unknown_format",
            Gap::Unreadable => "unreadable",
            Gap::Truncated => "truncated",
            Gap::Encoded => "encoded",
            Gap::BatchLimit => "batch_limit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Verdict(Verdict),
    Error(ScanError),
    Gap(Gap),
    /// The reply holds nothing to scan.
    Empty,
}

/// Why traffic passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allowed,
    /// Monitor mode: it would have been blocked.
    MonitoredBlock,
    /// It passed unscanned because the scanner failed: onApiError allow, or monitor mode.
    FailedOpen,
    /// It passed uninspected because onScanError is allow.
    GapAllowed,
    /// Monitor mode: uninspected content that would have been blocked.
    GapUnenforced,
    Empty,
    /// AIRS returned masked text that the policy did not apply.
    MaskNotApplied,
}

impl Outcome {
    pub fn name(&self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::MonitoredBlock => "monitored_block",
            Outcome::FailedOpen => "failed_open",
            Outcome::GapAllowed => "gap_allowed",
            Outcome::GapUnenforced => "gap_unenforced",
            Outcome::Empty => "empty",
            Outcome::MaskNotApplied => "mask_not_applied",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// AIRS blocked the content.
    Policy,
    /// The scanner failed and the policy fails closed.
    Scanner,
    /// The content could not be inspected and the policy fails closed.
    Gap,
    /// Sensitive data on a stream, which cannot be masked in place.
    DlpOnStream,
    /// The policy's configuration was rejected, so every request is refused.
    Config,
}

impl BlockKind {
    pub fn name(&self) -> &'static str {
        match self {
            BlockKind::Policy => "policy",
            BlockKind::Scanner => "scanner",
            BlockKind::Gap => "gap",
            BlockKind::DlpOnStream => "dlp_on_stream",
            BlockKind::Config => "config",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pass(Outcome),
    /// Replace the scanned field with this masked text, then pass.
    Mask(String),
    Block { status: u16, scan_id: Option<String>, kind: BlockKind },
}

/// `streamed`: the body is a stream; `slot_single`: the scanned text is exactly one string field.
pub fn decide(settings: &Settings, _leg: Leg, outcome: &ScanOutcome, streamed: bool, slot_single: bool) -> Decision {
    let enforced = enforce(settings, outcome, streamed, slot_single);
    if settings.mode == Mode::Enforce {
        return enforced;
    }
    match enforced {
        Decision::Block { kind: BlockKind::Gap, .. } => Decision::Pass(Outcome::GapUnenforced),
        Decision::Block { kind: BlockKind::Scanner, .. } => Decision::Pass(Outcome::FailedOpen),
        Decision::Block { .. } => Decision::Pass(Outcome::MonitoredBlock),
        Decision::Mask(_) => match outcome {
            ScanOutcome::Verdict(v) if v.action == Action::Block => Decision::Pass(Outcome::MonitoredBlock),
            _ => Decision::Pass(Outcome::MaskNotApplied),
        },
        pass => pass,
    }
}

fn enforce(settings: &Settings, outcome: &ScanOutcome, streamed: bool, slot_single: bool) -> Decision {
    match outcome {
        ScanOutcome::Empty => Decision::Pass(Outcome::Empty),
        ScanOutcome::Gap(_) => match settings.on_scan_error {
            OnError::Block => Decision::Block { status: 403, scan_id: None, kind: BlockKind::Gap },
            OnError::Allow => Decision::Pass(Outcome::GapAllowed),
        },
        ScanOutcome::Error(_) => match settings.on_api_error {
            OnError::Block => Decision::Block { status: 503, scan_id: None, kind: BlockKind::Scanner },
            OnError::Allow => Decision::Pass(Outcome::FailedOpen),
        },
        ScanOutcome::Verdict(v) => verdict(settings, v, streamed, slot_single),
    }
}

fn verdict(settings: &Settings, v: &Verdict, streamed: bool, slot_single: bool) -> Decision {
    let block = |kind| Decision::Block { status: 403, scan_id: v.scan_id.clone(), kind };
    let masked = v.masked_text.as_ref().filter(|_| settings.masking);
    match v.action {
        Action::Allow => match (v.masked_text.is_some(), masked) {
            (false, _) => Decision::Pass(Outcome::Allowed),
            (true, None) => Decision::Pass(Outcome::MaskNotApplied),
            (true, Some(_)) if streamed => block(BlockKind::DlpOnStream),
            (true, Some(text)) if slot_single => Decision::Mask(text.clone()),
            (true, Some(_)) => Decision::Pass(Outcome::MaskNotApplied),
        },
        Action::Block => match masked {
            Some(_) if v.is_pure_dlp() && streamed => block(BlockKind::DlpOnStream),
            Some(text) if v.is_pure_dlp() && slot_single => Decision::Mask(text.clone()),
            _ => block(BlockKind::Policy),
        },
    }
}

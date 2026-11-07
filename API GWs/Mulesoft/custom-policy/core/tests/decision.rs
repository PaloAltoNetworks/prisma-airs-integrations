use prisma_airs_core::airs::{Action, Leg, ScanError, Verdict};
use prisma_airs_core::decision::{decide, BlockKind, Decision, Gap, Outcome, ScanOutcome};
use prisma_airs_core::settings::Settings;
use serde_json::json;

fn settings(mode: &str, api_error: &str, scan_error: &str, masking: bool) -> Settings {
    Settings::from_json(&json!({
        "airsApiKey": "SECRET-123", "profileName": "my-security-profile",
        "airsEndpoint": "https://service.api.aisecurity.paloaltonetworks.com",
        "enforcementMode": mode, "onApiError": api_error, "onScanError": scan_error,
        "advancedConfiguration": {"applyDlpMasking": masking}
    }))
    .unwrap()
}

fn verdict(action: Action, detections: &[&str], masked: Option<&str>) -> ScanOutcome {
    ScanOutcome::Verdict(Verdict {
        action,
        scan_id: Some("scan-1".into()),
        report_id: Some("report-1".into()),
        category: Some(if action == Action::Block { "malicious" } else { "benign" }.into()),
        detections: detections.iter().map(|d| d.to_string()).collect(),
        masked_text: masked.map(str::to_string),
    })
}

fn block(status: u16, kind: BlockKind, with_scan_id: bool) -> Decision {
    Decision::Block { status, scan_id: with_scan_id.then(|| "scan-1".to_string()), kind }
}

#[test]
fn decision_table() {
    use Outcome::*;
    // (row, outcome, onApiError, onScanError, masking, streamed, single slot, enforce result, monitor result)
    let rows: Vec<(&str, ScanOutcome, &str, &str, bool, bool, bool, Decision, Decision)> = vec![
        ("allow", verdict(Action::Allow, &[], None), "block", "block", false, false, true,
            Decision::Pass(Allowed), Decision::Pass(Allowed)),
        ("allow + masked, masking on, single slot", verdict(Action::Allow, &[], Some("XXXX")), "block", "block", true, false, true,
            Decision::Mask("XXXX".into()), Decision::Pass(MaskNotApplied)),
        ("allow + masked, masking on, streamed", verdict(Action::Allow, &[], Some("XXXX")), "block", "block", true, true, true,
            block(403, BlockKind::DlpOnStream, true), Decision::Pass(MonitoredBlock)),
        ("allow + masked, masking off", verdict(Action::Allow, &[], Some("XXXX")), "block", "block", false, false, true,
            Decision::Pass(MaskNotApplied), Decision::Pass(MaskNotApplied)),
        ("allow + masked, masking on, several fields", verdict(Action::Allow, &[], Some("XXXX")), "block", "block", true, false, false,
            Decision::Pass(MaskNotApplied), Decision::Pass(MaskNotApplied)),
        ("block pure dlp + masked, masking on, single slot", verdict(Action::Block, &["dlp"], Some("XXXX")), "block", "block", true, false, true,
            Decision::Mask("XXXX".into()), Decision::Pass(MonitoredBlock)),
        ("block pure dlp + masked, masking on, several fields", verdict(Action::Block, &["dlp"], Some("XXXX")), "block", "block", true, false, false,
            block(403, BlockKind::Policy, true), Decision::Pass(MonitoredBlock)),
        ("block pure dlp + masked, masking on, streamed", verdict(Action::Block, &["dlp"], Some("XXXX")), "block", "block", true, true, true,
            block(403, BlockKind::DlpOnStream, true), Decision::Pass(MonitoredBlock)),
        ("block pure dlp + masked, masking off", verdict(Action::Block, &["dlp"], Some("XXXX")), "block", "block", false, false, true,
            block(403, BlockKind::Policy, true), Decision::Pass(MonitoredBlock)),
        ("block", verdict(Action::Block, &["injection"], None), "block", "block", false, false, true,
            block(403, BlockKind::Policy, true), Decision::Pass(MonitoredBlock)),
        ("error, onApiError block", ScanOutcome::Error(ScanError::Timeout), "block", "block", false, false, true,
            block(503, BlockKind::Scanner, false), Decision::Pass(FailedOpen)),
        ("error, onApiError allow", ScanOutcome::Error(ScanError::Status(500)), "allow", "block", false, false, true,
            Decision::Pass(FailedOpen), Decision::Pass(FailedOpen)),
        ("gap, onScanError block", ScanOutcome::Gap(Gap::UnknownFormat), "block", "block", false, false, true,
            block(403, BlockKind::Gap, false), Decision::Pass(GapUnenforced)),
        ("gap, onScanError allow", ScanOutcome::Gap(Gap::Truncated), "block", "allow", false, false, true,
            Decision::Pass(GapAllowed), Decision::Pass(GapAllowed)),
        ("empty", ScanOutcome::Empty, "block", "block", false, false, true,
            Decision::Pass(Empty), Decision::Pass(Empty)),
    ];
    for (row, outcome, api, scan, masking, streamed, single, enforce, monitor) in rows {
        for leg in [Leg::Prompt, Leg::Response] {
            let s = settings("enforce", api, scan, masking);
            assert_eq!(decide(&s, leg, &outcome, streamed, single), enforce, "enforce: {row} ({leg:?})");
            let s = settings("monitor", api, scan, masking);
            assert_eq!(decide(&s, leg, &outcome, streamed, single), monitor, "monitor: {row} ({leg:?})");
        }
    }
}

#[test]
fn masking_never_overrides_a_non_dlp_block() {
    let s = settings("enforce", "block", "block", true);
    for detections in [&["dlp", "injection"][..], &["url_cats"][..], &["dlp", "prompt.injection"][..]] {
        let o = verdict(Action::Block, detections, Some("XXXX"));
        assert_eq!(decide(&s, Leg::Response, &o, false, true), block(403, BlockKind::Policy, true), "{detections:?}");
    }
}

#[test]
fn monitor_never_blocks_or_masks() {
    let s = settings("monitor", "block", "block", true);
    let outcomes = [
        verdict(Action::Block, &["injection"], None),
        verdict(Action::Block, &["dlp"], Some("XXXX")),
        verdict(Action::Allow, &[], Some("XXXX")),
        ScanOutcome::Error(ScanError::BreakerOpen),
        ScanOutcome::Gap(Gap::Encoded),
    ];
    for o in &outcomes {
        for streamed in [false, true] {
            let d = decide(&s, Leg::Prompt, o, streamed, true);
            assert!(matches!(d, Decision::Pass(_)), "{o:?} streamed={streamed} gave {d:?}");
        }
    }
}

#[test]
fn names_are_stable_for_evidence() {
    assert_eq!(Outcome::MonitoredBlock.name(), "monitored_block");
    assert_eq!(Outcome::FailedOpen.name(), "failed_open");
    assert_eq!(Outcome::GapUnenforced.name(), "gap_unenforced");
    assert_eq!(BlockKind::DlpOnStream.name(), "dlp_on_stream");
    assert_eq!(Gap::Encoded.name(), "encoded");
}

#[test]
fn a_batch_over_the_limit_is_a_gap() {
    assert_eq!(Gap::BatchLimit.name(), "batch_limit");
    let s = settings("enforce", "block", "block", false);
    assert_eq!(decide(&s, Leg::Prompt, &ScanOutcome::Gap(Gap::BatchLimit), false, false), block(403, BlockKind::Gap, false));
    let allow = settings("enforce", "block", "allow", false);
    assert_eq!(decide(&allow, Leg::Prompt, &ScanOutcome::Gap(Gap::BatchLimit), false, false), Decision::Pass(Outcome::GapAllowed));
}

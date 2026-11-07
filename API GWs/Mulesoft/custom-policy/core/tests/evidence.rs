use prisma_airs_core::airs::{clamp_id, scan_request, Leg, ScanContext};
use prisma_airs_core::evidence::{clean_method, LegRecord, Record};
use prisma_airs_core::identity::app_user;
use prisma_airs_core::settings::ProfileRef;
use serde_json::Value;

#[test]
fn record_has_no_content_or_header_values() {
    let user = app_user(None, Some("hdr-value"), Some("hr-bot"), None);
    let ctx = ScanContext {
        profile: ProfileRef::Name("my-security-profile".into()),
        transaction_id: clamp_id("tx-1"),
        session_id: clamp_id("conv-secret-id"),
        app_name: "MuleSoft".into(),
        app_user: user,
        ai_model: Some("gpt-test".into()),
    };
    let _payload = scan_request(&ctx, Leg::Prompt, "secret prompt text", None);
    let mut record = Record::new("1.2.3", ctx.transaction_id.clone(), ctx.session_id.is_some(), None, Some("gpt-test".into()));
    record.format = Some("openai_chat".into());
    record.legs.push(LegRecord {
        leg: "prompt".into(),
        outcome: "allowed".into(),
        action: Some("allow".into()),
        scan_id: Some("scan-1".into()),
        report_id: Some("report-1".into()),
        ms: 12,
        cached: false,
        truncated: false,
        detections: vec![],
        content: None,
        method: None,
    });
    record.decision = "pass".into();
    record.status = 200;
    let line = record.to_log_line();
    assert!(line.starts_with("prisma-airs-guardrails evidence {"), "{line}");
    for secret in ["secret prompt text", "hdr-value", "conv-secret-id", "my-security-profile"] {
        assert!(!line.contains(secret), "{secret} leaked into {line}");
    }
    let json: Value = serde_json::from_str(line.trim_start_matches("prisma-airs-guardrails evidence ")).unwrap();
    assert_eq!(json["policy_version"], "1.2.3");
    assert_eq!(json["transaction_id"], "tx-1");
    assert_eq!(json["session_id_present"], true);
    assert_eq!(json["legs"][0]["scan_id"], "scan-1");
    assert_eq!(json["routed_model"], "gpt-test");
}

#[test]
fn new_record_defaults() {
    let r = Record::new("1.0.0", None, false, Some("too_long"), None);
    let json: Value = serde_json::from_str(r.to_log_line().trim_start_matches("prisma-airs-guardrails evidence ")).unwrap();
    assert_eq!(json["session_id_dropped"], "too_long");
    assert_eq!(json["legs"], serde_json::json!([]));
    assert_eq!(json["streamed"], false);
}

#[test]
fn mcp_fields_are_recorded_and_absent_for_llm_traffic() {
    let mut r = Record::new("1.2.3", Some("tx-1".into()), false, None, None);
    let llm: Value = serde_json::from_str(r.to_log_line().trim_start_matches("prisma-airs-guardrails evidence ")).unwrap();
    assert!(llm.get("methods").is_none(), "an LLM record is unchanged");
    r.methods = vec![clean_method("tools/call")];
    r.legs.push(LegRecord {
        leg: "prompt".into(),
        content: Some("tool_event".into()),
        method: Some("tools/call".into()),
        ..LegRecord::default()
    });
    r.legs.push(LegRecord { leg: "response".into(), ..LegRecord::default() });
    let json: Value = serde_json::from_str(r.to_log_line().trim_start_matches("prisma-airs-guardrails evidence ")).unwrap();
    assert_eq!(json["methods"], serde_json::json!(["tools/call"]));
    assert_eq!(json["legs"][0]["content"], "tool_event");
    assert_eq!(json["legs"][0]["method"], "tools/call");
    assert!(json["legs"][1].get("content").is_none() && json["legs"][1].get("method").is_none());
}

#[test]
fn methods_are_cleaned() {
    assert_eq!(clean_method("tools/call"), "tools/call");
    assert_eq!(clean_method("bad\nname\u{e9}"), "bad?name?");
    assert_eq!(clean_method(&"m".repeat(80)).chars().count(), 64);
}

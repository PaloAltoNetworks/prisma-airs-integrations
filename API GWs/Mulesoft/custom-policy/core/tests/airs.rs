use prisma_airs_core::airs::{clamp_id, parse_verdict, scan_request, Action, Leg, ScanContext, ScanError};
use prisma_airs_core::settings::ProfileRef;
use serde_json::{json, Value};

fn ctx() -> ScanContext {
    ScanContext {
        profile: ProfileRef::Name("my-security-profile".into()),
        transaction_id: Some("5b1e8f3a-2c4d-4e6f-8a9b-0c1d2e3f4a5b".into()),
        session_id: Some("conv-42".into()),
        app_name: "MuleSoft".into(),
        app_user: "hr-bot".into(),
        ai_model: Some("gpt-test".into()),
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/airs/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

// ---- the request -------------------------------------------------------------------------------------------------

#[test]
fn prompt_payload_shape() {
    let v = scan_request(&ctx(), Leg::Prompt, "hello", None);
    assert_eq!(v["contents"], json!([{"prompt":"hello"}]));
    assert_eq!(v["ai_profile"], json!({"profile_name":"my-security-profile"}));
    assert_eq!(v["metadata"], json!({"app_name":"MuleSoft","app_user":"hr-bot","ai_model":"gpt-test"}));
    assert!(v.get("tr_id").is_none());
    assert_eq!(v["transaction_id"], "5b1e8f3a-2c4d-4e6f-8a9b-0c1d2e3f4a5b");
    assert_eq!(v["session_id"], "conv-42");
}

#[test]
fn prompt_context_is_ignored_on_the_prompt_leg() {
    let v = scan_request(&ctx(), Leg::Prompt, "hello", Some("earlier"));
    assert_eq!(v["contents"], json!([{"prompt":"hello"}]));
}

#[test]
fn response_payload_shape_with_prompt_as_context() {
    let v = scan_request(&ctx(), Leg::Response, "the reply", Some("the prompt"));
    assert_eq!(v["contents"], json!([{"prompt":"the prompt"},{"response":"the reply"}]));
}

#[test]
fn response_payload_shape_without_prompt() {
    let v = scan_request(&ctx(), Leg::Response, "the reply", None);
    assert_eq!(v["contents"], json!([{"response":"the reply"}]));
    let blank = scan_request(&ctx(), Leg::Response, "the reply", Some("  "));
    assert_eq!(blank["contents"], json!([{"response":"the reply"}]));
}

#[test]
fn session_omitted_when_none() {
    let mut c = ctx();
    c.session_id = None;
    c.transaction_id = None;
    c.ai_model = None;
    let v = scan_request(&c, Leg::Prompt, "hello", None);
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("session_id") && !obj.contains_key("transaction_id") && !obj.contains_key("tr_id"));
    assert!(v["metadata"].get("ai_model").is_none());
}

#[test]
fn profile_id_variant() {
    let mut c = ctx();
    c.profile = ProfileRef::Id("0b6c0d2e-1111-2222-3333-444455556666".into());
    let v = scan_request(&c, Leg::Prompt, "hello", None);
    assert_eq!(v["ai_profile"], json!({"profile_id":"0b6c0d2e-1111-2222-3333-444455556666"}));
}

#[test]
fn text_with_quotes_and_newlines_stays_valid_json() {
    let text = "line \"one\"\nline \\two\\ \u{0}";
    let v = scan_request(&ctx(), Leg::Prompt, text, None);
    let round: Value = serde_json::from_str(&v.to_string()).unwrap();
    assert_eq!(round["contents"][0]["prompt"], text);
}

// ---- correlation ids ---------------------------------------------------------------------------------------------

#[test]
fn clamp_trims_and_keeps_100() {
    let hundred = "a".repeat(100);
    assert_eq!(clamp_id(&format!("  {hundred} ")).as_deref(), Some(hundred.as_str()));
}

#[test]
fn clamp_rejects_101_chars() {
    assert_eq!(clamp_id(&"a".repeat(101)), None);
}

#[test]
fn clamp_rejects_non_ascii() {
    assert_eq!(clamp_id("sesión"), None);
    assert_eq!(clamp_id("a\tb"), None);
    assert_eq!(clamp_id("a\u{7}b"), None);
}

#[test]
fn clamp_rejects_empty() {
    assert_eq!(clamp_id(""), None);
    assert_eq!(clamp_id("   "), None);
}

// ---- the verdict -------------------------------------------------------------------------------------------------

#[test]
fn parse_allow_fixture() {
    let v = parse_verdict(200, &fixture("allow_prompt.json"), Leg::Prompt).unwrap();
    assert_eq!(v.action, Action::Allow);
    assert!(v.scan_id.is_some() && v.report_id.is_some());
    assert!(v.detections.is_empty());
    assert_eq!(v.masked_text, None);
}

#[test]
fn parse_block_prompt_fixture() {
    let v = parse_verdict(200, &fixture("block_prompt.json"), Leg::Prompt).unwrap();
    assert_eq!(v.action, Action::Block);
    assert!(v.detections.contains(&"injection".to_string()), "{:?}", v.detections);
    assert_eq!(v.category.as_deref(), Some("malicious"));
    assert!(!v.detections.iter().any(|d| d.contains("malicious")), "category is never a detection: {:?}", v.detections);
    assert!(!v.is_pure_dlp());
}

#[test]
fn parse_block_response_fixture() {
    let v = parse_verdict(200, &fixture("block_response_url.json"), Leg::Response).unwrap();
    assert_eq!(v.action, Action::Block);
    assert_eq!(v.detections, vec!["url_cats".to_string()]);
}

#[test]
fn parse_dlp_response_with_masking() {
    let v = parse_verdict(200, &fixture("block_response_dlp_context.json"), Leg::Response).unwrap();
    assert_eq!(v.action, Action::Block);
    assert_eq!(v.detections, vec!["dlp".to_string()]);
    assert!(v.is_pure_dlp());
    let masked = v.masked_text.expect("the lab profile masks data-loss findings");
    assert!(masked.contains('X') && !masked.contains("021000021"), "{masked}");
}

#[test]
fn other_side_flags_are_named_with_their_side() {
    // A prompt/response pair re-judges the prompt; such flags never count as the reply's own, nor as pure DLP.
    let v = parse_verdict(200, &fixture("block_response_dlp.json"), Leg::Response).unwrap();
    assert!(v.detections.contains(&"dlp".to_string()), "{:?}", v.detections);
    assert!(v.detections.iter().any(|d| d.starts_with("prompt.")), "{:?}", v.detections);
    assert!(!v.is_pure_dlp());
}

#[test]
fn parse_non_200_is_status() {
    assert_eq!(parse_verdict(401, br#"{"error":{"message":"Invalid API Key"}}"#, Leg::Prompt).unwrap_err(), ScanError::Status(401));
    assert_eq!(parse_verdict(504, b"", Leg::Prompt).unwrap_err(), ScanError::Status(504));
}

#[test]
fn parse_garbage_is_undecodable() {
    assert_eq!(parse_verdict(200, b"<html>gateway</html>", Leg::Prompt).unwrap_err(), ScanError::Undecodable);
    assert_eq!(parse_verdict(200, b"[1,2]", Leg::Prompt).unwrap_err(), ScanError::Undecodable);
}

#[test]
fn parse_unknown_action_is_missing_action() {
    assert_eq!(parse_verdict(200, br#"{"action":"maybe","category":"benign"}"#, Leg::Prompt).unwrap_err(), ScanError::MissingAction);
    assert_eq!(parse_verdict(200, br#"{"category":"benign"}"#, Leg::Prompt).unwrap_err(), ScanError::MissingAction);
}

#[test]
fn parse_detector_error_on_allow_is_incomplete() {
    let body = br#"{"action":"allow","category":"benign","error":true,"timeout":false,
        "errors":[{"content_type":"prompt","feature":"dlp","status":"error"}],"scan_id":"s","report_id":"r"}"#;
    assert_eq!(parse_verdict(200, body, Leg::Prompt).unwrap_err(), ScanError::Incomplete(vec!["dlp:error".to_string()]));
    let by_category = br#"{"action":"allow","category":"timeout","error":false,"timeout":false,"errors":[]}"#;
    assert!(matches!(parse_verdict(200, by_category, Leg::Prompt), Err(ScanError::Incomplete(_))));
}

#[test]
fn parse_detector_timeout_on_block_still_blocks() {
    let body = br#"{"action":"block","category":"malicious","timeout":true,"prompt_detected":{"injection":true},
        "errors":[{"content_type":"prompt","feature":"url_cats","status":"timeout"}]}"#;
    assert_eq!(parse_verdict(200, body, Leg::Prompt).unwrap().action, Action::Block);
}

#[test]
fn pure_dlp_only_when_dlp_alone() {
    let dlp = br#"{"action":"block","category":"malicious","prompt_detected":{"dlp":true,"injection":false}}"#;
    assert!(parse_verdict(200, dlp, Leg::Prompt).unwrap().is_pure_dlp());
    let mixed = br#"{"action":"block","category":"malicious","prompt_detected":{"dlp":true,"url_cats":true}}"#;
    assert!(!parse_verdict(200, mixed, Leg::Prompt).unwrap().is_pure_dlp());
    let none = br#"{"action":"block","category":"malicious"}"#;
    assert!(!parse_verdict(200, none, Leg::Prompt).unwrap().is_pure_dlp());
}

#[test]
fn masked_text_read_from_leg_field() {
    let body = br#"{"action":"block","category":"malicious","prompt_detected":{"dlp":true},"response_detected":{"dlp":true},
        "prompt_masked_data":{"data":"prompt XXXX"},"response_masked_data":{"data":"reply XXXX"}}"#;
    assert_eq!(parse_verdict(200, body, Leg::Prompt).unwrap().masked_text.as_deref(), Some("prompt XXXX"));
    assert_eq!(parse_verdict(200, body, Leg::Response).unwrap().masked_text.as_deref(), Some("reply XXXX"));
}

#[test]
fn errors_never_contain_the_reply_body() {
    let err = parse_verdict(500, b"secret-looking upstream text", Leg::Prompt).unwrap_err();
    assert!(!format!("{err:?} {err}").contains("secret-looking"));
}

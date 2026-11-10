use prisma_airs_core::identity::{app_user, mcp_session_id, profile, session_id};
use prisma_airs_core::settings::{ProfileRef, Settings};
use serde_json::json;

fn settings(extra: serde_json::Value) -> Settings {
    let mut raw = json!({"airsApiKey": "k", "airsEndpoint": "https://service.api.aisecurity.paloaltonetworks.com"});
    for (k, v) in extra.as_object().unwrap() {
        raw[k] = v.clone();
    }
    Settings::from_json(&raw).unwrap()
}

#[test]
fn app_user_order() {
    assert_eq!(app_user(Some("alice"), Some("bob"), Some("hr-bot"), Some("cid")), "alice");
    assert_eq!(app_user(None, Some("bob"), Some("hr-bot"), Some("cid")), "bob");
    assert_eq!(app_user(None, None, Some("hr-bot"), Some("cid")), "hr-bot");
    assert_eq!(app_user(None, None, None, Some("cid")), "cid");
    assert_eq!(app_user(None, None, None, None), "anonymous");
    let long = "b".repeat(101);
    assert_eq!(app_user(None, Some(&long), Some("hr-bot"), None), "hr-bot", "an unusable header is skipped");
    assert_eq!(app_user(Some(" "), None, None, Some("cid")), "cid");
}

#[test]
fn session_order_and_drop_reason() {
    assert_eq!(session_id(Some("conv-1"), Some("claim-1")), (Some("conv-1".to_string()), None));
    let long = "s".repeat(150);
    assert_eq!(session_id(Some(&long), Some("claim-1")), (Some("claim-1".to_string()), Some("too_long")));
    assert_eq!(session_id(Some(&long), None), (None, Some("too_long")));
    assert_eq!(session_id(Some("sesión"), None), (None, Some("not_printable_ascii")));
    assert_eq!(session_id(None, Some("claim-1")), (Some("claim-1".to_string()), None));
    assert_eq!(session_id(None, None), (None, None));
    assert_eq!(session_id(Some(""), None), (None, None), "an empty header is simply absent");
}

#[test]
fn profile_map_and_fallback() {
    let mapped = settings(json!({"profile": "strict", "advancedConfiguration": {
        "profileMap": [{"clientName": "hr-bot", "profileName": "hr"}]}}));
    assert_eq!(profile(&mapped, Some("hr-bot")), ProfileRef::Name("hr".into()));
    assert_eq!(profile(&mapped, Some("HR-BOT")), ProfileRef::Name("strict".into()), "client names match exactly");
    assert_eq!(profile(&mapped, Some("other")), ProfileRef::Name("strict".into()));
    assert_eq!(profile(&mapped, None), ProfileRef::Name("strict".into()));
    let id = "0b6c0d2e-1111-2222-3333-444455556666";
    let by_id = settings(json!({"profile": id, "advancedConfiguration": {
        "profileMap": [{"clientName": "hr-bot", "profileName": "hr"}]}}));
    assert_eq!(profile(&by_id, Some("other")), ProfileRef::Id(id.into()), "apps the map does not name get the profile, an ID too");
    assert_eq!(profile(&by_id, Some("hr-bot")), ProfileRef::Name("hr".into()));
    let fixed = settings(json!({"profile": "my-security-profile"}));
    assert_eq!(profile(&fixed, Some("hr-bot")), ProfileRef::Name("my-security-profile".into()));
}

#[test]
fn mcp_session_header_comes_first() {
    assert_eq!(mcp_session_id(Some("mcp-1"), Some("hdr-1"), Some("claim-1")), (Some("mcp-1".into()), None));
    assert_eq!(mcp_session_id(None, Some("hdr-1"), Some("claim-1")), (Some("hdr-1".into()), None));
    assert_eq!(mcp_session_id(None, None, Some("claim-1")), (Some("claim-1".into()), None));
    assert_eq!(mcp_session_id(None, None, None), (None, None));
}

#[test]
fn an_unusable_mcp_session_falls_back() {
    let long = "s".repeat(101);
    assert_eq!(mcp_session_id(Some(&long), Some("hdr-1"), None), (Some("hdr-1".into()), Some("too_long")));
    assert_eq!(mcp_session_id(Some("caf\u{e9}"), None, None), (None, Some("not_printable_ascii")));
}

use prisma_airs_core::settings::{ConfigError, Mode, OnError, ProfileRef, Role, Settings};
use serde_json::{json, Value};

/// How a `format: service` value arrives in the policy's raw configuration.
const ENDPOINT: &str = "https://service.api.aisecurity.paloaltonetworks.com";

fn minimal() -> Value {
    json!({"airsApiKey": "k", "profile": "p", "airsEndpoint": ENDPOINT})
}

/// Basic settings are top-level properties; everything else sits in one `advancedConfiguration` object, the way
/// MuleSoft's own CrowdStrike policy groups its settings.
const BASIC: [&str; 8] = [
    "airsApiKey", "airsEndpoint", "profile", "scanRequests", "scanResponses",
    "enforcementMode", "onApiError", "onScanError",
];

const UUID: &str = "0b6c0d2e-1111-2222-3333-444455556666";

fn set(v: &mut Value, field: &str, value: Value) {
    if BASIC.contains(&field) {
        v[field] = value;
    } else {
        if v.get("advancedConfiguration").is_none() {
            v["advancedConfiguration"] = json!({});
        }
        v["advancedConfiguration"][field] = value;
    }
}

fn with(field: &str, value: Value) -> Value {
    let mut v = minimal();
    set(&mut v, field, value);
    v
}

fn err(raw: &Value) -> ConfigError {
    Settings::from_json(raw).expect_err("config should be rejected")
}

#[test]
fn defaults_from_minimal_config() {
    let s = Settings::from_json(&minimal()).unwrap();
    assert_eq!(s.mode, Mode::Enforce);
    assert_eq!((s.on_api_error, s.on_scan_error), (OnError::Block, OnError::Block));
    assert_eq!((s.timeout_ms, s.retries, s.breaker_failures), (5000, 0, 0));
    assert_eq!(s.breaker_cooldown_s, 30);
    assert_eq!(s.max_scan_chars, 100_000, "every user turn is scanned, and Prisma AIRS takes 2 MB per scan");
    assert!(s.truncation_fail_closed && !s.masking && s.scan_requests && s.scan_responses);
    assert_eq!(s.app_name, "MuleSoft");
    assert_eq!(s.session_header, "x-session-id");
    assert_eq!(s.user_header, None);
    assert!(s.roles.contains(Role::User) && !s.roles.contains(Role::Tool));
    assert_eq!(s.profile, ProfileRef::Name("p".into()));
    assert_eq!(s.endpoint, ENDPOINT);
    assert!(!s.cache_enabled());
    assert!(!s.show_categories);
}

#[test]
fn rejects_missing_api_key() {
    let mut raw = minimal();
    raw.as_object_mut().unwrap().remove("airsApiKey");
    assert_eq!(err(&raw).field, "airsApiKey");
}

#[test]
fn rejects_blank_api_key() {
    assert_eq!(err(&with("airsApiKey", json!("  "))).field, "airsApiKey");
}

#[test]
fn rejects_no_profile() {
    let mut raw = minimal();
    raw.as_object_mut().unwrap().remove("profile");
    assert_eq!(err(&raw).field, "profile");
}

#[test]
fn rejects_blank_profile() {
    assert_eq!(err(&with("profile", json!("   "))).field, "profile");
    assert_eq!(err(&with("profile", json!(null))).field, "profile");
}

#[test]
fn a_uuid_is_sent_as_the_profile_id() {
    // One required field takes a name or an ID (owner, 8 Nov): Strata Cloud Manager's profile IDs are UUIDs.
    assert_eq!(Settings::from_json(&with("profile", json!(UUID))).unwrap().profile, ProfileRef::Id(UUID.into()));
    // Sent in lowercase, the form Strata Cloud Manager shows, whatever case it was typed in.
    let upper = UUID.to_uppercase();
    assert_eq!(Settings::from_json(&with("profile", json!(upper))).unwrap().profile, ProfileRef::Id(UUID.into()));
    let padded = format!("  {UUID} ");
    assert_eq!(Settings::from_json(&with("profile", json!(padded))).unwrap().profile, ProfileRef::Id(UUID.into()));
}

#[test]
fn anything_that_is_not_a_uuid_is_a_name() {
    for name in [
        "my-security-profile",
        "0b6c0d2e-1111-2222-3333-44445555666",   // one digit short
        "0b6c0d2e-1111-2222-3333-4444555566667", // one digit long
        "0b6c0d2e-1111-2222-3333-44445555666g",  // not hex
        "0b6c0d2e111122223333444455556666",      // no hyphens
        "0b6c0d2e-11112-222-3333-444455556666",  // hyphens in the wrong places
        "{0b6c0d2e-1111-2222-3333-444455556666}",
    ] {
        assert_eq!(Settings::from_json(&with("profile", json!(name))).unwrap().profile, ProfileRef::Name(name.into()), "{name}");
    }
}

#[test]
fn profile_map_unnamed_apps_get_the_profile() {
    let s = Settings::from_json(&with("profileMap", json!([{"clientName": "hr-bot", "profileName": "hr"}]))).unwrap();
    let map = s.profile_map.as_ref().unwrap();
    assert_eq!(map.entries, vec![("hr-bot".to_string(), "hr".to_string())]);
    assert_eq!(map.fallback, ProfileRef::Name("p".into()));
    assert_eq!(s.profile, ProfileRef::Name("p".into()));
}

#[test]
fn profile_map_fallback_can_be_an_id() {
    let mut raw = with("profile", json!(UUID));
    set(&mut raw, "profileMap", json!([{"clientName": "hr-bot", "profileName": "hr"}]));
    let s = Settings::from_json(&raw).unwrap();
    assert_eq!(s.profile_map.unwrap().fallback, ProfileRef::Id(UUID.into()));
}

#[test]
fn profile_map_still_needs_the_profile() {
    let mut raw = with("profileMap", json!([{"clientName": "hr-bot", "profileName": "hr"}]));
    raw.as_object_mut().unwrap().remove("profile");
    assert_eq!(err(&raw).field, "profile");
}

#[test]
fn rejects_malformed_profile_map() {
    assert_eq!(err(&with("profileMap", json!([{"clientName": "hr-bot"}]))).field, "profileMap");
}

#[test]
fn blank_app_name_suffix_means_none() {
    // The console may send "" for a field the operator left empty; the base name is never empty.
    assert_eq!(Settings::from_json(&with("appNameSuffix", json!(""))).unwrap().app_name, "MuleSoft");
    assert_eq!(Settings::from_json(&with("appNameSuffix", json!("   "))).unwrap().app_name, "MuleSoft");
}

#[test]
fn rejects_bad_app_name_suffix() {
    assert_eq!(err(&with("appNameSuffix", json!("HR\nBot"))).field, "appNameSuffix");
    assert_eq!(err(&with("appNameSuffix", json!("x".repeat(65)))).field, "appNameSuffix");
}

#[test]
fn null_and_blank_optional_fields_are_unset() {
    let mut raw = with("userHeader", json!(""));
    set(&mut raw, "sessionHeader", json!(null));
    let s = Settings::from_json(&raw).unwrap();
    assert_eq!(s.profile, ProfileRef::Name("p".into()));
    assert_eq!(s.user_header, None);
    assert_eq!(s.session_header, "x-session-id");
}

#[test]
fn header_names_are_lowercased_and_checked() {
    let s = Settings::from_json(&with("userHeader", json!("X-End-User"))).unwrap();
    assert_eq!(s.user_header.as_deref(), Some("x-end-user"));
    assert_eq!(err(&with("userHeader", json!("x end user"))).field, "userHeader");
    assert_eq!(err(&with("sessionHeader", json!("x:session"))).field, "sessionHeader");
}

#[test]
fn rejects_endpoint_with_scan_path() {
    let raw = with("airsEndpoint", json!(format!("{ENDPOINT}/v1/scan/sync/request")));
    assert_eq!(err(&raw).field, "airsEndpoint", "the policy appends the scan path itself");
}

#[test]
fn rejects_duplicate_profile_map_entries() {
    let raw = with("profileMap", json!([
        {"clientName": "hr-bot", "profileName": "hr"},
        {"clientName": "hr-bot", "profileName": "other"}
    ]));
    assert_eq!(err(&raw).field, "profileMap");
}

#[test]
fn endpoint_trailing_slash_is_dropped() {
    let s = Settings::from_json(&with("airsEndpoint", json!(format!("{ENDPOINT}/")))).unwrap();
    assert_eq!(s.endpoint, ENDPOINT);
}

#[test]
fn api_key_is_trimmed() {
    assert_eq!(Settings::from_json(&with("airsApiKey", json!(" k\n"))).unwrap().api_key, "k");
}

#[test]
fn debug_never_shows_the_key() {
    let s = Settings::from_json(&with("airsApiKey", json!("SECRET-123"))).unwrap();
    assert!(!format!("{s:?}").contains("SECRET-123"));
}

#[test]
fn app_name_with_suffix() {
    let s = Settings::from_json(&with("appNameSuffix", json!("HR-Chatbot"))).unwrap();
    assert_eq!(s.app_name, "MuleSoft-HR-Chatbot");
}

#[test]
fn rejects_timeout_out_of_range() {
    assert_eq!(err(&with("timeoutMs", json!(50))).field, "timeoutMs");
    assert_eq!(err(&with("timeoutMs", json!(60001))).field, "timeoutMs");
}

#[test]
fn rejects_http_endpoint() {
    assert_eq!(err(&with("airsEndpoint", json!("http://service.api.aisecurity.paloaltonetworks.com"))).field, "airsEndpoint");
}

#[test]
fn rejects_unknown_enum_values() {
    assert_eq!(err(&with("enforcementMode", json!("audit"))).field, "enforcementMode");
    assert_eq!(err(&with("onApiError", json!("ignore"))).field, "onApiError");
    assert_eq!(err(&with("scanMessageRoles", json!(["user", "robot"]))).field, "scanMessageRoles");
}

#[test]
fn advanced_fields_are_read_from_the_nested_object() {
    let s = Settings::from_json(&with("timeoutMs", json!(3000))).unwrap();
    assert_eq!(s.timeout_ms, 3000);
    let mut raw = minimal();
    raw["timeoutMs"] = json!(3000);
    assert_eq!(Settings::from_json(&raw).unwrap().timeout_ms, 5000, "a top-level advanced key is not the setting");
}

#[test]
fn rejects_advanced_configuration_that_is_not_an_object() {
    let mut raw = minimal();
    raw["advancedConfiguration"] = json!("x");
    assert_eq!(err(&raw).field, "advancedConfiguration");
}

#[test]
fn roles_always_include_user() {
    let s = Settings::from_json(&with("scanMessageRoles", json!(["tool"]))).unwrap();
    assert!(s.roles.contains(Role::User) && s.roles.contains(Role::Tool));
    assert!(!s.roles.contains(Role::System) && !s.roles.contains(Role::Assistant));
}

#[test]
fn cache_on_only_with_ttl_and_no_masking() {
    assert!(Settings::from_json(&with("verdictCacheTtlS", json!(60))).unwrap().cache_enabled());
    let mut raw = with("verdictCacheTtlS", json!(60));
    set(&mut raw, "applyDlpMasking", json!(true));
    assert!(!Settings::from_json(&raw).unwrap().cache_enabled());
}

#[test]
fn integers_may_arrive_as_whole_floats() {
    let s = Settings::from_json(&with("timeoutMs", json!(3000.0))).unwrap();
    assert_eq!(s.timeout_ms, 3000);
    assert_eq!(err(&with("timeoutMs", json!(3000.5))).field, "timeoutMs");
}

#[test]
fn config_error_never_contains_the_key() {
    let bad: [(&str, Value); 7] = [
        ("profile", json!("  ")),
        ("timeoutMs", json!(1)),
        ("enforcementMode", json!("x")),
        ("appNameSuffix", json!("HR\nBot")),
        ("scanMessageRoles", json!(["x"])),
        ("airsEndpoint", json!("http://x")),
        ("verdictCacheTtlS", json!(301)),
    ];
    for (field, value) in bad {
        let mut raw = with(field, value);
        raw["airsApiKey"] = json!("SECRET-123");
        let e = err(&raw);
        assert!(!e.to_string().contains("SECRET-123"), "{field}: {e}");
        assert!(e.to_string().starts_with(e.field), "{field}: {e}");
    }
}

// ---- MCP settings ------------------------------------------------------------------------------------------------

#[test]
fn mcp_defaults() {
    let s = Settings::from_json(&minimal()).unwrap();
    assert_eq!(s.mcp_server_name, None);
    assert_eq!(s.mcp_batch_limit, 8);
    assert!(!s.allow_open_streams);
}

#[test]
fn mcp_settings_are_read() {
    let mut v = minimal();
    set(&mut v, "mcpServerName", json!("deepwiki-test"));
    set(&mut v, "mcpBatchLimit", json!(3));
    set(&mut v, "allowOpenStreams", json!(true));
    let s = Settings::from_json(&v).unwrap();
    assert_eq!(s.mcp_server_name.as_deref(), Some("deepwiki-test"));
    assert_eq!(s.mcp_batch_limit, 3);
    assert!(s.allow_open_streams);
}

#[test]
fn mcp_batch_limit_bounds() {
    assert_eq!(err(&with("mcpBatchLimit", json!(0))).field, "mcpBatchLimit");
    assert_eq!(err(&with("mcpBatchLimit", json!(101))).field, "mcpBatchLimit");
    assert_eq!(Settings::from_json(&with("mcpBatchLimit", json!(100))).unwrap().mcp_batch_limit, 100);
    assert_eq!(err(&with("allowOpenStreams", json!("yes"))).field, "allowOpenStreams");
}

#[test]
fn mcp_server_name_rules() {
    assert_eq!(Settings::from_json(&with("mcpServerName", json!("   "))).unwrap().mcp_server_name, None, "blank is not set");
    assert_eq!(err(&with("mcpServerName", json!("x".repeat(65)))).field, "mcpServerName");
    assert_eq!(err(&with("mcpServerName", json!("tab\there"))).field, "mcpServerName");
    assert_eq!(Settings::from_json(&with("mcpServerName", json!("My MCP-1"))).unwrap().mcp_server_name.as_deref(), Some("My MCP-1"));
}

use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct ProfileMap0Config {
    #[serde(alias = "clientName")]
    pub client_name: String,
    #[serde(alias = "profileName")]
    pub profile_name: String,
}
#[derive(Deserialize, Clone, Debug)]
pub struct AdvancedConfigurationConfig {
    #[serde(alias = "allowOpenStreams")]
    pub allow_open_streams: Option<bool>,
    #[serde(alias = "appNameSuffix")]
    pub app_name_suffix: Option<String>,
    #[serde(alias = "applyDlpMasking")]
    pub apply_dlp_masking: Option<bool>,
    #[serde(alias = "breakerCooldownS")]
    pub breaker_cooldown_s: Option<i64>,
    #[serde(alias = "breakerFailures")]
    pub breaker_failures: Option<i64>,
    #[serde(alias = "maxScanChars")]
    pub max_scan_chars: Option<i64>,
    #[serde(alias = "mcpBatchLimit")]
    pub mcp_batch_limit: Option<i64>,
    #[serde(alias = "mcpServerName")]
    pub mcp_server_name: Option<String>,
    #[serde(alias = "profileMap")]
    pub profile_map: Option<Vec<ProfileMap0Config>>,
    #[serde(alias = "scanMessageRoles")]
    pub scan_message_roles: Option<Vec<String>>,
    #[serde(alias = "scanRetries")]
    pub scan_retries: Option<i64>,
    #[serde(alias = "sessionClaim")]
    pub session_claim: Option<String>,
    #[serde(alias = "sessionHeader")]
    pub session_header: Option<String>,
    #[serde(alias = "showCategories")]
    pub show_categories: Option<bool>,
    #[serde(alias = "timeoutMs")]
    pub timeout_ms: Option<i64>,
    #[serde(alias = "truncationFailClosed")]
    pub truncation_fail_closed: Option<bool>,
    #[serde(alias = "userClaim")]
    pub user_claim: Option<String>,
    #[serde(alias = "userHeader")]
    pub user_header: Option<String>,
    #[serde(alias = "verdictCacheTtlS")]
    pub verdict_cache_ttl_s: Option<i64>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "advancedConfiguration")]
    pub advanced_configuration: Option<AdvancedConfigurationConfig>,
    #[serde(alias = "airsApiKey")]
    pub airs_api_key: String,
    #[serde(
        alias = "airsEndpoint",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub airs_endpoint: pdk::hl::Service,
    #[serde(alias = "enforcementMode")]
    pub enforcement_mode: Option<String>,
    #[serde(alias = "onApiError")]
    pub on_api_error: Option<String>,
    #[serde(alias = "onScanError")]
    pub on_scan_error: Option<String>,
    #[serde(alias = "profile")]
    pub profile: String,
    #[serde(alias = "scanRequests")]
    pub scan_requests: Option<bool>,
    #[serde(alias = "scanResponses")]
    pub scan_responses: Option<bool>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    abi.service_create(config.airs_endpoint)?;
    abi.setup()?;
    Ok(())
}

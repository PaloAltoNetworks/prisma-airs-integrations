//! The policy's settings, read from the raw configuration the gateway hands to the policy.
//!
//! Basic settings are top-level properties; the rest sit in one `advancedConfiguration` object, the way MuleSoft's
//! own guardrail policies group them. Validation runs in a fixed order, so a broken configuration always reports the
//! same first error. An error names the setting and the reason, never a value: the configuration carries the AIRS
//! API key.
//!
//! `null`, an empty string and an all-blank string all mean "not set" for optional text, because a console may send
//! any of them for a field the operator left empty.

use std::collections::HashSet;
use std::fmt;

use serde_json::{Map, Value};

/// The US Prisma AIRS API host, the default endpoint.
pub const DEFAULT_ENDPOINT: &str = "https://service.api.aisecurity.paloaltonetworks.com";
/// The path the policy appends to the endpoint for every scan.
pub const SCAN_PATH: &str = "/v1/scan/sync/request";
/// `app_name` is this, or this plus `-<appNameSuffix>`.
pub const BASE_APP_NAME: &str = "MuleSoft";
const DEFAULT_SESSION_HEADER: &str = "x-session-id";
const ADVANCED: &str = "advancedConfiguration";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    Block,
    Allow,
}

/// Which AIRS security profile judges the traffic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProfileRef {
    Name(String),
    Id(String),
}

/// A conversation role whose messages can be scanned on the prompt leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    User,
    System,
    Assistant,
    Tool,
}

impl Role {
    pub const ALL: [Role; 4] = [Role::User, Role::System, Role::Assistant, Role::Tool];

    fn bit(self) -> u8 {
        match self {
            Role::User => 1,
            Role::System => 2,
            Role::Assistant => 4,
            Role::Tool => 8,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::System => "system",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }

    fn parse(text: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|role| role.name() == text)
    }
}

/// The roles scanned on the prompt leg. `user` is always a member.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RoleSet(u8);

impl RoleSet {
    pub fn user_only() -> RoleSet {
        RoleSet(Role::User.bit())
    }

    pub fn with(self, role: Role) -> RoleSet {
        RoleSet(self.0 | role.bit())
    }

    pub fn contains(&self, role: Role) -> bool {
        self.0 & role.bit() != 0
    }
}

impl fmt::Debug for RoleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(Role::ALL.into_iter().filter(|role| self.contains(*role)).map(Role::name)).finish()
    }
}

/// A security profile per calling client application, plus the profile for every application it does not name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileMap {
    /// `(client application name, profile name)`, in the configured order.
    pub entries: Vec<(String, String)>,
    pub fallback: String,
}

/// A setting that is missing or wrong. `field` is the setting's configuration name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub field: &'static str,
    pub reason: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ConfigError {}

/// Validated settings. `Debug` never shows the API key.
#[derive(Clone)]
pub struct Settings {
    pub api_key: String,
    /// The AIRS host as `https://host[:port]`, without a trailing slash; [`SCAN_PATH`] is appended per scan.
    pub endpoint: String,
    /// The profile used when nothing more specific applies: the static profile, or the map's fallback.
    pub profile: ProfileRef,
    pub profile_map: Option<ProfileMap>,
    pub scan_requests: bool,
    pub scan_responses: bool,
    pub mode: Mode,
    pub on_api_error: OnError,
    pub on_scan_error: OnError,
    pub timeout_ms: u32,
    pub retries: u8,
    pub breaker_failures: u32,
    pub breaker_cooldown_s: u32,
    pub roles: RoleSet,
    pub max_scan_chars: usize,
    pub truncation_fail_closed: bool,
    pub masking: bool,
    pub app_name: String,
    /// Lower-cased header name.
    pub user_header: Option<String>,
    pub user_claim: Option<String>,
    /// Lower-cased header name.
    pub session_header: String,
    pub session_claim: Option<String>,
    pub cache_ttl_s: u32,
    pub show_categories: bool,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("api_key", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("profile", &self.profile)
            .field("profile_map", &self.profile_map)
            .field("scan_requests", &self.scan_requests)
            .field("scan_responses", &self.scan_responses)
            .field("mode", &self.mode)
            .field("on_api_error", &self.on_api_error)
            .field("on_scan_error", &self.on_scan_error)
            .field("timeout_ms", &self.timeout_ms)
            .field("retries", &self.retries)
            .field("breaker_failures", &self.breaker_failures)
            .field("breaker_cooldown_s", &self.breaker_cooldown_s)
            .field("roles", &self.roles)
            .field("max_scan_chars", &self.max_scan_chars)
            .field("truncation_fail_closed", &self.truncation_fail_closed)
            .field("masking", &self.masking)
            .field("app_name", &self.app_name)
            .field("user_header", &self.user_header)
            .field("user_claim", &self.user_claim)
            .field("session_header", &self.session_header)
            .field("session_claim", &self.session_claim)
            .field("cache_ttl_s", &self.cache_ttl_s)
            .field("show_categories", &self.show_categories)
            .finish()
    }
}

impl Settings {
    /// Reads and validates the raw configuration.
    pub fn from_json(raw: &Value) -> Result<Settings, ConfigError> {
        let basic = raw.as_object().ok_or_else(|| fail("configuration", "must be a JSON object"))?;
        let advanced = match present(basic.get(ADVANCED)) {
            None => None,
            Some(Value::Object(map)) => Some(map),
            Some(_) => return Err(fail(ADVANCED, "must be an object")),
        };
        let basic = Some(basic);

        let api_key = text(basic, "airsApiKey")?.ok_or_else(|| fail("airsApiKey", "is required"))?;
        let endpoint = endpoint(text(basic, "airsEndpoint")?)?;
        let (profile, profile_map) = profiles(basic, advanced)?;

        let scan_requests = flag(basic, "scanRequests", true)?;
        let scan_responses = flag(basic, "scanResponses", true)?;
        let mode = match choice(basic, "enforcementMode", "enforce", &["enforce", "monitor"])? {
            "monitor" => Mode::Monitor,
            _ => Mode::Enforce,
        };
        let on_api_error = on_error(basic, "onApiError")?;
        let on_scan_error = on_error(basic, "onScanError")?;

        let timeout_ms = whole(advanced, "timeoutMs", 5000, 100, 60_000)? as u32;
        let retries = whole(advanced, "scanRetries", 0, 0, 3)? as u8;
        let breaker_failures = whole(advanced, "breakerFailures", 0, 0, 100)? as u32;
        let breaker_cooldown_s = whole(advanced, "breakerCooldownS", 30, 1, 3600)? as u32;
        let roles = roles(advanced)?;
        let max_scan_chars = whole(advanced, "maxScanChars", 20_000, 1, 1_000_000)? as usize;
        let truncation_fail_closed = flag(advanced, "truncationFailClosed", true)?;
        let masking = flag(advanced, "applyDlpMasking", false)?;
        let app_name = app_name(text(advanced, "appNameSuffix")?)?;
        let user_header = header_name(advanced, "userHeader")?;
        let user_claim = claim(advanced, "userClaim")?;
        let session_header = header_name(advanced, "sessionHeader")?.unwrap_or_else(|| DEFAULT_SESSION_HEADER.into());
        let session_claim = claim(advanced, "sessionClaim")?;
        let cache_ttl_s = whole(advanced, "verdictCacheTtlS", 0, 0, 300)? as u32;
        let show_categories = flag(advanced, "showCategories", false)?;

        Ok(Settings {
            api_key,
            endpoint,
            profile,
            profile_map,
            scan_requests,
            scan_responses,
            mode,
            on_api_error,
            on_scan_error,
            timeout_ms,
            retries,
            breaker_failures,
            breaker_cooldown_s,
            roles,
            max_scan_chars,
            truncation_fail_closed,
            masking,
            app_name,
            user_header,
            user_claim,
            session_header,
            session_claim,
            cache_ttl_s,
            show_categories,
        })
    }

    /// The verdict cache runs only with a TTL and never with masking, because a cached allow would skip the masked
    /// text AIRS returns.
    pub fn cache_enabled(&self) -> bool {
        self.cache_ttl_s > 0 && !self.masking
    }
}

type Obj<'a> = Option<&'a Map<String, Value>>;

fn fail(field: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError { field, reason: reason.into() }
}

fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|v| !v.is_null())
}

/// Optional text: trimmed, with blank meaning unset.
fn text(obj: Obj<'_>, field: &'static str) -> Result<Option<String>, ConfigError> {
    match present(obj.and_then(|o| o.get(field))) {
        None => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Some(_) => Err(fail(field, "must be text")),
    }
}

fn flag(obj: Obj<'_>, field: &'static str, default: bool) -> Result<bool, ConfigError> {
    match present(obj.and_then(|o| o.get(field))) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(fail(field, "must be true or false")),
    }
}

/// A whole number in `min..=max`. A float with no fractional part counts, because some API clients send `3000.0`.
fn whole(obj: Obj<'_>, field: &'static str, default: u64, min: u64, max: u64) -> Result<u64, ConfigError> {
    let range = || fail(field, format!("must be a whole number from {min} to {max}"));
    match present(obj.and_then(|o| o.get(field))) {
        None => Ok(default),
        Some(Value::Number(n)) => {
            let value = match n.as_u64() {
                Some(v) => v,
                None => match n.as_f64() {
                    Some(f) if f.fract() == 0.0 && f >= 0.0 && f <= max as f64 => f as u64,
                    _ => return Err(range()),
                },
            };
            if (min..=max).contains(&value) {
                Ok(value)
            } else {
                Err(range())
            }
        }
        Some(_) => Err(range()),
    }
}

fn choice(obj: Obj<'_>, field: &'static str, default: &'static str, options: &[&'static str]) -> Result<&'static str, ConfigError> {
    match text(obj, field)? {
        None => Ok(default),
        Some(value) => options
            .iter()
            .copied()
            .find(|option| *option == value)
            .ok_or_else(|| fail(field, format!("must be one of: {}", options.join(", ")))),
    }
}

fn on_error(obj: Obj<'_>, field: &'static str) -> Result<OnError, ConfigError> {
    Ok(match choice(obj, field, "block", &["block", "allow"])? {
        "allow" => OnError::Allow,
        _ => OnError::Block,
    })
}

fn endpoint(value: Option<String>) -> Result<String, ConfigError> {
    let url = value.unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    let bad = || fail("airsEndpoint", "must be an https:// URL of the Prisma AIRS API host");
    let rest = url.strip_prefix("https://").ok_or_else(bad)?;
    if rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad());
    }
    let trimmed = url.trim_end_matches('/');
    let host = trimmed.trim_start_matches("https://").split('/').next().unwrap_or("");
    if host.is_empty() {
        return Err(bad());
    }
    if trimmed.ends_with(SCAN_PATH) {
        return Err(fail("airsEndpoint", format!("must be the host only; the policy adds {SCAN_PATH}")));
    }
    Ok(trimmed.to_string())
}

fn profiles(basic: Obj<'_>, advanced: Obj<'_>) -> Result<(ProfileRef, Option<ProfileMap>), ConfigError> {
    let name = text(basic, "profileName")?;
    let id = text(basic, "profileId")?;
    let entries = profile_map_entries(advanced)?;
    let fallback = text(advanced, "fallbackProfileName")?;

    if !entries.is_empty() {
        let fallback = fallback.ok_or_else(|| fail("fallbackProfileName", "is required when profileMap names client applications"))?;
        let unused = "is not used when profileMap is set; applications the map does not name get fallbackProfileName";
        if name.is_some() {
            return Err(fail("profileName", unused));
        }
        if id.is_some() {
            return Err(fail("profileId", unused));
        }
        return Ok((ProfileRef::Name(fallback.clone()), Some(ProfileMap { entries, fallback })));
    }
    if fallback.is_some() {
        return Err(fail("fallbackProfileName", "is only used with profileMap"));
    }
    match (name, id) {
        (None, None) => Err(fail("profileName", "set profileName or profileId")),
        (Some(_), Some(_)) => Err(fail("profileId", "set profileName or profileId, not both")),
        (Some(name), None) => Ok((ProfileRef::Name(name), None)),
        (None, Some(id)) => Ok((ProfileRef::Id(id), None)),
    }
}

fn profile_map_entries(advanced: Obj<'_>) -> Result<Vec<(String, String)>, ConfigError> {
    let shape = || fail("profileMap", "each entry needs a clientName and a profileName");
    let items = match present(advanced.and_then(|o| o.get("profileMap"))) {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(fail("profileMap", "must be a list")),
    };
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let obj = item.as_object().ok_or_else(shape)?;
        let client = text(Some(obj), "clientName").map_err(|_| shape())?.ok_or_else(shape)?;
        let profile = text(Some(obj), "profileName").map_err(|_| shape())?.ok_or_else(shape)?;
        if !seen.insert(client.clone()) {
            return Err(fail("profileMap", "a client application is named twice"));
        }
        entries.push((client, profile));
    }
    Ok(entries)
}

fn roles(advanced: Obj<'_>) -> Result<RoleSet, ConfigError> {
    let bad = || fail("scanMessageRoles", "each role must be one of: user, system, assistant, tool");
    let mut set = RoleSet::user_only();
    match present(advanced.and_then(|o| o.get("scanMessageRoles"))) {
        None => {}
        Some(Value::Array(items)) => {
            for item in items {
                let role = item.as_str().map(str::trim).and_then(Role::parse).ok_or_else(bad)?;
                set = set.with(role);
            }
        }
        Some(_) => return Err(bad()),
    }
    Ok(set)
}

fn app_name(suffix: Option<String>) -> Result<String, ConfigError> {
    match suffix {
        None => Ok(BASE_APP_NAME.to_string()),
        Some(s) if s.len() <= 64 && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') => Ok(format!("{BASE_APP_NAME}-{s}")),
        Some(_) => Err(fail("appNameSuffix", "must be 1 to 64 printable ASCII characters")),
    }
}

/// An HTTP header name (RFC 9110 token characters), lower-cased.
fn header_name(obj: Obj<'_>, field: &'static str) -> Result<Option<String>, ConfigError> {
    let Some(name) = text(obj, field)? else { return Ok(None) };
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if name.len() <= 128 && name.chars().all(token) {
        Ok(Some(name.to_ascii_lowercase()))
    } else {
        Err(fail(field, "must be an HTTP header name"))
    }
}

fn claim(obj: Obj<'_>, field: &'static str) -> Result<Option<String>, ConfigError> {
    let Some(name) = text(obj, field)? else { return Ok(None) };
    if name.len() <= 128 && name.chars().all(|c| c.is_ascii_graphic()) {
        Ok(Some(name))
    } else {
        Err(fail(field, "must be a claim name of up to 128 printable ASCII characters"))
    }
}

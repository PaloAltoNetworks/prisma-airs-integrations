//! Prisma AIRS Guardrails: a MuleSoft Omni Gateway policy that scans Model Proxy and MCP server traffic with Prisma
//! AIRS.
//!
//! The scanning logic lives in the `prisma-airs-core` crate; this crate wires it to the PDK. The request filter holds
//! the request (stop iteration) until AIRS has judged the prompt, and the response filter holds the reply, streamed or
//! not, until AIRS has judged it.
//!
//! A configuration the policy cannot use never loads as a working policy: every request is then refused, with 503,
//! or with JSON-RPC error -32003 when the body is an MCP message.
mod filter;
// The generated configuration is parsed for the AIRS service only; Settings validates everything else.
#[allow(dead_code)]
mod generated;
mod mcp;
mod scan;

use std::cell::RefCell;

use anyhow::Result;
use pdk::hl::*;
use pdk::logger;
use pdk::metadata::Metadata;
use pdk::policy_violation::PolicyViolations;
use prisma_airs_core::breaker::Breaker;
use prisma_airs_core::cache::VerdictCache;
use prisma_airs_core::settings::Settings;

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One per gateway worker, shared by every request that worker serves.
pub(crate) struct Shared {
    pub settings: Settings,
    pub service: Service,
    pub breaker: RefCell<Breaker>,
    pub cache: RefCell<VerdictCache>,
    pub violations: PolicyViolations,
    /// The `server_name` of MCP tool events: mcpServerName, else this API instance's name, else the application name.
    pub server_name: String,
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    violations: PolicyViolations,
    metadata: Metadata,
) -> Result<()> {
    // The raw configuration holds the AIRS API key, so neither it nor a parser's error text (which can quote a value)
    // is ever logged.
    match load(&bytes) {
        Ok((settings, service)) => {
            logger::info!(
                "prisma-airs-guardrails {VERSION}: settings accepted (mode {:?}, prompts {}, responses {}, timeout {} ms)",
                settings.mode,
                settings.scan_requests,
                settings.scan_responses,
                settings.timeout_ms
            );
            let server_name = server_name(&settings, &metadata);
            let shared = Shared {
                breaker: RefCell::new(Breaker::new(settings.breaker_failures, settings.breaker_cooldown_s as u64 * 1000)),
                cache: RefCell::new(VerdictCache::new(settings.cache_ttl_s as u64 * 1000, 1024)),
                settings,
                service,
                violations,
                server_name,
            };
            let filter = on_request(|rs, client, auth| filter::request(rs, client, auth, &shared))
                .on_response(|rs, data, client| filter::response(rs, data, client, &shared));
            launcher.launch(filter).await?;
        }
        Err(reason) => {
            logger::error!("prisma-airs-guardrails {VERSION}: {reason}; every request is refused (503, or -32003 on MCP)");
            launcher.launch(on_request(filter::refuse)).await?;
        }
    }
    Ok(())
}

fn load(bytes: &[u8]) -> Result<(Settings, Service), String> {
    let raw: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "the configuration is not JSON".to_string())?;
    let settings = Settings::from_json(&raw).map_err(|err| format!("settings rejected: {err}"))?;
    let config: generated::config::Config = serde_json::from_value(raw)
        .map_err(|_| "the configuration does not match the policy definition".to_string())?;
    Ok((settings, config.airs_endpoint))
}

/// The MCP server name tool events carry: the configured one, else the API instance's name (printable ASCII, at most 64
/// characters), else the application name.
fn server_name(settings: &Settings, metadata: &Metadata) -> String {
    let api_name: Option<String> = metadata
        .api_metadata
        .name
        .as_deref()
        .map(|n| n.trim().chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(64).collect::<String>())
        .filter(|n| !n.is_empty());
    settings.mcp_server_name.clone().or(api_name).unwrap_or_else(|| settings.app_name.clone())
}

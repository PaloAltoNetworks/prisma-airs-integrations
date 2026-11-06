//! Prisma AIRS Guardrails: a MuleSoft Omni Gateway policy that scans Model Proxy traffic with Prisma AIRS.
//!
//! Until the scanning filters are wired in, the policy validates its settings and refuses every request with 503,
//! so a build of this stage can never let traffic through unscanned.
mod generated;

use anyhow::Result;
use pdk::hl::*;
use pdk::logger;
use prisma_airs_core::settings::Settings;

const UNAVAILABLE_BODY: &str = r#"{"error":{"message":"Prisma AIRS could not scan this request, so it was not forwarded.","type":"prisma_airs_unavailable","param":null,"code":"prisma_airs_unavailable"}}"#;

async fn refuse(_request: RequestState) -> Flow<()> {
    Flow::Break(
        Response::new(503)
            .with_headers(vec![("content-type".to_string(), "application/json".to_string())])
            .with_body(UNAVAILABLE_BODY),
    )
}

#[entrypoint]
async fn configure(launcher: Launcher, Configuration(bytes): Configuration) -> Result<()> {
    // The raw configuration holds the AIRS API key, so it is never logged or put into an error.
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(raw) => match Settings::from_json(&raw) {
            Ok(settings) => logger::info!("prisma-airs-guardrails: settings accepted, mode {:?}", settings.mode),
            Err(err) => logger::error!("prisma-airs-guardrails: settings rejected: {err}"),
        },
        Err(_) => logger::error!("prisma-airs-guardrails: the configuration is not JSON"),
    }
    launcher.launch(on_request(refuse)).await?;
    Ok(())
}

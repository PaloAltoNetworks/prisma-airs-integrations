//! Who is calling and in which conversation, for the scan's `app_user`, `session_id` and profile.
//!
//! On Model Proxy the authenticated client application is the calling program, which Client ID Enforcement always
//! supplies, not the person. So a verified token claim and a configured user header come first, and the client
//! application only identifies the caller when nothing names the end user.

use crate::airs::checked_id;
use crate::settings::{ProfileRef, Settings};

/// The first usable value of: verified claim, user header, client application name, client application id; else
/// `anonymous`. An unusable value (too long, not printable ASCII) is skipped.
pub fn app_user(claim: Option<&str>, header: Option<&str>, client_name: Option<&str>, client_id: Option<&str>) -> String {
    [claim, header, client_name, client_id]
        .into_iter()
        .flatten()
        .find_map(|value| checked_id(value).ok().flatten())
        .unwrap_or_else(|| "anonymous".to_string())
}

/// The conversation id from the session header, else the verified claim. An unusable value is dropped and the
/// first drop's reason is returned; a missing session is left out, never invented.
pub fn session_id(header: Option<&str>, claim: Option<&str>) -> (Option<String>, Option<&'static str>) {
    let mut dropped = None;
    for value in [header, claim].into_iter().flatten() {
        match checked_id(value) {
            Ok(Some(id)) => return (Some(id), dropped),
            Ok(None) => {}
            Err(reason) => {
                dropped.get_or_insert(reason);
            }
        }
    }
    (None, dropped)
}

/// The profile for this caller: the profile map's entry for the client application's exact name, else the map's
/// fallback; without a map, the configured profile.
pub fn profile(settings: &Settings, client_name: Option<&str>) -> ProfileRef {
    match &settings.profile_map {
        Some(map) => client_name
            .and_then(|name| map.entries.iter().find(|(client, _)| client == name))
            .map(|(_, profile)| ProfileRef::Name(profile.clone()))
            .unwrap_or_else(|| ProfileRef::Name(map.fallback.clone())),
        None => settings.profile.clone(),
    }
}

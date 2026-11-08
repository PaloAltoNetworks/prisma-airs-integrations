/*
 * init-config.js — Phase 1: resolve configuration.
 *
 * Reads caller-supplied flow variables (set by the proxy before the
 * FlowCallout, the Apigee analog of APIM's <set-variable> before
 * <include-fragment>) and the FlowCallout `type` parameter, applies defaults,
 * and publishes a normalised airs.cfg.* namespace the rest of the flow reads.
 *
 * KVM-GetAIRSConfig has already populated airs.token and airs.profile from the
 * encrypted `airs-config` map; those are the fallbacks here.
 *
 * Caller-overridable flow variables (all optional):
 *   scanType | type ......... "prompt" | "response" | "both"  (phase)
 *   currentProfile .......... AIRS profile for LLM/Gemini scans
 *   toolProfile ............. AIRS profile for MCP tool events (default: currentProfile)
 *   prismaAirsEndpoint ...... AIRS host (default: US tenant)
 *   scanTools ............... "true"/"false" — fold tool results into scans (default true)
 *   failOpen ................ "true"/"false" — allow on AIRS failure (default false)
 *   appName ................. application label (default "Gateway")
 *   agentId / agentVersion .. optional agent identifiers for metadata
 *   airsDescriptions ........ JSON string of custom threat descriptions (merged over defaults)
 */

function cfg(name, dflt) {
    var v = context.getVariable(name);
    if (v === null || v === undefined || v === '') { return dflt; }
    return v;
}

/* ---- phase --------------------------------------------------------------- *
 * Two ways to express the phase, in priority order:
 *   1. FlowCallout parameter `type` ("user-prompt" | "response-prompt" | "both")
 *      — the V1 house convention, set on the FC policy in each proxy flow.
 *   2. scanType flow variable ("prompt" | "response" | "both") — APIM parity.
 * They normalise to airs.cfg.phase = "prompt" | "response" | "both".
 */
var typeParam = cfg('type', '');            // FlowCallout <Parameter name="type">
var scanType  = cfg('scanType', '');        // APIM-style variable
var phase;
if (typeParam === 'response-prompt' || scanType === 'response') { phase = 'response'; }
else if (typeParam === 'both' || scanType === 'both')           { phase = 'both'; }
else                                                            { phase = 'prompt'; }
context.setVariable('airs.cfg.phase', phase);

/* ---- profiles ------------------------------------------------------------ */
var kvmProfile = cfg('airs.profile', 'example-profile');      // from KVM
var profile    = cfg('currentProfile', kvmProfile);
context.setVariable('airs.cfg.profile', profile);
context.setVariable('airs.cfg.toolProfile', cfg('toolProfile', profile));

/* ---- endpoint (region) --------------------------------------------------- *
 * US:  service.api.aisecurity.paloaltonetworks.com          (default)
 * EU:  service-de.api.aisecurity.paloaltonetworks.com
 * IN/SG/JP/AU: service-in|sg|jp|au.api.aisecurity.paloaltonetworks.com
 */
context.setVariable('airs.cfg.endpoint',
    cfg('prismaAirsEndpoint', 'service.api.aisecurity.paloaltonetworks.com'));

/* ---- booleans (accept real bool or "true"/"false" string) ---------------- */
context.setVariable('airs.cfg.scanTools', airsTruthy(cfg('scanTools', true)) ? 'true' : 'false');
context.setVariable('airs.cfg.failOpen',  airsTruthy(cfg('failOpen', false)) ? 'true' : 'false');
// forceClaudeCode: treat all traffic as Claude Code even without the x-claude-code-*
// headers (Claude Code on Vertex does NOT send them). Enables <system-reminder>
// stripping + background-call skipping. Only for a proxy DEDICATED to fronting
// Claude Code — a general-purpose proxy must NOT set this, or an attacker could hide
// a payload inside a fake <system-reminder> and have it skipped.
context.setVariable('airs.cfg.forceCC', airsTruthy(cfg('forceClaudeCode', false)) ? 'true' : 'false');
// Security posture for requests we cannot classify (apiType == unknown). Default
// off = APIM behaviour (pass unscanned); on = refuse (403) rather than let
// unrecognised traffic through unscanned.
context.setVariable('airs.cfg.failClosedOnUnknown', airsTruthy(cfg('failClosedOnUnknown', false)) ? 'true' : 'false');
// Block HTTP status: "native" = return the caller's own 200-shaped envelope
// (default, SDK-friendly); a numeric string (e.g. "403") forces a hard status
// on non-streaming blocks so blocks are visible in status-code metrics.
context.setVariable('airs.cfg.blockStatus', cfg('blockStatus', 'native'));

/* ---- labels & agent metadata --------------------------------------------- */
context.setVariable('airs.cfg.appName', cfg('appName', 'Gateway'));

// agentId: explicit var → X-Agent-ID header → Claude Code subagent header.
var agentId = cfg('agentId', '');
if (airsIsBlank(agentId)) { agentId = airsHeader('X-Agent-ID'); }
if (airsIsBlank(agentId)) { agentId = airsHeader('x-claude-code-agent-id'); }
context.setVariable('airs.cfg.agentId', agentId || '');
context.setVariable('airs.cfg.agentVersion', cfg('agentVersion', '') || '');

/* ---- threat descriptions (defaults + optional override) ------------------ *
 * Used to turn per-detector booleans into human-readable block messages.
 */
var descriptions = {
    url_cats:        'Malicious or inappropriate URLs detected',
    dlp:             'Sensitive data (PII, credentials, secrets) detected',
    injection:       'Prompt injection or jailbreak attempt detected',
    toxic_content:   'Toxic, hateful, or inappropriate content detected',
    malicious_code:  'Malicious code or command injection detected',
    agent:           'AI agent manipulation attempt detected',
    topic_violation: 'Content violates topic policies',
    db_security:     'Database security violation detected',
    ungrounded:      'Ungrounded or hallucinated content detected'
};
var custom = airsParse(cfg('airsDescriptions', ''));
if (custom) {
    for (var k in custom) {
        if (Object.prototype.hasOwnProperty.call(custom, k)) { descriptions[k] = custom[k]; }
    }
}
context.setVariable('airs.cfg.descriptions', airsStringify(descriptions));

/* ---- key-presence guard -------------------------------------------------- *
 * KVM-GetAIRSConfig populated airs.token from the encrypted map. If it is
 * missing the flow surfaces a config error in fail-closed mode (RF-ConfigError);
 * in fail-open mode we proceed and the scan simply fails open downstream.
 */
context.setVariable('airs.cfg.keyMissing', airsIsBlank(cfg('airs.token', '')) ? 'true' : 'false');

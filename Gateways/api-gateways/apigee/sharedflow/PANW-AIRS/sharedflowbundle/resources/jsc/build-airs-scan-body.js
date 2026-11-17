/*
 * build-airs-scan-body.js — Phase 4b: assemble the AIRS sync/request body.
 *
 * Combines the extracted content (airs.promptText / responseText / toolEvent)
 * with config + identifiers into the JSON AIRS expects, then stores it as a
 * string (airsScanRequestBody) that AM-SetAIRSScanRequest drops into the
 * ServiceCallout payload verbatim. JSON.stringify handles all escaping.
 *
 * transaction_id is the per-request id the deployed AIRS API reads and echoes
 * back (parsed by EV-ParseAIRSVerdict). session_id groups a conversation and is
 * echoed back verbatim.
 */

var apiType = context.getVariable('airs.apiType');
var phase   = context.getVariable('airs.cfg.phase');

/* ---- app_user ------------------------------------------------------------ *
 * x-user-id header → Claude Code body metadata.user_id (account_uuid/device_id)
 * → "anonymous".
 */
function resolveAppUser() {
    var h = airsHeader('x-user-id');
    if (!airsIsBlank(h)) { return h; }
    var reqBody = airsParse(context.getVariable('request.content'));
    if (reqBody && reqBody.metadata && reqBody.metadata.user_id) {
        var uid = airsParse(reqBody.metadata.user_id);   // JSON-encoded string
        if (uid) { return String(uid.account_uuid || uid.device_id || reqBody.metadata.user_id); }
        return String(reqBody.metadata.user_id);
    }
    return 'anonymous';
}

/* ---- metadata (house rule: app_name = <VENDOR>-<CUSTOMER_APP>) ------------ */
var metadata = {
    app_name: 'Apigee-' + context.getVariable('airs.cfg.appName'),
    user_ip: context.getVariable('client.ip') || '',
    ai_model: context.getVariable('airs.model') || 'unknown',
    app_user: resolveAppUser()
};
var agentId = context.getVariable('airs.cfg.agentId');
var agentVersion = context.getVariable('airs.cfg.agentVersion');
if (!airsIsBlank(agentId) || !airsIsBlank(agentVersion)) {
    var am = {};
    if (!airsIsBlank(agentId)) { am.agent_id = agentId; }
    if (!airsIsBlank(agentVersion)) { am.agent_version = agentVersion; }
    metadata.agent_meta = am;
}

/* ---- contents ------------------------------------------------------------ */
var contents = [];
if (apiType === 'mcp') {
    var te = airsParse(context.getVariable('airs.toolEvent'));
    if (te) { contents.push({ tool_event: te }); }
} else {
    var promptText = context.getVariable('airs.promptText') || '';
    var responseText = context.getVariable('airs.responseText') || '';
    if (phase === 'both') {
        var c = {};
        if (promptText.length) { c.prompt = promptText; }
        if (responseText.length) { c.response = responseText; }
        if (c.prompt || c.response) { contents.push(c); }
    } else if (phase === 'response') {
        if (responseText.length) { contents.push({ response: responseText }); }
    } else {
        if (promptText.length) { contents.push({ prompt: promptText }); }
    }
}

/* ---- profile: tool events scan against toolProfile ----------------------- */
var profile = (apiType === 'mcp')
    ? context.getVariable('airs.cfg.toolProfile')
    : context.getVariable('airs.cfg.profile');

// AIRS correlation identifiers. PROVEN LIVE (Apigee debug trace, 2026-07-03): the
// deployed AIRS API reads the client transaction id from `transaction_id` and echoes
// it straight back. The `tr_id` field the aisecurity-python-sdk documents is NOT
// honored by the live API — a scan sent with only tr_id came back with a server-minted
// `pan_`-prefixed transaction_id, whereas sending `transaction_id` makes AIRS adopt our
// value. (The SDK lags the deployed API: its ScanResponse doesn't even model
// transaction_id.) session_id groups a conversation and is echoed back verbatim.
var body = {
    transaction_id: context.getVariable('airs.txnId') || '',
    session_id: context.getVariable('airs.sessionId') || '',
    ai_profile: { profile_name: profile || '' },
    metadata: metadata,
    contents: contents
};

context.setVariable('airsScanRequestBody', JSON.stringify(body));
// Republish content-presence for the flow's skip condition (contents may be
// empty even when hasContent was true, e.g. a tool_event that failed to parse).
context.setVariable('airs.contentCount', String(contents.length));

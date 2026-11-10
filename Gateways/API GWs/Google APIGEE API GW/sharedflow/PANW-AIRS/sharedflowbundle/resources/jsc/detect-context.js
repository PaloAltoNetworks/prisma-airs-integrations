/*
 * detect-context.js — Phase 2+3: request context, gating, identifiers.
 *
 * Publishes:
 *   airs.apiType     "llm" | "gemini" | "mcp" | "unknown"
 *   airs.isCC        "true"/"false"  — request came from Claude Code
 *   airs.shouldScan  "true"/"false"  — run the scan for this phase/type
 *   airs.sessionId   conversation-tracking id
 *   airs.txnId       per-request transaction id (wire field: transaction_id)
 *
 * Phase comes from airs.cfg.phase ("prompt" | "response" | "both"); the proxy
 * calls this SharedFlow in the request flow for "prompt" and the response flow
 * for "response"/"both", so the phase already encodes the leg.
 */

var phase   = context.getVariable('airs.cfg.phase');
var reqRaw  = context.getVariable('request.content');
var reqBody = airsParse(reqRaw);

/* ---- API type ------------------------------------------------------------ */
function detectApiType() {
    var verb = context.getVariable('request.verb');
    if (verb && String(verb).toUpperCase() !== 'POST') { return 'unknown'; }

    // MCP is identified by the JSON-RPC method, regardless of path.
    if (reqBody && reqBody.method && String(reqBody.method) === 'tools/call') { return 'mcp'; }

    var path = context.getVariable('proxy.pathsuffix');
    if (airsIsBlank(path)) { path = context.getVariable('request.uri') || ''; }
    path = String(path).toLowerCase();

    if (path.indexOf('generatecontent') !== -1 || path.indexOf('streamgeneratecontent') !== -1) {
        return 'gemini';
    }
    if (/\/chat\/completions$/.test(path) || /\/responses$/.test(path) ||
        /\/v1\/messages$/.test(path) || path.indexOf('/anthropic/v1/messages') !== -1) {
        return 'llm';
    }
    // Vertex / GCP Agent-Platform partner-model endpoints. Claude on Vertex is
    // invoked via :rawPredict / :streamRawPredict on a publishers/anthropic model:
    // the model is in the URL and the body is the Anthropic Messages shape, so it
    // scans through the same "llm" path. count-tokens:rawPredict is a pure utility
    // (no generation; its content is scanned on the real turn) — leave it
    // unclassified so it passes through untouched instead of double-scanning.
    if (path.indexOf('count-tokens') !== -1) { return 'unknown'; }
    if ((path.indexOf(':rawpredict') !== -1 || path.indexOf(':streamrawpredict') !== -1) &&
        path.indexOf('/anthropic/') !== -1) {
        return 'llm';
    }
    return 'unknown';
}
var apiType = detectApiType();
context.setVariable('airs.apiType', apiType);

/* ---- Claude Code detection ----------------------------------------------- */
var isCC = false;
if (!airsIsBlank(airsHeader('x-claude-code-session-id'))) { isCC = true; }
else if (airsHeader('x-app') === 'cli') { isCC = true; }
// Claude Code on Vertex (:rawPredict) does NOT send the x-claude-code-* headers, so
// the sniff above misses and its own <system-reminder> scaffolding gets scanned as
// user input (tripping the injection detector). A Claude-Code-dedicated proxy sets
// forceClaudeCode=true so we still apply CC handling (strip reminders, skip bg calls).
else if (context.getVariable('airs.cfg.forceCC') === 'true') { isCC = true; }
context.setVariable('airs.isCC', isCC ? 'true' : 'false');

/* ---- Claude Code background-call skip ------------------------------------ *
 * Real agent turns carry the full tool set AND a large max_tokens (32000).
 * Background utility calls (title / recap / suggestion) are toolless and/or
 * tiny completions derived from already-scanned content — skipping them keeps
 * AIRS focused on genuine user input. Marker check is on the LAST user message
 * (never a tool_result) so poisoned tool output can't fake a skip. Benign
 * failure: if the marker is renamed, the call is simply scanned again.
 */
function isClaudeCodeBackground() {
    if (!reqBody) { return false; }
    var tools = reqBody.tools;
    var toolCount = (tools && tools.length) ? tools.length : 0;
    var maxTokens = reqBody.max_tokens ? Number(reqBody.max_tokens) : 0;
    if (toolCount === 0 || (maxTokens > 0 && maxTokens <= 4096)) { return true; }

    var msgs = reqBody.messages;
    if (msgs && msgs.length) {
        for (var j = msgs.length - 1; j >= 0; j--) {
            var m = msgs[j];
            if (m && m.role === 'user') {
                var text = '';
                var c = m.content;
                if (typeof c === 'string') { text = c; }
                else if (c && Object.prototype.toString.call(c) === '[object Array]') {
                    for (var b = 0; b < c.length; b++) {
                        if (c[b] && c[b].type === 'text') { text += (c[b].text || ''); }
                    }
                }
                if (text.indexOf('[SUGGESTION MODE:') !== -1) { return true; }
                break;
            }
        }
    }
    return false;
}

/* ---- shouldScan ---------------------------------------------------------- */
function computeShouldScan() {
    if (apiType === 'unknown') { return false; }
    if (isCC && isClaudeCodeBackground()) { return false; }

    if (phase === 'prompt') {
        // Request leg — scan the user prompt, or (MCP) the tool INPUT before the
        // tool server executes it. Scanning MCP input pre-execution is an
        // improvement over the APIM fragment, which scans MCP only afterwards on
        // the response leg (input+output together). A proxy that also includes
        // the flow on its response leg still gets the input+output scan.
        return true;
    }
    // response / both — response leg: only scan successful (2xx) responses.
    var code = Number(context.getVariable('response.status.code') || 0);
    if (code < 200 || code >= 300) { return false; }
    if (phase === 'both' && apiType === 'mcp') { return false; }  // MCP has no "both"
    return true;
}
var shouldScan = computeShouldScan();
context.setVariable('airs.shouldScan', shouldScan ? 'true' : 'false');

/* ---- fail-closed on unclassified traffic --------------------------------- *
 * apiType == unknown means we can't classify the payload to scan it. Default
 * behaviour (APIM parity) is to pass it through unscanned. With
 * failClosedOnUnknown=true we refuse it instead (a hard 403) so unrecognised
 * shapes can't bypass the gateway. Sets outcome=block; RF-Block returns it.
 */
if (apiType === 'unknown' && context.getVariable('airs.cfg.failClosedOnUnknown') === 'true') {
    context.setVariable('airs.outcome', 'block');
    context.setVariable('airs.block.body', JSON.stringify({ error: '🛡️ PRISMA AIRS SECURITY ALERT: request could not be classified for scanning and was blocked (failClosedOnUnknown).' }));
    context.setVariable('airs.block.status', '403');
    context.setVariable('airs.block.ctype', 'application/json');
    context.setVariable('airs.block.reason', 'Forbidden');
    context.setVariable('airs.block.category', 'unclassified');
}

/* ---- session id ---------------------------------------------------------- */
function computeSessionId() {
    var h;
    h = airsHeader('x-claude-code-session-id'); if (!airsIsBlank(h)) { return h; }
    h = airsHeader('x-session-id');             if (!airsIsBlank(h)) { return h; }
    if (apiType === 'mcp') { h = airsHeader('Mcp-Session-Id'); if (!airsIsBlank(h)) { return h; } }

    if (reqBody && reqBody.previous_response_id) { return String(reqBody.previous_response_id); }

    // Derive a stable id from IP + system + first user message (best-effort).
    try {
        if (reqBody) {
            var ip = context.getVariable('client.ip') || context.getVariable('request.header.x-forwarded-for') || '';
            var seed = ip + '|';
            var msgs = reqBody.messages;
            if (msgs && msgs.length) {
                for (var i = 0; i < msgs.length; i++) {
                    if (msgs[i] && msgs[i].role === 'system' && msgs[i].content) { seed += String(msgs[i].content) + '|'; break; }
                }
                for (var u = 0; u < msgs.length; u++) {
                    if (msgs[u] && msgs[u].role === 'user' && msgs[u].content) {
                        var cu = msgs[u].content;
                        seed += (typeof cu === 'string') ? cu : airsCollectJoined(cu);
                        break;
                    }
                }
            } else if (reqBody.system) { seed += String(reqBody.system) + '|'; }
            else if (reqBody.contents && reqBody.contents.length) { seed += airsCollectJoined(reqBody.contents[0]); }

            if (seed.length > (String(ip).length + 1)) {
                try {
                    var sha = crypto.getSHA256();      // Apigee crypto object
                    sha.update(seed);
                    return 'conv-' + String(sha.digest('hex')).substring(0, 16).toLowerCase();
                } catch (eh) { /* crypto unavailable — fall through */ }
            }
        }
    } catch (e) { /* fall through */ }

    return context.getVariable('messageid');
}
context.setVariable('airs.sessionId', computeSessionId());

/* ---- transaction id (wire field: transaction_id) ------------------------- */
var reqId = airsHeader('x-request-id');
context.setVariable('airs.txnId', airsIsBlank(reqId) ? context.getVariable('messageid') : reqId);

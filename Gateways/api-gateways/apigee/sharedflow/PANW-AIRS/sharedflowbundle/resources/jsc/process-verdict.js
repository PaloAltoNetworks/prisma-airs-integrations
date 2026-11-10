/*
 * process-verdict.js — Phase 6+8: decide the outcome and build the response.
 *
 * Reads the canonical airs.* variables from EV-ParseAIRSVerdict and the AIRS
 * callout status, then sets:
 *   airs.outcome        "allow" | "mask" | "block"
 *   airs.block.body     response payload   (when block)
 *   airs.block.status   HTTP status        (when block)
 *   airs.block.ctype    Content-Type       (when block)
 *
 * A single format-aware builder replaces V1's fixed per-detector RaiseFaults:
 * the block body must now match the *caller's* dialect — Vertex, OpenAI
 * chat/completions, OpenAI Responses, Anthropic messages, or MCP JSON-RPC —
 * and, for streaming callers (incl. Claude Code), be a graceful SSE refusal so
 * the client/session isn't broken. The per-detector booleans still drive the
 * human-readable threat list, preserving V1's "name the detector" behaviour.
 *
 * Blocks are returned in the client's native shape with HTTP 200 + an
 * `x-airs-blocked: true` header (Vertex also carries an `airs` object), matching
 * the V1 Apigee "graceful block" posture — AIRS has already logged/enforced the
 * block; this only controls how the caller is told.
 */

var apiType = context.getVariable('airs.apiType');
var phase   = context.getVariable('airs.cfg.phase');
var failOpen = context.getVariable('airs.cfg.failOpen') === 'true';
var model   = context.getVariable('airs.model') || 'model';
var scanId  = context.getVariable('airs.scan_id') || '';
var trId    = context.getVariable('airs.transaction_id') || context.getVariable('airs.txnId') || '';
var descriptions = airsParse(context.getVariable('airs.cfg.descriptions')) || {};

var reqBody = airsParse(context.getVariable('request.content'));
var _spath = String(context.getVariable('proxy.pathsuffix') || context.getVariable('request.uri') || '').toLowerCase();
// Streaming callers must get an SSE refusal, not JSON. Detect from the request
// body flag (OpenAI/Anthropic native set stream:true) OR the endpoint itself:
// Gemini streamGenerateContent and Vertex :streamRawPredict (Claude on Vertex,
// where the stream is the endpoint — not a body field — so the flag alone misses it).
var streaming = (reqBody && reqBody.stream === true) ||
    _spath.indexOf('streamgeneratecontent') !== -1 ||
    _spath.indexOf(':streamrawpredict') !== -1;

/* ---- llm flavour (for the right block shape) ----------------------------- */
function llmFlavor() {
    var p = String(context.getVariable('proxy.pathsuffix') || context.getVariable('request.uri') || '').toLowerCase();
    if (/\/responses$/.test(p)) { return 'openai-responses'; }
    if (p.indexOf('/v1/messages') !== -1 || p.indexOf('/anthropic/') !== -1) { return 'anthropic'; }
    return 'openai-chat';
}

/* ---- AIRS call success? -------------------------------------------------- */
var scStatus = Number(context.getVariable('airsScanResponse.status.code') || 0);

if (scStatus !== 200) {
    // Scanner failed / unreachable.
    if (failOpen) { context.setVariable('airs.outcome', 'allow'); }
    else { buildFailClosed(); }
} else {
    var action = context.getVariable('airs.action');
    if (action === 'block') { context.setVariable('airs.outcome', 'block'); buildBlock(); }
    else if (hasMaskedData()) { context.setVariable('airs.outcome', 'mask'); }
    else { context.setVariable('airs.outcome', 'allow'); }
}

/* ================================================================== *
 * Detector helpers
 * ================================================================== */
function det(name) { return airsTruthy(context.getVariable('airs.' + name)); }

// Ordered detector keys for the current phase/apiType.
function activeDetectors() {
    if (apiType === 'mcp') { return [['tool.injection','injection'],['tool.dlp','dlp'],['tool.url_cats','url_cats'],['tool.malicious_code','malicious_code']]; }
    var list = [];
    if (phase === 'prompt' || phase === 'both') {
        list = list.concat([['prompt.injection','injection'],['prompt.dlp','dlp'],['prompt.url_cats','url_cats'],['prompt.toxic_content','toxic_content'],['prompt.agent','agent']]);
    }
    if (phase === 'response' || phase === 'both') {
        list = list.concat([['response.dlp','dlp'],['response.url_cats','url_cats'],['response.malicious_code','malicious_code'],['response.toxic_content','toxic_content'],['response.db_security','db_security'],['response.ungrounded','ungrounded'],['response.agent','agent']]);
    }
    return list;
}

function detectedThreatList() {
    var out = [], seen = {};
    var d = activeDetectors();
    for (var i = 0; i < d.length; i++) {
        if (det(d[i][0])) {
            var key = d[i][1];
            if (!seen[key]) { seen[key] = true; out.push(descriptions[key] || key); }
        }
    }
    return out;
}

function category() {
    var map = { injection: 'prompt-injection', dlp: 'dlp', url_cats: 'malicious-url',
        malicious_code: 'malicious-code', toxic_content: 'toxic-content',
        db_security: 'db-security', ungrounded: 'ungrounded', agent: 'agent-manipulation' };
    var d = activeDetectors();
    for (var i = 0; i < d.length; i++) { if (det(d[i][0])) { return map[d[i][1]] || 'malicious'; } }
    return 'malicious';
}

function hasMaskedData() {
    return !airsIsBlank(context.getVariable('airs.prompt.masked')) ||
           !airsIsBlank(context.getVariable('airs.response.masked')) ||
           !airsIsBlank(context.getVariable('airs.tool.input.masked')) ||
           !airsIsBlank(context.getVariable('airs.tool.output.masked'));
}

/* ================================================================== *
 * Block builders (format-aware)
 * ================================================================== */
function noticeText() {
    var threats = detectedThreatList();
    var head = 'PRISMA AIRS SECURITY ALERT: ' + ((phase === 'response') ? 'RESPONSE BLOCKED' : 'REQUEST BLOCKED');
    return head + (threats.length ? (': ' + threats.join(', ')) : '');
}

function put(body, status, ctype) {
    // blockStatus knob: force a hard status on non-streaming native-200 blocks so
    // blocks show up in status-code metrics. SSE stays 200 (a stream needs it);
    // fail-closed (status 500) is untouched since the override only fires on 200.
    var eff = status;
    if (status === 200 && ctype !== 'text/event-stream') {
        var bs = context.getVariable('airs.cfg.blockStatus');
        if (bs && bs !== 'native' && /^[0-9]+$/.test(String(bs))) { eff = parseInt(bs, 10); }
    }
    context.setVariable('airs.block.body', body);
    context.setVariable('airs.block.status', String(eff));
    context.setVariable('airs.block.ctype', ctype);
    context.setVariable('airs.block.reason', eff === 200 ? 'OK' : (eff === 403 ? 'Forbidden' : (eff >= 500 ? 'Internal Server Error' : 'Blocked')));
}

function airsObj(cat) { return { action: 'block', category: cat, scan_id: scanId, transaction_id: trId }; }

function buildBlock() {
    var notice = noticeText();
    var cat = category();
    context.setVariable('airs.block.category', cat);   // specific category for the x-airs-category header

    if (apiType === 'mcp') {
        put(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: '🛡️ ' + notice } }), 200, 'application/json');
        return;
    }
    if (apiType === 'gemini') {
        put(JSON.stringify({
            candidates: [{ content: { role: 'model', parts: [{ text: notice }] }, finishReason: 'STOP' }],
            modelVersion: model, airs: airsObj(cat)
        }), 200, 'application/json');
        return;
    }
    // llm
    var flavor = llmFlavor();
    if (streaming) { put(buildLlmSSE(flavor, notice), 200, 'text/event-stream'); return; }

    if (flavor === 'anthropic') {
        put(JSON.stringify({
            id: 'msg_airs_block', type: 'message', role: 'assistant', model: model,
            content: [{ type: 'text', text: notice }], stop_reason: 'end_turn', stop_sequence: null,
            usage: { input_tokens: 0, output_tokens: 0 }, airs: airsObj(cat)
        }), 200, 'application/json');
    } else if (flavor === 'openai-responses') {
        put(JSON.stringify({
            id: 'resp_airs_block', object: 'response', model: model,
            output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: notice }] }],
            airs: airsObj(cat)
        }), 200, 'application/json');
    } else { // openai-chat
        put(JSON.stringify({
            id: 'chatcmpl-airs-block', object: 'chat.completion', model: model,
            choices: [{ index: 0, message: { role: 'assistant', content: notice }, finish_reason: 'stop' }],
            usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }, airs: airsObj(cat)
        }), 200, 'application/json');
    }
}

// Graceful streaming refusal so the caller's SSE parser (incl. Claude Code)
// completes cleanly instead of erroring.
function buildLlmSSE(flavor, notice) {
    var sb = [];
    if (flavor === 'openai-chat' || flavor === 'openai-responses') {
        var base = { id: 'chatcmpl-airs-block', object: 'chat.completion.chunk', model: model };
        sb.push('data: ' + JSON.stringify({ id: base.id, object: base.object, model: model, choices: [{ index: 0, delta: { role: 'assistant', content: notice }, finish_reason: null }] }));
        sb.push('data: ' + JSON.stringify({ id: base.id, object: base.object, model: model, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }));
        sb.push('data: [DONE]');
        return sb.join('\n\n') + '\n\n';
    }
    // Anthropic streaming events
    function ev(type, obj) { return 'event: ' + type + '\ndata: ' + JSON.stringify(obj); }
    sb.push(ev('message_start', { type: 'message_start', message: { id: 'msg_airs_block', type: 'message', role: 'assistant', model: model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } }));
    sb.push(ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }));
    sb.push(ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: notice } }));
    sb.push(ev('content_block_stop', { type: 'content_block_stop', index: 0 }));
    sb.push(ev('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 0 } }));
    sb.push(ev('message_stop', { type: 'message_stop' }));
    return sb.join('\n\n') + '\n\n';
}

/* ================================================================== *
 * Fail-closed (scanner unavailable, failOpen=false)
 * ================================================================== */
function buildFailClosed() {
    context.setVariable('airs.outcome', 'block');
    context.setVariable('airs.block.category', 'scanner-unavailable');
    var detail = '';
    var scStatus2 = Number(context.getVariable('airsScanResponse.status.code') || 0);
    detail = scStatus2 ? ('HTTP ' + scStatus2) : 'AIRS API unreachable';
    var msg = '🛡️ PRISMA AIRS SECURITY ALERT: Security scanner failed (' + detail + '). Request blocked for safety.';
    if (apiType === 'mcp') {
        put(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: msg } }), 200, 'application/json');
    } else {
        put(JSON.stringify({ error: msg }), 500, 'application/json');
    }
}

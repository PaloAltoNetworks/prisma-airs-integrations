/*
 * apply-masking.js — Phase 7: DLP masking (outcome == "mask").
 *
 * When AIRS allows the traffic but returns masked data (the profile is set to
 * mask rather than block), rewrite the message in-place with the masked text so
 * sensitive values never reach the model (prompt leg) or the caller (response
 * leg). Per-leg:
 *   phase "prompt"          -> mask request.content  with airs.prompt.masked
 *   phase "response"/"both" -> mask response.content with airs.response.masked
 *   MCP (response leg)      -> mask response.content with airs.tool.output.masked
 *
 * Every branch is defensive: on any parse failure the original body is left
 * untouched (masking is best-effort; it must never corrupt traffic).
 */

var apiType = context.getVariable('airs.apiType');
var phase   = context.getVariable('airs.cfg.phase');

/* ================================================================== *
 * REQUEST leg — prompt masking (before the model)
 * ================================================================== */
function maskRequest(masked) {
    var body = airsParse(context.getVariable('request.content'));
    if (!body) { return; }

    if (apiType === 'gemini') {
        if (body.contents && body.contents.length) {
            var last = body.contents[body.contents.length - 1];
            if (last && last.parts) {
                for (var i = 0; i < last.parts.length; i++) {
                    if (typeof last.parts[i].text === 'string') { last.parts[i].text = masked; break; }
                }
            }
        }
    } else { // llm: messages or input array
        var arr = (body.messages && body.messages.length) ? body.messages
                : ((body.input && body.input.length) ? body.input : null);
        if (arr) {
            for (var m = arr.length - 1; m >= 0; m--) {
                if (arr[m] && arr[m].role === 'user') {
                    var c = arr[m].content;
                    if (typeof c === 'string') { arr[m].content = masked; }
                    else if (c && c.length) {
                        for (var b = 0; b < c.length; b++) { if (c[b] && c[b].type === 'text') { c[b].text = masked; break; } }
                    }
                    break;
                }
            }
        }
    }
    context.setVariable('request.content', JSON.stringify(body));
    context.setVariable('airs.mask.applied', 'request');
}

/* ================================================================== *
 * RESPONSE leg — response / tool-output masking (before the caller)
 * ================================================================== */
function maskResponse(masked) {
    var raw = context.getVariable('response.content');
    if (!raw) { return; }

    // MCP tool output (JSON or single-line SSE)
    if (apiType === 'mcp') {
        var ct = String(context.getVariable('response.header.Content-Type') || '');
        var isSSE = ct.indexOf('text/event-stream') !== -1;
        var obj = isSSE ? sseFirstJson(raw) : airsParse(raw);
        if (obj && obj.result && obj.result.content) {
            for (var i = 0; i < obj.result.content.length; i++) {
                if (obj.result.content[i] && obj.result.content[i].type === 'text') { obj.result.content[i].text = masked; break; }
            }
            context.setVariable('response.content', isSSE ? ('event: message\ndata: ' + JSON.stringify(obj) + '\n\n') : JSON.stringify(obj));
            context.setVariable('airs.mask.applied', 'tool-output');
        }
        return;
    }

    // Streaming SSE (OpenAI / Anthropic / Gemini)
    if (String(raw).indexOf('data:') !== -1 || String(raw).replace(/^\s+/, '').charAt(0) === '[') {
        context.setVariable('response.content', maskStream(raw, masked));
        context.setVariable('airs.mask.applied', 'response-stream');
        return;
    }

    // Non-streaming JSON
    var body = airsParse(raw);
    if (!body) { return; }
    if (apiType === 'gemini') {
        if (body.candidates) { setFirstGeminiText(body.candidates, masked); }
    } else if (body.content && body.content.length) {              // Anthropic
        for (var a = 0; a < body.content.length; a++) { if (body.content[a] && body.content[a].type === 'text') { body.content[a].text = masked; break; } }
    } else if (body.choices && body.choices.length) {             // OpenAI chat
        if (body.choices[0].message) { body.choices[0].message.content = masked; }
    } else if (body.output && body.output.length) {               // OpenAI Responses
        for (var o = 0; o < body.output.length; o++) {
            var it = body.output[o];
            if (it && it.type === 'message' && it.content) {
                for (var cb = 0; cb < it.content.length; cb++) { if (it.content[cb] && it.content[cb].type === 'output_text') { it.content[cb].text = masked; break; } }
                break;
            }
        }
    }
    context.setVariable('response.content', JSON.stringify(body));
    context.setVariable('airs.mask.applied', 'response');
}

/* ---- helpers ------------------------------------------------------------- */
function setFirstGeminiText(candidates, masked) {
    for (var i = 0; i < candidates.length; i++) {
        var parts = candidates[i] && candidates[i].content && candidates[i].content.parts;
        if (parts) { for (var j = 0; j < parts.length; j++) { if (typeof parts[j].text === 'string') { parts[j].text = masked; return; } } }
    }
}

function sseFirstJson(raw) {
    var lines = airsSplitLines(raw);
    for (var i = 0; i < lines.length; i++) { if (String(lines[i]).indexOf('data:') === 0) { var o = airsParse(airsStripDataPrefix(lines[i])); if (o) { return o; } } }
    return null;
}

// Rebuild a streamed body with the masked text delivered ONCE. Incremental
// deltas get the masked string on the first text-bearing chunk and are blanked
// thereafter (the naive "set every chunk to the full masked string" repeats it
// N times — a bug in the APIM fragment we deliberately do not reproduce).
// Terminal snapshot events (which carry the full text) get the full masked value.
function maskStream(raw, masked) {
    var trimmed = String(raw).replace(/^\s+/, '');
    var state = { done: false };
    function once() { if (state.done) { return ''; } state.done = true; return masked; }

    if (trimmed.charAt(0) === '[') {                 // Gemini streamed JSON array
        var arr = airsParse(trimmed);
        if (!arr) { return raw; }
        for (var a = 0; a < arr.length; a++) { if (arr[a] && arr[a].candidates) { maskGeminiStreamText(arr[a].candidates, once); } }
        return JSON.stringify(arr);
    }
    var out = [];
    var lines = String(raw).split('\n');
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (String(line).replace(/^\s+|\s+$/g, '').indexOf('data:') !== 0) { out.push(line); continue; }
        var js = airsStripDataPrefix(line);
        if (!js || js.indexOf('[DONE]') !== -1) { out.push(line); continue; }
        var chunk = airsParse(js);
        if (!chunk) { out.push(line); continue; }

        // incremental deltas — masked once, then blanked
        if (chunk.choices && chunk.choices[0] && chunk.choices[0].delta && chunk.choices[0].delta.content != null) { chunk.choices[0].delta.content = once(); }   // OpenAI chat
        if (chunk.type === 'content_block_delta' && chunk.delta && chunk.delta.text != null) { chunk.delta.text = once(); }                                        // Anthropic
        if (chunk.type === 'response.output_text.delta' && chunk.delta != null) { chunk.delta = once(); }                                                          // OpenAI Responses (delta)
        if (chunk.candidates) { maskGeminiStreamText(chunk.candidates, once); }                                                                                    // Gemini SSE

        // OpenAI Responses terminal snapshots — carry the FULL text, so full masked value
        if (chunk.type === 'response.output_text.done' && chunk.text != null) { chunk.text = masked; }
        if (chunk.type === 'response.content_part.done' && chunk.part && chunk.part.text != null) { chunk.part.text = masked; }
        if (chunk.type === 'response.output_item.done' && chunk.item && chunk.item.content) {
            for (var c = 0; c < chunk.item.content.length; c++) { if (chunk.item.content[c] && chunk.item.content[c].type === 'output_text' && chunk.item.content[c].text != null) { chunk.item.content[c].text = masked; } }
        }
        if (chunk.type === 'response.completed' && chunk.response && chunk.response.output) {
            for (var o = 0; o < chunk.response.output.length; o++) {
                var it = chunk.response.output[o];
                if (it && it.content) { for (var cc = 0; cc < it.content.length; cc++) { if (it.content[cc] && it.content[cc].type === 'output_text' && it.content[cc].text != null) { it.content[cc].text = masked; } } }
            }
        }

        out.push('data: ' + JSON.stringify(chunk));
    }
    return out.join('\n');
}

// Set streamed Gemini text parts via the once() emitter (masked once, then blank).
function maskGeminiStreamText(candidates, once) {
    if (!candidates) { return; }
    for (var i = 0; i < candidates.length; i++) {
        var parts = candidates[i] && candidates[i].content && candidates[i].content.parts;
        if (!parts) { continue; }
        for (var j = 0; j < parts.length; j++) { if (typeof parts[j].text === 'string') { parts[j].text = once(); } }
    }
}

/* ================================================================== *
 * Dispatch by leg
 * ================================================================== */
if (phase === 'prompt') {
    var pm = context.getVariable('airs.prompt.masked');
    if (!airsIsBlank(pm)) { maskRequest(pm); }
} else {
    if (apiType === 'mcp') {
        var tom = context.getVariable('airs.tool.output.masked');
        if (!airsIsBlank(tom)) { maskResponse(tom); }
    } else {
        var rm = context.getVariable('airs.response.masked');
        if (!airsIsBlank(rm)) { maskResponse(rm); }
    }
}

/*
 * extract-content.js — Phase 4: content extraction (the heart of the flow).
 *
 * Turns a request/response of ANY supported shape into the plain text AIRS
 * scans. Publishes:
 *   airs.promptText    user input to scan   (prompt / both phases)
 *   airs.responseText  model output to scan  (response / both phases)
 *   airs.toolEvent     JSON tool_event       (MCP only)
 *   airs.model         model name for metadata
 *   airs.scanLeg       "prompt"|"toolresult"|"response"|"toolcall"|"both"|"tool_event"
 *   airs.hasContent    "true"/"false"
 *
 * Two deliberate design points, both learned from the el-cacheo tool-call study:
 *
 *  1. INLINE TOOL-CALL SCANNING (superset over the APIM fragment). When the
 *     model emits a native function call (Gemini functionCall, Anthropic
 *     tool_use, OpenAI tool_calls) we do NOT skip it — we extract its argument
 *     *values* (airsCollect: clean strings, no JSON wrapper) into the response
 *     scan. Symmetrically, an inbound Gemini functionResponse is scanned as
 *     untrusted input. This closes the inline agentic blind spot.
 *
 *  2. PER-TURN ISOLATION. We scan the NEWEST turn's content, not a re-flatten
 *     of the whole conversation. Prior turns were scanned when they were new;
 *     re-concatenating them muddies attribution (a benign prompt blended with a
 *     poisoned tool result) and re-bills already-scanned tokens.
 */

var phase     = context.getVariable('airs.cfg.phase');
var apiType   = context.getVariable('airs.apiType');
var isCC      = context.getVariable('airs.isCC') === 'true';
var scanTools = context.getVariable('airs.cfg.scanTools') === 'true';

var reqBody = airsParse(context.getVariable('request.content'));
var respRaw = context.getVariable('response.content');   // null on request leg

var promptText = '';
var responseText = '';
var toolEventJson = '';
var usedToolResult = false;
var usedToolCall = false;

/* ---- model name ---------------------------------------------------------- */
function extractModel() {
    if (apiType === 'mcp') { return 'mcp-tool-server'; }
    if (apiType === 'llm') {
        if (reqBody && reqBody.model) { return String(reqBody.model); }   // OpenAI / Anthropic native — model in body
        // Vertex rawPredict puts the model in the URL (…/models/{model}:rawPredict).
        var lp = context.getVariable('proxy.pathsuffix') || context.getVariable('request.uri') || '';
        var lseg = String(lp).split('/');
        for (var k = 0; k < lseg.length; k++) {
            if (lseg[k] === 'models' && k + 1 < lseg.length) { return lseg[k + 1].split(':')[0]; }
        }
    }
    if (apiType === 'gemini') {
        var path = context.getVariable('proxy.pathsuffix') || context.getVariable('request.uri') || '';
        var seg = String(path).split('/');
        for (var i = 0; i < seg.length; i++) {
            if (seg[i] === 'models' && i + 1 < seg.length) { return seg[i + 1].split(':')[0]; }
        }
        return 'gemini-model';
    }
    return 'unknown-model';
}

/* ================================================================== *
 * MCP — build an AIRS tool_event (input always; output on response leg)
 * ================================================================== */
function buildMcpToolEvent() {
    if (!reqBody) { return ''; }
    var toolName = (reqBody.params && reqBody.params.name) ? String(reqBody.params.name) : 'unknown';
    var toolArgs = (reqBody.params && reqBody.params.arguments !== undefined)
        ? (typeof reqBody.params.arguments === 'string' ? reqBody.params.arguments : airsStringify(reqBody.params.arguments))
        : '{}';

    var serverName = context.getVariable('apiproxy.name') || 'mcp-server';

    var toolEvent = {
        metadata: { ecosystem: 'mcp', method: 'tools/call', server_name: serverName, tool_invoked: toolName },
        input: toolArgs
    };

    // Output: parse the tool server's response (JSON or single-line SSE).
    if ((phase === 'response' || phase === 'both') && respRaw) {
        var body = null;
        var ct = context.getVariable('response.header.Content-Type') || '';
        if (String(ct).indexOf('text/event-stream') !== -1) {
            var lines = airsSplitLines(respRaw);
            for (var i = 0; i < lines.length; i++) {
                if (String(lines[i]).indexOf('data:') === 0) { body = airsParse(airsStripDataPrefix(lines[i])); if (body) { break; } }
            }
        } else { body = airsParse(respRaw); }

        if (body && body.result && body.result.content && body.result.content.length) {
            var out = '';
            for (var c = 0; c < body.result.content.length; c++) {
                if (body.result.content[c] && body.result.content[c].type === 'text') { out += (body.result.content[c].text || ''); }
            }
            if (out.length) { toolEvent.output = out; }
        }
    }
    return airsStringify(toolEvent);
}

/* ================================================================== *
 * GEMINI / VERTEX
 * ================================================================== */
function geminiPrompt() {
    // Scan the newest turn only.
    if (!reqBody || !reqBody.contents || !reqBody.contents.length) { return; }
    var last = reqBody.contents[reqBody.contents.length - 1];
    var parts = (last && last.parts) ? last.parts : [];
    var buf = [];
    for (var i = 0; i < parts.length; i++) {
        var p = parts[i];
        if (!p) { continue; }
        if (typeof p.text === 'string') {
            buf.push(isCC ? airsStripReminders(p.text) : p.text);
        } else if (p.functionResponse && scanTools) {
            // Inbound inline tool result — scan its clean values as untrusted input.
            buf.push(airsCollectJoined(p.functionResponse.response));
            usedToolResult = true;
        }
    }
    promptText = buf.join('\n');
}

function geminiResponse() {
    var text = extractGeminiResponseText(respRaw);   // handles array / SSE / single
    responseText = text;
}

// Returns concatenated model text AND folds inline functionCall args (clean values).
function extractGeminiResponseText(raw) {
    if (!raw) { return ''; }
    var sb = [];
    var trimmed = String(raw).replace(/^\s+/, '');

    function harvest(candidates) {
        if (!candidates) { return; }
        for (var i = 0; i < candidates.length; i++) {
            var content = candidates[i] && candidates[i].content;
            var parts = content && content.parts ? content.parts : [];
            for (var j = 0; j < parts.length; j++) {
                if (typeof parts[j].text === 'string' && parts[j].text.length) { sb.push(parts[j].text); }
                else if (parts[j].functionCall) {
                    var vals = airsCollectJoined(parts[j].functionCall.args);   // inline tool-call scan
                    if (vals.length) { sb.push(vals); usedToolCall = true; }
                }
            }
        }
    }

    if (trimmed.charAt(0) === '[') {                       // streamed JSON array
        var arr = airsParse(trimmed);
        if (arr) { for (var a = 0; a < arr.length; a++) { harvest(arr[a] && arr[a].candidates); } }
    } else if (String(raw).indexOf('data:') !== -1) {      // SSE
        var lines = airsSplitLines(raw);
        for (var l = 0; l < lines.length; l++) {
            var js = airsStripDataPrefix(lines[l]);
            if (!js || js.indexOf('[DONE]') !== -1) { continue; }
            var chunk = airsParse(js);
            if (chunk) { harvest(chunk.candidates); }
        }
    } else {                                               // single JSON object
        var obj = airsParse(raw);
        if (obj) { harvest(obj.candidates); }
    }
    return sb.join('');
}

/* ================================================================== *
 * LLM — OpenAI (chat/completions + Responses API) & Anthropic
 * ================================================================== */
function llmPrompt() {
    var arr = null;
    if (reqBody && reqBody.messages && reqBody.messages.length) { arr = reqBody.messages; }
    else if (reqBody && reqBody.input && reqBody.input.length) { arr = reqBody.input; }
    if (!arr) { return; }

    // Newest turn only: last message (a user turn or a trailing tool result).
    var msg = arr[arr.length - 1];
    var role = msg && msg.role;
    var buf = [];

    if (role === 'user') {
        var content = msg.content;
        if (typeof content === 'string') {
            buf.push(isCC ? airsStripReminders(content) : content);
        } else if (content && content.length) {
            for (var b = 0; b < content.length; b++) {
                var blk = content[b];
                if (!blk) { continue; }
                if (blk.type === 'text') {
                    buf.push(isCC ? airsStripReminders(blk.text || '') : (blk.text || ''));
                } else if (blk.type === 'tool_result' && scanTools && !isCC) {
                    // Anthropic tool result folded as untrusted input (APIM parity).
                    // Skipped for Claude Code: local tool chatter is covered at the MCP chokepoint.
                    buf.push(typeof blk.content === 'string' ? blk.content : airsCollectJoined(blk.content));
                    usedToolResult = true;
                }
            }
        }
    } else if (role === 'tool' && scanTools && !isCC) {
        // OpenAI tool result message.
        buf.push(typeof msg.content === 'string' ? msg.content : airsCollectJoined(msg.content));
        usedToolResult = true;
    }
    promptText = buf.join('\n');
}

function llmResponse() {
    if (!respRaw) { return; }
    if (String(respRaw).indexOf('data:') !== -1) { responseText = llmResponseSSE(respRaw); return; }

    var body = airsParse(respRaw);
    if (!body) { return; }
    var sb = [];

    if (body.choices && body.choices.length) {                       // OpenAI chat/completions
        var m = body.choices[body.choices.length - 1].message;
        if (m) {
            if (m.content) { sb.push(String(m.content)); }
            if (m.tool_calls && m.tool_calls.length) {                // inline tool-call scan
                for (var t = 0; t < m.tool_calls.length; t++) {
                    var fn = m.tool_calls[t].function;
                    if (fn && fn.arguments) { sb.push(airsCollectJoined(airsParse(fn.arguments) || fn.arguments)); usedToolCall = true; }
                }
            }
        }
    } else if (body.output && body.output.length) {                  // OpenAI Responses API
        for (var o = 0; o < body.output.length; o++) {
            var item = body.output[o];
            if (item && item.type === 'message' && item.role === 'assistant' && item.content) {
                for (var cb = 0; cb < item.content.length; cb++) {
                    if (item.content[cb] && item.content[cb].type === 'output_text') { sb.push(item.content[cb].text || ''); }
                }
            } else if (item && item.type === 'function_call' && item.arguments) {   // inline tool-call scan
                sb.push(airsCollectJoined(airsParse(item.arguments) || item.arguments)); usedToolCall = true;
            }
        }
    } else if (body.content && body.content.length) {                // Anthropic messages
        for (var a = 0; a < body.content.length; a++) {
            var blk = body.content[a];
            if (!blk) { continue; }
            if (blk.type === 'text') { sb.push(blk.text || ''); }
            else if (blk.type === 'tool_use') { sb.push(airsCollectJoined(blk.input)); usedToolCall = true; }  // inline tool-call scan
        }
    }
    responseText = sb.join('');
}

// Streaming SSE reassembly across OpenAI, Anthropic, and OpenAI Responses.
function llmResponseSSE(raw) {
    var sb = [];
    var toolArgs = '';           // accumulates streamed tool-call argument fragments
    var lines = airsSplitLines(raw);
    for (var i = 0; i < lines.length; i++) {
        var line = String(lines[i]);
        if (line.replace(/^\s+/, '').indexOf('data:') !== 0) { continue; }
        var js = airsStripDataPrefix(line);
        if (!js || js.indexOf('[DONE]') !== -1) { continue; }
        var chunk = airsParse(js);
        if (!chunk) { continue; }

        // OpenAI chat/completions streaming
        if (chunk.choices && chunk.choices[0]) {
            var delta = chunk.choices[0].delta;
            if (delta) {
                if (delta.content) { sb.push(delta.content); }
                if (delta.tool_calls && delta.tool_calls.length) {
                    for (var tc = 0; tc < delta.tool_calls.length; tc++) {
                        var f = delta.tool_calls[tc].function;
                        if (f && f.arguments) { toolArgs += f.arguments; }
                    }
                }
            }
        }
        // Anthropic streaming
        var et = chunk.type;
        if (et === 'content_block_delta' && chunk.delta) {
            if (chunk.delta.type === 'text_delta' && chunk.delta.text) { sb.push(chunk.delta.text); }
            if (chunk.delta.type === 'input_json_delta' && chunk.delta.partial_json) { toolArgs += chunk.delta.partial_json; }
        }
        // OpenAI Responses API streaming
        if (et === 'response.output_text.delta' && chunk.delta) { sb.push(String(chunk.delta)); }
    }
    if (toolArgs.length) {                       // inline tool-call scan (streamed)
        var parsed = airsParse(toolArgs);
        sb.push(parsed ? airsCollectJoined(parsed) : toolArgs);
        usedToolCall = true;
    }
    return sb.join('');
}

/* ================================================================== *
 * Orchestrate
 * ================================================================== */
var model = extractModel();

if (apiType === 'mcp') {
    toolEventJson = buildMcpToolEvent();
} else {
    if (phase === 'prompt' || phase === 'both') {
        if (apiType === 'gemini') { geminiPrompt(); } else { llmPrompt(); }
    }
    if (phase === 'response' || phase === 'both') {
        if (apiType === 'gemini') { geminiResponse(); } else { llmResponse(); }
    }
}

/* ---- scanLeg label (attribution, à la el-cacheo) ------------------------- */
var leg;
if (apiType === 'mcp') { leg = 'tool_event'; }
else if (phase === 'both') { leg = 'both'; }
else if (phase === 'prompt') { leg = usedToolResult ? 'toolresult' : 'prompt'; }
else { leg = usedToolCall ? 'toolcall' : 'response'; }

context.setVariable('airs.promptText', promptText);
context.setVariable('airs.responseText', responseText);
context.setVariable('airs.toolEvent', toolEventJson);
context.setVariable('airs.model', model);
context.setVariable('airs.scanLeg', leg);

var hasContent = (promptText && promptText.length) || (responseText && responseText.length) || (toolEventJson && toolEventJson.length);
context.setVariable('airs.hasContent', hasContent ? 'true' : 'false');

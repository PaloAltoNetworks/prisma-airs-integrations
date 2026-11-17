'use strict';
/*
 * MuleSoft's live integration tests (tests/integration/run.py), ported as v3 unit cases.
 * Each case names the recorded Prisma AIRS reply its callout gets; nothing here decides a verdict from content.
 * Where v3 differs from MuleSoft on purpose, the case follows v3's rule and its title says so. The texts are harmless:
 * plain sentences, the marker and the Visa test card.
 *
 * Two things shape some setups:
 *   - On this runtime v3's request leg turns streaming off, so the model answers JSON (L1). An event-stream reply
 *     reaches v3's stream readers only on a runtime that shows streams, and only when v3 isn't on the request leg. Cases
 *     that test a stream reader therefore run the reply leg alone, as a proxy that calls v3 only on its response leg.
 *   - run.js's silent-leg check reads the flow's last airs3.route, so a request leg that passes with nothing to scan,
 *     followed by a reply leg that scans or refuses, reads as silent. Cases about such a reply run the reply leg alone.
 * MuleSoft's monitor mode, breaker, cache, batch limit, open streams and initialize session adoption are not ported:
 * v3's phase 1 has none of them.
 */
const zlib = require('zlib');
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const MARK = 'AIRSV3-MARKER';
const MASKED = 'XXXXXXXXXXXXXXXXXXX';
const FMTS = ['chat', 'responses', 'anthropic', 'gemini'];
const MS = { chat: 'openai', responses: 'responses', anthropic: 'anthropic', gemini: 'gemini' };         // MuleSoft's names
const PATH = { chat: S.P.chat, responses: S.P.responses, anthropic: S.P.anthropic, gemini: S.P.gemini };
// v3 turns a Gemini stream off by rewriting target.url, so a proxy runs v3's request leg in the TargetEndpoint PreFlow,
// where target.url is set.
const TARGET = 'https://aiplatform.example/v1/projects/p/locations/global/publishers/google/models/gemini-x:streamGenerateContent?alt=sse';
// A setting v3 refuses: an endpoint that already holds the scan path (MuleSoft's rejects_endpoint_with_scan_path).
const BAD_ENDPOINT = 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request';
const CARD_PROMPT = 'Please store my card ' + C + ' for the next order.';     // block-dlp-prompt-masked was recorded for it
const CARD_REPLY = 'The card on file is ' + C + '.';                          // block-dlp-response-masked was recorded for it

/* ---- requests ------------------------------------------------------------------------------------------------- */
// MuleSoft's body_for(): one user text, optionally streamed, optionally after a system text.
function bodyFor(fmt, text, o) {
    o = o || {};
    var b;
    if (fmt === 'chat') { b = { model: 'gpt-test', messages: (o.system ? [{ role: 'system', content: o.system }] : []).concat([{ role: 'user', content: text }]) }; }
    else if (fmt === 'responses') { b = { model: 'gpt-test', input: text }; if (o.system) { b.instructions = o.system; } }
    else if (fmt === 'anthropic') { b = { model: 'claude-test', max_tokens: 50, messages: [{ role: 'user', content: text }] }; if (o.system) { b.system = o.system; } }
    else { b = { contents: [{ role: 'user', parts: [{ text: text }] }] }; if (o.system) { b.systemInstruction = { parts: [{ text: o.system }] }; } }
    if (o.stream && fmt !== 'gemini') { b.stream = true; }                      // Gemini streams by its path
    return b;
}
// A request in one format: o.body replaces the built body, o.headers adds headers, o.stream asks for a stream.
function ask(fmt, text, o) {
    o = o || {};
    var gs = fmt === 'gemini' && !!o.stream;
    var s = S.req(gs ? S.P.geminiStream : PATH[fmt], o.body || bodyFor(fmt, text, o), o.headers, gs ? 'alt=sse' : '');
    s.vars = gs ? { 'target.url': TARGET } : {};
    return s;
}
function setup(base, extra) { var s = Object.assign({}, base, extra); s.vars = Object.assign({}, base.vars || {}, extra.vars || {}); return s; }

/* ---- replies, as MuleSoft's mock upstream writes them ---------------------------------------------------------- */
function replyFor(fmt, text) {
    if (fmt === 'chat') { return { id: 'chatcmpl-itest', object: 'chat.completion', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }; }
    if (fmt === 'responses') { return { id: 'resp-itest', object: 'response', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: text }] }] }; }
    if (fmt === 'anthropic') { return { id: 'msg-itest', type: 'message', role: 'assistant', content: [{ type: 'text', text: text }] }; }
    return { candidates: [{ index: 0, content: { role: 'model', parts: [{ text: text }] } }] };
}
function ev(name, data, nl) { nl = nl || '\n'; return (name ? 'event: ' + name + nl : '') + 'data: ' + (typeof data === 'string' ? data : JSON.stringify(data)) + nl + nl; }
function stream(body) { return { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: body }; }
// text_reply(stream=True): the text split over two events.
function replyStream(fmt, text) {
    var h = Math.floor(text.length / 2), a = text.slice(0, h), b = text.slice(h);
    if (fmt === 'chat') { return ev(null, { choices: [{ index: 0, delta: { role: 'assistant', content: a } }] }) + ev(null, { choices: [{ index: 0, delta: { content: b } }] }) + ev(null, '[DONE]'); }
    if (fmt === 'responses') {
        return ev('response.output_text.delta', { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: a }) +
               ev('response.output_text.delta', { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: b }) +
               ev('response.completed', { type: 'response.completed', response: replyFor('responses', text) });
    }
    if (fmt === 'anthropic') {
        return ev('message_start', { type: 'message_start', message: { id: 'msg-itest', content: [] } }) +
               ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }) +
               ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: a } }) + ev('ping', { type: 'ping' }) +
               ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: b } }) +
               ev('content_block_stop', { type: 'content_block_stop', index: 0 }) + ev('message_stop', { type: 'message_stop' });
    }
    return ev(null, replyFor('gemini', a), '\r\n') + ev(null, replyFor('gemini', b), '\r\n');
}
// tool_reply(): a reply that is only a tool call, carrying the text in its arguments.
function toolReply(fmt, text) {
    var args = JSON.stringify({ body: text });
    if (fmt === 'chat') { return { choices: [{ index: 0, message: { role: 'assistant', content: null, tool_calls: [{ id: 'call-1', type: 'function', 'function': { name: 'send_email', arguments: args } }] } }] }; }
    if (fmt === 'responses') { return { output: [{ type: 'function_call', name: 'send_email', arguments: args }] }; }
    if (fmt === 'anthropic') { return { content: [{ type: 'tool_use', id: 'toolu-1', name: 'send_email', input: { body: text } }] }; }
    return { candidates: [{ index: 0, content: { parts: [{ functionCall: { name: 'send_email', args: { body: text } } }] } }] };
}
function toolStream(fmt, text) {
    var args = JSON.stringify({ body: text });
    if (fmt === 'chat') {
        return ev(null, { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 'call-1', 'function': { name: 'send_email', arguments: args.slice(0, 5) } }] } }] }) +
               ev(null, { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, 'function': { arguments: args.slice(5) } }] } }] }) + ev(null, '[DONE]');
    }
    if (fmt === 'responses') { return ev('response.completed', { type: 'response.completed', response: toolReply('responses', text) }); }
    if (fmt === 'anthropic') {
        return ev('message_start', { type: 'message_start', message: { content: [] } }) +
               ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'send_email', input: {} } }) +
               ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: args.slice(0, 5) } }) +
               ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: args.slice(5) } }) +
               ev('message_stop', { type: 'message_stop' });
    }
    return ev(null, toolReply('gemini', text), '\r\n');
}
// sseedge: a keep-alive comment, Azure's empty first event, "data:" with no space, a comment line, CRLF, the text in two.
function edgeStream(text) {
    var h = Math.floor(text.length / 2);
    return ': keep-alive\r\n\r\n' + 'data: {"choices":[],"prompt_filter_results":[{"prompt_index":0}]}\r\n\r\n' +
           'data:' + JSON.stringify({ choices: [{ index: 0, delta: { content: text.slice(0, h) } }] }) + '\r\n\r\n' + ': ping\r\n' +
           'data: ' + JSON.stringify({ choices: [{ index: 0, delta: { content: text.slice(h) } }] }) + '\r\n\r\n' + 'data: [DONE]\r\n\r\n';
}
// pcm64(): audio with no file header, 16-bit little-endian samples of a 440 Hz tone, as Gemini sends speech.
function pcm64(seconds) {
    var rate = 24000, n = Math.floor(seconds * rate), b = Buffer.alloc(n * 2);
    for (var i = 0; i < n; i++) { b.writeInt16LE(Math.trunc(Math.sin(i * 440 * 2 * Math.PI / rate) * 8000), i * 2); }
    return b.toString('base64');
}
// png64(): a real PNG, a 24 x 24 colour gradient stored uncompressed.
function crc32(buf) {
    var crc = 0xFFFFFFFF;
    for (var i = 0; i < buf.length; i++) { crc ^= buf[i]; for (var k = 0; k < 8; k++) { crc = (crc >>> 1) ^ (0xEDB88320 & -(crc & 1)); } }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}
function png64() {
    var size = 24;
    function chunk(kind, data) {
        var len = Buffer.alloc(4), kd = Buffer.concat([Buffer.from(kind, 'latin1'), data]), crc = Buffer.alloc(4);
        len.writeUInt32BE(data.length); crc.writeUInt32BE(crc32(kd));
        return Buffer.concat([len, kd, crc]);
    }
    var rows = [];
    for (var y = 0; y < size; y++) { rows.push(0); for (var x = 0; x < size; x++) { rows.push((x * 10) % 256, (y * 10) % 256, 160); } }
    var ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 2;
    return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), chunk('IHDR', ihdr),
                          chunk('IDAT', zlib.deflateSync(Buffer.from(rows), { level: 0 })), chunk('IEND', Buffer.alloc(0))]).toString('base64');
}
function speech(seconds) { return { candidates: [{ index: 0, content: { role: 'model', parts: [{ inlineData: { mimeType: 'audio/L16;codec=pcm;rate=24000', data: pcm64(seconds) } }] } }] }; }

/* ---- what the client got ---------------------------------------------------------------------------------------- */
function hdr(x, name) { var m = x && x.flow.messages.response; return m ? m.header(name) : null; }
function refusedAs(x, kind) { return !!(x && x.blocked && hdr(x, 'x-airs-kind') === kind); }
function isStream(x) { return /text\/event-stream/.test(x.contentType || ''); }
function fwd(x) { return String(x.request.content); }
function events(body) {
    var out = [];
    String(body).split(/\r?\n\r?\n/).forEach(function (block) {
        var data = block.split(/\r?\n/).filter(function (l) { return /^data:/.test(l); }).map(function (l) { return l.replace(/^data: ?/, ''); }).join('\n');
        if (data === '' || data === '[DONE]') { return; }
        try { out.push(JSON.parse(data)); } catch (e) { out.push({ unreadable: data }); }
    });
    return out;
}
// The message the client reads, from a refusal in its own format (MuleSoft's error_shape(), for v3's shapes).
function said(fmt, x) {
    try {
        if (!isStream(x)) {
            var b = JSON.parse(x.body);
            if (fmt === 'chat') { return b.object === 'chat.completion' ? b.choices[0].message.content : null; }
            if (fmt === 'responses') { return b.object === 'response' ? b.output[0].content[0].text : null; }
            if (fmt === 'anthropic') { return b.type === 'message' ? b.content[0].text : null; }
            if (fmt === 'gemini') { return b.candidates[0].content.parts[0].text; }
            return b.error ? b.error.message : null;                              // MCP, and an endpoint v3 doesn't read
        }
        var out = [];
        events(x.body).forEach(function (d) {
            if (fmt === 'chat' && d.object === 'chat.completion.chunk' && d.choices[0] && typeof d.choices[0].delta.content === 'string') { out.push(d.choices[0].delta.content); }
            if (fmt === 'responses' && d.type === 'response.output_text.delta') { out.push(d.delta); }
            if (fmt === 'anthropic' && d.type === 'content_block_delta' && d.delta.type === 'text_delta') { out.push(d.delta.text); }
            if (fmt === 'gemini' && d.candidates) { out.push(d.candidates[0].content.parts[0].text); }
        });
        return out.length ? out.join('') : null;
    } catch (e) { return null; }
}
function rpcBody(x) { try { return JSON.parse(x.body); } catch (e) { return null; } }
// A JSON-RPC refusal, HTTP 200, carrying the request id as sent.
function rpcRefusal(x, id, code) { var b = x && rpcBody(x); return !!(x && x.blocked && x.status === 200 && b && b.jsonrpc === '2.0' && b.id === id && b.error && b.error.code === code); }
function tools(x) { return x.scans.map(function (b) { return b && b.contents && b.contents[0] && b.contents[0].tool_event; }).filter(Boolean); }
function logLine(x, i) { try { return JSON.parse(x.flow.logs[i].line); } catch (e) { return null; } }

/* ---- MCP ---------------------------------------------------------------------------------------------------------- */
const ACCEPT = { Accept: 'application/json, text/event-stream' };
function rpc(msg, headers) { return S.req(S.P.mcp, msg, Object.assign({}, ACCEPT, headers || {})); }
function call(text, n) { return { jsonrpc: '2.0', id: n === undefined ? 3 : n, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
function answer(id, result) { return S.reply({ jsonrpc: '2.0', id: id, result: result }); }
function echoed(text) { return { content: [{ type: 'text', text: 'echo: ' + JSON.stringify({ text: text }) }], isError: false }; }
const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'itest', version: '1' } } };
const LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list' };
const SCHEMA = { type: 'object', properties: { text: { type: 'string' } } };
const PAD = new Array(71).join('pad ');                                         // MuleSoft's DATA_PAD, 280 characters
const GET_STREAM_REPLY = 'event: message\ndata: ' + JSON.stringify({ jsonrpc: '2.0', id: 'srv-1', method: 'sampling/createMessage',
    params: { messages: [{ role: 'user', content: { type: 'text', text: 'Card on file: ' + C } }], maxTokens: 10 } }) + '\n\n';

const cases = [];

/* ---- run.py:141-187, the main path -------------------------------------------------------------------------------- */
FMTS.forEach(function (fmt) {
    var tx = 'itest-allow-' + MS[fmt], text = 'Hello! How can I help?', reply = S.reply(replyFor(fmt, text));
    cases.push({
        finding: 'MS-allow-legs',
        title: 'run.py:141 allow_both_legs_' + MS[fmt] + ': one scan per leg, the transaction id on both, no tr_id; the reply scan is one entry {prompt, response} (v3; MuleSoft sends the prompt as a separate first entry)',
        setup: setup(ask(fmt, 'hello there', { headers: { 'x-correlation-id': tx } }), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: reply }),
        v3: function (r) {
            var q = r.request, p = r.response;
            if (!q || q.fault || !p || p.fault) { return 'the exchange did not pass'; }
            if (q.scans.length !== 1 || p.scans.length !== 1) { return (q.scans.length + p.scans.length) + ' scans, not one per leg'; }
            var both = [q.scans[0], p.scans[0]];
            for (var i = 0; i < both.length; i++) {
                if (both[i].transaction_id !== tx || 'tr_id' in both[i]) { return 'scan ' + (i + 1) + ': transaction_id ' + both[i].transaction_id + ', tr_id ' + both[i].tr_id; }
                if (both[i].metadata.app_name !== 'Apigee-Gateway') { return 'scan ' + (i + 1) + ': app_name ' + both[i].metadata.app_name; }
            }
            if (JSON.stringify(q.scans[0].contents) !== JSON.stringify([{ prompt: 'hello there' }])) { return 'prompt scan ' + JSON.stringify(q.scans[0].contents); }
            var c = p.scans[0].contents;
            if (c.length !== 1 || c[0].prompt !== 'hello there' || c[0].response !== text) { return 'reply scan ' + JSON.stringify(c); }
            return S.check(p.status === 200 && p.body === reply.content, 'the reply did not reach the client unchanged');
        }
    });
});

FMTS.forEach(function (fmt) {
    [false, true].forEach(function (st) {
        cases.push({
            finding: 'MS-block-prompt',
            title: 'run.py:158 block_prompt_' + MS[fmt] + '_' + (st ? 'sse' : 'json') + ': refused in the client\'s own format' + (st ? ', its own event stream,' : '') + ' with the scan id (v3: HTTP 200, x-airs-kind block; MuleSoft 403); the model is never called',
            setup: setup(ask(fmt, CARD_PROMPT, { stream: st }), { legs: ['request', 'response'], airs: R.answers('block-dlp-prompt-masked'), response: S.reply(replyFor(fmt, 'unused')) }),
            v3: function (r) {
                var q = r.request;
                if (!refusedAs(q, 'block')) { return 'not refused as a block'; }
                if (r.response) { return 'the request reached the model'; }
                if (q.status !== 200 || hdr(q, 'x-airs-scan-id') !== 'SCAN_ID') { return 'status ' + q.status + ', x-airs-scan-id ' + hdr(q, 'x-airs-scan-id'); }
                if (isStream(q) !== st) { return 'content type ' + q.contentType; }
                var m = said(fmt, q);
                return S.check(m && m.indexOf('Request blocked by Prisma AIRS security policy.') === 0 && m.indexOf('Scan ID: SCAN_ID.') !== -1, 'message ' + JSON.stringify(m));
            }
        });
    });
});

FMTS.forEach(function (fmt) {
    [false, true].forEach(function (st) {
        cases.push({
            finding: 'MS-block-reply',
            title: 'run.py:170 block_reply_' + MS[fmt] + '_' + (st ? 'sse' : 'json') + ': the blocked reply is replaced and none of it reaches the client' +
                   (st ? ' (v3 turned the stream off, so the model answered JSON; the refusal is the client\'s own event stream, not MuleSoft\'s JSON 403)' : ' (v3: HTTP 200 in the client\'s format)'),
            setup: setup(ask(fmt, 'What card is on file?', { stream: st }), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: S.reply(replyFor(fmt, CARD_REPLY)) }),
            v3: function (r) {
                var q = r.request, p = r.response;
                if (!q || q.fault || !p) { return 'the request leg did not pass'; }
                if (st) {
                    var off = fmt === 'gemini' ? /:generateContent$/.test(q.flow.get('target.url') || '') : JSON.parse(fwd(q)).stream === false;
                    if (!off || !q.flow.get('airs3.destreamed')) { return 'streaming was not turned off on the way to the model'; }
                }
                if (!refusedAs(p, 'block') || p.status !== 200) { return 'the reply was not refused as a block'; }
                if (isStream(p) !== st) { return 'content type ' + p.contentType; }
                if (p.body.indexOf(C) !== -1 || p.body.indexOf('card on file') !== -1) { return 'the reply leaked to the client'; }
                var m = said(fmt, p);
                return S.check(m && m.indexOf('Response blocked by Prisma AIRS security policy.') === 0 && m.indexOf('Scan ID: SCAN_ID.') !== -1, 'message ' + JSON.stringify(m));
            }
        });
    });
});

/* ---- run.py:191-303, failures, gaps, settings and ids ------------------------------------------------------------ */
cases.push({
    finding: 'MS-airs-slow',
    title: 'run.py:191 airs_slow_is_503_within_bound: no answer within the callout\'s fixed 5,000 ms is a scanner failure, refused (v3: x-airs-kind failure in the client\'s format; MuleSoft 503 within 3 s); the model is never called',
    setup: setup(ask('chat', 'hello'), { legs: ['request', 'response'], airs: R.answers(R.noAnswer('timeout')), response: S.reply(replyFor('chat', 'unused')) }),
    v3: function (r) {
        var q = r.request;
        if (q.calls.length !== 1 || q.calls[0].timeout !== 5000) { return 'the scan is not bounded at 5,000 ms'; }
        if (!refusedAs(q, 'failure') || r.response) { return 'not refused as a scanner failure before the model'; }
        var m = said('chat', q);
        return S.check(m && m.indexOf('could not scan') !== -1, 'message ' + JSON.stringify(m));
    }
});
cases.push({
    finding: 'MS-airs-500',
    title: 'run.py:201 airs_500_is_503_and_fail_open_is_recorded (default): an HTTP 500 from Prisma AIRS is a scanner failure, refused (v3: x-airs-kind failure); the model is never called',
    setup: setup(ask('chat', 'hello'), { legs: ['request', 'response'], airs: R.answers(R.status(500, { error: { message: 'internal error' } })), response: S.reply(replyFor('chat', 'unused')) }),
    v3: function (r) { return S.check(refusedAs(r.request, 'failure') && !r.response, 'an HTTP 500 was not refused as a scanner failure'); }
});
cases.push({
    finding: 'MS-airs-500',
    title: 'run.py:201 airs_500_is_503_and_fail_open_is_recorded (failOpen=true, v3\'s onApiError=allow): the exchange passes, and the log line records the request leg as failed open',
    setup: setup(ask('chat', 'hello', { headers: { 'x-correlation-id': 'itest-failopen' } }), { legs: ['request', 'response'], vars: { failOpen: 'true' },
        airs: R.answers(R.status(500, { error: { message: 'internal error' } }), 'allow-prompt-response'), response: S.reply(replyFor('chat', 'Hello!')) }),
    v3: function (r) {
        var q = r.request, p = r.response;
        if (!q || q.fault || !p || p.fault) { return 'the exchange did not pass'; }
        var l = logLine(q, 0);
        return S.check(l && l.leg === 'request' && l.outcome === 'allow' && /^failed open/.test(l.note) && l.airs_status === '500' && l.transaction_id === 'itest-failopen', 'log line ' + JSON.stringify(l));
    }
});
// MuleSoft's DETECTORFAIL verdict: the recorded allow, reporting a detector error (synthetic, as A15's case does).
function degradedAllow() {
    var a = R.recorded('allow-prompt');
    a.body = Object.assign({}, a.body, { error: true, errors: [{ content_type: 'prompt', feature: 'dlp', status: 'error' }] });
    a.synthetic = 'error set to true';
    return a;
}
cases.push({
    finding: 'MS-detector-fail',
    title: 'run.py:213 detector_failure_is_503 (anthropic): an allow that reports a detector error is a scanner failure, refused in the client\'s format (synthetic reply)',
    setup: setup(ask('anthropic', 'hello'), { legs: ['request', 'response'], airs: R.answers(degradedAllow()), response: S.reply(replyFor('anthropic', 'unused')) }),
    v3: function (r) { var m = said('anthropic', r.request); return S.check(refusedAs(r.request, 'failure') && !r.response && m && m.indexOf('could not scan') !== -1, 'the degraded allow was not refused as a failure: ' + JSON.stringify(m)); }
});
cases.push({
    finding: 'MS-garbage',
    title: 'run.py:220 garbage_verdict_is_503 (gemini): an HTTP 200 whose body is not JSON is a scanner failure, refused in the client\'s format',
    setup: setup(ask('gemini', 'hello'), { legs: ['request', 'response'], airs: R.answers(R.status(200, '<<not a verdict>>')), response: S.reply(replyFor('gemini', 'unused')) }),
    v3: function (r) { var m = said('gemini', r.request); return S.check(refusedAs(r.request, 'failure') && !r.response && m && m.indexOf('could not scan') !== -1, 'the unreadable verdict was not refused as a failure: ' + JSON.stringify(m)); }
});

const UNKNOWN = { model: 'm', messages: [{ role: 'user', content: 'hi' }] };
cases.push({
    finding: 'MS-unknown-format',
    title: 'run.py:236 unknown_format_gap: a messages body on an unknown path, with no format header, gets HTTP 403 with an OpenAI-style "could not inspect" error, unscanned and not forwarded',
    setup: setup(S.req('/x/v2/chat', UNKNOWN), { legs: ['request', 'response'], airs: R.answers('allow-prompt'), response: S.reply(replyFor('chat', 'unused')) }),
    v3: function (r) {
        var q = r.request, b = rpcBody(q);
        if (!refusedAs(q, 'refused') || q.status !== 403 || q.calls.length !== 0 || r.response) { return 'not refused, unscanned, with 403'; }
        return S.check(b && b.error && b.error.type === 'prisma_airs_refused' && b.error.message.indexOf('could not inspect') !== -1, 'body ' + q.body);
    }
});
cases.push({
    finding: 'MS-unknown-format',
    title: 'run.py:236 unknown_format_gap (onScanError=allow): the same request passes unscanned, and so does its reply',
    setup: setup(S.req('/x/v2/chat', UNKNOWN), { legs: ['request', 'response'], vars: { onScanError: 'allow' }, airs: R.answers('allow-prompt'), response: S.reply(replyFor('chat', 'Hi.')) }),
    v3: function (r) {
        var q = r.request, p = r.response;
        return S.check(q && !q.fault && q.calls.length === 0 && p && !p.fault && p.calls.length === 0 && fwd(q) === JSON.stringify(UNKNOWN), 'the allowed gap did not pass unscanned');
    }
});
cases.push({
    finding: 'MS-get-no-body',
    title: 'run.py:248 get_without_body: a GET with no body is not scanned and passes, and neither is its reply',
    setup: { path: '/v1/models', request: { verb: 'GET', headers: {}, content: '' }, legs: ['request', 'response'], airs: R.answers('allow-prompt'), response: S.reply({ object: 'list', data: [] }) },
    v3: function (r) {
        var q = r.request, p = r.response;
        return S.check(q && !q.fault && q.calls.length === 0 && p && !p.fault && p.calls.length === 0 && p.flow.get('airs3.route') === 'pass', 'the GET was scanned or refused');
    }
});
cases.push({
    finding: 'MS-trunc-closed',
    title: 'run.py:256 truncation_fail_closed: over maxScanChars (50) the request is refused, with no scan and no forward (v3: x-airs-kind refused)',
    setup: setup(ask('chat', new Array(101).join('a')), { legs: ['request', 'response'], vars: { maxScanChars: '50' }, airs: R.answers('allow-prompt'), response: S.reply(replyFor('chat', 'unused')) }),
    v3: function (r) { var q = r.request; return S.check(refusedAs(q, 'refused') && q.calls.length === 0 && !r.response, 'the over-limit prompt was scanned or forwarded'); }
});
cases.push({
    finding: 'MS-trunc-open',
    title: 'run.py:264 truncation_open_scans_newest_n: with truncationFailClosed=false the newest 50 characters are scanned, the request goes on whole, and the log line says so',
    setup: setup(ask('chat', new Array(101).join('a') + new Array(51).join('b')), { legs: ['request', 'response'], vars: { maxScanChars: '50', truncationFailClosed: 'false' },
        airs: R.answers('allow-prompt', 'allow-prompt-response'), response: S.reply(replyFor('chat', 'Fine.')) }),
    v3: function (r) {
        var q = r.request, p = r.response, newest = new Array(51).join('b');
        if (!q || q.fault || !p || p.fault) { return 'the exchange did not pass'; }
        if (JSON.stringify(q.scans[0].contents) !== JSON.stringify([{ prompt: newest }])) { return 'scanned ' + JSON.stringify(q.scans[0].contents); }
        if (JSON.parse(fwd(q)).messages[0].content !== new Array(101).join('a') + newest) { return 'the forwarded prompt changed'; }
        var l = logLine(q, 0);
        return S.check(l && /newest 50/.test(l.note), 'log line ' + JSON.stringify(l));
    }
});
FMTS.forEach(function (fmt) {
    cases.push({
        finding: 'MS-misconfigured',
        title: 'run.py:274 misconfigured_is_503_for_all (' + MS[fmt] + '): a setting v3 refuses refuses the request in the client\'s own format, saying "not configured correctly" and naming the setting, never its value (v3: HTTP 200, x-airs-kind config; MuleSoft 503)',
        setup: setup(ask(fmt, 'hello'), { legs: ['request', 'response'], vars: { prismaAirsEndpoint: BAD_ENDPOINT }, airs: R.answers('allow-prompt'), response: S.reply(replyFor(fmt, 'unused')) }),
        v3: function (r) {
            var q = r.request;
            if (!refusedAs(q, 'config') || q.calls.length !== 0 || r.response) { return 'not refused as a configuration problem before any scan'; }
            if (q.body.indexOf('scan/sync') !== -1) { return 'the refusal holds the setting\'s value'; }
            var m = said(fmt, q);
            if (!m || m.indexOf('not configured correctly') === -1 || m.indexOf('prismaAirsEndpoint') === -1) { return 'not in the client\'s format: HTTP ' + q.status + ' ' + q.body.slice(0, 160); }
            return S.check(q.status === 200, 'status ' + q.status);
        }
    });
});
cases.push({
    finding: 'MS-long-session',
    title: 'run.py:284 long_session_header: a 150-character x-session-id is skipped, never cut, and the scan goes on without a session_id (v3 logs no drop reason)',
    setup: setup(ask('chat', 'hello', { headers: { 'x-session-id': new Array(151).join('s'), 'x-correlation-id': 'itest-session' } }), { legs: ['request'], airs: R.answers('allow-prompt') }),
    v3: function (r) { var q = r.request; return S.check(!q.fault && q.scans.length === 1 && !('session_id' in q.scans[0]) && q.scans[0].transaction_id === 'itest-session', 'session_id ' + (q.scans[0] && q.scans[0].session_id)); }
});
cases.push({
    finding: 'MS-long-session',
    title: 'run.py:284 long_session_header (v3\'s next source): with the long x-session-id skipped, x-claude-code-session-id is used',
    setup: setup(ask('chat', 'hello', { headers: { 'x-session-id': new Array(151).join('s'), 'x-claude-code-session-id': 'conv-7' } }), { legs: ['request'], airs: R.answers('allow-prompt') }),
    v3: function (r) { var q = r.request; return S.check(!q.fault && q.scans.length === 1 && q.scans[0].session_id === 'conv-7', 'session_id ' + (q.scans[0] && q.scans[0].session_id)); }
});
cases.push({
    finding: 'MS-accept-encoding',
    title: 'run.py:304 accept_encoding_removed: the request v3 forwards has no Accept-Encoding',
    setup: setup(ask('chat', 'hello', { headers: { 'Accept-Encoding': 'gzip' } }), { legs: ['request'], airs: R.answers('allow-prompt') }),
    v3: function (r) { var q = r.request; return S.check(!q.fault && q.calls.length === 1 && q.request.header('Accept-Encoding') === null, 'Accept-Encoding ' + q.request.header('Accept-Encoding')); }
});

/* ---- run.py:341-488, masking, tool calls, streams, sizes, roles ------------------------------------------------ */
cases.push({
    finding: 'MS-mask-stream-req',
    title: 'run.py:341 masking_rewrites_prompt_of_streamed_request: a request body is never a stream, so a streamed call\'s prompt is masked (applyDlpMasking=true); v3 also turns the stream off (L1), MuleSoft keeps stream: true',
    setup: setup(ask('chat', CARD_PROMPT, { stream: true }), { legs: ['request'], vars: { applyDlpMasking: 'true' }, airs: R.answers('block-dlp-prompt-masked') }),
    v3: function (r) {
        var q = r.request, b = JSON.parse(fwd(q));
        if (q.fault) { return 'refused: ' + q.body.slice(0, 160); }
        if (b.messages[0].content !== 'Please store my card ' + MASKED + ' for the next order.' || fwd(q).indexOf(C) !== -1) { return 'forwarded ' + fwd(q).slice(0, 200); }
        return S.check(b.stream === false && q.flow.get('airs3.destreamed') === 'chat-sse', 'streaming was not turned off');
    }
});
cases.push({
    finding: 'MS-mask-reply',
    title: 'run.py:352 masking_rewrites_reply (anthropic): a JSON reply is masked in place (applyDlpMasking=true)',
    setup: setup(ask('anthropic', 'What card is on file?'), { legs: ['request', 'response'], vars: { applyDlpMasking: 'true' }, airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
        response: S.reply(replyFor('anthropic', CARD_REPLY)) }),
    v3: function (r) {
        var p = r.response;
        if (!p || p.fault) { return 'the reply was refused'; }
        return S.check(JSON.parse(p.body).content[0].text === 'The card on file is ' + MASKED + '.' && p.body.indexOf(C) === -1, 'client got ' + p.body.slice(0, 200));
    }
});
cases.push({
    finding: 'MS-mask-on-stream',
    title: 'run.py:360 masking_on_stream_blocks: a reply that arrives as an event stream is never masked; the masking verdict blocks it and none of it leaks (reply leg alone, on a runtime that shows the stream)',
    setup: setup(ask('chat', 'What card is on file?', { stream: true }), { legs: ['response'], vars: { applyDlpMasking: 'true' }, airs: R.answers('block-dlp-response-masked'),
        response: stream(replyStream('chat', CARD_REPLY)) }),
    v3: function (r) {
        var p = r.response;
        if (!p || p.calls.length !== 1 || !S.has(p, CARD_REPLY)) { return 'the stream was not read whole'; }
        return S.check(refusedAs(p, 'block') && isStream(p) && p.body.indexOf(C) === -1 && p.body.indexOf('card on file') === -1, 'the stream was masked or leaked: ' + String(p.body).slice(0, 160));
    }
});
cases.push({
    finding: 'MS-mask-on-stream',
    title: 'run.py:360 masking_on_stream_blocks (v3\'s G9, a deliberate difference): a streamed call v3 turned off arrives as JSON, so it is masked, then sent back as one burst of the client\'s stream',
    setup: setup(ask('chat', 'What card is on file?', { stream: true }), { legs: ['request', 'response'], vars: { applyDlpMasking: 'true' }, airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
        response: S.reply(replyFor('chat', CARD_REPLY)) }),
    v3: function (r) {
        var p = r.response;
        if (!p || p.fault) { return 'the reply was refused: ' + (p ? p.body.slice(0, 160) : ''); }
        return S.check(isStream(p) && said('chat', p) === 'The card on file is ' + MASKED + '.' && p.body.indexOf(C) === -1, 'client got ' + String(p.body).slice(0, 200));
    }
});
cases.push({
    finding: 'MS-mask-off',
    title: 'run.py:368 masking_off_blocks_dlp: with applyDlpMasking off (the default), the sensitive-data verdict refuses the request; the model is never called',
    setup: setup(ask('chat', CARD_PROMPT), { legs: ['request', 'response'], airs: R.answers('block-dlp-prompt-masked'), response: S.reply(replyFor('chat', 'unused')) }),
    v3: function (r) { var q = r.request; return S.check(refusedAs(q, 'block') && !r.response && q.body.indexOf(C) === -1, 'not refused before the model'); }
});

FMTS.forEach(function (fmt) {
    [false, true].forEach(function (st) {
        var text = 'Card on file: ' + C;
        cases.push({
            finding: 'MS-tool-n2',
            title: 'run.py:376 tool_and_n2_blocks (' + MS[fmt] + ', ' + (st ? 'streamed' : 'JSON') + '): a reply that is only a tool call is read, not taken as empty, and the named block refuses it' +
                   (st ? ' (reply leg alone, on a runtime that shows the stream)' : ''),
            setup: st ? setup(ask(fmt, 'hello', { stream: true }), { legs: ['response'], airs: R.answers('block-dlp-response-masked'), response: stream(toolStream(fmt, text)) })
                      : setup(ask(fmt, 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: S.reply(toolReply(fmt, text)) }),
            v3: function (r) {
                var p = r.response;
                if (!p || p.calls.length !== 1) { return 'the tool-call-only reply was not scanned'; }
                if (!S.has(p, 'send_email') || !S.has(p, C)) { return 'the tool call is missing from the scan: ' + JSON.stringify(p.scanned).slice(0, 200); }
                if (!refusedAs(p, 'block') || isStream(p) !== st) { return 'not refused in the client\'s format'; }
                return S.check(p.body.indexOf(C) === -1, 'the tool call reached the client');
            }
        });
    });
});
cases.push({
    finding: 'MS-tool-n2',
    title: 'run.py:376 tool_and_n2_blocks (n=2): the second of two choices is read, and the named block refuses the reply',
    setup: setup(ask('chat', 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
        response: S.reply({ choices: [{ index: 0, message: { content: 'fine' } }, { index: 1, message: { content: 'Card on file: ' + C } }] }) }),
    v3: function (r) { var p = r.response; return S.check(p && S.has(p, 'fine') && S.has(p, C) && refusedAs(p, 'block') && p.body.indexOf(C) === -1, 'the second choice was not read or not refused'); }
});
cases.push({
    finding: 'MS-sse-edge',
    title: 'run.py:397 sse_edge_events: Azure\'s empty first event, comments, CRLF, "data:" with no space and a text split over two events read as "hello world"; the allowed stream passes as sent (reply leg alone, on a runtime that shows the stream)',
    setup: setup(ask('chat', 'hello', { stream: true }), { legs: ['response'], airs: R.answers('allow-prompt-response'), response: stream(edgeStream('hello world')) }),
    v3: function (r) {
        var p = r.response;
        if (!p || p.scans.length !== 1) { return 'the stream was not scanned once'; }
        if (JSON.stringify(p.scans[0].contents) !== JSON.stringify([{ response: 'hello world' }])) { return 'scanned ' + JSON.stringify(p.scans[0].contents); }
        return S.check(!p.fault && p.body === edgeStream('hello world'), 'the allowed stream did not pass as sent');
    }
});
cases.push({
    finding: 'MS-sse-edge',
    title: 'run.py:397 sse_edge_events (block): the same edge stream carrying the card is read whole, and the named block refuses it',
    setup: setup(ask('chat', 'hello', { stream: true }), { legs: ['response'], airs: R.answers('block-dlp-response-masked'), response: stream(edgeStream('Card on file: ' + C)) }),
    v3: function (r) { var p = r.response; return S.check(p && S.has(p, 'Card on file: ' + C) && refusedAs(p, 'block') && p.body.indexOf(C) === -1, 'the split text was not read whole or not refused'); }
});

const BIG = new Array(2 * 1024 * 1024 + 1).join('a');                         // MuleSoft's 2 MiB reply
cases.push({
    finding: 'MS-oversized-reply',
    title: 'run.py:441 oversized_reply_never_passes (JSON): a 2 MiB reply is over maxScanChars, so it is withheld without a scan and none of it reaches the client',
    setup: setup(ask('chat', 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: S.reply(replyFor('chat', BIG)) }),
    v3: function (r) { var p = r.response; return S.check(p && refusedAs(p, 'refused') && p.calls.length === 0 && p.body.indexOf('aaaa') === -1, 'the 2 MiB reply passed or was scanned'); }
});
cases.push({
    finding: 'MS-oversized-reply',
    title: 'run.py:441 oversized_reply_never_passes (streamed): a 2 MiB event stream is withheld the same way (reply leg alone, on a runtime that shows the stream)',
    setup: setup(ask('chat', 'hello', { stream: true }), { legs: ['response'], airs: R.answers('allow-prompt-response'), response: stream(replyStream('chat', BIG)) }),
    v3: function (r) { var p = r.response; return S.check(p && refusedAs(p, 'refused') && p.calls.length === 0 && p.body.indexOf('aaaa') === -1, 'the 2 MiB stream passed or was scanned'); }
});
const SPEECH = S.reply(speech(2));
cases.push({
    finding: 'MS-speech',
    title: 'run.py:450 gemini_speech_reply_passes (JSON): two seconds of headerless audio pass unchanged, its bytes left out of the scan',
    setup: setup(ask('gemini', 'say hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: SPEECH }),
    v3: function (r) {
        var p = r.response, rep = p && p.scans[0] && p.scans[0].contents[0].response;
        if (!p || p.fault || p.body !== SPEECH.content) { return 'the speech reply did not pass unchanged'; }
        return S.check(typeof rep === 'string' && rep.indexOf('<binary,') !== -1 && rep.length < 10000, 'the audio bytes were scanned: ' + String(rep).slice(0, 120));
    }
});
const SPEECH_STREAM = stream([0, 1, 2, 3].map(function () { return ev(null, speech(0.5), '\r\n'); }).join(''));
cases.push({
    finding: 'MS-speech',
    title: 'run.py:450 gemini_speech_reply_passes (streamed): half-second audio chunks pass as sent, their bytes left out of the scan (reply leg alone, on a runtime that shows the stream)',
    setup: setup(ask('gemini', 'say hello', { stream: true }), { legs: ['response'], airs: R.answers('allow-prompt-response'), response: SPEECH_STREAM }),
    v3: function (r) {
        var p = r.response, rep = p && p.scans[0] && p.scans[0].contents[0].response;
        if (!p || p.fault || p.body !== SPEECH_STREAM.content) { return 'the speech stream did not pass as sent'; }
        return S.check(typeof rep === 'string' && rep.indexOf('<binary,') !== -1 && rep.length < 10000, 'the audio bytes were scanned: ' + String(rep).slice(0, 120));
    }
});
cases.push({
    finding: 'MS-compressed',
    title: 'run.py:461 compressed_reply_is_a_gap (gzip, a measured difference): this runtime hands the flow a gzip reply decompressed (L3), so v3 scans it like any JSON reply',
    setup: setup(ask('chat', 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
        response: { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, content: JSON.stringify(replyFor('chat', 'compressed reply')) } }),
    v3: function (r) { var p = r.response; return S.check(p && !p.fault && p.calls.length === 1 && S.has(p, 'compressed reply'), 'the decompressed reply was not scanned and passed'); }
});
cases.push({
    finding: 'MS-compressed',
    title: 'run.py:461 compressed_reply_is_a_gap (deflate): a reply whose bytes the flow sees compressed is refused as "could not inspect", unscanned (v3: x-airs-kind refused; MuleSoft 403)',
    setup: setup(ask('chat', 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
        response: { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'deflate' }, content: zlib.deflateSync(Buffer.from(JSON.stringify(replyFor('chat', 'compressed reply')))).toString('latin1') } }),
    v3: function (r) {
        var p = r.response, m = p && said('chat', p);
        return S.check(p && refusedAs(p, 'refused') && p.calls.length === 0 && m && m.indexOf('could not inspect') !== -1, 'the compressed reply was not refused: ' + JSON.stringify(m));
    }
});
FMTS.forEach(function (fmt) {
    var sys = 'You answer questions about the bakery. Card on file: ' + C;
    cases.push({
        finding: 'MS-roles-system',
        title: 'run.py:469 scan_roles_system (' + MS[fmt] + ', default roles): the system text is not scanned, so the named allow passes it',
        setup: setup(ask(fmt, 'hello', { system: sys }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { var q = r.request; return S.check(!q.fault && q.calls.length === 1 && S.has(q, 'hello') && !S.has(q, C), 'scanned ' + JSON.stringify(q.scanned).slice(0, 160)); }
    });
    cases.push({
        finding: 'MS-roles-system',
        title: 'run.py:469 scan_roles_system (' + MS[fmt] + ', scanMessageRoles=user,system): the system text is scanned first, and the named block refuses before the model',
        setup: setup(ask(fmt, 'hello', { system: sys }), { legs: ['request', 'response'], vars: { scanMessageRoles: 'user,system' }, airs: R.answers('block-dlp-prompt-masked'), response: S.reply(replyFor(fmt, 'unused')) }),
        v3: function (r) {
            var q = r.request;
            if (!S.has(q, C) || q.scanned.indexOf(C) > q.scanned.indexOf('hello')) { return 'the system text was not scanned first: ' + JSON.stringify(q.scanned).slice(0, 160); }
            return S.check(refusedAs(q, 'block') && !r.response, 'not refused before the model');
        }
    });
});
cases.push({
    finding: 'MS-upstream-error',
    title: 'run.py:480 upstream_error_passes_unscanned: a 429 reply passes unscanned (phase 1, as in MuleSoft; A31 is phase 3)',
    setup: setup(ask('chat', 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
        response: { status: 429, headers: { 'Content-Type': 'application/json' }, content: JSON.stringify({ error: { message: 'upstream error' } }) } }),
    v3: function (r) { var p = r.response; return S.check(p && !p.fault && p.calls.length === 0 && p.status === 429, 'the 429 reply was scanned or refused'); }
});
cases.push({
    finding: 'MS-empty-reply',
    title: 'run.py:488 empty_reply_passes (gemini): a reply with no text passes, unscanned',
    setup: setup(ask('gemini', 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: S.reply(replyFor('gemini', '')) }),
    v3: function (r) { var p = r.response; return S.check(p && !p.fault && p.calls.length === 0 && p.flow.get('airs3.route') === 'pass', 'the empty reply was scanned or refused'); }
});
cases.push({
    finding: 'MS-empty-reply',
    title: 'run.py:488 empty_reply_passes (v3\'s A21 guard, a deliberate difference): a 200 with no body is withheld, because the flow can\'t tell it from an event stream it can\'t see',
    setup: setup(ask('gemini', 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: { status: 200, headers: { 'Content-Type': 'application/json' }, content: '' } }),
    v3: function (r) { var p = r.response; return S.check(p && refusedAs(p, 'refused') && p.calls.length === 0, 'the empty 200 was not withheld'); }
});
cases.push({
    finding: 'MS-empty-reply',
    title: 'run.py:488 empty_reply_passes (204): a 204 with no body passes, unscanned',
    setup: setup(ask('gemini', 'hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: { status: 204, headers: {}, content: '' } }),
    v3: function (r) { var p = r.response; return S.check(p && !p.fault && p.calls.length === 0 && p.status === 204, 'the 204 was scanned or refused'); }
});

/* ---- run.py:536-557, earlier turns, documents, masking across turns --------------------------------------------- */
const FIRST = 'My card number is ' + C + '. Please remember it.';
const HISTORY = {
    chat: { model: 'gpt-test', messages: [{ role: 'user', content: FIRST }, { role: 'assistant', content: 'Noted.' }, { role: 'user', content: 'hello' }] },
    responses: { model: 'gpt-test', input: [{ role: 'user', content: FIRST }, { role: 'assistant', content: 'Noted.' }, { role: 'user', content: 'hello' }] },
    anthropic: { model: 'claude-test', max_tokens: 50, messages: [{ role: 'user', content: FIRST }, { role: 'assistant', content: 'Noted.' }, { role: 'user', content: 'hello' }] },
    gemini: { contents: [{ role: 'user', parts: [{ text: FIRST }] }, { role: 'model', parts: [{ text: 'Noted.' }] }, { role: 'user', parts: [{ text: 'hello' }] }] }
};
FMTS.forEach(function (fmt) {
    cases.push({
        finding: 'MS-earlier-turn',
        title: 'run.py:536 earlier_user_turn_is_scanned (' + MS[fmt] + '): the first of three turns is scanned with the newest (the assistant turn is not, by default), and the named block refuses before the model',
        setup: setup(ask(fmt, '', { body: HISTORY[fmt] }), { legs: ['request', 'response'], airs: R.answers('block-dlp-prompt-masked'), response: S.reply(replyFor(fmt, 'unused')) }),
        v3: function (r) {
            var q = r.request;
            if (!S.has(q, FIRST) || !S.has(q, 'hello') || S.has(q, 'Noted.')) { return 'scanned ' + JSON.stringify(q.scanned).slice(0, 160); }
            return S.check(refusedAs(q, 'block') && !r.response, 'not refused before the model');
        }
    });
});
cases.push({
    finding: 'MS-document',
    title: 'run.py:546 document_part_is_scanned: an Anthropic text document\'s data is scanned with the text block, and the named block refuses before the model',
    setup: setup(ask('anthropic', '', { body: { model: 'claude-test', max_tokens: 50, messages: [{ role: 'user', content: [
        { type: 'document', source: { type: 'text', media_type: 'text/plain', data: 'Card on file: ' + C } }, { type: 'text', text: 'summarise the document' }] }] } }),
        { legs: ['request', 'response'], airs: R.answers('block-dlp-prompt-masked'), response: S.reply(replyFor('anthropic', 'unused')) }),
    v3: function (r) { var q = r.request; return S.check(S.has(q, 'Card on file: ' + C) && S.has(q, 'summarise the document') && refusedAs(q, 'block') && !r.response, 'the document was not scanned or not refused'); }
});
// mask-v3-chat-two-blocks was recorded for exactly this scan text: "Please store this card for the next order.\nCard number: <card>".
const TURNS = { model: 'gpt-test', messages: [{ role: 'user', content: 'Please store this card for the next order.' }, { role: 'assistant', content: 'Noted.' }, { role: 'user', content: 'Card number: ' + C }] };
cases.push({
    finding: 'MS-mask-turns',
    title: 'run.py:557 masking_rewrites_every_user_turn: masked text goes back into each scanned user turn, the assistant turn untouched (the card in the second turn only; 58-ms-fixture-cases.js has a card in both)',
    setup: setup(ask('chat', '', { body: TURNS }), { legs: ['request'], vars: { applyDlpMasking: 'true' }, airs: R.answers('mask-v3-chat-two-blocks') }),
    v3: function (r) {
        var q = r.request, m = JSON.parse(fwd(q)).messages;
        if (q.fault) { return 'refused: ' + q.body.slice(0, 160); }
        return S.check(m[0].content === 'Please store this card for the next order.' && m[1].content === 'Noted.' && m[2].content === 'Card number: ' + MASKED && fwd(q).indexOf(C) === -1, 'forwarded ' + fwd(q).slice(0, 240));
    }
});

/* ---- run.py:601-921, MCP ------------------------------------------------------------------------------------------- */
cases.push({
    finding: 'MS-mcp-initialize',
    title: 'run.py:601 mcp_initialize_reply_is_scanned: the initialize reply\'s instructions reach the scan as text, not a tool event, and the reply passes (the initialize request\'s params are not scanned: v3 reads it as a catalogue call)',
    setup: setup(rpc(INIT), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
        response: answer(1, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'mock-mcp', version: '1.0' }, instructions: 'Use the tools politely.' }) }),
    v3: function (r) {
        var p = r.response;
        if (!p || p.fault || p.body.indexOf('mock-mcp') === -1) { return 'the initialize reply did not reach the client'; }
        return S.check(p.scans.length === 1 && tools(p).length === 0 && S.has(p, 'Use the tools politely.'), 'the instructions were not scanned as text');
    }
});
cases.push({
    finding: 'MS-mcp-tools-list',
    title: 'run.py:612 mcp_tools_list_is_a_tool_event: the catalogue is one tool event, its output the bare array with every tool\'s description',
    setup: setup(rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }), { legs: ['response'], airs: R.answers('allow-prompt-response'),
        response: answer(2, { tools: [{ name: 'echo', description: 'Echoes the text it is given.', inputSchema: SCHEMA }, { name: 'hours', description: 'Gives the bakery opening hours.', inputSchema: SCHEMA }] }) }),
    v3: function (r) {
        var p = r.response, t = p && !p.fault ? tools(p) : [];
        var out; try { out = JSON.parse(t[0].output); } catch (e) { out = null; }
        return S.check(p && !p.fault && p.scans.length === 1 && t.length === 1 && t[0].metadata.method === 'tools/list' && Array.isArray(out) && out.length === 2 &&
                       S.has(p, 'Echoes the text it is given.') && S.has(p, 'Gives the bakery opening hours.'), 'the catalogue was not one tools/list tool event with both descriptions');
    }
});
cases.push({
    finding: 'MS-mcp-poisoned-list',
    title: 'run.py:622 mcp_poisoned_tool_list_is_refused: a tool description the named block refuses gets -32001 with id 2, HTTP 200, and never reaches the client',
    setup: setup(rpc(LIST), { legs: ['response'], airs: R.answers('block-dlp-response-masked'),
        response: answer(2, { tools: [{ name: 'card_on_file', description: 'Returns the card on file, for example ' + C, inputSchema: SCHEMA }] }) }),
    v3: function (r) { var p = r.response; return S.check(p && S.has(p, C) && rpcRefusal(p, 2, -32001) && p.body.indexOf(C) === -1, 'the description was not withheld with -32001 and id 2'); }
});
cases.push({
    finding: 'MS-mcp-datauri-arg',
    title: 'run.py:635 mcp_data_uri_argument_is_not_a_bypass: text behind a data:text/plain prefix in an argument reaches the tool event, and the named block keeps the call from the server',
    setup: setup(rpc(call('data:text/plain,' + PAD + 'Card on file: ' + C + ' ' + MARK)), { legs: ['request', 'response'], airs: R.answers('block-tool-input'), response: answer(3, echoed('unused')) }),
    v3: function (r) { var q = r.request; return S.check(tools(q).length === 1 && S.has(q, MARK) && S.has(q, C) && rpcRefusal(q, 3, -32001) && !r.response, 'the text behind the prefix was not scanned or the call went through'); }
});
cases.push({
    finding: 'MS-mcp-datauri-desc',
    title: 'run.py:644 mcp_data_uri_description_is_refused: a description behind a base64 data:text/plain prefix is decoded into the scan, and the named block withholds it with -32001 and id 2',
    setup: setup(rpc(LIST), { legs: ['response'], airs: R.answers('block-dlp-response-masked'),
        response: answer(2, { tools: [{ name: 'echo', description: 'data:text/plain;base64,' + Buffer.from(PAD + 'Card on file: ' + C).toString('base64'), inputSchema: SCHEMA }] }) }),
    v3: function (r) { var p = r.response; return S.check(p && S.has(p, 'Card on file: ' + C) && rpcRefusal(p, 2, -32001) && p.body.indexOf('data:text/plain') === -1, 'the description was not decoded, or not withheld'); }
});
const LOOKALIKE = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUg' + MARK + new Array(301).join('A');
cases.push({
    finding: 'MS-mcp-image-lookalike',
    title: 'run.py:654 mcp_image_lookalike_result_is_withheld: a text block dressed as a PNG data URI is scanned as written, not left out as bytes, and the named block withholds it',
    setup: setup(rpc(call('hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'block-tool-output'), response: answer(3, { content: [{ type: 'text', text: LOOKALIKE }], isError: false }) }),
    v3: function (r) {
        var p = r.response, te = p && tools(p)[0];
        return S.check(te && String(te.output).indexOf(LOOKALIKE) !== -1 && rpcRefusal(p, 3, -32001) && p.body.indexOf(MARK) === -1, 'the look-alike was left out of the scan or reached the client');
    }
});
const PNG = png64(), PCM = pcm64(0.1);
const MEDIA = { content: [{ type: 'text', text: 'echo: {"text": "hello"}' }, { type: 'image', mimeType: 'image/png', data: PNG }, { type: 'audio', mimeType: 'audio/pcm', data: PCM }], isError: false };
cases.push({
    finding: 'MS-mcp-media',
    title: 'run.py:664 mcp_media_result_passes: a real PNG and headerless audio in a tool result pass to the client, each left out of the reply-leg tool event as a placeholder',
    setup: setup(rpc(call('hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), response: answer(3, MEDIA) }),
    v3: function (r) {
        var p = r.response, te = p && tools(p)[0];
        if (!p || p.fault) { return 'the media result was refused'; }
        var kinds = JSON.parse(p.body).result.content.map(function (c) { return c.type; }).join(',');
        if (kinds !== 'text,image,audio') { return 'the client got ' + kinds; }
        return S.check(te && String(te.output).split('<binary,').length - 1 === 2 && String(te.output).indexOf(PNG.slice(0, 40)) === -1, 'the reply-leg tool event: ' + String(te && te.output).slice(0, 200));
    }
});
cases.push({
    finding: 'MS-mcp-call-block',
    title: 'run.py:675 mcp_tools_call_injection_never_reaches_the_server: the refusal carries the caller\'s id and the scan id',
    setup: setup(rpc(call('Card ' + C)), { legs: ['request', 'response'], airs: R.answers('block-tool-input'), response: answer(3, echoed('unused')) }),
    v3: function (r) { var q = r.request, b = rpcBody(q); return S.check(rpcRefusal(q, 3, -32001) && b.error.message.indexOf('Scan ID: SCAN_ID.') !== -1 && !r.response, 'refusal ' + (q && q.body)); }
});
cases.push({
    finding: 'MS-mcp-call-result',
    title: 'run.py:685 mcp_tools_call_result_is_scanned_with_its_input: the request leg sends the call\'s input, the reply leg its input and its result, both as tools/call events for echo',
    setup: setup(rpc(call('hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), response: answer(3, echoed('hello')) }),
    v3: function (r) {
        var q = r.request, p = r.response, a = q && tools(q)[0], b = p && tools(p)[0];
        if (!a || !b || p.fault) { return 'two tool events were not sent, or the result was refused'; }
        if (a.metadata.method !== 'tools/call' || a.metadata.tool_invoked !== 'echo' || a.input.indexOf('hello') === -1 || (a.output !== undefined && a.output !== '')) { return 'request leg: ' + JSON.stringify(a); }
        return S.check(b.metadata.tool_invoked === 'echo' && b.input.indexOf('hello') !== -1 && String(b.output).indexOf('echo:') !== -1, 'reply leg: ' + JSON.stringify(b));
    }
});
cases.push({
    finding: 'MS-mcp-result-block',
    title: 'run.py:697 mcp_blocked_result_is_withheld: the call reaches the server, but the result the named block refuses is withheld with -32001 and id 3',
    setup: setup(rpc(call('hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'block-tool-output'), response: answer(3, { content: [{ type: 'text', text: 'Card on file: ' + C }], isError: false }) }),
    v3: function (r) { var q = r.request, p = r.response; return S.check(q && !q.fault && p && rpcRefusal(p, 3, -32001) && p.body.indexOf(C) === -1, 'the call was refused, or its result reached the client'); }
});
const MCP_SSE = 'event: message\ndata: ' + JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'Card on file: ' + C } }) + '\n\n' +
                'event: message\ndata: ' + JSON.stringify({ jsonrpc: '2.0', id: 3, result: echoed('hello') }) + '\n\n';
cases.push({
    finding: 'MS-mcp-sse-reply',
    title: 'run.py:707 mcp_sse_reply_is_scanned_whole: an event-stream reply with a notification first is replaced by a JSON-RPC error, -32001 with id 3 (v3 phase 1 withholds MCP event streams unscanned; MuleSoft scans them)',
    setup: setup(rpc(call('hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), response: stream(MCP_SSE) }),
    v3: function (r) {
        var p = r.response;
        return S.check(p && rpcRefusal(p, 3, -32001) && /application\/json/.test(p.contentType || '') && p.body.indexOf(C) === -1 && p.calls.length === 0, 'the stream was not replaced by a JSON-RPC error');
    }
});
cases.push({
    finding: 'MS-mcp-sse-reply',
    title: 'run.py:707 mcp_sse_reply_is_scanned_whole (this runtime, L1): the flow sees the event-stream reply empty, and it is withheld with -32001 and id 3',
    setup: setup(rpc(call('hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), response: stream('') }),
    v3: function (r) { var p = r.response; return S.check(p && rpcRefusal(p, 3, -32001) && p.calls.length === 0, 'the unseen stream was not withheld'); }
});
cases.push({
    finding: 'MS-mcp-batch',
    title: 'run.py:716 mcp_batch_with_ping_first_is_scanned: [ping, tools/call] is read member by member; the named block on the tools/call keeps the whole batch from the server, with an error for each member\'s id, [1, 2] (A29)',
    setup: setup(rpc([{ jsonrpc: '2.0', id: 1, method: 'ping' }, call('Card ' + C, 2)]), { legs: ['request', 'response'], airs: R.answers('block-tool-input'), response: S.reply([]) }),
    v3: function (r) {
        var q = r.request, b = rpcBody(q);
        if (!q.blocked || q.calls.length !== 1 || tools(q).length !== 1 || !S.has(q, C) || r.response) { return 'the batch was not scanned member by member and refused: ' + q.calls.length + ' scans'; }
        var ids = Array.isArray(b) ? b.map(function (e) { return e && e.error && e.error.code === -32001 ? e.id : 'bad'; }) : [b && b.id];
        return S.check(q.status === 200 && JSON.stringify(ids) === '[1,2]', 'the refusal answers ids ' + JSON.stringify(ids) + ': ' + q.body.slice(0, 160));
    }
});
cases.push({
    finding: 'MS-mcp-batch-limit',
    title: 'run.py:726 mcp_batch_over_the_limit_is_a_gap: a batch of 9 pings gets 9 errors saying it could not be inspected, before any scan',
    setup: setup(rpc([1, 2, 3, 4, 5, 6, 7, 8, 9].map(function (n) { return { jsonrpc: '2.0', id: n, method: 'ping' }; })),
                 { legs: ['request', 'response'], airs: R.answers('allow-prompt'), response: S.reply([]) }),
    v3: function (r) {
        var q = r.request, b = rpcBody(q);
        return S.check(q.blocked && q.calls.length === 0 && !r.response && Array.isArray(b) && b.length === 9 &&
                       b.every(function (e, i) { return e.id === i + 1 && e.error && e.error.code === -32001 && /could not inspect/.test(e.error.message); }),
                       'not 9 refusals before any scan: ' + String(q.body).slice(0, 200));
    }
});
cases.push({
    finding: 'MS-mcp-bolted',
    title: 'run.py:735 mcp_bolted_messages_are_scanned: a messages member bolted onto a ping is scanned, and the named block refuses with -32001 and id 1',
    setup: setup(rpc({ jsonrpc: '2.0', id: 1, method: 'ping', messages: [{ role: 'user', content: 'Card on file: ' + C }] }), { legs: ['request', 'response'], airs: R.answers('block-dlp-prompt-masked'), response: answer(1, {}) }),
    v3: function (r) { var q = r.request; return S.check(S.has(q, 'Card on file: ' + C) && rpcRefusal(q, 1, -32001) && !r.response, 'the bolted member was not scanned or not refused'); }
});
cases.push({
    finding: 'MS-mcp-control',
    title: 'run.py:745 mcp_control_messages_pass_unscanned (ping): a ping and its empty result pass with no scan on either leg',
    setup: setup(rpc({ jsonrpc: '2.0', id: 4, method: 'ping' }), { legs: ['request', 'response'], airs: R.answers('allow-prompt-response'), response: answer(4, {}) }),
    v3: function (r) {
        var q = r.request, p = r.response;
        if (!q || q.fault || !p || p.fault) { return 'the ping was refused'; }
        return S.check(q.calls.length === 0 && p.calls.length === 0, 'scanned: request ' + q.calls.length + ', reply ' + p.calls.length + ' (' + JSON.stringify(p.scanned) + ')');
    }
});
cases.push({
    finding: 'MS-mcp-control',
    title: 'run.py:745 mcp_control_messages_pass_unscanned (notification): notifications/initialized and its 202 pass with no scan',
    setup: setup(rpc({ jsonrpc: '2.0', method: 'notifications/initialized' }), { legs: ['request', 'response'], airs: R.answers('allow-prompt'), response: { status: 202, headers: {}, content: '' } }),
    v3: function (r) { var q = r.request, p = r.response; return S.check(q && !q.fault && q.calls.length === 0 && p && !p.fault && p.calls.length === 0 && p.status === 202, 'the notification was scanned or refused'); }
});
cases.push({
    finding: 'MS-mcp-get-405',
    title: 'run.py:755 mcp_get_stream_is_refused_with_405: a GET asking for an event stream gets 405 with Allow: POST, DELETE and a JSON-RPC error, -32001 with id null, and never reaches the server',
    setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, legs: ['request'], airs: R.answers('allow-prompt') },
    v3: function (r) {
        var q = r.request, b = rpcBody(q);
        if (!q.fault) { return 'the GET stream was not refused: it would reach the server (route ' + q.flow.get('airs3.route') + ')'; }
        if (q.status !== 405 || String(hdr(q, 'Allow')).indexOf('POST') === -1) { return 'status ' + q.status + ', Allow ' + hdr(q, 'Allow'); }
        return S.check(b && b.jsonrpc === '2.0' && b.id === null && b.error && b.error.code === -32001 && hdr(q, 'x-airs-kind') === 'refused', 'body ' + q.body + ', x-airs-kind ' + hdr(q, 'x-airs-kind'));
    }
});
const BODILESS_GET = { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: '*/*' }, content: '' } };
cases.push({
    finding: 'MS-mcp-bodiless-sse',
    title: 'run.py:763 mcp_bodiless_event_stream_reply_is_scanned: an unrequested event stream in reply to a bodiless GET, here a server request carrying the card, is withheld (reply leg alone, on a runtime that shows the stream)',
    setup: Object.assign({}, BODILESS_GET, { legs: ['response'], airs: R.answers('block-dlp-response-masked'), response: stream(GET_STREAM_REPLY) }),
    v3: function (r) { var p = r.response; return S.check(p && p.blocked && p.body.indexOf(C) === -1, 'the server\'s event stream reached the client (route ' + (p && p.flow.get('airs3.route')) + ')'); }
});
cases.push({
    finding: 'MS-mcp-bodiless-sse',
    title: 'run.py:763 mcp_bodiless_event_stream_reply_is_scanned (this runtime, L1): the same event stream, which the flow sees empty, is withheld by the A21 guard',
    setup: Object.assign({}, BODILESS_GET, { legs: ['response'], airs: R.answers('block-dlp-response-masked'), response: stream('') }),
    v3: function (r) { var p = r.response; return S.check(p && p.blocked, 'the unseen event stream passed (route ' + (p && p.flow.get('airs3.route')) + ')'); }
});
cases.push({
    finding: 'MS-mcp-session',
    title: 'run.py:849 mcp_session_id_comes_from_mcp_session_id: Mcp-Session-Id wins over x-session-id, on both legs',
    setup: setup(rpc(call('hello'), { 'Mcp-Session-Id': 'sess-mcp-1', 'x-session-id': 'other-session' }), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), response: answer(3, echoed('hello')) }),
    v3: function (r) {
        var all = (r.request ? r.request.scans : []).concat(r.response ? r.response.scans : []);
        return S.check(all.length === 2 && all.every(function (b) { return b.session_id === 'sess-mcp-1'; }), 'session ids ' + JSON.stringify(all.map(function (b) { return b.session_id; })));
    }
});
cases.push({
    finding: 'MS-mcp-failure',
    title: 'run.py:865 mcp_scanner_failure_is_minus_32003: an HTTP 500 from Prisma AIRS gives -32003 with id 3, HTTP 200, and the call never reaches the server',
    setup: setup(rpc(call('hello')), { legs: ['request', 'response'], airs: R.answers(R.status(500, { error: { message: 'internal error' } })), response: answer(3, echoed('hello')) }),
    v3: function (r) { var q = r.request; return S.check(rpcRefusal(q, 3, -32003) && hdr(q, 'x-airs-kind') === 'failure' && !r.response, 'refusal ' + (q && q.body)); }
});
cases.push({
    finding: 'MS-mcp-misconfigured',
    title: 'run.py:874 mcp_misconfigured_is_a_jsonrpc_error: a setting v3 refuses gives a JSON-RPC error, -32003 with id 3, HTTP 200, saying "not configured correctly", before any scan',
    setup: setup(rpc(call('hello')), { legs: ['request', 'response'], vars: { prismaAirsEndpoint: BAD_ENDPOINT }, airs: R.answers('allow-tool'), response: answer(3, echoed('hello')) }),
    v3: function (r) {
        var q = r.request, b = rpcBody(q);
        if (!refusedAs(q, 'config') || q.calls.length !== 0 || r.response) { return 'not refused as a configuration problem before any scan'; }
        return S.check(rpcRefusal(q, 3, -32003) && b.error.message.indexOf('not configured correctly') !== -1, 'not a JSON-RPC error: HTTP ' + q.status + ' ' + q.body.slice(0, 160));
    }
});
cases.push({
    finding: 'MS-mcp-trunc',
    title: 'run.py:899 mcp_truncation_closed_is_a_gap: a call over maxScanChars (50) gets -32001 with id 3, with no scan and no forward',
    setup: setup(rpc(call(new Array(31).join('long '))), { legs: ['request', 'response'], vars: { maxScanChars: '50' }, airs: R.answers('allow-tool'), response: answer(3, echoed('unused')) }),
    v3: function (r) { var q = r.request; return S.check(rpcRefusal(q, 3, -32001) && q.calls.length === 0 && !r.response, 'the over-limit call was scanned or forwarded'); }
});
cases.push({
    finding: 'MS-mcp-server-name',
    title: 'run.py:908 mcp_server_name_comes_from_the_setting: server_name is the API proxy\'s name, on both legs (v3 has no mcpServerName setting; MuleSoft\'s default is likewise the API instance\'s name)',
    setup: setup(rpc(call('hello')), { proxyName: 'harness-mcp', legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), response: answer(3, echoed('hello')) }),
    v3: function (r) {
        var all = (r.request ? tools(r.request) : []).concat(r.response ? tools(r.response) : []);
        return S.check(all.length === 2 && all.every(function (t) { return t.metadata.server_name === 'harness-mcp'; }), 'server names ' + JSON.stringify(all.map(function (t) { return t.metadata.server_name; })));
    }
});
cases.push({
    finding: 'MS-llm-jsonrpc',
    title: 'run.py:921 llm_jsonrpc_lookalike_is_not_a_bypass: a Chat Completions body that adds jsonrpc, id and method is still scanned, messages included, and the named block keeps it from the model',
    setup: setup(S.req(S.P.chat, { model: 'gpt-test', messages: [{ role: 'user', content: 'Card on file: ' + C }], jsonrpc: '2.0', id: 1, method: 'ping' }),
        { legs: ['request', 'response'], airs: R.answers('block-dlp-prompt-masked'), response: S.reply(replyFor('chat', 'unused')) }),
    v3: function (r) { var q = r.request; return S.check(S.has(q, 'Card on file: ' + C) && q.blocked && !r.response, 'the messages were not scanned, or the body reached the model'); }
});

module.exports = cases;

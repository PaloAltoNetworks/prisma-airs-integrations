'use strict';
/*
 * MuleSoft's core/tests/mcp_reply.rs, ported to v3: what the MCP reply leg scans, withholds or
 * passes. Each case names the line of the MuleSoft test it ports (MS-mcp-reply-<line>).
 * MCP reply text that is not a tool event goes to Prisma AIRS as a prompt with no context, MuleSoft's rule (its src/mcp.rs
 * run(): MCP text reaches a model as input); the phase 2 review (P2GATE-SIDE) moved v3 to it from {prompt: context, response}.
 * Where v3's phase 1 differs on purpose, the case holds v3's rule:
 *   - an MCP event-stream reply is withheld with -32001 and the request id, even when a runtime shows its body;
 *   - a 2xx reply with no body is refused, unless it says it has none: a 202 or 204, or Content-Length: 0 with no
 *     Transfer-Encoding (A21). A body that is not JSON is refused (A13).
 * The only marked text is AIRSV3-MARKER; nothing here decides a verdict, each case names its recorded replies.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const M = 'AIRSV3-MARKER';
// A catalogue or tools/list request (MuleSoft scans none of its params) runs the reply leg alone, as a proxy that calls
// v3 only on its response leg does. run.js reads airs3.route after both legs, so a request leg that passes unscanned
// before a reply leg that scans would be reported as a silent leg.
const REPLY_LEG = ['response'];

/* ---- shapes --------------------------------------------------------------------------------------------------- */
function rpc(body) { return S.req(S.P.mcp, body, { Accept: 'application/json, text/event-stream' }); }
// MuleSoft's call_req(): tools/call id 3, read_wiki_structure.
function callReq() { return rpc({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'read_wiki_structure', arguments: { repoName: 'modelcontextprotocol/servers' } } }); }
function listReq(params) { var b = { jsonrpc: '2.0', id: 2, method: 'tools/list' }; if (params) { b.params = params; } return rpc(b); }
function answer(id, result) { return S.reply({ jsonrpc: '2.0', id: id, result: result }); }
function sse(events) { return { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: events.join('') }; }
function event(msg) { return 'event: message\ndata: ' + JSON.stringify(msg) + '\n\n'; }
// MuleSoft's helpers: a PNG's base64 (its signature, then its first chunk, 480 characters), base64 of text, and audio with
// no file header (16-bit samples of a 440 Hz tone at 24 kHz: not UTF-8, no known signature).
function png64() { return new Array(21).join('iVBORw0KGgoAAAANSUhEUgAA'); }
function b64(text) { return Buffer.from(text, 'utf8').toString('base64'); }
function pcm(samples) {
    var b = Buffer.alloc(samples * 2);
    for (var i = 0; i < samples; i++) { b.writeInt16LE(Math.trunc(Math.sin(i * 440 * 2 * Math.PI / 24000) * 8000), i * 2); }
    return b;
}
function pad(n) { return new Array(n + 1).join('pad '); }
function svg(words) { return '<svg xmlns="http://www.w3.org/2000/svg"><text>' + words + '</text>' + new Array(61).join('<g/>') + '</svg>'; }
// Text a model may read that looks like base64 under a data-like key (MuleSoft's look-alike string, with v3's marker).
const WORDS = M + '-' + new Array(151).join('x-');

/* ---- what a case looks at -------------------------------------------------------------------------------------- */
// The reply leg's one Prisma AIRS entry, or null.
function sent(r) { return r.response && r.response.scans.length === 1 && r.response.scans[0] ? r.response.scans[0].contents[0] : null; }
// The reply text v3 sent: the tool event's output, or the text, which goes as a prompt with no context (no response part).
function replyText(r) { var e = sent(r); return !e ? '' : (e.tool_event ? String(e.tool_event.output || '') : (e.response === undefined ? String(e.prompt || '') : '')); }
function scannedOnce(r) {
    if (!r.response) { return 'the request leg stopped: ' + r.request.body; }
    if (r.response.fault) { return 'the reply was refused: ' + r.response.body; }
    return S.check(r.response.calls.length === 1, r.response.calls.length + ' scans on the reply leg, not 1');
}
function scannedWith(r, text) {
    var once = scannedOnce(r);
    if (once !== true) { return once; }
    return S.check(replyText(r).indexOf(text) !== -1, '"' + text + '" did not reach the scan: ' + replyText(r).slice(0, 300));
}
// Withheld inside the protocol: HTTP 200, a JSON-RPC error -32001 with the request id as sent, no scan on the reply leg.
function withheld(r, id) {
    if (!r.response) { return 'the request leg stopped: ' + r.request.body; }
    if (!r.response.blocked) { return 'the reply was not withheld (' + r.response.calls.length + ' scans, route ' + r.response.flow.get('airs3.route') + ')'; }
    var b = JSON.parse(r.response.body);
    return S.check(r.response.status === 200 && b.jsonrpc === '2.0' && b.error && b.error.code === -32001 && b.id === id && r.response.calls.length === 0,
                   'not withheld with HTTP 200, -32001 and id ' + JSON.stringify(id) + ' before any scan: ' + r.response.status + ' ' + r.response.body);
}
function passedUnscanned(r) {
    if (!r.response) { return 'the request leg stopped: ' + r.request.body; }
    return S.check(!r.response.fault && r.response.calls.length === 0 && r.response.flow.get('airs3.route') === 'pass',
                   'the reply was ' + (r.response.fault ? 'refused' : 'scanned ' + r.response.calls.length + ' times: ' + replyText(r)));
}

module.exports = [
    /* ---- 45 json_and_event_stream_replies_give_the_same_messages ---- */
    {
        finding: 'MS-mcp-reply-45a', title: 'MCP reply as JSON: its message is read (the pair of 45b)',
        setup: Object.assign(listReq({}), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(2, { tools: [{ name: 'lookup', description: 'Lists the pages. ' + M }] }) }),
        v3: function (r) { return scannedWith(r, M); }
    },
    {
        finding: 'MS-mcp-reply-45b', title: 'The same reply as an event stream, after a priming event without data, is withheld (phase 1)',
        setup: Object.assign(listReq({}), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: sse(['id: 1\ndata:\n\n', event({ jsonrpc: '2.0', id: 2, result: { tools: [{ name: 'lookup', description: 'Lists the pages. ' + M }] } })]) }),
        v3: function (r) { return withheld(r, 2); }
    },
    {
        finding: 'MS-mcp-reply-45c', title: 'A reply batch is split: the answer to tools/list is its tool event; an empty answer to an id nobody sent adds no scan',
        setup: Object.assign(listReq({}), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: S.reply([{ jsonrpc: '2.0', id: 2, result: { tools: [{ name: 'lookup', description: M }] } }, { jsonrpc: '2.0', id: 9, result: {} }]) }),
        v3: function (r) {
            var once = scannedOnce(r); if (once !== true) { return once; }
            var t = sent(r).tool_event;
            return S.check(t && t.metadata.method === 'tools/list' && String(t.output).indexOf(M) !== -1, 'not one tools/list tool event: ' + JSON.stringify(sent(r)).slice(0, 200));
        }
    },

    /* ---- 58 tools_call_reply_is_a_tool_event_with_input_and_output ---- */
    {
        finding: 'MS-mcp-reply-58', title: 'tools/call reply: one tool event, the request\'s arguments as input, the result as output',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), proxyName: 'deepwiki-test',
            response: answer(3, { content: [{ type: 'text', text: 'Available pages: ' + M }], isError: false }) }),
        v3: function (r) {
            var once = scannedOnce(r); if (once !== true) { return once; }
            var t = sent(r).tool_event;
            if (!t) { return 'not a tool event: ' + JSON.stringify(sent(r)); }
            return S.check(t.metadata && t.metadata.ecosystem === 'mcp' && t.metadata.method === 'tools/call' && t.metadata.server_name === 'deepwiki-test' &&
                           t.metadata.tool_invoked === 'read_wiki_structure' && t.input === '{"repoName":"modelcontextprotocol/servers"}' &&
                           String(t.output).indexOf('Available pages: ' + M) !== -1, 'the tool event is not as expected: ' + JSON.stringify(t));
        }
    },

    /* ---- 73 tools_list_reply_output_is_the_bare_tools_array ---- */
    {
        finding: 'MS-mcp-reply-73', title: 'tools/list reply with nextCursor: one tool event, its output the bare tools array, its input {}, no tool_invoked; nextCursor adds no scan',
        setup: Object.assign(listReq({}), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(2, { tools: [{ name: 'read_wiki_structure', description: 'Get topics. ' + M, inputSchema: { type: 'object' } }], nextCursor: 'page-2' }) }),
        v3: function (r) {
            var ok = scannedWith(r, M); if (ok !== true) { return ok; }
            var t = sent(r).tool_event;
            if (!t) { return 'not a tool event: ' + JSON.stringify(sent(r)).slice(0, 200); }
            var out; try { out = JSON.parse(t.output); } catch (e) { out = null; }
            // Prisma AIRS refuses the {tools: [...]} object, so the output is the bare array.
            return S.check(t.metadata.method === 'tools/list' && !t.metadata.tool_invoked && t.input === '{}' && Array.isArray(out) && out.length === 1 &&
                           String(t.output).indexOf('page-2') === -1, 'the tool event is not as MuleSoft sends it: ' + JSON.stringify(t).slice(0, 300));
        }
    },

    /* ---- 89 tools_list_extra_result_members_are_scanned ---- */
    {
        finding: 'MS-mcp-reply-89', title: 'tools/list reply: result members other than tools, nextCursor and _meta are a second scan, as text',
        setup: Object.assign(listReq(), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(2, { tools: [], notice: 'Extra text. ' + M }) }),
        v3: function (r) {
            if (!r.response || r.response.fault) { return 'the reply was refused: ' + (r.response && r.response.body); }
            var p = r.response;
            if (p.calls.length !== 2) { return p.calls.length + ' scans on the reply leg, not 2'; }
            var a = p.scans[0].contents[0], b = p.scans[1].contents[0];
            return S.check(a.tool_event && a.tool_event.output === '[]' && b.response === undefined && String(b.prompt || '').indexOf('Extra text. ' + M) !== -1 && String(b.prompt).indexOf('"tools"') === -1,
                           'not a tool event, then the other members as text: ' + JSON.stringify([a, b]).slice(0, 300));
        }
    },

    /* ---- 99 tools_list_reply_without_tools_is_scanned_as_text ---- */
    {
        finding: 'MS-mcp-reply-99', title: 'tools/list reply without a tools list is scanned as text',
        setup: Object.assign(listReq(), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(2, { tool: 'not a list, ' + M }) }),
        v3: function (r) { return scannedWith(r, 'not a list, ' + M); }
    },

    /* ---- 108 catalogue_replies_are_scanned_as_text ---- */
    {
        finding: 'MS-mcp-reply-108a', title: 'initialize reply: instructions and serverInfo are scanned',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }), {
            legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(1, { protocolVersion: '2025-06-18', serverInfo: { name: 'DeepWiki', version: '4.0.2' }, instructions: 'Use the tools politely. ' + M }) }),
        v3: function (r) { var ok = scannedWith(r, 'Use the tools politely. ' + M); return ok !== true ? ok : S.check(replyText(r).indexOf('DeepWiki') !== -1, 'serverInfo was not scanned'); }
    },
    {
        finding: 'MS-mcp-reply-108b', title: 'resources/list reply: resource descriptions are scanned',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 5, method: 'resources/list' }), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(5, { resources: [{ uri: 'file:///a', name: 'a', description: 'Resource description text. ' + M }] }) }),
        v3: function (r) { return scannedWith(r, 'Resource description text. ' + M); }
    },

    /* ---- 123 error_replies_are_scanned_as_text ---- */
    {
        finding: 'MS-mcp-reply-123', title: 'An error answer to tools/call is scanned as text, not as a tool event',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-prompt-response'),
            response: S.reply({ jsonrpc: '2.0', id: 3, error: { code: -32000, message: 'Tool failed: ' + M } }) }),
        v3: function (r) { var ok = scannedWith(r, 'Tool failed: ' + M); return ok !== true ? ok : S.check(!sent(r).tool_event, 'the error was sent as a tool event'); }
    },

    /* ---- 132 every_other_message_in_the_reply_is_scanned ---- */
    {
        finding: 'MS-mcp-reply-132a', title: 'An event-stream reply with a notification and an elicitation before the answer is withheld (phase 1)',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: sse([event({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'Log text. ' + M } }),
                           event({ jsonrpc: '2.0', id: 'srv-1', method: 'elicitation/create', params: { message: 'Elicit text. ' + M, requestedSchema: { type: 'object' } } }),
                           event({ jsonrpc: '2.0', id: 3, result: { content: [{ type: 'text', text: 'ok' }] } })]) }),
        v3: function (r) { return withheld(r, 3); }
    },
    {
        finding: 'MS-mcp-reply-132b', title: 'A JSON reply that is a server request (elicitation/create), not the answer, is scanned or withheld, never passed unread',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-prompt-response'),
            response: S.reply({ jsonrpc: '2.0', id: 'srv-1', method: 'elicitation/create', params: { message: 'Elicit text. ' + M, requestedSchema: { type: 'object' } } }) }),
        v3: function (r) { return withheld(r, 3) === true ? true : scannedWith(r, 'Elicit text. ' + M); }
    },

    /* ---- 149 ids_match_by_value ---- */
    {
        finding: 'MS-mcp-reply-149', title: 'A reply whose id is "1" to request 1 is still scanned (v3 reads it as the answer; MuleSoft as text)',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 't', arguments: {} } }), {
            legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: answer('1', { content: [{ type: 'text', text: 'String id reply. ' + M }] }) }),
        v3: function (r) { return scannedWith(r, 'String id reply. ' + M); }
    },

    /* ---- 159 an_unreadable_event_is_unreadable ---- */
    {
        finding: 'MS-mcp-reply-159a', title: 'An event-stream reply whose data is not JSON is withheld',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), response: sse(['event: message\ndata: {not json\n\n']) }),
        v3: function (r) { return withheld(r, 3); }
    },
    {
        finding: 'MS-mcp-reply-159b', title: 'An HTML reply body (HTTP 200) is unreadable: withheld',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: { status: 200, headers: { 'Content-Type': 'text/html' }, content: '<html>oops ' + M + '</html>' } }),
        v3: function (r) { return withheld(r, 3); }
    },

    /* ---- 165 an_empty_reply_has_no_messages ---- */
    {
        finding: 'MS-mcp-reply-165a', title: 'A notification answered 202 with no body passes, with no scan on either leg',
        setup: Object.assign(rpc({ jsonrpc: '2.0', method: 'notifications/initialized' }), { legs: ['request', 'response'], airs: R.answers('allow-prompt'),
            response: { status: 202, headers: {}, content: '' } }),
        v3: function (r) { return r.request.calls.length !== 0 || r.request.fault ? 'the notification was scanned or refused' : passedUnscanned(r); }
    },
    {
        finding: 'MS-mcp-reply-165b', title: 'A 200 reply with no body is withheld (A21: on this runtime an event stream looks empty)',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: { status: 200, headers: { 'Content-Type': 'application/json' }, content: '' } }),
        v3: function (r) { return withheld(r, 3); }
    },
    {
        finding: 'MS-mcp-reply-165c', title: 'A 200 reply whose body is blank is withheld (not JSON, A13)',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: { status: 200, headers: { 'Content-Type': 'application/json' }, content: '  \n' } }),
        v3: function (r) { return withheld(r, 3); }
    },

    /* ---- 172 a_ping_reply_scans_nothing ---- */
    {
        finding: 'MS-mcp-reply-172', title: 'A ping\'s empty result scans nothing and passes',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 4, method: 'ping' }), { legs: ['request', 'response'], airs: R.answers('allow-prompt-response'),
            response: answer(4, {}) }),
        v3: function (r) { return r.request.calls.length !== 0 || r.request.fault ? 'the ping was scanned or refused' : passedUnscanned(r); }
    },

    /* ---- 178 a_bodiless_request_reply_is_scanned_as_text (and 250's sampling half) ---- */
    {
        finding: 'MS-mcp-reply-178a', title: 'A bodiless GET asking for an event stream (where a server request would arrive) gets 405, with no scan',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, legs: ['request'], airs: R.answers('allow-prompt') },
        v3: function (r) {
            var x = r.request, b;
            try { b = JSON.parse(x.body); } catch (e) { b = null; }
            return S.check(x.fault && x.status === 405 && /POST/.test(x.flow.messages.response.header('Allow') || '') && b && b.id === null && b.error && b.error.code === -32001 && x.calls.length === 0,
                           'not refused with 405, Allow: POST, DELETE and a JSON-RPC error with id null: ' + x.status + ' ' + x.body);
        }
    },
    {
        finding: 'MS-mcp-reply-178b', title: 'A JSON reply that is a sampling request: its messages and systemPrompt are scanned, its image left out (or it is withheld)',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-prompt-response'),
            response: S.reply({ jsonrpc: '2.0', id: 's1', method: 'sampling/createMessage', params: { maxTokens: 5, systemPrompt: 'System text. ' + M,
                messages: [{ role: 'user', content: { type: 'text', text: 'Sample text. ' + M } }, { role: 'user', content: { type: 'image', data: png64(), mimeType: 'image/png' } }] } }) }),
        v3: function (r) {
            if (withheld(r, 3) === true) { return true; }
            var ok = scannedWith(r, 'Sample text. ' + M); if (ok !== true) { return ok; }
            return S.check(replyText(r).indexOf('System text. ' + M) !== -1 && replyText(r).indexOf(png64().slice(0, 48)) === -1, 'the systemPrompt was not scanned, or the image bytes were');
        }
    },

    /* ---- 188 oversize_reply_tool_event_becomes_text ---- */
    {
        finding: 'MS-mcp-reply-188a', title: 'A tool result over maxScanChars (150) is withheld without a scan (truncationFailClosed default)',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-prompt-response'), vars: { maxScanChars: '150' },
            response: answer(3, { content: [{ type: 'text', text: S.filler(200) }] }) }),
        v3: function (r) { return withheld(r, 3); }
    },
    {
        finding: 'MS-mcp-reply-188b', title: 'With truncationFailClosed=false, an oversize tool result becomes text cut to its first 150 characters',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-prompt-response'), vars: { maxScanChars: '150', truncationFailClosed: 'false' },
            response: answer(3, { content: [{ type: 'text', text: S.filler(200) }] }) }),
        v3: function (r) {
            var once = scannedOnce(r); if (once !== true) { return once; }
            var e = sent(r);
            return S.check(!e.tool_event && e.response === undefined && e.prompt === S.filler(150), 'not the first 150 characters as text: ' + JSON.stringify(e).slice(0, 300));
        }
    },

    /* ---- 197 a_tool_description_behind_a_data_prefix_is_scanned_as_written ---- */
    {
        finding: 'MS-mcp-reply-197', title: 'A tool description dressed as a PNG data URI is scanned as written',
        setup: Object.assign(listReq(), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(2, { tools: [{ name: 't', description: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUg' + M + new Array(301).join('A') }] }) }),
        v3: function (r) { return scannedWith(r, M); }
    },

    /* ---- 206 a_tool_result_behind_a_data_prefix_is_scanned_as_written ---- */
    {
        finding: 'MS-mcp-reply-206', title: 'A data URI in a text block, and a data member in structuredContent, are scanned',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: answer(3, { content: [{ type: 'text', text: 'data:text/plain,' + pad(70) + M + ' in a text block' }], structuredContent: { data: WORDS } }) }),
        v3: function (r) {
            var ok = scannedWith(r, M + ' in a text block'); if (ok !== true) { return ok; }
            return S.check(replyText(r).indexOf(M + '-x-x') !== -1, 'the data member of structuredContent was not scanned');
        }
    },

    /* ---- 218 binary_slots_are_left_out_and_text_blobs_are_read ---- */
    {
        finding: 'MS-mcp-reply-218a', title: 'An image block\'s data is left out of the tool result, as a placeholder',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: answer(3, { content: [{ type: 'text', text: 'Here is the chart.' }, { type: 'image', data: png64(), mimeType: 'image/png' }] }) }),
        v3: function (r) {
            var ok = scannedWith(r, 'Here is the chart.'); if (ok !== true) { return ok; }
            return S.check(replyText(r).indexOf(png64().slice(0, 48)) === -1 && replyText(r).indexOf('<binary, 480 characters>') !== -1, 'the image bytes were scanned: ' + replyText(r).slice(0, 200));
        }
    },
    {
        finding: 'MS-mcp-reply-218b', title: 'A text resource sent as a base64 blob (text/plain) is decoded and scanned as its text',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: answer(3, { content: [{ type: 'resource', resource: { uri: 'file:///notes.txt', mimeType: 'text/plain', blob: b64(M + ' notes ' + pad(70)) } }] }) }),
        v3: function (r) { return scannedWith(r, M + ' notes'); }
    },

    /* ---- 229 initialize_instructions_behind_a_data_prefix_are_scanned ---- */
    {
        finding: 'MS-mcp-reply-229', title: 'Server instructions behind a data:text/plain prefix are scanned',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(1, { protocolVersion: '2025-06-18', instructions: 'data:text/plain,' + pad(70) + M + ' instructions' }) }),
        v3: function (r) { return scannedWith(r, M + ' instructions'); }
    },

    /* ---- 238 look_alike_slots_in_structured_content_and_schemas_are_scanned ---- */
    {
        finding: 'MS-mcp-reply-238a', title: 'blob and image look-alikes inside structuredContent are text: both are scanned',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: answer(3, { content: [], structuredContent: { file: { uri: 'file:///a', blob: WORDS }, picture: { type: 'image', data: WORDS } } }) }),
        v3: function (r) { var ok = scannedOnce(r); return ok !== true ? ok : S.check(replyText(r).split(M + '-x-x').length - 1 === 2, 'not both look-alikes were scanned: ' + replyText(r).slice(0, 200)); }
    },
    {
        finding: 'MS-mcp-reply-238b', title: 'Icons inside a tool\'s inputSchema are text: scanned',
        setup: Object.assign(listReq(), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(2, { tools: [{ name: 't', description: 'd', inputSchema: { type: 'object', icons: [{ src: WORDS }] } }] }) }),
        v3: function (r) { return scannedWith(r, M + '-x-x'); }
    },

    /* ---- 250 resource_and_message_slots_are_left_out (the sampling half is in 178b) ---- */
    {
        finding: 'MS-mcp-reply-250', title: 'resources/read reply: a PNG blob is left out, its uri is scanned',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 4, method: 'resources/read', params: { uri: 'file:///logo.png' } }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: answer(4, { contents: [{ uri: 'file:///logo.png', mimeType: 'image/png', blob: png64() }] }) }),
        v3: function (r) { var ok = scannedWith(r, 'file:///logo.png'); return ok !== true ? ok : S.check(replyText(r).indexOf(png64().slice(0, 48)) === -1, 'the blob bytes were scanned'); }
    },

    /* ---- 263 icons_are_left_out ---- */
    {
        finding: 'MS-mcp-reply-263', title: 'A tool icon given as a PNG data URI is left out',
        setup: Object.assign(listReq(), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(2, { tools: [{ name: 't', description: 'Tool description. ' + M, icons: [{ src: 'data:image/png;base64,' + png64(), mimeType: 'image/png' }] }] }) }),
        v3: function (r) { var ok = scannedWith(r, 'Tool description. ' + M); return ok !== true ? ok : S.check(replyText(r).indexOf(png64().slice(0, 48)) === -1, 'the icon bytes were scanned'); }
    },

    /* ---- 272 an_icon_is_left_out_whatever_it_holds ---- */
    {
        finding: 'MS-mcp-reply-272', title: 'An icon is left out whatever it holds (SVG or text data URI); an icon link is scanned',
        setup: Object.assign(listReq(), { legs: REPLY_LEG, airs: R.answers('allow-prompt-response'),
            response: answer(2, { tools: [{ name: 't', description: 'Tool description.', icons: [
                { src: 'data:image/svg+xml;base64,' + b64(svg(M + ' svg')), mimeType: 'image/svg+xml' }, { src: 'data:text/plain,' + M + ' plain' }, { src: 'https://icons.example/tool.png' }] }] }) }),
        v3: function (r) {
            var ok = scannedWith(r, 'https://icons.example/tool.png'); if (ok !== true) { return ok; }
            return S.check(replyText(r).indexOf(M) === -1, 'text inside an icon was scanned: ' + replyText(r).slice(0, 300));
        }
    },

    /* ---- 284 an_svg_image_result_is_scanned_as_its_markup ---- */
    {
        finding: 'MS-mcp-reply-284', title: 'An SVG image block in a tool result is scanned as its markup',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: answer(3, { content: [{ type: 'image', data: b64(svg(M + ' chart')), mimeType: 'image/svg+xml' }] }) }),
        v3: function (r) { return scannedWith(r, M + ' chart'); }
    },

    /* ---- 292 an_audio_block_without_a_known_header_is_left_out ---- */
    {
        finding: 'MS-mcp-reply-292', title: 'Headerless audio (audio/pcm) in a tool result is left out',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: answer(3, { content: [{ type: 'text', text: 'Here is the tone.' }, { type: 'audio', data: pcm(2000).toString('base64'), mimeType: 'audio/pcm' }] }) }),
        v3: function (r) {
            var ok = scannedWith(r, 'Here is the tone.'); if (ok !== true) { return ok; }
            return S.check(replyText(r).indexOf('<binary,') !== -1 && replyText(r).indexOf(pcm(2000).toString('base64').slice(0, 48)) === -1, 'the audio bytes were scanned');
        }
    },

    /* ---- 300 a_blob_of_text_under_a_binary_type_is_read ---- */
    {
        finding: 'MS-mcp-reply-300', title: 'A blob that holds text under application/octet-stream is decoded and scanned',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 4, method: 'resources/read', params: { uri: 'file:///notes' } }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: answer(4, { contents: [{ uri: 'file:///notes', mimeType: 'application/octet-stream', blob: b64(M + ' notes ' + pad(70)) }] }) }),
        v3: function (r) { return scannedWith(r, M + ' notes'); }
    },

    /* ---- 309 an_image_sent_as_text_counts_toward_the_limit ---- */
    {
        finding: 'MS-mcp-reply-309a', title: 'A PNG data URI in a text block counts toward maxScanChars (300): withheld',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), vars: { maxScanChars: '300' },
            response: answer(3, { content: [{ type: 'text', text: 'data:image/png;base64,' + png64() }] }) }),
        v3: function (r) { return withheld(r, 3); }
    },
    {
        finding: 'MS-mcp-reply-309b', title: 'The same PNG as an image block does not count toward maxScanChars (300): one tool event',
        setup: Object.assign(callReq(), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), vars: { maxScanChars: '300' },
            response: answer(3, { content: [{ type: 'image', data: png64(), mimeType: 'image/png' }] }) }),
        v3: function (r) { var ok = scannedOnce(r); return ok !== true ? ok : S.check(!!sent(r).tool_event, 'the image block was not sent as a tool event: ' + JSON.stringify(sent(r)).slice(0, 200)); }
    }
];

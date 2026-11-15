'use strict';
/*
 * The review of phase 2, conformance lens: MuleSoft's MCP rules (its policy's code and MCP tests, in this repository)
 * and v3's phase 2 rules, against v3's phase 2 code.
 * A case returns true when v3 behaves as those rules require.
 *   - P2GATE-<finding>: fails on v3 as of 15 Nov (the review's findings).
 *   - P2GATE-GUARD-*: regression guards; they pass today and pin MuleSoft rules no other case pins for batches.
 * The only marked text is AIRSV3-MARKER and the test card; nothing here decides a verdict from content: each case names
 * its recorded Prisma AIRS replies.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };

function rpc(body, headers) { return S.req(S.P.mcp, body, Object.assign({}, H, headers || {})); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
function ans(id, result) { return { jsonrpc: '2.0', id: id, result: result }; }
function echoed(text) { return { content: [{ type: 'text', text: text }], isError: false }; }
function body(x) { try { return JSON.parse(x.body); } catch (e) { return null; } }
function v(x, leaf) { return String(x.flow.get('airs3.' + leaf) || ''); }
function entry(x, i) { var b = x.scans[i]; return b && b.contents && b.contents[0]; }
// The last log line, for a case that runs one leg only (the flow's log list holds both legs' lines).
function lastLog(x) { var l = x.flow.logs; try { return l.length ? JSON.parse(l[l.length - 1].line) : null; } catch (e) { return null; } }
function passed(x) { return !x ? 'the leg did not run' : (x.fault ? 'it was refused: ' + String(x.body).slice(0, 200) : true); }
function and() { for (var i = 0; i < arguments.length; i++) { if (arguments[i] !== true) { return arguments[i]; } } return true; }
function shape(x) { return JSON.stringify(x.scans.map(function (s) { return s && s.contents; })).slice(0, 400); }
// The batch refusal: HTTP 200, one error per member with an id, each with the code given, the ids as sent.
function refusedBatch(x, ids, code) {
    var b = body(x);
    var got = Array.isArray(b) ? b.map(function (e) { return e && e.error && e.error.code === code ? e.id : 'bad'; }) : null;
    return S.check(x && x.blocked && x.status === 200 && JSON.stringify(got) === JSON.stringify(ids),
                   'not refused as ' + JSON.stringify(ids) + ' with ' + code + ': HTTP ' + (x && x.status) + ' ' + String(x && x.body).slice(0, 200));
}

module.exports = [
    /* ================= findings: each fails on today's v3 ================= */

    /* ---- MCP text goes to Prisma AIRS as {prompt}, without context, on both legs (MuleSoft's rule) ---- */
    {
        finding: 'P2GATE-REPLY-TEXT-AS-PROMPT', title: 'A resources/read answer\'s text goes to Prisma AIRS as {prompt: text}, without context, as MuleSoft sends every MCP text that is not a tool event (not as response, whose detectors read no injection)',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri: 'lab://note' } }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt'),
            response: S.reply(ans(5, { contents: [{ uri: 'lab://note', mimeType: 'text/plain', text: 'Resource text. ' + M }] })) }),
        v3: function (r) {
            var p = r.response, e = p && entry(p, 0);
            return and(passed(p), S.check(p.calls.length === 1 && e && !e.tool_event && e.response === undefined && String(e.prompt || '').indexOf('Resource text. ' + M) !== -1,
                                          'the reply-leg entry is ' + JSON.stringify(e)));
        }
    },
    {
        finding: 'P2GATE-REPLY-TEXT-AS-PROMPT', title: 'Reply array: the joint scan of messages that answer no member (a server\'s sampling request) goes as {prompt: text}, after the answer\'s tool event',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool', 'allow-prompt'),
            response: S.reply([ans(3, echoed('the answer')),
                               { jsonrpc: '2.0', id: 77, method: 'sampling/createMessage', params: { messages: [{ role: 'user', content: { type: 'text', text: 'Server asks. ' + M } }], maxTokens: 10 } }]) }),
        v3: function (r) {
            var p = r.response, a = p && entry(p, 0), b = p && entry(p, 1);
            return and(passed(p), S.check(p.calls.length === 2 && a && a.tool_event && b && b.response === undefined && String(b.prompt || '').indexOf('Server asks. ' + M) !== -1,
                                          'the scans are ' + shape(p)));
        }
    },

    /* ---- tools/call answers: output is the result, read as server-sent (MuleSoft's rule) ---- */
    {
        finding: 'P2GATE-CALL-TEXTBLOCK', title: 'A tools/call answer: a text block\'s members besides text (result.content[0]._meta) are collected into the tool event\'s output',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply(ans(3, { content: [{ type: 'text', text: 'done', _meta: { note: 'Block meta text. ' + M } }], isError: false })) }),
        v3: function (r) {
            var p = r.response, e = p && entry(p, 0);
            return and(passed(p), S.check(p.calls.length === 1 && e && e.tool_event && String(e.tool_event.output).indexOf('Block meta text. ' + M) !== -1,
                                          'result.content[0]._meta is not collected: ' + JSON.stringify(e).slice(0, 300)));
        }
    },
    {
        finding: 'P2GATE-CALL-RESULT-AND-ERROR', title: 'A tools/call answer that carries result and error: the error\'s text is collected too (members outside result are scanned as text)',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply({ jsonrpc: '2.0', id: 3, result: echoed('done'), error: { code: -32000, message: 'Error text. ' + M } }) }),
        v3: function (r) { var p = r.response; return and(passed(p), S.check(p.scanned.indexOf('Error text. ' + M) !== -1, 'error.message is not collected; scanned: ' + p.scanned.slice(0, 300))); }
    },

    /* ---- the slots: the early stop and the verdict judge an answer alike ---- */
    {
        finding: 'P2GATE-SLOT-STOP-AGREES', title: 'Reply array on a reply-leg proxy: slot 1 is an allow whose masked copy is the tool input\'s; the slots stop there, so the verdict must refuse too, never pass slot 2\'s answer unscanned',
        setup: Object.assign(rpc([call(1, 'Card ' + C), call(2, 'hello')]), { legs: ['response'], airs: R.answers(R.asAllow('mask-a24-tool-input'), 'block-tool-output'),
            response: S.reply([ans(1, echoed('done one')), ans(2, echoed('Card ' + C + ' ' + M))]) }),
        v3: function (r) {
            var p = r.response, b = p && body(p);
            return S.check(p && p.blocked && Array.isArray(b) && p.body.indexOf(M) === -1,
                           'the reply reached the client after ' + (p && p.calls.length) + ' scan(s); slot 2 ran: ' + (p && v(p, 'slotRan2')) + '; outcome ' + (p && v(p, 'outcome')));
        }
    },

    /* ---- type=both judges the prompt with the reply, on MCP legs of several scans too ---- */
    {
        finding: 'P2GATE-BOTH-BATCH', title: 'type=both on a reply-leg proxy: a batch\'s request text (a resources/read member\'s params) is judged with the reply array, as both promises',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri: 'lab://note-' + M } }, call(6, 'hello')]), {
            legs: ['response'], params: { response: { type: 'both' } }, airs: R.answers('allow-prompt-response'),
            response: S.reply([ans(5, { contents: [{ uri: 'lab://note', mimeType: 'text/plain', text: 'Resource text' }] }), ans(6, echoed('ok'))]) }),
        v3: function (r) {
            var p = r.response;
            return and(passed(p), S.check(p.scanned.indexOf('lab://note-' + M) !== -1, 'the request\'s text was not judged; the scans are ' + shape(p)));
        }
    },

    /* ---- session: an initialize reply adopts the server-issued Mcp-Session-Id (run.py:857) ---- */
    {
        finding: 'P2GATE-SESSION-INIT', title: 'The initialize reply\'s own scan carries the Mcp-Session-Id the server issues, when no session was known yet (run.py:857)',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'lab', version: '1' } } }), {
            legs: ['response'], airs: R.answers('allow-prompt-response'),
            response: { status: 200, headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': 'lab-session-0001' },
                        content: JSON.stringify(ans(1, { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'lab', version: '1' }, instructions: 'Server text. ' + M })) } }),
        v3: function (r) {
            var p = r.response, sc = p && p.scans[0];
            return and(passed(p), S.check(sc && sc.session_id === 'lab-session-0001', 'session_id ' + JSON.stringify(sc && sc.session_id)));
        }
    },

    /* ---- request leg: params._meta is never scanned (MuleSoft's rule) ---- */
    {
        finding: 'P2GATE-META-CONTENT', title: 'A content method (resources/read): params._meta adds nothing to the scan; the rest of params is scanned',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri: 'lab://note-' + M, _meta: { progressToken: 'Meta text only' } } }),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var q = r.request;
            return and(passed(q), S.check(S.has(q, 'lab://note-' + M) && !S.has(q, 'Meta text only'), 'scanned: ' + q.scanned.slice(0, 300)));
        }
    },

    /* ---- logging: an MCP GET stream is logged as MCP ---- */
    {
        finding: 'P2GATE-LOG-OPEN-FORMAT', title: 'allowOpenStreams=true: the request leg\'s log line for an MCP GET stream says format mcp (live P2O1 logged "unknown"; the 405 line too)',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, legs: ['request'], airs: R.answers('allow-prompt'),
                 vars: { allowOpenStreams: 'true' } },
        v3: function (r) { var q = r.request, l = lastLog(q); return and(passed(q), S.check(l && l.format === 'mcp', 'the log line says format ' + (l && l.format))); }
    },
    {
        finding: 'P2GATE-LOG-OPEN-FORMAT', title: 'Without the setting, the 405 for an MCP GET stream is logged with format mcp (live r14 logged "unknown")',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, legs: ['request'], airs: R.answers('allow-prompt') },
        v3: function (r) { var q = r.request, l = lastLog(q); return S.check(q.fault && q.status === 405 && l && l.format === 'mcp', 'HTTP ' + q.status + '; the log line says format ' + (l && l.format)); }
    },

    /* ================= regression guards: pass today ================= */
    {
        finding: 'P2GATE-GUARD-BATCH-IDS', title: 'Guard: a refused batch answers each id as sent, a number and a string, in the batch\'s order (errors.rs:101, :118)',
        setup: Object.assign(rpc([call(1, 'Card ' + C), call('two', 'hello')]), { legs: ['request'], airs: R.answers('block-tool-input', 'allow-tool') }),
        v3: function (r) { return refusedBatch(r.request, [1, 'two'], -32001); }
    },
    {
        finding: 'P2GATE-GUARD-NOTIF-BATCH', title: 'Guard: a batch of notifications only, refused, gets one error with id null in HTTP 403 (errors.rs:132)',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 1, progress: 1 }, messages: [{ role: 'user', content: 'Card ' + C }] }]),
                             { legs: ['request'], airs: R.answers('block-dlp-prompt-masked') }),
        v3: function (r) {
            var q = r.request, b = body(q);
            return S.check(q.blocked && q.status === 403 && b && !Array.isArray(b) && b.id === null && b.error && b.error.code === -32001, 'HTTP ' + q.status + ' ' + q.body);
        }
    },
    {
        finding: 'P2GATE-GUARD-BATCH-CONFIG', title: 'Guard: a rejected setting refuses a batch with -32003 per id, HTTP 200, before any scan (errors.rs:143)',
        setup: Object.assign(rpc([call(1, 'hello'), call(2, 'hello')]), { legs: ['request'], airs: R.answers('allow-tool'), vars: { mcpBatchLimit: '9' } }),
        v3: function (r) { var q = r.request; return and(S.check(q.calls.length === 0, q.calls.length + ' scans'), refusedBatch(q, [1, 2], -32003)); }
    },
    {
        finding: 'P2GATE-GUARD-ARRAY-ERROR', title: 'Guard: in a reply array, an error answer to a tools/call member is its own text scan, not a tool event (mcp_reply.rs:123)',
        setup: Object.assign(rpc([call(1, 'hello'), call(2, 'hello')]), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: S.reply([ans(1, echoed('ok')), { jsonrpc: '2.0', id: 2, error: { code: -32000, message: 'Tool failed. ' + M } }]) }),
        v3: function (r) {
            var p = r.response, a = entry(p, 0), b = entry(p, 1);
            return and(passed(p), S.check(p.calls.length === 2 && a.tool_event && b && !b.tool_event && p.scanned.indexOf('Tool failed. ' + M) !== -1, 'the scans are ' + shape(p)));
        }
    },
    {
        finding: 'P2GATE-GUARD-MEMBER-GAP', title: 'Guard: a batch member over maxScanChars refuses the whole batch before any scan, -32001 per id (the first gap ends the leg)',
        setup: Object.assign(rpc([call(1, 'hello'), call(2, S.filler(300))]), { legs: ['request'], airs: R.answers('allow-tool'), vars: { maxScanChars: '200' } }),
        v3: function (r) { var q = r.request; return and(S.check(q.calls.length === 0, q.calls.length + ' scans'), refusedBatch(q, [1, 2], -32001)); }
    },
    {
        finding: 'P2GATE-GUARD-CLIENT-REPLY-MEMBER', title: 'Guard: a client\'s answer to a server request (an elicitation result) inside a batch is its own text scan, in order (mcp_request.rs:166, :175)',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', id: 'srv-7', result: { action: 'accept', content: { note: 'Elicit answer. ' + M } } }, call(2, 'hello')]),
                             { legs: ['request'], airs: R.answers('allow-prompt', 'allow-tool') }),
        v3: function (r) {
            var q = r.request, a = entry(q, 0), b = entry(q, 1);
            return and(passed(q), S.check(q.calls.length === 2 && a && !a.tool_event && String(a.prompt).indexOf('Elicit answer. ' + M) !== -1 && b && b.tool_event, 'the scans are ' + shape(q)));
        }
    },
    {
        finding: 'P2GATE-GUARD-OPEN-POST', title: 'Guard: allowOpenStreams=true opens no POST: a tools/call with the card is still scanned and refused, -32001 with id 44 (MuleSoft\'s setting is for GET streams)',
        setup: Object.assign(rpc(call(44, 'Card ' + C)), { legs: ['request'], airs: R.answers('block-tool-input'), vars: { allowOpenStreams: 'true' } }),
        v3: function (r) {
            var q = r.request, b = body(q);
            return S.check(q.blocked && q.status === 200 && q.calls.length === 1 && b && b.id === 44 && b.error && b.error.code === -32001, 'HTTP ' + q.status + ' ' + q.body);
        }
    }
];

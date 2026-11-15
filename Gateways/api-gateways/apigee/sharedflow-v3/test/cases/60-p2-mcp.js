'use strict';
/*
 * Phase 2, MCP completely: batches member by member, the scan slots, the messages that answer no request member, the
 * settings mcpBatchLimit and allowOpenStreams, and a tools/list tool event past the size limit. The rules are those of
 * this repository's MuleSoft policy; the MuleSoft tests ported as such are in 53 to 57.
 *   - P2-BATCH-*: each member its own scan, in order; the first refusal stops the slots after it and refuses the batch,
 *     one JSON-RPC error per member with an id; a failure that failOpen lets pass goes on to the next member.
 *   - P2-SLOTS-*: the 8 slots: 8 members are 8 scans; a leg that needs more is refused.
 *   - P2-REPLY-*: a reply array is split; an answer is matched by its id as a JSON value; messages that answer no member
 *     are one text scan, after the answers.
 *   - P2-SET-*: the two settings, read strictly.
 *   - P2-OPEN-*: allowOpenStreams lets an MCP GET stream and an MCP event-stream reply pass unscanned, logged.
 *   - P2-LIST-*: a tools/list tool event over maxScanChars goes as text.
 * The only marked text is AIRSV3-MARKER and the test card; nothing here decides a verdict, each case names its replies.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };

function rpc(body, headers) { return S.req(S.P.mcp, body, Object.assign({}, H, headers || {})); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
function list(id) { return { jsonrpc: '2.0', id: id, method: 'tools/list', params: {} }; }
function ans(id, result) { return { jsonrpc: '2.0', id: id, result: result }; }
function echoed(text) { return { content: [{ type: 'text', text: text }], isError: false }; }
function calls(n, text) { var out = []; for (var i = 1; i <= n; i++) { out.push(call(i, (text || 'hello') + ' ' + i)); } return out; }
function body(x) { try { return JSON.parse(x.body); } catch (e) { return null; } }
function v(x, leaf) { return String(x.flow.get('airs3.' + leaf) || ''); }
function entry(x, i) { var b = x.scans[i]; return b && b.contents && b.contents[0]; }
function lastLog(x) { var l = x.flow.logs; try { return l.length ? JSON.parse(l[l.length - 1].line) : null; } catch (e) { return null; } }
function passed(x) { return !x ? 'the leg did not run' : (x.fault ? 'it was refused: ' + String(x.body).slice(0, 200) : true); }
function and() { for (var i = 0; i < arguments.length; i++) { if (arguments[i] !== true) { return arguments[i]; } } return true; }
// The batch refusal: HTTP 200, one error per member with an id, each with the code given.
function refusedBatch(x, ids, code) {
    var b = body(x);
    var got = Array.isArray(b) ? b.map(function (e) { return e && e.error && e.error.code === code ? e.id : 'bad'; }) : null;
    return S.check(x && x.blocked && x.status === 200 && JSON.stringify(got) === JSON.stringify(ids),
                   'not refused as ' + JSON.stringify(ids) + ' with ' + code + ': HTTP ' + (x && x.status) + ' ' + String(x && x.body).slice(0, 200));
}

module.exports = [
    /* ---------------- batches ---------------- */
    {
        finding: 'P2-BATCH-1', title: 'A batch of two tools/call members is two scans, in order, both tool events; allowed, it passes, and the log line counts 2 scans and says it was a batch',
        setup: Object.assign(rpc([call(1, 'first ' + M), call(2, 'second ' + M)]), { legs: ['request'], airs: R.answers('allow-tool', 'allow-tool') }),
        v3: function (r) {
            var x = r.request, a = entry(x, 0), b = entry(x, 1), l = lastLog(x);
            return and(passed(x), S.check(x.calls.length === 2 && a && a.tool_event && b && b.tool_event &&
                                          String(a.tool_event.input).indexOf('first') !== -1 && String(b.tool_event.input).indexOf('second') !== -1,
                                          'not two tool events in order: ' + JSON.stringify([a, b]).slice(0, 300)),
                       S.check(l && String(l.scans) === '2' && l.note === 'a batch of 2 messages', 'the log line is ' + JSON.stringify(l)));
        }
    },
    {
        finding: 'P2-BATCH-2', title: 'The first block stops the slots after it: [card, hello] is one scan, and the whole batch is refused, -32001 for ids 1 and 2',
        setup: Object.assign(rpc([call(1, 'Card ' + C), call(2, 'hello')]), { legs: ['request'], airs: R.answers('block-tool-input', 'allow-tool') }),
        v3: function (r) { var x = r.request; return and(S.check(x.calls.length === 1, x.calls.length + ' scans, not 1 (slot 2 ran after the block)'), refusedBatch(x, [1, 2], -32001)); }
    },
    {
        finding: 'P2-BATCH-3', title: 'A scanner failure on the first member stops the batch: one scan, the batch refused with -32003 per id',
        setup: Object.assign(rpc(calls(2)), { legs: ['request'], airs: R.answers(R.noAnswer(), 'allow-tool') }),
        v3: function (r) { var x = r.request; return and(S.check(x.calls.length === 1, x.calls.length + ' scans, not 1'), refusedBatch(x, [1, 2], -32003)); }
    },
    {
        finding: 'P2-BATCH-4', title: 'With failOpen=true, a failure on the first member goes on to the second; both allowed, the batch passes, logged as failed open',
        setup: Object.assign(rpc(calls(2)), { legs: ['request'], airs: R.answers(R.noAnswer(), 'allow-tool'), vars: { failOpen: 'true' } }),
        v3: function (r) {
            var x = r.request, l = lastLog(x);
            return and(passed(x), S.check(x.calls.length === 2, x.calls.length + ' scans, not 2'),
                       S.check(l && /^failed open/.test(l.note || '') && String(l.scans) === '2', 'the log line is ' + JSON.stringify(l)));
        }
    },
    {
        finding: 'P2-BATCH-5', title: 'A block on the last member of three still refuses the whole batch, after three scans',
        setup: Object.assign(rpc([call(1, 'hello'), call(2, 'hello'), call(3, 'Card ' + C)]), { legs: ['request'], airs: R.answers('allow-tool', 'allow-tool', 'block-tool-input') }),
        v3: function (r) { var x = r.request; return and(S.check(x.calls.length === 3, x.calls.length + ' scans, not 3'), refusedBatch(x, [1, 2, 3], -32001)); }
    },
    {
        finding: 'P2-BATCH-6', title: 'Quiet members scan nothing: [ping, tools/list, notifications/initialized, a tools/call] is one scan',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', id: 1, method: 'ping' }, list(2), { jsonrpc: '2.0', method: 'notifications/initialized' }, call(4, 'hello ' + M)]),
                             { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) { var x = r.request; return and(passed(x), S.check(x.calls.length === 1 && S.has(x, M), x.calls.length + ' scans, not 1')); }
    },
    {
        finding: 'P2-BATCH-7', title: 'A batch whose members scan nothing passes with no scan, logged',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', id: 1, method: 'ping' }, list(2)]), { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) { var x = r.request; return and(passed(x), S.check(x.calls.length === 0 && v(x, 'route') === 'pass', x.calls.length + ' scans, route ' + v(x, 'route'))); }
    },
    {
        finding: 'P2-BATCH-8', title: 'A member that carries text but is not tools/call (resources/read) is a text scan, between the tool events, in order',
        setup: Object.assign(rpc([call(1, 'hello'), { jsonrpc: '2.0', id: 2, method: 'resources/read', params: { uri: 'lab://note-' + M } }, call(3, 'bye')]),
                             { legs: ['request'], airs: R.answers('allow-tool', 'allow-prompt', 'allow-tool') }),
        v3: function (r) {
            var x = r.request, b = entry(x, 1);
            return and(passed(x), S.check(x.calls.length === 3 && entry(x, 0).tool_event && b && !b.tool_event && String(b.prompt || '').indexOf(M) !== -1 && entry(x, 2).tool_event,
                                          'not tool event, text, tool event: ' + JSON.stringify(x.scans.map(function (s) { return s && s.contents[0]; })).slice(0, 300)));
        }
    },

    /* ---------------- the slots ---------------- */
    {
        finding: 'P2-SLOTS-1', title: 'Eight members, the default mcpBatchLimit, are eight scans, slot 8 included',
        setup: Object.assign(rpc(calls(8)), { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) { var x = r.request; return and(passed(x), S.check(x.calls.length === 8 && v(x, 'slotRan8') === 'true', x.calls.length + ' scans; slot 8 ran: ' + v(x, 'slotRan8'))); }
    },
    {
        finding: 'P2-SLOTS-2', title: 'A reply that needs more than 8 scans (5 tools/list answers, each with a member besides tools) is withheld before any scan',
        setup: Object.assign(rpc([list(1), list(2), list(3), list(4), list(5)]), { legs: ['response'], airs: R.answers('allow-prompt-response'),
            response: S.reply([1, 2, 3, 4, 5].map(function (n) { return ans(n, { tools: [{ name: 't' + n, description: 'tool ' + n }], notice: 'note ' + n }); })) }),
        v3: function (r) {
            var p = r.response;
            return and(S.check(p && p.fault && p.calls.length === 0 && v(p, 'refuseMsg').indexOf('more than 8 scans') !== -1, 'not withheld before any scan: ' + (p && v(p, 'refuseMsg'))),
                       refusedBatch(p, [1, 2, 3, 4, 5], -32001));
        }
    },
    {
        finding: 'P2-SLOTS-3', title: 'Each leg starts with every slot flag false: a reply leg of one scan after a request leg of three reads slot 1 only',
        setup: Object.assign(rpc(calls(3)), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool', 'allow-tool', 'allow-tool'),
            response: S.reply([ans(1, echoed('one'))]) }),
        v3: function (r) {
            var p = r.response;
            return and(passed(p), S.check(p.calls.length === 1 && v(p, 'slotRan2') === 'false' && v(p, 'slotRan3') === 'false' && v(p, 'scansRan') === '1',
                                          'reply leg: ' + p.calls.length + ' scans, slotRan2 ' + v(p, 'slotRan2') + ', scansRan ' + v(p, 'scansRan')));
        }
    },

    /* ---------------- replies ---------------- */
    {
        finding: 'P2-REPLY-1', title: 'A reply array to a batch: each answer is its member\'s tool event, with that member\'s arguments as input',
        setup: Object.assign(rpc([call(1, 'ask one'), call(2, 'ask two')]), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: S.reply([ans(2, echoed('answer two ' + M)), ans(1, echoed('answer one ' + M))]) }),
        v3: function (r) {
            var p = r.response, a = entry(p, 0), b = entry(p, 1);
            return and(passed(p), S.check(p.calls.length === 2 && a.tool_event && b.tool_event &&
                                          String(a.tool_event.input).indexOf('ask two') !== -1 && String(a.tool_event.output).indexOf('answer two') !== -1 &&
                                          String(b.tool_event.input).indexOf('ask one') !== -1 && String(b.tool_event.output).indexOf('answer one') !== -1,
                                          'the answers were not matched to their members: ' + JSON.stringify([a, b]).slice(0, 400)));
        }
    },
    {
        finding: 'P2-REPLY-2', title: 'An answer matches by its id as a JSON value: "1" does not answer 1, so it is read as a message that answers no member, as text, after the answers',
        setup: Object.assign(rpc([call(1, 'ask one'), call(2, 'ask two')]), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: S.reply([ans('1', echoed('string id ' + M)), ans(2, echoed('answer two'))]) }),
        v3: function (r) {
            var p = r.response, a = entry(p, 0), b = entry(p, 1);
            return and(passed(p), S.check(p.calls.length === 2 && a.tool_event && String(a.tool_event.output).indexOf('answer two') !== -1 &&
                                          b && !b.tool_event && b.response === undefined && String(b.prompt || '').indexOf('string id ' + M) !== -1,
                                          'not the answer, then the stray message as text: ' + JSON.stringify([a, b]).slice(0, 400)));
        }
    },
    {
        finding: 'P2-REPLY-3', title: 'Notifications and the server\'s own requests in a reply array are one text scan, after the answer',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: S.reply([{ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'note one ' + M } },
                               ans(3, echoed('the answer')),
                               { jsonrpc: '2.0', id: 77, method: 'sampling/createMessage', params: { messages: [{ role: 'user', content: { type: 'text', text: 'server asks ' + M } }] } }]) }),
        v3: function (r) {
            var p = r.response, a = entry(p, 0), b = entry(p, 1);
            return and(passed(p), S.check(p.calls.length === 2 && a.tool_event && String(a.tool_event.output).indexOf('the answer') !== -1 &&
                                          b && !b.tool_event && b.response === undefined && String(b.prompt).indexOf('note one ' + M) !== -1 && String(b.prompt).indexOf('server asks ' + M) !== -1,
                                          'not the answer, then both other messages in one text: ' + JSON.stringify([a, b]).slice(0, 400)));
        }
    },
    {
        finding: 'P2-REPLY-4', title: 'A block on the second answer of a reply array withholds the whole reply, one error per request member with an id',
        setup: Object.assign(rpc([call(1, 'hello'), call(2, 'hello')]), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool', 'allow-tool', 'block-tool-output'),
            response: S.reply([ans(1, echoed('fine')), ans(2, echoed('Card ' + C))]) }),
        v3: function (r) { var p = r.response; return and(S.check(p.calls.length === 2, p.calls.length + ' scans, not 2'), refusedBatch(p, [1, 2], -32001)); }
    },

    /* ---------------- settings ---------------- */
    {
        finding: 'P2-SET-1', title: 'mcpBatchLimit=3: a batch of 4 is refused before any scan; a batch of 3 is scanned',
        setup: Object.assign(rpc(calls(4)), { legs: ['request'], airs: R.answers('allow-tool'), vars: { mcpBatchLimit: '3' } }),
        v3: function (r) { var x = r.request; return and(S.check(x.calls.length === 0, x.calls.length + ' scans'), refusedBatch(x, [1, 2, 3, 4], -32001)); }
    },
    {
        finding: 'P2-SET-1b', title: 'Guard: mcpBatchLimit=3 and a batch of 3: three scans, it passes',
        setup: Object.assign(rpc(calls(3)), { legs: ['request'], airs: R.answers('allow-tool'), vars: { mcpBatchLimit: '3' } }),
        v3: function (r) { var x = r.request; return and(passed(x), S.check(x.calls.length === 3, x.calls.length + ' scans, not 3')); }
    },
    {
        finding: 'P2-SET-2', title: 'mcpBatchLimit above the 8 slots (9), not a number, or 0 refuses every request as a setting problem, naming it',
        setup: Object.assign(rpc(call(1, 'hello')), { legs: ['request'], airs: R.answers('allow-tool'), vars: { mcpBatchLimit: '9' } }),
        v3: function (r) { var x = r.request; return S.check(x.fault && x.calls.length === 0 && v(x, 'refuse') === 'config' && v(x, 'refuseMsg').indexOf('mcpBatchLimit') !== -1, 'not a config refusal: ' + v(x, 'refuseMsg')); }
    },
    {
        finding: 'P2-SET-2b', title: 'mcpBatchLimit=abc refuses as a setting problem',
        setup: Object.assign(rpc(call(1, 'hello')), { legs: ['request'], airs: R.answers('allow-tool'), vars: { mcpBatchLimit: 'abc' } }),
        v3: function (r) { var x = r.request; return S.check(x.fault && v(x, 'refuse') === 'config' && v(x, 'refuseMsg').indexOf('mcpBatchLimit') !== -1, 'not a config refusal: ' + v(x, 'refuseMsg')); }
    },
    {
        finding: 'P2-SET-2c', title: 'mcpBatchLimit=0 refuses as a setting problem',
        setup: Object.assign(rpc(call(1, 'hello')), { legs: ['request'], airs: R.answers('allow-tool'), vars: { mcpBatchLimit: '0' } }),
        v3: function (r) { var x = r.request; return S.check(x.fault && v(x, 'refuse') === 'config' && v(x, 'refuseMsg').indexOf('mcpBatchLimit') !== -1, 'not a config refusal: ' + v(x, 'refuseMsg')); }
    },
    {
        finding: 'P2-SET-3', title: 'allowOpenStreams=maybe refuses every request as a setting problem, naming it',
        setup: Object.assign(rpc(call(1, 'hello')), { legs: ['request'], airs: R.answers('allow-tool'), vars: { allowOpenStreams: 'maybe' } }),
        v3: function (r) { var x = r.request; return S.check(x.fault && v(x, 'refuse') === 'config' && v(x, 'refuseMsg').indexOf('allowOpenStreams') !== -1, 'not a config refusal: ' + v(x, 'refuseMsg')); }
    },

    /* ---------------- open streams ---------------- */
    {
        finding: 'P2-OPEN-1', title: 'allowOpenStreams=true: an MCP GET for an event stream passes unscanned on both legs, logged',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, legs: ['request', 'response'], airs: R.answers('allow-prompt'),
                 vars: { allowOpenStreams: 'true' }, response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } },
        v3: function (r) {
            var q = r.request, p = r.response, lq = lastLog(q), lp = lastLog(p);
            return and(passed(q), passed(p), S.check(q.calls.length === 0 && p.calls.length === 0, 'scanned'),
                       S.check(lq && /open stream passes unscanned/.test(lq.note || '') && lp && /open stream passes unscanned/.test(lp.note || ''),
                               'log lines: ' + JSON.stringify([lq && lq.note, lp && lp.note])));
        }
    },
    {
        finding: 'P2-OPEN-1g', title: 'Guard: without the setting, the same GET still gets 405',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, legs: ['request'], airs: R.answers('allow-prompt') },
        v3: function (r) { var x = r.request; return S.check(x.fault && x.status === 405 && x.calls.length === 0, 'HTTP ' + x.status); }
    },
    {
        finding: 'P2-OPEN-2', title: 'allowOpenStreams=true: an MCP reply sent as an event stream the flow can\'t see passes unscanned, logged, after the request was scanned',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'), vars: { allowOpenStreams: 'true' },
            response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } }),
        v3: function (r) {
            var q = r.request, p = r.response, l = lastLog(p);
            return and(passed(q), passed(p), S.check(q.calls.length === 1 && p.calls.length === 0 && l && /event-stream reply passes unscanned/.test(l.note || ''),
                                                    'request scans ' + q.calls.length + ', reply scans ' + p.calls.length + ', note ' + (l && l.note)));
        }
    },
    {
        finding: 'P2-OPEN-2b', title: 'allowOpenStreams=true: the same reply when a runtime shows its body also passes unscanned, logged',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'), vars: { allowOpenStreams: 'true' },
            response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: 'event: message\ndata: ' + JSON.stringify(ans(3, echoed('Card ' + C))) + '\n\n' } }),
        v3: function (r) { var p = r.response, l = lastLog(p); return and(passed(p), S.check(p.calls.length === 0 && l && /event-stream reply passes unscanned/.test(l.note || ''), 'note ' + (l && l.note))); }
    },
    {
        finding: 'P2-OPEN-2g', title: 'Guard: without the setting, the same event-stream reply is withheld with -32001 and id 3',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } }),
        v3: function (r) {
            var p = r.response, b = body(p);
            return S.check(p && p.blocked && p.status === 200 && b && b.id === 3 && b.error && b.error.code === -32001 && p.calls.length === 0, 'HTTP ' + (p && p.status) + ': ' + (p && p.body));
        }
    },

    /* ---------------- tools/list past the size limit ---------------- */
    {
        finding: 'P2-LIST-1', title: 'A tools/list tool event over maxScanChars goes as text, cut to the first part with truncationFailClosed=false',
        setup: Object.assign(rpc(list(2)), { legs: ['response'], airs: R.answers('allow-prompt-response'), vars: { maxScanChars: '500', truncationFailClosed: 'false' },
            response: S.reply(ans(2, { tools: [{ name: 'long', description: M + ' ' + S.filler(600) }] })) }),
        v3: function (r) {
            var p = r.response, e = entry(p, 0);
            return and(passed(p), S.check(p.calls.length === 1 && e && !e.tool_event && e.response === undefined && String(e.prompt || '').length === 500 && String(e.prompt).indexOf(M) !== -1,
                                          'not 500 characters of text: ' + JSON.stringify(e).slice(0, 200)));
        }
    }
];

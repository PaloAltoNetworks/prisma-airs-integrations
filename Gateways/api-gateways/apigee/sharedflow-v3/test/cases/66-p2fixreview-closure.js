'use strict';
/*
 * The fixes for the review of phase 2, reviewed for closure and new holes (15 Nov 2026): does each fix close its finding on both
 * legs, on the one-scan and the several-scan path, for near variants of its input, and did a fix open a skip?
 *   - P2FR-C-01: type=both on MCP drops a request tool event that the reply's tool event repeats. When that reply tool
 *     event is over maxScanChars it goes as text holding the result only, so the request's arguments reach no scan.
 *   - P2FR-C-02: MCP text over the limit now keeps its first part on the request leg too. A chat body that adds jsonrpc,
 *     id and method is read as MCP, so with truncationFailClosed=false its newest turn, which the LLM rule keeps, is the
 *     part left unscanned: an LLM body dressed as JSON-RPC gains a skip (design 3.1 says it gains none).
 *   - P2FR-C-03: type=both puts the request's scans first, so with onScanError=allow the slots past 8 that pass
 *     unscanned are the reply's own answers, which type=response-prompt scans.
 *   - P2FR-C-04: an answer's error is now a second scan beside its tool event, and an `error: null` (JSON-RPC 1.0's
 *     success shape) counts as one: a text scan of "null" per answer, so a batch of 5 calls needs 10 scans and is refused.
 *   - P2FR-C-05: a scan passed by the per-scan gap rule is logged in many(), but the verdict's note replaces that note
 *     when another slot fails open, so the log line no longer says a part passed unscanned.
 *   - P2FR-C-GUARD: near variants of the review's findings that the fixes do close; they pass today and pin the fixes.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get, and
 * nothing here decides a verdict from content. Bodies with a member named like an Object.prototype property are JSON text.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };

function rpc(body) { return S.req(S.P.mcp, body, H); }
function call(id, args) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: args } }; }
function read(id, uri) { return { jsonrpc: '2.0', id: id, method: 'resources/read', params: { uri: uri } }; }
function ans(id, result) { return { jsonrpc: '2.0', id: id, result: result }; }
function echoed(text) { return { content: [{ type: 'text', text: text }], isError: false }; }
function page(uri, text) { return { contents: [{ uri: uri, mimeType: 'text/plain', text: text }] }; }
function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' scan(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 160) : ', passed');
}
function shape(x) { return JSON.stringify(x.scans.map(function (s) { return s && s.contents; })).slice(0, 300); }
function passed(x) { return !x ? 'the leg did not run' : (x.fault ? 'it was refused: ' + String(x.body).slice(0, 200) : true); }
function and() { for (var i = 0; i < arguments.length; i++) { if (arguments[i] !== true) { return arguments[i]; } } return true; }
// Scanned, or withheld: either keeps the text from passing unread (fail closed).
function scannedOrRefused(x, text) {
    if (!x) { return 'the leg did not run'; }
    if (x.fault && x.blocked) { return true; }
    return S.check(x.scanned.indexOf(text) !== -1, '"' + text + '" passed unscanned: ' + state(x) + ' ' + shape(x));
}
// The last log line, for a case that runs one leg only.
function lastLog(x) { var l = x && x.flow ? x.flow.logs : []; try { return l.length ? JSON.parse(l[l.length - 1].line) : null; } catch (e) { return null; } }

// P2FR-C-01: arguments of about 200 characters with the card, a result of 25; together over a limit of 200, each within it.
const BIG_ARGS = { text: 'Card ' + C + '. ' + S.filler(160) };
const SHORT_RESULT = 'done ' + S.filler(20);
// P2FR-C-02: a chat body whose newest turn sits past the first 200 characters.
const TURNS = [{ role: 'user', content: S.filler(300) }, { role: 'user', content: 'Newest turn. ' + M }];
function chatBody(body) { return { path: S.P.chat, request: { verb: 'POST', headers: { 'Content-Type': 'application/json' }, content: JSON.stringify(body) } }; }
// P2FR-C-03: five resources/read and their five answers; the fifth carries the marker.
const FIVE_READS = [1, 2, 3, 4, 5].map(function (n) { return read(n, 'lab://p' + n); });
const FIVE_PAGES = [1, 2, 3, 4, 5].map(function (n) { return ans(n, page('lab://p' + n, n === 5 ? 'Page five. ' + M : 'Page ' + n + '.')); });

module.exports = [
    /* ================= findings: each fails on today's v3 ================= */
    {
        // airs3-read.js:146-153 drops a request tool event whose (tool, input) a reply tool event repeats; many() (line 84)
        // then sends that reply tool event as text when input + output pass maxScanChars, and its text (replyOne's
        // callSegs, airs3-fmt-mcp.js:162-163) is the result only, where MuleSoft's text form holds the arguments and the
        // result (reply.rs:94-95, mod.rs tool_or_text()). The arguments, which would have fit as their own tool event,
        // reach no scan; README's type row says such an event "is judged once".
        finding: 'P2FR-C-01', title: 'type=both, reply leg only: a tools/call whose arguments carry the card, answered so that arguments and result together pass maxScanChars: the arguments are scanned or the reply withheld',
        setup: Object.assign(rpc(call(3, BIG_ARGS)), { legs: ['response'], params: { response: { type: 'both' } }, vars: { maxScanChars: '200' },
            airs: R.answers('allow-prompt', 'allow-tool'), response: S.reply(ans(3, echoed(SHORT_RESULT))) }),
        v3: function (r) { return scannedOrRefused(r.response, 'Card ' + C); }
    },
    {
        // The same through replyOne's members-outside-the-envelope branch (airs3-fmt-mcp.js:143-149): its tool event's
        // text, over the limit, is the reply body alone.
        finding: 'P2FR-C-01', title: 'type=both, reply leg only: the same call answered with a bolted member beside the result: the arguments are scanned or the reply withheld',
        setup: Object.assign(rpc(call(3, BIG_ARGS)), { legs: ['response'], params: { response: { type: 'both' } }, vars: { maxScanChars: '200' },
            airs: R.answers('allow-prompt', 'allow-tool'),
            response: S.reply({ jsonrpc: '2.0', id: 3, result: { content: [{ type: 'text', text: 'done' }] }, extra: 'Bolted text.' }) }),
        v3: function (r) { return scannedOrRefused(r.response, 'Card ' + C); }
    },
    {
        // airs3-read.js:179: with truncationFailClosed=false the newest part is kept only when format !== 'mcp'. A body
        // with jsonrpc, id and method is MCP on any path (airs3-detect.js:76) and is read whole (requestOne's extras path),
        // so its first 200 characters are scanned and its newest turn passes unscanned to the model. Before the fixes
        // the request leg kept the newest part for MCP too. The README advises this setting for agent proxies.
        finding: 'P2FR-C-02', title: 'truncationFailClosed=false: a chat body at /v1/chat/completions that adds jsonrpc, id and method has its newest turn scanned, as the same body without them does',
        setup: Object.assign(chatBody({ jsonrpc: '2.0', id: 1, method: 'chat', model: 'm', messages: TURNS }),
                             { legs: ['request'], airs: R.answers('allow-prompt'), vars: { maxScanChars: '200', truncationFailClosed: 'false' } }),
        v3: function (r) { return scannedOrRefused(r.request, 'Newest turn. ' + M); }
    },
    {
        // airs3-read.js:154 many(list.concat(replyScans)): 5 request scans, then 5 answers; many() keeps the first 8
        // (lines 100-105), so answers 4 and 5 pass unscanned, which type=response-prompt would scan (the guard below).
        finding: 'P2FR-C-03', title: 'type=both with onScanError=allow, reply leg only: a batch of 5 resources/read: the fifth answer is scanned or the reply withheld, as with type=response-prompt',
        setup: Object.assign(rpc(FIVE_READS), { legs: ['response'], params: { response: { type: 'both' } }, vars: { onScanError: 'allow' },
            airs: R.answers('allow-prompt'), response: S.reply(FIVE_PAGES) }),
        v3: function (r) { return scannedOrRefused(r.response, 'Page five. ' + M); }
    },
    {
        // airs3-fmt-mcp.js:157 seg(asWritten(null)) gives the text "null", so each tools/call answer becomes 2 scans
        // (lines 165-167). MuleSoft's outside() (reply.rs:96, 125-130) collects no text from a null (mod.rs collect(),
        // `_ => {}`), so text_scan() makes no second scan (reply.rs:118). 5 answers need 10 scans: more than the 8 slots,
        // refused with the defaults, where the request leg passed the same 5 calls.
        finding: 'P2FR-C-04', title: 'A batch of 5 tools/call answered with a result and "error": null each: the reply passes with one tool event per answer, no "null" text scans',
        setup: Object.assign(rpc([1, 2, 3, 4, 5].map(function (n) { return call(n, { text: 'ask ' + n }); })), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: S.reply([1, 2, 3, 4, 5].map(function (n) { return { jsonrpc: '2.0', id: n, result: echoed('answer ' + n), error: null }; })) }),
        v3: function (r) {
            var p = r.response, nulls = p ? p.scans.filter(function (s) { var e = s && s.contents && s.contents[0]; return e && e.prompt === 'null'; }).length : 0;
            return and(passed(p), S.check(p.calls.length === 5 && nulls === 0, state(p) + ' ' + shape(p)));
        }
    },
    {
        // airs3-read.js:107 logs the gap-allowed part; airs3-verdict.js:49 replaces logNote with the picked slot's note
        // ("failed open: ..."), so the line no longer says that a part passed unscanned (design 3.1: every logged pass
        // depends on the line).
        finding: 'P2FR-C-05', title: 'onScanError=allow and failOpen=true: a batch [an oversize call, a short call] whose scan gets no answer: the log line still says the oversize part passed unscanned',
        setup: Object.assign(rpc([call(1, { text: S.filler(300) }), call(2, { text: 'short' })]),
                             { legs: ['request'], airs: R.answers(R.noAnswer()), vars: { maxScanChars: '200', onScanError: 'allow', failOpen: 'true' } }),
        v3: function (r) {
            var x = r.request, line = lastLog(x);
            return and(passed(x), S.check(line && /gap allowed/.test(line.note || ''), 'the log line\'s note: ' + JSON.stringify(line && line.note) + ' ' + state(x)));
        }
    },

    /* ================= guards: pass today, pin the fixes on near variants ================= */
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (C-01): type=both, the same call within the limit: one scan, the reply\'s tool event, which carries the arguments',
        setup: Object.assign(rpc(call(3, BIG_ARGS)), { legs: ['response'], params: { response: { type: 'both' } },
            airs: R.answers('allow-tool'), response: S.reply(ans(3, echoed(SHORT_RESULT))) }),
        v3: function (r) {
            var p = r.response, e = p && p.scans[0] && p.scans[0].contents[0];
            return and(passed(p), S.check(p.calls.length === 1 && e && e.tool_event && String(e.tool_event.input).indexOf('Card ' + C) !== -1 &&
                                          String(e.tool_event.output).indexOf('done') !== -1, state(p) + ' ' + shape(p)));
        }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (C-01): type=both, a tools/call answered with an error: no reply tool event repeats the call, so the request\'s tool event is judged',
        setup: Object.assign(rpc(call(3, { text: 'Card ' + C })), { legs: ['response'], params: { response: { type: 'both' } },
            airs: R.answers('allow-tool', 'allow-prompt'), response: S.reply({ jsonrpc: '2.0', id: 3, error: { code: -32000, message: 'Tool failed.' } }) }),
        v3: function (r) {
            var p = r.response, te = p ? p.scans.filter(function (s) { var e = s && s.contents && s.contents[0]; return e && e.tool_event && String(e.tool_event.input).indexOf('Card ' + C) !== -1; }) : [];
            return and(passed(p), S.check(p.calls.length === 2 && te.length === 1 && S.has(p, 'Tool failed.'), state(p) + ' ' + shape(p)));
        }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (C-02): truncationFailClosed=false: the same chat body without jsonrpc, id and method has its newest 200 characters scanned',
        setup: Object.assign(chatBody({ model: 'm', messages: TURNS }), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { maxScanChars: '200', truncationFailClosed: 'false' } }),
        v3: function (r) { var x = r.request; return and(passed(x), S.check(x.calls.length === 1 && S.has(x, 'Newest turn. ' + M), state(x) + ' ' + shape(x))); }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (C-03): type=response-prompt with onScanError=allow, the same batch of 5 resources/read: all 5 answers are scanned',
        setup: Object.assign(rpc(FIVE_READS), { legs: ['response'], vars: { onScanError: 'allow' }, airs: R.answers('allow-prompt'), response: S.reply(FIVE_PAGES) }),
        v3: function (r) { var p = r.response; return and(passed(p), S.check(p.calls.length === 5 && S.has(p, 'Page five. ' + M), state(p))); }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (C-04): a tools/list answer with an error beside its tools: the tool event, then the error as a second scan, as text',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }), { legs: ['response'], airs: R.answers('allow-tool', 'allow-prompt'),
            response: S.reply({ jsonrpc: '2.0', id: 2, result: { tools: [] }, error: { code: 1, message: 'List note. ' + M } }) }),
        v3: function (r) {
            var p = r.response, a = p && p.scans[0] && p.scans[0].contents[0], b = p && p.scans[1] && p.scans[1].contents[0];
            return and(passed(p), S.check(p.calls.length === 2 && a && a.tool_event && b && !b.tool_event && String(b.prompt).indexOf('List note. ' + M) !== -1, state(p) + ' ' + shape(p)));
        }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (C-05): onScanError=allow, the same batch with a clean allow: the log line says the oversize part passed unscanned',
        setup: Object.assign(rpc([call(1, { text: S.filler(300) }), call(2, { text: 'short' })]),
                             { legs: ['request'], airs: R.answers('allow-tool'), vars: { maxScanChars: '200', onScanError: 'allow' } }),
        v3: function (r) { var x = r.request, line = lastLog(x); return and(passed(x), S.check(line && /gap allowed/.test(line.note || ''), JSON.stringify(line && line.note))); }
    },
    {
        // P2GATE-STOP and AR1 at a later slot: the masked copy of a tool input in slot 2's allow, not slot 1's.
        finding: 'P2FR-C-GUARD', title: 'Guard (STOP, AR1): a reply array of 3 tools/call answers whose second scan is an allow carrying a masked copy of its input: 2 scans, refused for ids 1 to 3',
        setup: Object.assign(rpc([call(1, { text: 'one' }), call(2, { text: 'two' }), call(3, { text: 'three' })]), { legs: ['response'],
            airs: R.answers('allow-tool', R.asAllow('block-tool-input'), 'allow-tool'), response: S.reply([ans(1, echoed('a1')), ans(2, echoed('a2')), ans(3, echoed('a3 ' + M))]) }),
        v3: function (r) {
            var p = r.response, b = null;
            try { b = JSON.parse(p.body); } catch (e) { b = null; }
            return S.check(p && p.blocked && p.calls.length === 2 && Array.isArray(b) && b.length === 3 && b[2].id === 3 && b[2].error.code === -32001, state(p));
        }
    },
    {
        // The one-scan path of the same rule: before the fixes, a request-leg allow whose masked copy sat on the
        // response side passed (the verdict read the prompt side only).
        finding: 'P2FR-C-GUARD', title: 'Guard (STOP, AR1): one resources/read with the card, its scan an allow carrying a masked copy on the response side: refused with -32001',
        setup: Object.assign(rpc(read(1, 'lab://one ' + C)), { legs: ['request'], airs: R.answers(R.asAllow('block-dlp-response-masked')) }),
        v3: function (r) {
            var x = r.request, b = null;
            try { b = JSON.parse(x.body); } catch (e) { b = null; }
            return S.check(x.blocked && x.calls.length === 1 && b && b.id === 1 && b.error && b.error.code === -32001, state(x));
        }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (GAPALL): a reply array with a stray element that is a plain string: its text joins the joint scan',
        setup: Object.assign(rpc([call(1, { text: 'one' })]), { legs: ['response'], airs: R.answers('allow-tool', 'allow-prompt'),
            response: S.reply([ans(1, echoed('a1')), 'Stray text. ' + M]) }),
        v3: function (r) { var p = r.response; return and(passed(p), S.check(p.calls.length === 2 && S.has(p, 'Stray text. ' + M), state(p) + ' ' + shape(p))); }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (MIXED): reply leg only, failClosedOnUnknown=false: the reply to the array [tools/call, 5] at /mcp is withheld in JSON-RPC\'s shape, with no scan',
        setup: Object.assign(rpc([call(1, { text: 'Card ' + C }), 5]), { legs: ['response'], vars: { failClosedOnUnknown: 'false' }, airs: R.answers('allow-tool'),
            response: S.reply([ans(1, echoed('Answer. ' + M))]) }),
        v3: function (r) {
            var p = r.response, b = null;
            try { b = JSON.parse(p.body); } catch (e) { b = null; }
            return S.check(p.blocked && p.calls.length === 0 && Array.isArray(b) && b[0] && b[0].id === 1 && b[0].error.code === -32001, state(p));
        }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (OPEN): allowOpenStreams=true at /mcp: a batch [ping, a chat body with jsonrpc and method] has its event-stream reply withheld',
        setup: { path: S.P.mcp, request: { verb: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
                                           content: JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'ping' }, { jsonrpc: '2.0', id: 2, method: 'chat', model: 'm', messages: [{ role: 'user', content: 'hello' }] }]) },
                 legs: ['request', 'response'], airs: R.answers('allow-prompt'), vars: { allowOpenStreams: 'true' },
                 response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } },
        v3: function (r) { var p = r.response; return S.check(p && p.blocked && p.calls.length === 0 && v(p, 'route') !== 'pass', state(p)); }
    },
    {
        finding: 'P2FR-C-GUARD', title: 'Guard (PROTO): a ping with a bolted member named hasOwnProperty: the message is scanned whole',
        setup: Object.assign(S.req(S.P.mcp, '{"jsonrpc":"2.0","id":1,"method":"ping","hasOwnProperty":"Bolted note. ' + M + '"}', H), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return and(passed(x), S.check(x.calls.length === 1 && S.has(x, 'Bolted note. ' + M), state(x))); }
    }
];

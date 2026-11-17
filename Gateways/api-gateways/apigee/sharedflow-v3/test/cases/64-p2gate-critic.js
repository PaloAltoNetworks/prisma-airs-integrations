'use strict';
/*
 * The review of phase 2, completeness critic (15 Nov 2026): what the coverage, Apigee-realism and conformance reviews
 * (61, 62, 63) did not reach. Each case passes when v3 does what v3's rules (A31 for non-2xx replies) and MuleSoft's MCP
 * rules (its policy's code, in this repository) require. A case that fails today is a finding; a case titled "Guard"
 * passes today and stays as a regression guard for the fix.
 *   - P2GATE-NON2XX:     an MCP reply with an HTTP status outside 2xx is never read, though MuleSoft reads a readable
 *                        MCP reply whatever its status; on Apigee's default success codes the reply leg doesn't even
 *                        run for 4xx and 5xx (live P2B2 and P2B3: no reply-leg line). Fixed in phase 2 by the owner's
 *                        call (15 Nov); the MCP target's success.codes must count 4xx and 5xx (README).
 *   - P2GATE-GAPALL:     with onScanError=allow, one batch member or reply message that v3 can't inspect makes the
 *                        whole leg pass unscanned; MuleSoft lets that one scan pass as a gap and scans the rest.
 *   - P2GATE-BOTHTOOL:   type=both, one scan that is a tool event: the request's text beyond the tool's arguments
 *                        (a params member, a bolted member) is never judged with the reply.
 *   - P2GATE-LIMITREPLY: on a reply-leg-only proxy, mcpBatchLimit is never applied (MuleSoft checks it even with
 *                        scanRequests off).
 *   - P2GATE-CHARS:      the log line's chars counts the members the early stop never scanned.
 *   - P2GATE-ISERROR:    a tools/call answer: result.isError is not collected into the tool event's output.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get, and
 * nothing here decides a verdict from content.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };

function rpc(body, headers) { return S.req(S.P.mcp, body, Object.assign({}, H, headers || {})); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
function ping(id) { return { jsonrpc: '2.0', id: id, method: 'ping' }; }
function ans(id, result) { return { jsonrpc: '2.0', id: id, result: result }; }
function echoed(text) { return { content: [{ type: 'text', text: text }], isError: false }; }
function body(x) { try { return JSON.parse(x.body); } catch (e) { return null; } }
function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function and() { for (var i = 0; i < arguments.length; i++) { if (arguments[i] !== true) { return arguments[i]; } } return true; }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' scan(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 160) : ', passed');
}
function passed(x) { return !x ? 'the leg did not run' : (x.fault ? 'it was refused: ' + String(x.body).slice(0, 200) : true); }
// Scanned, or withheld: either keeps the text from passing unread (fail closed).
function scannedOrRefused(x, text) {
    if (!x) { return 'the leg did not run'; }
    if (x.fault && x.blocked) { return true; }
    return S.check(x.scanned.indexOf(text) !== -1, '"' + text + '" passed unscanned: ' + state(x));
}
// The batch refusal: HTTP 200, one error per member with a method and an id, each with the code given.
function refusedBatch(x, ids, code) {
    var b = body(x);
    var got = Array.isArray(b) ? b.map(function (e) { return e && e.error && e.error.code === code ? e.id : 'bad'; }) : null;
    return S.check(x && x.blocked && x.status === 200 && JSON.stringify(got) === JSON.stringify(ids),
                   'not refused as ' + JSON.stringify(ids) + ' with ' + code + ': ' + state(x));
}
// The last log line of the flow (a case that runs one leg only).
function lastLog(x) { var l = x.flow.logs; try { return l.length ? JSON.parse(l[l.length - 1].line) : null; } catch (e) { return null; } }
// The characters of the scans this leg really sent: a tool event's input and output, or the text.
function sentChars(x) {
    var n = 0;
    x.scans.forEach(function (s) {
        var e = s && s.contents && s.contents[0];
        if (!e) { return; }
        if (e.tool_event) { n += String(e.tool_event.input || '').length + String(e.tool_event.output || '').length; }
        else { n += String(e.prompt || e.response || '').length; }
    });
    return n;
}
function range(a, b) { var out = []; for (var i = a; i <= b; i++) { out.push(i); } return out; }

module.exports = [
    /* ---------------- an MCP reply outside 2xx ---------------- */
    {
        // MuleSoft's rule: "A body that cannot be read is a gap if the status is 2xx and passes otherwise. A
        // readable reply is scanned whatever its HTTP status" (MuleSoft src/mcp.rs response(): Ok(msgs) is scanned for any
        // status; only an unreadable non-2xx body passes as upstream_status). airs3-detect.js line 169 passes every
        // non-2xx reply before it is read, MCP included, so the JSON-RPC body reaches the client unread. Design 3.3 keeps
        // A31 (LLM and MCP alike) for phase 3 "unless phase 1 shows a provider that puts model text into an error reply";
        // the lab's own MCP server answers with JSON-RPC text in HTTP 400 replies (P2B2, P2B3: the request's text echoed
        // back), and MuleSoft's MCP rule reads such a reply. The owner's call whether this half of A31 moves into phase 2.
        // Fixed (the owner moved this half of A31 into phase 2, 15 Nov): an MCP reply outside 2xx is read as a 2xx one
        // is; only a body that is empty or not JSON passes, logged. More cases in 68-p2-non2xx.js.
        finding: 'P2GATE-NON2XX', title: 'An MCP tools/call answered with HTTP 500 and a JSON-RPC result is scanned (MuleSoft reads a readable MCP reply whatever its status)',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'block-tool-output'),
            response: { status: 500, headers: { 'Content-Type': 'application/json' }, content: JSON.stringify(ans(3, echoed('Server text. ' + M))) } }),
        v3: function (r) { return scannedOrRefused(r.response, 'Server text. ' + M); }
    },
    {
        finding: 'P2GATE-NON2XX', title: 'Guard: an MCP reply with HTTP 400 whose body is not JSON passes unscanned, logged (MuleSoft: an error it cannot read carries no text it could scan)',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: { status: 400, headers: { 'Content-Type': 'text/plain' }, content: 'Bad Request' } }),
        v3: function (r) { var p = r.response; return and(passed(p), S.check(p.calls.length === 0 && p.status === 400 && v(p, 'logNote') === 'a non-2xx reply that is not JSON passes unscanned', state(p))); }
    },

    /* ---------------- onScanError=allow: one gap must not unscan the rest of the leg ---------------- */
    {
        // MuleSoft's rule: "Each batch member and each answer is its own scan ... Cut text under
        // truncationFailClosed is a gap, without calling AIRS"; line 99: "the first block, gap or scanner failure ends the
        // leg" in enforce mode. MuleSoft src/mcp.rs request(): each scan's gap goes through decide(), which with
        // onScanError=allow passes that scan and goes on to the next, so member 1's block still refuses. airs3-read.js
        // many() returns gap() for the whole leg on the first member over maxScanChars, and gap() with onScanError=allow
        // sets route=pass: member 1 reaches the server with no scan. README Settings, onScanError: "allow lets all of it
        // [content v3 can't inspect] pass unscanned"; member 1 is not such content.
        finding: 'P2GATE-GAPALL', title: 'onScanError=allow: a batch [tools/call with the card, tools/call over maxScanChars] still scans the first member and is refused; only the member over the limit may pass unscanned',
        setup: Object.assign(rpc([call(1, 'Card ' + C), call(2, S.filler(300))]), { legs: ['request'], airs: R.answers('block-tool-input', 'allow-tool'),
                             vars: { onScanError: 'allow', maxScanChars: '200' } }),
        v3: function (r) { var x = r.request; return S.check(x && (x.blocked || S.has(x, 'Card ' + C)), 'the first member reached the server unscanned: ' + state(x)); }
    },
    {
        // MuleSoft's rule: "batch arrays are split", and every message of a reply is scanned;
        // MuleSoft core/src/mcp/reply.rs reply_scans() reads an element that answers no member as text (text_values), so
        // a stray element never makes the reply unreadable. airs3-fmt-mcp.js replyMany() returns unreadable for the
        // whole reply on one element that is not a JSON-RPC message, and with onScanError=allow airs3-read.js passes it
        // all, the first answer included.
        finding: 'P2GATE-GAPALL', title: 'onScanError=allow: a reply array [an answer carrying the card, a stray element that is not a message]: the answer is still scanned and the reply withheld',
        setup: Object.assign(rpc([call(1, 'ask one'), call(2, 'ask two')]), { legs: ['request', 'response'],
            airs: R.answers('allow-tool', 'allow-tool', 'block-tool-output', 'allow-tool'), vars: { onScanError: 'allow' },
            response: S.reply([ans(1, echoed('Card ' + C)), 'Stray note.']) }),
        v3: function (r) { return scannedOrRefused(r.response, 'Card ' + C); }
    },
    {
        finding: 'P2GATE-GAPALL', title: 'Guard: with the default onScanError=block, the same batch [tools/call with the card, tools/call over maxScanChars] is refused before the server, -32001 per id',
        setup: Object.assign(rpc([call(1, 'Card ' + C), call(2, S.filler(300))]), { legs: ['request'], airs: R.answers('block-tool-input', 'allow-tool'),
                             vars: { maxScanChars: '200' } }),
        v3: function (r) { return refusedBatch(r.request, [1, 2], -32001); }
    },

    /* ---------------- type=both: the request's own text, when the one scan is a tool event ---------------- */
    {
        // README Settings, type: "both, on the reply leg, judges the prompt and the reply together, so a detection in
        // either blocks the reply". Design 3.1: "a tools/call whose params hold members beyond name, arguments and _meta
        // is scanned whole, as the tool event's input" (airs3-fmt-mcp.js requestOne()). airs3-read.js, reply leg, phase
        // both, assembles the request's text (prompt.text, here the whole message) but then sends entry = { tool_event }
        // alone, built by replyOne() from params.arguments only: the request's params.note is never judged. 61 and 63
        // reported the many() path (several scans); this is the one-scan path.
        finding: 'P2GATE-BOTHTOOL', title: 'type=both on a reply-leg proxy: a tools/call whose params carry a member besides name and arguments: that member\'s text is judged with the reply',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { text: 'hi' }, note: 'Params note. ' + M } }),
                             { legs: ['response'], params: { response: { type: 'both' } }, airs: R.answers('allow-tool'), response: S.reply(ans(3, echoed('done'))) }),
        v3: function (r) { return scannedOrRefused(r.response, 'Params note. ' + M); }
    },
    {
        // The same path for tools/list: a member bolted onto the request is scanned on the request leg (MuleSoft
        // request.rs other_text(); design 3.1 "Members outside the JSON-RPC envelope are always scanned"), but with
        // type=both the reply's one tool event carries the request's params only.
        finding: 'P2GATE-BOTHTOOL', title: 'type=both on a reply-leg proxy: a tools/list request with a bolted member: that member\'s text is judged with the catalogue',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {}, note: 'Bolted note. ' + M }),
                             { legs: ['response'], params: { response: { type: 'both' } }, airs: R.answers('allow-tool'),
                               response: S.reply(ans(2, { tools: [{ name: 'echo', description: 'Return the given text unchanged.' }] })) }),
        v3: function (r) { return scannedOrRefused(r.response, 'Bolted note. ' + M); }
    },
    {
        finding: 'P2GATE-BOTHTOOL', title: 'Guard: type=both on a reply-leg proxy, a plain tools/call: its arguments are judged, as the tool event\'s input',
        setup: Object.assign(rpc(call(3, 'Arguments text. ' + M)), { legs: ['response'], params: { response: { type: 'both' } }, airs: R.answers('allow-tool'),
                             response: S.reply(ans(3, echoed('done'))) }),
        v3: function (r) { var p = r.response; return and(passed(p), S.check(p.calls.length === 1 && S.has(p, 'Arguments text. ' + M), state(p))); }
    },

    /* ---------------- mcpBatchLimit on a proxy that calls v3 on its reply leg only ---------------- */
    {
        // MuleSoft's rule: "More than mcpBatchLimit members (default 8) is the gap batch_limit, checked
        // before any scan, even with scanRequests off" (MuleSoft src/mcp.rs request(): the limit is checked before the
        // scanRequests switch); on Apigee the proxy picks the leg, "but the flag's semantics must
        // hold: ... gaps are still refused". README mcpBatchLimit: "A larger batch is refused before any scan".
        // airs3-detect.js checks the limit on the request leg only, so a reply-leg-only proxy scans the reply of a
        // 9-member batch (one scan here: the pings answer {}) and passes it.
        finding: 'P2GATE-LIMITREPLY', title: 'A reply-leg-only proxy: the reply to a batch of 9 members (8 pings and a tools/call), one over the default mcpBatchLimit, is withheld before any scan, -32001 per id',
        setup: Object.assign(rpc(range(1, 8).map(ping).concat([call(9, 'hello')])), { legs: ['response'], airs: R.answers('allow-tool'),
            response: S.reply(range(1, 8).map(function (n) { return ans(n, {}); }).concat([ans(9, echoed('done'))])) }),
        v3: function (r) { var p = r.response; return and(S.check(p && p.calls.length === 0, 'the reply was scanned instead: ' + state(p)), refusedBatch(p, range(1, 9), -32001)); }
    },

    /* ---------------- the log line ---------------- */
    {
        // README Logging: "chars | The characters scanned on this leg". airs3-read.js many() sets airs3.scanChars to the
        // total of every body it prepared; the early stop then skips the later slots, and airs3-verdict.js never corrects
        // it. Live on revision 14 (P2B4): "chars": "85", "scans": "2",
        // the third member never scanned.
        finding: 'P2GATE-CHARS', title: 'A batch [hello, card, a third call] stopped at slot 2: the log line\'s chars counts the two scans that ran, not the third member',
        setup: Object.assign(rpc([call(1, 'hello'), call(2, 'Card ' + C), call(3, 'hello there friend')]), { legs: ['request'], airs: R.answers('allow-tool', 'block-tool-input') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x), sent = sentChars(x);
            return S.check(x.blocked && l && String(l.scans) === '2' && Number(l.chars) === sent,
                           'the log line says chars ' + (l && l.chars) + ' for ' + (l && l.scans) + ' scans; the scans sent held ' + sent + ' characters');
        }
    },

    /* ---------------- a tools/call answer's members ---------------- */
    {
        // MuleSoft's rule: a tools/call answer's tool event has "output = the result JSON, read as
        // server-sent" (MuleSoft reply.rs answer(): json_text(result), every member). airs3-fmt-mcp.js resultText() drops
        // result.isError whatever it holds (k !== 'isError'), so a value that is not a boolean is never sent. This field's
        // text is not collected: result.isError. (63's CALL-TEXTBLOCK is the same function, another member.)
        finding: 'P2GATE-ISERROR', title: 'A tools/call answer: result.isError, when it is not a boolean, is collected into the tool event\'s output',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply(ans(3, { content: [{ type: 'text', text: 'done' }], isError: 'Flag text. ' + M })) }),
        v3: function (r) { return scannedOrRefused(r.response, 'Flag text. ' + M); }
    }
];

'use strict';
/*
 * The fixes for the review of phase 2, reviewed for live-Apigee realism and regressions (15 Nov 2026). Each case passes
 * when v3 does what v3's rules, MuleSoft's MCP rules (its policy's code, in this repository) and the measured platform
 * facts (VERIFICATION L1, L6, L14 to L16) require. A case that fails
 * today is a finding; a case titled "Guard" passes today and pins a fix's intended behaviour.
 *   - P2FR-R-01: type=both on MCP drops a request tool event that the reply's tool event repeats, but when that reply
 *                event is over maxScanChars it goes as text holding only the result, so the arguments reach no scan
 *                (phase 1's one-scan path sent them as the prompt part; MuleSoft's tool_or_text keeps both).
 *   - P2FR-R-02: allowOpenStreams opens an event-stream reply only when the path ends in exactly /mcp: an MCP route at
 *                another path (the lab's own /mcp-marked, a trailing slash) now has every such reply withheld, though
 *                the envelope check alone keeps LLM bodies out.
 *   - P2FR-R-03: a leg of several scans with onScanError=allow: the verdict's note replaces many()'s "gap allowed"
 *                note, so the log line no longer says which part passed unscanned.
 *   - Guards: the harness's new createNew status 200 still reads a slot with no answer as no answer (aiStatus none);
 *     a reply-leg MCP text block is refused as a response, in JSON-RPC's shape; and the shapes the MCP Python and
 *     TypeScript SDK clients (Claude Code, Gemini CLI) send pass the new checks.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get, and
 * nothing here decides a verdict from content.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };

function rpc(path, body, headers) { return S.req(path, body, Object.assign({}, H, headers || {})); }
function call(id, args, meta) {
    var p = { name: 'echo', arguments: args };
    if (meta) { p._meta = meta; }
    return { jsonrpc: '2.0', id: id, method: 'tools/call', params: p };
}
function ans(id, result) { return { jsonrpc: '2.0', id: id, result: result }; }
function text(t) { return { content: [{ type: 'text', text: t }], isError: false }; }
function sse() { return { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' }; }   // L1: the flow sees no body
function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function and() { for (var i = 0; i < arguments.length; i++) { if (arguments[i] !== true) { return arguments[i]; } } return true; }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' scan(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', aiStatus ' + v(x, 'aiStatus') + ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 200) : ', passed');
}
function passed(x) { return !x ? 'the leg did not run' : (x.fault ? 'it was refused: ' + String(x.body).slice(0, 200) : true); }
function scannedOrRefused(x, t) {
    if (!x) { return 'the leg did not run'; }
    if (x.fault && x.blocked) { return true; }
    return S.check(x.scanned.indexOf(t) !== -1, '"' + t + '" passed unscanned: ' + state(x));
}
function body(x) { try { return JSON.parse(x.body); } catch (e) { return null; } }
function lastLog(x) { var l = x && x.flow ? x.flow.logs : []; try { return l.length ? JSON.parse(l[l.length - 1].line) : null; } catch (e) { return null; } }
function entry(x, i) { var s = x && x.scans[i]; return s && s.contents ? s.contents[0] : null; }

module.exports = [
    /* ---------------- P2FR-R-01: type=both, a repeated tool event over maxScanChars ---------------- */
    {
        // A proxy that calls v3 on its reply leg only, type=both: the arguments carry the card, the answer is long enough
        // that arguments plus answer exceed maxScanChars, while the answer alone fits. read.js drops the request's tool
        // event as a repeat of the reply's; many() then turns the reply's event into text, and that text is the answer
        // alone (fmt-mcp.js replyOne: callSegs holds outText only). Before the fix the arguments went as the prompt part.
        finding: 'P2FR-R-01', title: 'type=both, reply leg only: a tools/call whose arguments carry the card and whose answer pushes the tool event over maxScanChars: the arguments still reach a scan, or the reply is withheld',
        setup: Object.assign(S.mcp('tools/call', { name: 'echo', arguments: { text: 'Card ' + C } }), {
            legs: ['response'], params: { response: { type: 'both' } }, vars: { maxScanChars: '300' }, airs: R.answers('allow-prompt'),
            response: S.reply(ans(1, text(S.filler(280)))) }),
        v3: function (r) { return scannedOrRefused(r.response, 'Card ' + C); }
    },
    {
        finding: 'P2FR-R-01', title: 'Guard: type=both, reply leg only, the same call with a short answer: one scan, a tool event whose input holds the arguments (the request\'s repeat is judged there)',
        setup: Object.assign(S.mcp('tools/call', { name: 'echo', arguments: { text: 'Card ' + C } }), {
            legs: ['response'], params: { response: { type: 'both' } }, vars: { maxScanChars: '300' }, airs: R.answers('allow-tool'),
            response: S.reply(ans(1, text('done'))) }),
        v3: function (r) {
            var x = r.response, e = entry(x, 0);
            return and(passed(x), S.check(x.calls.length === 1 && e && e.tool_event && String(e.tool_event.input).indexOf('Card ' + C) !== -1 && e.tool_event.output === 'done',
                                          'not one tool event with the arguments and the answer: ' + JSON.stringify(e).slice(0, 300)));
        }
    },

    /* ---------------- P2FR-R-02: allowOpenStreams and the MCP route ---------------- */
    {
        // The lab's own event-stream route (lab/mcp-server/main.py: /mcp-marked; lab_bundles.py routes it with no
        // apiFormat). The request is plain JSON-RPC, so no LLM body is dressed as MCP; before the fix this reply passed.
        finding: 'P2FR-R-02', title: 'allowOpenStreams=true, an MCP route at /mcp-marked (the lab server\'s event-stream route): a harmless tools/call answered as an event stream passes unscanned, logged',
        setup: Object.assign(rpc('/mcp-marked', call(43, { text: 'hello' })), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            vars: { allowOpenStreams: 'true' }, response: sse() }),
        v3: function (r) {
            var x = r.response;
            return and(passed(x), S.check(x.calls.length === 0 && v(x, 'logNote') === 'an MCP event-stream reply passes unscanned (allowOpenStreams)', state(x)));
        }
    },
    {
        // Client URLs with a trailing slash are common; Express (used by the TypeScript SDK's server examples) routes /mcp/
        // to the /mcp handler by default, so a client configured with the slash reaches the same server.
        finding: 'P2FR-R-02', title: 'allowOpenStreams=true, a client pointed at .../mcp/ (a trailing slash): a harmless tools/call answered as an event stream passes unscanned, logged',
        setup: Object.assign(rpc('/mcp/', call(44, { text: 'hello' })), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            vars: { allowOpenStreams: 'true' }, response: sse() }),
        v3: function (r) {
            var x = r.response;
            return and(passed(x), S.check(x.calls.length === 0 && v(x, 'logNote') === 'an MCP event-stream reply passes unscanned (allowOpenStreams)', state(x)));
        }
    },
    {
        // The SDK client shape: Accept for both, a progress token in params._meta (the TypeScript SDK adds one when the
        // caller asks for progress), so every member is in the JSON-RPC envelope.
        finding: 'P2FR-R-02', title: 'Guard: allowOpenStreams=true at /mcp: an SDK-shaped tools/call (params._meta.progressToken) is scanned as a tool event, and its event-stream answer passes unscanned, logged',
        setup: Object.assign(rpc(S.P.mcp, call(45, { text: 'hello' }, { progressToken: 45 })), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            vars: { allowOpenStreams: 'true' }, response: sse() }),
        v3: function (r) {
            var q = r.request, x = r.response, e = entry(q, 0);
            return and(passed(q), passed(x),
                       S.check(q.calls.length === 1 && e && e.tool_event && e.tool_event.input === '{"text":"hello"}', 'the request was not one tool event of the arguments: ' + JSON.stringify(e)),
                       S.check(x.calls.length === 0 && v(x, 'logNote') === 'an MCP event-stream reply passes unscanned (allowOpenStreams)', state(x)));
        }
    },

    /* ---------------- P2FR-R-03: the log note on a leg of several scans ---------------- */
    {
        // onScanError=allow lets the oversize member pass unscanned (many(): "gap allowed: a request part over ...");
        // failOpen=true lets the other member's scan, which gets no answer, pass. The log line must still say that a part
        // passed unscanned for size; today the verdict's "failed open: ..." note replaces it.
        finding: 'P2FR-R-03', title: 'onScanError=allow and failOpen=true, a batch [an oversize tools/call, a short one whose scan gets no answer]: the log line\'s note keeps the oversize member\'s "gap allowed"',
        setup: Object.assign(rpc(S.P.mcp, [call(1, { text: S.filler(400) }), call(2, { text: 'hello' })]), { legs: ['request'],
            airs: R.answers(R.noAnswer()), vars: { maxScanChars: '300', onScanError: 'allow', failOpen: 'true' } }),
        v3: function (r) {
            var x = r.request, line = lastLog(x);
            return and(passed(x), S.check(x.calls.length === 1 && line && /gap allowed: a request part over 300 characters/.test(line.note || '') && /failed open/.test(line.note || ''),
                                          'the note: ' + JSON.stringify(line && line.note)));
        }
    },

    /* ---------------- Guards: the harness's createNew status 200 (L14, L15) ---------------- */
    {
        finding: 'P2FR-R-04', title: 'Guard: reply leg, a reply array of two answers whose second scan gets no answer: refused as a scanner failure (-32003 per id), aiStatus none, never read as an HTTP 200 answer',
        setup: Object.assign(rpc(S.P.mcp, [call(1, { text: 'one' }), call(2, { text: 'two' })]), { legs: ['response'], airs: R.answers('allow-tool', R.noAnswer()),
            response: S.reply([ans(1, text('Answer one.')), ans(2, text('Answer two.'))]) }),
        v3: function (r) {
            var x = r.response, b = body(x);
            var ids = Array.isArray(b) ? b.map(function (e) { return e && e.error && e.error.code === -32003 ? e.id : 'bad'; }) : null;
            return S.check(x.blocked && x.calls.length === 2 && JSON.stringify(ids) === '[1,2]' && v(x, 'aiStatus') === 'none' && v(x, 'outcome') === 'failure' &&
                           v(x, 'logNote') === 'no answer from Prisma AIRS' && v(x, 'scansRan') === '2', state(x));
        }
    },
    {
        finding: 'P2FR-R-04', title: 'Guard: two legs, the request leg\'s scan answered, the reply leg\'s got no answer: the reply is withheld as a failure with aiStatus none, not judged on the fresh message\'s 200',
        setup: Object.assign(S.mcp('resources/read', { uri: 'lab://page' }, 6), { legs: ['request', 'response'], airs: R.answers('allow-prompt', R.noAnswer()),
            response: S.reply(ans(6, { contents: [{ uri: 'lab://page', mimeType: 'text/plain', text: 'Page text.' }] })) }),
        v3: function (r) {
            var x = r.response, b = body(x);
            return S.check(x.blocked && b && b.id === 6 && b.error && b.error.code === -32003 && v(x, 'aiStatus') === 'none' && v(x, 'logNote') === 'no answer from Prisma AIRS', state(x));
        }
    },
    {
        finding: 'P2FR-R-04', title: 'Guard: failOpen=true, the same reply leg with no answer: passes, logged "failed open: no answer from Prisma AIRS" with aiStatus none',
        setup: Object.assign(S.mcp('resources/read', { uri: 'lab://page' }, 6), { legs: ['request', 'response'], airs: R.answers('allow-prompt', R.noAnswer()),
            vars: { failOpen: 'true' }, response: S.reply(ans(6, { contents: [{ uri: 'lab://page', mimeType: 'text/plain', text: 'Page text.' }] })) }),
        v3: function (r) {
            var x = r.response;
            return and(passed(x), S.check(v(x, 'aiStatus') === 'none' && v(x, 'logNote') === 'failed open: no answer from Prisma AIRS', state(x)));
        }
    },

    /* ---------------- Guards: a reply-leg MCP text block, as the client sees it ---------------- */
    {
        // MCP reply text goes as a prompt, so the realistic answer to a resource carrying the card is a prompt-side DLP
        // block (as P2F1 measured live). The client gets a response refusal, with its id; the log names prompt.dlp.
        finding: 'P2FR-R-05', title: 'Guard: resources/read whose answer carries the card, blocked on prompt.dlp: HTTP 200, -32001 with id 51, "Response blocked ...", sensitive data named; logged prompt.dlp, kind block',
        setup: Object.assign(S.mcp('resources/read', { uri: 'lab://card-note' }, 51), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-prompt-masked'),
            response: S.reply(ans(51, { contents: [{ uri: 'lab://card-note', mimeType: 'text/plain', text: 'Card on file: ' + C }] })) }),
        v3: function (r) {
            var x = r.response, b = body(x), line = lastLog(x), msg = b && b.error ? String(b.error.message) : '';
            return S.check(x.blocked && x.status === 200 && b && b.id === 51 && b.error.code === -32001 && msg.indexOf('Response blocked by Prisma AIRS security policy.') === 0 &&
                           /Sensitive data/.test(msg) && line && line.detections === 'prompt.dlp' && line.kind === 'block' && line.leg === 'response', state(x) + ' log ' + JSON.stringify(line));
        }
    },

    /* ---------------- Guards: what SDK clients send (no new false positives) ---------------- */
    {
        // The TypeScript SDK's initialize, with no Mcp-Session-Id yet; the server issues one on its JSON answer.
        finding: 'P2FR-R-06', title: 'Guard: an SDK initialize with no session yet: the request scans nothing, the answer is scanned as a prompt carrying the server\'s Mcp-Session-Id, and passes',
        setup: Object.assign(rpc(S.P.mcp, { jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: { roots: { listChanged: true } }, clientInfo: { name: 'claude-code', version: '2.1.321' } } }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt'),
            response: { status: 200, headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': 'sess-lab-1' },
                        content: JSON.stringify(ans(0, { protocolVersion: '2025-06-18', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'lab-mcp', version: '1.30.0' } })) } }),
        v3: function (r) {
            var q = r.request, x = r.response, e = entry(x, 0), sid = x && x.scans[0] ? x.scans[0].session_id : null;
            return and(passed(q), passed(x), S.check(q.calls.length === 0 && x.calls.length === 1 && e && e.response === undefined && /lab-mcp/.test(String(e.prompt)) && sid === 'sess-lab-1',
                                                     'not one prompt scan with the issued session: ' + JSON.stringify(x && x.scans[0]).slice(0, 300)));
        }
    },
    {
        // After initialize, the TypeScript SDK opens the GET stream, resuming with Last-Event-ID; 405 is the answer it
        // handles (it carries on without the stream). Logged as MCP since the fix (P2GATE-LOG-OPEN-FORMAT).
        finding: 'P2FR-R-06', title: 'Guard: the SDK\'s GET for an event stream with Last-Event-ID and a session: 405 with Allow: POST, DELETE, a JSON-RPC error with id null, logged with format mcp',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream', 'Last-Event-ID': '17', 'Mcp-Session-Id': 'sess-lab-1' }, content: '' },
                 legs: ['request'], airs: R.answers('allow-prompt') },
        v3: function (r) {
            var x = r.request, b = body(x), line = lastLog(x);
            return S.check(x.status === 405 && x.flow.messages.response.header('Allow') === 'POST, DELETE' && b && b.id === null && b.error.code === -32001 &&
                           x.calls.length === 0 && line && line.format === 'mcp', state(x) + ' log ' + JSON.stringify(line));
        }
    },
    {
        finding: 'P2FR-R-06', title: 'Guard: the SDK\'s DELETE that ends a session (no body) and the server\'s 200 with Content-Length 0: both legs pass, no scan',
        setup: { path: S.P.mcp, request: { verb: 'DELETE', headers: { 'Mcp-Session-Id': 'sess-lab-1' }, content: '' },
                 legs: ['request', 'response'], airs: R.answers('allow-prompt'),
                 response: { status: 200, headers: { 'Content-Length': '0' }, content: '' } },
        v3: function (r) {
            return and(passed(r.request), passed(r.response), S.check(r.request.calls.length === 0 && r.response.calls.length === 0, state(r.response)));
        }
    },
    {
        // What the proposed fix for P2FR-R-02 relies on: every LLM API needs a member outside the JSON-RPC envelope
        // (model, messages, input, contents), so the envelope check alone keeps a look-alike shut, even on /mcp.
        finding: 'P2FR-R-02', title: 'Guard: allowOpenStreams=true at /mcp, a Chat Completions body dressed as JSON-RPC (model, messages and stream outside the envelope): its event-stream reply is withheld',
        setup: Object.assign(rpc(S.P.mcp, { jsonrpc: '2.0', id: 46, method: 'resources/read', params: { uri: 'lab://page' }, model: 'm', stream: true,
                                            messages: [{ role: 'user', content: 'Say hello.' }] }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt'), vars: { allowOpenStreams: 'true' }, response: sse() }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && x.fault && x.calls.length === 0 && v(x, 'route') !== 'pass', 'the look-alike\'s event-stream reply passed: ' + state(x));
        }
    },
    {
        // The other reading of a fresh message (L14): status 200, no body, the failed flag not true. The flow never
        // leaves a slot so (its ClearScan and its callout share one condition), and Prisma AIRS answering 200 with no
        // body reads the same: a scanner failure, never a verdict.
        finding: 'P2FR-R-04', title: 'Guard: a scan answered HTTP 200 with no body (the failed flag false): a scanner failure, -32003 with the id, never a verdict',
        setup: Object.assign(S.mcp('resources/read', { uri: 'lab://page' }, 8), { legs: ['request'], airs: R.answers(R.status(200, '')) }),
        v3: function (r) {
            var x = r.request, b = body(x);
            return S.check(x.blocked && b && b.id === 8 && b.error && b.error.code === -32003 && v(x, 'outcome') === 'failure' && v(x, 'logNote') === 'an answer that is not a JSON object', state(x));
        }
    }
];

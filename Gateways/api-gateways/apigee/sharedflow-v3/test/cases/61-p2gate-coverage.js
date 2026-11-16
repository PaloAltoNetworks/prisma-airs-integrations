'use strict';
/*
 * The phase 2 gate, coverage and failing closed (15 Nov 2026): does every MCP text phase 2 handles reach Prisma AIRS or
 * a refusal, with the defaults, and does a refusal, once a slot finds one, stay a refusal?
 * Each case passes when v3 does what v3's phase 2 rules and MuleSoft's MCP rules (its policy's code, in this repository)
 * require.
 * A case that fails today is a finding. Cases titled "Guard" pass today and stay as regression guards.
 *   - P2GATE-STOP:   the early stop and the verdict judge a slot differently, so a stop can end as a pass.
 *   - P2GATE-SIDE:   MCP reply-leg text goes as `response`, which Prisma AIRS reads without its injection detector.
 *   - P2GATE-ENV:    a message's envelope members that its kind doesn't use (a result next to a method, params next
 *                    to a result) are never scanned, on either leg.
 *   - P2GATE-ERR:    a tools/call answer's error next to its result is never sent: only the tool event goes.
 *   - P2GATE-STRRES: a client reply whose result is a plain string adds no text.
 *   - P2GATE-PROTO:  a bolted member named like an Object.prototype property is not seen as bolted.
 *   - P2GATE-BOTH:   type=both drops the request's text when the reply needs several scans.
 *   - P2GATE-OPEN:   allowOpenStreams also opens an LLM route's stream.
 *   - P2GATE-MIXED:  an array at /mcp that is not a batch counts as an unknown endpoint.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get, and
 * nothing here decides a verdict from content.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };

function rpc(body, headers) { return S.req(S.P.mcp, body, Object.assign({}, H, headers || {})); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
function read(id, uri) { return { jsonrpc: '2.0', id: id, method: 'resources/read', params: { uri: uri } }; }
function ans(id, result) { return { jsonrpc: '2.0', id: id, result: result }; }
function echoed(text) { return { content: [{ type: 'text', text: text }], isError: false }; }
function page(uri, text) { return { contents: [{ uri: uri, mimeType: 'text/plain', text: text }] }; }
function v(x, leaf) { return String(x.flow.get('airs3.' + leaf) || ''); }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' scan(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 160) : ', passed');
}
function passed(x) { return !x ? 'the leg did not run' : (x.fault ? 'it was refused: ' + String(x.body).slice(0, 200) : true); }
function and() { for (var i = 0; i < arguments.length; i++) { if (arguments[i] !== true) { return arguments[i]; } } return true; }
// Scanned, or withheld: either keeps the text from passing unread (fail closed).
function scannedOrRefused(x, text) {
    if (!x) { return 'the leg did not run'; }
    if (x.fault && x.blocked) { return true; }
    return S.check(x.scanned.indexOf(text) !== -1, '"' + text + '" passed unscanned: ' + state(x));
}
const LOOKALIKE = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'chat', model: 'm', stream: true, messages: [{ role: 'user', content: 'hello ' + M }] });

module.exports = [
    /* ---------------- the early stop and the verdict must agree ---------------- */
    {
        // Plan task 2: the step after each callout "stops the remaining slots when that reply is not a clean allow";
        // design 3.2 and airs3-verdict.js: the first slot that would refuse decides. airs3-lib.js slotPasses() stops on an
        // allow that carries a masked copy on EITHER side (hasMasked), but airs3-verdict.js looks for the masked copy on
        // this leg's own side only (reply leg: response_masked_data, or tool output entry 0), so the same answer is judged
        // an allow: the leg passes, and the slots after it never ran.
        finding: 'P2GATE-STOP', title: 'A reply array of two tools/call answers: slot 1\'s allow carries a masked copy of the tool input only. The stop skips slot 2 and ' +
            'the verdict passes slot 1, so answer 2 reaches the client unscanned',
        setup: Object.assign(rpc([call(1, 'ask one'), call(2, 'ask two')]), { legs: ['request', 'response'],
            airs: R.answers('allow-tool', 'allow-tool', R.asAllow('block-tool-input'), 'block-tool-output'),
            response: S.reply([ans(1, echoed('answer one')), ans(2, echoed('answer two ' + M))]) }),
        v3: function (r) { return scannedOrRefused(r.response, 'answer two ' + M); }
    },
    {
        // The same disagreement through the reply leg's prompt-only rule: slotPasses() takes slot 1's block as a refusal and
        // stops; airs3-verdict.js then turns that block into an allow (every detection is prompt.*, and the request leg
        // allowed), so slot 2 never ran. many() sends no prompt context, so the rule has nothing to excuse here.
        finding: 'P2GATE-STOP', title: 'A reply array of two resources/read answers: slot 1 blocks on prompt.* detections only; the stop skips slot 2 and the ' +
            'prompt-only rule turns slot 1 into an allow, so answer 2 reaches the client unscanned',
        setup: Object.assign(rpc([read(1, 'lab://one'), read(2, 'lab://two')]), { legs: ['request', 'response'],
            airs: R.answers('allow-prompt', 'allow-prompt', 'block-dlp-prompt-masked', 'block-dlp-response-masked'),
            response: S.reply([ans(1, page('lab://one', 'page one')), ans(2, page('lab://two', 'page two ' + M))]) }),
        v3: function (r) { return scannedOrRefused(r.response, 'page two ' + M); }
    },
    {
        finding: 'P2GATE-STOP', title: 'Guard: the same reply array when slot 1\'s masked copy is on the reply\'s own side: one scan, refused with -32001 for ids 1 and 2',
        setup: Object.assign(rpc([call(1, 'ask one'), call(2, 'ask two')]), { legs: ['request', 'response'],
            airs: R.answers('allow-tool', 'allow-tool', R.asAllow('block-dlp-response-masked'), 'allow-tool'),
            response: S.reply([ans(1, echoed('answer one')), ans(2, echoed('answer two'))]) }),
        v3: function (r) {
            var p = r.response, b = null;
            try { b = JSON.parse(p.body); } catch (e) { b = null; }
            return S.check(p && p.fault && p.calls.length === 1 && Array.isArray(b) && b.length === 2 && b[0].error.code === -32001 && b[1].id === 2, state(p));
        }
    },

    /* ---------------- which side of the scan MCP reply text goes in ---------------- */
    {
        // MuleSoft's rule: "Every other text goes as {prompt: text}, on both legs, without context" (MuleSoft
        // src/mcp.rs:239 What::Text { leg: Leg::Prompt }; its README: "sent as a prompt, on both legs, because MCP text
        // reaches a model as input"). airs3-read.js many() says it sends MCP text "as MuleSoft sends MCP text", but on
        // the reply leg it sends {response: text}. Prisma AIRS's response side has no injection or agent detector: every
        // recorded response_detected holds db_security, dlp, malicious_code, toxic_content and url_cats only, and no live
        // log line ever showed response.injection. So a resources/read answer, a prompt, a sampling request or a
        // notification is never checked for prompt injection; only the two tool events are.
        finding: 'P2GATE-SIDE', title: 'A reply array of two resources/read answers: each answer\'s text goes to Prisma AIRS as prompt text (MuleSoft\'s rule), where the injection detector reads it',
        setup: Object.assign(rpc([read(1, 'lab://one'), read(2, 'lab://two')]), { legs: ['request', 'response'], airs: R.answers('allow-prompt'),
            response: S.reply([ans(1, page('lab://one', 'page one ' + M)), ans(2, page('lab://two', 'page two'))]) }),
        v3: function (r) {
            var p = r.response;
            if (!p || p.fault) { return 'the reply leg did not pass: ' + state(p); }
            var e = p.scans.map(function (s) { return s && s.contents && s.contents[0]; }).filter(function (x) { return x && JSON.stringify(x).indexOf('page one ' + M) !== -1; })[0];
            return S.check(e && (e.tool_event || (typeof e.prompt === 'string' && e.prompt.indexOf('page one ' + M) !== -1)),
                           'the answer\'s text went as ' + JSON.stringify(e ? Object.keys(e) : null) + ', the side Prisma AIRS reads without its injection detector');
        }
    },

    /* ---------------- envelope members a message's kind doesn't use ---------------- */
    {
        // MuleSoft's rule (reply.rs:69-76 answered()): an answer is a message with a result or an error
        // whose id is a request member's id; a method beside them doesn't change that. v3's replyOne() reads any message
        // with a method as a server request or notification and scans its params only, so this reply has "nothing to
        // scan" and passes as an empty reply. A client that matches answers by id and result reads the result.
        finding: 'P2GATE-ENV', title: 'Reply leg: a reply to tools/call id 3 that carries id 3 and a result, and also a method: the result is scanned or the reply withheld, never passed unread',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply({ jsonrpc: '2.0', id: 3, method: 'notifications/message', result: echoed('result text ' + M) }) }),
        v3: function (r) { return scannedOrRefused(r.response, 'result text ' + M); }
    },
    {
        // MuleSoft's rule: messages that answer no member are scanned together, as the text of the message (every
        // string but the top-level jsonrpc, id and method: MuleSoft mod.rs text_values()); an answer to a member other
        // than tools/call and tools/list is scanned whole (reply.rs:116). v3 scans a notification's params only, and an
        // answer's result and error only.
        finding: 'P2GATE-ENV', title: 'Reply leg: in a reply array, a notification that also carries a result, and an answer that also carries params: both texts are scanned',
        setup: Object.assign(rpc([read(1, 'lab://one'), read(2, 'lab://two')]), { legs: ['request', 'response'], airs: R.answers('allow-prompt'),
            response: S.reply([{ jsonrpc: '2.0', id: 1, result: page('lab://one', 'page one'), params: { note: 'answer params ' + M } },
                               ans(2, page('lab://two', 'page two')),
                               { jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: 1, progress: 1 }, result: echoed('side text ' + M) }]) }),
        v3: function (r) { return and(scannedOrRefused(r.response, 'answer params ' + M), scannedOrRefused(r.response, 'side text ' + M)); }
    },
    {
        // MuleSoft's rule, request leg: "content methods and client replies. One text scan of params (except _meta),
        // result, error and every extra top-level member" (MuleSoft request.rs:45-66 other_text()). v3's requestOne() scans
        // a method's params only, and a client reply's result and error only.
        finding: 'P2GATE-ENV', title: 'Request leg: a batch [resources/read that also carries an error, a client reply that also carries params]: both texts are scanned before the server',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', id: 1, method: 'resources/read', params: { uri: 'lab://one' }, error: { code: 1, message: 'read note ' + M } },
                                  { jsonrpc: '2.0', id: 'srv-1', result: { action: 'accept', content: { note: 'fine' } }, params: { note: 'reply params ' + M } }]),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return and(scannedOrRefused(r.request, 'read note ' + M), scannedOrRefused(r.request, 'reply params ' + M)); }
    },

    /* ---------------- a tools/call answer: the error next to the result ---------------- */
    {
        // MuleSoft reply.rs:84-96: beside a tools/call answer's tool event, the answer's other members (outside(obj,
        // ["result"]): its error, its params) are a text scan. v3's replyOne() puts the error into its segments, but many()
        // and the one-scan path send the tool event alone (input, and output = the result), so the error is never sent.
        finding: 'P2GATE-ERR', title: 'A tools/call answer in a reply array that carries a result and an error: the error\'s text is scanned beside the tool event',
        setup: Object.assign(rpc([call(1, 'ask one'), call(2, 'ask two')]), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: S.reply([{ jsonrpc: '2.0', id: 1, result: echoed('answer one'), error: { code: -32000, message: 'error note ' + M } }, ans(2, echoed('answer two'))]) }),
        v3: function (r) { return scannedOrRefused(r.response, 'error note ' + M); }
    },

    /* ---------------- a client reply with a plain-string result ---------------- */
    {
        // MuleSoft's rule: a client reply's result is scanned (MuleSoft request.rs other_text(): any JSON type).
        // v3's requestOne() reads it through copyClient(), which round-trips it through JSON.parse: a plain string is not
        // JSON, comes back undefined, and AIRS3.seg() drops it.
        finding: 'P2GATE-STRRES', title: 'A batch of two client replies, the first with a plain-string result: that result is scanned before the batch reaches the server',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', id: 'srv-1', result: 'client answer ' + M }, { jsonrpc: '2.0', id: 'srv-2', result: { action: 'accept', content: { note: 'fine' } } }]),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return scannedOrRefused(r.request, 'client answer ' + M); }
    },
    {
        finding: 'P2GATE-STRRES', title: 'Guard: a client reply whose result is an object is its own scan in a batch',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', id: 'srv-2', result: { action: 'accept', content: { note: 'object answer ' + M } } }, call(3, 'hello')]),
                             { legs: ['request'], airs: R.answers('allow-prompt', 'allow-tool') }),
        v3: function (r) { var x = r.request; return and(passed(x), S.check(x.calls.length === 2 && S.has(x, 'object answer ' + M), state(x))); }
    },

    /* ---------------- bolted members, whatever their name ---------------- */
    {
        // Design 3.1: "Members outside the JSON-RPC envelope are always scanned"; MuleSoft request.rs other_text() scans
        // every key but jsonrpc, id and method. v3's extras() tests !ENVELOPE[k] on a plain object, so a key that names an
        // Object.prototype property (constructor, toString, valueOf, hasOwnProperty, ...) finds the inherited function and
        // counts as envelope: the member is never scanned.
        finding: 'P2GATE-PROTO', title: 'Request leg: a batch [ping with a bolted member named "constructor", tools/call]: the bolted member is scanned',
        setup: Object.assign(rpc([{ jsonrpc: '2.0', id: 1, method: 'ping', constructor: { note: 'bolted note ' + M } }, call(2, 'hello')]),
                             { legs: ['request'], airs: R.answers('allow-tool', 'allow-prompt') }),
        v3: function (r) { return scannedOrRefused(r.request, 'bolted note ' + M); }
    },
    {
        finding: 'P2GATE-PROTO', title: 'Reply leg: a tools/call answer with a bolted member named "valueOf" is scanned whole, as a member named "extra" is',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply('{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"fine"}]},"valueOf":"bolted note ' + M + '"}') }),
        v3: function (r) { return scannedOrRefused(r.response, 'bolted note ' + M); }
    },

    /* ---------------- type=both: the prompt is judged with the reply ---------------- */
    {
        // README Settings, type: "both, on the reply leg, judges the prompt and the reply together". airs3-read.js does
        // that for one scan (phase === 'both': the request's segments as the prompt), but a reply that needs several scans
        // goes to many(), which never reads the request, so the batch's own text is not judged at all.
        finding: 'P2GATE-BOTH', title: 'type=both on a reply-leg-only proxy: a batch of two resources/read is judged with its reply array, the request\'s text included',
        setup: Object.assign(rpc([read(1, 'lab://note ' + M), read(2, 'lab://other')]), { legs: ['response'], params: { response: { type: 'both' } },
            airs: R.answers('allow-prompt-response'),
            response: S.reply([ans(1, page('lab://n', 'page one')), ans(2, page('lab://o', 'page two'))]) }),
        v3: function (r) { return scannedOrRefused(r.response, 'lab://note ' + M); }
    },
    {
        // Updated with the review's fixes: MCP text goes as a prompt with no context (P2GATE-SIDE), so type=both judges the
        // request's own scan first, then the reply's, as two scans, where phase 1 sent one scan with the request as context.
        finding: 'P2GATE-BOTH', title: 'Guard: type=both with one resources/read and one answer: the request\'s text is judged with the reply, as its own scan before the reply\'s',
        setup: Object.assign(rpc(read(1, 'lab://note ' + M)), { legs: ['response'], params: { response: { type: 'both' } },
            airs: R.answers('allow-prompt-response'), response: S.reply(ans(1, page('lab://n', 'page one'))) }),
        v3: function (r) {
            var p = r.response, a = p && p.scans[0] && p.scans[0].contents[0], b = p && p.scans[1] && p.scans[1].contents[0];
            return and(passed(p), S.check(p.calls.length === 2 && a && String(a.prompt).indexOf('lab://note ' + M) !== -1 && b && String(b.prompt).indexOf('page one') !== -1, state(p)));
        }
    },

    /* ---------------- allowOpenStreams opens MCP streams only ---------------- */
    {
        // Plan task 4 and the README: allowOpenStreams lets "an MCP GET for an event stream, and an MCP reply sent as an
        // event stream" pass. Design 3.1: an LLM body that adds jsonrpc and method gains no skip from MCP's reading. A
        // JSON-RPC look-alike with stream: true at the chat path is MCP by its body, so nothing turns its stream off (the
        // MCP module has no destream), and the model's event-stream reply passes unread under the setting.
        finding: 'P2GATE-OPEN', title: 'allowOpenStreams=true does not open an LLM route: a JSON-RPC look-alike with stream: true at /v1/chat/completions has its event-stream reply withheld',
        setup: { path: S.P.chat, request: { verb: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' }, content: LOOKALIKE },
                 legs: ['request', 'response'], airs: R.answers('allow-prompt'), vars: { allowOpenStreams: 'true' },
                 response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } },
        v3: function (r) {
            var q = r.request, p = r.response;
            return and(S.check(q && !q.fault && S.has(q, M), 'request leg: ' + state(q)), S.check(p && p.fault && p.blocked, 'reply leg: ' + state(p)));
        }
    },
    {
        finding: 'P2GATE-OPEN', title: 'Guard: without the setting, the same look-alike\'s event-stream reply is withheld',
        setup: { path: S.P.chat, request: { verb: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' }, content: LOOKALIKE },
                 legs: ['request', 'response'], airs: R.answers('allow-prompt'),
                 response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } },
        v3: function (r) { var p = r.response; return S.check(p && p.fault && p.blocked, 'reply leg: ' + state(p)); }
    },

    /* ---------------- a body at /mcp that is not JSON-RPC as v3 classifies it ---------------- */
    {
        // README Settings, failClosedOnUnknown: "false lets requests to endpoints v3 doesn't read ... pass unscanned ... A
        // body v3 can't read at an endpoint it does read is still refused." airs3-detect.js treats /mcp as an MCP route
        // (mcpPath: the 405, the empty-body refusal, the JSON-RPC refusal shape), but refuses an array that is not a batch
        // as an unknown endpoint (gap(..., true)), so with failClosedOnUnknown=false it passes unread; a JSON-RPC server
        // answers each valid member of an array on its own.
        finding: 'P2GATE-MIXED', title: 'failClosedOnUnknown=false: an array at /mcp holding a tools/call and one member that is not a message is still refused',
        setup: Object.assign(rpc([call(1, 'Card ' + C), 5]), { legs: ['request'], airs: R.answers('block-tool-input'), vars: { failClosedOnUnknown: 'false' } }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && x.blocked, state(x)); }
    },
    {
        // The same rule for one message that v3 doesn't classify as JSON-RPC (no jsonrpc member): with apiFormat=mcp it
        // is read and scanned; at /mcp without it, failClosedOnUnknown=false lets it pass unread.
        finding: 'P2GATE-MIXED', title: 'failClosedOnUnknown=false: a tools/call without a jsonrpc member at /mcp is read or refused, as it is with apiFormat=mcp',
        setup: Object.assign(rpc({ id: 1, method: 'tools/call', params: { name: 'echo', arguments: { text: 'hello ' + M } } }),
                             { legs: ['request'], airs: R.answers('allow-tool'), vars: { failClosedOnUnknown: 'false' } }),
        v3: function (r) { return scannedOrRefused(r.request, 'hello ' + M); }
    },
    {
        finding: 'P2GATE-MIXED', title: 'Guard: with the defaults, the array [tools/call, 5] at /mcp is refused before the server, with no scan',
        setup: Object.assign(rpc([call(1, 'Card ' + C), 5]), { legs: ['request'], airs: R.answers('block-tool-input') }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && x.blocked && x.calls.length === 0, state(x)); }
    }
];

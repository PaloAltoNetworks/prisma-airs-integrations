'use strict';
/*
 * The fixes for the review of phase 2 (15 Nov 2026): cases for defects found while fixing its findings, one family with
 * 61's P2GATE-PROTO (a member named like an Object.prototype property).
 *   - P2FIX-PROTO: JSON.parse makes a member named __proto__ an own member, but rebuilding an object by assignment
 *     (o[k] = ...) sets the new object's prototype instead, so the member dropped out of the scan text: on V8 (this
 *     harness) for certain; on Apigee's Rhino it is a live check. Now each rebuild defines such a member
 *     (AIRS3.put), and a body whose parsed objects have a prototype that isn't the plain one is refused (AIRS3.oddProto).
 *     Gemini's part reader also looked members up in a plain object, so a part member named constructor was taken for
 *     a field it reads and left out.
 *   - P2FIX-NOTE: a refusal before any scan logged an empty note (live r14, P2B5), so the log could not tell a batch over
 *     mcpBatchLimit from a leg that needs more than 8 scans or an oversize member (61's and the critic's doc gaps).
 *   - P2FIX-SIDE: guards for the fixes to 61's P2GATE-SIDE and P2GATE-ENV that a mutation check showed no case held.
 *     MCP reply text now goes to Prisma AIRS as a prompt, so prompt.* detections on the reply leg are the reply's own:
 *     the LLM rule that lets a reply through when only its prompt context was flagged must never apply to MCP. And an
 *     answer in a reply array is an answer whatever method sits beside its result, so a tools/call answer stays a tool
 *     event.
 *   - P2FIX-OPEN: allowOpenStreams passes an event-stream reply only on an MCP route (a path ending in /mcp, or
 *     apiFormat=mcp); 61's P2GATE-OPEN holds the other half (a body with members outside the envelope).
 *   - P2FIX-BOTHDUP: with type=both the reply leg judges the request too, but read it without the request leg's checks
 *     for duplicate keys (A20) and for members the runtime reads as prototypes (seen by the review of the fixes).
 * Bodies with a __proto__ member are written as JSON text: in a JavaScript literal, __proto__ sets the prototype.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };

function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' scan(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 160) : ', passed');
}
function scannedOrRefused(x, text) {
    if (!x) { return 'the leg did not run'; }
    if (x.fault && x.blocked) { return true; }
    return S.check(x.scanned.indexOf(text) !== -1, '"' + text + '" passed unscanned: ' + state(x));
}

module.exports = [
    {
        finding: 'P2FIX-PROTO', title: 'Request leg: a tools/call whose arguments carry a member named __proto__ (the card in it): that member reaches the tool event\'s input',
        setup: Object.assign(S.req(S.P.mcp, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi","__proto__":{"note":"Card ' + C + '"}}}}', H),
                             { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) { return scannedOrRefused(r.request, 'Card ' + C); }
    },
    {
        finding: 'P2FIX-PROTO', title: 'Reply leg: a tools/call answer whose result carries a member named __proto__: that member reaches the tool event\'s output',
        setup: Object.assign(S.mcp('tools/call', { name: 'echo', arguments: { text: 'hi' } }), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: { status: 200, headers: { 'Content-Type': 'application/json' },
                        content: '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}],"__proto__":{"note":"Proto text. ' + M + '"}}}' } }),
        v3: function (r) { return scannedOrRefused(r.response, 'Proto text. ' + M); }
    },
    {
        finding: 'P2FIX-PROTO', title: 'Gemini: a part member named constructor is scanned with the part, not taken for a field the reader handles',
        setup: Object.assign(S.req(S.P.gemini, '{"contents":[{"role":"user","parts":[{"text":"hello","constructor":"Constructor text. ' + M + '"}]}]}'),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return scannedOrRefused(r.request, 'Constructor text. ' + M); }
    },
    {
        finding: 'P2FIX-PROTO', title: 'Guard: a tools/call whose arguments carry an ordinary member (note) with the card: scanned as the tool event\'s input',
        setup: Object.assign(S.req(S.P.mcp, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi","note":{"note":"Card ' + C + '"}}}}', H),
                             { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) { return scannedOrRefused(r.request, 'Card ' + C); }
    },
    {
        finding: 'P2FIX-NOTE', title: 'A batch of 9 pings, over the default mcpBatchLimit, is refused before any scan and its log line says why',
        setup: Object.assign(S.req(S.P.mcp, [1, 2, 3, 4, 5, 6, 7, 8, 9].map(function (n) { return { jsonrpc: '2.0', id: n, method: 'ping' }; }), H),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request, l = x.flow.logs, line = null;
            try { line = l.length ? JSON.parse(l[l.length - 1].line) : null; } catch (e) { line = null; }
            return S.check(x.fault && x.calls.length === 0 && line && /more than 8 messages/.test(line.note || ''), 'the log line\'s note: ' + JSON.stringify(line && line.note) + ' ' + state(x));
        }
    },
    {
        finding: 'P2FIX-SIDE', title: 'A resources/read answer that Prisma AIRS blocks on prompt.* detections only (injection, agent) is withheld, though the request leg allowed: on MCP those are the reply\'s own',
        setup: Object.assign(S.mcp('resources/read', { uri: 'lab://page' }, 4), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-injection-agent-prompt'),
            response: S.reply({ jsonrpc: '2.0', id: 4, result: { contents: [{ uri: 'lab://page', mimeType: 'text/plain', text: 'Page text. ' + M }] } }) }),
        v3: function (r) {
            var x = r.response, b = null;
            try { b = JSON.parse(x.body); } catch (e) { b = null; }
            return S.check(x && x.blocked && x.calls.length === 1 && b && b.id === 4 && b.error && b.error.code === -32001, 'not withheld with -32001 for id 4: ' + state(x));
        }
    },
    {
        finding: 'P2FIX-SIDE', title: 'A reply array: an answer to tools/call id 1 that carries a method beside its result is still that call\'s answer, a tool event',
        setup: Object.assign(S.req(S.P.mcp, [{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { text: 'one' } } },
                                             { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { text: 'two' } } }], H),
                             { legs: ['request', 'response'], airs: R.answers('allow-tool'),
                               response: S.reply([{ jsonrpc: '2.0', id: 1, method: 'notifications/odd', result: { content: [{ type: 'text', text: 'Answer one. ' + M }] } },
                                                  { jsonrpc: '2.0', id: 2, result: { content: [{ type: 'text', text: 'Answer two.' }] } }]) }),
        v3: function (r) {
            var x = r.response, e = x && x.scans[0] && x.scans[0].contents[0];
            return S.check(x && !x.fault && x.calls.length === 2 && e && e.tool_event && String(e.tool_event.output).indexOf('Answer one. ' + M) !== -1 && e.tool_event.metadata.tool_invoked === 'echo',
                           'answer one was not a tool event: ' + JSON.stringify(e).slice(0, 240) + ' ' + state(x));
        }
    },
    {
        finding: 'P2FIX-OPEN', title: 'allowOpenStreams=true: a plain JSON-RPC request at a path that is not an MCP route (/v1/chat/completions) has its event-stream reply withheld',
        setup: { path: S.P.chat, request: { verb: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
                                            content: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri: 'lab://page' } }) },
                 legs: ['request', 'response'], airs: R.answers('allow-prompt'), vars: { allowOpenStreams: 'true' },
                 response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } },
        v3: function (r) {
            var x = r.response;
            return S.check(x && x.fault && x.calls.length === 0 && v(x, 'route') !== 'pass', 'the event-stream reply passed: ' + state(x));
        }
    },
    {
        finding: 'P2FIX-BOTHDUP', title: 'type=both on a reply-leg-only proxy: a Gemini request with two contents keys has its reply withheld before any scan, as the request leg refuses such a body (A20)',
        setup: Object.assign(S.req(S.P.gemini, '{"contents":[{"role":"user","parts":[{"text":"first ' + M + '"}]}],"contents":[{"role":"user","parts":[{"text":"second"}]}]}'),
                             { legs: ['response'], params: { response: { type: 'both' } }, airs: R.answers('allow-prompt-response'),
                               response: S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: 'Second.' }] }, finishReason: 'STOP' }] }) }),
        v3: function (r) { var x = r.response; return S.check(x && x.fault && x.calls.length === 0, 'the reply was judged with one copy of the request: ' + state(x)); }
    },
    {
        finding: 'P2FIX-BOTHDUP', title: 'Guard: type=both on a reply-leg-only proxy, the same request with one contents key: judged with its reply and allowed',
        setup: Object.assign(S.req(S.P.gemini, '{"contents":[{"role":"user","parts":[{"text":"second"}]}]}'),
                             { legs: ['response'], params: { response: { type: 'both' } }, airs: R.answers('allow-prompt-response'),
                               response: S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: 'Second.' }] }, finishReason: 'STOP' }] }) }),
        v3: function (r) { var x = r.response; return S.check(x && !x.fault && x.calls.length === 1, state(x)); }
    }
];

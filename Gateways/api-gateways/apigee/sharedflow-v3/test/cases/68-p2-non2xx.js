'use strict';
/*
 * MCP replies outside 2xx (15 Nov 2026): A31's MCP half, moved into phase 2 (P2GATE-NON2XX in 64-p2gate-critic.js).
 * MuleSoft's rule (src/mcp.rs response(), core/src/mcp/reply.rs messages()): a reply body it can read is scanned whatever
 * its HTTP status; a body it cannot read is a gap on a 2xx reply and passes on any other, as an error that carries no
 * text it could scan. v3 now reads an MCP reply outside 2xx as it reads a 2xx one, with the same checks (duplicate keys,
 * members the runtime reads as prototypes, size, event streams); only a body that is empty or not JSON passes, logged.
 * An LLM reply outside 2xx still passes unscanned (A31: no provider puts model text into an error reply). On Apigee such a reply reaches v3's reply leg only when
 * the MCP target's success.codes count 4xx and 5xx (L16); this emulator always runs the reply leg.
 *   - P2NON2XX: the lab's MCP server answers a message it cannot validate with HTTP 400 and a JSON-RPC error whose message
 *     quotes the value it refused (live, P2B2): server text the client receives, in an error reply.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get, and
 * nothing here decides a verdict from content.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };

function rpc(body, headers) { return S.req(S.P.mcp, body, Object.assign({}, H, headers || {})); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
function json(status, b) { return { status: status, headers: { 'Content-Type': 'application/json' }, content: typeof b === 'string' ? b : JSON.stringify(b) }; }
// The lab server's refusal of a message it cannot validate: an error that answers no member, quoting the refused value.
function invalid(value) {
    return { jsonrpc: '2.0', id: 'server-error', error: { code: -32602, message: 'Validation error: 1 validation error for JSONRPCMessage\nparams\n' +
             '  Input should be a valid dictionary [type=dict_type, input_value=\'' + value + '\', input_type=str]' } };
}
function body(x) { try { return JSON.parse(x.body); } catch (e) { return null; } }
function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' scan(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 160) : ', passed');
}
function entry(x, i) { var s = x && x.scans[i]; return s && s.contents && s.contents[0] || null; }
// MCP text goes to Prisma AIRS as a prompt, with no other member.
function asPrompt(x, i) { var e = entry(x, i); return !!(e && typeof e.prompt === 'string' && e.response === undefined && !e.tool_event); }
// Withheld as a single MCP message: -32001 with the request's id.
function withheld(x, id) { var b = body(x); return !!(x && x.fault && x.blocked && b && b.id === id && b.error && b.error.code === -32001); }
function passedAsIs(x, status, content) { return !!(x && !x.fault && x.status === status && x.body === content); }

const LAB_ERR = JSON.stringify(invalid('hello'));

module.exports = [
    {
        finding: 'P2NON2XX', title: 'HTTP 400, a JSON-RPC error that answers no member and quotes the card: scanned as the reply\'s text (a prompt) and withheld, -32001 with the request\'s id',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'block-dlp-prompt-masked'),
            response: json(400, invalid('Card ' + C)) }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && x.calls.length === 1 && S.has(x, 'Card ' + C) && asPrompt(x, 0) && withheld(x, 7), 'not scanned as a prompt and withheld: ' + state(x));
        }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 400, the same error with harmless text: one scan, allowed; the client gets the server\'s 400 and body as they were',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-prompt'),
            response: json(400, LAB_ERR) }),
        v3: function (r) { var x = r.response; return S.check(x && x.calls.length === 1 && passedAsIs(x, 400, LAB_ERR), 'not scanned once and passed as it was: ' + state(x)); }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 500, a tools/call answered with a result that carries the card: a tool event (the arguments in, the result out), withheld',
        setup: Object.assign(rpc(call(3, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'block-tool-output'),
            response: json(500, { jsonrpc: '2.0', id: 3, result: { content: [{ type: 'text', text: 'Server text. Card ' + C }], isError: false } }) }),
        v3: function (r) {
            var x = r.response, e = entry(x, 0);
            return S.check(x && x.calls.length === 1 && e && e.tool_event && String(e.tool_event.output).indexOf('Card ' + C) !== -1 && withheld(x, 3),
                           'not a withheld tool event: ' + state(x));
        }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 400 to a batch of two tools/call, an error for each, the second quoting the card: two scans after the request\'s two, the batch withheld',
        setup: Object.assign(rpc([call(1, 'hello'), call(2, 'hello')]), { legs: ['request', 'response'],
            airs: R.answers('allow-tool', 'allow-tool', 'allow-prompt', 'block-dlp-prompt-masked'),
            response: json(400, [{ jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'Bad value: hello' } },
                                 { jsonrpc: '2.0', id: 2, error: { code: -32602, message: 'Bad value: Card ' + C } }]) }),
        v3: function (r) {
            var x = r.response, b = body(x);
            var ids = Array.isArray(b) ? b.map(function (e) { return e && e.error && e.error.code === -32001 ? e.id : 'bad'; }) : null;
            return S.check(x && x.blocked && x.calls.length === 2 && S.has(x, 'Card ' + C) && JSON.stringify(ids) === '[1,2]', 'not two scans and the batch withheld: ' + state(x));
        }
    },
    {
        finding: 'P2NON2XX', title: 'type=both, reply leg only: tools/call hello answered with HTTP 400 and an error: the request\'s tool event, then the error as text; allowed, the 400 kept',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['response'], params: { response: { type: 'both' } }, airs: R.answers('allow-tool', 'allow-prompt'),
            response: json(400, LAB_ERR) }),
        v3: function (r) {
            var x = r.response, e = entry(x, 0);
            return S.check(x && x.calls.length === 2 && e && e.tool_event && asPrompt(x, 1) && passedAsIs(x, 400, LAB_ERR), 'not judged with its request and passed: ' + state(x));
        }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 404 with no body (Content-Length: 0): passes, no scan, logged',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: { status: 404, headers: { 'Content-Length': '0' }, content: '' } }),
        v3: function (r) { var x = r.response; return S.check(x && x.calls.length === 0 && passedAsIs(x, 404, '') && v(x, 'logNote') === 'a reply with no body passes', state(x)); }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 404 with an empty JSON body and no length header: passes, no scan, logged (a 2xx reply like it is withheld, A21: its body may be a stream the flow cannot see)',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: { status: 404, headers: { 'Content-Type': 'application/json' }, content: '' } }),
        v3: function (r) { var x = r.response; return S.check(x && x.calls.length === 0 && passedAsIs(x, 404, '') && v(x, 'logNote') === 'a reply with no body passes', state(x)); }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 502 with an HTML page: not JSON, so no text v3 could scan (MuleSoft: upstream_status); passes as it was, logged',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: { status: 502, headers: { 'Content-Type': 'text/html' }, content: '<html><body>Bad gateway</body></html>' } }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && x.calls.length === 0 && passedAsIs(x, 502, '<html><body>Bad gateway</body></html>') && v(x, 'logNote') === 'a non-2xx reply that is not JSON passes unscanned', state(x));
        }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 400 whose JSON has two error keys: withheld before any scan, as a 2xx reply like it is (A20)',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: json(400, '{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"first"},"error":{"code":-32602,"message":"second ' + M + '"}}') }),
        v3: function (r) { var x = r.response; return S.check(x && x.fault && x.calls.length === 0, 'the reply passed or was scanned: ' + state(x)); }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 400 whose JSON is not a JSON-RPC message (no result, error or method): withheld as content v3 cannot inspect, as a 2xx reply like it is',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: json(400, { jsonrpc: '2.0', id: 7 }) }),
        v3: function (r) { var x = r.response; return S.check(x && x.fault && x.calls.length === 0, 'the reply passed or was scanned: ' + state(x)); }
    },
    {
        finding: 'P2NON2XX', title: 'HTTP 500 announced as an event stream whose body the flow cannot see: withheld, as a 2xx one is',
        setup: Object.assign(rpc(call(7, 'hello')), { legs: ['request', 'response'], airs: R.answers('allow-tool'),
            response: { status: 500, headers: { 'Content-Type': 'text/event-stream' }, content: '' } }),
        v3: function (r) { var x = r.response; return S.check(x && x.fault && x.calls.length === 0, 'the reply passed: ' + state(x)); }
    },
    {
        finding: 'P2NON2XX', title: 'Guard (A31): a Gemini reply with HTTP 500 that quotes the card still passes unscanned, logged',
        setup: Object.assign(S.gemini([S.user('What is the capital of France?')]), { legs: ['request', 'response'], airs: R.answers('allow-prompt'),
            response: json(500, { error: { message: 'Card on file: ' + C } }) }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && !x.fault && x.calls.length === 0 && x.status === 500 && v(x, 'logNote') === 'a non-2xx reply is not scanned', state(x));
        }
    },
    {
        finding: 'P2NON2XX', title: 'Guard: allowOpenStreams=true, a GET for an event stream that the server answers with HTTP 405 and a JSON-RPC error: passes unread, as before (a bodiless request: MuleSoft passes its reply unread too)',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, legs: ['request', 'response'], airs: R.answers(),
                 vars: { allowOpenStreams: 'true' },
                 response: json(405, { jsonrpc: '2.0', id: 'server-error', error: { code: -32000, message: 'Method Not Allowed' } }) },
        v3: function (r) { var x = r.response; return S.check(x && !x.fault && x.calls.length === 0 && x.status === 405, state(x)); }
    }
];

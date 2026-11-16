'use strict';
/*
 * A review of the change that reads MCP replies outside 2xx (15 Nov 2026, 68-p2-non2xx.js), for defects. Each case failed
 * until its fix and passes now; titles that start with "Guard" were written with the fixes and pin their other side.
 * The fixes: with type=both, a request with no body has nothing to judge, so the reply's scans run alone (P2NR-1); on an
 * MCP route, an event stream to a request with no body is withheld whatever its status, unless allowOpenStreams opens it
 * (P2NR-2); only a request is answered by its id, so a refused client reply gets id null in HTTP 403 (P2NR-3).
 *   - P2NR-1: type=both judges the request on the reply leg, and airs3-read.js counts a request with no body as one it
 *     can't read ("its request: the body is not a JSON-RPC message"). At an apiFormat=mcp route (a path that doesn't end in
 *     /mcp) the reply to a GET or a DELETE was never read outside 2xx; now it is, so an MCP server's 405 or 404 to the
 *     SDK's GET for a stream or its DELETE that ends a session is withheld, HTTP 403 with id null, where it passed before.
 *     MuleSoft passes a bodiless request's reply unread (mcp.rs response(): "A bodiless request: anything but an
 *     unexpected event stream passes as it did before MCP, unread").
 *   - P2NR-2: at a path ending in /mcp, the reply to a request with no body is checked for an event stream only when it is
 *     2xx (airs3-detect.js, the GET-stream check). The same stream outside 2xx falls to "the reply to a request with no
 *     body passes": the flow can't see its body (L1) and the client gets all of it, unread, where the 2xx one, and the
 *     same reply at an apiFormat=mcp route, are withheld. MuleSoft reads an event stream that a bodiless request gets,
 *     whatever its status, unless it is a GET stream that allowOpenStreams opened (mcp.rs response(): stream_get).
 *   - P2NR-3: a withheld reply to the client's own JSON-RPC reply (no method: its id is the server's) is answered with
 *     HTTP 200 and that id. MuleSoft answers only request members (mcp.rs request_ids: "a client reply's id is the
 *     server's"), so it has no id to answer: id null in HTTP 403, as v3 itself answers a batch of client replies (README,
 *     MCP refusals). Outside 2xx is where a server answers a client reply it can't accept (an HTTP error status, and a
 *     JSON-RPC error with no id), so that refusal now runs there.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get, and
 * nothing here decides a verdict from content.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const H = { Accept: 'application/json, text/event-stream' };

function rpc(body) { return S.req(S.P.mcp, body, H); }
function json(status, b) { return { status: status, headers: { 'Content-Type': 'application/json' }, content: typeof b === 'string' ? b : JSON.stringify(b) }; }
function body(x) { try { return JSON.parse(x.body); } catch (e) { return null; } }
function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' scan(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 200) : ', passed');
}
function passedAsIs(x, status, content) { return !!(x && !x.fault && x.status === status && x.body === content); }

// What an MCP server sends where it offers no stream or no session end, and where the session has ended: a JSON-RPC
// error that answers no member.
const NOT_ALLOWED = JSON.stringify({ jsonrpc: '2.0', id: 'server-error', error: { code: -32600, message: 'Method Not Allowed' } });
const NO_SESSION = JSON.stringify({ jsonrpc: '2.0', id: 'server-error', error: { code: -32600, message: 'Not Found: the session has ended' } });
// type=both on the reply leg only, at a route that apiFormat=mcp marks (the README's setup for a server not at /mcp).
const BOTH_MCP = { response: { type: 'both', apiFormat: 'mcp' } };

module.exports = [
    /* ---------------- P2NR-1: type=both and a request with no body ---------------- */
    {
        finding: 'P2NR-1', title: 'type=both, reply leg only, apiFormat=mcp: the DELETE that ends a session (no body), answered HTTP 405 with a JSON-RPC error, reaches the client as it was (it passed before the change; MuleSoft passes a bodiless request\'s reply), not withheld as a request v3 cannot read',
        setup: { path: '', request: { verb: 'DELETE', headers: { 'Mcp-Session-Id': 'conv-42' }, content: '' }, legs: ['response'], params: BOTH_MCP,
                 airs: R.answers('allow-prompt'), response: json(405, NOT_ALLOWED) },
        v3: function (r) { var x = r.response; return S.check(passedAsIs(x, 405, NOT_ALLOWED), 'not passed as it was: ' + state(x)); }
    },
    {
        finding: 'P2NR-1', title: 'type=both, reply leg only, apiFormat=mcp: a GET for an event stream whose session has ended, answered HTTP 404 with a JSON-RPC error: the client still gets the 404 (on a 404 an MCP client starts a new session), not HTTP 403',
        setup: { path: '', request: { verb: 'GET', headers: { Accept: 'text/event-stream', 'Mcp-Session-Id': 'conv-42' }, content: '' }, legs: ['response'], params: BOTH_MCP,
                 airs: R.answers('allow-prompt'), response: json(404, NO_SESSION) },
        v3: function (r) { var x = r.response; return S.check(passedAsIs(x, 404, NO_SESSION), 'not passed as it was: ' + state(x)); }
    },

    /* ---------------- P2NR-2: an event stream outside 2xx, to a request with no body, at /mcp ---------------- */
    {
        finding: 'P2NR-2', title: 'Reply leg only, at /mcp: a GET for an event stream answered HTTP 400 as an event stream whose body the flow cannot see (L1): withheld, as the same reply with HTTP 200 is, and as it is at an apiFormat=mcp route',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream', 'Mcp-Session-Id': 'conv-42' }, content: '' }, legs: ['response'],
                 airs: R.answers('allow-prompt'), response: { status: 400, headers: { 'Content-Type': 'text/event-stream' }, content: '' } },
        v3: function (r) { var x = r.response; return S.check(x && x.fault && x.blocked && x.calls.length === 0, 'the event stream passed unread: ' + state(x)); }
    },

    /* ---------------- P2NR-3: the refusal of a reply to the client's own reply ---------------- */
    {
        finding: 'P2NR-3', title: 'The client\'s JSON-RPC reply (id 0, no method) answered HTTP 400 with a JSON-RPC error with no id that quotes the card: withheld with -32001 and id null in HTTP 403, as MuleSoft answers (mcp.rs request_ids) and v3 answers a batch of client replies; not HTTP 200 with the server\'s own id 0',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 0, result: { action: 'accept', content: { note: 'hello' } } }), { legs: ['request', 'response'],
            airs: R.answers('allow-prompt', 'block-dlp-prompt-masked'),
            response: json(400, { jsonrpc: '2.0', error: { code: -32600, message: 'Cannot accept this reply: Card ' + C } }) }),
        v3: function (r) {
            var x = r.response, b = body(x);
            return S.check(x && x.fault && x.blocked && x.status === 403 && b && !Array.isArray(b) && b.id === null && b.error && b.error.code === -32001,
                           'not -32001 with id null in HTTP 403: ' + state(x));
        }
    },

    /* ---------------- Guards written with the fixes ---------------- */
    {
        finding: 'P2NR-1', title: 'Guard: type=both, reply leg only, apiFormat=mcp: a DELETE (no body) answered HTTP 200 with a result that quotes the card: the reply is still scanned, on its own, and withheld',
        setup: { path: '', request: { verb: 'DELETE', headers: { 'Mcp-Session-Id': 'conv-42' }, content: '' }, legs: ['response'], params: BOTH_MCP,
                 airs: R.answers('block-dlp-prompt-masked'), response: json(200, { jsonrpc: '2.0', id: 'server-error', result: { note: 'Card ' + C } }) },
        v3: function (r) { var x = r.response; return S.check(x && x.fault && x.blocked && x.calls.length === 1 && S.has(x, 'Card ' + C), 'the reply was not scanned on its own and withheld: ' + state(x)); }
    },
    {
        finding: 'P2NR-2', title: 'Guard: allowOpenStreams=true, reply leg only, at /mcp: the same GET answered HTTP 400 as an event stream passes unscanned, logged (the stream the client asked for)',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream', 'Mcp-Session-Id': 'conv-42' }, content: '' }, legs: ['response'],
                 vars: { allowOpenStreams: 'true' }, airs: R.answers(), response: { status: 400, headers: { 'Content-Type': 'text/event-stream' }, content: '' } },
        v3: function (r) {
            var x = r.response;
            return S.check(x && !x.fault && x.calls.length === 0 && x.status === 400 && v(x, 'logNote') === 'an open stream passes unscanned (allowOpenStreams)', state(x));
        }
    },
    {
        finding: 'P2NR-2', title: 'Guard (A31): a GET at a path that is not an MCP route (/v1/models) answered HTTP 500 as an event stream still passes, logged',
        setup: { path: '/v1/models', request: { verb: 'GET', headers: {}, content: '' }, legs: ['response'], airs: R.answers(),
                 response: { status: 500, headers: { 'Content-Type': 'text/event-stream' }, content: '' } },
        v3: function (r) { var x = r.response; return S.check(x && !x.fault && x.calls.length === 0 && x.status === 500, state(x)); }
    },
    {
        finding: 'P2NR-3', title: 'Guard: request leg: the client\'s reply (id 0, no method) whose result quotes the card is refused with -32001 and id null in HTTP 403, not HTTP 200 with the server\'s id',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 0, result: { action: 'accept', content: { note: 'Card ' + C } } }), { legs: ['request'],
            airs: R.answers('block-dlp-prompt-masked') }),
        v3: function (r) {
            var x = r.request, b = body(x);
            return S.check(x && x.fault && x.blocked && x.status === 403 && b && !Array.isArray(b) && b.id === null && b.error && b.error.code === -32001,
                           'not -32001 with id null in HTTP 403: ' + state(x));
        }
    },
    {
        finding: 'P2NR-3', title: 'Guard: request leg: a blocked tools/call (id 5) is still answered with its own id, in HTTP 200',
        setup: Object.assign(rpc({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'echo', arguments: { text: 'Card ' + C } } }), { legs: ['request'],
            airs: R.answers('block-tool-input') }),
        v3: function (r) { var x = r.request, b = body(x); return S.check(x && x.blocked && x.status === 200 && b && b.id === 5 && b.error && b.error.code === -32001, state(x)); }
    }
];

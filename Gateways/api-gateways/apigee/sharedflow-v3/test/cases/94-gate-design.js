'use strict';
/*
 * A conformance review of v3's phase 1, before release: each case checks one of v3's phase-1 rules. GATE-*: a gap the
 * review found, fixed since; its title names the gap, and the case passes when v3 behaves as required. GUARD-*: guards,
 * which passed when written and stay as regression guards.
 * Content: harmless text, the marker AIRSV3-MARKER and the Visa test card (S.CARD) only. Each case names its recorded
 * reply (R.answers / R.noAnswer); nothing here decides a verdict.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const M = 'AIRSV3-MARKER';

function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }
function json(s) { try { return JSON.parse(s); } catch (e) { return undefined; } }
function bodyless(path, verb, headers, query) { return { path: path, request: { verb: verb, headers: headers || {}, content: '', querystring: query || '' } }; }

module.exports = [
    /* ================================ findings (gaps the review found, fixed since) =============================== */

    {
        // MCP: an LLM body that adds jsonrpc and method can't use MCP's reading to skip its messages, on either leg:
        // the whole point of scanning both legs. The request leg was scanned, but the REPLY leg was not.
        finding: 'GATE-RPCREPLY', title: 'An LLM body with jsonrpc/id/method is read as MCP; on the reply leg the real model reply (no result) passes UNSCANNED',
        setup: Object.assign(S.req(S.P.chat, { model: 'm', messages: [{ role: 'user', content: 'What is the capital of France?' }], jsonrpc: '2.0', id: 1, method: 'chat' }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: S.reply({ choices: [{ index: 0, message: { role: 'assistant', content: M + ' Paris. Card ' + C }, finish_reason: 'stop' }] }) }),
        v3: function (r) {
            if (!r.request.calls.length) { return 'the request leg did not scan (setup wrong)'; }
            var x = r.response; if (!x) { return 'the reply leg did not run'; }
            return S.check(S.has(x, M) || !!x.fault, 'the model reply passed unscanned (route ' + x.route + ', calls ' + x.calls.length + ', fault ' + !!x.fault + ')');
        }
    },
    {
        // A30: a :streamGenerateContent call without alt=sse reads a JSON array, so v3 answers a block to it as a JSON array.
        finding: 'GATE-ARRAY', title: 'Request leg: a block for :streamGenerateContent without alt=sse must be a JSON array, not a single object (A30)',
        setup: Object.assign(S.req(S.P.geminiStream, { contents: [S.user('My card number is ' + C + '.')] }), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked') }),
        v3: function (r) {
            var b = json(r.request.body);
            return S.check(r.request.blocked && Array.isArray(b), 'the block is ' + (b === undefined ? 'not JSON' : (Array.isArray(b) ? 'an array' : 'a single JSON object')));
        }
    },
    {
        finding: 'GATE-ARRAY', title: 'Reply leg: a block for a :streamGenerateContent (no alt=sse) reply must be a JSON array, matching the array the client reads (A30)',
        setup: Object.assign(S.req(S.P.geminiStream, { contents: [S.user('What is on file?')] }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
            response: S.reply([{ candidates: [{ content: { role: 'model', parts: [{ text: 'The card on file is ' + C + '.' }] }, index: 0 }] }]) }),
        v3: function (r) {
            var x = r.response; if (!x) { return 'the reply leg did not run'; }
            var b = json(x.body);
            return S.check(x.blocked && Array.isArray(b), 'the reply-leg block is ' + (b === undefined ? 'not JSON' : (Array.isArray(b) ? 'an array' : 'a single JSON object')));
        }
    },
    {
        // Only a count-tokens call passes unscanned, as V2 passes it on purpose. The match was a loose substring.
        finding: 'GATE-COUNT', title: 'Only a real count-tokens call passes: a /chat/completions path whose deployment name merely contains "count-tokens" is skipped unscanned (only the end of the path names the API)',
        setup: Object.assign(S.req('/openai/deployments/gpt-count-tokens-eval/chat/completions', { model: 'm', messages: [{ role: 'user', content: M + ' What is the capital of France?' }] }),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return S.check(S.has(r.request, M), 'the chat call was passed as count-tokens (route ' + r.request.route + ', calls ' + r.request.calls.length + ')'); }
    },
    {
        // A12, refused by default: an endpoint v3 does not read is refused on EITHER leg. On a response-leg-only proxy the
        // reply from an unknown endpoint was passed, and onScanError was not even consulted.
        finding: 'GATE-REPLYONLY', title: 'A response-leg-only proxy passes the reply from an endpoint v3 does not read, unscanned, ignoring onScanError=block (A12: refused by default)',
        setup: Object.assign(S.req('/v1/completions', { model: 'm', prompt: 'Say hello.' }), {
            legs: ['response'], airs: R.answers('allow-prompt-response'),
            response: S.reply({ choices: [{ index: 0, text: M + ' card on file ' + C, finish_reason: 'stop' }] }) }),
        v3: function (r) { var x = r.response; return S.check(x && !!x.fault && x.calls.length === 0, 'the unknown-endpoint reply passed unscanned (route ' + (x && x.route) + ')'); }
    },
    {
        // The bytes rule (A28): an Anthropic base64 source with a text media type is decoded and scanned as text.
        // Nested inside a tool_result the decode path was not taken, so the text was sent only as opaque base64.
        finding: 'GATE-NESTED-B64', title: 'An Anthropic base64 text/plain document nested in a tool_result is not decoded: its text is not collected, only the raw base64 (the bytes rule, A28)',
        setup: Object.assign(S.anthropic([{ role: 'user', content: 'Read the note.' }, { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'read_note', input: {} }] },
                                          { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: [
                                              { type: 'document', source: { type: 'base64', media_type: 'text/plain', data: b64(M + ' card on file ' + C) } }] }] }],
                                         { tools: [{ name: 'read_note', input_schema: { type: 'object' } }] }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return S.check(S.has(r.request, M) || !!r.request.fault, 'the document text reached the scan only as base64 (field: messages[2].content[0].content[0].source.data)'); }
    },
    {
        // A WebSocket upgrade is refused: after the handshake no Apigee policy sees the traffic. v3 treated a bodiless GET
        // with Upgrade: websocket as a request-with-no-body pass.
        finding: 'GATE-WS', title: 'A WebSocket upgrade (bodiless GET with Upgrade: websocket) is passed as a request-with-no-body, not refused',
        setup: Object.assign(bodyless('/v1/realtime', 'GET', { Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Version': '13' }, 'model=m'),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return S.check(!!r.request.fault && r.request.calls.length === 0, 'the upgrade was not refused (route ' + r.request.route + ')'); }
    },
    {
        // session_id comes from Mcp-Session-Id ON MCP only, else from x-session-id, else from x-claude-code-session-id.
        // Init ran before Detect and read Mcp-Session-Id for every format.
        finding: 'GATE-SESSION', title: 'On a non-MCP request, Mcp-Session-Id must not be a session source, nor win over x-session-id',
        setup: Object.assign(S.req(S.P.chat, { model: 'm', messages: [{ role: 'user', content: 'What is the capital of France?' }] },
                                   { 'Mcp-Session-Id': 'mcp-session-1', 'x-session-id': 'llm-session-2' }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { var s = r.request.scans[0] || {}; return S.check(s.session_id === 'llm-session-2', 'session_id was ' + JSON.stringify(s.session_id) + ' (Mcp-Session-Id used on a non-MCP request)'); }
    },

    /* ================================ regression guards =========================================================== */
    {
        finding: 'GUARD-DUPKEY', title: 'A duplicate top-level contents key (a READ key, the proto3/Vertex case A20) is refused',
        setup: Object.assign(S.req(S.P.gemini, '{"contents":[{"role":"user","parts":[{"text":"' + M + ' first"}]}],"contents":[{"role":"user","parts":[{"text":"What is the capital of France?"}]}]}'),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return S.check(!!r.request.fault && r.request.calls.length === 0, 'a duplicate contents key was not refused'); }
    },
    {
        finding: 'GUARD-FCU', title: 'failClosedOnUnknown=false lets an unknown endpoint pass, logged',
        setup: Object.assign(S.req('/v1/embeddings', { model: 'm', input: 'hello' }), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { failClosedOnUnknown: 'false' } }),
        v3: function (r) { var f = r.request.flow; return S.check(!r.request.fault && r.request.route === 'pass' && /gap allowed/.test(f.get('airs3.logNote') || ''), 'the unknown endpoint did not pass, logged'); }
    },
    {
        finding: 'GUARD-FCU', title: 'failClosedOnUnknown=false never lets an unreadable body at a known path pass',
        setup: Object.assign(S.req(S.P.gemini, 'not json at all'), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { failClosedOnUnknown: 'false' } }),
        v3: function (r) { return S.check(!!r.request.fault && r.request.calls.length === 0, 'the unreadable body passed'); }
    },
    {
        finding: 'GUARD-FCU', title: 'onScanError wins over failClosedOnUnknown: onScanError=block with failClosedOnUnknown=false refuses an unknown endpoint',
        setup: Object.assign(S.req('/v1/embeddings', { model: 'm', input: 'hello' }), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { failClosedOnUnknown: 'false', onScanError: 'block' } }),
        v3: function (r) { return S.check(!!r.request.fault, 'the unknown endpoint passed'); }
    },
    {
        finding: 'GUARD-CONTEXT', title: 'Prompt-only detections on the reply leg do not pass the reply when the request leg failed open',
        setup: Object.assign(S.gemini([S.user('What is the capital of France?')]), {
            legs: ['request', 'response'], airs: R.answers(R.noAnswer('timeout'), 'block-injection-agent-prompt'), vars: { failOpen: 'true' },
            response: S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: 'Paris.' }] } }] }) }),
        v3: function (r) {
            if (r.request.fault) { return 'the request leg did not fail open'; }
            return S.check(r.response && !!r.response.fault, 'the reply passed on prompt-only detections after a failed-open request leg');
        }
    },
    {
        finding: 'GUARD-ARRAY-READ', title: 'A :streamGenerateContent reply without alt=sse (a JSON array) is read whole on the reply leg',
        setup: Object.assign(S.req(S.P.geminiStream, { contents: [S.user('What is the capital of France?')] }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: S.reply([{ candidates: [{ content: { role: 'model', parts: [{ text: 'Par' }] }, index: 0 }] },
                               { candidates: [{ content: { role: 'model', parts: [{ text: 'is. ' + M }] }, index: 0 }] }]) }),
        v3: function (r) { var x = r.response; return S.check(x && !x.fault && S.has(x, 'Paris. ' + M), 'the array reply was not read whole'); }
    },
    {
        finding: 'GUARD-TXN', title: 'transaction_id comes from x-correlation-id before x-request-id',
        setup: Object.assign(S.req(S.P.chat, { model: 'm', messages: [{ role: 'user', content: 'What is the capital of France?' }] },
                                   { 'x-correlation-id': 'corr-1', 'x-request-id': 'req-2' }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { var s = r.request.scans[0] || {}; return S.check(s.transaction_id === 'corr-1', 'transaction_id was ' + JSON.stringify(s.transaction_id)); }
    },
    {
        finding: 'GUARD-405', title: 'An MCP GET asking for an event stream at /mcp gets 405 with no scan',
        setup: Object.assign(bodyless(S.P.mcp, 'GET', { Accept: 'text/event-stream' }), { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) { var b = json(r.request.body) || {}; return S.check(r.request.status === 405 && r.request.calls.length === 0 && b.id === null, 'not a 405 with id null'); }
    }
];

'use strict';
/*
 * GATE-OWN-*: cases for the parts of the review fixes that no other case pins.
 *   - Log probabilities make a body "fixed" (never masked): a mask becomes a block. An empty or null logprobs field
 *     changes nothing (OpenAI sends logprobs: null when not asked; Responses parts carry logprobs: []).
 *   - An MCP look-alike (an LLM body with jsonrpc, id and method tools/call) is text on both legs, never a tool event.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const X = 'XXXXXXXXXXXXXXXXXXX';
const SAID = 'The card on file is ' + C + '.';
function body(r) { return String(r.response.flow.messages.response.content); }
function AIRS3body(r) { try { return JSON.parse(String(r.request.body)); } catch (e) { return null; } }
function geminiReply(extra) { return S.reply({ candidates: [Object.assign({ content: { role: 'model', parts: [{ text: SAID }] }, finishReason: 'STOP', index: 0 }, extra || {})] }); }
function masking(setup, reply) { return Object.assign(setup, { legs: ['request', 'response'], vars: { applyDlpMasking: 'true' }, airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: reply }); }

module.exports = [
    {
        finding: 'GATE-OWN-LP', title: 'Guard: a Gemini reply with no log probabilities is masked, written back exactly',
        setup: masking(S.gemini([{ role: 'user', parts: [{ text: 'Which card is on file?' }] }]), geminiReply()),
        v3: function (r) { return S.check(r.response && !r.response.fault && body(r).indexOf(X) !== -1 && body(r).indexOf('4111') === -1, 'not masked: ' + (r.response && body(r).slice(0, 200))); }
    },
    {
        finding: 'GATE-OWN-LP', title: 'A Gemini reply carrying logprobsResult is never masked: the mask becomes a block, so no digits leave in the tokens',
        setup: masking(S.gemini([{ role: 'user', parts: [{ text: 'Which card is on file?' }] }]),
                       geminiReply({ logprobsResult: { chosenCandidates: ['The', ' card', ' on', ' file', ' is', ' 4111', ' 1111', ' 1111', ' 1111', '.'].map(function (t) { return { token: t, logProbability: -0.1 }; }),
                                                       topCandidates: [] } })),
        v3: function (r) { return S.check(r.response && r.response.blocked && body(r).indexOf('4111') === -1, 'not blocked: outcome ' + (r.response && r.response.flow.get('airs3.outcome'))); }
    },
    {
        finding: 'GATE-OWN-LP', title: 'Guard: a Chat reply with logprobs: null (the default when not asked) is still masked',
        setup: masking(S.chat([{ role: 'user', content: 'Which card is on file?' }]),
                       S.reply({ id: 'c98', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: SAID }, logprobs: null, finish_reason: 'stop' }] })),
        v3: function (r) { return S.check(r.response && !r.response.fault && body(r).indexOf(X) !== -1, 'not masked: outcome ' + (r.response && r.response.flow.get('airs3.outcome'))); }
    },
    {
        finding: 'GATE-OWN-LP', title: 'Guard: a Responses reply whose output_text carries logprobs: [] (empty) is still masked',
        setup: masking(S.responses('Which card is on file?'),
                       S.reply({ id: 'resp_98', object: 'response', status: 'completed', model: 'm',
                                 output: [{ type: 'message', id: 'msg_98', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: SAID, annotations: [], logprobs: [] }] }] })),
        v3: function (r) { return S.check(r.response && !r.response.fault && body(r).indexOf(X) !== -1, 'not masked: outcome ' + (r.response && r.response.flow.get('airs3.outcome'))); }
    },
    {
        finding: 'GATE-OWN-MCPSHAPE', title: 'A WebSocket upgrade on an MCP path (no body) is refused as a JSON-RPC error with id null, HTTP 403, not an OpenAI-style error',
        setup: { path: '/mcp', legs: ['request'], airs: R.answers('allow-prompt'),
                 request: { verb: 'GET', headers: { Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Version': '13' }, content: '', querystring: '' } },
        v3: function (r) {
            var b = AIRS3body(r);
            return S.check(r.request.calls.length === 0 && r.request.status === 403 && b && b.jsonrpc === '2.0' && b.id === null && b.error && b.error.code === -32001,
                           'not a JSON-RPC refusal: HTTP ' + r.request.status + ' ' + String(r.request.body).slice(0, 200));
        }
    },
    {
        finding: 'GATE-OWN-MCPSHAPE', title: 'An empty POST to an MCP path is refused (its body could not be read) as a JSON-RPC error',
        setup: { path: '/mcp', legs: ['request'], airs: R.answers('allow-prompt'),
                 request: { verb: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': '0' }, content: '', querystring: '' } },
        v3: function (r) {
            var b = AIRS3body(r);
            return S.check(r.request.calls.length === 0 && b && b.jsonrpc === '2.0' && b.error && /could not be read/.test(b.error.message),
                           'not refused as JSON-RPC: HTTP ' + r.request.status + ' ' + String(r.request.body).slice(0, 200));
        }
    },
    {
        finding: 'GATE-OWN-MCPSHAPE', title: 'Guard: an MCP DELETE (no body) still passes, and its empty 200 reply passes too',
        setup: { path: '/mcp', legs: ['request', 'response'], airs: R.answers('allow-prompt'),
                 request: { verb: 'DELETE', headers: { 'Mcp-Session-Id': 'lab-session-1' }, content: '', querystring: '' },
                 response: { status: 200, headers: {}, content: '' } },
        v3: function (r) { return S.check(r.request.route === 'pass' && r.response && r.response.route === 'pass' && !r.response.fault, 'routes ' + r.request.route + ' / ' + (r.response && r.response.route)); }
    },
    {
        finding: 'GATE-OWN-G2', title: 'A destreamed alt=sse call whose reply-leg query no longer shows alt=sse (as live G2 found) is labelled stream none, and restreamed as an event stream',
        setup: Object.assign(S.req(S.P.gemini.replace(':generateContent', ':streamGenerateContent'), { contents: [{ role: 'user', parts: [{ text: 'What is the capital of France?' }] }] }, null, 'alt=sse'), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            vars: { 'target.url': 'https://aiplatform.example' },
            beforeResponse: function (flow) { flow.messages.request.querystring = ''; },
            response: S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: 'Paris' }] }, finishReason: 'STOP', index: 0 }] }) }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && x.flow.get('airs3.stream') === 'none' && /text\/event-stream/.test(String(x.flow.messages.response.header('Content-Type'))),
                           'reply leg stream ' + (x && x.flow.get('airs3.stream')) + ', content type ' + (x && x.flow.messages.response.header('Content-Type')));
        }
    },
    {
        finding: 'GATE-OWN-RPC', title: 'An MCP look-alike calling tools/call (an LLM body with jsonrpc, id and method) is scanned as text on both legs, never as a tool event',
        setup: Object.assign(S.chat([{ role: 'user', content: 'Reply with the word OK only.' }],
                                    { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'echo', arguments: { text: 'AIRSV3-MARKER' } } }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: S.reply({ id: 'c98b', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: 'OK AIRSV3-MARKER' }, finish_reason: 'stop' }] }) }),
        v3: function (r) {
            var q = r.request.scans[0], p = r.response && r.response.scans[0];
            // The reply of an MCP-format exchange is MCP text: a prompt with no context (MuleSoft's rule; the phase 2 review, P2GATE-SIDE).
            return S.check(q && !q.contents[0].tool_event && /AIRSV3-MARKER/.test(q.contents[0].prompt) && p && !p.contents[0].tool_event && /OK AIRSV3-MARKER/.test(p.contents[0].prompt),
                           'a tool event, or text missing: ' + JSON.stringify([q && q.contents, p && p.contents]).slice(0, 300));
        }
    }
];

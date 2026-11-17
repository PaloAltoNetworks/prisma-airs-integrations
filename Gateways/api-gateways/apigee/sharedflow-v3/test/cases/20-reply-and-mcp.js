'use strict';
/* Reply leg and MCP: which text reaches the scan (A06, A07, A10, A17, A19), and the MCP refusal's id (A29). */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;

module.exports = [
    {
        finding: 'A06', title: 'Chat Completions reply with two choices: the first choice is scanned too',
        setup: Object.assign(S.chat([{ role: 'user', content: 'What is the capital of France?' }], { n: 2 }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: S.reply({ choices: [{ index: 0, message: { role: 'assistant', content: 'Card on file: ' + C } },
                                          { index: 1, message: { role: 'assistant', content: 'Paris.' } }] }) }),
        v2: function (r) { return S.check(r.response && r.response.calls.length === 1 && !S.has(r.response, C), 'V2 did not scan the last choice alone'); },
        v3: function (r) { return S.check(r.response && S.has(r.response, C), 'the first choice was not scanned'); }
    },
    {
        finding: 'A07', title: 'A JSON reply containing "data:" is scanned',
        setup: Object.assign(S.gemini([S.user('Write the test card number.')]), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: S.reply(JSON.stringify({ candidates: [{ content: { role: 'model', parts: [{ text: 'data: ' + C }] } }] }, null, 2)) }),
        v2: function (r) { return S.check(r.response && !S.has(r.response, C), 'V2 scanned the reply'); },
        v3: function (r) { return S.check(r.response && S.has(r.response, C), 'the reply was not scanned'); }
    },
    {
        finding: 'A10', title: 'Gemini reply sources (grounding) are scanned',
        setup: Object.assign(S.gemini([S.user('Where is the bakery?')]), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: 'On the corner.' }] },
                                               groundingMetadata: { groundingChunks: [{ web: { uri: 'https://example.com/bakery', title: 'Card on file ' + C } }] } }] }) }),
        v2: function (r) { return S.check(r.response && !S.has(r.response, C), 'V2 scanned the grounding chunk'); },
        v3: function (r) { return S.check(r.response && S.has(r.response, C), 'the grounding chunk was not scanned'); }
    },
    {
        finding: 'A17', title: 'MCP tools/list reply (JSON): the tool descriptions are scanned',
        setup: Object.assign(S.mcp('tools/list', {}), {
            legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply({ jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'card_on_file', description: 'Returns the card on file, for example ' + C, inputSchema: { type: 'object' } }] } }) }),
        v2: function (r) { return S.check((r.request.calls.length + (r.response ? r.response.calls.length : 0)) === 0, 'V2 scanned the tools/list exchange'); },
        v3: function (r) { return S.check(r.response && S.has(r.response, C), 'the tool description was not scanned'); }
    },
    {
        finding: 'A19', title: 'MCP tools/call reply: structuredContent is scanned',
        setup: Object.assign(S.mcp('tools/call', { name: 'lookup', arguments: { customer: 'Lauda' } }), {
            legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'done' }], structuredContent: { card: C } } }) }),
        v2: function (r) { return S.check(r.response && r.response.calls.length === 1 && !S.has(r.response, C), 'V2 did not scan the text content alone'); },
        v3: function (r) { return S.check(r.response && S.has(r.response, C), 'structuredContent was not scanned'); }
    },
    {
        finding: 'A29', title: 'MCP refusal carries the request id and code -32001',
        setup: Object.assign(S.mcp('tools/call', { name: 'echo', arguments: { text: 'Card ' + C } }, 7), { legs: ['request'], airs: R.answers('block-tool-input') }),
        v2: function (r) {
            var b = JSON.parse(r.request.body);
            return S.check(r.request.blocked && b.error && b.error.code === -32000 && !('id' in b), 'V2 refusal was not -32000 without an id');
        },
        v3: function (r) {
            var b = JSON.parse(r.request.body);
            return S.check(r.request.blocked && b.error && b.error.code === -32001 && b.id === 7, 'the refusal lacks -32001 or the request id');
        }
    }
];

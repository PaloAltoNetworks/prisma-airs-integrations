'use strict';
/* Request leg: which text reaches the scan (A01 to A05). Each case's text holds the test card where coverage is tested. */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const allow = function () { return R.answers('allow-prompt'); };

module.exports = [
    {
        finding: 'A01', title: 'Gemini: an earlier user turn reaches the scan',
        setup: Object.assign(S.gemini([S.user('My card number is ' + C + '. Please remember it.'), { role: 'model', parts: [{ text: 'Noted.' }] },
                                       S.user('What is the capital of France?')]), { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(r.request.calls.length === 1 && !S.has(r.request, C), 'V2 did not scan only the newest turn'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the earlier user turn was not scanned'); }
    },
    {
        finding: 'A01', title: 'Chat Completions: an earlier user turn reaches the scan',
        setup: Object.assign(S.chat([{ role: 'user', content: 'My card number is ' + C + '.' }, { role: 'assistant', content: 'Noted.' },
                                     { role: 'user', content: 'What is the capital of France?' }]), { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(r.request.calls.length === 1 && !S.has(r.request, C), 'V2 did not scan only the newest turn'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the earlier user turn was not scanned'); }
    },
    {
        finding: 'A01', title: 'Anthropic: an earlier user turn reaches the scan',
        setup: Object.assign(S.anthropic([{ role: 'user', content: 'My card number is ' + C + '.' }, { role: 'assistant', content: 'Noted.' },
                                          { role: 'user', content: 'What is the capital of France?' }]), { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(r.request.calls.length === 1 && !S.has(r.request, C), 'V2 did not scan only the newest turn'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the earlier user turn was not scanned'); }
    },
    {
        finding: 'A01', title: 'Gemini systemInstruction: left out by default, scanned with scanMessageRoles=user,system',
        setup: Object.assign(S.gemini([S.user('What is the capital of France?')], { systemInstruction: { parts: [{ text: 'Card on file: ' + C }] } }),
                             { legs: ['request'], airs: allow(), vars: { scanMessageRoles: 'user,system' } }),
        v2: function (r) { return S.check(!S.has(r.request, C), 'V2 scanned the system instruction'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'with system opted in, the system instruction was not scanned'); }
    },
    {
        finding: 'A02', title: 'Chat Completions ending in an assistant prefill: the user turn is still scanned',
        setup: Object.assign(S.chat([{ role: 'user', content: 'My card number is ' + C + '. Repeat it back.' }, { role: 'assistant', content: 'Sure, the number is' }]),
                             { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(!S.has(r.request, C), 'V2 scanned a request ending in a prefill'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the user turn before the prefill was not scanned'); }
    },
    {
        finding: 'A02', title: 'Anthropic ending in an assistant prefill: the user turn is still scanned',
        setup: Object.assign(S.anthropic([{ role: 'user', content: 'My card number is ' + C + '. Repeat it back.' }, { role: 'assistant', content: 'Sure, the number is' }]),
                             { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(!S.has(r.request, C), 'V2 scanned a request ending in a prefill'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the user turn before the prefill was not scanned'); }
    },
    {
        finding: 'A03', title: 'Responses API: input as a plain string is scanned',
        setup: Object.assign(S.responses('My card number is ' + C + '. Please remember it.'), { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(!S.has(r.request, C), 'V2 scanned a plain-string input'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the plain-string input was not scanned'); }
    },
    {
        finding: 'A03', title: 'Responses API: input_text parts are scanned',
        setup: Object.assign(S.responses([{ role: 'user', content: [{ type: 'input_text', text: 'My card number is ' + C + '.' }] }]), { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(!S.has(r.request, C), 'V2 scanned input_text parts'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the input_text part was not scanned'); }
    },
    {
        finding: 'A03', title: 'Responses API: a function_call_output is scanned',
        setup: Object.assign(S.responses([{ role: 'user', content: 'Look up my card.' }, { type: 'function_call', call_id: 'c1', name: 'lookup', arguments: '{}' },
                                          { type: 'function_call_output', call_id: 'c1', output: 'Card on file: ' + C }]), { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(!S.has(r.request, C), 'V2 scanned the function_call_output'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the function_call_output was not scanned'); }
    },
    {
        finding: 'A04', title: 'x-app: cli with no tools: the prompt is still scanned',
        setup: Object.assign(S.anthropic([{ role: 'user', content: 'My card number is ' + C + '.' }], {}, { 'x-app': 'cli' }), { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(r.request.calls.length === 0, 'V2 scanned a toolless x-app: cli request'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the x-app header switched scanning off'); }
    },
    {
        finding: 'A04', title: 'x-app: cli with tools, ending in a tool_result: the tool result is scanned',
        setup: Object.assign(S.anthropic([{ role: 'user', content: 'Look up my card.' },
                                          { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'lookup', input: {} }] },
                                          { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'Card on file: ' + C }] }],
                                         { tools: [{ name: 'lookup', description: 'Look up', input_schema: { type: 'object' } }] }, { 'x-app': 'cli' }),
                             { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(!S.has(r.request, C), 'V2 scanned the tool result'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the tool result was not scanned'); }
    },
    {
        finding: 'A05', title: 'Anthropic document block: its text is scanned',
        setup: Object.assign(S.anthropic([{ role: 'user', content: [{ type: 'document', source: { type: 'text', media_type: 'text/plain', data: 'Card on file: ' + C } },
                                                                    { type: 'text', text: 'Summarise the document.' }] }]), { legs: ['request'], airs: allow() }),
        v2: function (r) { return S.check(r.request.calls.length === 1 && !S.has(r.request, C), 'V2 did not scan the text block alone'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the document block was not scanned'); }
    }
];

'use strict';
/* Masking (A22 to A24), event streams (A08, A09, A18, A21, A30), and the rest of the Probe rows (A11, A12, A16, A28, A31). */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const MASKED = 'XXXXXXXXXXXXXXXXXXX';

function fwd(r) { return String(r.request.request.content); }          // the request as it would be forwarded
function sse(events, ct) { return { status: 200, headers: { 'Content-Type': ct || 'text/event-stream' }, content: events.join('') }; }
// A PNG's first bytes, then filler: the kind of tool-result image A28 is about.
function pngBase64() { var b = Buffer.alloc(600); Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b); for (var i = 8; i < b.length; i++) { b[i] = (i * 37) & 255; } return b.toString('base64'); }
const B64 = pngBase64();

module.exports = [
    {
        finding: 'A22', title: 'Masking two Chat Completions text blocks: each block gets its own stretch, nothing unmasked goes on',
        setup: Object.assign(S.chat([{ role: 'user', content: [{ type: 'text', text: 'Please store this card for the next order.' }, { type: 'text', text: 'Card number: ' + C }] }]), {
            legs: ['request'], airsFor: { v2: R.answers(R.asAllow('mask-v3-chat-two-blocks')), v3: R.answers('mask-v3-chat-two-blocks') },
            varsFor: { v3: { applyDlpMasking: 'true' } } }),
        v2: function (r) {
            var parts = JSON.parse(fwd(r)).messages[0].content;
            return S.check(fwd(r).indexOf(C) !== -1 && parts[0].text.indexOf(MASKED) !== -1, 'V2 did not leave the card in the second block');
        },
        v3: function (r) {
            var parts = JSON.parse(fwd(r)).messages[0].content;
            return S.check(!r.request.fault && fwd(r).indexOf(C) === -1 && parts[0].text === 'Please store this card for the next order.' && parts[1].text === 'Card number: ' + MASKED, 'the blocks were not masked exactly');
        }
    },
    {
        finding: 'A22', title: 'Masking a request that ends in a tool result: the tool result is masked, the user message stays',
        setup: Object.assign(S.anthropic([{ role: 'user', content: 'Look up my card.' }, { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'lookup', input: {} }] },
                                          { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'Card on file: ' + C }] }],
                                         { tools: [{ name: 'lookup', input_schema: { type: 'object' } }] }), {
            legs: ['request'], airsFor: { v2: R.answers(R.asAllow('mask-a22-tool-result')), v3: R.answers('mask-v3-tool-result') },
            varsFor: { v3: { applyDlpMasking: 'true' } } }),
        v2: function (r) { return S.check(fwd(r).indexOf(C) !== -1, 'V2 masked the tool result'); },
        v3: function (r) {
            var m = JSON.parse(fwd(r)).messages;
            return S.check(!r.request.fault && fwd(r).indexOf(C) === -1 && m[0].content === 'Look up my card.' && m[2].content[0].content === 'Card on file: ' + MASKED, 'the tool result was not masked exactly');
        }
    },
    {
        finding: 'A23', title: 'A one-line Gemini JSON reply with "data:" in it is read as JSON, not as a stream, so its mask is written back',
        setup: Object.assign(S.gemini([S.user('Which card is on file?')]), {
            legs: ['request', 'response'],
            airsFor: { v2: R.answers('allow-prompt', R.asAllow('block-dlp-response-masked')), v3: R.answers('allow-prompt', 'block-dlp-response-masked') },
            varsFor: { v3: { applyDlpMasking: 'true' } },
            response: S.reply(JSON.stringify({ candidates: [{ content: { role: 'model', parts: [{ text: 'The card on file is ' + C + '.' }] }, finishReason: 'STOP', index: 0 }],
                                               responseId: 'data: 7' })) }),
        v2: function (r) { var b = r.response && String(r.response.flow.messages.response.content); return S.check(r.response && !r.response.fault && b.indexOf(C) !== -1, 'V2 masked or withheld the reply'); },
        v3: function (r) {
            var b = r.response && String(r.response.flow.messages.response.content);
            return S.check(r.response && !r.response.fault && b.indexOf(C) === -1 && b.indexOf('The card on file is ' + MASKED + '.') !== -1, 'the reply was not masked exactly: ' + (b && b.slice(0, 160)));
        }
    },
    {
        finding: 'A24', title: 'MCP tool arguments that Prisma AIRS asks to mask are blocked, not forwarded',
        setup: Object.assign(S.mcp('tools/call', { name: 'echo', arguments: { text: 'Card ' + C } }, 3), {
            legs: ['request'], airsFor: { v2: R.answers(R.asAllow('mask-a24-tool-input')), v3: R.answers(R.asAllow('mask-a24-tool-input')) } }),
        v2: function (r) { return S.check(!r.request.fault && fwd(r).indexOf(C) !== -1, 'V2 did not forward the arguments unmasked'); },
        v3: function (r) { return S.check(r.request.blocked && fwd(r).indexOf(C) === -1 || (r.request.blocked && !!r.request.fault), 'the arguments were forwarded'); }
    },
    {
        finding: 'A28', title: 'Base64 image data in a tool result is left out of the scan',
        setup: Object.assign(S.anthropic([{ role: 'user', content: 'Take a screenshot.' }, { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'shot', input: {} }] },
                                          { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: B64 } }] }] }],
                                         { tools: [{ name: 'shot', input_schema: { type: 'object' } }] }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v2: function (r) { return S.check(S.has(r.request, B64.slice(0, 200)), 'V2 left the image bytes out'); },
        v3: function (r) { return S.check(r.request.calls.length === 1 && !S.has(r.request, B64.slice(0, 200)), 'the image bytes were sent as text'); }
    },
    {
        finding: 'A11', title: 'Keys inside a tool result are scanned, not only its values',
        setup: Object.assign(S.gemini([S.user('Look it up.'), { role: 'model', parts: [{ functionCall: { name: 'lookup', args: {} } }] },
                                       { role: 'user', parts: [{ functionResponse: { name: 'lookup', response: { ['card ' + C]: true } } }] }]), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v2: function (r) { return S.check(r.request.calls.length === 1 && !S.has(r.request, C), 'V2 scanned the key'); },
        v3: function (r) { return S.check(S.has(r.request, C), 'the key was not scanned'); }
    },
    {
        finding: 'A12', title: 'An endpoint v3 does not recognise (embeddings) is refused by default',
        setup: Object.assign(S.req('/v1/embeddings', { model: 'm', input: 'Card on file: ' + C }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v2: function (r) { return S.check(!r.request.fault && r.request.calls.length === 0, 'V2 refused or scanned it'); },
        v3: function (r) { return S.check(!!r.request.fault && r.request.calls.length === 0, 'the unknown endpoint was let through'); }
    },
    {
        finding: 'A21', title: 'A 2xx reply whose body the flow cannot see (an event stream on this runtime) is refused',
        setup: Object.assign(S.req(S.P.geminiStream, { contents: [S.user('What is the capital of France?')] }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: sse([]) }),
        v2: function (r) { return S.check(r.response && !r.response.fault, 'V2 refused the unseen reply'); },
        v3: function (r) { return S.check(r.response && !!r.response.fault, 'the unseen reply was let through'); }
    },
    {
        finding: 'A18', title: 'An MCP event-stream reply is withheld, even when a runtime shows its body (notification first)',
        setup: Object.assign(S.mcp('tools/call', { name: 'card_lookup_notify', arguments: { customer: 'Lauda' } }, 4), {
            legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: sse(['event: message\ndata: {"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"working"}}\n\n',
                           'event: message\ndata: {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"Card on file for Lauda: ' + C + '"}]}}\n\n']) }),
        v2: function (r) { return S.check(r.response && !r.response.fault && !S.has(r.response, C), 'V2 scanned the result or refused'); },
        v3: function (r) {
            if (!r.response || !r.response.fault) { return 'the event-stream reply was not withheld'; }
            var b = JSON.parse(r.response.body); return S.check(b.error && b.error.code === -32001 && b.id === 4, 'withheld without -32001 and the request id');
        }
    },
    {
        finding: 'A08', title: 'Streamed Responses API tool-call arguments are read (a runtime that shows the stream)',
        setup: Object.assign(S.responses([{ role: 'user', content: 'Look up my card.' }], { stream: true }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: sse(['event: response.function_call_arguments.delta\ndata: {"type":"response.function_call_arguments.delta","delta":"{\\"card\\": \\"' + C + '\\"}"}\n\n',
                           'event: response.completed\ndata: {"type":"response.completed","response":{"status":"completed"}}\n\n']) }),
        v2: function (r) { return S.check(r.response && !S.has(r.response, C), 'V2 read the streamed arguments'); },
        v3: function (r) { return S.check(r.response && (S.has(r.response, C) || !!r.response.fault), 'the streamed arguments were neither read nor refused'); }
    },
    {
        finding: 'A09', title: 'An event whose JSON spans two data: lines is read whole (a runtime that shows the stream)',
        setup: Object.assign(S.chat([{ role: 'user', content: 'Hello' }], { stream: true }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: sse(['data: {"choices":[{"index":0,"delta":\ndata: {"content":"Card on file: ' + C + '"}}]}\n\n', 'data: [DONE]\n\n']) }),
        v2: function (r) { return S.check(r.response && !S.has(r.response, C), 'V2 read the split event'); },
        v3: function (r) { return S.check(r.response && (S.has(r.response, C) || !!r.response.fault), 'the split event was neither read nor refused'); }
    },
    {
        finding: 'A30', title: 'A block for a streaming Gemini client (alt=sse) comes back as an event stream',
        setup: Object.assign(S.req(S.P.geminiStream, { contents: [S.user('My card number is ' + C + '.')] }, null, 'alt=sse'), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked') }),
        v2: function (r) { return S.check(r.request.blocked && /application\/json/.test(r.request.contentType || ''), 'V2 did not answer one JSON object'); },
        v3: function (r) { return S.check(r.request.blocked && /text\/event-stream/.test(r.request.contentType || '') && /^data: /m.test(r.request.body), 'the block is not an event stream'); }
    },
    {
        finding: 'A30', title: 'A block for a streaming Responses API client comes back as Responses events',
        setup: Object.assign(S.responses([{ role: 'user', content: 'My card number is ' + C + '.' }], { stream: true }), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked') }),
        v2: function (r) { return S.check(r.request.blocked && /chat\.completion\.chunk/.test(r.request.body), 'V2 did not answer Chat Completions chunks'); },
        v3: function (r) { return S.check(r.request.blocked && /"type":"response\./.test(r.request.body) && !/chat\.completion\.chunk/.test(r.request.body), 'the block is not in Responses events'); }
    },
    {
        finding: 'A16', title: 'An unreadable Prisma AIRS answer on the reply leg is a scanner failure, not the prompt\'s verdict',
        setup: Object.assign(S.gemini([S.user('What is the capital of France?')]), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', R.status(200, '<html>maintenance</html>')),
            response: S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: 'Paris.' }] } }] }) }),
        v2: function (r) { return S.check(r.response && !r.response.fault && r.response.outcome === 'allow', 'V2 did not allow the reply on the prompt\'s verdict'); },
        v3: function (r) { return S.check(r.response && !!r.response.fault, 'the reply passed on an unreadable verdict'); }
    },
    {
        // Phase 3 decided the LLM half: Gemini, Claude on Vertex and the OpenAI-compatible endpoint answer an error with the
        // platform's own message, never model text (measured live, VERIFICATION.md), and MuleSoft passes them too (run.py:480). The
        // MCP half is scanned (68-p2-non2xx.js). V2 never scans either.
        finding: 'A31', title: 'An LLM reply outside 2xx passes unscanned, logged: no provider puts model text into an error reply (decided in phase 3)',
        setup: Object.assign(S.gemini([S.user('What is the capital of France?')]), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: { status: 500, headers: { 'Content-Type': 'application/json' }, content: JSON.stringify({ error: { message: 'Card on file: ' + C } }) } }),
        v2: function (r) { return S.check(r.response && r.response.calls.length === 0, 'V2 scanned the non-2xx reply'); },
        v3: function (r) {
            var x = r.response, n = x && x.flow ? String(x.flow.get('airs3.logNote') || '') : '';
            return S.check(x && !x.fault && x.calls.length === 0 && x.status === 500 && n === 'a non-2xx reply is not scanned', 'not passed unscanned with its note');
        }
    }
];

'use strict';
/*
 * MuleSoft's reply-leg tests (core/tests/response_extract.rs), ported to v3: which text of a
 * reply, JSON or event stream, reaches the scan, and what v3 does with a reply it can't read.
 *   - Each case runs both legs. The prompt is a harmless question (recorded allow); the reply leg's scan gets the
 *     recorded benign allow, so these cases check coverage, not a verdict. The reply text is read from the `response`
 *     member of the scan's one contents entry; the prompt rides along in the same entry as context.
 *   - Event-stream cases give the reply a text/event-stream body, as a runtime that shows streams would (this one
 *     doesn't: L1). Their request asks for no stream, so v3 has no stream to turn off and none to restore.
 *   - Recorded LLM replies are MuleSoft's (core/tests/fixtures/response/), trimmed (shorter ids, fewer filter and usage
 *     fields); their text, their event order and the way they split it are unchanged.
 *   - sse_event_names_and_lone_cr: only its lone-CR half is observable here. v3's readers go by each event's own data
 *     `type`, so an event name changes nothing a case can see.
 *   - Where v3 decides otherwise (body order, a single "\n" between pieces, per-field masking, deltas scanned next to
 *     response.completed), the case states v3's rule and its title says so.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const M = 'AIRSV3-MARKER';
const Q = 'What is the weather in Paris?';

/* ---- setups ---------------------------------------------------------------------------------------------------- */
const REQ = {
    chat: function (q) { return S.chat([{ role: 'user', content: q || Q }]); },
    anthropic: function (q) { return S.anthropic([{ role: 'user', content: q || Q }]); },
    responses: function (q) { return S.responses(q || Q); },
    gemini: function (q) { return S.gemini([S.user(q || Q)]); }
};
// Both legs: the prompt passes on the recorded benign allow, then the reply leg reads `response`.
function exchange(fmt, response, extra) {
    return Object.assign(REQ[fmt](), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: response }, extra || {});
}
function json(body) { return S.reply(body); }
function sse(events) { return { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: Array.isArray(events) ? events.join('') : events }; }
// One event-stream event; `eol` is the line ending ("\n", "\r\n" or a lone "\r").
function ev(event, data, eol) { eol = eol || '\n'; return (event ? 'event: ' + event + eol : '') + 'data: ' + (typeof data === 'string' ? data : JSON.stringify(data)) + eol + eol; }

/* ---- what a case looks at -------------------------------------------------------------------------------------- */
// The reply as the reply leg sent it to Prisma AIRS: the `response` member of its one contents entry.
function replyText(r) {
    var x = r.response, s = x && x.scans && x.scans[0], e = s && s.contents && s.contents[0];
    return e && typeof e.response === 'string' ? e.response : null;
}
function why(r) {
    var x = r.response;
    if (!x) { return ' (the reply leg did not run: the request leg ended with ' + (r.request.fault ? r.request.fault.policy : 'no fault') + ')'; }
    var f = x.flow;
    return ' (route=' + f.get('airs3.route') + ' outcome=' + f.get('airs3.outcome') + ' refuse=' + f.get('airs3.refuse') + ' note=' + f.get('airs3.logNote') +
           ' calls=' + x.calls.length + ' fault=' + (x.fault ? x.fault.policy : '-') + ')';
}
function header(x, name) { var m = x && x.flow.messages.response; return m ? m.header(name) : null; }
function same(r, want) {
    var t = replyText(r);
    return S.check(t === want && !r.response.fault, 'the reply scan was ' + JSON.stringify(t) + ', not ' + JSON.stringify(want) + why(r));
}
function holds(r, list) {
    var t = replyText(r);
    for (var i = 0; i < list.length; i++) {
        if (t === null || t.indexOf(list[i]) < 0) { return 'the reply scan ' + JSON.stringify(t === null ? t : t.slice(0, 300)) + ' lacks ' + JSON.stringify(list[i]) + why(r); }
    }
    return S.check(!r.response.fault, 'the reply was refused after its scan' + why(r));
}
// An empty reply passes, logged, with no scan.
function passedEmpty(r) {
    var x = r.response;
    return S.check(x && !x.fault && x.calls.length === 0 && x.flow.get('airs3.route') === 'pass', 'the empty reply did not pass unscanned' + why(r));
}
// A reply v3 can't read is withheld (onScanError=block): HTTP 200 in the client's format, x-airs-kind refused, no scan.
function withheld(r) {
    var x = r.response;
    return S.check(x && x.blocked && header(x, 'x-airs-kind') === 'refused' && x.calls.length === 0 && x.status === 200,
                   'the unreadable reply was not withheld as refused' + why(r));
}
function segments(r) { return JSON.parse(r.response.flow.get('airs3.segments') || '{}'); }

/* ---- recorded replies (MuleSoft's core/tests/fixtures/response/, trimmed) -------------------------------------- */
// anthropic/tool.sse: the arguments arrive as input_json_delta fragments, the first one empty.
const ANTHROPIC_TOOL_SSE = [
    ev('message_start', { type: 'message_start', message: { model: 'anthropic.claude-haiku-4-5-20251001-v1:0', id: 'msg_bdrk_01', type: 'message', role: 'assistant', content: [],
                                                             stop_reason: null, stop_sequence: null, usage: { input_tokens: 664, output_tokens: 16 } } }),
    ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'toolu_bdrk_01', name: 'get_weather', input: {} } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '' } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"city"' } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: ': "Pari' } }),
    ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: 's"}' } }),
    ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
    ev('message_delta', { type: 'message_delta', delta: { stop_reason: 'tool_use', stop_sequence: null }, usage: { output_tokens: 33 } }),
    ev('message_stop', { type: 'message_stop' })
];
// anthropic/thinking.json: the thinking block comes first in the body, then the text.
const THINKING = '17 times 23:\n17 × 23 = 17 × (20 + 3) = 17 × 20 + 17 × 3 = 340 + 51 = 391';
const ANTHROPIC_THINKING = { model: 'anthropic.claude-haiku-4-5-20251001-v1:0', id: 'msg_bdrk_02', type: 'message', role: 'assistant',
                             content: [{ type: 'thinking', thinking: THINKING, signature: 'ErMCCoQBCBMQARgCKkA6J3Oeye9GBywJ' }, { type: 'text', text: '391' }],
                             stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 51, output_tokens: 64 } };
// openai/n2.json (Azure): two choices, both "Blue".
const FILTERS = { hate: { filtered: false, severity: 'safe' }, self_harm: { filtered: false, severity: 'safe' }, sexual: { filtered: false, severity: 'safe' }, violence: { filtered: false, severity: 'safe' } };
const OPENAI_N2 = { id: 'chatcmpl-Eh9m', object: 'chat.completion', created: 1793954399, model: 'gpt-6-luna-2026-09-22',
                    choices: [0, 1].map(function (i) { return { content_filter_results: FILTERS, finish_reason: 'stop', index: i, logprobs: null,
                                                                message: { annotations: [], content: 'Blue', refusal: null, role: 'assistant' } }; }),
                    prompt_filter_results: [{ prompt_index: 0, content_filter_results: FILTERS }], usage: { completion_tokens: 46, prompt_tokens: 13, total_tokens: 59 } };
// openai/tool.sse and openai/plain.sse (Azure): the first event is the prompt-filter event, with empty choices.
const AZURE_FIRST = { choices: [], created: 0, id: '', model: '', object: '', prompt_filter_results: [{ prompt_index: 0, content_filter_results: FILTERS }] };
function chunk(choice) { return { choices: [choice], created: 1793954502, id: 'chatcmpl-Eh9ny', model: 'gpt-6-luna-2026-09-22', object: 'chat.completion.chunk' }; }
function argsDelta(a) { return ev('', chunk({ content_filter_results: {}, delta: { tool_calls: [{ function: { arguments: a }, index: 0 }] }, finish_reason: null, index: 0, logprobs: null })); }
const OPENAI_TOOL_SSE = [
    ev('', AZURE_FIRST),
    ev('', chunk({ content_filter_results: {}, delta: { content: null, refusal: null, role: 'assistant',
                                                          tool_calls: [{ function: { arguments: '', name: 'get_weather' }, id: 'call_6j5R5tUK', index: 0, type: 'function' }] },
                   finish_reason: null, index: 0, logprobs: null })),
    argsDelta('{"'), argsDelta('city'), argsDelta('":"'), argsDelta('Paris'), argsDelta('"}'),
    ev('', chunk({ content_filter_results: {}, delta: {}, finish_reason: 'tool_calls', index: 0, logprobs: null })),
    'data: [DONE]\n\n'
];
const OPENAI_PLAIN_SSE = [
    ev('', AZURE_FIRST),
    ev('', chunk({ content_filter_results: {}, delta: { content: '', refusal: null, role: 'assistant' }, finish_reason: null, index: 0, logprobs: null })),
    ev('', chunk({ content_filter_results: {}, delta: { content: 'ready' }, finish_reason: null, index: 0, logprobs: null })),
    ev('', chunk({ content_filter_results: {}, delta: {}, finish_reason: 'stop', index: 0, logprobs: null })),
    'data: [DONE]\n\n'
];
// responses/tool.sse and responses/plain.sse: every event the recording has, in its order.
function resp(status, output) { return { id: 'resp_07c89ccc', object: 'response', created_at: 1793954504, status: status, model: 'gpt-6-luna', output: output }; }
function rev(type, obj) { obj.type = type; return ev(type, obj); }
const FC_ITEM = { id: 'fc_07c8', type: 'function_call', status: 'completed', arguments: '{"city":"Paris"}', call_id: 'call_lzVL', name: 'get_weather' };
const RESPONSES_TOOL_SSE = [
    rev('response.created', { response: resp('in_progress', []), sequence_number: 0 }),
    rev('response.in_progress', { response: resp('in_progress', []), sequence_number: 1 }),
    rev('response.output_item.added', { item: { id: 'fc_07c8', type: 'function_call', status: 'in_progress', arguments: '', call_id: 'call_lzVL', name: 'get_weather' },
                                        output_index: 0, sequence_number: 2 }),
    rev('response.function_call_arguments.delta', { delta: '{"', item_id: 'fc_07c8', output_index: 0, sequence_number: 3 }),
    rev('response.function_call_arguments.delta', { delta: 'city', item_id: 'fc_07c8', output_index: 0, sequence_number: 4 }),
    rev('response.function_call_arguments.delta', { delta: '":"', item_id: 'fc_07c8', output_index: 0, sequence_number: 5 }),
    rev('response.function_call_arguments.delta', { delta: 'Paris', item_id: 'fc_07c8', output_index: 0, sequence_number: 6 }),
    rev('response.function_call_arguments.delta', { delta: '"}', item_id: 'fc_07c8', output_index: 0, sequence_number: 7 }),
    rev('response.function_call_arguments.done', { arguments: '{"city":"Paris"}', item_id: 'fc_07c8', output_index: 0, sequence_number: 8 }),
    rev('response.output_item.done', { item: FC_ITEM, output_index: 0, sequence_number: 9 }),
    rev('response.completed', { response: resp('completed', [FC_ITEM]), sequence_number: 10 })
];
const MSG_ITEM = { id: 'msg_0c3b', type: 'message', status: 'completed', content: [{ type: 'output_text', annotations: [], logprobs: [], text: 'ready' }], phase: 'final_answer', role: 'assistant' };
const RESPONSES_PLAIN_SSE = [
    rev('response.created', { response: resp('in_progress', []), sequence_number: 0 }),
    rev('response.in_progress', { response: resp('in_progress', []), sequence_number: 1 }),
    rev('response.output_item.added', { item: { id: 'msg_0c3b', type: 'message', status: 'in_progress', content: [], phase: 'final_answer', role: 'assistant' }, output_index: 0, sequence_number: 2 }),
    rev('response.content_part.added', { content_index: 0, item_id: 'msg_0c3b', output_index: 0, part: { type: 'output_text', annotations: [], logprobs: [], text: '' }, sequence_number: 3 }),
    rev('response.output_text.delta', { content_index: 0, delta: 'ready', item_id: 'msg_0c3b', logprobs: [], output_index: 0, sequence_number: 4 }),
    rev('response.output_text.done', { content_index: 0, item_id: 'msg_0c3b', logprobs: [], output_index: 0, sequence_number: 5, text: 'ready' }),
    rev('response.content_part.done', { content_index: 0, item_id: 'msg_0c3b', output_index: 0, part: MSG_ITEM.content[0], sequence_number: 6 }),
    rev('response.output_item.done', { item: MSG_ITEM, output_index: 0, sequence_number: 7 }),
    rev('response.completed', { response: resp('completed', [MSG_ITEM]), sequence_number: 8 })
];
// The MuleSoft test drops the response.completed event from each recording.
function withoutCompleted(events) { return events.filter(function (e) { return e.indexOf('response.completed') < 0; }); }
// gemini/tool.sse: Gemini's own spacing and CRLF line endings; the functionCall part carries a thoughtSignature.
const GEMINI_TOOL_SSE =
    'data: {"candidates": [{"content": {"parts": [{"functionCall": {"name": "get_weather","args": {"city": "Paris"},"id": "call_1335"},' +
    '"thoughtSignature": "EpADCo0DAWkUfRMUPNFCS9Qoz"}],"role": "model"},"index": 0}],"usageMetadata": {"promptTokenCount": 54,"candidatesTokenCount": 16,' +
    '"totalTokenCount": 132,"thoughtsTokenCount": 62},"modelVersion": "gemini-3.6-flash","responseId": "eZLtasfhN7rmjMcP0JOt8QQ"}\r\n\r\n' +
    'data: {"candidates": [{"content": {"parts": [{"text": ""}],"role": "model"},"finishReason": "STOP","index": 0}],"usageMetadata": {"promptTokenCount": 54,' +
    '"candidatesTokenCount": 16,"totalTokenCount": 132,"thoughtsTokenCount": 62},"modelVersion": "gemini-3.6-flash","responseId": "eZLtasfhN7rmjMcP0JOt8QQ"}\r\n\r\n';

/* ---- Gemini speech: headerless PCM, as MuleSoft's tests/common pcm() makes it (a 440 Hz tone, 24 kHz, 16-bit LE) - */
function pcm(samples) {
    var b = Buffer.alloc(samples * 2);
    for (var i = 0; i < samples; i++) { b.writeInt16LE(Math.trunc(Math.sin(i * 440 * 2 * Math.PI / 24000) * 8000), i * 2); }
    return b;
}
function speechPart(samples) { return { inlineData: { mimeType: 'audio/L16;codec=pcm;rate=24000', data: pcm(samples).toString('base64') } }; }
const SPEECH = speechPart(48000);                                  // two seconds: 96,000 bytes, 128,000 base64 characters
const SPEECH_CHUNK = speechPart(12000);

module.exports = [
    /* ---- recorded replies, JSON and event stream --------------------------------------------------------------- */
    {
        finding: 'MS-sse-anthropic-tool', title: 'Anthropic stream (recorded): the input_json_delta fragments rebuild the tool call\'s name and arguments',
        setup: exchange('anthropic', sse(ANTHROPIC_TOOL_SSE)),
        v3: function (r) {
            var t = replyText(r) || '', args = t.replace(/^tool get_weather: /, '');
            var parsed; try { parsed = JSON.parse(args); } catch (e) { parsed = null; }
            return S.check(t.indexOf('tool get_weather: ') === 0 && parsed && parsed.city === 'Paris' && Object.keys(parsed).length === 1 && !r.response.fault,
                           'the rebuilt tool call was ' + JSON.stringify(t) + why(r));
        }
    },
    {
        finding: 'MS-json-anthropic-thinking', title: 'Anthropic reply with thinking (recorded): the thinking and the text are both scanned (v3: in body order, one "\\n" between)',
        setup: exchange('anthropic', json(ANTHROPIC_THINKING)),
        v3: function (r) { return same(r, THINKING + '\n391'); }
    },
    {
        finding: 'MS-json-openai-n2', title: 'Chat Completions reply with n=2 (recorded): two texts; v3 keeps each choice as its own maskable field',
        setup: exchange('chat', json(OPENAI_N2)),
        v3: function (r) {
            var ok = same(r, 'Blue\nBlue');
            if (ok !== true) { return ok; }
            var s = segments(r), map = s.map || [];
            return S.check(map.length === 2 && map[0].maskable && map[1].maskable && !s.cut && map[1].start === 5 &&
                           JSON.stringify(map[1].at) === JSON.stringify(['choices', 1, 'message', 'content']), 'the write-back map is ' + JSON.stringify(s));
        }
    },
    {
        finding: 'MS-sse-openai-tool', title: 'Chat Completions stream (recorded, Azure): the argument fragments of a streamed tool call are joined',
        setup: exchange('chat', sse(OPENAI_TOOL_SSE)),
        v3: function (r) { return same(r, 'tool get_weather: {"city":"Paris"}'); }
    },
    {
        finding: 'MS-sse-responses-tool', title: 'Responses stream (recorded): the function_call is rebuilt, name and arguments',
        setup: exchange('responses', sse(RESPONSES_TOOL_SSE)),
        v3: function (r) { return holds(r, ['tool get_weather: {"city":"Paris"}']); }
    },
    {
        finding: 'MS-sse-gemini-tool', title: 'Gemini stream (recorded, CRLF line endings): the functionCall is read',
        setup: exchange('gemini', sse(GEMINI_TOOL_SSE)),
        v3: function (r) { return same(r, 'tool get_weather: {"city":"Paris"}'); }
    },

    /* ---- event-stream edge cases ---------------------------------------------------------------------------------- */
    {
        finding: 'MS-sse-azure-empty-first', title: 'Chat Completions stream (recorded, Azure): a first event with empty choices does not empty the reply',
        setup: exchange('chat', sse(OPENAI_PLAIN_SSE)),
        v3: function (r) { return same(r, 'ready'); }
    },
    {
        finding: 'MS-sse-keepalive-crlf', title: 'Event stream: comment lines, CRLF, "data:" with no space, and one event split over two data: lines',
        setup: exchange('chat', sse(': keep-alive\r\n\r\ndata:{"choices":[{"index":0,"delta":{"content":"hel"}}]}\r\n\r\n: ping\r\n' +
                                    'data: {"choices":[{"index":0,\r\ndata: "delta":{"content":"lo"}}]}\r\n\r\ndata: [DONE]\r\n\r\n')),
        // A09: V2 drops the event split over two data: lines.
        v2: function (r) { return S.check(r.response && S.has(r.response, 'hel') && !S.has(r.response, 'hello'), 'V2 read the event split over two data: lines'); },
        v3: function (r) { return same(r, 'hello'); }
    },
    {
        finding: 'MS-sse-lone-cr', title: 'Event stream with lone CR line endings and event: lines: every event is read',
        setup: exchange('anthropic', sse([
            ev('message_start', { type: 'message_start', message: { content: [] } }, '\r'),
            ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }, '\r'),
            ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Lone CR line endings: ' + M } }, '\r')])),
        v3: function (r) { return same(r, 'Lone CR line endings: ' + M); }
    },
    {
        finding: 'MS-sse-unterminated-last', title: 'Event stream (Gemini): a last event with no blank line after it is still scanned',
        setup: exchange('gemini', sse('data: {"candidates":[{"content":{"parts":[{"text":"tail"}]}}]}')),
        v3: function (r) { return same(r, 'tail'); }
    },
    {
        finding: 'MS-sse-anthropic-error', title: 'Anthropic stream: a ping is skipped, and the text that arrived before an error event is scanned',
        setup: exchange('anthropic', sse([
            ev('message_start', { type: 'message_start', message: { content: [] } }),
            ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }),
            ev('ping', { type: 'ping' }),
            ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: M + ' half' } }),
            ev('error', { type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } })])),
        v3: function (r) { return same(r, M + ' half'); }
    },
    {
        finding: 'MS-sse-garbage', title: 'Event stream with one event that is not JSON: unreadable, so withheld, never treated as empty',
        setup: exchange('chat', sse('data: {"choices":[]}\n\ndata: not json\n\n')),
        v3: function (r) { return withheld(r); }
    },
    {
        finding: 'MS-sse-partial-tool-json', title: 'Anthropic stream: tool-call JSON cut short is scanned as the raw string',
        setup: exchange('anthropic', sse([
            ev('', { type: 'message_start', message: { content: [] } }),
            ev('', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'lookup', input: {} } }),
            ev('', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"note": "' + M + ', cut sh' } })])),
        v3: function (r) { return same(r, 'tool lookup: {"note": "' + M + ', cut sh'); }
    },

    /* ---- what a reply must not hide ------------------------------------------------------------------------------- */
    {
        finding: 'MS-tool-only-openai', title: 'Chat Completions reply that is only a tool call: not empty; its name and arguments are scanned',
        setup: exchange('chat', json({ choices: [{ index: 0, message: { role: 'assistant', content: null,
            tool_calls: [{ id: 'c1', type: 'function', 'function': { name: 'send_email', arguments: '{"to":"x@example.com"}' } }] } }] })),
        v3: function (r) { return same(r, 'tool send_email: {"to":"x@example.com"}'); }
    },
    {
        finding: 'MS-tool-only-anthropic', title: 'Anthropic reply that is only a tool_use: not empty; its name and input are scanned',
        setup: exchange('anthropic', json({ content: [{ type: 'tool_use', id: 't', name: 'send_email', input: { to: 'x@example.com' } }] })),
        v3: function (r) { return same(r, 'tool send_email: {"to":"x@example.com"}'); }
    },
    {
        finding: 'MS-n2-both-choices', title: 'Chat Completions reply with n=2: both choices are scanned',
        setup: exchange('chat', json({ choices: [{ index: 0, message: { content: 'fine' } }, { index: 1, message: { content: M } }] })),
        // A06: V2 scans only the last choice.
        v2: function (r) { return S.check(r.response && r.response.calls.length === 1 && S.has(r.response, M) && !S.has(r.response, 'fine'), 'V2 did not scan the last choice alone'); },
        v3: function (r) { return same(r, 'fine\n' + M); }
    },
    {
        finding: 'MS-n2-streamed', title: 'Chat Completions stream with n=2: every choice index is rebuilt, its fragments joined',
        setup: exchange('chat', sse([
            ev('', { choices: [{ index: 0, delta: { content: 'fine' } }, { index: 1, delta: { content: 'AIRSV3-' } }] }),
            ev('', { choices: [{ index: 1, delta: { content: 'MARKER' } }] }),
            'data: [DONE]\n\n'])),
        v3: function (r) { return same(r, 'fine\n' + M); }
    },
    {
        finding: 'MS-gemini-fc-thought', title: 'Gemini reply: a thought part is scanned, and so are a functionCall\'s name and args (v3: in body order)',
        setup: exchange('gemini', json({ candidates: [{ index: 0, content: { role: 'model', parts: [
            { text: 'thinking about it', thought: true }, { functionCall: { name: 'lookup', args: { q: M } } }, { text: 'done' }] } }] })),
        v3: function (r) { return same(r, 'thinking about it\ntool lookup: {"q":"' + M + '"}\ndone'); }
    },
    {
        finding: 'MS-gemini-two-candidates', title: 'Gemini reply with two candidates: each candidate is its own text',
        setup: exchange('gemini', json({ candidates: [{ index: 0, content: { parts: [{ text: 'a' }] } }, { index: 1, content: { parts: [{ text: 'b' }] } }] })),
        v3: function (r) { return same(r, 'a\nb'); }
    },
    {
        finding: 'MS-responses-completed', title: 'Responses stream: response.completed\'s output is scanned (v3, stricter: the deltas a client renders are scanned too)',
        setup: exchange('responses', sse([
            ev('response.output_text.delta', { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: 'partial' }),
            ev('response.completed', { type: 'response.completed', response: { output: [{ type: 'message', role: 'assistant',
                                                                                         content: [{ type: 'output_text', text: 'the final text' }] }] } })])),
        v3: function (r) { return holds(r, ['the final text', 'partial']); }
    },
    {
        finding: 'MS-responses-rebuilt-text', title: 'Responses stream without response.completed (recorded, the event removed): the text is rebuilt',
        setup: exchange('responses', sse(withoutCompleted(RESPONSES_PLAIN_SSE))),
        v3: function (r) { return holds(r, ['ready']); }
    },
    {
        finding: 'MS-responses-rebuilt-tool', title: 'Responses stream without response.completed (recorded, the event removed): the tool call is rebuilt, its name too',
        setup: exchange('responses', sse(withoutCompleted(RESPONSES_TOOL_SSE))),
        v3: function (r) { return holds(r, ['get_weather', '{"city":"Paris"}']); }
    },
    {
        finding: 'MS-anthropic-unknown-block', title: 'Anthropic reply with a server tool result block: scanned as its JSON, not dropped',
        setup: exchange('anthropic', json({ content: [{ type: 'web_search_tool_result', content: [{ type: 'web_search_result', title: M }] }] })),
        v3: function (r) { return holds(r, ['web_search_tool_result', M]); }
    },

    /* ---- empty and unreadable ------------------------------------------------------------------------------------- */
    {
        finding: 'MS-empty-reply', title: 'Chat Completions reply whose text is empty: empty, so it passes with no scan',
        setup: exchange('chat', json({ choices: [{ message: { content: '' } }] })),
        v3: function (r) { return passedEmpty(r); }
    },
    {
        finding: 'MS-empty-stream', title: 'Chat Completions stream of only a filter event and [DONE]: empty, so it passes with no scan',
        setup: exchange('chat', sse('data: {"choices":[],"prompt_filter_results":[]}\n\ndata: [DONE]\n\n')),
        v3: function (r) { return passedEmpty(r); }
    },
    {
        finding: 'MS-no-container-openai', title: 'Chat Completions reply with no choices list: unreadable, so withheld',
        setup: exchange('chat', json({ id: 'x' })),
        v3: function (r) { return withheld(r); }
    },
    {
        finding: 'MS-no-container-anthropic', title: 'Anthropic reply with no content list: unreadable, so withheld',
        setup: exchange('anthropic', json({ id: 'x' })),
        v3: function (r) { return withheld(r); }
    },
    {
        finding: 'MS-no-container-responses', title: 'Responses reply with no output list: unreadable, so withheld',
        setup: exchange('responses', json({ id: 'x' })),
        v3: function (r) { return withheld(r); }
    },
    {
        finding: 'MS-no-container-gemini', title: 'Gemini reply with neither candidates nor promptFeedback: unreadable, so withheld',
        setup: exchange('gemini', json({ id: 'x' })),
        v3: function (r) { return withheld(r); }
    },
    {
        finding: 'MS-no-container-gemini', title: 'Gemini reply that is a JSON string, not an object: unreadable, so withheld',
        setup: exchange('gemini', json('"x"')),
        v3: function (r) { return withheld(r); }
    },
    {
        finding: 'MS-gemini-prompt-blocked', title: 'Gemini reply with promptFeedback and no candidates (a blocked prompt): empty, so it passes with no scan',
        setup: exchange('gemini', json({ promptFeedback: { blockReason: 'SAFETY' } })),
        v3: function (r) { return passedEmpty(r); }
    },
    {
        finding: 'MS-trunc-chars', title: 'A reply over maxScanChars with truncationFailClosed=false: its first characters are scanned, counted as characters, and nothing is maskable',
        setup: Object.assign(REQ.chat('Hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
                                                  vars: { maxScanChars: '10', truncationFailClosed: 'false' },
                                                  response: json({ choices: [{ message: { content: new Array(31).join('é') } }] }) }),
        v3: function (r) {
            var ok = same(r, new Array(11).join('é'));
            if (ok !== true) { return ok; }
            var s = segments(r);
            return S.check(s.cut === true && (s.map || []).length === 0 && s.length === 10, 'the cut reply kept a write-back map: ' + JSON.stringify(s));
        }
    },
    {
        finding: 'MS-trunc-chars', title: 'A reply over maxScanChars, truncationFailClosed at its default (true): withheld without a scan',
        setup: Object.assign(REQ.chat('Hello'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
                                                  vars: { maxScanChars: '10' },
                                                  response: json({ choices: [{ message: { content: new Array(31).join('é') } }] }) }),
        v3: function (r) { return withheld(r); }
    },
    {
        finding: 'MS-trunc-slot', title: 'A cut reply has no slot: a DLP-only block (applyDlpMasking=true) whose masked copy lines up still blocks',
        setup: Object.assign(REQ.chat('Which card is on file?'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
                                                                   vars: { maxScanChars: '40', truncationFailClosed: 'false', applyDlpMasking: 'true' },
                                                                   response: json({ choices: [{ index: 0, message: { role: 'assistant', content: 'The card on file is ' + C + '. Thanks.' } }] }) }),
        v3: function (r) {
            var x = r.response;
            if (replyText(r) !== 'The card on file is ' + C + '.') { return 'the reply scan was ' + JSON.stringify(replyText(r)) + why(r); }
            return S.check(x.blocked && header(x, 'x-airs-kind') === 'block' && x.body.indexOf(C) < 0 && x.flow.get('airs3.masked') !== 'true',
                           'the cut reply was masked or let through' + why(r));
        }
    },
    {
        finding: 'MS-trunc-slot', title: 'Control: the same reply at exactly maxScanChars is not cut, so the same verdict masks it in place',
        setup: Object.assign(REQ.chat('Which card is on file?'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
                                                                   vars: { maxScanChars: '40', truncationFailClosed: 'false', applyDlpMasking: 'true' },
                                                                   response: json({ choices: [{ index: 0, message: { role: 'assistant', content: 'The card on file is ' + C + '.' } }] }) }),
        v3: function (r) {
            var x = r.response;
            if (!x || x.fault) { return 'the reply was refused' + why(r); }
            var out = JSON.parse(x.flow.messages.response.content);
            return S.check(out.choices[0].message.content === 'The card on file is XXXXXXXXXXXXXXXXXXX.' && x.flow.get('airs3.masked') === 'true',
                           'the reply was not masked in place: ' + JSON.stringify(out.choices[0].message.content) + why(r));
        }
    },

    /* ---- Gemini parts and candidate metadata ---------------------------------------------------------------------- */
    {
        finding: 'MS-gemini-parts-metadata', title: 'Gemini reply of an inline image and sources: the image\'s MIME type and the grounding, citation and URL-context sources are scanned',
        setup: exchange('gemini', json({ candidates: [{ index: 0, content: { role: 'model', parts: [{ inlineData: { mimeType: 'image/png', data: 'iVBORw0KGgo' } }] },
            groundingMetadata: { groundingChunks: [{ web: { uri: 'https://' + M + '.example/a', title: 't' } }] },
            citationMetadata: { citationSources: [{ uri: 'https://cite.example/b' }] },
            urlContextMetadata: { urlMetadata: [{ retrievedUrl: 'https://ctx.example/c' }] } }] })),
        // A10: V2 doesn't read Gemini's reply sources.
        v2: function (r) { return S.check(r.response && !S.has(r.response, M) && !S.has(r.response, 'cite.example'), 'V2 scanned the reply sources'); },
        v3: function (r) { return holds(r, [M, 'cite.example', 'ctx.example', 'image/png']); }
    },
    {
        finding: 'MS-gemini-grounding-links', title: 'Gemini reply with grounding: the text, the chunk URI and the links in searchEntryPoint.renderedContent are scanned',
        setup: exchange('gemini', json({ candidates: [{ index: 0, content: { role: 'model', parts: [{ text: 'See the source.' }] },
            groundingMetadata: { groundingChunks: [{ web: { uri: 'https://' + M + '.example/a' } }],
                                 searchEntryPoint: { renderedContent: '<a href="https://' + M + '.example/b">x</a>' } } }] })),
        // A10: V2 scans the text, not the grounding.
        v2: function (r) { return S.check(r.response && S.has(r.response, 'See the source.') && !S.has(r.response, M), 'V2 scanned the grounding, or not the text'); },
        v3: function (r) { return holds(r, ['See the source.', 'https://' + M + '.example/a', 'https://' + M + '.example/b']); }
    },
    {
        finding: 'MS-gemini-stream-metadata', title: 'Gemini stream (CRLF): grounding that arrives in a later event survives the rebuild, and the text is joined across events',
        setup: exchange('gemini', sse(
            'data: {"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Hello"}]}}]}\r\n\r\n' +
            'data: {"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":" world"}]},' +
            '"groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://' + M + '.example/a"}}]}}]}\r\n\r\n')),
        // A10: V2 scans the streamed text, not the grounding.
        v2: function (r) { return S.check(r.response && S.has(r.response, 'Hello world') && !S.has(r.response, M), 'V2 scanned the streamed grounding, or not the text'); },
        v3: function (r) { return holds(r, ['Hello world', 'https://' + M + '.example/a']); }
    },
    {
        finding: 'MS-gemini-speech', title: 'Gemini speech reply (two seconds of headerless PCM): scanned without its bytes, so it fits the default limit',
        setup: exchange('gemini', json({ candidates: [{ index: 0, content: { role: 'model', parts: [SPEECH] } }] })),
        v3: function (r) {
            var t = replyText(r);
            if (t === null) { return 'the speech reply was not scanned' + why(r); }
            return S.check(!r.response.fault && t.indexOf('audio/L16') >= 0 && t.indexOf('<binary, ') >= 0 && t.indexOf(SPEECH.inlineData.data.slice(0, 48)) < 0 && t.length < 1000,
                           'the speech bytes reached the scan (' + t.length + ' characters)' + why(r));
        }
    },
    {
        finding: 'MS-gemini-speech-stream', title: 'Gemini speech stream (four chunks, CRLF): each chunk\'s bytes are left out',
        setup: exchange('gemini', sse([0, 1, 2, 3].map(function () { return 'data: ' + JSON.stringify({ candidates: [{ index: 0, content: { role: 'model', parts: [SPEECH_CHUNK] } }] }) + '\r\n\r\n'; }))),
        v3: function (r) {
            var t = replyText(r);
            if (t === null) { return 'the speech stream was not scanned' + why(r); }
            var n = t.split('<binary, ').length - 1;
            return S.check(!r.response.fault && t.indexOf('audio/L16') >= 0 && n === 4 && t.indexOf(SPEECH_CHUNK.inlineData.data.slice(0, 48)) < 0 && t.length < 2000,
                           'the speech chunks reached the scan (' + t.length + ' characters, ' + n + ' placeholders)' + why(r));
        }
    }
];

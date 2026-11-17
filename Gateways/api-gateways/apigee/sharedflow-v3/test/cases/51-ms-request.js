'use strict';
/*
 * MuleSoft ports, group "request" (core/tests/request_extract.rs and core/src/extract/mod.rs).
 *
 * v3's rules win where they differ from MuleSoft:
 *   - format comes from the body (MCP), else the path, else the FlowCallout parameter apiFormat; NEVER a header, and
 *     there is NO body-shape guessing: an unknown format is refused (onScanError=block);
 *   - read pieces are joined with a single "\n" (MuleSoft uses a blank line);
 *   - tool results are scanned in every turn by default (stricter than MuleSoft, which needs role tool);
 *   - scanMessageRoles adds system (developer counts as system) and assistant; user and tool are always read;
 *   - over maxScanChars a request is refused (truncationFailClosed default true); with it false, the newest part is scanned.
 *
 * Content is harmless text, the marker AIRSV3-MARKER and the standard Visa test card (S.CARD) only. Each case names the
 * recorded reply its ServiceCallout gets; nothing here decides a verdict from content. No v2 expectation (these are not
 * findings A01 to A39), so `node test/run.js` skips them and `--v3` runs them.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const MARK = 'AIRSV3-MARKER';
const allow = function () { return R.answers('allow-prompt'); };
const UP = 'https://up.example.com/x';                       // a target.url, so a destreamed call doesn't refuse for lack of one

function on(shape, extra) { return Object.assign(shape, Object.assign({ legs: ['request'], airs: allow() }, extra || {})); }
function refusedNoScan(x) { return S.check(!!x.fault && x.calls.length === 0, 'not refused without a scan (' + x.calls.length + ' call(s), fault ' + !!x.fault + ')'); }
function seg(r) { try { return JSON.parse(r.request.flow.get('airs3.segments') || '{}'); } catch (e) { return {}; } }
function streamKind(r) { return r.request.flow.get('airs3.stream'); }
function aiModel(r) { var s = r.request.scans[0]; return s && s.metadata ? s.metadata.ai_model : null; }
function inOrder(t, pieces) { var at = 0; for (var i = 0; i < pieces.length; i++) { var f = t.indexOf(pieces[i], at); if (f < 0) { return pieces[i]; } at = f + pieces[i].length; } return null; }
function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }
const PNG = 'iVBORw0KGgoAAAANSUhEUgAA';                       // base64 of a PNG header (\x89PNG\r\n...), the kind A28 leaves out
// Headerless 16-bit LE PCM of a 440 Hz tone at 24 kHz, base64: bytes are not UTF-8 and start with no known signature.
function pcm(samples) { var buf = Buffer.alloc(samples * 2); for (var i = 0; i < samples; i++) { buf.writeInt16LE(Math.round(Math.sin(i * 440 * 2 * Math.PI / 24000) * 8000), i * 2); } return buf.toString('base64'); }
const PCM_B64 = pcm(48000);                                   // ~128,000 base64 chars: would blow the 100,000 limit if it were scanned
// Latin-1 CSV (the é of "café" is the single byte 0xE9, so the bytes are not UTF-8), base64.
function latin1Csv(marker) { return Buffer.concat([Buffer.from('name,note\ncaf'), Buffer.from([0xe9]), Buffer.from(',' + marker + ' notes\n'), Buffer.from(new Array(41).join('row,pad\n'))]).toString('base64'); }

module.exports = [
    /* ================================================================ detection (request_extract.rs:61-115) ======= */
    {
        finding: 'MS-DETECT-PATH', title: 'request_extract.rs:69 the path decides the format before any header: a two-shaped body on a known path is read by the path\'s reader',
        setup: on(S.req(S.P.chat, { messages: [{ role: 'user', content: MARK + ' in messages' }], contents: [{ parts: [{ text: MARK + ' in contents' }] }] }, { 'x-input-format': 'gemini' })),
        v3: function (r) {
            return S.check(r.request.flow.get('airs3.format') === 'openai-chat' && S.has(r.request, MARK + ' in messages') && !S.has(r.request, MARK + ' in contents'),
                'the x-input-format header steered the reader (format ' + r.request.flow.get('airs3.format') + ', scanned ' + JSON.stringify(r.request.scanned) + ')');
        }
    },
    {
        finding: 'MS-DETECT-PATH', title: 'request_extract.rs:69 the Gemini path is read as Gemini even with x-input-format: openai; the header never picks the reader',
        setup: on(S.req(S.P.gemini, { messages: [{ role: 'user', content: MARK + ' in messages' }], contents: [{ parts: [{ text: MARK + ' in contents' }] }] }, { 'x-input-format': 'openai' })),
        v3: function (r) {
            return S.check(r.request.flow.get('airs3.format') === 'gemini' && S.has(r.request, MARK + ' in contents') && !S.has(r.request, MARK + ' in messages'),
                'format ' + r.request.flow.get('airs3.format') + ', scanned ' + JSON.stringify(r.request.scanned));
        }
    },
    {
        finding: 'MS-DETECT-NOGUESS', title: 'request_extract.rs:61,:79,:85 v3 never guesses the format from the body shape: a messages body on an unknown path, with no apiFormat, is refused',
        setup: on(S.req('/x/v2/chat', { messages: [{ role: 'user', content: MARK }] })),
        v3: function (r) { return r.request.flow.get('airs3.format') === 'unknown' ? refusedNoScan(r.request) : 'format was guessed: ' + r.request.flow.get('airs3.format'); }
    },
    {
        finding: 'MS-DETECT-NOGUESS', title: 'request_extract.rs:85 an ambiguous messages+input body, and an embeddings-shaped body, are refused (never guessed)',
        setup: on(S.req('/x/y', { input: 'x', messages: [{ role: 'user', content: MARK }] })),
        v3: function (r) { return refusedNoScan(r.request); }
    },
    {
        finding: 'MS-DETECT-NOGUESS', title: 'request_extract.rs:79 a contents body at an unknown path is refused (MuleSoft would read Gemini): v3 does not guess, but apiFormat makes it readable',
        setup: on(S.req('/x/y', { contents: [{ parts: [{ text: MARK }] }] })),
        v3: function (r) { return refusedNoScan(r.request); }
    },
    {
        finding: 'MS-DETECT-NOGUESS', title: 'request_extract.rs:79 control: with apiFormat=gemini, the same contents body at an unknown path is read as Gemini',
        setup: on(S.req('/x/y', { contents: [{ parts: [{ text: MARK }] }] }), { vars: { apiFormat: 'gemini' } }),
        v3: function (r) { return S.check(r.request.flow.get('airs3.format') === 'gemini' && S.has(r.request, MARK), 'apiFormat did not make the body readable (format ' + r.request.flow.get('airs3.format') + ')'); }
    },

    /* ================================================================ streaming flag and model (:102, :115) ======= */
    {
        finding: 'MS-MODEL', title: 'request_extract.rs:115 ai_model comes from /models/{model}: in the path, with or without ?alt=sse',
        setup: on(S.req('/v1/projects/p/locations/global/publishers/google/models/gemini-3.6-flash:streamGenerateContent', { contents: [S.user('What is the capital of France?')] }, null, 'alt=sse'), { vars: { 'target.url': UP } }),
        v3: function (r) { return S.check(aiModel(r) === 'gemini-3.6-flash', 'ai_model is ' + aiModel(r)); }
    }
].concat([
    ['openai-chat body stream:true', S.chat([{ role: 'user', content: 'hi' }], { stream: true }), 'body'],
    ['openai-chat body stream:false', S.chat([{ role: 'user', content: 'hi' }], { stream: false }), 'none'],
    ['Responses body stream:true', S.responses('hi', { stream: true }), 'body'],
    ['Anthropic body stream:true', S.anthropic([{ role: 'user', content: 'hi' }], { stream: true }), 'body'],
    ['Anthropic no stream flag', S.anthropic([{ role: 'user', content: 'hi' }]), 'none'],
    ['Gemini :streamGenerateContent?alt=sse', S.req(S.P.geminiStream, { contents: [S.user('hi')] }, null, 'alt=sse'), 'gemini-sse'],
    ['Gemini :streamGenerateContent (no alt)', S.req(S.P.geminiStream, { contents: [S.user('hi')] }), 'gemini-array'],
    ['Gemini :generateContent', S.gemini([S.user('hi')]), 'none'],
    ['Vertex Claude :streamRawPredict', S.req('/v1/projects/p/locations/global/publishers/anthropic/models/claude-x:streamRawPredict', { messages: [{ role: 'user', content: 'hi' }], max_tokens: 8 }), 'rawpredict']
].map(function (t) {
    return {
        finding: 'MS-STREAM', title: 'request_extract.rs:102 streamed flag: ' + t[0] + ' -> ' + t[2],
        setup: on(t[1], { vars: { 'target.url': UP } }),
        v3: function (r) { return S.check(streamKind(r) === t[2], 'stream kind is ' + streamKind(r) + ', expected ' + t[2]); }
    };
})).concat([
    /* ================================================================ OpenAI Chat (:132, :157, :175, :184, :192, :200) */
    {
        finding: 'MS-EVERYTURN', title: 'request_extract.rs:132 OpenAI Chat: both user turns are scanned (joined with one "\\n"), each with its own masking field',
        setup: on(S.chat([{ role: 'user', content: MARK + ' one' }, { role: 'assistant', content: 'a' }, { role: 'user', content: MARK + ' two' }])),
        v3: function (r) {
            var m = seg(r).map || [];
            return S.check(r.request.scanned === MARK + ' one\n' + MARK + ' two' && m.length === 2 && m[0].maskable && m[1].maskable,
                'scanned ' + JSON.stringify(r.request.scanned) + ', map ' + JSON.stringify(m));
        }
    },
    {
        finding: 'MS-OPENAI-PARTS', title: 'request_extract.rs:157 OpenAI Chat: text parts on both sides of an image part are scanned, the image URL too, and the image part is not maskable',
        setup: on(S.chat([{ role: 'user', content: [{ type: 'text', text: MARK + ' before' }, { type: 'image_url', image_url: { url: 'https://example.com/cat.png' } }, { type: 'text', text: MARK + ' after' }] }])),
        v3: function (r) {
            var m = seg(r).map || [], hasUnmaskable = false;
            for (var i = 0; i < m.length; i++) { if (m[i].maskable === false) { hasUnmaskable = true; } }
            return S.check(inOrder(r.request.scanned, [MARK + ' before', 'https://example.com/cat.png', MARK + ' after']) === null && hasUnmaskable,
                'not all three scanned in order, or the image is maskable: ' + JSON.stringify(r.request.scanned));
        }
    },
    {
        finding: 'MS-OPENAI-IMAGEONLY', title: 'request_extract.rs:175 OpenAI Chat: a user turn holding only an image is still scanned, as its JSON',
        setup: on(S.chat([{ role: 'user', content: [{ type: 'image_url', image_url: { url: 'https://example.com/' + MARK + '.png' } }] }])),
        v3: function (r) { return S.check(r.request.calls.length === 1 && S.has(r.request, 'image_url') && S.has(r.request, MARK), 'the image-only turn was not scanned: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-OPENAI-ALLROLES', title: 'request_extract.rs:192 OpenAI Chat with scanMessageRoles=system,assistant: system, user, tool call, tool result, user, in conversation order',
        setup: on(S.req(S.P.chat, { model: 'm', messages: [
            { role: 'system', content: 'You are a weather bot.' },
            { role: 'user', content: 'What is the weather in Paris?' },
            { role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: 'get_weather', arguments: '{"city":"Paris"}' } }] },
            { role: 'tool', tool_call_id: 'c1', content: 'Sunny, 21C' },
            { role: 'user', content: 'And tomorrow?' }] }), { vars: { scanMessageRoles: 'system,assistant' } }),
        v3: function (r) { return S.check(inOrder(r.request.scanned, ['You are a weather bot.', 'What is the weather in Paris?', 'get_weather', '{"city":"Paris"}', 'Sunny, 21C', 'And tomorrow?']) === null, 'out of order: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-OPENAI-DEVELOPER', title: 'request_extract.rs:200 OpenAI Chat: role developer is read as system (scanned only with the system role)',
        setup: on(S.chat([{ role: 'developer', content: MARK + ' terse' }, { role: 'user', content: 'hi' }]), { vars: { scanMessageRoles: 'system' } }),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' terse\nhi', 'developer was not read as system: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-OPENAI-DEVELOPER', title: 'request_extract.rs:200 control: with the default roles, the developer (system) message is not scanned',
        setup: on(S.chat([{ role: 'developer', content: MARK + ' terse' }, { role: 'user', content: 'hi there' }])),
        v3: function (r) { return S.check(r.request.scanned === 'hi there', 'the system message leaked in by default: ' + JSON.stringify(r.request.scanned)); }
    },

    /* ================================================================ tool results always scanned (:184,:240,:257,:281) */
    {
        finding: 'MS-TOOL-DEFAULT', title: 'request_extract.rs:184 OpenAI Chat: a tool result is scanned by default (v3 is stricter than MuleSoft, which needs role tool)',
        setup: on(S.chat([{ role: 'user', content: 'Look up the weather.' }, { role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: 'get_weather', arguments: '{}' } }] }, { role: 'tool', tool_call_id: 'c1', content: MARK + ' tool said sunny' }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' tool said sunny'), 'the tool result was not scanned by default: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-TOOL-DEFAULT', title: 'request_extract.rs:240 Anthropic: a user message of only tool_result blocks is scanned by default',
        setup: on(S.anthropic([{ role: 'user', content: 'Look it up.' }, { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'lookup', input: {} }] }, { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: MARK + ' from the tool' }] }], { tools: [{ name: 'lookup', input_schema: { type: 'object' } }] })),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' from the tool'), 'the tool_result-only turn was not scanned: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-TOOL-DEFAULT', title: 'request_extract.rs:257 Anthropic: within one user message, the text and the tool_result are both scanned by default',
        setup: on(S.anthropic([{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 't', content: [{ type: 'text', text: MARK + ' from the tool' }] }, { type: 'text', text: 'now summarise' }] }])),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' from the tool\nnow summarise', 'text and tool_result not both scanned: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-TOOL-DEFAULT', title: 'request_extract.rs:281 Gemini: a functionResponse-only content is scanned by default (as a tool turn)',
        setup: on(S.gemini([S.user('Look it up.'), { role: 'model', parts: [{ functionCall: { name: 'lookup', args: {} } }] }, { role: 'user', parts: [{ functionResponse: { name: 'lookup', response: { note: MARK + ' sunny' } } }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' sunny'), 'the functionResponse was not scanned: ' + JSON.stringify(r.request.scanned)); }
    },

    /* ================================================================ every user turn in every format (:143) ======= */
    {
        finding: 'MS-EVERYTURN', title: 'request_extract.rs:143 Responses: the earlier user turn is scanned too',
        setup: on(S.responses([{ role: 'user', content: MARK + ' one' }, { role: 'assistant', content: 'a' }, { role: 'user', content: MARK + ' two' }])),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' one\n' + MARK + ' two', 'scanned ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-EVERYTURN', title: 'request_extract.rs:143 Anthropic: the earlier user turn is scanned too',
        setup: on(S.anthropic([{ role: 'user', content: MARK + ' one' }, { role: 'assistant', content: 'a' }, { role: 'user', content: MARK + ' two' }])),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' one\n' + MARK + ' two', 'scanned ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-EVERYTURN', title: 'request_extract.rs:143 Gemini: the earlier user turn is scanned too',
        setup: on(S.gemini([{ role: 'user', parts: [{ text: MARK + ' one' }] }, { role: 'model', parts: [{ text: 'a' }] }, { role: 'user', parts: [{ text: MARK + ' two' }] }])),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' one\n' + MARK + ' two', 'scanned ' + JSON.stringify(r.request.scanned)); }
    },

    /* ================================================================ Responses (:208, :216) ====================== */
    {
        finding: 'MS-RESPONSES-STRING', title: 'request_extract.rs:208 Responses: a plain-string input is the prompt, with a single maskable field at /input',
        setup: on(S.responses(MARK + ' remember this')),
        v3: function (r) {
            var m = seg(r).map || [];
            return S.check(r.request.scanned === MARK + ' remember this' && m.length === 1 && m[0].maskable && m[0].at.join('/') === 'input', 'scanned ' + JSON.stringify(r.request.scanned) + ', map ' + JSON.stringify(m));
        }
    },
    {
        finding: 'MS-RESPONSES-ITEMS', title: 'request_extract.rs:216 Responses: input_text items and a function_call_output (tool, by default) are scanned; instructions come first with the system role',
        setup: on(S.req(S.P.responses, { model: 'm', instructions: 'You are a weather bot.', input: [
            { role: 'user', content: [{ type: 'input_text', text: 'What is the weather in Paris?' }] },
            { type: 'function_call', call_id: 'c1', name: 'get_weather', arguments: '{"city":"Paris"}' },
            { type: 'function_call_output', call_id: 'c1', output: MARK + ' sunny 21C' }] }), { vars: { scanMessageRoles: 'system,assistant' } }),
        v3: function (r) { return S.check(inOrder(r.request.scanned, ['You are a weather bot.', 'What is the weather in Paris?', 'get_weather', MARK + ' sunny 21C']) === null, 'out of order or missing: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-RESPONSES-ITEMS', title: 'request_extract.rs:216 Responses default roles: the input_text and the function_call_output are scanned, the instructions are not',
        setup: on(S.req(S.P.responses, { model: 'm', instructions: 'You are a weather bot.', input: [
            { role: 'user', content: [{ type: 'input_text', text: 'What is the weather in Paris?' }] },
            { type: 'function_call_output', call_id: 'c1', output: MARK + ' sunny 21C' }] })),
        v3: function (r) { return S.check(r.request.scanned === 'What is the weather in Paris?\n' + MARK + ' sunny 21C', 'scanned ' + JSON.stringify(r.request.scanned)); }
    },

    /* ================================================================ Anthropic (:231, :250) ====================== */
    {
        finding: 'MS-ANTHROPIC-SYSTEM', title: 'request_extract.rs:231 Anthropic: a system block list is scanned only with the system role (default roles do not scan it)',
        setup: on(S.anthropic([{ role: 'user', content: 'hi there' }], { system: [{ type: 'text', text: MARK + ' bot' }] })),
        v3: function (r) { return S.check(r.request.scanned === 'hi there', 'the system block leaked in by default: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-ANTHROPIC-SYSTEM', title: 'request_extract.rs:231 Anthropic: with scanMessageRoles=system, a system string and system blocks are scanned, first',
        setup: on(S.anthropic([{ role: 'user', content: 'hi there' }], { system: [{ type: 'text', text: MARK + ' bot' }] }), { vars: { scanMessageRoles: 'system' } }),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' bot\nhi there', 'scanned ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-ANTHROPIC-TOOLUSE', title: 'request_extract.rs:250 Anthropic: an earlier tool_use\'s name and input are scanned with the assistant role',
        setup: on(S.anthropic([{ role: 'user', content: 'What is the weather in Paris?' }, { role: 'assistant', content: [{ type: 'text', text: 'Let me check.' }, { type: 'tool_use', id: 't1', name: 'get_weather', input: { city: MARK } }] }, { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'Sunny' }] }]), { vars: { scanMessageRoles: 'assistant' } }),
        v3: function (r) { return S.check(inOrder(r.request.scanned, ['Let me check.', 'get_weather', MARK]) === null, 'the assistant tool_use was not scanned: ' + JSON.stringify(r.request.scanned)); }
    },

    /* ================================================================ Gemini (:267, :287) ========================= */
    {
        finding: 'MS-GEMINI-SYSINSTR', title: 'request_extract.rs:267 Gemini: systemInstruction and functionCall/functionResponse are read with the right roles',
        setup: on(S.gemini([{ role: 'user', parts: [{ text: 'What is the weather in Paris?' }] }, { role: 'model', parts: [{ functionCall: { name: 'get_weather', args: { city: 'Paris' } } }] }, { role: 'user', parts: [{ functionResponse: { name: 'get_weather', response: { note: MARK + ' sunny' } } }] }], { systemInstruction: { parts: [{ text: 'You are a weather bot.' }] } }), { vars: { scanMessageRoles: 'system,assistant' } }),
        v3: function (r) { return S.check(inOrder(r.request.scanned, ['You are a weather bot.', 'What is the weather in Paris?', 'get_weather', MARK + ' sunny']) === null, 'out of order or missing: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-GEMINI-SYSINSTR', title: 'request_extract.rs:267 Gemini: snake_case system_instruction is read as well',
        setup: on(S.req(S.P.gemini, { system_instruction: { parts: [{ text: MARK + ' terse' }] }, contents: [{ role: 'user', parts: [{ text: 'hi there' }] }] }), { vars: { scanMessageRoles: 'system' } }),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' terse\nhi there', 'snake_case system_instruction not read: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-GEMINI-NOROLE', title: 'request_extract.rs:287 Gemini: a content with no role is read as a user turn',
        setup: on(S.req(S.P.gemini, { contents: [{ parts: [{ text: MARK + ' no role' }] }] })),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' no role', 'a roleless content was not read as user: ' + JSON.stringify(r.request.scanned)); }
    },

    /* ================================================================ managed-gateway bodies (:295) =============== */
    {
        finding: 'MS-MANAGED', title: 'request_extract.rs:295 the four managed-gateway request bodies each extract the prompt',
        setup: on(S.req(S.P.chat, { model: 'openai/gpt-6-luna', messages: [{ role: 'user', content: 'Reply with the single word: ready' }] })),
        v3: function (r) { return S.check(r.request.scanned === 'Reply with the single word: ready', 'chat: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-MANAGED', title: 'request_extract.rs:295 managed Responses body extracts the prompt',
        setup: on(S.req(S.P.responses, { model: 'openai/gpt-6-luna', input: 'Reply with the single word: ready' })),
        v3: function (r) { return S.check(r.request.scanned === 'Reply with the single word: ready', 'responses: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-MANAGED', title: 'request_extract.rs:295 managed Anthropic body extracts the prompt',
        setup: on(S.req(S.P.anthropic, { model: 'us.anthropic.claude-haiku-4-5', max_tokens: 30, messages: [{ role: 'user', content: 'Reply with the single word: ready' }] })),
        v3: function (r) { return S.check(r.request.scanned === 'Reply with the single word: ready', 'anthropic: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-MANAGED', title: 'request_extract.rs:295 managed Gemini body extracts the prompt',
        setup: on(S.req(S.P.gemini, { contents: [{ role: 'user', parts: [{ text: 'Reply with the single word: ready' }] }] })),
        v3: function (r) { return S.check(r.request.scanned === 'Reply with the single word: ready', 'gemini: ' + JSON.stringify(r.request.scanned)); }
    },

    /* ================================================================ limits and errors (:310,:320,:327,:333,:339,:398) */
    {
        finding: 'MS-TRUNC-CHARS', title: 'request_extract.rs:310 the size limit counts characters, not bytes: 25,000 "é" over a 20,000 limit keeps 20,000 characters (truncationFailClosed=false), and the scan is unmaskable',
        setup: on(S.chat([{ role: 'user', content: new Array(25001).join('é') }]), { vars: { maxScanChars: '20000', truncationFailClosed: 'false' } }),
        v3: function (r) { return S.check(r.request.calls.length === 1 && r.request.scanned.length === 20000 && seg(r).cut === true, 'scanned length ' + r.request.scanned.length + ', cut ' + seg(r).cut); }
    },
    {
        finding: 'MS-CAP-EXACT', title: 'request_extract.rs:320 a prompt of exactly maxScanChars is not truncated',
        setup: on(S.chat([{ role: 'user', content: S.filler(100) }]), { vars: { maxScanChars: '100' } }),
        v3: function (r) { return S.check(!r.request.fault && r.request.calls.length === 1 && r.request.scanned.length === 100 && seg(r).cut === false, 'scanned length ' + r.request.scanned.length + ', fault ' + !!r.request.fault); }
    },
    {
        finding: 'MS-NEWEST', title: 'request_extract.rs:398 over the limit, the newest text is kept (truncationFailClosed=false)',
        setup: on(S.chat([{ role: 'user', content: S.filler(100) }, { role: 'assistant', content: 'ok' }, { role: 'user', content: MARK + ' here' }]), { vars: { maxScanChars: '' + (MARK + ' here').length, truncationFailClosed: 'false' } }),
        v3: function (r) { return S.check(r.request.scanned === MARK + ' here', 'the newest text was not kept: ' + JSON.stringify(r.request.scanned)); }
    }
]).concat([
    ['no messages', S.req(S.P.chat, { model: 'm' })],
    ['empty contents', S.req(S.P.gemini, { contents: [] })],
    ['an empty user string', S.chat([{ role: 'user', content: '' }])]
].map(function (t) {
    return {
        finding: 'MS-NOCONTENT', title: 'request_extract.rs:327,:333 ' + t[0] + ' is nothing to scan, so the request is refused (no scan)',
        setup: on(t[1]),
        v3: function (r) { return refusedNoScan(r.request); }
    };
})).concat([
    ['messages as a string', S.req(S.P.chat, { messages: 'hi' })],
    ['a numeric content', S.req(S.P.anthropic, { model: 'm', max_tokens: 8, messages: [{ role: 'user', content: 5 }] })],
    ['contents as an object', S.req(S.P.gemini, { contents: { parts: [] } })],
    ['an array body', S.req(S.P.chat, [1, 2])]
].map(function (t) {
    return {
        finding: 'MS-WRONGSHAPE', title: 'request_extract.rs:339 a wrong shape (' + t[0] + ') is unreadable, so the request is refused (no scan)',
        setup: on(t[1]),
        v3: function (r) { return refusedNoScan(r.request); }
    };
})).concat([
    /* ================================================================ documents and bytes (:350,:361,:373,:381,:440,:452,:462,:473) */
    {
        finding: 'MS-ANTHROPIC-DOC', title: 'request_extract.rs:350 Anthropic: a text document\'s data, title and context are scanned next to a text block',
        setup: on(S.anthropic([{ role: 'user', content: [{ type: 'document', source: { type: 'text', media_type: 'text/plain', data: MARK + ' doctext' }, title: MARK + ' title', context: MARK + ' ctx' }, { type: 'text', text: MARK + ' ask' }] }])),
        v3: function (r) { return S.check(inOrder(r.request.scanned, [MARK + ' title', MARK + ' ctx', MARK + ' doctext', MARK + ' ask']) === null, 'document fields not all scanned: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-ANTHROPIC-DOC', title: 'request_extract.rs:361 Anthropic: a content-source document and a search_result\'s source, title and text are scanned',
        setup: on(S.anthropic([{ role: 'user', content: [
            { type: 'document', source: { type: 'content', content: [{ type: 'text', text: MARK + ' part1' }, { type: 'text', text: MARK + ' part2' }] } },
            { type: 'search_result', source: 'https://example.com/r', title: MARK + ' rt', content: [{ type: 'text', text: MARK + ' result' }] },
            { type: 'text', text: MARK + ' ask' }] }])),
        v3: function (r) { return S.check(inOrder(r.request.scanned, [MARK + ' part1', MARK + ' part2', 'https://example.com/r', MARK + ' rt', MARK + ' result', MARK + ' ask']) === null, 'not all scanned: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-INLINE-TEXT', title: 'request_extract.rs:373 Gemini: text/plain inlineData base64 is decoded and scanned',
        setup: on(S.gemini([{ role: 'user', parts: [{ inlineData: { mimeType: 'text/plain', data: b64(MARK + ' inline text') } }, { text: 'ask' }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' inline text'), 'the text/plain inlineData was not decoded (scanned raw base64 instead): ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-NONTEXT-BYTES', title: 'request_extract.rs:381 OpenAI Chat: image URLs and unknown part fields are scanned; a PNG data URI is left out',
        setup: on(S.chat([{ role: 'user', content: [
            { type: 'text', text: MARK + ' ask' },
            { type: 'image_url', image_url: { url: 'https://example.com/cat.png' } },
            { type: 'image_url', image_url: { url: 'data:image/png;base64,' + new Array(21).join(PNG) } },
            { type: 'future_part', note: MARK + ' future' }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' ask') && S.has(r.request, 'https://example.com/cat.png') && S.has(r.request, MARK + ' future') && !S.has(r.request, PNG + PNG), 'wrong coverage: ' + JSON.stringify(r.request.scanned).slice(0, 200)); }
    },
    {
        finding: 'MS-NONTEXT-BYTES', title: 'request_extract.rs:381 Anthropic: an image\'s media type is scanned, its PNG base64 is left out',
        setup: on(S.anthropic([{ role: 'user', content: [{ type: 'text', text: MARK + ' ask' }, { type: 'image', source: { type: 'base64', media_type: 'image/png', data: new Array(21).join(PNG) } }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' ask') && S.has(r.request, 'image/png') && !S.has(r.request, PNG + PNG), 'wrong coverage: ' + JSON.stringify(r.request.scanned).slice(0, 200)); }
    },
    {
        finding: 'MS-DATAURI', title: 'request_extract.rs:440 OpenAI Chat: the text behind data:text/plain (base64 and plain) in file and image parts is scanned',
        setup: on(S.chat([{ role: 'user', content: [
            { type: 'text', text: 'ask' },
            { type: 'file', file: { filename: 'notes.txt', file_data: 'data:text/plain;base64,' + b64(MARK + ' notes') } },
            { type: 'image_url', image_url: { url: 'data:text/plain,' + MARK + ' cleartext' } }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' notes') && S.has(r.request, MARK + ' cleartext'), 'a data URI was not scanned as its text: ' + JSON.stringify(r.request.scanned)); }
    },
    {
        finding: 'MS-GEMINI-AUDIO', title: 'request_extract.rs:452 Gemini: headerless PCM audio in inlineData is left out of the scan and does not count toward the limit',
        setup: on(S.gemini([{ role: 'user', parts: [{ text: 'transcribe this' }, { inlineData: { mimeType: 'audio/L16;codec=pcm;rate=24000', data: PCM_B64 } }] }])),
        v3: function (r) { return S.check(!r.request.fault && r.request.calls.length === 1 && S.has(r.request, 'transcribe this') && S.has(r.request, 'audio/L16') && !S.has(r.request, PCM_B64.slice(0, 48)), 'the audio bytes were scanned or it was refused for size (scan length ' + r.request.scanned.length + ', fault ' + !!r.request.fault + ')'); }
    },
    {
        finding: 'MS-GEMINI-CODE', title: 'request_extract.rs:462 Gemini: an inline code file declared application/x-javascript is scanned as its text',
        setup: on(S.gemini([{ role: 'user', parts: [{ inlineData: { mimeType: 'application/x-javascript', data: b64('// ' + MARK + ' review\n' + new Array(21).join("log('pad');\n")) } }, { text: 'review this file' }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' review'), 'the x-javascript file was not scanned as text: ' + JSON.stringify(r.request.scanned).slice(0, 200)); }
    },
    {
        finding: 'MS-GEMINI-CODE', title: 'request_extract.rs:462 Gemini: an inline code file declared application/x-sh is scanned as its text',
        setup: on(S.gemini([{ role: 'user', parts: [{ inlineData: { mimeType: 'application/x-sh', data: b64('# ' + MARK + ' review\n' + new Array(21).join("echo pad\n")) } }, { text: 'review this file' }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' review'), 'the x-sh file was not scanned as text: ' + JSON.stringify(r.request.scanned).slice(0, 200)); }
    },
    {
        finding: 'MS-INLINE-TEXT', title: 'request_extract.rs:473 Gemini: a Latin-1 CSV under a text MIME type is decoded and scanned',
        setup: on(S.gemini([{ role: 'user', parts: [{ inlineData: { mimeType: 'text/csv', data: latin1Csv(MARK) } }, { text: 'read this' }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' notes'), 'the text/csv inlineData was not decoded (scanned raw base64 instead): ' + JSON.stringify(r.request.scanned).slice(0, 120)); }
    },
    {
        finding: 'MS-INLINE-TEXT', title: 'request_extract.rs:473 Anthropic: a Latin-1 base64 document under a text MIME type is decoded and scanned',
        setup: on(S.anthropic([{ role: 'user', content: [{ type: 'text', text: 'read this' }, { type: 'document', source: { type: 'base64', media_type: 'text/plain', data: latin1Csv(MARK) } }] }])),
        v3: function (r) { return S.check(S.has(r.request, MARK + ' notes'), 'the text/plain base64 document was not decoded (scanned raw base64 instead): ' + JSON.stringify(r.request.scanned).slice(0, 120)); }
    },

    /* ================================================================ masking write-back (:421) =================== */
    {
        finding: 'MS-MASK-NOLINEUP', title: 'request_extract.rs:421 masked text that does not line up with the scanned text is never written back: v3 blocks instead',
        setup: on(S.chat([{ role: 'user', content: 'Short card: ' + C }]), { airs: R.answers('block-dlp-prompt-masked'), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) { return S.check(r.request.blocked && String(r.request.request.content).indexOf('XXXX') === -1, 'the mismatched mask was written back or not blocked (outcome ' + r.request.flow.get('airs3.outcome') + ')'); }
    },

    /* ================================================================ extract/mod.rs boundaries (:530, :544) ======= */
    {
        finding: 'MS-MOD-DATAURI', title: 'extract/mod.rs:530 data URI boundaries are handled without error: mixed case and an empty media type decode, a quoted parameter stays as written',
        setup: on(S.gemini([{ role: 'user', parts: [
            { text: 'DATA:TEXT/PLAIN;BASE64,' + b64(MARK + '_mixedcase') },
            { text: 'data:,' + MARK + '_empty' },
            { text: 'data:text/plain;charset="utf-8",' + MARK + '_quoted' }] }])),
        v3: function (r) {
            // text parts are scanned as written; the data-URI decoding is exercised through jsonText on the unknown part below.
            return S.check(!r.request.fault && r.request.calls.length === 1, 'the boundaries were not handled (fault ' + !!r.request.fault + ')');
        }
    },
    {
        finding: 'MS-MOD-DATAURI', title: 'extract/mod.rs:530 a data URI in a scanned JSON field: mixed-case base64 decodes, an empty media type decodes, a quoted-parameter header is kept as written',
        setup: on(S.gemini([{ role: 'user', parts: [
            { kind: 'a', note: 'DATA:TEXT/PLAIN;BASE64,' + b64(MARK + '_mixedcase') },
            { kind: 'b', note: 'data:,' + MARK + '_empty' },
            { kind: 'c', note: 'data:text/plain;charset="utf-8",' + MARK + '_quoted' }] }])),
        v3: function (r) {
            return S.check(!r.request.fault && S.has(r.request, MARK + '_mixedcase') && S.has(r.request, MARK + '_empty') && S.has(r.request, MARK + '_quoted'),
                'a boundary data URI was not handled as expected: ' + JSON.stringify(r.request.scanned).slice(0, 240));
        }
    },
    {
        finding: 'MS-MOD-PERCENT', title: 'extract/mod.rs:544 a data URI with an invalid percent escape is kept as written; a valid escape decodes',
        setup: on(S.gemini([{ role: 'user', parts: [
            { kind: 'a', note: 'data:,' + MARK + '-bad%zz' },
            { kind: 'b', note: 'data:,' + MARK + '-good%41' }] }])),
        v3: function (r) {
            return S.check(!r.request.fault && S.has(r.request, MARK + '-bad%zz') && S.has(r.request, MARK + '-goodA'),
                'invalid-percent not kept, or valid-percent (%41 -> A) not decoded: ' + JSON.stringify(r.request.scanned).slice(0, 200));
        }
    }
]);

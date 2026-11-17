'use strict';
/*
 * A coverage review of v3's phase 1, before release. For each format and both legs: is every field a client or a model
 * can put text in collected under v3's defaults (user turns and tool results always; system and assistant only with
 * scanMessageRoles; tool definitions not read), do the bytes rule and the size limit hold, and can format detection
 * hand a body to a reader that skips a field?
 *   - GATE-COV-NN: a gap the review found, fixed since. The title names the gap; the case passes when v3 behaves as
 *     required.
 *   - GATE-COV-GNN: a guard, which passed then too. It keeps a field the readers do collect from being lost.
 * Content is harmless only: the marker AIRSV3-MARKER, the standard Visa test card number, plain sentences.
 * Each case names the recorded reply its ServiceCallout gets; nothing here decides a verdict from content.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const M = 'AIRSV3-MARKER';
const MC = M + ' card on file ' + C;                      // the text a field carries in each coverage case

function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }
function get(path, headers) { return { path: path, request: { verb: 'GET', headers: Object.assign({ Accept: 'application/json' }, headers || {}), content: '', querystring: '' } }; }
function sse(events) { return { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: events.join('') }; }
function ev(event, data) { return 'event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n'; }

/* ---- what a case looks at ---------------------------------------------------------------------------------------- */
function state(x) {
    if (!x) { return '(the leg did not run)'; }
    var f = x.flow;
    return '(route=' + f.get('airs3.route') + ' format=' + f.get('airs3.format') + ' outcome=' + f.get('airs3.outcome') + ' refuse=' + f.get('airs3.refuse') +
           ' note=' + f.get('airs3.logNote') + ' calls=' + x.calls.length + ' fault=' + (x.fault ? x.fault.policy : '-') + ')';
}
// The reply leg's own text, as sent to Prisma AIRS: the entry's response, or a tool event's output.
function replyScan(r) {
    var x = r.response, s = x && x.scans && x.scans[0], e = s && s.contents && s.contents[0];
    if (!e) { return null; }
    // An LLM reply goes as the response (its prompt is context); MCP reply text goes as a prompt with no response part.
    var text = typeof e.response === 'string' ? e.response : (typeof e.prompt === 'string' ? e.prompt : '');
    return [text, e.tool_event && e.tool_event.output ? String(e.tool_event.output) : ''].join('\n');
}
// Request leg: the field's text reached the scan, or v3 refused the request before the model.
function requestCovers(r, text) {
    var q = r.request;
    if (S.has(q, text)) { return true; }
    if (q.blocked && q.calls.length === 0) { return true; }
    return 'not collected: ' + JSON.stringify(text) + ' is not in the request scan ' + JSON.stringify(q.scanned.slice(0, 160)) + ' ' + state(q);
}
// Reply leg: the field's text reached the reply scan, or v3 withheld the reply without a scan (content it can't read).
function replyCovers(r, text) {
    var x = r.response;
    if (!x) { return 'the reply leg did not run ' + state(r.request); }
    var t = replyScan(r);
    if (t !== null && t.indexOf(text) !== -1) { return true; }
    if (x.blocked && x.calls.length === 0) { return true; }
    return 'not collected: ' + JSON.stringify(text) + ' is not in the reply scan ' + JSON.stringify(t === null ? t : t.slice(0, 160)) +
           (x.calls.length === 0 && !x.fault ? '; the reply reached the client with no scan at all ' : ' ') + state(x);
}
// Both legs: a harmless prompt on the recorded benign allow, then the reply leg on the recorded benign reply allow.
function exchange(base, response, extra) {
    return Object.assign(base, { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: response }, extra || {});
}
function requestOnly(base, extra) { return Object.assign(base, { legs: ['request'], airs: R.answers('allow-prompt') }, extra || {}); }
const ASK = 'When does the bakery on the corner open?';

/* ---- replies, in each provider's current shape (trimmed) --------------------------------------------------------- */
function chatReply(message, extra) {
    return S.reply(Object.assign({ id: 'chatcmpl-91a', object: 'chat.completion', created: 1794272592, model: 'gpt-lab',
        choices: [{ index: 0, message: Object.assign({ role: 'assistant', content: null, refusal: null, annotations: [] }, message), logprobs: null, finish_reason: 'stop' }],
        usage: { prompt_tokens: 12, completion_tokens: 9, total_tokens: 21 } }, extra || {}));
}
function responsesReply(output, extra) {
    return S.reply(Object.assign({ id: 'resp_91a', object: 'response', created_at: 1794272592, status: 'completed', model: 'gpt-lab', output: output,
        usage: { input_tokens: 12, output_tokens: 9, total_tokens: 21 } }, extra || {}));
}
function anthropicReply(content) {
    return S.reply({ id: 'msg_91a', type: 'message', role: 'assistant', model: 'claude-lab', content: content, stop_reason: 'end_turn', stop_sequence: null,
                     usage: { input_tokens: 12, output_tokens: 9 } });
}
const WEB_FETCH = { type: 'web_fetch_tool_result', tool_use_id: 'srvtoolu_91a',
    content: { type: 'web_fetch_result', url: 'https://bakery.example/hours', retrieved_at: '2026-11-10T08:00:00Z',
               content: { type: 'document', title: 'Opening hours', citations: { enabled: true }, source: { type: 'text', media_type: 'text/plain', data: MC } } } };
const FETCH_USE = { type: 'server_tool_use', id: 'srvtoolu_91a', name: 'web_fetch', input: { url: 'https://bakery.example/hours' } };

/* ---- a WAV header whose bytes are not UTF-8: bytes the bytes rule must leave out -------------------------------- */
const WAV = (function () {
    var head = Buffer.from([0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0, 0, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6d, 0x74, 0x20, 0x10, 0, 0, 0, 1, 0, 1, 0,
                            0x40, 0x1f, 0, 0, 0x80, 0x3e, 0, 0, 2, 0, 0x10, 0, 0x64, 0x61, 0x74, 0x61, 0, 0x08, 0, 0]);
    var body = Buffer.alloc(240, 0x80);
    return Buffer.concat([head, body]).toString('base64');
})();

module.exports = [
    /* ================================================================ findings: gaps the review found, fixed since === */

    /* ---- format detection: a reply read by no reader --------------------------------------------------------------- */
    {
        finding: 'GATE-COV-01', title: 'Responses background mode: the stored output fetched by GET /v1/responses/{id} is not collected (reply passes unscanned)',
        setup: Object.assign(get('/v1/responses/resp_91a'), { legs: ['request', 'response'], airs: R.answers('allow-prompt-response'),
            response: responsesReply([{ type: 'message', id: 'msg_91a', status: 'completed', role: 'assistant',
                                        content: [{ type: 'output_text', annotations: [], text: MC }] }], { background: true }) }),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-02', title: 'MCP-format reply leg: the model reply to a Chat Completions body that adds jsonrpc and method is not collected',
        setup: exchange(S.req(S.P.chat, { model: 'gpt-lab', messages: [{ role: 'user', content: ASK }], jsonrpc: '2.0', id: 1, method: 'chat' }),
                        chatReply({ content: MC })),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-03', title: 'A proxy that runs v3 only on its response leg: the reply of an endpoint v3 does not read (/v1/completions) passes unscanned',
        setup: Object.assign(S.req('/v1/completions', { model: 'gpt-lab', prompt: ASK, max_tokens: 64 }),
            { legs: ['response'], airs: R.answers('allow-prompt-response'),
              response: S.reply({ id: 'cmpl-91a', object: 'text_completion', created: 1794272592, model: 'gpt-lab',
                                  choices: [{ index: 0, text: MC, logprobs: null, finish_reason: 'stop' }] }) }),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-04', title: 'Path match: a path that only contains "count-tokens" (/v1/count-tokens/../chat/completions) passes as a count-tokens call, unscanned',
        setup: requestOnly(S.req('/v1/count-tokens/../chat/completions', { model: 'gpt-lab', messages: [{ role: 'user', content: MC }] })),
        v3: function (r) { return requestCovers(r, MC); }
    },

    /* ---- OpenAI Chat Completions --------------------------------------------------------------------------------- */
    {
        finding: 'GATE-COV-05', title: 'Chat reply: choices[].message.tool_calls[].custom.input (a custom tool call) is not collected',
        setup: exchange(S.chat([{ role: 'user', content: ASK }]),
                        chatReply({ tool_calls: [{ id: 'call_91a', type: 'custom', custom: { name: 'notes', input: MC } }] })),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-06', title: 'Chat reply: choices[].message.audio.transcript is not collected',
        setup: exchange(S.chat([{ role: 'user', content: ASK }], { modalities: ['text', 'audio'], audio: { voice: 'alloy', format: 'wav' } }),
                        chatReply({ audio: { id: 'audio_91a', expires_at: 1794275592, data: 'UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=', transcript: MC } })),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-07', title: 'Chat request: messages[].name (the participant name the model reads) is not collected',
        setup: requestOnly(S.chat([{ role: 'user', name: M, content: ASK }])),
        v3: function (r) { return requestCovers(r, M); }
    },
    {
        finding: 'GATE-COV-08', title: 'Chat request with scanMessageRoles=user,assistant: an assistant message\'s refusal field is not collected',
        setup: requestOnly(S.chat([{ role: 'user', content: ASK }, { role: 'assistant', content: null, refusal: MC }, { role: 'user', content: 'Thanks.' }]),
                           { vars: { scanMessageRoles: 'user,assistant' } }),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-09', title: 'Chat reply masked by applyDlpMasking: choices[].logprobs tokens are not collected, so the client still gets the unmasked digits',
        setup: Object.assign(S.chat([{ role: 'user', content: 'What is the card on file?' }], { logprobs: true }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'), vars: { applyDlpMasking: 'true' },
            response: S.reply({ id: 'chatcmpl-91b', object: 'chat.completion', created: 1794272592, model: 'gpt-lab',
                choices: [{ index: 0, message: { role: 'assistant', content: 'The card on file is ' + C + '.', refusal: null }, finish_reason: 'stop',
                            logprobs: { content: ['The', ' card', ' on', ' file', ' is', ' 4111', ' 1111', ' 1111', ' 1111', '.'].map(function (t) {
                                return { token: t, logprob: -0.01, bytes: Array.from(Buffer.from(t, 'utf8')), top_logprobs: [] }; }), refusal: null } }] }) }),
        v3: function (r) {
            var x = r.response;
            if (!x) { return 'the reply leg did not run ' + state(r.request); }
            if (x.blocked) { return true; }
            return S.check(x.body.indexOf('4111') === -1, 'the masked reply still carries the card digits in logprobs: ' + x.body.slice(x.body.indexOf('logprobs'), x.body.indexOf('logprobs') + 120) + ' ' + state(x));
        }
    },

    /* ---- OpenAI Responses ---------------------------------------------------------------------------------------- */
    {
        finding: 'GATE-COV-10', title: 'Responses request: prompt.variables (a reusable prompt\'s values) are not collected',
        setup: requestOnly(S.responses(ASK, { prompt: { id: 'pmpt_91a', version: '2', variables: { note: MC } } })),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-11', title: 'Responses reply: a reasoning item\'s content[].text (reasoning_text) is not collected',
        setup: exchange(S.responses(ASK), responsesReply([{ type: 'reasoning', id: 'rs_91a', summary: [], content: [{ type: 'reasoning_text', text: MC }] }],
                                                           { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } })),
        v3: function (r) { return replyCovers(r, MC); }
    },

    /* ---- Anthropic Messages (and Claude on Vertex) ----------------------------------------------------------------- */
    {
        finding: 'GATE-COV-12', title: 'Anthropic request: a web_fetch_tool_result in an earlier assistant turn (a tool result) is not collected by default',
        setup: requestOnly(S.anthropic([{ role: 'user', content: ASK }, { role: 'assistant', content: [FETCH_USE, WEB_FETCH, { type: 'text', text: 'It opens at seven.' }] },
                                        { role: 'user', content: 'And on Sundays?' }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-12', title: 'Claude on Vertex rawPredict: a web_search_tool_result title in an earlier assistant turn (a tool result) is not collected by default',
        setup: requestOnly(S.req(S.P.claudeVertex, { anthropic_version: 'vertex-2023-10-16', max_tokens: 1024, messages: [
            { role: 'user', content: ASK },
            { role: 'assistant', content: [{ type: 'server_tool_use', id: 'srvtoolu_91b', name: 'web_search', input: { query: 'bakery opening hours' } },
                                           { type: 'web_search_tool_result', tool_use_id: 'srvtoolu_91b', content: [{ type: 'web_search_result', url: 'https://bakery.example/hours',
                                             title: MC, encrypted_content: 'EqgfCioIARgBIiQ3YTAwMjY1Mi1mZjM5', page_age: 'November 2, 2026' }] },
                                           { type: 'text', text: 'It opens at seven.' }] },
            { role: 'user', content: 'And on Sundays?' }] })),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-12', title: 'Anthropic request: an mcp_tool_result (MCP connector) in an earlier assistant turn is not collected by default',
        setup: requestOnly(S.anthropic([{ role: 'user', content: 'Look up the customer Lauda.' },
            { role: 'assistant', content: [{ type: 'mcp_tool_use', id: 'mcptoolu_91a', name: 'lookup', server_name: 'crm', input: { customer: 'Lauda' } },
                                           { type: 'mcp_tool_result', tool_use_id: 'mcptoolu_91a', is_error: false, content: [{ type: 'text', text: MC }] }] },
            { role: 'user', content: 'Thanks. Anything else?' }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-13', title: 'Anthropic reply: content[].citations[].cited_text is not collected',
        setup: exchange(S.anthropic([{ role: 'user', content: ASK }]), anthropicReply([{ type: 'text', text: 'It opens at seven.',
            citations: [{ type: 'web_search_result_location', url: 'https://bakery.example/hours', title: 'Opening hours', encrypted_index: 'Eo8BCioIAhgB', cited_text: MC }] }])),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-13', title: 'Chat reply: choices[].message.annotations[].url_citation (title and url) is not collected',
        setup: exchange(S.chat([{ role: 'user', content: ASK }], { web_search_options: {} }),
                        chatReply({ content: 'It opens at seven.', annotations: [{ type: 'url_citation', url_citation: { url: 'https://bakery.example/hours', title: MC, start_index: 0, end_index: 18 } }] })),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-13', title: 'Responses reply: an output_text part\'s annotations (url_citation title) are not collected',
        setup: exchange(S.responses(ASK), responsesReply([{ type: 'message', id: 'msg_91b', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: 'It opens at seven.',
            annotations: [{ type: 'url_citation', url: 'https://bakery.example/hours', title: MC, start_index: 0, end_index: 18 }] }] }])),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-14', title: 'Anthropic event-stream reply (a runtime that shows streams): a web_fetch_tool_result block is dropped, though the JSON reader collects it',
        setup: exchange(S.anthropic([{ role: 'user', content: ASK }]), sse([
            ev('message_start', { type: 'message_start', message: { id: 'msg_91b', type: 'message', role: 'assistant', model: 'claude-lab', content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 12, output_tokens: 1 } } }),
            ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'server_tool_use', id: 'srvtoolu_91a', name: 'web_fetch', input: {} } }),
            ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"url": "https://bakery.example/hours"}' } }),
            ev('content_block_stop', { type: 'content_block_stop', index: 0 }),
            ev('content_block_start', { type: 'content_block_start', index: 1, content_block: WEB_FETCH }),
            ev('content_block_stop', { type: 'content_block_stop', index: 1 }),
            ev('content_block_start', { type: 'content_block_start', index: 2, content_block: { type: 'text', text: '' } }),
            ev('content_block_delta', { type: 'content_block_delta', index: 2, delta: { type: 'text_delta', text: 'It opens at seven.' } }),
            ev('content_block_stop', { type: 'content_block_stop', index: 2 }),
            ev('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 9 } }),
            ev('message_stop', { type: 'message_stop' })])),
        v3: function (r) { return replyCovers(r, MC); }
    },

    /* ---- Gemini -------------------------------------------------------------------------------------------------- */
    {
        finding: 'GATE-COV-15', title: 'Gemini request: functionResponse.parts[].inlineData (a multimodal function response, text/plain) is not collected',
        setup: requestOnly(S.gemini([S.user('Fetch the note.'), { role: 'model', parts: [{ functionCall: { name: 'get_note', args: {} } }] },
            { role: 'user', parts: [{ functionResponse: { name: 'get_note', response: { note: { $ref: 'note.txt' } },
                parts: [{ inlineData: { mimeType: 'text/plain', displayName: 'note.txt', data: b64(MC) } }] } }] }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-16', title: 'Gemini request: a user-turn part the caller marks thought:true is not collected by default',
        setup: requestOnly(S.gemini([{ role: 'user', parts: [{ text: ASK }, { text: MC, thought: true }] }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-17', title: 'Gemini request: a part carrying both functionResponse and function_response is read by one name only',
        setup: requestOnly(S.gemini([S.user('Fetch the note.'), { role: 'model', parts: [{ functionCall: { name: 'get_note', args: {} } }] },
            { role: 'user', parts: [{ functionResponse: { name: 'get_note', response: { note: 'ready' } },
                                      function_response: { name: 'get_note', response: { note: MC } } }] }])),
        v3: function (r) { return requestCovers(r, MC); }
    },

    /* ---- MCP ----------------------------------------------------------------------------------------------------- */
    {
        finding: 'GATE-COV-18', title: 'MCP tools/call: a params member other than name, arguments and _meta is not collected (MuleSoft scans it)',
        setup: Object.assign(S.mcp('tools/call', { name: 'lookup', arguments: { customer: 'Lauda' }, note: MC }), { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-19', title: 'MCP tools/call reply: a result whose content is one block, not a list, is not collected',
        setup: Object.assign(S.mcp('tools/call', { name: 'lookup', arguments: { customer: 'Lauda' } }), {
            legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply({ jsonrpc: '2.0', id: 1, result: { content: { type: 'text', text: MC }, isError: false } }) }),
        v3: function (r) { return replyCovers(r, MC); }
    },

    /* ---- adjacent: what a destreamed client gets back ------------------------------------------------------------- */
    {
        finding: 'GATE-COV-20', title: 'Chat stream:true: the one-burst stream v3 sends back drops a custom tool call\'s name and input',
        setup: Object.assign(S.chat([{ role: 'user', content: ASK }], { stream: true }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: chatReply({ content: 'Saving it.', tool_calls: [{ id: 'call_91a', type: 'custom', custom: { name: 'notes', input: M + ' note' } }] }) }),
        v3: function (r) {
            var x = r.response;
            if (!x) { return 'the reply leg did not run ' + state(r.request); }
            return S.check(/event-stream/.test(String(x.contentType)) && x.body.indexOf(M + ' note') !== -1 && x.body.indexOf('"notes"') !== -1,
                           'the client\'s stream lacks the custom tool call\'s name or input: ' + x.body.slice(0, 260) + ' ' + state(x));
        }
    },
    {
        finding: 'GATE-COV-21', title: 'Gemini alt=sse: a reply with nothing to scan (promptFeedback only) goes back as JSON, not as the client\'s event stream',
        setup: Object.assign(S.req(S.P.geminiStream, { contents: [S.user(ASK)] }, {}, 'alt=sse'), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            vars: { 'target.url': 'https://aiplatform.example' + S.P.geminiStream + '?alt=sse' },
            response: S.reply({ promptFeedback: { blockReason: 'OTHER' }, usageMetadata: { promptTokenCount: 7, totalTokenCount: 7 }, modelVersion: 'gemini-x' }) }),
        v3: function (r) {
            var x = r.response;
            if (!x) { return 'the reply leg did not run ' + state(r.request); }
            if (x.blocked) { return true; }
            return S.check(/event-stream/.test(String(x.contentType)) && /^data: /.test(x.body), 'the streaming client got ' + x.contentType + ': ' + x.body.slice(0, 120) + ' ' + state(x));
        }
    },

    /* ================================================================ regression guards ============================ */
    {
        finding: 'GATE-COV-G01', title: 'guard: Responses request: a shell_call_output item\'s stdout is collected as a tool result, by default',
        setup: requestOnly(S.responses([{ role: 'user', content: 'List the files.' }, { type: 'shell_call', call_id: 'sh_91a', action: { commands: ['ls'] }, status: 'completed' },
            { type: 'shell_call_output', call_id: 'sh_91a', output: [{ stdout: MC, stderr: '', outcome: { type: 'exit', exit_code: 0 } }] }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G02', title: 'guard: Responses request: an earlier mcp_call item\'s output is collected, by default',
        setup: requestOnly(S.responses([{ role: 'user', content: 'Look up the customer Lauda.' },
            { type: 'mcp_call', id: 'mcp_91a', server_label: 'crm', name: 'lookup', arguments: '{"customer":"Lauda"}', output: MC, error: null },
            { role: 'user', content: 'Thanks.' }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G03', title: 'guard: Responses request: an input_file whose file_data is a text data URI is decoded and collected',
        setup: requestOnly(S.responses([{ role: 'user', content: [{ type: 'input_text', text: 'Summarise the note.' },
            { type: 'input_file', filename: 'note.txt', file_data: 'data:text/plain;base64,' + b64(MC) }] }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G04', title: 'guard: Responses reply: a custom_tool_call\'s input is collected',
        setup: exchange(S.responses(ASK), responsesReply([{ type: 'custom_tool_call', id: 'ctc_91a', call_id: 'call_91a', name: 'notes', input: MC, status: 'completed' }])),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G05', title: 'guard: Anthropic reply (JSON): a web_fetch_tool_result\'s document text is collected',
        setup: exchange(S.anthropic([{ role: 'user', content: ASK }]), anthropicReply([FETCH_USE, WEB_FETCH, { type: 'text', text: 'It opens at seven.' }])),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G06', title: 'guard: Gemini request: a codeExecutionResult output is collected, by default',
        setup: requestOnly(S.gemini([S.user('Run the sum.'), { role: 'model', parts: [{ executableCode: { language: 'PYTHON', code: 'print(1 + 1)' } }, { codeExecutionResult: { outcome: 'OUTCOME_OK', output: MC } }] },
                                     S.user('Thanks.')])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G07', title: 'guard: Gemini request: a fileData part\'s displayName is collected',
        setup: requestOnly(S.gemini([{ role: 'user', parts: [{ text: 'Summarise the file.' }, { fileData: { mimeType: 'application/pdf', fileUri: 'gs://bakery-lab/hours.pdf', displayName: MC } }] }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G08', title: 'guard: Anthropic /v1/messages/count_tokens passes unscanned with a log note, on both legs (count-tokens calls pass unscanned, logged)',
        setup: Object.assign(S.req('/v1/messages/count_tokens', { model: 'claude-lab', messages: [{ role: 'user', content: ASK }] }),
            { legs: ['request', 'response'], airs: R.answers('allow-prompt'), response: S.reply({ input_tokens: 14 }) }),
        v3: function (r) {
            var q = r.request, x = r.response, lines = q.flow.logs.map(function (l) { return JSON.parse(l.line); });   // one log line per leg
            return S.check(q.calls.length === 0 && !q.fault && q.route === 'pass' && lines.length === 2 && /count-tokens/.test(lines[0].note) &&
                           x && x.calls.length === 0 && !x.fault && lines[1].route === 'pass',
                           'the count-tokens call was not passed with a log note: ' + JSON.stringify(lines));
        }
    },
    {
        finding: 'GATE-COV-G09', title: 'guard: MCP prompts/get: the arguments are collected',
        setup: Object.assign(S.mcp('prompts/get', { name: 'summary', arguments: { topic: MC } }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G09', title: 'guard: MCP completion/complete: the argument value is collected',
        setup: Object.assign(S.mcp('completion/complete', { ref: { type: 'ref/prompt', name: 'summary' }, argument: { name: 'topic', value: MC } }),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G10', title: 'guard: MCP tools/call reply: a resource_link block\'s description is collected in the tool event output',
        setup: Object.assign(S.mcp('tools/call', { name: 'lookup', arguments: { customer: 'Lauda' } }), {
            legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
            response: S.reply({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'Found one file.' },
                { type: 'resource_link', uri: 'file:///crm/lauda.txt', name: 'lauda.txt', mimeType: 'text/plain', description: MC }], isError: false } }) }),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        finding: 'GATE-COV-G11', title: 'guard: size limit: a tool result counts toward maxScanChars, so a short user turn plus a long tool result is refused without a scan',
        setup: requestOnly(S.anthropic([{ role: 'user', content: 'Look it up.' }, { role: 'assistant', content: [{ type: 'tool_use', id: 't91', name: 'lookup', input: {} }] },
                                        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't91', content: S.filler(200) }] }]), { vars: { maxScanChars: '150' } }),
        v3: function (r) { var q = r.request; return S.check(q.blocked && q.calls.length === 0, 'the over-limit tool result was ' + (q.calls.length ? 'scanned' : 'let through') + ' ' + state(q)); }
    },
    {
        finding: 'GATE-COV-G12', title: 'guard: bytes rule: Chat input_audio bytes (a WAV header, not UTF-8) are left out, while the part\'s format is still collected',
        setup: requestOnly(S.chat([{ role: 'user', content: [{ type: 'text', text: 'Transcribe this.' }, { type: 'input_audio', input_audio: { data: WAV, format: 'wav' } }] }])),
        v3: function (r) {
            var q = r.request;
            return S.check(q.calls.length === 1 && q.scanned.indexOf(WAV.slice(0, 40)) === -1 && /"format":"wav"/.test(q.scanned) && /<binary, \d+ characters>/.test(q.scanned),
                           'the audio bytes were scanned, or the part\'s fields were lost: ' + JSON.stringify(q.scanned.slice(0, 200)) + ' ' + state(q));
        }
    }
];

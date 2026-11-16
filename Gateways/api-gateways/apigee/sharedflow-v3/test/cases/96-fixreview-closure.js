'use strict';
/*
 * A closure review of the fixes for GATE-* findings, before release. For each GATE-* finding: does its fix close
 * it fully (both legs, the stream reader, every format it names, near variants of its input), and did a fix open a new
 * hole? Scope: the code the fixes changed; unchanged code only where a fix interacts with it.
 *   - FIX-C-NN: a gap this review found, fixed since. The title names the gap; the case passes when v3 behaves as
 *     required.
 *   - FIX-C-GNN: a guard, which passed then too. It pins what a fix meant to do.
 * Content is harmless only: the marker AIRSV3-MARKER, the standard Visa test card number (S.CARD), plain sentences.
 * Each case names the recorded reply its ServiceCallout gets; nothing here decides a verdict from content.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const M = 'AIRSV3-MARKER';
const MC = M + ' card on file ' + C;
const ASK = 'When does the bakery on the corner open?';

function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }
function json(s) { try { return JSON.parse(s); } catch (e) { return undefined; } }
function get(path, headers, query) { return { path: path, request: { verb: 'GET', headers: Object.assign({ Accept: 'application/json' }, headers || {}), content: '', querystring: query || '' } }; }
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
    return [typeof e.response === 'string' ? e.response : '', e.tool_event && e.tool_event.output ? String(e.tool_event.output) : ''].join('\n');
}
// Request leg: the field's text reached the scan, or v3 refused the request before the model.
function requestCovers(r, text) {
    var q = r.request;
    if (S.has(q, text)) { return true; }
    if (q.blocked && q.calls.length === 0) { return true; }
    return 'not collected: ' + JSON.stringify(text) + ' is not in the request scan ' + JSON.stringify(q.scanned.slice(0, 200)) + ' ' + state(q);
}
// Reply leg: the field's text reached the reply scan, or v3 withheld the reply without a scan.
function replyCovers(r, text) {
    var x = r.response;
    if (!x) { return 'the reply leg did not run ' + state(r.request); }
    var t = replyScan(r);
    if (t !== null && t.indexOf(text) !== -1) { return true; }
    if (x.blocked && x.calls.length === 0) { return true; }
    return 'not collected: ' + JSON.stringify(text) + ' is not in the reply scan ' + JSON.stringify(t === null ? t : t.slice(0, 160)) +
           (x.calls.length === 0 && !x.fault ? '; the reply reached the client with no scan at all ' : ' ') + state(x);
}
function requestOnly(base, extra) { return Object.assign(base, { legs: ['request'], airs: R.answers('allow-prompt') }, extra || {}); }

// A stand-in for JS-Airs3Init being cut on the reply leg (as 93-gate-apigee-realism.js does): Init reads scanType once per
// leg, after it has cleared the leg's variables (airs3-init.js:42-47) and before it sets the leg. The request
// leg's read gives an unset value; the reply leg's read throws, so Init stops there, as a timeLimit cut would.
function initStopsOnReplyLeg() {
    var reads = 0;
    return { toString: function () { reads++; if (reads > 1) { throw new Error('JS-Airs3Init cut on the reply leg (stand-in for a timeLimit cut)'); } return ''; } };
}
function responsesItem(text) { return { type: 'message', id: 'msg_96a', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: text, annotations: [], logprobs: [] }] }; }

module.exports = [
    /* ================================================================ findings: gaps the review found, fixed since === */

    /* ---- new holes: a fix dropped a field the code before the fixes scanned ----------------------------------------- */
    {
        // airs3-fmt-gemini.js: text is QUIET, so it was left out of the part's JSON rest, and part() read it only when it
        // is a string. Before the fixes, a part whose text was not a string fell through to jsonText(p) and was scanned.
        // A text that isn't a string now goes in the part's JSON.
        finding: 'FIX-C-01', title: 'Gemini request: a part whose text is not a string (a list here) is no longer collected; the part rewrite (GATE-CRIT-GEM-MULTIFIELD) dropped it from the JSON rest',
        setup: requestOnly(S.gemini([{ role: 'user', parts: [{ text: ASK }, { text: [MC] }] }])),
        v3: function (r) { return requestCovers(r, MC); }
    },
    {
        // airs3-fmt-anthropic.js:22 sends tool_result content through blocks(), whose thinking, tool_use and
        // server_tool_use (line 16) branches hard-coded the assistant role, which is off by default, and whose
        // redacted_thinking branch read nothing. Before the fixes every non-text block of a tool result was scanned as
        // tool JSON. Inside a tool result, those branches now read the block under the tool role.
        finding: 'FIX-C-02', title: 'Anthropic request: a thinking block inside a tool_result\'s content is read as assistant text (off by default), so the tool result text is not collected; before the fixes it was',
        setup: requestOnly(S.anthropic([{ role: 'user', content: 'Read the note.' }, { role: 'assistant', content: [{ type: 'tool_use', id: 't96', name: 'read_note', input: {} }] },
                                        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't96', content: [{ type: 'text', text: 'Here is the note.' }, { type: 'thinking', thinking: MC }] }] }])),
        v3: function (r) { return requestCovers(r, MC); }
    },

    /* ---- GATE-COV-01: a background answer fetched by another bodiless GET ------------------------------------------- */
    {
        // airs3-detect.js's storedByPath() read a stored answer only at /responses/{id}. A background response stored into
        // a conversation is also returned by GET /v1/conversations/{id}/items, which was 'unknown', so the reply leg passed
        // it. storedByPath() now reads a conversation's items too.
        finding: 'FIX-C-03', title: 'Responses background mode: the stored output fetched by GET /v1/conversations/{id}/items is not collected (the reply passes unscanned)',
        setup: Object.assign(get('/v1/conversations/conv_96a/items'), { legs: ['request', 'response'], airs: R.answers('allow-prompt-response'),
            response: S.reply({ object: 'list', data: [responsesItem(MC)], first_id: 'msg_96a', last_id: 'msg_96a', has_more: false }) }),
        v3: function (r) { return replyCovers(r, MC); }
    },
    {
        // airs3-detect.js:42 makes a trailing slash 'unknown', and that came before storedByPath was tried (byPath ||
        // stored), so the GET's reply passed instead of being read or withheld. A stored answer is now found with or
        // without a trailing slash.
        finding: 'FIX-C-03', title: 'Responses background mode: the stored output fetched by GET /v1/responses/{id}/ (a trailing slash) is not collected (the reply passes unscanned)',
        setup: Object.assign(get('/v1/responses/resp_96a/'), { legs: ['request', 'response'], airs: R.answers('allow-prompt-response'),
            response: S.reply({ id: 'resp_96a', object: 'response', created_at: 1794272592, status: 'completed', background: true, model: 'gpt-lab', output: [responsesItem(MC)] }) }),
        v3: function (r) { return replyCovers(r, MC); }
    },

    /* ---- GATE-COV-03 with GATE-R1: the reply-only rule ignores a declared body ---------------------------------------- */
    {
        // airs3-detect.js treats a declared but unseen body as a body on the request leg (GATE-R1); the reply leg's
        // unknown-endpoint rule tested only reqRaw !== '', so on a proxy that runs v3 on its response leg only, the same
        // unseen body made the reply 'the reply to a request with no body', and it passed. The rule now tests the
        // declared body too.
        finding: 'FIX-C-04', title: 'A response-leg-only proxy: the reply of an endpoint v3 does not read, to a request that declares a 96-byte body the flow sees empty, passes unscanned',
        setup: { path: '/v1/completions', request: { verb: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': '96' }, content: '' },
                 legs: ['response'], airs: R.answers('allow-prompt-response'),
                 response: S.reply({ id: 'cmpl-96a', object: 'text_completion', created: 1794272592, model: 'gpt-lab', choices: [{ index: 0, text: MC, logprobs: null, finish_reason: 'stop' }] }) },
        v3: function (r) { return replyCovers(r, MC); }
    },

    /* ---- GATE-NESTED-B64: the decode does not reach server tool results ----------------------------------------------- */
    {
        // airs3-fmt-anthropic.js read every *_tool_result block as jsonText(sealed(b)); jsonText decodes only data URIs,
        // so a base64 text source inside it (web_fetch_tool_result -> document) was scanned as base64, never as its text.
        // A base64 source inside one is now decoded like a document's.
        finding: 'FIX-C-05', title: 'Anthropic request: a base64 text/plain document inside a web_fetch_tool_result (a tool result, read since GATE-COV-12) is not decoded: its text is not collected',
        setup: requestOnly(S.anthropic([{ role: 'user', content: ASK },
            { role: 'assistant', content: [{ type: 'server_tool_use', id: 'srvtoolu_96a', name: 'web_fetch', input: { url: 'https://bakery.example/hours' } },
                { type: 'web_fetch_tool_result', tool_use_id: 'srvtoolu_96a', content: { type: 'web_fetch_result', url: 'https://bakery.example/hours', retrieved_at: '2026-11-10T08:00:00Z',
                    content: { type: 'document', title: 'Opening hours', source: { type: 'base64', media_type: 'text/plain', data: b64(MC) } } } },
                { type: 'text', text: 'It opens at seven.' }] },
            { role: 'user', content: 'And on Sundays?' }])),
        v3: function (r) { return requestCovers(r, MC); }
    },

    /* ---- GATE-R2: what is left of a cut reply-leg Init ---------------------------------------------------------------- */
    {
        // GATE-R2's fix recovered the leg for Respond only (airs3-respond.js:13). The log line still logged airs3.leg,
        // which the cut Init never set on the reply leg, so the reply's line said "request"; airs3-logline.js:8 now names
        // the leg as Respond does. (The refusal's shape after the same cut, an OpenAI-style 403 because airs3-init.js then
        // cleared format and mcpId, is 97-fixreview-realism.js's FIX-R-01; one fix closed both.)
        finding: 'FIX-C-06', title: 'Chat: when the reply leg\'s JS-Airs3Init is cut, its log line names the request leg (airs3.leg is the request leg\'s)',
        setup: Object.assign(S.chat([{ role: 'user', content: 'What is the capital of France? Answer in one word.' }]), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), vars: { scanType: initStopsOnReplyLeg() },
            response: S.reply({ id: 'chatcmpl-96a', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: 'Paris. ' + M }, finish_reason: 'stop' }] }) }),
        v3: function (r) {
            var x = r.response;
            if (!x) { return 'no reply leg ran ' + state(r.request); }
            var lines = x.flow.logs.map(function (l) { return json(l.line) || {}; });
            var last = lines[lines.length - 1] || {};
            return S.check(x.blocked && lines.length === 2 && last.leg === 'response' && last.kind === 'failure',
                'the reply leg\'s log line: ' + JSON.stringify(last));
        }
    },

    /* ---- GATE-COV-02 and GATE-COV-18: the MCP rules for them dropped the tool event ---------------------------------- */
    {
        // airs3-fmt-mcp.js's reply extras rule, which the fixes added, scanned a reply with any member outside the envelope
        // as plain text and returned no toolEvent, so airs3-read.js used the LLM profile, not toolProfile. Before the fixes
        // this tools/call result was a tool event under toolProfile; the MCP server could pick the profile by adding one
        // member. A tools/call result now stays a tool event.
        finding: 'FIX-C-07', title: 'MCP tools/call reply with a member outside the JSON-RPC envelope: it is no longer a tool event, so it is scanned under the LLM profile, not toolProfile (the server picks)',
        setup: Object.assign(S.mcp('tools/call', { name: 'lookup', arguments: { customer: 'Lauda' } }), {
            legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), vars: { toolProfile: 'TOOL_PROFILE' },
            response: S.reply({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: MC }], isError: false }, note: 'lab' }) }),
        v3: function (r) {
            var x = r.response;
            if (!x) { return 'the reply leg did not run ' + state(r.request); }
            var s = x.scans[0] || {}, e = s.contents && s.contents[0] || {};
            return S.check(x.calls.length === 1 && s.ai_profile && s.ai_profile.profile_name === 'TOOL_PROFILE' && e.tool_event && String(e.tool_event.output).indexOf(MC) !== -1,
                'the tool result was scanned with ' + JSON.stringify(s.ai_profile) + ', as ' + (e.tool_event ? 'a tool event' : 'plain text') + ' ' + state(x));
        }
    },
    {
        // airs3-fmt-mcp.js's otherParams rule, which the fixes also added, did the same on the request leg: one params
        // member beyond name, arguments and _meta, and the client's tool call was plain text under the LLM profile. It now
        // stays a tool event under toolProfile.
        finding: 'FIX-C-07', title: 'MCP tools/call request with a params member beyond name, arguments and _meta: it is no longer a tool event, so it is scanned under the LLM profile, not toolProfile (the client picks)',
        setup: Object.assign(S.mcp('tools/call', { name: 'lookup', arguments: { customer: 'Lauda' }, note: MC }), {
            legs: ['request'], airs: R.answers('allow-tool'), vars: { toolProfile: 'TOOL_PROFILE' } }),
        v3: function (r) {
            var q = r.request, s = q.scans[0] || {}, e = s.contents && s.contents[0] || {};
            return S.check(q.calls.length === 1 && s.ai_profile && s.ai_profile.profile_name === 'TOOL_PROFILE' && e.tool_event && S.has(q, MC),
                'the tool call was scanned with ' + JSON.stringify(s.ai_profile) + ', as ' + (e.tool_event ? 'a tool event' : 'plain text') + ' ' + state(q));
        }
    },

    /* ---- GATE-COV-13 in Chat: the other citation shape ---------------------------------------------------------------- */
    {
        // airs3-fmt-openai-chat.js read OpenAI's message.annotations only. Azure OpenAI's chat completions with
        // data_sources (served at /openai/deployments/{d}/chat/completions, a path v3 reads as Chat) put the cited chunks'
        // text in message.context.citations[].content, which was not collected; so a mask on content left it in place too.
        // message.context is now read as well.
        finding: 'FIX-C-08', title: 'Chat reply (Azure OpenAI with data_sources): choices[].message.context.citations[].content (the cited text) is not collected',
        setup: Object.assign(S.req('/openai/deployments/gpt-lab/chat/completions', { messages: [{ role: 'user', content: ASK }],
            data_sources: [{ type: 'azure_search', parameters: { endpoint: 'https://search-lab.example', index_name: 'bakery-hours', authentication: { type: 'system_assigned_managed_identity' } } }] },
            null, 'api-version=2024-10-21'), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: S.reply({ id: 'chatcmpl-96b', object: 'chat.completion', created: 1794272592, model: 'gpt-lab',
                choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'It opens at seven [doc1].', end_turn: true,
                    context: { citations: [{ content: MC, title: 'Opening hours', url: 'https://bakery.example/hours', filepath: null, chunk_id: '0' }], intent: '["bakery opening hours"]' } } }] }) }),
        v3: function (r) { return replyCovers(r, MC); }
    },

    /* ================================================================ regression guards ============================ */
    {
        // GATE-COV-07 added messages[].name with a path: a mask that touches it is written back there and in the content.
        finding: 'FIX-C-G01', title: 'guard: Chat request masked by applyDlpMasking: the card in messages[].name and in its content are both written back (no partial masking)',
        setup: Object.assign(S.chat([{ role: 'user', name: 'My card number is ' + C + '.', content: 'Use ' + C + ' for the order.' }]),
                             { legs: ['request'], airs: R.answers('mask-v3-two-turns-cards'), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) {
            var q = r.request, body = String(q.request.content);
            return S.check(!q.fault && q.flow.get('airs3.outcome') === 'mask' && body.indexOf('4111') === -1 && /"name":"My card number is X{19}\."/.test(body),
                'the masked request: ' + body.slice(0, 200) + ' ' + state(q));
        }
    },
    {
        // GATE-COV-10 added prompt.variables with a path: a mask is written back into the variable exactly.
        finding: 'FIX-C-G02', title: 'guard: Responses request masked by applyDlpMasking: a prompt variable\'s card is written back in place',
        setup: Object.assign(S.req(S.P.responses, { model: 'm', prompt: { id: 'pmpt_96a', version: '2', variables: { note: 'Please store my card ' + C + ' for the next order.' } } }),
                             { legs: ['request'], airs: R.answers('block-dlp-prompt-masked'), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) {
            var q = r.request, b = json(String(q.request.content)) || {};
            var v = b.prompt && b.prompt.variables && b.prompt.variables.note;
            return S.check(!q.fault && q.flow.get('airs3.outcome') === 'mask' && v === 'Please store my card XXXXXXXXXXXXXXXXXXX for the next order.',
                'the masked variable: ' + JSON.stringify(v) + ' ' + state(q));
        }
    },
    {
        // GATE-COV-17's both-names refusal also runs on the parts of a multimodal function response (GATE-COV-15 recursion).
        finding: 'FIX-C-G03', title: 'guard: Gemini request: a part inside functionResponse.parts that carries inlineData and inline_data is refused',
        setup: requestOnly(S.gemini([S.user('Fetch the note.'), { role: 'model', parts: [{ functionCall: { name: 'get_note', args: {} } }] },
            { role: 'user', parts: [{ functionResponse: { name: 'get_note', response: { note: 'ready' }, parts: [{ inlineData: { mimeType: 'text/plain', data: b64('The note is ready.') },
                                                                                                                         inline_data: { mime_type: 'text/plain', data: b64(MC) } }] } }] }])),
        v3: function (r) { var q = r.request; return S.check(q.blocked && q.calls.length === 0, 'a part naming inlineData twice was not refused ' + state(q)); }
    },
    {
        // GATE-COV-01 reads stored answers; a stored answer fetched as an event stream (?stream=true) is still withheld.
        finding: 'FIX-C-G04', title: 'guard: GET /v1/responses/{id}?stream=true answered as an event stream is withheld, not passed',
        setup: Object.assign(get('/v1/responses/resp_96b', { Accept: 'text/event-stream' }, 'stream=true'), { legs: ['request', 'response'], airs: R.answers('allow-prompt-response'),
            response: { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } }),
        v3: function (r) {
            var x = r.response;
            return S.check(r.request.route === 'pass' && x && x.blocked && x.calls.length === 0, 'the streamed stored answer was not withheld ' + state(x));
        }
    },
    {
        // GATE-COUNT / GATE-COV-04 anchored the count-tokens match; Claude on Vertex's real count-tokens endpoint still passes.
        finding: 'FIX-C-G05', title: 'guard: Claude on Vertex .../models/count-tokens:rawPredict still passes unscanned with a log note, on both legs',
        setup: Object.assign(S.req('/v1/projects/p/locations/global/publishers/anthropic/models/count-tokens:rawPredict', { model: 'claude-x', messages: [{ role: 'user', content: ASK }] }),
            { legs: ['request', 'response'], airs: R.answers('allow-prompt'), response: S.reply({ input_tokens: 14 }) }),
        v3: function (r) {
            var q = r.request, x = r.response;
            return S.check(q.calls.length === 0 && !q.fault && q.route === 'pass' && x && x.calls.length === 0 && !x.fault && x.route === 'pass' && /count-tokens/.test(String(x.flow.get('airs3.logNote'))),
                'the count-tokens call did not pass on both legs ' + state(q) + ' ' + state(x));
        }
    },
    {
        // GATE-COV-03 withholds an unknown endpoint's reply only when its request had a body; a model list still passes.
        finding: 'FIX-C-G06', title: 'guard: a response-leg-only proxy: the reply to a bodiless GET at an endpoint v3 does not read (a model list) passes, logged',
        setup: Object.assign(get('/v1/models'), { legs: ['response'], airs: R.answers('allow-prompt-response'),
            response: S.reply({ object: 'list', data: [{ id: 'gpt-lab', object: 'model', created: 1794272592, owned_by: 'lab' }] }) }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && !x.fault && x.calls.length === 0 && x.route === 'pass' && /no body/.test(String(x.flow.get('airs3.logNote'))), 'the model list was not passed with a log note ' + state(x));
        }
    }
];

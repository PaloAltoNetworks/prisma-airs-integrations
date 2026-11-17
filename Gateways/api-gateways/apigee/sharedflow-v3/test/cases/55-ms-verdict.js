'use strict';
/*
 * MuleSoft's tests of the scan request, the verdict, the decision, the refusals, the log line and the ids
 * (core/tests/airs.rs, decision.rs, errors.rs, evidence.rs and identity.rs), ported to v3's rules. Where v3 differs on
 * purpose the case holds v3's rule and its title says so:
 *   - a refusal is HTTP 200 in the client's own format with the x-airs-* headers (blockStatus can force a status); an
 *     endpoint v3 does not read gets an OpenAI-style 403; MCP gets a JSON-RPC error with the id as sent, HTTP 200;
 *   - a 400 or 413 from Prisma AIRS is content it refused (onScanError), never an outage (failOpen);
 *   - the reply scan sends one entry, {prompt, response};
 *   - an allow that carries a masked copy is masked wherever the copy can be written back exactly; anything else blocks.
 * Monitor mode, the profile map, showCategories, tools/list tool events and batch scanning are not in phase 1.
 * Each case names the reply its ServiceCallout gets. Where a masked copy must fit, the text is the one the fixture was
 * recorded for (test/record-airs-fixtures.py). Synthetic replies (MuleSoft's own literals) say so in the title.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const MARK = 'AIRSV3-MARKER';
const KEY = 'lab-key-for-unit-tests';                                              // the harness's key (test/run.js)

// The texts the recorded replies were scanned with, so a masked copy fits exactly.
const BENIGN = 'What is the capital of France?', PARIS = 'Paris.';                   // allow-prompt, allow-prompt-response
const STORE = 'Please store my card ' + C + ' for the next order.';                 // block-dlp-prompt-masked
const STORE_X = 'Please store my card XXXXXXXXXXXXXXXXXXX for the next order.';
const ASK = 'Which card is on file?', ON_FILE = 'The card on file is ' + C + '.';   // block-dlp-response-masked
const ON_FILE_X = 'The card on file is XXXXXXXXXXXXXXXXXXX.';
const FIRST = 'First block.', MY_CARD = 'My card is ' + C + '.';                   // mask-a22-chat-two-blocks
const NOT_SCANNED = 'Prisma AIRS could not scan this request, so it was not forwarded.';
const REPLY_NOT_SCANNED = 'Prisma AIRS could not scan this response, so it was withheld.';

/* ---- shapes ----------------------------------------------------------------------------------------------------- */
function chat(text, headers, extra) { return S.req(S.P.chat, Object.assign({ model: 'm', messages: [{ role: 'user', content: text }] }, extra || {}), headers); }
function chatReply(text) { return S.reply({ id: 'chatcmpl-1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }); }
function chatStream(text) {
    return { status: 200, headers: { 'Content-Type': 'text/event-stream' },
             content: 'data: ' + JSON.stringify({ id: 'chatcmpl-1', object: 'chat.completion.chunk', choices: [{ index: 0, delta: { content: text } }] }) + '\n\ndata: [DONE]\n\n' };
}
function rpc(method, params, id) { var m = { jsonrpc: '2.0' }; if (id !== undefined) { m.id = id; } m.method = method; if (params !== undefined) { m.params = params; } return m; }
function mcp(msg, headers) { return S.req(S.P.mcp, msg, Object.assign({ Accept: 'application/json, text/event-stream' }, headers || {})); }
function toolCall(id, args, name, headers) { return mcp(rpc('tools/call', { name: name || 'echo', arguments: args }, id), headers); }
function toolResult(id, text) { return S.reply({ jsonrpc: '2.0', id: id, result: { content: [{ type: 'text', text: text }] } }); }
function synthetic(obj) { return R.status(200, JSON.stringify(obj)); }

/* ---- what a case looks at ---------------------------------------------------------------------------------------- */
function json(s) { try { return JSON.parse(s); } catch (e) { return undefined; } }
function v(x, leaf) { return x.flow.get('airs3.' + leaf); }
function hdr(x, name) { var m = x && x.fault ? x.flow.messages.response : null; return m ? m.header(name) : null; }
function fwd(x) { return json(String(x.request.content)); }                         // the request as it would be forwarded
function logs(x) { return x.flow.logs.map(function (l) { return l.line; }); }
function lastLog(x) { var l = logs(x); return l.length ? json(l[l.length - 1]) : null; }
function airs3Vars(x) { var out = []; x.flow.vars.forEach(function (val, k) { if (k.indexOf('airs3.') === 0) { out.push(k + '=' + val); } }); return out; }
function canon(o) {
    if (Array.isArray(o)) { return o.map(canon); }
    if (o && typeof o === 'object') { var c = {}; Object.keys(o).sort().forEach(function (k) { c[k] = canon(o[k]); }); return c; }
    return o;
}
function same(a, b) { return JSON.stringify(canon(a)) === JSON.stringify(canon(b)); }
function has(o, k) { return !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k); }
// The message a refusal carries, whatever the client's format.
function said(x) {
    var b = json(x && x.body);
    if (!b || typeof b !== 'object') { return null; }
    try {
        if (b.jsonrpc && b.error) { return b.error.message; }
        if (b.object === 'chat.completion') { return b.choices[0].message.content; }
        if (b.object === 'response') { return b.output[0].content[0].text; }
        if (b.type === 'message') { return b.content[0].text; }
        if (b.candidates) { return b.candidates[0].content.parts[0].text; }
        if (b.error) { return b.error.message; }
    } catch (e) { return null; }
    return null;
}
function streamSaid(x) { var m = /^data: (\{.*\})$/m.exec((x && x.body) || ''); var d = m && json(m[1]); return d && d.choices && d.choices[0].delta ? d.choices[0].delta.content : null; }
// The first result that isn't true, else true.
function and() { for (var i = 0; i < arguments.length; i++) { if (arguments[i] !== true) { return arguments[i]; } } return true; }
function passed(x) { return !x ? 'the leg did not run' : (x.fault ? 'it was refused: ' + String(x.body).slice(0, 160) : true); }
// A refusal with x-airs-blocked: true and this x-airs-kind, and, when given, exactly this message.
function refused(x, kind, message) {
    if (!x) { return 'the leg did not run'; }
    if (!x.fault) { return 'it was not refused (outcome ' + v(x, 'outcome') + ', route ' + v(x, 'route') + ')'; }
    if (!x.blocked) { return 'the refusal has no x-airs-blocked: true'; }
    if (hdr(x, 'x-airs-kind') !== kind) { return 'x-airs-kind is ' + hdr(x, 'x-airs-kind') + ', not ' + kind; }
    if (message !== undefined && said(x) !== message) { return 'the refusal says ' + JSON.stringify(said(x)) + ', not ' + JSON.stringify(message); }
    return true;
}
// A JSON-RPC refusal: HTTP 200, this code, and the request id as sent.
function rpcRefused(x, code, id) {
    if (!x || !x.fault) { return 'it was not refused' + (x ? ' (outcome ' + v(x, 'outcome') + ')' : ''); }
    var b = json(x.body);
    if (!b || b.jsonrpc !== '2.0' || !b.error) { return 'HTTP ' + x.status + ', not a JSON-RPC error: ' + String(x.body).slice(0, 200); }
    if (x.status !== 200) { return 'HTTP ' + x.status + ', not 200'; }
    if (b.error.code !== code) { return 'code ' + b.error.code + ', not ' + code; }
    if (!has(b, 'id') || b.id !== id) { return 'id ' + JSON.stringify(b.id) + ' (' + typeof b.id + '), not ' + JSON.stringify(id); }
    return true;
}

/* ---- ids (airs.rs:87-108, identity.rs) ---------------------------------------------------------------------------- */
const T100 = 't'.repeat(100), T101 = 't'.repeat(101), S100 = 's'.repeat(100), S101 = 's'.repeat(101);
// want.tx: the transaction_id ('messageid' for Apigee's own), want.session: the session_id, or null when none is sent.
function idCase(finding, title, headers, want, onMcp) {
    var setup = onMcp ? toolCall(1, { text: 'hello' }, 'echo', headers) : chat(BENIGN, headers);
    return {
        finding: finding, title: title,
        setup: Object.assign(setup, { legs: ['request'], airs: R.answers(onMcp ? 'allow-tool' : 'allow-prompt') }),
        v3: function (r) {
            var b = r.request.scans[0];
            if (!b) { return 'nothing was scanned'; }
            var tx = want.tx === 'messageid' ? r.request.flow.get('messageid') : want.tx;
            return and(
                S.check(!has(b, 'tr_id'), 'tr_id was sent'),
                S.check(want.tx === undefined || b.transaction_id === tx, 'transaction_id is ' + JSON.stringify(b.transaction_id) + ', not ' + JSON.stringify(tx)),
                S.check(want.session === undefined || (want.session === null ? !has(b, 'session_id') : b.session_id === want.session),
                        'session_id is ' + (has(b, 'session_id') ? JSON.stringify(b.session_id) : 'left out') + ', not ' + (want.session === null ? 'left out' : JSON.stringify(want.session))),
                S.check(want.user === undefined || b.metadata.app_user === want.user, 'app_user is ' + JSON.stringify(b.metadata.app_user) + ', not ' + JSON.stringify(want.user)));
        }
    };
}

/* ---- the verdict gate (airs.rs:158-189) ------------------------------------------------------------------------- */
function failureCase(title, reply, extraVars) {
    return {
        finding: 'MS-verdict-gate', title: title,
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers(reply), vars: extraVars || {} }),
        v3: function (r) {
            return and(refused(r.request, 'failure'), S.check(v(r.request, 'outcome') === 'failure', 'outcome ' + v(r.request, 'outcome')),
                       S.check((said(r.request) || '').indexOf(NOT_SCANNED) === 0, 'the refusal says ' + JSON.stringify(said(r.request))));
        }
    };
}
const MS_DEGRADED_ERROR = { action: 'allow', category: 'benign', error: true, timeout: false, errors: [{ content_type: 'prompt', feature: 'dlp', status: 'error' }], scan_id: 's', report_id: 'r' };
const MS_DEGRADED_CATEGORY = { action: 'allow', category: 'timeout', error: false, timeout: false, errors: [] };
const MS_TIMEOUT_BLOCK = { action: 'block', category: 'malicious', timeout: true, prompt_detected: { injection: true }, errors: [{ content_type: 'prompt', feature: 'url_cats', status: 'timeout' }] };
const MS_TOOL_SUMMARY = { action: 'block', category: 'malicious', scan_id: 's-1',
                          tool_detected: { verdict: 'malicious', summary: { detections: { agent: false, injection: true }, threats: [] },
                                           input_detected: { detection_entries: null }, output_detected: { detection_entries: null } } };
const MS_TOOL_DEGRADED = { action: 'allow', category: 'benign', error: true, errors: [{ feature: 'agent', status: 'timeout' }], tool_detected: {} };
const BATCH = [rpc('tools/call', { name: 'echo', arguments: { text: 'hello' } }, 1), rpc('tools/call', { name: 'echo', arguments: { text: 'hello' } }, 2)];
// One member over mcpBatchLimit's default, 8.
const BATCH9 = [1, 2, 3, 4, 5, 6, 7, 8, 9].map(function (n) { return rpc('tools/call', { name: 'echo', arguments: { text: 'hello' } }, n); });

module.exports = [
    /* ================= the scan request (airs.rs) ================= */
    {
        finding: 'MS-prompt-payload', title: 'The prompt scan sends one entry, the profile name, metadata, transaction_id and session_id; never tr_id (airs.rs:26 prompt_payload_shape)',
        setup: Object.assign(S.req(S.P.chat, { model: 'gpt-test', messages: [{ role: 'user', content: BENIGN }] },
                                   { 'x-correlation-id': '5b1e8f3a-2c4d-4e6f-8a9b-0c1d2e3f4a5b', 'x-session-id': 'conv-42', 'x-user-id': 'hr-bot' }),
                             { legs: ['request'], airs: R.answers('allow-prompt'), vars: { currentProfile: 'my-security-profile', appName: 'hr-portal' } }),
        v3: function (r) {
            var b = r.request.scans[0];
            if (!b) { return 'nothing was scanned'; }
            return and(
                S.check(same(Object.keys(b).sort(), ['ai_profile', 'contents', 'metadata', 'session_id', 'transaction_id']), 'the scan body has ' + Object.keys(b).join(', ')),
                S.check(same(b.contents, [{ prompt: BENIGN }]), 'contents is ' + JSON.stringify(b.contents)),
                S.check(same(b.ai_profile, { profile_name: 'my-security-profile' }), 'ai_profile is ' + JSON.stringify(b.ai_profile)),
                S.check(same(b.metadata, { app_name: 'Apigee-hr-portal', app_user: 'hr-bot', ai_model: 'gpt-test' }), 'metadata is ' + JSON.stringify(b.metadata)),
                S.check(b.transaction_id === '5b1e8f3a-2c4d-4e6f-8a9b-0c1d2e3f4a5b' && b.session_id === 'conv-42', 'the ids are ' + JSON.stringify([b.transaction_id, b.session_id])),
                passed(r.request));
        }
    },
    {
        finding: 'MS-prompt-payload', title: 'With no id headers and no model nothing goes empty: no session_id, transaction_id is Apigee\'s messageid, no blank metadata (airs.rs:57 session_omitted_when_none)',
        setup: Object.assign(S.req(S.P.chat, { messages: [{ role: 'user', content: BENIGN }] }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var b = r.request.scans[0];
            if (!b) { return 'nothing was scanned'; }
            var blank = Object.keys(b.metadata).filter(function (k) { return typeof b.metadata[k] !== 'string' || b.metadata[k].trim() === ''; });
            return and(
                S.check(!has(b, 'session_id') && !has(b, 'tr_id'), 'session_id or tr_id was sent: ' + JSON.stringify(b)),
                S.check(b.transaction_id === r.request.flow.get('messageid'), 'transaction_id is ' + JSON.stringify(b.transaction_id) + ', not the messageid'),
                S.check(blank.length === 0, 'metadata sent blank: ' + blank.join(', ')));
        }
    },
    {
        finding: 'MS-reply-payload', title: 'The reply scan carries the prompt as context in the same entry, [{prompt, response}] (airs.rs:43; v3 sends one entry where MuleSoft sends two, because Prisma AIRS judges only the last)',
        setup: Object.assign(chat(BENIGN), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: chatReply(PARIS) }),
        v3: function (r) {
            var q = r.request.scans[0], a = r.response && r.response.scans[0];
            return and(S.check(q && same(q.contents, [{ prompt: BENIGN }]), 'the prompt scan sent ' + JSON.stringify(q && q.contents)),
                       S.check(a && same(a.contents, [{ prompt: BENIGN, response: PARIS }]), 'the reply scan sent ' + JSON.stringify(a && a.contents)),
                       passed(r.response));
        }
    },
    {
        finding: 'MS-reply-payload', title: 'A reply scan with no prompt context (v3 on the response leg only) sends [{response}], no blank prompt (airs.rs:49 response_payload_shape_without_prompt)',
        setup: Object.assign(chat(BENIGN), { legs: ['response'], airs: R.answers('allow-prompt-response'), response: chatReply(PARIS) }),
        v3: function (r) {
            var a = r.response && r.response.scans[0];
            return S.check(a && same(a.contents, [{ response: PARIS }]), 'the reply scan sent ' + JSON.stringify(a && a.contents));
        }
    },
    idCase('MS-clamp', 'Ids are trimmed and 100 characters are kept whole (airs.rs:87 clamp_trims_and_keeps_100)',
           { 'x-correlation-id': '  ' + T100 + ' ', 'x-session-id': ' ' + S100 + '  ' }, { tx: T100, session: S100 }),
    idCase('MS-clamp', 'An id of 101 characters is skipped for the next source, never cut (airs.rs:93 clamp_rejects_101_chars)',
           { 'x-correlation-id': T101, 'x-request-id': 'req-2', 'x-session-id': S101, 'x-claude-code-session-id': 'cc-2' }, { tx: 'req-2', session: 'cc-2' }),
    idCase('MS-clamp', 'With no other source, a 101-character id gives way to Apigee\'s messageid and no session_id, never a cut copy (airs.rs:93)',
           { 'x-correlation-id': T101, 'x-session-id': S101 }, { tx: 'messageid', session: null }),
    idCase('MS-clamp', 'A non-ASCII id (sesión) is skipped (airs.rs:98 clamp_rejects_non_ascii)',
           { 'x-correlation-id': 'sesión', 'x-request-id': 'req-3', 'x-session-id': 'sesión' }, { tx: 'req-3', session: null }),
    idCase('MS-clamp', 'An id holding a tab is skipped (airs.rs:98 clamp_rejects_non_ascii)',
           { 'x-correlation-id': 'a\tb', 'x-request-id': 'req-3', 'x-session-id': 'a\tb' }, { tx: 'req-3', session: null }),
    idCase('MS-clamp', 'An id holding a control character is skipped (airs.rs:98 clamp_rejects_non_ascii)',
           { 'x-correlation-id': 'a\u0007b', 'x-request-id': 'req-3', 'x-session-id': 'a\u0007b' }, { tx: 'req-3', session: null }),
    idCase('MS-clamp', 'Empty and all-blank ids count as absent (airs.rs:104 clamp_rejects_empty)',
           { 'x-correlation-id': '', 'x-request-id': '   ', 'x-session-id': '   ', 'x-claude-code-session-id': 'cc-4' }, { tx: 'messageid', session: 'cc-4' }),

    /* ================= the verdict (airs.rs) ================= */
    {
        finding: 'MS-detections', title: 'The category is never a detection: a block reads only the true flags, and they are not pure DLP (airs.rs:122; block-injection-agent-prompt, recorded for another 100,000 characters of harmless repeated sentences)',
        setup: Object.assign(chat(S.filler(100000)), { legs: ['request'], airs: R.answers('block-injection-agent-prompt'), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) {
            var d = v(r.request, 'detections');
            return and(refused(r.request, 'block'), S.check(d === 'prompt.agent,prompt.injection', 'detections ' + JSON.stringify(d)),
                       S.check(v(r.request, 'category') === 'malicious' && hdr(r.request, 'x-airs-category') === 'malicious', 'the category was not kept apart from the detections'),
                       S.check(!/malicious/i.test(said(r.request) || ''), 'the message names the category: ' + said(r.request)));
        }
    },
    {
        finding: 'MS-detections', title: 'Prompt-side flags on a reply verdict are named prompt.<flag>; when the request leg allowed that prompt, they let the reply through, logged (the prompt-context rule; airs.rs:149)',
        setup: Object.assign(chat(BENIGN), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-injection-agent-prompt'),
                                            vars: { applyDlpMasking: 'true' }, response: chatReply(PARIS) }),
        v3: function (r) {
            var d = r.response && v(r.response, 'detections');
            return and(S.check(r.response && !r.response.fault, 'the reply was refused'), S.check(d === 'prompt.agent,prompt.injection', 'detections ' + JSON.stringify(d)),
                       S.check(/only the prompt context was flagged/.test(v(r.response, 'logNote') || ''), 'the note is ' + JSON.stringify(v(r.response, 'logNote'))));
        }
    },
    failureCase('A 401 from Prisma AIRS is a scanner failure (airs.rs:158 parse_non_200_is_status; synthetic reply)', R.status(401, '{"error":{"message":"Invalid API Key"}}')),
    failureCase('A 504 from Prisma AIRS is a scanner failure (airs.rs:158 parse_non_200_is_status)', R.status(504, '')),
    failureCase('The recorded 403 for a wrong key is a scanner failure (airs.rs:158 parse_non_200_is_status)', 'error-403-wrong-key'),
    failureCase('A 200 whose body is HTML is a scanner failure (airs.rs:164 parse_garbage_is_undecodable)', R.status(200, '<html>gateway</html>')),
    failureCase('A 200 whose body is a JSON array is a scanner failure (airs.rs:164 parse_garbage_is_undecodable)', R.status(200, '[1,2]')),
    failureCase('A 200 with an empty body is a scanner failure (airs.rs:164; A14)', R.status(200, '')),
    failureCase('Action "maybe" is a scanner failure (airs.rs:170 parse_unknown_action_is_missing_action; synthetic reply)', R.status(200, '{"action":"maybe","category":"benign"}')),
    failureCase('No action at all is a scanner failure (airs.rs:170 parse_unknown_action_is_missing_action; synthetic reply)', R.status(200, '{"category":"benign"}')),
    failureCase('Action "BLOCK" in capitals is not a verdict: a scanner failure (airs.rs:170; A14; synthetic reply)', R.status(200, '{"action":"BLOCK","category":"malicious"}')),
    failureCase('An allow with error:true is a scanner failure (airs.rs:176 parse_detector_error_on_allow_is_incomplete; synthetic reply)', synthetic(MS_DEGRADED_ERROR)),
    failureCase('An allow with category timeout is a scanner failure (airs.rs:176; synthetic reply)', synthetic(MS_DEGRADED_CATEGORY)),
    failureCase('An allow with timeout:true is a scanner failure (airs.rs:176; A15; synthetic reply)', synthetic(Object.assign({}, MS_DEGRADED_CATEGORY, { category: 'benign', timeout: true }))),
    {
        finding: 'MS-verdict-gate', title: 'A block that reports a detector time-out still blocks, even with failOpen=true (airs.rs:185 parse_detector_timeout_on_block_still_blocks; synthetic reply)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers(synthetic(MS_TIMEOUT_BLOCK)), vars: { failOpen: 'true' } }),
        v3: function (r) { return and(refused(r.request, 'block'), S.check(v(r.request, 'detections') === 'prompt.injection', 'detections ' + JSON.stringify(v(r.request, 'detections')))); }
    },
    {
        finding: 'MS-verdict-gate', title: 'The recorded 400 from Prisma AIRS is content it refused, not an outage: refused even with failOpen=true (v3 differs on purpose; MuleSoft counts it a scanner failure, airs.rs:158)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers('error-400-prompt-too-long'), vars: { failOpen: 'true' } }),
        v3: function (r) { return refused(r.request, 'refused', 'Prisma AIRS could not inspect this request, so it was not forwarded.'); }
    },
    {
        finding: 'MS-verdict-gate', title: 'A 413 from Prisma AIRS is content it refused: refused even with failOpen=true (v3\'s rule, as for a 400)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers(R.status(413, '')), vars: { failOpen: 'true' } }),
        v3: function (r) { return refused(r.request, 'refused', 'Prisma AIRS could not inspect this request, so it was not forwarded.'); }
    },
    {
        finding: 'MS-pure-dlp', title: 'A block whose only detection is dlp is masked from prompt_masked_data with applyDlpMasking=true (airs.rs:192, airs.rs:202, decision.rs:32 row "block pure dlp + masked, masking on"; block-dlp-prompt-masked, recorded for this text)',
        setup: Object.assign(chat(STORE), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked'), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) {
            var m = fwd(r.request);
            return and(passed(r.request), S.check(m && m.messages[0].content === STORE_X, 'forwarded ' + JSON.stringify(m && m.messages[0].content)));
        }
    },
    {
        finding: 'MS-pure-dlp', title: 'DLP with other flags is not pure DLP: with applyDlpMasking=true the request is blocked, not masked (airs.rs:192, decision.rs:78; mask-a22-chat-two-blocks, recorded for this text)',
        setup: Object.assign(S.req(S.P.chat, { model: 'm', messages: [{ role: 'user', content: [{ type: 'text', text: FIRST }, { type: 'text', text: MY_CARD }] }] }),
                             { legs: ['request'], airs: R.answers('mask-a22-chat-two-blocks'), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) {
            var q = r.request.scans[0], m = fwd(r.request);
            return and(S.check(q && same(q.contents, [{ prompt: FIRST + '\n' + MY_CARD }]), 'the scan text is not the recorded one: ' + JSON.stringify(q && q.contents)),
                       refused(r.request, 'block'),
                       S.check(v(r.request, 'masked') !== 'true' && m && m.messages[0].content[1].text === MY_CARD, 'the request was rewritten'));
        }
    },
    {
        finding: 'MS-pure-dlp', title: 'A block with no detections is not pure DLP: with applyDlpMasking=true it stays a block (airs.rs:192; MuleSoft\'s literal, no masked copy)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers(R.status(200, '{"action":"block","category":"malicious"}')), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) { return and(refused(r.request, 'block'), S.check(v(r.request, 'detections') === '', 'detections ' + JSON.stringify(v(r.request, 'detections')))); }
    },
    {
        finding: 'MS-masked-field', title: 'On the reply leg the masked copy comes from response_masked_data: a DLP-only block with applyDlpMasking=true is masked (airs.rs:202; block-dlp-response-masked, recorded for this prompt and reply)',
        setup: Object.assign(chat(ASK), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
                                         vars: { applyDlpMasking: 'true' }, response: chatReply(ON_FILE) }),
        v3: function (r) {
            var a = r.response && r.response.scans[0], out = r.response && json(r.response.body);
            return and(S.check(a && same(a.contents, [{ prompt: ASK, response: ON_FILE }]), 'the reply scan is not the recorded one: ' + JSON.stringify(a && a.contents)),
                       passed(r.response), S.check(out && out.choices[0].message.content === ON_FILE_X, 'the client got ' + JSON.stringify(out && out.choices[0].message.content)));
        }
    },
    {
        finding: 'MS-masked-field', title: 'The prompt leg never applies response_masked_data (airs.rs:202; block-dlp-response-masked turned into an allow)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers(R.asAllow('block-dlp-response-masked')) }),
        v3: function (r) {
            var m = fwd(r.request);
            return and(passed(r.request), S.check(m && m.messages[0].content === BENIGN && v(r.request, 'masked') !== 'true', 'the prompt was rewritten: ' + JSON.stringify(m)));
        }
    },
    {
        finding: 'MS-masked-field', title: 'The reply leg never applies prompt_masked_data (airs.rs:202; block-dlp-prompt-masked turned into an allow)',
        setup: Object.assign(chat(BENIGN), { legs: ['request', 'response'], airs: R.answers('allow-prompt', R.asAllow('block-dlp-prompt-masked')), response: chatReply(PARIS) }),
        v3: function (r) {
            var out = r.response && json(r.response.body);
            return and(passed(r.response), S.check(out && out.choices[0].message.content === PARIS, 'the reply was rewritten: ' + JSON.stringify(out)));
        }
    }
].concat([
    [R.status(500, MARK + ' upstream text'), MARK, 'a 500 with a body'],
    ['error-400-prompt-too-long', 'prompt length exceeds', 'the recorded 400'],
    ['error-403-wrong-key', 'Invalid API Key', 'the recorded 403'],
    [R.status(200, '<html>' + MARK + '</html>'), MARK, 'an HTML 200']
].map(function (t) {
    return {
        finding: 'MS-no-reply-body', title: 'Prisma AIRS\'s reply body never reaches the client, a header, a log line or a variable: ' + t[2] + ' (airs.rs:210 errors_never_contain_the_reply_body)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers(t[0]) }),
        v3: function (r) {
            var x = r.request;
            if (!x.fault) { return 'it was not refused'; }
            var seen = [x.body, JSON.stringify(x.flow.messages.response.headers)].concat(logs(x), airs3Vars(x));
            var hit = seen.filter(function (s) { return String(s).indexOf(t[1]) !== -1; });
            return S.check(hit.length === 0, 'the reply body shows in: ' + hit.join(' | ').slice(0, 240));
        }
    };
})).concat([
    /* ================= MCP tool events (airs.rs) ================= */
    {
        finding: 'MS-tool-event', title: 'A tools/call request is one tool_event: input as JSON text, metadata exactly ecosystem, method, server_name and tool_invoked, the ids, never tr_id (airs.rs:228; v3 leaves output out on the request leg, as the recorded tool-input scans did)',
        setup: Object.assign(toolCall(1, { question: 'hi' }, 'ask_wiki_question', { 'Mcp-Session-Id': 'conv-42', 'x-correlation-id': 'tx-42' }),
                             { legs: ['request'], airs: R.answers('allow-tool'), proxyName: 'deepwiki-test', vars: { currentProfile: 'my-security-profile' } }),
        v3: function (r) {
            var b = r.request.scans[0];
            if (!b) { return 'nothing was scanned'; }
            var te = b.contents.length === 1 && b.contents[0].tool_event;
            return and(
                S.check(!!te && same(Object.keys(b.contents[0]), ['tool_event']), 'contents is ' + JSON.stringify(b.contents)),
                S.check(te && same(te.metadata, { ecosystem: 'mcp', method: 'tools/call', server_name: 'deepwiki-test', tool_invoked: 'ask_wiki_question' }), 'metadata is ' + JSON.stringify(te && te.metadata)),
                S.check(te && te.input === '{"question":"hi"}' && (te.output === undefined || te.output === ''), 'input/output are ' + JSON.stringify(te)),
                S.check(te && same(Object.keys(te).filter(function (k) { return k !== 'output'; }).sort(), ['input', 'metadata']), 'the tool event has ' + Object.keys(te || {}).join(', ')),
                S.check(same(b.ai_profile, { profile_name: 'my-security-profile' }), 'ai_profile is ' + JSON.stringify(b.ai_profile)),
                S.check(b.transaction_id === 'tx-42' && b.session_id === 'conv-42' && !has(b, 'tr_id'), 'the ids are ' + JSON.stringify([b.transaction_id, b.session_id, b.tr_id])),
                passed(r.request));
        }
    },
    {
        finding: 'MS-tool-event', title: 'A tools/call reply is one tool_event: the request\'s arguments as input and the result as output, both JSON text strings (airs.rs:228)',
        setup: Object.assign(toolCall(1, { question: 'hi' }, 'ask_wiki_question'), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'),
                                                                                   proxyName: 'deepwiki-test', response: toolResult(1, 'hello') }),
        v3: function (r) {
            var b = r.response && r.response.scans[0], te = b && b.contents.length === 1 && b.contents[0].tool_event;
            return and(S.check(te && typeof te.input === 'string' && typeof te.output === 'string', 'the reply scan is ' + JSON.stringify(b && b.contents)),
                       S.check(te && te.input === '{"question":"hi"}' && te.output === 'hello', 'input/output are ' + JSON.stringify(te)),
                       S.check(te && same(te.metadata, { ecosystem: 'mcp', method: 'tools/call', server_name: 'deepwiki-test', tool_invoked: 'ask_wiki_question' }), 'metadata is ' + JSON.stringify(te && te.metadata)),
                       passed(r.response));
        }
    },
    {
        finding: 'MS-tool-flags', title: 'A tool-input verdict is read as tool_input.<flag> (airs.rs:266 tool_verdict_reads_tool_detections; mask-a24-tool-input, recorded for this tool event)',
        setup: Object.assign(toolCall(5, { text: 'Card ' + C }), { legs: ['request'], airs: R.answers('mask-a24-tool-input') }),
        v3: function (r) {
            var b = r.request.scans[0], d = v(r.request, 'detections');
            return and(S.check(b && b.contents[0].tool_event && b.contents[0].tool_event.input === '{"text":"Card ' + C + '"}', 'the tool input is not the recorded one: ' + JSON.stringify(b && b.contents)),
                       S.check(d === 'tool_input.agent,tool_input.dlp,tool_input.injection', 'detections ' + JSON.stringify(d)), rpcRefused(r.request, -32001, 5));
        }
    },
    {
        finding: 'MS-tool-flags', title: 'A tool-output verdict is read as tool_output.<flag>, and the refusal reads "Response blocked" (airs.rs:266; block-tool-output)',
        setup: Object.assign(toolCall(6, { customer: 'Lauda' }), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'block-tool-output'), proxyName: 'mcp-server',
                                                                  response: toolResult(6, 'Card on file for Lauda: ' + C) }),
        v3: function (r) {
            var d = r.response && v(r.response, 'detections');
            return and(S.check(d === 'tool_output.agent,tool_output.dlp,tool_output.injection', 'detections ' + JSON.stringify(d)), rpcRefused(r.response, -32001, 6),
                       S.check(/^Response blocked by Prisma AIRS security policy\./.test(said(r.response) || ''), 'the refusal says ' + JSON.stringify(said(r.response))));
        }
    },
    {
        finding: 'MS-tool-flags', title: 'With no detection entries, the tool summary\'s flags are read as tool.<flag> (airs.rs:287 tool_verdict_falls_back_to_the_summary; synthetic reply, MuleSoft\'s)',
        setup: Object.assign(toolCall(2, { text: 'hello' }), { legs: ['request'], airs: R.answers(synthetic(MS_TOOL_SUMMARY)) }),
        v3: function (r) { var d = v(r.request, 'detections'); return and(rpcRefused(r.request, -32001, 2), S.check(d === 'tool.injection', 'detections ' + JSON.stringify(d) + ', not "tool.injection"')); }
    },
    {
        finding: 'MS-tool-gate', title: 'A degraded allow on a tool event is a scanner failure: -32003 (airs.rs:298 tool_verdict_degraded_allow_is_incomplete; synthetic reply, MuleSoft\'s)',
        setup: Object.assign(toolCall(3, { text: 'hello' }), { legs: ['request'], airs: R.answers(synthetic(MS_TOOL_DEGRADED)) }),
        v3: function (r) { return and(rpcRefused(r.request, -32003, 3), S.check(hdr(r.request, 'x-airs-kind') === 'failure', 'x-airs-kind ' + hdr(r.request, 'x-airs-kind'))); }
    },
    {
        finding: 'MS-tool-gate', title: 'A 400 on a tool event is content Prisma AIRS refused: -32001, even with failOpen=true (airs.rs:306; v3 counts a 400 as a gap, MuleSoft as a scanner failure)',
        setup: Object.assign(toolCall(13, { text: 'hello' }), { legs: ['request'], airs: R.answers(R.status(400, '{}')), vars: { failOpen: 'true' } }),
        v3: function (r) { return and(rpcRefused(r.request, -32001, 13), S.check(hdr(r.request, 'x-airs-kind') === 'refused', 'x-airs-kind ' + hdr(r.request, 'x-airs-kind'))); }
    },
    {
        finding: 'MS-tool-gate', title: 'An HTML body on a tool event is a scanner failure: -32003 (airs.rs:306 tool_verdict_errors_like_any_scan)',
        setup: Object.assign(toolCall(14, { text: 'hello' }), { legs: ['request'], airs: R.answers(R.status(200, '<html>')) }),
        v3: function (r) { return and(rpcRefused(r.request, -32003, 14), S.check(hdr(r.request, 'x-airs-kind') === 'failure', 'x-airs-kind ' + hdr(r.request, 'x-airs-kind'))); }
    },
    {
        finding: 'MS-tool-gate', title: 'A missing action on a tool event is a scanner failure: -32003 (airs.rs:306 tool_verdict_errors_like_any_scan; synthetic reply)',
        setup: Object.assign(toolCall(15, { text: 'hello' }), { legs: ['request'], airs: R.answers(R.status(200, '{"category":"benign"}')) }),
        v3: function (r) { return and(rpcRefused(r.request, -32003, 15), S.check(hdr(r.request, 'x-airs-kind') === 'failure', 'x-airs-kind ' + hdr(r.request, 'x-airs-kind'))); }
    },

    /* ================= the decision table (decision.rs:32), in v3's rules ================= */
    {
        finding: 'MS-decision', title: 'Decision "allow": both legs pass, unchanged (decision.rs:32)',
        setup: Object.assign(chat(BENIGN), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), response: chatReply(PARIS) }),
        v3: function (r) {
            var m = fwd(r.request), out = r.response && json(r.response.body);
            return and(S.check(r.request.calls.length === 1 && !r.request.fault, 'the request was not scanned and passed'), passed(r.response),
                       S.check(m && m.messages[0].content === BENIGN, 'the request was changed'), S.check(out && out.choices[0].message.content === PARIS, 'the reply was changed'));
        }
    }
]).concat([[{}, 'with applyDlpMasking unset (v3 keeps V2\'s rule; MuleSoft passes it unmasked)'], [{ applyDlpMasking: 'true' }, 'with applyDlpMasking=true']].map(function (t) {
    return {
        finding: 'MS-decision', title: 'Decision "allow + masked": the prompt is masked where the copy fits exactly, ' + t[1] + ' (decision.rs:32; block-dlp-prompt-masked turned into an allow)',
        setup: Object.assign(chat(STORE), { legs: ['request'], airs: R.answers(R.asAllow('block-dlp-prompt-masked')), vars: t[0] }),
        v3: function (r) { var m = fwd(r.request); return and(passed(r.request), S.check(m && m.messages[0].content === STORE_X, 'forwarded ' + JSON.stringify(m && m.messages[0].content))); }
    };
})).concat([
    {
        finding: 'MS-decision', title: 'Decision "allow + masked" on the reply leg: the reply is masked where the copy fits exactly (decision.rs:32; block-dlp-response-masked turned into an allow)',
        setup: Object.assign(chat(ASK), { legs: ['request', 'response'], airs: R.answers('allow-prompt', R.asAllow('block-dlp-response-masked')), response: chatReply(ON_FILE) }),
        v3: function (r) { var out = r.response && json(r.response.body); return and(passed(r.response), S.check(out && out.choices[0].message.content === ON_FILE_X, 'the client got ' + JSON.stringify(out && out.choices[0].message.content))); }
    },
    {
        finding: 'MS-decision', title: 'Decision "allow + masked, streamed": a masked copy for a reply seen as an event stream withholds it, "Response blocked" in the client\'s stream (decision.rs:32; errors.rs:56 dlp_on_stream_reads_as_a_policy_block; block-dlp-response-masked as an allow)',
        setup: Object.assign(chat(ASK, null, { stream: true }), { legs: ['request', 'response'], airs: R.answers('allow-prompt', R.asAllow('block-dlp-response-masked')), response: chatStream(ON_FILE) }),
        v3: function (r) {
            var a = r.response && r.response.scans[0];
            return and(S.check(a && same(a.contents, [{ prompt: ASK, response: ON_FILE }]), 'the reply scan is not the recorded one: ' + JSON.stringify(a && a.contents)),
                       refused(r.response, 'block'), S.check(/text\/event-stream/.test(r.response.contentType || ''), 'the refusal is ' + r.response.contentType + ', not an event stream'),
                       S.check(/^Response blocked by Prisma AIRS security policy\./.test(streamSaid(r.response) || ''), 'the refusal says ' + JSON.stringify(streamSaid(r.response))),
                       S.check(String(r.response.body).indexOf(C) === -1, 'the card reached the client'));
        }
    },
    {
        finding: 'MS-decision', title: 'Decision "block pure dlp + masked, masking on, streamed": a reply seen as an event stream stays blocked (decision.rs:32; block-dlp-response-masked)',
        setup: Object.assign(chat(ASK, null, { stream: true }), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
                                                                  vars: { applyDlpMasking: 'true' }, response: chatStream(ON_FILE) }),
        v3: function (r) { return and(refused(r.response, 'block'), S.check(String(r.response.body).indexOf(C) === -1, 'the card reached the client')); }
    }
]).concat([[R.asAllow('block-dlp-prompt-masked'), {}, 'An allow with a masked copy'], ['block-dlp-prompt-masked', { applyDlpMasking: 'true' }, 'A DLP-only block with applyDlpMasking=true']].map(function (t) {
    return {
        finding: 'MS-decision', title: 'Decision "masked, several fields": ' + t[2] + ' for a prompt that was cut (truncationFailClosed=false) is a block, as it can\'t be written back exactly (decision.rs:32; the newest 60 characters are the recorded text)',
        setup: Object.assign(chat('Hello. ' + STORE), { legs: ['request'], airs: R.answers(t[0]), vars: Object.assign({ maxScanChars: '60', truncationFailClosed: 'false' }, t[1]) }),
        v3: function (r) {
            var q = r.request.scans[0], m = fwd(r.request);
            return and(S.check(q && same(q.contents, [{ prompt: STORE }]), 'the scan was not the newest 60 characters: ' + JSON.stringify(q && q.contents)),
                       refused(r.request, 'block'), S.check(m && m.messages[0].content === 'Hello. ' + STORE, 'the request was rewritten'));
        }
    };
})).concat([
    {
        finding: 'MS-error-body', title: 'Decision "block pure dlp, masking off" blocks; an OpenAI client gets HTTP 200, a chat.completion with the scan id, and the x-airs headers (decision.rs:32; errors.rs:14, in v3\'s refusal style; block-dlp-prompt-masked)',
        setup: Object.assign(chat(STORE), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked') }),
        v3: function (r) {
            var x = r.request, b = json(x.body);
            return and(refused(x, 'block', 'Request blocked by Prisma AIRS security policy. Sensitive data (PII, credentials, secrets) detected. Scan ID: SCAN_ID.'),
                       S.check(x.status === 200 && /application\/json/.test(x.contentType || ''), 'HTTP ' + x.status + ' ' + x.contentType),
                       S.check(b && b.object === 'chat.completion' && b.choices[0].message.role === 'assistant' && b.choices[0].finish_reason === 'stop', 'not a chat.completion: ' + x.body),
                       S.check(hdr(x, 'x-airs-scan-id') === 'SCAN_ID', 'x-airs-scan-id is ' + hdr(x, 'x-airs-scan-id')));
        }
    },
    {
        finding: 'MS-decision', title: 'Decision "block pure dlp, masking off" on the reply leg withholds the reply: "Response blocked" (decision.rs:32; block-dlp-response-masked)',
        setup: Object.assign(chat(ASK), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: chatReply(ON_FILE) }),
        v3: function (r) {
            return and(refused(r.response, 'block', 'Response blocked by Prisma AIRS security policy. Sensitive data (PII, credentials, secrets) detected. Scan ID: SCAN_ID.'),
                       S.check(String(r.response.body).indexOf(C) === -1, 'the card reached the client'));
        }
    },
    {
        finding: 'MS-decision', title: 'Decision "error, onApiError block": no answer from Prisma AIRS (a time-out) refuses the request (decision.rs:32)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers(R.noAnswer('timeout')) }),
        v3: function (r) { return refused(r.request, 'failure', NOT_SCANNED); }
    },
    {
        finding: 'MS-decision', title: 'Decision "error, onApiError block" on the reply leg: no answer withholds the reply and never reuses the prompt\'s verdict (decision.rs:32, response leg; A16)',
        setup: Object.assign(chat(BENIGN), { legs: ['request', 'response'], airs: R.answers('allow-prompt', R.noAnswer('timeout')), response: chatReply(PARIS) }),
        v3: function (r) { return refused(r.response, 'failure', REPLY_NOT_SCANNED); }
    },
    {
        finding: 'MS-error-body', title: 'A scanner failure on the reply leg: an Anthropic client gets HTTP 200 and a message saying the response could not be scanned (errors.rs:14, in v3\'s refusal style)',
        setup: Object.assign(S.anthropic([{ role: 'user', content: BENIGN }]), { legs: ['request', 'response'], airs: R.answers('allow-prompt', R.status(503, '')),
                             response: S.reply({ id: 'msg_1', type: 'message', role: 'assistant', model: 'm', content: [{ type: 'text', text: PARIS }], stop_reason: 'end_turn' }) }),
        v3: function (r) {
            var x = r.response, b = x && json(x.body);
            return and(refused(x, 'failure', REPLY_NOT_SCANNED), S.check(x.status === 200, 'HTTP ' + x.status),
                       S.check(b && b.type === 'message' && b.role === 'assistant' && b.content.length === 1 && b.content[0].type === 'text', 'not an Anthropic message: ' + x.body));
        }
    },
    {
        finding: 'MS-error-body', title: 'Content v3 can\'t inspect: a Gemini client gets HTTP 200 and a candidate saying the request was not forwarded (errors.rs:14, in v3\'s refusal style)',
        setup: Object.assign(S.req(S.P.gemini, 'this is not JSON'), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request, b = json(x.body);
            return and(refused(x, 'refused', 'Prisma AIRS could not inspect this request (its body is not JSON), so it was not forwarded.'),
                       S.check(x.status === 200 && x.calls.length === 0, 'HTTP ' + x.status + ', ' + x.calls.length + ' scans'),
                       S.check(b && b.candidates && b.candidates[0].content.role === 'model', 'not a Gemini reply: ' + x.body));
        }
    },
    {
        finding: 'MS-error-body', title: 'blockStatus=403 forces the status for a client that does not stream; the body stays in its own format (errors.rs:14, v3\'s rule)',
        setup: Object.assign(chat(STORE), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked'), vars: { blockStatus: '403' } }),
        v3: function (r) { var b = json(r.request.body); return and(refused(r.request, 'block'), S.check(r.request.status === 403, 'HTTP ' + r.request.status), S.check(b && b.object === 'chat.completion', 'not a chat.completion: ' + r.request.body)); }
    },
    {
        finding: 'MS-error-body', title: 'An endpoint v3 does not read gets HTTP 403 with an OpenAI-style error (errors.rs:50 unknown_format_gets_the_openai_shape; decision.rs:32 "gap, onScanError block"; type prisma_airs_refused in v3)',
        setup: Object.assign(S.req('/v1/embeddings', { model: 'm', input: BENIGN }), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request, b = json(x.body), e = b && b.error;
            return and(refused(x, 'refused'), S.check(x.status === 403 && x.calls.length === 0, 'HTTP ' + x.status + ', ' + x.calls.length + ' scans'),
                       S.check(e && same(Object.keys(e).sort(), ['code', 'message', 'param', 'type']) && e.param === null && e.type === 'prisma_airs_refused' && e.code === 'prisma_airs_refused', 'not the OpenAI error shape: ' + x.body),
                       S.check(/^Prisma AIRS could not inspect this request/.test((e && e.message) || ''), 'the message is ' + JSON.stringify(e && e.message)));
        }
    },
    {
        finding: 'MS-decision', title: 'Decision "error, onApiError allow": with failOpen=true a scanner failure passes, and the log line says it failed open (decision.rs:32)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers(R.status(500, '')), vars: { failOpen: 'true' } }),
        v3: function (r) { var l = lastLog(r.request); return and(passed(r.request), S.check(l && /^failed open/.test(l.note || ''), 'the log line is ' + JSON.stringify(l))); }
    },
    {
        finding: 'MS-decision', title: 'Decision "error, onApiError allow" on the reply leg: the reply passes unchanged, logged as failed open (decision.rs:32, response leg)',
        setup: Object.assign(chat(BENIGN), { legs: ['request', 'response'], airs: R.answers('allow-prompt', R.status(500, '')), vars: { failOpen: 'true' }, response: chatReply(PARIS) }),
        v3: function (r) {
            var l = lastLog(r.response), out = r.response && json(r.response.body);
            return and(passed(r.response), S.check(out && out.choices[0].message.content === PARIS, 'the reply was changed'), S.check(l && /^failed open/.test(l.note || ''), 'the log line is ' + JSON.stringify(l)));
        }
    },
    {
        finding: 'MS-decision', title: 'Decision "gap, onScanError allow": a prompt over maxScanChars passes unscanned, logged (decision.rs:32)',
        setup: Object.assign(chat(S.filler(150)), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { maxScanChars: '100', onScanError: 'allow' } }),
        v3: function (r) { var l = lastLog(r.request); return and(passed(r.request), S.check(r.request.calls.length === 0, 'it was scanned'), S.check(l && /^gap allowed/.test(l.note || ''), 'the log line is ' + JSON.stringify(l))); }
    },
    {
        finding: 'MS-decision', title: 'Decision "gap, onScanError allow": a 400 from Prisma AIRS (content it refused) passes, logged (decision.rs:32; v3 counts a 400 as a gap)',
        setup: Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers('error-400-prompt-too-long'), vars: { onScanError: 'allow' } }),
        v3: function (r) { var l = lastLog(r.request); return and(passed(r.request), S.check(l && /^gap allowed/.test(l.note || ''), 'the log line is ' + JSON.stringify(l))); }
    },
    {
        finding: 'MS-decision', title: 'Decision "empty": a reply with nothing to scan passes without a scan (decision.rs:32)',
        setup: Object.assign(chat(BENIGN), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
                                            response: S.reply({ choices: [{ index: 0, message: { role: 'assistant', content: null }, finish_reason: 'stop' }] }) }),
        v3: function (r) { return and(passed(r.response), S.check(r.response.calls.length === 0 && v(r.response, 'route') === 'pass', 'the empty reply was scanned, or passed without route pass')); }
    },
    {
        finding: 'MS-batch', title: 'An MCP batch over mcpBatchLimit (9 members; the default is 8) is a gap: refused before any scan, one -32001 per member with an id, in an array, HTTP 200 (decision.rs:114; errors.rs:118)',
        setup: Object.assign(mcp(BATCH9), { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) {
            var x = r.request, b = json(x.body);
            return and(S.check(!!x.fault && x.calls.length === 0, 'the batch was not refused before any scan'), S.check(x.status === 200 && Array.isArray(b) && b.length === 9 && b.every(function (e) { return e.error && e.error.code === -32001 && e.id !== null; }), 'HTTP ' + x.status + ': ' + x.body),
                       S.check(hdr(x, 'x-airs-kind') === 'refused', 'x-airs-kind ' + hdr(x, 'x-airs-kind')));
        }
    },
    {
        finding: 'MS-batch', title: 'An MCP batch over the limit with onScanError=allow passes unscanned, logged (decision.rs:114)',
        setup: Object.assign(mcp(BATCH9), { legs: ['request'], airs: R.answers('allow-tool'), vars: { onScanError: 'allow' } }),
        v3: function (r) { var l = lastLog(r.request); return and(passed(r.request), S.check(r.request.calls.length === 0, 'it was scanned'), S.check(l && /^gap allowed/.test(l.note || ''), 'the log line is ' + JSON.stringify(l))); }
    }
]).concat([
    ['an OpenAI block', function () { return Object.assign(chat(STORE), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked') }); }],
    ['a Responses API scanner failure', function () { return Object.assign(S.responses(BENIGN), { legs: ['request'], airs: R.answers(R.noAnswer()) }); }],
    ['an Anthropic body v3 can\'t read', function () { return Object.assign(S.req(S.P.anthropic, 'not JSON'), { legs: ['request'], airs: R.answers('allow-prompt') }); }],
    ['a Gemini reply block', function () {
        return Object.assign(S.gemini([S.user(ASK)]), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
                                                       response: S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: ON_FILE }] } }] }) });
    }],
    ['an endpoint v3 does not read', function () { return Object.assign(S.req('/v1/embeddings', { model: 'm', input: BENIGN }), { legs: ['request'], airs: R.answers('allow-prompt') }); }],
    ['an MCP block', function () { return Object.assign(toolCall(8, { text: 'Card ' + C }), { legs: ['request'], airs: R.answers('mask-a24-tool-input') }); }],
    ['an MCP scanner failure', function () { return Object.assign(toolCall(8, { text: 'hello' }), { legs: ['request'], airs: R.answers(R.noAnswer()) }); }],
    ['a rejected configuration', function () { return Object.assign(chat(BENIGN), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { failOpen: MARK } }); }]
].map(function (t) {
    return {
        finding: 'MS-no-key', title: 'No refusal carries the key, in its body, headers or log line: ' + t[0] + ' (errors.rs:71 bodies_never_contain_the_key)',
        setup: t[1](),
        v3: function (r) {
            var x = r.response && r.response.fault ? r.response : r.request;
            if (!x.fault) { return 'it was not refused'; }
            var seen = [x.body, JSON.stringify(x.flow.messages.response.headers)].concat(logs(x));
            return S.check(seen.every(function (s) { return String(s).indexOf(KEY) === -1; }), 'the key shows in the refusal or the log line');
        }
    };
})).concat([
    ['an OpenAI client', function () { return chat(BENIGN); }],
    ['an Anthropic client', function () { return S.anthropic([{ role: 'user', content: BENIGN }]); }],
    ['a Gemini client', function () { return S.gemini([S.user(BENIGN)]); }],
    ['an endpoint v3 does not read', function () { return S.req('/v1/embeddings', { model: 'm', input: BENIGN }); }],
    ['an MCP client', function () { return toolCall(9, { text: 'hello' }); }]
].map(function (t) {
    return {
        finding: 'MS-config', title: 'A rejected configuration says so and names the setting, never "could not scan" or the value: ' + t[0] + ' (errors.rs:84 rejected_configuration_has_its_own_message)',
        setup: Object.assign(t[1](), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { failOpen: MARK } }),
        v3: function (r) {
            var m = said(r.request) || '';
            return and(refused(r.request, 'config'), S.check(r.request.calls.length === 0, 'it was scanned'),
                       S.check(/not configured correctly/.test(m) && /failOpen/.test(m) && !/could not scan/.test(m), 'the message is ' + JSON.stringify(m)),
                       S.check(String(r.request.body).indexOf(MARK) === -1, 'the setting\'s value shows in the refusal'));
        }
    };
})).concat([
    {
        finding: 'MS-config', title: 'A rejected configuration is answered in the client\'s own format: a Gemini client gets HTTP 200 and a candidate, not an OpenAI-style 403 (errors.rs:84; v3\'s refusal style, x-airs-kind config)',
        setup: Object.assign(S.gemini([S.user(BENIGN)]), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { failOpen: MARK } }),
        v3: function (r) {
            var x = r.request, b = json(x.body);
            return and(refused(x, 'config'), S.check(x.status === 200, 'HTTP ' + x.status + ', not 200'),
                       S.check(b && b.candidates && /not configured correctly/.test(b.candidates[0].content.parts[0].text), 'not a Gemini reply: ' + x.body));
        }
    },

    /* ================= MCP refusals (errors.rs) ================= */
    {
        finding: 'MS-mcp-refusal', title: 'An MCP block answers the numeric id as sent, code -32001, HTTP 200, JSON, the scan id in the message (errors.rs:101 mcp_refusal_answers_each_id; mask-a24-tool-input)',
        setup: Object.assign(toolCall(7, { text: 'Card ' + C }), { legs: ['request'], airs: R.answers('mask-a24-tool-input') }),
        v3: function (r) {
            var m = said(r.request) || '';
            return and(rpcRefused(r.request, -32001, 7), S.check(/application\/json/.test(r.request.contentType || ''), 'Content-Type ' + r.request.contentType),
                       S.check(/^Request blocked by Prisma AIRS security policy\./.test(m) && /Scan ID: SCAN_ID\.$/.test(m), 'the message is ' + JSON.stringify(m)));
        }
    },
    {
        finding: 'MS-mcp-refusal', title: 'A string id stays a string, and a reply-leg block reads "Response blocked" (errors.rs:101; block-tool-output)',
        setup: Object.assign(toolCall('abc', { customer: 'Lauda' }), { legs: ['request', 'response'], airs: R.answers('allow-tool', 'block-tool-output'), proxyName: 'mcp-server',
                                                                       response: toolResult('abc', 'Card on file for Lauda: ' + C) }),
        v3: function (r) { return and(rpcRefused(r.response, -32001, 'abc'), S.check(/^Response blocked by Prisma AIRS security policy\./.test(said(r.response) || ''), 'the message is ' + JSON.stringify(said(r.response)))); }
    },
    {
        finding: 'MS-mcp-refusal', title: 'A string id that looks like a number ("7") stays a string (errors.rs:101; mask-a24-tool-input)',
        setup: Object.assign(toolCall('7', { text: 'Card ' + C }), { legs: ['request'], airs: R.answers('mask-a24-tool-input') }),
        v3: function (r) { return rpcRefused(r.request, -32001, '7'); }
    },
    {
        finding: 'MS-mcp-refusal', title: 'An id of 0 stays 0, not null (errors.rs:101; mask-a24-tool-input)',
        setup: Object.assign(toolCall(0, { text: 'Card ' + C }), { legs: ['request'], airs: R.answers('mask-a24-tool-input') }),
        v3: function (r) { return rpcRefused(r.request, -32001, 0); }
    },
    {
        finding: 'MS-mcp-refusal', title: 'A refused message with no id (a notification) gets one error with id null and HTTP 403, as MuleSoft answers: there is no id to answer (errors.rs:132 mcp_refusal_without_an_id_uses_null; block-dlp-prompt-masked)',
        // notifications/* params are not scanned (MuleSoft's method table), so the message with no id is a vendor method's.
        setup: Object.assign(mcp(rpc('vendor/note', { note: 'Card on file: ' + C })), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked') }),
        v3: function (r) { var b = json(r.request.body); return and(S.check(r.request.blocked && r.request.status === 403, 'HTTP ' + r.request.status), S.check(b && !Array.isArray(b) && b.id === null && b.error && b.error.code === -32001, 'not one error with id null and -32001: ' + r.request.body)); }
    },
    {
        finding: 'MS-mcp-refusal', title: 'An MCP scanner failure is -32003 with the id, HTTP 200 (errors.rs:143 scanner_failure_is_minus_32003)',
        setup: Object.assign(toolCall(11, { text: 'hello' }), { legs: ['request'], airs: R.answers(R.noAnswer('timeout')) }),
        v3: function (r) { return and(rpcRefused(r.request, -32003, 11), S.check(said(r.request) === NOT_SCANNED, 'the message is ' + JSON.stringify(said(r.request)))); }
    },
    {
        finding: 'MS-mcp-refusal', title: 'A rejected configuration on MCP is -32003 with the id, HTTP 200, not an HTTP 403 (errors.rs:143, errors.rs:154)',
        setup: Object.assign(toolCall(12, { text: 'hello' }), { legs: ['request'], airs: R.answers('allow-tool'), vars: { failOpen: MARK } }),
        v3: function (r) { return and(rpcRefused(r.request, -32003, 12), S.check(/not configured correctly/.test(said(r.request) || ''), 'the message is ' + JSON.stringify(said(r.request)))); }
    }
]).concat([['mask-a24-tool-input', -32001, 'block', 'a block'], [R.status(400, '{}'), -32001, 'refused', 'content Prisma AIRS refused (400)'],
           [R.noAnswer('timeout'), -32003, 'failure', 'a scanner failure']].map(function (t, i) {
    var id = 20 + i;
    return {
        finding: 'MS-mcp-refusal', title: 'MCP refusals are HTTP 200 whatever the kind, and blockStatus=403 does not apply: ' + t[3] + ' (errors.rs:154 the_refusal_status_follows_r2)',
        setup: Object.assign(toolCall(id, { text: 'Card ' + C }), { legs: ['request'], airs: R.answers(t[0]), vars: { blockStatus: '403' } }),
        v3: function (r) { return and(rpcRefused(r.request, t[1], id), S.check(hdr(r.request, 'x-airs-kind') === t[2], 'x-airs-kind ' + hdr(r.request, 'x-airs-kind'))); }
    };
})).concat([
    {
        finding: 'MS-mcp-get', title: 'An MCP GET asking for an event stream gets 405, Allow: POST, DELETE, and a JSON-RPC error with id null telling the client to POST (errors.rs:175 stream_refusal_says_what_to_do)',
        setup: { path: S.P.mcp, request: { verb: 'GET', headers: { Accept: 'text/event-stream', 'Mcp-Session-Id': 'conv-42' }, content: '' }, legs: ['request'], airs: R.answers('allow-tool') },
        v3: function (r) {
            var x = r.request;
            if (!x.fault) { return 'the GET was not refused (route ' + v(x, 'route') + ', no refusal step ran)'; }
            var b = json(x.body), e = b && b.error;
            return and(S.check(x.status === 405 && hdr(x, 'Allow') === 'POST, DELETE', 'HTTP ' + x.status + ', Allow ' + hdr(x, 'Allow')),
                       S.check(b && b.jsonrpc === '2.0' && has(b, 'id') && b.id === null && e && e.code === -32001, 'the body is ' + x.body),
                       S.check(e && /POST/.test(e.message || ''), 'the message does not tell the client to POST: ' + JSON.stringify(e && e.message)));
        }
    },

    /* ================= identity (identity.rs) ================= */
    idCase('MS-app-user', 'app_user is the user header when it is usable (identity.rs:14 app_user_order; v3 has no claim or client-application sources)', { 'x-user-id': 'alice' }, { user: 'alice' }),
    idCase('MS-app-user', 'Without a user header app_user is v3\'s fallback, never blank (identity.rs:14)', {}, { user: 'apigee' }),
    idCase('MS-app-user', 'A user header of 101 characters is skipped, never cut (identity.rs:14)', { 'x-user-id': 'b'.repeat(101) }, { user: 'apigee' }),
    idCase('MS-session', 'The session header comes first, x-session-id before x-claude-code-session-id (identity.rs:26 session_order_and_drop_reason)',
           { 'x-session-id': 'conv-1', 'x-claude-code-session-id': 'cc-1' }, { session: 'conv-1' }),
    idCase('MS-session', 'A too-long session header gives way to the next source (identity.rs:26)', { 'x-session-id': 's'.repeat(150), 'x-claude-code-session-id': 'cc-1' }, { session: 'cc-1' }),
    idCase('MS-session', 'A too-long session header with nothing after it: no session_id (identity.rs:26)', { 'x-session-id': 's'.repeat(150) }, { session: null }),
    idCase('MS-session', 'A non-ASCII session header: no session_id (identity.rs:26)', { 'x-session-id': 'sesión' }, { session: null }),
    idCase('MS-session', 'An empty session header counts as absent (identity.rs:26)', { 'x-session-id': '', 'x-claude-code-session-id': 'cc-1' }, { session: 'cc-1' }),
    idCase('MS-mcp-session', 'On MCP, Mcp-Session-Id comes before the session headers (identity.rs:55 mcp_session_header_comes_first)',
           { 'Mcp-Session-Id': 'mcp-1', 'x-session-id': 'hdr-1', 'x-claude-code-session-id': 'cc-1' }, { session: 'mcp-1' }, true),
    idCase('MS-mcp-session', 'On MCP without Mcp-Session-Id, x-session-id is next (identity.rs:55)', { 'x-session-id': 'hdr-1', 'x-claude-code-session-id': 'cc-1' }, { session: 'hdr-1' }, true),
    idCase('MS-mcp-session', 'On MCP with only x-claude-code-session-id, it is used (identity.rs:55)', { 'x-claude-code-session-id': 'cc-1' }, { session: 'cc-1' }, true),
    idCase('MS-mcp-session', 'On MCP with no session source, no session_id is sent (identity.rs:55)', {}, { session: null }, true),
    idCase('MS-mcp-session', 'An Mcp-Session-Id of 101 characters falls back to x-session-id (identity.rs:63 an_unusable_mcp_session_falls_back)',
           { 'Mcp-Session-Id': S101, 'x-session-id': 'hdr-1' }, { session: 'hdr-1' }, true),
    idCase('MS-mcp-session', 'A non-ASCII Mcp-Session-Id (café) with nothing after it: no session_id (identity.rs:63)', { 'Mcp-Session-Id': 'café' }, { session: null }, true),

    /* ================= the log line (evidence.rs) ================= */
    {
        finding: 'MS-evidence', title: 'One log line per leg holds the transaction id and the scan id, never the prompt, the reply, a header value, the session id, the profile or the key (evidence.rs:8)',
        setup: Object.assign(S.req(S.P.chat, { model: 'm', messages: [{ role: 'user', content: 'Please remember ' + MARK + '-PROMPT.' }] },
                                   { 'x-correlation-id': 'tx-1', 'x-user-id': MARK + '-USER', 'x-session-id': MARK + '-SESSION' }),
                             { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'), vars: { currentProfile: MARK + '-PROFILE' },
                               response: chatReply(MARK + '-REPLY') }),
        v3: function (r) {
            var lines = logs(r.request), parsed = lines.map(json);
            var bad = lines.filter(function (l) { return l.indexOf(MARK) !== -1 || l.indexOf(KEY) !== -1; });
            return and(S.check(r.request.scans[0] && r.request.scans[0].session_id === MARK + '-SESSION', 'the session id was not sent, so the check proves nothing'),
                       S.check(lines.length === 2, lines.length + ' log lines, not one per leg'),
                       S.check(bad.length === 0, 'a log line holds content or a header value: ' + bad.join(' | ').slice(0, 240)),
                       S.check(parsed.every(function (p) { return p && p.transaction_id === 'tx-1' && p.scan_id === 'SCAN_ID'; }), 'the ids are missing: ' + lines.join(' | ')));
        }
    },
    {
        finding: 'MS-evidence', title: 'A block\'s log line names the outcome and the detections, never the prompt (evidence.rs:8; block-dlp-prompt-masked)',
        setup: Object.assign(chat(STORE, { 'x-correlation-id': 'tx-2' }), { legs: ['request'], airs: R.answers('block-dlp-prompt-masked') }),
        v3: function (r) {
            var lines = logs(r.request), l = json(lines[lines.length - 1]);
            return and(S.check(lines.length === 1 && !!l, lines.length + ' log lines'),
                       S.check(lines[0].indexOf(C) === -1 && lines[0].indexOf('Please store') === -1 && lines[0].indexOf('XXXX') === -1, 'the log line holds the prompt: ' + lines[0]),
                       S.check(l && l.outcome === 'block' && l.kind === 'block' && l.detections === 'prompt.dlp' && l.transaction_id === 'tx-2', 'the log line is ' + lines[0]));
        }
    }
]);

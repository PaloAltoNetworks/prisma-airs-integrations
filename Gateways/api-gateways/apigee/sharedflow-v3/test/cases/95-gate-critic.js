'use strict';
/*
 * A completeness review of v3's phase 1, before release, after the coverage (91), fail-closed (92), Apigee-realism (93)
 * and conformance (94) reviews. This file holds what those reviews missed: a format reader detail, a tool_result shape
 * and a masking-leak field that none of their cases touch. GATE-CRIT-*: a gap this review found, fixed since; the case
 * passes when v3 behaves as required. GUARD-CRIT-*: guards, which passed then too (each title says guard).
 *
 * Content is harmless only: plain sentences, the marker AIRSV3-MARKER and the Visa test card number (S.CARD). Each case
 * names the recorded Prisma AIRS reply its ServiceCallout gets (R.answers / R.noAnswer); nothing here decides a verdict
 * from content. Coverage findings are stated as "this field's text is not collected", with the field's path.
 *
 * Scope note (not restated here): the other four reviews already cover the Gemini dual-JSON-name part (COV-17), the
 * nested base64 tool_result decode (94 GATE-NESTED-B64), the Chat logprobs leak on ONE format (COV-09), the MCP
 * single-block content (COV-19), and the custom-tool / audio / citation / reasoning reply fields (COV-05, 06, 11, 13).
 * The three findings below are a different reader branch, a different format's tool_result shape, and the same logprobs
 * leak in the formats COV-09 did not reach.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const M = 'AIRSV3-MARKER';
const MC = M + ' card on file ' + C;

function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }
function state(x) {
    if (!x) { return '(the leg did not run)'; }
    var f = x.flow;
    return '(route=' + f.get('airs3.route') + ' format=' + f.get('airs3.format') + ' outcome=' + f.get('airs3.outcome') +
           ' refuse=' + f.get('airs3.refuse') + ' calls=' + x.calls.length + ' fault=' + (x.fault ? x.fault.policy : '-') + ')';
}
// Request leg: the field's text reached the scan, or v3 refused the request before the model.
function requestCovers(r, text) {
    var q = r.request;
    if (S.has(q, text)) { return true; }
    if (q.blocked && q.calls.length === 0) { return true; }
    return 'not collected: ' + JSON.stringify(text) + ' is not in the request scan ' + JSON.stringify(q.scanned.slice(0, 180)) + ' ' + state(q);
}
// The reply leg's own text, as sent to Prisma AIRS.
function replyScan(r) {
    var x = r.response, s = x && x.scans && x.scans[0], e = s && s.contents && s.contents[0];
    if (!e) { return null; }
    return [typeof e.response === 'string' ? e.response : '', e.tool_event && e.tool_event.output ? String(e.tool_event.output) : ''].join('\n');
}

module.exports = [

    /* ============================ findings (gaps the review found, fixed since) =================================== */

    {
        /*
         * Not covered by 91-94. airs3-fmt-gemini.js part() tested the part's union fields in order -- text first -- and
         * RETURNED after the first one it recognised. So a single part that carried `text` AND a second union field kept
         * only the text; the second field was dropped. Here the second field is `functionResponse` -- a TOOL RESULT, which
         * v3 scans in every turn, always. As with duplicate keys (A20) and dual JSON names (COV-17), v3 and Vertex's proto3
         * oneof backend can resolve a multi-field part differently (L4 found Vertex took the *last* of two `contents`), so
         * the tool result v3 dropped could be the one the model reads. COV-17 is the SAME field under two casings; this is
         * TWO different fields in one part. The same early return dropped `inlineData` after `text`
         * (contents[].parts[].inlineData). part() now reads every field a part carries. airs3-fmt-openai-chat.js
         * contentOf() has the twin (a type:"text" part keeps its text, drops a co-located image_url), but there OpenAI's
         * type discriminator means the model ignores it too, so Gemini was the exposure case.
         */
        finding: 'GATE-CRIT-GEM-MULTIFIELD',
        title: 'Gemini request: a part carrying text AND functionResponse (a tool result) keeps only the text; the functionResponse is not collected (field: contents[].parts[].functionResponse; airs3-fmt-gemini.js part() returned after the first union field)',
        setup: Object.assign(S.gemini([
            S.user('Fetch the stored note.'),
            { role: 'model', parts: [{ functionCall: { name: 'get_note', args: {} } }] },
            { role: 'function', parts: [{ text: 'The note is ready.', functionResponse: { name: 'get_note', response: { note: MC } } }] },
            S.user('Summarise it.')
        ]), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return requestCovers(r, MC); }
    },

    {
        /*
         * Not covered by 91-94. airs3-fmt-anthropic.js blocks() handled tool_result content that is a string or a list;
         * any OTHER shape (a bare {type:"text", text:...} object, a number) fell through and NOTHING was collected -- and
         * nothing failed closed, so the request was scanned WITHOUT the tool result and ALLOWED (calls=1, outcome=allow,
         * the card absent from the scan). Contrast the sibling handler: a top-level message `content` of the same
         * non-string/non-list shape returns unreadable and the request is REFUSED (fail closed). v3 scans every tool
         * result, and content it can't read is refused, not passed; here a tool result's text passed unscanned on a
         * fail-OPEN path, which a lenient gateway can normalise back into a valid array before the model. The tool_result
         * handler now refuses any other shape, as the message handler does.
         * Distinct from COV-19 (MCP single-block content) and 94 GATE-NESTED-B64 (base64 inside a list tool_result).
         */
        finding: 'GATE-CRIT-ANTH-TR-SHAPE',
        title: 'Anthropic request: a tool_result whose content is a bare object (not a string or a list) is silently dropped and the request allowed -- fails OPEN, where a message content of the same shape is refused (field: messages[].content[].content; airs3-fmt-anthropic.js tool_result handler)',
        setup: Object.assign(S.anthropic([
            { role: 'user', content: 'Read the customer note.' },
            { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'read_note', input: {} }] },
            { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: { type: 'text', text: MC } }] }
        ]), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return requestCovers(r, MC); }
    },

    {
        /*
         * Not covered by 91-94. COV-09 found the logprobs unmask leak for ONE format and leg: "Chat Completions reply:
         * choices[].logprobs". It was not Chat-only. On the Responses API the same per-token text sits at
         * output[].content[].logprobs[].token, and airs3-fmt-openai-responses.js did not read it (parts() collected only
         * output_text / refusal). So applyDlpMasking rewrote the output_text (A22 exact write-back) while the identical
         * card digits rode out untouched in logprobs: outcome=mask, the masked "XXXX..." written, and the response body
         * still holding the card digits. The same leak was in Gemini at candidates[].logprobsResult, so a fix scoped to
         * COV-09's Chat field would have left two formats leaking. (The destream/restream path dropped logprobs then, so
         * the leak was the NON-streamed masked reply.) A reply that carries log probabilities is now never masked: the
         * mask becomes a block.
         */
        finding: 'GATE-CRIT-RESP-LOGPROBS',
        title: 'Masked Responses reply: output[].content[].logprobs tokens are not collected, so the client still receives the unmasked card digits (COV-09 found this for Chat only; the same field exists on Responses and Gemini logprobsResult)',
        setup: Object.assign(S.responses('What is the card on file?'), {
            legs: ['request', 'response'], vars: { applyDlpMasking: 'true' }, airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
            response: S.reply({ id: 'resp_95a', object: 'response', created_at: 1794272592, status: 'completed', model: 'gpt-lab',
                output: [{ type: 'message', id: 'msg_95a', status: 'completed', role: 'assistant',
                    content: [{ type: 'output_text', text: 'The card on file is ' + C + '.', annotations: [],
                        logprobs: ['The', ' card', ' on', ' file', ' is', ' 4111', ' 1111', ' 1111', ' 1111', '.'].map(function (t) {
                            return { token: t, logprob: -0.02, bytes: Array.from(Buffer.from(t, 'utf8')), top_logprobs: [] }; }) }] }],
                usage: { input_tokens: 12, output_tokens: 9, total_tokens: 21 } })
        }),
        v3: function (r) {
            var x = r.response;
            if (!x) { return 'the reply leg did not run ' + state(r.request); }
            if (x.blocked) { return true; }                                  // a fix that blocks the unmaskable reply is fine too
            if (x.flow.get('airs3.outcome') !== 'mask') { return 'setup did not reach the masking path (outcome ' + x.flow.get('airs3.outcome') + ')'; }
            return S.check(String(x.body).indexOf('4111') === -1,
                'the masked reply still carries the card digits in logprobs: ' + String(x.body).slice(String(x.body).indexOf('logprobs'), String(x.body).indexOf('logprobs') + 120) + ' ' + state(x));
        }
    },

    /* ============================ regression guards =============================================================== */

    {
        finding: 'GUARD-CRIT-G1',
        title: 'guard: a Gemini part with ONLY functionResponse (no co-located text) has its tool-result text collected (contrast with GATE-CRIT-GEM-MULTIFIELD)',
        setup: Object.assign(S.gemini([
            S.user('Fetch the stored note.'),
            { role: 'model', parts: [{ functionCall: { name: 'get_note', args: {} } }] },
            { role: 'function', parts: [{ functionResponse: { name: 'get_note', response: { note: MC } } }] }
        ]), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return requestCovers(r, MC); }
    },

    {
        finding: 'GUARD-CRIT-G2',
        title: 'guard: an Anthropic tool_result whose content is a LIST of text blocks has its text collected (contrast with GATE-CRIT-ANTH-TR-SHAPE)',
        setup: Object.assign(S.anthropic([
            { role: 'user', content: 'Read the customer note.' },
            { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'read_note', input: {} }] },
            { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: [{ type: 'text', text: MC }] }] }
        ]), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) { return requestCovers(r, MC); }
    },

    {
        finding: 'GUARD-CRIT-G3',
        title: 'guard: a masked Responses reply with NO logprobs leaves no card digits in the client body (isolates the leak to the logprobs field)',
        setup: Object.assign(S.responses('What is the card on file?'), {
            legs: ['request', 'response'], vars: { applyDlpMasking: 'true' }, airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
            response: S.reply({ id: 'resp_95b', object: 'response', created_at: 1794272592, status: 'completed', model: 'gpt-lab',
                output: [{ type: 'message', id: 'msg_95b', status: 'completed', role: 'assistant',
                    content: [{ type: 'output_text', text: 'The card on file is ' + C + '.', annotations: [] }] }],
                usage: { input_tokens: 12, output_tokens: 9, total_tokens: 21 } })
        }),
        v3: function (r) {
            var x = r.response;
            if (!x) { return 'the reply leg did not run ' + state(r.request); }
            if (x.blocked) { return true; }
            return S.check(x.flow.get('airs3.outcome') === 'mask' && String(x.body).indexOf('4111') === -1,
                'the clean masked reply unexpectedly carries the card or did not mask (outcome ' + x.flow.get('airs3.outcome') + ')');
        }
    }
];

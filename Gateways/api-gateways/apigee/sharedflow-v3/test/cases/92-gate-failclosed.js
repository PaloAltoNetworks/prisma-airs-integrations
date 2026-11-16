'use strict';
/*
 * A review of v3's phase 1 for failing closed, before release.
 * Walk sharedflows/default.xml with each step not finishing, each policy failing and each variable missing, on both
 * legs, with failOpen=false and onScanError=block (the defaults). Looking for a leg that continues with no scan and
 * no refusal, a pass that should not be a pass, or a refusal that comes out in the wrong shape; and the de-stream /
 * restream path, masking write-back, and the reply leg after a request-leg refusal or pass.
 *
 * GATE-FC-*: a gap the review found, fixed since; the case passes when v3 behaves as required. GUARD-FC-*: guards,
 * which passed then too and lock in correct fail-closed behaviour (each title says GUARD).
 *
 * Content is harmless only: plain sentences, the marker AIRSV3-MARKER and the Visa test card number (S.CARD). Every
 * case names the recorded Prisma AIRS reply its ServiceCallout gets; nothing here decides a verdict from content.
 *
 * Scope note: the response-leg "JS-Airs3Init did not finish -> reply passes unscanned" fail-open, the count-tokens
 * path skip, the uncollected reply fields, and the promptFeedback-reply-returned-as-JSON case are covered by
 * 91-gate-coverage.js, 93-gate-apigee-realism.js and 94-gate-design.js; this file does not restate them.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const MARK = 'AIRSV3-MARKER';

function chatReply(text) { return S.reply({ id: 'c1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }); }
function raw(path, bodyStr, headers, querystring) { return { path: path, request: { verb: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), content: bodyStr, querystring: querystring || '' } }; }
function ct(x) { return String(x && x.contentType || ''); }

module.exports = [

    /* ===== GATE-FC-1 (finding) ==================================================================================
     * airs3-detect.js ran its request-leg refusals (a gap) BEFORE it set airs3.stream: the oversize check ran before
     * the format was even known, and the duplicate-key / not-JSON / unknown-endpoint gaps ran before the stream kind
     * was set. airs3-respond.js decides the refusal shape from airs3.stream, so a client that sent stream:true (or
     * alt=sse) was refused as application/json instead of the client's own event stream (A30: each streaming client
     * gets its own format; every refusal, a step that didn't finish included, is in the client's format). It failed
     * CLOSED (the request was not forwarded, calls=0), but the streaming SDK that sent the request cannot read an
     * application/json refusal. airs3-detect.js now sets the format and the stream kind before any refusal.
     *
     * Shown with a streamed Chat request carrying duplicate "messages" keys. The same wrong shape hit a streamed
     * Responses body, a Gemini alt=sse call, and -- worse, because the oversize gap preceded the format too -- an
     * oversize MCP request, which then got an OpenAI-style 403 instead of a JSON-RPC error.
     */
    {
        finding: 'GATE-FC-1',
        title: 'A streaming request refused by a detect-time gap (duplicate keys) must come back in the client\'s event-stream shape, not application/json (airs3-detect.js sets airs3.stream before any gap returns)',
        setup: Object.assign(
            raw(S.P.chat, '{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}],"messages":[{"role":"user","content":"My card is ' + C + '."}]}'),
            { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request;
            if (!x.fault) { return 'the duplicate-key streamed request was not refused at all'; }
            return S.check(/text\/event-stream/.test(ct(x)) && /^data: /m.test(String(x.body || '')),
                'the streaming client (stream:true) got a ' + (ct(x) || 'missing') + ' refusal, not its event stream (airs3.stream was "' + x.flow.get('airs3.stream') + '" when airs3-respond.js chose the shape)');
        }
    },

    /* ===== GUARD-FC-A (guard) ===================================================================================
     * Contrast and guard for GATE-FC-1: an init-time refusal (a bad setting value) on the SAME streamed Chat request
     * IS correctly shaped as an event stream, because airs3-detect.js sets airs3.stream before its init-refused branch
     * returns. It showed that GATE-FC-1's defect was specific to the detect-time gaps, and it locks in the correct
     * streaming-refusal shape for configuration refusals.
     */
    {
        finding: 'GUARD-FC-A',
        title: 'GUARD: a configuration refusal on a streamed Chat request is returned as an event stream (contrast with GATE-FC-1)',
        setup: Object.assign(
            S.chat([{ role: 'user', content: MARK }], { stream: true }),
            { legs: ['request'], vars: { failOpen: 'maybe' }, airs: R.answers('allow-prompt') }),   // failOpen=maybe: a value v3 can't read -> config refusal
        v3: function (r) {
            var x = r.request;
            if (!x.fault) { return 'the bad setting did not refuse the request'; }
            return S.check(x.flow.get('airs3.refuse') === 'config' && /text\/event-stream/.test(ct(x)),
                'a config refusal on a streaming client was ' + (ct(x) || 'missing') + ', not an event stream');
        }
    },

    /* ===== GUARD-FC-B (guard) ===================================================================================
     * The reply leg after a request-leg PASS: an empty-body request passes with nothing to scan, and the reply leg
     * must still scan the reply and block the card on its own -- a request-leg pass never carries over to skip the
     * reply (A16: each scan starts clean).
     */
    /* An empty POST to /chat/completions is refused (GATE-R1), so the request with no body here is a GET of a stored
     * chat completion, whose reply v3 reads (GATE-COV-01). */
    {
        finding: 'GUARD-FC-B',
        title: 'GUARD: after a request with no body passes (a GET of a stored chat completion), the reply leg still scans and blocks the card',
        setup: Object.assign(
            { path: '/v1/chat/completions/chatcmpl-stored-1', request: { verb: 'GET', headers: {}, content: '', querystring: '' } },
            { legs: ['request', 'response'], airs: R.answers('block-dlp-response-masked'),
              response: chatReply('The card on file is ' + C + '.') }),
        v3: function (r) {
            return S.check(r.request.route === 'pass' && r.request.calls.length === 0 && r.response && r.response.blocked && r.response.calls.length === 1,
                'the reply was not independently scanned and blocked after the request-leg pass (reply route ' + (r.response && r.response.route) + ')');
        }
    },

    /* ===== GUARD-FC-C (guard) ===================================================================================
     * Masking write-back on the reply leg: the recorded masked copy lines up, so v3 masks the reply; the guard
     * confirms no cleartext card leaves v3 on the masking path (masking only where the masked copy writes back
     * exactly, otherwise block).
     */
    {
        finding: 'GUARD-FC-C',
        title: 'GUARD: reply-leg masking replaces the card in the client\'s reply (no cleartext card leaves v3)',
        setup: Object.assign(
            S.chat([{ role: 'user', content: 'Which card is on file?' }]),
            { legs: ['request', 'response'], vars: { applyDlpMasking: 'true' }, airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
              response: chatReply('The card on file is ' + C + '.') }),
        v3: function (r) {
            if (!r.response) { return 'the reply leg did not run'; }
            var outcome = r.response.flow.get('airs3.outcome');
            var body = String(r.response.flow.messages.response.content);
            return S.check(outcome === 'mask' && body.indexOf(C) === -1, 'the reply still carried the card or did not mask (outcome ' + outcome + ')');
        }
    }
];

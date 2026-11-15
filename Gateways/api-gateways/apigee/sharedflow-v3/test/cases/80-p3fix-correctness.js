'use strict';
/*
 * Phase 3, a second look at the changes made for 75 to 78 (15 Nov 2026): does each one close its finding on every format, leg
 * and setting, and did any of them break phase 1 to 3 behaviour? Each case passes when v3 does what the README, MIGRATION
 * and MuleSoft's policy say. A case that fails today is a finding; cases titled "Guard" pass today and stay.
 *   - P3FIX-COR-PARTS:      never twice now re-scans after a run that didn't enforce, and two FlowCallouts on one reply leg both
 *                           scan. The later run reads the reply as the event stream the earlier run made, and the Chat
 *                           Completions stream reader takes only text deltas: v3's own restream of a reply whose content is a
 *                           list of parts (which the JSON reader reads) carries that list as the delta, so the later run
 *                           finds nothing and passes the reply as "an empty reply", in enforce mode, with no call.
 *   - P3FIX-COR-SRVTOOL:    the same re-scan of an Anthropic reply: v3's restream puts a server tool call whole in its
 *                           content_block_start, and the stream reader takes only deltas for it, so the call's input is
 *                           never scanned.
 *   - P3FIX-COR-RESPDUP:    the same re-scan of a Responses API reply reads the output twice (response.completed and the
 *                           deltas), so a reply over half of maxScanChars, which the first run scanned, is refused as too large.
 *   - P3FIX-COR-TRUNC:      the never-twice mark is set after a run that scanned only part of the text
 *                           (truncationFailClosed=false), so the other kind of run, whose settings refuse such text, skips it.
 *   - P3FIX-COR-REQFMT:     on the request leg, a hook that scans again after the proxy's FlowCallout turned a body's stream
 *                           flag off sees stream:false, so its refusal goes to the streaming client as plain JSON (A30).
 *   - P3FIX-COR-GAPREFUSE:  onScanError=allow now restreams a reply Read let pass; a reply whose shape v3 can't read can't be
 *                           restreamed, so it is withheld as a scanner failure, under a "gap allowed" note.
 *   - P3FIX-COR-MONALLGAP:  monitor mode passes over each MCP scan it can't inspect; when every scan is such a gap the verdict
 *                           never runs, so the line's outcome is empty where it was gap_unenforced.
 *   - P3FIX-COR-MONERR:     monitor mode's late JS-Airs3Restream after a refusal before any verdict also runs for an LLM error
 *                           reply (A31: passed as it is), and Gemini's restream wraps it as an event.
 *   - P3FIX-COR-LATELABEL:  monitor mode's late JS-Airs3Destream that can't turn streaming off renames the outcome Respond
 *                           logged (gap_unenforced) to config_unenforced, beside kind refused.
 *   - P3FIX-COR-STALEOUT:   AM-Airs3Reset now makes a run whose JS-Airs3Init is cut an enforce-mode one, but not its outcome:
 *                           after a monitor-mode run, Respond takes the stale monitored_block for the kind, so the cut leg is
 *                           refused as a block naming the other leg's detections and scan, not as a scanner failure (GATE-R2).
 *   - P3FIX-COR-GUARD:      guards for the changes that hold: a reply-leg cache hit restreamed, airs_hook numbers and booleans.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get.
 */
const crypto = require('crypto');
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const KEY = 'lab-key-for-unit-tests';                                   // test/run.js's Prisma AIRS key
const EP = 'service.api.aisecurity.paloaltonetworks.com';
const PROFILE = { profile_name: 'PROFILE_NAME' };                          // test/run.js's config map profile
const UP = 'https://aiplatform.googleapis.com';                          // target.url as a TargetEndpoint PreFlow reads it
const FC_REQ = { type: 'user-prompt' }, FC_RESP = { type: 'response-prompt' };
const HOOK_REQ = { hookMode: 'request' }, HOOK_RESP = { hookMode: 'response' };
// The config map entry airs_hook; the harness's proxy.basepath is /lab.
function hookMap(settings) { return { airs_hook: JSON.stringify({ routes: ['/lab'], settings: settings || {} }) }; }

function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function line(x) { return x && x.lines && x.lines.length ? x.lines[x.lines.length - 1] : null; }
// The last log line of one leg (a two-leg case's flow holds both legs' lines, and its variables are the last leg's).
function lastLog(x, leg) {
    var l = x && x.flow ? x.flow.logs : [], out = null;
    for (var i = 0; i < l.length; i++) { try { var j = JSON.parse(l[i].line); if (j.leg === leg) { out = j; } } catch (e) { /* not a v3 line */ } }
    return out;
}
function state(x) {
    return !x ? 'the run did not happen' : 'HTTP ' + x.status + ', ' + x.calls.length + ' call(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 140) : ', passed') + ', Content-Type ' + x.contentType;
}
function ask(text) { return S.chat([{ role: 'user', content: text || 'hello' }]); }
function streamAsk(text) { return S.chat([{ role: 'user', content: text || 'hello' }], { stream: true }); }
function chatReply(text) { return S.reply({ id: 'c1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }); }
// A Chat Completions reply whose message content is a list of parts, which the format's JSON reader reads part by part.
function partsReply(text) { return S.reply({ id: 'c1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: [{ type: 'text', text: text }] }, finish_reason: 'stop' }] }); }
function responsesReply(text) {
    return S.reply({ id: 'resp_1', object: 'response', status: 'completed', model: 'm',
                     output: [{ type: 'message', id: 'msg_1', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: text, annotations: [] }] }] });
}
function geminiReply(text) { return S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: text }] }, finishReason: 'STOP', index: 0 }] }); }
function geminiStream(query) { return S.req(S.P.geminiStream, { contents: [S.user('hello')] }, null, query); }
// Gemini's own error reply (no model text in it: A31), as a target whose success.codes count 4xx passes it to the reply leg (L16).
const GEMINI_ERROR = JSON.stringify({ error: { code: 400, message: 'Request contains an invalid argument.', status: 'INVALID_ARGUMENT' } });
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
const MCPH = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
function forwarded(x) { try { return JSON.parse(x.flow.messages.request.content); } catch (e) { return null; } }
function gotStream(x, text) { return !!(x && !x.fault && /event-stream/.test(String(x.contentType)) && String(x.body).indexOf(text) !== -1); }
function vcKey(leg, contents) {
    var parts = ['airs3-vc-1', KEY, EP, JSON.stringify(PROFILE), leg, '100000', 'true', JSON.stringify(contents)];
    return 'airs3-verdict-' + crypto.createHash('sha256').update(parts.map(function (p) { return p.length + ':' + p; }).join(''), 'utf8').digest('hex');
}

module.exports = [
    /* ---------------- a later run reads the event stream an earlier run made ---------------- */
    {
        finding: 'P3FIX-COR-PARTS',
        title: 'airs_hook in monitor mode, a stream:true chat whose reply content is a list of text parts holding the test card: the post-target hook logs a monitored block and puts the reply back into the client\'s stream; the proxy\'s own enforce-mode reply-leg FlowCallout must scan that text and refuse it, not pass it as "an empty reply" with no call',
        setup: Object.assign(streamAsk(), { kvm: hookMap({ enforcementMode: 'monitor' }), response: partsReply('Card on file: ' + C),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'block-dlp-response-masked', 'block-dlp-response-masked') }),
        v3: function (r) {
            var h = r.runs[1], f = r.runs[2], lh = line(h);
            if (!gotStream(h, C) || !lh || lh.outcome !== 'monitored_block') { return 'precondition: the hook did not log a monitored block and pass the reply as the client\'s stream: ' + state(h) + ' ' + JSON.stringify(lh); }
            return S.check(f && f.blocked && f.calls.length === 1 && String(f.body).indexOf(C) === -1,
                'the card reached the client past the enforce-mode FlowCallout: ' + state(f) + ' ' + JSON.stringify(line(f)));
        }
    },
    {
        finding: 'P3FIX-COR-PARTS',
        title: 'Two FlowCallouts on one reply leg (both scan), the first with enforcementMode=monitor as its parameter, the second enforce: a stream:true chat whose reply content is a list of parts holding the test card must be refused by the second, not passed as "an empty reply" (it was withheld before the second run left event-stream replies as they are)',
        setup: Object.assign(streamAsk(), { response: partsReply('Card on file: ' + C),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: { type: 'response-prompt', enforcementMode: 'monitor' } },
                   { leg: 'response', params: { type: 'response-prompt', enforcementMode: 'enforce' } }],
            airs: R.answers('allow-prompt', 'block-dlp-response-masked', 'block-dlp-response-masked') }),
        v3: function (r) {
            var a = r.runs[1], b = r.runs[2];
            if (!gotStream(a, C)) { return 'precondition: the first FlowCallout did not pass the reply as the client\'s stream: ' + state(a); }
            return S.check(b && b.blocked && String(b.body).indexOf(C) === -1, 'the enforce-mode FlowCallout passed the card: ' + state(b) + ' ' + JSON.stringify(line(b)));
        }
    },
    {
        finding: 'P3FIX-COR-PARTS',
        title: 'Guard: two FlowCallouts on one reply leg of a stream:true chat whose reply content is a string: both scan, and the client gets its stream once, unchanged by the second',
        setup: Object.assign(streamAsk(), { response: chatReply('Hi there.'),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: FC_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'allow-prompt-response', 'allow-prompt-response') }),
        v3: function (r) {
            var a = r.runs[1], b = r.runs[2];
            return S.check(a && a.calls.length === 1 && gotStream(a, 'Hi there.') && b && b.calls.length === 1 && gotStream(b, 'Hi there.') && b.body === a.body,
                'not scanned twice and streamed once: ' + state(a) + ' | ' + state(b));
        }
    },
    {
        finding: 'P3FIX-COR-SRVTOOL',
        title: 'airs_hook in monitor mode, an Anthropic stream:true call whose reply holds a server tool call (web_search, its query the marker): the proxy\'s own reply-leg FlowCallout, reading the stream the hook made, scans the tool call\'s input as the hook\'s JSON read did',
        setup: Object.assign(S.anthropic([{ role: 'user', content: 'hello' }], { stream: true }), { kvm: hookMap({ enforcementMode: 'monitor' }),
            response: S.reply({ id: 'msg_1', type: 'message', role: 'assistant', model: 'm', stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 1 },
                                content: [{ type: 'server_tool_use', id: 'srvtoolu_80a', name: 'web_search', input: { query: M } }, { type: 'text', text: 'Hi.' }] }),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'allow-prompt-response', 'allow-prompt-response') }),
        v3: function (r) {
            var h = r.runs[1], f = r.runs[2];
            if (!h || h.calls.length !== 1 || !S.has(h, M) || !gotStream(h, M)) { return 'precondition: the hook did not scan the tool call and pass the stream: ' + state(h); }
            return S.check(f && f.calls.length === 1 && S.has(f, M), 'the FlowCallout\'s scan left the tool call\'s input out: ' + state(f) + ', scanned "' + (f ? f.scanned : '') + '"');
        }
    },
    {
        finding: 'P3FIX-COR-RESPDUP',
        title: 'airs_hook in monitor mode, both runs with maxScanChars=100, a Responses API stream:true call whose 60-character reply the hook scans and puts back into the client\'s stream: the proxy\'s own reply-leg FlowCallout scans it once and passes it, not refuses it as larger than 100 characters',
        setup: Object.assign(S.responses('hello', { stream: true }), { vars: { maxScanChars: '100' }, kvm: hookMap({ enforcementMode: 'monitor', maxScanChars: '100' }),
            response: responsesReply(S.filler(60)),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'allow-prompt-response', 'allow-prompt-response') }),
        v3: function (r) {
            var h = r.runs[1], f = r.runs[2], lh = line(h);
            if (!h || h.fault || h.calls.length !== 1 || !lh || lh.chars !== '60') { return 'precondition: the hook did not scan the 60 characters and pass: ' + state(h) + ' ' + JSON.stringify(lh); }
            return S.check(f && !f.fault && f.calls.length === 1, 'the FlowCallout refused a reply the same limit let through: ' + state(f) + ' ' + JSON.stringify(line(f)));
        }
    },

    /* ---------------- never twice: what marks a leg ---------------- */
    {
        finding: 'P3FIX-COR-TRUNC',
        title: 'Reply leg: the post-target hook (airs_hook truncationFailClosed=false, maxScanChars=60) scans only the first 60 characters of a reply with the test card after them; the proxy\'s own reply-leg FlowCallout (maxScanChars=60, truncationFailClosed unset, so such a reply is refused) must not skip it as already scanned',
        setup: Object.assign(ask(), { vars: { maxScanChars: '60' }, kvm: hookMap({ maxScanChars: '60', truncationFailClosed: 'false' }), response: chatReply(S.filler(200) + ' ' + C),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'allow-prompt-response', 'block-dlp-response-masked') }),
        v3: function (r) {
            var h = r.runs[1], f = r.runs[2], lh = line(h);
            if (!h || h.fault || !lh || !/scanned the first 60/.test(lh.note)) { return 'precondition: the hook did not pass the reply on a cut scan: ' + state(h) + ' ' + JSON.stringify(lh); }
            return S.check(f && f.fault && String(f.body).indexOf(C) === -1, 'the FlowCallout passed a reply only partly scanned: ' + state(f) + ' ' + JSON.stringify(line(f)));
        }
    },

    /* ---------------- the request leg scanned again after streaming was turned off ---------------- */
    {
        finding: 'P3FIX-COR-REQFMT',
        title: 'A stream:true chat; the proxy\'s own request-leg FlowCallout (enforcementMode=monitor) logs a block and turns streaming off; the pre-target hook (enforce) scans the leg again and refuses it: the refusal goes back in the client\'s stream format (A30), not as plain JSON',
        setup: Object.assign(streamAsk(M), { kvm: hookMap({}), vars: { enforcementMode: 'monitor' },
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }], airs: R.answers('block-injection-agent-prompt', 'block-injection-agent-prompt') }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1], la = line(a);
            if (!a || a.fault || !la || la.outcome !== 'monitored_block' || (forwarded(a) || {}).stream !== false) { return 'precondition: the FlowCallout did not log a monitored block with streaming off: ' + state(a) + ' ' + JSON.stringify(la); }
            return S.check(b && b.blocked && /text\/event-stream/.test(String(b.contentType)), 'the hook\'s refusal is not in the client\'s stream format: ' + state(b));
        }
    },
    {
        finding: 'P3FIX-COR-REQFMT',
        title: 'Guard: the same with a Gemini alt=sse call (its stream named by the path): the hook\'s refusal is one Gemini event',
        setup: Object.assign(geminiStream('alt=sse'), { kvm: hookMap({}), vars: { enforcementMode: 'monitor', 'target.url': UP },
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }], airs: R.answers('block-injection-agent-prompt', 'block-injection-agent-prompt') }),
        v3: function (r) { var b = r.runs[1]; return S.check(b && b.blocked && /text\/event-stream/.test(String(b.contentType)) && /^data: /.test(String(b.body)), 'not refused as a Gemini event: ' + state(b)); }
    },
    {
        finding: 'P3FIX-COR-REQFMT',
        title: 'Guard: a Gemini alt=sse call with another query parameter; the proxy\'s own request-leg FlowCallout (monitor) turns streaming off, then the pre-target hook (enforce) scans again and passes: target.url is rewritten once (:generateContent, the other parameter kept once, no alt), and the reply goes back as the client\'s stream',
        setup: Object.assign(geminiStream('alt=sse&foo=1'), { kvm: hookMap({}), vars: { enforcementMode: 'monitor', 'target.url': UP }, response: geminiReply('Hi.'),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }, { leg: 'response', params: HOOK_RESP }],
            airs: R.answers('allow-prompt', 'allow-prompt', 'allow-prompt-response') }),
        v3: function (r) {
            var b = r.runs[1], c = r.runs[2], t = b ? String(b.flow.get('target.url') || '') : '';
            return S.check(b && !b.fault && b.calls.length === 1 && t === UP + S.P.gemini + '?foo=1' && gotStream(c, 'Hi.'),
                'target.url ' + t + ' | ' + state(b) + ' | ' + state(c));
        }
    },

    /* ---------------- onScanError=allow on a reply that can't be put back into a stream ---------------- */
    {
        finding: 'P3FIX-COR-GAPREFUSE',
        title: 'onScanError=allow, a stream:true chat whose de-streamed reply has no choices list (a shape v3 can\'t read): the reply passes unscanned, logged "gap allowed", as onScanError=allow says; it is not withheld as a scanner failure under that note',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { onScanError: 'allow' },
            response: S.reply({ id: 'c1', object: 'chat.completion', model: 'm' }), airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var q = r.request, x = r.response, l = lastLog(x, 'response');
            if (!q || q.fault || (forwarded(q) || {}).stream !== false) { return 'precondition: the request was not passed with streaming off: ' + state(q); }
            return S.check(x && !x.fault && l && /gap allowed/.test(l.note), 'withheld under onScanError=allow: ' + state(x) + ' ' + JSON.stringify(l));
        }
    },

    /* ---------------- monitor mode's log line ---------------- */
    {
        finding: 'P3FIX-COR-MONALLGAP',
        title: 'Monitor mode, an MCP batch of two tool calls, each over maxScanChars (enforce mode refuses the batch): forwarded, and the line names what enforce mode would have done, gap_unenforced, not an empty outcome',
        setup: Object.assign(S.req(S.P.mcp, [call(1, S.filler(200)), call(2, S.filler(200))], MCPH), { legs: ['request'], vars: { enforcementMode: 'monitor', maxScanChars: '60' },
            airs: R.answers('allow-tool') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x, 'request');
            return S.check(x && !x.fault && l && l.outcome === 'gap_unenforced', 'not logged gap_unenforced: ' + state(x) + ' ' + JSON.stringify(l));
        }
    },
    {
        finding: 'P3FIX-COR-MONALLGAP',
        title: 'Guard: monitor mode, one MCP tool call over maxScanChars: forwarded, logged gap_unenforced',
        setup: Object.assign(S.req(S.P.mcp, call(1, S.filler(200)), MCPH), { legs: ['request'], vars: { enforcementMode: 'monitor', maxScanChars: '60' }, airs: R.answers('allow-tool') }),
        v3: function (r) { var x = r.request, l = lastLog(x, 'request'); return S.check(x && !x.fault && l && l.outcome === 'gap_unenforced', 'not logged gap_unenforced: ' + state(x) + ' ' + JSON.stringify(l)); }
    },
    {
        finding: 'P3FIX-COR-LATELABEL',
        title: 'Monitor mode, a Gemini alt=sse call from the ProxyEndpoint (no target.url) whose prompt is over maxScanChars: enforce mode refuses it as content it can\'t inspect, so the line says gap_unenforced (kind refused), not config_unenforced from the late de-stream step',
        setup: Object.assign(S.req(S.P.geminiStream, { contents: [S.user(S.filler(300))] }, null, 'alt=sse'), { legs: ['request'], vars: { enforcementMode: 'monitor', maxScanChars: '100' },
            airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x, 'request');
            return S.check(x && !x.fault && l && l.outcome === 'gap_unenforced' && l.kind === 'refused', 'the line names another outcome: ' + JSON.stringify(l));
        }
    },

    /* ---------------- monitor mode changes nothing the client gets ---------------- */
    {
        finding: 'P3FIX-COR-MONERR',
        title: 'Monitor mode with a setting v3 can\'t read (maxScanChars abc), a Gemini alt=sse call (streaming turned off), and Gemini\'s HTTP 400 error reply on a target whose success.codes count 4xx: the error reaches the client as Gemini sent it (A31), not wrapped as an event',
        setup: Object.assign(geminiStream('alt=sse'), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', maxScanChars: 'abc', 'target.url': UP },
            response: { status: 400, headers: { 'Content-Type': 'application/json' }, content: GEMINI_ERROR } }),
        v3: function (r) {
            var q = r.request, x = r.response, lq = lastLog(q, 'request');
            if (!q || q.fault || !lq || lq.outcome !== 'config_unenforced') { return 'precondition: the request leg was not logged config_unenforced and passed: ' + state(q); }
            return S.check(x && !x.fault && x.status === 400 && x.body === GEMINI_ERROR && /application\/json/.test(String(x.contentType)),
                'monitor mode changed the error reply: ' + state(x) + ', body ' + String(x && x.body).slice(0, 120));
        }
    },
    {
        finding: 'P3FIX-COR-MONERR',
        title: 'Guard: enforce mode, valid settings, the same call and error reply: it reaches the client as Gemini sent it, logged "a non-2xx reply is not scanned"',
        setup: Object.assign(geminiStream('alt=sse'), { legs: ['request', 'response'], vars: { 'target.url': UP }, airs: R.answers('allow-prompt'),
            response: { status: 400, headers: { 'Content-Type': 'application/json' }, content: GEMINI_ERROR } }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && !x.fault && x.status === 400 && x.body === GEMINI_ERROR && /non-2xx/.test(v(x, 'logNote')), 'the error reply was changed: ' + state(x));
        }
    },

    /* ---------------- a run whose JS-Airs3Init is cut, after a monitor-mode run ---------------- */
    {
        // A cut at Init's first statement, before it clears the leg's variables (S.cutInit, set just before the reply leg), as 75's STALE guard does.
        finding: 'P3FIX-COR-STALEOUT',
        title: 'A proxy that monitors prompts and enforces replies: the request leg logs a monitored block; the reply leg\'s JS-Airs3Init is cut before it clears the leg\'s variables: refused as a scanner failure (GATE-R2), not as a block that names the prompt\'s detections and the request leg\'s scan',
        setup: Object.assign(S.chat([{ role: 'user', content: M }]), { legs: ['request', 'response'],
            params: { request: { enforcementMode: 'monitor' }, response: { enforcementMode: 'enforce' } },
            beforeResponse: S.cutInit,
            airs: R.answers('block-injection-agent-prompt', 'allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) {
            var q = r.request, x = r.response, lq = lastLog(q, 'request'), m = x && x.flow.messages.response;
            if (!q || q.fault || !lq || lq.outcome !== 'monitored_block') { return 'precondition: the request leg was not logged as a monitored block: ' + state(q); }
            var kind = m ? m.header('x-airs-kind') : null;
            return S.check(x && x.blocked && v(x, 'doneInit') !== 'true' && kind === 'failure' && !/blocked by Prisma AIRS/.test(String(x.body)),
                'refused as ' + kind + ' (doneInit ' + v(x, 'doneInit') + '): ' + state(x));
        }
    },

    /* ---------------- guards for the other changes ---------------- */
    {
        finding: 'P3FIX-COR-GUARD',
        title: 'Guard: a stream:true chat, the reply leg answered from the verdict cache (its own lookup, after its own keys): no call, logged cached 1, and the reply goes back as the client\'s stream',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { verdictCacheTtlS: '60' }, response: chatReply('Hi there.'),
            cache: (function () { var c = {}; c[vcKey('response', [{ prompt: 'hello', response: 'Hi there.' }])] = 'scan-of-hi'; return c; })(),
            airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var q = r.request, x = r.response, l = lastLog(x, 'response');
            return S.check(q && q.calls.length === 1 && x && x.calls.length === 0 && x.cachedScans === 1 && l && l.cached === 1 && l.scan_id === 'scan-of-hi' && gotStream(x, 'Hi there.'),
                'not answered from the cache and restreamed: ' + state(q) + ' | ' + state(x) + ' ' + JSON.stringify(l));
        }
    },
    {
        finding: 'P3FIX-COR-GUARD',
        title: 'Guard: hook mode, airs_hook settings written as JSON numbers and booleans (maxScanChars 60, truncationFailClosed false) are read as written: a 200-character prompt is scanned in its newest 60 characters',
        setup: Object.assign(ask(S.filler(200)), { kvm: hookMap({ maxScanChars: 60, truncationFailClosed: false }), runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.runs[0], l = line(x);
            return S.check(x && !x.fault && x.calls.length === 1 && l && l.chars === '60' && /scanned the newest 60/.test(l.note), 'not read as written: ' + state(x) + ' ' + JSON.stringify(l));
        }
    }
];

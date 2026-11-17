'use strict';
/*
 * The review of phase 3's fixes, completeness lens (15 Nov 2026): what the fixes for 75 to 78 left half done, and what
 * one of them broke.
 *   - P3FIX-CMP-TRUNC: never twice now marks a leg only when a run "enforced a verdict on all of it" (airs3-verdict.js sets
 *     airs3.judged), and the README promises that a run that let content pass unscanned leaves the leg to the other run,
 *     "so the stricter of the two holds". A run that scanned only part of the leg under truncationFailClosed=false, which
 *     the README's Settings list among the settings that let content pass unscanned, still marks it: readGap is set for an
 *     MCP part passed over, never for a cut. So the other run's stricter size rule is skipped, on either leg.
 *   - P3FIX-CMP-RESCAN: a run that doesn't judge the leg (here airs_hook in monitor mode, the README's first rollout) still
 *     puts the reply back into the client's stream, so the proxy's own reply-leg FlowCallout then reads an event stream,
 *     which v3 never masks: an allow with a masked copy, which the proxy masks with no hook, becomes a refusal. Monitor mode
 *     is to change nothing the client receives (decision.rs, airs3-respond.js).
 *   - P3FIX-CMP-MONGAP: monitor mode, an MCP leg whose every part is a gap. Read passes it with no verdict, so the line's
 *     outcome is empty, where one gap with a clean rest (P3GATE-FIX-MONGAP) and one scan over the limit log gap_unenforced:
 *     monitor mode logs what enforce mode would have done, and enforce mode refuses this leg.
 *   - P3FIX-CMP-READGAP (a guard): AM-Airs3Reset's reset of airs3.readGap is the only one (JS-Airs3Init's clear list
 *     doesn't hold it), and no other case fails when it is removed: the reply leg then takes the request leg's gap for its
 *     own, logged gap_unenforced, and never counts as judged.
 *   - P3FIX-CMP-GAPSTREAM: Read's gap-allow now asks for the reply to go back into the client's stream (AIRS3.streamNeeds).
 *     A de-streamed reply that is a gap because the reader can't read it can't be put back, so JS-Airs3Respond refuses it as
 *     a scanner failure ("could not scan"), though onScanError=allow lets content v3 can't inspect pass, and the leg's line
 *     says "gap allowed". Before, it passed.
 * Guards pin the other side of each. The only marked text is AIRSV3-MARKER and the test card; each case names the recorded
 * replies its scans get.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const M = 'AIRSV3-MARKER';
const FC_REQ = { type: 'user-prompt' }, FC_RESP = { type: 'response-prompt' };
const HOOK_REQ = { hookMode: 'request' }, HOOK_RESP = { hookMode: 'response' };
function hookMap(settings) { return { airs_hook: JSON.stringify({ routes: ['/lab'], settings: settings || {} }) }; }   // the harness's proxy.basepath is /lab

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
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 160) : ', passed') + ', Content-Type ' + x.contentType;
}
function ask(text) { return S.chat([{ role: 'user', content: text || 'hello' }]); }
function streamAsk(text) { return S.chat([{ role: 'user', content: text || 'hello' }], { stream: true }); }
function chatReply(text) { return S.reply({ id: 'c1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
const MCPH = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
function forwarded(x) { try { return JSON.parse(x.flow.messages.request.content); } catch (e) { return null; } }
function scannedText(x) { return x ? x.scanned : ''; }

module.exports = [
    /* ---------------- never twice: a scan of part of the leg is not a verdict on all of it ---------------- */
    {
        finding: 'P3FIX-CMP-TRUNC',
        title: 'Reply leg: the post-target hook (airs_hook truncationFailClosed=false, maxScanChars=60) scans only the first 60 characters of a reply that carries the test card further on; the proxy\'s own reply-leg FlowCallout (maxScanChars=60, truncationFailClosed unset, so it refuses a reply over the limit) still judges the leg with its own settings, so the card is withheld',
        setup: Object.assign(ask(), { vars: { maxScanChars: '60' }, kvm: hookMap({ maxScanChars: '60', truncationFailClosed: 'false' }),
            response: chatReply(S.filler(120) + ' Card on file: ' + C),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'allow-prompt-response') }),
        v3: function (r) {
            var h = r.runs[2], f = r.runs[3], lh = line(h);
            if (!h || h.fault || h.calls.length !== 1 || !lh || !/scanned the first 60 characters/.test(lh.note) || scannedText(h).indexOf(C) !== -1) {
                return 'precondition: the hook did not scan only the reply\'s first 60 characters and pass it: ' + state(h) + ' ' + JSON.stringify(lh);
            }
            return S.check(f && f.fault && String(f.body).indexOf(C) === -1,
                'the proxy\'s FlowCallout passed a reply the hook scanned only in part ("' + (line(f) || {}).note + '"), so the card reached the client: ' + state(f));
        }
    },
    {
        finding: 'P3FIX-CMP-TRUNC',
        title: 'Request leg: the proxy\'s own FlowCallout (truncationFailClosed=false, maxScanChars=60, as the README advises for Claude Code) scans the newest 60 characters of a prompt that carries the test card before them; the pre-target hook (airs_hook maxScanChars=60, truncationFailClosed unset) then judges the leg with its own settings and refuses it, so the card never reaches the model',
        setup: Object.assign(ask('Card on file: ' + C + '. ' + S.filler(120)), { vars: { maxScanChars: '60', truncationFailClosed: 'false' }, kvm: hookMap({ maxScanChars: '60' }),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1], la = line(a);
            if (!a || a.fault || a.calls.length !== 1 || !la || !/scanned the newest 60 characters/.test(la.note) || scannedText(a).indexOf(C) !== -1) {
                return 'precondition: the FlowCallout did not scan only the newest 60 characters and pass the prompt: ' + state(a) + ' ' + JSON.stringify(la);
            }
            return S.check(b && b.fault && b.calls.length === 0,
                'the hook passed a leg the FlowCallout scanned only in part ("' + (line(b) || {}).note + '"), so the card reached the model: ' + state(b));
        }
    },
    {
        finding: 'P3FIX-CMP-TRUNC',
        title: 'Guard: the reply leg\'s whole text scanned and allowed by the post-target hook (no cut) still marks the leg, so the proxy\'s own reply-leg FlowCallout passes it with no second call, logged',
        setup: Object.assign(ask(), { vars: { maxScanChars: '60' }, kvm: hookMap({ maxScanChars: '60' }), response: chatReply('Hi there.'),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'allow-prompt-response') }),
        v3: function (r) {
            var h = r.runs[1], f = r.runs[2], lf = line(f);
            if (!h || h.fault || h.calls.length !== 1) { return 'precondition: the hook did not scan and pass the reply: ' + state(h); }
            return S.check(f && !f.fault && f.calls.length === 0 && lf && /already scanned on this leg by the flow hook/.test(lf.note),
                'the FlowCallout did not pass a leg the hook judged whole: ' + state(f) + ' ' + JSON.stringify(lf));
        }
    },

    /* ---------------- never twice: a monitor-mode hook run changes what the proxy's own FlowCallout can do ---------------- */
    {
        finding: 'P3FIX-CMP-RESCAN',
        title: 'airs_hook in monitor mode (a first rollout of the hooks), a stream:true chat to a listed proxy with its own FlowCallouts, a reply Prisma AIRS allows with a masked copy: the client still gets the masked reply in its stream format, as it does with no hook; the monitor-mode hook does not turn the proxy\'s mask into a refusal',
        setup: Object.assign(streamAsk('Which card is on file?'), { kvm: hookMap({ enforcementMode: 'monitor' }), response: chatReply('The card on file is ' + C + '.'),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', R.asAllow('block-dlp-response-masked')) }),
        v3: function (r) {
            var h = r.runs[2], f = r.runs[3], lh = line(h);
            if (!h || h.fault || !lh || lh.outcome !== 'mask_not_applied') { return 'precondition: the hook did not log mask_not_applied and pass: ' + state(h) + ' ' + JSON.stringify(lh); }
            return S.check(f && !f.fault && /event-stream/.test(String(f.contentType)) && String(f.body).indexOf('XXXXXXXXXXXXXXXXXXX') !== -1 && String(f.body).indexOf(C) === -1,
                'with the monitor-mode hook on, the client no longer gets the masked reply (the FlowCallout logged "' + (line(f) || {}).note + '"): ' + state(f));
        }
    },
    {
        finding: 'P3FIX-CMP-RESCAN',
        title: 'Guard: no hook, the same proxy and exchange: its FlowCallouts mask the reply and send it back in the client\'s stream format',
        setup: Object.assign(streamAsk('Which card is on file?'), { response: chatReply('The card on file is ' + C + '.'),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: FC_RESP }], airs: R.answers('allow-prompt', R.asAllow('block-dlp-response-masked')) }),
        v3: function (r) {
            var f = r.runs[1];
            return S.check(f && !f.fault && /event-stream/.test(String(f.contentType)) && String(f.body).indexOf('XXXXXXXXXXXXXXXXXXX') !== -1 && String(f.body).indexOf(C) === -1,
                'the masked reply was not sent back in the client\'s stream format: ' + state(f));
        }
    },

    /* ---------------- monitor mode: an MCP leg whose every part is a gap ---------------- */
    {
        finding: 'P3FIX-CMP-MONGAP',
        title: 'Monitor mode, an MCP batch whose two members are both over maxScanChars: forwarded with no call and logged gap_unenforced, what enforce mode would have done (it refuses the batch), as one gap with a clean rest and one scan over the limit are logged',
        setup: Object.assign(S.req(S.P.mcp, [call(1, S.filler(200)), call(2, S.filler(150) + ' ' + M)], MCPH), { legs: ['request'], vars: { enforcementMode: 'monitor', maxScanChars: '60' },
            airs: R.answers('allow-tool') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x, 'request');
            if (!x || x.fault || x.calls.length !== 0) { return 'precondition: the batch was not forwarded with no call: ' + state(x); }
            return S.check(l && l.outcome === 'gap_unenforced' && /gap not enforced/.test(l.note), 'not logged as a gap monitor mode did not enforce: ' + JSON.stringify(l));
        }
    },
    {
        finding: 'P3FIX-CMP-MONGAP',
        title: 'Guard: enforce mode, the same batch: refused with no call, as content v3 can\'t inspect',
        setup: Object.assign(S.req(S.P.mcp, [call(1, S.filler(200)), call(2, S.filler(150) + ' ' + M)], MCPH), { legs: ['request'], vars: { maxScanChars: '60' },
            airs: R.answers('allow-tool') }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && x.calls.length === 0 && /-32001/.test(String(x.body)), 'not refused as content v3 can\'t inspect: ' + state(x)); }
    },
    {
        finding: 'P3FIX-CMP-MONGAP',
        title: 'Guard: monitor mode, one chat prompt over maxScanChars: forwarded with no call, logged gap_unenforced',
        setup: Object.assign(ask(S.filler(200)), { legs: ['request'], vars: { enforcementMode: 'monitor', maxScanChars: '60' }, airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request, l = lastLog(x, 'request'); return S.check(x && !x.fault && x.calls.length === 0 && l && l.outcome === 'gap_unenforced', 'not logged gap_unenforced: ' + state(x) + ' ' + JSON.stringify(l)); }
    },

    {
        finding: 'P3FIX-CMP-READGAP',
        title: 'Guard: monitor mode, an MCP batch whose first member is over maxScanChars (the request leg logs gap_unenforced) and whose reply Prisma AIRS allows whole: the reply leg logs allow, not gap_unenforced, since its own Read passed nothing over (AM-Airs3Reset clears readGap on every leg; JS-Airs3Init does not)',
        setup: Object.assign(S.req(S.P.mcp, [call(1, S.filler(200)), call(2, 'hello')], MCPH), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', maxScanChars: '60' },
            response: S.reply([{ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'ok' }] } }, { jsonrpc: '2.0', id: 2, result: { content: [{ type: 'text', text: 'ok' }] } }]),
            airs: R.answers('allow-tool') }),
        v3: function (r) {
            var q = lastLog(r.request, 'request'), x = r.response, lx = lastLog(x, 'response');
            if (!q || q.outcome !== 'gap_unenforced') { return 'precondition: the request leg did not log gap_unenforced: ' + JSON.stringify(q); }
            return S.check(x && !x.fault && x.calls.length >= 1 && lx && lx.outcome === 'allow', 'the reply leg took the request leg\'s gap for its own: ' + state(x) + ' ' + JSON.stringify(lx));
        }
    },

    /* ---------------- a gap onScanError lets through, on a reply that can't go back into a stream ---------------- */
    {
        finding: 'P3FIX-CMP-GAPSTREAM',
        title: 'onScanError=allow, a stream:true chat whose reply is JSON with no choices list (content v3 can\'t inspect): the gap passes, as onScanError=allow says and as it did before gap passes asked for a restream; it is not refused as a scanner failure under a line that says "gap allowed"',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { onScanError: 'allow' },
            response: S.reply({ id: 'c1', object: 'chat.completion', model: 'm', usage: { prompt_tokens: 1, completion_tokens: 0, total_tokens: 1 } }), airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var q = r.request, x = r.response, lx = lastLog(x, 'response');
            if (!q || q.fault || (forwarded(q) || {}).stream !== false) { return 'precondition: the request was not passed with streaming off: ' + state(q); }
            if (!lx || !/gap allowed/.test(lx.note)) { return 'precondition: the reply leg did not log a gap allowed: ' + JSON.stringify(lx); }
            return S.check(x && !x.fault, 'onScanError=allow refused the reply, kind "' + lx.kind + '", while its line says "' + lx.note + '": ' + state(x));
        }
    },
    {
        finding: 'P3FIX-CMP-GAPSTREAM',
        title: 'Guard: onScanError unset (block), the same reply: withheld as content v3 can\'t inspect, in the client\'s stream format',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'],
            response: S.reply({ id: 'c1', object: 'chat.completion', model: 'm', usage: { prompt_tokens: 1, completion_tokens: 0, total_tokens: 1 } }), airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && x.blocked && /event-stream/.test(String(x.contentType)) && /could not inspect this response/.test(String(x.body)), 'not withheld as content v3 can\'t inspect: ' + state(x));
        }
    }
];

'use strict';
/*
 * Phase 3's gate fixes (15 Nov 2026): behaviour the fixes for 75 to 78 introduced, which no reviewer's case pins.
 *   - P3GATE-FIX-RESCAN: never twice now marks a leg only when a run enforced a verdict on it. A later run on a reply an
 *     earlier run put back into the client's stream reads that event stream itself, and leaves it as it is: a reply that is
 *     already an event stream is never put back into one again (that would fail, and refuse a reply both scans allowed).
 *   - P3GATE-FIX-GAPSTREAM: a gap onScanError=allow lets through is a pass like any other: streaming is turned off on the
 *     way to the model and back on for the client (AIRS3.streamNeeds), as for the breaker's fail-open and monitor mode.
 *   - P3GATE-FIX-LATE: monitor mode's pass of a refusal made before any verdict (here a setting v3 can't read) still turns
 *     streaming off and back on: JS-Airs3Destream and JS-Airs3Restream run again after JS-Airs3Respond (airs3.lateStream).
 *   - P3GATE-FIX-HOOKAPI: in hook mode apiFormat comes from airs_hook alone, as every other setting does.
 *   - P3GATE-FIX-HOOKVAL: v3's hook SharedFlows pass hookMode=request or hookMode=response; any other value is not v3's,
 *     so the run is a FlowCallout's and the variable is left as it was.
 *   - P3GATE-FIX-HITS: a slot is a cache hit only when this leg's own lookup hit (airs3.vcHit<k>, set by JS-Airs3CacheHits),
 *     never by the runtime's lookupcache variable, which the other leg may have left true (L6).
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get.
 */
const crypto = require('crypto');
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const KEY = 'lab-key-for-unit-tests';                                   // test/run.js's Prisma AIRS key
const EP = 'service.api.aisecurity.paloaltonetworks.com';
const PROFILE = { profile_name: 'PROFILE_NAME' };                          // test/run.js's config map profile
const FC_REQ = { type: 'user-prompt' }, FC_RESP = { type: 'response-prompt' };
const HOOK_REQ = { hookMode: 'request' }, HOOK_RESP = { hookMode: 'response' };
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
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
const MCPH = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
function forwarded(x) { try { return JSON.parse(x.flow.messages.request.content); } catch (e) { return null; } }
function gotStream(x, text) { return !!(x && !x.fault && /event-stream/.test(String(x.contentType)) && String(x.body).indexOf(text) !== -1); }
function vcKey(leg, contents) {
    var parts = ['airs3-vc-1', S.CRED, EP, JSON.stringify(PROFILE), leg, '100000', 'true', JSON.stringify(contents)];
    return 'airs3-verdict-' + crypto.createHash('sha256').update(parts.map(function (p) { return p.length + ':' + p; }).join(''), 'utf8').digest('hex');
}
// A stand-in for JS-Airs3CacheKeys cut on the reply leg only (L2): the key's read throws from airs3-cache.js once the reply leg
// has started, as 76's does on every leg (the harness names each script's frames after its file).
function cutKeysOnReply() {
    var st = { reply: false };
    return { mark: function () { st.reply = true; },
             token: { toString: function () { if (st.reply && String(new Error().stack).indexOf('airs3-cache.js') !== -1) { throw new Error('JS-Airs3CacheKeys cut'); } return S.CRED_VALUE; } } };
}
const HITS = cutKeysOnReply();

module.exports = [
    /* ---------------- never twice, narrowed: a later run reads the stream an earlier one made ---------------- */
    {
        finding: 'P3GATE-FIX-RESCAN',
        title: 'A stream:true chat, airs_hook in monitor mode: the post-target hook scans the reply and puts it back into the client\'s stream; the proxy\'s own reply-leg FlowCallout (enforce) scans that event stream itself and passes it as it is',
        setup: Object.assign(streamAsk(), { kvm: hookMap({ enforcementMode: 'monitor' }), response: chatReply('Hi there.'),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'allow-prompt-response', 'allow-prompt-response') }),
        v3: function (r) {
            var h = r.runs[1], f = r.runs[2];
            if (!gotStream(h, 'Hi there.')) { return 'precondition: the hook did not pass the reply as the client\'s stream: ' + state(h); }
            return S.check(f && f.calls.length === 1 && gotStream(f, 'Hi there.') && S.sameStream(f.body, h.body),
                'the FlowCallout did not scan the stream once and leave it as it was: ' + state(f));
        }
    },
    {
        finding: 'P3GATE-FIX-RESCAN',
        title: 'The same, the reply carries the test card: the hook logs it as monitored_block and passes it; the proxy\'s FlowCallout (enforce) scans the stream and refuses it in the client\'s stream format',
        setup: Object.assign(streamAsk(), { kvm: hookMap({ enforcementMode: 'monitor' }), response: chatReply('Card on file: ' + C),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'block-dlp-response-masked', 'block-dlp-response-masked') }),
        v3: function (r) {
            var h = r.runs[1], f = r.runs[2], lh = line(h);
            if (!h || h.fault || !lh || lh.outcome !== 'monitored_block') { return 'precondition: the hook did not log a monitored block and pass: ' + state(h) + ' ' + JSON.stringify(lh); }
            return S.check(f && f.blocked && f.calls.length === 1 && /event-stream/.test(String(f.contentType)) && String(f.body).indexOf(C) === -1,
                'the card was not refused in the client\'s stream format: ' + state(f));
        }
    },

    /* ---------------- a gap onScanError lets through is a pass like any other ---------------- */
    {
        finding: 'P3GATE-FIX-GAPSTREAM',
        title: 'onScanError=allow, maxScanChars=20, a stream:true chat whose reply is longer: the reply passes as a gap and goes back as the client\'s stream, not as plain JSON',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { onScanError: 'allow', maxScanChars: '20' },
            response: chatReply('This reply is longer than twenty characters.'), airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var q = r.request, x = r.response;
            if (!q || q.fault || (forwarded(q) || {}).stream !== false) { return 'precondition: the request was not passed with streaming off: ' + state(q); }
            return S.check(gotStream(x, 'This reply is longer') && /gap allowed/.test(v(x, 'logNote')), 'not passed as a gap in the client\'s stream: ' + state(x));
        }
    },
    {
        finding: 'P3GATE-FIX-GAPSTREAM',
        title: 'onScanError=allow, maxScanChars=20, a stream:true chat whose prompt is longer: the prompt passes as a gap, streaming is still turned off on the way to the model, and the reply is read and goes back as the client\'s stream',
        setup: Object.assign(streamAsk('A prompt that is longer than twenty characters.'), { legs: ['request', 'response'], vars: { onScanError: 'allow', maxScanChars: '20' },
            response: chatReply('Hi.'), airs: R.answers('allow-prompt-response') }),
        v3: function (r) {
            var q = r.request, x = r.response, lq = lastLog(q, 'request');
            return S.check(q && !q.fault && (forwarded(q) || {}).stream === false && lq && /gap allowed/.test(lq.note) && x && x.calls.length === 1 && gotStream(x, 'Hi.'),
                'streaming not turned off and back on around a gap: ' + state(q) + ' | ' + state(x));
        }
    },

    /* ---------------- monitor mode's pass of a refusal before any verdict ---------------- */
    {
        finding: 'P3GATE-FIX-LATE',
        title: 'Monitor mode, a setting v3 can\'t read (maxScanChars abc), a stream:true chat: both legs logged config_unenforced, streaming turned off on the way to the model and the reply sent back as the client\'s stream',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', maxScanChars: 'abc' }, response: chatReply('Hi there.') }),
        v3: function (r) {
            var q = r.request, x = r.response;
            var lq = lastLog(q, 'request'), lx = lastLog(x, 'response');
            return S.check(q && !q.fault && lq && lq.outcome === 'config_unenforced' && (forwarded(q) || {}).stream === false && lx && lx.outcome === 'config_unenforced' && gotStream(x, 'Hi there.'),
                'not turned off and back on: ' + state(q) + ' | ' + state(x));
        }
    },
    {
        finding: 'P3GATE-FIX-LATE',
        title: 'Guard: enforce mode, the same setting: refused on the request leg in the client\'s stream format, nothing forwarded',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { maxScanChars: 'abc' }, response: chatReply('Hi there.') }),
        v3: function (r) { var q = r.request; return S.check(q && q.blocked && /event-stream/.test(String(q.contentType)) && /maxScanChars/.test(q.body), 'not refused: ' + state(q)); }
    },

    /* ---------------- hook mode: apiFormat from airs_hook alone ---------------- */
    {
        finding: 'P3GATE-FIX-HOOKAPI',
        title: 'Hook mode, a listed proxy whose own flow variable apiFormat is mcp and airs_hook sets none: the proxy\'s variable doesn\'t make a GET for an event stream at /events an MCP stream (no 405)',
        setup: { path: '/events', request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, vars: { apiFormat: 'mcp' },
                 kvm: hookMap({}), runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-tool') },
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.status !== 405, 'the proxy\'s variable decided the format: ' + state(x)); }
    },
    {
        finding: 'P3GATE-FIX-HOOKAPI',
        title: 'Guard: the proxy\'s own FlowCallout, the same variable: apiFormat=mcp is its setting, so the GET is answered 405',
        setup: { path: '/events', request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' }, vars: { apiFormat: 'mcp' },
                 runs: [{ leg: 'request', params: FC_REQ }], airs: R.answers('allow-tool') },
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.fault && x.status === 405, 'not answered 405: ' + state(x)); }
    },

    /* ---------------- hookMode values ---------------- */
    {
        finding: 'P3GATE-FIX-HOOKVAL',
        title: 'hookMode=true (not a value v3\'s hook SharedFlows pass) with type=user-prompt: the run is a FlowCallout\'s, so airs_hook\'s failOpen=true doesn\'t apply, a scan with no answer is refused, and hookMode is left as it was',
        setup: Object.assign(ask(), { kvm: hookMap({ failOpen: 'true' }), runs: [{ leg: 'request', params: { type: 'user-prompt', hookMode: 'true' } }], airs: R.answers(R.noAnswer('timeout')) }),
        v3: function (r) {
            var x = r.runs[0], l = line(x);
            return S.check(x && x.fault && l && l.hook === false && String(x.flow.get('hookMode')) === 'true', 'taken for a hook run, or hookMode changed: ' + state(x) + ' ' + JSON.stringify(l));
        }
    },
    {
        finding: 'P3GATE-FIX-HOOKVAL',
        title: 'hookMode=request: a hook run on the request leg, and hookMode is cleared at once',
        setup: Object.assign(ask(), { kvm: hookMap({}), runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.runs[0], l = line(x), hm = x && x.flow.get('hookMode');
            return S.check(x && !x.fault && x.calls.length === 1 && l && l.hook === true && (hm === null || hm === undefined || String(hm) === ''), 'not a hook run, or hookMode left set: ' + state(x));
        }
    },
    {
        finding: 'P3GATE-FIX-HOOKVAL',
        title: 'hookMode=response on the request leg (a wrapper on the wrong hook point): refused as a setting problem naming hookMode',
        setup: Object.assign(ask(), { kvm: hookMap({}), runs: [{ leg: 'request', params: HOOK_RESP }], airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.fault && x.calls.length === 0 && /hookMode/.test(x.body), 'not refused naming hookMode: ' + state(x)); }
    },

    /* ---------------- never twice: a partial gap, and a mark from the other leg ---------------- */
    {
        finding: 'P3GATE-FIX-RESCAN',
        title: 'Request leg: the proxy\'s FlowCallout (onScanError=allow) lets one MCP batch member over maxScanChars pass unscanned and scans the rest; the pre-target hook (airs_hook: onScanError unset, so block) then scans the leg itself and refuses the gap',
        setup: Object.assign(S.req(S.P.mcp, [call(1, S.filler(200)), call(2, 'hello')], MCPH), { vars: { onScanError: 'allow', maxScanChars: '60' }, kvm: hookMap({ maxScanChars: '60' }),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-tool', 'allow-tool') }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1];
            if (!a || a.fault || a.calls.length !== 1) { return 'precondition: the FlowCallout did not pass the batch with one scan: ' + state(a); }
            return S.check(b && b.fault && b.calls.length === 0, 'the hook passed a leg the FlowCallout only partly scanned: ' + state(b));
        }
    },
    {
        finding: 'P3GATE-FIX-RESCAN',
        title: 'The request leg is scanned and allowed by the proxy\'s FlowCallout; on the reply leg the post-target hook lets a reply over maxScanChars pass as a gap (airs_hook onScanError=allow), so nothing marks the reply leg, and the proxy\'s reply-leg FlowCallout refuses the gap',
        setup: Object.assign(ask(), { vars: { maxScanChars: '200' }, kvm: hookMap({ onScanError: 'allow', maxScanChars: '200' }), response: chatReply(S.filler(300)),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var h = r.runs[1], f = r.runs[2], lh = line(h);
            if (!h || h.fault || !lh || !/gap allowed/.test(lh.note)) { return 'precondition: the hook did not pass the reply as a gap: ' + state(h) + ' ' + JSON.stringify(lh); }
            return S.check(f && f.fault, 'the FlowCallout passed the reply on a mark the request leg left: ' + state(f));
        }
    },

    /* ---------------- a later run reads the reply the earlier run kept, unless something changed it since ---------------- */
    {
        finding: 'P3GATE-FIX-RESCAN',
        title: 'airs_hook in monitor mode, a stream:true chat: the post-target hook puts the reply back into the client\'s stream; the proxy then adds an event of its own carrying the test card; the proxy\'s reply-leg FlowCallout scans the reply as it is now (the card included), not the JSON the hook kept',
        setup: Object.assign(streamAsk(), { kvm: hookMap({ enforcementMode: 'monitor' }), response: chatReply('Hi there.'),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP },
                   { leg: 'response', params: FC_RESP, before: function (flow) {
                       var m = flow.messages.response;
                       m.content = String(m.content) + 'data: ' + JSON.stringify({ id: 'c2', object: 'chat.completion.chunk', model: 'm', choices: [{ index: 0, delta: { content: 'Card on file: ' + C }, finish_reason: null }] }) + '\n\n';
                   } }],
            airs: R.answers('allow-prompt', 'allow-prompt-response', 'block-dlp-response-masked') }),
        v3: function (r) {
            var f = r.runs[2];
            return S.check(f && f.calls.length === 1 && String(f.scanned).indexOf(C) !== -1 && f.blocked, 'the FlowCallout did not scan the reply as the proxy left it: ' + state(f) + '; scanned: ' + String(f && f.scanned).slice(0, 120));
        }
    },
    {
        finding: 'P3GATE-FIX-RESCAN',
        title: 'The same, the event the proxy adds is harmless and the proxy\'s FlowCallout allows the reply: it reads the event stream as it is and passes it as it is (an event stream is never put back into one), not refused as a restream that failed',
        setup: Object.assign(streamAsk(), { kvm: hookMap({ enforcementMode: 'monitor' }), response: chatReply('Hi there.'),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'response', params: HOOK_RESP },
                   { leg: 'response', params: FC_RESP, before: function (flow) {
                       var m = flow.messages.response;
                       m.content = String(m.content) + 'data: ' + JSON.stringify({ id: 'c2', object: 'chat.completion.chunk', model: 'm', choices: [{ index: 0, delta: { content: ' And goodbye.' }, finish_reason: null }] }) + '\n\n';
                   } }],
            airs: R.answers('allow-prompt', 'allow-prompt-response', 'allow-prompt-response') }),
        v3: function (r) {
            var f = r.runs[2];
            return S.check(f && f.calls.length === 1 && gotStream(f, 'And goodbye.') && String(f.scanned).indexOf('And goodbye.') !== -1,
                'the changed reply was not scanned and passed as it is: ' + state(f));
        }
    },
    {
        finding: 'P3GATE-FIX-RESCAN',
        title: 'An event-stream reply the flow can see, whose chunks carry content as a list of text parts with the test card: the card is scanned (as the JSON reader reads such a list) and the reply withheld, not passed as an empty reply',
        setup: Object.assign(ask(), { legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
            response: S.reply('data: ' + JSON.stringify({ id: 'c1', object: 'chat.completion.chunk', model: 'm', choices: [{ index: 0, delta: { role: 'assistant', content: [{ type: 'text', text: 'Card on file: ' + C }] }, finish_reason: null }] }) + '\n\ndata: [DONE]\n\n', 'text/event-stream') }),
        v3: function (r) { var x = r.response; return S.check(x && x.blocked && x.calls.length === 1 && String(x.scanned).indexOf(C) !== -1, 'the list content was not scanned: ' + state(x)); }
    },
    {
        finding: 'P3GATE-FIX-RESCAN',
        title: 'Request leg: the proxy\'s FlowCallout (truncationFailClosed=false, maxScanChars=60) scans only the first 60 characters of an MCP batch member; the pre-target hook (airs_hook: truncationFailClosed unset, so a part over the limit refuses) scans the leg itself and refuses it',
        setup: Object.assign(S.req(S.P.mcp, [call(1, S.filler(200)), call(2, 'hello')], MCPH), { vars: { truncationFailClosed: 'false', maxScanChars: '60' }, kvm: hookMap({ maxScanChars: '60' }),
            runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-tool', 'allow-tool') }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1];
            if (!a || a.fault || a.calls.length !== 2) { return 'precondition: the FlowCallout did not scan both members (the first cut): ' + state(a); }
            return S.check(b && b.fault && b.calls.length === 0, 'the hook passed a leg the FlowCallout scanned only in part: ' + state(b));
        }
    },

    /* ---------------- monitor mode: a batch with a gap ---------------- */
    {
        finding: 'P3GATE-FIX-MONGAP',
        title: 'Monitor mode, an MCP batch whose first member is over maxScanChars and whose other member Prisma AIRS allows: forwarded, logged gap_unenforced (enforce mode would have refused the batch), the gap named in the note',
        setup: Object.assign(S.req(S.P.mcp, [call(1, S.filler(200)), call(2, 'hello')], MCPH), { legs: ['request'], vars: { enforcementMode: 'monitor', maxScanChars: '60' },
            airs: R.answers('allow-tool') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x, 'request');
            return S.check(x && !x.fault && x.calls.length === 1 && l && l.outcome === 'gap_unenforced' && /gap not enforced/.test(l.note), 'not logged as a gap not enforced: ' + state(x) + ' ' + JSON.stringify(l));
        }
    },

    /* ---------------- airs_hook's apiFormat is read strictly ---------------- */
    {
        finding: 'P3GATE-FIX-HOOKAPI',
        title: 'Hook mode, airs_hook\'s apiFormat is not text (a number): refused as a setting problem naming apiFormat, as a proxy\'s would be',
        setup: Object.assign(ask(), { kvm: hookMap({ apiFormat: 5 }), runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.fault && x.calls.length === 0 && /apiFormat/.test(x.body), 'not refused naming apiFormat: ' + state(x)); }
    },

    /* ---------------- a cache hit is this leg's own ---------------- */
    {
        finding: 'P3GATE-FIX-HITS',
        title: 'Guard: the request leg is answered from the verdict cache; the reply leg\'s JS-Airs3CacheKeys is cut, so its lookup never runs and the runtime\'s cachehit variable still says true: the reply is not taken for a hit, it is scanned, and the card is withheld',
        setup: Object.assign(ask(), { legs: ['request', 'response'], vars: { verdictCacheTtlS: '60' }, kvm: S.credKvm(HITS.token),
            cache: (function () { var c = {}; c[vcKey('request', [{ prompt: 'hello' }])] = 'scan-of-hello'; return c; })(),
            beforeResponse: function () { HITS.mark(); }, response: chatReply('Card on file: ' + C), airs: R.answers('block-dlp-response-masked') }),
        v3: function (r) {
            var q = r.request, x = r.response;
            if (!q || q.fault || q.calls.length !== 0 || q.cachedScans !== 1) { return 'precondition: the request leg was not answered from the cache: ' + state(q); }
            if (!S.cutIn(x, 'JS-Airs3CacheKeys', 'response')) { return 'precondition: the reply leg\'s JS-Airs3CacheKeys was not cut: ' + state(x); }
            return S.check(x && x.blocked && x.calls.length === 1, 'the reply passed as a cache hit it never had: ' + state(x));
        }
    }
];

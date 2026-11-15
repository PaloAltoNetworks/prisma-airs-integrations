'use strict';
/*
 * The phase 3 gate, coverage and failing closed (15 Nov 2026): does phase 3 (monitor mode, the retry, the circuit breaker,
 * the verdict cache, flow hooks) ever let content reach a model, a tool server or a client unscanned or unrefused when the
 * settings say it must not, and do its passes keep the client's stream and say what happened?
 * Each case passes when v3 does what phase 3's decisions, the README and MuleSoft's policy require.
 * A case that fails today is a finding. Cases titled "Guard" pass today and stay as regression guards.
 *   - P3GATE-COV-KEYCUT:    when JS-Airs3CacheKeys doesn't finish, every slot's key stays '' (AM-Airs3Reset), and the lookups
 *                           and writes still run on it: a cut leg's allow is stored under that one shared key, and any later
 *                           cut leg, of any proxy, tenant, profile, leg or text, is answered from it with no scan (its policy
 *                           says "if it doesn't finish, no slot hits").
 *   - P3GATE-COV-TWICE:     never twice marks a leg scanned whenever a run finished, so after a hook run that got no verdict
 *                           (failed open, a gap allowed) the proxy's own FlowCallout skips the reply, logged "already
 *                           scanned on this leg by the flow hook".
 *   - P3GATE-COV-MONHOOK:   a hook run in monitor mode (airs_hook's enforcementMode) marks the reply leg, so a listed proxy's
 *                           own enforce-mode FlowCallout skips it and a reply its profile blocks reaches the client, while
 *                           the same proxy's request leg is still enforced.
 *   - P3GATE-COV-STALE:     AM-Airs3Reset doesn't reset phase 3's flags that decide the refusal steps (mode, skipLeg, quiet):
 *                           a run whose JS-Airs3Init doesn't finish keeps the previous run's monitor mode, so Respond passes
 *                           the leg and the backstop stays off, or a hook's quiet pass, so the leg passes with no refusal and
 *                           no log line (GATE-R2 requires a scanner-failure refusal).
 *   - P3GATE-COV-TYPE:      a hook FlowCallout's `type` stays set after it returns, so a later FlowCallout that names its leg
 *                           with V2's `scanType` (read only when `type` is unset) takes the hook's: scanType=both on the reply
 *                           leg becomes response-prompt, and the request is never judged.
 *   - P3GATE-COV-BRKSTREAM: the open breaker's fail-open pass skips the verdict, so streaming is neither turned off nor turned
 *                           back on: a client that asked for a stream gets plain JSON, and a stream request goes out
 *                           streaming, so its reply is withheld although failOpen=true.
 *   - P3GATE-COV-MONSTREAM: monitor mode's pass from Respond (content v3 can't inspect, an open breaker) skips the same steps:
 *                           a client that asked for a stream gets plain JSON, so monitor mode changes what it receives, and
 *                           the request goes out streaming, so its reply is never read.
 *   - P3GATE-COV-HOOKSET:   in hook mode a listed proxy's own flow variable overrides airs_hook's setting (the README: settings
 *                           come from airs_hook for every listed route), so a proxy variable enforcementMode=monitor turns the
 *                           environment's hook enforcement off for that proxy.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get, and nothing
 * here decides a verdict from content. A step that doesn't finish is stood in for, as 93, 96 and 97 do, by a variable whose
 * read throws at that statement (a timeLimit cut or an error, which continueOnError=true makes silent: L2); before Init's
 * first read, by a variable that extends one Init clears, which the harness's strict mode refuses to set past.
 */
const crypto = require('crypto');
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const KEY = 'lab-key-for-unit-tests';                                   // test/run.js's Prisma AIRS key
const EP = 'service.api.aisecurity.paloaltonetworks.com';
const NOW = Date.now();
const HOOK_REQ = { hookMode: 'request' }, HOOK_RESP = { hookMode: 'response' };
const FC_REQ = { type: 'user-prompt' }, FC_RESP = { type: 'response-prompt' };
// The config map entry airs_hook; the harness's proxy.basepath is /lab.
function hookMap(settings, routes) { return { airs_hook: JSON.stringify({ routes: routes || ['/lab'], settings: settings || {} }) }; }

function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function hdr(x, n) { var m = x && x.flow && x.flow.messages.response; return m ? m.header(n) : null; }
function state(x) {
    return !x ? 'the run did not happen' : 'HTTP ' + x.status + ', ' + x.calls.length + ' call(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', mode ' + v(x, 'mode') + ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 140) : ', passed');
}
function lastLine(x) { return x && x.lines && x.lines.length ? x.lines[x.lines.length - 1] : null; }
function lastLog(x, leg) {
    var l = x && x.flow ? x.flow.logs : [], out = null;
    for (var i = 0; i < l.length; i++) { try { var j = JSON.parse(l[i].line); if (j.leg === leg) { out = j; } } catch (e) { /* not a v3 line */ } }
    return out;
}
function completion(text) { return { id: 'c1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }; }
function chatReply(text) { return S.reply(completion(text)); }
function ask(text, extra) { return S.chat([{ role: 'user', content: text || 'hello' }], extra); }
function sentBody(x) { try { return JSON.parse(x.flow.messages.request.content); } catch (e) { return null; } }
function clientGot(x) { var m = x && x.flow && x.flow.messages.response; return m ? String(m.content) : ''; }
function isStream(x) { return /text\/event-stream/.test(String(x && x.contentType)); }
// The breaker's state for test/run.js's key, as airs3-init.js keys it.
function breakerSeed(failures, openUntil) {
    var c = {}; c['airs3-breaker-' + crypto.createHash('sha256').update(EP + '\n' + KEY, 'utf8').digest('hex')] = JSON.stringify({ failures: failures, openUntil: openUntil });
    return c;
}
// A stand-in for a step that doesn't finish: the value reads as `value` except on read number `n`, which throws, so the
// step stops at that statement, as a timeLimit cut or an error there would (continueOnError=true: L2).
function cutOnRead(n, value) {
    var reads = 0;
    return { toString: function () { reads++; if (reads === n) { throw new Error('a step cut at this read (stand-in)'); } return value; } };
}
// The model behind the proxy, for a chat stream:true call: JSON when the request leg turned streaming off, else an event
// stream, whose body the flow can't see (L1). `bind` goes in setup.beforeResponse, so the reply follows what was sent.
function upstream(text) {
    var flow = null;
    function off() { return !!(flow && sentBody({ flow: flow }) && sentBody({ flow: flow }).stream === false); }
    return {
        bind: function (f) { flow = f; },
        response: {
            get status() { return 200; },
            get headers() { return off() ? { 'Content-Type': 'application/json' } : { 'Content-Type': 'text/event-stream', 'Transfer-Encoding': 'chunked' }; },
            get content() { return off() ? JSON.stringify(completion(text)) : ''; }
        }
    };
}

const UP_BRK = upstream('Hi there.');

module.exports = [
    /* ================ P3GATE-COV-KEYCUT: a cut JS-Airs3CacheKeys and its one shared key ================ */
    // private.airs3_token is read by JS-Airs3Init (it must be set), then first thing in JS-Airs3CacheKeys, then by the scan
    // request's header. Read 2 throws: JS-Airs3CacheKeys stops before any key is made, so every airs3.vcKey<k> stays ''.
    {
        finding: 'P3GATE-COV-KEYCUT',
        title: 'JS-Airs3CacheKeys cut (its policy: "if it doesn\'t finish, no slot hits"): the entry an earlier cut leg wrote under the empty key, for ' +
               'other text of any proxy or tenant, answers this leg, and a prompt Prisma AIRS blocks reaches the model with no scan',
        setup: Object.assign(ask(M), { legs: ['request'], vars: { verdictCacheTtlS: '60' },
            kvm: { airs_token: cutOnRead(2, KEY) }, cache: { '': 'scan-of-other-text' }, airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x, 'request');
            return S.check(x && x.fault, 'forwarded unscanned, answered from the empty-key entry: ' + state(x) + ', log cached ' + (l && l.cached) + ', scan_id ' + (l && l.scan_id));
        }
    },
    {
        finding: 'P3GATE-COV-KEYCUT',
        title: 'JS-Airs3CacheKeys cut, then a clean allow: the allow is written under the empty key, the entry any later cut leg reads for any text',
        setup: Object.assign(ask('hello'), { legs: ['request'], vars: { verdictCacheTtlS: '60' },
            kvm: { airs_token: cutOnRead(2, KEY) }, airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request, bad = Object.keys(x.flow.cache).filter(function (k) { return !/^airs3-(verdict|breaker)-[0-9a-f]{64}$/.test(k); });
            return S.check(x && bad.length === 0, 'written under a key that is no hash of the scan: ' + JSON.stringify(bad) + ' ' + state(x));
        }
    },
    {
        finding: 'P3GATE-COV-KEYCUT',
        title: 'Guard: JS-Airs3CacheKeys finishing: an entry under the empty key is never read; the prompt is scanned and refused',
        setup: Object.assign(ask(M), { legs: ['request'], vars: { verdictCacheTtlS: '60' },
            cache: { '': 'scan-of-other-text' }, airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.blocked && x.calls.length === 1, 'not scanned and refused: ' + state(x)); }
    },

    /* ================ P3GATE-COV-TWICE: a hook run with no verdict marks the leg ================ */
    {
        finding: 'P3GATE-COV-TWICE',
        title: 'Reply leg: the post-target hook gets no answer and fails open (airs_hook failOpen=true); the listed proxy\'s own FlowCallout (failOpen ' +
               'unset, so it refuses) then passes the reply with no call, logged "already scanned on this leg by the flow hook", though nothing scanned it',
        setup: Object.assign(ask('hello'), { kvm: hookMap({ failOpen: 'true' }), runs: [{ leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers(R.noAnswer('timeout'), 'block-dlp-response-masked'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1], l = lastLine(b);
            if (!a || a.fault) { return 'the hook run did not pass: ' + state(a); }
            return S.check(b && (b.fault || b.calls.length > 0), 'the FlowCallout skipped a reply nothing scanned: ' + state(b) + '; its line\'s note "' + (l && l.note) +
                '"; the client got "' + clientGot(b).slice(0, 110) + '"');
        }
    },
    {
        finding: 'P3GATE-COV-TWICE',
        title: 'Reply leg: the post-target hook lets a reply over maxScanChars pass as a gap (airs_hook onScanError=allow); the listed proxy\'s own ' +
               'FlowCallout (onScanError unset: block) then passes it unscanned as "already scanned"',
        // maxScanChars in both places: since the hook-settings fix a hook reads airs_hook's settings alone, the FlowCallout the flow's.
        setup: Object.assign(ask('hello'), { vars: { maxScanChars: '200' }, kvm: hookMap({ onScanError: 'allow', maxScanChars: '200' }),
            runs: [{ leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt-response'), response: chatReply(S.filler(300)) }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1];
            if (!a || a.fault) { return 'the hook run did not pass: ' + state(a); }
            return S.check(b && (b.fault || b.calls.length > 0), 'the FlowCallout skipped a reply nothing scanned: ' + state(b));
        }
    },
    {
        finding: 'P3GATE-COV-TWICE',
        title: 'Guard: the hook got a real allow on the reply leg: the proxy\'s FlowCallout passes it without a second call (never twice)',
        setup: Object.assign(ask('hello'), { kvm: hookMap({}), runs: [{ leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt-response', 'allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) { var a = r.runs[0], b = r.runs[1]; return S.check(a && a.calls.length === 1 && b && !b.fault && b.calls.length === 0, 'scanned twice: ' + state(a) + ' | ' + state(b)); }
    },

    /* ================ P3GATE-COV-MONHOOK: a monitor-mode hook run and an enforce-mode FlowCallout ================ */
    {
        finding: 'P3GATE-COV-MONHOOK',
        title: 'airs_hook enforcementMode=monitor (a first rollout of the hooks), a listed proxy with its own FlowCallouts and no enforcementMode of its ' +
               'own: the post-target hook logs a blocked reply as monitored_block, then the proxy\'s enforce-mode FlowCallout skips it: the card reaches the client',
        setup: Object.assign(ask('hello'), { kvm: hookMap({ enforcementMode: 'monitor' }), runs: [{ leg: 'response', params: HOOK_RESP }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('block-dlp-response-masked', 'block-dlp-response-masked'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1];
            if (!a || a.fault) { return 'the hook run did not pass: ' + state(a); }
            return S.check(b && b.fault, 'the enforce-mode FlowCallout passed a reply its profile blocks: ' + state(b) + '; the client got "' + clientGot(b).slice(0, 110) + '"');
        }
    },
    {
        finding: 'P3GATE-COV-MONHOOK',
        title: 'Guard: the same proxy\'s request leg: its FlowCallout runs before the pre-target hook, in enforce mode, and refuses the prompt',
        setup: Object.assign(ask(M), { kvm: hookMap({ enforcementMode: 'monitor' }), runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: HOOK_REQ }],
            airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) { var a = r.runs[0]; return S.check(a && a.blocked, 'not refused by the FlowCallout: ' + state(a)); }
    },

    /* ================ P3GATE-COV-STALE: flags AM-Airs3Reset doesn't reset ================ */
    {
        finding: 'P3GATE-COV-STALE',
        title: 'A proxy that monitors prompts and enforces replies (enforcementMode monitor for its request-leg FlowCallout, enforce for its reply-leg ' +
               'one): the reply leg\'s JS-Airs3Init is cut before it sets the mode, so the request leg\'s monitor mode stays, Respond passes the reply and ' +
               'the backstop is off (GATE-R2: refuse as a scanner failure)',
        setup: Object.assign(ask('hello'), {
            runs: [{ leg: 'request', params: { type: 'user-prompt', enforcementMode: 'monitor' } },
                   { leg: 'response', params: { type: 'response-prompt', enforcementMode: cutOnRead(1, 'enforce') } }],
            airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1], l = lastLine(b);
            if (!a || a.fault) { return 'the request leg did not pass: ' + state(a); }
            return S.check(b && b.blocked && hdr(b, 'x-airs-kind') === 'failure', 'the reply passed with JS-Airs3Init cut (doneInit ' + v(b, 'doneInit') + '): ' + state(b) +
                '; logged mode ' + (l && l.mode) + ', outcome ' + (l && l.outcome));
        }
    },
    {
        finding: 'P3GATE-COV-STALE',
        title: 'The same through the hooks: the pre-target hook scans the request in monitor mode (airs_hook), the post-target point holds another ' +
               'SharedFlow, and the listed proxy\'s own reply-leg FlowCallout (enforce) has its JS-Airs3Init cut: the reply passes',
        // The FlowCallout's first read of enforcementMode cuts its Init: since the hook-settings fix the hook never reads the flow's.
        setup: Object.assign(ask('hello'), { vars: { enforcementMode: cutOnRead(1, '') }, kvm: hookMap({ enforcementMode: 'monitor' }),
            runs: [{ leg: 'request', params: HOOK_REQ }, { leg: 'response', params: FC_RESP }],
            airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1];
            if (!a || a.fault) { return 'the hook run did not pass: ' + state(a); }
            return S.check(b && b.blocked && hdr(b, 'x-airs-kind') === 'failure', 'the reply passed with JS-Airs3Init cut (doneInit ' + v(b, 'doneInit') + '): ' + state(b));
        }
    },
    {
        // A cut at Init's first statement, before it clears the leg's variables (S.cutInit, set just before the reply leg).
        finding: 'P3GATE-COV-STALE',
        title: 'Hooks attached, a proxy airs_hook doesn\'t list: the pre-target hook\'s quiet pass leaves skipLeg and quiet true, and the proxy\'s own ' +
               'reply-leg FlowCallout has its JS-Airs3Init cut before it clears them: the reply passes unscanned, with no refusal and no log line',
        setup: Object.assign(ask('hello'), { legs: ['request', 'response'], kvm: hookMap({}, ['/other']), params: { request: { hookMode: 'request' } },
            beforeResponse: S.cutInit,
            airs: R.answers('allow-prompt-response'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var q = r.request, x = r.response;
            if (!q || q.fault || q.calls.length !== 0) { return 'the hook did not pass the request leg untouched: ' + state(q); }
            return S.check(x && x.blocked && hdr(x, 'x-airs-kind') === 'failure', 'the reply passed on the hook\'s skipLeg ' + v(x, 'skipLeg') + ', quiet ' + v(x, 'quiet') +
                ' (doneInit ' + v(x, 'doneInit') + ', ' + x.flow.logs.length + ' log line(s)): ' + state(x));
        }
    },
    {
        finding: 'P3GATE-COV-STALE',
        title: 'Guard: the same cut after an enforce-mode request leg: refused as a scanner failure, as GATE-R2 requires',
        setup: Object.assign(ask('hello'), {
            runs: [{ leg: 'request', params: { type: 'user-prompt' } }, { leg: 'response', params: { type: 'response-prompt', enforcementMode: cutOnRead(1, 'enforce') } }],
            airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) { var b = r.runs[1]; return S.check(b && b.blocked && hdr(b, 'x-airs-kind') === 'failure', 'not refused: ' + state(b)); }
    },

    /* ================ P3GATE-COV-TYPE: the hooks' type parameter stays set ================ */
    {
        finding: 'P3GATE-COV-TYPE',
        title: 'Hooks attached, a proxy not listed that calls PANW-AIRS on its reply leg only, with V2\'s scanType=both: the post-target hook\'s ' +
               'type=response-prompt is still set, so its request (with the marker) is never judged with the reply',
        setup: Object.assign(ask(M), { kvm: hookMap({}, ['/other']),
            runs: [{ leg: 'request', params: HOOK_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: { scanType: 'both' } }],
            airs: R.answers('allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) {
            var x = r.runs[2];
            return S.check(x && S.has(x, M), 'the request\'s text is not in the reply leg\'s scan (phase ' + v(x, 'phase') + ', type "' + (x && x.flow.get('type')) + '"): ' +
                JSON.stringify(x && x.scanned).slice(0, 120) + ' ' + state(x));
        }
    },
    {
        finding: 'P3GATE-COV-TYPE',
        title: 'Guard: the same proxy with no hooks attached: scanType=both judges the request with the reply',
        setup: Object.assign(ask(M), { runs: [{ leg: 'response', params: { scanType: 'both' } }],
            airs: R.answers('allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) { var x = r.runs[0]; return S.check(x && S.has(x, M), 'not judged with the reply: ' + state(x)); }
    },

    /* ================ P3GATE-COV-BRKSTREAM: the breaker's fail-open pass and streams ================ */
    {
        finding: 'P3GATE-COV-BRKSTREAM',
        title: 'failOpen=true, breakerFailures=1, chat stream:true: the request leg gets no answer, fails open, is de-streamed and opens the breaker; ' +
               'the reply leg passes on the open breaker but is not put back into the client\'s stream: the client gets plain JSON',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { failOpen: 'true', breakerFailures: '1' },
            airs: R.answers(R.noAnswer('timeout')), response: chatReply('Hi there.') }),
        v3: function (r) {
            var q = r.request, x = r.response, sent = sentBody(q);
            if (!q || q.fault || !sent || sent.stream !== false) { return 'the request leg did not pass de-streamed: ' + state(q); }
            return S.check(x && !x.fault && isStream(x), 'the stream client got ' + String(x && x.contentType) + ': ' + clientGot(x).slice(0, 90) + ' ' + state(x));
        }
    },
    {
        finding: 'P3GATE-COV-BRKSTREAM',
        title: 'failOpen=true, the breaker open, chat stream:true: the request passes with no call but still streaming, so the model\'s event-stream ' +
               'reply, which the flow can\'t see, is withheld as content v3 can\'t inspect, although failOpen=true (the guard below: the same outage with no breaker passes)',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { failOpen: 'true', breakerFailures: '3' },
            cache: breakerSeed(3, NOW + 60000), airs: R.answers('allow-prompt'), beforeResponse: UP_BRK.bind, response: UP_BRK.response }),
        v3: function (r) {
            var q = r.request, x = r.response, sent = sentBody(q);
            if (!q || q.fault || q.calls.length !== 0) { return 'not passed on the open breaker: ' + state(q); }
            return S.check(x && !x.fault && isStream(x), 'sent with stream ' + (sent && sent.stream) + '; the reply: ' + state(x) + ' ' + String(x && x.contentType));
        }
    },
    {
        finding: 'P3GATE-COV-BRKSTREAM',
        title: 'Guard: failOpen=true, the breaker off, no answer on both legs, chat stream:true: de-streamed, and the reply comes back in the client\'s stream',
        setup: (function () {
            var up = upstream('Hi there.');
            return Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { failOpen: 'true' },
                airs: R.answers(R.noAnswer('timeout')), beforeResponse: up.bind, response: up.response });
        })(),
        v3: function (r) {
            var q = r.request, x = r.response, sent = sentBody(q);
            return S.check(q && !q.fault && sent && sent.stream === false && x && !x.fault && isStream(x), 'not de-streamed and re-streamed: ' + state(q) + ' | ' + state(x));
        }
    },
    {
        finding: 'P3GATE-COV-BRKSTREAM',
        title: 'Guard: failOpen unset, the breaker open, chat stream:true: refused before the model, in the client\'s stream format',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request'], vars: { breakerFailures: '3' }, cache: breakerSeed(3, NOW + 60000), airs: R.answers('allow-prompt') }),
        v3: function (r) { var q = r.request; return S.check(q && q.blocked && q.calls.length === 0 && isStream(q) && hdr(q, 'x-airs-kind') === 'failure', 'not refused as a stream: ' + state(q)); }
    },

    /* ================ P3GATE-COV-MONSTREAM: monitor mode's pass from Respond and streams ================ */
    {
        finding: 'P3GATE-COV-MONSTREAM',
        title: 'Monitor mode, chat stream:true, a reply over maxScanChars: logged gap_unenforced and passed, but not put back into the client\'s stream: ' +
               'the client gets plain JSON (decision.rs: in monitor mode nothing the client receives changes)',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', maxScanChars: '200' },
            airs: R.answers('allow-prompt', 'allow-prompt-response'), response: chatReply(S.filler(300)) }),
        v3: function (r) {
            var q = r.request, x = r.response, sent = sentBody(q), l = lastLog(x, 'response');
            if (!q || q.fault || !sent || sent.stream !== false) { return 'the request leg did not pass de-streamed: ' + state(q); }
            return S.check(x && !x.fault && l && l.outcome === 'gap_unenforced' && isStream(x),
                'the stream client got ' + String(x && x.contentType) + ', logged ' + (l && l.outcome) + ' ' + state(x));
        }
    },
    {
        finding: 'P3GATE-COV-MONSTREAM',
        title: 'Monitor mode, breakerFailures=1, chat stream:true: the request leg fails open (failed_open), opens the breaker and is de-streamed; ' +
               'the reply leg passes on the open breaker in plain JSON',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', breakerFailures: '1' },
            airs: R.answers(R.noAnswer('timeout')), response: chatReply('Hi there.') }),
        v3: function (r) {
            var q = r.request, x = r.response, sent = sentBody(q);
            if (!q || q.fault || !sent || sent.stream !== false) { return 'the request leg did not pass de-streamed: ' + state(q); }
            return S.check(x && !x.fault && isStream(x), 'the stream client got ' + String(x && x.contentType) + ' ' + state(x));
        }
    },
    {
        finding: 'P3GATE-COV-MONSTREAM',
        title: 'Monitor mode, chat stream:true, a prompt over maxScanChars: logged gap_unenforced and forwarded still streaming (README: "Streaming is ' +
               'still turned off on the way to the model, so replies are read")',
        setup: Object.assign(ask(S.filler(300), { stream: true }), { legs: ['request'], vars: { enforcementMode: 'monitor', maxScanChars: '200' }, airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var q = r.request, sent = sentBody(q), l = lastLog(q, 'request');
            if (!q || q.fault || !l || l.outcome !== 'gap_unenforced') { return 'not passed as gap_unenforced: ' + state(q); }
            return S.check(sent && sent.stream === false, 'sent to the model with stream ' + (sent && sent.stream) + ': ' + state(q));
        }
    },
    {
        finding: 'P3GATE-COV-MONSTREAM',
        title: 'Guard: enforce mode, the same reply over maxScanChars: refused in the client\'s own stream format',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { maxScanChars: '200' },
            airs: R.answers('allow-prompt', 'allow-prompt-response'), response: chatReply(S.filler(300)) }),
        v3: function (r) { var x = r.response; return S.check(x && x.blocked && isStream(x), 'not refused as a stream: ' + state(x) + ' ' + String(x && x.contentType)); }
    },

    /* ================ P3GATE-COV-HOOKSET: whose settings a hook run uses ================ */
    {
        finding: 'P3GATE-COV-HOOKSET',
        title: 'Hook mode, a listed route, airs_hook enforcementMode=enforce, and a flow variable enforcementMode=monitor the proxy set for itself: the ' +
               'README says airs_hook\'s settings hold for every listed route, but the proxy\'s variable wins and a prompt Prisma AIRS blocks reaches the model',
        setup: Object.assign(ask(M), { vars: { enforcementMode: 'monitor' }, kvm: hookMap({ enforcementMode: 'enforce' }),
            runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.blocked, 'the proxy\'s variable overrode airs_hook: ' + state(x)); }
    }
];

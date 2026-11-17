'use strict';
/*
 * The phase 3 gate, lens: Apigee realism (15 Nov 2026). Phase 3 leans on runtime behaviour: the event-stream body the flow
 * can't see (L1), a cut step that continueOnError=true makes silent (L2), flow variables that last the whole exchange and a
 * FlowCallout's parameters that stay set (L6, the hookMode fix), hooks that see the proxy's variables (L20), and the cache
 * (L19). Each case runs the SharedFlow's own XML and JavaScript under the harness. A case that fails today is a finding;
 * a case titled "Guard" passes today and pins what must not change.
 *   - P3GATE-APIGEE-BRKSTREAM: the open breaker's failOpen pass (JS-Airs3BreakerCheck sets route=pass) skips
 *     JS-Airs3Verdict, the only step that sets needDestream and needRestream: a stream request is forwarded still
 *     streaming, so its reply, which the flow can't see (L1), is withheld although failOpen=true; and a reply leg that
 *     meets a breaker opened by its own request leg goes back as plain JSON to a client that asked for a stream.
 *   - P3GATE-APIGEE-MONSTREAM: monitor mode passes a refusal made before any verdict in JS-Airs3Respond, which runs after
 *     JS-Airs3Restream, and needRestream is never set on that path: a reply over maxScanChars, or one that meets an open
 *     breaker, goes back as plain JSON, though monitor mode turns streaming off and must turn it back on.
 *   - P3GATE-APIGEE-HOOKPARAM: the hook SharedFlows' FlowCallout parameters become flow variables in every proxy of the
 *     environment and stay set (only hookMode is cleared): an unlisted proxy's own variable `type` is overwritten on both
 *     legs, and a later FlowCallout that names its leg with V2's scanType (read only when type is unset) takes the hook's
 *     type, so scanType=both on the reply leg becomes response-prompt and the prompt is never judged.
 *   - P3GATE-APIGEE-KEYCUT: when JS-Airs3CacheKeys doesn't finish, every key stays '' (AM-Airs3Reset), the lookups and the
 *     writes still run on that one shared key, and an allow stored under it answers any later cut leg with no scan.
 *   - P3GATE-APIGEE-HOOKVAR: in hook mode a flow variable the proxy set wins over airs_hook's setting of that name (L20:
 *     a hook sees the proxy's variables), so a listed proxy's own analytics label in a variable named appName refuses
 *     every request on its route as a setting problem.
 *   - P3GATE-APIGEE-HOOKJSON: airs_hook's settings are read with String(), so airsDescriptions given as a JSON object
 *     (the README's form for the setting, and what HOOK_SETTINGS passes through) becomes "[object Object]" and every
 *     listed route is refused.
 *   - P3GATE-APIGEE-RUNNER: test/run.js's no-silent-leg rule for setup.runs lacks the all-cached exception the legs rule
 *     has, so a run answered wholly from the verdict cache fails its case although v3 is right.
 *   - P3GATE-APIGEE-G1: Guard: the hook SharedFlows as shipped, their FlowCallout read from their own XML (no other case
 *     runs it): one unconditional step, continueOnError=false, the bundle PANW-AIRS, and parameters that put v3 in hook mode.
 * A step that doesn't finish is stood in for by a config-map value whose read throws only inside that step's script (the
 * harness names each script's frames after its file), as 93, 96 and 97 do: a timeLimit cut or an error, silent with
 * continueOnError=true (L2). The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies
 * its scans get, and nothing here decides a verdict from content.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const S = require('./_shapes');
const R = require('../harness/replies');
const H = require('../harness/apigee');
const X = require('../harness/xml');
const C = S.CARD, M = 'AIRSV3-MARKER';
const KEY = 'lab-key-for-unit-tests';                                   // test/run.js's Prisma AIRS key
const EP = 'service.api.aisecurity.paloaltonetworks.com';
const BKEY = 'airs3-breaker-' + crypto.createHash('sha256').update(EP + '\n' + S.CRED, 'utf8').digest('hex');
const NOW = Date.now();
const HOOK_REQ = { hookMode: 'request' }, HOOK_RESP = { hookMode: 'response' };
const FC_REQ = { type: 'user-prompt' };
function hookMap(settings, routes) { return { airs_hook: JSON.stringify({ routes: routes || ['/lab'], settings: settings || {} }) }; }   // the harness's base path is /lab
const UNLISTED = hookMap({}, ['/airs-llm']);

function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' call(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', mode ' + (v(x, 'mode') || 'enforce') + ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 140) : ', passed');
}
function line(x) { return x && x.lines && x.lines.length ? x.lines[x.lines.length - 1] : null; }
function lastLog(x, leg) {
    var l = x && x.flow ? x.flow.logs : [], out = null;
    for (var i = 0; i < l.length; i++) { try { var j = JSON.parse(l[i].line); if (j.leg === leg) { out = j; } } catch (e) { /* not a v3 line */ } }
    return out;
}
function seed(failures, openUntil) { var c = {}; c[BKEY] = JSON.stringify({ failures: failures, openUntil: openUntil }); return c; }
function ask(text, extra) { return S.chat([{ role: 'user', content: text || 'hello' }], extra); }
function chatReply(text) { return S.reply({ id: 'c1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }); }
function sent(x) { try { return JSON.parse(x.flow.messages.request.content); } catch (e) { return null; } }
// The model answers what the request leg forwarded: a request still asking for a stream gets an event stream, whose body the
// flow can't see (L1); a request v3 turned streaming off for gets JSON.
function streamingModel(setup, json) {
    var seen = null;
    setup.beforeResponse = function (flow) { seen = flow; };
    Object.defineProperty(setup, 'response', { enumerable: true, get: function () {
        var b = null;
        try { b = JSON.parse(seen.messages.request.content); } catch (e) { b = null; }
        return b && b.stream === true ? { status: 200, headers: { 'Content-Type': 'text/event-stream' }, content: '' } : json;
    } });
    return setup;
}
// The client got the reply in the stream format it asked for: v3 put it back (a body of events), or let the stream through.
function streamed(x, rewritten) {
    var ok = x && !x.fault && /^text\/event-stream/.test(String(x.contentType || '')) && (!rewritten || /^data: /.test(String(x.body || '')));
    return S.check(ok, 'the client did not get its stream: ' + state(x) + ', Content-Type ' + (x && x.contentType) + ', body ' + String(x && x.body).slice(0, 100));
}
// The config map's key, as a value whose read fails only inside airs3-cache.js: JS-Airs3CacheKeys doesn't finish (its 1000 ms
// timeLimit, or an error), which continueOnError=true makes silent (L2). Every other read gets the key.
function keyCutToken() {
    return { toString: function () { if (String(new Error().stack).indexOf('airs3-cache.js') !== -1) { throw new Error('JS-Airs3CacheKeys cut'); } return S.CRED_VALUE; } };
}

// The hook SharedFlows as shipped, beside v3 (the lab's src/ or the published folder): their one FlowCallout, from its XML.
const ROOT = path.join(__dirname, '..', '..');
function hookShape(leg) {
    var dirs = [path.join(ROOT, 'PANW-AIRS-hook-' + leg, 'sharedflowbundle'), path.join(ROOT, 'src', 'PANW-AIRS-hook-' + leg, 'sharedflowbundle')];
    var dir = dirs.filter(function (d) { return fs.existsSync(d); })[0];
    if (!dir) { return { error: 'no PANW-AIRS-hook-' + leg + ' bundle beside PANW-AIRS' }; }
    try {
        var b = new H.Bundle(dir), steps = b.steps(), names = Object.keys(b.policies);
        if (steps.length !== 1 || steps[0].cond || names.length !== 1) { return { error: leg + ' hook: not one unconditional step and one policy: ' + JSON.stringify(steps) }; }
        var p = b.policies[steps[0].name];
        if (!p || p.name !== 'FlowCallout') { return { error: leg + ' hook: its step is not a FlowCallout' }; }
        var params = {};
        X.kids(X.kid(p, 'Parameters'), 'Parameter').forEach(function (pr) { params[pr.attrs.name] = X.text(pr); });
        return { name: b.name(), coe: p.attrs.continueOnError, bundle: X.text(X.kid(p, 'SharedFlowBundle')), params: params };
    } catch (e) { return { error: leg + ' hook: ' + e.message }; }
}
const HOOK_XML = { request: hookShape('request'), response: hookShape('response') };

module.exports = [
    /* ================================ findings ================================ */
    {
        finding: 'P3GATE-APIGEE-BRKSTREAM',
        title: 'failOpen=true, the breaker open, a Chat Completions stream: the request passes without a call but is forwarded still streaming (JS-Airs3Verdict, which sets needDestream, never runs), so the model\'s event-stream reply, whose body the flow can\'t see (L1), is withheld; the same outage without the breaker turns streaming off and the reply passes',
        setup: streamingModel(Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { breakerFailures: '3', failOpen: 'true' },
            cache: seed(3, NOW + 60000), airs: R.answers('allow-prompt') }), chatReply('Hi.')),
        v3: function (r) {
            var q = r.request;
            if (!q || q.fault) { return 'the request leg was refused: ' + state(q); }
            return streamed(r.response, false);
        }
    },
    {
        finding: 'P3GATE-APIGEE-BRKSTREAM',
        title: 'failOpen=true, breakerFailures=3 with two counted, a Chat Completions stream: the request leg gets no answer, fails open, turns streaming off and opens the breaker; the reply leg passes on the open breaker before JS-Airs3Verdict, so needRestream stays false and the client that asked for a stream gets plain JSON',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { breakerFailures: '3', failOpen: 'true' }, cache: seed(2, 0),
            airs: R.answers(R.noAnswer('timeout'), 'allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) {
            var b = sent(r.request);
            if (!b || b.stream !== false) { return 'precondition: the request leg did not turn streaming off: ' + state(r.request); }
            return streamed(r.response, true);
        }
    },
    {
        finding: 'P3GATE-APIGEE-MONSTREAM',
        title: 'Monitor mode, breakerFailures=3 with two counted, a Chat Completions stream: the request leg logs failed_open, turns streaming off and opens the breaker; the reply leg passes through JS-Airs3Respond (after JS-Airs3Restream in the flow), so the client gets plain JSON, though monitor mode must not change what the client receives',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', breakerFailures: '3' }, cache: seed(2, 0),
            airs: R.answers(R.noAnswer('timeout'), 'allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) {
            var b = sent(r.request);
            if (!b || b.stream !== false) { return 'precondition: the request leg did not turn streaming off: ' + state(r.request); }
            return streamed(r.response, true);
        }
    },
    {
        finding: 'P3GATE-APIGEE-MONSTREAM',
        title: 'Monitor mode, maxScanChars=40, a Chat Completions stream whose reply holds 72 characters: logged gap_unenforced and passed, but as plain JSON, not in the client\'s stream (needRestream is set only by JS-Airs3Verdict, which a refusal before any verdict skips)',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', maxScanChars: '40' },
            airs: R.answers('allow-prompt', 'allow-prompt-response'), response: chatReply(S.filler(72)) }),
        v3: function (r) {
            var l = lastLog(r.response, 'response');
            if (!l || l.outcome !== 'gap_unenforced') { return 'precondition: the reply leg was not logged gap_unenforced: ' + JSON.stringify(l); }
            return streamed(r.response, true);
        }
    },
    {
        finding: 'P3GATE-APIGEE-HOOKPARAM',
        title: 'Hooks attached, a proxy not listed in airs_hook with a flow variable of its own named type (an ExtractVariables with no prefix, say): the hook FlowCallouts\' parameter overwrites it on both legs, so the proxy\'s response flows read response-prompt, though the README says every other proxy passes untouched',
        setup: Object.assign(ask(), { kvm: UNLISTED, vars: { type: 'invoice' }, runs: [{ leg: 'request', params: HOOK_REQ }, { leg: 'response', params: HOOK_RESP }],
            airs: R.answers('allow-prompt'), response: chatReply('Hi.') }),
        v3: function (r) {
            var x = r.runs[1], t = x && x.flow ? x.flow.get('type') : null;
            if (!x || x.fault || x.calls.length !== 0 || x.lines.length !== 0) { return 'precondition: the unlisted proxy was touched: ' + state(x); }
            return S.check(t === 'invoice', 'the proxy\'s own variable type now reads ' + JSON.stringify(t));
        }
    },
    {
        finding: 'P3GATE-APIGEE-HOOKPARAM',
        title: 'Hooks attached, a proxy not listed that calls v3 on its reply leg only with V2\'s scanType=both: the post-target hook\'s type=response-prompt is still set when the proxy\'s FlowCallout runs, and type wins over scanType, so the prompt (with the marker) is never judged with the reply',
        setup: Object.assign(ask('Note ' + M), { kvm: UNLISTED, runs: [{ leg: 'request', params: HOOK_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: { scanType: 'both' } }],
            airs: R.answers('allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) { var x = r.runs[2]; return S.check(x && x.calls.length === 1 && S.has(x, M), 'the prompt was not judged: phase ' + v(x, 'phase') + ', scanned "' + (x && x.scanned) + '"'); }
    },
    {
        finding: 'P3GATE-APIGEE-KEYCUT',
        title: 'verdictCacheTtlS=60, JS-Airs3CacheKeys cut on both legs of one call: the request leg\'s allow is written under the empty key (AM-Airs3Reset\'s value) and the reply leg\'s lookup of the same empty key hits, so a reply with the card that Prisma AIRS would block reaches the client with no scan (JS-Airs3CacheKeys.xml: "if it doesn\'t finish, no slot hits")',
        setup: Object.assign(ask(), { legs: ['request', 'response'], kvm: S.credKvm(keyCutToken()), vars: { verdictCacheTtlS: '60' },
            airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var x = r.response;
            if (!r.request || r.request.fault || r.request.calls.length !== 1) { return 'precondition: the request leg was not scanned and allowed: ' + state(r.request); }
            if (!S.cutIn(x, 'JS-Airs3CacheKeys', 'request') || !S.cutIn(x, 'JS-Airs3CacheKeys', 'response')) { return 'precondition: JS-Airs3CacheKeys was not cut on both legs: ' + state(x); }
            return S.check(x && x.calls.length === 1 && x.blocked, 'the reply was not scanned: ' + state(x) + ', cached ' + v(x, 'cachedScans'));
        }
    },
    {
        finding: 'P3GATE-APIGEE-KEYCUT',
        title: 'JS-Airs3CacheKeys cut, then an allow: nothing may be stored under the empty key (today PC-Airs3Verdict runs with airs3.vcKey1 empty: JS-Airs3CacheRecord sets vcWrite1 without checking the key)',
        setup: Object.assign(ask(), { legs: ['request'], kvm: S.credKvm(keyCutToken()), vars: { verdictCacheTtlS: '60' }, airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request, c = x && x.flow ? x.flow.cache : {};
            if (!S.cutIn(x, 'JS-Airs3CacheKeys', 'request')) { return 'precondition: JS-Airs3CacheKeys was not cut: ' + state(x); }
            return S.check(x && !x.fault && x.calls.length === 1 && !Object.prototype.hasOwnProperty.call(c, ''), 'stored under the empty key: ' + JSON.stringify(c));
        }
    },
    {
        finding: 'P3GATE-APIGEE-HOOKVAR',
        title: 'Hook mode, a listed proxy with no FlowCallout of its own that keeps an analytics label in a flow variable named appName ("Billing (EU)"): the hook reads the proxy\'s variable before airs_hook\'s settings (L20: a hook sees the proxy\'s variables), so every request on the route is refused naming appName; the README says hook-mode settings come from airs_hook',
        setup: Object.assign(ask(), { kvm: hookMap({}), vars: { appName: 'Billing (EU)' }, runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.runs[0], l = line(x); return S.check(x && !x.fault && x.calls.length === 1 && l && l.hook === true, 'not scanned in hook mode: ' + state(x)); }
    },
    {
        finding: 'P3GATE-APIGEE-HOOKJSON',
        title: 'Hook mode, airs_hook settings {"airsDescriptions": {"dlp": "Card number found"}}, a JSON object as the README describes the setting and as HOOK_SETTINGS passes it on: read with String() it is "[object Object]", so every request on every listed route is refused naming airsDescriptions',
        setup: Object.assign(ask('My card number is ' + C + '.'), { kvm: hookMap({ airsDescriptions: { dlp: 'Card number found' } }), runs: [{ leg: 'request', params: HOOK_REQ }],
            airs: R.answers('block-dlp-prompt-masked') }),
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.blocked && x.calls.length === 1 && /Card number found/.test(String(x.body)), 'not blocked with the description: ' + state(x)); }
    },
    {
        finding: 'P3GATE-APIGEE-RUNNER',
        title: 'Two FlowCallouts on one leg, verdictCacheTtlS=60: the first scans and writes the allow, the second is answered from the cache with no call, logged cached 1, as v3 should; test/run.js\'s no-silent-leg rule for setup.runs has no all-cached exception (its legs rule has one), so it fails this case: "run 2 ended with no scan, no refusal and no pass"',
        setup: Object.assign(ask(), { vars: { verdictCacheTtlS: '60' }, runs: [{ leg: 'request', params: FC_REQ }, { leg: 'request', params: FC_REQ }],
            airs: R.answers('allow-prompt', 'block-injection-agent-prompt') }),
        v3: function (r) {
            var a = r.runs[0], b = r.runs[1], l = line(b);
            return S.check(a && a.calls.length === 1 && b && !b.fault && b.calls.length === 0 && l && l.cached === 1 && l.scan_id === 'SCAN_ID',
                           'v3 did not answer the second run from the cache: ' + state(b) + ' ' + JSON.stringify(l));
        }
    },

    /* ================================ guards (pass today) ================================ */
    {
        finding: 'P3GATE-APIGEE-BRKSTREAM',
        title: 'Guard: failOpen=true and no breaker, the same stream and outage on both legs: streaming turned off, both legs failed open, and the reply put back into the client\'s stream (what the open breaker\'s pass must match)',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { failOpen: 'true' },
            airs: R.answers(R.noAnswer('timeout'), R.noAnswer('timeout')), response: chatReply('Hi.') }),
        v3: function (r) { return streamed(r.response, true); }
    },
    {
        finding: 'P3GATE-APIGEE-MONSTREAM',
        title: 'Guard: monitor mode, a Chat Completions stream whose reply Prisma AIRS blocks: logged monitored_block, and the reply put back into the client\'s stream (the verdict path does it)',
        setup: Object.assign(ask('hello', { stream: true }), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor' },
            airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var l = lastLog(r.response, 'response');
            if (!l || l.outcome !== 'monitored_block') { return 'not logged monitored_block: ' + JSON.stringify(l); }
            return streamed(r.response, true);
        }
    },
    {
        finding: 'P3GATE-APIGEE-HOOKPARAM',
        title: 'Guard: no hooks, the same reply-leg FlowCallout with scanType=both: the prompt is judged with the reply',
        setup: Object.assign(ask('Note ' + M), { kvm: UNLISTED, runs: [{ leg: 'response', params: { scanType: 'both' } }], airs: R.answers('allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.calls.length === 1 && S.has(x, M) && v(x, 'phase') === 'both', 'the prompt was not judged: ' + state(x)); }
    },
    {
        finding: 'P3GATE-APIGEE-HOOKJSON',
        title: 'Guard: the same description given as a string that holds JSON: the block names it',
        setup: Object.assign(ask('My card number is ' + C + '.'), { kvm: hookMap({ airsDescriptions: JSON.stringify({ dlp: 'Card number found' }) }), runs: [{ leg: 'request', params: HOOK_REQ }],
            airs: R.answers('block-dlp-prompt-masked') }),
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.blocked && /Card number found/.test(String(x.body)), 'not blocked with the description: ' + state(x)); }
    },
    {
        finding: 'P3GATE-APIGEE-G1',
        title: 'Guard: the hook SharedFlows as shipped (no other case runs their XML): each one unconditional FlowCallout to PANW-AIRS with continueOnError=false, and its own parameters, read from the XML, put v3 in hook mode on its leg: a listed route is scanned on both legs, each line hook true',
        setup: Object.assign(ask(), { kvm: hookMap({}),
            runs: [{ leg: 'request', params: HOOK_XML.request.params || {} }, { leg: 'response', params: HOOK_XML.response.params || {} }],
            airs: R.answers('allow-prompt', 'allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) {
            var legs = ['request', 'response'];
            for (var i = 0; i < legs.length; i++) {
                var h = HOOK_XML[legs[i]], x = r.runs[i], l = line(x);
                if (h.error) { return h.error; }
                if (h.name !== 'PANW-AIRS-hook-' + legs[i] || h.coe !== 'false' || h.bundle !== 'PANW-AIRS') { return legs[i] + ' hook: ' + JSON.stringify(h); }
                if (!x || x.fault || x.calls.length !== 1 || !l || l.hook !== true || l.leg !== legs[i]) { return legs[i] + ' hook run not scanned in hook mode: ' + state(x) + ' ' + JSON.stringify(l); }
            }
            return true;
        }
    }
];

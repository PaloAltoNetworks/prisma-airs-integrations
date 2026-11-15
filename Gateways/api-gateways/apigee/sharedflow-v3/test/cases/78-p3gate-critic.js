'use strict';
/*
 * The review of phase 3, completeness critic (15 Nov 2026): what the coverage, Apigee-realism and conformance reviews are
 * likely to miss. Each case passes when v3 does what phase 3's decisions and v3's own rules say. A case that fails today is
 * a finding; a case titled "Guard:" passes today and pins behaviour that must not change, or a part of phase 3 that no
 * case touched.
 *   - P3GATE-CRIT-BRKSTREAM: an open circuit breaker with failOpen=true passes the request leg before JS-Airs3Verdict, the
 *     only step that asks for streaming to be turned off. A streaming call then reaches the model as a stream, and its
 *     reply, whose body the flow can't see (L1), is withheld as content v3 can't inspect: failOpen=true refuses every
 *     streaming call while the breaker is open, after the model has run.
 *   - P3GATE-CRIT-RESTREAM: a reply leg that passes before JS-Airs3Verdict, in monitor mode (an open breaker, a reply over
 *     the size limit) or by the breaker's fail-open, never asks for the reply to go back as the client's stream, so a client
 *     that asked for a stream gets plain JSON. Decided: monitor mode still turns streaming off and back on.
 *   - P3GATE-CRIT-STALESKIP: AM-Airs3Reset doesn't reset airs3.skipLeg or airs3.quiet, which phase 3 put into the
 *     conditions of JS-Airs3Respond, RF-Airs3Backstop and the two log steps. With v3's hooks attached, the pre-target hook's
 *     quiet pass on a proxy airs_hook doesn't list leaves both true; if that proxy's own reply-leg FlowCallout has its
 *     JS-Airs3Init cut before Init clears them, the reply passes unscanned, with no refusal and no log line.
 *   - P3GATE-CRIT-HOOKPREC: in hook mode a setting the proxy sets as a flow variable wins over airs_hook's, so a listed
 *     proxy turns the environment's hook policy to monitor mode (or fail open) by setting a variable. The README says hook
 *     mode's settings come from airs_hook.
 *   - P3GATE-CRIT-HOOKOBJ: an airs_hook setting given as a JSON object, the form the settings table documents for
 *     airsDescriptions, is read as "[object Object]" and refuses every request on every listed route.
 *   - P3GATE-CRIT-HOOKSET: an airs_hook "settings" member that isn't a JSON object is ignored without a word, and the listed
 *     routes run on defaults. MuleSoft's settings.rs refuses an advanced block that isn't an object (A39's rule).
 *   - P3GATE-CRIT-CACHED: airs3.cachedScans is never reset per leg, so a leg that doesn't reach JS-Airs3Verdict logs the
 *     previous leg's cache hits as its own.
 *   - P3GATE-CRIT-RUNNER: test/run.js's all-cached exemption reads airs3.cachedScans and airs3.scansRan after both legs ran,
 *     so it judges a two-leg case's request leg by the reply leg's counts, and fails a correct case.
 *   - P3GATE-CRIT-NOCASE: guards for phase 3 parts no case touched: the hook SharedFlows' FlowCallouts, airs_hook's
 *     apiFormat (hookApiFormat), and a reply leg answered from the verdict cache.
 * The only marked text is AIRSV3-MARKER and the test card; each case names the recorded replies its scans get, and nothing
 * here decides a verdict from content.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const H = require('../harness/apigee');
const X = require('../harness/xml');
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const KEY = 'lab-key-for-unit-tests';                                   // test/run.js's Prisma AIRS key
const EP = 'service.api.aisecurity.paloaltonetworks.com';
const PROFILE = { profile_name: 'PROFILE_NAME' };                          // test/run.js's config map profile
const BKEY = 'airs3-breaker-' + crypto.createHash('sha256').update(EP + '\n' + KEY, 'utf8').digest('hex');
const HOOK_REQ = { hookMode: 'request' };
const LISTED = { airs_hook: JSON.stringify({ routes: ['/lab'], settings: {} }) };     // the harness's proxy.basepath is /lab

function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function hdr(x, n) { var m = x && x.flow && x.flow.messages.response; return m ? m.header(n) : null; }
// The last log line of one leg (a two-leg case's flow holds both legs' lines).
function lastLog(x, leg) {
    var l = x && x.flow ? x.flow.logs : [], out = null;
    for (var i = 0; i < l.length; i++) { try { var j = JSON.parse(l[i].line); if (j.leg === leg) { out = j; } } catch (e) { /* not a v3 line */ } }
    return out;
}
function line(x) { return x && x.lines && x.lines.length ? x.lines[x.lines.length - 1] : null; }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' call(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 160) : ', passed') + ', Content-Type ' + x.contentType;
}
function ask(text) { return S.chat([{ role: 'user', content: text || 'hello' }]); }
function streamAsk() { return S.chat([{ role: 'user', content: 'hello' }], { stream: true }); }
function chatReply(text) { return S.reply({ id: 'c1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
// The request as forwarded to the model (the reply leg never changes it).
function forwarded(x) { try { return JSON.parse(x.flow.messages.request.content); } catch (e) { return null; } }
// The client got its own stream (Chat Completions chunks) carrying the reply's text.
function gotStream(x, text) { return !!(x && !x.fault && /event-stream/.test(String(x.contentType)) && String(x.body).indexOf(text) !== -1); }
function openBreaker() { var c = {}; c[BKEY] = JSON.stringify({ failures: 3, openUntil: Date.now() + 60000 }); return c; }
// The verdict cache's key, as 73-p3-cache.js specifies it.
function vcKey(leg, contents) {
    var parts = ['airs3-vc-1', KEY, EP, JSON.stringify(PROFILE), leg, '100000', 'true', JSON.stringify(contents)];
    return 'airs3-verdict-' + crypto.createHash('sha256').update(parts.map(function (p) { return p.length + ':' + p; }).join(''), 'utf8').digest('hex');
}
function seed(pairs) { var c = {}; pairs.forEach(function (p) { c[p[0]] = p[1]; }); return c; }
const ECHO_HELLO = [{ tool_event: { metadata: { ecosystem: 'mcp', method: 'tools/call', server_name: 'lab-proxy', tool_invoked: 'echo' }, input: '{"text":"hello"}' } }];

// A stand-in for JS-Airs3Init cut at its first statement, before it clears a per-leg variable (L2): S.cutInit.
const cutInitAtItsFirstClear = S.cutInit;

// The hook SharedFlows as shipped: in the lab under src/, in the published folder beside PANW-AIRS/.
function hookDir(leg) {
    var name = 'PANW-AIRS-hook-' + leg, c = [path.join(__dirname, '..', '..', 'src', name, 'sharedflowbundle'), path.join(__dirname, '..', '..', name, 'sharedflowbundle')];
    for (var i = 0; i < c.length; i++) { if (fs.existsSync(c[i])) { return c[i]; } }
    return null;
}
// What the hook SharedFlow's one step is: its FlowCallout's attributes, parameters and target, or the reason it can't be read.
function hookStep(leg) {
    try {
        var dir = hookDir(leg);
        if (!dir) { return { problem: 'no PANW-AIRS-hook-' + leg + ' bundle' }; }
        var b = new H.Bundle(dir), steps = b.steps(), p = steps.length === 1 ? b.policies[steps[0].name] : null, params = {};
        if (!p) { return { problem: 'not one step: ' + JSON.stringify(steps) }; }
        X.kids(X.kid(p, 'Parameters'), 'Parameter').forEach(function (q) { params[q.attrs.name] = X.text(q); });
        return { bundle: b.name(), kind: p.name, coe: p.attrs.continueOnError, cond: steps[0].cond, params: params, target: X.text(X.kid(p, 'SharedFlowBundle')) };
    } catch (e) { return { problem: String(e && e.message) }; }
}
const HOOK_SF = { request: hookStep('request'), response: hookStep('response') };

module.exports = [
    /* ---------------- the breaker's fail-open and streaming ---------------- */
    {
        finding: 'P3GATE-CRIT-BRKSTREAM',
        title: 'Breaker open, failOpen=true, a Chat call with stream:true: streaming is still turned off on the way to the model (as for any scanner failure that fails open), so the reply can be read and isn\'t withheld',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { failOpen: 'true', breakerFailures: '3' }, cache: openBreaker(),
            airs: R.answers('allow-prompt'), response: chatReply('Hi there.') }),
        v3: function (r) {
            var q = r.request, x = r.response, sent = q && forwarded(q);
            if (!q || q.fault) { return 'the request was refused: ' + state(q); }
            if (!sent || sent.stream !== false) {
                return 'streaming was not turned off: the model gets ' + JSON.stringify(sent) + ', so it answers with an event stream the flow can\'t see (L1), which the reply leg withholds as content it can\'t inspect';
            }
            return S.check(x && !x.fault, 'the reply was withheld: ' + state(x));
        }
    },

    /* ---------------- turned off, never turned back on ---------------- */
    {
        finding: 'P3GATE-CRIT-RESTREAM',
        title: 'Monitor mode, breakerFailures=1, a Chat call with stream:true, Prisma AIRS not answering: the request leg turns streaming off and opens the breaker; the reply leg, where the open breaker decides, still sends the reply back as the client\'s stream',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', breakerFailures: '1' },
            airs: R.answers(R.noAnswer('timeout')), response: chatReply('Hi there.') }),
        v3: function (r) {
            var q = r.request, x = r.response, sent = q && forwarded(q);
            if (!q || q.fault || !sent || sent.stream !== false) { return 'precondition: the request leg did not pass with streaming turned off: ' + state(q); }
            return S.check(gotStream(x, 'Hi there.'), 'the client asked for a stream and got plain JSON, unlike enforce mode: ' + state(x));
        }
    },
    {
        finding: 'P3GATE-CRIT-RESTREAM',
        title: 'Monitor mode, maxScanChars=20, a Chat call with stream:true whose reply is longer: the reply passes, logged gap_unenforced, and goes back as the client\'s stream, not as plain JSON',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor', maxScanChars: '20' },
            airs: R.answers('allow-prompt'), response: chatReply('This reply is longer than twenty characters.') }),
        v3: function (r) {
            var x = r.response, l = lastLog(x, 'response');
            if (!l || l.outcome !== 'gap_unenforced') { return 'precondition: the reply was not passed as gap_unenforced: ' + state(x); }
            return S.check(gotStream(x, 'This reply is longer than twenty characters.'), 'the client asked for a stream and got plain JSON: ' + state(x));
        }
    },
    {
        finding: 'P3GATE-CRIT-RESTREAM',
        title: 'failOpen=true, breakerFailures=1, a Chat call with stream:true, Prisma AIRS not answering: the reply leg, failed open by the breaker the request leg opened, still sends the reply back as the client\'s stream',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { failOpen: 'true', breakerFailures: '1' },
            airs: R.answers(R.noAnswer('timeout')), response: chatReply('Hi there.') }),
        v3: function (r) {
            var x = r.response;
            if (!x || x.fault || !/circuit breaker is open/.test(v(x, 'logNote'))) { return 'precondition: the reply leg did not fail open by the breaker: ' + state(x); }
            return S.check(gotStream(x, 'Hi there.'), 'the client asked for a stream and got plain JSON: ' + state(x));
        }
    },
    {
        finding: 'P3GATE-CRIT-RESTREAM',
        title: 'Guard: failOpen=true with the breaker off, the same call and the same silence: the reply leg fails open in JS-Airs3Verdict and goes back as the client\'s stream',
        setup: Object.assign(streamAsk(), { legs: ['request', 'response'], vars: { failOpen: 'true' }, airs: R.answers(R.noAnswer('timeout')), response: chatReply('Hi there.') }),
        v3: function (r) { return S.check(gotStream(r.response, 'Hi there.'), 'not sent back as the client\'s stream: ' + state(r.response)); }
    },

    /* ---------------- a leg's state left by a hook's pass ---------------- */
    {
        finding: 'P3GATE-CRIT-STALESKIP',
        title: 'Hooks attached, a proxy airs_hook doesn\'t list, with its own reply-leg FlowCallout: after the pre-target hook\'s quiet pass, a reply-leg JS-Airs3Init cut before it clears the per-leg variables refuses the reply as a step that didn\'t finish (GATE-R2), not passes it unscanned and unlogged',
        setup: Object.assign(ask(), { legs: ['request', 'response'], kvm: { airs_hook: JSON.stringify({ routes: ['/another-proxy'], settings: {} }) },
            params: { request: { hookMode: 'request' } }, beforeResponse: cutInitAtItsFirstClear,
            airs: R.answers('allow-prompt-response'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var q = r.request, x = r.response;
            if (!q || q.fault || q.calls.length !== 0) { return 'precondition: the hook did not pass the request leg untouched: ' + state(q); }
            return S.check(x && x.blocked && hdr(x, 'x-airs-kind') === 'failure',
                'the reply passed (' + (x && x.body && x.body.indexOf(C) !== -1 ? 'the card reached the client' : 'no refusal') + ') on the hook\'s leftovers: skipLeg ' + v(x, 'skipLeg') +
                ', quiet ' + v(x, 'quiet') + ', doneInit ' + v(x, 'doneInit') + ', ' + (x ? x.flow.logs.length : 0) + ' log line(s); ' + state(x));
        }
    },
    {
        finding: 'P3GATE-CRIT-STALESKIP',
        title: 'Guard: no hook on the exchange, the same cut of the reply leg\'s JS-Airs3Init: the reply is refused as a scanner failure',
        setup: Object.assign(ask(), { legs: ['request', 'response'], beforeResponse: cutInitAtItsFirstClear,
            airs: R.answers('allow-prompt', 'allow-prompt-response'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) { var x = r.response; return S.check(x && x.blocked && hdr(x, 'x-airs-kind') === 'failure', 'not refused: ' + state(x)); }
    },

    /* ---------------- airs_hook's settings ---------------- */
    {
        finding: 'P3GATE-CRIT-HOOKPREC',
        title: 'Hook mode, airs_hook sets enforcementMode=enforce and the listed proxy sets a flow variable enforcementMode=monitor: the environment\'s setting holds, so the block refuses the prompt',
        setup: Object.assign(ask(M), { kvm: { airs_hook: JSON.stringify({ routes: ['/lab'], settings: { enforcementMode: 'enforce' } }) }, vars: { enforcementMode: 'monitor' },
            runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) {
            var x = r.runs[0], l = line(x);
            return S.check(x && x.blocked && l && l.mode === 'enforce', 'the proxy\'s variable overrode airs_hook: mode ' + (l && l.mode) + ', outcome ' + (l && l.outcome) + '; ' + state(x));
        }
    },
    {
        finding: 'P3GATE-CRIT-HOOKOBJ',
        title: 'Hook mode, airs_hook\'s settings give airsDescriptions as a JSON object, the form the settings table documents: the block names the custom text, and the request isn\'t refused as a setting v3 can\'t read',
        setup: Object.assign(ask(M), { kvm: { airs_hook: JSON.stringify({ routes: ['/lab'], settings: { airsDescriptions: { injection: 'Custom text for this detection' } } }) },
            runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) {
            var x = r.runs[0];
            return S.check(x && x.blocked && x.calls.length === 1 && String(x.body).indexOf('Custom text for this detection') !== -1, 'not a block naming the custom text: ' + state(x));
        }
    },
    {
        finding: 'P3GATE-CRIT-HOOKSET',
        title: 'Hook mode, airs_hook\'s "settings" is an array, not a JSON object: refused naming it, or passed as an unreadable airs_hook and logged; never scanned on defaults without a word',
        setup: Object.assign(ask(), { kvm: { airs_hook: JSON.stringify({ routes: ['/lab'], settings: ['enforcementMode', 'monitor'] }) },
            runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.runs[0], l = line(x), note = l ? String(l.note) : '';
            var refused = !!(x && x.fault && /airs_hook|settings/.test(String(x.body)));
            var passedLogged = !!(x && !x.fault && x.calls.length === 0 && /airs_hook/.test(note));
            return S.check(refused || passedLogged, 'the settings were dropped without a word, and the route ran on defaults: ' + state(x) + ', line note "' + note + '"');
        }
    },

    /* ---------------- the log line's cache count ---------------- */
    {
        finding: 'P3GATE-CRIT-CACHED',
        title: 'MCP batch of two, slot 1 answered from the cache: the request leg logs cached 1; the reply, HTTP 202 with no body, passes without a scan and logs cached 0, not the request leg\'s count',
        setup: Object.assign(S.req(S.P.mcp, [call(1, 'hello'), call(2, 'hello there')], { Accept: 'application/json, text/event-stream' }), {
            legs: ['request', 'response'], vars: { verdictCacheTtlS: '60' }, cache: seed([[vcKey('request', ECHO_HELLO), 'cached-1']]), airs: R.answers('allow-tool'),
            response: { status: 202, headers: { 'Content-Length': '0' }, content: '' } }),
        v3: function (r) {
            var a = lastLog(r.request, 'request'), b = lastLog(r.response, 'response');
            if (!a || String(a.cached) !== '1' || r.request.calls.length !== 1) { return 'precondition: the request leg did not log one cache hit and one call: ' + JSON.stringify(a); }
            return S.check(r.response && !r.response.fault && b && /no body/.test(String(b.note)) && String(b.cached) === '0',
                'the reply leg, which no cache answered, logs cached ' + (b && b.cached) + ': ' + JSON.stringify(b));
        }
    },

    /* ---------------- the runner ---------------- */
    {
        finding: 'P3GATE-CRIT-RUNNER',
        title: 'A request leg answered wholly from the verdict cache, then a reply leg scanned by a call: both legs pass, and the runner\'s no-silent-leg rule must judge each leg by its own cache counts',
        setup: Object.assign(ask(), { legs: ['request', 'response'], vars: { verdictCacheTtlS: '60' }, cache: seed([[vcKey('request', [{ prompt: 'hello' }]), 'scan-from-cache']]),
            airs: R.answers('allow-prompt-response'), response: chatReply('Hi.') }),
        v3: function (r) {
            var q = r.request, x = r.response, a = lastLog(q, 'request');
            return S.check(q && !q.fault && q.calls.length === 0 && a && String(a.cached) === '1' && x && !x.fault && x.calls.length === 1,
                'v3 did not answer the request leg from the cache and scan the reply: ' + state(q) + ' | ' + state(x));
        }
    },

    /* ---------------- phase 3 parts no case touched ---------------- */
    {
        finding: 'P3GATE-CRIT-NOCASE',
        title: 'Guard: each hook SharedFlow is one unconditional FlowCallout to PANW-AIRS with continueOnError=false and one parameter, hookMode set to its own leg, and v3 run with those parameters scans both legs of a listed route',
        setup: Object.assign(ask(), { kvm: LISTED, response: chatReply('Card on file: ' + C), airs: R.answers('allow-prompt', 'block-dlp-response-masked'),
            runs: [{ leg: 'request', params: HOOK_SF.request.params || {} }, { leg: 'response', params: HOOK_SF.response.params || {} }] }),
        v3: function (r) {
            var legs = ['request', 'response'];
            for (var i = 0; i < legs.length; i++) {
                var h = HOOK_SF[legs[i]], p = h.params || {};
                if (h.problem) { return 'PANW-AIRS-hook-' + legs[i] + ': ' + h.problem; }
                if (h.bundle !== 'PANW-AIRS-hook-' + legs[i] || h.kind !== 'FlowCallout' || h.coe !== 'false' || h.cond || h.target !== 'PANW-AIRS' ||
                    p.hookMode !== legs[i] || Object.keys(p).length !== 1) { return 'PANW-AIRS-hook-' + legs[i] + ' is not as shipped: ' + JSON.stringify(h); }
            }
            var a = r.runs[0], b = r.runs[1], la = line(a);
            return S.check(a && !a.fault && a.calls.length === 1 && la && la.hook === true && b && b.blocked && b.calls.length === 1,
                'the hook parameters did not scan both legs: ' + state(a) + ' | ' + state(b));
        }
    },
    {
        finding: 'P3GATE-CRIT-NOCASE',
        title: 'Guard: hook mode takes apiFormat from airs_hook\'s settings: with apiFormat=mcp there, a GET for an event stream at a path that doesn\'t end in /mcp is answered 405',
        setup: { path: '/events', request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '' },
                 kvm: { airs_hook: JSON.stringify({ routes: ['/lab'], settings: { apiFormat: 'mcp' } }) }, runs: [{ leg: 'request', params: HOOK_REQ }], airs: R.answers('allow-tool') },
        v3: function (r) { var x = r.runs[0]; return S.check(x && x.fault && x.status === 405 && x.calls.length === 0, 'not answered 405: ' + state(x)); }
    },
    {
        finding: 'P3GATE-CRIT-NOCASE',
        title: 'Guard: a reply leg answered from the verdict cache (its key has leg response and the prompt as context): no call, passed, logged cached 1 with the stored scan id',
        setup: Object.assign(ask(), { legs: ['request', 'response'], vars: { verdictCacheTtlS: '60' }, cache: seed([[vcKey('response', [{ prompt: 'hello', response: 'Hi.' }]), 'scan-reply-cache']]),
            airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: chatReply('Hi.') }),
        v3: function (r) {
            var x = r.response, l = lastLog(x, 'response');
            return S.check(x && !x.fault && x.calls.length === 0 && l && String(l.cached) === '1' && l.scan_id === 'scan-reply-cache' && x.body.indexOf('Hi.') !== -1,
                'not answered from the cache: ' + state(x) + ' ' + JSON.stringify(l));
        }
    }
];

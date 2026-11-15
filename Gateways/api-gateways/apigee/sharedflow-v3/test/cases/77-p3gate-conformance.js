'use strict';
/*
 * The review of phase 3 (15 Nov 2026), conformance lens: MuleSoft's monitor mode (core/src/decision.rs), retry rule
 * and circuit breaker (core/src/breaker.rs, src/scan.rs), verdict cache (core/src/cache.rs) and settings
 * (core/src/settings.rs), with their tests (core/tests/decision.rs, breaker.rs, cache.rs; tests/integration/run.py),
 * against v3's phase 3 code and the decisions taken for it. A case returns true when v3 keeps the rule.
 * Findings, each failing on v3 as of 15 Nov:
 *   - P3GATE-CONF-HOOK-TYPE: a FlowCallout's parameters stay set, and the hook SharedFlows' `type` outlives the hook's
 *     run, also on a route airs_hook doesn't list. JS-Airs3Init reads `type` before V2's `scanType`, so a proxy whose
 *     reply-leg FlowCallout names its leg with scanType is refused on every reply as a setting problem when only the
 *     pre-target hook is attached (deploy.sh attaches it, then stops when the post-target point holds another SharedFlow),
 *     and with both hooks attached scanType=both is read as response-prompt: a reply-leg-only proxy no longer judges its
 *     prompt. The decision: an unlisted base path passes untouched.
 *   - P3GATE-CONF-HOOK-PARAMS: in hook mode a setting the flow holds wins over airs_hook's, so the parameters a proxy's
 *     own FlowCallout left on the other leg replace airs_hook's settings (failOpen=true, enforcementMode=monitor here).
 *     The decision: airs_hook's settings apply to every listed route.
 *   - P3GATE-CONF-MON-GAP: in monitor mode, an MCP leg of several scans where one is content v3 can't inspect (a member
 *     over maxScanChars) runs none of the other scans. MuleSoft judges the gap on its own scan and scans on (src/mcp.rs:
 *     "in monitor mode every scan still runs and is recorded"); v3's README says "every scan of a leg runs".
 *   - P3GATE-CONF-RUNNER-CACHED: test/run.js accepts a leg answered wholly from the verdict cache, but not a run of
 *     setup.runs, so run.py's cache_one_scan_for_repeat can't be ported as two requests in a row.
 *   - P3GATE-CONF-GUARD-*: MuleSoft's own tests that v3 had no case for, ported; they pass today. The breaker's sequences
 *     (breaker_opens_after_threshold, success_resets_the_count, breaker_half_open_after_cooldown; run.py
 *     breaker_stops_calls), a degraded allow and a 401 counted as failures, the retry table (retryable_table: 413, 500,
 *     599, a reply with no action), the cache's TTL and key fields (cache_hit_within_ttl_miss_after,
 *     cache_key_differs_by_leg_profile_endpoint_tenant: the endpoint, truncationFailClosed, the prompt context), and
 *     monitor_never_blocks_or_masks for a reply v3 can't read.
 * Findings with no case (docs, in the review's report): P3GATE-CONF-BRK-4XX (v3 resets the breaker on HTTP 400 and 413;
 * MuleSoft counts every non-verdict as a failure, and 72-p3-breaker.js says scan.rs records "every answer as a success"),
 * P3GATE-CONF-MODE-CASE (v3 reads enforcementMode=MONITOR as monitor; MuleSoft's choice() matches exactly, and
 * 70-p3-monitor.js says it is case-insensitive), P3GATE-CONF-DOC-BOUND (the README says the breaker bounds the retry's 80
 * seconds; read once per leg, it doesn't bound the leg that meets the outage), P3GATE-CONF-DOC-STALE (the README still
 * says phases 1 and 2, no flow hooks and no retry in this release).
 * The only marked text is AIRSV3-MARKER and the test card; each case names its recorded Prisma AIRS replies.
 */
const crypto = require('crypto');
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const KEY = 'lab-key-for-unit-tests';                                   // test/run.js's Prisma AIRS key
const EP = 'service.api.aisecurity.paloaltonetworks.com';
const BKEY = 'airs3-breaker-' + crypto.createHash('sha256').update(EP + '\n' + KEY, 'utf8').digest('hex');
const PROFILE = { profile_name: 'PROFILE_NAME' };                          // test/run.js's config map profile
const MCPH = { Accept: 'application/json, text/event-stream' };
const FC_REQ = { type: 'user-prompt' }, HOOK_REQ = { hookMode: 'request' }, HOOK_RESP = { hookMode: 'response' };
const UNLISTED = { airs_hook: JSON.stringify({ routes: ['/airs-llm'], settings: {} }) };     // the harness's proxy.basepath is /lab
const NOW = Date.now();

function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' call(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', mode ' + v(x, 'mode') + ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 160) : ', passed');
}
function lastLog(x, leg) {
    var l = x && x.flow ? x.flow.logs : [], out = null;
    for (var i = 0; i < l.length; i++) { try { var j = JSON.parse(l[i].line); if (j.leg === leg) { out = j; } } catch (e) { /* not a v3 line */ } }
    return out;
}
function ask(text) { return S.chat([{ role: 'user', content: text || 'hello' }]); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
function chatReply(text) { return S.reply({ id: 'c1', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] }); }
// The circuit breaker's entry, as 72-p3-breaker.js seeds and reads it.
function seedB(failures, openUntil) { var c = {}; c[BKEY] = JSON.stringify({ failures: failures, openUntil: openUntil }); return c; }
function storedB(x) { var e = x && x.flow && x.flow.cache[BKEY]; try { return e ? JSON.parse(e.value) : null; } catch (err) { return 'unreadable'; } }
function isOpen(s) { return !!(s && typeof s === 'object' && s.openUntil > Date.now() + 20000); }
// The verdict cache's key, by the spec 73-p3-cache.js shares with airs3-cache.js.
function vcKey(leg, contents, o) {
    o = o || {};
    var parts = ['airs3-vc-1', KEY, o.ep || EP, JSON.stringify(PROFILE), leg, String(o.max || 100000), String(o.trunc === undefined ? true : o.trunc), JSON.stringify(contents)];
    return 'airs3-verdict-' + crypto.createHash('sha256').update(parts.map(function (p) { return p.length + ':' + p; }).join(''), 'utf8').digest('hex');
}
function seed(pairs) { var c = {}; pairs.forEach(function (p) { c[p[0]] = p[1]; }); return c; }
const HELLO = vcKey('request', [{ prompt: 'hello' }]);
// n runs of the request leg on one flow: n requests in a row, through one cache (as run.py's Session keeps one worker).
function requests(n) { var out = []; for (var i = 0; i < n; i++) { out.push({ leg: 'request', params: FC_REQ }); } return out; }
function callsOf(r) { return JSON.stringify((r.runs || []).map(function (x) { return x ? x.calls.length : null; })); }
function runsState(r) { return (r.runs || []).map(function (x, i) { return 'run ' + (i + 1) + ': ' + state(x); }).join(' | '); }
// Passed or refused after this many calls.
function after(x, calls, passed) {
    return S.check(x && x.calls.length === calls && (passed ? !x.fault : !!x.fault), 'not ' + (passed ? 'passed' : 'refused') + ' after ' + calls + ' call(s): ' + state(x));
}

module.exports = [
    /* ================= findings: each fails on today's v3 ================= */

    /* ---- monitor mode scans every other member when one is a gap (MuleSoft's mcp.rs; v3's README "every scan of a leg runs") ---- */
    {
        finding: 'P3GATE-CONF-MON-GAP', title: 'Monitor mode, an MCP batch whose first member is over maxScanChars: the other two members are still scanned (MuleSoft judges the gap on its own scan and scans on), and the batch is forwarded',
        setup: Object.assign(S.req(S.P.mcp, [call(1, S.filler(200)), call(2, 'Card ' + C), call(3, 'hello')], MCPH),
            { legs: ['request'], vars: { enforcementMode: 'monitor', maxScanChars: '60' }, airs: R.answers('block-tool-input', 'allow-tool') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x, 'request');
            return S.check(x && !x.fault && x.calls.length === 2 && l && l.mode === 'monitor',
                           'the other members were not scanned (the would-be block in member 2 leaves no verdict): ' + state(x) + ' log ' + JSON.stringify(l));
        }
    },

    /* ---- the hook SharedFlows' type parameter must not outlive the hook's run (an unlisted route passes untouched) ---- */
    {
        finding: 'P3GATE-CONF-HOOK-TYPE', title: 'Only the pre-target hook attached, a route airs_hook doesn\'t list, the proxy naming its legs with V2\'s scanType: its reply is scanned and passes, not refused as a setting problem on the hook\'s leftover type=user-prompt',
        setup: Object.assign(ask(), { kvm: UNLISTED, response: chatReply('Hi.'), airs: R.answers('allow-prompt', 'allow-prompt-response'),
            runs: [{ leg: 'request', params: { scanType: 'prompt' } }, { leg: 'request', params: HOOK_REQ }, { leg: 'response', params: { scanType: 'response' } }] }),
        v3: function (r) {
            var x = r.runs[2];
            return S.check(x && !x.fault && x.calls.length === 1 && v(x, 'phase') === 'response', 'the proxy\'s own reply leg was not scanned as scanType says: ' + state(x));
        }
    },
    {
        finding: 'P3GATE-CONF-HOOK-TYPE', title: 'Both hooks attached, a route airs_hook doesn\'t list, a reply-leg-only proxy with V2\'s scanType=both: its prompt is judged with the reply, not dropped because the post-target hook left type=response-prompt',
        setup: Object.assign(ask('Prompt text. ' + M), { kvm: UNLISTED, response: chatReply('Hi.'), airs: R.answers('allow-prompt-response'),
            runs: [{ leg: 'request', params: HOOK_REQ }, { leg: 'response', params: HOOK_RESP }, { leg: 'response', params: { scanType: 'both' } }] }),
        v3: function (r) {
            var x = r.runs[2];
            return S.check(x && !x.fault && x.calls.length === 1 && v(x, 'phase') === 'both' && S.has(x, 'Prompt text. ' + M), 'scanType=both was read as another leg\'s type, and the prompt was not scanned: ' + state(x) + ', phase ' + v(x, 'phase') + ', scanned "' + (x ? x.scanned : '') + '"');
        }
    },

    /* ---- a hook's run takes airs_hook's settings, not the parameters another FlowCallout left on the flow ---- */
    {
        finding: 'P3GATE-CONF-HOOK-PARAMS', title: 'A listed proxy with its own request-leg FlowCallout (failOpen=true), the post-target hook scanning its reply with airs_hook failOpen=false: a reply scan with no answer is withheld, not failed open on the FlowCallout\'s leftover parameter',
        setup: Object.assign(ask(), { kvm: { airs_hook: JSON.stringify({ routes: ['/lab'], settings: { failOpen: 'false' } }) },
            runs: [{ leg: 'request', params: { type: 'user-prompt', failOpen: 'true' } }, { leg: 'response', params: HOOK_RESP }],
            airs: R.answers('allow-prompt', R.noAnswer('timeout')), response: chatReply('Hi.') }),
        v3: function (r) {
            var x = r.runs[1];
            return S.check(x && x.fault && x.calls.length === 1, 'the hook\'s reply scan used the FlowCallout\'s failOpen=true, not airs_hook\'s: ' + state(x));
        }
    },
    {
        finding: 'P3GATE-CONF-HOOK-PARAMS', title: 'The same proxy, its request-leg FlowCallout in monitor mode, airs_hook with no enforcementMode (enforce): the hook withholds a reply the profile blocks',
        setup: Object.assign(ask(), { kvm: { airs_hook: JSON.stringify({ routes: ['/lab'], settings: {} }) },
            runs: [{ leg: 'request', params: { type: 'user-prompt', enforcementMode: 'monitor' } }, { leg: 'response', params: HOOK_RESP }],
            airs: R.answers('allow-prompt', 'block-dlp-response-masked'), response: chatReply('Card on file: ' + C) }),
        v3: function (r) {
            var x = r.runs[1];
            return S.check(x && x.blocked && String(x.body).indexOf(C) === -1, 'the hook\'s reply scan ran in the FlowCallout\'s monitor mode: ' + state(x));
        }
    },

    /* ---- the runner: a run answered wholly from the verdict cache is not a silent run (run.py cache_one_scan_for_repeat) ---- */
    {
        finding: 'P3GATE-CONF-RUNNER-CACHED', title: 'The same prompt twice through one cache, as two runs on one flow (run.py cache_one_scan_for_repeat): one scan, and the second request passes on the cached allow, logged cached; test/run.js must accept that run as it accepts such a leg',
        setup: Object.assign(ask(), { vars: { verdictCacheTtlS: '60' }, runs: requests(2), airs: R.answers('allow-prompt', 'block-injection-agent-prompt') }),
        v3: function (r) {
            var x = r.runs[1], l = x && x.lines && x.lines.length ? x.lines[x.lines.length - 1] : null;
            return S.check(callsOf(r) === '[1,0]' && x && !x.fault && l && String(l.cached) === '1' && l.scan_id === 'SCAN_ID', 'calls ' + callsOf(r) + ': ' + runsState(r));
        }
    },

    /* ================= guards: MuleSoft's tests, ported; they pass today ================= */

    /* ---- the circuit breaker's sequences (core/tests/breaker.rs; run.py breaker_stops_calls), as requests in a row ---- */
    {
        finding: 'P3GATE-CONF-GUARD-BRK', title: 'Guard: breakerFailures=2 (breaker_opens_after_threshold, run.py breaker_stops_calls): one failure is below the threshold, the second opens it, and the third request makes no call',
        setup: Object.assign(ask(), { vars: { breakerFailures: '2', failOpen: 'true' }, runs: requests(3), airs: R.answers(R.noAnswer('timeout'), R.noAnswer('timeout'), 'allow-prompt') }),
        v3: function (r) {
            var x = r.runs[2];
            return S.check(callsOf(r) === '[1,1,0]' && x && !x.fault && /circuit breaker is open/.test(v(x, 'logNote')), 'calls ' + callsOf(r) + ': ' + runsState(r));
        }
    },
    {
        finding: 'P3GATE-CONF-GUARD-BRK', title: 'Guard: breakerFailures=2, a failure, an answer, a failure (success_resets_the_count): the count started again, so the fourth request still calls',
        setup: Object.assign(ask(), { vars: { breakerFailures: '2', failOpen: 'true' }, runs: requests(4), airs: R.answers(R.noAnswer('timeout'), 'allow-prompt', R.noAnswer('timeout'), 'allow-prompt') }),
        v3: function (r) { var s = storedB(r.runs[3]); return S.check(callsOf(r) === '[1,1,1,1]' && s && s.failures === 0 && s.openUntil === 0, 'calls ' + callsOf(r) + ', state ' + JSON.stringify(s) + ': ' + runsState(r)); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-BRK', title: 'Guard: after the cooldown, a trial that is answered closes the breaker, and one failure after it is below the threshold again (breaker_half_open_after_cooldown: "after a success the count starts again")',
        setup: Object.assign(ask(), { vars: { breakerFailures: '2', failOpen: 'true' }, cache: seedB(2, NOW - 1000), runs: requests(3),
            airs: R.answers('allow-prompt', R.noAnswer('timeout'), 'allow-prompt') }),
        v3: function (r) { var s = storedB(r.runs[2]); return S.check(callsOf(r) === '[1,1,1]' && s && s.failures === 0 && s.openUntil === 0, 'calls ' + callsOf(r) + ', state ' + JSON.stringify(s) + ': ' + runsState(r)); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-BRK', title: 'Guard: after the cooldown, a trial that fails re-opens the breaker, and the next request makes no call (breaker_half_open_after_cooldown: "a failed trial re-opens the breaker")',
        setup: Object.assign(ask(), { vars: { breakerFailures: '2', failOpen: 'true' }, cache: seedB(2, NOW - 1000), runs: requests(2), airs: R.answers(R.noAnswer('timeout'), 'allow-prompt') }),
        v3: function (r) { return S.check(callsOf(r) === '[1,0]' && isOpen(storedB(r.runs[1])), 'calls ' + callsOf(r) + ', state ' + JSON.stringify(storedB(r.runs[1])) + ': ' + runsState(r)); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-BRK', title: 'Guard: two failures counted, then an allow whose detection service failed (error: true): a failure (scan.rs: Incomplete is an Err, so record_failure), and the breaker opens',
        setup: Object.assign(ask(), { legs: ['request'], vars: { breakerFailures: '3' }, cache: seedB(2, 0),
            airs: R.answers({ status: 200, body: { action: 'allow', category: 'benign', error: true, errors: [{ code: 'x' }], scan_id: 'SCAN_ID' } }) }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && isOpen(storedB(x)), 'not opened: ' + JSON.stringify(storedB(x)) + ' ' + state(x)); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-BRK', title: 'Guard: two failures counted, scanRetries=1, then HTTP 401: not retried (retryable_table), a failure, and the breaker opens',
        setup: Object.assign(ask(), { legs: ['request'], vars: { breakerFailures: '3', scanRetries: '1' }, cache: seedB(2, 0),
            airs: R.answers(R.status(401, '{"error":{"message":"unauthorized"}}'), 'allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && x.calls.length === 1 && isOpen(storedB(x)), 'not one call and opened: ' + JSON.stringify(storedB(x)) + ' ' + state(x)); }
    },

    /* ---- the retry table (core/tests/breaker.rs retryable_table), with scanRetries=1 ---- */
    {
        finding: 'P3GATE-CONF-GUARD-RETRY', title: 'Guard: HTTP 413 is not retried (retryable_table); one call, refused',
        setup: Object.assign(ask(), { legs: ['request'], vars: { scanRetries: '1' }, airs: R.answers(R.status(413, '{"error":{"message":"too large"}}'), 'allow-prompt') }),
        v3: function (r) { return after(r.request, 1, false); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-RETRY', title: 'Guard: HTTP 500, then an allow: retried (retryable_table: 500..=599), passed',
        setup: Object.assign(ask(), { legs: ['request'], vars: { scanRetries: '1' }, airs: R.answers(R.status(500, '{"error":"internal"}'), 'allow-prompt') }),
        v3: function (r) { return after(r.request, 2, true); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-RETRY', title: 'Guard: HTTP 599, then an allow: retried (retryable_table), passed',
        setup: Object.assign(ask(), { legs: ['request'], vars: { scanRetries: '1' }, airs: R.answers(R.status(599, ''), 'allow-prompt') }),
        v3: function (r) { return after(r.request, 2, true); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-RETRY', title: 'Guard: HTTP 200 with no action (MissingAction) is not retried; one call, refused as a scanner failure',
        setup: Object.assign(ask(), { legs: ['request'], vars: { scanRetries: '1' }, airs: R.answers(R.status(200, '{"category":"benign","scan_id":"SCAN_ID"}'), 'allow-prompt') }),
        v3: function (r) { var g = after(r.request, 1, false); return g !== true ? g : S.check(v(r.request, 'outcome') === 'failure', 'not a failure: ' + state(r.request)); }
    },

    /* ---- the verdict cache (core/tests/cache.rs; run.py cache_one_scan_for_repeat) ---- */
    {
        finding: 'P3GATE-CONF-GUARD-VC', title: 'Guard: an allow is kept for verdictCacheTtlS and no longer (cache_hit_within_ttl_miss_after): written to expire 60 s from now',
        setup: Object.assign(ask(), { legs: ['request'], vars: { verdictCacheTtlS: '60' }, airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var e = r.request && r.request.flow.cache[HELLO], left = e && e.expires !== null ? e.expires - Date.now() : null;
            return S.check(e && e.value === 'SCAN_ID' && left !== null && left > 55000 && left <= 60000, 'not kept for 60 s: ' + JSON.stringify(e) + ' ' + state(r.request));
        }
    },
    {
        finding: 'P3GATE-CONF-GUARD-VC', title: 'Guard: another endpoint is another key (cache_key_differs...: service-de): the default endpoint\'s entry is no hit',
        setup: Object.assign(ask(), { legs: ['request'], vars: { verdictCacheTtlS: '60', prismaAirsEndpoint: 'service-de.api.aisecurity.paloaltonetworks.com' },
            cache: seed([[HELLO, 'x']]), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.calls.length === 1 && x.flow.cache[vcKey('request', [{ prompt: 'hello' }], { ep: 'service-de.api.aisecurity.paloaltonetworks.com' })], 'the other endpoint\'s entry answered, or none was written: ' + state(x)); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-VC', title: 'Guard: truncationFailClosed=false is another key (cache_key_differs...): the entry made with true is no hit',
        setup: Object.assign(ask(), { legs: ['request'], vars: { verdictCacheTtlS: '60', truncationFailClosed: 'false' }, cache: seed([[HELLO, 'x']]), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.calls.length === 1, 'the entry made with truncationFailClosed=true answered: ' + state(x)); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-VC', title: 'Guard: on the reply leg the prompt context is in the key (cache_key_differs...: "context"): an entry for the same reply with another prompt is no hit',
        setup: Object.assign(ask(), { legs: ['request', 'response'], vars: { verdictCacheTtlS: '60' }, response: chatReply('Hi.'),
            cache: seed([[vcKey('response', [{ prompt: 'another prompt', response: 'Hi.' }]), 'x']]), airs: R.answers('allow-prompt', 'allow-prompt-response') }),
        v3: function (r) { var x = r.response; return S.check(x && !x.fault && x.calls.length === 1, 'another prompt\'s entry answered the reply: ' + state(x)); }
    },
    {
        finding: 'P3GATE-CONF-GUARD-VC', title: 'Guard: the control for the case above: the entry for this prompt and this reply is a hit, and the reply leg makes no call',
        setup: Object.assign(ask(), { legs: ['request', 'response'], vars: { verdictCacheTtlS: '60' }, response: chatReply('Hi.'),
            cache: seed([[vcKey('response', [{ prompt: 'hello', response: 'Hi.' }]), 'scan-from-cache']]), airs: R.answers('allow-prompt', 'block-dlp-response-masked') }),
        v3: function (r) { var x = r.response, l = lastLog(x, 'response'); return S.check(x && !x.fault && x.calls.length === 0 && l && String(l.cached) === '1', 'not answered from the cache: ' + state(x)); }
    },

    /* ---- monitor mode (core/tests/decision.rs monitor_never_blocks_or_masks: Gap::Encoded) ---- */
    {
        finding: 'P3GATE-CONF-GUARD-MON', title: 'Guard: monitor mode, a compressed reply v3 can\'t read: passes unchanged, logged gap_unenforced (monitor_never_blocks_or_masks)',
        setup: Object.assign(ask(), { legs: ['request', 'response'], vars: { enforcementMode: 'monitor' }, airs: R.answers('allow-prompt'),
            response: { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, content: '\u001f\u008b\u0008\u0000AIRSV3-MARKER' } }),
        v3: function (r) {
            var x = r.response, l = lastLog(x, 'response');
            return S.check(x && !x.fault && l && l.outcome === 'gap_unenforced' && String(x.flow.messages.response.content).indexOf('AIRSV3-MARKER') !== -1, 'not passed as gap_unenforced: ' + state(x));
        }
    }
];

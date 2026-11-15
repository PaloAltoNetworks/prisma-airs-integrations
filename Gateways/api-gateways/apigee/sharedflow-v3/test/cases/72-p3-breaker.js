'use strict';
/*
 * Phase 3, the circuit breaker (15 Nov 2026): breakerFailures (0 = off) and breakerCooldownS (30), MuleSoft's settings and
 * rule (core/src/breaker.rs: "After threshold consecutive failures the breaker opens, and for the cooldown the policy does
 * not call AIRS at all ... An open breaker never allows traffic: the request is then decided like any other scanner failure
 * (onApiError). After the cooldown, calls are tried again; a success closes the breaker and a failure opens it for another
 * cooldown"; src/scan.rs records every failed call, retries included, as a failure, and every verdict as a success).
 *   v3 differs on one point (gate review, P3GATE-CONF-BRK-4XX): a 400 or 413, Prisma AIRS refusing the content, resets the
 *   count, where scan.rs counts any status but 200 as a failure. The state is shared by every proxy on the tenant (below), so
 *   one client's content would otherwise open the breaker for all of them; the README says so.
 *   - P3-BRK: on Apigee the state lives in the environment's cache (L19: a SharedFlow's cache is shared by every proxy that
 *     calls it), under a key that is SHA-256 of the endpoint and the API key (L18), so two tenants never share a breaker and
 *     the key is never stored. It is read once per leg, before the first call, and written after the leg's calls, in slot
 *     order; MuleSoft's breaker is per worker and read before every call. Its counts are approximate under concurrency.
 * The state is JSON: {"failures": n, "openUntil": ms since the epoch, 0 when closed}. Each case seeds it and reads it back.
 * Each case names the replies its calls get; the only marked text is AIRSV3-MARKER and the test card.
 */
const crypto = require('crypto');
const S = require('./_shapes');
const R = require('../harness/replies');
const KEY = 'lab-key-for-unit-tests';                                   // test/run.js's Prisma AIRS key
const EP = 'service.api.aisecurity.paloaltonetworks.com';
const BKEY = 'airs3-breaker-' + crypto.createHash('sha256').update(EP + '\n' + KEY, 'utf8').digest('hex');
const ON = { breakerFailures: '3' };
const NOW = Date.now();

function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' call(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 140) : ', passed');
}
function ask() { return S.chat([{ role: 'user', content: 'hello' }]); }
function seed(failures, openUntil) { var c = {}; c[BKEY] = JSON.stringify({ failures: failures, openUntil: openUntil }); return c; }
function stored(x) { var e = x && x.flow && x.flow.cache[BKEY]; try { return e ? JSON.parse(e.value) : null; } catch (err) { return 'unreadable'; } }
function lastLog(x, leg) {
    var l = x && x.flow ? x.flow.logs : [], out = null;
    for (var i = 0; i < l.length; i++) { try { var j = JSON.parse(l[i].line); if (j.leg === leg) { out = j; } } catch (e) { /* not a v3 line */ } }
    return out;
}
function isClosed(s, failures) { return !!(s && s.failures === failures && s.openUntil === 0); }
function isOpen(s) { return !!(s && s.openUntil > NOW + 20000); }                 // about now + 30 s
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }

module.exports = [
    /* ---------------- counting ---------------- */
    {
        finding: 'P3-BRK', title: 'Closed, an allow: passed, and no state written (nothing to count)',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && !x.fault && stored(x) === null, 'state written: ' + JSON.stringify(stored(x)) + ' ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'Closed, no answer: a scanner failure, and one failure counted',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, airs: R.answers(R.noAnswer('timeout')) }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && isClosed(stored(x), 1), 'not one failure counted: ' + JSON.stringify(stored(x)) + ' ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'Two failures counted, a third (HTTP 503): the breaker opens for the cooldown',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, cache: seed(2, 0), airs: R.answers(R.status(503, '{"error":"unavailable"}')) }),
        v3: function (r) { var x = r.request, s = stored(x); return S.check(x && x.fault && isOpen(s) && s.failures === 3, 'not opened: ' + JSON.stringify(s) + ' ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'Two failures counted, then a block: a verdict closes the count (refused as the block)',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, cache: seed(2, 0), airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.blocked && isClosed(stored(x), 0), 'the count was not reset: ' + JSON.stringify(stored(x)) + ' ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'Two failures counted, then HTTP 400 (Prisma AIRS refused the content on purpose): an answer, so the count is reset',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, cache: seed(2, 0), airs: R.answers('error-400-prompt-too-long') }),
        v3: function (r) { var x = r.request; return S.check(x && isClosed(stored(x), 0), 'the count was not reset: ' + JSON.stringify(stored(x)) + ' ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'With scanRetries=1, one failure counted, then no answer twice: both calls count, and the breaker opens',
        setup: Object.assign(ask(), { legs: ['request'], vars: Object.assign({ scanRetries: '1' }, ON), cache: seed(1, 0),
            airs: R.answers(R.noAnswer('timeout'), R.noAnswer('timeout')) }),
        v3: function (r) { var x = r.request, s = stored(x); return S.check(x && x.calls.length === 2 && isOpen(s), 'not opened after the retry: ' + JSON.stringify(s) + ' ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'MCP batch, failOpen=true: no answer, an allow, no answer: counted in slot order, so one failure remains',
        setup: Object.assign(S.req(S.P.mcp, [call(1, 'hello'), call(2, 'hello'), call(3, 'hello')], { Accept: 'application/json, text/event-stream' }),
            { legs: ['request'], vars: Object.assign({ failOpen: 'true' }, ON), airs: R.answers(R.noAnswer('timeout'), 'allow-tool', R.noAnswer('timeout')) }),
        v3: function (r) { var x = r.request; return S.check(x && x.calls.length === 3 && isClosed(stored(x), 1), 'not one failure: ' + JSON.stringify(stored(x)) + ' ' + state(x)); }
    },

    {
        finding: 'P3-BRK', title: 'MCP batch, failOpen=true, two failures counted: slot 1 gets no answer and the breaker opens; the allows after it are not counted (MuleSoft would not have called)',
        setup: Object.assign(S.req(S.P.mcp, [call(1, 'hello'), call(2, 'hello'), call(3, 'hello')], { Accept: 'application/json, text/event-stream' }),
            { legs: ['request'], vars: Object.assign({ failOpen: 'true' }, ON), cache: seed(2, 0), airs: R.answers(R.noAnswer('timeout'), 'allow-tool', 'allow-tool') }),
        v3: function (r) { var x = r.request, s = stored(x); return S.check(x && x.calls.length === 3 && isOpen(s), 'closed again by later answers: ' + JSON.stringify(s) + ' ' + state(x)); }
    },

    /* ---------------- open ---------------- */
    {
        finding: 'P3-BRK', title: 'Open: Prisma AIRS is not called, and the request is refused as a scanner failure (failOpen is false)',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, cache: seed(3, NOW + 60000), airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x, 'request');
            return S.check(x && x.fault && x.calls.length === 0 && l && l.outcome === 'failure' && /circuit breaker is open/.test(l.note), 'not refused without a call: ' + state(x));
        }
    },
    {
        finding: 'P3-BRK', title: 'Open, failOpen=true: passes unscanned, logged as failed open',
        setup: Object.assign(ask(), { legs: ['request'], vars: Object.assign({ failOpen: 'true' }, ON), cache: seed(3, NOW + 60000), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && !x.fault && x.calls.length === 0 && /^failed open: the circuit breaker is open/.test(v(x, 'logNote')), 'not passed as failed open: ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'Open, monitor mode: passes unscanned, logged failed_open',
        setup: Object.assign(ask(), { legs: ['request'], vars: Object.assign({ enforcementMode: 'monitor' }, ON), cache: seed(3, NOW + 60000), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request, l = lastLog(x, 'request'); return S.check(x && !x.fault && x.calls.length === 0 && l && l.outcome === 'failed_open', 'not passed as failed_open: ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'Cooldown over: one call is tried (half-open); an allow closes the breaker',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, cache: seed(3, NOW - 1000), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && !x.fault && x.calls.length === 1 && isClosed(stored(x), 0), 'not closed: ' + JSON.stringify(stored(x)) + ' ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'Cooldown over, the trial call gets no answer: open again at once, whatever the count (here 1, as legs running at once can leave it)',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, cache: seed(1, NOW - 1000), airs: R.answers(R.noAnswer('timeout')) }),
        v3: function (r) { var x = r.request; return S.check(x && x.calls.length === 1 && isOpen(stored(x)), 'not reopened: ' + JSON.stringify(stored(x)) + ' ' + state(x)); }
    },

    /* ---------------- scope and settings ---------------- */
    {
        finding: 'P3-BRK', title: 'Another tenant\'s open breaker (another key\'s entry) changes nothing here: the call is made',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, airs: R.answers('allow-prompt'),
            cache: (function () { var c = {}; c['airs3-breaker-' + crypto.createHash('sha256').update(EP + '\nanother-tenant-key', 'utf8').digest('hex')] = JSON.stringify({ failures: 3, openUntil: NOW + 60000 }); return c; })() }),
        v3: function (r) { var x = r.request; return S.check(x && !x.fault && x.calls.length === 1, 'the other tenant\'s breaker applied: ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'Guard: breakerFailures unset (0): an open entry is not read, the call is made, and nothing is written',
        setup: Object.assign(ask(), { legs: ['request'], cache: seed(3, NOW + 60000), airs: R.answers(R.noAnswer('timeout')) }),
        v3: function (r) {
            var x = r.request, s = stored(x);
            return S.check(x && x.calls.length === 1 && s && s.failures === 3 && s.openUntil === NOW + 60000, 'the breaker ran with the setting off: ' + JSON.stringify(s) + ' ' + state(x));
        }
    },
    {
        finding: 'P3-BRK', title: 'breakerFailures=101 (over 100): every request refused as a setting problem, naming breakerFailures',
        setup: Object.assign(ask(), { legs: ['request'], vars: { breakerFailures: '101' }, airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && /breakerFailures/.test(x.body) && x.calls.length === 0, 'not refused naming the setting: ' + state(x)); }
    },
    {
        finding: 'P3-BRK', title: 'breakerCooldownS=0 (under 1): every request refused as a setting problem, naming breakerCooldownS',
        setup: Object.assign(ask(), { legs: ['request'], vars: Object.assign({ breakerCooldownS: '0' }, ON), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && /breakerCooldownS/.test(x.body) && x.calls.length === 0, 'not refused naming the setting: ' + state(x)); }
    }
];

'use strict';
/*
 * Phase 3, the verdict cache (15 Nov 2026): verdictCacheTtlS (0 = off, at most 300), MuleSoft's setting and rule
 * (core/src/cache.rs: "It stores allow verdicts only: a cached block would freeze a false positive for the whole TTL ...
 * The key is SHA-256 over every input that can change a verdict, each field length-prefixed so two fields can never run
 * into each other. The API key is one of those inputs (two tenants never share an entry); it is hashed, never stored";
 * settings.rs: "The verdict cache runs only with a TTL and never with masking"; src/scan.rs: the cache is read before the
 * breaker, and an allow with a scan id is written).
 *   - P3-VC: v3's key, the spec these cases share with airs3-cache.js: 'airs3-verdict-' + SHA-256 (hex) of the fields
 *     'airs3-vc-1', the API key, the endpoint, the scan's ai_profile as JSON, the leg, maxScanChars, truncationFailClosed
 *     and the scan's contents as JSON, each written as its length, ':', then itself. Ids and metadata stay out, as in
 *     MuleSoft (they never change a verdict). v3 masks an allow that carries a masked copy whatever applyDlpMasking says,
 *     so such an allow is never written either. Inside a SharedFlow the cache is shared by every proxy (L19); the key keeps
 *     tenants and profiles apart.
 * Each case names the replies its calls get; the only marked text is AIRSV3-MARKER and the test card.
 */
const crypto = require('crypto');
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const KEY = 'lab-key-for-unit-tests';                                   // test/run.js's Prisma AIRS key
const EP = 'service.api.aisecurity.paloaltonetworks.com';
const ON = { verdictCacheTtlS: '60' };
const PROFILE = { profile_name: 'PROFILE_NAME' };                          // test/run.js's config map profile

function vcKey(leg, profile, contents, maxChars, truncClosed) {
    var parts = ['airs3-vc-1', KEY, EP, JSON.stringify(profile), leg, String(maxChars || 100000), String(truncClosed === undefined ? true : truncClosed), JSON.stringify(contents)];
    return 'airs3-verdict-' + crypto.createHash('sha256').update(parts.map(function (p) { return p.length + ':' + p; }).join(''), 'utf8').digest('hex');
}
function seed(pairs) { var c = {}; pairs.forEach(function (p) { c[p[0]] = p[1]; }); return c; }
function written(x) {
    var out = {}, c = x && x.flow ? x.flow.cache : {};
    for (var k in c) { if (k.indexOf('airs3-verdict-') === 0) { out[k] = c[k].value; } }
    return out;
}
function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function lastLog(x, leg) {
    var l = x && x.flow ? x.flow.logs : [], out = null;
    for (var i = 0; i < l.length; i++) { try { var j = JSON.parse(l[i].line); if (j.leg === leg) { out = j; } } catch (e) { /* not a v3 line */ } }
    return out;
}
function state(x) {
    return !x ? 'the leg did not run' : 'HTTP ' + x.status + ', ' + x.calls.length + ' call(s), route ' + v(x, 'route') + ', outcome ' + v(x, 'outcome') +
        ', note "' + v(x, 'logNote') + '"' + (x.fault ? ', refused: ' + String(x.body).slice(0, 140) : ', passed');
}
function ask(text) { return S.chat([{ role: 'user', content: text || 'hello' }]); }
const HELLO = vcKey('request', PROFILE, [{ prompt: 'hello' }]);
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }

module.exports = [
    /* ---------------- written ---------------- */
    {
        finding: 'P3-VC', title: 'A miss, then an allow: passed, and the allow written under the key, holding only its scan id',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request, w = written(x); return S.check(x && !x.fault && x.calls.length === 1 && w[HELLO] === 'SCAN_ID' && Object.keys(w).length === 1, 'not written as specified: ' + JSON.stringify(w) + ' ' + state(x)); }
    },
    {
        finding: 'P3-VC', title: 'A block is never written (cache.rs: a cached block would freeze a false positive)',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.blocked && Object.keys(written(x)).length === 0, 'a block was written: ' + JSON.stringify(written(x))); }
    },
    {
        finding: 'P3-VC', title: 'An allow that carries a masked copy is never written: a hit would skip the mask v3 writes for it',
        setup: Object.assign(ask('My card number is ' + C + '.'), { legs: ['request'], vars: ON, airs: R.answers(R.asAllow('block-dlp-prompt-masked')) }),
        v3: function (r) { var x = r.request; return S.check(x && Object.keys(written(x)).length === 0, 'a masked allow was written: ' + JSON.stringify(written(x)) + ' ' + state(x)); }
    },
    {
        finding: 'P3-VC', title: 'An allow that reports an error (a failed detection service) is never written',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON,
            airs: R.answers({ status: 200, body: { action: 'allow', category: 'benign', error: true, errors: [{ code: 'x' }], scan_id: 'SCAN_ID' } }) }),
        v3: function (r) { var x = r.request; return S.check(x && Object.keys(written(x)).length === 0, 'written: ' + JSON.stringify(written(x)) + ' ' + state(x)); }
    },

    /* ---------------- read ---------------- */
    {
        finding: 'P3-VC', title: 'A hit: Prisma AIRS is not called; passed, logged as cached with the stored scan id',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, cache: seed([[HELLO, 'scan-from-cache']]), airs: R.answers('block-injection-agent-prompt') }),
        v3: function (r) {
            var x = r.request, l = lastLog(x, 'request');
            return S.check(x && !x.fault && x.calls.length === 0 && l && String(l.cached) === '1' && l.scan_id === 'scan-from-cache', 'not answered from the cache: ' + state(x) + ' ' + JSON.stringify(l));
        }
    },
    {
        finding: 'P3-VC', title: 'Another profile\'s entry for the same text is no hit: the call is made',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, cache: seed([[vcKey('request', { profile_name: 'OTHER' }, [{ prompt: 'hello' }]), 'x']]), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.calls.length === 1, 'another profile\'s entry answered: ' + state(x)); }
    },
    {
        finding: 'P3-VC', title: 'An entry made under another API key (another tenant) is no hit: the call is made',
        setup: Object.assign(ask(), { legs: ['request'], vars: ON, airs: R.answers('allow-prompt'),
            cache: (function () {
                var parts = ['airs3-vc-1', 'another-tenant-key', EP, JSON.stringify(PROFILE), 'request', '100000', 'true', JSON.stringify([{ prompt: 'hello' }])];
                var k = 'airs3-verdict-' + crypto.createHash('sha256').update(parts.map(function (p) { return p.length + ':' + p; }).join(''), 'utf8').digest('hex');
                return seed([[k, 'x']]);
            })() }),
        v3: function (r) { var x = r.request; return S.check(x && x.calls.length === 1, 'another tenant\'s entry answered: ' + state(x)); }
    },
    {
        finding: 'P3-VC', title: 'Another maxScanChars is another key: the entry made with the default is no hit at 50,000',
        setup: Object.assign(ask(), { legs: ['request'], vars: Object.assign({ maxScanChars: '50000' }, ON), cache: seed([[HELLO, 'x']]), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.calls.length === 1, 'the default size\'s entry answered: ' + state(x)); }
    },
    {
        finding: 'P3-VC', title: 'MCP batch of two: slot 1 a hit, slot 2 a miss: one call, both allowed, slot 2 written',
        setup: Object.assign(S.req(S.P.mcp, [call(1, 'hello'), call(2, 'hello there')], { Accept: 'application/json, text/event-stream' }), { legs: ['request'], vars: ON, airs: R.answers('allow-tool'),
            cache: seed([[vcKey('request', PROFILE, [{ tool_event: { metadata: { ecosystem: 'mcp', method: 'tools/call', server_name: 'lab-proxy', tool_invoked: 'echo' }, input: '{"text":"hello"}' } }]), 'cached-1']]) }),
        v3: function (r) {
            var x = r.request, w = written(x), l = lastLog(x, 'request');
            return S.check(x && !x.fault && x.calls.length === 1 && Object.keys(w).length === 2 && l && String(l.cached) === '1', 'not one hit and one call: ' + JSON.stringify(w) + ' ' + state(x));
        }
    },

    /* ---------------- with the other settings ---------------- */
    {
        finding: 'P3-VC', title: 'applyDlpMasking=true: the cache is not used (settings.rs: never with masking); a stored entry is not read',
        setup: Object.assign(ask(), { legs: ['request'], vars: Object.assign({ applyDlpMasking: 'true' }, ON), cache: seed([[HELLO, 'x']]), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.calls.length === 1, 'the cache answered with masking on: ' + state(x)); }
    },
    {
        finding: 'P3-VC', title: 'An open circuit breaker, but every scan of the leg is a hit: passed without a call (the cache is read before the breaker)',
        setup: Object.assign(ask(), { legs: ['request'], vars: Object.assign({ breakerFailures: '3' }, ON), airs: R.answers('allow-prompt'),
            cache: (function () {
                var c = seed([[HELLO, 'scan-from-cache']]);
                c['airs3-breaker-' + crypto.createHash('sha256').update(EP + '\n' + KEY, 'utf8').digest('hex')] = JSON.stringify({ failures: 3, openUntil: Date.now() + 60000 });
                return c;
            })() }),
        v3: function (r) { var x = r.request; return S.check(x && !x.fault && x.calls.length === 0, 'refused by the breaker, or called: ' + state(x)); }
    },
    {
        finding: 'P3-VC', title: 'Breaker on with two failures counted, an MCP batch: slot 1 a hit, slot 2 no answer: a hit is no call, so this is the third failure in a row, and the breaker opens',
        setup: Object.assign(S.req(S.P.mcp, [call(1, 'hello'), call(2, 'hello there')], { Accept: 'application/json, text/event-stream' }),
            { legs: ['request'], vars: Object.assign({ breakerFailures: '3' }, ON), airs: R.answers(R.noAnswer('timeout')),
              cache: (function () {
                  var c = seed([[vcKey('request', PROFILE, [{ tool_event: { metadata: { ecosystem: 'mcp', method: 'tools/call', server_name: 'lab-proxy', tool_invoked: 'echo' }, input: '{"text":"hello"}' } }]), 'cached-1']]);
                  c['airs3-breaker-' + crypto.createHash('sha256').update(EP + '\n' + KEY, 'utf8').digest('hex')] = JSON.stringify({ failures: 2, openUntil: 0 });
                  return c;
              })() }),
        v3: function (r) {
            var x = r.request, e = x && x.flow.cache['airs3-breaker-' + crypto.createHash('sha256').update(EP + '\n' + KEY, 'utf8').digest('hex')], s = null;
            try { s = JSON.parse(e.value); } catch (err) { s = null; }
            return S.check(x && x.calls.length === 1 && s && s.openUntil > Date.now(), 'the breaker did not open: ' + JSON.stringify(s) + ' ' + state(x));
        }
    },
    {
        finding: 'P3-VC', title: 'Guard: verdictCacheTtlS unset (0): a stored entry is not read, the call is made, and nothing is written',
        setup: Object.assign(ask(), { legs: ['request'], cache: seed([[HELLO, 'x']]), airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request, w = written(x); return S.check(x && x.calls.length === 1 && Object.keys(w).length === 1 && w[HELLO] === 'x', 'the cache ran with the setting off: ' + JSON.stringify(w) + ' ' + state(x)); }
    },
    {
        finding: 'P3-VC', title: 'verdictCacheTtlS=301 (over 300): every request refused as a setting problem, naming verdictCacheTtlS',
        setup: Object.assign(ask(), { legs: ['request'], vars: { verdictCacheTtlS: '301' }, airs: R.answers('allow-prompt') }),
        v3: function (r) { var x = r.request; return S.check(x && x.fault && /verdictCacheTtlS/.test(x.body) && x.calls.length === 0, 'not refused naming the setting: ' + state(x)); }
    }
];

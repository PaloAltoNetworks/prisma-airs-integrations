'use strict';
/*
 * Phase 2 gate, lens: Apigee realism of the scan-slot flow (runtime 1-18-0-apigee-8, Rhino 1.7.13).
 * Each case runs the SharedFlow's own XML and JavaScript under the harness, with recorded Prisma AIRS replies; nothing
 * decides a verdict from content. Texts are harmless: plain sentences, AIRSV3-MARKER and the Visa test card.
 *   - P2GATE-AR*: findings, each a case that fails on today's v3 and passes once v3 behaves as v3's rules and MuleSoft's
 *     rules require.
 *   - P2GATE-G*: regression guards, which pass today, for slot behaviour that a live runtime could break and the rest of
 *     the suite does not pin.
 * What the live lab already settled (VERIFICATION.md): slots 1 to 3 on the request leg (P2B3: 3 scans,
 * so AM-Airs3ClearScan<k>'s AssignVariable mark lands beside its AssignTo createNew), the early stop (P2B4: 2 scans of 3,
 * so JS-Airs3Slot2 read properties.slot as 2 on Rhino), and no key in Debug for slots 1 to 3. Not settled live: slots 4 to
 * 8, any reply-leg slot above 1, and whether AssignTo createNew empties a message a ServiceCallout filled on the other leg
 * ("each scan starts clean" is unit only); G2 holds v3's own guard for the 2xx half of that.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD, M = 'AIRSV3-MARKER';
const H = { Accept: 'application/json, text/event-stream' };
const KEY = 'lab-key-for-unit-tests';                  // run.js's config-map key

function rpc(body, headers) { return S.req(S.P.mcp, body, Object.assign({}, H, headers || {})); }
function call(id, text) { return { jsonrpc: '2.0', id: id, method: 'tools/call', params: { name: 'echo', arguments: { text: text } } }; }
function calls(n, text) { var out = []; for (var i = 1; i <= n; i++) { out.push(call(i, (text || 'hello') + ' ' + i)); } return out; }
function ans(id, result) { return { jsonrpc: '2.0', id: id, result: result }; }
function echoed(text) { return { content: [{ type: 'text', text: text }], isError: false }; }
function body(x) { try { return JSON.parse(x.body); } catch (e) { return null; } }
function v(x, leaf) { var s = x && x.flow ? x.flow.get('airs3.' + leaf) : null; return s === null || s === undefined ? '' : String(s); }
function entry(x, i) { var b = x && x.scans[i]; return b && b.contents && b.contents[0]; }
function and() { for (var i = 0; i < arguments.length; i++) { if (arguments[i] !== true) { return arguments[i]; } } return true; }
function refusedBatch(x, ids, code) {
    var b = body(x);
    var got = Array.isArray(b) ? b.map(function (e) { return e && e.error && e.error.code === code ? e.id : 'bad'; }) : null;
    return S.check(x && x.blocked && x.status === 200 && JSON.stringify(got) === JSON.stringify(ids),
                   'not refused as ' + JSON.stringify(ids) + ' with ' + code + ': HTTP ' + (x && x.status) + ' ' + String(x && x.body).slice(0, 200));
}
function refusedOne(x, id, code) {
    var b = body(x);
    return S.check(x && x.blocked && x.status === 200 && b && b.id === id && b.error && b.error.code === code,
                   'not refused as id ' + id + ' with ' + code + ': ' + (x && x.blocked ? 'HTTP ' + x.status + ' ' + String(x.body).slice(0, 200)
                                                                                     : 'passed to the client after ' + (x && x.calls.length) + ' scan(s)'));
}

/* A tools/list page whose cursor carries the card. MCP servers issue nextCursor and clients send it back as
   params.cursor; the request leg never scans a tools/list request's params (MuleSoft's table), so the reply leg's
   tool event is the first scan that holds the cursor: it is the event's input. */
function listPage(id, cursor) { return { jsonrpc: '2.0', id: id, method: 'tools/list', params: { cursor: cursor } }; }
const CATALOGUE = [{ name: 'echo', description: 'Return the given text unchanged.', inputSchema: { type: 'object', properties: { text: { type: 'string' } } } }];

module.exports = [
    /* ================================ findings ================================ */
    {
        finding: 'P2GATE-AR1',
        title: 'Reply leg, two scans (a tools/list answer with a member besides tools): when slot 1 is an allow carrying a masked copy of the ' +
               'tool event\'s input, JS-Airs3Slot1 stops slot 2, yet JS-Airs3Verdict passes the reply, so result.notice reaches the client ' +
               'with no scan (the leg must be withheld, as the slot step judged, or slot 2 scanned)',
        setup: Object.assign(rpc(listPage(2, 'page-2 ' + C)), {
            legs: ['request', 'response'],
            airs: R.answers(R.asAllow('block-tool-input'), 'allow-prompt-response'),
            response: S.reply(ans(2, { tools: CATALOGUE, notice: 'Server notice ' + M })) }),
        v3: function (r) {
            var q = r.request, p = r.response;
            if (!q || q.fault) { return 'the request leg did not pass: ' + (q && q.body); }
            if (!p) { return 'no reply leg ran'; }
            var noticeScanned = p.scans.some(function (s) { var e = s && s.contents && s.contents[0]; return e && String(e.response || '').indexOf(M) !== -1; });
            if (!p.fault && !noticeScanned) {
                return 'the reply passed with result.notice never scanned: ' + p.calls.length + ' scan(s); slotStop=' + v(p, 'slotStop') +
                       ', slotRan2=' + v(p, 'slotRan2') + ', outcome=' + v(p, 'outcome') + ', detections=' + v(p, 'detections');
            }
            return p.fault ? refusedOne(p, 2, -32001) : true;
        }
    },

    /* ================================ guards (pass today) ================================ */
    {
        finding: 'P2GATE-G1',
        title: 'Guard: every slot of an 8-member batch calls Prisma AIRS as slot 1 does: the key only on a private. message, Enforce=true, ' +
               'the 5,000 ms timeout and the same scan URL (A25, A26 for slots 2 to 8; Debug was measured live on slots 1 to 3 only)',
        setup: Object.assign(rpc(calls(8)), { legs: ['request'], airs: R.answers('allow-tool') }),
        v3: function (r) {
            var x = r.request, f = x.flow, bad = [];
            if (x.calls.length !== 8) { return x.calls.length + ' scans, not 8'; }
            x.calls.forEach(function (c, i) {
                var slot = i + 1, want = 'SC-Airs3Scan' + (slot > 1 ? slot : '');
                if (c.policy !== want) { bad.push('call ' + slot + ' by ' + c.policy); }
                if (c.headers['x-pan-token'] !== KEY) { bad.push(want + ' sent no key'); }
                if (c.enforce !== true) { bad.push(want + ' without Enforce=true'); }
                if (c.timeout !== 5000) { bad.push(want + ' timeout ' + c.timeout); }
                if (c.url !== x.calls[0].url) { bad.push(want + ' URL ' + c.url); }
            });
            Object.keys(f.messages).forEach(function (name) {
                var m = f.messages[name];
                if (m && m.header('x-pan-token') !== null && name.indexOf('private.') !== 0) { bad.push('the key sits on the message ' + name); }
            });
            var leaks = require('../harness/apigee').keyLeaks(f, KEY);
            if (leaks.length) { bad.push('the key sits in ' + leaks.join(', ')); }
            return S.check(bad.length === 0, bad.join('; '));
        }
    },
    {
        finding: 'P2GATE-G2',
        title: 'Guard: if AM-Airs3ClearScan2 left the request leg\'s airs3ScanResponse2 in place (a stand-in: "each scan starts clean" is ' +
               'unit only), a reply-leg slot 2 that gets no answer is a scanner failure, -32003 per id, never the request leg\'s allow ' +
               '(servicecallout.SC-Airs3Scan2.failed is read per slot)',
        setup: (function () {
            var s = Object.assign(rpc(calls(2)), { legs: ['request', 'response'],
                response: S.reply([ans(1, echoed('answer one')), ans(2, echoed('answer two ' + M))]) });
            var named = R.answers('allow-tool', 'allow-tool', 'allow-tool'), kept = null;
            s.beforeResponse = function (flow) { kept = flow.messages.airs3ScanResponse2; };            // the request leg's answer for slot 2
            s.airs = function (c, flow) {
                if (flow.leg === 'response' && c.policy === 'SC-Airs3Scan2') { flow.messages.airs3ScanResponse2 = kept; return R.noAnswer(); }
                return named(c, flow);
            };
            return s;
        })(),
        v3: function (r) {
            var q = r.request, p = r.response;
            if (!q || q.fault) { return 'the request leg did not pass: ' + (q && q.body); }
            if (!p) { return 'no reply leg ran'; }
            return and(S.check(p.calls.length === 2, p.calls.length + ' reply-leg scans, not 2'), refusedBatch(p, [1, 2], -32003),
                       S.check(v(p, 'aiStatus') === 'none', 'airs_status ' + v(p, 'aiStatus') + ', not none'));
        }
    },
    {
        finding: 'P2GATE-G3',
        title: 'Guard: slot 8 on the reply leg, after the request leg used it: a reply array of 8 answers is 8 scans, each with its own ' +
               'member\'s input, and a block on the 8th answer withholds the whole reply (no reply-leg slot above 1 has run live)',
        setup: Object.assign(rpc(calls(8, 'ask')), { legs: ['request', 'response'],
            airs: R.answers('allow-tool', 'allow-tool', 'allow-tool', 'allow-tool', 'allow-tool', 'allow-tool', 'allow-tool', 'allow-tool',
                            'allow-tool', 'allow-tool', 'allow-tool', 'allow-tool', 'allow-tool', 'allow-tool', 'allow-tool', 'block-tool-output'),
            response: S.reply([1, 2, 3, 4, 5, 6, 7, 8].map(function (n) { return ans(n, echoed(n === 8 ? 'Card ' + C : 'answer ' + n)); })) }),
        v3: function (r) {
            var q = r.request, p = r.response;
            if (!q || q.fault) { return 'the request leg did not pass: ' + (q && q.body); }
            if (!p) { return 'no reply leg ran'; }
            var e8 = entry(p, 7);
            return and(S.check(q.calls.length === 8 && p.calls.length === 8 && v(p, 'slotRan8') === 'true', 'scans: request ' + q.calls.length + ', reply ' + p.calls.length),
                       S.check(e8 && e8.tool_event && String(e8.tool_event.input).indexOf('ask 8') !== -1 && String(e8.tool_event.output).indexOf(C) !== -1,
                               'slot 8 did not carry member 8: ' + JSON.stringify(e8).slice(0, 200)),
                       refusedBatch(p, [1, 2, 3, 4, 5, 6, 7, 8], -32001));
        }
    }
];

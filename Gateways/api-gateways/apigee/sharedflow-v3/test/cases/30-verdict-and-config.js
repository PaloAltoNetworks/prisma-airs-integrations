'use strict';
/* What the flow does with a recorded reply or a setting (A13, A14, A15, A25, A26, A27, A39). */
const S = require('./_shapes');
const R = require('../harness/replies');

function benign() { return S.gemini([S.user('What is the capital of France?')]); }
// A synthetic reply for rows no tenant gives on demand (A15): the recorded allow, reporting a detector error.
function degradedAllow() { var a = R.recorded('allow-prompt'); a.body = Object.assign({}, a.body, { error: true, errors: [{ code: 'detector-timeout' }] }); return a; }

module.exports = [
    {
        finding: 'A13', title: 'A body that is not JSON, at a Gemini path, is refused',
        setup: Object.assign(S.req(S.P.gemini, 'this is not JSON'), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v2: function (r) { return S.check(!r.request.fault && r.request.calls.length === 0, 'V2 refused or scanned an unreadable body'); },
        v3: function (r) { return S.check(!!r.request.fault && r.request.calls.length === 0, 'the unreadable body was not refused'); }
    },
    {
        finding: 'A14', title: 'A 200 from Prisma AIRS whose body is HTML is a scanner failure (failOpen=false)',
        setup: Object.assign(benign(), { legs: ['request'], airs: R.answers(R.status(200, '<html><body>maintenance</body></html>')) }),
        v2: function (r) { return S.check(!r.request.fault && r.request.outcome === 'allow', 'V2 did not allow it'); },
        v3: function (r) { return S.check(!!r.request.fault, 'the unreadable verdict was let through'); }
    },
    {
        finding: 'A15', title: 'An allow that reports a detector error is a scanner failure (failOpen=false; synthetic reply)',
        setup: Object.assign(benign(), { legs: ['request'], airs: R.answers(degradedAllow()) }),
        v2: function (r) { return S.check(!r.request.fault && r.request.outcome === 'allow', 'V2 did not allow it'); },
        v3: function (r) { return S.check(!!r.request.fault, 'the degraded allow was let through'); }
    },
    {
        finding: 'A25', title: 'The key is held only in a private. variable',
        setup: Object.assign(benign(), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v2: function (r) { var l = require('../harness/apigee').keyLeaks(r.request.flow, 'lab-key-for-unit-tests'); return S.check(l.length > 0, 'V2 kept the key private'); },
        v3: function (r) { var l = require('../harness/apigee').keyLeaks(r.request.flow, 'lab-key-for-unit-tests'); return S.check(l.length === 0, 'the key sits in ' + l.join(', ')); }
    },
    {
        finding: 'A26', title: 'The call to Prisma AIRS sets Enforce=true',
        setup: Object.assign(benign(), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v2: function (r) { return S.check(r.request.calls.length === 1 && r.request.calls[0].enforce === false, 'V2 enforced certificate checks'); },
        v3: function (r) { return S.check(r.request.calls.length === 1 && r.request.calls[0].enforce === true, 'Enforce=true is not set'); }
    },
    {
        finding: 'A27', title: 'A prompt over the size limit (150,000 characters) is refused without a scan',
        setup: Object.assign(S.gemini([S.user(S.filler(150000))]),
                             { legs: ['request'], airs: R.answers('allow-prompt') }),
        v2: function (r) { return S.check(r.request.calls.length === 1 && r.request.scanned.length >= 150000, 'V2 did not send the whole prompt'); },
        v3: function (r) { return S.check(!!r.request.fault && r.request.calls.length === 0, 'the oversized prompt was scanned or let through'); }
    },
    {
        finding: 'A39', title: 'A setting v3 cannot read (failOpen=yes) refuses every request',
        setup: Object.assign(benign(), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { failOpen: 'yes' } }),
        v2: function (r) { return S.check(r.request.flow.get('airs.cfg.failOpen') === 'false' && !r.request.fault, 'V2 did not read it as false'); },
        v3: function (r) { return S.check(!!r.request.fault && r.request.calls.length === 0, 'the unreadable setting did not refuse the request'); }
    }
];

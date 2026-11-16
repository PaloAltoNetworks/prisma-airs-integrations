'use strict';
/*
 * A review of v3's phase 1 against Apigee's real behaviour, before release. Cases where the harness itself can show a
 * v3 defect that sits on how Apigee behaves on runtime 1-18-0-apigee-8:
 *   - flow variables live for the whole exchange, so the reply leg starts with every value the request leg left (L6);
 *   - a JavaScript step with continueOnError=true that is cut (timeLimit) or throws leaves the flow running with whatever
 *     it had already written, and only its done flag shows it (L2);
 *   - in a TargetEndpoint PreFlow, target.url is the TargetEndpoint's <URL>, or whatever a proxy step set before v3, which
 *     the placement rule allows (v3's request leg runs after any step that sets target.url); outside it, a write has no
 *     effect (L1);
 *   - a body the flow can't see reads as empty, not as an error (L1: event-stream replies).
 * Each case names its recorded Prisma AIRS reply; nothing decides a verdict from content. Texts are harmless.
 * GATE-R1 to GATE-R3: gaps the review found, fixed since; each case passes when v3 behaves as required. GATE-G1 and
 * GATE-G2: guards, which passed then too, for two ways target.url reads: the TargetEndpoint <URL> alone, in a
 * TargetEndpoint PreFlow, and empty, outside the TargetEndpoint.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const MARK = 'AIRSV3-MARKER';

function hdr(x, n) { var m = x && x.flow && x.flow.messages.response; return m ? m.header(n) : null; }
function kindOf(x) { return hdr(x, 'x-airs-kind'); }
function chatReply(text) {
    return S.reply({ id: 'chatcmpl-gate', object: 'chat.completion', model: 'm', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }] });
}
function geminiStream(path, query, targetUrl) {
    var s = S.req(path, { contents: [S.user('What is the capital of France? Answer in one word.')] }, null, query);
    s.legs = ['request'];
    s.airs = R.answers('allow-prompt');
    s.vars = targetUrl ? { 'target.url': targetUrl } : {};
    return s;
}

// A stand-in for JS-Airs3Init being cut on the reply leg: a timeLimit cut or an error, which continueOnError=true makes
// silent (L2). Init reads scanType once per leg, after it resets the later steps' done flags and before it sets the
// leg. The first read (the request leg) gives an unset value; the second (the reply leg) throws, so Init stops there,
// as a cut at that statement would.
function initStopsOnReplyLeg() {
    var reads = 0;
    return { toString: function () { reads++; if (reads > 1) { throw new Error('JS-Airs3Init cut on the reply leg (stand-in for a timeLimit cut)'); } return ''; } };
}

// Vertex express mode authenticates with ?key=; a proxy step that builds target.url puts it there (placeholder value).
const EXPRESS_PATH = '/v1/publishers/google/models/gemini-x:streamGenerateContent';
const EXPRESS_TARGET = 'https://aiplatform.example/v1/publishers/google/models/gemini-x:streamGenerateContent?key=placeholder';
// A model alias: the client names "default", a proxy step routes it to a concrete model by setting target.url.
const ALIAS_PATH = '/v1/projects/p/locations/global/publishers/google/models/default:streamGenerateContent';
const ALIAS_TARGET = 'https://aiplatform.example/v1/projects/p/locations/global/publishers/google/models/gemini-x:streamGenerateContent';

module.exports = [
    {
        finding: 'GATE-R1',
        title: 'Request leg: a POST to a path v3 reads, whose headers declare a 96-byte body but whose content the flow sees empty ' +
               '(as Apigee shows a body it does not buffer, L1), is refused like the reply leg\'s A21 guard, not passed as "a request with no body"',
        setup: { path: S.P.chat, request: { verb: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': '96' }, content: '' },
                 legs: ['request'], airs: R.answers('allow-prompt') },
        v3: function (r) {
            var q = r.request;
            return S.check(q.blocked && q.calls.length === 0,
                'forwarded to the model unscanned: route ' + q.route + ', fault ' + !!q.fault + ', log note "' + q.flow.get('airs3.logNote') + '"');
        }
    },
    {
        finding: 'GATE-R2',
        title: 'Reply leg: when JS-Airs3Init does not finish (cut or error, continueOnError=true), the request leg\'s values are still ' +
               'set (L6), so the reply leg must refuse as a scanner failure, as for any v3 step that didn\'t finish, not re-read the prompt as a request and pass the reply unscanned',
        setup: Object.assign(S.chat([{ role: 'user', content: 'What is the capital of France? Answer in one word.' }]), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            vars: { scanType: initStopsOnReplyLeg() }, response: chatReply('Paris. ' + MARK) }),
        v3: function (r) {
            var q = r.request, p = r.response;
            if (!q || q.fault) { return 'the request leg did not pass, so the reply leg never ran'; }
            if (!p) { return 'no reply leg ran'; }
            return S.check(p.blocked && kindOf(p) === 'failure',
                'reply leg ran on the request leg\'s state (leg=' + p.flow.get('airs3.leg') + ', doneInit=' + p.flow.get('airs3.doneInit') +
                '), scanned the reply: ' + S.has(p, MARK) + ', ' + (p.blocked ? 'refused as ' + kindOf(p) : 'reply passed to the client'));
        }
    },
    {
        finding: 'GATE-R3',
        title: 'Turning a Gemini stream off keeps the query a proxy step put into target.url (Vertex express mode\'s ?key=), and removes only alt, ' +
               'rather than stripping target.url\'s own query',
        setup: geminiStream(EXPRESS_PATH, 'alt=sse', EXPRESS_TARGET),
        v3: function (r) {
            var t = String(r.request.flow.get('target.url') || '');
            return S.check(!r.request.fault && /:generateContent(\?|$)/.test(t) && /[?&]key=placeholder(&|$)/.test(t) && !/[?&]alt=/.test(t),
                'target.url after turning streaming off: ' + t);
        }
    },
    {
        finding: 'GATE-R3',
        title: 'Turning a Gemini stream off edits the path a proxy step put into target.url (a model alias routed to gemini-x), ' +
               'rather than appending the client\'s path to it',
        setup: geminiStream(ALIAS_PATH, 'alt=sse', ALIAS_TARGET),
        v3: function (r) {
            var t = String(r.request.flow.get('target.url') || '');
            return S.check(!r.request.fault && t === ALIAS_TARGET.replace(':streamGenerateContent', ':generateContent'), 'target.url after turning streaming off: ' + t);
        }
    },
    {
        finding: 'GATE-G1',
        title: 'Guard: with target.url as Apigee reports it in a TargetEndpoint PreFlow (the TargetEndpoint <URL> only, as in airs-llm-guard), ' +
               'a Gemini alt=sse call goes to :generateContent with no alt, and Apigee is told not to append the path suffix or the client query',
        setup: geminiStream(S.P.geminiStream, 'alt=sse', 'https://aiplatform.googleapis.com'),
        v3: function (r) {
            var f = r.request.flow, t = String(f.get('target.url') || '');
            return S.check(!r.request.fault && t === 'https://aiplatform.googleapis.com' + S.P.gemini &&
                           f.get('target.copy.pathsuffix') === false && f.get('target.copy.queryparams') === false,
                'target.url ' + t + ', copy.pathsuffix ' + f.get('target.copy.pathsuffix') + ', copy.queryparams ' + f.get('target.copy.queryparams'));
        }
    },
    {
        finding: 'GATE-G2',
        title: 'Guard: where target.url reads empty (the request leg placed outside the TargetEndpoint, where a write has no effect: L1), ' +
               'a Gemini alt=sse call is refused as a configuration problem, in the client\'s event-stream format, and never forwarded',
        setup: geminiStream(S.P.geminiStream, 'alt=sse', null),
        v3: function (r) {
            var q = r.request;
            return S.check(q.blocked && kindOf(q) === 'config' && /text\/event-stream/.test(q.contentType || '') && /TargetEndpoint PreFlow/.test(q.body || ''),
                'blocked ' + q.blocked + ', kind ' + kindOf(q) + ', type ' + q.contentType + ', body ' + String(q.body).slice(0, 160));
        }
    }
];

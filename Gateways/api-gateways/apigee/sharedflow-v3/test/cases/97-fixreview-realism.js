'use strict';
/*
 * A review of the fixes for GATE-* findings, before release: realism on a live Apigee, and regressions.
 * Scope: those fixes only (AM-Airs3Reset, the Respond leg fallback, airs3-destream.js's target.url rewrite, the
 * airs3-detect.js rules and stream kinds they added, the reply-leg gemini-array refusal, the chat restream's
 * added fields).
 * Facts used (runtime 1-18-0-apigee-8): flow variables last the whole exchange (L6); a JS step with
 * continueOnError=true that is cut or throws keeps what it already wrote (L2); target.url can be changed only from
 * the TargetEndpoint flow (L1); SSE reply bodies are invisible to the flow (L1). Proxies set target.url in one of two
 * ways: a step of their own sets target.copy.pathsuffix=false, target.copy.queryparams=false and
 * target.url = https://<host><proxy.pathsuffix>?<query> before the v3 request leg (the proxies the live rows used);
 * or only the TargetEndpoint <URL> is set, as in the example proxies.
 * FIX-R-*: gaps this review found, fixed since; each case passes when v3 behaves as required. GUARD-R-*: guards,
 * which passed then too and pin what a fix meant to keep.
 * Each case names its recorded Prisma AIRS reply; nothing decides a verdict from content. Texts are harmless.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const MARK = 'AIRSV3-MARKER';
const Q = 'What is the capital of France? Answer in one word.';

function hdr(x, n) { var m = x && x.flow && x.flow.messages.response; return m ? m.header(n) : null; }
function json(s) { try { return JSON.parse(s); } catch (e) { return undefined; } }
function ct(x) { return String(x && x.contentType || ''); }
// The data: payloads of an event stream, parsed ([DONE] and non-JSON lines left out).
function sseData(body) {
    var out = [];
    String(body || '').split(/\r?\n/).forEach(function (l) { if (l.indexOf('data: ') === 0) { var d = json(l.slice(6)); if (d !== undefined) { out.push(d); } } });
    return out;
}
// A stand-in for JS-Airs3Init being cut (a timeLimit cut or an error; continueOnError=true makes it silent: L2).
// Init reads scanType once per leg, after it has cleared the per-leg variables; the read on the chosen leg throws.
function initStopsOn(leg) {
    var reads = 0, stopAt = leg === 'request' ? 1 : 2;
    return { toString: function () { reads++; if (reads === stopAt) { throw new Error('JS-Airs3Init cut on the ' + leg + ' leg (stand-in)'); } return ''; } };
}

const VERTEX = 'https://aiplatform.googleapis.com';
const GEM_STREAM = '/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-flash:streamGenerateContent';
const GEM_PLAIN = GEM_STREAM.replace(':streamGenerateContent', ':generateContent');
const CLAUDE_STREAM = '/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-x@20250101:streamRawPredict';
const CLAUDE_HOST = 'https://us-east5-aiplatform.googleapis.com';
function geminiCall(query, vars, legs, response) {
    var s = S.req(GEM_STREAM, { contents: [S.user(Q)] }, null, query);
    s.legs = legs || ['request']; s.airs = R.answers('allow-prompt', 'allow-prompt-response'); s.vars = vars || {};
    if (response) { s.response = response; }
    return s;
}
function claudeCall(vars, legs, response) {
    var s = S.req(CLAUDE_STREAM, { anthropic_version: 'vertex-2023-10-16', max_tokens: 64, stream: true, messages: [{ role: 'user', content: Q }] });
    s.legs = legs || ['request']; s.airs = R.answers('allow-prompt', 'allow-prompt-response'); s.vars = vars || {};
    if (response) { s.response = response; }
    return s;
}
const GEM_REPLY = S.reply({ candidates: [{ content: { role: 'model', parts: [{ text: 'Paris. ' + MARK }] }, finishReason: 'STOP', index: 0 }] });
const CLAUDE_REPLY = S.reply({ id: 'msg_lab', type: 'message', role: 'assistant', model: 'claude-x', content: [{ type: 'text', text: 'Paris.' }],
                               stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 12, output_tokens: 3 } });

module.exports = [
    /* ================================ findings (gaps the review found, fixed since) =============================== */
    {
        finding: 'FIX-R-01',
        title: 'Reply leg, JS-Airs3Init cut (GATE-R2\'s path): an MCP client gets a JSON-RPC -32003 with its request id at HTTP 200, ' +
               'not an OpenAI-style 403, though Detect never runs again after the cut (Init keeps format and mcpId)',
        setup: Object.assign(S.mcp('tools/call', { name: 'echo', arguments: { text: 'hello' } }, 7), {
            legs: ['request', 'response'], airs: R.answers('allow-tool', 'allow-tool'), vars: { scanType: initStopsOn('response') },
            response: S.reply({ jsonrpc: '2.0', id: 7, result: { content: [{ type: 'text', text: 'hello ' + MARK }] } }) }),
        v3: function (r) {
            if (!r.request || r.request.fault) { return 'the request leg did not pass, so the reply leg never ran'; }
            var p = r.response, b = json(p && p.body);
            return S.check(p && p.blocked && p.status === 200 && b && b.jsonrpc === '2.0' && b.id === 7 && b.error && b.error.code === -32003,
                'the MCP client got HTTP ' + (p && p.status) + ' ' + ct(p) + ': ' + String(p && p.body).slice(0, 140) +
                ' (airs3.format "' + (p && p.flow.get('airs3.format')) + '", airs3.mcpId "' + (p && p.flow.get('airs3.mcpId')) + '")');
        }
    },
    {
        finding: 'FIX-R-01',
        title: 'Reply leg, JS-Airs3Init cut: a destreamed Gemini alt=sse client gets its refusal as an event stream (as GATE-G2 and the ' +
               'other stream refusals do), not a JSON 403',
        setup: geminiCall('alt=sse', { 'target.url': VERTEX, scanType: initStopsOn('response') }, ['request', 'response'], GEM_REPLY),
        v3: function (r) {
            if (!r.request || r.request.fault) { return 'the request leg did not pass, so the reply leg never ran'; }
            var p = r.response;
            return S.check(p && p.blocked && hdr(p, 'x-airs-kind') === 'failure' && /text\/event-stream/.test(ct(p)) && sseData(p.body).length > 0,
                'the alt=sse client got HTTP ' + (p && p.status) + ' ' + ct(p) + ' (destreamed "' + (p && p.flow.get('airs3.destreamed')) +
                '", airs3.format "' + (p && p.flow.get('airs3.format')) + '")');
        }
    },
    {
        finding: 'FIX-R-02',
        title: 'GET /v1/responses/{id}?stream=true (resuming a background stream; read as Responses since GATE-COV-01): the reply is ' +
               'an event stream the flow sees empty, so it is withheld; the refusal must be the client\'s event stream, not a 200 JSON body',
        setup: { path: '/v1/responses/resp_lab1', request: { verb: 'GET', headers: { Accept: 'text/event-stream' }, content: '', querystring: 'stream=true' },
                 legs: ['request', 'response'], airs: R.answers('allow-prompt-response'),
                 response: { status: 200, headers: { 'Content-Type': 'text/event-stream; charset=utf-8' }, content: '' } },
        v3: function (r) {
            var p = r.response;
            if (r.request.route !== 'pass' || !p) { return 'setup: the bodiless GET did not pass the request leg (route ' + r.request.route + ')'; }
            return S.check(p.blocked && /text\/event-stream/.test(ct(p)) && sseData(p.body).length > 0,
                'the stream reader got HTTP ' + p.status + ' ' + ct(p) + ', which an SSE reader parses as no events (format "' +
                p.flow.get('airs3.format') + '", stream "' + p.flow.get('airs3.stream') + '")');
        }
    },
    {
        finding: 'FIX-R-03',
        title: 'Chat stream:true, destreamed: the restreamed burst carries the choice\'s logprob tokens once, and not on the chunk that opens ' +
               'the choice (OpenAI opens a choice with an empty logprobs list; the SDK stream helpers treat the opening chunk\'s logprobs specially)',
        setup: Object.assign(S.chat([{ role: 'user', content: Q }], { stream: true, logprobs: true, top_logprobs: 1 }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'allow-prompt-response'),
            response: S.reply({ id: 'chatcmpl-lab', object: 'chat.completion', created: 1, model: 'm',
                choices: [{ index: 0, message: { role: 'assistant', content: 'Paris' }, finish_reason: 'stop',
                            logprobs: { content: [{ token: 'Paris', logprob: -0.01, bytes: [80, 97, 114, 105, 115], top_logprobs: [{ token: 'Paris', logprob: -0.01, bytes: [80, 97, 114, 105, 115] }] }], refusal: null } }] }) }),
        v3: function (r) {
            var p = r.response;
            if (!p || p.blocked || !/text\/event-stream/.test(ct(p))) { return 'setup: the reply was not restreamed (' + (p && ct(p)) + ')'; }
            var chunks = sseData(p.body).filter(function (d) { return d.choices && d.choices.length && d.choices[0].index === 0; });
            var opening = chunks[0], n = 0;
            chunks.forEach(function (d) { var lp = d.choices[0].logprobs; n += lp && lp.content ? lp.content.length : 0; });
            var openN = opening && opening.choices[0].logprobs && opening.choices[0].logprobs.content ? opening.choices[0].logprobs.content.length : 0;
            return S.check(n === 1 && openN === 0, 'logprob tokens in the burst: ' + n + ', on the chunk that opens the choice: ' + openN);
        }
    },
    {
        finding: 'FIX-R-04',
        title: 'Turning a Gemini stream off keeps every client query parameter but alt, whatever its name: one named like an Object.prototype ' +
               'member (constructor) is dropped by the repeated-name check a fix added, where the code before it kept it',
        setup: geminiCall('alt=sse&constructor=lab', { 'target.url': VERTEX }),
        v3: function (r) {
            var t = String(r.request.flow.get('target.url') || '');
            return S.check(!r.request.fault && t === VERTEX + GEM_PLAIN + '?constructor=lab', 'target.url after turning streaming off: ' + t);
        }
    },

    /* ================================ guards ======================================================================== */
    {
        finding: 'GUARD-R-01',
        title: 'Guard, the lab\'s form: JS-LabTarget put the full path and the client query into target.url and turned both copy flags off; ' +
               'destream edits the stream method in place, drops alt, keeps the other parameter once',
        setup: geminiCall('alt=sse&prettyPrint=false', { 'target.url': VERTEX + GEM_STREAM + '?alt=sse&prettyPrint=false',
                                                          'target.copy.pathsuffix': false, 'target.copy.queryparams': false }),
        v3: function (r) {
            var f = r.request.flow, t = String(f.get('target.url') || '');
            return S.check(!r.request.fault && t === VERTEX + GEM_PLAIN + '?prettyPrint=false' && f.get('airs3.destreamed') === 'gemini-sse',
                'target.url ' + t + ', destreamed ' + f.get('airs3.destreamed'));
        }
    },
    {
        finding: 'GUARD-R-02',
        title: 'Guard, the lab\'s form when the copy flags read back unset (not measured live): the client query is not added a second ' +
               'time, because target.url already carries it',
        setup: geminiCall('alt=sse&prettyPrint=false', { 'target.url': VERTEX + GEM_STREAM + '?alt=sse&prettyPrint=false' }),
        v3: function (r) {
            var t = String(r.request.flow.get('target.url') || '');
            return S.check(!r.request.fault && t === VERTEX + GEM_PLAIN + '?prettyPrint=false', 'target.url ' + t);
        }
    },
    {
        finding: 'GUARD-R-03',
        title: 'Guard, Claude on Vertex :streamRawPredict in the lab\'s form (regional host, a model id with @): the target gets :rawPredict ' +
               'with stream false, and the JSON reply goes back as one burst of Anthropic events',
        setup: claudeCall({ 'target.url': CLAUDE_HOST + CLAUDE_STREAM, 'target.copy.pathsuffix': false, 'target.copy.queryparams': false },
                          ['request', 'response'], CLAUDE_REPLY),
        v3: function (r) {
            var q = r.request, p = r.response, t = String(q.flow.get('target.url') || ''), sent = json(q.flow.messages.request.content) || {};
            return S.check(!q.fault && t === CLAUDE_HOST + CLAUDE_STREAM.replace(':streamRawPredict', ':rawPredict') && sent.stream === false &&
                           p && !p.blocked && /text\/event-stream/.test(ct(p)) && /event: message_start/.test(p.body) && p.body.indexOf('Paris.') !== -1,
                'target.url ' + t + ', stream ' + sent.stream + ', reply ' + (p && ct(p)) + ' blocked ' + (p && p.blocked));
        }
    },
    {
        finding: 'GUARD-R-04',
        title: 'Guard, Claude on Vertex :streamRawPredict with target.url as the TargetEndpoint <URL> only (the example proxies\' form): ' +
               'the client\'s path is appended with :rawPredict',
        setup: claudeCall({ 'target.url': VERTEX }),
        v3: function (r) {
            var t = String(r.request.flow.get('target.url') || '');
            return S.check(!r.request.fault && t === VERTEX + CLAUDE_STREAM.replace(':streamRawPredict', ':rawPredict'), 'target.url ' + t);
        }
    },
    {
        finding: 'GUARD-R-05',
        title: 'Guard, no false positive: an SDK chat call to an Azure OpenAI deployment with a dotted name, api-version, and HTTP/1.1 ' +
               'headers (Connection, Content-Length, Accept-Encoding) is scanned, not refused by the Upgrade, empty-body or odd-path rules',
        setup: (function () {
            var body = JSON.stringify({ model: 'gpt-4.1-mini', messages: [{ role: 'user', content: Q }] });
            return { path: '/openai/deployments/gpt-4.1-mini/chat/completions', legs: ['request'], airs: R.answers('allow-prompt'),
                     request: { verb: 'POST', content: body, querystring: 'api-version=2024-10-21',
                                headers: { 'Content-Type': 'application/json', Accept: 'application/json', Connection: 'keep-alive', 'Accept-Encoding': 'gzip, deflate',
                                           'Content-Length': String(body.length), 'User-Agent': 'AzureOpenAI/Python 1.99.0', 'X-Stainless-Lang': 'python' } } };
        })(),
        v3: function (r) {
            var q = r.request;
            return S.check(!q.fault && q.route === 'scan' && q.calls.length === 1, 'route ' + q.route + ', calls ' + q.calls.length + ', refuse ' + q.flow.get('airs3.refuseMsg'));
        }
    },
    {
        finding: 'GUARD-R-06',
        title: 'Guard, no false positive: an empty-body POST that names no API v3 reads (Anthropic message batch cancel, Content-Length: 0) ' +
               'still passes as a request with no body, on both legs',
        setup: { path: '/v1/messages/batches/msgbatch_lab1/cancel', legs: ['request', 'response'], airs: R.answers('allow-prompt'),
                 request: { verb: 'POST', headers: { 'Content-Length': '0', 'anthropic-version': '2023-06-01' }, content: '', querystring: '' },
                 response: S.reply({ id: 'msgbatch_lab1', type: 'message_batch', processing_status: 'canceling' }) },
        v3: function (r) {
            var q = r.request, p = r.response;
            return S.check(q.route === 'pass' && !q.fault && p && p.route === 'pass' && !p.fault,
                'request route ' + q.route + ' (' + q.flow.get('airs3.refuseMsg') + '), reply route ' + (p && p.route));
        }
    },
    {
        finding: 'GUARD-R-07',
        title: 'Guard, no false positive: an MCP DELETE (end of session, no body) passes on both legs',
        setup: { path: S.P.mcp, legs: ['request', 'response'], airs: R.answers('allow-tool'),
                 request: { verb: 'DELETE', headers: { 'Mcp-Session-Id': 'sess-lab-1' }, content: '', querystring: '' },
                 response: { status: 204, headers: {}, content: '' } },
        v3: function (r) {
            var q = r.request, p = r.response;
            return S.check(q.route === 'pass' && !q.fault && p && p.route === 'pass' && !p.fault, 'request route ' + q.route + ', reply route ' + (p && p.route));
        }
    },
    {
        finding: 'GUARD-R-08',
        title: 'Guard, the Respond leg fallback on the request leg: when JS-Airs3Init is cut there (no target answer yet), the refusal is a ' +
               'scanner failure worded for the request',
        setup: Object.assign(S.chat([{ role: 'user', content: Q }]), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { scanType: initStopsOn('request') } }),
        v3: function (r) {
            var q = r.request;
            return S.check(q.blocked && hdr(q, 'x-airs-kind') === 'failure' && q.calls.length === 0 && /this request, so it was not forwarded/.test(q.body || ''),
                'blocked ' + q.blocked + ', kind ' + hdr(q, 'x-airs-kind') + ', body ' + String(q.body).slice(0, 160));
        }
    }
];

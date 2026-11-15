'use strict';
/*
 * The leg a FlowCallout's `type` names must be the leg the step runs on, and an empty reply that says it has no body
 * passes.
 *   - LEG-*: `type` (or V2's `scanType`) is checked against the flow the step runs in; the runtime shows it, since the
 *     reply's status exists only on the reply leg. A mismatch would scan the wrong message and pass the other unscanned,
 *     so it is a `config` refusal on the leg the step really runs on. LEG-G*: guards, the matching cases.
 *   - EMPTY-*: a 2xx reply with no body passes when its status (202, 204) or its headers (Content-Length: 0, no
 *     Transfer-Encoding) say there is none, as when an MCP server ends a session with HTTP 200. A reply whose body the
 *     flow can't see, and that doesn't say it has none, is still withheld.
 */
const S = require('./_shapes');
const R = require('../harness/replies');

const MODEL_TEXT = 'MODEL-REPLY-TEXT about the bakery';
function chatReply() {
    return S.reply({ id: 'chatcmpl-1', object: 'chat.completion', model: 'm',
                     choices: [{ index: 0, message: { role: 'assistant', content: MODEL_TEXT }, finish_reason: 'stop' }] });
}
function ask() { return S.chat([{ role: 'user', content: 'When does the bakery open?' }]); }
function msg(x) { return String(x.flow.get('airs3.refuseMsg') || ''); }
function refusedFor(x, setting, legName) {
    return S.check(x && x.fault && x.calls.length === 0 && msg(x).indexOf('Check the setting: ' + setting + ' (this step runs on the ' + legName + ' leg)') !== -1 &&
                   String(x.body).indexOf(MODEL_TEXT) === -1,
                   'not a config refusal naming ' + setting + ': fault ' + (x && x.fault ? x.fault.policy : '-') + ', calls ' + (x && x.calls.length) + ', message ' + (x && msg(x)));
}
// V2: the reply reached the client, and what was scanned on the reply leg was the request again, never the reply.
function v2ReplyUnscanned(r) {
    var x = r.response;
    return S.check(x && !x.fault && String(x.flow.messages.response.content).indexOf(MODEL_TEXT) !== -1 && x.scanned.indexOf(MODEL_TEXT) === -1,
                   'V2 scanned or withheld the reply');
}
function mcpEnd(replyHeaders) {
    return { path: '/v1/agent', legs: ['request', 'response'], vars: { apiFormat: 'mcp' }, airs: R.answers('allow-prompt'),
             request: { verb: 'DELETE', headers: { 'Mcp-Session-Id': 'session-1' }, content: '' },
             response: { status: 200, headers: replyHeaders, content: '' } };
}

module.exports = [
    {
        finding: 'LEG-1', title: 'type=user-prompt on the reply leg is refused there as a setting problem: the reply is withheld, not passed unscanned',
        setup: Object.assign(ask(), { legs: ['request', 'response'], params: { response: { type: 'user-prompt' } },
                                      airs: R.answers('allow-prompt'), response: chatReply() }),
        v2: v2ReplyUnscanned,
        v3: function (r) {
            if (!(r.request && !r.request.fault && r.request.calls.length === 1)) { return 'the request leg did not scan and pass'; }
            return refusedFor(r.response, 'type', 'reply');
        }
    },
    {
        finding: 'LEG-2', title: 'A reply-leg FlowCallout with no type (the default is the request leg) is refused as a setting problem',
        setup: Object.assign(ask(), { legs: ['response'], params: { response: { type: null } }, airs: R.answers('allow-prompt-response'), response: chatReply() }),
        v2: v2ReplyUnscanned,
        v3: function (r) { return refusedFor(r.response, 'type', 'reply'); }
    },
    {
        finding: 'LEG-3', title: 'type=both on the request leg is refused as a setting problem: the request is not forwarded unscanned',
        setup: Object.assign(ask(), { legs: ['request'], params: { request: { type: 'both' } }, airs: R.answers('allow-prompt') }),
        v2: function (r) { return S.check(r.request && !r.request.fault && r.request.calls.length === 0, 'V2 scanned or refused the request'); },
        v3: function (r) { return refusedFor(r.request, 'type', 'request'); }
    },
    {
        finding: 'LEG-4', title: 'V2\'s scanType=response on the request leg is refused, naming scanType',
        setup: Object.assign(ask(), { legs: ['request'], params: { request: { type: null, scanType: 'response' } }, airs: R.answers('allow-prompt') }),
        v3: function (r) { return refusedFor(r.request, 'scanType', 'request'); }
    },
    {
        finding: 'LEG-G1', title: 'Guard: type=both on the reply leg scans the prompt and the reply together, and the reply passes',
        setup: Object.assign(ask(), { legs: ['response'], params: { response: { type: 'both' } }, airs: R.answers('allow-prompt-response'), response: chatReply() }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && !x.fault && x.calls.length === 1 && x.scanned.indexOf('When does the bakery open?') !== -1 && x.scanned.indexOf(MODEL_TEXT) !== -1,
                           'not scanned together and passed: fault ' + (x && x.fault ? x.fault.policy : '-') + ', calls ' + (x && x.calls.length));
        }
    },
    {
        finding: 'LEG-G2', title: 'Guard: V2\'s scanType=prompt on the request leg, with no type, scans the request',
        setup: Object.assign(ask(), { legs: ['request'], params: { request: { type: null, scanType: 'prompt' } }, airs: R.answers('allow-prompt') }),
        v3: function (r) { return S.check(r.request && !r.request.fault && r.request.calls.length === 1, 'not scanned: ' + (r.request && msg(r.request))); }
    },
    {
        finding: 'EMPTY-1', title: 'An MCP session end (DELETE) answered HTTP 200 with Content-Length: 0 passes, with apiFormat=mcp at a path that is not /mcp',
        setup: mcpEnd({ 'Content-Type': 'application/json', 'Content-Length': '0' }),
        v3: function (r) {
            var x = r.response;
            return S.check(x && !x.fault && x.calls.length === 0 && x.flow.get('airs3.logNote') === 'a reply with no body passes',
                           'not passed: fault ' + (x && x.fault ? x.fault.policy : '-') + ', note ' + (x && x.flow.get('airs3.logNote')));
        }
    },
    {
        finding: 'EMPTY-G1', title: 'Guard: an empty HTTP 200 reply with no Content-Length is withheld (its body may be one the flow can\'t see)',
        setup: mcpEnd({ 'Content-Type': 'application/json' }),
        v3: function (r) { return S.check(r.response && r.response.fault && r.response.calls.length === 0, 'not withheld'); }
    },
    {
        finding: 'EMPTY-G2', title: 'Guard: an empty HTTP 200 reply with Content-Length: 0 and Transfer-Encoding is withheld',
        setup: mcpEnd({ 'Content-Type': 'application/json', 'Content-Length': '0', 'Transfer-Encoding': 'chunked' }),
        v3: function (r) { return S.check(r.response && r.response.fault && r.response.calls.length === 0, 'not withheld'); }
    }
];

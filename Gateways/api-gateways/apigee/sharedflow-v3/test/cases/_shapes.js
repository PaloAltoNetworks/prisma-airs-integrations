'use strict';
/* Request and reply shapes the cases share. The only sensitive value is the standard Visa test card number. */
const CARD = '4111 1111 1111 1111';
const JSONH = { 'Content-Type': 'application/json' };

function req(path, body, headers, querystring) {
    return { path: path, request: { verb: 'POST', headers: Object.assign({}, JSONH, headers || {}), content: typeof body === 'string' ? body : JSON.stringify(body),
                                    querystring: querystring || '' } };
}
const P = {
    gemini: '/v1/projects/p/locations/global/publishers/google/models/gemini-x:generateContent',
    geminiStream: '/v1/projects/p/locations/global/publishers/google/models/gemini-x:streamGenerateContent',
    chat: '/v1/chat/completions',
    responses: '/v1/responses',
    anthropic: '/v1/messages',
    claudeVertex: '/v1/projects/p/locations/global/publishers/anthropic/models/claude-x:rawPredict',
    mcp: '/mcp'
};
function gemini(contents, extra) { return req(P.gemini, Object.assign({ contents: contents }, extra || {})); }
function chat(messages, extra) { return req(P.chat, Object.assign({ model: 'm', messages: messages }, extra || {})); }
function anthropic(messages, extra, headers) { return req(P.anthropic, Object.assign({ model: 'm', max_tokens: 32000, messages: messages }, extra || {}), headers); }
function responses(input, extra) { return req(P.responses, Object.assign({ model: 'm', input: input }, extra || {})); }
function mcp(method, params, id) { return req(P.mcp, { jsonrpc: '2.0', id: id === undefined ? 1 : id, method: method, params: params || {} }, { Accept: 'application/json, text/event-stream' }); }
function user(text) { return { role: 'user', parts: [{ text: text }] }; }

function reply(body, contentType) { return { status: 200, headers: { 'Content-Type': contentType || 'application/json' }, content: typeof body === 'string' ? body : JSON.stringify(body) }; }

// Harmless filler of exactly n characters.
function filler(n) { var s = 'The bakery on the corner opens at seven and sells rye bread until noon. '; var out = ''; while (out.length < n) { out += s; } return out.slice(0, n); }

function has(r, text) { return r.scanned.indexOf(text) !== -1; }
function check(cond, msg) { return cond ? true : msg; }

// A stand-in for JS-Airs3Init cut at its first statement (L2: a step with continueOnError=true that its timeLimit cuts keeps
// what it wrote and goes no further): from here on, every flow variable JS-Airs3Init writes throws (the harness names the
// policy that writes), so it stops at its first write; AM-Airs3Reset, before it, and every later step are untouched.
function cutInit(flow) {
    var set = flow.set;
    flow.set = function (name, value, by) { if (by === 'JS-Airs3Init') { throw new Error('JS-Airs3Init cut (stand-in)'); } return set.apply(this, arguments); };
}
module.exports = { CARD: CARD, cutInit: cutInit, P: P, req: req, gemini: gemini, chat: chat, anthropic: anthropic, responses: responses, mcp: mcp, user: user,
                   reply: reply, has: has, check: check, filler: filler };

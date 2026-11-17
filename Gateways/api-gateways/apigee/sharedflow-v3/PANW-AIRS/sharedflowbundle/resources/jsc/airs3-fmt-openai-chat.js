/*
 * airs3-fmt-openai-chat.js: OpenAI Chat Completions, and Vertex's OpenAI-compatible endpoint.
 */
AIRS3_FMT['openai-chat'] = (function () {
    function roleOf(r) {
        if (r === 'system' || r === 'developer') { return 'system'; }
        if (r === 'assistant') { return 'assistant'; }
        if (r === 'tool' || r === 'function') { return 'tool'; }
        return 'user';
    }
    function isTextPart(p) { return p.type === 'text' || p.type === 'refusal' || (typeof p.type === 'string' && /_text$/.test(p.type)) || (p.type === undefined && (typeof p.text === 'string' || typeof p.refusal === 'string')); }
    function contentOf(c, role, at, out) {
        if (c === null || c === undefined) { return null; }
        if (typeof c === 'string') { AIRS3.seg(out, c, role, at); return null; }
        if (!AIRS3.isArray(c)) { return 'a content is neither a string nor a list'; }
        for (var j = 0; j < c.length; j++) {
            var p = c[j];
            if (typeof p === 'string') { AIRS3.seg(out, p, role, at.concat([j])); continue; }
            if (!AIRS3.isObject(p)) { return 'a content part is not an object'; }
            if (isTextPart(p)) {
                var k = typeof p.text === 'string' ? 'text' : 'refusal';
                AIRS3.seg(out, p[k], role, at.concat([j, k]));
                continue;
            }
            AIRS3.seg(out, AIRS3.jsonText(p), role);                          // images, audio, files: their JSON, bytes left out
        }
        return null;
    }
    function toolCalls(m, out) {
        if (AIRS3.isArray(m.tool_calls)) {
            for (var t = 0; t < m.tool_calls.length; t++) {
                var f = m.tool_calls[t] && m.tool_calls[t].function;
                if (f) { AIRS3.seg(out, AIRS3.toolCall(f.name, f.arguments), 'assistant'); }
                var cu = m.tool_calls[t] && m.tool_calls[t].custom;          // a custom tool's free-form input
                if (cu) { AIRS3.seg(out, AIRS3.toolCall(cu.name, cu.input), 'assistant'); }
            }
        }
        if (m.function_call) { AIRS3.seg(out, AIRS3.toolCall(m.function_call.name, m.function_call.arguments), 'assistant'); }
    }
    // A choice's log probabilities, current shape (content and refusal lists) or the legacy one (tokens): see AIRS3.nonEmpty.
    function tokens(lp) { return AIRS3.isObject(lp) && (AIRS3.nonEmpty(lp.content) || AIRS3.nonEmpty(lp.refusal) || AIRS3.nonEmpty(lp.tokens)); }
    function completion(message, cx) {
        return { id: 'chatcmpl-prisma-airs', object: 'chat.completion', created: Math.floor(new Date().getTime() / 1000), model: cx.model || 'prisma-airs',
                 choices: [{ index: 0, message: { role: 'assistant', content: message }, finish_reason: 'stop' }],
                 usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 } };
    }
    function chunk(id, model, choice) { return { id: id, object: 'chat.completion.chunk', created: Math.floor(new Date().getTime() / 1000), model: model, choices: [choice] }; }

    return {
        request: function (body, cx) {
            if (!AIRS3.isObject(body)) { return { segments: [], unreadable: 'the body is not a JSON object' }; }
            if (!AIRS3.isArray(body.messages)) { return { segments: [], unreadable: 'messages is not a list' }; }
            var out = [];
            for (var i = 0; i < body.messages.length; i++) {
                var m = body.messages[i];
                if (!AIRS3.isObject(m)) { return { segments: [], unreadable: 'a message is not an object' }; }
                var role = roleOf(m.role);
                if (typeof m.name === 'string') { AIRS3.seg(out, m.name, role, ['messages', i, 'name']); }      // the model reads it
                var e = contentOf(m.content, role, ['messages', i, 'content'], out);
                if (e) { return { segments: [], unreadable: e }; }
                if (role === 'assistant') {
                    if (typeof m.refusal === 'string') { AIRS3.seg(out, m.refusal, 'assistant', ['messages', i, 'refusal']); }
                    toolCalls(m, out);
                }
            }
            return { segments: out, unreadable: null };
        },
        reply: function (body, cx) {
            if (!AIRS3.isObject(body) || !AIRS3.isArray(body.choices)) { return { segments: [], unreadable: 'the reply has no choices list' }; }
            var out = [];
            for (var i = 0; i < body.choices.length; i++) {
                var ch = body.choices[i];
                if (!AIRS3.isObject(ch)) { return { segments: [], unreadable: 'a choice is not an object' }; }
                if (typeof ch.text === 'string') { AIRS3.seg(out, ch.text, 'assistant', ['choices', i, 'text']); }
                var m = ch.message;
                if (!AIRS3.isObject(m)) { continue; }
                var e = contentOf(m.content, 'assistant', ['choices', i, 'message', 'content'], out);
                if (e) { return { segments: [], unreadable: e }; }
                if (typeof m.refusal === 'string') { AIRS3.seg(out, m.refusal, 'assistant', ['choices', i, 'message', 'refusal']); }
                if (typeof m.reasoning_content === 'string') { AIRS3.seg(out, m.reasoning_content, 'assistant'); }
                if (typeof m.reasoning === 'string') { AIRS3.seg(out, m.reasoning, 'assistant'); }
                // An audio reply's text; never rewritten, because the audio says it too.
                if (AIRS3.isObject(m.audio) && typeof m.audio.transcript === 'string') { AIRS3.seg(out, m.audio.transcript, 'assistant'); }
                if (AIRS3.isArray(m.annotations) && m.annotations.length) { AIRS3.seg(out, AIRS3.jsonText(m.annotations), 'assistant'); }   // cited URLs
                // Azure OpenAI's On Your Data: the retrieved chunks' text and their sources.
                if (AIRS3.isObject(m.context)) { AIRS3.seg(out, AIRS3.jsonText(m.context), 'assistant'); }
                toolCalls(m, out);
            }
            var fixed = false;
            for (var l = 0; l < body.choices.length; l++) { if (tokens(body.choices[l].logprobs)) { fixed = true; } }
            return { segments: out, unreadable: null, fixed: fixed };
        },
        replyStream: function (text, cx) {
            var ev = AIRS3.sseEvents(text);
            if (ev === null) { return { segments: [], unreadable: 'an event that is not JSON' }; }
            var byChoice = {}, order = [], calls = {}, callOrder = [], out = [], extra = [];
            for (var i = 0; i < ev.length; i++) {
                if (ev[i].data === '[DONE]') { continue; }
                var d = JSON.parse(ev[i].data);
                var cs = d && AIRS3.isArray(d.choices) ? d.choices : [];
                for (var j = 0; j < cs.length; j++) {
                    if (!AIRS3.isObject(cs[j])) { continue; }
                    var idx = cs[j].index !== undefined ? cs[j].index : j, dl = cs[j].delta || {};
                    if (byChoice[idx] === undefined) { byChoice[idx] = []; order.push(idx); }
                    var bits = [dl.content, dl.refusal, dl.reasoning_content, dl.reasoning, AIRS3.isObject(dl.audio) ? dl.audio.transcript : undefined];
                    for (var b = 0; b < bits.length; b++) { if (typeof bits[b] === 'string') { byChoice[idx].push(bits[b]); } }
                    // content as a list of parts, as the JSON reader reads it (v3's own restream copies a list as it is)
                    if (AIRS3.isArray(dl.content)) { for (var pc = 0; pc < dl.content.length; pc++) { var cp = dl.content[pc]; if (typeof cp === 'string') { byChoice[idx].push(cp); } else if (AIRS3.isObject(cp) && typeof cp.text === 'string') { byChoice[idx].push(cp.text); } } }
                    if (AIRS3.isArray(dl.annotations) && dl.annotations.length) { extra.push(AIRS3.jsonText(dl.annotations)); }
                    if (AIRS3.isObject(dl.context)) { extra.push(AIRS3.jsonText(dl.context)); }
                    var tc = AIRS3.isArray(dl.tool_calls) ? dl.tool_calls : [];
                    for (var t = 0; t < tc.length; t++) {
                        var key = idx + ':' + (tc[t].index !== undefined ? tc[t].index : t);
                        if (!calls[key]) { calls[key] = { name: '', args: '' }; callOrder.push(key); }
                        var fn = tc[t]['function'] || tc[t].custom || {};
                        if (fn.name && !calls[key].name) { calls[key].name = fn.name; }
                        if (typeof fn.arguments === 'string') { calls[key].args += fn.arguments; }
                        if (typeof fn.input === 'string') { calls[key].args += fn.input; }
                    }
                }
            }
            for (var o = 0; o < order.length; o++) { AIRS3.seg(out, byChoice[order[o]].join(''), 'assistant'); }
            for (var c = 0; c < callOrder.length; c++) { AIRS3.seg(out, AIRS3.toolCall(calls[callOrder[c]].name, calls[callOrder[c]].args), 'assistant'); }
            for (var p = 0; p < extra.length; p++) { AIRS3.seg(out, extra[p], 'assistant'); }
            return { segments: out, unreadable: null };
        },
        writeBack: function (body, cuts) { return AIRS3.writeCuts(body, cuts); },
        refusal: function (kind, message, cx) { return { code: 200, type: 'application/json', body: JSON.stringify(completion(message, cx)) }; },
        streamRefusal: function (kind, message, cx) {
            var m = cx.model || 'prisma-airs';
            return { code: 200, type: 'text/event-stream',
                     body: AIRS3.sse('', chunk('chatcmpl-prisma-airs', m, { index: 0, delta: { role: 'assistant', content: message }, finish_reason: null })) +
                           AIRS3.sse('', chunk('chatcmpl-prisma-airs', m, { index: 0, delta: {}, finish_reason: 'stop' })) + 'data: [DONE]\n\n' };
        },
        destream: function (body, path, query) {
            if (!AIRS3.isObject(body) || body.stream !== true) { return null; }
            var b = JSON.parse(JSON.stringify(body));
            b.stream = false;
            delete b.stream_options;
            return { body: b, path: path, query: query, kind: 'chat-sse' };
        },
        restream: function (reply, kind) {
            if (!AIRS3.isObject(reply) || !AIRS3.isArray(reply.choices)) { return null; }
            var id = reply.id || 'chatcmpl-prisma-airs', model = reply.model || '', s = '';
            for (var i = 0; i < reply.choices.length; i++) {
                var ch = reply.choices[i], m = ch.message || {}, delta = { role: 'assistant' };
                if (m.content !== undefined && m.content !== null) { delta.content = m.content; }
                if (m.refusal) { delta.refusal = m.refusal; }
                var copied = ['reasoning_content', 'reasoning', 'audio', 'annotations', 'context'];   // the rest of the message, as sent
                for (var k = 0; k < copied.length; k++) { if (m[copied[k]] !== undefined && m[copied[k]] !== null) { delta[copied[k]] = m[copied[k]]; } }
                if (AIRS3.isArray(m.tool_calls)) {
                    delta.tool_calls = [];
                    for (var t = 0; t < m.tool_calls.length; t++) {
                        var tc = m.tool_calls[t] || {}, dc = { index: t, id: tc.id, type: tc.type || 'function' };
                        if (tc.custom) { dc.custom = tc.custom; } else { dc['function'] = tc['function']; }
                        delta.tool_calls.push(dc);
                    }
                }
                s += AIRS3.sse('', chunk(id, model, { index: ch.index !== undefined ? ch.index : i, delta: delta, finish_reason: null }));
                // The tokens ride on the finish chunk: the SDK stream helpers copy an opening chunk's logprobs and then append
                // to them, so tokens there would count twice.
                var last = { index: ch.index !== undefined ? ch.index : i, delta: {}, finish_reason: ch.finish_reason || 'stop' };
                if (ch.logprobs !== undefined && ch.logprobs !== null) { last.logprobs = ch.logprobs; }
                s += AIRS3.sse('', chunk(id, model, last));
            }
            if (reply.usage) { s += AIRS3.sse('', { id: id, object: 'chat.completion.chunk', created: reply.created, model: model, choices: [], usage: reply.usage }); }
            return { type: 'text/event-stream', body: s + 'data: [DONE]\n\n' };
        }
    };
})();

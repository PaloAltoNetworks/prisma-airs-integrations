/*
 * airs3-fmt-openai-responses.js: the OpenAI Responses API in full (A03, A08, A30).
 */
AIRS3_FMT['openai-responses'] = (function () {
    function isText(p) { return p.type === 'input_text' || p.type === 'output_text' || p.type === 'text' || p.type === 'refusal' || p.type === 'summary_text'; }
    function parts(c, role, at, out) {
        if (c === null || c === undefined) { return null; }
        if (typeof c === 'string') { AIRS3.seg(out, c, role, at); return null; }
        if (!AIRS3.isArray(c)) { return 'a content is neither a string nor a list'; }
        for (var j = 0; j < c.length; j++) {
            var p = c[j];
            if (typeof p === 'string') { AIRS3.seg(out, p, role, at.concat([j])); continue; }
            if (!AIRS3.isObject(p)) { return 'a content part is not an object'; }
            if (isText(p)) {
                var k = typeof p.text === 'string' ? 'text' : 'refusal';
                AIRS3.seg(out, p[k], role, at.concat([j, k]));
                if (AIRS3.isArray(p.annotations) && p.annotations.length) { AIRS3.seg(out, AIRS3.jsonText(p.annotations), role); }
                if (AIRS3.nonEmpty(p.logprobs)) { state.fixed = true; }    // never masked
            }
            else { AIRS3.seg(out, AIRS3.jsonText(p), role); }             // input_image, input_file: JSON, bytes left out
        }
        return null;
    }
    var state = { fixed: false };                                         // reset by request() and reply()
    function item(it, at, out, onReply) {
        if (!AIRS3.isObject(it)) { return 'an item is not an object'; }
        var t = it.type || 'message';
        if (t === 'message') {
            var role = onReply ? 'assistant' : (it.role === 'system' || it.role === 'developer' ? 'system' : (it.role === 'assistant' ? 'assistant' : 'user'));
            return parts(it.content, role, at.concat(['content']), out);
        }
        if (t === 'function_call') { AIRS3.seg(out, AIRS3.toolCall(it.name, it.arguments), 'assistant'); return null; }
        if (t === 'custom_tool_call') { AIRS3.seg(out, AIRS3.toolCall(it.name, it.input), 'assistant'); return null; }
        if (t === 'reasoning') {
            if (AIRS3.isArray(it.summary)) { for (var s = 0; s < it.summary.length; s++) { AIRS3.seg(out, it.summary[s] && it.summary[s].text, 'assistant'); } }
            if (AIRS3.isArray(it.content)) { for (var rc = 0; rc < it.content.length; rc++) { AIRS3.seg(out, it.content[rc] && it.content[rc].text, 'assistant'); } }   // reasoning_text
            return null;
        }
        if (/_output$/.test(t)) {                                           // function_call_output and every other tool result
            var o = it.output;
            if (typeof o === 'string') { AIRS3.seg(out, o, 'tool', at.concat(['output'])); }
            else if (AIRS3.isArray(o)) { return parts(o, 'tool', at.concat(['output']), out); }
            else if (o !== undefined) { AIRS3.seg(out, AIRS3.jsonText(o), 'tool'); }
            return null;
        }
        AIRS3.seg(out, AIRS3.jsonText(it), onReply ? 'assistant' : 'tool');  // web search, file search, MCP items: their JSON
        return null;
    }
    function response(text, cx) {
        return { id: 'resp_prisma_airs', object: 'response', created_at: Math.floor(new Date().getTime() / 1000), status: 'completed', model: cx.model || 'prisma-airs',
                 output: [{ type: 'message', id: 'msg_prisma_airs', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: text, annotations: [] }] }],
                 usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 } };
    }
    function events(r) {
        var seq = 0, s = '';
        function ev(type, obj) { obj.type = type; obj.sequence_number = seq++; s += AIRS3.sse(type, obj); }
        var head = JSON.parse(JSON.stringify(r)); head.output = []; head.status = 'in_progress';
        ev('response.created', { response: head });
        var out = r.output || [];
        for (var i = 0; i < out.length; i++) {
            var it = out[i];
            var start = JSON.parse(JSON.stringify(it));
            if (start.type === 'message') { start.content = []; start.status = 'in_progress'; }
            ev('response.output_item.added', { output_index: i, item: start });
            if (it.type === 'message') {
                var cs = it.content || [];
                for (var c = 0; c < cs.length; c++) {
                    var part = cs[c];
                    ev('response.content_part.added', { item_id: it.id, output_index: i, content_index: c, part: { type: part.type, text: '', annotations: [] } });
                    if (part.type === 'output_text') {
                        ev('response.output_text.delta', { item_id: it.id, output_index: i, content_index: c, delta: part.text });
                        ev('response.output_text.done', { item_id: it.id, output_index: i, content_index: c, text: part.text });
                    } else if (part.type === 'refusal') {
                        ev('response.refusal.delta', { item_id: it.id, output_index: i, content_index: c, delta: part.refusal });
                        ev('response.refusal.done', { item_id: it.id, output_index: i, content_index: c, refusal: part.refusal });
                    }
                    ev('response.content_part.done', { item_id: it.id, output_index: i, content_index: c, part: part });
                }
            } else if (it.type === 'function_call') {
                ev('response.function_call_arguments.delta', { item_id: it.id, output_index: i, delta: it.arguments || '' });
                ev('response.function_call_arguments.done', { item_id: it.id, output_index: i, arguments: it.arguments || '' });
            }
            ev('response.output_item.done', { output_index: i, item: it });
        }
        ev('response.completed', { response: r });
        return s;
    }
    function fromDeltas(ev) {
        var out = [], texts = {}, order = [], names = {};
        for (var i = 0; i < ev.length; i++) {
            if (ev[i].data === '[DONE]') { continue; }
            var d = JSON.parse(ev[i].data);
            if (!AIRS3.isObject(d) || typeof d.type !== 'string') { continue; }
            var idx = String(d.output_index !== undefined ? d.output_index : 0);
            if (/^response\.output_item\.(added|done)$/.test(d.type) && AIRS3.isObject(d.item) && (d.item.type === 'function_call' || d.item.type === 'custom_tool_call')) {
                names[idx] = d.item.name || names[idx] || '';
            }
            var key = idx + ':' + d.type.replace(/\.(delta|done)$/, '');
            if (/\.delta$/.test(d.type) && typeof d.delta === 'string') { if (!texts[key]) { texts[key] = []; order.push(key); } texts[key].push(d.delta); }
        }
        for (var o = 0; o < order.length; o++) {
            var k = order[o], at = k.split(':')[0], text = texts[k].join('');
            AIRS3.seg(out, /function_call_arguments|custom_tool_call_input/.test(k) ? AIRS3.toolCall(names[at], text) : text, 'assistant');
        }
        return out;
    }

    return {
        request: function (body, cx) {
            if (!AIRS3.isObject(body)) { return { segments: [], unreadable: 'the body is not a JSON object' }; }
            var out = [], e;
            state.fixed = false;
            if (typeof body.instructions === 'string') { AIRS3.seg(out, body.instructions, 'system', ['instructions']); }
            else if (body.instructions !== undefined && body.instructions !== null) { return { segments: [], unreadable: 'instructions is not a string' }; }
            // A stored prompt's variables: the caller's text, filled into the prompt.
            if (body.prompt !== undefined && body.prompt !== null) {
                if (!AIRS3.isObject(body.prompt)) { return { segments: [], unreadable: 'prompt is not an object' }; }
                var vs = body.prompt.variables;
                if (vs !== undefined && vs !== null && !AIRS3.isObject(vs)) { return { segments: [], unreadable: 'prompt variables is not an object' }; }
                for (var vk in (vs || {})) {
                    if (!Object.prototype.hasOwnProperty.call(vs, vk)) { continue; }
                    var v = vs[vk];
                    if (typeof v === 'string') { AIRS3.seg(out, v, 'user', ['prompt', 'variables', vk]); }
                    else if (AIRS3.isObject(v) && isText(v) && typeof v.text === 'string') { AIRS3.seg(out, v.text, 'user', ['prompt', 'variables', vk, 'text']); }
                    else if (v !== null && v !== undefined) { AIRS3.seg(out, AIRS3.jsonText(v), 'user'); }
                }
            }
            if (typeof body.input === 'string') { AIRS3.seg(out, body.input, 'user', ['input']); }
            else if (AIRS3.isArray(body.input)) {
                for (var i = 0; i < body.input.length; i++) { e = item(body.input[i], ['input', i], out, false); if (e) { return { segments: [], unreadable: e }; } }
            } else if (body.input !== undefined) { return { segments: [], unreadable: 'input is neither a string nor a list' }; }
            return { segments: out, unreadable: null, fixed: state.fixed };
        },
        reply: function (body, cx) {
            var out = [], e, i;
            state.fixed = false;
            // A stored conversation's items, as a list or one at a time: read like a reply's output.
            if (AIRS3.isObject(body) && body.object === 'list' && AIRS3.isArray(body.data)) {
                for (i = 0; i < body.data.length; i++) { e = item(body.data[i], ['data', i], out, true); if (e) { return { segments: [], unreadable: e }; } }
                return { segments: out, unreadable: null, fixed: state.fixed };
            }
            if (AIRS3.isObject(body) && body.output === undefined && typeof body.type === 'string' && body.object !== 'response') {
                e = item(body, [], out, true);
                return e ? { segments: [], unreadable: e } : { segments: out, unreadable: null, fixed: state.fixed };
            }
            if (!AIRS3.isObject(body) || !AIRS3.isArray(body.output)) { return { segments: [], unreadable: 'the reply has no output list' }; }
            for (i = 0; i < body.output.length; i++) { e = item(body.output[i], ['output', i], out, true); if (e) { return { segments: [], unreadable: e }; } }
            return { segments: out, unreadable: null, fixed: state.fixed };
        },
        replyStream: function (text, cx) {
            var ev = AIRS3.sseEvents(text);
            if (ev === null) { return { segments: [], unreadable: 'an event that is not JSON' }; }
            for (var i = ev.length - 1; i >= 0; i--) {
                var d = ev[i].data === '[DONE]' ? null : JSON.parse(ev[i].data);
                if (d && /^response\.(completed|incomplete|failed)$/.test(d.type) && d.response && AIRS3.isArray(d.response.output)) {
                    var res = this.reply(d.response, cx);
                    var deltas = fromDeltas(ev);                            // what a client renders is scanned too
                    return { segments: (res.segments || []).concat(deltas), unreadable: res.unreadable };
                }
            }
            return { segments: fromDeltas(ev), unreadable: null };
        },
        writeBack: function (body, cuts) { return AIRS3.writeCuts(body, cuts); },
        refusal: function (kind, message, cx) { return { code: 200, type: 'application/json', body: JSON.stringify(response(message, cx)) }; },
        streamRefusal: function (kind, message, cx) { return { code: 200, type: 'text/event-stream', body: events(response(message, cx)) }; },
        destream: function (body, path, query) {
            if (!AIRS3.isObject(body) || body.stream !== true) { return null; }
            var b = JSON.parse(JSON.stringify(body)); b.stream = false; delete b.stream_options;
            return { body: b, path: path, query: query, kind: 'responses-sse' };
        },
        restream: function (reply, kind) {
            if (!AIRS3.isObject(reply) || !AIRS3.isArray(reply.output)) { return null; }
            return { type: 'text/event-stream', body: events(reply) };
        }
    };
})();

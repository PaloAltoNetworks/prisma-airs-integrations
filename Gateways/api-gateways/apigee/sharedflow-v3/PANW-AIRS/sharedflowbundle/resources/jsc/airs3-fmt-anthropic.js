/*
 * airs3-fmt-anthropic.js: Anthropic Messages, and Claude on Vertex (rawPredict and streamRawPredict).
 */
AIRS3_FMT['anthropic'] = (function () {
    function blocks(list, role, at, out) {
        for (var j = 0; j < list.length; j++) {
            var b = list[j], here = at.concat([j]);
            if (typeof b === 'string') { AIRS3.seg(out, b, role, here); continue; }
            if (!AIRS3.isObject(b)) { return 'a content block is not an object'; }
            var t = b.type;
            if (t === 'text') {
                AIRS3.seg(out, b.text, role, here.concat(['text']));
                if (AIRS3.isArray(b.citations) && b.citations.length) { AIRS3.seg(out, AIRS3.jsonText(sealed(b.citations)), role); }   // cited text and URLs
            }
            // A block is read under its turn's role (assistant in an assistant turn, tool inside a tool result).
            else if (t === 'tool_use' || t === 'server_tool_use') { AIRS3.seg(out, AIRS3.toolCall(b.name, b.input), role === 'tool' ? 'tool' : 'assistant'); }
            else if (t === 'tool_result') {
                // Its content is read like any content: text, documents and images (a base64 text source is decoded).
                // Any other shape is refused, as it is for a message.
                var c = b.content;
                if (typeof c === 'string') { AIRS3.seg(out, c, 'tool', here.concat(['content'])); }
                else if (AIRS3.isArray(c)) { var e0 = blocks(c, 'tool', here.concat(['content']), out); if (e0) { return e0; } }
                else if (c !== undefined && c !== null) { return 'a tool result content is neither a string nor a list'; }
            }
            // Server and MCP tool results (web fetch, web search, code execution, MCP) sit in assistant turns: they are tool
            // results, always read. Encrypted parts only Anthropic can read are left out.
            // A base64 source inside one is decoded like a document's.
            else if (typeof t === 'string' && /_tool_result$/.test(t)) { AIRS3.seg(out, AIRS3.jsonText(unpacked(sealed(b), out)), 'tool'); }
            else if (t === 'thinking') { AIRS3.seg(out, b.thinking, role === 'tool' ? 'tool' : 'assistant'); }
            else if (t === 'redacted_thinking') { if (role === 'tool') { AIRS3.seg(out, AIRS3.jsonText(b), 'tool'); } }   // encrypted: nothing to read, except where it doesn't belong
            else if (t === 'document') {
                AIRS3.seg(out, b.title, role); AIRS3.seg(out, b.context, role);
                var src = b.source || {};
                if (src.type === 'text' && typeof src.data === 'string') { AIRS3.seg(out, src.data, role, here.concat(['source', 'data'])); }
                else if (src.type === 'content' && AIRS3.isArray(src.content)) { var e = blocks(src.content, role, here.concat(['source', 'content']), out); if (e) { return e; } }
                else if (src.type === 'base64') { var r = AIRS3.slotText(src.data || '', src.media_type); if (r.kind === 'text') { AIRS3.seg(out, r.text, role); } AIRS3.seg(out, AIRS3.jsonText(slotless(b, r)), role); }
                else { AIRS3.seg(out, AIRS3.jsonText(b), role); }
            }
            else if (t === 'search_result') {
                AIRS3.seg(out, b.source, role); AIRS3.seg(out, b.title, role);
                if (AIRS3.isArray(b.content)) { var e2 = blocks(b.content, role, here.concat(['content']), out); if (e2) { return e2; } }
            }
            else {
                var s2 = b.source;
                var r2 = null;
                if (AIRS3.isObject(s2) && s2.type === 'base64') { r2 = AIRS3.slotText(s2.data || '', s2.media_type); if (r2.kind === 'text') { AIRS3.seg(out, r2.text, role); } }
                AIRS3.seg(out, AIRS3.jsonText(r2 ? slotless(b, r2) : b), role);
            }
        }
        return null;
    }
    // A copy with every encrypted value (encrypted_content, encrypted_index) replaced by a placeholder.
    function sealed(v) {
        if (AIRS3.isArray(v)) { var a = []; for (var i = 0; i < v.length; i++) { a.push(sealed(v[i])); } return a; }
        if (!AIRS3.isObject(v)) { return v; }
        var o = {};
        for (var k in v) {
            if (!Object.prototype.hasOwnProperty.call(v, k)) { continue; }
            AIRS3.put(o, k, /^encrypted_/.test(k) && typeof v[k] === 'string' ? '<encrypted, ' + v[k].length + ' characters>' : sealed(v[k]));
        }
        return o;
    }
    // A copy (from sealed()) whose base64 sources are read by the bytes rule: text goes out as its own tool segment and the
    // copy says where it went.
    function unpacked(v, out) {
        if (AIRS3.isArray(v)) { for (var i = 0; i < v.length; i++) { v[i] = unpacked(v[i], out); } return v; }
        if (!AIRS3.isObject(v)) { return v; }
        if (v.type === 'base64' && typeof v.data === 'string') {
            var r = AIRS3.slotText(v.data, v.media_type);
            if (r.kind === 'text') { AIRS3.seg(out, r.text, 'tool'); }
            v.data = r.kind === 'text' ? '<text, read above>' : '<binary, ' + v.data.length + ' characters>';
            return v;
        }
        for (var k in v) { if (Object.prototype.hasOwnProperty.call(v, k)) { v[k] = unpacked(v[k], out); } }
        return v;
    }
    // A block's JSON with its base64 source replaced by where it went: read above as text, or left out.
    function slotless(b, r) {
        var c = JSON.parse(JSON.stringify(b));
        c.source.data = r.kind === 'text' ? '<text, read above>' : '<binary, ' + String(b.source.data || '').length + ' characters>';
        return c;
    }
    function message(text, cx) {
        return { id: 'msg_prisma_airs', type: 'message', role: 'assistant', model: cx.model || 'prisma-airs', content: [{ type: 'text', text: text }],
                 stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } };
    }
    function events(msg) {
        var head = JSON.parse(JSON.stringify(msg)); head.content = []; head.stop_reason = null;
        var s = AIRS3.sse('message_start', { type: 'message_start', message: head });
        for (var i = 0; i < msg.content.length; i++) {
            var b = msg.content[i];
            if (b.type === 'text') {
                s += AIRS3.sse('content_block_start', { type: 'content_block_start', index: i, content_block: { type: 'text', text: '' } });
                s += AIRS3.sse('content_block_delta', { type: 'content_block_delta', index: i, delta: { type: 'text_delta', text: b.text } });
            } else if (b.type === 'tool_use') {
                s += AIRS3.sse('content_block_start', { type: 'content_block_start', index: i, content_block: { type: 'tool_use', id: b.id, name: b.name, input: {} } });
                s += AIRS3.sse('content_block_delta', { type: 'content_block_delta', index: i, delta: { type: 'input_json_delta', partial_json: JSON.stringify(b.input || {}) } });
            } else if (b.type === 'thinking') {
                s += AIRS3.sse('content_block_start', { type: 'content_block_start', index: i, content_block: { type: 'thinking', thinking: '' } });
                s += AIRS3.sse('content_block_delta', { type: 'content_block_delta', index: i, delta: { type: 'thinking_delta', thinking: b.thinking } });
                if (b.signature) { s += AIRS3.sse('content_block_delta', { type: 'content_block_delta', index: i, delta: { type: 'signature_delta', signature: b.signature } }); }
            } else {
                s += AIRS3.sse('content_block_start', { type: 'content_block_start', index: i, content_block: b });
            }
            s += AIRS3.sse('content_block_stop', { type: 'content_block_stop', index: i });
        }
        s += AIRS3.sse('message_delta', { type: 'message_delta', delta: { stop_reason: msg.stop_reason || 'end_turn', stop_sequence: msg.stop_sequence || null },
                                          usage: { output_tokens: (msg.usage && msg.usage.output_tokens) || 0 } });
        s += AIRS3.sse('message_stop', { type: 'message_stop' });
        return s;
    }

    return {
        request: function (body, cx) {
            if (!AIRS3.isObject(body)) { return { segments: [], unreadable: 'the body is not a JSON object' }; }
            var out = [], e;
            if (typeof body.system === 'string') { AIRS3.seg(out, body.system, 'system', ['system']); }
            else if (AIRS3.isArray(body.system)) { e = blocks(body.system, 'system', ['system'], out); if (e) { return { segments: [], unreadable: e }; } }
            else if (body.system !== undefined) { return { segments: [], unreadable: 'system is neither a string nor a list' }; }
            if (!AIRS3.isArray(body.messages)) { return { segments: [], unreadable: 'messages is not a list' }; }
            for (var i = 0; i < body.messages.length; i++) {
                var m = body.messages[i];
                if (!AIRS3.isObject(m)) { return { segments: [], unreadable: 'a message is not an object' }; }
                var role = m.role === 'assistant' ? 'assistant' : 'user';
                if (typeof m.content === 'string') { AIRS3.seg(out, m.content, role, ['messages', i, 'content']); }
                else if (AIRS3.isArray(m.content)) { e = blocks(m.content, role, ['messages', i, 'content'], out); if (e) { return { segments: [], unreadable: e }; } }
                else { return { segments: [], unreadable: 'a content is neither a string nor a list' }; }
            }
            return { segments: out, unreadable: null };
        },
        reply: function (body, cx) {
            if (!AIRS3.isObject(body) || !AIRS3.isArray(body.content)) { return { segments: [], unreadable: 'the reply has no content list' }; }
            var out = [], e = blocks(body.content, 'assistant', ['content'], out);
            return e ? { segments: [], unreadable: e } : { segments: out, unreadable: null };
        },
        replyStream: function (text, cx) {
            var ev = AIRS3.sseEvents(text);
            if (ev === null) { return { segments: [], unreadable: 'an event that is not JSON' }; }
            var parts = {}, order = [], out = [];
            for (var i = 0; i < ev.length; i++) {
                if (ev[i].data === '[DONE]') { continue; }
                var d = JSON.parse(ev[i].data);
                if (!AIRS3.isObject(d)) { continue; }
                if (d.type === 'error') { break; }
                if (d.type === 'content_block_start') {
                    var cb = d.content_block || {};
                    // A server tool result arrives whole in its start event.
                    var known = /^(text|thinking|redacted_thinking|tool_use|server_tool_use)$/.test(String(cb.type));
                    parts[d.index] = { type: cb.type, name: cb.name, text: known ? (cb.text || cb.thinking || '') : AIRS3.jsonText(sealed(cb)) };
                    order.push(d.index);
                } else if (d.type === 'content_block_delta' && parts[d.index]) {
                    var dl = d.delta || {};
                    if (dl.type === 'text_delta') { parts[d.index].text += dl.text || ''; }
                    else if (dl.type === 'thinking_delta') { parts[d.index].text += dl.thinking || ''; }
                    else if (dl.type === 'input_json_delta') { parts[d.index].text += dl.partial_json || ''; }
                    else if (dl.type === 'citations_delta' && dl.citation !== undefined) { parts[d.index].text += '\n' + AIRS3.jsonText(sealed(dl.citation)); }
                }
            }
            for (var o = 0; o < order.length; o++) {
                var p = parts[order[o]];
                AIRS3.seg(out, p.type === 'tool_use' || p.type === 'server_tool_use' ? AIRS3.toolCall(p.name, p.text) : p.text, 'assistant');
            }
            return { segments: out, unreadable: null };
        },
        writeBack: function (body, cuts) { return AIRS3.writeCuts(body, cuts); },
        refusal: function (kind, message, cx) { return { code: 200, type: 'application/json', body: JSON.stringify(message ? messageOf(message, cx) : {}) }; },
        streamRefusal: function (kind, message, cx) { return { code: 200, type: 'text/event-stream', body: events(messageOf(message, cx)) }; },
        destream: function (body, path, query) {
            var raw = /:streamRawPredict$/.test(path);
            var flag = AIRS3.isObject(body) && body.stream === true;
            if (!raw && !flag) { return null; }
            var b = flag ? JSON.parse(JSON.stringify(body)) : null;
            if (b) { b.stream = false; }
            return { body: b, path: raw ? path.replace(/:streamRawPredict$/, ':rawPredict') : path, query: query, kind: raw ? 'anthropic-rawpredict' : 'anthropic-sse' };
        },
        restream: function (reply, kind) {
            if (!AIRS3.isObject(reply) || !AIRS3.isArray(reply.content)) { return null; }
            return { type: 'text/event-stream', body: events(reply) };
        }
    };
    function messageOf(text, cx) { return message(text, cx); }
})();

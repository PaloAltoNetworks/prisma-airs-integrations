/*
 * airs3-fmt-gemini.js: Gemini and Vertex generateContent. camelCase and snake_case field names are both read.
 */
AIRS3_FMT['gemini'] = (function () {
    function pick(o, a, b) { return o[a] !== undefined ? o[a] : o[b]; }
    function roleOf(r) { return r === 'model' ? 'assistant' : ((r === 'function' || r === 'tool') ? 'tool' : 'user'); }

    // A part's fields, by both JSON names. A part that names one field twice is refused, because which copy the model reads
    // is not known.
    var FIELDS = [['functionCall', 'function_call'], ['functionResponse', 'function_response'], ['inlineData', 'inline_data'], ['fileData', 'file_data'],
                  ['executableCode', 'executable_code'], ['codeExecutionResult', 'code_execution_result']];
    var QUIET = { text: 1, thought: 1, thoughtSignature: 1, thought_signature: 1 };    // read below, or opaque
    for (var f = 0; f < FIELDS.length; f++) { QUIET[FIELDS[f][0]] = 1; QUIET[FIELDS[f][1]] = 1; }

    // One part of a request or reply; `role` is its turn's role; `at` the part's path. Every field the part carries is read,
    // under its turn's role: a part is meant to hold one, but a body may hold more (a thought flag in a
    // user turn changes nothing).
    function part(p, role, at, out) {
        if (!AIRS3.isObject(p)) { return 'a part is not an object'; }
        for (var w = 0; w < FIELDS.length; w++) { if (p[FIELDS[w][0]] !== undefined && p[FIELDS[w][1]] !== undefined) { return 'a part names one field twice'; } }
        if (typeof p.text === 'string') { AIRS3.seg(out, p.text, role, at.concat(['text'])); }
        var fc = pick(p, 'functionCall', 'function_call');
        if (fc !== undefined) { AIRS3.seg(out, AIRS3.toolCall(fc && fc.name, fc && fc.args), role); }
        var fr = pick(p, 'functionResponse', 'function_response');
        if (fr !== undefined) {
            AIRS3.seg(out, (fr && fr.name ? fr.name + ': ' : '') + AIRS3.jsonText(fr && fr.response !== undefined ? fr.response : fr), 'tool');
            // A multimodal function response's own parts (inline data, files): read as parts.
            var frp = AIRS3.isObject(fr) ? fr.parts : undefined, fk = p.functionResponse !== undefined ? 'functionResponse' : 'function_response';
            if (frp !== undefined && !AIRS3.isArray(frp)) { return 'a function response\'s parts is not a list'; }
            for (var q = 0; frp && q < frp.length; q++) { var e0 = part(frp[q], 'tool', at.concat([fk, 'parts', q]), out); if (e0) { return e0; } }
        }
        var ec = pick(p, 'executableCode', 'executable_code');
        if (ec !== undefined) { AIRS3.seg(out, ec && ec.code, role); }
        var cr = pick(p, 'codeExecutionResult', 'code_execution_result');
        if (cr !== undefined) { AIRS3.seg(out, cr && cr.output, 'tool'); }
        var inl = pick(p, 'inlineData', 'inline_data');
        if (AIRS3.isObject(inl)) {
            var mt = pick(inl, 'mimeType', 'mime_type');
            var r = AIRS3.slotText(inl.data || '', mt);
            if (r.kind === 'text') { AIRS3.seg(out, r.text, role); }
            var ci = JSON.parse(JSON.stringify(inl)), ik = p.inlineData !== undefined ? 'inlineData' : 'inline_data', wrap = {};
            ci.data = r.kind === 'text' ? '<text, read above>' : '<binary, ' + String(inl.data || '').length + ' characters>';
            wrap[ik] = ci;
            AIRS3.seg(out, AIRS3.jsonText(wrap), role);               // its media type and any name are scanned too (A28)
        } else if (inl !== undefined) { AIRS3.seg(out, AIRS3.jsonText(inl), role); }
        var fd = pick(p, 'fileData', 'file_data');
        if (fd !== undefined) { var fw = {}; fw[p.fileData !== undefined ? 'fileData' : 'file_data'] = fd; AIRS3.seg(out, AIRS3.jsonText(fw), role); }
        var rest = {}, n = 0;                                         // anything else the part carries: its JSON
        for (var k in p) {
            if (!Object.prototype.hasOwnProperty.call(p, k)) { continue; }
            // a text that isn't a string, or a thought flag that isn't a boolean, goes in the JSON too
            // own members of QUIET only: a member named like an Object.prototype property (constructor) is not quiet
            if (!Object.prototype.hasOwnProperty.call(QUIET, k) || (k === 'text' && typeof p.text !== 'string') || (k === 'thought' && typeof p.thought !== 'boolean')) { AIRS3.put(rest, k, p[k]); n++; }
        }
        if (n) { AIRS3.seg(out, AIRS3.jsonText(rest), role); }
        return null;
    }
    // A candidate's log probabilities: see AIRS3.nonEmpty; the reply is then never masked.
    function tokens(lp) {
        return AIRS3.isObject(lp) && (AIRS3.nonEmpty(pick(lp, 'chosenCandidates', 'chosen_candidates')) || AIRS3.nonEmpty(pick(lp, 'topCandidates', 'top_candidates')));
    }
    var state = { fixed: false };                                         // reset by reply()
    function content(c, role, at, out) {
        if (typeof c === 'string') { AIRS3.seg(out, c, role, at); return null; }
        if (!AIRS3.isObject(c)) { return 'a content is not an object'; }
        var parts = c.parts;
        if (parts === undefined) { return null; }
        if (!AIRS3.isArray(parts)) { return 'parts is not a list'; }
        for (var j = 0; j < parts.length; j++) { var e = part(parts[j], role, at.concat(['parts', j]), out); if (e) { return e; } }
        return null;
    }
    function candidates(list, at, out) {
        for (var i = 0; i < list.length; i++) {
            var cd = list[i];
            if (!AIRS3.isObject(cd)) { return 'a candidate is not an object'; }
            if (cd.content !== undefined) { var e = content(cd.content, 'assistant', at.concat([i, 'content']), out); if (e) { return e; } }
            var metas = [['groundingMetadata', 'grounding_metadata'], ['citationMetadata', 'citation_metadata'], ['urlContextMetadata', 'url_context_metadata']];
            for (var m = 0; m < metas.length; m++) { var md = pick(cd, metas[m][0], metas[m][1]); if (md !== undefined) { AIRS3.seg(out, AIRS3.jsonText(md), 'assistant'); } }
            if (tokens(pick(cd, 'logprobsResult', 'logprobs_result'))) { state.fixed = true; }
        }
        return null;
    }
    // A stream's chunks (a JSON array, or event-stream events): text joined per candidate, because chunks split words.
    function merged(chunks) {
        var texts = {}, order = [], out = [], i, j;
        for (i = 0; i < chunks.length; i++) {
            var ch = chunks[i];
            if (!AIRS3.isObject(ch)) { return { unreadable: 'a stream chunk is not an object' }; }
            if (ch.error !== undefined) { break; }
            var cs = ch.candidates || [];
            if (!AIRS3.isArray(cs)) { return { unreadable: 'candidates is not a list' }; }
            for (j = 0; j < cs.length; j++) {
                var idx = cs[j] && cs[j].index !== undefined ? cs[j].index : j;
                var tmp = [];
                var e = candidates([cs[j]], [], tmp);
                if (e) { return { unreadable: e }; }
                if (texts[idx] === undefined) { texts[idx] = []; order.push(idx); }
                for (var k = 0; k < tmp.length; k++) { texts[idx].push(tmp[k].text); }
            }
        }
        for (i = 0; i < order.length; i++) { AIRS3.seg(out, texts[order[i]].join(''), 'assistant'); }
        return { segments: out, unreadable: null };
    }

    function refusalBody(message) {
        return { candidates: [{ content: { role: 'model', parts: [{ text: message }] }, finishReason: 'STOP', index: 0 }],
                 usageMetadata: { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 }, modelVersion: 'prisma-airs' };
    }

    return {
        request: function (body, cx) {
            if (!AIRS3.isObject(body)) { return { segments: [], unreadable: 'the body is not a JSON object' }; }
            var out = [], e;
            if (body.systemInstruction !== undefined && body.system_instruction !== undefined) { return { segments: [], unreadable: 'the body names systemInstruction twice' }; }
            var si = pick(body, 'systemInstruction', 'system_instruction');
            var siKey = body.systemInstruction !== undefined ? 'systemInstruction' : 'system_instruction';
            if (si !== undefined) { e = content(si, 'system', [siKey], out); if (e) { return { segments: [], unreadable: e }; } }
            var cs = body.contents;
            if (cs === undefined) { cs = []; }
            if (!AIRS3.isArray(cs)) { return { segments: [], unreadable: 'contents is not a list' }; }
            for (var i = 0; i < cs.length; i++) {
                if (!AIRS3.isObject(cs[i])) { return { segments: [], unreadable: 'a content is not an object' }; }
                e = content(cs[i], roleOf(cs[i].role), ['contents', i], out);
                if (e) { return { segments: [], unreadable: e }; }
            }
            return { segments: out, unreadable: null };
        },
        reply: function (body, cx) {
            state.fixed = false;
            if (AIRS3.isArray(body)) { var mg = merged(body); mg.fixed = state.fixed; return mg; }   // :streamGenerateContent without alt=sse
            if (!AIRS3.isObject(body)) { return { segments: [], unreadable: 'the reply is not a JSON object' }; }
            if (body.candidates === undefined) {
                return body.promptFeedback !== undefined || body.prompt_feedback !== undefined ? { segments: [], unreadable: null } : { segments: [], unreadable: 'the reply has no candidates' };
            }
            if (!AIRS3.isArray(body.candidates)) { return { segments: [], unreadable: 'candidates is not a list' }; }
            var out = [], e = candidates(body.candidates, ['candidates'], out);
            return e ? { segments: [], unreadable: e } : { segments: out, unreadable: null, fixed: state.fixed };
        },
        replyStream: function (text, cx) {
            var ev = AIRS3.sseEvents(text);
            if (ev === null) { return { segments: [], unreadable: 'an event that is not JSON' }; }
            var chunks = [];
            for (var i = 0; i < ev.length; i++) { if (ev[i].data !== '[DONE]') { chunks.push(JSON.parse(ev[i].data)); } }
            return merged(chunks);
        },
        writeBack: function (body, cuts) { return AIRS3.writeCuts(body, cuts); },
        refusal: function (kind, message, cx) { return { code: 200, type: 'application/json', body: JSON.stringify(refusalBody(message)) }; },
        streamRefusal: function (kind, message, cx) {
            if (cx.stream === 'gemini-array') { return { code: 200, type: 'application/json', body: JSON.stringify([refusalBody(message)]) }; }
            return { code: 200, type: 'text/event-stream', body: 'data: ' + JSON.stringify(refusalBody(message)) + '\r\n\r\n' };
        },
        destream: function (body, path, query) {
            if (!/:streamGenerateContent$/.test(path)) { return null; }
            var sse = /(^|&)alt=sse(&|$)/.test(query);
            var q = query.split('&').filter(function (p) { return p && p.indexOf('alt=') !== 0; }).join('&');
            return { body: null, path: path.replace(/:streamGenerateContent$/, ':generateContent'), query: q, kind: sse ? 'gemini-sse' : 'gemini-array' };
        },
        restream: function (reply, kind) {
            if (kind === 'gemini-array') { return { type: 'application/json', body: JSON.stringify([reply]) }; }
            return { type: 'text/event-stream', body: 'data: ' + JSON.stringify(reply) + '\r\n\r\n' };
        }
    };
})();

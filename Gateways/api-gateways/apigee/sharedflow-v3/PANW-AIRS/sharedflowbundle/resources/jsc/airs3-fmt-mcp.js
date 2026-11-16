/*
 * airs3-fmt-mcp.js: MCP over JSON-RPC (A17, A19, A24, A29).
 *   Request leg. Control (ping, logging/setLevel, initialized, notifications/*), catalogue (initialize, resources/list,
 *   resources/templates/list, prompts/list, roots/list) and tools/list: their params are not scanned. tools/call becomes
 *   a Prisma AIRS tool event. Every other method's params but _meta, and a client's reply (its result, error and params),
 *   are scanned as text; so is a result or an error on any message. Members outside the JSON-RPC envelope are always
 *   scanned, so a message carrying them is scanned whole, as text.
 *   Reply leg. Every message is scanned whole but its protocol members (a ping's empty result has nothing). An answer is
 *   a message with a result or an error; a method beside them changes nothing. A tools/call result is the tool event's
 *   output, a tools/list answer a tool event whose output is the bare tools array; what such an answer carries besides
 *   (an error, params, the list's other members but nextCursor and _meta) is a second scan, as text. Everything else is
 *   text, server requests and notifications included.
 *   Batches. Each member is its own scan, in order, on both legs; a reply is matched to its request member by id, as a
 *   JSON value, and the messages that answer no member are scanned together, as one text after the answers. Several
 *   scans come back as `scans`, which airs3-read.js puts into slots 1 to 8.
 *   Bytes. Strings are scanned as written. Only an image or audio block's data and a resource's blob are binary slots,
 *   read against their mimeType; an icon's data-URI src is always left out, an icon link is scanned. Look-alikes
 *   elsewhere (a data URI in a text block, base64 in arguments, structuredContent, schemas, _meta) stay text.
 *   MCP text is never rewritten; refusals are written by airs3-respond.js.
 */
AIRS3_FMT['mcp'] = (function () {
    var ENVELOPE = { jsonrpc: 1, id: 1, method: 1, params: 1, result: 1, error: 1 };
    var QUIET = { 'ping': 1, 'logging/setLevel': 1, 'initialized': 1, 'initialize': 1, 'resources/list': 1, 'resources/templates/list': 1,
                  'prompts/list': 1, 'roots/list': 1, 'tools/list': 1 };
    function quiet(method) { return QUIET[method] === 1 || /^notifications\//.test(String(method)); }
    function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
    // Own members only: a member named like an Object.prototype property (constructor, valueOf) is not the envelope's.
    function extras(m) { for (var k in m) { if (own(m, k) && !own(ENVELOPE, k)) { return true; } } return false; }
    function otherParams(p) { for (var k in p) { if (Object.prototype.hasOwnProperty.call(p, k) && k !== 'name' && k !== 'arguments' && k !== '_meta') { return true; } } return false; }
    function asWritten(v) { return typeof v === 'string' ? v : JSON.stringify(v); }
    // Client-sent (params, arguments, a client's replies): the LLM rule, so a data URI is decoded.
    function clientText(v) { return typeof v === 'string' ? AIRS3.bytesRule(v).text : AIRS3.jsonText(v); }
    function empty(v) { return v === undefined || v === null || (AIRS3.isObject(v) && AIRS3.keys(v).length === 0); }
    // params without _meta, protocol metadata (a progress token, say) that MuleSoft never scans on the request leg.
    function noMeta(p) {
        if (!AIRS3.isObject(p) || !own(p, '_meta')) { return p; }
        var o = {}; for (var k in p) { if (own(p, k) && k !== '_meta') { AIRS3.put(o, k, p[k]); } } return o;
    }

    // A copy of server-sent JSON with its binary slots judged, by place.
    function slot(data, mt) { var r = AIRS3.slotText(data, mt); return r.kind === 'skip' ? '<binary, ' + String(data).length + ' characters>' : r.text; }
    function icons(list) {
        if (!AIRS3.isArray(list)) { return list; }
        var out = [];
        for (var i = 0; i < list.length; i++) {
            var ic = list[i];
            if (AIRS3.isObject(ic) && typeof ic.src === 'string' && /^data:/i.test(ic.src)) {
                var c = {}; for (var k in ic) { if (Object.prototype.hasOwnProperty.call(ic, k)) { AIRS3.put(c, k, ic[k]); } }
                var comma = ic.src.indexOf(',');
                c.src = (comma > 0 ? ic.src.slice(0, comma + 1) : 'data:,') + '<binary, ' + ic.src.length + ' characters>';
                out.push(c);
            } else { out.push(ic); }
        }
        return out;
    }
    // Server-sent data URIs: one that carries text is scanned as that text; one that carries bytes stays as written, so text
    // dressed as an image is never left out (look-alikes are never slots).
    function serverUri(x) { var t = AIRS3.bytesRule(x).text; return t.indexOf('<binary, ') !== -1 ? x : t; }
    function copy(v, place) {
        if (typeof v === 'string') { return /^data:/i.test(v) ? serverUri(v) : v; }
        if (!AIRS3.isObject(v) && !AIRS3.isArray(v)) { return v; }
        if (AIRS3.isArray(v)) { var a = []; for (var i = 0; i < v.length; i++) { a.push(copy(v[i], place)); } return a; }
        var o = {}, k;
        for (k in v) {
            if (!Object.prototype.hasOwnProperty.call(v, k)) { continue; }
            var x = v[k];
            if (k === 'icons' && (place === 'block' || place === 'resource' || place === 'definition')) { AIRS3.put(o, k, icons(x)); }
            else if (place === 'body' && k === 'content') { AIRS3.put(o, k, copy(x, 'block')); }
            else if (place === 'body' && k === 'contents') { AIRS3.put(o, k, copy(x, 'resource')); }
            else if (place === 'body' && k === 'messages') { AIRS3.put(o, k, copy(x, 'body')); }
            else if (place === 'body' && (k === 'tools' || k === 'prompts' || k === 'resources' || k === 'resourceTemplates')) { AIRS3.put(o, k, copy(x, 'definition')); }
            else if (place === 'body' && (k === 'serverInfo' || k === 'clientInfo')) { AIRS3.put(o, k, copy(x, 'definition')); }
            else if (place === 'block' && k === 'data' && (v.type === 'image' || v.type === 'audio') && typeof x === 'string') { AIRS3.put(o, k, slot(x, v.mimeType)); }
            else if (place === 'block' && k === 'resource') { AIRS3.put(o, k, copy(x, 'resource')); }
            else if (place === 'block' && k === 'content') { AIRS3.put(o, k, copy(x, 'block')); }                 // a sampling message's content
            else if (place === 'resource' && k === 'blob' && typeof x === 'string') { AIRS3.put(o, k, slot(x, v.mimeType)); }
            else if (typeof x === 'string' && /^data:/i.test(x)) { AIRS3.put(o, k, serverUri(x)); }              // a text data URI is decoded
            else if (AIRS3.isObject(x) || AIRS3.isArray(x)) { AIRS3.put(o, k, copy(x, 'opaque')); }
            else { AIRS3.put(o, k, x); }                                            // arguments, structuredContent, schemas, _meta: as written
        }
        return o;
    }
    function serverText(v) { return JSON.stringify(copy(v, 'body')); }
    // A client's reply has the same places as a server's (resources, blobs), read by the client rule otherwise.
    function copyClient(v) { var c = copy(v, 'body'); return AIRS3.parse(AIRS3.jsonText(c)); }
    // A client's result as text: a string as written (a data URI read for its text), anything else as JSON, places judged.
    function clientValue(v) { return typeof v === 'string' ? clientText(v) : JSON.stringify(copyClient(v)); }

    function toolEvent(cx, name, input, output, method) {
        var te = { metadata: { ecosystem: 'mcp', method: method || 'tools/call', server_name: cx.serverName || 'mcp-server' }, input: input };
        if (name) { te.metadata.tool_invoked = String(name); }
        if (output !== undefined) { te.output = output; }
        return te;
    }
    // The text of a tools/call result: text blocks as written, then the rest of the result, slots judged (A19).
    function resultText(r) {
        if (!AIRS3.isObject(r)) { return asWritten(r); }
        var c = copy(r, 'body'), bits = [], blocks = AIRS3.isArray(c.content) ? c.content : [];
        for (var i = 0; i < blocks.length; i++) {
            if (AIRS3.isObject(blocks[i]) && blocks[i].type === 'text' && typeof blocks[i].text === 'string') {
                bits.push(blocks[i].text);
                var more = {}, any = false;                          // its other members (_meta, annotations, ...): scanned too
                for (var m in blocks[i]) { if (own(blocks[i], m) && m !== 'type' && m !== 'text') { AIRS3.put(more, m, blocks[i][m]); any = true; } }
                if (any) { bits.push(JSON.stringify(more)); }
            }
            else { bits.push(JSON.stringify(blocks[i])); }
        }
        var rest = {};                                                // a content that isn't a list stays in the rest
        for (var k in c) { if (own(c, k) && !(k === 'content' && AIRS3.isArray(c.content)) && !(k === 'isError' && typeof c[k] === 'boolean')) { AIRS3.put(rest, k, c[k]); } }
        if (AIRS3.keys(rest).length) { bits.push(JSON.stringify(rest)); }
        return bits.join('\n');
    }

    function requestOne(body, cx) {
        if (!AIRS3.isObject(body)) { return { segments: [], unreadable: 'the body is not a JSON-RPC message' }; }
        var out = [];
        // read whole as text; over the size limit it keeps its newest part, as LLM text does (an LLM body dressed as JSON-RPC)
        if (extras(body)) { AIRS3.seg(out, clientText(body), 'user'); return { segments: out, unreadable: null, newest: true }; }
        // tools/call params beyond name, arguments and _meta, or a result or an error beside the call: the whole message is
        // the tool event's input, still a tool event under toolProfile
        if (body.method === 'tools/call' && AIRS3.isObject(body.params) && (otherParams(body.params) || body.result !== undefined || body.error !== undefined)) {
            var whole = clientText(body);
            AIRS3.seg(out, whole, 'tool');
            return { segments: out, unreadable: null, toolEvent: toolEvent(cx, body.params.name, whole) };
        }
        if (body.method === 'tools/call' && AIRS3.isObject(body.params)) {
            var input = body.params.arguments === undefined ? '{}' : clientText(body.params.arguments);
            AIRS3.seg(out, input, 'tool');
            return { segments: out, unreadable: null, toolEvent: toolEvent(cx, body.params.name, input) };
        }
        // A method's params (but a quiet method's) and a client's reply's params, without _meta; then any result or error,
        // whatever the message: a client's answer to a server request, or one carried by a request (MuleSoft's rule).
        var params = noMeta(body.params);
        if ((body.method === undefined || !quiet(body.method)) && !empty(params)) { AIRS3.seg(out, clientText(params), 'user'); }
        if (!empty(body.result)) { AIRS3.seg(out, clientValue(body.result), 'user'); }
        if (body.error !== undefined && body.error !== null) { AIRS3.seg(out, clientText(body.error), 'user'); }
        return { segments: out, unreadable: null };
    }
    function replyOne(body, cx, reqBody) {
        if (!AIRS3.isObject(body)) { return { segments: [], unreadable: 'the reply is not a JSON-RPC message' }; }
        var out = [], method = AIRS3.isObject(reqBody) ? reqBody.method : '';
        // Members outside the envelope (an LLM reply to a look-alike request, say): all of it, as text. A body with no
        // result, error or method is not a JSON-RPC reply at all.
        if (extras(body)) {
            var all = serverText(body);
            AIRS3.seg(out, all, 'tool');
            if (method === 'tools/call' && AIRS3.isObject(reqBody.params) && !extras(reqBody)) {      // still a tool event
                var inp = reqBody.params.arguments === undefined ? '{}' : clientText(reqBody.params.arguments);
                return { segments: out, unreadable: null, toolEvent: toolEvent(cx, reqBody.params.name, inp, all) };
            }
            return { segments: out, unreadable: null };
        }
        if (body.method === undefined && body.result === undefined && body.error === undefined) { return { segments: [], unreadable: 'the reply is not a JSON-RPC message' }; }
        // A server request's or a notification's params; params beside an answer. Then, for an answer (a result or an
        // error, whether or not a method sits beside them: MuleSoft's rule), its error.
        if (!empty(body.params)) { AIRS3.seg(out, serverText(body.params), 'tool'); }
        if (body.result === undefined && body.error === undefined) { return { segments: out, unreadable: null }; }
        if (body.error !== undefined && body.error !== null) { AIRS3.seg(out, asWritten(body.error), 'tool'); }   // a null adds no text
        if (empty(body.result)) { return { segments: out, unreadable: null }; }                  // a ping's {} has nothing
        if (method === 'tools/call' && AIRS3.isObject(reqBody.params)) {
            var outText = resultText(body.result);
            var input = reqBody.params.arguments === undefined ? '{}' : clientText(reqBody.params.arguments);
            var callSegs = [];
            AIRS3.seg(callSegs, outText, 'tool');
            var call = toolEvent(cx, reqBody.params.name, input, outText);
            if (!out.length) { return { segments: callSegs, unreadable: null, toolEvent: call }; }
            // what the answer carries besides its result (an error, params): a second scan, as text (MuleSoft's rule)
            return { scans: [{ segments: callSegs, toolEvent: call }, { segments: out }], segments: [], unreadable: null };
        }
        // tools/list: a tool event whose output is the bare tools array (Prisma AIRS refuses the {tools: [...]} object with
        // HTTP 400, as MuleSoft measured); the result's other members, but nextCursor and _meta, are a second scan, as text.
        if (method === 'tools/list' && AIRS3.isObject(body.result) && AIRS3.isArray(body.result.tools)) {
            var tin = empty(reqBody.params) ? '{}' : clientText(reqBody.params);
            var tout = JSON.stringify(copy(body.result.tools, 'definition'));
            var teSegs = [];
            AIRS3.seg(teSegs, tout, 'tool');
            var te = toolEvent(cx, null, tin, tout, 'tools/list');
            var more = {}, hasMore = false;
            for (var key in body.result) {
                if (own(body.result, key) && key !== 'tools' && key !== 'nextCursor' && key !== '_meta') { AIRS3.put(more, key, body.result[key]); hasMore = true; }
            }
            if (hasMore) { AIRS3.seg(out, serverText(more), 'tool'); }          // with any error or params already in out
            if (!out.length) { return { segments: teSegs, unreadable: null, toolEvent: te }; }
            return { scans: [{ segments: teSegs, toolEvent: te }, { segments: out }], segments: [], unreadable: null };
        }
        AIRS3.seg(out, serverText(body.result), 'tool');               // initialize, resources/read, prompts/get, ...
        return { segments: out, unreadable: null };
    }
    // One read result's scans: its own list, or itself when it has a tool event or text.
    function scansOf(r) {
        if (r.scans) { return r.scans; }
        return (r.toolEvent || (r.segments && r.segments.length)) ? [r] : [];
    }
    // A reply to a batch, or a reply that is an array: each answer is matched to the request member that has its id, as a
    // JSON value ('1' does not answer 1), and scanned as that member's answer. Messages that answer no member (notifications,
    // the server's own requests, answers to ids nobody sent) are scanned together, as one text after the answers.
    function replyMany(body, cx, reqBody) {
        var msgs = AIRS3.isArray(body) ? body : [body];
        if (!msgs.length) { return { segments: [], unreadable: 'an empty reply batch' }; }
        var members = AIRS3.isArray(reqBody) ? reqBody : (AIRS3.isObject(reqBody) ? [reqBody] : []), asked = {};
        for (var i = 0; i < members.length; i++) {
            var m = members[i];
            if (AIRS3.isObject(m) && typeof m.method === 'string' && m.id !== undefined && m.id !== null) { asked[AIRS3.idText(m.id)] = m; }
        }
        var scans = [], rest = [];
        for (var j = 0; j < msgs.length; j++) {
            var x = msgs[j];
            // an answer: a result or an error, with an id a request member sent; a method beside them changes nothing
            var answer = AIRS3.isObject(x) && (x.result !== undefined || x.error !== undefined) && x.id !== undefined;
            var mem = answer && own(asked, AIRS3.idText(x.id)) ? asked[AIRS3.idText(x.id)] : null;
            var r = replyOne(x, cx, mem || {});
            // an element that is not a JSON-RPC message: its text joins the joint scan (MuleSoft reads it as text)
            if (r.unreadable) { AIRS3.seg(rest, typeof x === 'string' ? x : serverText(x), 'tool'); continue; }
            if (mem) { var got = scansOf(r); for (var s = 0; s < got.length; s++) { scans.push(got[s]); } }
            else { for (var q = 0; q < (r.segments || []).length; q++) { rest.push(r.segments[q]); } }
        }
        if (rest.length) { scans.push({ segments: rest }); }
        return { scans: scans, segments: [], unreadable: null };
    }

    return {
        request: function (body, cx) {
            if (!AIRS3.isArray(body)) { return requestOne(body, cx); }
            var scans = [];                                               // a batch: each member its own scan, in order
            for (var i = 0; i < body.length; i++) {
                var r = requestOne(body[i], cx);
                if (r.unreadable) { return { segments: [], unreadable: r.unreadable + ' (a batch member)' }; }
                var got = scansOf(r);
                for (var s = 0; s < got.length; s++) { scans.push(got[s]); }
            }
            return { scans: scans, segments: [], unreadable: null };
        },
        reply: function (body, cx, reqBody) {
            if (AIRS3.isArray(body) || AIRS3.isArray(reqBody)) { return replyMany(body, cx, reqBody); }
            return replyOne(body, cx, reqBody);
        },
        writeBack: function () { return null; },
        refusal: null,
        destream: function () { return null; },
        restream: function () { return null; }
    };
})();

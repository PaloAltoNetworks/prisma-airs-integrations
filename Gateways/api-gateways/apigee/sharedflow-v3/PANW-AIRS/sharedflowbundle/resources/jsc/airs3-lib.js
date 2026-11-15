/*
 * airs3-lib.js: helpers every v3 step includes (ES5, Rhino 1.7.13).
 * Names: every flow variable v3 sets is airs3.<leaf> with no further dot, or private.airs3_<leaf>, so no name ever
 * extends another (Apigee drops such a set silently: L6). The README lists the steps and variables.
 */
var AIRS3 = AIRS3 || {};
var AIRS3_FMT = AIRS3_FMT || {};

AIRS3.raw = function (name) {
    var v = context.getVariable(name);
    return (v === null || v === undefined) ? null : v;
};
AIRS3.str = function (name) { var v = AIRS3.raw(name); return v === null ? '' : String(v); };
AIRS3.get = function (leaf) { return AIRS3.str('airs3.' + leaf); };
AIRS3.set = function (leaf, value) {
    if (String(leaf).indexOf('.') !== -1) { throw new Error('airs3 leaf names have no dot: ' + leaf); }
    context.setVariable('airs3.' + leaf, (value === null || value === undefined) ? '' : String(value));
};
AIRS3.done = function (step) { context.setVariable('airs3.done' + step, 'true'); };

AIRS3.isArray = function (x) { return Object.prototype.toString.call(x) === '[object Array]'; };
AIRS3.isObject = function (x) { return x !== null && typeof x === 'object' && !AIRS3.isArray(x); };
AIRS3.parse = function (s) {
    if (s === null || s === undefined) { return undefined; }
    try { return JSON.parse(String(s)); } catch (e) { return undefined; }
};
AIRS3.keys = function (o) { var out = []; for (var k in o) { if (Object.prototype.hasOwnProperty.call(o, k)) { out.push(k); } } return out; };
/* Sets member k of a new object. A member named __proto__ (JSON.parse makes it an own member) is defined, not assigned:
 * assigning it would set the object's prototype instead, and the member would drop out of the scan text. */
AIRS3.put = function (o, k, v) {
    if (k === '__proto__') { Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true }); }
    else { o[k] = v; }
};
/* Whether a parsed body holds an object or array whose prototype is not the plain one: a runtime whose JSON.parse turned a
 * __proto__ member into a prototype, which hides that member from every reader. Such a body can't be inspected. */
AIRS3.oddProto = function (v) {
    if (AIRS3.isArray(v)) {
        if (Object.getPrototypeOf(v) !== Array.prototype) { return true; }
        for (var i = 0; i < v.length; i++) { if (AIRS3.oddProto(v[i])) { return true; } }
        return false;
    }
    if (v === null || typeof v !== 'object') { return false; }
    if (Object.getPrototypeOf(v) !== Object.prototype) { return true; }
    for (var k in v) { if (Object.prototype.hasOwnProperty.call(v, k) && AIRS3.oddProto(v[k])) { return true; } }
    return false;
};

/* Scan slots. Slot 1 is SC-Airs3Scan, answering into airs3ScanResponse; slots 2 to 8 are SC-Airs3Scan<k>, answering into
 * airs3ScanResponse<k>. Only MCP uses more than one: a batch's members, and a tools/list answer with more than its tools. */
AIRS3.SLOTS = 8;
/* One slot's answer, judged (A14 to A16): only HTTP 200 with a JSON object whose action is exactly allow or block is a
 * verdict; an allow that reports an error or a time-out is a failure; 400 or 413 is content Prisma AIRS refused. */
/* Whether slot k was answered from the verdict cache on this leg: JS-Airs3CacheHits sets airs3.vcHit<k> only after this leg's
 * keys were all made and its own lookup hit with a scan id. AM-Airs3Reset sets it false on every leg, so a lookup that didn't
 * run or didn't finish is a miss, whatever the runtime's lookupcache variables still hold from the other leg (L6). */
AIRS3.cacheHit = function (k) { return AIRS3.get('vcHit' + k) === 'true'; };
AIRS3.judge = function (k) {
    var sfx = k > 1 ? String(k) : '';
    // A hit stands for the allow it was written from: only a clean allow is ever written (airs3-cache.js).
    if (AIRS3.cacheHit(k)) { return { status: 200, body: { action: 'allow', category: 'benign', scan_id: AIRS3.get('vcScan' + k) }, outcome: 'allow', note: '', cached: true }; }
    var sraw = AIRS3.str('airs3ScanResponse' + sfx + '.status.code');
    var status = sraw === '' ? null : parseInt(sraw, 10);
    // A failed call that shows a 2xx or 3xx got no answer: AM-Airs3ClearScan's new message has status 200 and no body on
    // Apigee (L14), and a call with no answer leaves it so, with its failed flag true. A 4xx or 5xx is a real answer.
    if (status !== null && status < 400 && AIRS3.str('servicecallout.SC-Airs3Scan' + sfx + '.failed') === 'true') { status = null; }
    var body = status === 200 ? AIRS3.parse(AIRS3.str('airs3ScanResponse' + sfx + '.content')) : undefined;
    var outcome, note = '';
    if (status === null) { outcome = 'failure'; note = 'no answer from Prisma AIRS'; }
    else if (status === 400 || status === 413) { outcome = 'refused'; note = 'Prisma AIRS refused the content (HTTP ' + status + ')'; }
    else if (status !== 200) { outcome = 'failure'; note = 'Prisma AIRS answered HTTP ' + status; }
    else if (!AIRS3.isObject(body)) { outcome = 'failure'; note = 'an answer that is not a JSON object'; }
    else if (body.action !== 'allow' && body.action !== 'block') { outcome = 'failure'; note = 'an answer with no action'; }
    else if (body.action === 'allow' && (body.error === true || body.timeout === true || body.category === 'error' || body.category === 'timeout')) {
        outcome = 'failure'; note = 'an allow that reports an error or a time-out';
    } else { outcome = body.action; }
    return { status: status, body: body, outcome: outcome, note: note };
};
/* Whether an answer carries a masked copy, on either side or in a tool entry. */
AIRS3.hasMasked = function (body) {
    if (!AIRS3.isObject(body)) { return false; }
    function md(x) { return AIRS3.isObject(x) && typeof x.data === 'string'; }
    if (md(body.prompt_masked_data) || md(body.response_masked_data)) { return true; }
    var td = body.tool_detected, sides = ['input_detected', 'output_detected'];
    for (var s = 0; s < sides.length; s++) {
        var e = AIRS3.isObject(td) && td[sides[s]] && td[sides[s]].detection_entries;
        if (AIRS3.isArray(e)) { for (var i = 0; i < e.length; i++) { if (e[i] && md(e[i].masked_data)) { return true; } } }
    }
    return false;
};
/* The decision on one judged answer (j, from AIRS3.judge), as this leg takes it: its detections, masking, the reply leg's
 * prompt-only rule for LLM traffic, then failOpen and onScanError. It changes nothing, so JS-Airs3Slot<k> (the early stop)
 * and JS-Airs3Verdict judge every slot by the same rules. `passes`: the leg may go on; `via`: what let an answer that is
 * not a clean allow pass (failOpen, onScanError, or the prompt-only rule). */
AIRS3.decide = function (j) {
    var leg = AIRS3.get('leg'), format = AIRS3.get('format');
    var body = j.body, outcome = j.outcome, note = j.note, dets = [], masked = null, isTool = false;
    var d = { status: j.status, body: body, category: '', scanId: '', maskedText: null, via: '' };
    function flags(obj, prefix) { if (!AIRS3.isObject(obj)) { return; } for (var k in obj) { if (obj[k] === true) { dets.push(prefix + k); } } }
    // Detections: this leg's side first, then the other side, then tool events; each a true flag. MCP text goes to Prisma
    // AIRS as a prompt on both legs (MuleSoft's rule), so its own side is the prompt's.
    if (AIRS3.isObject(body)) {
        var own = leg === 'request' || format === 'mcp' ? 'prompt' : 'response', other = own === 'prompt' ? 'response' : 'prompt';
        flags(body[own + '_detected'], own + '.');
        flags(body[other + '_detected'], other + '.');
        var td = body.tool_detected;
        var entries = 0;
        if (AIRS3.isObject(td) && (td.input_detected || td.output_detected)) {
            isTool = true;
            var sides = [['input_detected', 'tool_input.'], ['output_detected', 'tool_output.']];
            for (var s = 0; s < sides.length; s++) {
                var e = td[sides[s][0]] && td[sides[s][0]].detection_entries;
                if (AIRS3.isArray(e)) { for (var i = 0; i < e.length; i++) { entries++; flags(e[i] && e[i].detections, sides[s][1]); } }
            }
        }
        if (AIRS3.isObject(td) && entries === 0 && AIRS3.isObject(td.summary)) { flags(td.summary.detections, 'tool.'); }
        var md = leg === 'request' ? body.prompt_masked_data : body.response_masked_data;
        if (AIRS3.isObject(md) && typeof md.data === 'string') { masked = md.data; }
        if (isTool) {
            var te = leg === 'request' ? td.input_detected : td.output_detected;
            var ent = te && AIRS3.isArray(te.detection_entries) ? te.detection_entries[0] : null;
            if (ent && AIRS3.isObject(ent.masked_data) && typeof ent.masked_data.data === 'string') { masked = ent.masked_data.data; }
        }
        d.category = typeof body.category === 'string' ? body.category : '';
        d.scanId = typeof body.scan_id === 'string' ? body.scan_id : '';
    }

    // Masking. A request body is never a stream, so a prompt can always be masked; a reply seen as an event stream never
    // is. MCP text is never rewritten (A24): an allow that carries a masked copy of any of it, on either side or in any
    // tool entry, is refused as a block would be; arguments are not forwarded, results are withheld.
    var onlyDlp = dets.length > 0;
    for (var q = 0; q < dets.length; q++) { if (!/\.dlp$/.test(dets[q])) { onlyDlp = false; } }
    var streamSeen = AIRS3.get('stream') === 'event-stream-reply';
    if (format === 'mcp') {
        if (outcome === 'allow' && AIRS3.hasMasked(body)) { outcome = 'block'; note = 'Prisma AIRS asked to mask text that v3 never rewrites'; }
    } else if (masked !== null && outcome === 'block' && AIRS3.get('applyMask') === 'true' && onlyDlp && !streamSeen) { outcome = 'mask'; }
    else if (masked !== null && outcome === 'allow') {
        if (streamSeen) { outcome = 'block'; note = 'Prisma AIRS asked to mask text that v3 never rewrites'; }
        else { outcome = 'mask'; }
    }
    if (outcome === 'mask') {
        var seg = AIRS3.parse(AIRS3.get('segments')) || {};
        if (seg.cut || seg.fixed || masked.length !== seg.length) { outcome = 'block'; note = 'the masked text could not be written back exactly'; }
        else { d.maskedText = masked; }
    }

    // The reply leg judges the reply: on LLM traffic, a block whose detections are all the prompt's (sent as context) lets
    // it through. MCP scans carry no context, so their prompt.* detections are the reply's own.
    if (outcome === 'block' && leg === 'response' && format !== 'mcp' && AIRS3.get('phase') !== 'both' && dets.length) {
        var promptOnly = true;
        for (var p = 0; p < dets.length; p++) { if (dets[p].indexOf('prompt.') !== 0) { promptOnly = false; } }
        if (promptOnly && (AIRS3.get('promptVerdict') === 'allow' || AIRS3.get('promptVerdict') === 'mask')) { outcome = 'allow'; note = 'only the prompt context was flagged; the reply itself was clean'; d.via = 'prompt-only'; }
    }
    if (outcome === 'failure' && AIRS3.get('failOpen') === 'true') { outcome = 'allow'; note = 'failed open: ' + note; d.via = 'failOpen'; }
    if (outcome === 'refused' && AIRS3.get('onScanError') === 'allow') { outcome = 'allow'; note = 'gap allowed: ' + note; d.via = 'onScanError'; }
    d.outcome = outcome; d.note = note; d.dets = dets;
    d.passes = outcome === 'allow' || outcome === 'mask';
    return d;
};
/* Whether slot k's answer lets the leg go on: the same decision JS-Airs3Verdict makes on it. In monitor mode every slot
 * runs, as MuleSoft scans on after a decision it doesn't enforce. */
AIRS3.slotPasses = function (k) { return AIRS3.get('mode') === 'monitor' || AIRS3.decide(AIRS3.judge(k)).passes; };

/* A leg that passes: streaming is turned off on the way to the model, so the reply can be read (L1), and the reply goes back in
 * the client's own stream format. Every pass on a leg v3 reads sets these, whatever decided it: the verdict, an open circuit
 * breaker with failOpen, a gap onScanError lets through, an empty reply, or monitor mode. A reply that is already an event
 * stream, or one outside 2xx (an error, which passes as it is: A31), stays as it is. True when either is needed. */
AIRS3.streamNeeds = function () {
    var leg = AIRS3.get('leg'), kind = AIRS3.get('stream');
    var d = leg === 'request' && (kind === 'body' || kind === 'gemini-sse' || kind === 'rawpredict');
    var r = leg === 'response' && AIRS3.get('destreamed') !== '' && kind !== 'event-stream-reply' && /^2[0-9][0-9]$/.test(AIRS3.str('response.status.code'));
    AIRS3.set('needDestream', d ? 'true' : 'false');
    AIRS3.set('needRestream', r ? 'true' : 'false');
    return d || r;
};

/* A refusal: kind is 'refused' (content that can't be inspected) or 'config'. The message holds no content, header or key,
 * and no setting's value but mcpBatchLimit's number, so the log line can carry it too. */
AIRS3.refuse = function (kind, message) {
    if (AIRS3.get('refuse') !== 'none' && AIRS3.get('refuse') !== '') { return; }          // the first reason stands
    AIRS3.set('refuse', kind);
    AIRS3.set('refuseMsg', message);
};

/*
 * The bytes rule (A28): is a string text to scan, or bytes to leave out?
 *   - a data: URI is decoded; text media types and valid UTF-8 are scanned as text;
 *   - long base64 is left out only when it is not valid UTF-8 AND starts with a known binary signature;
 *   - otherwise the string is scanned as written.
 * Returns { kind: 'text' | 'skip', text: <what to scan> }.
 */
AIRS3.B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
AIRS3.b64Bytes = function (s, maxBytes) {
    var t = String(s).replace(/[\r\n\s]/g, ''), out = [], buf = 0, bits = 0, i, c, v;
    t = t.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
    for (i = 0; i < t.length; i++) {
        c = t.charAt(i); v = AIRS3.B64.indexOf(c);
        if (v < 0) { return null; }
        buf = (buf << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 255); if (maxBytes && out.length >= maxBytes) { break; } }
    }
    return out;
};
AIRS3.utf8 = function (bytes) {
    var i = 0, n = bytes.length, out = [], b, need, cp, k;
    while (i < n) {
        b = bytes[i];
        if (b < 0x80) { out.push(String.fromCharCode(b)); i++; continue; }
        if ((b >> 5) === 6) { need = 1; cp = b & 31; } else if ((b >> 4) === 14) { need = 2; cp = b & 15; } else if ((b >> 3) === 30) { need = 3; cp = b & 7; } else { return null; }
        for (k = 1; k <= need; k++) { if (i + k >= n || (bytes[i + k] >> 6) !== 2) { return null; } cp = (cp << 6) | (bytes[i + k] & 63); }
        if (cp > 0xFFFF) { cp -= 0x10000; out.push(String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 1023))); } else { out.push(String.fromCharCode(cp)); }
        i += need + 1;
    }
    return out.join('');
};
AIRS3.SIGNATURES = [
    [0x89, 0x50, 0x4E, 0x47], [0xFF, 0xD8, 0xFF], [0x47, 0x49, 0x46, 0x38], [0x25, 0x50, 0x44, 0x46], [0x50, 0x4B, 0x03, 0x04],
    [0x52, 0x49, 0x46, 0x46], [0x49, 0x44, 0x33], [0x1F, 0x8B], [0x42, 0x4D], [0x00, 0x00, 0x00]
];
AIRS3.hasSignature = function (bytes) {
    for (var s = 0; s < AIRS3.SIGNATURES.length; s++) {
        var sig = AIRS3.SIGNATURES[s], ok = bytes.length >= sig.length;
        for (var i = 0; ok && i < sig.length; i++) { if (bytes[i] !== sig[i]) { ok = false; } }
        if (ok) { return true; }
    }
    return false;
};
AIRS3.isTextType = function (mt) { mt = String(mt || '').toLowerCase(); return mt.indexOf('text/') === 0 || /json|xml|javascript|yaml|csv|svg|x-sh|x-python|x-www-form/.test(mt); };
AIRS3.latin1 = function (bytes) { var out = []; for (var i = 0; i < bytes.length; i++) { out.push(String.fromCharCode(bytes[i])); } return out.join(''); };
// A declared payload (Gemini inlineData, an Anthropic base64 source, an MCP image, audio or blob), read against its media
// type: a text type is decoded (leniently, so Latin-1 text keeps its ASCII); valid UTF-8 is text, whatever it starts with;
// anything else is left out.
AIRS3.slotText = function (data, mediaType) {
    var bytes = AIRS3.b64Bytes(String(data));
    if (bytes === null) { return { kind: 'text', text: String(data) }; }          // not base64: scanned as written
    var u = AIRS3.utf8(bytes);
    if (AIRS3.isTextType(mediaType)) { return { kind: 'text', text: u !== null ? u : AIRS3.latin1(bytes) }; }
    if (u !== null) { return { kind: 'text', text: u }; }
    return { kind: 'skip', text: '' };
};
// A data URI: 'data:', a media type (type/subtype, optional parameters, no spaces; at most 255 characters), ';base64'
// optionally, then a comma. 'data: some sentence' is not one.
AIRS3.DATA_URI = /^data:((?:[A-Za-z0-9!#$&^_.+\-]+\/[A-Za-z0-9!#$&^_.+\-]+)?(?:;[A-Za-z0-9!#$&^_.+\-]+=[^;,\s]*)*)(;base64)?,/i;
AIRS3.bytesRule = function (value, mediaType) {
    var s = String(value);
    var m = AIRS3.DATA_URI.exec(s);
    if (m && m[0].length <= 262) {
        var head = s.slice(0, m[0].length), payload = s.slice(m[0].length), mt = (m[1] || '').split(';')[0] || 'text/plain';
        if (!m[2]) { try { return { kind: 'text', text: head + decodeURIComponent(payload) }; } catch (e) { return { kind: 'text', text: s }; } }
        var bytes = AIRS3.b64Bytes(payload);
        if (bytes === null) { return { kind: 'text', text: s }; }
        var t = AIRS3.utf8(bytes);
        if (t !== null) { return { kind: 'text', text: head + t }; }                                // UTF-8 is always text
        if (AIRS3.isTextType(mt)) { return { kind: 'text', text: head + AIRS3.latin1(bytes) }; }
        if (AIRS3.hasSignature(bytes)) { return { kind: 'text', text: head + '<binary, ' + payload.length + ' characters>' }; }
        return { kind: 'text', text: s };
    }
    // Long base64 is left out only when it isn't UTF-8 AND starts with a known binary signature; anything else stays text.
    if (s.length >= 256 && /^[A-Za-z0-9+\/_\-\r\n]+={0,2}$/.test(s)) {
        var head2 = AIRS3.b64Bytes(s.slice(0, 64), 32);
        if (head2 !== null && AIRS3.hasSignature(head2)) {
            var all = AIRS3.b64Bytes(s);
            if (all !== null && AIRS3.utf8(all) === null) { return { kind: 'skip', text: '' }; }
        }
    }
    return { kind: 'text', text: s };
};

/*
 * Duplicate keys among the keys v3 reads (A20): a key that appears more often in the raw body than in the parsed tree
 * was duplicated somewhere, and JSON.parse kept only one copy. Cheaper than a character scan (L2).
 */
AIRS3.READ_KEYS = ['messages', 'contents', 'input', 'system', 'systemInstruction', 'system_instruction', 'instructions', 'parts', 'content',
                   'text', 'role', 'params', 'arguments', 'method', 'jsonrpc', 'result', 'choices', 'candidates', 'output', 'tool_calls',
                   'functionCall', 'functionResponse', 'response', 'data', 'structuredContent', 'resource', 'error', 'stream'];
AIRS3.duplicateKey = function (raw, parsed) {
    var counts = {};
    function walk(o) {
        if (AIRS3.isArray(o)) { for (var j = 0; j < o.length; j++) { walk(o[j]); } return; }
        if (!AIRS3.isObject(o)) { return; }
        for (var k in o) { if (Object.prototype.hasOwnProperty.call(o, k)) { counts[k] = (counts[k] || 0) + 1; walk(o[k]); } }
    }
    walk(parsed);
    for (var r = 0; r < AIRS3.READ_KEYS.length; r++) {
        var key = AIRS3.READ_KEYS[r];
        var re = new RegExp('"' + key + '"\\s*:', 'g'), n = 0;
        while (re.exec(raw) !== null) { n++; }
        if (n > (counts[key] || 0)) { return key; }
    }
    return null;
};

/* The JSON-RPC id as sent, kept as JSON text so a number stays a number and a string a string. */
AIRS3.idText = function (id) { return id === undefined ? '' : JSON.stringify(id); };
/* The first of these variables that holds an id Prisma AIRS accepts: never cut; one over 100 characters, or not printable
   ASCII, is skipped and the next source is used (L12). */
AIRS3.firstId = function (names) {
    for (var i = 0; i < names.length; i++) {
        var v = context.getVariable(names[i]);
        v = v === null || v === undefined ? '' : String(v).replace(/^\s+|\s+$/g, '');
        if (v !== '' && v.length <= 100 && /^[\x21-\x7E]+$/.test(v)) { return v; }
    }
    return '';
};

/* ---- paths into a body, for exact write-back --------------------------------------------------------------------- */
AIRS3.getAt = function (o, at) { for (var i = 0; i < at.length; i++) { if (o === null || typeof o !== 'object') { return undefined; } o = o[at[i]]; } return o; };
AIRS3.setAt = function (o, at, v) {
    if (!at || !at.length) { return false; }
    for (var i = 0; i < at.length - 1; i++) { if (o === null || typeof o !== 'object') { return false; } o = o[at[i]]; }
    if (o === null || typeof o !== 'object' || typeof o[at[at.length - 1]] !== 'string') { return false; }
    o[at[at.length - 1]] = v;
    return true;
};
AIRS3.writeCuts = function (body, cuts) {
    for (var i = 0; i < cuts.length; i++) { if (!AIRS3.setAt(body, cuts[i].at, cuts[i].text)) { return null; } }
    return body;
};

/* ---- segments ---------------------------------------------------------------------------------------------------- */
// One piece of text to scan. `at` is its JSON path when the text is one whole string field, so it can be masked;
// synthesized text (tool calls, JSON renderings, decoded payloads) has no path and is never rewritten.
AIRS3.seg = function (out, text, role, at) {
    if (text === null || text === undefined) { return; }
    text = String(text);
    if (text.replace(/\s+/g, '') === '') { return; }
    out.push({ text: text, role: role, at: at || null, maskable: !!at });
};
AIRS3.DATA_KEYS = { data: 1, file_data: 1, b64_json: 1, bytes: 1, image_data: 1, audio_data: 1, blob: 1 };
// A value as JSON text, with every string judged by the bytes rule: binary payloads become a placeholder, encoded text is
// shown decoded. Keys stay, so a key carrying text is scanned too (A11).
AIRS3.jsonText = function (value, mediaType) {
    function fix(v, key, mt) {
        if (typeof v === 'string') {
            if (/^data:/i.test(v) || (Object.prototype.hasOwnProperty.call(AIRS3.DATA_KEYS, key) && v.length >= 256)) {
                var r = AIRS3.bytesRule(v, mt);
                return r.kind === 'skip' ? '<binary, ' + v.length + ' characters>' : r.text;
            }
            return v;
        }
        if (AIRS3.isArray(v)) { var a = []; for (var i = 0; i < v.length; i++) { a.push(fix(v[i], key, mt)); } return a; }
        if (AIRS3.isObject(v)) {
            var o = {}, m = v.mimeType || v.mime_type || v.media_type || mt;
            for (var k in v) { if (Object.prototype.hasOwnProperty.call(v, k)) { AIRS3.put(o, k, fix(v[k], k, m)); } }
            return o;
        }
        return v;
    }
    return typeof value === 'string' ? value : JSON.stringify(fix(value, '', mediaType));
};
// Log probabilities repeat a reply's text token by token, in a form v3 never rewrites. They add nothing to the scan (the
// text is already read), but a body that carries them is never masked: a mask becomes a block.
// A format module reports such a body with `fixed: true`.
AIRS3.nonEmpty = function (v) { return AIRS3.isArray(v) && v.length > 0; };
// "tool <name>: <arguments>", the text of a tool call.
AIRS3.toolCall = function (name, args) {
    return 'tool ' + (name ? String(name) : 'unknown') + ': ' + (typeof args === 'string' ? args : (args === undefined ? '' : AIRS3.jsonText(args)));
};

/* ---- event streams (for a runtime that shows them; this one doesn't: L1) ------------------------------------ */
// Returns [{event, data}] with each event's data lines joined by "\n", or null when an event's data is neither JSON nor
// [DONE] (an unreadable stream). One leading byte order mark is removed.
AIRS3.sseEvents = function (text) {
    var s = String(text);
    if (s.charCodeAt(0) === 0xFEFF) { s = s.slice(1); }
    var lines = s.split(/\r\n|\r|\n/), events = [], cur = null, i, line, colon, field, val;
    function dispatch() {
        if (cur && cur.data !== null) {
            if (cur.data !== '[DONE]' && AIRS3.parse(cur.data) === undefined) { events = null; }
            if (events) { events.push(cur); }
        }
        cur = null;
    }
    for (i = 0; i < lines.length && events; i++) {
        line = lines[i];
        if (line === '') { dispatch(); continue; }
        if (line.charAt(0) === ':') { continue; }
        colon = line.indexOf(':');
        field = colon < 0 ? line : line.slice(0, colon);
        val = colon < 0 ? '' : line.slice(colon + 1);
        if (val.charAt(0) === ' ') { val = val.slice(1); }
        cur = cur || { event: '', data: null };
        if (field === 'data') { cur.data = cur.data === null ? val : cur.data + '\n' + val; }
        else if (field === 'event') { cur.event = val; }
    }
    if (events) { dispatch(); }
    return events;
};
// One event-stream event, as text.
AIRS3.sse = function (event, obj) { return (event ? 'event: ' + event + '\n' : '') + 'data: ' + (typeof obj === 'string' ? obj : JSON.stringify(obj)) + '\n\n'; };

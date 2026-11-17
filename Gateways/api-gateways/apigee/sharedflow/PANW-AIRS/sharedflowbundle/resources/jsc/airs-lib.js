/*
 * airs-lib.js — shared helpers for the PANW-AIRS SharedFlow.
 *
 * Included (via <IncludeURL>jsc://airs-lib.js</IncludeURL>) into every JS
 * policy in this bundle, so its functions are in scope before each script's
 * own resource runs. Pure ES5 (Apigee's Rhino engine) — no const/let, arrow
 * functions, template literals, or Array.prototype extras beyond ES5.
 *
 * Everything here is deliberately defensive: a gateway security control must
 * never throw on a malformed body. Parsers return null/`''` on failure and the
 * callers treat "couldn't parse" as "nothing to scan" (fail toward the
 * configured fail-open/closed posture), never as an unhandled 500.
 */

/* ------------------------------------------------------------------ *
 * JSON
 * ------------------------------------------------------------------ */

// Parse a JSON string, returning null (never throwing) on any failure.
function airsParse(str) {
    if (str === null || str === undefined || str === '') { return null; }
    try { return JSON.parse(str); } catch (e) { return null; }
}

// Compact JSON string of an object; '' on failure.
function airsStringify(obj) {
    try { return JSON.stringify(obj); } catch (e) { return ''; }
}

/* ------------------------------------------------------------------ *
 * Value collection (the el-cacheo "clean values" extractor)
 *
 * Recursively walk any JSON value and push its scalar *values* (strings,
 * numbers, booleans) into acc — dropping keys, braces and punctuation. Feeding
 * AIRS these natural values (not serialized JSON) is what keeps the text
 * detectors accurate on tool-call arguments and results; a JSON wrapper reads
 * as "code" and false-positives benign calls. See ARCHITECTURE.md §Tool calls.
 * ------------------------------------------------------------------ */
function airsCollect(node, acc) {
    if (node === null || node === undefined) { return; }
    var t = typeof node;
    if (t === 'string') { if (node.length) { acc.push(node); } return; }
    if (t === 'number' || t === 'boolean') { acc.push(String(node)); return; }
    if (Object.prototype.toString.call(node) === '[object Array]') {
        for (var i = 0; i < node.length; i++) { airsCollect(node[i], acc); }
        return;
    }
    if (t === 'object') {
        for (var k in node) {
            if (Object.prototype.hasOwnProperty.call(node, k)) { airsCollect(node[k], acc); }
        }
    }
}

// Convenience: collect a value's scalars and join them with a space.
function airsCollectJoined(node) {
    var acc = [];
    airsCollect(node, acc);
    return acc.join(' ');
}

/* ------------------------------------------------------------------ *
 * Headers
 * ------------------------------------------------------------------ */

// First value of a request header, or '' if absent. Apigee exposes the first
// header value at request.header.<name>; case-insensitive on the name.
function airsHeader(name) {
    var v = context.getVariable('request.header.' + name);
    return (v === null || v === undefined) ? '' : String(v);
}

/* ------------------------------------------------------------------ *
 * Claude Code scaffolding
 *
 * Claude Code injects <system-reminder>…</system-reminder> blocks into user
 * turns (harness context, not user intent). We strip them from USER text ONLY
 * before scanning so AIRS judges the actual user input — never from tool
 * results or model output, which must reach the scanner byte-for-byte.
 * Non-greedy, multiline, case-insensitive.
 * ------------------------------------------------------------------ */
var AIRS_SYSREMINDER_RE = /<system-reminder>[\s\S]*?<\/system-reminder>/gi;

function airsStripReminders(text) {
    if (!text) { return ''; }
    try { return String(text).replace(AIRS_SYSREMINDER_RE, '').replace(/^\s+|\s+$/g, ''); }
    catch (e) { return String(text); }
}

/* ------------------------------------------------------------------ *
 * SSE / streaming helpers
 * ------------------------------------------------------------------ */

// Split a raw body into lines on CR/LF, dropping empties.
function airsSplitLines(raw) {
    if (!raw) { return []; }
    return String(raw).split(/[\r\n]+/);
}

// Strip a leading "data:" SSE prefix (with optional space) and trim.
function airsStripDataPrefix(line) {
    var t = String(line);
    t = t.replace(/^\s+|\s+$/g, '');
    if (t.indexOf('data:') === 0) { t = t.substring(5).replace(/^\s+|\s+$/g, ''); }
    return t;
}

/* ------------------------------------------------------------------ *
 * Misc
 * ------------------------------------------------------------------ */

function airsIsBlank(s) { return s === null || s === undefined || String(s) === ''; }

// AIRS returns per-detector booleans as real JSON booleans; ExtractVariables
// surfaces them as the strings "true"/"false". Normalise either to a JS bool.
function airsTruthy(v) { return v === true || v === 'true'; }

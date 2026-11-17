'use strict';
/*
 * A small XML reader for Apigee bundles: elements, attributes, text, comments, CDATA, the XML declaration, and the
 * five named entities plus numeric ones. Enough for policy and flow files; anything it doesn't understand throws,
 * so a bundle the harness can't read never runs half-read.
 */

function decode(s) {
    return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, function (m, e) {
        if (e === 'amp') { return '&'; }
        if (e === 'lt') { return '<'; }
        if (e === 'gt') { return '>'; }
        if (e === 'quot') { return '"'; }
        if (e === 'apos') { return "'"; }
        var cp = e.charAt(1) === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return String.fromCodePoint(cp);
    });
}

function parse(src) {
    var i = 0, n = src.length;
    function fail(msg) { throw new Error('xml: ' + msg + ' at offset ' + i); }
    function skipMisc() {
        for (;;) {
            while (i < n && /\s/.test(src[i])) { i++; }
            if (src.startsWith('<?', i)) { var e = src.indexOf('?>', i); if (e < 0) { fail('open declaration'); } i = e + 2; continue; }
            if (src.startsWith('<!--', i)) { var c = src.indexOf('-->', i); if (c < 0) { fail('open comment'); } i = c + 3; continue; }
            if (src.startsWith('<!DOCTYPE', i)) { fail('DOCTYPE not supported'); }
            return;
        }
    }
    function element() {
        if (src[i] !== '<') { fail('expected <'); }
        i++;
        var m = /^[A-Za-z_][\w.\-:]*/.exec(src.slice(i, i + 200));
        if (!m) { fail('bad element name'); }
        var node = { name: m[0], attrs: {}, children: [], text: '' };
        i += m[0].length;
        for (;;) {
            while (i < n && /\s/.test(src[i])) { i++; }
            if (src.startsWith('/>', i)) { i += 2; return node; }
            if (src[i] === '>') { i++; break; }
            var a = /^([A-Za-z_][\w.\-:]*)\s*=\s*("([^"]*)"|'([^']*)')/.exec(src.slice(i, i + 4000));
            if (!a) { fail('bad attribute in <' + node.name + '>'); }
            node.attrs[a[1]] = decode(a[3] !== undefined ? a[3] : a[4]);
            i += a[0].length;
        }
        for (;;) {
            if (i >= n) { fail('unclosed <' + node.name + '>'); }
            if (src.startsWith('<!--', i)) { var c2 = src.indexOf('-->', i); if (c2 < 0) { fail('open comment'); } i = c2 + 3; continue; }
            if (src.startsWith('<![CDATA[', i)) { var d = src.indexOf(']]>', i); if (d < 0) { fail('open CDATA'); } node.text += src.slice(i + 9, d); i = d + 3; continue; }
            if (src.startsWith('</', i)) {
                var close = /^<\/([A-Za-z_][\w.\-:]*)\s*>/.exec(src.slice(i, i + 200));
                if (!close || close[1] !== node.name) { fail('mismatched close for <' + node.name + '>'); }
                i += close[0].length;
                return node;
            }
            if (src[i] === '<') { node.children.push(element()); continue; }
            var t = src.indexOf('<', i);
            if (t < 0) { fail('text runs to the end'); }
            node.text += decode(src.slice(i, t));
            i = t;
        }
    }
    skipMisc();
    var root = element();
    skipMisc();
    if (i < n) { fail('content after the root element'); }
    return root;
}

/* Helpers over the tree. */
function kids(node, name) { return node ? node.children.filter(function (c) { return c.name === name; }) : []; }
function kid(node, name) { return kids(node, name)[0] || null; }
function text(node) { return node ? node.text.trim() : null; }
function path(node, names) { var cur = node; for (var k = 0; k < names.length && cur; k++) { cur = kid(cur, names[k]); } return cur; }

module.exports = { parse: parse, kids: kids, kid: kid, text: text, path: path, decode: decode };

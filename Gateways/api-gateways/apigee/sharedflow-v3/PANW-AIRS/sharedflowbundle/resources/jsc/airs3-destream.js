/*
 * airs3-destream.js: turns streaming off on the way to the model (L1: the flow can't see an event-stream reply).
 * A body flag changes anywhere on the request leg. A path changes only from the TargetEndpoint's request flow, where
 * target.url is set; from the ProxyEndpoint's, setting it has no effect (L1), so v3 refuses with a message saying where
 * the FlowCallout must go.
 */
(function () {
    var format = AIRS3.get('format'), mod = AIRS3_FMT[format];
    var path = AIRS3.str('proxy.pathsuffix'), query = AIRS3.str('request.querystring');
    var body = AIRS3.parse(AIRS3.str('request.content'));
    var r = mod && mod.destream ? mod.destream(body, path, query) : null;
    if (!r) { AIRS3.done('Destream'); return; }                                  // nothing to turn off
    if (r.path !== path || r.query !== query) {
        var tu = AIRS3.str('target.url');
        if (tu === '') {
            var where = 'Prisma AIRS could not turn streaming off for this call: the request leg must run in the TargetEndpoint PreFlow. See the README.';
            if (AIRS3.get('doneRespond') === 'true') {
                // After JS-Airs3Respond (monitor mode's pass, airs3.lateStream): its outcome stands, this is noted, and the call goes on.
                var ln = AIRS3.get('logNote'); AIRS3.set('logNote', (ln ? ln + '; ' : '') + 'monitor mode, not enforced: ' + where);
            } else {
                AIRS3.refuse('config', where);
                AIRS3.set('outcome', 'refused');
            }
            AIRS3.done('Destream');
            return;
        }
        // target.url as a proxy step may have set it: the path a step named is edited in place, its query kept.
        var q = tu.indexOf('?'), base = q >= 0 ? tu.slice(0, q) : tu, own = q >= 0 ? tu.slice(q + 1) : '';
        var url;
        if (/:stream(GenerateContent|RawPredict)$/.test(base)) { url = base.replace(/:streamGenerateContent$/, ':generateContent').replace(/:streamRawPredict$/, ':rawPredict'); }
        else if (path !== '' && base.indexOf(path) >= 0) { url = base.replace(path, r.path); }
        else if (AIRS3.str('target.copy.pathsuffix') !== 'false') { url = base.replace(/\/$/, '') + r.path; }   // Apigee would add the client's path
        else { url = base; }                                                 // the proxy's own complete URL, with no stream method in it
        // The query: target.url's own, then the client's (unless the proxy turned that off), never alt (the stream switch).
        var noAlt = function (qs) { var out = [], ps = String(qs || '').split('&'); for (var a = 0; a < ps.length; a++) { if (ps[a] && !/^alt(=|$)/.test(ps[a])) { out.push(ps[a]); } } return out; };
        // Names are kept with a prefix, so none can meet an Object.prototype member such as constructor.
        var parts = noAlt(own), names = {};
        for (var i = 0; i < parts.length; i++) { names['=' + parts[i].split('=')[0]] = true; }
        if (AIRS3.str('target.copy.queryparams') !== 'false') {
            var cl = noAlt(r.query);
            for (var j = 0; j < cl.length; j++) { if (!names['=' + cl[j].split('=')[0]]) { parts.push(cl[j]); } }
        }
        context.setVariable('target.copy.pathsuffix', false);
        context.setVariable('target.copy.queryparams', false);
        context.setVariable('target.url', url + (parts.length ? '?' + parts.join('&') : ''));
    }
    if (r.body !== undefined && r.body !== null) { context.setVariable('request.content', JSON.stringify(r.body)); }
    AIRS3.set('destreamed', r.kind);
    AIRS3.done('Destream');
})();

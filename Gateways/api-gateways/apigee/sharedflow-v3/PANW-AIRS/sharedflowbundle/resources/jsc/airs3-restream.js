/*
 * airs3-restream.js: the scanned reply goes back as one burst of the client's own stream format, because the request
 * leg turned streaming off (airs3.destreamed holds the kind). The client gets the whole reply at once.
 */
(function () {
    var mod = AIRS3_FMT[AIRS3.get('format')];
    var raw = AIRS3.str('response.content');
    var reply = AIRS3.parse(raw);
    var r = mod && mod.restream ? mod.restream(reply, AIRS3.get('destreamed')) : null;
    if (r) {
        // A later run on this leg (a second FlowCallout, or never twice after a run that didn't enforce a verdict) reads the
        // reply as this run did, not v3's rendering of it: the JSON is kept, with a SHA-256 of what this step sends (L18), so
        // JS-Airs3Init puts it back only if nothing has changed the reply since.
        var h = crypto.getSHA256(); h.update(r.body);
        AIRS3.set('plainReply', raw);
        AIRS3.set('plainType', AIRS3.str('response.header.Content-Type'));
        AIRS3.set('restreamHash', h.digest());
        context.setVariable('response.content', r.body);
        context.setVariable('response.header.Content-Type', r.type);
        AIRS3.done('Restream');
    }
})();

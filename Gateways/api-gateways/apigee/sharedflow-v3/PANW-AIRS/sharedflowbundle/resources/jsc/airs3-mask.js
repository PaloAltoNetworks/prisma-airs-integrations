/*
 * airs3-mask.js: exact write-back (A22, A23). The masked copy has the scanned text's length, with every "\n"
 * separator in place; each segment gets its own stretch, written where the segment came from. Anything else blocks.
 */
(function () {
    var leg = AIRS3.get('leg'), format = AIRS3.get('format'), mod = AIRS3_FMT[format];
    var seg = AIRS3.parse(AIRS3.get('segments')) || { map: [] }, masked = AIRS3.get('maskedText');
    var ok = !!(mod && mod.writeBack && seg.map && seg.map.length);
    var cuts = [];
    for (var i = 0; ok && i < seg.map.length; i++) {
        var m = seg.map[i];
        var after = masked.charAt(m.start + m.len);
        if (i < seg.map.length - 1 && after !== '\n') { ok = false; break; }
        var stretch = masked.substr(m.start, m.len);
        if (!m.maskable) { if (stretch !== m.orig) { ok = false; break; } continue; }   // synthesized text: only if untouched
        cuts.push({ at: m.at, text: stretch });
    }
    var name = leg === 'request' ? 'request.content' : 'response.content';
    var body = ok ? AIRS3.parse(AIRS3.str(name)) : undefined;
    var out = ok ? mod.writeBack(body, cuts) : null;
    if (out === null || out === undefined) {
        AIRS3.set('outcome', 'block');
        AIRS3.set('logNote', 'the masked text could not be written back exactly');
    } else {
        context.setVariable(name, JSON.stringify(out));
        AIRS3.set('masked', 'true');
        if (leg === 'request') { AIRS3.set('promptContext', masked); }          // the prompt as forwarded
    }
    AIRS3.done('Mask');
})();

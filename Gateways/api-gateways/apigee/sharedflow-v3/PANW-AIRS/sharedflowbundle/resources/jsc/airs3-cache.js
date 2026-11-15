/*
 * airs3-cache.js: the verdict cache (phase 3; MuleSoft's cache.rs), when verdictCacheTtlS is above 0 and applyDlpMasking is
 * false (settings.rs: never with masking). Allow verdicts only: a cached block would freeze a false positive.
 *   op=keys, after Read: each scan's key, 'airs3-verdict-' + SHA-256 (L18) of length-prefixed fields: 'airs3-vc-1', the API
 *   key, the endpoint, the scan's ai_profile, the leg, maxScanChars, truncationFailClosed and the scan's contents. Ids and
 *   metadata never change a verdict, so they stay out, as in MuleSoft; the API key is hashed, never stored. It ends by
 *   setting airs3.doneCacheKeys: the lookups, the hits and the writes run only then, so a leg whose keys were not all made
 *   (a step cut by its time limit) never reads or writes an entry under a key it didn't finish (AM-Airs3Reset's empty one).
 *   op=hits, after LC-Airs3Verdict and LC-Airs3Verdict<k> read each slot's entry: airs3.vcHit<k> for each slot whose own
 *   lookup hit with a scan id. A slot with a hit makes no call.
 *   op=record, after the verdict: each slot's clean allow (a scan id, no masked copy, no error) is written with its scan id
 *   by PC-Airs3Verdict<k>. v3 writes the mask of an allow that carries a masked copy, so such an allow is never written; a
 *   block, a failure and an answer from the cache are not either.
 * Inside a SharedFlow the cache is shared by every proxy that calls it (L19): the key keeps tenants and profiles apart.
 */
(function () {
    var op = String(properties.op);
    if (op === 'keys') {
        var n = parseInt(AIRS3.get('scanCount'), 10) || 1;
        var fixed = ['airs3-vc-1', AIRS3.str('private.airs3_token'), AIRS3.get('endpoint')];
        for (var k = 1; k <= n && k <= AIRS3.SLOTS; k++) {
            var body = AIRS3.parse(AIRS3.get(k === 1 ? 'scanBody' : 'scanBody' + k));
            if (!AIRS3.isObject(body)) { continue; }
            var parts = fixed.concat([JSON.stringify(body.ai_profile), AIRS3.get('leg'), AIRS3.get('maxScanChars'), AIRS3.get('truncFailClosed'), JSON.stringify(body.contents)]);
            var s = '';
            for (var i = 0; i < parts.length; i++) { var p = parts[i] === undefined || parts[i] === null ? '' : String(parts[i]); s += p.length + ':' + p; }
            var h = crypto.getSHA256();
            h.update(s);
            AIRS3.set('vcKey' + k, 'airs3-verdict-' + h.digest());
        }
        AIRS3.done('CacheKeys');
        return;
    }
    if (op === 'hits') {
        var m = parseInt(AIRS3.get('scanCount'), 10) || 1;
        for (var q = 1; q <= m && q <= AIRS3.SLOTS; q++) {
            var hit = AIRS3.str('lookupcache.LC-Airs3Verdict' + (q > 1 ? String(q) : '') + '.cachehit') === 'true';
            if (hit && AIRS3.get('vcKey' + q) !== '' && AIRS3.get('vcScan' + q) !== '') { AIRS3.set('vcHit' + q, 'true'); }
        }
        return;
    }
    var ran = parseInt(AIRS3.get('scansRan'), 10) || 1;
    for (var j = 1; j <= ran && j <= AIRS3.SLOTS; j++) {
        if (AIRS3.cacheHit(j) || AIRS3.get('vcKey' + j) === '') { continue; }
        var a = AIRS3.judge(j), b = a.body;
        if (a.outcome === 'allow' && AIRS3.isObject(b) && b.action === 'allow' && typeof b.scan_id === 'string' && b.scan_id !== '' && !AIRS3.hasMasked(b)) {
            AIRS3.set('vcPut' + j, b.scan_id);
            AIRS3.set('vcWrite' + j, 'true');
        }
    }
})();

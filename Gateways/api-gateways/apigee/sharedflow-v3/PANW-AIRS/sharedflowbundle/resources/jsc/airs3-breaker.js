/*
 * airs3-breaker.js: the circuit breaker (phase 3; MuleSoft's breaker.rs), when breakerFailures is above 0. Its state, JSON
 * {"failures": n, "openUntil": ms since the epoch, 0 when closed}, sits in the environment's cache (LC-Airs3Breaker,
 * PC-Airs3Breaker) under a key from the endpoint and the API key, never the key itself.
 *   op=check, before the leg's first call: while it is open, Prisma AIRS isn't called and the leg is a scanner failure,
 *   which failOpen decides; once the cooldown is over, this leg's calls are the trial.
 *   op=record, after the verdict: each call the leg made, in slot order, a retry's first try included. A failure counts, and
 *   the threshold, or any failure on trial, opens it for the cooldown; an answer resets the count. Once it opens, the rest
 *   of the leg's calls are not counted (MuleSoft wouldn't have made them).
 * It is read once per leg (MuleSoft reads it before every call), so the leg that meets an outage still makes its calls, and
 * legs running at once may count from the same state, so its counts are approximate. A 400 or 413 (Prisma AIRS refusing the
 * content) resets the count, where MuleSoft counts it as a failure: one client's content would otherwise open the breaker for
 * every proxy on the tenant.
 */
(function () {
    var op = String(properties.op), now = new Date().getTime(), raw = AIRS3.get('breakerState');
    var st = AIRS3.parse(raw);
    if (!AIRS3.isObject(st) || typeof st.failures !== 'number' || typeof st.openUntil !== 'number') { st = { failures: 0, openUntil: 0 }; }
    if (op === 'check') {
        // The cache is read before the breaker (MuleSoft's scan.rs): a leg whose every scan is a hit makes no call.
        var all = AIRS3.get('vcOn') === 'true', sc = parseInt(AIRS3.get('scanCount'), 10) || 1;
        for (var c = 1; c <= sc && all; c++) { if (!AIRS3.cacheHit(c)) { all = false; } }
        if (all) { return; }
        if (st.openUntil > 0 && now < st.openUntil) {
            var note = 'the circuit breaker is open: Prisma AIRS was not called';
            // A pass as any scanner failure under failOpen is: streaming turned off and back on (MuleSoft: an open breaker is a scan error).
            if (AIRS3.get('failOpen') === 'true') { AIRS3.set('route', 'pass'); AIRS3.set('outcome', 'allow'); AIRS3.set('logNote', 'failed open: ' + note); AIRS3.streamNeeds(); }
            else {
                AIRS3.set('logNote', note);
                AIRS3.refuse('failure', 'Prisma AIRS could not scan this ' + (AIRS3.get('leg') === 'request' ? 'request, so it was not forwarded.' : 'response, so it was withheld.'));
            }
        } else if (st.openUntil > 0) { AIRS3.set('breakerHalf', 'true'); }
        return;
    }
    var limit = parseInt(AIRS3.get('breakerFailures'), 10), cool = parseInt(AIRS3.get('breakerCooldownS'), 10) * 1000;
    var trial = AIRS3.get('breakerHalf') === 'true', f = st.failures, until = st.openUntil, opened = false;
    var n = parseInt(AIRS3.get('scansRan'), 10) || 1, before = JSON.stringify({ failures: f, openUntil: until });
    function failed() { f += 1; if (trial || f >= limit) { until = now + cool; opened = true; } }
    for (var k = 1; k <= n && !opened; k++) {
        if (AIRS3.cacheHit(k)) { continue; }                                    // no call was made
        if (AIRS3.get('retry' + k) === 'true') { failed(); if (opened) { break; } }
        if (AIRS3.judge(k).outcome === 'failure') { failed(); } else { f = 0; until = 0; trial = false; }
    }
    var after = JSON.stringify({ failures: f, openUntil: until });
    if (after === before) { return; }
    AIRS3.set('breakerNew', after);
    AIRS3.set('breakerTtl', until > 0 ? Math.round(cool / 1000) + 600 : 600);       // an open state outlives its cooldown, for the trial
    AIRS3.set('breakerWrite', 'true');
    if (opened) { var rn = AIRS3.get('logNote'); AIRS3.set('logNote', (rn ? rn + '; ' : '') + 'the circuit breaker opened, after ' + f + ' failures in a row'); }
})();

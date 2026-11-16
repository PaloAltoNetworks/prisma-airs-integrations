/*
 * airs3-logline.js: one line per leg for MessageLogging: ids, outcome, kind, sizes and timings.
 * Never the scanned text, a header value other than the transaction id, the session id, the profile or a credential.
 */
(function () {
    var t0 = parseInt(AIRS3.get('t0'), 10);
    // Init didn't finish: name the leg by whether a target answer exists, as Respond does.
    var leg = AIRS3.get('doneInit') === 'true' ? AIRS3.get('leg') : (AIRS3.str('response.status.code') !== '' ? 'response' : 'request');
    var line = {
        v: 'panw-airs-v3', leg: leg, mode: AIRS3.get('mode') || 'enforce', auth: AIRS3.get('authMode'), hook: AIRS3.get('hook') === 'true', format: AIRS3.get('format'), route: AIRS3.get('route'), stream: AIRS3.get('stream'),
        outcome: AIRS3.get('outcome') || (AIRS3.get('refuse') !== 'none' ? AIRS3.get('refuse') : ''), kind: AIRS3.get('blockKind'),
        detections: AIRS3.get('detections'), scan_id: AIRS3.get('scanId'), airs_status: AIRS3.get('aiStatus'), transaction_id: AIRS3.get('txnId'),
        chars: AIRS3.get('scanChars'), scans: AIRS3.get('scansRan'), retries: parseInt(AIRS3.get('retried'), 10) || 0, cached: parseInt(AIRS3.get('cachedScans'), 10) || 0, masked: AIRS3.get('masked') === 'true', destreamed: AIRS3.get('destreamed'),
        // A refusal before any scan has no note of its own: its reason is the client's message, which never holds a value.
        ms: isNaN(t0) ? '' : (new Date().getTime() - t0),
        note: AIRS3.get('logNote') || (AIRS3.get('refuse') !== 'none' && AIRS3.get('refuse') !== '' ? AIRS3.get('refuseMsg') : '')
    };
    AIRS3.set('logLine', JSON.stringify(line));
    // Never twice (phase 3): a hook or a FlowCallout enforced a verdict on all of this leg (airs3-verdict.js sets judged); the
    // other kind passes it (airs3-init.js). A run that failed open, let a gap pass or only monitored marks nothing.
    if (AIRS3.get('doneInit') === 'true' && AIRS3.get('skipLeg') !== 'true' && AIRS3.get('judged') === 'true') { AIRS3.set(leg === 'response' ? 'scannedResponse' : 'scannedRequest', AIRS3.get('hook') === 'true' ? 'hook' : 'callout'); }
    AIRS3.done('Log');
})();

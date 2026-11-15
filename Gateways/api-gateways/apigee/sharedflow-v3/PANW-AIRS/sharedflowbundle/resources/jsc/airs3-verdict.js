/*
 * airs3-verdict.js: Prisma AIRS's answer, read in JavaScript (A14 to A16).
 *   - Only HTTP 200 with a JSON object whose action is exactly allow or block is a verdict.
 *   - An allow that reports an error or a time-out is a scanner failure (A15).
 *   - 400 or 413: Prisma AIRS refused the content, so it counts as content that can't be inspected (a design choice).
 *   - Any other status, or no status at all (a time-out or a refused connection: L5 and L10), is a scanner failure.
 * Failures follow failOpen; content that can't be inspected follows onScanError. A mask is applied only where it can be
 * written back exactly; anywhere else it becomes a block. The rules are AIRS3.decide's (airs3-lib.js), which the early stop
 * after each scan slot uses too, so the two never judge an answer differently.
 * Several scans (MCP only: a batch's members, a tools/list answer with more than its tools): the slots that ran are judged
 * in order and the first that would refuse decides, as MuleSoft's loop stops at the first refusal. When all pass, the one
 * reported is the first that passed only by failOpen or onScanError, else the last. A slot that should have run and did
 * not, with no refusal before it, is a failure. One scan is slot 1, judged as it always was.
 */
(function () {
    var leg = AIRS3.get('leg'), monitor = AIRS3.get('mode') === 'monitor';
    var count = parseInt(AIRS3.get('scanCount'), 10) || 1, pick = 1, skipped = false, opened = 0;
    if (count > 1) {
        for (var k = 1; k <= count; k++) {
            pick = k;
            if (k > 1 && AIRS3.get('slotRan' + k) !== 'true' && !AIRS3.cacheHit(k)) { skipped = true; break; }   // set by AM-Airs3ClearScan<k>, this leg only; a cache hit makes no call
            var dk = AIRS3.decide(AIRS3.judge(k));                                               // as JS-Airs3Slot<k> judged it
            if (!dk.passes) { break; }
            if (!opened && dk.via) { opened = k; }
            if (k === count && opened) { pick = opened; }
        }
    }
    var d = AIRS3.decide(skipped ? { status: null, body: undefined, outcome: 'failure', note: 'a scan step did not run' } : AIRS3.judge(pick));
    var outcome = d.outcome, note = d.note;
    AIRS3.set('aiStatus', d.status === null ? 'none' : d.status);
    var ranSlots = 1;
    if (count > 1) {
        ranSlots = skipped ? pick - 1 : (monitor || (opened && pick === opened) ? count : pick);
        var sizes = AIRS3.get('slotChars').split(','), ran = 0;          // the characters of the slots that ran, for the log
        for (var c = 0; c < ranSlots && c < sizes.length; c++) { ran += parseInt(sizes[c], 10) || 0; }
        AIRS3.set('scanChars', ran);
    }
    AIRS3.set('scansRan', ranSlots);
    var hits = 0;
    for (var h = 1; h <= ranSlots; h++) { if (AIRS3.cacheHit(h)) { hits++; } }
    AIRS3.set('cachedScans', hits);
    if (AIRS3.isObject(d.body)) { AIRS3.set('category', d.category); AIRS3.set('scanId', d.scanId); }
    AIRS3.set('detections', d.dets.join(','));
    if (outcome === 'mask') { AIRS3.set('maskedText', d.maskedText); }

    var passes = outcome === 'allow' || outcome === 'mask';
    if (leg === 'request') { AIRS3.set('promptVerdict', /^failed open/.test(note) ? 'failed-open' : outcome); }   // read by the reply leg
    // Monitor mode lets every leg go on, so streaming is turned off and back on as in enforce mode, and the reply is read.
    if (passes || monitor) { AIRS3.streamNeeds(); } else { AIRS3.set('needDestream', 'false'); AIRS3.set('needRestream', 'false'); }
    // Never twice (phase 3): the leg counts as scanned only when this run enforced a verdict on all of it. A run that failed
    // open, let a gap pass or only monitored leaves the leg to a later run, which scans it with its own settings (airs3-logline.js).
    AIRS3.set('judged', !monitor && passes && d.via !== 'failOpen' && d.via !== 'onScanError' && AIRS3.get('readGap') === '' ? 'true' : 'false');
    // Monitor mode: a decision that would change what the client gets is named for what it would have been (MuleSoft's
    // decision.rs), so no mask is written, and JS-Airs3Respond logs it and lets the leg pass. An allow whose masked copy
    // v3 can't write back (MCP text, several parts) is a mask not applied; on an event stream, a monitored block.
    if (monitor && outcome !== 'allow') {
        var act = AIRS3.isObject(d.body) ? d.body.action : '';
        if (outcome === 'mask') { outcome = act === 'block' ? 'monitored_block' : 'mask_not_applied'; }
        else if (outcome === 'block') { outcome = act === 'allow' && AIRS3.get('stream') !== 'event-stream-reply' ? 'mask_not_applied' : 'monitored_block'; }
        else if (outcome === 'failure') { outcome = 'failed_open'; }
        else if (outcome === 'refused') { outcome = 'gap_unenforced'; }
    }
    // Monitor mode, an MCP leg whose part Read let pass unscanned (enforce mode would have refused the leg): the rest scanned clean.
    if (monitor && outcome === 'allow' && AIRS3.get('readGap') === 'monitor') { outcome = 'gap_unenforced'; }
    AIRS3.set('outcome', outcome);
    // The verdict's reason, after anything Read logged about a part it cut or let pass unscanned.
    if (note) { var rn = AIRS3.get('readNote'); AIRS3.set('logNote', rn ? rn + '; ' + note : note); }
    AIRS3.done('Verdict');
})();

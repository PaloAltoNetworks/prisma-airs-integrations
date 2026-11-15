/*
 * airs3-retry.js: runs after a scan slot's call when scanRetries is 1. One more call when the first got no answer, HTTP 429
 * or a 5xx (MuleSoft's breaker.rs: a time-out, a transport error, 429 and 5xx); never after an answer Prisma AIRS gave on
 * purpose (any other 4xx), one v3 can't read, or a verdict, failed detection service included. The same ServiceCallout
 * then runs again, after its response message is cleared again, and its failed flag resets (L15), so the second answer is
 * the one judged. The slot number comes from the step's properties.
 */
(function () {
    var k = parseInt(properties.slot, 10);
    if (!(k >= 1 && k <= AIRS3.SLOTS)) { return; }
    var status = AIRS3.judge(k).status;
    if (status === null || status === 429 || status >= 500) {
        AIRS3.set('retry' + k, 'true');
        AIRS3.set('retried', (parseInt(AIRS3.get('retried'), 10) || 0) + 1);
    }
})();

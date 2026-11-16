/*
 * airs3-slot.js: runs after a scan slot's ServiceCallout when a leg makes more than one scan (MCP only: a batch's members,
 * and a tools/list answer with more than its tools). Once an answer would refuse the leg, the slots after it don't run, as
 * MuleSoft's loop stops at the first refusal; JS-Airs3Verdict then judges the slots that ran, in order. The slot number
 * comes from the step's properties. If this step doesn't finish, the next slots run anyway: an extra scan, never a missed one.
 */
(function () {
    var k = parseInt(properties.slot, 10);
    if (!(k >= 1 && k <= AIRS3.SLOTS)) { return; }
    if (!AIRS3.slotPasses(k)) { AIRS3.set('slotStop', 'true'); }
})();

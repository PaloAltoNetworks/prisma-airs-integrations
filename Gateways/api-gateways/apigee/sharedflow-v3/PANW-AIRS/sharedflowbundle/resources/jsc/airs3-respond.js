/*
 * airs3-respond.js: every refusal, in the client's own format:
 *   - LLM clients: V2's style, an HTTP 200 reply in the client's format that says what happened, with the scan id;
 *     blockStatus can force a status code, except for a streaming client. A streaming client gets its own stream
 *     format (A30).
 *   - MCP: a JSON-RPC error with the request id as sent: -32001 for a block or content that can't be inspected,
 *     -32003 for a scanner failure or a configuration problem (A29). An MCP GET for an event stream gets 405.
 * Kinds: block, refused (content that can't be inspected), failure (Prisma AIRS couldn't scan), config.
 */
(function () {
    var leg = AIRS3.get('leg'), format = AIRS3.get('format'), route = AIRS3.get('route'), outcome = AIRS3.get('outcome');
    // Init didn't finish, so airs3.leg may be the other leg's: a target answer means this is the reply leg.
    if (AIRS3.get('doneInit') !== 'true') { leg = AIRS3.str('response.status.code') !== '' ? 'response' : 'request'; }
    var req = leg === 'request';
    var MSG = {
        block: req ? 'Request blocked by Prisma AIRS security policy.' : 'Response blocked by Prisma AIRS security policy.',
        refused: req ? 'Prisma AIRS could not inspect this request, so it was not forwarded.' : 'Prisma AIRS could not inspect this response, so it was withheld.',
        failure: req ? 'Prisma AIRS could not scan this request, so it was not forwarded.' : 'Prisma AIRS could not scan this response, so it was withheld.'
    };
    var kind, message;
    var refuse = AIRS3.get('refuse');
    // Monitor mode names a verdict's outcome for what it would have been (airs3-verdict.js), which this step doesn't run
    // for; if it runs anyway (a de-stream step that didn't finish), the kind follows that name.
    var MONITORED = { monitored_block: 'block', mask_not_applied: 'block', failed_open: 'failure', gap_unenforced: 'refused' };
    if (MONITORED[outcome]) { kind = MONITORED[outcome]; message = MSG[kind]; }
    else if (route === 'mcp405') { kind = 'refused'; message = 'This MCP endpoint does not stream replies through Prisma AIRS: send each request with POST.'; }
    else if (AIRS3.get('doneInit') !== 'true') { kind = 'failure'; message = MSG.failure; }
    else if (refuse === 'config') { kind = 'config'; message = AIRS3.get('refuseMsg'); }
    else if (refuse === 'refused') { kind = 'refused'; message = AIRS3.get('refuseMsg') || MSG.refused; }
    else if (AIRS3.get('doneDetect') !== 'true') { kind = 'failure'; message = MSG.failure; }
    else if (route === 'scan' && (AIRS3.get('doneRead') !== 'true' || AIRS3.get('doneVerdict') !== 'true')) { kind = 'failure'; message = MSG.failure; }
    else if (outcome === 'block' || (outcome === 'mask' && AIRS3.get('doneMask') !== 'true')) { kind = 'block'; message = MSG.block; }
    else if (outcome === 'refused') { kind = 'refused'; message = MSG.refused; }
    else { kind = 'failure'; message = MSG.failure; }

    // Name what was found, with V2's wording (airsDescriptions may override it), then the scan id.
    if (kind === 'block') {
        var D = { url_cats: 'Malicious or inappropriate URLs detected', dlp: 'Sensitive data (PII, credentials, secrets) detected',
                  injection: 'Prompt injection or jailbreak attempt detected', toxic_content: 'Toxic, hateful, or inappropriate content detected',
                  malicious_code: 'Malicious code or command injection detected', agent: 'AI agent manipulation attempt detected',
                  topic_violation: 'Content violates topic policies', db_security: 'Database security violation detected',
                  ungrounded: 'Ungrounded or hallucinated content detected' };
        var custom = AIRS3.parse(AIRS3.get('descriptions'));
        if (AIRS3.isObject(custom)) { for (var ck in custom) { if (typeof custom[ck] === 'string') { D[ck] = custom[ck]; } } }
        var seen = {}, names = [], dets = AIRS3.get('detections') ? AIRS3.get('detections').split(',') : [];
        for (var i = 0; i < dets.length; i++) {
            var key = dets[i].replace(/^[a-z_]+\./, '');
            if (D[key] && !seen[key]) { seen[key] = true; names.push(D[key]); }
        }
        if (names.length) { message += ' ' + names.join('; ') + '.'; }
    }
    if (AIRS3.get('scanId')) { message += ' Scan ID: ' + AIRS3.get('scanId') + '.'; }

    // Monitor mode: nothing the client receives changes. A refusal made before any verdict (a setting v3 can't read,
    // content it can't inspect, an MCP GET stream, an open circuit breaker) is logged as what it would have been, and the
    // leg passes (MuleSoft's decision.rs), with streaming turned off and back on as for any pass: JS-Airs3Destream and
    // JS-Airs3Restream run again after this step when airs3.lateStream is true (they ran before it, with nothing to do).
    if (AIRS3.get('mode') === 'monitor') {
        if (!MONITORED[outcome]) { AIRS3.set('outcome', { block: 'monitored_block', failure: 'failed_open', refused: 'gap_unenforced', config: 'config_unenforced' }[kind] || 'failed_open'); }
        AIRS3.set('blockKind', kind);
        AIRS3.set('route', 'pass');
        if (AIRS3.get('needDestream') !== 'true' && AIRS3.get('needRestream') !== 'true' && AIRS3.get('doneDetect') === 'true' && route !== 'mcp405' && AIRS3.streamNeeds()) {
            AIRS3.set('lateStream', 'true');
        }
        var mn = AIRS3.get('logNote');
        AIRS3.set('logNote', (mn ? mn + '; ' : '') + (AIRS3.get('outcome') === 'mask_not_applied' ? 'monitor mode: a masked copy was not applied' : 'monitor mode, not enforced: ' + message));
        AIRS3.done('Respond');
        return;
    }

    var code, type = 'application/json', body;
    if (format === 'mcp' || route === 'mcp405') {
        var ecode = (kind === 'failure' || kind === 'config') ? -32003 : -32001;
        var rb = AIRS3.parse(AIRS3.str('request.content'));
        if (AIRS3.isArray(rb)) {                                              // a batch: one error per member that has an id
            var errs = [];
            for (var b = 0; b < rb.length; b++) { if (AIRS3.isObject(rb[b]) && rb[b].method !== undefined && rb[b].id !== undefined) { errs.push({ jsonrpc: '2.0', id: rb[b].id, error: { code: ecode, message: message } }); } }
            body = JSON.stringify(errs.length ? errs : { jsonrpc: '2.0', id: null, error: { code: ecode, message: message } });
            code = errs.length ? 200 : (ecode === -32003 ? 503 : 403);
        } else {
            // Only a request is answered by its id: a client's reply carries the server's id (MuleSoft's request_ids).
            var mid = AIRS3.isObject(rb) && rb.method === undefined ? '' : AIRS3.get('mcpId');
            var id = mid === '' || mid === 'null' ? null : AIRS3.parse(mid);
            if (id === undefined) { id = null; }
            body = JSON.stringify({ jsonrpc: '2.0', id: id, error: { code: ecode, message: message } });
            code = route === 'mcp405' ? 405 : (id !== null ? 200 : (ecode === -32003 ? 503 : 403));   // no id to answer: an HTTP status says it
        }
    } else {
        var mod = AIRS3_FMT[format];
        var s = AIRS3.get('stream');
        // A request an earlier run on this leg already de-streamed (a second FlowCallout, or never twice after a run that didn't
        // enforce a verdict) shows no stream in its body any more: airs3.destreamed says the client asked for one (A30).
        var reqOff = req && s === 'none' && AIRS3.get('destreamed') !== '';
        if (reqOff) { s = AIRS3.get('destreamed'); }
        // A Gemini call without alt=sse reads a JSON array, on either leg.
        var streaming = (req && (s === 'body' || s === 'gemini-sse' || s === 'gemini-array' || s === 'rawpredict' || reqOff)) ||
                        (!req && (AIRS3.get('destreamed') !== '' || s === 'event-stream-reply' || s === 'gemini-array'));
        var cx = { leg: leg, kind: kind, stream: req ? s : (AIRS3.get('destreamed') || s), scanId: AIRS3.get('scanId'), category: AIRS3.get('category'),
                   model: (AIRS3.parse(AIRS3.str('request.content')) || {}).model || '' };
        var r;
        if (mod) { r = streaming && mod.streamRefusal ? mod.streamRefusal(kind, message, cx) : mod.refusal(kind, message, cx); }
        else {
            // An endpoint v3 doesn't read has no native shape: an OpenAI-style error, with a 403.
            r = { code: 403, type: 'application/json', body: JSON.stringify({ error: { message: message, type: 'prisma_airs_' + kind, param: null, code: 'prisma_airs_' + kind } }) };
        }
        code = r.code; type = r.type; body = r.body;
        var mode = AIRS3.get('blockMode');
        if (mod && !streaming && mode !== 'native') { code = parseInt(mode, 10); }
    }
    var REASONS = { 200: 'OK', 400: 'Bad Request', 403: 'Forbidden', 405: 'Method Not Allowed', 500: 'Internal Server Error', 503: 'Service Unavailable' };
    AIRS3.set('blockBody', body);
    AIRS3.set('blockType', type);
    AIRS3.set('blockCode', code);
    AIRS3.set('blockReason', REASONS[code] || 'Blocked');
    AIRS3.set('blockKind', kind);
    AIRS3.set('blockReady', 'true');
    AIRS3.done('Respond');
})();

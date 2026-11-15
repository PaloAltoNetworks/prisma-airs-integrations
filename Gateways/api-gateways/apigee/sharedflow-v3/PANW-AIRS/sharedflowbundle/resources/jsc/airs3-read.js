/*
 * airs3-read.js: the scan text for this leg, from the format module's segments; the size limit (A27); the scan body.
 * Request leg: every user turn and every tool result, plus system or assistant text when scanMessageRoles opts in.
 * Reply leg: everything the module reads from the reply, with the prompt as context in the same entry.
 * One entry in contents, always: Prisma AIRS judges only the last one (K3 and K4).
 * MCP (MuleSoft's rule): text that is not a tool event goes as a prompt on both legs, with no context, because MCP text
 * reaches a model as input (Prisma AIRS reads injection on the prompt side only); text over the limit keeps its first part.
 * Several scans (MCP only: a batch's members, a reply array's answers, a tools/list answer with more than its tools, an
 * answer that carries more than its result, and with type=both the request's scans before the reply's): one body per
 * scan, each with its own size check, into slots 1 to 8 (airs3.scanBody, scanBody2, ...).
 */
(function () {
    var leg = AIRS3.get('leg'), phase = AIRS3.get('phase'), format = AIRS3.get('format');
    var mod = AIRS3_FMT[format];
    function finish() { AIRS3.done('Read'); }
    function gap(message) {
        if (AIRS3.get('onScanError') === 'allow') {
            AIRS3.set('route', 'pass'); AIRS3.set('logNote', 'gap allowed: ' + message);
            // A pass: streaming off and back on, as for any pass, but only a reply its format can put back into the client's
            // stream is restreamed; one it can't read passes as the model sent it, logged, as onScanError=allow says.
            if (AIRS3.streamNeeds() && AIRS3.get('needRestream') === 'true' &&
                !(mod && mod.restream && mod.restream(AIRS3.parse(AIRS3.str('response.content')), AIRS3.get('destreamed')))) {
                AIRS3.set('needRestream', 'false');
                AIRS3.set('logNote', AIRS3.get('logNote') + '; passed as the model sent it, not in the client\'s stream format');
            }
            return finish();
        }
        AIRS3.refuse('refused', message);
        return finish();
    }
    if (!mod) { return gap('Prisma AIRS could not inspect this ' + (leg === 'request' ? 'request, so it was not forwarded.' : 'response, so it was withheld.')); }

    var roles = AIRS3.get('scanRoles').split(',');
    var cx = { leg: leg, phase: phase, scanRoles: roles, forceCC: AIRS3.get('forceCC') === 'true', stream: AIRS3.get('stream'),
               mcpMethod: AIRS3.get('mcpMethod'), path: AIRS3.str('proxy.pathsuffix'), bytes: AIRS3.bytesRule,
               serverName: AIRS3.str('apiproxy.name') };
    var reqBody = AIRS3.parse(AIRS3.str('request.content'));

    function wanted(seg) {
        if (seg.role === 'user' || seg.role === 'tool') { return true; }
        if (seg.role === 'system') { return roles.indexOf('system') >= 0; }
        if (seg.role === 'assistant') { return roles.indexOf('assistant') >= 0; }
        return false;                                           // tool definitions on an LLM request: not read (README)
    }
    // Join segments with "\n" and record where each one sits, for exact masking (airs3-mask.js).
    function assemble(segs, part, all) {
        var text = [], map = [], pos = 0;
        for (var i = 0; i < segs.length; i++) {
            var s = segs[i];
            if (!all && !wanted(s)) { continue; }
            if (typeof s.text !== 'string' || s.text === '') { continue; }
            map.push({ at: s.at, start: pos, len: s.text.length, maskable: s.maskable !== false, part: part, orig: s.maskable === false ? s.text : undefined });
            text.push(s.text);
            pos += s.text.length + 1;
        }
        return { text: text.join('\n'), map: map };
    }

    // The body of one scan: the entry, the profile (tool events may use their own) and the metadata.
    function scanBody(entry, isTool) {
        var model = '';
        if (AIRS3.isObject(reqBody) && typeof reqBody.model === 'string') { model = reqBody.model; }
        var pm = /\/models\/([^\/:]+)/.exec(cx.path);
        if (!model && pm) { model = pm[1]; }
        var user = AIRS3.str('request.header.x-user-id');
        var meta = { app_name: 'Apigee-' + AIRS3.get('appName'), app_user: (user && user.length <= 100) ? user : 'apigee', ai_model: model.slice(0, 100) || 'unknown' };
        if (AIRS3.get('agentId')) { meta.agent_meta = { agent_id: AIRS3.get('agentId'), agent_version: AIRS3.get('agentVersion') || undefined }; }
        var prof = isTool ? AIRS3.get('toolProfile') : AIRS3.get('profile');
        var UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
        var body = { transaction_id: AIRS3.get('txnId'), ai_profile: UUID.test(prof) ? { profile_id: prof.toLowerCase() } : { profile_name: prof },
                     metadata: meta, contents: [entry] };
        if (AIRS3.get('sessionId')) { body.session_id = AIRS3.get('sessionId'); }
        return JSON.stringify(body);
    }

    // A tool event's identity, for type=both: the tool and its input.
    function teKey(t) { return JSON.stringify([t.metadata && t.metadata.tool_invoked || '', String(t.input || '')]); }
    // One MCP read result's scans: its own list, or itself when it has a tool event or text.
    function scansOf(r) {
        if (r.scans) { return r.scans; }
        return (r.toolEvent || (r.segments && r.segments.length)) ? [r] : [];
    }

    // Several scans (MCP only): each its own size check (a tool event over the limit goes as text; text over it is cut or
    // refused, as for one scan); text goes as a prompt with no context; a scan with nothing in it is dropped. A gap is
    // judged for its own scan, as MuleSoft does: with onScanError=allow only that scan passes unscanned, logged, and the
    // others still run; otherwise it refuses the leg. A leg that needs more than the slots built in is a gap the same way:
    // refused, or with onScanError=allow its first slots scanned and the rest passed unscanned, logged. In monitor mode
    // (MuleSoft's mcp.rs) a gap is not enforced and every other scan still runs, as with onScanError=allow, logged as such.
    function many(list, pre) {
        var max = parseInt(AIRS3.get('maxScanChars'), 10), bodies = [], sizes = [], cuts = {}, notes = pre || [];
        var where = leg === 'request' ? 'request' : 'response', after = leg === 'request' ? 'not forwarded.' : 'withheld.';
        var byOse = AIRS3.get('onScanError') === 'allow', allow = byOse || AIRS3.get('mode') === 'monitor';
        var tag = byOse ? 'gap allowed: ' : 'monitor mode, gap not enforced: ';
        for (var i = 0; i < list.length; i++) {
            var te = list[i].toolEvent || null;
            var text = assemble(list[i].segments || [], 'prompt', true).text;
            if (te && (String(te.input || '').length + String(te.output || '').length) > max) { te = null; }
            if (!te && text.length > max) {
                if (AIRS3.get('truncFailClosed') !== 'false') {
                    var big = 'This ' + where + ' is larger than Prisma AIRS is set to inspect, so it was ' + after;
                    if (!allow) { return gap(big); }
                    notes.push(tag + 'a ' + where + ' part over ' + max + ' characters passed unscanned');
                    AIRS3.set('readGap', byOse ? 'allowed' : 'monitor');
                    continue;
                }
                // MCP text keeps its first part; an LLM body dressed as JSON-RPC (read whole) keeps its newest, as LLM text does
                text = list[i].newest ? text.slice(text.length - max) : text.slice(0, max);
                cuts[list[i].newest ? 'newest' : 'first'] = true;
                if (AIRS3.get('readGap') === '') { AIRS3.set('readGap', 'cut'); }       // part of the leg passed unscanned
            }
            if (!te && text === '') { continue; }
            bodies.push(scanBody(te ? { tool_event: te } : { prompt: text }, !!te));
            sizes.push(te ? String(te.input || '').length + String(te.output || '').length : text.length);
        }
        if (leg === 'request') { AIRS3.set('promptContext', ''); }
        if (bodies.length > AIRS3.SLOTS) {
            var over = 'Prisma AIRS could not inspect this ' + where + ' (it needs more than ' + AIRS3.SLOTS + ' scans), so it was ' + after;
            if (!allow) { return gap(over); }
            notes.push(tag + (bodies.length - AIRS3.SLOTS) + ' scans past the ' + AIRS3.SLOTS + ' slots passed unscanned');
            AIRS3.set('readGap', byOse ? 'allowed' : 'monitor');
            bodies = bodies.slice(0, AIRS3.SLOTS); sizes = sizes.slice(0, AIRS3.SLOTS);
        }
        if (cuts.first) { notes.push('scanned the first ' + max + ' characters of a ' + where + ' part'); }
        if (cuts.newest) { notes.push('scanned the newest ' + max + ' characters of a ' + where + ' part'); }
        if (notes.length) { AIRS3.set('logNote', notes.join('; ')); AIRS3.set('readNote', notes.join('; ')); }   // kept by the verdict
        if (!bodies.length) {
            AIRS3.set('route', 'pass');
            if (!notes.length) { AIRS3.set('logNote', leg === 'request' ? 'an MCP message with nothing to scan passes' : 'an empty reply passes'); }
            // Monitor mode, every part passed over as a gap: what enforce mode would have done, which refuses the leg.
            if (AIRS3.get('readGap') === 'monitor') { AIRS3.set('outcome', 'gap_unenforced'); AIRS3.set('blockKind', 'refused'); }
            return finish();
        }
        var total = 0;
        for (var k = 1; k <= bodies.length; k++) {
            AIRS3.set(k === 1 ? 'scanBody' : 'scanBody' + k, bodies[k - 1]);
            if (k > 1) { AIRS3.set('slot' + k, 'true'); }
            total += sizes[k - 1];
        }
        AIRS3.set('scanCount', bodies.length);
        AIRS3.set('scanChars', total);
        AIRS3.set('slotChars', sizes.join(','));                      // JS-Airs3Verdict counts only the slots that ran
        AIRS3.set('segments', JSON.stringify({ map: [], length: 0, cut: true, fixed: true }));   // MCP text is never rewritten
        return finish();
    }

    var res, prompt = { text: '', map: [] }, response = { text: '', map: [] }, toolEvent = null, fixed = false;
    if (leg === 'request') {
        res = mod.request(reqBody, cx);
        if (res.unreadable) { return gap('Prisma AIRS could not inspect this request (' + res.unreadable + '), so it was not forwarded.'); }
        if (res.scans) { return many(res.scans); }
        prompt = assemble(res.segments || [], 'prompt', format === 'mcp');
        toolEvent = res.toolEvent || null;
        fixed = !!res.fixed;
    } else {
        if (AIRS3.get('stream') === 'event-stream-reply') {
            res = mod.replyStream ? mod.replyStream(AIRS3.str('response.content'), cx) : { segments: [], unreadable: 'an event stream' };
        } else {
            res = mod.reply(AIRS3.parse(AIRS3.str('response.content')), cx, reqBody);
        }
        if (res.unreadable) { return gap('Prisma AIRS could not inspect this response (' + res.unreadable + '), so it was withheld.'); }
        if (format === 'mcp' && phase === 'both') {
            // type=both judges the request with its reply: on MCP, the request's own scans come first, then the reply's.
            // A request tool event that a reply tool event repeats (the same tool, the same input) is judged there, but
            // only when that reply tool event stays a tool event: one over maxScanChars goes as text of its result alone.
            // With onScanError=allow, a leg past the slots drops request scans first: the reply is what still travels.
            // A request with no body (a GET, the DELETE that ends a session) has nothing to judge: the reply's scans alone.
            var rqm = AIRS3.str('request.content') === '' ? { scans: [], segments: [], unreadable: null } : mod.request(reqBody, cx);
            if (rqm.unreadable) { return gap('Prisma AIRS could not inspect this response (its request: ' + rqm.unreadable + '), so it was withheld.'); }
            var replyScans = scansOf(res), judged = {}, list = [], lim = parseInt(AIRS3.get('maxScanChars'), 10), pre = [];
            for (var r1 = 0; r1 < replyScans.length; r1++) {
                var rt = replyScans[r1].toolEvent;
                if (rt && String(rt.input || '').length + String(rt.output || '').length <= lim) { judged[teKey(rt)] = true; }
            }
            var reqScans = scansOf(rqm);
            for (var r2 = 0; r2 < reqScans.length; r2++) {
                if (reqScans[r2].toolEvent && Object.prototype.hasOwnProperty.call(judged, teKey(reqScans[r2].toolEvent))) { continue; }
                list.push(reqScans[r2]);
            }
            var trimOse = AIRS3.get('onScanError') === 'allow';
            if ((trimOse || AIRS3.get('mode') === 'monitor') && list.length + replyScans.length > AIRS3.SLOTS) {
                var room = Math.max(0, AIRS3.SLOTS - replyScans.length);
                pre.push((trimOse ? 'gap allowed: ' : 'monitor mode, gap not enforced: ') + (list.length - room) + ' request scans past the ' + AIRS3.SLOTS + ' slots passed unscanned');
                AIRS3.set('readGap', trimOse ? 'allowed' : 'monitor');
                list = list.slice(0, room);
            }
            return many(list.concat(replyScans), pre);
        }
        if (res.scans) { return many(res.scans); }
        response = assemble(res.segments || [], 'response', true);
        toolEvent = res.toolEvent || null;
        fixed = !!res.fixed;
        if (phase === 'both') {
            var rq = mod.request(reqBody, cx);
            if (!rq.unreadable) { prompt = assemble(rq.segments || [], 'prompt', format === 'mcp'); }
        } else {
            prompt = { text: AIRS3.get('promptContext'), map: [] };       // context only: never masked or cut back
        }
    }

    var maxTE = parseInt(AIRS3.get('maxScanChars'), 10);
    if (toolEvent && (String(toolEvent.input || '').length + String(toolEvent.output || '').length) > maxTE) { toolEvent = null; }

    // The size limit counts the whole text this leg scans.
    var max = parseInt(AIRS3.get('maxScanChars'), 10);
    var scanned = leg === 'request' ? prompt : response;
    if (scanned.text.length > max) {
        if (AIRS3.get('truncFailClosed') !== 'false') {
            return gap('This ' + (leg === 'request' ? 'request is' : 'response is') + ' larger than Prisma AIRS is set to inspect, so it was ' + (leg === 'request' ? 'not forwarded.' : 'withheld.'));
        }
        // A prompt keeps its newest part, and so does an LLM body dressed as JSON-RPC (read whole as MCP text); a reply,
        // and MCP text, their first part. Logged; nothing is masked.
        var newest = leg === 'request' && (format !== 'mcp' || !!res.newest);
        scanned.text = newest ? scanned.text.slice(scanned.text.length - max) : scanned.text.slice(0, max);
        scanned.map = [];
        AIRS3.set('readGap', 'cut');                                  // the rest passed unscanned: no run counts it as enforced
        AIRS3.set('logNote', 'scanned ' + (newest ? 'the newest ' : 'the first ') + max + ' characters');
        AIRS3.set('readNote', AIRS3.get('logNote'));                  // kept by the verdict
    }
    if (prompt.text.length > max) { prompt.text = prompt.text.slice(prompt.text.length - max); }

    if (!toolEvent && scanned.text === '') {
        if (leg === 'request' && format !== 'mcp') { return gap('Prisma AIRS found nothing it could inspect in this request, so it was not forwarded.'); }
        AIRS3.set('route', 'pass'); AIRS3.set('logNote', leg === 'request' ? 'an MCP message with nothing to scan passes' : 'an empty reply passes');
        AIRS3.streamNeeds();                                                       // still in the client's stream
        return finish();
    }

    var entry;
    if (toolEvent) {
        entry = { tool_event: toolEvent };
    } else if (leg === 'request' || format === 'mcp') {
        entry = { prompt: scanned.text };                             // MCP reply text too: a prompt, with no context
    } else {
        entry = prompt.text ? { prompt: prompt.text, response: scanned.text } : { response: scanned.text };
    }
    if (leg === 'request') { AIRS3.set('promptContext', toolEvent ? '' : scanned.text); }

    AIRS3.set('scanBody', scanBody(entry, !!toolEvent));
    AIRS3.set('scanCount', 1);
    AIRS3.set('scanChars', scanned.text.length);
    // fixed: the body repeats its text in a form v3 never rewrites (log probabilities), so it is never masked.
    AIRS3.set('segments', JSON.stringify({ map: scanned.map, length: scanned.text.length, cut: scanned.map.length === 0, fixed: fixed }));
    finish();
})();

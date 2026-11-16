/*
 * airs3-init.js: the leg, every setting (read strictly: A39), the endpoint, the profile and the ids (L12).
 * An unset setting takes its default. A set value v3 can't read refuses the request (kind 'config'), with a message
 * that names the setting and never its value. Ends by setting airs3.doneInit.
 */
(function () {
    var problems = [];
    // Flow hooks (phase 3): v3's hook SharedFlows call it with hookMode=request or hookMode=response, and its settings then
    // come from the config map's airs_hook entry, JSON {"routes": [base paths], "settings": {name: value}}, and from nowhere else.
    var SETTINGS = { failOpen: 1, failClosedOnUnknown: 1, onScanError: 1, scanMessageRoles: 1, maxScanChars: 1, truncationFailClosed: 1,
                     applyDlpMasking: 1, forceClaudeCode: 1, mcpBatchLimit: 1, allowOpenStreams: 1, blockStatus: 1, appName: 1, agentId: 1,
                     agentVersion: 1, airsDescriptions: 1, prismaAirsEndpoint: 1, currentProfile: 1, toolProfile: 1, enforcementMode: 1,
                     scanRetries: 1, breakerFailures: 1, breakerCooldownS: 1, verdictCacheTtlS: 1, prismaAirsAuthMode: 1 };
    var hookSettings = null;
    function raw(name) {
        // Hook mode: a setting comes from airs_hook alone. A hook sees every variable the proxy set (L20), and a FlowCallout's
        // parameters stay set after it returns (L6), so no proxy variable of a setting's name takes part. A JSON object or
        // array there (airsDescriptions) is read as the JSON it is.
        if (hookSettings !== null && SETTINGS[name] === 1) {
            var hv = hookSettings[name];
            if (hv === undefined || hv === null) { return null; }
            hv = typeof hv === 'object' ? JSON.stringify(hv) : String(hv).replace(/^\s+|\s+$/g, '');
            return hv === '' ? null : hv;
        }
        var v = context.getVariable(name);
        if (v === null || v === undefined) { return null; }
        v = String(v).replace(/^\s+|\s+$/g, '');
        return v === '' ? null : v;
    }
    function bool(name, dflt) {
        var v = raw(name);
        if (v === null) { return dflt; }
        var l = v.toLowerCase();
        if (l === 'true') { return true; }
        if (l === 'false') { return false; }
        problems.push(name); return dflt;
    }
    function int(name, dflt, lo, hi) {
        var v = raw(name);
        if (v === null) { return dflt; }
        if (!/^[0-9]{1,9}$/.test(v)) { problems.push(name); return dflt; }
        var n = parseInt(v, 10);
        if (n < lo || n > hi) { problems.push(name); return dflt; }
        return n;
    }
    function oneOf(name, dflt, allowed) {
        var v = raw(name);
        if (v === null) { return dflt; }
        var l = v.toLowerCase();
        for (var i = 0; i < allowed.length; i++) { if (allowed[i] === l) { return l; } }
        problems.push(name); return dflt;
    }

    // Start clean on every leg: no state from the request leg decides the reply (A16). destreamed and promptContext
    // are carried from the request leg on purpose. format, stream, mcpMethod and mcpId are not cleared: airs3-detect.js
    // sets them again on every leg before any use, and if this step is cut, Respond still answers in the client's own
    // format with them.
    var flags = ['Detect', 'Read', 'CacheKeys', 'Verdict', 'Mask', 'Destream', 'Restream', 'Respond', 'Log'];
    for (var f = 0; f < flags.length; f++) { context.setVariable('airs3.done' + flags[f], 'false'); }
    var clear = ['outcome', 'detections', 'category', 'scanId', 'aiStatus', 'maskedText', 'masked', 'blockBody', 'blockType', 'blockCode',
                 'blockReason', 'blockKind', 'blockReady', 'needDestream', 'needRestream', 'scanBody', 'scanChars', 'segments', 'route',
                 'logNote', 'readNote', 'breakerState', 'breakerHalf', 'breakerWrite', 'breakerNew', 'breakerTtl', 'skipLeg', 'quiet', 'hook',
                 'hookApiFormat'];
    for (var c = 0; c < clear.length; c++) { AIRS3.set(clear[c], ''); }
    AIRS3.set('refuse', 'none');
    AIRS3.set('refuseMsg', '');
    AIRS3.set('t0', new Date().getTime());

    // Flow hooks and never twice (phase 3). In hook mode, a proxy whose base path airs_hook doesn't list passes untouched,
    // with no log line: without the list, v3's refusal of traffic it can't read would refuse every proxy in the environment.
    // A leg the other kind of run already enforced a verdict on passes, logged: the request-leg FlowCallout runs before the
    // pre-target hook, and the post-target hook before the reply-leg FlowCallout (L20). Two FlowCallouts on one leg both scan.
    // The hook SharedFlows pass one parameter, hookMode (the leg), and no other: a FlowCallout's parameters stay set after it
    // returns (L6), so it is cleared at once (the proxy's own FlowCallout later on this exchange must not be taken for a
    // hook), and no proxy's own variable, such as type, is ever written. Any other value is not v3's, and is left alone.
    var hmv = context.getVariable('hookMode'), hm = hmv === null || hmv === undefined ? '' : String(hmv).replace(/^\s+|\s+$/g, '');
    var hookMode = hm === 'request' || hm === 'response', onReplyNow = raw('response.status.code') !== null;
    if (hookMode) { context.setVariable('hookMode', ''); }
    var prior = AIRS3.get(onReplyNow ? 'scannedResponse' : 'scannedRequest');
    AIRS3.set('hook', hookMode ? 'true' : 'false');
    function skip(quiet, note) {
        AIRS3.set('skipLeg', 'true');
        AIRS3.set('quiet', quiet ? 'true' : 'false');
        AIRS3.set('route', 'pass');
        AIRS3.set('leg', onReplyNow ? 'response' : 'request');
        if (note) { AIRS3.set('logNote', note); }
        AIRS3.done('Init');
    }
    if (hookMode) {
        var hc = AIRS3.parse(raw('airs3.kvmHook'));
        if (!AIRS3.isObject(hc) || !AIRS3.isArray(hc.routes)) { return skip(false, 'hook mode: the config map has no readable airs_hook entry, so nothing was scanned'); }
        if (hc.routes.indexOf(AIRS3.str('proxy.basepath')) === -1) { return skip(true, ''); }
        if (prior !== '') { return skip(false, 'already scanned on this leg by the proxy\'s FlowCallout'); }
        // settings must be a JSON object, read as strictly as a proxy's settings are (A39): anything else refuses, naming it.
        if (hc.settings !== undefined && hc.settings !== null && !AIRS3.isObject(hc.settings)) { problems.push('settings (config map entry airs_hook)'); }
        hookSettings = AIRS3.isObject(hc.settings) ? hc.settings : {};
        if (hookSettings.apiFormat !== undefined && hookSettings.apiFormat !== null) {
            if (typeof hookSettings.apiFormat === 'string') { AIRS3.set('hookApiFormat', hookSettings.apiFormat); } else { problems.push('apiFormat'); }
        }
    } else if (prior === 'hook') { return skip(false, 'already scanned on this leg by the flow hook'); }
    // A reply an earlier run on this leg put back into the client's stream, unchanged since (airs3-restream.js): this run
    // reads the JSON it was made from, as that run did, and puts it back into the stream itself after its own verdict.
    if (onReplyNow && AIRS3.get('plainReply') !== '') {
        var rh = crypto.getSHA256(); rh.update(AIRS3.str('response.content'));
        if (rh.digest() === AIRS3.get('restreamHash')) {
            context.setVariable('response.content', AIRS3.get('plainReply'));
            context.setVariable('response.header.Content-Type', AIRS3.get('plainType'));
        }
        AIRS3.set('plainReply', ''); AIRS3.set('plainType', ''); AIRS3.set('restreamHash', '');
    }
    // Monitor mode (MuleSoft's enforcementMode): every decision is made and logged, and none changes what the client
    // gets. Read first; a value v3 can't read refuses, as in enforce mode, so the mode is never guessed.
    AIRS3.set('mode', oneOf('enforcementMode', 'enforce', ['enforce', 'monitor']));

    // The leg: in hook mode, hookMode's; else the FlowCallout parameter `type`, or V2's `scanType`. It must match the flow the
    // step runs in, which the runtime shows: the reply's status exists only on the reply leg. A mismatch would scan the wrong
    // message and pass the other one unscanned, so it is refused as a setting problem, on the leg the step really runs on.
    var type = hookMode ? (hm === 'request' ? 'user-prompt' : 'response-prompt') : raw('type'), scanType = hookMode ? null : raw('scanType');
    var phase = 'prompt', named = hookMode ? 'hookMode' : 'type', bad = false;
    if (type !== null) {
        if (type === 'user-prompt') { phase = 'prompt'; } else if (type === 'response-prompt') { phase = 'response'; } else if (type === 'both') { phase = 'both'; } else { problems.push('type'); bad = true; }
    } else if (scanType !== null) {
        named = 'scanType';
        var before = problems.length;
        phase = oneOf('scanType', 'prompt', ['prompt', 'response', 'both']);
        bad = problems.length > before;
    }
    var onReply = raw('response.status.code') !== null;
    if (!bad && (phase === 'prompt') === onReply) {
        problems.push(named + ' (this step runs on the ' + (onReply ? 'reply' : 'request') + ' leg)');
        phase = onReply ? 'response' : 'prompt';
    }
    AIRS3.set('phase', phase);
    AIRS3.set('leg', onReply ? 'response' : 'request');

    // Failures and gaps. V2's failClosedOnUnknown still works: true is onScanError=block; false lets only unknown
    // endpoints pass. onScanError wins when both are set.
    AIRS3.set('failOpen', bool('failOpen', false));
    var fcu = raw('failClosedOnUnknown') === null ? null : bool('failClosedOnUnknown', true);
    var ose = oneOf('onScanError', null, ['block', 'allow']);
    AIRS3.set('onScanError', ose !== null ? ose : (fcu === false ? 'allow-unknown' : 'block'));

    // What gets read. User turns and tool results always; system and assistant text only when opted in.
    var roles = raw('scanMessageRoles'), roleList = ['user'];
    if (roles !== null) {
        var parts = roles.toLowerCase().split(',');
        for (var p = 0; p < parts.length; p++) {
            var r = parts[p].replace(/^\s+|\s+$/g, '');
            if (r === 'user' || r === 'tool') { continue; }                     // tool results are always read
            if (r === 'system' || r === 'developer') { if (roleList.indexOf('system') < 0) { roleList.push('system'); } continue; }
            if (r === 'assistant') { if (roleList.indexOf('assistant') < 0) { roleList.push('assistant'); } continue; }
            problems.push('scanMessageRoles'); break;
        }
    }
    AIRS3.set('scanRoles', roleList.join(','));
    AIRS3.set('maxScanChars', int('maxScanChars', 100000, 1, 2097152));
    AIRS3.set('truncFailClosed', bool('truncationFailClosed', true));
    AIRS3.set('applyMask', bool('applyDlpMasking', false));
    AIRS3.set('forceCC', bool('forceClaudeCode', false));
    // MCP (phase 2): batch members, at most the 8 scan slots the SharedFlow is built with; open streams pass unscanned only when set.
    AIRS3.set('mcpBatchLimit', int('mcpBatchLimit', 8, 1, 8));
    AIRS3.set('openStreams', bool('allowOpenStreams', false));
    // Operations (phase 3, MuleSoft's settings): one more call after no answer, 429 or a 5xx, when 1.
    AIRS3.set('scanRetries', int('scanRetries', 0, 0, 1));
    // The circuit breaker, off at 0: after this many scanner failures in a row, no call for breakerCooldownS seconds.
    var bf = int('breakerFailures', 0, 0, 100);
    AIRS3.set('breakerFailures', bf);
    AIRS3.set('breakerCooldownS', int('breakerCooldownS', 30, 1, 3600));
    AIRS3.set('breakerOn', bf > 0 ? 'true' : 'false');
    // The verdict cache, off at 0: allows only, for at most verdictCacheTtlS seconds, and never with masking (MuleSoft).
    var vc = int('verdictCacheTtlS', 0, 0, 300);
    AIRS3.set('vcTtl', vc);
    AIRS3.set('vcOn', vc > 0 && AIRS3.get('applyMask') !== 'true' ? 'true' : 'false');

    // How blocks are answered: V2's style, an HTTP 200 in the client's format, unless blockStatus forces a code.
    var bs = raw('blockStatus');
    if (bs === null || bs.toLowerCase() === 'native') { AIRS3.set('blockMode', 'native'); }
    else if (/^[1-5][0-9][0-9]$/.test(bs)) { AIRS3.set('blockMode', bs); }
    else { problems.push('blockStatus'); AIRS3.set('blockMode', 'native'); }

    // Names in the scan's metadata.
    var app = raw('appName') || 'Gateway';
    if (!/^[A-Za-z0-9._\- ]{1,64}$/.test(app)) { problems.push('appName'); app = 'Gateway'; }
    AIRS3.set('appName', app);
    var agentId = raw('agentId') || raw('request.header.X-Agent-ID') || raw('request.header.x-claude-code-agent-id') || '';
    AIRS3.set('agentId', agentId.length <= 100 ? agentId : '');
    AIRS3.set('agentVersion', (raw('agentVersion') || '').slice(0, 100));
    var desc = raw('airsDescriptions');
    if (desc !== null && !AIRS3.isObject(AIRS3.parse(desc))) { problems.push('airsDescriptions'); }
    AIRS3.set('descriptions', desc || '');

    // The endpoint: one of Prisma AIRS's regional API hosts.
    var ep = (raw('prismaAirsEndpoint') || 'service.api.aisecurity.paloaltonetworks.com').toLowerCase();
    if (!/^service(-[a-z]{2})?\.api\.aisecurity\.paloaltonetworks\.com$/.test(ep)) { problems.push('prismaAirsEndpoint'); ep = 'service.api.aisecurity.paloaltonetworks.com'; }
    AIRS3.set('endpoint', ep);

    // The profile: the proxy's currentProfile, else the config map's; tool events may use their own.
    var profile = raw('currentProfile') || raw('airs3.kvmProfile');
    if (profile === null) { problems.push('the profile (config map entry airs_profile)'); }
    AIRS3.set('profile', profile || '');
    AIRS3.set('toolProfile', raw('toolProfile') || profile || '');
    // The credential (v3.1): prismaAirsAuthMode from the proxy (in hook mode from airs_hook alone), else the config map's
    // airs_auth_mode, else apikey. Bearer mode sends the config map's airs_bearer, checked as stored: 1 to 4,096 printable
    // ASCII characters and no spaces (APIM v2.2.0's rule), so a bad value can't add a header. It is never trimmed or written.
    var auth = 'apikey', cred = '';
    if (raw('prismaAirsAuthMode') !== null) { auth = oneOf('prismaAirsAuthMode', 'apikey', ['apikey', 'bearer']); }
    else if (raw('airs3.kvmAuthMode') !== null) {
        var km = raw('airs3.kvmAuthMode').toLowerCase();
        if (km === 'apikey' || km === 'bearer') { auth = km; } else { problems.push('the config map entry airs_auth_mode'); }
    }
    AIRS3.set('authMode', auth);
    if (auth === 'bearer') {
        var tk = context.getVariable('private.airs3_bearer');
        tk = tk === null || tk === undefined ? '' : String(tk);
        if (!/^[\x21-\x7e]{1,4096}$/.test(tk)) { problems.push('the Prisma AIRS OAuth token (config map entry airs_bearer)'); }
        cred = 'bearer:' + tk;
    } else {
        var key = raw('private.airs3_token');            // read once, as each credential is read once here
        if (key === null) { problems.push('the Prisma AIRS key (config map entry airs_token)'); }
        cred = key || '';
    }
    // The breaker's cache key: SHA-256 of the endpoint and the credential (L18), the API key or, in bearer mode, 'bearer:' and
    // the token: tenants never share one, a renewed token starts afresh, and no credential is stored.
    if (bf > 0) { var bh = crypto.getSHA256(); bh.update(ep + '\n' + cred); AIRS3.set('breakerKey', 'airs3-breaker-' + bh.digest()); }

    // Ids: never cut (L12). Mcp-Session-Id is read only on MCP, once airs3-detect.js knows the format.
    AIRS3.set('txnId', AIRS3.firstId(['request.header.x-correlation-id', 'request.header.x-request-id', 'messageid']));
    AIRS3.set('sessionId', AIRS3.firstId(['request.header.x-session-id', 'request.header.x-claude-code-session-id']));

    if (problems.length) {
        AIRS3.refuse('config', 'Prisma AIRS is not configured correctly, so it refused this request. Check the setting: ' + problems[0] + '.');
    }
    AIRS3.done('Init');
})();

/*
 * airs3-detect.js: the format, the stream kind and the route (scan, pass, refuse, mcp405), on either leg.
 * MCP: a batch with more members than mcpBatchLimit is refused before any scan (its reply withheld, on a proxy that calls
 * v3 on its reply leg only). With allowOpenStreams, an MCP GET for an event stream, and an MCP reply sent as an event
 * stream (which the flow can't see: L1), pass unscanned and logged; only on an MCP route (a path ending in /mcp, or
 * apiFormat=mcp) and to a request that is all JSON-RPC, so an LLM body dressed as JSON-RPC opens nothing. A body on an MCP
 * route that is not a JSON-RPC message or batch is content v3 can't inspect, whatever failClosedOnUnknown says.
 * The format comes from the body for MCP, else the provider's path, else the FlowCallout parameter apiFormat; never
 * from a header. What can't be read is refused unless onScanError lets it pass, logged.
 * The format and the stream kind are set before any refusal, so every refusal is in the client's own format.
 * Each leg decides alone: a proxy may call v3 on its reply leg only.
 */
(function () {
    var MAX_BODY = 10485760;                          // Apigee's own limit is about 10 MB (L2); a proxy may raise it
    var leg = AIRS3.get('leg');
    var verb = AIRS3.str('request.verb').toUpperCase();
    var path = AIRS3.str('proxy.pathsuffix').split('?')[0].split('#')[0];
    var query = AIRS3.str('request.querystring');
    var reqRaw = AIRS3.str('request.content');
    var ose = AIRS3.get('onScanError');

    function done(route) { if (route) { AIRS3.set('route', route); } AIRS3.done('Detect'); }
    function gap(message, unknownEndpoint) {
        if (ose === 'allow' || (ose === 'allow-unknown' && unknownEndpoint)) { AIRS3.set('logNote', 'gap allowed: ' + message); return done('pass'); }
        AIRS3.refuse('refused', message);
        return done('refuse');
    }

    var apiFormat = (AIRS3.get('hook') === 'true' ? AIRS3.get('hookApiFormat') : AIRS3.str('apiFormat')).replace(/^\s+|\s+$/g, '').toLowerCase();   // a hook's: airs_hook's alone
    var FORMATS = ['openai-chat', 'openai-responses', 'anthropic', 'gemini', 'mcp'];
    var badApiFormat = apiFormat !== '' && FORMATS.indexOf(apiFormat) < 0;
    if (badApiFormat) { apiFormat = ''; }                                         // refused below, once the format is known

    function isMessage(m) {
        return AIRS3.isObject(m) && m.jsonrpc === '2.0' &&
            ((typeof m.method === 'string' && m.method.length > 0) || (m.id !== undefined && (m.result !== undefined || m.error !== undefined)));
    }
    function isBatch(b) {
        if (!AIRS3.isArray(b) || !b.length) { return false; }
        for (var i = 0; i < b.length; i++) { if (!isMessage(b[i])) { return false; } }
        return true;
    }
    // Only the end of the path names the API, so a name inside it (a deployment, a model) never picks the reader.
    // Count-tokens calls are Anthropic's, Gemini's and Claude on Vertex's.
    function formatByPath(p) {
        if (/\/count_tokens$|:countTokens$|\/models\/count-tokens:rawPredict$/.test(p)) { return 'count-tokens'; }
        if (/\/$/.test(p)) { return 'unknown'; }                                         // a trailing slash (A12)
        if (/\/chat\/completions$/.test(p)) { return 'openai-chat'; }
        if (/\/responses$/.test(p)) { return 'openai-responses'; }
        if (/\/messages$/.test(p)) { return 'anthropic'; }
        if (/:(stream)?[gG]enerateContent$/.test(p)) { return 'gemini'; }
        if (/\/publishers\/anthropic\/models\/[^\/]+:(stream)?[rR]awPredict$/.test(p)) { return 'anthropic'; }
        return null;
    }
    // A model's answer fetched later, by a call with no body: Responses background mode (GET, or POST .../cancel) and
    // stored chat completions. Their replies are read.
    function storedByPath(p) {
        if (verb === 'GET' && /\/responses\/[^\/]+$/.test(p)) { return 'openai-responses'; }
        if (verb === 'POST' && /\/responses\/[^\/]+\/cancel$/.test(p)) { return 'openai-responses'; }
        if (verb === 'GET' && /\/conversations\/[^\/]+\/items(\/[^\/]+)?$/.test(p)) { return 'openai-responses'; }   // a conversation's items
        if (verb === 'GET' && /\/chat\/completions\/[^\/]+$/.test(p)) { return 'openai-chat'; }
        return null;
    }
    // Dot segments, encoded separators and backslashes can name one endpoint to v3 and another to the provider.
    var oddPath = /(^|\/)\.\.?(\/|$)|%2e|%2f|%5c|\\/i.test(path);

    var oversize = reqRaw.length > MAX_BODY;
    var reqBody = reqRaw === '' || oversize ? undefined : AIRS3.parse(reqRaw);
    var mcpPath = apiFormat === 'mcp' || /\/mcp\/?$/.test(path);
    // The headers say a body was sent, whether or not the flow can see it.
    var declared = parseInt(AIRS3.str('request.header.Content-Length'), 10) > 0 || AIRS3.str('request.header.Transfer-Encoding') !== '';

    // ---- the format, from the request (both legs read it: the request message is still there on the reply leg)
    // A stored reply is found with or without a trailing slash.
    var byPath = formatByPath(path), stored = reqRaw === '' ? storedByPath(path.replace(/\/+$/, '')) : null, format;
    if (reqBody !== undefined && (isMessage(reqBody) || isBatch(reqBody))) { format = 'mcp'; }
    else if (byPath === 'unknown' && stored) { format = stored; }
    else { format = byPath || stored || apiFormat || (oversize && mcpPath ? 'mcp' : 'unknown'); }
    AIRS3.set('format', format);
    // A refusal on an MCP path with no JSON-RPC body to go by is still a JSON-RPC error (id null), not an OpenAI-style one.
    function mcpShape() { if (format === 'unknown' && mcpPath) { format = 'mcp'; AIRS3.set('format', 'mcp'); AIRS3.set('mcpId', 'null'); } }
    if (format === 'mcp' && AIRS3.isObject(reqBody)) { AIRS3.set('mcpMethod', reqBody.method || ''); AIRS3.set('mcpId', AIRS3.idText(reqBody.id)); }
    if (format === 'mcp') {
        var sid = AIRS3.firstId(['request.header.Mcp-Session-Id']);
        // No session known yet: the initialize reply's own scan carries the session the server issues (MuleSoft's rule).
        if (!sid && leg === 'response' && AIRS3.get('mcpMethod') === 'initialize' && !AIRS3.get('sessionId')) { sid = AIRS3.firstId(['response.header.Mcp-Session-Id']); }
        if (sid) { AIRS3.set('sessionId', sid); }
    }
    // allowOpenStreams opens MCP's own streams only: on an MCP route, or to a JSON-RPC body at a path that names no API v3
    // reads, and only when every message of the request is all JSON-RPC (an LLM API always needs other members).
    function openStream() {
        if (AIRS3.get('openStreams') !== 'true' || !(mcpPath || (format === 'mcp' && byPath === null))) { return false; }
        var ms = AIRS3.isArray(reqBody) ? reqBody : [reqBody], env = { jsonrpc: 1, id: 1, method: 1, params: 1, result: 1, error: 1 };
        for (var i = 0; i < ms.length; i++) {
            if (!AIRS3.isObject(ms[i])) { continue; }
            for (var k in ms[i]) { if (Object.prototype.hasOwnProperty.call(ms[i], k) && !Object.prototype.hasOwnProperty.call(env, k)) { return false; } }
        }
        return true;
    }

    // ---- the stream kind: on the request leg, how this call streams (so it can be turned off on the way to the model,
    // L1); on the reply leg, whether the client reads a JSON array (Gemini without alt=sse).
    var sseQuery = /(^|&)alt=sse(&|$)/.test(query);
    if (leg === 'request') {
        var kind = 'none';
        if (AIRS3.isObject(reqBody) ? reqBody.stream === true
                                    : (oversize && /"stream"\s*:\s*true/.test(reqRaw.slice(0, 65536) + reqRaw.slice(-65536)))) { kind = 'body'; }
        if (/:streamGenerateContent$/.test(path)) { kind = sseQuery ? 'gemini-sse' : 'gemini-array'; }
        if (/:streamRawPredict$/.test(path)) { kind = 'rawpredict'; }
        AIRS3.set('stream', kind);
    } else {
        // After a destream the reply is JSON, and request.querystring no longer shows alt=sse (measured live): the
        // destreamed kind decides then.
        AIRS3.set('stream', AIRS3.get('destreamed') === '' && /:streamGenerateContent$/.test(path) && !sseQuery ? 'gemini-array' : 'none');
    }

    if (badApiFormat) {
        AIRS3.refuse('config', 'Prisma AIRS is not configured correctly, so it refused this request. Check the setting: apiFormat.');
        return done('refuse');
    }
    if (AIRS3.get('refuse') !== 'none') { return done('refuse'); }            // init refused: only the client's format was needed
    if (oddPath) {
        mcpShape();
        return gap(leg === 'request' ? 'Prisma AIRS could not inspect this request (its path is ambiguous), so it was not forwarded.'
                                     : 'Prisma AIRS could not inspect this response (its path is ambiguous), so it was withheld.', false);
    }
    if (oversize) {
        return gap(leg === 'request' ? 'This request is too large for Prisma AIRS to inspect, so it was not forwarded.'
                                     : 'This request was too large for Prisma AIRS to inspect, so its response was withheld.', false);
    }

    if (leg === 'request') {
        // After an upgrade (a WebSocket) no policy sees the traffic, so the upgrade itself is refused.
        if (AIRS3.str('request.header.Upgrade') !== '') {
            mcpShape();
            return gap('Prisma AIRS does not inspect upgraded connections (a WebSocket), so this one was not opened.', false);
        }
        if (reqRaw === '') {
            var accept = AIRS3.str('request.header.Accept').toLowerCase();
            if (verb === 'GET' && accept.indexOf('text/event-stream') !== -1 && mcpPath) {
                AIRS3.set('format', 'mcp'); AIRS3.set('mcpId', 'null');
                if (AIRS3.get('openStreams') === 'true') { AIRS3.set('logNote', 'an open stream passes unscanned (allowOpenStreams)'); return done('pass'); }
                return done('mcp405');
            }
            // A body the flow can't see is not a request with no body: refused when the endpoint takes a body
            // (a trailing slash doesn't change that) or the headers say one was sent.
            var takesBody = verb === 'POST' || verb === 'PUT' || verb === 'PATCH';
            var named = formatByPath(path.replace(/\/+$/, ''));
            if (takesBody && !stored && named !== 'count-tokens' && (declared || (named !== null && named !== 'unknown') || apiFormat !== '' || mcpPath)) {
                mcpShape();
                return gap('Prisma AIRS could not inspect this request (its body could not be read), so it was not forwarded.', false);
            }
            AIRS3.set('logNote', 'a request with no body passes');
            return done('pass');
        }
        if (format === 'count-tokens') { AIRS3.set('logNote', 'a count-tokens call passes'); return done('pass'); }
        if (format === 'unknown') {
            // On an MCP route a body that is not a JSON-RPC message or batch is content v3 can't inspect, refused in
            // JSON-RPC's shape; failClosedOnUnknown=false opens only endpoints v3 doesn't read.
            if (mcpPath) { mcpShape(); return gap('Prisma AIRS could not inspect this request (it is not a JSON-RPC message or batch), so it was not forwarded.', false); }
            return gap('Prisma AIRS could not inspect this request (an endpoint it does not read), so it was not forwarded.', true);
        }
        if (reqBody === undefined) { return gap('Prisma AIRS could not inspect this request (its body is not JSON), so it was not forwarded.', false); }
        if (AIRS3.duplicateKey(reqRaw, reqBody)) { return gap('Prisma AIRS could not inspect this request (it has duplicate JSON keys), so it was not forwarded.', false); }
        if (AIRS3.oddProto(reqBody)) { return gap('Prisma AIRS could not inspect this request (a member the runtime does not read as one), so it was not forwarded.', false); }
        if (format === 'mcp') {
            var limit = parseInt(AIRS3.get('mcpBatchLimit'), 10);
            if (AIRS3.isArray(reqBody) && reqBody.length > limit) {
                return gap('Prisma AIRS could not inspect this batch (more than ' + limit + ' messages), so it was not forwarded.', false);
            }
            if (AIRS3.isArray(reqBody)) { AIRS3.set('logNote', 'a batch of ' + reqBody.length + ' messages'); }
            else if (reqBody.method === undefined) { AIRS3.set('logNote', 'a JSON-RPC reply from the client'); }
        }
        return done('scan');
    }

    // ---- the reply leg
    var ctype = AIRS3.str('response.header.Content-Type').toLowerCase();
    // The batch limit holds on a proxy that calls v3 on its reply leg only: such a batch's reply is withheld.
    var rlimit = parseInt(AIRS3.get('mcpBatchLimit'), 10);
    if (format === 'mcp' && AIRS3.isArray(reqBody) && reqBody.length > rlimit) {
        return gap('Prisma AIRS could not inspect the reply to this batch (more than ' + rlimit + ' messages), so it was withheld.', false);
    }
    // type=both judges the request on this leg, so its body gets the request leg's checks too.
    if (AIRS3.get('phase') === 'both' && reqBody !== undefined && (AIRS3.duplicateKey(reqRaw, reqBody) || AIRS3.oddProto(reqBody))) {
        return gap('Prisma AIRS could not inspect this response (its request has duplicate JSON keys, or a member the runtime does not read as one), so it was withheld.', false);
    }
    // An event stream the client asked for is refused as an event stream.
    if (ctype.indexOf('text/event-stream') !== -1 && format !== 'mcp') { AIRS3.set('stream', 'event-stream-reply'); }
    // An event stream to a request with no body: the flow can't see its body (L1). On an MCP route, whatever its status
    // (MuleSoft reads such a stream, unless allowOpenStreams opened it).
    if (reqRaw === '' && ctype.indexOf('text/event-stream') !== -1 && (/^2[0-9][0-9]$/.test(AIRS3.str('response.status.code')) || mcpPath)) {
        if (mcpPath) { AIRS3.set('format', 'mcp'); AIRS3.set('mcpId', 'null'); }
        if (openStream()) { AIRS3.set('logNote', 'an open stream passes unscanned (allowOpenStreams)'); return done('pass'); }
        return gap('Prisma AIRS could not inspect this response (an event stream), so it was withheld.', false);
    }
    if (format === 'count-tokens') { AIRS3.set('logNote', 'a count-tokens reply passes'); return done('pass'); }
    if (format === 'unknown') {
        // The reply to a request with a body, at an endpoint v3 doesn't read, follows onScanError like the request would;
        // on an MCP route, a request that was not JSON-RPC is content v3 can't inspect.
        if ((reqRaw !== '' || declared) && mcpPath) { mcpShape(); return gap('Prisma AIRS could not inspect this response (its request is not a JSON-RPC message or batch), so it was withheld.', false); }
        if (reqRaw !== '' || declared) { return gap('Prisma AIRS could not inspect this response (an endpoint it does not read), so it was withheld.', true); }
        AIRS3.set('logNote', 'the reply to a request with no body passes');
        return done('pass');
    }
    var status = parseInt(AIRS3.str('response.status.code'), 10);
    var ok = status >= 200 && status < 300;
    // An LLM reply outside 2xx passes unscanned (A31: no provider puts model text into an error reply). An MCP one is
    // read as a 2xx one is (MuleSoft's rule): a
    // body that can be read is scanned whatever its status; one that is empty or not JSON carries no text and passes,
    // logged. On Apigee it reaches this leg only when the target's success.codes count 4xx and 5xx (L16).
    if (!ok && format !== 'mcp') { AIRS3.set('logNote', 'a non-2xx reply is not scanned'); return done('pass'); }
    var sse = ctype.indexOf('text/event-stream') !== -1;
    var respRaw = AIRS3.str('response.content');
    if (respRaw === '') {
        // No body, by its status or by its headers (an MCP server may end a session with 200 and Content-Length: 0). An
        // error reply's empty body is no body, unless it is announced as an event stream (which the flow can't see).
        var noBody = AIRS3.str('response.header.Content-Length') === '0' && AIRS3.str('response.header.Transfer-Encoding') === '';
        if (status === 204 || status === 202 || noBody || (!ok && !sse)) { AIRS3.set('logNote', 'a reply with no body passes'); return done('pass'); }
        if (format === 'mcp' && ctype.indexOf('text/event-stream') !== -1 && openStream()) {
            AIRS3.set('logNote', 'an MCP event-stream reply passes unscanned (allowOpenStreams)'); return done('pass');
        }
        // A 2xx body the flow can't see: on this runtime, any event stream (L1). The general guard (A21).
        return gap('Prisma AIRS could not inspect this response, so it was withheld.', false);
    }
    if (respRaw.length > MAX_BODY) { return gap('This response is too large for Prisma AIRS to inspect, so it was withheld.', false); }
    if (ctype.indexOf('text/event-stream') !== -1) {
        if (format === 'mcp') {
            if (openStream()) { AIRS3.set('logNote', 'an MCP event-stream reply passes unscanned (allowOpenStreams)'); return done('pass'); }
            return gap('Prisma AIRS does not inspect MCP event-stream replies, so this one was withheld.', false);
        }
        AIRS3.set('stream', 'event-stream-reply');
        return done('scan');
    }
    var respBody = AIRS3.parse(respRaw);
    if (respBody === undefined) {
        // An error reply that is not JSON (an HTML error page, say): MuleSoft's upstream_status.
        if (!ok) { AIRS3.set('logNote', 'a non-2xx reply that is not JSON passes unscanned'); return done('pass'); }
        return gap('Prisma AIRS could not inspect this response (its body is not JSON), so it was withheld.', false);
    }
    if (AIRS3.duplicateKey(respRaw, respBody)) { return gap('Prisma AIRS could not inspect this response (it has duplicate JSON keys), so it was withheld.', false); }
    if (AIRS3.oddProto(respBody)) { return gap('Prisma AIRS could not inspect this response (a member the runtime does not read as one), so it was withheld.', false); }
    return done('scan');
})();

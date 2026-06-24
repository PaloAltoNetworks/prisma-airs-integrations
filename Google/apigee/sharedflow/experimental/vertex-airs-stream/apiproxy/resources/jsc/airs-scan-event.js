// Per-event AIRS scan inside EventFlow.
//
// Strategy: cumulative buffer with a 200-char threshold. Each event's text is
// appended; once we've accumulated 200+ new chars (or finishReason=STOP fires)
// we POST the buffer to AIRS. If AIRS blocks, set a sticky flag and replace
// this + every subsequent event so the client stops receiving content past
// the block point.
//
// Why cumulative vs per-event scan: many jailbreaks/PII leaks span multiple
// SSE chunks, so per-event scanning misses them. The 200-char threshold
// balances scan frequency vs latency.

var BUFFER_THRESHOLD = 200;
var AIRS_TIMEOUT_MS = 4000;
var AIRS_URL = 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request';

var raw = context.getVariable('response.event.current.data') || '';
var blocked = context.getVariable('airs.stream.blocked') === 'true';
var buffer = context.getVariable('airs.stream.buffer') || '';
var sinceLastScan = parseInt(context.getVariable('airs.stream.since.last.scan') || '0', 10);
var count = parseInt(context.getVariable('airs.stream.event.count') || '0', 10);
count = count + 1;

if (blocked) {
    // Sticky gate: suppress every event after the block point.
    context.setVariable('response.event.current.content', '');
    context.setVariable('airs.stream.event.count', String(count));
} else {

    // Strip optional "data:" prefix if EventFlow handed us a raw SSE line.
    var jsonStr = raw;
    if (jsonStr.indexOf('data:') === 0) {
        jsonStr = jsonStr.substring(5).trim();
    } else {
        jsonStr = jsonStr.replace(/^\s+/, '');
    }

    var chunkText = '';
    var finishReason = '';

    if (jsonStr.length > 0 && jsonStr !== '[DONE]') {
        try {
            var parsed = JSON.parse(jsonStr);
            if (parsed.candidates && parsed.candidates.length > 0) {
                var cand = parsed.candidates[0];
                if (cand.content && cand.content.parts) {
                    for (var p = 0; p < cand.content.parts.length; p++) {
                        if (cand.content.parts[p].text) {
                            chunkText += cand.content.parts[p].text;
                        }
                    }
                }
                if (cand.finishReason) {
                    finishReason = cand.finishReason;
                }
            }
        } catch (e) {
            context.setVariable('airs.stream.parse.error', 'event ' + count + ': ' + e.message);
        }
    }

    buffer = buffer + chunkText;
    sinceLastScan = sinceLastScan + chunkText.length;

    var shouldScan = (sinceLastScan >= BUFFER_THRESHOLD) || (finishReason === 'STOP' && buffer.length > 0);

    if (shouldScan) {
        var token = context.getVariable('airs.token') || '';
        var profile = context.getVariable('airs.profile') || '';
        var model = context.getVariable('model') || 'unknown';
        var transactionId = context.getVariable('messageid') || ('stream-' + count);

        var payload = {
            transaction_id: transactionId,
            ai_profile: { profile_name: profile },
            metadata: {
                ai_model: model,
                app_user: 'apigee-shared-flow',
                app_name: 'Apigee-SharedFlow-Stream'
            },
            contents: [{ response: buffer }]
        };

        var req = new Request();
        req.url = AIRS_URL;
        req.method = 'POST';
        req.headers['Content-Type'] = 'application/json';
        req.headers['x-pan-token'] = token;
        req.body = JSON.stringify(payload);

        try {
            var exchange = httpClient.send(req);
            exchange.waitForComplete(AIRS_TIMEOUT_MS);

            if (exchange.isSuccess()) {
                var resp = exchange.getResponse();
                // Apigee Rhino quirk: response body access varies. Try the
                // common patterns until one returns a non-empty string.
                var respBody = '';
                try { if (resp.content && resp.content.asString) { respBody = resp.content.asString; } } catch (eA) {}
                if (!respBody) { try { respBody = String(resp.content); } catch (eB) {} }
                if (!respBody) { try { respBody = resp.body || ''; } catch (eC) {} }

                if (respBody) {
                    try {
                        var verdict = JSON.parse(respBody);
                        if (verdict.action === 'block') {
                            blocked = true;

                            // Map AIRS per-detector booleans to a category label.
                            // (response_detected only — output scans don't populate prompt_detected.)
                            var cat = 'unknown';
                            if (verdict.response_detected) {
                                if (verdict.response_detected.dlp)              cat = 'dlp';
                                else if (verdict.response_detected.malicious_code) cat = 'malicious-code';
                                else if (verdict.response_detected.url_cats)       cat = 'malicious-url';
                                else if (verdict.response_detected.toxic_content)  cat = 'toxic-content';
                                else if (verdict.response_detected.db_security)    cat = 'db-security';
                                else if (verdict.response_detected.ungrounded)     cat = 'ungrounded';
                            }

                            context.setVariable('airs.stream.blocked', 'true');
                            context.setVariable('airs.stream.blocked.at.event', String(count));
                            context.setVariable('airs.stream.blocked.category', cat);
                            context.setVariable('airs.stream.blocked.scan_id', verdict.scan_id || '');

                            // Replace this event with a Vertex-shaped block + STOP so the
                            // client sees a graceful "model stopped" with a clear reason.
                            var blockEvent = {
                                candidates: [{
                                    content: {
                                        role: 'model',
                                        parts: [{ text: '[BLOCKED BY AIRS — category: ' + cat + ', scan_id: ' + (verdict.scan_id || '') + ']' }]
                                    },
                                    finishReason: 'STOP'
                                }],
                                airs: {
                                    action: 'block',
                                    category: cat,
                                    scan_id: verdict.scan_id || ''
                                }
                            };
                            context.setVariable('response.event.current.content', 'data: ' + JSON.stringify(blockEvent) + '\n\n');
                        }
                    } catch (eParse) {
                        context.setVariable('airs.stream.scan.parse.error', eParse.message);
                    }
                }
            } else {
                var err = exchange.getError();
                context.setVariable('airs.stream.scan.error', String(err));
            }
        } catch (eHttp) {
            context.setVariable('airs.stream.scan.error', 'httpClient: ' + eHttp.message);
        }

        sinceLastScan = 0;
    }

    context.setVariable('airs.stream.event.count', String(count));
    context.setVariable('airs.stream.buffer', buffer);
    context.setVariable('airs.stream.since.last.scan', String(sinceLastScan));
    context.setVariable('airs.stream.finish.reason', finishReason);
}

'use strict';
/*
 * MuleSoft ports, group "settings" (core/tests/settings.rs, breaker.rs, cache.rs).
 * v3's rules: settings are flow variables, read strictly; a value v3 can't read refuses with kind 'config' and a message
 * that names the setting, never its value.
 * The circuit breaker, retries, the verdict cache and mcpBatchLimit are not in v3's phase 1, so their MuleSoft tests are
 * not ported.
 * Content: harmless text and the marker AIRSV3-MARKER only. Each case names the recorded reply its callout gets; for a
 * configuration refusal no call should happen at all, so a call is itself a failure.
 */
const S = require('./_shapes');
const R = require('../harness/replies');
const H = require('../harness/apigee');

const KEY = 'lab-key-for-unit-tests';                 // the config map's key in test/run.js
const MARK = 'AIRSV3-MARKER';
const SCAN_URL = 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request';
const UUID = '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d';

function benign() { return S.chat([{ role: 'user', content: 'When does the bakery on the corner open?' }]); }
function on(shape, vars, airs) { return Object.assign(shape, { legs: ['request'], airs: airs || R.answers('allow-prompt'), vars: vars || {} }); }
function kindOf(x) { var m = x && x.flow.messages.response; return m ? m.header('x-airs-kind') : null; }
function parsed(s) { try { return JSON.parse(s); } catch (e) { return null; } }
function profileOf(x) { var s = x.scans[0]; return s && s.ai_profile ? JSON.stringify(s.ai_profile) : 'no scan'; }
// A configuration refusal: refused before any scan, kind config, and the setting named (never its value).
function configRefusal(x, setting) {
    if (!x.fault) { return 'the request was not refused (' + x.calls.length + ' scan)'; }
    if (x.calls.length) { return 'Prisma AIRS was called before the refusal'; }
    if (!x.blocked || kindOf(x) !== 'config') { return 'refused, but not as a configuration problem (x-airs-kind ' + kindOf(x) + ')'; }
    return S.check(String(x.body).indexOf(setting) !== -1, 'the refusal does not name ' + setting + ': ' + x.body);
}

// Near-UUIDs from settings.rs:97: each one is a profile name, sent as written.
const NEAR_UUIDS = [
    ['a digit short', '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5'],
    ['a digit long', '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d6'],
    ['a letter that is not hex', '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5g'],
    ['no hyphens', '1a2b3c4d5e6f4a7b8c9d0e1f2a3b4c5d'],
    ['a misplaced hyphen', '1a2b3c4d5-e6f-4a7b-8c9d-0e1f2a3b4c5d'],
    ['braces around it', '{' + UUID + '}']
];

module.exports = [
    /* ---- the profile: an ID or a name (settings.rs:86, :97) ------------------------------------------------------ */
    {
        finding: 'MS-SET-UUID', title: 'A profile given as a UUID (upper case, padded) is sent lowercased as ai_profile.profile_id',
        setup: on(benign(), { currentProfile: '  ' + UUID.toUpperCase() + '  ' }),
        v3: function (r) {
            var x = r.request;
            if (x.fault || x.calls.length !== 1) { return 'not one scan: ' + (x.body || x.calls.length); }
            return S.check(profileOf(x) === JSON.stringify({ profile_id: UUID }), 'ai_profile is ' + profileOf(x));
        }
    },
    {
        finding: 'MS-SET-UUID', title: 'MCP tools/call: a toolProfile given as a UUID (mixed case) is sent lowercased as ai_profile.profile_id',
        setup: on(S.mcp('tools/call', { name: 'opening_hours', arguments: { shop: 'bakery' } }, 5), { toolProfile: '1A2b3C4d-5E6f-4A7b-8C9d-0E1f2A3b4C5d' }, R.answers('allow-tool')),
        v3: function (r) {
            var x = r.request;
            var c0 = x.scans[0] && x.scans[0].contents && x.scans[0].contents[0];
            if (x.fault || x.calls.length !== 1 || !c0 || !c0.tool_event) { return 'not one tool-event scan: ' + (x.body || x.calls.length); }
            return S.check(profileOf(x) === JSON.stringify({ profile_id: UUID }), 'ai_profile is ' + profileOf(x));
        }
    }
].concat(NEAR_UUIDS.map(function (n) {
    return {
        finding: 'MS-SET-NAME', title: 'A near-UUID (' + n[0] + ') is a profile name, sent as written in ai_profile.profile_name',
        setup: on(benign(), { currentProfile: n[1] }),
        v3: function (r) {
            var x = r.request;
            if (x.fault || x.calls.length !== 1) { return 'not one scan: ' + (x.body || x.calls.length); }
            return S.check(profileOf(x) === JSON.stringify({ profile_name: n[1] }), 'ai_profile is ' + profileOf(x));
        }
    };
})).concat([
    /* ---- the endpoint (settings.rs:172, :216); v3's setting is the host, prismaAirsEndpoint ----------------------- */
    {
        finding: 'MS-SET-EPPATH', title: 'An endpoint that already holds the scan path (host form) refuses every request, naming prismaAirsEndpoint',
        setup: on(benign(), { prismaAirsEndpoint: 'service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request' }),
        v3: function (r) { return configRefusal(r.request, 'prismaAirsEndpoint'); }
    },
    {
        finding: 'MS-SET-EPPATH', title: 'An endpoint that already holds the scan path (MuleSoft\'s full-URL form) refuses every request',
        setup: on(benign(), { prismaAirsEndpoint: SCAN_URL }),
        v3: function (r) { return configRefusal(r.request, 'prismaAirsEndpoint'); }
    },
    {
        finding: 'MS-SET-HTTP', title: 'An http:// endpoint refuses every request, naming prismaAirsEndpoint',
        setup: on(benign(), { prismaAirsEndpoint: 'http://service.api.aisecurity.paloaltonetworks.com' }),
        v3: function (r) { return configRefusal(r.request, 'prismaAirsEndpoint'); }
    },
    {
        finding: 'MS-SET-EP', title: 'The control for the endpoint cases: a regional host (upper case, padded) is read, and the call goes to it over https',
        setup: on(benign(), { prismaAirsEndpoint: ' SERVICE-DE.api.aisecurity.paloaltonetworks.com ' }),
        v3: function (r) {
            var x = r.request;
            if (x.fault || x.calls.length !== 1) { return 'not one scan: ' + (x.body || x.calls.length); }
            return S.check(x.calls[0].url === 'https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request', 'the call went to ' + x.calls[0].url);
        }
    },

    /* ---- scanMessageRoles (settings.rs:244): user turns and tool results always read; an unknown role refuses --- */
    {
        finding: 'MS-SET-ROLES', title: 'scanMessageRoles=tool still scans every user turn (and the tool result), in order, joined with one newline',
        setup: on(S.chat([
            { role: 'system', content: 'You answer questions about the bakery.' },
            { role: 'user', content: MARK + ': when does the bakery open?' },
            { role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', 'function': { name: 'opening_hours', arguments: '{"shop":"bakery"}' } }] },
            { role: 'tool', tool_call_id: 'c1', content: 'Opens at seven, closes at noon.' },
            { role: 'assistant', content: 'It opens at seven.' },
            { role: 'user', content: 'And when does it close?' }
        ]), { scanMessageRoles: 'tool' }),
        v3: function (r) {
            var x = r.request;
            if (x.fault || x.calls.length !== 1) { return 'not one scan: ' + (x.body || x.calls.length); }
            var want = [MARK + ': when does the bakery open?', 'Opens at seven, closes at noon.', 'And when does it close?'].join('\n');
            return S.check(x.scans[0].contents.length === 1 && x.scans[0].contents[0].prompt === want,
                           'the scan text is ' + JSON.stringify(x.scans[0].contents));
        }
    },
    {
        finding: 'MS-SET-ROLES', title: 'A role v3 does not know (user,moderator) refuses every request, naming scanMessageRoles',
        setup: on(benign(), { scanMessageRoles: 'user,moderator' }),
        v3: function (r) { return configRefusal(r.request, 'scanMessageRoles'); }
    },

    /* ---- integers (settings.rs:259) ------------------------------------------------------------------------------ */
    {
        finding: 'MS-SET-INT', title: 'maxScanChars " 3000 " is read: a 3,001-character prompt is refused as too large, without a scan',
        setup: on(S.chat([{ role: 'user', content: S.filler(3001) }]), { maxScanChars: ' 3000 ' }),
        v3: function (r) {
            var x = r.request;
            if (!x.fault || x.calls.length) { return 'the over-limit prompt was ' + (x.calls.length ? 'scanned' : 'let through'); }
            return S.check(x.blocked && kindOf(x) === 'refused' && x.flow.get('airs3.maxScanChars') === '3000',
                           'refused as ' + kindOf(x) + ' with maxScanChars ' + x.flow.get('airs3.maxScanChars'));
        }
    },
    {
        finding: 'MS-SET-INT', title: 'maxScanChars 3000.5 (not whole) refuses every request, naming maxScanChars',
        setup: on(benign(), { maxScanChars: '3000.5' }),
        v3: function (r) { return configRefusal(r.request, 'maxScanChars'); }
    },
    {
        finding: 'MS-SET-INT', title: 'maxScanChars 3000.0 refuses too: v3 reads numbers as decimal integers (MuleSoft accepts a whole float)',
        setup: on(benign(), { maxScanChars: '3000.0' }),
        v3: function (r) { return configRefusal(r.request, 'maxScanChars'); }
    },

    /* ---- null and blank mean unset (settings.rs:154) --------------------------------------------------------------- */
    {
        finding: 'MS-SET-BLANK', title: 'Null, empty and all-blank settings mean unset: every default applies and the scan goes out',
        setup: on(benign(), { failOpen: '', failClosedOnUnknown: '   ', onScanError: null, scanMessageRoles: ' ', maxScanChars: '', truncationFailClosed: '\t',
                              applyDlpMasking: null, forceClaudeCode: '  ', blockStatus: '', appName: ' ', agentId: '', agentVersion: ' ', airsDescriptions: '  ',
                              prismaAirsEndpoint: ' ', currentProfile: '   ', toolProfile: '', scanType: ' ' }),
        v3: function (r) {
            var x = r.request, f = x.flow;
            if (x.fault) { return 'a blank setting refused the request: ' + x.body; }
            if (x.calls.length !== 1) { return 'no scan'; }
            var want = { failOpen: 'false', onScanError: 'block', scanRoles: 'user', maxScanChars: '100000', truncFailClosed: 'true', applyMask: 'false',
                         forceCC: 'false', blockMode: 'native', appName: 'Gateway', endpoint: 'service.api.aisecurity.paloaltonetworks.com',
                         profile: 'PROFILE_NAME', toolProfile: 'PROFILE_NAME' };
            var off = Object.keys(want).filter(function (k) { return f.get('airs3.' + k) !== want[k]; })
                .map(function (k) { return k + '=' + f.get('airs3.' + k); });
            if (off.length) { return 'not the default: ' + off.join(', '); }
            var sb = x.scans[0];
            return S.check(x.calls[0].url === SCAN_URL && profileOf(x) === JSON.stringify({ profile_name: 'PROFILE_NAME' }) &&
                           sb.metadata.app_name === 'Apigee-Gateway' && sb.metadata.agent_meta === undefined,
                           'the scan did not carry the defaults: ' + x.calls[0].url + ' ' + JSON.stringify(sb.ai_profile) + ' ' + JSON.stringify(sb.metadata));
        }
    },
    {
        finding: 'MS-SET-BLANK', title: 'A blank apiFormat parameter means unset: the Chat Completions path decides and the prompt is scanned',
        setup: on(S.chat([{ role: 'user', content: MARK + ': when does the bakery open?' }]), { apiFormat: '   ' }),
        v3: function (r) {
            var x = r.request;
            return S.check(!x.fault && x.calls.length === 1 && S.has(x, MARK), 'a blank apiFormat ' + (x.fault ? 'refused the request: ' + x.body : 'did not lead to a scan'));
        }
    },

    /* ---- a configuration error names the setting, never a value or the key (settings.rs:266) ---------------------- */
    {
        finding: 'MS-SET-NOKEY', title: 'Two broken settings: the refusal and the log line name one setting, never a value, never the key',
        setup: on(benign(), { failOpen: MARK, maxScanChars: MARK + ' 12' }),
        v3: function (r) {
            var x = r.request;
            if (!x.fault || x.calls.length || !x.blocked || kindOf(x) !== 'config') { return 'not a configuration refusal before any scan (kind ' + kindOf(x) + ')'; }
            var resp = x.flow.messages.response;
            var seen = [x.body, JSON.stringify(resp.headers), JSON.stringify(x.flow.logs), String(x.flow.get('airs3.refuseMsg'))].join('\n');
            if (seen.indexOf(MARK) !== -1) { return 'a setting\'s value reached the client or the log'; }
            if (seen.indexOf(KEY) !== -1) { return 'the key reached the client or the log'; }
            var named = ['failOpen', 'maxScanChars'].filter(function (n) { return x.body.indexOf(n) !== -1; });
            if (named.length !== 1) { return 'the refusal names ' + named.length + ' settings, not one: ' + x.body; }
            var leaks = H.keyLeaks(x.flow, KEY);
            return S.check(leaks.length === 0, 'the key sits in ' + leaks.join(', '));
        }
    },

    /* ---- how a rejected configuration is answered (the refusal behind settings.rs:172 and :216) -------------------- */
    {
        finding: 'MS-SET-CFG', title: 'MCP: a rejected setting (an http:// endpoint) is a JSON-RPC error -32003 with the request id as sent, in HTTP 200',
        setup: on(S.mcp('tools/call', { name: 'opening_hours', arguments: { shop: 'bakery' } }, 'call-7'),
                  { prismaAirsEndpoint: 'http://service.api.aisecurity.paloaltonetworks.com' }, R.answers('allow-tool')),
        v3: function (r) {
            var x = r.request, b = parsed(x.body);
            if (!x.fault || x.calls.length) { return 'not refused before any scan'; }
            return S.check(x.blocked && x.status === 200 && kindOf(x) === 'config' && b && b.jsonrpc === '2.0' && b.id === 'call-7' && b.error && b.error.code === -32003,
                           'got HTTP ' + x.status + ', x-airs-kind ' + kindOf(x) + ': ' + x.body);
        }
    },
    {
        finding: 'MS-SET-CFG', title: 'Chat Completions: a rejected setting is answered in the client\'s own format (HTTP 200, x-airs-kind: config)',
        setup: on(benign(), { prismaAirsEndpoint: 'service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request' }),
        v3: function (r) {
            var x = r.request, b = parsed(x.body);
            if (!x.fault || x.calls.length) { return 'not refused before any scan'; }
            var text = b && b.choices && b.choices[0] && b.choices[0].message ? String(b.choices[0].message.content) : '';
            return S.check(x.blocked && x.status === 200 && kindOf(x) === 'config' && !!b && b.object === 'chat.completion' && text.indexOf('prismaAirsEndpoint') !== -1,
                           'got HTTP ' + x.status + ', x-airs-kind ' + kindOf(x) + ': ' + x.body);
        }
    }
]);

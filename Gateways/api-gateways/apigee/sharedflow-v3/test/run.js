#!/usr/bin/env node
'use strict';
/*
 * The v3 unit suite. Every case runs a SharedFlow bundle under the harness and checks one of two things:
 * which text reaches the scan, or what the flow does with a recorded Prisma AIRS reply.
 *   node test/run.js            V2's bundle (the "before"): each case's v2 expectation, the finding as MIGRATION.md states it
 *   node test/run.js --v3       v3's bundle: each case's v3 expectation
 *   node test/run.js --only A01 one finding;  --file 10-request-text.js one case file
 * A case passes on V2 when V2 shows the finding; the harness is trusted only if every Probe finding shows on V2.
 */
const fs = require('fs');
const path = require('path');
const H = require('./harness/apigee');

const ROOT = path.join(__dirname, '..');
// Two layouts: the published folder (sharedflow-v3/ next to V2's sharedflow/) and the lab's working copy.
function first(paths) { for (var i = 0; i < paths.length; i++) { if (fs.existsSync(paths[i])) { return paths[i]; } } return paths[0]; }
const BUNDLES = {
    v2: first([path.join(ROOT, '..', 'sharedflow', 'PANW-AIRS', 'sharedflowbundle'),
               path.join(ROOT, 'lab', 'build-upstream', 'Google', 'apigee', 'sharedflow', 'PANW-AIRS', 'sharedflowbundle')]),
    v3: first([path.join(ROOT, 'PANW-AIRS', 'sharedflowbundle'), path.join(ROOT, 'src', 'PANW-AIRS', 'sharedflowbundle')])
};
const KEY = 'lab-key-for-unit-tests';

const args = process.argv.slice(2);
const which = args.indexOf('--v3') >= 0 ? 'v3' : 'v2';
const only = args.indexOf('--only') >= 0 ? args[args.indexOf('--only') + 1] : null;
const onlyFile = args.indexOf('--file') >= 0 ? args[args.indexOf('--file') + 1] : null;

/* What a case gets to look at. */
function result(flow) {
    var calls = flow.calls.map(function (c) { try { return JSON.parse(c.body); } catch (e) { return null; } });
    function textOf(scan) {
        var out = [];
        (scan && scan.contents || []).forEach(function (c) {
            if (c.prompt) { out.push(c.prompt); }
            if (c.response) { out.push(c.response); }
            if (c.tool_event) { out.push(String(c.tool_event.input || '')); if (c.tool_event.output) { out.push(String(c.tool_event.output)); } }
        });
        return out.join('\n');
    }
    var resp = flow.messages.response;
    return {
        flow: flow,
        calls: flow.calls,
        scans: calls,
        scanned: calls.map(textOf).join('\n'),           // every text sent to Prisma AIRS, on this leg
        outcome: flow.get('airs.outcome'),
        fault: flow.fault,
        blocked: !!(flow.fault && resp && resp.header('x-airs-blocked') === 'true'),
        status: resp ? resp.status : null,
        contentType: resp ? resp.header('Content-Type') : null,
        body: resp ? String(resp.content) : null,
        request: flow.messages.request,
        route: flow.get('airs3.route'),
        // this leg's or run's own counts, read when it ends: the next leg on the same flow sets them again
        cachedScans: parseInt(flow.get('airs3.cachedScans'), 10) || 0,
        scansRan: parseInt(flow.get('airs3.scansRan'), 10) || 0
    };
}

/* The FlowCallout's parameters on one leg: `type` as a proxy would set it, unless the case changes it (null: not set). */
function params(s, leg, type) {
    var p = { type: type }, extra = (s.params && s.params[leg]) || {};
    for (var k in extra) { if (extra[k] === null) { delete p[k]; } else { p[k] = extra[k]; } }
    return p;
}

/* Run one leg, or both: the request leg first, then, if it didn't stop, the reply leg on the same flow. */
function run(bundle, c) {
    var s = c.setup;
    var kvm = {}; kvm[s.map || 'airs-config'] = Object.assign({ airs_token: KEY, airs_profile: 'PROFILE_NAME' }, s.kvm || {});
    var airs = s.airsFor ? s.airsFor[which] : s.airs;
    var vars = Object.assign({}, s.vars || {}, (s.varsFor && s.varsFor[which]) || {});
    var flow = H.newFlow({ mode: which === 'v3' ? 'strict' : 'apigee', pathsuffix: s.path, request: s.request, kvm: kvm,
                           airs: typeof airs === 'function' && airs.length === 0 && airs.fresh ? airs() : airs, vars: vars, proxyName: s.proxyName,
                           cache: s.cache });
    var out = {};
    // Several runs of the SharedFlow on one flow, in order (phase 3): a flow hook's run and a FlowCallout's on the same leg.
    // Each run gives its own parameters; the reply is set before the first run on the reply leg.
    if (s.runs) {
        out.runs = [];
        s.runs.forEach(function (one) {
            if (flow.fault) { out.runs.push(null); return; }
            if (one.leg === 'response' && !flow.messages.response) { H.setResponse(flow, s.response); }
            flow.calls = [];
            var logsBefore = flow.logs.length;
            if (typeof one.before === 'function') { one.before(flow); }        // what the proxy changes between two runs
            H.runSharedFlow(bundle, flow, one.leg, one.params);
            var x = result(flow);
            x.lines = flow.logs.slice(logsBefore).map(function (l) { try { return JSON.parse(l.line); } catch (e) { return null; } });
            out.runs.push(x);
        });
        return out;
    }
    if (s.legs.indexOf('request') >= 0) {
        H.runSharedFlow(bundle, flow, 'request', params(s, 'request', 'user-prompt'));
        out.request = result(flow);
    }
    if (s.legs.indexOf('response') >= 0 && !flow.fault) {
        flow.calls = [];
        if (typeof s.beforeResponse === 'function') { s.beforeResponse(flow); }      // what the platform changes between the legs (live G2)
        H.setResponse(flow, s.response);
        H.runSharedFlow(bundle, flow, 'response', params(s, 'response', 'response-prompt'));
        out.response = result(flow);
    }
    return out;
}

function loadCases() {
    var dir = path.join(__dirname, 'cases');
    return fs.readdirSync(dir).filter(function (f) { return f.endsWith('.js') && f.charAt(0) !== '_' && (!onlyFile || f === onlyFile); }).sort()
        .reduce(function (all, f) { return all.concat(require(path.join(dir, f))); }, []);
}

function main() {
    if (!fs.existsSync(BUNDLES[which])) { console.log('no ' + which + ' bundle yet at ' + BUNDLES[which]); process.exit(2); }
    var bundle = new H.Bundle(BUNDLES[which]);
    var cases = loadCases().filter(function (c) { return !only || c.finding === only; });
    var pass = 0, fail = 0, skipped = 0;
    cases.forEach(function (c) {
        var expect = c[which];
        if (!expect) { skipped++; return; }
        var verdict;
        try {
            var r = run(bundle, c);
            verdict = expect(r);
        // v3's invariant: no leg ends silently. Each one scans, refuses, or passes on an explicit route; a leg or run whose
        // every scan was answered by the verdict cache (phase 3) was scanned earlier, and is logged as cached. Each is judged
        // by its own counts (result() reads them when it ends).
        if (which === 'v3' && verdict === true) {
            var silent = function (x) { return x && !x.fault && x.calls.length === 0 && x.route !== 'pass' && !(x.cachedScans > 0 && x.cachedScans === x.scansRan); };
            ['request', 'response'].forEach(function (leg) {
                if (silent(r[leg])) { verdict = 'the ' + leg + ' leg ended with no scan, no refusal and no pass'; }
            });
            (r.runs || []).forEach(function (x, i) {
                if (silent(x)) { verdict = 'run ' + (i + 1) + ' ended with no scan, no refusal and no pass'; }
            });
        }
        } catch (e) { verdict = 'error: ' + (e && e.message); }
        var ok = verdict === true;
        if (ok) { pass++; } else { fail++; }
        console.log((ok ? 'PASS ' : 'FAIL ') + c.finding + '  ' + c.title + (ok ? '' : '\n       ' + verdict));
    });
    console.log('\n' + which + ': ' + pass + ' pass, ' + fail + ' fail' + (skipped ? ', ' + skipped + ' with no ' + which + ' expectation' : ''));
    process.exit(fail ? 1 : 0);
}

module.exports = { result: result, run: run, BUNDLES: BUNDLES };
if (require.main === module) { main(); }

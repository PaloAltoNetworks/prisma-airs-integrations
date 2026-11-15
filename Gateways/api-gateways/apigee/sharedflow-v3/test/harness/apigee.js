'use strict';
/*
 * An offline Apigee for the PANW-AIRS SharedFlow (finding A32).
 *
 * It runs a SharedFlow bundle the way the lab's Apigee did (runtime 1-18-0-apigee-8; the platform facts in VERIFICATION.md):
 *   - the steps of sharedflows/default.xml, in order, with their conditions;
 *   - each policy from its own XML: Javascript (IncludeURL, ResourceURL, Properties, timeLimit, continueOnError),
 *     KeyValueMapOperations (Get), AssignMessage, ServiceCallout, ExtractVariables (JSONPayload), RaiseFault,
 *     MessageLogging, and LookupCache and PopulateCache on one store per test, which a test may fill first (L19: inside a
 *     SharedFlow every scope is shared, so the scope is not modelled; an expiry is a value or a variable, not both);
 *   - flow variables with the rules measured live (L6): once `x` holds a value, setting `x.y` is silently dropped (mode
 *     "apigee"); mode "strict" throws on any name that extends another, in either order, so v3's code is held to the
 *     design's rule;
 *   - messages (request, response, and those AssignMessage creates) with headers, content, status, verb and path;
 *   - a ServiceCallout that answers from the test's responder: recorded Prisma AIRS replies, or no answer.
 * What it can't know is marked in the code. The live lab stays the judge.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');
const X = require('./xml');

/* ------------------------------------------------------------------ messages */
function Message(init) {
    init = init || {};
    this.headers = {};                       // lower-case name -> { name, value }
    var h = init.headers || {};
    for (var k in h) { this.headers[k.toLowerCase()] = { name: k, value: String(h[k]) }; }
    this.content = init.content === undefined ? '' : init.content;
    this.status = init.status === undefined ? null : init.status;
    this.reason = init.reason || null;
    this.verb = init.verb || null;
    this.path = init.path || null;
    this.querystring = init.querystring || '';
}
Message.prototype.header = function (n) { var e = this.headers[n.toLowerCase()]; return e ? e.value : null; };
Message.prototype.setHeader = function (n, v) { this.headers[n.toLowerCase()] = { name: n, value: String(v) }; };
Message.prototype.removeHeader = function (n) { delete this.headers[n.toLowerCase()]; };
Message.prototype.queryparam = function (q) {
    var parts = String(this.querystring || '').split('&');
    for (var i = 0; i < parts.length; i++) {
        var kv = parts[i].split('=');
        if (decodeURIComponent(kv[0] || '') === q) { return decodeURIComponent((kv.slice(1).join('=') || '').replace(/\+/g, ' ')); }
    }
    return null;
};

/* --------------------------------------------------------------------- flow */
const VAR_NAME = /^[A-Za-z_][A-Za-z0-9_.\-]*$/;
const MESSAGE_PARTS = ['content', 'header', 'headers', 'status', 'reason', 'verb', 'path', 'querystring', 'queryparam', 'uri'];

function Flow(opts) {
    opts = opts || {};
    this.mode = opts.mode || 'apigee';
    this.vars = new Map();
    this.messages = { request: new Message(opts.request) };
    this.messages.request.verb = this.messages.request.verb || 'POST';
    this.leg = 'request';
    this.fault = null;
    this.events = [];                         // dropped sets, policy runs, faults: for assertions
    this.logs = [];                           // MessageLogging lines
    this.calls = [];                          // ServiceCallout requests, as sent
    this.kvm = opts.kvm || {};
    this.responder = opts.airs || null;
    this.cache = {};                          // LookupCache / PopulateCache: key -> { value, expires (ms, or null) }
    var seed = opts.cache || {};
    for (var ck in seed) {
        var sv = seed[ck];
        this.cache[ck] = (sv && typeof sv === 'object') ? { value: String(sv.value), expires: sv.ttl ? Date.now() + sv.ttl * 1000 : null } : { value: String(sv), expires: null };
    }
    var sys = {
        'organization.name': 'lab-org', 'environment.name': 'lab-env', 'apiproxy.name': opts.proxyName || 'lab-proxy',
        'proxy.pathsuffix': opts.pathsuffix || '', 'proxy.basepath': opts.basepath || '/lab',
        'messageid': opts.messageid || 'rrt-lab-' + nodeCrypto.randomBytes(6).toString('hex'),
        'client.ip': opts.clientIp || '10.40.0.3', 'system.timestamp': String(Date.now())
    };
    for (var k in sys) { this.vars.set(k, sys[k]); }
    var extra = opts.vars || {};
    for (var e in extra) { this.vars.set(e, extra[e]); }
}

Flow.prototype.message = function (name) {
    if (name === 'message') { return this.leg === 'response' ? this.messages.response : this.messages.request; }
    return this.messages[name] || null;
};

// "request.header.X" -> ['request', 'header', 'X']; null when the name isn't a message part.
Flow.prototype.splitMessageRef = function (name) {
    var dot = name.indexOf('.');
    if (dot < 0) { return null; }
    var head = name.slice(0, dot);
    if (head !== 'message' && !(head in this.messages)) { return null; }
    var rest = name.slice(dot + 1);
    var d2 = rest.indexOf('.');
    var part = d2 < 0 ? rest : rest.slice(0, d2);
    if (MESSAGE_PARTS.indexOf(part) < 0) { return null; }
    return [head, part, d2 < 0 ? null : rest.slice(d2 + 1)];
};

Flow.prototype.get = function (name) {
    if (name === 'request.uri') {
        var rq = this.messages.request;
        return (this.vars.get('proxy.basepath') || '') + (this.vars.get('proxy.pathsuffix') || '') + (rq.querystring ? '?' + rq.querystring : '');
    }
    var ref = this.splitMessageRef(name);
    if (ref) {
        var m = this.message(ref[0]);
        if (!m) { return null; }
        switch (ref[1]) {
            case 'content': return m.content;
            case 'header': return ref[2] ? m.header(ref[2]) : null;
            case 'headers': return ref[2] === 'names' ? Object.keys(m.headers).map(function (k) { return m.headers[k].name; }).join(',') : null;
            case 'status': return (ref[2] === 'code' && m.status !== null) ? String(m.status) : null;
            case 'reason': return ref[2] === 'phrase' ? m.reason : null;
            case 'verb': return m.verb;
            case 'path': return m.path;
            case 'querystring': return m.querystring || null;
            case 'queryparam': return ref[2] ? m.queryparam(ref[2]) : null;
            case 'uri': return m.path;
        }
    }
    return this.vars.has(name) ? this.vars.get(name) : null;
};

// set() is what the bundle does (JavaScript, AssignMessage, ExtractVariables, config-map reads); sys() is the runtime.
Flow.prototype.set = function (name, value, by) {
    if (!VAR_NAME.test(name)) { throw new Error('bad variable name: ' + name); }
    var ref = this.splitMessageRef(name);
    if (ref) {
        var m = this.message(ref[0]);
        if (!m) { throw new Error('no message ' + ref[0] + ' for ' + name); }
        if (ref[1] === 'content') { m.content = value === null || value === undefined ? '' : String(value); return; }
        if (ref[1] === 'header' && ref[2]) { if (value === null) { m.removeHeader(ref[2]); } else { m.setHeader(ref[2], value); } return; }
        if (ref[1] === 'status' && ref[2] === 'code') { m.status = Number(value); return; }
        if (ref[1] === 'reason' && ref[2] === 'phrase') { m.reason = String(value); return; }
        if (ref[1] === 'verb') { m.verb = String(value); return; }
        throw new Error('the harness does not set ' + name);
    }
    // L6: a name that extends one already set is dropped. Strict mode holds v3 to its naming rule.
    var self = this, parent = null, child = null;
    this.vars.forEach(function (v, k) {
        if (v === null || v === undefined || self.isSystem(k)) { return; }
        if (name.indexOf(k + '.') === 0) { parent = k; }
        if (k.indexOf(name + '.') === 0) { child = k; }
    });
    if (this.mode === 'strict' && (parent || child)) {
        throw new Error('variable ' + name + ' and ' + (parent || child) + ': no name may extend another (design 6.1, L6)');
    }
    if (parent) { this.events.push({ type: 'dropped-set', name: name, parent: parent, by: by }); return; }
    if (value === undefined) { value = null; }
    this.vars.set(name, value);
};
Flow.prototype.sys = function (name, value) { this.vars.set(name, value); };
Flow.prototype.isSystem = function (k) {
    return /^(organization|environment|apiproxy|proxy|messageid|client|system|servicecallout|error|fault)\b/.test(k);
};
Flow.prototype.remove = function (name) { this.vars.delete(name); };

/* --------------------------------------------------------------- templates */
function render(flow, tpl, opts) {
    opts = opts || {};
    var pre = opts.prefix || '{', suf = opts.suffix || '}';
    var out = '', i = 0, unresolved = [];
    while (i < tpl.length) {
        var a = tpl.indexOf(pre, i);
        if (a < 0) { out += tpl.slice(i); break; }
        var b = tpl.indexOf(suf, a + pre.length);
        if (b < 0) { out += tpl.slice(i); break; }
        var name = tpl.slice(a + pre.length, b);
        if (!VAR_NAME.test(name)) { out += tpl.slice(i, a + pre.length); i = a + pre.length; continue; }   // a literal brace
        out += tpl.slice(i, a);
        var v = flow.get(name);
        if (v === null || v === undefined) { unresolved.push(name); v = ''; }
        out += String(v);
        i = b + suf.length;
    }
    if (unresolved.length && opts.strict) { var e = new Error('Unresolved variable : ' + unresolved[0]); e.unresolved = unresolved; throw e; }
    return out;
}

/* -------------------------------------------------------------- conditions */
function evalCondition(flow, src) {
    var toks = [], re = /\s*(\(|\)|!=|==|=|"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z0-9_.\-]*|\d+)/y, m, pos = 0;
    src = src.trim();
    while (pos < src.length) {
        re.lastIndex = pos;
        m = re.exec(src);
        if (!m) { throw new Error('condition: cannot read "' + src.slice(pos) + '" in: ' + src); }
        toks.push(m[1]);
        pos = re.lastIndex;
        while (pos < src.length && /\s/.test(src[pos])) { pos++; }
    }
    var k = 0;
    function peek() { return toks[k]; }
    function next() { return toks[k++]; }
    function operand() {
        var t = next();
        if (t === undefined) { throw new Error('condition ends early: ' + src); }
        if (t[0] === '"') { return { lit: JSON.parse(t) }; }
        if (/^\d+$/.test(t)) { return { lit: t }; }
        if (t === 'null') { return { lit: null }; }
        if (t === 'true' || t === 'false') { return { lit: t }; }
        return { ref: t };
    }
    function val(o) { return o.lit !== undefined ? o.lit : flow.get(o.ref); }
    function cmp() {
        if (peek() === '(') { next(); var v = orx(); if (next() !== ')') { throw new Error('condition: missing ) in ' + src); } return v; }
        if (peek() === 'not' || peek() === 'NOT') { next(); return !cmp(); }
        var left = operand();
        var op = peek();
        if (op === '=' || op === '==' || op === '!=' || op === 'equals' || op === 'notequals' || op === 'Equals' || op === 'NotEquals') {
            next();
            var right = operand(), l = val(left), r = val(right);
            var eq = (l === null || l === undefined || r === null || r === undefined) ? (l == null && r == null) : String(l) === String(r);
            return (op === '!=' || op === 'notequals' || op === 'NotEquals') ? !eq : eq;
        }
        var v1 = val(left);
        return !(v1 === null || v1 === undefined || v1 === false || v1 === 'false' || v1 === '');
    }
    function andx() { var v = cmp(); while (peek() === 'and' || peek() === 'AND') { next(); var w = cmp(); v = v && w; } return v; }
    function orx() { var v = andx(); while (peek() === 'or' || peek() === 'OR') { next(); var w = andx(); v = v || w; } return v; }
    var result = orx();
    if (k !== toks.length) { throw new Error('condition: unexpected "' + toks[k] + '" in: ' + src); }
    return result;
}

/* ---------------------------------------------------------------- jsonpath */
function jsonPath(obj, expr) {
    if (expr.trim() === '$') { return { found: true, value: obj }; }
    var m = /^\$((?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\]|\['[^']+'\])+)$/.exec(expr.trim());
    if (!m) { throw new Error('jsonpath not supported by the harness: ' + expr); }
    var cur = obj, re = /\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]|\['([^']+)'\]/g, s;
    while ((s = re.exec(m[1])) !== null) {
        if (cur === null || typeof cur !== 'object') { return { found: false }; }
        var key = s[1] !== undefined ? s[1] : (s[2] !== undefined ? Number(s[2]) : s[3]);
        if (!(key in cur)) { return { found: false }; }
        cur = cur[key];
    }
    return { found: true, value: cur };
}

/* ---------------------------------------------------------------- policies */
function Bundle(dir) {
    this.dir = dir;
    var root = fs.readdirSync(dir).find(function (f) { return f.endsWith('.xml'); });
    this.descriptor = root ? X.parse(fs.readFileSync(path.join(dir, root), 'utf8')) : null;
    this.flow = X.parse(fs.readFileSync(path.join(dir, 'sharedflows', 'default.xml'), 'utf8'));
    this.policies = {};
    var pdir = path.join(dir, 'policies');
    var self = this;
    fs.readdirSync(pdir).forEach(function (f) {
        if (f.endsWith('.xml')) { var p = X.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); self.policies[p.attrs.name] = p; }
    });
    this.jsc = {};
    var jdir = path.join(dir, 'resources', 'jsc');
    if (fs.existsSync(jdir)) { fs.readdirSync(jdir).forEach(function (f) { self.jsc[f] = fs.readFileSync(path.join(jdir, f), 'utf8'); }); }
}
Bundle.prototype.name = function () { return this.descriptor ? this.descriptor.attrs.name : path.basename(this.dir); };
Bundle.prototype.steps = function () {
    return X.kids(this.flow, 'Step').map(function (s) { return { name: X.text(X.kid(s, 'Name')), cond: X.text(X.kid(s, 'Condition')) }; });
};

function bool(attr, dflt) { return attr === undefined ? dflt : String(attr).trim() === 'true'; }

function raise(flow, policyName, faultName, status, body, kind) {
    flow.fault = { policy: policyName, name: faultName, kind: kind || 'error' };
    flow.messages.response = flow.messages.response || new Message({});
    var r = flow.messages.response;
    r.status = status;
    r.content = body;
    r.setHeader('Content-Type', 'application/json');
    flow.events.push({ type: 'fault', policy: policyName, name: faultName });
}

const runners = {
    Javascript: function (flow, b, p) {
        var coe = bool(p.attrs.continueOnError, false);
        var limit = p.attrs.timeLimit ? Number(p.attrs.timeLimit) : null;
        var code = X.kids(p, 'IncludeURL').map(function (inc) { return b.jsc[X.text(inc).replace('jsc://', '')]; }).join('\n');
        var res = X.text(X.kid(p, 'ResourceURL')).replace('jsc://', '');
        if (b.jsc[res] === undefined) { throw new Error('missing resource ' + res); }
        code += '\n' + b.jsc[res];
        var props = {};
        X.kids(X.kid(p, 'Properties'), 'Property').forEach(function (pr) { props[pr.attrs.name] = X.text(pr); });
        var ctx = {
            getVariable: function (n) { return flow.get(n); },
            setVariable: function (n, v) { flow.set(n, v, p.attrs.name); },
            removeVariable: function (n) { flow.remove(n); }
        };
        var sandbox = {
            context: ctx, properties: props, print: function () {},
            crypto: { getSHA256: function () { var buf = ''; return { update: function (s) { buf += s; }, digest: function () { return nodeCrypto.createHash('sha256').update(buf, 'utf8').digest('hex'); }, digest64: function () { return nodeCrypto.createHash('sha256').update(buf, 'utf8').digest('base64'); } }; } }
        };
        vm.createContext(sandbox);
        try {
            vm.runInContext(code, sandbox, limit ? { timeout: limit, filename: res } : { filename: res });
        } catch (e) {
            var timedOut = /Script execution timed out/.test(String(e && e.message));
            var msg = timedOut ? 'Javascript runtime exceeded limit of ' + limit + 'ms' : String(e && e.message);
            flow.events.push({ type: 'js-error', policy: p.attrs.name, message: msg });
            if (!coe) {
                raise(flow, p.attrs.name, 'steps.javascript.ScriptExecutionFailed', 500,
                    JSON.stringify({ fault: { faultstring: 'Execution of ' + p.attrs.name + ' failed with error: ' + msg, detail: { errorcode: 'steps.javascript.ScriptExecutionFailed' } } }));
            }
            // L2: with continueOnError=true the flow goes on and error.message stays empty.
        }
    },

    KeyValueMapOperations: function (flow, b, p) {
        var map = flow.kvm[p.attrs.mapIdentifier];
        if (!map) { throw new Error('the test gave no config map named ' + p.attrs.mapIdentifier); }
        X.kids(p, 'Get').forEach(function (g) {
            var key = X.text(X.path(g, ['Key', 'Parameter']));
            var v = Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
            if (v !== null) { flow.set(g.attrs.assignTo, v, p.attrs.name); }
        });
    },

    AssignMessage: function (flow, b, p) {
        var ignore = X.text(X.kid(p, 'IgnoreUnresolvedVariables')) !== 'false';
        var at = X.kid(p, 'AssignTo');
        var target;
        if (at && X.text(at)) {
            var mname = X.text(at);
            // A new response message has status 200 and no body on Apigee (measured, VERIFICATION L14), so a callout that
            // later gets no answer leaves 200 there, with its failed flag true.
            if (at.attrs.createNew === 'true' || !flow.messages[mname]) { flow.messages[mname] = new Message(at.attrs.type === 'response' ? { status: 200 } : {}); }
            target = flow.messages[mname];
        } else if (at && at.attrs.type === 'response') {
            target = flow.messages.response = flow.messages.response || new Message({});
        } else if (at && at.attrs.type === 'request') {
            target = flow.messages.request;
        } else {
            target = flow.leg === 'response' ? flow.messages.response : flow.messages.request;
        }
        function r(node) { return render(flow, X.text(node) || '', { prefix: node.attrs.variablePrefix, suffix: node.attrs.variableSuffix, strict: !ignore }); }
        X.kids(X.path(p, ['Remove', 'Headers']), 'Header').forEach(function (h) { target.removeHeader(h.attrs.name); });
        var set = X.kid(p, 'Set');
        if (set) {
            X.kids(X.kid(set, 'Headers'), 'Header').forEach(function (h) { target.setHeader(h.attrs.name, r(h)); });
            var pl = X.kid(set, 'Payload');
            if (pl) { target.content = r(pl); if (pl.attrs.contentType) { target.setHeader('Content-Type', pl.attrs.contentType); } }
            if (X.kid(set, 'Verb')) { target.verb = r(X.kid(set, 'Verb')); }
            if (X.kid(set, 'StatusCode')) { target.status = Number(r(X.kid(set, 'StatusCode'))); }
            if (X.kid(set, 'ReasonPhrase')) { target.reason = r(X.kid(set, 'ReasonPhrase')); }
        }
        X.kids(p, 'AssignVariable').forEach(function (av) {
            var name = X.text(X.kid(av, 'Name')), v = null;
            if (X.kid(av, 'Ref')) { v = flow.get(X.text(X.kid(av, 'Ref'))); }
            if (X.kid(av, 'Template')) {
                var t = X.kid(av, 'Template');
                v = t.attrs.ref ? render(flow, String(flow.get(t.attrs.ref) || ''), {}) : r(t);
            }
            if (v === null && X.kid(av, 'Value')) { v = X.text(X.kid(av, 'Value')); }
            flow.set(name, v, p.attrs.name);
        });
    },

    ServiceCallout: function (flow, b, p) {
        var coe = bool(p.attrs.continueOnError, false);
        var name = p.attrs.name;
        var reqNode = X.kid(p, 'Request');
        var reqMsg = flow.messages[reqNode.attrs.variable];
        if (!reqMsg) { reqMsg = flow.messages[reqNode.attrs.variable] = new Message({}); }
        var respVar = X.text(X.kid(p, 'Response'));
        var url = render(flow, X.text(X.path(p, ['HTTPTargetConnection', 'URL'])), {});
        var ssl = X.path(p, ['HTTPTargetConnection', 'SSLInfo']);
        var call = {
            policy: name, url: url, verb: reqMsg.verb || 'POST', timeout: Number(X.text(X.kid(p, 'Timeout')) || 55000),
            enforce: !!(ssl && X.text(X.kid(ssl, 'Enforce')) === 'true'),
            headers: Object.keys(reqMsg.headers).reduce(function (o, k) { o[reqMsg.headers[k].name] = reqMsg.headers[k].value; return o; }, {}),
            body: reqMsg.content
        };
        flow.calls.push(call);
        var reply = flow.responder ? flow.responder(call, flow) : { noAnswer: 'no responder' };
        var failed;
        if (!reply || reply.noAnswer) {
            failed = true;                                  // L10: no status at all
        } else {
            flow.messages[respVar] = new Message({ status: reply.status, headers: reply.headers || { 'Content-Type': 'application/json' },
                content: typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body) });
            failed = !(reply.status >= 100 && reply.status < 400);
        }
        flow.sys('servicecallout.' + name + '.failed', failed ? 'true' : 'false');
        if (failed && !coe) {
            raise(flow, name, 'steps.servicecallout.ExecutionFailed', 500,
                JSON.stringify({ fault: { faultstring: 'Execution of ServiceCallout ' + name + ' failed.', detail: { errorcode: 'steps.servicecallout.ExecutionFailed' } } }));
        }
    },

    ExtractVariables: function (flow, b, p) {
        var src = X.text(X.kid(p, 'Source')) || 'message';
        var prefix = X.text(X.kid(p, 'VariablePrefix'));
        var ignore = X.text(X.kid(p, 'IgnoreUnresolvedVariables')) === 'true';
        var content = flow.get(src + '.content');
        var obj;
        try { obj = JSON.parse(content); } catch (e) {
            // Not measured live (A16): the harness assumes ExtractVariables sets nothing on a body that isn't JSON.
            flow.events.push({ type: 'ev-not-json', policy: p.attrs.name });
            return;
        }
        X.kids(X.kid(p, 'JSONPayload'), 'Variable').forEach(function (v) {
            var res = jsonPath(obj, X.text(X.kid(v, 'JSONPath')));
            var vname = prefix ? prefix + '.' + v.attrs.name : v.attrs.name;
            if (!res.found || res.value === null) { if (!ignore) { raise(flow, p.attrs.name, 'steps.extractvariables.UnresolvedVariable', 500, '{}'); } return; }
            var val = (typeof res.value === 'object') ? JSON.stringify(res.value) : String(res.value);
            flow.set(vname, val, p.attrs.name);
        });
    },

    RaiseFault: function (flow, b, p) {
        var set = X.path(p, ['FaultResponse', 'Set']);
        var r = new Message({});
        if (set) {
            X.kids(X.kid(set, 'Headers'), 'Header').forEach(function (h) { r.setHeader(h.attrs.name, render(flow, X.text(h) || '', {})); });
            var pl = X.kid(set, 'Payload');
            if (pl) { r.content = render(flow, X.text(pl) || '', { prefix: pl.attrs.variablePrefix, suffix: pl.attrs.variableSuffix }); if (pl.attrs.contentType && !r.header('Content-Type')) { r.setHeader('Content-Type', pl.attrs.contentType); } }
            var sc = X.kid(set, 'StatusCode');
            r.status = sc ? Number(render(flow, X.text(sc), {})) : 500;
            if (X.kid(set, 'ReasonPhrase')) { r.reason = render(flow, X.text(X.kid(set, 'ReasonPhrase')), {}); }
        }
        flow.messages.response = r;
        flow.fault = { policy: p.attrs.name, name: 'RaiseFault', kind: 'raisefault' };
        flow.events.push({ type: 'raisefault', policy: p.attrs.name });
    },

    MessageLogging: function (flow, b, p) {
        var msg = X.path(p, ['CloudLogging', 'Message']) || X.path(p, ['Syslog', 'Message']);
        if (msg) { flow.logs.push({ policy: p.attrs.name, line: render(flow, X.text(msg) || '', {}) }); }
    },

    LookupCache: function (flow, b, p) {
        var name = p.attrs.name, key = cacheKey(flow, p), e = flow.cache[key];
        var hit = !!(e && (e.expires === null || e.expires > Date.now()));
        if (hit) { flow.set(X.text(X.kid(p, 'AssignTo')), e.value, name); }
        flow.sys('lookupcache.' + name + '.cachehit', hit ? 'true' : 'false');
    },

    PopulateCache: function (flow, b, p) {
        var t = X.path(p, ['ExpirySettings', 'TimeoutInSec']);
        if (t && t.attrs.ref && X.text(t) !== '') { throw new Error(p.attrs.name + ': TimeoutInSec takes a value or a ref, not both (L19)'); }
        var ttl = t ? Number(t.attrs.ref ? flow.get(t.attrs.ref) : X.text(t)) : 0;
        var v = flow.get(X.text(X.kid(p, 'Source')));
        flow.cache[cacheKey(flow, p)] = { value: v === null || v === undefined ? '' : String(v), expires: ttl > 0 ? Date.now() + ttl * 1000 : null };
    }
};

// A cache key: the Prefix, if any, then each KeyFragment (a ref's value, or the text), joined by '__' as Apigee does.
function cacheKey(flow, p) {
    var ck = X.kid(p, 'CacheKey'), parts = [];
    var pre = X.kid(ck, 'Prefix');
    if (pre) { parts.push(X.text(pre)); }
    X.kids(ck, 'KeyFragment').forEach(function (f) { parts.push(f.attrs.ref ? String(flow.get(f.attrs.ref)) : X.text(f)); });
    return parts.join('__');
}

/* ------------------------------------------------------------------ runner */
// Runs the SharedFlow once, on the given leg, as a FlowCallout with the given parameters would.
function runSharedFlow(bundle, flow, leg, params) {
    flow.leg = leg;
    if (leg === 'response' && !flow.messages.response) { throw new Error('the test set no response for the response leg'); }
    params = params || {};
    for (var k in params) { flow.set(k, params[k], 'FlowCallout'); }
    var steps = bundle.steps();
    for (var i = 0; i < steps.length; i++) {
        if (flow.fault) { break; }
        var s = steps[i];
        if (s.cond && !evalCondition(flow, s.cond)) { flow.events.push({ type: 'skip', policy: s.name }); continue; }
        var p = bundle.policies[s.name];
        if (!p) { throw new Error('step ' + s.name + ' has no policy'); }
        if (p.attrs.enabled === 'false') { continue; }
        var run = runners[p.name];
        if (!run) { throw new Error('the harness has no runner for ' + p.name + ' (' + s.name + ')'); }
        flow.events.push({ type: 'run', policy: s.name });
        run(flow, bundle, p);
    }
    return flow;
}

function newFlow(opts) {
    var f = new Flow(opts);
    if (opts && opts.response) { f.messages.response = new Message(opts.response); }
    return f;
}
function setResponse(flow, init) { flow.messages.response = new Message(init); return flow; }

/* Values a key may never sit in, outside a private. variable (A25). */
function keyLeaks(flow, key) {
    var out = [];
    flow.vars.forEach(function (v, k) { if (String(v) === key && k.indexOf('private.') !== 0) { out.push(k); } });
    return out;
}

/* A rough ES5 check, because Node runs code Rhino would refuse; the lab's Apigee is the final judge. */
function es5Problems(src) {
    var probs = [];
    var noStrings = src.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '').replace(/'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"/g, '""');
    [[/\blet\s/, 'let'], [/\bconst\s/, 'const'], [/=>/, 'arrow function'], [/`/, 'template literal'], [/\bclass\s+[A-Za-z]/, 'class'],
     [/\.\.\.[A-Za-z_\[]/, 'spread'], [/\bfor\s*\([^)]*\bof\b/, 'for...of'], [/\bObject\.assign\b/, 'Object.assign'],
     [/\bArray\.from\b/, 'Array.from'], [/\.includes\(/, 'String/Array includes'], [/\.startsWith\(|\.endsWith\(/, 'startsWith/endsWith'],
     [/\.padStart\(|\.padEnd\(/, 'padStart/padEnd'], [/\bnew\s+(Map|Set|WeakMap|Promise)\b/, 'Map/Set/Promise'], [/\bSymbol\b/, 'Symbol'],
     [/\basync\s+function\b|\bawait\s/, 'async/await']].forEach(function (t) { if (t[0].test(noStrings)) { probs.push(t[1]); } });
    return probs;
}

module.exports = { Bundle: Bundle, Flow: Flow, Message: Message, newFlow: newFlow, setResponse: setResponse, runSharedFlow: runSharedFlow,
                   evalCondition: evalCondition, render: render, jsonPath: jsonPath, keyLeaks: keyLeaks, es5Problems: es5Problems };

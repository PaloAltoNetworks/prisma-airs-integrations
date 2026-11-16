'use strict';
/*
 * Prisma AIRS replies for the unit harness: each test names the recorded reply its ServiceCallout gets.
 * The replies were recorded from the lab tenant (test/record-airs-fixtures.py); nothing here decides a verdict.
 * Live rows always use the real tenant.
 */
const fs = require('fs');
const path = require('path');

const FX = path.join(__dirname, '..', 'fixtures', 'airs');

function recorded(name) {
    var fx = JSON.parse(fs.readFileSync(path.join(FX, name + '.json'), 'utf8'));
    return { status: fx.status, body: fx.body, fixture: name };
}

// A responder that answers every call with the named replies, in turn; the last one repeats.
function answers() {
    var list = Array.prototype.slice.call(arguments).map(function (a) { return typeof a === 'string' ? recorded(a) : a; });
    var n = 0;
    return function () { var r = list[Math.min(n, list.length - 1)]; n++; return r; };
}

// Transport outcomes, not verdicts: no answer at all (a time-out or a refused connection, L5 and L10), or a status.
function noAnswer(why) { return { noAnswer: why || 'timeout' }; }
function status(code, body) { return { status: code, body: body === undefined ? '' : body }; }

// A recorded block-with-masked-copy turned into an allow, as a profile whose sensitive-data action is allow would answer.
// Synthetic: the lab's profile blocks sensitive data, so V2's mask path, which needs a non-block verdict, gets this copy.
function asAllow(name) {
    var r = recorded(name);
    r.body = JSON.parse(JSON.stringify(r.body)); r.body.action = 'allow'; r.body.category = 'benign'; r.synthetic = 'action set to allow';
    return r;
}

module.exports = { recorded: recorded, answers: answers, noAnswer: noAnswer, status: status, asAllow: asAllow };

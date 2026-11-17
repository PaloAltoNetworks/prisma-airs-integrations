'use strict';
/* The MuleSoft port's four cases that needed a reply recorded for v3's exact scan text (in test/fixtures/airs/). */
const S = require('./_shapes');
const R = require('../harness/replies');
const C = S.CARD;
const X = 'XXXXXXXXXXXXXXXXXXX';
function fwd(r) { return JSON.parse(String(r.request.request.content)); }

module.exports = [
    {
        finding: 'MS-mask-turns', title: 'applyDlpMasking: the masked text is written back into every scanned user turn; the assistant turn stays (request_extract.rs:408, run.py:557)',
        setup: Object.assign(S.chat([{ role: 'user', content: 'My card number is ' + C + '.' }, { role: 'assistant', content: 'Noted.' },
                                     { role: 'user', content: 'Use ' + C + ' for the order.' }]),
                             { legs: ['request'], airs: R.answers('mask-v3-two-turns-cards'), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) {
            var m = fwd(r).messages;
            return S.check(!r.request.fault && m[0].content === 'My card number is ' + X + '.' && m[1].content === 'Noted.' && m[2].content === 'Use ' + X + ' for the order.',
                           'not masked turn by turn: ' + JSON.stringify(m));
        }
    },
    {
        finding: 'MS-mask-turns', title: 'applyDlpMasking: a block that is not only about sensitive data (injection, agent) still blocks, masked copy or not',
        setup: Object.assign(S.chat([{ role: 'user', content: 'Card A ' + C }, { role: 'assistant', content: 'ok' }, { role: 'user', content: 'Card B ' + C }]),
                             { legs: ['request'], airs: R.answers('mask-v3-two-user-turns'), vars: { applyDlpMasking: 'true' } }),
        v3: function (r) { return S.check(r.request.blocked && r.request.flow.get('airs3.outcome') === 'block', 'it was not blocked: ' + r.request.flow.get('airs3.outcome')); }
    },
    {
        finding: 'MS-json-openai-n2', title: 'applyDlpMasking on a reply with two choices: each choice gets its own stretch of the masked copy',
        setup: Object.assign(S.chat([{ role: 'user', content: 'Which card is on file?' }], { n: 2 }), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'mask-v3-reply-n2'), vars: { applyDlpMasking: 'true' },
            response: S.reply({ choices: [{ index: 0, message: { role: 'assistant', content: 'Blue' } },
                                          { index: 1, message: { role: 'assistant', content: 'The card on file is ' + C + '.' } }] }) }),
        v3: function (r) {
            var b = r.response && JSON.parse(String(r.response.flow.messages.response.content));
            return S.check(r.response && !r.response.fault && b.choices[0].message.content === 'Blue' && b.choices[1].message.content === 'The card on file is ' + X + '.',
                           'the reply was not masked choice by choice: ' + (b ? JSON.stringify(b.choices) : 'refused'));
        }
    },
    {
        finding: 'MS-detections', title: 'A reply verdict with the reply\'s own dlp and the prompt context\'s injection is not pure DLP: it blocks, even with applyDlpMasking (decision.rs:78)',
        setup: Object.assign(S.chat([{ role: 'user', content: S.filler(100000) }]), {
            legs: ['request', 'response'], airs: R.answers('allow-prompt', 'block-v3-reply-mixed'), vars: { applyDlpMasking: 'true' },
            response: S.reply({ choices: [{ index: 0, message: { role: 'assistant', content: 'The card on file is ' + C + '.' } }] }) }),
        v3: function (r) {
            var d = r.response && r.response.flow.get('airs3.detections');
            return S.check(r.response && r.response.blocked && /response\.dlp/.test(d) && /prompt\.injection/.test(d), 'not blocked with mixed detections: ' + d);
        }
    }
];

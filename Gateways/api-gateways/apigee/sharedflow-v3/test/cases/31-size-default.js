'use strict';
/*
 * The size limit's default, 100,000 characters, and the setting an agent's proxy (Claude Code's) uses past it.
 *   - SIZE-1, SIZE-2: with the defaults, a request whose scan text is exactly 100,000 characters is scanned; one character
 *     more is refused without a scan. With the lab's profile (L11), natural prose was allowed at 50,000, 87,500 and 100,000
 *     characters; text built from a few repeated sentences was blocked as prompt injection at 50,000 to 100,000, depending
 *     on how much it repeats. Over the limit, the client gets a size refusal instead of a scan.
 *   - SIZE-3: with truncationFailClosed=false, as a proxy used for Claude Code sets it, a conversation past the limit is
 *     scanned by its newest 100,000 characters, where the new turn and tool results are, and passes; the cut is logged.
 */
const S = require('./_shapes');
const R = require('../harness/replies');

function said(x) { return String(x.flow.get('airs3.refuseMsg') || ''); }

const OLD = 'OLDEST-TURN-MARKER. ', NEW = ' NEWEST-TURN-MARKER';
function longConversation() {
    // Three user turns of 40,000 characters, joined by v3 with a newline each: 120,002 characters of scan text.
    var a = OLD + S.filler(40000 - OLD.length), b = S.filler(40000), c = S.filler(40000 - NEW.length) + NEW;
    return S.anthropic([{ role: 'user', content: a }, { role: 'assistant', content: 'Noted.' },
                        { role: 'user', content: b }, { role: 'assistant', content: 'Noted.' },
                        { role: 'user', content: c }]);
}

module.exports = [
    {
        finding: 'SIZE-1', title: 'With the defaults, a prompt of exactly 100,000 characters is scanned and passes',
        setup: Object.assign(S.chat([{ role: 'user', content: S.filler(100000) }]), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request;
            return S.check(x && !x.fault && x.calls.length === 1 && x.scanned.length === 100000 && x.flow.get('airs3.maxScanChars') === '100000',
                           'not scanned whole: fault ' + (x && x.fault ? x.fault.policy : '-') + ', calls ' + (x && x.calls.length) + ', scanned ' + (x && x.scanned.length));
        }
    },
    {
        finding: 'SIZE-2', title: 'With the defaults, a prompt of 100,001 characters is refused without a scan, as too large',
        setup: Object.assign(S.chat([{ role: 'user', content: S.filler(100001) }]), { legs: ['request'], airs: R.answers('allow-prompt') }),
        v3: function (r) {
            var x = r.request;
            return S.check(x && x.fault && x.calls.length === 0 && said(x).indexOf('larger than Prisma AIRS is set to inspect') !== -1,
                           'not refused as too large: fault ' + (x && x.fault ? x.fault.policy : '-') + ', calls ' + (x && x.calls.length) + ', message ' + (x && said(x)));
        }
    },
    {
        finding: 'SIZE-3', title: 'With truncationFailClosed=false, a 120,002-character conversation is scanned by its newest 100,000 characters and passes, logged',
        setup: Object.assign(longConversation(), { legs: ['request'], airs: R.answers('allow-prompt'), vars: { truncationFailClosed: 'false' } }),
        v3: function (r) {
            var x = r.request;
            if (!(x && !x.fault && x.calls.length === 1)) { return 'not scanned and passed: fault ' + (x && x.fault ? x.fault.policy : '-') + ', calls ' + (x && x.calls.length); }
            return S.check(x.scanned.length === 100000 && x.scanned.indexOf('NEWEST-TURN-MARKER') !== -1 && x.scanned.indexOf('OLDEST-TURN-MARKER') === -1 &&
                           x.flow.get('airs3.logNote') === 'scanned the newest 100000 characters',
                           'not the newest 100,000: scanned ' + x.scanned.length + ', newest ' + (x.scanned.indexOf('NEWEST-TURN-MARKER') !== -1) +
                           ', oldest ' + (x.scanned.indexOf('OLDEST-TURN-MARKER') !== -1) + ', note ' + x.flow.get('airs3.logNote'));
        }
    }
];

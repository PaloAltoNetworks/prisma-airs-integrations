'use strict';
// node test/debug.js "<title substring>" [v2|v3]: one case, with its scan text, key variables, errors and dropped sets.
const path = require('path'), fs = require('fs');
const H = require('./harness/apigee');
const want = process.argv[2], which = process.argv[3] || 'v3';
process.argv = [process.argv[0], 'run.js'].concat(which === 'v3' ? ['--v3'] : []);
const RUN = require('./run.js');
const dir = path.join(__dirname, 'cases');
const cases = fs.readdirSync(dir).filter(f => f.endsWith('.js') && f[0] !== '_').reduce((a, f) => a.concat(require(path.join(dir, f))), []);
const c = cases.find(x => x.title.indexOf(want) >= 0);
if (!c) { console.log('no case matches'); process.exit(1); }
const bundle = new H.Bundle(RUN.BUNDLES[which]);   // the same bundle paths as run.js, in either layout
const r = RUN.run(bundle, c);
for (const leg of ['request', 'response']) {
    const x = r[leg]; if (!x) continue;
    const f = x.flow, g = n => f.get('airs3.' + n);
    console.log(`== ${leg}: route=${g('route')} format=${g('format')} stream=${g('stream')} refuse=${g('refuse')} outcome=${g('outcome')} fault=${x.fault ? x.fault.policy : '-'} calls=${x.calls.length}`);
    console.log('   scanned:', JSON.stringify(x.scanned).slice(0, 400));
    console.log('   note:', g('logNote'), '| refuseMsg:', g('refuseMsg'));
    f.events.filter(e => e.type === 'js-error' || e.type === 'dropped-set').forEach(e => console.log('   EVENT', JSON.stringify(e)));
    if (x.fault) console.log('   reply:', x.status, x.contentType, String(x.body).slice(0, 300));
}

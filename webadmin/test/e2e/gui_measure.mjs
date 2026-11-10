// The measurements of the web interface in a browser (planning 8.2, last paragraph: "measured once in M6"): what loading the GUI costs, the list of the records of a big zone,
// and the preview and the commit of one record set in it.  Not a test: tests/run_webadmin_gui_measure.sh sets up SQLite3, a global master with TOTP off and the zone
// big.test of GUI_BIG records, runs this under the memory watchdog and prints "  [MEAS] ..." lines.  Times are what the driver sees (the page's own work plus the WebDriver
// round trip of a few milliseconds; the driver polls every 100 ms, so a time is good to about +-0.1 s), the median of the runs named in each line.
//
//   GUI_BASE=http://127.0.0.1:PORT GUI_ADMIN_PASSWORD=... GUI_DIR=work GUI_GECKODRIVER=... GUI_FIREFOX=... GUI_DRIVER_PORT=4444 GUI_BIG=100000 node webadmin/test/e2e/gui_measure.mjs

import { startBrowser } from './wd.mjs';

const BASE = process.env.GUI_BASE;
const BIG = Number(process.env.GUI_BIG ?? 100000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const median = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const fmt = (ms) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`);
const say = (name, value) => console.log(`  [MEAS] ${name}: ${value}`);

const started = await startBrowser({ driver: process.env.GUI_GECKODRIVER, firefox: process.env.GUI_FIREFOX, dir: process.env.GUI_DIR, port: Number(process.env.GUI_DRIVER_PORT) }).catch((e) => {
  console.log(`  the browser did not start: ${e.message}`);
  process.exit(3);
});
const b = started.browser;
const waitText = (css, re, o) => b.waitText(css, re, { timeout: 60000, ...o });
// the time (ms) from now until fn() is true (polled every 100 ms)
const until = async (fn, what) => {
  const t0 = Date.now();
  await b.waitFor(async () => (await fn()) || false, { timeout: 120000, message: what });
  return Date.now() - t0;
};
const click = async (text, scope = 'body') => {
  const r = await b.exec((t, s) => [...document.querySelector(s).querySelectorAll('button, a[href]')].find((e) => e.textContent.trim() === t && e.offsetParent !== null) ?? null, text, scope);
  if (!r) throw new Error(`no control "${text}" in ${scope}`);
  await b.wrap(r).click();
};
const fill = async (name, value, scope = '') => { const e = await b.$(`${scope} [name=${name}]`); await e.clear(); await e.type(value); };
const rows = () => b.exec(() => document.querySelectorAll('table.rrsets tbody tr').length);

try {
  // ---- loading the GUI: the first load (nothing cached), then reloads (the files are asked about again and answered 304)
  const times = [];
  let t0 = Date.now();
  await b.get(`${BASE}/`);
  await waitText('h1', /^Sign in$/);
  times.push(Date.now() - t0);
  const nav = await b.exec(() => {
    const n = performance.getEntriesByType('navigation')[0];
    const res = performance.getEntriesByType('resource').filter((e) => e.name.includes('/ui/'));
    return {
      files: res.length + 1, bytes: res.reduce((s, e) => s + e.decodedBodySize, 0) + n.decodedBodySize, wire: res.reduce((s, e) => s + e.encodedBodySize, 0) + n.encodedBodySize,
      dcl: Math.round(n.domContentLoadedEventEnd), load: Math.round(n.loadEventEnd), heap: null,
    };
  });
  const warm = [];
  for (let i = 0; i < 5; i++) {
    t0 = Date.now();
    await b.refresh();
    await waitText('h1', /^Sign in$/);
    warm.push(Date.now() - t0);
  }
  const warmNav = await b.exec(() => {
    const res = performance.getEntriesByType('resource').filter((e) => e.name.includes('/ui/'));
    return { answered: res.length, notModified: res.filter((e) => e.responseStatus === 304).length };
  });
  say('the GUI: files and size', `${nav.files} files, ${(nav.bytes / 1024).toFixed(0)} KiB (${(nav.wire / 1024).toFixed(0)} KiB on the wire, no compression)`);
  say('the GUI: first load to the sign-in form (nothing cached, the files are on this host)', fmt(times[0]));
  say('the GUI: a reload to the sign-in form (median of 5; every file asked about with its entity tag)', `${fmt(median(warm))} (${warmNav.answered} files)`);
  say('the GUI: DOMContentLoaded / load event of the first load (page clock)', `${nav.dcl} ms / ${nav.load} ms`);

  // ---- sign in
  await (await b.$('input[name=user]')).type('admin');
  await (await b.$('input[name=password]')).type(process.env.GUI_ADMIN_PASSWORD);
  t0 = Date.now();
  await click('Sign in', 'form');
  await waitText('h1', /^Welcome, /);
  say('sign-in: from the click to the start page', fmt(Date.now() - t0));

  // ---- the records of the big zone
  const zoneHash = '#/zones/main/big.test.';
  const open = async (hash, expect) => {
    await b.exec((x) => { window.location.hash = x; }, hash);
    return until(async () => (await rows()) >= expect, `${expect} rows at ${hash}`);
  };
  await b.exec(() => { window.location.hash = '#/'; });
  const first = [];
  for (let i = 0; i < 3; i++) {
    await b.exec(() => { window.location.hash = '#/'; });
    await waitText('h1', /^Welcome, /);
    first.push(await open(zoneHash, 100));
  }
  say(`the zone page of a zone of ${BIG} records: from the address to 100 rows (the default page; median of 3)`, fmt(median(first)));
  const big = [];
  for (let i = 0; i < 3; i++) {
    await b.exec(() => { window.location.hash = '#/'; });
    await waitText('h1', /^Welcome, /);
    big.push(await open(`${zoneHash}?n=500`, 500));
  }
  const dom = await b.exec(() => document.getElementsByTagName('*').length);
  say('...the same with 500 rows a page (the largest; median of 3)', `${fmt(median(big))}, ${dom} elements in the page`);
  const nextT = await (async () => {
    const firstName = await b.exec(() => document.querySelector('table.rrsets tbody tr th').textContent.trim());
    const t = Date.now();
    await click('Next page', 'main');
    await b.waitFor(async () => (await b.exec(() => window.location.hash)).includes('cursor='), { timeout: 60000, message: 'the cursor' });
    await until(async () => (await rows()) === 500 && (await b.exec(() => document.querySelector('table.rrsets tbody tr th').textContent.trim())) !== firstName, 'the second page');
    return Date.now() - t;
  })();
  say('...the next page of 500 (the cursor in the address)', fmt(nextT));
  await b.exec(() => { window.location.hash = '#/'; });
  await waitText('h1', /^Welcome, /);
  await open(zoneHash, 100);
  const searchT = await (async () => {
    await b.exec(() => { window.location.hash = '#/zones/main/big.test.?contains=h4999'; });
    return until(async () => { const r = await rows(); return r >= 1 && r < 100; }, 'the search result');
  })();
  say('...a search by a part of the name (contains=h4999; the whole zone is scanned)', fmt(searchT));

  // ---- one record set: edit, preview (a dry run), commit
  const prev = [];
  const commit = [];
  for (let i = 0; i < 3; i++) {
    // (a fresh page each round: the result of the last round is not on it)
    await b.exec(() => { window.location.hash = '#/'; });
    await waitText('h1', /^Welcome, /);
    await open(zoneHash, 100);
    const r = await b.exec(() => {
      const row = [...document.querySelectorAll('table.rrsets tbody tr')].find((tr) => tr.querySelector('th').textContent.trim() === 'h0' && tr.children[1].textContent.trim() === 'A');
      return row ? ([...row.querySelectorAll('button')].find((x) => x.textContent.trim() === 'Edit') ?? null) : null;
    });
    if (!r) throw new Error('no Edit button on h0 A');
    await b.wrap(r).click();
    await b.waitCss('dialog[open]');
    await fill('records', `192.0.2.${100 + i}`, 'dialog[open]');
    await click('Add to the changes', 'dialog[open]');
    await b.waitGone('dialog[open]');
    t0 = Date.now();
    await click('Preview', 'section.draft');
    await waitText('section.draft', /1 changed/);
    prev.push(Date.now() - t0);
    t0 = Date.now();
    await click('Commit', 'section.draft');
    await waitText('section[aria-labelledby=last-title]', /The change was saved\./);
    commit.push(Date.now() - t0);
    await sleep(300);
  }
  say(`one record set in the zone of ${BIG} records: Preview (a dry run: the zone is checked)`, `${fmt(median(prev))} (runs: ${prev.map(fmt).join(', ')})`);
  say('...Commit (the zone is checked, the permission is checked, the change is written)', `${fmt(median(commit))} (runs: ${commit.map(fmt).join(', ')})`);
  // ---- the same dry run asked of the API directly (no browser), without and with the precondition the page sends: what is the service's and what is the page's
  const lg = await fetch(`${BASE}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: 'admin', password: process.env.GUI_ADMIN_PASSWORD }) });
  const cookie = /karidns_session=[^;]+/.exec(lg.headers.get('set-cookie'))[0];
  const csrf = (await lg.json()).csrf;
  const dry = async (rr) => {
    const t = Date.now();
    const r = await fetch(`${BASE}/api/v1/datasets/main/zones/big.test/rrsets`, { method: 'PATCH', headers: { Cookie: cookie, 'X-KariDNS-CSRF': csrf, Origin: BASE, 'Content-Type': 'application/json' }, body: JSON.stringify({ rrsets: [rr], dry_run: true }) });
    await r.text();
    if (r.status !== 200) throw new Error(`the dry run answered ${r.status}`);
    return Date.now() - t;
  };
  const plain = []; const withExpect = [];
  for (let i = 0; i < 3; i++) {
    plain.push(await dry({ name: 'h1.big.test.', type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: '192.0.2.9' }] }));
    const cur = await (await fetch(`${BASE}/api/v1/datasets/main/zones/big.test/rrsets?name=h1.big.test.&type=A&rdata=1`, { headers: { Cookie: cookie } })).json();
    const rec = cur.rrsets[0];
    withExpect.push(await dry({ name: 'h1.big.test.', type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: '192.0.2.9' }], expect: rec.records.map((x) => ({ ttl: rec.ttl, content: x.rdata ?? x.content })) }));
  }
  say('the same dry run asked of the API without a browser: without / with the precondition (median of 3)', `${fmt(median(plain))} / ${fmt(median(withExpect))}`);
  const heap = await b.exec(() => (performance.memory ? performance.memory.usedJSHeapSize : null));
  if (heap) say('JavaScript heap at the end', `${(heap / 1048576).toFixed(0)} MiB`);
} catch (e) {
  console.log(`  [FAIL] ${e.message}`);
  await started.stop();
  process.exit(1);
}
await started.stop();
process.exit(0);

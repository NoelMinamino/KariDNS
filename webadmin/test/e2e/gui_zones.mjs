// The browser scenarios of the zone screens (planning 8.2, F-9; milestone M3): Firefox headless through geckodriver (wd.mjs) against a running karidns-webadmin with a REAL
// karidns (and its loader) behind it, so that the update button is checked with `dag`.  Not a node:test file: tests/run_webadmin_gui_test.sh (SQLite3) and
// tests/run_webadmin_gui_pg_test.sh (PostgreSQL) set the service up and run this.  Prints "  [ OK ] ..." / "  [FAIL] ..." lines, exits 1 when anything failed and 3 when no
// browser could be started.
//
//   GUI_BASE=http://127.0.0.1:PORT GUI_ADMIN_PASSWORD=... GUI_DIR=work GUI_GECKODRIVER=... GUI_FIREFOX=... GUI_DRIVER_PORT=4444 GUI_DNS_PORT=... GUI_DAG=./dag
//   GUI_DB=sqlite|pg GUI_SQL=script node webadmin/test/e2e/gui_zones.mjs
//
// GUI_SQL "statement" runs a statement on the zone database (milestone M4 makes a change behind the API's back with it, for the history screens).  Milestone M4 adds the
// scenarios of the history, the templates, the administration and the audit log (S9 to S12) at the end of this file, in the same browser.  The zones: example.test
// (served; a domain master `dom` with the record policy `web`, a subdomain master `sub` on sub.example.test), dskey.example.com (kept by the signer: DNSKEY and signer state
// made by SQL), xss.test (hostile record data), and zones the scenarios make and delete.  The service runs with require-totp = none.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { startBrowser, NAMED_KEYS, retryStale } from './wd.mjs';
import { pageProblems, overflowProblems } from './a11y.mjs';
import { dsDigest, keyTag, parseDnskey } from '../../lib/dnssec.js';
import { hotp, totpStep, base32Decode } from '../../lib/crypto.js';
import ja from '../../ui/i18n/ja.js';
import en from '../../ui/i18n/en.js';

const E = process.env;
const BASE = E.GUI_BASE;
const DIR = E.GUI_DIR;
const PG = E.GUI_DB === 'pg';
const DAG = E.GUI_DAG;
const DNS_PORT = E.GUI_DNS_PORT;
let pass = 0;
let fails = 0;
const ok = (name) => { pass++; console.log(`  [ OK ] ${name}`); };
const bad = (name, why) => { fails++; console.log(`  [FAIL] ${name}${why ? ` (${why})` : ''}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
class Failed extends Error {}
const must = (cond, what) => { if (!cond) throw new Failed(what); };
const eq = (got, want, what) => must(JSON.stringify(got) === JSON.stringify(want), `${what}: got ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);

// ---- the service, for the fixtures and for changes made behind the browser's back
async function call(method, p, { body, cookie, csrf } = {}) {
  const h = {};
  if (cookie) h.Cookie = `karidns_session=${cookie}`;
  if (csrf) { h['X-KariDNS-CSRF'] = csrf; h.Origin = BASE; }
  let payload;
  if (body !== undefined) { payload = JSON.stringify(body); h['Content-Type'] = 'application/json'; }
  const res = await fetch(`${BASE}/api/v1${p}`, { method, headers: h, body: payload });
  const text = await res.text();
  let parsed = text;
  if (/json/.test(res.headers.get('content-type') ?? '')) parsed = JSON.parse(text);
  return { status: res.status, headers: res.headers, body: parsed, text };
}
async function loginApi(user, password) {
  const r = await call('POST', '/auth/login', { body: { user, password } });
  const m = /karidns_session=([^;]+)/.exec(r.headers.get('set-cookie') ?? '');
  must(r.status === 200, `login ${user}: ${r.status} ${r.text}`);
  const s = { cookie: m[1], csrf: r.body.csrf };
  return (method, p, body) => call(method, p, { body, cookie: s.cookie, csrf: s.csrf });
}
const sh = (file, ...args) => spawnSync(file, args, { encoding: 'utf8' });
const sql = (text) => { const r = sh(E.GUI_SQL, text); must(r.status === 0, `sql: ${r.stderr}`); return r.stdout.trim(); };

// ---- the DNS server
const dagArgs = (name, t) => ['@127.0.0.1', '-p', DNS_PORT, name, t, '+nohexdump', '+time=2', '+tries=1'];
const answer = (name, t = 'A') => sh(DAG, ...dagArgs(name, t), '+short').stdout.trim().split('\n').filter(Boolean).sort().join(',');
async function waitAnswer(name, t, want, secs = 20) {
  const end = Date.now() + secs * 1000;
  let got;
  while (Date.now() < end) {
    got = answer(name, t);
    if (got === want) return true;
    await sleep(200);
  }
  throw new Failed(`dag ${name} ${t}: got "${got}", wanted "${want}"`);
}

// ---- the browser
const started = await startBrowser({ driver: E.GUI_GECKODRIVER, firefox: E.GUI_FIREFOX, dir: DIR, port: Number(E.GUI_DRIVER_PORT ?? 4444) }).catch((e) => {
  console.log(`  [SKIP] the browser did not start: ${e.message}`);
  process.exit(3);
});
const b = started.browser;
fs.mkdirSync(path.join(DIR, 'shots'), { recursive: true });
const files = path.join(DIR, 'files');
fs.mkdirSync(files, { recursive: true });

const h1 = async () => (await (await b.$('h1')).text()).trim();
const waitH1 = (re, o) => b.waitText('h1', re, o);
const bodyText = () => b.exec(() => document.body.innerText);
const fill = async (name, value, scope = '') => retryStale(async () => { const e = await b.$(`${scope} [name=${name}]`); await e.clear(); await e.type(value); });
const control = async (text, scope = 'body') => {
  const r = await b.exec((t, s) => [...document.querySelector(s).querySelectorAll('button, a[href]')].find((e) => e.textContent.trim() === t && e.offsetParent !== null) ?? null, text, scope);
  must(r, `no visible control "${text}" in ${scope}`);
  return b.wrap(r);
};
const click = (text, scope) => retryStale(async () => (await control(text, scope)).click());
// a button only ("Import" is also the name of a section of the zone)
const clickButton = (text, scope = 'body') => retryStale(async () => {
  const r = await b.exec((t, s) => [...document.querySelector(s).querySelectorAll('button')].find((e) => e.textContent.trim() === t && e.offsetParent !== null) ?? null, text, scope);
  must(r, `no visible button "${text}" in ${scope}`);
  await b.wrap(r).click();
});
// the button of a record set row
const rowButton = async (name, type, label) => {
  const r = await b.exec((n, t, l) => {
    const row = [...document.querySelectorAll('table.rrsets tbody tr')].find((tr) => tr.querySelector('th').textContent.trim() === n && tr.children[1].textContent.trim() === t);
    return row ? ([...row.querySelectorAll('button')].find((x) => x.textContent.trim() === l) ?? null) : null;
  }, name, type, label);
  must(r, `no button "${label}" on the row ${name} ${type}`);
  return b.wrap(r);
};
const rowText = (name, type) => b.exec((n, t) => {
  const row = [...document.querySelectorAll('table.rrsets tbody tr')].find((tr) => tr.querySelector('th').textContent.trim() === n && tr.children[1].textContent.trim() === t);
  return row ? [...row.children].map((c) => c.innerText.trim()) : null;
}, name, type);
// the records cell of a row becomes `want` (the table is read again after a change: not at the moment the answer arrives)
const rowIs = async (name, type, want, what) => {
  let got;
  await b.waitFor(async () => { got = (await rowText(name, type))?.[3]; return got === want; }, { message: `${what}: the row ${name} ${type} to hold ${JSON.stringify(want)}` })
    .catch((e) => { throw new Failed(`${e.message} (it holds ${JSON.stringify(got)})`); });
};
const setSelect = (name, value, scope = '') => b.exec((n, v, s) => { const el = document.querySelector(`${s} select[name=${n}]`); el.value = v; el.dispatchEvent(new Event('change', { bubbles: true })); }, name, value, scope);
const signIn = async (user, password) => {
  await fill('user', user);
  await fill('password', password);
  await click('Sign in', 'form');
  await waitH1(/^Welcome, /);
};
const logout = async () => {
  await click('Log out', 'header');
  await waitH1(/^(Sign in|ログイン)$/);
  await b.exec(() => { window.location.hash = '#/'; });                 // (the next sign-in starts at the start page, not at the page that was open)
};
const open = async (hash, h1re) => { await b.exec((x) => { window.location.hash = x; }, hash); await waitH1(h1re ?? /./); };
// the records page of a zone, once its table is there (every zone of the scenarios has an SOA)
const zonePage = async (zone) => {
  await open(`#/zones/main/${zone}`, new RegExp(`^${zone.replace(/\./g, '\\.')}`));
  await b.waitFor(async () => b.exec(() => document.querySelector('table.rrsets') !== null), { message: `the record sets of ${zone}` });
};
// the messages of error that are shown now (not the hidden ones of the other tabs of a form)
const visibleErrors = () => b.exec(() => [...document.querySelectorAll('main p.msg.error, main p.error')].filter((e) => e.offsetParent !== null).map((e) => e.innerText.trim()));
const waitErr = (re) => b.waitFor(async () => { const t = (await visibleErrors()).join(' | '); return re.test(t) ? t : null; }, { message: `an error that matches ${re}` });
const draftText = () => b.exec(() => (document.querySelector('section.draft') || { innerText: '' }).innerText);
const waitDraft = (re) => b.waitFor(async () => { const t = await draftText(); return re.test(t) ? t : null; }, { message: `the draft panel to match ${re}` });

const a11y = () => b.exec(pageProblems);                 // (a11y.mjs, shared with gui.mjs)
const labelsOk = async (screen) => eq(await a11y(), [], `${screen}: names and landmarks`);
const noTrouble = async () => {
  must(!(await b.exists('.csp-violation')), 'the policy of the page was violated');
  eq(await b.exec(() => [window.__xss, window.__xss2, window.__xss3]), [null, null, null], 'a canary was set');
};

async function scenario(name, fn) {
  try {
    await fn();
    ok(name);
  } catch (e) {
    bad(name, e.message);
    try { await b.screenshot(path.join(DIR, 'shots', `${name.replace(/[^A-Za-z0-9]+/g, '_').slice(0, 60)}.png`)); } catch { /* no picture */ }
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------- fixtures made through the API
let admin;
const IDS = {};
await (async () => {
  admin = await loginApi('admin', E.GUI_ADMIN_PASSWORD);
  const mk = async (p, body) => { const r = await admin('POST', p, body); must(r.status === 201 || r.status === 200, `${p}: ${r.status} ${r.text}`); return r.body; };
  const web = (await mk('/rr-policies', { name: 'web', allowed_types: ['A', 'AAAA', 'CNAME', 'TXT'], ttl_min: 60, ttl_max: 86400 })).policy.id;
  IDS.web = web;
  IDS.dom = (await mk('/principals', { kind: 'user', name: 'dom', display_name: 'Dora Domain', password: 'dora quartz lantern 12' })).principal.id;
  IDS.sub = (await mk('/principals', { kind: 'user', name: 'sub', display_name: 'Sam Sub', password: 'sam granite pine 1234' })).principal.id;
  IDS.evil = (await mk('/principals', { kind: 'user', name: 'evil', display_name: '<img src=x onerror="window.__xss=1">‮revo', password: 'delta echo foxtrot 34' })).principal.id;
  await mk('/grants', { principal: IDS.dom, role: 'domain_master', zone: 'example.test', policy: web });
  await mk('/grants', { principal: IDS.sub, role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policy: web });
  await mk('/grants', { principal: IDS.evil, role: 'domain_master', zone: 'xss.test', policy: web });
  await mk('/templates', { name: 'basic', description: 'name servers, mail and a web name', soa: { mname: 'ns1.nsprovider.test', rname: 'hostmaster.nsprovider.test' }, records: [
    { owner: '@', type: 'NS', content: 'ns1.nsprovider.test.' }, { owner: '@', type: 'MX', content: '10 mail' }, { owner: 'www', type: 'A', ttl: 600, content: '192.0.2.41' }] });
})().catch(async (e) => { console.log(`  [FAIL] the fixtures: ${e.message}`); await started.stop(); process.exit(1); });

let exitCode = 0;
try {
  // ------------------------------------------------------------------------------------------------------------------------------------------ the list
  console.log('-- the zone list (S3)');
  await scenario('a global master signs in and sees every zone with its role; the search narrows it', async () => {
    await b.get(`${BASE}/`);
    await waitH1(/^Sign in$/);
    await signIn('admin', E.GUI_ADMIN_PASSWORD);
    await click('Zones', 'nav');
    await waitH1(/^Zones$/);
    await b.waitCss('table tbody tr');
    const names = await b.exec(() => [...document.querySelectorAll('tbody tr th')].map((e) => e.innerText.trim()));
    for (const z of ['example.test.', 'dskey.example.com.', 'xss.test.']) must(names.includes(z), `${z} is not listed: ${names}`);
    must((await bodyText()).includes('Global master'), 'the role is not shown');
    await labelsOk('zone list');
    await fill('q', 'xss');
    await click('Find zones', 'form');
    await b.waitFor(async () => JSON.stringify(await b.exec(() => [...document.querySelectorAll('tbody tr th')].map((e) => e.innerText.trim()))) === '["xss.test."]', { message: 'the search to narrow the list' });
    await setSelect('kind', 'SLAVE');
    await click('Find zones', 'form');
    await b.waitText('main', /No zone matches\./);
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ editing
  console.log('-- a zone, a change with a preview, the update button (S4, S5)');
  await scenario('the zone page: names relative to the zone, the text form of the records (MX), the reasons, no button for the SOA of a non-global master', async () => {
    await zonePage('example.test.');
    await rowIs('@', 'MX', '10 mail.example.test.', 'the MX in text form (G2)');
    await rowIs('www', 'A', '192.0.2.10\n192.0.2.11', 'the A records');
    must((await rowText('@', 'SOA'))?.[4].includes('the service writes the serial'), 'the SOA is explained');
    must(await b.exec(() => [...document.querySelectorAll('button')].some((x) => x.textContent.trim() === 'Update the servers now')), 'no update button');
    await labelsOk('zone page');
  });

  await scenario('the MX round trip: the editor shows the text form, saving it unchanged says there is nothing to change, an added record is a diff of one line', async () => {
    await (await rowButton('@', 'MX', 'Edit')).click();
    await b.waitCss('dialog[open]');
    eq(await (await b.$('dialog[open] [name=records]')).prop('value'), '10 mail.example.test.', 'the records box');
    await labelsOk('editor');
    await click('Add to the changes', 'dialog[open]');
    await b.waitText('dialog[open]', /Nothing is different from what the zone has\./);
    await fill('records', '10 mail.example.test.\n20 mail2.example.test.', 'dialog[open]');
    await click('Add to the changes', 'dialog[open]');
    await b.waitGone('dialog[open]');
    await waitDraft(/Replace\s+@\s+MX/);
    await click('Preview', 'section.draft');
    const t = await waitDraft(/This is what the change would do/);
    must(/\+ 300 20 mail2\.example\.test\./.test(t), `the diff does not show the added record: ${t}`);
    must(/- 3600 10 mail\.example\.test\.[\s\S]*\+ 3600 10 mail\.example\.test\./.test(t) || /300 10 mail\.example\.test\./.test(t), 'the old record is in the diff');
    await labelsOk('draft with a preview');
    await click('Commit', 'section.draft');
    await b.waitText('section[aria-labelledby=last-title]', /The change was saved\./);
    await rowIs('@', 'MX', '10 mail.example.test.\n20 mail2.example.test.', 'the table after the commit');
  });

  await scenario('a domain master edits a TXT: preview, commit, the servers know nothing until the update button is pressed, then dag sees it', async () => {
    await logout();
    await signIn('dom', 'dora quartz lantern 12');
    await click('Zones', 'nav');
    await waitH1(/^Zones$/);
    await b.waitCss('table tbody tr');
    eq(await b.exec(() => [...document.querySelectorAll('tbody tr th')].map((e) => e.innerText.trim())), ['example.test.'], 'a domain master sees its zone only');
    must((await bodyText()).includes('Domain master'), 'the role');
    await b.exec(() => { document.querySelector('tbody tr th a').click(); });
    await b.waitText('h1', /^example\.test\./);
    await b.waitCss('table.rrsets');
    must(await b.exec(() => ![...document.querySelectorAll('button')].some((x) => x.textContent.trim() === 'Edit the SOA')), 'a domain master has no SOA form');
    must((await rowText('@', 'MX'))?.[4].includes('Read only'), 'the apex is read only for this grant');
    await click('Add a record set');
    await b.waitCss('dialog[open]');
    await fill('name', 'note', 'dialog[open]');
    await setSelect('type', 'TXT', 'dialog[open]');
    await fill('ttl', '300', 'dialog[open]');
    await fill('records', '"hello from the web interface"', 'dialog[open]');
    await click('Add to the changes', 'dialog[open]');
    await b.waitGone('dialog[open]');
    await fill('comment', 'a note', 'section.draft');
    await click('Preview', 'section.draft');
    await waitDraft(/1 added, 0 changed, 0 deleted/);
    await click('Commit', 'section.draft');
    await b.waitText('section[aria-labelledby=last-title]', /The change was saved\./);
    eq(answer('note.example.test', 'TXT'), '', 'the servers serve the old zone until the update');
    await rowIs('note', 'TXT', '"hello from the web interface"', 'the row');
    await click('Update the servers now', 'section[aria-labelledby=update-title]');
    await b.waitText('section[aria-labelledby=update-title]', /The servers were asked to load the zone again\./);
    await waitAnswer('note.example.test', 'TXT', '"hello from the web interface"');
    if (PG) await b.waitText('section[aria-labelledby=update-title]', /All \d+ servers have loaded the change\./, { timeout: 30000 });
  });

  console.log('-- a conflict made behind the back of the page (S5a)');
  await scenario('another writer changes the RRset after it was loaded: both ways out, in English', async () => {
    await zonePage('example.test.');
    // take theirs
    await (await rowButton('www', 'A', 'Edit')).click();
    await b.waitCss('dialog[open]');
    await fill('records', '192.0.2.77', 'dialog[open]');
    await click('Add to the changes', 'dialog[open]');
    await b.waitGone('dialog[open]');
    const r1 = await admin('PATCH', '/datasets/main/zones/example.test/rrsets', { rrsets: [{ name: 'www.example.test.', type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: '192.0.2.55' }] }] });
    must(r1.status === 200, `the other writer: ${r1.status} ${r1.text}`);
    await click('Preview', 'section.draft');
    await b.waitCss('div.conflict');
    const cols = await b.exec(() => [...document.querySelectorAll('div.conflict div.rec-block')].map((e) => e.innerText.trim()));
    eq(cols, ['300 192.0.2.10\n300 192.0.2.11', '300 192.0.2.55', '192.0.2.77'], 'loaded, now, mine');
    await labelsOk('conflict');
    await click('Take theirs', 'div.conflict');
    await b.waitFor(async () => (await rowText('www', 'A'))?.[3] === '192.0.2.55', { message: 'the table to show their records' });
    must(!(await b.exists('section.draft ul.draft-list')), 'my entry is still there');
    // keep mine
    await (await rowButton('www', 'A', 'Edit')).click();
    await b.waitCss('dialog[open]');
    await fill('records', '192.0.2.78', 'dialog[open]');
    await click('Add to the changes', 'dialog[open]');
    await b.waitGone('dialog[open]');
    const r2 = await admin('PATCH', '/datasets/main/zones/example.test/rrsets', { rrsets: [{ name: 'www.example.test.', type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: '192.0.2.56' }] }] });
    must(r2.status === 200, 'the other writer again');
    await click('Preview', 'section.draft');
    await b.waitCss('div.conflict');
    await click('Keep mine', 'div.conflict');
    await b.waitGone('div.conflict');
    await click('Preview', 'section.draft');
    await waitDraft(/This is what the change would do/);
    await click('Commit', 'section.draft');
    await b.waitText('section[aria-labelledby=last-title]', /The change was saved\./);
    await rowIs('www', 'A', '192.0.2.78', 'mine won');
    must(!(await rowText('www', 'A'))[3].includes('192.0.2.56'), 'theirs is gone');
  });

  await scenario('the same conflict in Japanese: the refusal and the choices', async () => {
    await open('#/account', /^Your account$/);
    await b.exec(() => document.querySelector('select').focus());
    await b.keys(NAMED_KEYS.ArrowDown);
    await waitH1(/^アカウント$/);
    await zonePage('example.test.');
    await (await rowButton('www', 'A', ja['rr.edit'])).click();
    await b.waitCss('dialog[open]');
    await fill('records', '192.0.2.79', 'dialog[open]');
    await click(ja['edit.ok'], 'dialog[open]');
    await b.waitGone('dialog[open]');
    const r = await admin('PATCH', '/datasets/main/zones/example.test/rrsets', { rrsets: [{ name: 'www.example.test.', type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: '192.0.2.57' }] }] });
    must(r.status === 200, 'the other writer');
    await click(ja['flow.preview'], 'section.draft');
    await b.waitCss('div.conflict');
    const t = await bodyText();
    must(t.includes(ja['api.precondition-failed']), 'the refusal in Japanese');
    must(t.includes(ja['conflict.take-theirs']) && t.includes(ja['conflict.keep-mine']), 'the choices in Japanese');
    must(!t.includes(en['api.precondition-failed']), 'English left on the page');
    await labelsOk('conflict in Japanese');
    await click(ja['conflict.take-theirs'], 'div.conflict');
    await b.waitFor(async () => (await rowText('www', 'A'))?.[3] === '192.0.2.57', { message: 'their records' });
    await open('#/account', /^アカウント$/);
    await b.exec(() => document.querySelector('select').focus());
    await b.keys(NAMED_KEYS.ArrowUp);
    await waitH1(/^Your account$/);
  });

  console.log('-- refusals of the service on the right place (422, 403)');
  const addSet = async (name, type, ttl, records) => {
    await click('Add a record set');
    await b.waitCss('dialog[open]');
    await fill('name', name, 'dialog[open]');
    await setSelect('type', type, 'dialog[open]');
    await fill('ttl', ttl, 'dialog[open]');
    await fill('records', records, 'dialog[open]');
    await click('Add to the changes', 'dialog[open]');
    await b.waitGone('dialog[open]');
  };
  await scenario('a record that is not RDATA is told at the record of its set; a CNAME beside data is refused by the zone checks; a TTL outside the policy is "not allowed" at the set', async () => {
    await zonePage('example.test.');
    // the reader of karidns-zone names the line of the change file: the message goes to the record (pointer /rrsets/0/records/0)
    await addSet('badaddr', 'A', '300', '192.0.2.300');
    await click('Preview', 'section.draft');
    await b.waitCss('section.draft ul.entry-errors');
    let where = await b.exec(() => document.querySelector('section.draft ul.entry-errors').closest('li.entry').innerText);
    must(/badaddr/.test(where) && /Record 1:/.test(where), `the error is not at the record: ${where}`);
    must(/The zone checks refuse this change\./.test(await draftText()), 'the general message');
    must(await b.exec(() => [...document.querySelectorAll('section.draft button')].find((x) => x.textContent.trim() === 'Commit').disabled), 'commit stays off');
    await click('Undo', 'section.draft');
    // a CNAME beside the A records of www: the zone checks refuse the zone as a whole; the messages are listed with their codes
    await addSet('www', 'CNAME', '300', 'other.example.test.');
    await click('Preview', 'section.draft');
    await b.waitText('section.draft', /The zone checks refuse this change\./);
    await b.waitCss('section.draft ul.messages');
    where = await b.exec(() => document.querySelector('section.draft ul.messages').innerText);
    must(/CNAME/i.test(where), `the zone check message: ${where}`);
    await click('Undo', 'section.draft');
    // the TTL is below ttl_min of the policy 'web'
    await addSet('mx2', 'A', '5', '192.0.2.5');
    await click('Preview', 'section.draft');
    await b.waitText('section.draft', /This is not allowed:/);
    must(await b.exists('section.draft ul.entry-errors'), 'the refusal is not at the record set');
    await click('Discard all changes', 'section.draft');
  });

  console.log('-- a draft survives the end of the session (F-13)');
  await scenario('the session is ended behind the page: the sign-in opens over it, the draft stays and goes on', async () => {
    await zonePage('example.test.');
    await click('Add a record set');
    await b.waitCss('dialog[open]');
    await fill('name', 'kept', 'dialog[open]');
    await setSelect('type', 'A', 'dialog[open]');
    await fill('ttl', '300', 'dialog[open]');
    await fill('records', '192.0.2.88', 'dialog[open]');
    await click('Add to the changes', 'dialog[open]');
    await b.waitGone('dialog[open]');
    const other = await loginApi('dom', 'dora quartz lantern 12');
    const gone = await other('POST', '/auth/logout', { all: true });
    must(gone.status === 204, `logout everywhere: ${gone.status}`);
    await click('Preview', 'section.draft');
    await b.waitText('dialog[open] h2', /session has ended/);
    await fill('user', 'dom', 'dialog[open]');
    await fill('password', 'dora quartz lantern 12', 'dialog[open]');
    await click('Sign in', 'dialog[open]');
    await b.waitGone('dialog[open]');
    must(/kept/.test(await draftText()) && /192\.0\.2\.88/.test(await draftText()), 'the draft is still there');
    await click('Preview', 'section.draft');
    await waitDraft(/This is what the change would do/);
    await click('Discard all changes', 'section.draft');
    await logout();
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ the subdomain master
  console.log('-- a subdomain master (S4)');
  await scenario('sees its suffix, the apex SOA and NS read only, not evilsub; no import, no DNSSEC; edits a name below its suffix', async () => {
    await signIn('sub', 'sam granite pine 1234');
    await zonePage('example.test.');
    const names = await b.exec(() => [...document.querySelectorAll('table.rrsets tbody tr')].map((tr) => `${tr.querySelector('th').innerText.trim()} ${tr.children[1].innerText.trim()}`));
    eq(names, ['a.sub TXT', '@ NS', '@ SOA', 'sub A'], 'the record sets it sees');
    must(!names.some((n) => n.startsWith('evilsub')), 'evilsub is listed');
    must((await rowText('@', 'NS'))?.[4].includes('Read only'), 'the apex NS is read only');
    eq(await b.exec(() => [...document.querySelectorAll('nav[aria-label="Sections of this zone"] a')].map((a) => a.innerText.trim())), ['Records', 'Versions', 'Settings'], 'the sections');
    await (await rowButton('a.sub', 'TXT', 'Edit')).click();
    await b.waitCss('dialog[open]');
    await fill('records', '"hello again"', 'dialog[open]');
    await click('Add to the changes', 'dialog[open]');
    await b.waitGone('dialog[open]');
    await click('Preview', 'section.draft');
    await waitDraft(/This is what the change would do/);
    await click('Commit', 'section.draft');
    await b.waitText('section[aria-labelledby=last-title]', /The change was saved\./);
    await rowIs('a.sub', 'TXT', '"hello again"', 'the row');
    await open('#/zones/main/example.test./import', /./);
    await b.waitText('main', /The import is for the masters of the whole zone\./);
    await open('#/zones/main/example.test./dnssec', /./);
    await b.waitText('main', /DNSSEC is for the masters of the whole zone\./);
    await logout();
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ new zones
  console.log('-- new zones (S6)');
  await scenario('a zone from a template, from a form with more records, and from a zone file; each previewed first', async () => {
    await signIn('admin', E.GUI_ADMIN_PASSWORD);
    await click('Zones', 'nav');
    await waitH1(/^Zones$/);
    await b.waitCss('table tbody tr');
    await click('New zone');
    await waitH1(/^New zone in main$/);
    await labelsOk('new zone');
    // the template
    await fill('name', 'tpl.test');
    await setSelect('how', 'template');
    await b.waitText('main', /3 records\./);
    await labelsOk('new zone from a template');
    await click('Preview the zone', 'main');
    await b.waitText('main', /This is what the change would do/);
    const preview = await bodyText();
    must(/www\.tpl\.test\.\s+A/.test(preview) && /\+ 600 192\.0\.2\.41/.test(preview), `the preview does not show the template's records: ${preview.slice(-600)}`);
    await click('Create the zone', 'main');
    await waitH1(/^tpl\.test\./);
    await b.waitCss('table.rrsets');
    await rowIs('www', 'A', '192.0.2.41', 'the copied record');
    await rowIs('@', 'MX', '10 mail.tpl.test.', 'the relative name of the template became absolute');
    // a form
    await open('#/create/main', /^New zone in main$/);
    await fill('name', 'form.test');
    await fill('mname', 'ns1.form.test');
    await fill('rname', 'hostmaster.form.test');
    await fill('nameservers', 'ns1.form.test.\nns2.form.test.');
    await fill('records', 'www 300 A 192.0.2.7\n_sip._tcp 300 SRV 10 5 5060 sip\nns1 300 A 192.0.2.53\nns2 300 A 192.0.2.54');
    await click('Preview the zone', 'main');
    await b.waitText('main', /This is what the change would do/);
    await click('Create the zone', 'main');
    await waitH1(/^form\.test\./);
    await b.waitCss('table.rrsets');
    await rowIs('_sip._tcp', 'SRV', '10 5 5060 sip.form.test.', 'a name inside the data, absolute');
    await rowIs('@', 'NS', 'ns1.form.test.\nns2.form.test.', 'the name servers');
    // a zone file
    await open('#/create/main', /^New zone in main$/);
    await fill('name', 'text.test');
    await setSelect('how', 'text');
    await fill('zone_text', '$ORIGIN text.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nweb IN A 192.0.2.2\n');
    await click('Preview the zone', 'main');
    await b.waitText('main', /This is what the change would do/);
    await click('Create the zone', 'main');
    await waitH1(/^text\.test\./);
    await b.waitCss('table.rrsets');
    await rowIs('web', 'A', '192.0.2.2', 'the record of the file');
  });

  await scenario('a refusal is told at the field: a zone that exists, a name server that is not a host name', async () => {
    await open('#/create/main', /^New zone in main$/);
    await fill('name', 'form.test');
    await fill('mname', 'ns1.form.test');
    await fill('rname', 'hostmaster.form.test');
    await fill('nameservers', 'ns1.form.test.');
    await click('Preview the zone', 'main');
    await waitErr(/exists already/);
    await fill('name', 'another.test');
    await fill('nameservers', 'not a host');
    await click('Preview the zone', 'main');
    await b.waitFor(async () => (await b.exec(() => [...document.querySelectorAll('main p.error:not([hidden])')].map((e) => e.innerText))).length > 0, { message: 'a message at a field' });
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ import and export
  console.log('-- import and export (S7)');
  await scenario('import: a file with merge and with replace (the diff), a file that is not UTF-8 is refused; export downloads the zone file', async () => {
    await open('#/zones/main/text.test./import', /./);
    await b.waitText('h2', /Import a zone file/);
    await labelsOk('import');
    const good = path.join(files, 'good.zone');
    fs.writeFileSync(good, '$ORIGIN text.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\nnew IN A 192.0.2.3\n');
    await (await b.$('input[type=file]')).type(good);
    await b.waitFor(async () => (await (await b.$('textarea[name=zone_text]')).prop('value')).includes('new IN A'), { message: 'the file to be read into the box' });
    await setSelect('mode', 'merge');
    await click('Preview the import', 'main');
    let t = await b.waitText('main', /1 added, 0 changed, 0 deleted/);
    must(!/- 300 192\.0\.2\.2/.test(t), 'merge deletes nothing');
    await setSelect('mode', 'replace');
    await click('Preview the import', 'main');
    t = await b.waitText('main', /1 added, 0 changed, 1 deleted/);
    must(/web\s+A/.test(t), 'replace deletes web');
    await clickButton('Import', 'main');
    await b.waitText('main', /The change was saved\./);
    // a file that is not UTF-8
    const latin = path.join(files, 'latin1.zone');
    fs.writeFileSync(latin, Buffer.from([0x24, 0x4f, 0x52, 0x49, 0x47, 0x49, 0x4e, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x0a, 0x78, 0x20, 0x49, 0x4e, 0x20, 0x54, 0x58, 0x54, 0x20, 0x22, 0xe9, 0x22, 0x0a]));
    await (await b.$('input[type=file]')).type(latin);
    await b.waitText('main', /The file is not UTF-8 text\./);
    // the export: a plain link; the browser saves the file the service sends as an attachment
    const exp = await b.exec(() => { const a = [...document.querySelectorAll('a')].find((x) => x.textContent.trim() === 'Export (zone file)'); return { href: a.getAttribute('href'), download: a.hasAttribute('download') }; });
    eq([exp.href, exp.download], ['/api/v1/datasets/main/zones/text.test./export', true], 'the export link');
    const hdr = await b.execAsync(async (u) => { const r = await fetch(u, { credentials: 'same-origin' }); return { status: r.status, type: r.headers.get('content-type'), disp: r.headers.get('content-disposition'), text: (await r.text()).slice(0, 400) }; }, exp.href);
    eq([hdr.status, hdr.type, hdr.disp], [200, 'text/plain; charset=utf-8', 'attachment; filename="text.test.zone"'], 'the headers of the export');
    must(/text\.test\./.test(hdr.text) && /SOA/.test(hdr.text), 'the export is the zone file');
    await click('Export (zone file)', 'nav[aria-label="Sections of this zone"]');
    const dl = path.join(DIR, 'downloads');
    const end = Date.now() + 20000;
    let saved = null;
    while (Date.now() < end && !saved) {
      saved = fs.readdirSync(dl).find((f) => f.startsWith('text.test') && !f.endsWith('.part'));
      if (!saved) await sleep(250);
    }
    must(saved, `no downloaded file in ${dl}: ${fs.readdirSync(dl)}`);
    const body = fs.readFileSync(path.join(dl, saved), 'utf8');
    // (the canonical form of karidns-zone export: owner, type, data; the replace import deleted `web`)
    must(/^new\s+A\s+192\.0\.2\.3$/m.test(body) && !/^web\s/m.test(body), `the downloaded zone file is not the zone as it is now: ${body.slice(0, 300)}`);
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ settings
  console.log('-- zone settings (S8)');
  await scenario('metadata is set and shown, a refused value is told at the box, a zone is deleted after its name is typed again', async () => {
    await open('#/zones/main/text.test./settings', /./);
    await b.waitText('h2', /Attributes/);
    await b.waitCss('textarea[name=content]');
    await labelsOk('zone settings');
    await setSelect('kind', 'ALLOW-AXFR-FROM');
    await fill('content', '192.0.2.0/24', 'form:has(textarea)');
    await click('Save', 'form:has(textarea)');
    await b.waitText('main', /Saved\./);
    must((await bodyText()).includes('192.0.2.0/24'), 'the value is in the table');
    await fill('content', 'not an address', 'form:has(textarea)');
    await click('Save', 'form:has(textarea)');
    await b.waitFor(async () => (await b.exec(() => [...document.querySelectorAll('p.error:not([hidden])')].map((e) => e.innerText))).length > 0, { message: 'a message at the box' });
    // delete form.test
    await open('#/zones/main/form.test./settings', /./);
    await b.waitCss('input[name=confirm]');
    await fill('confirm', 'other', 'form:has(input[name=confirm])');
    await click('Delete the zone', 'form:has(input[name=confirm])');
    await b.waitText('main', /This is not the name of the zone\./);
    await fill('confirm', 'form.test', 'form:has(input[name=confirm])');
    await click('Delete the zone', 'form:has(input[name=confirm])');
    await waitH1(/^Zones$/);
    await b.waitText('main', /The zone form\.test\. was deleted\./);
    await b.waitCss('table tbody tr');
    must(!(await b.exec(() => [...document.querySelectorAll('tbody tr th')].some((e) => e.innerText.trim() === 'form.test.'))), 'the zone is still listed');
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ DNSSEC
  console.log('-- DNSSEC (S13)');
  await scenario('a zone the signer keeps: no update button, the keys with their tags, the DS records to copy, the countdown, the last error; a key request is made once at a time', async () => {
    const dnskey = parseDnskey(`257 3 5 ${'AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw=='}`);
    const tag = keyTag(dnskey.rdata);
    const digest = dsDigest('dskey.example.com', dnskey.rdata, 2);
    await zonePage('dskey.example.com.');
    must(!(await b.exec(() => [...document.querySelectorAll('button')].some((x) => x.textContent.trim() === 'Update the servers now'))), 'a signer zone has an update button');
    must((await bodyText()).includes('there is no button to press'), 'the signer is explained');
    await open('#/zones/main/dskey.example.com./dnssec', /./);
    await b.waitText('h2', /DNSSEC/);
    await b.waitCss('table');
    const t = await bodyText();
    must(t.includes(String(tag)), `the key tag ${tag} is not shown`);
    must(t.includes(`${tag} 5 2 ${digest}`), 'the DS record (SHA-256) is not shown');
    must(/key signing key/.test(t), 'the role of the key');
    must(/First signature expires\s+in \d+ d/.test(t.replace(/\n/g, ' ')) || /First signature expires[\s\S]{0,40}in \d+ d/.test(t), `the countdown: ${t.slice(0, 700)}`);
    must(t.includes('could not sign <b>x</b>'), 'the last error of the signer is shown as text');
    eq(await b.exec(() => document.querySelectorAll('main b').length), 0, 'markup from the signer became an element');
    await labelsOk('DNSSEC');
    // the request: enable on example.test
    await open('#/zones/main/example.test./dnssec', /./);
    await b.waitText('h2', /DNSSEC/);
    await b.waitCss('select[name=kind]');
    await click('Send the request', 'form:has(select[name=kind])');
    await b.waitText('main', /The request was sent\./);
    await b.waitText('main', /pending/);
    await click('Send the request', 'form:has(select[name=kind])');
    await waitErr(/A request for this zone is waiting already\./);
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ read-only zones
  console.log('-- zones that are not edited here');
  await scenario('a secondary zone and a zone signed elsewhere are read only with the reason; the servers screen', async () => {
    await zonePage('slave.test.');
    must((await bodyText()).includes('Read only: this is not a primary zone.'), 'the secondary zone');
    must(!(await b.exec(() => [...document.querySelectorAll('button')].some((x) => x.textContent.trim() === 'Add a record set'))), 'a secondary zone has an add button');
    await zonePage('pre.test.');
    must((await bodyText()).includes('Read only: the zone is signed elsewhere.'), 'the zone signed elsewhere');
    await click('Servers', 'nav');
    await waitH1(/^Servers$/);
    await b.waitFor(async () => !/Loading/.test(await (await b.$('main')).text()), { message: 'the servers' });
    const t = await bodyText();
    if (PG) must(/every zone loaded/.test(t), `the server status: ${t.slice(0, 400)}`);
    else must(/karictl status/.test(t), `the note of SQLite3: ${t.slice(0, 400)}`);
    await labelsOk('servers');
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ hostile data
  console.log('-- hostile zone data (planning 5.2)');
  await scenario('record data, names and a display name with markup, script tags and bidi controls are text; nothing runs; the policy is not violated', async () => {
    await zonePage('xss.test.');
    const t = await bodyText();
    must(t.includes('<img src=x onerror=window.__xss=1>'), 'the img markup is not shown as text');
    must(t.includes('</script><script>window.__xss2=1</script>'), 'the script markup is not shown as text');
    // (the service writes bytes above 127 as \DDD escapes, so the bidi control reaches the page as three escapes, not as itself)
    must(!t.includes(String.fromCharCode(0x202e)), 'a bidi control is on the page as it is');
    must(t.includes('\\226\\128\\174'), 'the bytes of the bidi control are not shown as escapes');
    eq(await b.exec(() => document.querySelectorAll('main img, main script, header script').length), 0, 'an element came from zone data');
    must((await rowText('*.wild', 'A')) !== null && (await rowText('_dmarc', 'TXT')) !== null, 'names with * and _ are shown');
    // the editor holds the text as it is and an unchanged save is "nothing to change"
    const txt = await rowText('markup', 'TXT');
    must(txt, 'the markup row');
    await (await rowButton('markup', 'TXT', 'Edit')).click();
    await b.waitCss('dialog[open]');
    must((await (await b.$('dialog[open] [name=records]')).prop('value')).includes('<img src=x onerror=window.__xss=1>'), 'the box does not hold the markup as text');
    await click('Add to the changes', 'dialog[open]');
    await b.waitText('dialog[open]', /Nothing is different/);
    await click('Cancel', 'dialog[open]');
    await b.waitGone('dialog[open]');
    await noTrouble();
    // a zone name in the address is text too
    await open(`#/zones/main/${encodeURIComponent('<img src=x onerror=window.__xss3=1>.test.')}`, /./);
    await b.waitText('main', /(There is no such object, or you may not see it|The request was not valid)./);
    eq(await b.exec(() => document.querySelectorAll('main img').length), 0, 'an element came from the address');
    must((await h1()).includes('<img src=x onerror=window.__xss3=1>.test.'), 'the name is shown as text');
    await noTrouble();
    // the person with the hostile display name
    await logout();
    await signIn('evil', 'delta echo foxtrot 34');
    eq((await h1()), 'Welcome, <img src=x onerror="window.__xss=1"><U+202E>revo', 'the display name as text');
    await zonePage('xss.test.');
    must((await bodyText()).includes('Signed in as <img src=x onerror="window.__xss=1"><U+202E>revo'), 'the name in the header');
    await noTrouble();
    await logout();
    await signIn('admin', E.GUI_ADMIN_PASSWORD);
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ keyboard
  console.log('-- the keyboard alone');
  await scenario('a record set is added and previewed without the mouse', async () => {
    await zonePage('text.test.');
    await b.exec(() => { [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === 'Add a record set').focus(); });
    await b.keys(NAMED_KEYS.Enter);
    await b.waitCss('dialog[open]');
    must(await b.exec(() => document.activeElement.name === 'name' && document.activeElement.closest('dialog') !== null), 'the focus is not in the name box');
    await b.keys(...'kbd'.split(''), NAMED_KEYS.Tab, NAMED_KEYS.Tab);          // the type box, then the TTL
    await b.keys(...'300'.split(''), NAMED_KEYS.Tab);                            // the records box
    await b.keys(...'192.0.2.99'.split(''), NAMED_KEYS.Tab, NAMED_KEYS.Enter);   // the button "Add to the changes"
    await b.waitGone('dialog[open]');
    await waitDraft(/Add\s+kbd\s+A/);
    await b.exec(() => { [...document.querySelectorAll('section.draft button')].find((x) => x.textContent.trim() === 'Preview').focus(); });
    await b.keys(NAMED_KEYS.Enter);
    await waitDraft(/This is what the change would do/);
    must(await b.exec(() => /focus|outline/.test(JSON.stringify([...document.styleSheets].map((s) => [...s.cssRules].map((r) => r.cssText.slice(0, 80)))))), 'a style for the focus');
    await click('Discard all changes', 'section.draft');
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ milestone M4
  // The history, the templates, the administration and the audit log (S9 to S12).  hist.test is a zone made for this part, with a history written through the API; the
  // part ends signed in as the administrator, as it began.
  const m4start = Date.now();
  console.log('-- versions and rollback (S9)');
  let tplId = null;
  await scenario('the versions of a zone, one version, a difference; the comment of a version is text', async () => {
    const made = await admin('POST', '/datasets/main/zones', { name: 'hist.test', soa: { mname: 'ns1.nsprovider.test', rname: 'hostmaster.nsprovider.test' }, nameservers: ['ns1.nsprovider.test.'], comment: 'the first' });
    must(made.status === 201, `create hist.test: ${made.status} ${made.text}`);
    const patch = async (rrsets, comment) => {
      const r = await admin('PATCH', '/datasets/main/zones/hist.test/rrsets', { rrsets, comment });
      must(r.status === 200, `patch hist.test: ${r.status} ${r.text}`);
    };
    const rs = (name, ip) => ({ name: `${name}.hist.test.`, type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: ip }] });
    await patch([rs('www', '192.0.2.1')], 'add www <b>x</b>');
    await patch([rs('www', '192.0.2.2'), rs('api', '192.0.2.3')], 'move www, add api');
    await open('#/zones/main/hist.test./versions', /^hist\.test\./);
    await b.waitCss('table.versions');
    const rows = await b.exec(() => [...document.querySelectorAll('table.versions tbody tr')].filter((r) => r.querySelector('th')).map((r) => [...r.children].map((c) => c.innerText.trim())));
    eq(rows.map((r) => [r[0], r[1], r[3]]), [['3', 'edit', 'admin'], ['2', 'edit', 'admin'], ['1', 'created', 'admin']], 'the versions, newest first');
    must(rows[1][4] === 'add www <b>x</b>', `the comment is text: ${rows[1][4]}`);
    must(!(await b.exists('table.versions img, table.versions b')), 'a comment made an element');
    must(!(await b.exists('table.versions .outside')), 'nothing happened outside the versions yet');
    await labelsOk('the versions');
    // one version
    await open('#/zones/main/hist.test./versions/3', /^hist\.test\./);
    await b.waitText('main', /1 added, 1 changed, 0 deleted/);
    const names = await b.exec(() => [...document.querySelectorAll('table.diff-table tbody th')].map((e) => e.innerText.trim()));
    eq(names, ['api', 'www'], 'the record sets of the version');
    await labelsOk('a version');
    // version 1 against the zone as it is: the compare form
    await open('#/zones/main/hist.test./versions', /^hist\.test\./);
    await b.waitCss('table.versions');
    await fill('from', '1');
    await click('Compare', 'form.search');
    await b.waitText('main', /Version 1 against the zone as it is now/);
    await b.waitText('main', /2 added, 0 changed, 0 deleted/);
    await labelsOk('a difference');
    // two versions
    await open('#/zones/main/hist.test./versions/2/diff?to=3', /^hist\.test\./);
    await b.waitText('main', /Version 2 against version 3/);
    await b.waitText('main', /1 added, 1 changed, 0 deleted/);
  });

  await scenario('a change made outside the versions is marked; the rollback lists it as a conflict and waits for the question about force', async () => {
    sql("UPDATE records SET content = '192.0.2.99' WHERE name = 'api.hist.test' AND type = 'A'");
    await open('#/zones/main/hist.test./versions', /^hist\.test\./);
    await b.waitText('main', /Since the newest version:/);
    await open('#/zones/main/hist.test./versions/2', /^hist\.test\./);
    await b.waitCss('#rb-title');
    await labelsOk('the rollback');
    await fill('comment', 'back to 2', 'section[aria-labelledby=rb-title]');
    await click('Preview the rollback', 'section[aria-labelledby=rb-title]');
    await b.waitCss('section.conflict');
    must(await b.exec(() => [...document.querySelectorAll('section[aria-labelledby=rb-title] button')].find((x) => x.textContent.trim() === 'Roll back').disabled), 'a plain commit is possible with a conflict');
    eq(await b.exec(() => [...document.querySelectorAll('section.conflict tbody tr')].map((r) => [...r.children].map((c) => c.innerText.trim()))), [['api', 'A', '300 192.0.2.3', '300 192.0.2.99']], 'the conflict');
    await click('Roll back anyway and overwrite these', 'section.conflict');
    must(/Overwrite these 1 record sets\?/.test(await b.exec(() => document.querySelector('section.conflict').innerText)), 'the question');
    await click('No', 'section.conflict');
    must(!(await bodyText()).includes('The change was saved.'), 'saved without the answer yes');
    await click('Roll back anyway and overwrite these', 'section.conflict');
    await click('Yes', 'section.conflict');
    await b.waitText('main', /The change was saved\./);
    await zonePage('hist.test.');
    await rowIs('www', 'A', '192.0.2.1', 'www as it was at version 2');
    eq(await rowText('api', 'A'), null, 'api is gone');
    await open('#/zones/main/hist.test./versions', /^hist\.test\./);
    await b.waitText('main', /restores version 2/);
    eq(await b.exec(() => [...document.querySelectorAll('table.versions tbody tr')].filter((r) => r.querySelector('th'))[0].children[1].innerText.trim()), 'rollback', 'the new version is a rollback');
  });

  console.log('-- templates (S10)');
  await scenario('a template is checked by the zone checks (a bad address is refused at its line), saved, applied to a zone with a preview, and deleted', async () => {
    await open('#/templates', /^Templates$/);
    await b.waitCss('table tbody tr');
    must((await bodyText()).includes('basic'), 'the template of the fixtures');
    await labelsOk('templates');
    await click('New template', 'main');
    await waitH1(/^New template$/);
    await labelsOk('a new template');
    await fill('name', 'e2e');
    await fill('description', 'for the browser test');
    await fill('records', 'tplhost 600 A 192.0.2.88\nbad CNAME other.example.test.\nbad A 192.0.2.5\nbadip A 999.1.1.1');
    await click('Check', 'main');
    await b.waitText('main', /The zone checks refuse some records/);
    must(/Line 4: /.test(await bodyText()), 'a message does not name the line of its record');
    await fill('records', 'tplhost 600 A 192.0.2.88\n@ TXT "e2e"');
    await click('Check', 'main');
    await b.waitText('main', /The zone checks accept this template\./);
    await click('Create template', 'main');
    await waitH1(/^e2e$/);
    tplId = (await b.exec(() => window.location.hash)).replace(/^#\/templates\//, '');
    must(/^\d+$/.test(tplId), `the address of the template: ${tplId}`);
    must((await bodyText()).includes('The template was saved.'), 'saved');
    eq(await b.exec(() => [...document.querySelectorAll('main table tbody tr')].map((r) => [...r.children].map((c) => c.innerText.trim()))), [['tplhost', 'A', '600', '192.0.2.88'], ['@', 'TXT', '-', '"e2e"']], 'the records');
    await labelsOk('a template');
    await click('Check again', 'main');
    await b.waitText('main', /The zone checks accept this template\./);
    // applied to a zone
    await open('#/zones/main/hist.test./template', /^hist\.test\./);
    await b.waitCss('select[name=template]');
    await setSelect('template', tplId);
    await fill('default_ttl', '120');
    await labelsOk('apply a template');
    await click('Preview', 'main');
    await b.waitText('main', /This is what the change would do/);
    await click('Apply the template', 'main');
    await b.waitText('main', /The change was saved\./);
    await zonePage('hist.test.');
    await rowIs('tplhost', 'A', '192.0.2.88', 'the template was applied');
    await rowIs('@', 'TXT', '"e2e"', 'the record without a TTL');
    await open('#/zones/main/hist.test./versions', /^hist\.test\./);
    await b.waitText('main', /template applied/);
    // deleted after a question
    await open(`#/templates/${tplId}`, /^e2e$/);
    await click('Delete the template', 'main');
    await click('Yes', 'section.danger-zone');
    await waitH1(/^Templates$/);
    await b.waitText('main', /The template e2e was deleted\./);
  });

  console.log('-- administration (S11)');
  let groupHash = null;
  await scenario('users: a new user, a group with a member and a grant; the user signs in with the grant of the group', async () => {
    await open('#/admin/users', /^Administration$/);
    await b.waitCss('table tbody tr');
    const names = await b.exec(() => [...document.querySelectorAll('tbody tr th')].map((e) => e.innerText.trim()));
    for (const n of ['admin', 'dom', 'sub', 'evil']) must(names.includes(n), `${n} is not listed: ${names}`);
    await labelsOk('users');
    await fill('prefix', 'su', 'form.search');
    await click('Find', 'form.search');
    await b.waitFor(async () => JSON.stringify(await b.exec(() => [...document.querySelectorAll('tbody tr th')].map((e) => e.innerText.trim()))) === '["sub"]', { message: 'the search to narrow the list' });
    await open('#/admin/users', /^Administration$/);
    await b.waitCss('form[novalidate] input[name=password]');
    await fill('name', 'newbie', 'form:has(input[name=password])');
    await fill('display_name', 'New <b>Bie</b>', 'form:has(input[name=password])');
    await fill('password', 'a new person 12345', 'form:has(input[name=password])');
    await click('Create user', 'main');
    await b.waitText('main', /User: newbie/);
    must((await bodyText()).includes('newbie was created.'), 'created');
    must(!(await b.exists('main b')), 'a display name made an element');
    await labelsOk('a user');
    // a group, a member by name, a grant on a zone
    await open('#/admin/groups', /^Administration$/);
    await b.waitCss('form[novalidate]');
    await fill('name', 'e2e-ops', 'form:has(button.primary)');
    await click('Create group', 'main');
    await b.waitText('main', /Group: e2e-ops/);
    groupHash = await b.exec(() => window.location.hash);
    await labelsOk('a group');
    await fill('member', 'NEWBIE');
    await click('Add', 'main');
    await b.waitText('main', /newbie was added\./);
    await setSelect('policy', String(IDS.web), 'form:has(select[name=role])');
    await fill('zone', 'hist.test', 'form:has(select[name=role])');
    await click('Give the grant', 'main');
    await b.waitText('main', /The grant was given\./);
    // the list of grants is fetched again after the message: wait for its rows before reading them
    await b.waitFor(async () => (await b.exec(() => document.querySelectorAll('table.grants tbody tr').length)) > 0, { message: 'the grants of the group to be listed' });
    eq(await b.exec(() => [...document.querySelectorAll('table.grants tbody tr')].map((r) => [...r.children].slice(0, 3).map((c) => c.innerText.trim()))), [['Domain master', 'main / hist.test.', 'web']], 'the grant');
    // the user has the grant of the group
    await logout();
    await signIn('newbie', 'a new person 12345');
    await click('Zones', 'nav');
    await waitH1(/^Zones$/);
    await b.waitCss('table tbody tr');
    eq(await b.exec(() => [...document.querySelectorAll('tbody tr')].map((r) => [r.children[0].innerText.trim(), r.children[1].innerText.trim()])), [['hist.test.', 'Domain master']], 'the zones of the member of the group');
    await logout();
    await signIn('admin', E.GUI_ADMIN_PASSWORD);
  });

  await scenario('a lost device and a locked account: the TOTP is reset and the account unlocked by an administrator; a user cannot reset its own', async () => {
    const pw = 'a new person 12345';
    const me = await loginApi('newbie', pw);
    const enrol = await me('POST', '/auth/totp', { action: 'enroll' });
    must(enrol.status === 200, `enrol: ${enrol.status} ${enrol.text}`);
    const conf = await me('POST', '/auth/totp', { action: 'confirm', code: hotp(base32Decode(enrol.body.secret), totpStep(Date.now() / 1000)) });
    must(conf.status === 200, `confirm: ${conf.status} ${conf.text}`);
    for (let i = 0; i < 3; i++) must((await call('POST', '/auth/login', { body: { user: 'newbie', password: 'wrong password 1234' } })).status === 401, 'a wrong password was accepted');
    await open('#/admin/users', /^Administration$/);
    await b.waitCss('table tbody tr');
    await click('newbie', 'table');
    await b.waitText('main', /User: newbie/);
    await b.waitText('main', /Failed sign-in attempts\s*3/);
    must(/Two-step verification\s*on/.test(await bodyText()), 'the TOTP is not shown as on');
    await click('Unlock the account', 'main');
    await click('Yes', 'main');
    await b.waitText('main', /The account was unlocked\./);
    await b.waitText('main', /Failed sign-in attempts\s*0/);
    await click('Reset two-step verification', 'main');
    await click('Yes', 'main');
    await b.waitText('main', /Two-step verification was reset/);
    must(/Two-step verification\s*off/.test(await bodyText()), 'the TOTP is still on');
    const after = await call('POST', '/auth/login', { body: { user: 'newbie', password: pw } });
    must(after.status === 200, `the user cannot sign in with the password alone: ${after.status} ${after.text}`);
    // one's own account: no way to disable, delete or reset oneself
    await open('#/admin/users', /^Administration$/);
    await b.waitCss('table tbody tr');
    await click('admin', 'table');
    await b.waitText('main', /User: admin/);
    must(await b.exec(() => ![...document.querySelectorAll('main button')].some((x) => /^(Delete|Reset two-step verification)$/.test(x.textContent.trim())) && !document.querySelector('main input[name=disabled]')), 'oneself can be disabled, deleted or reset');
  });

  await scenario('record policies: a new one, edited, deleted; one that is in use is refused; grants by user and zone, one removed after a question', async () => {
    await open('#/admin/policies', /^Administration$/);
    await b.waitCss('table tbody tr');
    await labelsOk('policies');
    await fill('name', 'e2e-pol', 'form:has(input[name=allow_wildcard])');
    await fill('types', 'a txt', 'form:has(input[name=allow_wildcard])');
    await fill('ttl_min', '60', 'form:has(input[name=allow_wildcard])');
    await fill('ttl_max', '600', 'form:has(input[name=allow_wildcard])');
    await click('Create the policy', 'main');
    await b.waitText('main', /The policy e2e-pol was created\./);
    const inRow = async (th, label) => {
      const r = await b.exec((n, l) => {
        const row = [...document.querySelectorAll('table tbody tr')].find((tr) => tr.querySelector('th').textContent.trim() === n);
        return row ? ([...row.querySelectorAll('button')].find((x) => x.textContent.trim() === l && x.offsetParent !== null) ?? null) : null;
      }, th, label);
      must(r, `no button ${label} in the row ${th}`);
      return b.wrap(r);
    };
    eq(await b.exec(() => [...document.querySelectorAll('table tbody tr')].find((tr) => tr.querySelector('th').textContent.trim() === 'e2e-pol').children[1].innerText.trim()), 'A TXT', 'the types of the policy');
    await (await inRow('e2e-pol', 'Edit')).click();
    await b.waitText('main', /Edit the policy e2e-pol/);
    await fill('max_rr', '5', 'form:has(input[name=allow_wildcard])');
    await click('Save the policy', 'main');
    await b.waitText('main', /The policy e2e-pol was saved\./);
    await (await inRow('e2e-pol', 'Delete')).click();
    await (await inRow('e2e-pol', 'Yes')).click();
    await b.waitText('main', /The policy e2e-pol was deleted\./);
    await (await inRow('web', 'Delete')).click();
    await (await inRow('web', 'Yes')).click();
    await waitErr(/still in use/);
    // grants of the group, found by name
    await open('#/admin/grants?who=e2e-ops', /^Administration$/);
    await b.waitCss('table.grants');
    await b.waitFor(async () => (await b.exec(() => document.querySelectorAll('table.grants tbody tr').length)) > 0, { message: 'the grants of e2e-ops to be listed' });
    await labelsOk('grants');
    eq(await b.exec(() => [...document.querySelectorAll('table.grants tbody tr')].map((r) => [...r.children].slice(0, 4).map((c) => c.innerText.trim()))), [['e2e-ops', 'Domain master', 'main / hist.test.', 'web']], 'the grants of the group');
    await click('Remove', 'table.grants');
    await click('Yes', 'table.grants');
    await b.waitText('main', /There is no grant\./);
    // the group and the user are deleted (a question first)
    await open(groupHash, /^Administration$/);
    await b.waitText('main', /Group: e2e-ops/);
    await click('Delete', 'section.danger-zone');
    await click('Yes', 'section.danger-zone');
    await b.waitText('main', /e2e-ops was deleted\./);
    await open('#/admin/users?prefix=newbie', /^Administration$/);
    await b.waitCss('table tbody tr');
    await click('newbie', 'table');
    await b.waitText('main', /User: newbie/);
    await click('Delete', 'section.danger-zone');
    await click('Yes', 'section.danger-zone');
    await b.waitText('main', /newbie was deleted\./);
  });

  console.log('-- a domain master and a subdomain master (S9, S11, S12)');
  await scenario('a domain master: no administration, the audit log of its zone only, the grants of its zone with the policies no wider than its own', async () => {
    await logout();
    await signIn('dom', 'dora quartz lantern 12');
    eq(await b.exec(() => [...document.querySelectorAll('header.top nav a')].map((a) => a.textContent.trim())), ['Home', 'Zones', 'Templates', 'Servers', 'Audit log', 'Account', 'About'], 'the menu of a domain master');
    await open('#/admin/users', /^Administration$/);
    await b.waitText('main', /Only global masters administer users/);
    await open('#/audit', /^Audit log$/);
    await b.waitCss('table.audit tbody tr');
    const zones = await b.exec(() => [...new Set([...document.querySelectorAll('table.audit tbody tr')].map((r) => r.children[3].innerText.trim()))]);
    eq(zones, ['example.test.'], 'the zones of the rows a domain master reads');
    await labelsOk('the audit log');
    await open('#/zones/main/example.test./grants', /^example\.test\./);
    await b.waitCss('select[name=policy]');
    await labelsOk('the grants of a zone');
    eq(await b.exec(() => [...document.querySelectorAll('select[name=policy] option')].map((o) => o.textContent.trim())), ['web'], 'the policies a domain master may give');
    eq(await b.exec(() => [...document.querySelectorAll('select[name=role] option')].map((o) => o.textContent.trim())), ['Domain master', 'Subdomain master'], 'the roles');
    await fill('principal', 'sub', 'form:has(select[name=role])');
    await fill('suffix', 'zz.example.test', 'form:has(select[name=role])');
    await click('Give the grant', 'main');
    await b.waitText('main', /The grant was given\./);
    // (the list is fetched again after the message, as above)
    await b.waitFor(async () => (await b.exec(() => [...document.querySelectorAll('table.grants tbody tr')].some((r) => r.children[0] && r.children[0].innerText.trim() === 'sub'))), { message: 'the new grant of sub to be listed' }).catch(() => {});
    const rows = await b.exec(() => [...document.querySelectorAll('table.grants tbody tr')].map((r) => [...r.children].slice(0, 3).map((c) => c.innerText.trim())));
    must(rows.some((r) => r[0] === 'sub' && r[1] === 'Subdomain master' && r[2].includes('zz.example.test.')), `the grant is not listed: ${JSON.stringify(rows)}`);
    // a grant the service refuses: no more than the policy the person holds is a rule of the service; a zone that is not its own is not found
    await b.exec(() => { [...document.querySelectorAll('table.grants tbody tr')].find((r) => r.children[0].innerText.trim() === 'sub' && r.children[2].innerText.includes('zz.example.test')).querySelector('button').click(); });
    await click('Yes', 'table.grants');
    await b.waitText('main', /The grant was removed\./);
    // the versions of its zone, with the marker for what was done outside them
    await open('#/zones/main/example.test./versions', /^example\.test\./);
    await b.waitCss('table.versions');
    must((await b.exec(() => document.querySelectorAll('table.versions tbody tr').length)) >= 4, 'few versions');
    must((await bodyText()).includes('Roll back...'), 'no way to the rollback');
  });

  await scenario('a subdomain master: the versions are its part of each change, not the names of others', async () => {
    await logout();
    await signIn('sub', 'sam granite pine 1234');
    await open('#/zones/main/example.test./versions', /^example\.test\./);
    await b.waitCss('table.versions');
    await b.waitText('main', /part of each change that lies under your suffix/);
    must(!(await b.exists('table.versions .outside')), 'a subdomain master reads no marker (it cannot read the audit log)');
    const last = Number(await b.exec(() => [...document.querySelectorAll('table.versions tbody tr')].filter((r) => r.querySelector('th'))[0].querySelector('th').innerText.trim()));
    must(last >= 4, `few versions: ${last}`);
    eq(await b.exec(() => [...document.querySelectorAll('header.top nav a')].map((a) => a.textContent.trim())), ['Home', 'Zones', 'Templates', 'Servers', 'Account', 'About'], 'the menu');
    eq(await b.exec(() => [...document.querySelectorAll('nav[aria-label="Sections of this zone"] a')].map((a) => a.textContent.trim())), ['Records', 'Versions', 'Settings'], 'the sections');
    await open(`#/zones/main/example.test./versions/1/diff?to=${last}`, /^example\.test\./);
    await b.waitText('main', new RegExp(`Version 1 against version ${last}`));
    await b.waitFor(async () => (await b.exists('table.diff-table')) || /No difference\./.test(await bodyText()), { message: 'the difference' });
    const shown = await b.exec(() => [...document.querySelectorAll('table.diff-table tbody th')].map((e) => e.innerText.trim()));
    must(shown.length >= 1, 'a subdomain master sees nothing of its own part');
    for (const n of shown) must(/^(@|sub|.+\.sub)$/.test(n), `a name outside the suffix: ${n}`);
    must(!shown.includes('www') && !shown.includes('evilsub'), 'names of others');
    await open('#/zones/main/example.test./grants', /^example\.test\./);
    await b.waitText('main', /managed by the masters of the whole zone/);
    await logout();
    await signIn('admin', E.GUI_ADMIN_PASSWORD);
  });

  console.log('-- the audit log (S12)');
  await scenario('filters, a change set to its version, the rows of hostile data are text', async () => {
    await open('#/audit?zone=hist.test.&table=records', /^Audit log$/);
    await b.waitCss('table.audit tbody tr');
    eq(await b.exec(() => [...new Set([...document.querySelectorAll('table.audit tbody tr')].map((r) => r.children[3].innerText.trim()))]), ['hist.test.'], 'the zone of the rows');
    await labelsOk('the audit log');
    // the change set of a row leads to its version
    const link = await control('version', 'table.audit');
    await link.click();
    await b.waitCss('table.versions');
    must((await b.exec(() => window.location.hash)).includes('/versions?cs='), 'the address of the version');
    await b.waitCss('table.versions tr[aria-current=true]');
    must((await bodyText()).includes('the change you came from'), 'the version is not marked');
    // the form
    await open('#/audit', /^Audit log$/);
    await b.waitCss('table.audit tbody tr');
    await fill('who', 'admin', 'form.search');
    await fill('table', 'records', 'form.search');
    await fill('zone', 'hist.test.', 'form.search');
    await click('Show', 'form.search');
    await b.waitFor(async () => (await b.exec(() => window.location.hash)).includes('who=admin'), { message: 'the filter to be in the address' });
    await b.waitCss('table.audit tbody tr');
    must((await b.exec(() => [...document.querySelectorAll('table.audit tbody tr')].every((r) => r.children[1].innerText.trim() === 'admin'))), 'rows of another person');
    // a name nobody has, a field that is wrong
    await open('#/audit?who=nobody-here', /^Audit log$/);
    await b.waitText('main', /No user or group has this name\./);
    await open('#/audit?since=soon', /^Audit log$/);
    await b.waitText('main', /This is not a time\./);
    // before and after are text
    await open('#/audit?zone=xss.test.&table=records', /^Audit log$/);
    await b.waitCss('table.audit tbody tr');
    const json = await b.exec(() => [...document.querySelectorAll('table.audit pre')].map((p) => p.textContent).join('\n'));
    must(json.includes('onerror'), `the hostile record is not in the details: ${json.slice(0, 300)}`);
    must(!(await b.exists('table.audit img, table.audit script')), 'an element came from the audit log');
    await noTrouble();
    must((await b.exec(() => document.querySelector('table.audit pre').parentNode.querySelectorAll('div').length)) >= 1, 'no lines');
  });

  // ---- milestone M6: what M4 left to the fake DOM, in a real browser
  console.log('-- a conflict found at the commit, and a page of a list (M6)');
  await scenario('a rollback is previewed with no conflict, a change is made behind the page, and the commit is a 409 version-conflict: the conflict is listed, force is asked first', async () => {
    const made = await admin('POST', '/datasets/main/zones', { name: 'race.test', soa: { mname: 'ns1.nsprovider.test', rname: 'hostmaster.nsprovider.test' }, nameservers: ['ns1.nsprovider.test.'], comment: 'the first' });
    must(made.status === 201, `create race.test: ${made.status} ${made.text}`);
    for (const [ip, comment] of [['192.0.2.1', 'one'], ['192.0.2.2', 'two']]) {
      const r = await admin('PATCH', '/datasets/main/zones/race.test/rrsets', { rrsets: [{ name: 'www.race.test.', type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: ip }] }], comment });
      must(r.status === 200, `patch race.test: ${r.status} ${r.text}`);
    }
    await open('#/zones/main/race.test./versions/2', /^race\.test\./);
    await b.waitCss('#rb-title');
    const panel = 'section[aria-labelledby=rb-title]';
    await click('Preview the rollback', panel);
    await b.waitFor(async () => b.exec(() => { const x = [...document.querySelectorAll('section[aria-labelledby=rb-title] button')].find((e) => e.textContent.trim() === 'Roll back'); return x && !x.disabled; }), { message: 'a commit without a conflict' });
    must(!(await b.exists('section.conflict')), 'a conflict before anything was changed behind the page');
    // the change made behind the back of the page and of the versions
    sql("UPDATE records SET content = '192.0.2.77' WHERE name = 'www.race.test' AND type = 'A'");
    await click('Roll back', panel);
    await b.waitCss('section.conflict');
    eq(await b.exec(() => [...document.querySelectorAll('section.conflict tbody tr')].map((r) => [...r.children].map((c) => c.innerText.trim()))), [['www', 'A', '300 192.0.2.2', '300 192.0.2.77']], 'the conflict found at the commit');
    must(!(await bodyText()).includes('The change was saved.'), 'saved although the commit was refused');
    must(await b.exec(() => [...document.querySelectorAll('section[aria-labelledby=rb-title] button')].find((x) => x.textContent.trim() === 'Roll back').disabled), 'a plain commit is possible with a conflict');
    await labelsOk('the rollback with a conflict');
    await click('Roll back anyway and overwrite these', 'section.conflict');
    must(/Overwrite these 1 record sets\?/.test(await b.exec(() => document.querySelector('section.conflict').innerText)), 'the question');
    await click('Yes', 'section.conflict');
    await b.waitText('main', /The change was saved\./);
    await zonePage('race.test.');
    await rowIs('www', 'A', '192.0.2.1', 'www as it was at version 2');
    await noTrouble();
  });

  await scenario('a list has a next page: the link carries the cursor in the address, the second page has the rest, "First page" comes back', async () => {
    const lines = ['$ORIGIN page.test.', '$TTL 300', '@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300', '@ IN NS ns1', 'ns1 IN A 192.0.2.1'];
    for (let i = 1; i <= 60; i++) lines.push(`h${String(i).padStart(2, '0')} IN A 192.0.2.${(i % 200) + 10}`);
    const made = await admin('POST', '/datasets/main/zones', { name: 'page.test', zone_text: `${lines.join('\n')}\n`, comment: 'sixty hosts' });
    must(made.status === 201, `create page.test: ${made.status} ${made.text}`);
    await open('#/zones/main/page.test.?n=25', /^page\.test\./);
    const names = () => b.exec(() => [...document.querySelectorAll('table.rrsets tbody tr')].map((r) => (r.querySelector('th') || r.children[0]).innerText.trim()));
    await b.waitFor(async () => (await names()).length === 25, { message: 'the first page of 25' });
    const first = await names();
    eq(first[0], 'h01', 'the first page starts at the first name');
    must(!(await b.exec(() => [...document.querySelectorAll('main a')].some((a) => a.textContent.trim() === 'First page'))), 'a link back to the first page on the first page');
    await click('Next page');
    await b.waitFor(async () => (await b.exec(() => window.location.hash)).includes('cursor='), { message: 'the cursor to be in the address' });
    await b.waitFor(async () => { const n = await names(); return n.length > 0 && n[0] !== first[0]; }, { message: 'the second page' });
    const second = await names();
    eq(second.length, 25, 'the second page has 25 rows');
    must(second.every((n) => !first.includes(n)), 'a row of the first page is on the second');
    eq(second[0], 'h26', 'the second page continues where the first stopped');
    await labelsOk('the second page');
    // the last page has no next link; 63 sets in all: 25 + 25 + 13
    await click('Next page');
    await b.waitFor(async () => (await names()).length === 13, { message: 'the last page' });
    must(!(await b.exec(() => [...document.querySelectorAll('main a')].some((a) => a.textContent.trim() === 'Next page'))), 'a next link on the last page');
    await click('First page');
    await b.waitFor(async () => { const n = await names(); return n.length === 25 && n[0] === first[0]; }, { message: 'the first page again' });
    must(!(await b.exec(() => window.location.hash)).includes('cursor='), 'the cursor stays in the address after "First page"');
    await noTrouble();
  });

  await scenario('in 320 CSS pixels nothing but a table or a block of code reaches past the right edge: the zone list, a zone, the versions, the users, the audit log', async () => {
    await b.cmd('POST', '/window/rect', { width: 320, height: 800 });
    try {
      for (const [hash, h1] of [['#/zones', /^Zones$/], ['#/zones/main/hist.test.', /^hist\.test\./], ['#/zones/main/hist.test./versions', /^hist\.test\./], ['#/admin/users', /^Administration$/], ['#/audit', /^Audit log$/]]) {
        await open(hash, h1);
        await b.waitFor(async () => b.exec(() => !/Loading/.test(document.querySelector('main').innerText)), { message: `${hash} to be loaded`, timeout: 15000 });
        const r = await b.exec(overflowProblems);
        eq(r.bad, [], `${hash} at ${r.width} px`);
        must(r.window <= 640, `the window is wider than 40rem (${r.window} px)`);
      }
    } finally {
      await b.cmd('POST', '/window/rect', { width: 1280, height: 900 });
    }
  });

  console.log(`  [TIME] the scenarios of milestone M4 (S9 to S12) took ${Math.round((Date.now() - m4start) / 1000)} s`);
  console.log('-- the policy of the page');
  await scenario('every resource came from the origin and the page never reported a violation', async () => {
    const urls = await b.exec(() => performance.getEntriesByType('resource').map((e) => e.name));
    for (const u of urls) must(u.startsWith(`${BASE}/`), `${u} is not of the origin`);
    await noTrouble();
  });
} finally {
  await started.stop();
}
console.log(`\n${pass} passed, ${fails} failed`);
exitCode = fails ? 1 : 0;
process.exit(exitCode);

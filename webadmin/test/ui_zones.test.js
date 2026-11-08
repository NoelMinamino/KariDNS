// The zone screens (S3, S4, S5, S5a, reload, S14) on the fake DOM against a scripted API (planning 8.1, F-11): what is on the page, what the forms send, how every refusal is
// shown, hostile data (no element may come from it).

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootApp, reply, problem, flush, findAll, byText, GRANT_GLOBAL, POLICY, VERSION } from './ui_boot.js';
import { FakeEvent } from './fakedom.js';

const INFO = {
  name: 'example.test.', id: 1, kind: 'NATIVE', serial: 10, catalog: null, master: null, account: null, notified_serial: null, presigned: false, signer: false, nsec3param: null,
  generation: 5, changed_at: '2026-11-09T00:00:00Z', views: [], signer_state: null, waiting_for_signer: false, last_reload_request: null, role: 'global_master', grants: [GRANT_GLOBAL],
};
const rec = (rdata, ttl = 300, extra = {}) => ({ content: rdata, rdata, disabled: false, ttl, ...extra });
const RRSETS = [
  { name: 'example.test.', type: 'SOA', ttl: 3600, tagged: false, records: [rec('ns1.example.test. hostmaster.example.test. 10 7200 3600 1209600 300', 3600, { content: 'ns1.example.test hostmaster.example.test 10 7200 3600 1209600 300' })] },
  { name: 'example.test.', type: 'MX', ttl: 3600, tagged: false, records: [rec('10 mail.example.test.', 3600, { content: '10 mail.example.test' })] },
  { name: 'www.example.test.', type: 'A', ttl: 300, tagged: false, records: [rec('192.0.2.10'), rec('192.0.2.11')] },
  { name: 'txt.example.test.', type: 'TXT', ttl: 300, tagged: false, records: [rec('"<img src=x onerror=window.__xss=1>"'), rec(`"a${String.fromCharCode(0x202e)}b\u0001c"`)] },
  { name: 'tag.example.test.', type: 'A', ttl: 300, tagged: true, records: [rec('192.0.2.50')] },
  { name: 'sig.example.test.', type: 'RRSIG', ttl: 300, tagged: false, records: [rec('A 13 3 300 20261201000000 20261101000000 1 example.test. abc')] },
  { name: 'odd.example.test.', type: 'TXT', ttl: 300, tagged: false, records: [{ content: 'stored form', rdata: null, disabled: false, ttl: 300 }] },
  { name: 'off.example.test.', type: 'A', ttl: 300, tagged: false, records: [{ ...rec('192.0.2.40'), disabled: true }] },
];

// the routes of one zone; `st` is the state a test changes
function zoneRoutes(st = {}, over = {}) {
  return {
    'GET /datasets': () => reply(200, { api: 1, datasets: [{ name: 'main', driver: 'sqlite3', views: st.views ?? [] }] }),
    'GET /datasets/main/zones': () => reply(200, { api: 1, zones: st.zones ?? [{ name: 'example.test.', kind: 'NATIVE', serial: 10, presigned: false, signer: false, catalog: null, role: 'global_master' }], next_cursor: st.next ?? null }),
    'GET /datasets/main/zones/example.test.': () => reply(200, { api: 1, zone: { ...INFO, ...(st.info ?? {}) } }),
    'GET /datasets/main/zones/example.test./rrsets': () => reply(200, { api: 1, rrsets: st.rrsets ?? RRSETS, next_cursor: st.rrNext ?? null }),
    ...over,
  };
}
const ZONE = '#/zones/main/example.test.';
const TAGS = new Set(['DIV', 'SECTION', 'HEADER', 'MAIN', 'FOOTER', 'NAV', 'UL', 'LI', 'A', 'SPAN', 'STRONG', 'P', 'H1', 'H2', 'H3', 'H4', 'BUTTON', 'FORM', 'LABEL', 'INPUT', 'SELECT', 'OPTION',
  'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD', 'CAPTION', 'DL', 'DT', 'DD', 'CODE', 'TIME', 'OL', 'SVG', 'PATH', 'DIALOG', 'TEXTAREA', 'B', 'I', 'EM', 'FIELDSET', 'LEGEND']);
const noForeign = (ui) => { for (const e of findAll(ui.env.document.body, () => true)) assert.ok(TAGS.has(e.tagName), `unexpected element ${e.tagName}`); };
const rows = (ui) => ui.qa('table.rrsets tbody tr');
const rowOf = (ui, name, type) => rows(ui).find((r) => r.querySelector('th').textContent === name && r.childNodes[1].textContent === type);
const buttonIn = (el, re) => byText(el, 'button', re);
const sectionsNav = (ui) => findAll(ui.root, (e) => e.tagName === 'NAV' && e.getAttribute('aria-label') === 'Sections of this zone')[0];
const chosen = (ui, el, v) => { el.value = v; el.dispatchEvent(new FakeEvent('change')); return flush(); };

// ---------------------------------------------------------------------------------------------------------------------------------- S3
test('S3: the zone list shows the role, kind, serial and badges; the search form goes to the route with its query', async () => {
  const st = { zones: [
    { name: 'example.test.', kind: 'NATIVE', serial: 10, presigned: false, signer: true, catalog: null, role: 'domain_master' },
    { name: 'signed.test.', kind: 'MASTER', serial: null, presigned: true, signer: false, catalog: 'cat.test.', role: 'subdomain_master' },
    { name: '<b>x</b>.test.', kind: 'SLAVE', serial: 3, presigned: false, signer: false, catalog: null, role: 'global_master' },
  ] };
  const ui = await bootApp({ routes: zoneRoutes(st), hash: '#/zones' });
  assert.equal(ui.q('h1').textContent, 'Zones');
  assert.equal(ui.qa('select').length, 3, 'no dataset selector with one dataset: mode, kind, signed');
  const trs = ui.qa('tbody tr');
  assert.equal(trs.length, 3);
  assert.deepEqual(trs[0].childNodes.map((c) => c.textContent), ['example.test.', 'Domain master', 'NATIVE', '10', 'kept signed by the signer']);
  assert.deepEqual(trs[1].childNodes.map((c) => c.textContent), ['signed.test.', 'Subdomain master', 'MASTER', '-', 'signed elsewherecatalog cat.test.']);
  assert.equal(trs[2].querySelector('a').textContent, '<b>x</b>.test.', 'a name is text');
  assert.equal(trs[0].querySelector('a').getAttribute('href'), '#/zones/main/example.test.');
  assert.equal(trs[2].querySelector('a').getAttribute('href'), '#/zones/main/%3Cb%3Ex%3C%2Fb%3E.test.', 'the link is built from the encoded name');
  assert.equal(ui.link(/^Zones$/).getAttribute('aria-current'), 'page');
  assert.ok(ui.link(/^New zone$/), 'a global master can make a zone');
  assert.equal(ui.last('GET', '/datasets/main/zones').url, '/api/v1/datasets/main/zones?limit=100');
  noForeign(ui);

  // a search
  ui.type(ui.input('q'), 'exa');
  await chosen(ui, ui.input('mode'), 'prefix');
  await chosen(ui, ui.input('kind'), 'MASTER');
  await chosen(ui, ui.input('signed'), 'true');
  await ui.submit(ui.q('form'));
  assert.equal(ui.env.window.location.hash, '#/zones?ds=main&q=exa&mode=prefix&kind=MASTER&signed=true');
  assert.equal(ui.last('GET', '/datasets/main/zones').url, '/api/v1/datasets/main/zones?limit=100&kind=MASTER&signed=true&prefix=exa');
  // a text the service would refuse is told here
  ui.type(ui.input('q'), 'a b');
  await ui.submit(ui.q('form'));
  assert.match(ui.text(), /Use letters, digits, dots, hyphens and underscores only\./);
  assert.equal(ui.env.window.location.hash, '#/zones?ds=main&q=exa&mode=prefix&kind=MASTER&signed=true');
});

test('S3: contains by default, a next page with a cursor and a link back to the first; no zones; a failure; more than one dataset', async () => {
  const st = { next: 'CUR1' };
  const ui = await bootApp({ routes: { ...zoneRoutes(st), 'GET /datasets': () => reply(200, { datasets: [{ name: 'main', views: [] }, { name: 'other', views: [] }] }), 'GET /datasets/other/zones': () => reply(200, { zones: [], next_cursor: null }) }, hash: '#/zones?q=ex' });
  assert.match(ui.last('GET', '/zones').url, /contains=ex/);
  const next = ui.link(/^Next page$/);
  assert.equal(next.getAttribute('href'), '#/zones?q=ex&ds=main&cursor=CUR1');
  assert.equal(ui.qa('select').length, 4, 'a dataset selector');
  await ui.go('#/zones?q=ex&ds=main&cursor=CUR1');
  assert.match(ui.last('GET', '/zones').url, /cursor=CUR1/);
  assert.ok(ui.link(/^First page$/));
  // another dataset: nothing there
  await ui.go('#/zones?ds=other');
  assert.match(ui.text(), /No zone matches\./);
  await ui.go('#/zones?ds=other&cursor=X');
  assert.match(ui.text(), /There are no more zones\./);

  const none = await bootApp({ routes: { 'GET /datasets': reply(200, { datasets: [] }) }, hash: '#/zones' });
  assert.match(none.text(), /The service has no dataset\./);
  const down = await bootApp({ routes: { 'GET /datasets': problem(503, 'database-unavailable') }, hash: '#/zones' });
  assert.match(down.q('p.msg.error').textContent, /The database cannot be reached/);
});

test('S3: a person who is not a global master has no way to make a zone; the whole dataset can be reloaded after a question', async () => {
  const dom = await bootApp({ routes: zoneRoutes(), hash: '#/zones', me: { global: false, grants: [] } });
  assert.equal(dom.link(/^New zone$/), null);
  assert.equal(dom.button(/Update every zone/), null);

  const ui = await bootApp({ routes: zoneRoutes({}, { 'POST /datasets/main/reload': () => reply(200, { dataset: 'main', change_set: 'x', reload: 'requested' }) }), hash: '#/zones' });
  await ui.click(ui.button(/Update every zone/));
  assert.equal(ui.count('POST', '/datasets/main/reload'), 0, 'the first click asks');
  await ui.click(ui.button(/^Yes$/));
  assert.equal(ui.count('POST', '/datasets/main/reload'), 1);
  assert.match(ui.text(), /The servers were asked to load the zone again\./);
  ui.routes['POST /datasets/main/reload'] = () => problem(409, 'signer-zones');
  await ui.click(ui.button(/Update every zone/));
  await ui.click(ui.button(/^Yes$/));
  assert.match(ui.q('p.msg.error').textContent, /kept signed by the signer/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- S4
test('S4: the zone page: header, record sets with names relative to the zone, the reasons, hostile text as text', async () => {
  const ui = await bootApp({ routes: zoneRoutes(), hash: ZONE });
  assert.match(ui.q('h1').textContent, /^example\.test\. NATIVE/);
  assert.equal(ui.env.document.title, 'example.test. - KariDNS WebAdmin');
  const dl = ui.q('dl').textContent;
  assert.match(dl, /Serial10/);
  assert.match(dl, /Generation5/);
  assert.match(dl, /Your roleGlobal master/);
  assert.match(dl, /types: A, AAAA, CNAME, MX, NS, SOA, SRV, TXT; TTL: 0-2147483647; allowed: wildcards, delegations, zone apex/);
  assert.equal(ui.last('GET', '/rrsets').url, '/api/v1/datasets/main/zones/example.test./rrsets?rdata=1&limit=100');
  assert.equal(rows(ui).length, RRSETS.length);
  const mx = rowOf(ui, '@', 'MX');
  assert.equal(mx.childNodes[3].textContent, '10 mail.example.test.', 'the text form, not the stored one');
  assert.equal(rowOf(ui, 'www', 'A').childNodes[3].textContent, '192.0.2.10192.0.2.11');
  assert.equal(rowOf(ui, 'www', 'A').querySelector('th').getAttribute('title'), 'www.example.test.');
  // the reasons
  const state = (n, t) => rowOf(ui, n, t).childNodes[4].textContent;
  assert.match(state('@', 'SOA'), /The SOA: the service writes the serial\./);
  assert.match(state('tag', 'A'), /location or ECS tags/);
  assert.match(state('sig', 'RRSIG'), /the signer makes the DNSSEC records/);
  assert.match(state('odd', 'TXT'), /no text form/);
  assert.match(state('off', 'A'), /switched off/);
  assert.equal(state('www', 'A'), '');
  assert.ok(buttonIn(rowOf(ui, 'www', 'A'), /^Edit$/) && buttonIn(rowOf(ui, 'www', 'A'), /^Delete$/));
  assert.equal(buttonIn(rowOf(ui, 'tag', 'A'), /^Edit$/), null);
  assert.ok(buttonIn(rowOf(ui, '@', 'SOA'), /^Edit the SOA$/), 'a global master can edit the SOA in its own form');
  assert.equal(buttonIn(rowOf(ui, 'www', 'A'), /^Edit$/).getAttribute('aria-label'), 'Edit www A');
  // hostile data
  const txt = rowOf(ui, 'txt', 'TXT').childNodes[3];
  assert.equal(txt.textContent, '"<img src=x onerror=window.__xss=1>""a<U+202E>b\\001c"');
  assert.equal(findAll(txt, (e) => e.tagName === 'IMG').length, 0);
  noForeign(ui);
  // the sections of the zone and the export link
  const nav = sectionsNav(ui);
  assert.deepEqual(findAll(nav, (e) => e.tagName === 'A').map((a) => a.textContent), ['Records', 'Import', 'Settings', 'DNSSEC', 'Export (zone file)']);
  const exp = findAll(nav, (e) => e.tagName === 'A').pop();
  assert.equal(exp.getAttribute('href'), '/api/v1/datasets/main/zones/example.test./export');
  assert.equal(exp.getAttribute('download'), '');
  assert.equal(findAll(nav, (e) => e.tagName === 'A')[0].getAttribute('aria-current'), 'page');
});

test('S4: search, paging by cursor, the page size', async () => {
  const st = { rrNext: 'C2' };
  const ui = await bootApp({ routes: zoneRoutes(st), hash: `${ZONE}?contains=ww&type=a&n=25` });
  assert.equal(ui.last('GET', '/rrsets').url, '/api/v1/datasets/main/zones/example.test./rrsets?rdata=1&limit=25&contains=ww&type=a');
  assert.equal(ui.input('contains').value, 'ww');
  assert.equal(ui.input('n').value, '25');
  assert.equal(ui.link(/^Next page$/).getAttribute('href'), `${ZONE}?contains=ww&type=a&n=25&cursor=C2`);
  ui.type(ui.input('from'), 'm');
  ui.type(ui.input('contains'), '');
  await chosen(ui, ui.input('n'), '250');
  await ui.submit(ui.q('form.search'));
  assert.equal(ui.env.window.location.hash, `${ZONE}?from=m&type=a&n=250`);
  await ui.go(`${ZONE}?cursor=C2`);
  assert.match(ui.last('GET', '/rrsets').url, /cursor=C2/);
  assert.ok(ui.link(/^First page$/));
  st.rrsets = [];
  await ui.go(`${ZONE}?contains=zzz`);
  assert.match(ui.text(), /No record set matches\./);
});

test('S4: a zone that does not exist or may not be seen; a failure of the page of record sets', async () => {
  const ui = await bootApp({ routes: { 'GET /datasets/main/zones/nope.test.': problem(404, 'not-found') }, hash: '#/zones/main/nope.test.' });
  assert.match(ui.q('p.msg.error').textContent, /There is no such object, or you may not see it\./);
  assert.ok(ui.link(/^Back to the zones$/));
  const bad = await bootApp({ routes: zoneRoutes({}, { 'GET /datasets/main/zones/example.test./rrsets': problem(500, 'internal') }), hash: ZONE });
  assert.ok(findAll(bad.root, (e) => e.className === 'msg error').some((e) => /internal error/.test(e.textContent)));
});

test('S4: read-only zones: a secondary zone, a zone signed elsewhere, a zone the signer keeps, a subdomain master', async () => {
  const slave = await bootApp({ routes: zoneRoutes({ info: { kind: 'SLAVE' } }), hash: ZONE });
  assert.match(slave.text(), /Read only: this is not a primary zone\./);
  assert.equal(slave.button(/Add a record set/), null);
  assert.equal(slave.q('section.draft'), null, 'no draft panel');
  assert.equal(buttonIn(rowOf(slave, 'www', 'A'), /^Edit$/), null);
  const pre = await bootApp({ routes: zoneRoutes({ info: { presigned: true } }), hash: ZONE });
  assert.match(pre.text(), /Read only: the zone is signed elsewhere\./);
  assert.match(pre.q('h1').textContent, /signed elsewhere/);
  const signer = await bootApp({ routes: zoneRoutes({ info: { signer: true, waiting_for_signer: true, signer_state: { signed_serial: null } } }), hash: ZONE });
  assert.equal(signer.button(/Update the servers now/), null, 'no button for a zone the signer keeps');
  assert.match(signer.text(), /there is no button to press/);
  assert.match(signer.q('h1').textContent, /waiting for the signer/);
  assert.match(signer.q('dl').textContent, /Serial the signer has signednot signed yet/);
  assert.ok(buttonIn(rowOf(signer, 'www', 'A'), /^Edit$/), 'its data are edited');
  assert.equal(signer.findAll, undefined);
  // a subdomain master: only its part, the sections without import and DNSSEC
  const grants = [{ id: 3, role: 'subdomain_master', dataset: 'main', zone: 'example.test.', suffix: 'sub.example.test.', policy: { ...POLICY, apex_editable: true }, via: null }];
  const sub = await bootApp({
    routes: zoneRoutes({ info: { role: 'subdomain_master', grants }, rrsets: [
      { name: 'example.test.', type: 'SOA', ttl: 3600, tagged: false, records: [rec('a. b. 1 2 3 4 5')] },
      { name: 'example.test.', type: 'NS', ttl: 3600, tagged: false, records: [rec('ns1.example.test.')] },
      { name: 'a.sub.example.test.', type: 'A', ttl: 300, tagged: false, records: [rec('192.0.2.5')] },
      { name: 'evilsub.example.test.', type: 'A', ttl: 300, tagged: false, records: [rec('192.0.2.6')] }] }),
    hash: ZONE, me: { global: false, grants },
  });
  assert.deepEqual(findAll(sectionsNav(sub), (e) => e.tagName === 'A').map((a) => a.textContent), ['Records', 'Settings']);
  assert.match(sub.q('dl').textContent, /Subdomain master.*sub\.example\.test\./);
  assert.match(rowOf(sub, '@', 'NS').childNodes[4].textContent, /outside your part of the zone/);
  assert.equal(buttonIn(rowOf(sub, '@', 'SOA'), /Edit/), null, 'not a global master: no SOA form');
  assert.ok(buttonIn(rowOf(sub, 'a.sub', 'A'), /^Edit$/));
  assert.match(rowOf(sub, 'evilsub', 'A').childNodes[4].textContent, /outside your part of the zone/);
  await sub.go(`${ZONE}/import`);
  assert.match(sub.text(), /The import is for the masters of the whole zone\./);
  await sub.go(`${ZONE}/dnssec`);
  assert.match(sub.text(), /DNSSEC is for the masters of the whole zone\./);
});

// ---------------------------------------------------------------------------------------------------------------------------------- S5
const editorOf = (ui) => ui.dialogs()[0];
async function openEdit(ui, name, type) {
  await ui.click(buttonIn(rowOf(ui, name, type), /^Edit$/));
  return editorOf(ui);
}

test('S5: edit a record set: the editor, the draft, the preview (a dry run with expect from the text form), the commit and the result', async () => {
  const st = {};
  const patched = [];
  const ui = await bootApp({ routes: zoneRoutes(st, {
    'PATCH /datasets/main/zones/example.test./rrsets': (body) => {
      patched.push(body);
      if (body.dry_run) {
        return reply(200, { api: 1, dry_run: true, allowed: true, version: 4, generation: 6, serial: { before: 10, after: 11 }, records: { before: 7, after: 7 }, diff: [
          { name: 'www.example.test.', type: 'A', change: 'replace', before: [{ ttl: 300, content: '192.0.2.10' }, { ttl: 300, content: '192.0.2.11' }], after: [{ ttl: 60, content: '192.0.2.99' }] }],
        messages: [{ code: 'zone.ttl', severity: 'warning', text: 'a low TTL' }] });
      }
      return reply(200, { api: 1, committed: true, changed: true, change_set: 'cs', version: 4, generation: { before: 5, after: 6 }, serial: { before: 10, after: 11 }, records: { before: 7, after: 7 },
        diff: [{ name: 'www.example.test.', type: 'A', change: 'replace', before: [{ ttl: 300, content: '192.0.2.10' }], after: [{ ttl: 60, content: '192.0.2.99' }] }], messages: [], reload: 'requested' });
    },
  }), hash: ZONE });
  assert.match(ui.q('section.draft').textContent, /Nothing is changed yet/);
  const dlg = await openEdit(ui, 'www', 'A');
  assert.ok(dlg, 'the editor is a dialog');
  assert.equal(dlg.querySelector('h2').textContent, 'Edit www A');
  assert.equal(ui.input('records', dlg).value, '192.0.2.10\n192.0.2.11');
  assert.equal(ui.input('ttl', dlg).value, '300');
  assert.equal(findAll(dlg, (e) => e.className === 'hint').map((e) => e.textContent).join(' ').includes('Your policy allows 0 to 2147483647.'), true);
  // nothing different
  await ui.submit(dlg.querySelector('form'));
  assert.match(dlg.textContent, /Nothing is different from what the zone has\./);
  // bad input
  ui.type(ui.input('ttl', dlg), 'abc');
  await ui.submit(dlg.querySelector('form'));
  assert.match(dlg.textContent, /Enter a TTL from 0 to 2147483647\./);
  ui.type(ui.input('ttl', dlg), '60');
  ui.type(ui.input('records', dlg), ' \n ');
  await ui.submit(dlg.querySelector('form'));
  assert.match(dlg.textContent, /Enter at least one record\./);
  ui.type(ui.input('records', dlg), '192.0.2.99\n');
  await ui.submit(dlg.querySelector('form'));
  assert.equal(ui.dialogs().length, 0, 'the dialog is closed');
  // the draft
  const panel = ui.q('section.draft');
  assert.match(panel.querySelector('h2').textContent, /Your changes \(1\)/);
  assert.match(panel.querySelector('ul.draft-list').textContent, /Replace www A \(TTL 60\) Edit Undo192\.0\.2\.99/);
  assert.equal(rowOf(ui, 'www', 'A').className, 'drafted op-replace');
  assert.match(rowOf(ui, 'www', 'A').childNodes[4].textContent, /Replace/);
  assert.equal(ui.app.session.dirty(), true, 'the page asks before it is left');
  assert.equal(buttonIn(panel, /^Commit$/).disabled, true, 'commit waits for a preview');
  assert.equal(ui.count('PATCH', '/rrsets'), 0, 'nothing is sent while editing');

  // the preview
  ui.type(ui.input('comment', panel), 'move www');
  await ui.click(buttonIn(panel, /^Preview$/));
  assert.deepEqual(patched[0], { rrsets: [{ name: 'www.example.test.', type: 'A', changetype: 'REPLACE', ttl: 60, records: [{ content: '192.0.2.99' }],
    expect: [{ ttl: 300, content: '192.0.2.10' }, { ttl: 300, content: '192.0.2.11' }] }], comment: 'move www', reload: false, dry_run: true });
  assert.match(panel.textContent, /This is what the change would do\. Nothing is saved yet\./);
  assert.match(panel.textContent, /Version it would be4/);
  assert.match(panel.textContent, /Serial10 → 11/);
  assert.match(panel.textContent, /0 added, 1 changed, 0 deleted/);
  const diffRow = panel.querySelector('table.diff-table tbody tr');
  assert.equal(diffRow.className, 'change-replace');
  assert.equal(diffRow.childNodes[2].textContent, '~ changed');
  assert.equal(diffRow.childNodes[3].textContent, '- 300 192.0.2.10- 300 192.0.2.11+ 60 192.0.2.99', 'by sign and word, not colour alone');
  assert.match(panel.querySelector('ul.messages').textContent, /Warning zone\.ttl a low TTL/);
  assert.equal(buttonIn(panel, /^Commit$/).disabled, false);

  // a change to the draft makes the preview stale
  ui.routes['PATCH /datasets/main/zones/example.test./rrsets'].calls = undefined;
  await ui.click(buttonIn(panel.querySelector('ul.draft-list'), /^Edit$/));
  const dlg2 = editorOf(ui);
  assert.equal(ui.input('records', dlg2).value, '192.0.2.99');
  ui.type(ui.input('records', dlg2), '192.0.2.98');
  await ui.submit(dlg2.querySelector('form'));
  assert.equal(buttonIn(ui.q('section.draft'), /^Commit$/).disabled, true);
  assert.equal(ui.q('section.draft').querySelector('table'), null, 'the old preview is gone');
  assert.match(ui.q('ul.draft-list').textContent, /192\.0\.2\.98/);

  // preview again, then commit with "update the servers now" ticked
  await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/));
  ui.input('reload', ui.q('section.draft')).checked = true;
  await ui.click(buttonIn(ui.q('section.draft'), /^Commit$/));
  const commit = patched[patched.length - 1];
  assert.equal(commit.dry_run, undefined);
  assert.equal(commit.reload, true);
  assert.equal(commit.rrsets[0].records[0].content, '192.0.2.98');
  assert.match(ui.text(), /The change was saved\./);
  assert.match(ui.q('section[aria-labelledby="last-title"]').textContent, /Last change/);
  assert.match(ui.q('section[aria-labelledby="last-title"]').textContent, /Version4/);
  assert.match(ui.q('section[aria-labelledby="last-title"]').textContent, /ServersThe servers were asked to load the zone again\./);
  assert.equal(ui.app.session.dirty(), false, 'the draft is gone');
  assert.match(ui.q('section.draft').textContent, /Nothing is changed yet/);
  assert.equal(ui.count('GET', '/rrsets'), 2, 'the page of record sets was read again');
  assert.match(ui.polite(), /The change was saved\./);
});

test('S5: add a record set (name relative or absolute, a type from the list), delete one, undo, discard; the SOA has its own form with a warning and no precondition', async () => {
  const sent = [];
  const ui = await bootApp({ routes: zoneRoutes({}, { 'PATCH /datasets/main/zones/example.test./rrsets': (b) => { sent.push(b); return reply(200, { dry_run: true, allowed: true, diff: [], messages: [] }); } }), hash: ZONE });
  await ui.click(ui.button(/^Add a record set$/));
  let dlg = editorOf(ui);
  assert.equal(dlg.querySelector('h2').textContent, 'Add a record set');
  assert.equal(ui.input('type', dlg).value, 'A');
  assert.deepEqual(findAll(ui.input('type', dlg), (e) => e.tagName === 'OPTION').map((o) => o.textContent), ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV'].sort(), 'no SOA, no DNSSEC types');
  await ui.submit(dlg.querySelector('form'));
  assert.match(dlg.textContent, /Enter a name for the record set\./);
  ui.type(ui.input('name', dlg), 'bad name');
  await ui.submit(dlg.querySelector('form'));
  assert.match(dlg.textContent, /Enter a name for the record set\./);
  ui.type(ui.input('name', dlg), 'New');
  ui.type(ui.input('ttl', dlg), '300');
  ui.type(ui.input('records', dlg), '192.0.2.77');
  await chosen(ui, ui.input('type', dlg), 'A');
  await ui.submit(dlg.querySelector('form'));
  assert.match(ui.q('ul.draft-list').textContent, /Add new A \(TTL 300\) Edit Undo192\.0\.2\.77/);
  // an absolute name, and a type chosen
  await ui.click(ui.button(/^Add a record set$/));
  dlg = editorOf(ui);
  ui.type(ui.input('name', dlg), 'mail.example.test.');
  await chosen(ui, ui.input('type', dlg), 'MX');
  ui.type(ui.input('ttl', dlg), '3600');
  ui.type(ui.input('records', dlg), '10 mx.example.test.');
  await ui.submit(dlg.querySelector('form'));
  // a delete is a draft entry at once
  await ui.click(buttonIn(rowOf(ui, 'www', 'A'), /^Delete$/));
  assert.equal(rowOf(ui, 'www', 'A').className, 'drafted op-delete');
  assert.match(ui.q('ul.draft-list').textContent, /Delete www A  Undo/);
  assert.equal(ui.count('PATCH', '/rrsets'), 0);
  // undo from the table
  assert.ok(buttonIn(rowOf(ui, 'www', 'A'), /^Undo$/));
  await ui.click(buttonIn(rowOf(ui, 'www', 'A'), /^Undo$/));
  assert.equal(rowOf(ui, 'www', 'A').className, '');
  // the SOA: its own form
  await ui.click(buttonIn(rowOf(ui, '@', 'SOA'), /^Edit the SOA$/));
  dlg = editorOf(ui);
  assert.equal(dlg.querySelector('h2').textContent, 'Edit the SOA @ SOA');
  assert.match(dlg.textContent, /writes the SOA with the next serial whatever you type/);
  ui.type(ui.input('records', dlg), 'a\nb');
  await ui.submit(dlg.querySelector('form'));
  assert.match(dlg.textContent, /The SOA has exactly one record\./);
  ui.type(ui.input('records', dlg), 'ns1.example.test. hostmaster.example.test. 10 7200 3600 1209600 600');
  ui.type(ui.input('ttl', dlg), '7200');
  await ui.submit(dlg.querySelector('form'));
  await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/));
  assert.deepEqual(sent[0].rrsets.map((r) => [r.name, r.type, r.changetype, r.expect]), [
    ['new.example.test.', 'A', 'REPLACE', []], ['mail.example.test.', 'MX', 'REPLACE', []], ['example.test.', 'SOA', 'REPLACE', undefined]]);
  assert.equal(sent[0].rrsets[2].ttl, 7200);
  // discard everything
  await ui.click(ui.button(/^Discard all changes$/));
  assert.match(ui.q('section.draft').textContent, /Nothing is changed yet/);
  assert.equal(ui.app.session.dirty(), false);
});

// ---------------------------------------------------------------------------------------------------------------------------------- S5a
const rrsetsRoute = 'PATCH /datasets/main/zones/example.test./rrsets';
// a draft with one replaced RRset (www A), ready to preview
async function draftWww(ui, records = '192.0.2.99') {
  const dlg = await openEdit(ui, 'www', 'A');
  ui.type(ui.input('records', dlg), records);
  await ui.submit(dlg.querySelector('form'));
  return ui.q('section.draft');
}
const okDry = () => reply(200, { dry_run: true, allowed: true, version: 4, generation: 6, serial: { before: 10, after: 11 }, records: { before: 7, after: 7 }, diff: [], messages: [] });

test('S5a: a precondition that no longer holds: what I loaded, what is there now, my change; "keep mine" rebases and previews again, "take theirs" drops my entry and reads the page again', async () => {
  const seen = [];
  const current = [{ ttl: 300, content: '192.0.2.55' }];
  const ui = await bootApp({ routes: zoneRoutes({}, { [rrsetsRoute]: (body) => {
    seen.push(body);
    return seen.length === 1 ? problem(409, 'precondition-failed', { errors: [{ code: 'precondition-failed', severity: 'error', text: 'A www.example.test. is not as expected', pointer: '/rrsets/0/expect', current }] }) : okDry();
  } }), hash: ZONE });
  let panel = await draftWww(ui);
  await ui.click(buttonIn(panel, /^Preview$/));
  panel = ui.q('section.draft');
  assert.match(panel.textContent, /The records were changed by someone else after you loaded them\./);
  const card = panel.querySelector('div.conflict');
  assert.equal(card.querySelector('h3').textContent, 'www A');
  const cols = card.querySelectorAll('div.rec-block');
  assert.deepEqual(cols.map((c) => c.textContent), ['300 192.0.2.10300 192.0.2.11', '300 192.0.2.55', '192.0.2.99']);
  assert.equal(buttonIn(panel, /^Commit$/).disabled, true);
  // keep mine: the precondition is what is there now
  await ui.click(buttonIn(card, /^Keep mine$/));
  assert.equal(ui.q('section.draft').querySelector('div.conflict'), null);
  assert.match(ui.polite(), /Done\. Preview the changes again\./);
  await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/));
  assert.deepEqual(seen[1].rrsets[0].expect, current, 'the new precondition is the present state');
  assert.deepEqual(seen[1].rrsets[0].records, [{ content: '192.0.2.99' }], 'my records are still mine');
  assert.equal(buttonIn(ui.q('section.draft'), /^Commit$/).disabled, false);

  // take theirs: my entry goes, the page is read again
  seen.length = 0;
  const reads = ui.count('GET', '/rrsets');
  await ui.click(buttonIn(ui.q('ul.draft-list'), /^Undo$/));
  panel = await draftWww(ui);
  await ui.click(buttonIn(panel, /^Preview$/));
  await ui.click(buttonIn(ui.q('div.conflict'), /^Take theirs$/));
  assert.equal(ui.q('section.draft').querySelector('ul.draft-list'), null, 'my change is dropped');
  assert.ok(ui.count('GET', '/rrsets') > reads, 'the record sets were read again');
  assert.equal(rowOf(ui, 'www', 'A').className, '');
});

test('S5a: a precondition for an RRset that is gone: "now" is empty; a conflict for an entry that was undone in the meantime is not shown', async () => {
  const ui = await bootApp({ routes: zoneRoutes({}, { [rrsetsRoute]: () => problem(409, 'precondition-failed', { errors: [
    { code: 'precondition-failed', severity: 'error', text: 'x', pointer: '/rrsets/0/expect', current: null }, { code: 'precondition-failed', severity: 'error', text: 'y', pointer: '/rrsets/9/expect' }, { code: 'precondition-failed', severity: 'error', text: 'z' }] }) }), hash: ZONE });
  const panel = await draftWww(ui);
  await ui.click(buttonIn(panel, /^Preview$/));
  const cols = ui.q('div.conflict').querySelectorAll('div.rec-block');
  assert.equal(cols[1].textContent, 'none');
  assert.equal(ui.qa('div.conflict').length, 1, 'one conflict: the pointers that name no entry are not guessed');
  // the entry is deleted from the draft: nothing to decide any more
  await ui.click(buttonIn(ui.q('ul.draft-list'), /^Undo$/));
  assert.equal(ui.q('div.conflict'), null);
});

test('S5a: other refusals: 409 changed, 403 with the RRset, 422 with the record, a denial in the dry run, an unknown code with its request id', async () => {
  let answer = null;
  const ui = await bootApp({ routes: zoneRoutes({}, { [rrsetsRoute]: () => answer() }), hash: ZONE });
  await draftWww(ui);
  const preview = async () => { await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/)); return ui.q('section.draft'); };

  answer = () => problem(409, 'changed');
  let panel = await preview();
  assert.match(panel.querySelector('p.msg.error').textContent, /The zone was changed by someone else while this was done\./);
  assert.equal(panel.querySelector('div.conflict'), null);
  assert.equal(buttonIn(panel, /^Commit$/).disabled, true);

  answer = () => problem(403, 'forbidden', { errors: [{ code: 'not-permitted', severity: 'error', text: 'none of your grants allows A www.example.test. as the change sets it', pointer: '/rrsets/0' }] });
  panel = await preview();
  assert.match(panel.querySelector('p.msg.error').textContent, /You are not allowed to do this\./);
  assert.match(panel.querySelector('ul.entry-errors').textContent, /not-permitted none of your grants allows A www\.example\.test\./);
  assert.equal(panel.querySelector('ul.messages'), null, 'what is shown at the RRset is not listed again');

  answer = () => problem(403, 'max-rr', { errors: [{ code: 'max-rr', severity: 'error', text: 'this change would leave 9 records' }] });
  panel = await preview();
  assert.match(panel.querySelector('p.msg.error').textContent, /more records than your policy allows/);
  assert.match(panel.querySelector('ul.messages').textContent, /Error max-rr this change would leave 9 records/, 'no pointer: listed');

  answer = () => problem(422, 'zone-checks-failed', { errors: [
    { code: 'zone.cname-and-other', severity: 'error', text: 'CNAME and other data at www.example.test.', pointer: '/rrsets/0/records/0' },
    { code: 'zone.glue', severity: 'warning', text: 'no glue' }] });
  panel = await preview();
  assert.match(panel.querySelector('p.msg.error').textContent, /The zone checks refuse this change\./);
  assert.match(panel.querySelector('ul.entry-errors').textContent, /Record 1: zone\.cname-and-other CNAME and other data at www\.example\.test\./);
  assert.match(panel.querySelector('ul.messages').textContent, /Warning zone\.glue no glue/);
  // a new try clears what was said about the entry
  answer = okDry;
  panel = await preview();
  assert.equal(panel.querySelector('ul.entry-errors'), null);

  answer = () => reply(200, { dry_run: true, allowed: false, denied: { code: 'not-permitted', severity: 'error', text: 'none of your grants allows MX here', pointer: '/rrsets/0' }, messages: [] });
  panel = await preview();
  assert.match(panel.querySelector('p.msg.error').textContent, /This is not allowed: none of your grants allows MX here/);
  assert.match(panel.querySelector('ul.entry-errors').textContent, /none of your grants allows MX here/);
  assert.equal(buttonIn(panel, /^Commit$/).disabled, true);

  answer = () => problem(500, 'internal', { detail: undefined }, {});
  panel = await preview();
  assert.match(panel.querySelector('p.msg.error').textContent, /internal error.*rid1/);
  answer = () => problem(503, 'busy');
  panel = await preview();
  assert.match(panel.querySelector('p.msg.error').textContent, /The service is busy\./);
});

test('S5a: Retry-After: both buttons wait, counting down in the preview button; the commit asks again after it', async () => {
  let calls = 0;
  const ui = await bootApp({ routes: zoneRoutes({}, { [rrsetsRoute]: () => (++calls === 1 ? problem(429, 'rate-limited', {}, { 'Retry-After': '3' }) : okDry()) }), hash: ZONE });
  let panel = await draftWww(ui);
  const preview = buttonIn(panel, /^Preview$/);
  await ui.click(preview);
  panel = ui.q('section.draft');
  assert.match(panel.querySelector('p.msg.error').textContent, /Too many requests/);
  assert.equal(preview.disabled, true);
  assert.equal(preview.textContent, 'Try again in 3 s');
  await ui.clock.advance(1000);
  assert.equal(preview.textContent, 'Try again in 2 s');
  await ui.clock.advance(1000);
  assert.equal(preview.textContent, 'Try again in 1 s');
  await ui.clock.advance(1000);
  assert.equal(preview.textContent, 'Preview');
  assert.equal(preview.disabled, false);
  await ui.click(preview);
  assert.equal(calls, 2);
  assert.equal(buttonIn(ui.q('section.draft'), /^Commit$/).disabled, false);
});

test('S5: a commit that changes nothing says so; a commit that fails keeps the draft; nothing is sent twice by a double click', async () => {
  let n = 0;
  let wait = null;
  const ui = await bootApp({ routes: zoneRoutes({}, { [rrsetsRoute]: (body) => {
    n++;
    if (body.dry_run) return okDry();
    if (n === 2) return problem(422, 'zone-checks-failed', { errors: [] });
    return reply(200, { committed: false, changed: false, change_set: 'x', diff: [], messages: [], reload: 'not requested' });
  } }), hash: ZONE });
  await draftWww(ui);
  await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/));
  const commit = buttonIn(ui.q('section.draft'), /^Commit$/);
  commit.click();
  commit.click();
  await flush();
  assert.equal(n, 2, 'one request for two clicks');
  assert.equal(ui.app.session.dirty(), true, 'the draft stays after a refusal');
  assert.equal(commit.disabled, true, 'a refused commit needs a new preview');
  await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/));
  wait = ui.q('section.draft');
  await ui.click(buttonIn(wait, /^Commit$/));
  assert.match(ui.text(), /Nothing needed to change; nothing was saved\./);
  assert.equal(ui.app.session.dirty(), false);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the update button and the servers
test('the update button: asks for a reload, then looks at the servers every 5 s for two minutes at most (the only polling), and says how many have loaded it', async () => {
  const servers = [{ dataset: 'main', server_id: 'ns-a', generation: 6, applied_at: '2026-11-09T00:00:00Z', ok: true, failed_zones: [] }, { dataset: 'main', server_id: 'ns-b', generation: 6, applied_at: null, ok: true, failed_zones: [] },
    { dataset: 'other', server_id: 'ns-c', generation: 1, applied_at: null, ok: true, failed_zones: [] }];
  const st = { info: { last_reload_request: { generation: 7, at: '2026-11-09T00:01:00Z' } } };
  const ui = await bootApp({ routes: zoneRoutes(st, { 'POST /datasets/main/zones/example.test./reload': () => reply(200, { zone: 'example.test.', change_set: 'c', reload: 'requested' }), 'GET /servers': () => reply(200, { servers }) }), hash: ZONE });
  assert.equal(ui.count('GET', '/servers'), 0, 'nothing is polled on its own');
  await ui.click(ui.button(/^Update the servers now$/));
  assert.match(ui.q('section[aria-labelledby="update-title"]').textContent, /The servers were asked to load the zone again\./);
  await ui.clock.advance(5000);
  assert.match(ui.q('section[aria-labelledby="update-title"]').textContent, /0 of 2 servers have loaded the change\./);
  servers[0].generation = 7;
  await ui.clock.advance(5000);
  assert.match(ui.q('section[aria-labelledby="update-title"]').textContent, /1 of 2 servers have loaded the change\./);
  servers[1].generation = 8;
  await ui.clock.advance(5000);
  assert.match(ui.q('section[aria-labelledby="update-title"]').textContent, /All 2 servers have loaded the change\./);
  assert.equal(ui.clock.pending() > 0, true, 'only the session timer is left');
  const polls = ui.count('GET', '/servers');
  await ui.clock.advance(60000);
  assert.equal(ui.count('GET', '/servers'), polls, 'it stopped');

  // two minutes at most, then it gives up and says where to look
  servers[0].generation = 1;
  servers[1].generation = 1;
  const base = ui.count('GET', '/servers');
  await ui.click(ui.button(/^Update the servers now$/));
  await ui.clock.advance(125000);
  assert.match(ui.q('section[aria-labelledby="update-title"]').textContent, /Stopped waiting: 0 of 2 servers have loaded the change\./);
  const after = ui.count('GET', '/servers');
  assert.ok(after - base >= 20 && after - base <= 26, `about 24 polls in two minutes (${after - base})`);
  await ui.clock.advance(30000);
  assert.equal(ui.count('GET', '/servers'), after);
});

test('the update button: SQLite3 has no server status (no polling); the refusals of the service are shown; leaving the page stops the polling', async () => {
  let answer = () => reply(200, { zone: 'example.test.', change_set: 'c', reload: 'requested' });
  let servers = [{ dataset: 'main', server_id: 'ns-a', generation: 1, ok: true, failed_zones: [] }];
  const ui = await bootApp({ routes: zoneRoutes({ info: { last_reload_request: { generation: 7, at: 'x' } } }, { 'POST /datasets/main/zones/example.test./reload': () => answer(), 'GET /servers': () => reply(200, { servers, note: 'no table' }) }), hash: ZONE });
  servers = [];
  await ui.click(ui.button(/^Update the servers now$/));
  await ui.clock.advance(5000);
  assert.equal(ui.count('GET', '/servers'), 1);
  await ui.clock.advance(20000);
  assert.equal(ui.count('GET', '/servers'), 1, 'no server status: no more asking');
  answer = () => problem(409, 'signer-managed');
  await ui.click(ui.button(/^Update the servers now$/));
  assert.match(ui.q('section[aria-labelledby="update-title"] p.msg.error').textContent, /The signer keeps this zone/);
  answer = () => problem(400, 'bad-request', { detail: "a reload needs 'karictl-config'" });
  await ui.click(ui.button(/^Update the servers now$/));
  assert.match(ui.q('section[aria-labelledby="update-title"] p.msg.error').textContent, /The request was not valid\. a reload needs 'karictl-config'/);
  answer = () => problem(503, 'reload-failed', { detail: 'failed: karictl said no' });
  await ui.click(ui.button(/^Update the servers now$/));
  assert.match(ui.q('section[aria-labelledby="update-title"] p.msg.error').textContent, /could not be told to reload/);
  // polling that meets a failure stops; so does leaving the page
  servers = [{ dataset: 'main', server_id: 'ns-a', generation: 1, ok: true, failed_zones: [] }];
  answer = () => reply(200, { zone: 'example.test.', change_set: 'c', reload: 'requested' });
  await ui.click(ui.button(/^Update the servers now$/));
  ui.routes['GET /servers'] = () => problem(500, 'internal');
  await ui.clock.advance(5000);
  const polls = ui.count('GET', '/servers');
  await ui.clock.advance(20000);
  assert.equal(ui.count('GET', '/servers'), polls);
  ui.routes['GET /servers'] = () => reply(200, { servers });
  await ui.click(ui.button(/^Update the servers now$/));
  await ui.go('#/about');
  const before = ui.count('GET', '/servers');
  await ui.clock.advance(30000);
  assert.equal(ui.count('GET', '/servers'), before, 'a page that was left does not poll');
});

test('S14: the servers: generation applied, state and the zones that did not load; the note of SQLite3; refresh on demand; a failure', async () => {
  let r = { servers: [
    { dataset: 'main', server_id: 'ns-<a>', generation: 7, applied_at: '2026-11-09T00:00:00Z', ok: false, failed_zones: ['bad.test.: no SOA', 'x\u0001y'] },
    { dataset: 'main', server_id: 'ns-b', generation: 7, applied_at: null, ok: true, failed_zones: [] }] };
  const ui = await bootApp({ routes: { 'GET /servers': () => reply(200, r) }, hash: '#/servers' });
  const tr = ui.qa('tbody tr');
  assert.deepEqual(tr[0].childNodes.map((c) => c.textContent), ['ns-<a>', 'main', '7', tr[0].childNodes[3].textContent, 'some zones did not load', 'bad.test.: no SOAx\\001y']);
  assert.match(tr[0].childNodes[3].textContent, /2026/);
  assert.deepEqual(tr[1].childNodes.map((c) => c.textContent).slice(3), ['-', 'every zone loaded', '-']);
  assert.equal(ui.link(/^Servers$/).getAttribute('aria-current'), 'page');
  r = { servers: [], note: 'a SQLite3 deployment has no server status table: ask the server with karictl status' };
  await ui.click(ui.button(/^Refresh$/));
  assert.match(ui.text(), /There is no server status to show\./);
  assert.match(ui.q('p.notice').textContent, /karictl status/);
  ui.routes['GET /servers'] = () => problem(503, 'database-unavailable');
  await ui.click(ui.button(/^Refresh$/));
  assert.match(ui.q('p.msg.error').textContent, /database cannot be reached/);
  ui.routes['GET /servers'] = () => reply(200, { servers: [] });
  await ui.click(ui.button(/^Try again$/));
  assert.match(ui.text(), /There is no server status to show\./);
});

// The zone screens, part two: a new zone (S6), the import (S7), the settings (S8), DNSSEC (S13), the draft over sessions, labels and hostile data.

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootApp, reply, problem, flush, findAll, byText, GRANT_GLOBAL, POLICY, VERSION } from './ui_boot.js';
import { FakeEvent } from './fakedom.js';

const INFO = {
  name: 'example.test.', id: 1, kind: 'NATIVE', serial: 10, catalog: null, master: null, account: null, notified_serial: null, presigned: false, signer: false, nsec3param: null,
  generation: 5, changed_at: '2026-11-09T00:00:00Z', views: ['internal'], signer_state: null, waiting_for_signer: false, last_reload_request: null, role: 'global_master', grants: [GRANT_GLOBAL],
};
const ZONE = '#/zones/main/example.test.';
const zoneRoutes = (st = {}, over = {}) => ({
  'GET /datasets': () => reply(200, { datasets: [{ name: 'main', driver: 'sqlite3', views: ['internal', 'external'] }] }),
  'GET /datasets/main/zones': () => reply(200, { zones: [], next_cursor: null }),
  'GET /datasets/main/zones/example.test.': () => reply(200, { zone: { ...INFO, ...(st.info ?? {}) } }),
  'GET /datasets/main/zones/example.test./rrsets': () => reply(200, { rrsets: [], next_cursor: null }),
  ...over,
});
const buttonIn = (el, re) => byText(el, 'button', re);
const chosen = (ui, el, v) => { el.value = v; el.dispatchEvent(new FakeEvent('change')); return flush(); };
const typed = (ui, el, v) => { el.value = v; el.dispatchEvent(new FakeEvent('input')); };
const errorsOf = (root) => findAll(root, (e) => e.tagName === 'P' && e.className === 'error' && !e.hidden).map((e) => e.textContent);
// every control has exactly one label and every button a name (planning 7.1)
function labelled(ui) {
  for (const input of findAll(ui.root, (e) => ['INPUT', 'SELECT', 'TEXTAREA'].includes(e.tagName))) {
    const label = findAll(ui.root, (e) => e.tagName === 'LABEL' && e.htmlFor === input.getAttribute('id'));
    assert.equal(label.length, 1, `the control ${input.getAttribute('name')} has one label`);
    for (const id of (input.getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean)) assert.ok(ui.root.querySelector(`#${id}`), `${id} exists`);
  }
  for (const b of findAll(ui.root, (e) => e.tagName === 'BUTTON')) assert.ok(b.textContent.trim() !== '' || b.getAttribute('aria-label'), 'a button has a name');
}

// ---------------------------------------------------------------------------------------------------------------------------------- S6
const TEMPLATES = { templates: [{ id: 1, name: 'basic', description: '<b>mail</b> and web', revision: 2, soa: null, record_count: 3 }, { id: 2, name: 'bare', description: null, record_count: 0 }] };
const createRoutes = (over = {}) => ({ 'GET /datasets': zoneRoutes()['GET /datasets'], 'GET /templates': () => reply(200, TEMPLATES), ...over });

test('S6: a new zone from a form: the checks before anything is sent, the dry run with the whole request, the commit and the way to the new zone', async () => {
  const sent = [];
  const ui = await bootApp({ routes: createRoutes({ 'POST /datasets/main/zones': (b) => {
    sent.push(b);
    return b.dry_run ? reply(200, { dry_run: true, allowed: true, version: 1, serial: { before: 0, after: 2026110900 }, records: { before: 0, after: 4 }, diff: [
      { name: 'new.test.', type: 'SOA', change: 'add', before: null, after: [{ ttl: 3600, content: 'ns1.new.test. hostmaster.new.test. 2026110900 7200 3600 1209600 300' }] },
      { name: 'www.new.test.', type: 'A', change: 'add', before: null, after: [{ ttl: 300, content: '192.0.2.10' }] }], messages: [] })
      : reply(201, { zone: 'new.test.', committed: true, changed: true, change_set: 'c', version: 1, generation: { before: 0, after: 1 }, serial: { before: 0, after: 2026110900 }, records: { before: 0, after: 4 }, diff: [], messages: [], reload: 'not requested' });
  } }), hash: '#/create/main' });
  assert.equal(ui.q('h1').textContent, 'New zone in main');
  assert.equal(ui.env.document.title, 'New zone in main - KariDNS WebAdmin');
  labelled(ui);
  // nothing entered
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.equal(sent.length, 0);
  assert.deepEqual(errorsOf(ui.root), ['Enter the name of the zone.', 'Enter the primary name server.', 'Enter the responsible mailbox.', 'Enter at least one name server.']);
  assert.equal(ui.env.document.activeElement, ui.input('name'));
  // a number and a line that are not
  typed(ui, ui.input('name'), 'New.Test');
  typed(ui, ui.input('mname'), 'ns1.new.test');
  typed(ui, ui.input('rname'), 'hostmaster.new.test');
  typed(ui, ui.input('nameservers'), 'ns1.new.test.\nns2.new.test.\n');
  typed(ui, ui.input('refresh'), '12x');
  typed(ui, ui.input('records'), 'www 300 A 192.0.2.10\nrubbish');
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.deepEqual(errorsOf(ui.root), ['Enter a number of seconds.', 'Line 2 is not a record: name, an optional TTL, type and data are needed.']);
  typed(ui, ui.input('refresh'), '7200');
  typed(ui, ui.input('records'), 'www 300 A 192.0.2.10\n@ 3600 MX 10 mail');
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.deepEqual(sent[0], {
    name: 'New.Test', type: 'NATIVE', reload: false, dry_run: true, soa: { mname: 'ns1.new.test', rname: 'hostmaster.new.test', refresh: 7200 }, nameservers: ['ns1.new.test.', 'ns2.new.test.'],
    rrsets: [{ name: 'www.new.test.', type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: '192.0.2.10' }] }, { name: 'new.test.', type: 'MX', changetype: 'REPLACE', ttl: 3600, records: [{ content: '10 mail' }] }],
  });
  assert.match(ui.text(), /2 added|2 added, 0 changed, 0 deleted/);
  assert.match(ui.text(), /Version it would be1/);
  // a change of the form makes the preview stale
  const commit = buttonIn(ui.root, /^Create the zone$/);
  assert.equal(commit.disabled, false);
  typed(ui, ui.input('rname'), 'hostmaster2.new.test');
  assert.equal(commit.disabled, true);
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  ui.input('comment').value = 'first';
  await ui.click(commit);
  assert.equal(sent[2].dry_run, undefined);
  assert.equal(sent[2].comment, 'first');
  assert.equal(ui.env.window.location.hash, '#/zones/main/new.test.', 'the page of the new zone');
});

test('S6: refusals are put on the fields by their pointers; a name that exists; hostile description of a template is text', async () => {
  let answer = null;
  const ui = await bootApp({ routes: createRoutes({ 'POST /datasets/main/zones': () => answer() }), hash: '#/create/main' });
  typed(ui, ui.input('name'), 'exists.test');
  typed(ui, ui.input('mname'), 'ns1.exists.test');
  typed(ui, ui.input('rname'), 'hm.exists.test');
  typed(ui, ui.input('nameservers'), 'ns1.exists.test');
  answer = () => problem(409, 'exists');
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.match(findAll(ui.root, (e) => e.className === 'msg error' && !e.hidden)[0].textContent, /An object with this name exists already\./);
  answer = () => problem(400, 'bad-request', { errors: [
    { code: 'bad-request', text: 'a host name is expected', pointer: '/soa/mname' }, { code: 'bad-request', text: 'bad ns', pointer: '/nameservers/0' }, { code: 'bad-request', text: 'no such template', pointer: '/template' },
    { code: 'bad-request', text: 'name is odd', pointer: '/name' }, { code: 'bad-request', text: 'line', pointer: '/rrsets/0' }, { code: 'bad-request', text: 'serial', pointer: '/soa/refresh' }] });
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.deepEqual(errorsOf(ui.root).sort(), ['a host name is expected', 'bad ns', 'line', 'name is odd', 'serial'].sort());
  // the template way
  await chosen(ui, ui.input('how'), 'template');
  answer = () => problem(400, 'bad-request', { errors: [{ code: 'bad-request', text: 'no such template', pointer: '/template' }] });
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.match(findAll(ui.root, (e) => e.className === 'msg error' && !e.hidden).map((e) => e.textContent).join(' '), /no such template/);
  assert.match(ui.text(), /<b>mail<\/b> and web 3 records\./, 'the description is text');
  assert.equal(findAll(ui.root, (e) => e.tagName === 'B').length, 0);
  await chosen(ui, ui.input('template'), 'bare');
  assert.match(ui.text(), /0 records\./);
  answer = okCreate;
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.equal(ui.last('POST', '/zones').body.template, 'bare');
  labelled(ui);
});
const okCreate = () => reply(200, { dry_run: true, allowed: true, diff: [], messages: [] });

test('S6: a template needs no SOA values; a zone file: typed, read from a file (UTF-8 only), too large, empty; a failure to read the templates', async () => {
  const sent = [];
  const ui = await bootApp({ routes: createRoutes({ 'POST /datasets/main/zones': (b) => { sent.push(b); return okCreate(); } }), hash: '#/create/main' });
  typed(ui, ui.input('name'), 'tpl.test');
  await chosen(ui, ui.input('how'), 'template');
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.deepEqual(sent[0], { name: 'tpl.test', type: 'NATIVE', reload: false, dry_run: true, template: 'basic' });
  // a zone file
  await chosen(ui, ui.input('how'), 'text');
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.deepEqual(errorsOf(ui.root), ['Enter the zone file or choose a file.']);
  const file = ui.input('zone_text_file');
  const pick = async (bytes, size) => { file.files = [{ size: size ?? bytes.length, arrayBuffer: async () => bytes.buffer }]; file.dispatchEvent(new FakeEvent('change')); await flush(); };
  await pick(new Uint8Array([0xff, 0xfe, 0x41]));
  assert.match(ui.text(), /The file is not UTF-8 text\./);
  await pick(new Uint8Array(10), 5000);
  assert.match(ui.text(), /larger than the 0 MiB the service takes/);
  await pick(new TextEncoder().encode('$ORIGIN tpl.test.\n@ SOA a b 1 2 3 4 5\n@ NS a\n'));
  assert.equal(ui.input('zone_text').value, '$ORIGIN tpl.test.\n@ SOA a b 1 2 3 4 5\n@ NS a\n');
  assert.equal(errorsOf(ui.root).length, 0);
  file.files = [];
  file.dispatchEvent(new FakeEvent('change'));
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.deepEqual(sent[1], { name: 'tpl.test', type: 'NATIVE', reload: false, dry_run: true, zone_text: '$ORIGIN tpl.test.\n@ SOA a b 1 2 3 4 5\n@ NS a\n' });
  typed(ui, ui.input('zone_text'), 'x'.repeat(2000));
  await ui.click(buttonIn(ui.root, /^Preview the zone$/));
  assert.match(errorsOf(ui.root)[0], /larger than the/);
  labelled(ui);
  // the templates cannot be read
  const bad = await bootApp({ routes: { 'GET /templates': problem(503, 'database-unavailable') }, hash: '#/create/main' });
  assert.match(bad.q('p.msg.error').textContent, /database cannot be reached/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- S7
test('S7: import: the file or text, the mode, a dry run whose diff is paged by 200, the commit; refusals at the text', async () => {
  const diff = Array.from({ length: 450 }, (_, i) => ({ name: `h${String(i).padStart(3, '0')}.example.test.`, type: 'A', change: 'add', before: null, after: [{ ttl: 300, content: `192.0.2.${i % 250}` }] }));
  const sent = [];
  let answer = null;
  const ui = await bootApp({ routes: zoneRoutes({}, { 'POST /datasets/main/zones/example.test./import': (b) => { sent.push(b); return answer(b); } }), hash: `${ZONE}/import` });
  assert.equal(ui.q('h2').textContent, 'Import a zone file');
  assert.equal(ui.link(/^Import$/).getAttribute('aria-current'), 'page');
  labelled(ui);
  await ui.click(buttonIn(ui.root, /^Preview the import$/));
  assert.deepEqual(errorsOf(ui.root), ['Enter the zone file or choose a file.']);
  typed(ui, ui.input('zone_text'), '$ORIGIN example.test.\nx A 192.0.2.1\n');
  await chosen(ui, ui.input('mode'), 'merge');
  answer = () => reply(200, { dry_run: true, allowed: true, version: 3, serial: { before: 10, after: 11 }, records: { before: 5, after: 455 }, diff, messages: [] });
  await ui.click(buttonIn(ui.root, /^Preview the import$/));
  assert.deepEqual(sent[0], { zone_text: '$ORIGIN example.test.\nx A 192.0.2.1\n', mode: 'merge', reload: false, dry_run: true });
  assert.match(ui.text(), /450 added|450 added, 0 changed, 0 deleted/);
  assert.equal(ui.qa('table.diff-table tbody tr').length, 200, 'a page of 200');
  assert.match(ui.text(), /1-200 of 450 record sets/);
  assert.equal(buttonIn(ui.root, /^Previous$/).disabled, true);
  await ui.click(buttonIn(ui.root, /^Next$/));
  assert.match(ui.text(), /201-400 of 450 record sets/);
  assert.equal(ui.qa('table.diff-table tbody tr')[0].querySelector('th').textContent, 'h200');
  await ui.click(buttonIn(ui.root, /^Next$/));
  assert.match(ui.text(), /401-450 of 450 record sets/);
  assert.equal(ui.qa('table.diff-table tbody tr').length, 50);
  assert.equal(buttonIn(ui.root, /^Next$/).disabled, true);
  await ui.click(buttonIn(ui.root, /^Previous$/));
  assert.match(ui.text(), /201-400/);
  // the commit makes the zone's header new
  const gets = ui.count('GET', '/zones/example.test.');
  answer = () => reply(200, { committed: true, changed: true, change_set: 'c', version: 3, serial: { before: 10, after: 11 }, records: { before: 5, after: 455 }, diff: [], messages: [], reload: 'not requested' });
  await ui.click(buttonIn(ui.root, /^Import$/));
  assert.equal(sent[1].dry_run, undefined);
  assert.match(ui.text(), /The change was saved\./);
  assert.ok(ui.count('GET', '/zones/example.test.') > gets);
  // a refusal at the text
  answer = () => problem(422, 'zone-checks-failed', { errors: [{ code: 'zone.syntax', severity: 'error', text: 'line 2: bad RDATA', pointer: '/zone_text' }] });
  await ui.click(buttonIn(ui.root, /^Preview the import$/));
  assert.deepEqual(errorsOf(ui.root), ['line 2: bad RDATA']);
  answer = () => problem(409, 'tagged-rrset', { detail: 'x' });
  await ui.click(buttonIn(ui.root, /^Preview the import$/));
  assert.match(ui.q('p.msg.error').textContent, /location tags/);
  // a zone the signer keeps has no "update the servers" box
  const signer = await bootApp({ routes: zoneRoutes({ info: { signer: true } }), hash: `${ZONE}/import` });
  assert.equal(signer.input('reload'), undefined);
});

// ---------------------------------------------------------------------------------------------------------------------------------- S8
const META = { metadata: [{ kind: 'ALLOW-AXFR-FROM', content: ['192.0.2.0/24', '2001:db8::/32'] }, { kind: 'PRESIGNED', content: ['1'] }], writable: ['ALLOW-AXFR-FROM', 'ALSO-NOTIFY'] };

test('S8: settings: attributes, the catalog and views, metadata (set, remove), the zone deleted after its name is typed again', async () => {
  const calls = [];
  const state = { meta: META };
  const ui = await bootApp({ routes: zoneRoutes({ info: { catalog: 'cat.test.', master: '192.0.2.5', account: 'acct', nsec3param: '1 0 5 -' } }, {
    'GET /datasets/main/zones/example.test./metadata': () => reply(200, state.meta),
    'PATCH /datasets/main/zones/example.test.': (b) => { calls.push(['PATCH', b]); return b.catalog === 'bad.test.' ? problem(409, 'not-a-catalog') : reply(200, { zone: 'example.test.', catalog: b.catalog, views: b.views ?? [], change_set: 'c' }); },
    'PUT /datasets/main/zones/example.test./metadata/ALLOW-AXFR-FROM': (b) => { calls.push(['PUT', b]); return b.content.includes('nonsense') ? problem(400, 'bad-request', { errors: [{ code: 'bad-request', text: 'not an address', pointer: '/content' }] }) : reply(200, { zone: 'example.test.', kind: 'ALLOW-AXFR-FROM', content: b.content }); },
    'DELETE /datasets/main/zones/example.test./metadata/ALSO-NOTIFY': () => { calls.push(['DELETE', 'ALSO-NOTIFY']); return reply(200, { content: [] }); },
    'DELETE /datasets/main/zones/example.test.': (b) => { calls.push(['DELETE zone', b]); return reply(200, { deleted: 'example.test.', change_set: 'c', reload: 'requested' }); },
  }), hash: `${ZONE}/settings` });
  assert.equal(ui.link(/^Settings$/).getAttribute('aria-current'), 'page');
  const dl = ui.q('dl').textContent;
  labelled(ui);
  assert.match(ui.text(), /Catalog zonecat\.test\./);
  assert.match(ui.text(), /Mastersexample|192\.0\.2\.5/);
  assert.match(ui.text(), /NSEC3PARAM1 0 5 -/);
  assert.ok(dl.length > 0);
  // the table of metadata
  const trs = ui.qa('tbody tr');
  assert.deepEqual(trs.map((r) => r.childNodes.map((c) => c.textContent)), [['ALLOW-AXFR-FROM', '192.0.2.0/24' + '2001:db8::/32', 'can be changed here'], ['PRESIGNED', '1', 'read only']]);
  // the catalog and the views
  assert.equal(ui.input('catalog').value, 'cat.test.');
  assert.equal(ui.input('view-internal').checked, true);
  assert.equal(ui.input('view-external').checked, false);
  ui.input('view-external').checked = true;
  typed(ui, ui.input('catalog'), '');
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('input[name=catalog]')));
  assert.deepEqual(calls[0], ['PATCH', { catalog: null, views: ['internal', 'external'] }]);
  assert.match(ui.text(), /Saved\./);
  typed(ui, ui.input('catalog'), 'bad.test.');
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('input[name=catalog]')));
  assert.deepEqual(errorsOf(ui.root), ['This zone is not a catalog zone.']);
  // metadata: the values of the kind are in the box; a refusal at the box; remove asks
  assert.equal(ui.input('content').value, '192.0.2.0/24\n2001:db8::/32');
  typed(ui, ui.input('content'), '192.0.2.9\nnonsense');
  const metaForm = findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('textarea[name=content]'));
  await ui.submit(metaForm);
  assert.deepEqual(calls[2], ['PUT', { content: ['192.0.2.9', 'nonsense'] }]);
  assert.deepEqual(errorsOf(ui.root).slice(-1), ['not an address']);
  typed(ui, ui.input('content'), '192.0.2.9');
  state.meta = { ...META, metadata: [{ kind: 'ALLOW-AXFR-FROM', content: ['192.0.2.9'] }] };
  await ui.submit(metaForm);
  assert.match(ui.text(), /Saved\./);
  assert.equal(ui.input('content').value, '192.0.2.9', 'the list is read again');
  await chosen(ui, ui.input('kind'), 'ALSO-NOTIFY');
  assert.equal(ui.input('content').value, '');
  await ui.click(buttonIn(ui.root, /^Remove this kind$/));
  assert.equal(calls.length, 4, 'asking first');
  await ui.click(buttonIn(ui.root, /^Yes$/));
  assert.deepEqual(calls[4], ['DELETE', 'ALSO-NOTIFY']);

  // delete the zone
  const zoneForm = findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('input[name=confirm]'));
  await ui.submit(zoneForm);
  assert.deepEqual(errorsOf(ui.root).slice(-1), ['This is not the name of the zone.']);
  assert.equal(calls.length, 5);
  typed(ui, ui.input('confirm'), 'example.test');
  await ui.submit(zoneForm);
  assert.deepEqual(calls[5], ['DELETE zone', { confirm: 'example.test', reload: false }]);
  assert.equal(ui.env.window.location.hash, '#/zones?ds=main');
  assert.match(ui.text(), /The zone example\.test\. was deleted\. Servers: The servers were asked to load the zone again\./);
});

test('S8: a person who is not a global master reads the settings and cannot change them; a failing metadata list; a failed delete', async () => {
  const grants = [{ id: 3, role: 'domain_master', dataset: 'main', zone: 'example.test.', suffix: null, policy: POLICY, via: null }];
  const ui = await bootApp({ routes: zoneRoutes({ info: { role: 'domain_master', grants } }, { 'GET /datasets/main/zones/example.test./metadata': () => reply(200, META) }), hash: `${ZONE}/settings`, me: { global: false, grants } });
  assert.equal(findAll(ui.root, (e) => e.tagName === 'FORM').length, 0, 'no form at all');
  assert.equal(ui.input('confirm'), undefined);
  assert.equal(ui.qa('tbody tr').length, 2);
  const bad = await bootApp({ routes: zoneRoutes({}, { 'GET /datasets/main/zones/example.test./metadata': () => problem(500, 'internal'), 'DELETE /datasets/main/zones/example.test.': () => problem(409, 'refused') }), hash: `${ZONE}/settings` });
  assert.ok(findAll(bad.root, (e) => e.className === 'msg error').length >= 1);
  typed(bad, bad.input('confirm'), 'example.test.');
  await bad.submit(findAll(bad.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('input[name=confirm]')));
  assert.match(bad.q('section.danger-zone p.msg.error').textContent, /The database refused this change\./);
});

// ---------------------------------------------------------------------------------------------------------------------------------- S13
const DNSSEC = {
  zone: 'example.test.', signed: true, signer: true, presigned: false, nsec3param: '1 0 5 -', serial: 10, waiting_for_signer: true,
  signer_state: { signed_at: '2026-11-08T00:00:00Z', signed_serial: 9, min_expire: '2026-11-12T04:00:00Z', next_due: '2026-11-08T23:00:00Z', attempts: 2, last_error: 'could not sign <b>x</b>\u0001' },
  keys: [{ flags: 257, protocol: 3, algorithm: 13, key_tag: 12345, sep: true, zone_key: true, ttl: 3600 }, { flags: 256, protocol: 3, algorithm: 13, key_tag: 23456, sep: false, zone_key: true, ttl: 3600 }],
  ds: [{ key_tag: 12345, algorithm: 13, digest_type: 2, digest: 'AB12', text: '12345 13 2 AB12' }, { key_tag: 12345, algorithm: 13, digest_type: 4, digest: 'CD34', text: '12345 13 4 CD34' }],
  cryptokeys: [{ id: 1, flags: 257, active: true, published: true }],
  requests: [{ id: 4, kind: 'add', algorithm: 13, bits: null, key_type: 'zsk', nsec: null, state: 'done', message: 'ok', requested_by: 7, created_at: '2026-11-08T00:00:00Z', done_at: '2026-11-08T00:01:00Z' },
    { id: 3, kind: 'enable', algorithm: 8, bits: 2048, key_type: 'csk', nsec: 'nsec3', state: 'failed', message: null, requested_by: 7, created_at: '2026-11-07T00:00:00Z', done_at: null }],
};

test('S13: DNSSEC: signer state with the time left, keys with their tags, DS records with copy buttons, requests; the last error is text', async () => {
  const written = [];
  const ui = await bootApp({ routes: zoneRoutes({ info: { signer: true } }, { 'GET /datasets/main/zones/example.test./dnssec': () => reply(200, { dnssec: DNSSEC }) }), hash: `${ZONE}/dnssec` });
  ui.env.clipboard.writeText = async (s) => { written.push(s); };
  assert.equal(ui.link(/^DNSSEC$/).getAttribute('aria-current'), 'page');
  const t = ui.text();
  assert.match(t, /Signingkept signed by karidns-signer/);
  assert.match(t, /NSEC3PARAM1 0 5 -/);
  assert.match(t, /Waiting for the signerYes/);
  assert.match(t, /First signature expires.*(in|ago) .*(d|h|min)/);
  assert.match(t, /Failed attempts in a row2/);
  assert.match(t, /Last error of the signer: could not sign <b>x<\/b>\\001/);
  assert.equal(findAll(ui.root, (e) => e.tagName === 'B').length, 0);
  const keyRows = ui.qa('table')[0].querySelectorAll('tbody tr');
  assert.deepEqual(keyRows.map((r) => r.childNodes.map((c) => c.textContent)), [['12345', 'key signing key (SEP)', '13 ECDSAP256SHA256', '257', '3600'], ['23456', 'zone signing key', '13 ECDSAP256SHA256', '256', '3600']]);
  const dsRows = ui.qa('table')[1].querySelectorAll('tbody tr');
  assert.equal(dsRows.length, 2);
  await ui.click(buttonIn(dsRows[1], /^Copy$/));
  assert.deepEqual(written, ['example.test. IN DS 12345 13 4 CD34']);
  assert.match(dsRows[1].textContent, /Copied\./);
  ui.env.clipboard.writeText = async () => { throw new Error('no'); };
  await ui.click(buttonIn(dsRows[0], /^Copy$/));
  assert.match(dsRows[0].textContent, /did not allow copying/);
  assert.match(ui.qa('table')[2].textContent, /3enable8\/2048 csk nsec3failed/);
  labelled(ui);
});

test('S13: a request for a key: enable or add, RSA with bits, a refusal; a zone that cannot have one; no keys', async () => {
  const sent = [];
  let answer = () => reply(201, { request: {}, change_set: 'c' });
  const open = { ...DNSSEC, signer: false, signed: false, waiting_for_signer: false, signer_state: null, keys: [], ds: [], requests: [], nsec3param: null };
  const ui = await bootApp({ routes: zoneRoutes({}, { 'GET /datasets/main/zones/example.test./dnssec': () => reply(200, { dnssec: open }), 'POST /datasets/main/zones/example.test./dnssec/requests': (b) => { sent.push(b); return answer(); } }), hash: `${ZONE}/dnssec` });
  assert.match(ui.text(), /Signingnot signed/);
  assert.match(ui.text(), /The zone has no DNSKEY records\./);
  assert.match(ui.text(), /No key has the SEP flag/);
  assert.match(ui.text(), /No request has been made\./);
  assert.equal(ui.input('nsec').value, 'nsec3');
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('select[name=kind]')));
  assert.deepEqual(sent[0], { kind: 'enable', algorithm: 13, key_type: 'csk', nsec: 'nsec3' });
  assert.match(ui.text(), /The request was sent\. The signer answers it\./);
  const form = () => findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('select[name=kind]'));
  await chosen(ui, ui.input('algorithm'), '8');
  typed(ui, ui.input('bits'), '512');
  await ui.submit(form());
  assert.deepEqual(errorsOf(ui.root), ['Enter a size from 1024 to 8192.']);
  typed(ui, ui.input('bits'), '3072');
  await chosen(ui, ui.input('nsec'), 'nsec');
  await chosen(ui, ui.input('key_type'), 'ksk');
  await ui.submit(form());
  assert.deepEqual(sent[1], { kind: 'enable', algorithm: 8, key_type: 'ksk', nsec: 'nsec', bits: 3072 });
  answer = () => problem(409, 'request-pending');
  await ui.submit(form());
  assert.match(ui.q('p.msg.error').textContent, /A request for this zone is waiting already\./);
  // a zone the signer keeps: "add"
  const signer = await bootApp({ routes: zoneRoutes({ info: { signer: true } }, { 'GET /datasets/main/zones/example.test./dnssec': () => reply(200, { dnssec: DNSSEC }), 'POST /datasets/main/zones/example.test./dnssec/requests': (b) => { sent.push(b); return reply(201, {}); } }), hash: `${ZONE}/dnssec` });
  assert.equal(signer.input('nsec'), undefined);
  assert.deepEqual(findAll(signer.input('kind'), (e) => e.tagName === 'OPTION').map((o) => o.textContent), ['Add one more key']);
  await signer.submit(findAll(signer.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('select[name=kind]')));
  assert.deepEqual(sent[sent.length - 1], { kind: 'add', algorithm: 13, key_type: 'csk' });
  // signed elsewhere or not a primary zone: no form
  const pre = await bootApp({ routes: zoneRoutes({ info: { presigned: true } }, { 'GET /datasets/main/zones/example.test./dnssec': () => reply(200, { dnssec: { ...open, presigned: true } }) }), hash: `${ZONE}/dnssec` });
  assert.match(pre.text(), /Key requests are not possible for this zone\./);
  assert.match(pre.text(), /signed elsewhere \(the zone is served as it is\)/);
  const fail = await bootApp({ routes: zoneRoutes({}, { 'GET /datasets/main/zones/example.test./dnssec': () => problem(403, 'forbidden') }), hash: `${ZONE}/dnssec` });
  assert.match(fail.q('p.msg.error').textContent, /not allowed/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the draft over sessions
const wwwRoutes = (over = {}) => zoneRoutes({}, {
  'GET /datasets/main/zones/example.test./rrsets': () => reply(200, { rrsets: [{ name: 'www.example.test.', type: 'A', ttl: 300, tagged: false, records: [{ content: '192.0.2.10', rdata: '192.0.2.10', disabled: false, ttl: 300 }] }], next_cursor: null }),
  ...over,
});
async function withDraft(ui) {
  await ui.click(buttonIn(ui.qa('table.rrsets tbody tr')[0], /^Edit$/));
  const dlg = ui.dialogs()[0];
  typed(ui, ui.input('records', dlg), '192.0.2.99');
  await ui.submit(dlg.querySelector('form'));
}
const loginAs = (principal) => reply(200, { api: 1, principal, csrf: 'csrf-2', expires_at: 'x', totp: { enabled: false, enrollment_required: false } });

test('F-13: a 401 in the middle of a commit: the sign-in opens over the page, the draft stays, the write is not repeated; the same person goes on, another one starts empty', async () => {
  let first = true;
  const ui = await bootApp({ routes: wwwRoutes({ 'PATCH /datasets/main/zones/example.test./rrsets': () => { if (first) { first = false; return problem(401, 'unauthenticated'); } return reply(200, { dry_run: true, allowed: true, diff: [], messages: [] }); }, 'POST /auth/login': () => loginAs({ id: 7, kind: 'user', name: 'alice', display_name: 'Alice A.' }) }), hash: ZONE });
  await withDraft(ui);
  await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/));
  const dlg = ui.dialogs()[0];
  assert.match(dlg.textContent, /Your session has ended/);
  assert.equal(ui.count('PATCH', '/rrsets'), 1);
  ui.type(ui.input('user', dlg), 'alice');
  ui.type(ui.input('password', dlg), 'pw');
  await ui.submit(dlg.querySelector('form'));
  assert.equal(ui.dialogs().length, 0);
  assert.equal(ui.count('PATCH', '/rrsets'), 1, 'a write is not repeated');
  assert.equal(ui.app.session.dirty(), true, 'the draft is still there');
  assert.match(ui.q('ul.draft-list').textContent, /192\.0\.2\.99/);
  await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/));
  assert.equal(ui.count('PATCH', '/rrsets'), 2, 'the person asks again');

  // another person signs in over the dialog: nothing of the first person's work is carried over
  let again = true;
  ui.routes['PATCH /datasets/main/zones/example.test./rrsets'] = () => { if (again) { again = false; return problem(401, 'unauthenticated'); } return okDry(); };
  ui.routes['POST /auth/login'] = () => loginAs({ id: 8, kind: 'user', name: 'bob', display_name: 'Bob' });
  await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/));
  const dlg2 = ui.dialogs()[0];
  ui.type(ui.input('user', dlg2), 'bob');
  ui.type(ui.input('password', dlg2), 'pw');
  await ui.submit(dlg2.querySelector('form'));
  assert.equal(ui.app.session.dirty(), false, 'the draft was the first person\'s');
  assert.equal(ui.env.window.location.hash, '#/');
});
const okDry = () => reply(200, { dry_run: true, allowed: true, diff: [], messages: [] });

test('F-13: logging out, here or in another tab, drops the draft; the draft of one zone is not the draft of another', async () => {
  const ui = await bootApp({ routes: wwwRoutes({ 'GET /datasets/main/zones/other.test.': () => reply(200, { zone: { ...INFO, name: 'other.test.' } }), 'GET /datasets/main/zones/other.test./rrsets': () => reply(200, { rrsets: [], next_cursor: null }) }), hash: ZONE });
  await withDraft(ui);
  assert.equal(ui.app.ctx.drafts.count(), 1);
  await ui.go('#/zones/main/other.test.');
  assert.match(ui.q('section.draft').textContent, /Nothing is changed yet/);
  assert.equal(ui.app.ctx.drafts.count(), 1, 'the first zone keeps its draft');
  await ui.go(ZONE);
  assert.match(ui.q('ul.draft-list').textContent, /192\.0\.2\.99/, 'and shows it again');
  await ui.click(ui.button(/^Log out$/));
  assert.equal(ui.app.ctx.drafts.count(), 0);
  // another tab signs out
  const tabs = await bootApp({ routes: wwwRoutes(), hash: ZONE });
  await withDraft(tabs);
  assert.equal(tabs.app.ctx.drafts.count(), 1);
  new tabs.env.BroadcastChannel('karidns-webadmin').postMessage({ type: 'logout' });
  await flush();
  assert.equal(tabs.app.ctx.drafts.count(), 0, 'the other tab ended the session: the work of this one goes with it');
  assert.match(tabs.q('.notice').textContent, /signed out in another tab/);
});

test('the page asks before it is left with a draft, and not without one', async () => {
  const ui = await bootApp({ routes: wwwRoutes(), hash: ZONE });
  const ask = () => { const ev = new FakeEvent('beforeunload'); ev.returnValue = undefined; ui.env.window.dispatchEvent(ev); return ev.defaultPrevented; };
  assert.equal(ask(), false);
  await withDraft(ui);
  assert.equal(ask(), true);
});

// ---------------------------------------------------------------------------------------------------------------------------------- hostile route parts
test('a zone name from the address is text: markup, bidi controls and a name that does not decode', async () => {
  const name = '<img src=x onerror=window.__xss=1>.test.';
  const ui = await bootApp({ routes: { [`GET /datasets/main/zones/${encodeURIComponent(name)}`]: problem(404, 'not-found') }, hash: `#/zones/main/${encodeURIComponent(name)}` });
  assert.equal(ui.q('h1').textContent, name, 'text');
  assert.equal(findAll(ui.env.document.body, (e) => e.tagName === 'IMG').length, 0);
  assert.equal(ui.env.document.title, `${name} - KariDNS WebAdmin`);
  await ui.go('#/zones/main/%E0%A4%A');
  assert.match(ui.q('h1').textContent, /Page not found/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the rest
test('the state of a reload in the words of the service: failed, waiting for the signer, anything else', async () => {
  let reload = 'failed: karictl said no (the change is in the database; the server serves the old version until it is reloaded)';
  const ui = await bootApp({ routes: wwwRoutes({ 'PATCH /datasets/main/zones/example.test./rrsets': (b) => (b.dry_run ? okDry() : reply(200, { committed: true, changed: true, version: 2, serial: { before: 1, after: 2 }, records: { before: 1, after: 1 }, diff: [], messages: [], reload })) }), hash: ZONE });
  const commit = async () => { await ui.click(buttonIn(ui.q('section.draft'), /^Preview$/)); await ui.click(buttonIn(ui.q('section.draft'), /^Commit$/)); };
  await withDraft(ui);
  await commit();
  assert.match(ui.text(), /ServersThe change is saved, but the servers could not be asked to reload: karictl said no \(the change is in the database/);
  reload = 'waiting for the signer';
  await withDraft(ui);
  await commit();
  assert.match(ui.text(), /ServersThe signer asks the servers to load the zone when it has signed the change\./);
  reload = 'something new\u0001';
  await withDraft(ui);
  await commit();
  assert.match(ui.text(), /Serverssomething new\\001/);
});

test('the dialog of the editor is cancelled; a view that is left stops what it was doing; DNSSEC can be refreshed; a failure of the settings that is not about a field', async () => {
  const dnssec = { ...DNSSEC, signer_state: null };
  const ui = await bootApp({ routes: wwwRoutes({ 'GET /datasets/main/zones/example.test./dnssec': () => reply(200, { dnssec }), 'GET /servers': () => reply(200, { servers: [] }), 'PATCH /datasets/main/zones/example.test.': () => problem(500, 'internal'), 'GET /datasets/main/zones/example.test./metadata': () => reply(200, META) }), hash: ZONE });
  await ui.click(buttonIn(ui.qa('table.rrsets tbody tr')[0], /^Edit$/));
  assert.equal(ui.dialogs().length, 1);
  await ui.click(buttonIn(ui.dialogs()[0], /^Cancel$/));
  assert.equal(ui.dialogs().length, 0);
  assert.equal(ui.app.ctx.drafts.count(), 0, 'cancel adds nothing');
  await ui.go(`${ZONE}/dnssec`);
  const before = ui.count('GET', '/dnssec');
  await ui.click(buttonIn(ui.root, /^Refresh$/));
  assert.equal(ui.count('GET', '/dnssec'), before + 1);
  await ui.go(`${ZONE}/import`);
  await ui.go('#/servers');
  await ui.go(`${ZONE}/settings`);
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector('input[name=catalog]')));
  assert.match(findAll(ui.root, (e) => e.className === 'msg error' && !e.hidden)[0].textContent, /internal error/);
});

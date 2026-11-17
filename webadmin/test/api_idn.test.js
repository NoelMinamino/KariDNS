// Internationalized names through the HTTP server (0.7): names typed in Unicode reach karidns-zone and the database as A-labels, the replies carry the U-label form
// (`unicode`) and the IDN warnings, the search takes either form, GET /idn, and the ldns.jp link of GET /version (ldns-link, ldns-resolver).

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast, makeRun, ok, exit, applyDoc, entry } from './helpers.js';
import { parseConfig } from '../lib/config.js';
import { parseTemplate } from '../lib/templates.js';
import { parseChangeSet } from '../lib/changes.js';

const KZ = '/opt/karidns-zone';
const standard = (diff) => (c) => {
  if (c.file !== KZ) return exit(0, { stdout: 'OK\n' });
  const isCheck = c.argv.includes('--dry-run');
  return ok(applyDoc({ apply: isCheck ? { dry_run: true, diff } : { dry_run: false, committed: true, version: 3, generation_after: 8, diff, created: c.argv.includes('--create') } }));
};

const withTools = (handler, fn, settings = {}) => async () => {
  const t = makeRun(handler);
  const d = await deploy({ run: t.run, settings: { 'karidns-zone': KZ, ...settings } });
  d.app.sleep = async () => {};
  try {
    await cast(d);
    const root = d.as(await d.login('root', 'correct horse battery'));
    const dom = d.as(await d.login('dom', 'dom password 12345'));
    await fn(d, { root, dom }, t);
  } finally {
    await d.close();
  }
};
const run = (d, text, params = []) => d.backend.tx({ write: true }, (tx) => tx.run(text, params));
const is = (r, status) => assert.equal(r.status, status, JSON.stringify(r.body));
const rr = (name) => ({ name, type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: '192.0.2.50' }] });

test('a change set with Unicode names: karidns-zone gets A-labels, the reply the warnings', withTools(standard([entry('xn--n3h.example.test.', 'A', null, ['300 A 192.0.2.50'])]), async (d, { dom }, t) => {
  const r = await dom('PATCH', '/datasets/main/zones/example.test/rrsets', { body: { rrsets: [rr('ウェブ.example.test'), rr('☃.EXAMPLE.test.')] } });
  is(r, 200);
  assert.equal(t.calls[0].input, 'rr xn--gckc5l.example.test. 300 A 192.0.2.50\nrr xn--n3h.example.test. 300 A 192.0.2.50\n');
  assert.deepEqual(r.body.warnings.map((w) => [w.code, w.label]), [['idn-disallowed', '☃']]);
  // a name with no A-label form is a 400 at its RRset; a plain change has no warnings
  const bad = await dom('PATCH', '/datasets/main/zones/example.test/rrsets', { body: { rrsets: [rr('www.example.test'), rr('a‍b.example.test')] } });
  is(bad, 400);
  assert.equal(bad.body.errors[0].pointer, '/rrsets/1/name');
  const plain = await dom('PATCH', '/datasets/main/zones/example.test/rrsets', { body: { rrsets: [rr('www.example.test')] } });
  is(plain, 200);
  assert.equal(plain.body.warnings, undefined);
}));

test('a new zone named in Unicode is made under its A-labels, the way dig converts the name', withTools(standard([entry('xn--ss-gsx.test.', 'SOA', null, ['3600 SOA ns1.example.test. h.example.test. 1 2 3 4 5'])]), async (d, { root }, t) => {
  const body = { name: 'ß☃.test', soa: { mname: 'ns1.example.test', rname: 'hostmaster.example.test' }, nameservers: ['ns1.example.test'] };
  const r = await root('POST', '/datasets/main/zones', { body });
  is(r, 201);
  assert.equal(r.body.zone, 'xn--ss-gsx.test.');
  assert.equal(t.calls[0].argv.at(-1), 'xn--ss-gsx.test');
  assert.deepEqual(r.body.warnings.map((w) => w.code), ['idn-disallowed', 'idn-transitional']);
}));

test('the read side: the U-label form beside the name, a zone in the path in Unicode, the search in either form', withTools(standard([]), async (d, { root }) => {
  await run(d, "INSERT INTO domains (name, type) VALUES ('xn--r8jz45g.test', 'NATIVE')");
  const id = (await d.backend.tx({}, (tx) => tx.get("SELECT id FROM domains WHERE name = 'xn--r8jz45g.test'"))).id;
  for (const [name, type, content] of [['xn--r8jz45g.test', 'SOA', 'ns1.example.test h.example.test 1 2 3 4 5'], ['www.xn--r8jz45g.test', 'A', '192.0.2.1'], ['xn--gckc5l.xn--r8jz45g.test', 'A', '192.0.2.2']]) {
    await run(d, 'INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES (?, ?, ?, ?, 300, 0, 0)', [id, name, type, content]);
  }
  for (const q of ['contains=例え', 'prefix=例え', 'contains=xn--r8jz45g', 'prefix=%E4%BE%8B%E3%81%88.test']) {
    const r = await root('GET', `/datasets/main/zones?${q}`);
    is(r, 200);
    assert.deepEqual(r.body.zones.map((z) => [z.name, z.unicode]), [['xn--r8jz45g.test.', '例え.test.']], q);
  }
  const plainZone = (await root('GET', '/datasets/main/zones?contains=example')).body.zones[0];
  assert.equal(plainZone.unicode, undefined);
  is(await root('GET', '/datasets/main/zones?contains=a%20b'), 400);
  is(await root('GET', '/datasets/main/zones?contains=a%E2%80%8Db'), 400);
  is(await root('GET', '/datasets/main/zones?contains=%E3%88%B1'), 400);
  const z = await root('GET', `/datasets/main/zones/${encodeURIComponent('例え.test')}`);
  is(z, 200);
  assert.deepEqual([z.body.zone.name, z.body.zone.unicode], ['xn--r8jz45g.test.', '例え.test.']);
  const rs = await root('GET', `/datasets/main/zones/xn--r8jz45g.test/rrsets?contains=${encodeURIComponent('ウェブ')}`);
  is(rs, 200);
  assert.deepEqual(rs.body.rrsets.map((s) => [s.name, s.unicode]), [['xn--gckc5l.xn--r8jz45g.test.', 'ウェブ.例え.test.']]);
  const from = await root('GET', `/datasets/main/zones/xn--r8jz45g.test/rrsets?from=${encodeURIComponent('www.例え.test')}`);
  assert.deepEqual(from.body.rrsets.map((s) => s.name), ['www.xn--r8jz45g.test.', 'xn--gckc5l.xn--r8jz45g.test.', 'xn--r8jz45g.test.'], 'the names from it on, in the order of the A-labels');
  const named = await root('GET', `/datasets/main/zones/xn--r8jz45g.test/rrsets?name=${encodeURIComponent('ＷＷＷ.例え.test')}`);
  assert.deepEqual(named.body.rrsets.map((s) => s.name), ['www.xn--r8jz45g.test.']);
}));

test('GET /idn: what a name becomes, its U-label form, the warnings; a name with no A-label form is a 400', withTools(standard([]), async (d, { dom }) => {
  const r = await dom('GET', `/idn?name=${encodeURIComponent('ＷＷＷ.例え.test.')}`);
  is(r, 200);
  assert.deepEqual(r.body, { api: 1, ascii: 'www.xn--r8jz45g.test.', unicode: 'www.例え.test.', warnings: [], dig: true });
  const w = await dom('GET', `/idn?name=${encodeURIComponent('-例.test')}`);
  assert.deepEqual([w.body.ascii, w.body.dig, w.body.warnings.map((x) => x.code)], ['xn----lb7a.test', false, ['idn-hyphen', 'idn-not-dig']]);
  assert.equal((await dom('GET', '/idn?name=www.example.test')).body.unicode, null);
  const bad = await dom('GET', `/idn?name=${encodeURIComponent('a‍b.test')}`);
  is(bad, 400);
  assert.equal(bad.body.errors[0].pointer, '?name');
  is(await dom('GET', '/idn'), 400);
}));

test('GET /version: the ldns.jp link is on by default, ldns-link = no turns it off, ldns-resolver picks the resolver', async () => {
  for (const [settings, want] of [[{}, { url: 'https://ldns.jp/', resolver: 'google' }], [{ 'ldns-resolver': 'iij' }, { url: 'https://ldns.jp/', resolver: 'iij' }], [{ 'ldns-link': 'no' }, null]]) {
    await withTools(standard([]), async (d, { dom }) => {
      assert.deepEqual((await dom('GET', '/version')).body.ui.ldns, want);
    }, settings)();
  }
  assert.throws(() => parseConfig('ldns-resolver = quad9\n'), /line 1/);
  assert.throws(() => parseConfig('ldns-link = maybe\n'), /line 1/);
});

test('the parsers collect the IDN warnings of the names: a change set, a template', () => {
  const ch = parseChangeSet({ rrsets: [rr('a・b.example.test'), rr('аpple.example.test')] }, 'example.test');
  assert.deepEqual(ch.rrsets.map((s) => s.name), ['xn--ab-3n4a.example.test', 'xn--pple-43d.example.test']);
  assert.deepEqual(ch.warnings.map((w) => w.code), ['idn-contexto', 'idn-mixed-script']);
  const tpl = parseTemplate({ name: 't', records: [{ owner: 'メール', type: 'A', content: '192.0.2.1' }, { owner: '☃', type: 'A', content: '192.0.2.2' }] }, { create: true });
  assert.deepEqual(tpl.records.map((r) => r.owner), ['xn--4dkua4c', 'xn--n3h']);
  assert.deepEqual(tpl.warnings.map((w) => w.code), ['idn-disallowed']);
  assert.equal(parseTemplate({ name: 't', records: [{ owner: 'www', type: 'A', content: '192.0.2.1' }] }, { create: true }).warnings, undefined);
});

// The pure parts of E (planning 5 and 6): the arithmetic of the history (fold, diff, rollback set, outside changes), templates (validation, the zone text karicheck
// reads, the RRsets they make) and the creation of a zone from a template.

import test from 'node:test';
import assert from 'node:assert/strict';
import { fold, diffEntries, showEntry, sameState, rollbackRRsets, outsideChanges, OUTSIDE_SHOWN } from '../lib/versions.js';
import { parseTemplate, templateZoneText, templateMessages, templateComment } from '../lib/templates.js';
import { parseCreate, createRRsets, templateRRsets, templateLabel, renderChangeFile, mapMessages } from '../lib/changes.js';

const row = (version, owner, type, before, after) => ({ version, owner, type, before, after });
const A = (...ips) => ips.map((ip) => `300 A ${ip}`).join('\n');

// ---------------------------------------------------------------------------------------------------------------------------------- the history
test('fold: one entry per RRset, its state before the first version that touched it and after the last', () => {
  const rows = [
    row(2, 'www.example.test', 'A', A('192.0.2.10'), A('192.0.2.50')),
    row(2, 'new.example.test', 'A', null, A('192.0.2.60')),
    row(3, 'www.example.test', 'A', A('192.0.2.50'), A('192.0.2.51')),
    row(4, 'new.example.test', 'A', A('192.0.2.60'), null),
    row(4, 'a.example.test', 'TXT', null, '300 TXT "x"'),
  ];
  const f = fold(rows);
  assert.deepEqual(f.map((e) => [e.owner, e.type, e.first, e.last, e.versions]), [
    ['a.example.test', 'TXT', null, '300 TXT "x"', [4]],
    ['new.example.test', 'A', null, null, [2, 4]],
    ['www.example.test', 'A', A('192.0.2.10'), A('192.0.2.51'), [2, 3]],
  ]);
  assert.deepEqual(fold([]), []);
  // the same owner and type of another kind is another RRset; the order is by name, then type
  assert.deepEqual(fold([row(1, 'b.t', 'A', null, A('192.0.2.1')), row(1, 'b.t', 'AAAA', null, '300 AAAA ::1'), row(1, 'a.t', 'MX', null, '300 MX 10 m.t.')]).map((e) => `${e.owner} ${e.type}`), ['a.t MX', 'b.t A', 'b.t AAAA']);
});

test('diff: what is different at the two ends; an RRset that came back to its state is not; an SOA differs in more than the serial', () => {
  const soa = (serial, refresh = 7200) => `3600 SOA ns1.example.test. hostmaster.example.test. ${serial} ${refresh} 3600 1209600 300`;
  const rows = [
    row(2, 'www.example.test', 'A', A('192.0.2.10'), A('192.0.2.50')),
    row(3, 'www.example.test', 'A', A('192.0.2.50'), A('192.0.2.10')),
    row(2, 'x.example.test', 'A', null, A('192.0.2.1')),
    row(3, 'example.test', 'SOA', soa(10), soa(11)),
    row(4, 'example.test', 'SOA', soa(11), soa(12, 100)),
  ];
  assert.deepEqual(diffEntries(fold(rows.slice(0, 4))).map((e) => e.owner), ['x.example.test']);
  assert.deepEqual(diffEntries(fold(rows)).map((e) => e.owner), ['example.test', 'x.example.test']);
  assert.deepEqual(showEntry('x.example.test', 'A', null, A('192.0.2.1')), { name: 'x.example.test.', type: 'A', change: 'add', before: null, after: [{ ttl: 300, content: '192.0.2.1' }] });
  assert.equal(showEntry('x.example.test', 'A', A('192.0.2.1'), null).change, 'delete');
  assert.equal(showEntry('x.example.test', 'A', A('192.0.2.1'), A('192.0.2.2')).change, 'replace');
  // the lines in any order are the same state; the serial and the case of the names do not count for an SOA
  assert.equal(sameState('A', A('192.0.2.1', '192.0.2.2'), A('192.0.2.2', '192.0.2.1')), true);
  assert.equal(sameState('SOA', soa(1), soa(9).replace('ns1.example.test.', 'NS1.example.test')), true);
  assert.equal(sameState('SOA', soa(1), soa(1, 5)), false);
  assert.equal(sameState('A', null, null), true);
  assert.equal(sameState('A', null, A('192.0.2.1')), false);
  assert.equal(sameState('SOA', 'broken', 'broken2'), false);
});

test('rollback: every RRset touched goes back to the state before the first version, expecting the state the last one left', () => {
  const rows = [
    row(2, 'www.example.test', 'A', `${A('192.0.2.10')}\n600 A 192.0.2.11`, A('192.0.2.50')),
    row(2, 'new.example.test', 'A', null, A('192.0.2.60')),
    row(3, 'www.example.test', 'A', A('192.0.2.50'), A('192.0.2.51')),
    row(3, 'gone.example.test', 'MX', '300 MX 10 mail.example.test.', null),
    row(3, 'example.test', 'SOA', '3600 SOA a. b. 1 2 3 4 5', '3600 SOA a. c. 2 2 3 4 5'),
  ];
  const { rrsets, skipped } = rollbackRRsets(fold(rows), 'example.test', { force: false });
  assert.deepEqual(rrsets, [
    { name: 'gone.example.test', type: 'MX', op: 'replace', ttl: 300, ttls: [300], records: ['10 mail.example.test.'], expect: [] },
    { name: 'new.example.test', type: 'A', op: 'delete', ttl: null, ttls: null, records: [], expect: [{ ttl: 300, content: '192.0.2.60' }] },
    { name: 'www.example.test', type: 'A', op: 'replace', ttl: 300, ttls: [300, 600], records: ['192.0.2.10', '192.0.2.11'], expect: [{ ttl: 300, content: '192.0.2.51' }] },
  ]);
  assert.deepEqual(skipped.map((s) => [s.name, s.type]), [['example.test.', 'SOA']]);
  // force: no expectation
  assert.ok(rollbackRRsets(fold(rows), 'example.test', { force: true }).rrsets.every((r) => r.expect === null));
  // the change file takes the TTL of each record
  assert.equal(renderChangeFile(rrsets).text, 'rr gone.example.test. 300 MX 10 mail.example.test.\ndelete new.example.test. A\nrr www.example.test. 300 A 192.0.2.10\nrr www.example.test. 600 A 192.0.2.11\n');
  // a history the API cannot read back is refused, not guessed: no TTL, RDATA that could end its line or hide the rest of it, a name that is none, in the state to restore
  // and in the state it is expected to be in
  const refused = (r) => assert.throws(() => rollbackRRsets(fold([r]), 'example.test', { force: false }), (e) => e.status === 409 && e.code === 'cannot-restore');
  refused(row(2, 'x.example.test', 'A', 'no ttl here', null));
  refused(row(2, 'x.example.test', 'TXT', '300 TXT "a" ; b', null));
  refused(row(2, 'x.example.test', 'TXT', null, '300 TXT "a" ; b'));
  refused(row(2, 'x.example.test\nrr evil.example.test. 1 A 192.0.2.1', 'A', A('192.0.2.1'), null));
  refused(row(2, 'x.example.test', 'A', A('192.0.2.1'), 'no ttl here'));
  assert.equal(rollbackRRsets(fold([row(2, 'x.example.test', 'TXT', null, '300 TXT "a ; b"')]), 'example.test', { force: true }).rrsets.length, 1, 'a semicolon inside quotes is data');
});

test('changes outside the versions: not the DNSSEC types, not the serial of the SOA', () => {
  const rec = (type, content, extra = {}) => ({ name: 'x.example.test', type, content, ttl: 300, prio: 0, disabled: 0, ...extra });
  const soa = (serial) => rec('SOA', `ns1.example.test hostmaster.example.test ${serial} 7200 3600 1209600 300`, { name: 'example.test' });
  const rows = [
    { op: 'I', before: null, after: rec('RRSIG', 'x') },
    { op: 'U', before: soa(1), after: soa(2) },
    { op: 'U', before: soa(2), after: { ...soa(2), disabled: 1 } },
    { op: 'U', before: rec('A', '192.0.2.1'), after: rec('A', '192.0.2.2') },
    { op: 'D', before: rec('TXT', '"x"', { name: 'T.Example.test.' }), after: null },
    { op: 'I', before: null, after: rec('A', '192.0.2.3') },
    { op: 'I', before: null, after: null },
  ];
  assert.deepEqual(outsideChanges(rows), { count: 4, rrsets: [{ name: 'example.test.', type: 'SOA' }, { name: 'x.example.test.', type: 'A' }, { name: 't.example.test.', type: 'TXT' }] });
  // the SOA with another TTL is a change, so is one with another name server
  assert.equal(outsideChanges([{ op: 'U', before: soa(1), after: { ...soa(1), ttl: 5 } }]).count, 1);
  assert.equal(outsideChanges([{ op: 'U', before: soa(1), after: { ...soa(1), content: 'ns9.example.test hostmaster.example.test 1 7200 3600 1209600 300' } }]).count, 1);
  assert.equal(outsideChanges([{ op: 'U', before: { ...soa(1), content: 'short' }, after: { ...soa(1), content: 'short2' } }]).count, 1);
  // at most a few RRsets are named, all are counted
  const many = Array.from({ length: OUTSIDE_SHOWN + 5 }, (_, i) => ({ op: 'I', before: null, after: rec('A', '192.0.2.1', { name: `h${i}.example.test` }) }));
  const o = outsideChanges(many);
  assert.equal(o.count, OUTSIDE_SHOWN + 5);
  assert.equal(o.rrsets.length, OUTSIDE_SHOWN);
});

// ---------------------------------------------------------------------------------------------------------------------------------- templates
const bad = (fn, pointer, re) => assert.throws(fn, (e) => {
  assert.equal(e.status, 400, e.message);
  if (pointer) assert.equal(e.errors?.[0]?.pointer, pointer, JSON.stringify(e.errors));
  if (re) assert.match(e.errors?.[0]?.text ?? e.detail, re);
  return true;
});

test('a template: owners relative to the zone, types upper case, no SOA and no DNSSEC types, one TTL to an RRset', () => {
  const t = parseTemplate({
    name: 'standard', description: 'the usual', soa: { mname: 'NS1.example.test.', rname: 'hostmaster.example.test', refresh: 7200, minimum: 300 },
    records: [{ owner: '@', type: 'ns', content: 'ns1.example.test.' }, { owner: 'WWW', type: 'a', ttl: 300, content: '192.0.2.1' }, { owner: '*.dev', type: 'A', ttl: 300, content: '192.0.2.2' },
      { owner: 'WWW', type: 'A', ttl: 300, content: '192.0.2.3' }, { owner: '@', type: 'MX', content: '10 mail' }],
    dry_run: true,
  }, { create: true });
  assert.deepEqual(t, {
    dryRun: true, name: 'standard', description: 'the usual',
    soa: { mname: 'ns1.example.test', rname: 'hostmaster.example.test', refresh: 7200, retry: null, expire: null, minimum: 300 },
    records: [
      { owner: '@', type: 'NS', ttl: null, content: 'ns1.example.test.' }, { owner: 'www', type: 'A', ttl: 300, content: '192.0.2.1' }, { owner: '*.dev', type: 'A', ttl: 300, content: '192.0.2.2' },
      { owner: 'www', type: 'A', ttl: 300, content: '192.0.2.3' }, { owner: '@', type: 'MX', ttl: null, content: '10 mail' },
    ],
  });
  // a PATCH has only what it carries; the SOA defaults can be cleared; a creation has an empty list of records at least
  assert.deepEqual(parseTemplate({ description: null, soa: null }), { dryRun: false, description: null, soa: null });
  assert.deepEqual(parseTemplate({ name: 'x' }, { create: true }), { dryRun: false, name: 'x', records: [] });
  assert.deepEqual(parseTemplate({ soa: { mname: 'a.test' } }).soa, { mname: 'a.test', rname: null, refresh: null, retry: null, expire: null, minimum: null });
  const types = new Set(['A', 'NS', 'MX', 'CAA']);
  const rec = (over) => ({ name: 'x', records: [{ owner: '@', type: 'A', content: '192.0.2.1', ...over }] });
  bad(() => parseTemplate({}, { create: true }), '/name');
  bad(() => parseTemplate({ name: '-x' }), '/name');
  bad(() => parseTemplate({ name: 'x', surprise: 1 }), '/surprise');
  bad(() => parseTemplate({ name: 'x', soa: { mname: 'a b' } }), '/soa/mname');
  bad(() => parseTemplate({ name: 'x', soa: { rname: 'a;b' } }), '/soa/rname');
  bad(() => parseTemplate(rec({ owner: 'www.' })), '/records/0/owner', /no final dot/);
  bad(() => parseTemplate(rec({ owner: 'a..b' })), '/records/0/owner');
  bad(() => parseTemplate(rec({ type: 'SOA' })), '/records/0/type', /soa fields/);
  bad(() => parseTemplate(rec({ type: 'rrsig' })), '/records/0/type', /signer/);
  bad(() => parseTemplate(rec({ type: 'type48' })), '/records/0/type', /signer/);
  bad(() => parseTemplate(rec({ type: 'WKS' }), { types }), '/records/0/type', /not a record type/);
  bad(() => parseTemplate(rec({ content: 'a;b' })), '/records/0/content');
  bad(() => parseTemplate(rec({ content: '$INCLUDE x' })), '/records/0/content');
  bad(() => parseTemplate(rec({ content: 'a\nb' })), '/records/0/content');
  bad(() => parseTemplate(rec({ ttl: -1 })), '/records/0/ttl');
  bad(() => parseTemplate({ name: 'x', records: [{ owner: '@', type: 'A', ttl: 300, content: '192.0.2.1' }, { owner: '@', type: 'A', ttl: 60, content: '192.0.2.2' }] }), '/records/1/ttl', /same TTL/);
  bad(() => parseTemplate({ name: 'x', records: [{ owner: '@', type: 'A', ttl: 300, content: '192.0.2.1' }, { owner: '@', type: 'A', content: '192.0.2.2' }] }), '/records/1/ttl', /same TTL/);
});

test('the zone text karicheck reads, and its messages mapped back to the records', () => {
  const recs = [{ owner: 'www', type: 'A', ttl: 300, content: '192.0.2.1' }, { owner: '@', type: 'MX', ttl: null, content: '10 mail' }];
  const z = templateZoneText(recs);
  assert.equal(z.text, '$ORIGIN template.invalid.\n$TTL 3600\n@ IN SOA ns.nameserver.invalid. hostmaster.template.invalid. 1 7200 3600 1209600 300\n@ IN NS ns.nameserver.invalid.\n'
    + 'www 300 IN A 192.0.2.1\n@ IN MX 10 mail\n');
  assert.equal(z.base, 4);
  // a template that has its own NS at the apex gets no synthetic one
  const own = templateZoneText([{ owner: '@', type: 'NS', ttl: null, content: 'ns1.example.test.' }]);
  assert.equal(own.base, 3);
  assert.ok(!own.text.includes('IN NS ns.nameserver.invalid.'));
  assert.equal(templateZoneText([]).base, 4);
  const msgs = [
    { severity: 'error', code: 'zone.cname-other', text: 'standard input:5: bad', line: 5 },
    { severity: 'warning', code: 'zone.something', text: 'synthetic', line: 3 },
    { severity: 'warning', code: 'zone.nolines', text: 'no line', line: null },
    { severity: 'note', code: 'n', text: 'x', line: 6 },
    { severity: 'error', code: 'zone.syntax', text: 'standard input:6: worse', line: 6 },
  ];
  assert.deepEqual(templateMessages(msgs, 4), [
    { code: 'zone.cname-other', severity: 'error', text: 'standard input:5: bad', pointer: '/records/0' },
    { code: 'zone.nolines', severity: 'warning', text: 'no line' },
    { code: 'zone.syntax', severity: 'error', text: 'standard input:6: worse', pointer: '/records/1' },
  ]);
  assert.deepEqual(templateMessages(undefined, 4), []);
});

test('the comment of the version a template makes names the template, its id and revision', () => {
  const tpl = { id: 4, name: 'standard', revision: 7 };
  assert.equal(templateComment(tpl, undefined), 'template "standard" (id 4, revision 7)');
  assert.equal(templateComment(tpl, 'new customer'), 'new customer [template "standard" (id 4, revision 7)]');
  const long = templateComment(tpl, 'x'.repeat(1024));
  assert.ok(Buffer.byteLength(long) <= 1024 && long.endsWith('[template "standard" (id 4, revision 7)]'));
  assert.equal(templateComment({ ...tpl, name: 'n'.repeat(255) }, 'y').length < 1025, true);
});

test('the RRsets of a template: one per owner and type, relative owners under the zone, the TTL of the template or the default', () => {
  const tpl = { records: [
    { owner: '@', type: 'NS', ttl: null, content: 'ns1.example.test.' }, { owner: '@', type: 'NS', ttl: null, content: 'ns2.example.test.' },
    { owner: 'www', type: 'A', ttl: 300, content: '192.0.2.1' }, { owner: '*.dev', type: 'CNAME', ttl: 60, content: 'www' }, { owner: '@', type: 'MX', ttl: null, content: '10 mail' },
  ] };
  const r = templateRRsets(tpl, 'new.test', 900);
  assert.deepEqual(r.map((x) => [x.name, x.type, x.ttl, x.records, x.first]), [
    ['new.test', 'NS', 900, ['ns1.example.test.', 'ns2.example.test.'], 0],
    ['www.new.test', 'A', 300, ['192.0.2.1'], 2],
    ['*.dev.new.test', 'CNAME', 60, ['www'], 3],
    ['new.test', 'MX', 900, ['10 mail'], 4],
  ]);
  assert.equal(templateLabel(r)(1).path, '/template/records/2');
  // a template the database was written to by others: what could end a line or name something that is no name is not copied
  const unfit = (rec) => assert.throws(() => templateRRsets({ records: [rec] }, 'new.test', 60), (e) => e.status === 409 && e.code === 'template-invalid');
  unfit({ owner: 'www', type: 'A', ttl: 1, content: '192.0.2.1\nrr evil.new.test. 1 A 192.0.2.2' });
  unfit({ owner: 'www', type: 'TXT', ttl: 1, content: '"a" ; b' });
  unfit({ owner: 'www.', type: 'A', ttl: 1, content: '192.0.2.1' });
  unfit({ owner: 'a b', type: 'A', ttl: 1, content: '192.0.2.1' });
  assert.equal(renderChangeFile(r, templateLabel(r)).text, 'rr new.test. 900 NS ns1.example.test.\nrr new.test. 900 NS ns2.example.test.\nrr www.new.test. 300 A 192.0.2.1\n'
    + 'rr *.dev.new.test. 60 CNAME www\nrr new.test. 900 MX 10 mail\n');
});

test('a new zone from a template: the SOA values and the records of the template, what the request says wins', () => {
  const day = new Date(Date.UTC(2026, 10, 8));
  const tpl = {
    id: 3, name: 'standard', revision: 2, soa: { mname: 'ns1.example.test', rname: 'hostmaster.example.test', refresh: 1800, retry: null, expire: null, minimum: 60 },
    records: [{ owner: '@', type: 'NS', ttl: null, content: 'ns1.example.test.' }, { owner: '@', type: 'TXT', ttl: null, content: '"v=spf1 -all"' }, { owner: 'www', type: 'A', ttl: 300, content: '192.0.2.1' }],
  };
  const c = parseCreate({ name: 'new.test', template: 'standard', rrsets: [{ name: 'www.new.test', type: 'A', changetype: 'REPLACE', ttl: 60, records: [{ content: '192.0.2.99' }] }], default_ttl: 900 }, { now: day });
  assert.equal(c.template, 'standard');
  const made = createRRsets(c, 'new.test', tpl);
  assert.deepEqual(made.rrsets.map((r) => [r.name, r.type, r.ttl, r.records]), [
    ['new.test', 'SOA', 900, ['ns1.example.test. hostmaster.example.test. 2026110800 1800 3600 1209600 60']],
    ['new.test', 'NS', 900, ['ns1.example.test.']],
    ['new.test', 'TXT', 900, ['"v=spf1 -all"']],
    ['www.new.test', 'A', 60, ['192.0.2.99']],
  ]);
  assert.equal(made.serial, 2026110800);
  assert.deepEqual([0, 1, 2, 3].map((i) => made.label(i)), [{ path: '/soa' }, { path: '/template/records/0' }, { path: '/template/records/1' }, { path: '/rrsets/0', records: 'records' }]);
  // the request's name servers replace the template's apex NS; the request's SOA values replace the template's
  const c2 = parseCreate({ name: 'new.test', template_id: 3, soa: { mname: 'ns9.example.test', rname: 'h.example.test', serial: 5 }, nameservers: ['ns9.example.test.'] }, { now: day });
  assert.equal(c2.templateId, 3);
  const m2 = createRRsets(c2, 'new.test', tpl);
  assert.deepEqual(m2.rrsets.map((r) => [r.type, r.records]), [['SOA', ['ns9.example.test. h.example.test. 5 1800 3600 1209600 60']], ['NS', ['ns9.example.test.']], ['TXT', ['"v=spf1 -all"']], ['A', ['192.0.2.1']]]);
  assert.deepEqual(m2.label(1), { path: '/nameservers', records: '' });
  // no SOA names in the request or the template
  bad(() => createRRsets(parseCreate({ name: 'n.test', template: 'x' }), 'n.test', { soa: null, records: [] }), '/soa/mname');
  bad(() => createRRsets(parseCreate({ name: 'n.test', template: 'x', soa: { mname: 'a.n.test' } }), 'n.test', { soa: null, records: [] }), '/soa/rname');
  // the template without SOA values, the request with them, and no name servers at all (karidns-zone refuses a zone without NS)
  const c3 = parseCreate({ name: 'n.test', template: 'x', soa: { mname: 'a.n.test', rname: 'h.n.test' } }, { now: day });
  assert.deepEqual(createRRsets(c3, 'n.test', { soa: null, records: [] }).rrsets.map((r) => r.type), ['SOA']);
  // the shape of the request
  bad(() => parseCreate({ name: 'n.test', template: 'x', template_id: 1 }), '/template_id');
  bad(() => parseCreate({ name: 'n.test', zone_text: 'x', template: 'x' }), '/template');
  bad(() => parseCreate({ name: 'n.test', soa: { rname: 'h.n.test' }, nameservers: ['a'] }), '/soa/mname');
  bad(() => parseCreate({ name: 'n.test', soa: { mname: 'h.n.test' }, nameservers: ['a'] }), '/soa/rname');
});

test('mapMessages: an RRset that comes from a template points at the template; one without a place has no pointer', () => {
  const tpl = { records: [{ owner: '@', type: 'A', ttl: 1, content: '192.0.2.1' }] };
  const r = templateRRsets(tpl, 'z.test', 60);
  const maps = renderChangeFile(r, templateLabel(r));
  const m = mapMessages([{ severity: 'error', code: 'c', text: 'standard input:2: bad' }], maps);
  assert.equal(m[0].pointer, '/template/records/0');
  const none = renderChangeFile(r, () => ({}));
  assert.equal(mapMessages([{ severity: 'error', code: 'c', text: 'standard input:2: bad' }], none)[0].pointer, undefined);
  assert.equal(mapMessages([{ severity: 'error', code: 'c', text: 'standard input: line 1: bad' }], none)[0].pointer, undefined);
});

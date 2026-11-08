// change sets, permission of a whole diff, DS records, zone metadata, the pool and the zone lock: the pure parts of the write side (planning 2.3, 4.1, 8.1)

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseChangeSet, renderChangeFile, renderExpectations, contentProblem, parseLine, showDiff, diffItems, mapMessages, entryIndex, entryPointer, parseCreate, createRRsets,
  createLabel, rrsetLabel,
} from '../lib/changes.js';
import { chooseGrant } from '../lib/perm.js';
import { wireName, keyTag, parseDnskey, dsDigest, dnskeyView } from '../lib/dnssec.js';
import { metaKind, metaProblem, KINDS, MAX_ROWS } from '../lib/meta.js';
import { Pool, KeyedLock } from '../lib/pool.js';
import { checkArgv, commitArgv, reloadArgv, dbArgs } from '../lib/tools.js';

const rr = (name, type, ttl, ...contents) => ({ name, type, changetype: 'REPLACE', ttl, records: contents.map((content) => ({ content })) });
const bad = (fn, pointer, re) => assert.throws(fn, (e) => {
  assert.equal(e.status, 400);
  if (pointer) assert.equal(e.errors?.[0]?.pointer, pointer, JSON.stringify(e.errors));
  if (re) assert.match(e.errors?.[0]?.text ?? e.detail, re);
  return true;
});

// ---------------------------------------------------------------------------------------------------------------------------------- the request
test('a change set: names are canonical, types upper case, the shape is checked', () => {
  const c = parseChangeSet({ comment: 'move www', dry_run: true, reload: false, rrsets: [rr('WWW.Example.test.', 'a', 300, '192.0.2.10', '192.0.2.11'), { name: 'old.example.test', type: 'txt', changetype: 'DELETE' }] }, 'example.test');
  assert.deepEqual(c, {
    comment: 'move www', dryRun: true, reload: false,
    rrsets: [
      { name: 'www.example.test', type: 'A', op: 'replace', ttl: 300, records: ['192.0.2.10', '192.0.2.11'], expect: null },
      { name: 'old.example.test', type: 'TXT', op: 'delete', ttl: null, records: [], expect: null },
    ],
  });
  assert.equal(parseChangeSet({ rrsets: [rr('example.test.', 'NS', 1, 'ns1.example.test.')] }, 'example.test').reload, undefined);
  // the types karidns-zone names, TYPEnnn, and nothing else
  const types = new Set(['A', 'MX']);
  assert.equal(parseChangeSet({ rrsets: [rr('a.example.test', 'type65', 1, '\\# 0')] }, 'example.test', { types }).rrsets[0].type, 'TYPE65');
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'RRSIG', 1, 'x')] }, 'example.test', { types }), '/rrsets/0/type', /RRSIG is not a record type/);
  // shape
  bad(() => parseChangeSet(undefined, 'example.test'), '');
  bad(() => parseChangeSet({}, 'example.test'), '/rrsets');
  bad(() => parseChangeSet({ rrsets: [] }, 'example.test'), '/rrsets');
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'A', 1, '192.0.2.1')], surprise: 1 }, 'example.test'), '/surprise');
  bad(() => parseChangeSet({ rrsets: [{ ...rr('a.example.test', 'A', 1, '192.0.2.1'), extra: 1 }] }, 'example.test'), '/rrsets/0/extra');
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'A', 1, '192.0.2.1')].concat({ name: 'b.example.test', type: 'A', changetype: 'PATCH' }) }, 'example.test'), '/rrsets/1/changetype');
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'A', -1, 'x')] }, 'example.test'), '/rrsets/0/ttl');
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'A', 2147483648, 'x')] }, 'example.test'), '/rrsets/0/ttl');
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'A', 1.5, 'x')] }, 'example.test'), '/rrsets/0/ttl');
  // names
  bad(() => parseChangeSet({ rrsets: [rr('a.other.test', 'A', 1, 'x')] }, 'example.test'), '/rrsets/0/name', /not in the zone/);
  bad(() => parseChangeSet({ rrsets: [rr('wwwexample.test', 'A', 1, 'x')] }, 'example.test'), '/rrsets/0/name', /not in the zone/);
  bad(() => parseChangeSet({ rrsets: [rr('a..example.test', 'A', 1, 'x')] }, 'example.test'), '/rrsets/0/name');
  bad(() => parseChangeSet({ rrsets: [rr('a\\.example.test', 'A', 1, 'x')] }, 'example.test'), '/rrsets/0/name');
  bad(() => parseChangeSet({ rrsets: [rr('a b.example.test', 'A', 1, 'x')] }, 'example.test'), '/rrsets/0/name');
  bad(() => parseChangeSet({ rrsets: [rr('é.example.test', 'A', 1, 'x')] }, 'example.test'), '/rrsets/0/name');
  bad(() => parseChangeSet({ rrsets: [rr(`${'a'.repeat(64)}.example.test`, 'A', 1, 'x')] }, 'example.test'), '/rrsets/0/name');
  // REPLACE and DELETE
  bad(() => parseChangeSet({ rrsets: [{ name: 'a.example.test', type: 'A', changetype: 'REPLACE', records: [{ content: 'x' }] }] }, 'example.test'), '/rrsets/0/ttl', /needs a ttl/);
  bad(() => parseChangeSet({ rrsets: [{ name: 'a.example.test', type: 'A', changetype: 'REPLACE', ttl: 1 }] }, 'example.test'), '/rrsets/0/records');
  bad(() => parseChangeSet({ rrsets: [{ name: 'a.example.test', type: 'A', changetype: 'REPLACE', ttl: 1, records: [] }] }, 'example.test'), '/rrsets/0/records');
  bad(() => parseChangeSet({ rrsets: [{ name: 'a.example.test', type: 'A', changetype: 'DELETE', ttl: 1 }] }, 'example.test'), '/rrsets/0/ttl');
  bad(() => parseChangeSet({ rrsets: [{ name: 'a.example.test', type: 'A', changetype: 'DELETE', records: [{ content: 'x' }] }] }, 'example.test'), '/rrsets/0/records');
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'A', 1, 'x'), rr('A.example.test.', 'a', 2, 'y')] }, 'example.test'), '/rrsets/1', /twice/);
  // expectations
  const e = parseChangeSet({ rrsets: [{ ...rr('a.example.test', 'A', 1, '192.0.2.1'), expect: [{ ttl: 300, content: '192.0.2.9' }] }, { name: 'b.example.test', type: 'A', changetype: 'DELETE', expect: [] }] }, 'example.test');
  assert.deepEqual(e.rrsets.map((r) => r.expect), [[{ ttl: 300, content: '192.0.2.9' }], []]);
  bad(() => parseChangeSet({ rrsets: [{ ...rr('a.example.test', 'A', 1, 'x'), expect: [{ ttl: 300 }] }] }, 'example.test'), '/rrsets/0/expect/0/content');
  bad(() => parseChangeSet({ rrsets: [{ ...rr('a.example.test', 'A', 1, 'x'), expect: [{ ttl: 300, content: 'a;b' }] }] }, 'example.test'), '/rrsets/0/expect/0/content');
});

test('the text of a record: nothing that could end its line or hide the rest of it', () => {
  for (const ok of ['192.0.2.1', '"v=spf1 -all"', '"a;b (c) $d"', '10 mail.example.test.', '"quote \\" inside; still"', '0 issue "ca.example.test"', 'a\\;b-looks-like-a-semicolon-escape-no'.replace(';', '')]) {
    assert.equal(contentProblem(ok), null, ok);
  }
  for (const [text, re] of [
    ['a\nb', /control/], ['a\rb', /control/], ['a\0b', /control/], ['a\tb', /control/], ['a\x7fb', /control/],
    ['$INCLUDE /etc/passwd', /directive/], ['$ORIGIN x.', /directive/],
    ['1.2.3.4 ; comment', /comment/], ['(1.2.3.4', /parentheses/], ['1.2.3.4)', /parentheses/],
    ['"open quote', /not closed/], ['"a" "b', /not closed/], ['trailing\\', /backslash/], ['"x\\"', /not closed/],
  ]) assert.match(contentProblem(text), re, JSON.stringify(text));
  // and through a request: the pointer names the record
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'TXT', 1, '"ok"', '"x" ; y')] }, 'example.test'), '/rrsets/0/records/1/content');
  bad(() => parseChangeSet({ rrsets: [rr('a.example.test', 'TXT', 1, 'a\nrr evil.example.test. 1 A 1.2.3.4')] }, 'example.test'), '/rrsets/0/records/0/content');
});

test('the change file: one line per operation, absolute names, and the maps from the lines back to the request', () => {
  const c = parseChangeSet({ rrsets: [rr('www.example.test', 'A', 300, '192.0.2.10', '192.0.2.11'), { name: 'old.example.test', type: 'TXT', changetype: 'DELETE' }, rr('Example.TEST', 'MX', 3600, '10 mail')] }, 'example.test');
  const f = renderChangeFile(c.rrsets);
  assert.equal(f.text, 'rr www.example.test. 300 A 192.0.2.10\nrr www.example.test. 300 A 192.0.2.11\ndelete old.example.test. TXT\nrr example.test. 3600 MX 10 mail\n');
  assert.equal(f.ops.length, 4);
  assert.deepEqual(f.rr.map((x) => [x.path, x.record]), [['/rrsets/0', 0], ['/rrsets/0', 1], ['/rrsets/2', 0]]);
  // the zone text karidns-zone makes has $ORIGIN first, then the rr lines: line 2 is the first rr line
  const m = (text, line) => mapMessages([{ severity: 'error', code: 'zone.x', text, line: null }], f)[0];
  assert.equal(m('Syntax error: standard input:3: A record requires exactly 1 parameter').pointer, '/rrsets/0/records/1');
  assert.equal(m('Zone x: standard input:4: no good').pointer, '/rrsets/2/records/0');
  assert.equal(m('standard input:1: the origin').pointer, undefined);
  assert.equal(m('standard input:99: past the end').pointer, undefined);
  assert.equal(m('standard input: line 3: owner is outside the zone').pointer, '/rrsets/1');
  assert.equal(m('standard input: line 1: bad').pointer, '/rrsets/0/records/0');
  assert.equal(m('no line in this one').pointer, undefined);
  // notes and infos are not passed on; codes and severities are
  const out = mapMessages([{ severity: 'note', code: 'db.import.change', text: 'add x' }, { severity: 'info', code: 'a', text: 'b' }, { severity: 'warning', code: 'zone.ttl.missing', text: 'w' }], f);
  assert.deepEqual(out, [{ code: 'zone.ttl.missing', severity: 'warning', text: 'w' }]);
  assert.deepEqual(mapMessages(undefined, f), []);
  // a zone text has no request to point into: the line is passed on
  assert.deepEqual(mapMessages([{ severity: 'error', code: 'zone.syntax', text: 'bad: new.zone:12: oops' }], null), [{ code: 'zone.syntax', severity: 'error', text: 'bad: new.zone:12: oops', pointer: '/zone_text', line: 12 }]);
  assert.deepEqual(mapMessages([{ severity: 'error', code: 'zone.syntax', text: 'no line' }], null), [{ code: 'zone.syntax', severity: 'error', text: 'no line' }]);
});

test('the preconditions are a change file of their own', () => {
  const c = parseChangeSet({ rrsets: [
    { ...rr('a.example.test', 'A', 1, '192.0.2.9'), expect: [{ ttl: 300, content: '192.0.2.1' }, { ttl: 300, content: '192.0.2.2' }] },
    rr('b.example.test', 'A', 1, '192.0.2.9'),
    { name: 'c.example.test', type: 'TXT', changetype: 'DELETE', expect: [] },
  ] }, 'example.test');
  const x = renderExpectations(c.rrsets);
  assert.equal(x.text, 'rr a.example.test. 300 A 192.0.2.1\nrr a.example.test. 300 A 192.0.2.2\ndelete c.example.test. TXT\n');
  assert.deepEqual(x.index, [0, 2]);
  assert.equal(renderExpectations(parseChangeSet({ rrsets: [rr('b.example.test', 'A', 1, 'x')] }, 'example.test').rrsets), null);
});

test('the diff of karidns-zone as the API shows it and as the permission check sees it', () => {
  const diff = [
    { owner: 'www.example.test.', type: 'A', change: 'replace', before: ['300 A 192.0.2.1'], after: ['300 A 192.0.2.10', '600 A 192.0.2.11'] },
    { owner: 'New.Example.test.', type: 'TXT', change: 'add', before: null, after: ['60 TXT "a b"'] },
    { owner: 'gone.example.test.', type: 'MX', change: 'delete', before: ['3600 MX 10 mail.example.test.'], after: null },
  ];
  assert.deepEqual(parseLine('300 A 192.0.2.1'), { ttl: 300, content: '192.0.2.1' });
  assert.deepEqual(parseLine('60 TXT "a b"'), { ttl: 60, content: '"a b"' });
  assert.deepEqual(parseLine('not a line'), { ttl: null, content: 'not a line' });
  assert.deepEqual(showDiff(diff)[1], { name: 'New.Example.test.', type: 'TXT', change: 'add', before: null, after: [{ ttl: 60, content: '"a b"' }] });
  assert.deepEqual(showDiff(diff)[0].after, [{ ttl: 300, content: '192.0.2.10' }, { ttl: 600, content: '192.0.2.11' }]);
  assert.deepEqual(diffItems(diff), [
    { name: 'www.example.test', type: 'A', ttls: [300, 300, 600] }, { name: 'new.example.test', type: 'TXT', ttls: [60] }, { name: 'gone.example.test', type: 'MX', ttls: [3600] },
  ]);
  assert.deepEqual(diffItems([{ owner: 'x.example.test.', type: 'A', before: ['oops'], after: null }]), [{ name: 'x.example.test', type: 'A', ttls: [0] }]);
  const c = parseChangeSet({ rrsets: [rr('www.example.test', 'A', 300, 'x'), rr('new.example.test', 'TXT', 60, '"a b"')] }, 'example.test');
  assert.equal(entryIndex(c.rrsets, diff[0]), 0);
  assert.equal(entryIndex(c.rrsets, diff[1]), 1);
  assert.equal(entryIndex(c.rrsets, diff[2]), -1);
  assert.equal(entryPointer(c.rrsets, diff[1]), '/rrsets/1');
  assert.equal(entryPointer(c.rrsets, diff[2]), undefined);
  assert.equal(entryPointer(c.rrsets, diff[1], createLabel), '/nameservers');
});

// ---------------------------------------------------------------------------------------------------------------------------------- a new zone
test('a new zone: the SOA and name servers of the request, or a zone text', () => {
  const day = new Date(Date.UTC(2026, 10, 8, 12));
  const c = parseCreate({ name: 'new.test', soa: { mname: 'NS1.new.test.', rname: 'hostmaster.new.test' }, nameservers: ['ns1.new.test.', 'ns2.example.test'], reload: true,
    rrsets: [rr('www.new.test', 'A', 300, '192.0.2.1')] }, { now: day });
  assert.equal(c.kind, 'NATIVE');
  assert.equal(c.reload, true);
  const made = createRRsets(c, 'new.test');
  assert.deepEqual(made.rrsets.map((r) => [r.name, r.type, r.ttl, r.records]), [
    ['new.test', 'SOA', 3600, ['ns1.new.test. hostmaster.new.test. 2026110800 7200 3600 1209600 300']],
    ['new.test', 'NS', 3600, ['ns1.new.test.', 'ns2.example.test.']],
    ['www.new.test', 'A', 300, ['192.0.2.1']],
  ]);
  const f = renderChangeFile(made.rrsets, createLabel);
  assert.equal(f.text.split('\n')[0], 'rr new.test. 3600 SOA ns1.new.test. hostmaster.new.test. 2026110800 7200 3600 1209600 300');
  assert.deepEqual(f.rr.map((x) => x.path + (x.records === undefined ? '' : `|${x.records}|${x.record}`)), ['/soa', '/nameservers||0', '/nameservers||1', '/rrsets/0|records|0']);
  assert.equal(mapMessages([{ severity: 'error', code: 'zone.x', text: 'standard input:4: bad' }], f)[0].pointer, '/nameservers/1');
  assert.equal(mapMessages([{ severity: 'error', code: 'zone.x', text: 'standard input:2: bad' }], f)[0].pointer, '/soa');
  assert.equal(createLabel(5).path, '/rrsets/3');
  // the given values
  const g = createRRsets(parseCreate({ name: 'x.test', type: 'MASTER', soa: { mname: 'ns.x.test', rname: 'h.x.test', serial: 5, refresh: 1, retry: 2, expire: 3, minimum: 4, ttl: 99 }, nameservers: ['ns.x.test'], ns_ttl: 7 }, { now: day }), 'x.test');
  assert.deepEqual(g.rrsets.map((r) => [r.ttl, r.records[0]]), [[99, 'ns.x.test. h.x.test. 5 1 2 3 4'], [7, 'ns.x.test.']]);
  assert.equal(parseCreate({ name: 'x.test', type: 'MASTER', soa: { mname: 'a', rname: 'b' }, nameservers: ['c'] }).kind, 'MASTER');
  // a zone text brings its own SOA, name servers and records
  const t = parseCreate({ name: 'new.test', zone_text: '$ORIGIN new.test.\n@ SOA a b 1 2 3 4 5\n' });
  assert.equal(t.zoneText.startsWith('$ORIGIN'), true);
  bad(() => parseCreate({ name: 'new.test', zone_text: 'x', nameservers: ['a'] }), '/nameservers');
  bad(() => parseCreate({ name: 'new.test', zone_text: 'x', soa: { mname: 'a', rname: 'b' } }), '/soa');
  bad(() => parseCreate({ name: 'new.test', zone_text: 'x', rrsets: [] }), '/rrsets');
  bad(() => parseCreate({ name: 'new.test', nameservers: ['a'] }), '/soa');
  bad(() => parseCreate({ name: 'new.test', soa: { mname: 'a', rname: 'b' } }), '/nameservers');
  bad(() => parseCreate({ name: 'new.test', soa: { mname: 'a', rname: 'b' }, nameservers: [] }), '/nameservers');
  bad(() => parseCreate({ name: 'new.test', type: 'SLAVE', soa: { mname: 'a', rname: 'b' }, nameservers: ['c'] }), '/type');
  bad(() => createRRsets(parseCreate({ name: 'n.test', soa: { mname: 'a b', rname: 'h.n.test' }, nameservers: ['c'] }), 'n.test'), '/soa/mname');
  bad(() => createRRsets(parseCreate({ name: 'n.test', soa: { mname: 'a.n.test', rname: 'h.n.test' }, nameservers: ['c;d'] }), 'n.test'), '/nameservers/0');
  bad(() => createRRsets(parseCreate({ name: 'n.test', soa: { mname: 'a.n.test', rname: 'h.n.test' }, nameservers: ['c.n.test'], rrsets: [{ name: 'x.n.test', type: 'A', changetype: 'DELETE' }] }), 'n.test'), '/rrsets/0/changetype');
  bad(() => createRRsets(parseCreate({ name: 'n.test', soa: { mname: 'a.n.test', rname: 'h.n.test' }, nameservers: ['c.n.test'], rrsets: [rr('n.test', 'NS', 1, 'x.')] }), 'n.test'), '/rrsets/0');
  bad(() => createRRsets(parseCreate({ name: 'n.test', soa: { mname: 'a.n.test', rname: 'h.n.test' }, nameservers: ['c.n.test'], rrsets: [rr('x.n.test', 'A', 1, '1.2.3.4'), rr('x.n.test', 'A', 1, '1.2.3.5')] }), 'n.test'), '/rrsets/1');
  assert.equal(rrsetLabel(3).path, '/rrsets/3');
});

// ---------------------------------------------------------------------------------------------------------------------------------- one grant for the whole change set
const policy = (over = {}) => ({ allowed_types: ['A', 'AAAA', 'TXT'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 60, ttl_max: 86400, max_rr: null, ...over });
const domain = (zone, over) => ({ id: 1, role: 'domain_master', data_schema: '', zone_name: zone, name_suffix: null, policy: policy(over) });
const subdomain = (zone, sfx, over) => ({ id: 2, role: 'subdomain_master', data_schema: '', zone_name: zone, name_suffix: sfx, policy: policy(over) });
const item = (name, type, ...ttls) => ({ name, type, ttls: ttls.length ? ttls : null });

test('chooseGrant: one grant must allow every RRset of the change set', () => {
  const dom = domain('example.test');
  const sub = subdomain('example.test', 'sub.example.test');
  const call = (grants, items, scopeAfter) => chooseGrant(grants, { schema: '', zone: 'example.test', items, scopeAfter });
  assert.equal(call([dom], [item('www.example.test', 'A', 300), item('x.example.test', 'TXT', 60)]).grant, dom);
  // a type, a TTL, the apex, a wildcard, a delegation: the first RRset no grant allows
  assert.deepEqual(call([dom], [item('www.example.test', 'A', 300), item('www.example.test', 'MX', 300)]).denied, { reason: 'rrset', index: 1 });
  assert.deepEqual(call([dom], [item('www.example.test', 'A', 59)]).denied, { reason: 'rrset', index: 0 });
  assert.deepEqual(call([dom], [item('www.example.test', 'A', 300, 86401)]).denied, { reason: 'rrset', index: 0 });
  assert.deepEqual(call([dom], [item('example.test', 'A', 300)]).denied, { reason: 'rrset', index: 0 });
  assert.deepEqual(call([dom], [item('*.example.test', 'A', 300)]).denied, { reason: 'rrset', index: 0 });
  assert.deepEqual(call([dom], [item('other.test', 'A', 300)]).denied, { reason: 'rrset', index: 0 });
  assert.deepEqual(call([dom], [item('x.example.test', 'RRSIG', 300)]).denied, { reason: 'rrset', index: 0 });
  // a DELETE (no TTLs) is tested with the lowest TTL the policy allows, so the type and the scope decide
  assert.equal(call([dom], [item('www.example.test', 'A')]).grant, dom);
  assert.deepEqual(call([dom], [item('www.example.test', 'MX')]).denied, { reason: 'rrset', index: 0 });
  // the label boundary of a subdomain master
  assert.equal(call([sub], [item('a.sub.example.test', 'A', 300), item('sub.example.test', 'TXT', 300)]).grant, sub);
  assert.deepEqual(call([sub], [item('evilsub.example.test', 'A', 300)]).denied, { reason: 'rrset', index: 0 });
  assert.deepEqual(call([sub], [item('example.test', 'TXT', 300)]).denied, { reason: 'rrset', index: 0 });
  // two grants that each cover half are not one grant
  const narrow = domain('example.test', { allowed_types: ['A'] });
  const other = domain('example.test', { allowed_types: ['TXT'] });
  const both = call([narrow, other], [item('a.example.test', 'A', 300), item('b.example.test', 'TXT', 300)]);
  assert.deepEqual(both.denied, { reason: 'no-single-grant', index: 1 });
  assert.equal(call([narrow, other], [item('a.example.test', 'A', 300)]).grant, narrow);
  // the strongest grant is tried first; a global master's grant applies to every zone
  const glob = { id: 3, role: 'global_master', data_schema: null, zone_name: null, name_suffix: null, policy: policy({ allowed_types: ['A', 'SOA', 'NS'], apex_editable: true }) };
  assert.equal(call([sub, dom, glob], [item('example.test', 'SOA', 300)]).grant, glob);
  assert.equal(call([sub, glob], [item('www.example.test', 'A', 300)]).grant, glob);
  assert.deepEqual(chooseGrant([glob], { schema: '', zone: 'example.test', items: [] }).grant, glob);
  assert.deepEqual(chooseGrant([], { schema: '', zone: 'example.test', items: [item('a.example.test', 'A', 1)] }).denied, { reason: 'rrset', index: 0 });
  assert.deepEqual(chooseGrant([], { schema: '', zone: 'example.test', items: [] }).denied, { reason: 'no-single-grant', index: 0 });
  // max_rr (A-24): the records in the scope after the change
  const capped = domain('example.test', { max_rr: 10 });
  assert.equal(call([capped], [item('a.example.test', 'A', 300)], () => 10).grant, capped);
  assert.deepEqual(call([capped], [item('a.example.test', 'A', 300)], () => 11).denied, { reason: 'max-rr', limit: 10, count: 11 });
  assert.equal(call([capped], [item('a.example.test', 'A', 300)], () => null).grant, capped);
  assert.equal(call([capped], [item('a.example.test', 'A', 300)]).grant, capped);
  // ... another grant that allows the change and has no limit is used
  assert.equal(call([capped, domain('example.test', { max_rr: null })], [item('a.example.test', 'A', 300)], (g) => (g.policy.max_rr === null ? null : 99)).grant.policy.max_rr, null);
});

// ---------------------------------------------------------------------------------------------------------------------------------- DS records
test('DNSKEY: the key tag and the DS digest (RFC 4034 section 5.4 and appendix B)', () => {
  // the example of RFC 4034 section 5.4
  const content = '256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==';
  const k = parseDnskey(content);
  assert.deepEqual([k.flags, k.protocol, k.algorithm], [256, 3, 5]);
  assert.equal(keyTag(k.rdata), 60485);
  assert.equal(dsDigest('dskey.example.com', k.rdata, 1), '2BB183AF5F22588179A53B0A98631FAD1A292118');
  assert.equal(dsDigest('DSKEY.Example.COM.', k.rdata, 1), '2BB183AF5F22588179A53B0A98631FAD1A292118', 'the owner name in lower case (RFC 4034 section 6.2)');
  assert.equal(dsDigest('dskey.example.com', k.rdata, 2).length, 64);
  assert.equal(dsDigest('dskey.example.com', k.rdata, 4).length, 96);
  assert.throws(() => dsDigest('x.test', k.rdata, 3), /no such digest type/);
  assert.deepEqual([...wireName('a.B.test.')], [1, 97, 1, 98, 4, 116, 101, 115, 116, 0]);
  assert.deepEqual([...wireName('')], [0]);
  // the base64 may be split by blanks (a zone file's way)
  assert.deepEqual(parseDnskey(content.replace('AQOeiiR0GOMYkDshWoSKz9Xz', 'AQOeiiR0GOMYkDshWoSKz9Xz ')).rdata, k.rdata);
  for (const badKey of ['', 'x', '256 3 5', '256 3 5 !!!', '99999 3 5 AAAA', '256 300 5 AAAA', '256 3 300 AAAA', '256 3 5 A', null]) assert.equal(parseDnskey(badKey), null, String(badKey));
  // the view: a key with the SEP bit gets DS records (SHA-256 and SHA-384), the others do not; a record that is no key is left out
  const v = dnskeyView('dskey.example.com', [{ ttl: 300, content: '257 3 5 ' + content.split(' ')[3] }, { ttl: 300, content }, { ttl: 1, content: 'garbage' }, { ttl: 300, content: '257 3 1 AQOeiiR0GOMYkDshWoSKz9Xz' }]);
  assert.equal(v.keys.length, 3);
  assert.deepEqual(v.keys.map((x) => [x.flags, x.sep, x.zone_key, x.key_tag === null]), [[257, true, true, false], [256, false, true, false], [257, true, true, true]]);
  assert.deepEqual(v.ds.map((x) => [x.key_tag, x.algorithm, x.digest_type, x.digest.length]), [[60486, 5, 2, 64], [60486, 5, 4, 96]]);
  assert.equal(v.ds[0].text, `60486 5 2 ${v.ds[0].digest}`);
});

// ---------------------------------------------------------------------------------------------------------------------------------- metadata
test('metadata the API writes: an allowlist, each value by the loader reader\'s rules', () => {
  assert.equal(metaKind('allow-axfr-from'), 'ALLOW-AXFR-FROM');
  for (const k of ['PRESIGNED', 'NSEC3PARAM', 'X-KARIDNS-SIGNER', 'X-KARIDNS-FORMAT', 'ENABLE-LUA-RECORDS', 'AXFR-MASTER-TSIG', 'X-KARIDNS-CACHE', 'constructor', '__proto__', '']) assert.equal(metaKind(k), null, k);
  assert.deepEqual(Object.keys(KINDS), ['ALLOW-AXFR-FROM', 'ALLOW-DNSUPDATE-FROM', 'TSIG-ALLOW-AXFR', 'TSIG-ALLOW-DNSUPDATE', 'ALSO-NOTIFY', 'X-KARIDNS-PROFILE', 'X-KARIDNS-ECS-TRUSTED-RESOLVERS']);
  const good = (kind, ...v) => assert.equal(metaProblem(kind, v), null, `${kind} ${v}`);
  const no = (kind, re, ...v) => assert.match(metaProblem(kind, v), re, `${kind} ${v}`);
  good('ALLOW-AXFR-FROM', '192.0.2.0/24', '2001:db8::/32', '198.51.100.7', '2001:db8::1');
  no('ALLOW-AXFR-FROM', /value 1/, '192.0.2.1', 'AUTO-NS');
  no('ALLOW-DNSUPDATE-FROM', /value 0/, '192.0.2.0/33');
  no('ALLOW-DNSUPDATE-FROM', /value 0/, '2001:db8::/129');
  no('ALLOW-DNSUPDATE-FROM', /value 0/, '192.0.2.0/24/1');
  no('ALLOW-DNSUPDATE-FROM', /value 0/, '192.0.2.0/x');
  good('TSIG-ALLOW-AXFR', 'transfer-key', 'k.example.test.');
  no('TSIG-ALLOW-AXFR', /value 0/, 'any');
  no('TSIG-ALLOW-AXFR', /value 0/, 'LocalHost.');
  no('TSIG-ALLOW-DNSUPDATE', /value 0/, 'a b');
  no('TSIG-ALLOW-DNSUPDATE', /value 0/, '192.0.2.1');
  good('ALSO-NOTIFY', '192.0.2.9', '192.0.2.9:5353', '[2001:db8::1]:53', '2001:db8::2');
  no('ALSO-NOTIFY', /value 0/, '192.0.2.9:0');
  no('ALSO-NOTIFY', /value 0/, '192.0.2.9:99999');
  no('ALSO-NOTIFY', /value 0/, '[192.0.2.9]:53');
  no('ALSO-NOTIFY', /value 0/, 'ns.example.test');
  good('X-KARIDNS-PROFILE', 'secondary-1');
  no('X-KARIDNS-PROFILE', /takes one value/, 'a', 'b');
  no('X-KARIDNS-PROFILE', /value 0/, 'a b');
  good('X-KARIDNS-ECS-TRUSTED-RESOLVERS', '192.0.2.0/24, !192.0.2.7 2001:db8::/32');
  no('X-KARIDNS-ECS-TRUSTED-RESOLVERS', /value 0/, '192.0.2.0/24, nonsense');
  no('X-KARIDNS-ECS-TRUSTED-RESOLVERS', /value 0/, ',');
  assert.match(metaProblem('ALLOW-AXFR-FROM', Array(MAX_ROWS + 1).fill('192.0.2.1')), /at most/);
  assert.equal(metaProblem('ALLOW-AXFR-FROM', []), null);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the pool and the lock
test('the pool: at most `limit` jobs run, `queue` wait, the rest are refused', async () => {
  const pool = new Pool({ limit: 2, queue: 2 });
  let running = 0;
  let peak = 0;
  const gates = [];
  const job = () => pool.run(async () => {
    running++;
    peak = Math.max(peak, running);
    await new Promise((resolve) => { gates.push(resolve); });
    running--;
    return 'done';
  });
  const jobs = [job(), job(), job(), job()];
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(running, 2);
  await assert.rejects(job(), (e) => e.status === 503 && e.code === 'busy' && e.headers['Retry-After'] === '2');
  while (gates.length) {
    gates.shift()();
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.deepEqual(await Promise.all(jobs), ['done', 'done', 'done', 'done']);
  assert.equal(peak, 2);
  assert.equal(pool.active, 0);
  // a job that throws gives its slot back
  await assert.rejects(pool.run(async () => { throw new Error('x'); }), /x/);
  assert.equal(pool.active, 0);
  assert.equal(await pool.run(async () => 7), 7);
});

test('the zone lock: one holder per key, in order; a long queue is refused', async () => {
  const lock = new KeyedLock({ waiters: 2 });
  const order = [];
  const take = async (key, tag, hold) => {
    const release = await lock.acquire(key);
    order.push(`${tag}+`);
    await new Promise((resolve) => setTimeout(resolve, hold));
    order.push(`${tag}-`);
    release();
  };
  await Promise.all([take('z', 'a', 20), take('z', 'b', 5), take('y', 'c', 5), take('z', 'd', 1)]);
  assert.deepEqual(order.filter((x) => x[0] !== 'c'), ['a+', 'a-', 'b+', 'b-', 'd+', 'd-']);
  assert.ok(order.indexOf('c+') < order.indexOf('a-'), 'another key does not wait');
  assert.equal(lock.tails.size, 0);
  assert.equal(lock.counts.size, 0);
  const held = await lock.acquire('k');
  const waiting = [lock.acquire('k'), lock.acquire('k')];
  await assert.rejects(lock.acquire('k'), (e) => e.status === 503);
  held();
  for (const w of waiting) (await w)();
  assert.equal(lock.counts.size, 0);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the arguments of the tools
test('the arguments of karidns-zone: the check run as the check role, the commit run as the API role', () => {
  const pg = { database: 'pg', 'api-conninfo-file': '/etc/api.ci', 'check-conninfo-file': '/etc/check.ci', 'sqlite-file': undefined, 'karictl-config': '/etc/ctl.conf' };
  const lite = { database: 'sqlite3', 'sqlite-file': '/var/db/z.sqlite3' };
  const ds = { name: 'main', schema: 'public' };
  assert.deepEqual(dbArgs(pg, ds), ['--no-config', '--conninfo-file', '/etc/check.ci', '--schema', 'public']);
  assert.deepEqual(dbArgs(pg, ds, 'api'), ['--no-config', '--conninfo-file', '/etc/api.ci', '--schema', 'public']);
  assert.deepEqual(dbArgs(lite, ds, 'api'), ['--no-config', '--sqlite3', '/var/db/z.sqlite3']);
  assert.deepEqual(checkArgv(pg, ds, { zone: 'Example.TEST', text: false }), ['apply', '--dry-run', '--json', '--no-config', '--conninfo-file', '/etc/check.ci', '--schema', 'public', '--changes', '-', 'example.test']);
  assert.deepEqual(checkArgv(lite, ds, { zone: 'example.test', text: true, deleteOthers: true }).slice(3), ['--no-config', '--sqlite3', '/var/db/z.sqlite3', '--zone-file', '-', '--delete-others', 'example.test']);
  assert.deepEqual(checkArgv(lite, ds, { zone: 'new.test', text: false, create: true, zoneType: 'MASTER' }).slice(-5), ['-', '--create', '--type', 'MASTER', 'new.test']);
  assert.ok(!checkArgv(lite, ds, { zone: 'new.test', text: true, deleteOthers: true, create: true, zoneType: 'NATIVE' }).includes('--delete-others'));
  const spec = { zone: 'example.test', text: false, generation: 7, principal: { id: 12, name: 'dom' }, changeSet: 'cs-1', kind: 'edit', comment: 'move www', reload: true };
  assert.deepEqual(commitArgv(pg, ds, spec), ['apply', '--json', '--no-config', '--conninfo-file', '/etc/api.ci', '--schema', 'public', '--changes', '-', '--expect-generation', '7', '--readback', 'changed',
    '--version-kind', 'edit', '--principal', '12', '--principal-name', 'dom', '--change-set', 'cs-1', '--comment', 'move www', '--reload', 'example.test']);
  assert.ok(!commitArgv(lite, ds, spec).includes('--reload'), 'SQLite3 has no reload requests');
  assert.ok(!commitArgv(pg, ds, { ...spec, reload: false, comment: '' }).includes('--comment'));
  assert.ok(commitArgv(lite, ds, { ...spec, kind: 'rollback', rollbackOf: 3 }).join(' ').includes('--expect-generation 7 --readback changed --version-kind rollback'));
  assert.ok(commitArgv(lite, ds, { ...spec, kind: 'rollback', rollbackOf: 3 }).join(' ').includes('--rollback-of 3'));
  const created = commitArgv(lite, ds, { zone: 'new.test', text: false, create: true, zoneType: 'NATIVE', principal: { id: 1, name: 'root' }, changeSet: 'cs-2' });
  assert.ok(created.includes('--create') && created.includes('--readback') && !created.includes('--expect-generation') && !created.includes('--version-kind'));
  assert.deepEqual(reloadArgv({ 'karictl-config': '/etc/ctl.conf' }, 'Example.Test'), ['-f', '/etc/ctl.conf', 'reload', 'example.test']);
  assert.deepEqual(reloadArgv({ 'karictl-config': '/etc/ctl.conf' }, 'example.test', 'v1'), ['-f', '/etc/ctl.conf', 'reload', 'example.test', 'v1']);
});

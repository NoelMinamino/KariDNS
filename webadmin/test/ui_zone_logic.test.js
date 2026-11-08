// The logic of the zone screens that needs no DOM (planning 8.1): names relative to a zone, the lines of a records box, the reasons an RRset is not edited, the draft
// change set and its request, the pointers of the service's errors, the diff in pages.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  relName, absName, recordLines, recordsText, parseRecordLine, rdataOf, expectOf, policyReason, editReason, zoneEditable, ttlRange, addableTypes, remaining, zonePath, datasetPath,
  DNSSEC_TYPES,
} from '../ui/js/zonelib.js';
import { createDrafts, replaceEntry, addEntry, deleteEntry, soaEntry, entryKey, rrsetOf } from '../ui/js/draft.js';
import { segments, entryOf, placeOnEntries, placeOnFields } from '../ui/js/pointer.js';
import { diffCounts, diffPage, lineText, DIFF_PAGE } from '../ui/js/diffmodel.js';
import { rrsetsFromLines } from '../ui/js/views/zonecreate.js';
import { POLICY } from './ui_boot.js';

test('paths: every part is encoded', () => {
  assert.equal(zonePath('main', 'example.test.'), '/datasets/main/zones/example.test.');
  assert.equal(zonePath('a b', 'x/y?z.'), '/datasets/a%20b/zones/x%2Fy%3Fz.');
  assert.equal(datasetPath('m#1'), '/datasets/m%231');
});

test('relName: the apex is @, a name inside is relative, a name outside is left alone', () => {
  assert.equal(relName('example.test.', 'example.test.'), '@');
  assert.equal(relName('www.example.test.', 'example.test.'), 'www');
  assert.equal(relName('A.B.Example.Test.', 'example.test.'), 'A.B');
  assert.equal(relName('www.other.test.', 'example.test.'), 'www.other.test.');
  assert.equal(relName('xexample.test.', 'example.test.'), 'xexample.test.');
});

test('absName: @, relative, absolute, the zone written out, a U-label, nonsense', () => {
  const z = 'example.test.';
  assert.equal(absName('', z), null);
  assert.equal(absName('   ', z), null);
  assert.equal(absName('@', z), 'example.test.');
  assert.equal(absName('WWW', z), 'www.example.test.');
  assert.equal(absName('a.b', z), 'a.b.example.test.');
  assert.equal(absName('www.example.test', z), 'www.example.test.');
  assert.equal(absName('example.test', z), 'example.test.');
  assert.equal(absName('www.example.test.', z), 'www.example.test.');
  assert.equal(absName('www.other.test.', z), 'www.other.test.');
  assert.equal(absName('*.wild', z), '*.wild.example.test.');
  assert.equal(absName('bücher', z), 'xn--bcher-kva.example.test.');
  assert.equal(absName('a bé', z), null, 'a space makes no host name');
  assert.equal(absName('é', z), 'xn--9ca.example.test.');
});

test('the lines of a records box and of the "more records" box', () => {
  assert.deepEqual(recordLines('  a  \r\n\n b\n  \nc'), ['a', 'b', 'c']);
  assert.deepEqual(recordLines(undefined), []);
  assert.equal(recordsText(['a', 'b']), 'a\nb');
  assert.deepEqual(parseRecordLine('www 300 a 192.0.2.1'), { owner: 'www', ttl: 300, type: 'A', content: '192.0.2.1' });
  assert.deepEqual(parseRecordLine('@ MX 10 mail'), { owner: '@', ttl: undefined, type: 'MX', content: '10 mail' });
  assert.deepEqual(parseRecordLine('t TXT "a b"  "c"'), { owner: 't', ttl: undefined, type: 'TXT', content: '"a b"  "c"' });
  assert.equal(parseRecordLine('only'), null);
  assert.equal(parseRecordLine('www A'), null);
  const r = rrsetsFromLines('www 60 A 192.0.2.1\nwww A 192.0.2.2\n@ NS ns1.example.test.', 'example.test.');
  assert.deepEqual(r.rrsets, [
    { name: 'www.example.test.', type: 'A', changetype: 'REPLACE', ttl: 60, records: [{ content: '192.0.2.1' }, { content: '192.0.2.2' }] },
    { name: 'example.test.', type: 'NS', changetype: 'REPLACE', ttl: 3600, records: [{ content: 'ns1.example.test.' }] },
  ]);
  assert.deepEqual(rrsetsFromLines('www A 192.0.2.1\nnonsense', 'example.test.'), { error: 'line', line: 2 });
  assert.deepEqual(rrsetsFromLines('', 'example.test.'), { rrsets: [] });
});

const rr = (over = {}) => ({ name: 'www.example.test.', type: 'A', ttl: 300, tagged: false, records: [{ content: '192.0.2.1', rdata: '192.0.2.1', disabled: false, ttl: 300 }], ...over });
const zone = (over = {}) => ({ name: 'example.test.', kind: 'NATIVE', presigned: false, signer: false, role: 'domain_master', grants: [{ role: 'domain_master', suffix: null, policy: POLICY }], ...over });

test('rdataOf and expectOf: the text a change set takes, with the TTL each record has', () => {
  assert.equal(rdataOf({ content: '10 mail', rdata: '10 mail.example.test.' }), '10 mail.example.test.');
  assert.equal(rdataOf({ content: 'stored', rdata: null }), 'stored');
  assert.deepEqual(expectOf(rr({ records: [{ content: 'x', rdata: 'y', ttl: 60 }, { content: 'z', rdata: 'z', ttl: null }] })), [{ ttl: 60, content: 'y' }, { ttl: 300, content: 'z' }]);
  assert.deepEqual(expectOf({ ttl: null, records: [{ content: 'a', rdata: 'a' }] }), [{ ttl: 0, content: 'a' }]);
});

test('why an RRset is shown but not edited (planning 3 S4)', () => {
  const types = ['A', 'TXT', 'SOA', 'NS'];
  assert.equal(editReason(rr(), zone(), types), null);
  assert.equal(editReason(rr(), zone({ kind: 'SLAVE' }), types), 'zone-kind');
  assert.equal(editReason(rr(), zone({ kind: 'native' }), types), null, 'the kind is read in any case');
  assert.equal(editReason(rr(), zone({ presigned: true }), types), 'presigned');
  assert.equal(editReason(rr(), zone({ presigned: true, signer: true }), types), null, 'a zone the signer keeps is edited');
  assert.equal(editReason(rr({ type: 'rrsig' }), zone(), types), 'dnssec');
  assert.equal(editReason(rr({ tagged: true }), zone(), types), 'tagged');
  assert.equal(editReason(rr({ type: 'SOA' }), zone(), types), 'soa');
  assert.equal(editReason(rr({ records: [{ content: 'x', rdata: null }] }), zone(), types), 'no-text');
  assert.equal(editReason(rr({ records: [{ content: 'x', rdata: 'x', disabled: true }] }), zone(), types), 'disabled');
  assert.equal(editReason(rr({ type: 'HINFO' }), zone(), types), 'unknown-type');
  assert.equal(editReason(rr({ type: 'TYPE65280' }), zone(), null), 'type', 'a generic type the policy does not list');
  assert.equal(editReason(rr({ type: 'HINFO' }), zone(), null), 'type', 'the types are not known: the policy decides');
  assert.equal(editReason(rr({ type: 'A' }), zone(), null), null);
  assert.ok(DNSSEC_TYPES.has('DNSKEY') && !DNSSEC_TYPES.has('DS'));
});

test('policyReason: the rules of the policy as a hint, with the first reason that fits', () => {
  const sub = { role: 'subdomain_master', suffix: 'sub.example.test.', policy: { ...POLICY, apex_editable: true } };
  const z = 'example.test.';
  assert.equal(policyReason([sub], z, 'a.sub.example.test.', 'A', 300), null);
  assert.equal(policyReason([sub], z, 'sub.example.test.', 'A', 300), null);
  assert.equal(policyReason([sub], z, 'evilsub.example.test.', 'A', 300), 'scope');
  assert.equal(policyReason([sub], z, 'example.test.', 'NS', 300), 'scope');
  const dom = { role: 'domain_master', suffix: null, policy: { ...POLICY, apex_editable: false, allow_wildcard: false, allow_delegation: false, allow_dname: false, ttl_min: 60, ttl_max: 3600 } };
  assert.equal(policyReason([dom], z, 'example.test.', 'MX', 300), 'apex');
  assert.equal(policyReason([dom], z, 'x.example.test.', 'HINFO', 300), 'type');
  assert.equal(policyReason([dom], z, '*.example.test.', 'A', 300), 'policy', 'a wildcard');
  assert.equal(policyReason([dom], z, 'x.example.test.', 'A', 30), 'policy', 'a TTL below the range');
  assert.equal(policyReason([dom], z, 'x.example.test.', 'A', 4000), 'policy', 'a TTL above the range');
  assert.equal(policyReason([dom], z, 'sub.example.test.', 'NS', 300), 'policy', 'a delegation');
  assert.equal(policyReason([{ ...dom, policy: { ...dom.policy, allowed_types: ['DNAME'] } }], z, 'x.example.test.', 'DNAME', 300), 'policy', 'a DNAME');
  assert.equal(policyReason([{ role: 'domain_master', policy: { ...POLICY, apex_editable: true } }], z, 'example.test.', 'SOA', 300), 'policy', 'the SOA is for a global master');
  assert.equal(policyReason([{ role: 'global_master', policy: POLICY }], z, 'example.test.', 'SOA', 300), null);
  assert.equal(policyReason([], z, 'x.example.test.', 'A', 300), null, 'no grants known: no hint');
  assert.equal(policyReason(undefined, z, 'x.example.test.', 'A', 300), null);
  assert.equal(policyReason([{ role: 'domain_master' }], z, 'x.example.test.', 'A', 300), null, 'a grant without a policy: no hint');
});

test('zoneEditable, ttlRange, addableTypes', () => {
  assert.equal(zoneEditable({ kind: 'MASTER' }), null);
  assert.equal(zoneEditable({ kind: 'CONSUMER' }), 'zone-kind');
  assert.equal(zoneEditable({ kind: 'NATIVE', presigned: true, signer: false }), 'presigned');
  assert.deepEqual(ttlRange([{ policy: POLICY }]), [0, 2147483647]);
  assert.equal(ttlRange([{ role: 'x' }]), null);
  assert.equal(ttlRange(undefined), null);
  assert.deepEqual(addableTypes(['A', 'SOA', 'RRSIG', 'MX', 'TXT'], [{ policy: { allowed_types: ['A', 'TXT', 'SOA'] } }]), ['A', 'TXT']);
  assert.deepEqual(addableTypes(['A', 'MX'], [{ role: 'x' }]), ['A', 'MX'], 'no policy known: the service\'s list');
  assert.deepEqual(addableTypes(null, []), []);
});

test('remaining: days, hours, minutes, seconds; past and future; a bad time', () => {
  const now = Date.parse('2026-11-09T00:00:00Z');
  assert.deepEqual(remaining('2026-11-12T04:00:00Z', now), { sec: 3 * 86400 + 4 * 3600, past: false, text: '3 d 4 h' });
  assert.equal(remaining('2026-11-09T02:05:00Z', now).text, '2 h 5 min');
  assert.equal(remaining('2026-11-09T00:03:10Z', now).text, '3 min 10 s');
  assert.equal(remaining('2026-11-09T00:00:40Z', now).text, '40 s');
  const past = remaining('2026-11-08T22:00:00Z', now);
  assert.equal(past.past, true);
  assert.equal(past.text, '2 h 0 min');
  assert.equal(remaining('nonsense', now), null);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the draft
test('a draft: entries replace the one of the same RRset in place, undo, clear, rebase, listeners', () => {
  const drafts = createDrafts();
  const d = drafts.of('main', 'Example.Test.');
  assert.equal(drafts.of('main', 'example.test.'), d, 'the zone name is read in any case');
  assert.equal(drafts.dirty(), false);
  let n = 0;
  const on = () => n++;
  d.onChange(on);
  const loaded = rr({ records: [{ content: '192.0.2.1', rdata: '192.0.2.1', ttl: 300 }] });
  const e1 = replaceEntry(loaded, 60, ['192.0.2.9'], expectOf(loaded));
  const e2 = addEntry('new.example.test.', 'TXT', 300, ['"x"']);
  const e3 = deleteEntry(rr({ name: 'old.example.test.', type: 'MX' }), [{ ttl: 300, content: '10 m.example.test.' }]);
  d.put(e1); d.put(e2); d.put(e3);
  assert.equal(d.size, 3);
  assert.equal(drafts.count(), 3);
  assert.equal(drafts.dirty(), true);
  assert.equal(d.find('www.example.test.', 'A'), e1);
  assert.equal(d.find('nope.example.test.', 'A'), undefined);
  assert.equal(entryKey(e1), 'www.example.test. A');
  // the same RRset again: the place in the request stays
  const e1b = replaceEntry(loaded, 120, ['192.0.2.8'], expectOf(loaded));
  d.put(e1b);
  assert.deepEqual(d.entries.map((e) => e.id), [e1b.id, e2.id, e3.id]);
  assert.equal(n, 4);
  d.remove('nonexistent');
  assert.equal(n, 4, 'removing what is not there is nothing');
  d.remove(e2.id);
  assert.deepEqual(d.entries.map((e) => e.id), [e1b.id, e3.id]);
  assert.equal(d.revision, 5);
  d.offChange(on);
  d.offChange(on);
  d.clear();
  d.clear();
  assert.equal(d.size, 0);
  assert.equal(n, 5, 'one listener call for the removal, none after offChange');
  assert.equal(drafts.dirty(), false);
  d.put(e1);
  drafts.clear();
  assert.equal(d.size, 0);
});

test('the request of a draft: REPLACE with expect, DELETE with expect, an addition that must not exist, the SOA without a precondition', () => {
  const d = createDrafts().of('main', 'example.test.');
  const loaded = rr({ records: [{ content: '192.0.2.1', rdata: '192.0.2.1', ttl: 300 }, { content: '192.0.2.2', rdata: '192.0.2.2', ttl: 300 }] });
  const soa = rr({ name: 'example.test.', type: 'SOA', ttl: 3600, records: [{ content: 'ns hm 1 2 3 4 5', rdata: 'ns. hm. 1 2 3 4 5', ttl: 3600 }] });
  const e1 = replaceEntry(loaded, 60, ['192.0.2.9'], expectOf(loaded));
  const e2 = addEntry('new.example.test.', 'TXT', 300, ['"x"']);
  const e3 = deleteEntry(rr({ name: 'old.example.test.', type: 'MX' }), [{ ttl: 300, content: '10 m.example.test.' }]);
  const e4 = soaEntry(soa, ['ns. hm. 2 2 3 4 5']);
  for (const e of [e1, e2, e3, e4]) d.put(e);
  const { body, order } = d.request({ comment: '  move www  ', reload: true, dryRun: true });
  assert.deepEqual(order, [e1.id, e2.id, e3.id, e4.id]);
  assert.deepEqual(body, {
    rrsets: [
      { name: 'www.example.test.', type: 'A', changetype: 'REPLACE', ttl: 60, records: [{ content: '192.0.2.9' }], expect: [{ ttl: 300, content: '192.0.2.1' }, { ttl: 300, content: '192.0.2.2' }] },
      { name: 'new.example.test.', type: 'TXT', changetype: 'REPLACE', ttl: 300, records: [{ content: '"x"' }], expect: [] },
      { name: 'old.example.test.', type: 'MX', changetype: 'DELETE', expect: [{ ttl: 300, content: '10 m.example.test.' }] },
      { name: 'example.test.', type: 'SOA', changetype: 'REPLACE', ttl: 3600, records: [{ content: 'ns. hm. 2 2 3 4 5' }] },
    ],
    comment: 'move www', reload: true, dry_run: true,
  });
  assert.equal('expect' in body.rrsets[3], false, 'the SOA has no expect');
  assert.deepEqual(e4.before, [{ ttl: 3600, content: 'ns. hm. 1 2 3 4 5' }], 'the SOA shows the text form it was loaded in');
  const plainReq = d.request({ comment: '   ', dryRun: false });
  assert.equal('comment' in plainReq.body, false);
  assert.equal('reload' in plainReq.body, false);
  assert.equal('dry_run' in plainReq.body, false);
  assert.equal(d.request({ reload: false }).body.reload, false);
  assert.deepEqual(rrsetOf(e3).changetype, 'DELETE');
});

test('rebase: "keep mine" makes the present state the precondition; an addition that has appeared becomes a replacement, a replacement of a vanished RRset an addition', () => {
  const d = createDrafts().of('main', 'example.test.');
  const loaded = rr();
  const e1 = replaceEntry(loaded, 60, ['192.0.2.9'], expectOf(loaded));
  const e2 = addEntry('new.example.test.', 'TXT', 300, ['"x"']);
  const e3 = soaEntry(rr({ name: 'example.test.', type: 'SOA', records: [{ content: 'a', rdata: 'a', ttl: 1 }] }), ['b']);
  d.put(e1); d.put(e2); d.put(e3);
  d.rebase(e1.id, null);
  assert.equal(d.find('www.example.test.', 'A').op, 'add');
  assert.deepEqual(d.find('www.example.test.', 'A').expect, []);
  d.rebase(e2.id, [{ ttl: 5, content: '"theirs"', extra: 'x' }]);
  assert.equal(d.find('new.example.test.', 'TXT').op, 'replace');
  assert.deepEqual(d.find('new.example.test.', 'TXT').expect, [{ ttl: 5, content: '"theirs"' }]);
  assert.deepEqual(d.find('new.example.test.', 'TXT').before, [{ ttl: 5, content: '"theirs"' }]);
  d.rebase(e3.id, [{ ttl: 1, content: 'a' }]);
  assert.equal(d.find('example.test.', 'SOA').expect, null, 'the SOA keeps no precondition');
  d.rebase('nonexistent', undefined);
  assert.equal(d.size, 3);
  d.rebase(e2.id, undefined);
  assert.equal(d.find('new.example.test.', 'TXT').op, 'add');
});

// ---------------------------------------------------------------------------------------------------------------------------------- pointers
test('pointers: segments, the entry of a draft, errors placed on entries and on fields', () => {
  assert.deepEqual(segments('/rrsets/3/records/0'), ['rrsets', '3', 'records', '0']);
  assert.deepEqual(segments('/a~1b/c~0d'), ['a/b', 'c~d']);
  assert.deepEqual(segments(''), []);
  assert.equal(segments(undefined), null);
  assert.equal(segments('rrsets'), null);
  assert.deepEqual(entryOf('/rrsets/2/records/1'), { index: 2, record: 1 });
  assert.deepEqual(entryOf('/rrsets/2/expect'), { index: 2, record: null });
  assert.deepEqual(entryOf('/rrsets/2'), { index: 2, record: null });
  assert.equal(entryOf('/rrsets/x'), null);
  assert.equal(entryOf('/soa/mname'), null);
  assert.equal(entryOf(undefined), null);

  const errors = [
    { code: 'a', text: 'one', pointer: '/rrsets/1/records/0' }, { code: 'b', text: 'two', pointer: '/rrsets/0' }, { code: 'c', text: 'three' }, { code: 'd', text: 'four', pointer: '/rrsets/9' },
    { code: 'e', text: 'five', pointer: '/rrsets/1/ttl' },
  ];
  const placed = placeOnEntries(errors, ['id-a', 'id-b']);
  assert.deepEqual([...placed.byEntry.keys()], ['id-b', 'id-a']);
  assert.deepEqual(placed.byEntry.get('id-b'), [{ code: 'a', text: 'one', pointer: '/rrsets/1/records/0', record: 0 }, { code: 'e', text: 'five', pointer: '/rrsets/1/ttl', record: null }]);
  assert.deepEqual(placed.loose.map((e) => e.code), ['c', 'd']);
  assert.deepEqual(placeOnEntries(undefined, []), { byEntry: new Map(), loose: [] });

  const got = {};
  const field = (k) => ({ setError: (t) => { got[k] = t; } });
  const loose = placeOnFields([
    { text: 'bad name', pointer: '/name' }, { text: 'x‮y', pointer: '/soa/mname' }, { text: 'ns 2', pointer: '/nameservers/2' }, { text: 'ns 0', pointer: '/nameservers/0' },
    { text: 'soa other', pointer: '/soa/refresh' }, { text: 'no pointer' }, { text: 'prefix only', pointer: '/namex' },
  ], { '/name': field('name'), '/soa/mname': field('mname'), '/soa': field('soa'), '/nameservers': field('ns') });
  assert.deepEqual(got, { name: 'bad name', mname: 'x<U+202E>y', ns: 'ns 2 ns 0', soa: 'soa other' });
  assert.deepEqual(loose.map((e) => e.text), ['no pointer', 'prefix only']);
  assert.deepEqual(placeOnFields(undefined, {}), []);
});

test('the diff: counts, pages of 200 (clamped), the text of a line', () => {
  const diff = Array.from({ length: 450 }, (_, i) => ({ name: `n${i}.`, type: 'A', change: ['add', 'replace', 'delete'][i % 3], before: null, after: null }));
  assert.deepEqual(diffCounts(diff), { add: 150, replace: 150, delete: 150 });
  assert.deepEqual(diffCounts([{ change: 'weird' }]), { add: 0, replace: 0, delete: 0 });
  assert.equal(DIFF_PAGE, 200);
  const p0 = diffPage(diff, 0);
  assert.deepEqual([p0.items.length, p0.page, p0.pages, p0.from, p0.to, p0.total], [200, 0, 3, 1, 200, 450]);
  const p2 = diffPage(diff, 2);
  assert.deepEqual([p2.items.length, p2.from, p2.to], [50, 401, 450]);
  assert.equal(diffPage(diff, 99).page, 2);
  assert.equal(diffPage(diff, -5).page, 0);
  assert.deepEqual(diffPage([], 0), { items: [], page: 0, pages: 1, from: 0, to: 0, total: 0 });
  assert.equal(diffPage(diff, 1, 100).items[0].name, 'n100.');
  assert.equal(lineText({ ttl: 300, content: '192.0.2.1' }), '300 192.0.2.1');
  assert.equal(lineText({ content: 'x' }), '? x');
});

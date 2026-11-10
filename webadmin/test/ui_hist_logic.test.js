// The logic of the history, template, administration and audit screens that needs no DOM (planning 8.1): the compare form, the markers of changes outside the versions, the
// conflicts of a rollback, the text form of a template, a record policy from its form, the lookup of a principal, the filters of the audit log.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  versionsPath, versionPath, isVersionNo, parseCompare, outsideOf, conflictsOf, templateLine, templateText, parseTemplateText, soaOf, withLineNumbers, SOA_FIELDS,
} from '../ui/js/histlib.js';
import {
  parseTypes, policyBody, policyWithin, lookupPrincipal, principalLabel, whenText, auditQuery, datasetOfRow, jsonLines, JSON_SHOWN,
} from '../ui/js/adminlib.js';
import { POLICY } from './ui_boot.js';

test('paths and version numbers', () => {
  assert.equal(versionsPath('main', 'example.test.'), '/datasets/main/zones/example.test./versions');
  assert.equal(versionPath('a b', 'x/y.', 7), '/datasets/a%20b/zones/x%2Fy./versions/7');
  for (const ok of ['1', '12', '999999999', ' 5 ']) assert.ok(isVersionNo(ok), ok);
  for (const bad of ['0', '01', '-1', '1e3', '1.5', '', 'current', '1234567890', undefined, null]) assert.ok(!isVersionNo(bad), String(bad));
});

test('the compare form: a number, a later number or the zone as it is', () => {
  assert.deepEqual(parseCompare('3', ''), { from: 3, to: 'current' });
  assert.deepEqual(parseCompare(' 3 ', ' CURRENT '), { from: 3, to: 'current' });
  assert.deepEqual(parseCompare('3', undefined), { from: 3, to: 'current' });
  assert.deepEqual(parseCompare('3', '5'), { from: 3, to: 5 });
  assert.deepEqual(parseCompare('x', '5'), { error: 'from' });
  assert.deepEqual(parseCompare('', ''), { error: 'from' });
  assert.deepEqual(parseCompare('3', 'x'), { error: 'to' });
  assert.deepEqual(parseCompare('3', '3'), { error: 'order' });
  assert.deepEqual(parseCompare('3', '2'), { error: 'order' });
});

test('the marker "changed outside the versions": the audit basis, the generation basis, nothing, and rubbish', () => {
  assert.equal(outsideOf(null), null);
  assert.equal(outsideOf(undefined), null);
  assert.equal(outsideOf('x'), null);
  assert.deepEqual(outsideOf({ basis: 'audit', count: 2, rrsets: [{ name: 'www.example.test.', type: 'A' }, { name: 5, type: 'A' }, null] }), { basis: 'audit', count: 2, rrsets: [{ name: 'www.example.test.', type: 'A' }] });
  assert.deepEqual(outsideOf({ basis: 'generation', count: null, rrsets: [] }), { basis: 'generation', count: null, rrsets: [] });
  assert.deepEqual(outsideOf({ basis: '<b>', count: 'x' }), { basis: 'generation', count: null, rrsets: [] });
});

test('the conflicts of a rollback: only the version-conflict errors with a name and type; lines that are not records are dropped', () => {
  const list = [
    { code: 'version-conflict', name: 'www.example.test.', type: 'A', expected: [{ ttl: 300, content: '192.0.2.1' }, 5, { ttl: 1 }], current: [{ ttl: 60, content: '192.0.2.2' }] },
    { code: 'version-conflict', name: 'gone.example.test.', type: 'TXT', expected: [{ ttl: 300, content: '"a"' }], current: null },
    { code: 'version-conflict', name: 'odd.example.test.', type: 'TXT' },
    { code: 'other', name: 'x.', type: 'A' },
    { code: 'version-conflict', type: 'A' },
    null,
  ];
  assert.deepEqual(conflictsOf(list), [
    { name: 'www.example.test.', type: 'A', expected: [{ ttl: 300, content: '192.0.2.1' }], current: [{ ttl: 60, content: '192.0.2.2' }] },
    { name: 'gone.example.test.', type: 'TXT', expected: [{ ttl: 300, content: '"a"' }], current: null },
    { name: 'odd.example.test.', type: 'TXT', expected: [], current: null },
  ]);
  assert.deepEqual(conflictsOf(undefined), []);
});

test('a template as text: one record a line, the TTL optional, comments and blank lines nothing, bad lines named', () => {
  assert.equal(templateLine({ owner: 'www', type: 'A', ttl: 600, content: '192.0.2.41' }), 'www 600 A 192.0.2.41');
  assert.equal(templateLine({ owner: '@', type: 'MX', ttl: null, content: '10 mail' }), '@ MX 10 mail');
  assert.equal(templateLine({ owner: '@', type: 'NS', content: 'ns1.example.test.' }), '@ NS ns1.example.test.');
  assert.equal(templateText([{ owner: '@', type: 'NS', ttl: null, content: 'ns1.' }, { owner: 'www', type: 'A', ttl: 600, content: '192.0.2.41' }]), '@ NS ns1.\nwww 600 A 192.0.2.41');
  assert.equal(templateText(undefined), '');
  const p = parseTemplateText('; a comment\n@ NS ns1.example.test.\n\nwww 600 a 192.0.2.41\nnonsense\n  \r\n@ MX 10 mail\nwww A');
  assert.deepEqual(p.records, [
    { owner: '@', type: 'NS', content: 'ns1.example.test.' },
    { owner: 'www', type: 'A', content: '192.0.2.41', ttl: 600 },
    { owner: '@', type: 'MX', content: '10 mail' },
  ]);
  assert.deepEqual(p.lines, [2, 4, 7]);
  assert.deepEqual(p.bad, [5, 8]);
  assert.deepEqual(parseTemplateText(undefined), { records: [], lines: [], bad: [] });
});

test('the SOA defaults of a template: numbers checked, empty = none', () => {
  assert.deepEqual(SOA_FIELDS, ['mname', 'rname', 'refresh', 'retry', 'expire', 'minimum']);
  assert.deepEqual(soaOf({}), { soa: null });
  assert.deepEqual(soaOf({ mname: ' ', refresh: '' }), { soa: null });
  assert.deepEqual(soaOf({ mname: 'ns1.example.test', rname: 'hm.example.test', refresh: '1800', minimum: '0' }), { soa: { mname: 'ns1.example.test', rname: 'hm.example.test', refresh: 1800, minimum: 0 } });
  assert.deepEqual(soaOf({ refresh: '12x' }), { error: 'refresh' });
  assert.deepEqual(soaOf({ retry: '2147483648' }), { error: 'retry' });
  assert.deepEqual(soaOf({ mname: 'ns', expire: '-1' }), { error: 'expire' });
});

test('the line of a record in the text box is put in front of the message about it', () => {
  const errs = [{ pointer: '/records/1/content', text: 'bad' }, { pointer: '/records/9', text: 'far' }, { pointer: '/name', text: 'n' }, { text: 'none' }, { pointer: '/recordsX', text: 'x' }];
  const out = withLineNumbers(errs, [2, 5], (n) => `L${n}: `);
  assert.deepEqual(out.map((e) => e.text), ['L5: bad', 'far', 'n', 'none', 'x']);
  assert.deepEqual(withLineNumbers(undefined, [], () => ''), []);
});

// ---------------------------------------------------------------------------------------------------------------------------------- administration
test('types: upper case, once each, in the order typed', () => {
  assert.deepEqual(parseTypes('a, aaaa  mx,,A\ntxt'), ['A', 'AAAA', 'MX', 'TXT']);
  assert.deepEqual(parseTypes(''), []);
  assert.deepEqual(parseTypes(undefined), []);
});

test('a policy from its form: what is sent, and the first field that cannot be', () => {
  const base = { name: ' web ', types: 'a txt', wildcard: true, delegation: false, dname: false, apex: true, ttl_min: '60', ttl_max: '86400', max_rr: '' };
  assert.deepEqual(policyBody(base), { body: { name: 'web', allowed_types: ['A', 'TXT'], allow_wildcard: true, allow_delegation: false, allow_dname: false, apex_editable: true, ttl_min: 60, ttl_max: 86400, max_rr: null } });
  assert.deepEqual(policyBody({ ...base, ttl_min: '', ttl_max: '', max_rr: '100' }).body, { name: 'web', allowed_types: ['A', 'TXT'], allow_wildcard: true, allow_delegation: false, allow_dname: false, apex_editable: true, max_rr: 100 });
  assert.deepEqual(policyBody({ ...base, name: ' ' }), { error: 'name' });
  assert.deepEqual(policyBody({ ...base, types: ' , ' }), { error: 'types' });
  assert.deepEqual(policyBody({ ...base, ttl_min: 'x' }), { error: 'ttl_min' });
  assert.deepEqual(policyBody({ ...base, ttl_max: '2147483648' }), { error: 'ttl_max' });
  assert.deepEqual(policyBody({ ...base, ttl_min: '100', ttl_max: '50' }), { error: 'ttl_min' });
  assert.deepEqual(policyBody({ ...base, ttl_min: '100', ttl_max: '' }).body.ttl_min, 100);
  assert.deepEqual(policyBody({ ...base, ttl_max: '5', ttl_min: '' }).body.ttl_max, 5);
  assert.deepEqual(policyBody({ ...base, max_rr: '1.5' }), { error: 'max_rr' });
  assert.deepEqual(policyBody({ ...base, max_rr: '1000000001' }), { error: 'max_rr' });
  assert.deepEqual(policyBody({ name: 'x', types: 'A' }).body.allow_wildcard, false);
});

test('a policy no wider than another (the rule of perm.js policySubset): types, each flag, the TTL range, max_rr', () => {
  const own = { ...POLICY, allowed_types: ['A', 'TXT'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 60, ttl_max: 3600, max_rr: 100 };
  const sub = (o) => ({ ...own, ...o });
  assert.ok(policyWithin(sub({}), own));
  assert.ok(policyWithin(sub({ allowed_types: ['A'], ttl_min: 120, ttl_max: 300, max_rr: 10 }), own));
  assert.ok(!policyWithin(sub({ allowed_types: ['A', 'MX'] }), own));
  for (const flag of ['allow_wildcard', 'allow_delegation', 'allow_dname', 'apex_editable']) assert.ok(!policyWithin(sub({ [flag]: true }), own), flag);
  assert.ok(policyWithin(sub({ allow_wildcard: true }), sub({ allow_wildcard: true })));
  assert.ok(!policyWithin(sub({ ttl_min: 30 }), own));
  assert.ok(!policyWithin(sub({ ttl_max: 7200 }), own));
  assert.ok(!policyWithin(sub({ max_rr: 101 }), own));
  assert.ok(!policyWithin(sub({ max_rr: null }), own));
  assert.ok(policyWithin(sub({ max_rr: null }), sub({ max_rr: null })));
  assert.ok(policyWithin(sub({ max_rr: 5 }), sub({ max_rr: undefined })));
  assert.ok(policyWithin(sub({}), null), 'no policy of one\'s own to compare with: everything is offered (a global master)');
});

test('the lookup of a principal by name: exact, whatever the case; the prefix is cut to 64 characters', async () => {
  const calls = [];
  const api = { get: async (path, o) => { calls.push([path, o.query]); return { principals: [{ id: 1, name: 'alice2' }, { id: 2, name: 'Alice' }] }; } };
  assert.deepEqual(await lookupPrincipal(api, ' alice ', 'user'), { id: 2, name: 'Alice' });
  assert.deepEqual(calls[0], ['/principals', { prefix: 'alice', kind: 'user', limit: 100 }]);
  assert.equal(await lookupPrincipal(api, 'nobody'), null);
  assert.equal(await lookupPrincipal(api, '   '), null);
  assert.equal(await lookupPrincipal(api, undefined), null);
  await lookupPrincipal(api, 'x'.repeat(100));
  assert.equal(calls.at(-1)[1].prefix.length, 64);
  assert.equal(principalLabel({ name: 'a', display_name: 'A B' }), 'a (A B)');
  assert.equal(principalLabel({ name: 'a', display_name: null }), 'a');
});

// ---------------------------------------------------------------------------------------------------------------------------------- audit
test('a time typed for the audit log', () => {
  assert.equal(whenText(' 2026-11-08T12:00:00Z '), '2026-11-08T12:00:00Z');
  assert.equal(whenText('2026-11-08'), '2026-11-08');
  for (const bad of ['', 'yesterday', undefined, '2026-11-08T12:00:00Z'.repeat(3)]) assert.equal(whenText(bad), null, String(bad));
});

test('the query of the audit log: the filters of the route, checked; the first that is wrong is named', () => {
  assert.deepEqual(auditQuery({}), { query: { limit: 100 } });
  assert.deepEqual(auditQuery({ zone: ' example.test. ', change_set: 'a-b:c.1', table: 'records', since: '2026-11-08T00:00:00Z', until: '2026-11-09', cursor: 'C1' }, 7),
    { query: { limit: 100, zone: 'example.test.', principal: 7, change_set: 'a-b:c.1', table: 'records', since: '2026-11-08T00:00:00Z', until: '2026-11-09', cursor: 'C1' } });
  assert.equal(auditQuery({ zone: 'a b' }).error, 'zone');
  assert.equal(auditQuery({ zone: 'a'.repeat(256) }).error, 'zone');
  assert.equal(auditQuery({ change_set: 'a b' }).error, 'change_set');
  assert.equal(auditQuery({ change_set: 'a'.repeat(65) }).error, 'change_set');
  assert.equal(auditQuery({ table: 'Records' }).error, 'table');
  assert.equal(auditQuery({ table: 'a'.repeat(65) }).error, 'table');
  assert.equal(auditQuery({ since: 'soon' }).error, 'since');
  assert.equal(auditQuery({ until: 'late' }).error, 'until');
  assert.equal(auditQuery({}, null).query.principal, undefined);
});

test('the dataset of an audit row: the only one, else the one the schema is named after', () => {
  assert.equal(datasetOfRow([{ name: 'main' }], 'public'), 'main');
  assert.equal(datasetOfRow([{ name: 'main' }, { name: 'other' }], 'other'), 'other');
  assert.equal(datasetOfRow([{ name: 'main' }, { name: 'other' }], 'public'), null);
  assert.equal(datasetOfRow([], 'x'), null);
});

test('JSON of an audit row: pretty-printed lines, cut when long, nothing for what is not JSON', () => {
  assert.deepEqual(jsonLines({ a: 1, b: ['x'] }), { lines: ['{', '  "a": 1,', '  "b": [', '    "x"', '  ]', '}'], cut: false });
  assert.deepEqual(jsonLines(undefined), { lines: [], cut: false });
  const circular = {};
  circular.self = circular;
  assert.deepEqual(jsonLines(circular), { lines: [], cut: false });
  const big = jsonLines({ k: 'x'.repeat(JSON_SHOWN * 2) });
  assert.equal(big.cut, true);
  assert.ok(big.lines.join('\n').length <= JSON_SHOWN);
});

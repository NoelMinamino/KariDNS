// What the history and the templates send to PostgreSQL (E), against a fake transaction: the statements, the parameters, the shape of the rows that come back.  The
// real thing runs in tests/run_webadmin_versions_pg_test.sh.

import test from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../lib/store.js';

function fakeTx(script = []) {
  const log = [];
  const rows = (sql) => (script.find(([re]) => re.test(sql)) ?? [null, []])[1];
  const clean = (sql) => sql.replace(/\s+/g, ' ').trim();
  return {
    log,
    dialect: 'pg',
    A: 'karidns_auth.',
    z: (s) => `"${s}".`,
    ts: (ms) => new Date(ms),
    list: (col, n, type = 'text') => `${col} = ANY($${n}::${type}[])`,
    listParam: (a) => a,
    all: async (sql, params = []) => { log.push([clean(sql), params]); return rows(sql); },
    get: async (sql, params = []) => { log.push([clean(sql), params]); return rows(sql)[0]; },
    run: async (sql, params = []) => { log.push([clean(sql), params]); return { changes: 1 }; },
  };
}

const vrow = (over = {}) => ({
  id: 7, version: 3, kind: 'edit', at: new Date(Date.UTC(2026, 10, 8)), principal_id: 5, principal_name: 'dom', db_role: 'karidns_api', change_set: 'cs', comment: null, serial_before: 10,
  serial_after: 11, generation_before: 4, generation_after: 5, rollback_of: null, delta_complete: true, n: 2, ...over,
});

test('versions: the list, one version, the delta, the sizes; a subdomain master\'s condition is in the statement as well as in the policy', async () => {
  const tx = fakeTx([[/FROM "s".karidns_zone_versions v WHERE v.domain_id/, [vrow()]]]);
  const rows = await S.listVersions(tx, 's', 8, { before: 9, limit: 20, zone: 'example.test', visibility: null });
  assert.deepEqual(rows[0], {
    version: 3, kind: 'edit', at: '2026-11-08T00:00:00Z', principal_id: 5, principal: 'dom', db_role: 'karidns_api', change_set: 'cs', comment: null, serial_before: 10, serial_after: 11,
    generation_before: 4, generation_after: 5, rollback_of: null, delta_complete: true, id: 7, rrsets: 2,
  });
  assert.match(tx.log[0][0], /SELECT v\.id, v\.version, .*\(SELECT count\(\*\) FROM "s"\.karidns_zone_version_rrsets r WHERE r\.version_id = v\.id AND 1 = 1\) AS n FROM "s"\.karidns_zone_versions v WHERE v\.domain_id = \$1 AND v\.version < \$2 ORDER BY v\.version DESC LIMIT \$3/);
  assert.deepEqual(tx.log[0][1], [8, 9, 21]);
  // a version with no principal (an operator's) and a count that was not asked for
  const op = (await S.listVersions(fakeTx([[/karidns_zone_versions/, [vrow({ principal_id: null, principal_name: null, n: undefined })]]]), 's', 8, { limit: 1, zone: 'z.test', visibility: null }))[0];
  assert.deepEqual([op.principal_id, op.principal, 'rrsets' in op], [null, null, false]);
  const sub = fakeTx();
  await S.listVersions(sub, 's', 8, { limit: 5, zone: 'example.test', visibility: { suffixes: ['sub.example.test'] } });
  assert.match(sub.log[0][0], /\(r\.owner = \$3 OR substr\(r\.owner, length\(r\.owner\) - 16\) = \$4\) OR \(r\.owner = \$5 AND upper\(r\.type\) IN \('SOA', 'NS'\)\)/);
  assert.deepEqual(sub.log[0][1], [8, 2147483647, 'sub.example.test', '.sub.example.test', 'example.test', 6]);
  // one version
  const one = fakeTx([[/v\.version = \$/, [vrow()]]]);
  assert.equal((await S.getVersion(one, 's', 8, 3, { zone: 'example.test' })).version, 3);
  assert.equal(await S.getVersion(fakeTx(), 's', 8, 3), undefined);
  assert.deepEqual(one.log[0][1], [8, 3]);
  // its delta, after a cursor
  const d = fakeTx();
  await S.versionRRsets(d, 's', 7, { zone: 'example.test', visibility: null, after: { name: 'b.example.test', type: 'A' }, limit: 100 });
  assert.match(d.log[0][0], /FROM "s"\.karidns_zone_version_rrsets r WHERE r\.version_id = \$1 AND 1 = 1 AND r\.owner >= \$2 AND \(r\.owner > \$2 OR \(r\.owner = \$2 AND r\.type > \$3\)\) ORDER BY r\.owner, r\.type LIMIT \$4/);
  assert.deepEqual(d.log[0][1], [7, 'b.example.test', 'A', 101]);
  await S.versionRRsets(d, 's', 7, { zone: 'example.test', visibility: null, limit: 5 });
  assert.deepEqual(d.log[1][1], [7, 6]);
  // a range
  const c = fakeTx([[/count\(\*\) AS n/, [{ n: 12 }]], [/SELECT v\.version, v\.delta_complete/, [{ version: 2, delta_complete: true }, { version: 3, delta_complete: false }]],
    [/SELECT v\.version, r\.owner/, [{ version: 2, owner: 'a.t', type: 'A', before: null, after: '300 A 1.1.1.1' }]]]);
  assert.equal(await S.versionRowCount(c, 's', 8, 1, undefined, { zone: 'example.test', visibility: null }), 12);
  assert.equal(await S.versionRowCount(c, 's', 8, 1, 3, { zone: 'example.test', visibility: null }), 12);
  assert.match(c.log[0][0], /JOIN "s"\.karidns_zone_versions v ON v\.id = r\.version_id WHERE v\.domain_id = \$1 AND v\.version > \$2 AND 1 = 1$/);
  assert.match(c.log[1][0], /v\.version > \$2 AND v\.version <= \$3 AND 1 = 1$/);
  const b = await S.versionsBetween(c, 's', 8, 1, 3, { zone: 'example.test', visibility: null });
  assert.deepEqual(b.headers, [{ version: 2, delta_complete: true }, { version: 3, delta_complete: false }]);
  assert.equal(b.rows.length, 1);
  await S.versionsBetween(c, 's', 8, 1, undefined, { zone: 'example.test', visibility: null });
  assert.match(c.log.at(-1)[0], /ORDER BY v\.version, r\.owner, r\.type$/);
  // the generation, and the change sets of the versions
  assert.equal(await S.zoneGeneration(fakeTx([[/karidns_zone_state/, [{ generation: 17 }]]]), 's', 8), 17);
  assert.equal(await S.zoneGeneration(fakeTx(), 's', 8), 0);
  assert.deepEqual(await S.versionChangeSets(fakeTx([[/change_set/, [{ change_set: 'a' }, { change_set: 'b' }]]]), 's', 8), ['a', 'b']);
});

test('the audit rows that are changes of the records of a zone between two versions: jsonb on PostgreSQL, the versions\' own times', async () => {
  const tx = fakeTx([[/SELECT 1 AS ok FROM karidns_auth\.audit_log/, [{ ok: 1 }]], [/SELECT a\.op, a\.before, a\.after/, [{ op: 'I', before: null, after: { type: 'A', name: 'x.example.test' } }]]]);
  const r = await S.auditRecordChanges(tx, 's', 'example.test', { since: 7, until: 9, exclude: ['cs-1', 'cs-2'] });
  assert.deepEqual(r, { any: true, rows: [{ op: 'I', before: null, after: { type: 'A', name: 'x.example.test' } }] });
  const win = String.raw`WHERE a\.zone_name IN \(\$1, \$2\) AND a\.at (>=?) \(SELECT v\.at FROM "s"\.karidns_zone_versions v WHERE v\.id = \$3\) AND a\.data_schema = \$4 AND a\.at (<=?) \(SELECT v\.at FROM "s"\.karidns_zone_versions v WHERE v\.id = \$5\) AND \(a\.change_set IS NULL OR NOT \(a\.change_set = ANY\(\$6::text\[\]\)\)\)`;
  assert.match(tx.log[0][0], new RegExp(`${win} LIMIT 1$`));
  assert.deepEqual(tx.log[0][1], ['example.test', 'example.test.', 7, 's', 9, ['cs-1', 'cs-2']]);
  assert.deepEqual(new RegExp(win).exec(tx.log[0][0]).slice(1), ['>', '<'], 'both ends excluded: the rows of an operator\'s version cannot be told from others\'');
  assert.match(tx.log[1][0], /AND a\.table_name = 'records' AND \(coalesce\(a\.after, a\.before\) ->> 'summary'\) IS NULL/);
  assert.match(tx.log[1][0], /NOT IN \('RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY'\) AND \(a\.op <> 'U' OR \(a\.before - 'ordername' - 'auth'\) IS DISTINCT FROM \(a\.after - 'ordername' - 'auth'\)\) ORDER BY a\.id LIMIT 2000$/);
  assert.deepEqual(tx.log[1][1], tx.log[0][1]);
  // the ends of versions that have a change set are in the window (their own rows are left out by the change set)
  const incl = fakeTx();
  await S.auditRecordChanges(incl, 's', 'example.test', { since: 7, sinceIncl: true, until: 9, untilIncl: true, exclude: [] });
  assert.deepEqual(new RegExp(win).exec(incl.log[0][0]).slice(1), ['>=', '<=']);
  // up to now: no second version
  const open = fakeTx();
  const o = await S.auditRecordChanges(open, 's', 'example.test', { since: 7, exclude: [] });
  assert.deepEqual(o, { any: false, rows: [] });
  assert.ok(!/a\.at < /.test(open.log[0][0]));
});

test('templates: the statements; the SOA defaults are six columns; the records are replaced as a list', async () => {
  const trow = { id: 4, name: 'standard', description: null, revision: 3, soa_mname: 'ns1.example.test', soa_rname: null, soa_refresh: 1800, soa_retry: null, soa_expire: null, soa_minimum: null, created_by: 1, updated_at: new Date(Date.UTC(2026, 10, 8)), n: 2 };
  const tx = fakeTx([[/FROM karidns_auth\.templates t WHERE t\.id > /, [trow]], [/FROM karidns_auth\.templates t WHERE t\.id = /, [trow]], [/FROM karidns_auth\.templates t WHERE t\.name = /, [trow]],
    [/FROM karidns_auth\.template_records WHERE/, [{ ordinal: 0, owner: '@', type: 'NS', ttl: null, content: 'ns1.example.test.' }]], [/INSERT INTO karidns_auth\.templates/, [{ id: 9 }]]]);
  const l = await S.listTemplates(tx, { prefix: 'St', after: 2, limit: 10 });
  assert.deepEqual(l[0], { id: 4, name: 'standard', description: null, revision: 3, soa: { mname: 'ns1.example.test', rname: null, refresh: 1800, retry: null, expire: null, minimum: null }, created_by: 1, updated_at: '2026-11-08T00:00:00Z', record_count: 2 });
  assert.match(tx.log[0][0], /WHERE t\.id > \$1 AND substr\(lower\(t\.name\), 1, 2\) = \$2 ORDER BY t\.id LIMIT \$3/);
  assert.deepEqual(tx.log[0][1], [2, 'st', 11]);
  const g = await S.getTemplate(tx, 4);
  assert.deepEqual(g.records, [{ owner: '@', type: 'NS', ttl: null, content: 'ns1.example.test.' }]);
  assert.equal((await S.getTemplateByName(tx, 'standard')).id, 4);
  assert.equal(await S.getTemplate(fakeTx(), 5), undefined);
  assert.deepEqual(tx.log.at(-1)[1], [4]);
  // no SOA default at all is no soa object
  const none = await S.getTemplate(fakeTx([[/FROM karidns_auth\.templates t WHERE t\.id = /, [{ ...trow, soa_mname: null, soa_refresh: null }]]]), 4);
  assert.equal(none.soa, null);
  // create: the template, then its records one by one
  const c = fakeTx([[/INSERT INTO karidns_auth\.templates/, [{ id: 9 }]]]);
  const id = await S.createTemplate(c, { name: 'n', description: 'd', soa: { mname: 'a', rname: 'b', refresh: 1, retry: 2, expire: 3, minimum: 4 }, records: [{ owner: '@', type: 'A', ttl: 5, content: 'x' }, { owner: 'w', type: 'A', content: 'y' }] }, 1);
  assert.equal(id, 9);
  assert.match(c.log[0][0], /INSERT INTO karidns_auth\.templates \(name, description, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_minimum, created_by\) VALUES \(\$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9\) RETURNING id/);
  assert.deepEqual(c.log[0][1], ['n', 'd', 'a', 'b', 1, 2, 3, 4, 1]);
  assert.deepEqual(c.log.slice(1).map((l) => l[1]), [[9], [9, 0, '@', 'A', 5, 'x'], [9, 1, 'w', 'A', null, 'y']]);
  // update: only the columns given; records replaced; a PATCH with only records still touches the row (the revision)
  const u = fakeTx();
  await S.updateTemplate(u, 4, { name: 'm', description: null, soa: null, records: [] });
  assert.match(u.log[0][0], /^UPDATE karidns_auth\.templates SET name = \$1, description = \$2, soa_mname = \$3, soa_rname = \$4, soa_refresh = \$5, soa_retry = \$6, soa_expire = \$7, soa_minimum = \$8 WHERE id = \$9$/);
  assert.deepEqual(u.log[0][1], ['m', null, null, null, null, null, null, null, 4]);
  assert.match(u.log[1][0], /^DELETE FROM karidns_auth\.template_records WHERE template_id = \$1$/);
  const u2 = fakeTx();
  await S.updateTemplate(u2, 4, { records: [{ owner: '@', type: 'A', content: 'x' }] });
  assert.match(u2.log[0][0], /^UPDATE karidns_auth\.templates SET name = name WHERE id = \$1$/);
  const del = fakeTx();
  assert.equal(await S.deleteTemplate(del, 4), 1);
  assert.deepEqual(del.log[0], ['DELETE FROM karidns_auth.templates WHERE id = $1', [4]]);
  // a template that is not there: nothing is written to its records
  const gone = { ...fakeTx(), run: async () => ({ changes: 0 }) };
  assert.equal(await S.updateTemplate(gone, 99, { records: [] }), 0);
});

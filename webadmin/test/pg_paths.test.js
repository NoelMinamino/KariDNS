// What differs on PostgreSQL, against a fake transaction: the statements the store sends, the parameters, and the handlers that read PostgreSQL-only tables.
// The real thing runs in tests/run_webadmin_pg_test.sh.

import test from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../lib/store.js';
import { dbArgs, exportArgv, typesArgv } from '../lib/tools.js';
import { serversList, auditList } from '../lib/handlers/zones.js';
import { App } from '../lib/app.js';
import { parseConfig } from '../lib/config.js';

// a transaction that answers from a script: [pattern, rows] pairs, first match wins; every statement is recorded
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
    setPrincipal: async () => {},
    all: async (sql, params = []) => { log.push([clean(sql), params]); return rows(sql); },
    get: async (sql, params = []) => { log.push([clean(sql), params]); return rows(sql)[0]; },
    run: async (sql, params = []) => { log.push([clean(sql), params]); return { changes: 1 }; },
  };
}

test('sessions and tokens are looked up by the functions of the schema', async () => {
  const tx = fakeTx([
    [/session_lookup/, [{ principal_id: 4, csrf_hash: Buffer.alloc(32, 1), created_at: new Date(1000), last_seen: new Date(2000), expires_at: new Date(3000), totp_ok: true }]],
    [/api_token_lookup/, [{ principal_id: 5, read_only: false, expires_at: new Date(9000) }]],
  ]);
  const h = Buffer.alloc(32, 9);
  assert.deepEqual(await S.lookupSession(tx, h, 1), { principal_id: 4, csrf_hash: Buffer.alloc(32, 1), created: 1000, last_seen: 2000, expires: 3000, totp_ok: true });
  assert.deepEqual(tx.log[0], ['SELECT principal_id, csrf_hash, created_at, last_seen, expires_at, totp_ok FROM karidns_auth.session_lookup($1)', [h]]);
  assert.deepEqual(await S.lookupToken(tx, 7, h, 1), { principal_id: 5, read_only: false, expires: 9000 });
  assert.deepEqual(tx.log[1], ['SELECT principal_id, read_only, expires_at FROM karidns_auth.api_token_lookup($1, $2)', [7, h]]);
  assert.equal(await S.lookupSession(fakeTx(), h, 1), undefined);
  assert.equal(await S.lookupToken(fakeTx(), 1, h, 1), undefined);
});

test('policies: the types are an array column', async () => {
  const tx = fakeTx([[/FROM karidns_auth.rr_policies/, [{ id: 3, name: 'web', allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 60, ttl_max: 86400, max_rr: null, allowed_types: ['A', 'TXT'] }]]]);
  const p = (await S.listPolicies(tx, { ids: [3] }))[0];
  assert.deepEqual(p.allowed_types, ['A', 'TXT']);
  assert.match(tx.log[0][0], /SELECT id, name, allow_wildcard, .*, allowed_types FROM karidns_auth\.rr_policies WHERE id > \$1 AND id = ANY\(\$2::bigint\[\]\) ORDER BY id LIMIT \$3/);
  assert.deepEqual(tx.log[0][1], [0, [3], 100000]);
  const t2 = fakeTx([[/INSERT INTO karidns_auth.rr_policies/, [{ id: 9 }]]]);
  const id = await S.createPolicy(t2, { name: 'n', allowed_types: ['A'], allow_wildcard: true, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 0, ttl_max: 5, max_rr: 3 }, 1);
  assert.equal(id, 9);
  assert.match(t2.log[0][0], /\(name, allowed_types, allow_wildcard.*VALUES \(\$1, \$2::text\[\], \$3/);
  assert.deepEqual(t2.log[0][1], ['n', ['A'], true, false, false, false, 0, 5, 3, 1]);
  assert.equal(t2.log.length, 1, 'no second table');
  const t3 = fakeTx();
  await S.updatePolicy(t3, 4, { allowed_types: ['MX'], ttl_max: 9 });
  assert.deepEqual(t3.log.map((l) => l[0]), ['UPDATE karidns_auth.rr_policies SET ttl_max = $1 WHERE id = $2', 'UPDATE karidns_auth.rr_policies SET allowed_types = $2::text[] WHERE id = $1']);
});

test('grants: a global master has no schema; the schema of a domain master is the dataset\'s', async () => {
  const tx = fakeTx([[/INSERT INTO karidns_auth.grants/, [{ id: 1 }]]]);
  await S.createGrant(tx, { principalId: 2, role: 'domain_master', schema: 'public', zone: 'example.test', suffix: null, policyId: 3, grantedBy: 1 });
  assert.deepEqual(tx.log[0][1], [2, 'domain_master', 'public', 'example.test', null, 3, 1]);
  const eff = fakeTx([
    [/FROM karidns_auth.principal_closure/, [{ id: 1, role: 'global_master', data_schema: null, zone_name: null, name_suffix: null, rr_policy_id: 3, via: 2, via_name: 'g' }]],
    [/FROM karidns_auth.rr_policies/, [{ id: 3, name: 'p', allow_wildcard: 1, allow_delegation: 0, allow_dname: 0, apex_editable: 1, ttl_min: 0, ttl_max: 9, max_rr: null, allowed_types: ['A'] }]],
  ]);
  const g = (await S.effectiveGrants(eff, 2))[0];
  assert.equal(g.data_schema, null);
  assert.deepEqual(g.policy.allowed_types, ['A']);
  assert.equal(g.policy.allow_wildcard, true);
});

test('a zone: the reload requests are read, the zone state may be missing', async () => {
  const tx = fakeTx([
    [/FROM "s".domains d WHERE d.name IN/, [{ id: 8, name: 'example.test', type: 'MASTER', master: null, catalog: null, account: null, notified_serial: null, soa: 'ns h 7 1 1 1 1', presigned: false, signer: false }]],
    [/max\(generation\)/, [{ g: 12, at: new Date(Date.UTC(2026, 0, 1)) }]],
  ]);
  const z = await S.getZone(tx, 's', 'example.test');
  assert.equal(z.serial, 7);
  assert.equal(z.generation, 0);
  assert.equal(z.changed_at, null);
  assert.deepEqual(z.last_reload_request, { generation: 12, at: '2026-01-01T00:00:00Z' });
  assert.deepEqual(tx.log.at(-1)[1], ['example.test', 'example.test.']);
  const none = fakeTx([[/FROM "s".domains d WHERE d.name IN/, [{ id: 8, name: 'example.test.', type: 'MASTER', soa: null }]], [/max\(generation\)/, [{ g: null, at: null }]]]);
  assert.equal((await S.getZone(none, 's', 'example.test')).last_reload_request, null);
  assert.equal(await S.getZone(fakeTx(), 's', 'nothing.test'), undefined);
  assert.equal((await S.zoneId(fakeTx([[/SELECT d.id/, [{ id: 3 }]]]), 's', 'x.test')), 3);
});

test('the zone list: a list of names is one array parameter; PostgreSQL has the same text as SQLite3', async () => {
  const tx = fakeTx();
  await S.listZones(tx, 's', { names: ['a.test', 'b.test'], limit: 10 });
  assert.match(tx.log[0][0], /WHERE 1 = 1 AND d\.name = ANY\(\$1::text\[\]\) ORDER BY d\.name LIMIT \$2/);
  assert.deepEqual(tx.log[0][1], [['a.test', 'a.test.', 'b.test', 'b.test.'], 11]);
});

test('the audit log is one table; the cursor is the id', async () => {
  const row = { id: 9, at: new Date(Date.UTC(2026, 0, 1)), db_role: 'karidns_api', principal_id: 1, principal_name: 'root', change_set: null, data_schema: 'karidns_auth', table_name: 'grants', op: 'I', zone_name: 'z.test', row_id: 3, before: null, after: { data_schema: 's' } };
  const tx = fakeTx([[/FROM karidns_auth.audit_log/, [row]]]);
  const rows = await S.listAudit(tx, { zone: 'z.test', since: 5, until: 6, principalId: 1, changeSet: 'c', table: 'grants' }, { at: '2026-01-02T00:00:00Z', rank: 0, id: 20 }, 50);
  assert.equal(rows[0].source, 'audit');
  assert.equal(rows[0].at, '2026-01-01T00:00:00Z');
  assert.match(tx.log[0][0], /FROM karidns_auth\.audit_log WHERE 1 = 1 AND zone_name = \$1 AND principal_id = \$2 AND change_set = \$3 AND table_name = \$4 AND at >= \$5 AND at <= \$6 AND id < \$8 ORDER BY id DESC, id DESC LIMIT \$9/);
});

test('server status and the schema checks', async () => {
  const tx = fakeTx([
    [/karidns_server_status/, [{ server_id: 'a', generation: 3, applied_at: new Date(Date.UTC(2026, 0, 1)), ok: false, failed_zones: 'x.test: bad\ny.test: worse' }]],
    [/to_regclass/, [{ ok: true }]],
    [/max\(version\)/, [{ v: 3 }]],
  ]);
  assert.deepEqual(await S.serverStatus(tx, 's'), [{ server_id: 'a', generation: 3, applied_at: '2026-01-01T00:00:00Z', ok: false, failed_zones: 'x.test: bad\ny.test: worse' }]);
  assert.deepEqual(await S.missingTables(tx, 's', ['auth.principals', 'domains']), []);
  assert.deepEqual(tx.log.filter((l) => /to_regclass/.test(l[0])).map((l) => l[1][0]), ['karidns_auth.principals', '"s".domains']);
  assert.deepEqual(await S.schemaVersions(tx, 's'), { auth: 3, data: 3 });
  assert.deepEqual(await S.missingTables(fakeTx([[/to_regclass/, [{ ok: false }]]]), 's', ['domains']), ['domains']);
  assert.deepEqual(await S.schemaVersions(fakeTx(), 's'), { auth: null, data: null });
});

test('the arguments of karidns-zone: the check role on PostgreSQL, the file on SQLite3', () => {
  const pg = parseConfig('database = pg\ncheck-conninfo-file = /etc/check.conninfo\n').settings;
  assert.deepEqual(dbArgs(pg, { schema: 'zones' }), ['--no-config', '--conninfo-file', '/etc/check.conninfo', '--schema', 'zones']);
  assert.deepEqual(exportArgv(pg, { schema: 'zones' }, 'Example.TEST.'), ['export', '--no-config', '--conninfo-file', '/etc/check.conninfo', '--schema', 'zones', 'example.test']);
  assert.throws(() => exportArgv(pg, { schema: 'zones' }, '-x'), /zone name/);
  const lite = parseConfig('database = sqlite3\nsqlite-file = /var/db/z.sqlite3\n').settings;
  assert.deepEqual(dbArgs(lite, { schema: '' }), ['--no-config', '--sqlite3', '/var/db/z.sqlite3']);
  assert.deepEqual(typesArgv(), ['--types-list', '--json']);
});

function ctxFor(grants, rowsBySchema) {
  const config = parseConfig('listen = 127.0.0.1:1\npublic-origin = http://127.0.0.1:1\ndatabase = pg\napi-conninfo-file = /a\ncheck-conninfo-file = /b\n[dataset one]\nschema = s1\n[dataset two]\nschema = s2\n');
  const app = new App({ config, backend: { dialect: 'pg' }, log: {}, run: null, key: Buffer.alloc(32) });
  const tx = fakeTx([[/karidns_server_status/, null]]);
  tx.all = async (sql) => {
    const m = /"(s\d)"/.exec(sql);
    return rowsBySchema[m[1]] ?? [];
  };
  return { app, auth: { grants }, db: (fn) => fn(tx), query: new URLSearchParams() };
}
const grant = (role, schema, zone) => ({ role, data_schema: schema, zone_name: zone, name_suffix: null, policy: null });

test('/servers: the datasets a principal has a grant on, the failed zones it has a grant on', async () => {
  const rows = { s1: [{ server_id: 'a', generation: 3, applied_at: new Date(0), ok: false, failed_zones: 'x.test: bad\ny.test.: worse\n\nz.test: also' }], s2: [{ server_id: 'b', generation: 1, applied_at: new Date(0), ok: true, failed_zones: '' }] };
  const asRoot = await serversList(ctxFor([grant('global_master', null, null)], rows));
  assert.deepEqual(asRoot.servers.map((s) => [s.dataset, s.server_id, s.failed_zones.length]), [['one', 'a', 3], ['two', 'b', 0]]);
  const asDom = await serversList(ctxFor([grant('domain_master', 's1', 'y.test')], rows));
  assert.deepEqual(asDom.servers.map((s) => [s.dataset, s.failed_zones]), [['one', ['y.test.: worse']]]);
  assert.equal(asDom.note, undefined);
  assert.deepEqual((await serversList(ctxFor([], rows))).servers, []);
});

test('the audit log on PostgreSQL: the data schema of a grant row is in the row', async () => {
  const row = (zone, schema) => ({ id: 1, at: new Date(0), db_role: 'r', principal_id: 1, principal_name: 'p', change_set: null, data_schema: 'karidns_auth', table_name: 'grants', op: 'I', zone_name: zone, row_id: 1, before: null, after: { data_schema: schema } });
  const ctx = (grants, rows) => {
    const c = ctxFor(grants, {});
    c.db = (fn) => fn(fakeTx([[/audit_log/, rows]]));
    return c;
  };
  const dom = [grant('domain_master', 's1', 'z.test')];
  assert.equal((await auditList(ctx(dom, [row('z.test', 's1')]))).audit.length, 1);
  assert.equal((await auditList(ctx(dom, [row('z.test', 's2')]))).audit.length, 0, 'the grant is on another schema\'s zone of that name');
  assert.equal((await auditList(ctx(dom, [{ ...row('z.test', 's1'), after: null, before: null }]))).audit.length, 0);
  const plain = { ...row('z.test', null), data_schema: 's1', table_name: 'records' };
  assert.equal((await auditList(ctx(dom, [plain]))).audit.length, 1);
});

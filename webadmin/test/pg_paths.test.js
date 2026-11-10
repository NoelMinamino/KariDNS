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

test('the sign-in with a provider on PostgreSQL goes through the functions of the schema, never the table', async () => {
  const h = Buffer.alloc(32, 1);
  const tx = fakeTx([
    [/oidc_state_put/, [{ ok: true }]],
    [/oidc_state_take/, [{ browser_hash: h, provider: 'idp', nonce: 'n', verifier: 'v', return_route: '/' }]],
    [/oidc_lookup/, [{ id: 7 }]],
  ]);
  assert.equal(await S.putOidcState(tx, { stateHash: h, browserHash: h, provider: 'idp', nonce: 'n', verifier: 'v', route: '/zones', nowMs: 1 }), true);
  assert.deepEqual(tx.log[0], ['SELECT karidns_auth.oidc_state_put($1, $2, $3, $4, $5, $6, $7) AS ok', [h, h, 'idp', 'n', 'v', '/zones', 600]]);
  assert.deepEqual(await S.takeOidcState(tx, h, 1), { browser_hash: h, provider: 'idp', nonce: 'n', verifier: 'v', return_route: '/' });
  assert.deepEqual(tx.log[1], ['SELECT browser_hash, provider, nonce, verifier, return_route FROM karidns_auth.oidc_state_take($1)', [h]]);
  assert.equal(await S.oidcLookup(tx, 'https://idp.example.test', 'sub'), 7);
  assert.deepEqual(tx.log[2], ['SELECT karidns_auth.oidc_lookup($1, $2) AS id', ['https://idp.example.test', 'sub']]);
  assert.equal(await S.oidcLookup(fakeTx(), 'i', 's'), null);
  assert.equal(await S.putOidcState(fakeTx([[/oidc_state_put/, [{ ok: false }]]]), { stateHash: h, browserHash: h, provider: 'idp', nonce: 'n', verifier: 'v', route: '/', nowMs: 1 }), false);
  // the link is plain SQL on credentials (a global master's policy allows it)
  await S.setOidc(tx, 7, 'i', 's');
  assert.match(tx.log.at(-1)[0], /^UPDATE karidns_auth\.credentials SET oidc_issuer = \$2, oidc_subject = \$3 WHERE principal_id = \$1$/);
});

test('principals and policies in the reach of a domain master: the zones are (schema, zone) pairs', async () => {
  const zones = [{ schema: 'karidns_a', zone: 'example.test' }, { schema: 'karidns_b', zone: 'other.test' }];
  const tx = fakeTx([[/FROM karidns_auth.principals p/, [{ id: 5, kind: 'user', name: 'u', disabled: false }]], [/SELECT DISTINCT g.rr_policy_id/, [{ id: 8 }]]]);
  assert.equal((await S.listPrincipals(tx, { scope: { ids: [1], groups: [2], zones }, limit: 10 })).length, 1);
  assert.match(tx.log[0][0], /\(p\.id = ANY\(\$2::bigint\[\]\) OR p\.id IN \(SELECT c\.member_id FROM karidns_auth\.principal_closure c WHERE c\.group_id = ANY\(\$3::bigint\[\]\)\) OR EXISTS \(SELECT 1 FROM karidns_auth\.grants g WHERE g\.principal_id = p\.id AND \(\(g\.zone_name = \$4 AND g\.data_schema = \$5\) OR \(g\.zone_name = \$6 AND g\.data_schema = \$7\)\)\)\)/);
  assert.deepEqual(tx.log[0][1], [0, [1], [2], 'example.test', 'karidns_a', 'other.test', 'karidns_b', 11]);
  assert.deepEqual(await S.policyIdsOnZones(tx, zones), [8]);
  assert.match(tx.log[1][0], /^SELECT DISTINCT g\.rr_policy_id AS id FROM karidns_auth\.grants g WHERE \(\(g\.zone_name = \$1 AND g\.data_schema = \$2\) OR /);
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

// ---------------------------------------------------------------------------------------------------------------------------------- M3: the write side
test('writing zones on PostgreSQL: the statements and their parameters', async () => {
  const tx = fakeTx([
    [/^SELECT d\.type FROM/, [{ type: 'PRODUCER' }]],
    [/^SELECT d\.id, d\.name/, [{ id: 8, name: 'Example.test.', type: 'NATIVE', catalog: null, presigned: true, signer: false }]],
    [/count\(\*\) AS n FROM "s".records/, [{ n: '41' }]],
    [/FROM "s".records r WHERE/, [{ name: 'WWW.example.test', type: 'A' }, { name: 'other.example.test', type: 'MX' }]],
    [/count\(\*\) AS n FROM "s".domainmetadata/, [{ n: 2 }]],
    [/FROM "s".domainmetadata WHERE domain_id = \$1 ORDER/, [{ kind: 'ALSO-NOTIFY', content: '192.0.2.1' }]],
    [/FROM "s".karidns_key_requests WHERE domain_id = \$1 AND state/, [{ id: 4 }]],
    [/INSERT INTO "s".karidns_key_requests/, [{ id: 5 }]],
    [/FROM "s".karidns_key_requests/, [{ id: 5, kind: 'enable', algorithm: 13, bits: null, key_type: 'csk', nsec: null, state: 'pending', message: null, requested_by: 3, created_at: new Date(0), done_at: null }]],
    [/FROM "s".cryptokeys/, [{ id: 1, flags: 257, active: true, published: false }]],
    [/FROM "s".records WHERE domain_id = \$1 AND name = \$2 AND upper\(type\) = 'DNSKEY'/, [{ ttl: 300, content: '257 3 13 AAAA' }]],
    [/karidns_domain_views/, [{ view_name: 'a' }]],
    [/sweep_expired/, [{ n: '3' }]],
  ]);
  assert.deepEqual(await S.zoneFacts(tx, 's', 'example.test'), { id: 8, name: 'example.test', kind: 'NATIVE', catalog: null, presigned: true, signer: false });
  assert.deepEqual(tx.log[0][1], ['example.test', 'example.test.']);
  // the tagged RRsets among the ones asked about: the names go in as one array
  const pairs = [{ name: 'www.example.test', type: 'A' }, { name: 'www.example.test', type: 'TXT' }, { name: 'other.example.test', type: 'MX' }];
  assert.deepEqual(await S.taggedRRsets(tx, 's', 8, pairs), [{ name: 'www.example.test', type: 'A' }, { name: 'other.example.test', type: 'MX' }]);
  assert.deepEqual(tx.log.at(-1)[1], [8, ['www.example.test', 'other.example.test']]);
  assert.match(tx.log.at(-1)[0], /r\.name = ANY\(\$2::text\[\]\) ORDER BY 1, 2 LIMIT 100000/);
  assert.equal((await S.taggedRRsets(tx, 's', 8)).length, 2);
  assert.match(tx.log.at(-1)[0], /LIMIT 1$/);
  assert.equal(await S.countUnder(tx, 's', 8, 'sub.example.test'), 41);
  assert.deepEqual(tx.log.at(-1)[1], [8, 'sub.example.test', 16, '.sub.example.test']);
  assert.match(tx.log.at(-1)[0], /r\.disabled IS NOT TRUE/);
  // a zone goes by its foreign keys; the reload request is one row
  const d = fakeTx();
  await S.deleteZone(d, 's', 8, 'example.test');
  assert.deepEqual(d.log, [['DELETE FROM "s".domains WHERE id = $1', [8]]]);
  await S.requestReload(d, 's', 'example.test');
  await S.requestReload(d, 's');
  assert.deepEqual(d.log.slice(1), [['INSERT INTO "s".karidns_reload_requests (zone) VALUES ($1)', ['example.test']], ['INSERT INTO "s".karidns_reload_requests DEFAULT VALUES', []]]);
  assert.equal(await S.signerZoneCount(tx, 's'), 2);
  assert.deepEqual(await S.listMetadata(tx, 's', 8), [{ kind: 'ALSO-NOTIFY', content: '192.0.2.1' }]);
  await S.setMetadata(d, 's', 8, 'ALSO-NOTIFY', ['192.0.2.1', '192.0.2.2']);
  assert.deepEqual(d.log.slice(3).map((l) => l[1]), [[8, 'ALSO-NOTIFY'], [8, 'ALSO-NOTIFY', '192.0.2.1'], [8, 'ALSO-NOTIFY', '192.0.2.2']]);
  await S.setCatalog(d, 's', 8, 'cat.test');
  await S.setViews(d, 's', 8, ['a', 'b']);
  assert.deepEqual(d.log.slice(6).map((l) => l[1]), [[8, 'cat.test'], [8], [8, 'a'], [8, 'b']]);
  assert.equal(await S.producerZone(tx, 's', 'cat.test'), true);
  assert.equal(await S.producerZone(fakeTx(), 's', 'cat.test'), false);
  assert.deepEqual(await S.zoneViews(tx, 's', 8), ['a']);
  assert.deepEqual(await S.dnskeyRecords(tx, 's', 8, 'example.test'), [{ ttl: 300, content: '257 3 13 AAAA' }]);
  assert.deepEqual(await S.cryptoKeys(tx, 's', 8), [{ id: 1, flags: 257, active: true, published: false }]);
  assert.equal(await S.pendingKeyRequest(tx, 's', 8), 4);
  assert.equal(await S.insertKeyRequest(tx, 's', 8, { kind: 'enable', algorithm: 13, key_type: 'csk' }, 3), 5);
  assert.deepEqual(tx.log.at(-1)[1], [8, 'enable', 13, null, 'csk', null, 3]);
  assert.deepEqual((await S.listKeyRequests(tx, 's', 8))[0], { id: 5, kind: 'enable', algorithm: 13, bits: null, key_type: 'csk', nsec: null, state: 'pending', message: null, requested_by: 3, created_at: '1970-01-01T00:00:00Z', done_at: null });
  assert.equal(await S.sweepExpired(tx), 3);
});

// a context for the handlers of the write side on PostgreSQL: the transaction answers from a script, the tools are scripted
function writeCtx(grants, script, over = {}) {
  const config = parseConfig('listen = 127.0.0.1:1\npublic-origin = http://127.0.0.1:1\ndatabase = pg\napi-conninfo-file = /a\ncheck-conninfo-file = /b\nkarictl = /opt/karictl\n');
  const tx = fakeTx(script);
  const calls = [];
  const app = new App({ config, backend: { dialect: 'pg' }, log: { error: () => {}, warn: () => {} }, run: async (file, argv) => { calls.push([file, argv]); return { code: 0, stdout: '', stderr: '' }; }, key: Buffer.alloc(32) });
  const ctx = { app, auth: { grants, principal: { id: 4, name: 'p' } }, db: (fn, o) => { calls.push(['tx', o]); return fn(tx); }, params: { ds: 'main', zone: 'example.test', ...over.params }, body: over.body, id: 'rid' };
  return { ctx, tx, calls, app };
}
const ZONE_FACTS = [/FROM "public".domains d WHERE d.name IN/, [{ id: 8, name: 'example.test', type: 'NATIVE', catalog: null, presigned: false, signer: false }]];

test('the update button on PostgreSQL is a row in karidns_reload_requests; every zone only when the signer keeps none', async () => {
  const { reloadZone, reloadAll } = await import('../lib/handlers/write.js');
  const global = [grant('global_master', null, null)];
  const a = writeCtx(global, [ZONE_FACTS]);
  assert.deepEqual((await reloadZone(a.ctx)).reload, 'requested');
  assert.ok(a.tx.log.some((l) => /INSERT INTO "public".karidns_reload_requests \(zone\) VALUES \(\$1\)/.test(l[0]) && l[1][0] === 'example.test'));
  assert.deepEqual(a.calls.filter((c) => c[0] === 'tx').map((c) => c[1]).at(-1).write, true);
  assert.ok(!a.calls.some((c) => c[0] === '/opt/karictl'), 'no karictl on PostgreSQL');
  // every zone of the dataset
  const b = writeCtx(global, [[/count\(\*\) AS n FROM "public".domainmetadata/, [{ n: 0 }]]]);
  assert.equal((await reloadAll(b.ctx)).reload, 'requested');
  assert.ok(b.tx.log.some((l) => /INSERT INTO "public".karidns_reload_requests DEFAULT VALUES/.test(l[0])));
  const c = writeCtx(global, [[/count\(\*\) AS n FROM "public".domainmetadata/, [{ n: 1 }]]]);
  await assert.rejects(reloadAll(c.ctx), (e) => e.status === 409 && e.code === 'signer-zones');
  assert.ok(!c.tx.log.some((l) => /INSERT/.test(l[0])));
});

test('a change set on PostgreSQL asks the commit run for the reload request, and the check run is the check role', async () => {
  const { rrsetsPatch } = await import('../lib/handlers/write.js');
  const grants = [{ role: 'domain_master', data_schema: 'public', zone_name: 'example.test', name_suffix: null, policy: { allowed_types: ['A'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 0, ttl_max: 9999, max_rr: null } }];
  const doc = (dry) => JSON.stringify({ 'karidns-zone': 1, messages: [], apply: { dry_run: dry, generation: 3, generation_after: 4, serial: { before: 1, after: 2 }, version: 2, records_before: 5, records_after: 5, diff: [{ owner: 'www.example.test.', type: 'A', change: 'replace', before: ['300 A 192.0.2.1'], after: ['300 A 192.0.2.2'] }] } });
  const w = writeCtx(grants, [ZONE_FACTS], { body: { reload: true, rrsets: [{ name: 'www.example.test', type: 'A', changetype: 'REPLACE', ttl: 300, records: [{ content: '192.0.2.2' }] }] } });
  w.app.run = async (file, argv) => { w.calls.push([file, argv]); return { code: 0, stdout: doc(argv.includes('--dry-run')), stderr: '' }; };
  const r = await rrsetsPatch(w.ctx);
  assert.equal(r.reload, 'requested');
  const [check, commit] = w.calls.filter((c) => c[0] !== 'tx').map((c) => c[1]);
  assert.deepEqual(check.slice(3, 8), ['--no-config', '--conninfo-file', '/b', '--schema', 'public']);
  assert.deepEqual(commit.slice(2, 7), ['--no-config', '--conninfo-file', '/a', '--schema', 'public']);
  assert.ok(commit.includes('--reload') && !check.includes('--reload'));
  // a signer zone: no --reload, the signer asks
  const s = writeCtx(grants, [[ZONE_FACTS[0], [{ id: 8, name: 'example.test', type: 'NATIVE', catalog: null, presigned: true, signer: true }]]].map(([re, rows]) => [re, rows]), { body: w.ctx.body });
  s.app.run = async (file, argv) => { s.calls.push([file, argv]); return { code: 0, stdout: doc(argv.includes('--dry-run')), stderr: '' }; };
  assert.equal((await rrsetsPatch(s.ctx)).reload, 'waiting for the signer');
  assert.ok(!s.calls.filter((c) => c[0] !== 'tx').some((c) => c[1].includes('--reload')));
});

test('a page of RRsets is two statements: the keys, then the records of those names (no self join that row level security would test row by row)', async () => {
  const tx = fakeTx([
    [/GROUP BY k\.name/, [{ name: 'a.example.test', type: 'A' }, { name: 'a.example.test', type: 'TXT' }, { name: 'b.example.test', type: 'A' }]],
    [/FROM "public"\.records r/, [
      { id: 1, name: 'a.example.test', type: 'A', ttl: 300, content: '192.0.2.1', prio: 0, disabled: false },
      { id: 2, name: 'a.example.test', type: 'MX', ttl: 300, content: 'mail', prio: 10, disabled: false },
      { id: 3, name: 'a.example.test', type: 'TXT', ttl: 300, content: '"x"', prio: 0, disabled: false },
      { id: 4, name: 'b.example.test', type: 'A', ttl: 60, content: '192.0.2.2', prio: 0, disabled: true },
    ]],
  ]);
  const rows = await S.listRRsets(tx, 'public', 7, { zone: 'example.test', visibility: null, limit: 2 });
  assert.equal(tx.log.length, 2);
  assert.match(tx.log[0][0], /^SELECT k\.name, upper\(k\.type\) AS type FROM "public"\.records k WHERE k\.domain_id = \$1 .* GROUP BY k\.name, upper\(k\.type\) ORDER BY k\.name, upper\(k\.type\) LIMIT \$\d+$/);
  assert.equal(tx.log[0][1].at(-1), 3, 'one more than the page');
  assert.match(tx.log[1][0], /^SELECT r\.id, r\.name, upper\(r\.type\) AS type, .* FROM "public"\.records r WHERE r\.domain_id = \$1 AND r\.name = ANY\(\$2::text\[\]\) ORDER BY r\.name, upper\(r\.type\), r\.id$/);
  assert.deepEqual(tx.log[1][1], [7, ['a.example.test', 'b.example.test']]);
  assert.deepEqual(rows.map((r) => `${r.id} ${r.name} ${r.type}`), ['1 a.example.test A', '3 a.example.test TXT', '4 b.example.test A'], 'the MX of the same name was not asked for');
  assert.equal(rows[2].disabled, true);
  // nothing found: one statement
  const none = fakeTx([[/GROUP BY k\.name/, []]]);
  assert.deepEqual(await S.listRRsets(none, 'public', 7, { zone: 'example.test', visibility: null, limit: 5 }), []);
  assert.equal(none.log.length, 1);
});

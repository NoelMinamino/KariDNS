// datasets, zones, RRsets, export, audit, servers, health: the read side, through the HTTP server, on SQLite3

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { deploy, cast, sqlite } from './helpers.js';

const withCast = (fn, opts) => async () => {
  const d = await deploy(opts);
  try {
    const c = await cast(d);
    const root = d.as(await d.login('root', 'correct horse battery'));
    const dom = d.as(await d.login('dom', 'dom password 12345'));
    const sub = d.as(await d.login('sub', 'sub password 12345'));
    await fn(d, { ...c, root, dom, sub });
  } finally {
    await d.close();
  }
};
const is = (r, status, type) => {
  assert.equal(r.status, status, JSON.stringify(r.body));
  if (type) assert.equal(r.body.type, `urn:karidns:api:${type}`, JSON.stringify(r.body));
};
const names = (r) => r.body.rrsets.map((s) => `${s.name} ${s.type}`);

test('datasets', withCast(async (d, { sub }) => {
  const r = await sub('GET', '/datasets');
  assert.deepEqual(r.body.datasets, [{ name: 'main', driver: 'sqlite3', views: [] }]);
}));

test('the zone list: only the zones a principal has a grant on', withCast(async (d, { root, dom, sub }) => {
  const all = await root('GET', '/datasets/main/zones');
  assert.deepEqual(all.body.zones.map((z) => [z.name, z.kind, z.serial, z.presigned, z.role]), [
    ['example.test.', 'NATIVE', 10, false, 'global_master'], ['other.test.', 'NATIVE', 5, true, 'global_master'], ['slave.test.', 'SLAVE', null, false, 'global_master'],
  ]);
  assert.deepEqual((await dom('GET', '/datasets/main/zones')).body.zones.map((z) => [z.name, z.role]), [['example.test.', 'domain_master']]);
  assert.deepEqual((await sub('GET', '/datasets/main/zones')).body.zones.map((z) => [z.name, z.role]), [['example.test.', 'subdomain_master']]);
  // filters and paging
  assert.deepEqual((await root('GET', '/datasets/main/zones?kind=SLAVE')).body.zones.map((z) => z.name), ['slave.test.']);
  assert.deepEqual((await root('GET', '/datasets/main/zones?prefix=oth')).body.zones.map((z) => z.name), ['other.test.']);
  assert.deepEqual((await root('GET', '/datasets/main/zones?signed=true')).body.zones.map((z) => z.name), ['other.test.']);
  assert.deepEqual((await root('GET', '/datasets/main/zones?signed=false')).body.zones.map((z) => z.name), ['example.test.', 'slave.test.']);
  const p1 = await root('GET', '/datasets/main/zones?limit=2');
  assert.deepEqual(p1.body.zones.map((z) => z.name), ['example.test.', 'other.test.']);
  assert.deepEqual((await root('GET', `/datasets/main/zones?limit=2&cursor=${p1.body.next_cursor}`)).body.zones.map((z) => z.name), ['slave.test.']);
  is(await root('GET', '/datasets/main/zones?kind=BOGUS'), 400, 'bad-request');
  is(await root('GET', '/datasets/main/zones?cursor=e30'), 400, 'bad-request');
  is(await root('GET', '/datasets/main/zones?prefix=a%20b'), 400, 'bad-request');
  is(await root('GET', '/datasets/nowhere/zones'), 404, 'not-found');
  // a principal with no grant sees an empty list, not an error
  const nobody = await d.makeUser('nobody', 'nobody password 12');
  assert.ok(nobody);
  const n = d.as(await d.login('nobody', 'nobody password 12'));
  assert.deepEqual((await n('GET', '/datasets/main/zones')).body, { api: 1, zones: [], next_cursor: null });
}));

test('zone info: 404 for a zone without a grant, whether it exists or not', withCast(async (d, { root, dom, sub }) => {
  const z = (await dom('GET', '/datasets/main/zones/example.test.')).body.zone;
  assert.equal(z.name, 'example.test.');
  assert.equal(z.kind, 'NATIVE');
  assert.equal(z.serial, 10);
  assert.ok(z.generation >= 1);
  assert.equal(z.role, 'domain_master');
  assert.deepEqual(z.views, []);
  assert.equal(z.signer_state, null);
  assert.equal(z.waiting_for_signer, false);
  assert.equal(z.last_reload_request, null);
  assert.equal(z.grants.length, 1);
  assert.equal(z.grants[0].policy.name, 'web');
  assert.equal((await sub('GET', '/datasets/main/zones/EXAMPLE.test')).body.zone.role, 'subdomain_master');
  const hidden = await dom('GET', '/datasets/main/zones/other.test');
  is(hidden, 404, 'not-found');
  const missing = await dom('GET', '/datasets/main/zones/ghost.test');
  is(missing, 404, 'not-found');
  assert.equal(hidden.body.detail, missing.body.detail, 'the same answer');
  is(await root('GET', '/datasets/main/zones/ghost.test'), 404, 'not-found');
  is(await root('GET', '/datasets/main/zones/bad%20zone'), 400, 'bad-request');
  is(await root('GET', '/datasets/main/zones/bad%2Fzone'), 400, 'bad-request');
  is(await root('GET', '/datasets/nowhere/zones/example.test'), 404, 'not-found');
  // a presigned zone, views, a signer zone and its state
  const o = (await root('GET', '/datasets/main/zones/other.test')).body.zone;
  assert.equal(o.presigned, true);
  d.backend.db.exec(`INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'internal'), (1, 'external');
    INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'X-KARIDNS-SIGNER', '1'), (1, 'NSEC3PARAM', '1 0 0 -');
    INSERT INTO karidns_signer_state (domain_id, signed_at, signed_serial, min_expire, next_due, attempts, last_error) VALUES (1, '2026-11-08T01:00:00Z', 9, '2026-11-20T00:00:00Z', '2026-11-12T00:00:00Z', 2, 'oops')`);
  const s = (await root('GET', '/datasets/main/zones/example.test')).body.zone;
  assert.deepEqual(s.views, ['external', 'internal']);
  assert.equal(s.signer, true);
  assert.equal(s.nsec3param, '1 0 0 -');
  assert.equal(s.waiting_for_signer, true);                     // signed_serial 9, the zone's serial 10
  assert.deepEqual(s.signer_state, { signed_at: '2026-11-08T01:00:00Z', signed_serial: 9, min_expire: '2026-11-20T00:00:00Z', next_due: '2026-11-12T00:00:00Z', attempts: 2, last_error: 'oops', last_duration_ms: null });
  d.backend.db.exec('UPDATE karidns_signer_state SET signed_serial = 10');
  assert.equal((await root('GET', '/datasets/main/zones/example.test')).body.zone.waiting_for_signer, false);
}));

test('RRsets: a domain master reads the zone, a subdomain master its names and the apex SOA and NS', withCast(async (d, { root, dom, sub }) => {
  const r = await dom('GET', '/datasets/main/zones/example.test/rrsets');
  assert.deepEqual(names(r), [
    'a.sub.example.test. TXT', 'evilsub.example.test. A', 'example.test. MX', 'example.test. NS', 'example.test. SOA', 'ns1.example.test. A', 'off.example.test. A', 'sub.example.test. A', 'www.example.test. A',
  ]);
  const www = r.body.rrsets.find((s) => s.name === 'www.example.test.');
  assert.deepEqual(www, { name: 'www.example.test.', type: 'A', ttl: 300, records: [{ content: '192.0.2.10', disabled: false, ttl: 300 }, { content: '192.0.2.11', disabled: false, ttl: 300 }] });
  assert.equal(r.body.rrsets.find((s) => s.type === 'MX').records[0].content, '10 mail.example.test', 'the priority is part of the content');
  assert.equal(r.body.rrsets.find((s) => s.name === 'off.example.test.').records[0].disabled, true);
  assert.equal(r.body.next_cursor, null);
  assert.deepEqual(names(await sub('GET', '/datasets/main/zones/example.test/rrsets')), ['a.sub.example.test. TXT', 'example.test. NS', 'example.test. SOA', 'sub.example.test. A']);
  assert.deepEqual(names(await sub('GET', '/datasets/main/zones/example.test/rrsets?name=evilsub.example.test')), []);
  assert.deepEqual(names(await sub('GET', '/datasets/main/zones/example.test/rrsets?name=example.test&type=mx')), []);
  assert.deepEqual(names(await sub('GET', '/datasets/main/zones/example.test/rrsets?name=sub.example.test.')), ['sub.example.test. A']);
  // filters
  assert.deepEqual(names(await root('GET', '/datasets/main/zones/example.test/rrsets?type=a&limit=100')).length, 5);
  assert.deepEqual(names(await root('GET', '/datasets/main/zones/example.test/rrsets?name=WWW.example.test.')), ['www.example.test. A']);
  assert.deepEqual(names(await root('GET', '/datasets/main/zones/example.test/rrsets?name=example.test&type=SOA')), ['example.test. SOA']);
  assert.deepEqual(names(await root('GET', '/datasets/main/zones/example.test/rrsets?name=nothing.example.test')), []);
  is(await root('GET', '/datasets/main/zones/example.test/rrsets?name=www.other.test'), 400, 'bad-request');
  is(await root('GET', '/datasets/main/zones/example.test/rrsets?name=bad%20name'), 400, 'bad-request');
  is(await root('GET', '/datasets/main/zones/example.test/rrsets?type=A%20B'), 400, 'bad-request');
  is(await root('GET', '/datasets/main/zones/example.test/rrsets?limit=0'), 400, 'bad-request');
  is(await root('GET', '/datasets/main/zones/example.test/rrsets?cursor=e30'), 400, 'bad-request');
  // no grant, no such zone (even for a global master)
  is(await dom('GET', '/datasets/main/zones/other.test/rrsets'), 404, 'not-found');
  is(await root('GET', '/datasets/main/zones/ghost.test/rrsets'), 404, 'not-found');
}));

test('RRsets: paging by RRset, the same sets in every page, none twice', withCast(async (d, { root, sub }) => {
  const seen = [];
  let cursor = '';
  let pages = 0;
  for (;;) {
    const r = await root('GET', `/datasets/main/zones/example.test/rrsets?limit=2${cursor}`);
    is(r, 200);
    assert.ok(r.body.rrsets.length <= 2);
    seen.push(...names(r));
    pages++;
    if (!r.body.next_cursor) break;
    cursor = `&cursor=${r.body.next_cursor}`;
  }
  assert.equal(pages, 5);
  assert.equal(seen.length, 9);
  assert.equal(new Set(seen).size, 9);
  assert.deepEqual(seen, [...seen].sort());
  // a subdomain master's pages hold what it may see
  const first = await sub('GET', '/datasets/main/zones/example.test/rrsets?limit=3');
  assert.deepEqual(names(first), ['a.sub.example.test. TXT', 'example.test. NS', 'example.test. SOA']);
  assert.deepEqual(names(await sub('GET', `/datasets/main/zones/example.test/rrsets?limit=3&cursor=${first.body.next_cursor}`)), ['sub.example.test. A']);
}));

test('RRsets: SRV with its priority in a column, records with different TTLs, a content that has the priority already', withCast(async (d, { root }) => {
  d.backend.db.exec(`INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES
    (1, '_sip._tcp.example.test', 'SRV', '5 5060 sip.example.test', 300, 10, 0),
    (1, '_sip._tcp.example.test', 'SRV', '10 20 5060 sip2.example.test', 600, 0, 0),
    (1, 'n.example.test', 'A', '192.0.2.99', NULL, 0, 0)`);
  const r = await root('GET', '/datasets/main/zones/example.test/rrsets?type=SRV');
  const srv = r.body.rrsets[0];
  assert.equal(srv.ttl, 300);
  assert.deepEqual(srv.records.map((x) => x.content), ['10 5 5060 sip.example.test', '10 20 5060 sip2.example.test']);
  assert.equal((await root('GET', '/datasets/main/zones/example.test/rrsets?name=n.example.test')).body.rrsets[0].ttl, null);
}));

test('the export: karidns-zone export through the argv, text/plain', async () => {
  const calls = [];
  const run = async (file, argv, opts) => {
    calls.push([file, argv, opts]);
    if (argv.at(-1) === 'bad') return { code: 1, stdout: '', stderr: 'boom', truncated: false, timedOut: false, spawnError: null };
    return { code: 0, stdout: '$ORIGIN example.test.\n@ IN SOA ns1 h 10 1 1 1 1\n', stderr: '', truncated: false, timedOut: false, spawnError: null };
  };
  const d = await deploy({ run });
  try {
    await cast(d);
    const root = d.as(await d.login('root', 'correct horse battery'));
    const dom = d.as(await d.login('dom', 'dom password 12345'));
    const sub = d.as(await d.login('sub', 'sub password 12345'));
    const ok = await dom('GET', '/datasets/main/zones/Example.TEST./export');
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('content-type'), 'text/plain; charset=utf-8');
    assert.equal(ok.headers.get('content-disposition'), 'attachment; filename="example.test.zone"');
    assert.equal(ok.headers.get('x-content-type-options'), 'nosniff');
    assert.match(ok.text, /^\$ORIGIN example\.test\./);
    assert.deepEqual(calls[0][1], ['export', '--no-config', '--sqlite3', path.join(d.dir, 'zones.sqlite3'), 'example.test']);
    assert.equal(calls[0][0], d.app.settings['karidns-zone']);
    is(await sub('GET', '/datasets/main/zones/example.test/export'), 403, 'forbidden');
    is(await dom('GET', '/datasets/main/zones/other.test/export'), 404, 'not-found');
    assert.equal((await root('GET', '/datasets/main/zones/example.test/export')).status, 200);
    // failures: the zone is not there, anything else (logged, the answer says nothing)
    run.next = null;
    const fail = (result) => { d.app.run = async () => result; };
    fail({ code: 1, stdout: '', stderr: 'karidns-zone: example.test: no such zone', truncated: false, timedOut: false, spawnError: null });
    is(await root('GET', '/datasets/main/zones/example.test/export'), 404, 'not-found');
    fail({ code: 1, stdout: '', stderr: 'karidns-zone: cannot open the database: boom', truncated: false, timedOut: false, spawnError: null });
    const e = await root('GET', '/datasets/main/zones/example.test/export');
    is(e, 500, 'internal');
    assert.equal(JSON.stringify(e.body).includes('boom'), false);
    assert.ok(d.log.lines.some((l) => /^error [0-9a-f]{16}: karidns-zone export example\.test failed \(status 1\): karidns-zone: cannot open the database: boom/.test(l)));
    for (const bad of [{ spawnError: 'ENOENT' }, { timedOut: true }, { truncated: true }]) {
      fail({ code: 0, stdout: '', stderr: '', truncated: false, timedOut: false, spawnError: null, ...bad });
      is(await root('GET', '/datasets/main/zones/example.test/export'), 500, 'internal');
    }
  } finally {
    await d.close();
  }
});

test('the audit log: a global master reads all, a domain master the rows of its zone, newest first, paged', withCast(async (d, { root, dom, sub }) => {
  await root('POST', '/principals', { body: { kind: 'group', name: 'audited' } });
  const a = await root('GET', '/audit?limit=500');
  assert.ok(a.body.audit.length > 10);
  const ids = a.body.audit.map((r) => r.at);
  assert.deepEqual(ids, [...ids].sort().reverse(), 'newest first');
  const created = a.body.audit.find((r) => r.table === 'principals' && r.after?.name === 'audited');
  assert.equal(created.principal, 'root');
  assert.equal(created.op, 'I');
  assert.equal(created.source, 'auth');
  assert.equal(created.db_role, 'karidns-webadmin');
  assert.equal(JSON.stringify(a.body).includes('password_hash\":\"$'), false, 'no hash in the log');
  assert.ok(a.body.audit.some((r) => r.table === 'credentials' && r.after?.password_hash === '<redacted>'));
  assert.ok(a.body.audit.some((r) => r.source === 'zone' && r.zone === 'example.test.'));
  // filters
  assert.ok((await root('GET', '/audit?table=principals&limit=500')).body.audit.every((r) => r.table === 'principals'));
  assert.ok((await root('GET', '/audit?zone=example.test&limit=500')).body.audit.every((r) => r.zone === 'example.test.'));
  assert.ok((await root('GET', '/audit?principal=1&limit=500')).body.audit.every((r) => r.principal_id === 1));
  assert.equal((await root('GET', '/audit?change_set=nothing')).body.audit.length, 0);
  assert.equal((await root('GET', '/audit?since=2999-01-01T00:00:00Z')).body.audit.length, 0);
  assert.ok((await root('GET', '/audit?until=2999-01-01T00:00:00Z')).body.audit.length > 0);
  is(await root('GET', '/audit?since=yesterday'), 400, 'bad-request');
  is(await root('GET', '/audit?until=x'), 400, 'bad-request');
  is(await root('GET', '/audit?zone=bad%20zone'), 400, 'bad-request');
  is(await root('GET', '/audit?cursor=e30'), 400, 'bad-request');
  // paging walks the merged log once
  const seen = [];
  let cursor = '';
  for (let i = 0; i < 200; i++) {
    const p = await root('GET', `/audit?limit=7${cursor}`);
    seen.push(...p.body.audit.map((r) => `${r.source}:${r.id}`));
    if (!p.body.next_cursor) break;
    cursor = `&cursor=${p.body.next_cursor}`;
  }
  assert.equal(seen.length, a.body.audit.length);
  assert.equal(new Set(seen).size, seen.length);
  // a domain master: the rows of its zone only (the zone's data rows, the grants on the zone); a subdomain master none
  const mine = await dom('GET', '/audit?limit=500');
  assert.ok(mine.body.audit.length > 0);
  assert.ok(mine.body.audit.every((r) => r.zone === 'example.test.'), JSON.stringify(mine.body.audit.map((r) => r.zone)));
  assert.ok(mine.body.audit.some((r) => r.table === 'grants'));
  assert.deepEqual((await sub('GET', '/audit?limit=500')).body.audit, []);
  const small = await dom('GET', '/audit?limit=2');
  assert.equal(small.body.audit.length, 2);
  assert.ok(small.body.next_cursor);
}));

test('the audit log: rows of the same second in both files are walked once, in the same order, whatever the page size', withCast(async (d, { root }) => {
  const at = '2030-01-01T00:00:00Z';
  const rows = (n) => Array.from({ length: n }, (_, i) => `('${at}', 'records', 'I', 'example.test', ${i + 1})`).join(', ');
  d.backend.db.exec(`INSERT INTO karidns_audit_log (at, table_name, op, zone_name, row_id) VALUES ${rows(5)};
    INSERT INTO auth.karidns_auth_audit (at, table_name, op, zone_name, row_id) VALUES ${rows(4)}`);
  const walk = async (limit) => {
    const seen = [];
    let cursor = '';
    for (let i = 0; i < 500; i++) {
      const p = await root('GET', `/audit?limit=${limit}${cursor}`);
      seen.push(...p.body.audit.map((r) => `${r.at} ${r.source}:${r.id}`));
      if (!p.body.next_cursor) break;
      cursor = `&cursor=${p.body.next_cursor}`;
    }
    return seen;
  };
  const all = await walk(500);
  assert.equal(new Set(all).size, all.length);
  assert.deepEqual(all.slice(0, 9).map((s) => s.replace(/\d+$/, '')), [`${at} zone:`, `${at} zone:`, `${at} zone:`, `${at} zone:`, `${at} zone:`, `${at} auth:`, `${at} auth:`, `${at} auth:`, `${at} auth:`]);
  for (const limit of [1, 2, 3, 4, 5, 7, 9, 10]) assert.deepEqual(await walk(limit), all, `page size ${limit}`);
}));

test('the audit log: a page of rows nobody may see is skipped, not shown', withCast(async (d, { sub }) => {
  const r = await sub('GET', '/audit?limit=1');
  assert.deepEqual(r.body.audit, []);
  assert.equal(r.body.next_cursor, null);
}));

test('servers: SQLite3 has no status table', withCast(async (d, { root, sub }) => {
  const r = await root('GET', '/servers');
  assert.deepEqual(r.body.servers, []);
  assert.match(r.body.note, /karictl status/);
  assert.deepEqual((await sub('GET', '/servers')).body.servers, []);
}));

test('health needs no login and says when the database is gone; /version needs one', withCast(async (d, { sub }) => {
  const h = await d.request('GET', '/health');
  assert.deepEqual(h.body, { api: 1, status: 'ok', database: 'ok' });
  d.app.versions = { karicheck: 'karicheck 0.6.0' };
  const v = await sub('GET', '/version');
  assert.deepEqual(v.body, { api: 1, version: '0.6.0', tools: { karicheck: 'karicheck 0.6.0' }, datasets: ['main'] });
  is(await d.request('GET', '/version'), 401, 'unauthenticated');
  const sql = new sqlite.DatabaseSync(':memory:');
  assert.ok(sql);
  const real = d.backend.tx;
  d.backend.tx = () => Promise.reject(new Error('the database is gone'));
  const gone = await d.request('GET', '/health');
  assert.equal(gone.status, 503);
  assert.deepEqual(gone.body, { api: 1, status: 'unavailable', database: 'error' });
  d.backend.tx = real;
}));

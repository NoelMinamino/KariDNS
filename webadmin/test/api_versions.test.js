// Zone versions and templates through the HTTP server over SQLite3 (E, planning 5 and 6): the list with the marker for changes outside the versions, a version's delta,
// the diff between two versions and against the zone, the rollback (conflicts, force, permissions, signer zones), template CRUD with the karicheck validation, a zone made
// from a template and a template applied to a zone.  karidns-zone and karicheck are scripted here; the real ones run in tests/run_webadmin_versions_test.sh.

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast, makeRun, ok, exit, applyDoc, entry } from './helpers.js';

const KZ = '/opt/karidns-zone';
const KCK = '/opt/karicheck';
const KCTL = '/opt/karictl';
const CTL_CONF = '/opt/ctl.conf';
const V = '/datasets/main/zones/example.test/versions';

const withTools = (handler, fn, settings = {}) => async () => {
  const t = makeRun(handler);
  const d = await deploy({ run: t.run, settings: { 'karidns-zone': KZ, karicheck: KCK, karictl: KCTL, ...settings } });
  d.app.sleep = async () => {};
  try {
    const c = await cast(d);
    const as = async (u, p) => d.as(await d.login(u, p));
    const root = await as('root', 'correct horse battery');
    const dom = await as('dom', 'dom password 12345');
    const sub = await as('sub', 'sub password 12345');
    try {
      await fn(d, { ...c, root, dom, sub }, t);
    } catch (e) {
      const errors = d.log.lines.filter((l) => /^(error|warn) /.test(l));
      if (errors.length) e.message += `\nthe server logged: ${errors.join(' | ').slice(0, 800)}`;
      throw e;
    }
  } finally {
    await d.close();
  }
};
const is = (r, status, type) => {
  assert.equal(r.status, status, JSON.stringify(r.body));
  if (type) assert.equal(r.body.type, `urn:karidns:api:${type}`, JSON.stringify(r.body));
};
const sql = (d, text, params = []) => d.backend.tx({}, (tx) => tx.all(text, params));
const run = (d, text, params = []) => d.backend.tx({ write: true }, (tx) => tx.run(text, params));
const A = (...ips) => ips.map((ip) => `300 A ${ip}`).join('\n');
const soa = (serial, refresh = 7200) => `3600 SOA ns1.example.test. hostmaster.example.test. ${serial} ${refresh} 3600 1209600 300`;

// One version of example.test (id 1) with its RRsets: rows = [[owner, type, before, after]].  The time is a day of 2020 (or `at`), so that the audit rows made while the
// test runs lie after it.
async function addVersion(d, n, over = {}, rows = []) {
  const v = {
    kind: 'edit', change_set: `cs-${n}`, principal_id: null, principal_name: null, db_role: 'karidns-webadmin', at: `2020-01-0${n}T00:00:00Z`, comment: null, serial_before: 9 + n,
    serial_after: 10 + n, generation_before: 0, generation_after: 0, rollback_of: null, delta_complete: 1, ...over,
  };
  await run(d, `INSERT INTO karidns_zone_versions (domain_id, version, kind, change_set, principal_id, principal_name, db_role, at, comment, serial_before, serial_after,
                generation_before, generation_after, rollback_of, delta_complete) VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
  [n, v.kind, v.change_set, v.principal_id, v.principal_name, v.db_role, v.at, v.comment, v.serial_before, v.serial_after, v.generation_before, v.generation_after, v.rollback_of, v.delta_complete]);
  const id = (await sql(d, 'SELECT id FROM karidns_zone_versions WHERE domain_id = 1 AND version = $1', [n]))[0].id;
  for (const [owner, type, before, after] of rows) await run(d, 'INSERT INTO karidns_zone_version_rrsets (version_id, owner, type, before, after) VALUES ($1, $2, $3, $4, $5)', [id, owner, type, before, after]);
}

// The history of the tests: 1 (an import by an operator), 2 (the domain master), 3 (a global master; a gap in the generation before it).
async function history(d, { gap = true, lastAt } = {}) {
  const dom = (await sql(d, "SELECT id FROM auth.principals WHERE name = 'dom'"))[0].id;
  const root = (await sql(d, "SELECT id FROM auth.principals WHERE name = 'root'"))[0].id;
  await addVersion(d, 1, { kind: 'import', change_set: null, generation_before: 0, generation_after: 10, serial_before: null, serial_after: 10, comment: 'the first import' }, [
    ['www.example.test', 'A', null, A('192.0.2.10', '192.0.2.11')], ['sub.example.test', 'A', null, A('192.0.2.20')], ['a.sub.example.test', 'TXT', null, '300 TXT "hello"'], ['example.test', 'SOA', null, soa(10)],
  ]);
  await addVersion(d, 2, { principal_id: dom, principal_name: 'dom', generation_before: 10, generation_after: 12, comment: 'move www' }, [
    ['www.example.test', 'A', A('192.0.2.10', '192.0.2.11'), A('192.0.2.50')], ['new.example.test', 'A', null, A('192.0.2.60')], ['a.sub.example.test', 'TXT', '300 TXT "hello"', '300 TXT "bye"'],
  ]);
  await addVersion(d, 3, { principal_id: root, principal_name: 'root', generation_before: gap ? 14 : 12, generation_after: gap ? 15 : 13, ...(lastAt ? { at: lastAt } : {}) }, [
    ['www.example.test', 'A', A('192.0.2.50'), A('192.0.2.51')], ['x.sub.example.test', 'A', null, A('192.0.2.70')], ['example.test', 'SOA', soa(11), soa(12, 100)],
  ]);
}
const generation = async (d) => Number((await sql(d, 'SELECT generation AS g FROM karidns_zone_state WHERE domain_id = 1'))[0].g);

// ---------------------------------------------------------------------------------------------------------------------------------- the list and one version
test('the versions of a zone: newest first, who, when, the RRsets each changed; paged', withTools(() => exit(0), async (d, { root, dom, sub }) => {
  await history(d, { gap: false });
  await run(d, 'UPDATE karidns_zone_state SET generation = 13 WHERE domain_id = 1');
  const r = await root('GET', V);
  is(r, 200);
  assert.deepEqual(r.body.versions.map((v) => [v.version, v.kind, v.rrsets, v.principal?.name ?? null]), [[3, 'edit', 3, 'root'], [2, 'edit', 3, 'dom'], [1, 'import', 4, null]]);
  assert.deepEqual(r.body.versions[1], {
    version: 2, kind: 'edit', at: '2020-01-02T00:00:00Z', principal: { id: r.body.versions[1].principal.id, name: 'dom' }, db_role: 'karidns-webadmin', change_set: 'cs-2', comment: 'move www',
    serial: { before: 11, after: 12 }, generation: { before: 10, after: 12 }, rollback_of: null, delta_complete: true, rrsets: 3, changed_outside_before: null,
  });
  assert.equal(r.body.changed_outside_since, null);
  assert.equal(r.body.next_cursor, null);
  // pages: limit 2 gives the newest two and a cursor for the rest
  const p1 = await root('GET', `${V}?limit=2`);
  assert.deepEqual(p1.body.versions.map((v) => v.version), [3, 2]);
  assert.ok(p1.body.next_cursor);
  const p2 = await root('GET', `${V}?limit=2&cursor=${p1.body.next_cursor}`);
  assert.deepEqual([p2.body.versions.map((v) => v.version), p2.body.next_cursor, p2.body.changed_outside_since], [[1], null, undefined]);
  is(await root('GET', `${V}?cursor=!`), 400, 'bad-request');
  is(await root('GET', `${V}?cursor=${Buffer.from('{"v":0}').toString('base64url')}`), 400, 'bad-request');
  // a domain master sees the same; a subdomain master the part of each delta under its suffix (and the apex SOA and NS), no markers
  assert.deepEqual((await dom('GET', V)).body.versions.map((v) => v.rrsets), [3, 3, 4]);
  const s = await sub('GET', V);
  assert.deepEqual(s.body.versions.map((v) => [v.version, v.rrsets]), [[3, 2], [2, 1], [1, 3]]);
  assert.ok(s.body.versions.every((v) => !('changed_outside_before' in v)) && !('changed_outside_since' in s.body));
  // no zone, no grant, no history
  is(await root('GET', '/datasets/main/zones/ghost.test/versions'), 404, 'not-found');
  is(await sub('GET', '/datasets/main/zones/other.test/versions'), 404, 'not-found');
  assert.deepEqual((await root('GET', '/datasets/main/zones/other.test/versions')).body.versions, []);
}));

test('one version: its delta, paged; a subdomain master sees its part; a version that is not there is 404', withTools(() => exit(0), async (d, { root, sub }) => {
  await history(d);
  const r = await root('GET', `${V}/2`);
  is(r, 200);
  assert.equal(r.body.version.version, 2);
  assert.equal(r.body.version.rrsets, 3);
  assert.deepEqual(r.body.rrsets, [
    { name: 'a.sub.example.test.', type: 'TXT', change: 'replace', before: [{ ttl: 300, content: '"hello"' }], after: [{ ttl: 300, content: '"bye"' }] },
    { name: 'new.example.test.', type: 'A', change: 'add', before: null, after: [{ ttl: 300, content: '192.0.2.60' }] },
    { name: 'www.example.test.', type: 'A', change: 'replace', before: [{ ttl: 300, content: '192.0.2.10' }, { ttl: 300, content: '192.0.2.11' }], after: [{ ttl: 300, content: '192.0.2.50' }] },
  ]);
  const p1 = await root('GET', `${V}/2?limit=2`);
  assert.deepEqual(p1.body.rrsets.map((x) => x.name), ['a.sub.example.test.', 'new.example.test.']);
  const p2 = await root('GET', `${V}/2?limit=2&cursor=${p1.body.next_cursor}`);
  assert.deepEqual([p2.body.rrsets.map((x) => x.name), p2.body.next_cursor], [['www.example.test.'], null]);
  const s = await sub('GET', `${V}/2`);
  assert.deepEqual([s.body.version.rrsets, s.body.rrsets.map((x) => x.name)], [1, ['a.sub.example.test.']]);
  assert.deepEqual((await sub('GET', `${V}/3`)).body.rrsets.map((x) => x.name), ['example.test.', 'x.sub.example.test.'], 'the apex SOA is visible to everybody with a grant on the zone');
  is(await root('GET', `${V}/9`), 404, 'not-found');
  is(await root('GET', `${V}/two`), 404, 'not-found');
  is(await root('GET', '/datasets/main/zones/ghost.test/versions/1'), 404, 'not-found');
  is(await root('GET', `${V}/2?surprise=1`), 400, 'bad-request');
  // a version too big to keep its RRsets says so
  await run(d, 'UPDATE karidns_zone_versions SET delta_complete = 0 WHERE version = 3');
  const big = await root('GET', `${V}/3`);
  assert.deepEqual([big.body.version.delta_complete, big.body.rrsets.length > 0], [false, true]);
}));

test('a change outside the versions: the generation grew and the audit log says what; the signer re-signing is no change', withTools(() => exit(0), async (d, { root, dom }) => {
  const marker = async (as = root) => (await as('GET', V)).body;
  await run(d, 'DELETE FROM karidns_audit_log');
  // what the signer does: signatures, the NSEC chain, ordername / auth of every record, the serial of the SOA
  await run(d, "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES (1, 'example.test', 'RRSIG', 'x', 300, 0, 0), (1, 'www.example.test', 'NSEC', 'y', 300, 0, 0)");
  await run(d, "UPDATE records SET ordername = 'abc', auth = 1 WHERE name = 'www.example.test' AND type = 'A'");
  await run(d, "UPDATE records SET content = 'ns1.example.test hostmaster.example.test 11 7200 3600 1209600 300' WHERE type = 'SOA' AND domain_id = 1");
  await run(d, "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'NSEC3PARAM', '1 0 5 -')");
  assert.ok((await sql(d, "SELECT count(*) AS n FROM karidns_audit_log WHERE zone_name = 'example.test'"))[0].n >= 6, 'the audit log saw them');
  await history(d, { lastAt: '2099-01-01T00:00:00Z' });
  await run(d, `UPDATE karidns_zone_versions SET generation_after = ${await generation(d)} WHERE version = 3`);
  let b = await marker();
  assert.deepEqual(b.versions.map((v) => v.changed_outside_before), [null, null, null], 'a gap that only the signer explains is no marker');
  assert.equal(b.changed_outside_since, null);
  // somebody changes a record with SQL: the gap before version 3 is no longer unexplained
  await run(d, "UPDATE records SET content = '192.0.2.99' WHERE name = 'www.example.test' AND content = '192.0.2.10'");
  await run(d, "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES (1, 'sneaky.example.test', 'A', '192.0.2.98', 300, 0, 0)");
  b = await marker();
  assert.deepEqual(b.versions[0].changed_outside_before, { basis: 'audit', count: 2, rrsets: [{ name: 'www.example.test.', type: 'A' }, { name: 'sneaky.example.test.', type: 'A' }] });
  assert.equal(b.versions[1].changed_outside_before, null);
  assert.equal(b.versions[2].changed_outside_before, null);
  // the generation after the newest version has moved too: "since the newest version"
  await run(d, "UPDATE karidns_zone_versions SET generation_after = 1, at = '2020-01-03T00:00:00Z' WHERE version = 3");
  b = await marker();
  assert.deepEqual(b.changed_outside_since, { basis: 'audit', count: 2, rrsets: [{ name: 'www.example.test.', type: 'A' }, { name: 'sneaky.example.test.', type: 'A' }] });
  // the change sets of the versions are not outside changes: the rows of version 3's own change set are in the same window
  await run(d, "UPDATE karidns_audit_log SET change_set = 'cs-3'");
  b = await marker();
  assert.deepEqual(b.changed_outside_since, { basis: 'generation', count: null, rrsets: [] }, 'nothing but the version\'s own rows: the generation moved and the log has nothing to say about it');
  // ... and the signer's rows beside them explain it: the log has something to say, and it is no change of the RRsets
  await run(d, "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES (1, 'www.example.test', 'RRSIG', 'x', 300, 0, 0)");
  b = await marker();
  assert.equal(b.changed_outside_since, null);
  // an audit log that has no row of the zone in the window cannot say: the generation alone is the marker
  await run(d, 'DELETE FROM karidns_audit_log');
  b = await marker();
  assert.deepEqual([b.versions[0].changed_outside_before, b.changed_outside_since], [{ basis: 'generation', count: null, rrsets: [] }, { basis: 'generation', count: null, rrsets: [] }]);
  // ... also when the table is not there (a zone file without the audit triggers)
  await run(d, 'DROP TABLE karidns_audit_log');
  assert.equal((await marker()).versions[0].changed_outside_before.basis, 'generation');
  // the domain master sees the same markers (it may read the audit log of its zone), the later pages have no "since"
  assert.equal((await marker(dom)).versions[0].changed_outside_before.basis, 'generation');
}));

// ---------------------------------------------------------------------------------------------------------------------------------- the diff
test('the diff between two versions, and against the zone as it is', async () => {
  const toCurrent = (c) => {
    if (c.file === KZ) return ok(applyDoc({ apply: { dry_run: true, diff: [entry('www.example.test.', 'A', ['300 A 192.0.2.51'], A('192.0.2.10', '192.0.2.11').split('\n')), entry('new.example.test.', 'A', ['300 A 192.0.2.60'], null), entry('x.sub.example.test.', 'A', ['300 A 192.0.2.70'], null)] } }));
    return exit(0);
  };
  await withTools(toCurrent, async (d, { root, dom, sub }, t) => {
    await history(d);
    // 1 -> 3: the states at the two ends; an RRset that changed twice is one entry; the SOA changed in more than its serial
    const r = await root('GET', `${V}/1/diff?to=3`);
    is(r, 200);
    assert.deepEqual([r.body.from, r.body.to], [1, 3]);
    assert.deepEqual(r.body.rrsets.map((x) => [x.name, x.type, x.change]), [['a.sub.example.test.', 'TXT', 'replace'], ['example.test.', 'SOA', 'replace'], ['new.example.test.', 'A', 'add'], ['www.example.test.', 'A', 'replace'], ['x.sub.example.test.', 'A', 'add']]);
    assert.deepEqual(r.body.rrsets[3], { name: 'www.example.test.', type: 'A', change: 'replace', before: [{ ttl: 300, content: '192.0.2.10' }, { ttl: 300, content: '192.0.2.11' }], after: [{ ttl: 300, content: '192.0.2.51' }] });
    assert.equal(t.calls.length, 0, 'no tool: the history is in the database');
    assert.deepEqual((await root('GET', `${V}/2/diff?to=3`)).body.rrsets.map((x) => x.name), ['example.test.', 'www.example.test.', 'x.sub.example.test.']);
    // an RRset that was changed and changed back is not in the diff
    await addVersion(d, 4, { generation_before: 15, generation_after: 16 }, [['www.example.test', 'A', A('192.0.2.51'), A('192.0.2.50')]]);
    assert.deepEqual((await root('GET', `${V}/2/diff?to=4`)).body.rrsets.map((x) => x.name), ['example.test.', 'x.sub.example.test.']);
    // a subdomain master sees its part, paged
    assert.deepEqual((await sub('GET', `${V}/1/diff?to=3`)).body.rrsets.map((x) => x.name), ['a.sub.example.test.', 'example.test.', 'x.sub.example.test.']);
    const p1 = await root('GET', `${V}/1/diff?to=3&limit=2`);
    const p2 = await root('GET', `${V}/1/diff?to=3&limit=2&cursor=${p1.body.next_cursor}`);
    assert.deepEqual([p1.body.rrsets.length, p2.body.rrsets.length], [2, 2]);
    assert.notEqual(p1.body.rrsets[1].name, p2.body.rrsets[0].name);
    // wrong asks
    is(await root('GET', `${V}/3/diff?to=2`), 400, 'bad-request');
    is(await root('GET', `${V}/2/diff?to=2`), 400, 'bad-request');
    is(await root('GET', `${V}/1/diff?to=soon`), 400, 'bad-request');
    is(await root('GET', `${V}/9/diff?to=10`), 404, 'not-found');
    is(await root('GET', `${V}/1/diff?to=9`), 404, 'not-found');
    // against the zone: the state at version 1 of every RRset touched since is written as a change, the check run says what that changes
    t.calls.length = 0;
    const c = await dom('GET', `${V}/1/diff?to=current`);
    is(c, 200);
    assert.equal(t.calls.length, 1);
    assert.ok(t.calls[0].argv.includes('--dry-run') && !t.calls[0].argv.includes('--principal'));
    assert.equal(t.calls[0].input, 'rr a.sub.example.test. 300 TXT "hello"\ndelete new.example.test. A\nrr www.example.test. 300 A 192.0.2.10\nrr www.example.test. 300 A 192.0.2.11\ndelete x.sub.example.test. A\n');
    assert.deepEqual(c.body.rrsets.map((x) => [x.name, x.change, x.before?.map((r) => r.content) ?? null, x.after?.map((r) => r.content) ?? null]), [
      ["new.example.test.", "add", null, ["192.0.2.60"]],
      ["www.example.test.", "replace", ["192.0.2.10", "192.0.2.11"], ["192.0.2.51"]],
      ["x.sub.example.test.", "add", null, ["192.0.2.70"]],
    ]);
    // ... without `to` the same; a subdomain master's change file has its names only
    t.calls.length = 0;
    const sc = await sub('GET', `${V}/1/diff`);
    assert.equal(t.calls[0].input, 'rr a.sub.example.test. 300 TXT "hello"\ndelete x.sub.example.test. A\n');
    assert.deepEqual(sc.body.rrsets.map((x) => x.name), ['x.sub.example.test.'], 'what the check run found, filtered to what it may see');
    // nothing touched since: no tool
    t.calls.length = 0;
    assert.deepEqual((await root('GET', `${V}/4/diff?to=current`)).body.rrsets, []);
    assert.equal(t.calls.length, 0);
    // a version too big to keep its RRsets cannot be crossed
    await run(d, 'UPDATE karidns_zone_versions SET delta_complete = 0 WHERE version = 3');
    is(await root('GET', `${V}/1/diff?to=4`), 409, 'delta-incomplete');
    is(await root('GET', `${V}/3/diff?to=4`), 200);
    is(await root('GET', `${V}/2/diff?to=current`), 409, 'delta-incomplete');
  })();
  // the zone checks refuse the state at that version (it would not fit the zone as it is): the messages, as for any change
  await withTools(() => exit(1, { stdout: JSON.stringify(applyDoc({ messages: [{ severity: 'error', code: 'zone.cname-other', text: 'standard input:3: x has a CNAME and other data' }] })) }), async (d, { root }) => {
    await history(d);
    const r = await root('GET', `${V}/1/diff?to=current`);
    is(r, 422, 'zone-checks-failed');
  })();
});

test('a range that touches too many RRsets is refused before it is read', withTools(() => exit(0), async (d, { root }) => {
  await addVersion(d, 1, { generation_before: 0, generation_after: 1 }, [['www.example.test', 'A', null, A('192.0.2.1')]]);
  await addVersion(d, 2, { generation_before: 1, generation_after: 2 });
  await run(d, `INSERT INTO karidns_zone_version_rrsets (version_id, owner, type, before, after)
                WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 50001) SELECT (SELECT id FROM karidns_zone_versions WHERE version = 2), 'h' || i || '.example.test', 'A', NULL, '300 A 192.0.2.1' FROM n`);
  const r = await root('GET', `${V}/1/diff?to=2`);
  is(r, 409, 'too-large');
  assert.match(r.body.detail, /more than 50000 RRsets/);
}));

// ---------------------------------------------------------------------------------------------------------------------------------- rollback
const CHANGE_1 = 'rr a.sub.example.test. 300 TXT "hello"\ndelete new.example.test. A\nrr www.example.test. 300 A 192.0.2.10\nrr www.example.test. 300 A 192.0.2.11\ndelete x.sub.example.test. A\n';
const EXPECT_1 = 'rr a.sub.example.test. 300 TXT "bye"\nrr new.example.test. 300 A 192.0.2.60\nrr www.example.test. 300 A 192.0.2.51\nrr x.sub.example.test. 300 A 192.0.2.70\n';
const RESTORE_DIFF = [
  entry('a.sub.example.test.', 'TXT', ['300 TXT "bye"'], ['300 TXT "hello"']), entry('new.example.test.', 'A', ['300 A 192.0.2.60'], null),
  entry('www.example.test.', 'A', ['300 A 192.0.2.51'], A('192.0.2.10', '192.0.2.11').split('\n')), entry('x.sub.example.test.', 'A', ['300 A 192.0.2.70'], null),
];
// the expectation run is the dry run whose input is the expectation; `moved` is what it finds different from the expectation
const rollbackTools = ({ moved = [], diff = RESTORE_DIFF, expect = EXPECT_1 } = {}) => (c) => {
  if (c.file === KCTL) return exit(0, { stdout: 'OK reloaded\n' });
  if (c.argv.includes('--dry-run')) return ok(applyDoc({ apply: { dry_run: true, generation: 20, diff: c.input === expect ? moved : diff } }));
  return ok(applyDoc({ apply: { dry_run: false, committed: true, version: 4, generation: 20, generation_after: 21, diff } }));
};

test('a rollback is a change set that restores every RRset the later versions touched', withTools(rollbackTools(), async (d, { root }, t) => {
  await history(d);
  const r = await root('POST', `${V}/1/rollback`, { body: { comment: 'oops', reload: true } });
  is(r, 200);
  assert.equal(t.calls.length, 4, 'the expectations, the check, the commit, karictl');
  const [exp, check, commit] = t.calls;
  assert.equal(exp.input, EXPECT_1);
  assert.equal(check.input, CHANGE_1);
  assert.equal(commit.input, CHANGE_1);
  const arg = (name) => commit.argv[commit.argv.indexOf(name) + 1];
  assert.deepEqual([arg('--version-kind'), arg('--rollback-of'), arg('--comment'), arg('--expect-generation'), arg('--principal-name')], ['rollback', '1', 'rollback to version 1: oops', '20', 'root']);
  assert.deepEqual([r.body.committed, r.body.version, r.body.rollback_of, r.body.restored, r.body.versions_undone, r.body.reload], [true, 4, 1, 4, 2, 'requested']);
  assert.deepEqual(r.body.skipped.map((s) => [s.name, s.type]), [['example.test.', 'SOA']]);
  assert.equal(r.body.diff.length, 4);
  // the comment is optional
  t.calls.length = 0;
  await root('POST', `${V}/2/rollback`, { body: { force: true } });
  assert.equal(t.calls.at(-1).argv[t.calls.at(-1).argv.indexOf('--comment') + 1], 'rollback to version 2');
}, { 'karictl-config': CTL_CONF }));

test('a rollback to the newest version has nothing to do; to a version that is not there is 404', withTools(rollbackTools(), async (d, { root }, t) => {
  await history(d);
  const r = await root('POST', `${V}/3/rollback`, { body: {} });
  is(r, 200);
  assert.deepEqual([r.body.committed, r.body.changed, r.body.restored, r.body.rollback_of, r.body.diff], [false, false, 0, 3, []]);
  const dry = await root('POST', `${V}/3/rollback`, { body: { dry_run: true } });
  assert.deepEqual([dry.body.dry_run, dry.body.allowed], [true, true]);
  assert.equal(t.calls.length, 0);
  is(await root('POST', `${V}/9/rollback`, { body: {} }), 404, 'not-found');
  is(await root('POST', `${V}/0/rollback`, { body: {} }), 404, 'not-found');
  is(await root('POST', '/datasets/main/zones/ghost.test/versions/1/rollback', { body: {} }), 404, 'not-found');
  is(await root('POST', `${V}/1/rollback`, { body: { surprise: 1 } }), 400, 'bad-request');
  is(await root('POST', `${V}/1/rollback`, { body: { comment: 'x'.repeat(901) } }), 400, 'bad-request');
}));

test('a rollback finds what changed after the versions: a conflict (409) unless forced; the dry run lists them', async () => {
  const moved = [entry('www.example.test.', 'A', ['300 A 192.0.2.99'], ['300 A 192.0.2.51']), entry('new.example.test.', 'A', null, ['300 A 192.0.2.60'])];
  await withTools(rollbackTools({ moved }), async (d, { root }, t) => {
    await history(d);
    const r = await root('POST', `${V}/1/rollback`, { body: {} });
    is(r, 409, 'version-conflict');
    assert.equal(t.calls.length, 1, 'nothing else ran');
    assert.deepEqual(r.body.errors.map((e) => [e.name, e.type, e.expected, e.current]), [
      ['www.example.test.', 'A', [{ ttl: 300, content: '192.0.2.51' }], [{ ttl: 300, content: '192.0.2.99' }]],
      ['new.example.test.', 'A', [{ ttl: 300, content: '192.0.2.60' }], null],
    ]);
    assert.match(r.body.detail, /force: true/);
    // the dry run goes on and says what would be restored if forced
    t.calls.length = 0;
    const dry = await root('POST', `${V}/1/rollback`, { body: { dry_run: true } });
    is(dry, 200);
    assert.equal(dry.body.conflicts.length, 2);
    assert.deepEqual([dry.body.dry_run, dry.body.allowed, dry.body.diff.length], [true, true, 4]);
    assert.equal(t.calls.length, 2);
    // forced: no expectation, one grant for everything
    t.calls.length = 0;
    const f = await root('POST', `${V}/1/rollback`, { body: { force: true } });
    is(f, 200);
    assert.deepEqual([f.body.committed, t.calls.length, t.calls[0].input], [true, 2, CHANGE_1]);
    t.calls.length = 0;
    const fd = await root('POST', `${V}/1/rollback`, { body: { force: true, dry_run: true } });
    assert.deepEqual([fd.body.conflicts, t.calls.length], [undefined, 1]);
  })();
  // the zone moved between the plan and the commit: the whole plan is made again (the history is read again too)
  let commits = 0;
  await withTools((c) => {
    if (c.argv.includes('--dry-run')) return ok(applyDoc({ apply: { dry_run: true, generation: 20 + commits, diff: c.input === EXPECT_1 ? [] : RESTORE_DIFF } }));
    commits++;
    return commits === 1 ? exit(3, { stdout: JSON.stringify(applyDoc({ apply: { changed: true } })) }) : ok(applyDoc({ apply: { dry_run: false, committed: true, version: 4, diff: RESTORE_DIFF } }));
  }, async (d, { root }, t) => {
    await history(d);
    is(await root('POST', `${V}/1/rollback`, { body: {} }), 200);
    assert.equal(t.calls.length, 6);
  })();
});

test('a rollback is a change set: the caller needs one grant that allows every RRset it restores', async () => {
  // the domain master may restore names and the types of its policy, not the apex
  const apex = [...RESTORE_DIFF, entry('example.test.', 'NS', ['3600 NS ns1.example.test.'], ['3600 NS ns9.example.test.'])];
  await withTools(rollbackTools({ diff: apex }), async (d, { dom, sub }, t) => {
    await history(d);
    const r = await dom('POST', `${V}/1/rollback`, { body: {} });
    is(r, 403, 'forbidden');
    assert.match(r.body.errors[0].text, /NS example\.test\./);
    assert.equal(r.body.errors[0].pointer, undefined);
    assert.equal(t.calls.length, 2, 'the expectations and the check; nothing was committed');
    const dry = await dom('POST', `${V}/1/rollback`, { body: { dry_run: true } });
    assert.deepEqual([dry.body.allowed, dry.body.diff, dry.body.denied.code], [false, undefined, 'not-permitted']);
    // a subdomain master reads the history of its names only, so it restores those: a change file of its names (and the check run is the judge of the rest)
    t.calls.length = 0;
    const s = await sub('POST', `${V}/1/rollback`, { body: { dry_run: true } });
    assert.equal(t.calls.at(-1).input, 'rr a.sub.example.test. 300 TXT "hello"\ndelete x.sub.example.test. A\n');
    assert.equal(s.body.allowed, false, 'the diff of the check run holds names outside its suffix');
  })();
  // a rollback to a state a policy does not allow (a TTL of 10 is under the 60 of the policy) cannot be made by that principal, a global master can
  const low = [entry('www.example.test.', 'A', ['300 A 192.0.2.51'], ['10 A 192.0.2.10'])];
  await withTools(rollbackTools({ diff: low }), async (d, { dom, root }) => {
    await history(d);
    is(await dom('POST', `${V}/1/rollback`, { body: { force: true } }), 403, 'forbidden');
    is(await root('POST', `${V}/1/rollback`, { body: { force: true } }), 200);
  })();
  // a policy's max_rr counts after the change
  const more = [entry('a.sub.example.test.', 'TXT', ['300 TXT "bye"'], ['300 TXT "hello"', '300 TXT "hello2"', '300 TXT "hello3"'])];
  await withTools(rollbackTools({ diff: more }), async (d, { sub }) => {
    await history(d);
    const p = await d.makePolicy({ name: 'capped', allowed_types: ['A', 'TXT'], ttl_min: 0, ttl_max: 86400, max_rr: 1 });
    await d.makeUser('capped', 'capped password 12', { grants: [{ role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policyId: p, schema: '' }] });
    const c = d.as(await d.login('capped', 'capped password 12'));
    const r = await c('POST', `${V}/1/rollback`, { body: { force: true } });
    is(r, 403, 'max-rr');
    assert.ok(sub);
  })();
});

test('a rollback cannot cross a version that is not complete; a zone that is not primary is not rolled back; tagged RRsets are not restored', withTools(rollbackTools(), async (d, { root }, t) => {
  await history(d);
  await run(d, 'UPDATE karidns_zone_versions SET delta_complete = 0 WHERE version = 3');
  is(await root('POST', `${V}/1/rollback`, { body: {} }), 409, 'delta-incomplete');
  is(await root('POST', `${V}/2/rollback`, { body: {} }), 409, 'delta-incomplete');
  assert.equal((await root('POST', `${V}/3/rollback`, { body: {} })).body.committed, false);
  assert.equal(t.calls.length, 0);
  await run(d, 'UPDATE karidns_zone_versions SET delta_complete = 1 WHERE version = 3');
  is(await root('POST', '/datasets/main/zones/slave.test/versions/1/rollback', { body: {} }), 409, 'zone-not-editable');
  is(await root('POST', '/datasets/main/zones/other.test/versions/1/rollback', { body: {} }), 409, 'presigned-zone');
  // a record of www.example.test with a location tag: the API does not edit it, a rollback does not either
  const id = (await sql(d, "SELECT id FROM records WHERE name = 'www.example.test' AND content = '192.0.2.10'"))[0].id;
  await run(d, 'INSERT INTO karidns_record_tags (record_id, location_tag) VALUES ($1, $2)', [id, 'office']);
  const tg = await root('POST', `${V}/1/rollback`, { body: {} });
  is(tg, 409, 'tagged-rrset');
  assert.equal(t.calls.length, 0);
}));

test('a zone kept signed: the rollback is unsigned data, the signer signs it and the API does not reload', withTools(rollbackTools(), async (d, { root }, t) => {
  await history(d);
  await run(d, "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'X-KARIDNS-SIGNER', '1')");
  const r = await root('POST', `${V}/1/rollback`, { body: { reload: true } });
  is(r, 200);
  assert.deepEqual([r.body.committed, r.body.reload], [true, 'waiting for the signer']);
  assert.equal(t.calls.filter((c) => c.file === KCTL).length, 0);
  assert.ok(!t.calls.at(-1).argv.includes('--reload'));
}, { 'karictl-config': CTL_CONF }));

test('a rollback of a signed zone is not disturbed by the signer: its rows are no outside change', withTools(rollbackTools(), async (d, { root }) => {
  await history(d, { lastAt: '2099-01-01T00:00:00Z' });
  await run(d, 'DELETE FROM karidns_audit_log');
  await run(d, "INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES (1, 'www.example.test', 'RRSIG', 'x', 300, 0, 0)");
  await run(d, `UPDATE karidns_zone_versions SET generation_after = ${await generation(d)} WHERE version = 3`);
  const b = (await root('GET', V)).body;
  assert.deepEqual([b.versions[0].changed_outside_before, b.changed_outside_since], [null, null]);
  is(await root('POST', `${V}/1/rollback`, { body: {} }), 200);
}));

// ---------------------------------------------------------------------------------------------------------------------------------- templates
const kcOk = (messages = []) => ok({ karicheck: 1, version: '0.6.0', command: 'zone', result: 'ok', counts: { error: 0, warning: 0, checked: 1, skipped: 0, dropped: 0 }, truncated: false, messages, zones: [] });
const msg = (severity, code, text, line) => ({ severity, code, text, file: '<stdin>', line, zone: 'template.invalid.', view: null });
const STD = {
  name: 'standard', description: 'the usual', soa: { mname: 'ns1.example.test.', rname: 'hostmaster.example.test.', refresh: 1800, minimum: 60 },
  records: [{ owner: '@', type: 'NS', content: 'ns1.example.test.' }, { owner: '@', type: 'NS', content: 'ns2.example.test.' }, { owner: 'www', type: 'A', ttl: 300, content: '192.0.2.1' },
    { owner: '@', type: 'TXT', content: '"v=spf1 -all"' }],
};

test('templates: everybody reads, global masters write; the records are checked by karicheck before they are stored', withTools((c) => (c.file === KCK ? kcOk([msg('warning', 'zone.warn', 'standard input:7: a warning', 7)]) : exit(0)), async (d, { root, dom }, t) => {
  const r = await root('POST', '/templates', { body: STD });
  is(r, 201);
  assert.match(r.headers.get('location'), /^\/api\/v1\/templates\/\d+$/);
  const id = r.body.template.id;
  assert.deepEqual(t.calls[0].argv, ['--json', 'zone', 'template.invalid', '-']);
  assert.equal(t.calls[0].file, KCK);
  assert.equal(t.calls[0].input, '$ORIGIN template.invalid.\n$TTL 3600\n@ IN SOA ns.nameserver.invalid. hostmaster.template.invalid. 1 7200 3600 1209600 300\n'
    + '@ IN NS ns1.example.test.\n@ IN NS ns2.example.test.\nwww 300 IN A 192.0.2.1\n@ IN TXT "v=spf1 -all"\n'.replace('@ IN NS ns1', '@ IN NS ns1'));
  assert.deepEqual(r.body.template.records, [
    { owner: '@', type: 'NS', ttl: null, content: 'ns1.example.test.' }, { owner: '@', type: 'NS', ttl: null, content: 'ns2.example.test.' },
    { owner: 'www', type: 'A', ttl: 300, content: '192.0.2.1' }, { owner: '@', type: 'TXT', ttl: null, content: '"v=spf1 -all"' },
  ]);
  assert.deepEqual(r.body.template.soa, { mname: 'ns1.example.test', rname: 'hostmaster.example.test', refresh: 1800, retry: null, expire: null, minimum: 60 });
  assert.equal(r.body.template.name, 'standard');
  assert.ok(r.body.template.revision >= 1);
  assert.deepEqual(r.body.messages, [{ code: 'zone.warn', severity: 'warning', text: 'standard input:7: a warning', pointer: '/records/3' }], 'a warning is passed on, the record it is about is named');
  // everybody reads
  const l = await dom('GET', '/templates');
  assert.deepEqual(l.body.templates.map((x) => [x.name, x.record_count]), [['standard', 4]]);
  assert.equal(l.body.templates[0].records, undefined);
  assert.deepEqual((await dom('GET', `/templates/${id}`)).body.template.records.length, 4);
  assert.equal((await dom('GET', '/templates?prefix=ST')).body.templates.length, 1);
  assert.equal((await dom('GET', '/templates?prefix=x')).body.templates.length, 0);
  await root('POST', '/templates', { body: { name: 'second' } });
  const pg1 = await dom('GET', '/templates?limit=1');
  const pg2 = await dom('GET', `/templates?limit=1&cursor=${pg1.body.next_cursor}`);
  assert.deepEqual([pg1.body.templates.map((x) => x.name), pg2.body.templates.map((x) => x.name), pg2.body.next_cursor], [['standard'], ['second'], null]);
  is(await root('DELETE', `/templates/${pg2.body.templates[0].id}`), 204);
  is(await dom('GET', '/templates/999'), 404, 'not-found');
  is(await dom('GET', '/templates/abc'), 404, 'not-found');
  // only global masters write
  is(await dom('POST', '/templates', { body: { name: 'mine', records: [] } }), 403, 'forbidden');
  is(await dom('PATCH', `/templates/${id}`, { body: { description: 'x' } }), 403, 'forbidden');
  is(await dom('DELETE', `/templates/${id}`), 403, 'forbidden');
  // a name is unique
  is(await root('POST', '/templates', { body: { name: 'standard' } }), 409, 'exists');
  // a dry run only checks
  t.calls.length = 0;
  const dry = await root('POST', '/templates', { body: { name: 'draft', records: [{ owner: '@', type: 'A', content: '192.0.2.1' }], dry_run: true } });
  assert.deepEqual([dry.status, dry.body.dry_run, dry.body.valid, t.calls.length], [200, true, true, 1]);
  assert.equal((await root('GET', '/templates')).body.templates.length, 1);
  // update: a PATCH changes only what it carries, the revision grows, the records are replaced as a list, the SOA defaults can be cleared
  const rev = (await root('GET', `/templates/${id}`)).body.template.revision;
  const u = await root('PATCH', `/templates/${id}`, { body: { description: null, soa: null, name: 'standard2' } });
  is(u, 200);
  assert.deepEqual([u.body.template.name, u.body.template.description, u.body.template.soa, u.body.template.records.length], ['standard2', null, null, 4]);
  assert.ok(u.body.template.revision > rev);
  const u2 = await root('PATCH', `/templates/${id}`, { body: { records: [{ owner: 'mail', type: 'MX', content: '10 mx.example.test.' }] } });
  assert.deepEqual(u2.body.template.records, [{ owner: 'mail', type: 'MX', ttl: null, content: '10 mx.example.test.' }]);
  is(await root('PATCH', `/templates/${id}`, { body: {} }), 400, 'bad-request');
  is(await root('PATCH', '/templates/999', { body: { description: 'x' } }), 404, 'not-found');
  const dryU = await root('PATCH', `/templates/${id}`, { body: { records: [], dry_run: true } });
  assert.equal(dryU.body.dry_run, true);
  assert.equal((await root('GET', `/templates/${id}`)).body.template.records.length, 1);
  // validate: the stored template through karicheck again
  const v = await root('POST', `/templates/${id}/validate`);
  assert.deepEqual([v.status, v.body.valid, v.body.template.name, v.body.messages.length], [200, true, 'standard2', 1]);
  is(await root('POST', '/templates/999/validate'), 404, 'not-found');
  // delete
  is(await root('DELETE', `/templates/${id}`), 204);
  is(await root('DELETE', `/templates/${id}`), 404, 'not-found');
  is(await root('GET', `/templates/${id}`), 404, 'not-found');
  // the audit log names the principal and the change set
  const aud = await sql(d, "SELECT principal_name, change_set FROM auth.karidns_auth_audit WHERE table_name = 'templates' AND op = 'I'");
  assert.deepEqual([aud[0].principal_name, aud[0].change_set !== null], ['root', true]);
}));

test('a template that karicheck refuses is not stored: 422, each error at its record; a karicheck that does not work is a 500', async () => {
  const refuse = (c) => (c.file === KCK ? exit(1, { stdout: JSON.stringify({ karicheck: 1, messages: [msg('error', 'zone.cname-other', 'standard input:5: www has a CNAME and other data', 5), msg('warning', 'zone.x', 'standard input:6: w', 6), msg('error', 'zone.synthetic', 'the SOA', 3)] }) }) : exit(0));
  await withTools(refuse, async (d, { root }) => {
    const body = { name: 'bad', records: [{ owner: 'www', type: 'CNAME', content: 'x.example.test.' }, { owner: 'www', type: 'A', content: '192.0.2.1' }] };
    const r = await root('POST', '/templates', { body });
    is(r, 422, 'template-checks-failed');
    assert.deepEqual(r.body.errors.map((e) => [e.code, e.severity, e.pointer]), [['zone.cname-other', 'error', '/records/0'], ['zone.x', 'warning', '/records/1']]);
    assert.equal((await root('GET', '/templates')).body.templates.length, 0);
    // a PATCH of the records is checked, a PATCH of the name is checked with the stored records
    await run(d, "INSERT INTO auth.templates (name) VALUES ('t')");
    is(await root('PATCH', '/templates/1', { body: { records: body.records } }), 422, 'template-checks-failed');
  })();
  for (const [what, result, re] of [
    ['no such program', exit(null, { spawnError: 'ENOENT' }), /karicheck did not check the template \(ENOENT\)/],
    ['too slow', exit(null, { timedOut: true }), /timed out/],
    ['too much', exit(null, { truncated: true }), /wrote too much/],
    ['no document', exit(2, { stderr: 'usage' }), /exit status 2: usage/],
  ]) {
    await withTools(() => result, async (d, { root }) => {
      is(await root('POST', '/templates', { body: { name: 'x' } }), 500, 'internal');
      assert.ok(d.log.lines.some((l) => re.test(l)), what + d.log.lines.join('|'));
    })();
  }
  // a validation of a stored template that has errors is a 200 that says so
  await withTools(refuse, async (d, { root }) => {
    await run(d, "INSERT INTO auth.templates (name) VALUES ('t')");
    await run(d, "INSERT INTO auth.template_records (template_id, ordinal, owner, type, content) VALUES (1, 0, 'www', 'CNAME', 'x.')");
    const v = await root('POST', '/templates/1/validate');
    assert.deepEqual([v.status, v.body.valid, v.body.messages[0].pointer], [200, false, '/records/0']);
  })();
});

test('a zone made from a template: its SOA values and records, the version names the template', async () => {
  const diff = [entry('new.test.', 'SOA', null, ['3600 SOA ns1.example.test. hostmaster.example.test. 2026110800 1800 3600 1209600 60']), entry('new.test.', 'NS', null, ['3600 NS ns1.example.test.'])];
  const tools = (c) => {
    if (c.file === KCK) return kcOk();
    return ok(applyDoc({ apply: c.argv.includes('--dry-run') ? { dry_run: true, diff } : { dry_run: false, committed: true, created: true, version: 1, diff } }));
  };
  await withTools(tools, async (d, { root, dom }, t) => {
    const id = (await root('POST', '/templates', { body: STD })).body.template.id;
    const rev = (await root('GET', `/templates/${id}`)).body.template.revision;
    t.calls.length = 0;
    const r = await root('POST', '/datasets/main/zones', { body: { name: 'new.test', template: 'standard', comment: 'for a customer', rrsets: [{ name: 'www.new.test', type: 'A', changetype: 'REPLACE', ttl: 60, records: [{ content: '192.0.2.99' }] }] } });
    is(r, 201);
    assert.equal(t.calls.length, 2);
    assert.match(t.calls[0].input, /^rr new\.test\. 3600 SOA ns1\.example\.test\. hostmaster\.example\.test\. \d{8}00 1800 3600 1209600 60\nrr new\.test\. 3600 NS ns1\.example\.test\.\nrr new\.test\. 3600 NS ns2\.example\.test\.\nrr new\.test\. 3600 TXT "v=spf1 -all"\nrr www\.new\.test\. 60 A 192\.0\.2\.99\n$/);
    const commit = t.calls[1];
    assert.equal(commit.argv[commit.argv.indexOf('--comment') + 1], `for a customer [template "standard" (id ${id}, revision ${rev})]`);
    // by id, with the default TTL of the request
    t.calls.length = 0;
    const by = await root('POST', '/datasets/main/zones', { body: { name: 'newer.test', template_id: id, default_ttl: 900, dry_run: true } });
    is(by, 200);
    assert.match(t.calls[0].input, /^rr newer\.test\. 900 SOA ns1\.example\.test\. hostmaster\.example\.test\. \d{8}00 1800 3600 1209600 60\nrr newer\.test\. 900 NS ns1\.example\.test\.\n/);
    assert.match(t.calls[0].input, /rr www\.newer\.test\. 300 A 192\.0\.2\.1\n/);
    // not a template, not the allowed
    is(await root('POST', '/datasets/main/zones', { body: { name: 'x.test', template: 'ghost' } }), 404, 'not-found');
    is(await root('POST', '/datasets/main/zones', { body: { name: 'x.test', template_id: 999 } }), 404, 'not-found');
    is(await dom('POST', '/datasets/main/zones', { body: { name: 'x.test', template: 'standard' } }), 403, 'forbidden');
    // a template without SOA values: the request has them or it is refused
    await root('POST', '/templates', { body: { name: 'bare', records: [{ owner: '@', type: 'NS', content: 'ns1.example.test.' }] } });
    const bare = await root('POST', '/datasets/main/zones', { body: { name: 'bare.test', template: 'bare' } });
    is(bare, 400, 'bad-request');
    assert.equal(bare.body.errors[0].pointer, '/soa/mname');
    const bare2 = await root('POST', '/datasets/main/zones', { body: { name: 'bare.test', template: 'bare', soa: { mname: 'ns1.bare.test', rname: 'h.bare.test' }, dry_run: true } });
    is(bare2, 200);
  })();
});

test('a template applied to a zone: a change set of REPLACE operations, kind template, the grants decide', async () => {
  const diff = [entry('www.example.test.', 'A', ['300 A 192.0.2.50'], ['300 A 192.0.2.1'])];
  const tools = (c) => {
    if (c.file === KCK) return kcOk();
    return ok(applyDoc({ apply: c.argv.includes('--dry-run') ? { dry_run: true, diff } : { dry_run: false, committed: true, version: 4, diff } }));
  };
  await withTools(tools, async (d, { root, dom }, t) => {
    const id = (await root('POST', '/templates', { body: { name: 'web', records: [{ owner: 'www', type: 'A', ttl: 300, content: '192.0.2.1' }, { owner: 'www', type: 'TXT', content: '"hi"' }] } })).body.template.id;
    const rev = (await root('GET', `/templates/${id}`)).body.template.revision;
    const AP = '/datasets/main/zones/example.test/apply-template';
    // a dry run shows what it would overwrite
    t.calls.length = 0;
    const dry = await dom('POST', AP, { body: { template: 'web', dry_run: true } });
    is(dry, 200);
    assert.deepEqual([dry.body.dry_run, dry.body.allowed, dry.body.diff.length, t.calls.length], [true, true, 1, 1]);
    assert.equal(t.calls[0].input, 'rr www.example.test. 300 A 192.0.2.1\nrr www.example.test. 3600 TXT "hi"\n');
    const r = await dom('POST', AP, { body: { template_id: id, comment: 'standard web', default_ttl: 120 } });
    is(r, 200);
    const commit = t.calls.at(-1);
    assert.equal(commit.input, 'rr www.example.test. 300 A 192.0.2.1\nrr www.example.test. 120 TXT "hi"\n');
    const arg = (n) => commit.argv[commit.argv.indexOf(n) + 1];
    assert.deepEqual([arg('--version-kind'), arg('--comment'), arg('--principal-name')], ['template', `standard web [template "web" (id ${id}, revision ${rev})]`, 'dom']);
    assert.equal(commit.argv.includes('--rollback-of'), false);
    // the apex is for a policy that allows it: the domain master's does not; the refusal names the record of the template
    const apex = (await root('POST', '/templates', { body: { name: 'apex', records: [{ owner: '@', type: 'TXT', content: '"x"' }] } })).body.template.id;
    const denied = await dom('POST', AP, { body: { template_id: apex } });
    is(denied, 403, 'forbidden');
    assert.equal(denied.body.errors[0].pointer, '/template/records/0');
    is(await dom('POST', AP, { body: { template_id: apex, dry_run: true } }), 200);
    // a subdomain master: its suffix is not where a template puts things
    is(await d.as(await d.login('sub', 'sub password 12345'))('POST', AP, { body: { template_id: id } }), 403, 'forbidden');
    // shape, unknown things, zones that are not edited
    is(await dom('POST', AP, { body: {} }), 400, 'bad-request');
    is(await dom('POST', AP, { body: { template: 'web', template_id: id } }), 400, 'bad-request');
    is(await dom('POST', AP, { body: { template: 'ghost' } }), 404, 'not-found');
    is(await root('POST', '/datasets/main/zones/slave.test/apply-template', { body: { template: 'web' } }), 409, 'zone-not-editable');
    is(await dom('POST', '/datasets/main/zones/other.test/apply-template', { body: { template: 'web' } }), 404, 'not-found');
    const empty = (await root('POST', '/templates', { body: { name: 'empty' } })).body.template.id;
    is(await root('POST', AP, { body: { template_id: empty } }), 400, 'bad-request');
  })();
});

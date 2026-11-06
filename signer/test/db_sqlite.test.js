// The SQLite3 side against a real database file with the PowerDNS schema and db/karidns_ext.sqlite3.sql.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SqliteDb, loadSqlite, acquireFileLock } from '../lib/db_sqlite.js';

const sqlite = await loadSqlite();
const SCHEMA = [new URL('../../tests/db/pdns_schema.sqlite3.sql', import.meta.url), new URL('../../db/karidns_ext.sqlite3.sql', import.meta.url)];

function fresh() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-sq-'));
  const file = path.join(dir, 'p.sqlite3');
  const raw = new sqlite.DatabaseSync(file);
  for (const s of SCHEMA) raw.exec(fs.readFileSync(s, 'utf8'));
  raw.exec("INSERT INTO domains (name, type) VALUES ('a.test', 'NATIVE'), ('b.test', 'NATIVE'), ('c.test', 'NATIVE')");
  raw.exec('PRAGMA foreign_keys = ON');
  const db = new SqliteDb({ file, sqlite, sleepFn: async () => {} });
  db.open();
  return { dir, file, raw, db, done: () => { db.close(); raw.close(); rmDir(dir); } };
}
// Windows keeps SQLite files open a little longer; a left-over temporary directory is not a failure of the test
const rmDir = (d) => { try { fs.rmSync(d, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 }); } catch (e) { if (process.platform !== "win32") throw e; } };
const id = (raw, n) => raw.prepare('SELECT id FROM domains WHERE name = ?').get(n).id;

test('loadSqlite: no ExperimentalWarning line, the original emitWarning is back, a missing module is explained', async () => {
  const before = process.emitWarning;
  const seen = [];
  process.on('warning', (w) => seen.push(w));
  await loadSqlite();
  assert.equal(process.emitWarning, before);
  await assert.rejects(loadSqlite(() => Promise.reject(new Error('no such module'))), /needs node:sqlite \(Node 22\.13 or newer\): no such module/);
  assert.equal(process.emitWarning, before);
  // the filter passes other warnings through, and an object-form ExperimentalWarning about something else
  const emit = process.emitWarning;
  let passed = 0;
  process.emitWarning = () => { passed++; };
  try {
    await loadSqlite(async () => {
      process.emitWarning('SQLite is an experimental feature', 'ExperimentalWarning');
      process.emitWarning('SQLite is an experimental feature', { type: 'ExperimentalWarning' });
      process.emitWarning('something else', 'ExperimentalWarning');
      process.emitWarning('SQLite deprecated', 'DeprecationWarning');
      return sqlite;
    });
  } finally {
    process.emitWarning = emit;
  }
  assert.equal(passed, 2);
});

test('one signer per database file; the lock of a dead process is taken over', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-lock-'));
  try {
    const f = path.join(dir, 'x.lock');
    const rel = acquireFileLock(f, { pid: 100 });
    assert.equal(fs.readFileSync(f, 'utf8'), '100\n');
    assert.throws(() => acquireFileLock(f, { pid: 200, kill: () => true }), /another karidns-signer \(pid 100\)/);
    assert.throws(() => acquireFileLock(f, { pid: 200, kill: () => { const e = new Error('x'); e.code = 'EPERM'; throw e; } }), /another karidns-signer/);
    const dead = () => { const e = new Error('x'); e.code = 'ESRCH'; throw e; };
    const rel2 = acquireFileLock(f, { pid: 200, kill: dead });                // takes over
    assert.equal(fs.readFileSync(f, 'utf8'), '200\n');
    rel2();
    assert.ok(!fs.existsSync(f));
    rel2();                                                                  // already gone
    rel();
    fs.writeFileSync(f, 'garbage\n');
    const rel3 = acquireFileLock(f, { pid: 300 });                          // an unreadable pid: the file is stale
    rel3();
    fs.writeFileSync(f, '300\n');
    const rel4 = acquireFileLock(f, { pid: 300 });                          // our own pid in the file: ours
    rel4();
    assert.throws(() => acquireFileLock(path.join(dir, 'no/such/dir/x.lock')), /cannot create the lock file/);
  } finally { rmDir(dir); }
});

test('open: the lock file, the tables; close releases the lock', () => {
  const t = fresh();
  try {
    assert.ok(fs.existsSync(`${t.file}.signer.lock`));
    const second = new SqliteDb({ file: t.file, sqlite });
    fs.writeFileSync(`${t.file}.signer.lock`, `${process.ppid}\n`);        // another (live) process holds it
    assert.throws(() => second.open(), /another karidns-signer/);
    fs.writeFileSync(`${t.file}.signer.lock`, `${process.pid}\n`);
    t.db.close();
    assert.ok(!fs.existsSync(`${t.file}.signer.lock`));
    t.db.open();
    t.db.close();
    t.db.close();
    t.db.open();
  } finally { t.done(); }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-sq-'));
  try {
    const file = path.join(dir, 'empty.sqlite3');
    new sqlite.DatabaseSync(file).close();
    const db = new SqliteDb({ file, sqlite });
    assert.throws(() => db.open(), /table karidns_signer_state does not exist/);
    assert.ok(!fs.existsSync(`${file}.signer.lock`));
  } finally { rmDir(dir); }
});

test('metadata, keys', async () => {
  const t = fresh();
  try {
    const a = id(t.raw, 'a.test');
    assert.deepEqual(await t.db.getMeta(a), { signer: false, presigned: false, nsec3param: null });
    t.raw.exec(`INSERT INTO domainmetadata (domain_id, kind, content) VALUES (${a}, 'presigned', '1'), (${a}, 'NSEC3PARAM', '1 0 0 -'), (${a}, 'X-KARIDNS-SIGNER', '1'), (${a}, 'ALLOW-AXFR-FROM', 'AUTO-NS')`);
    assert.deepEqual(await t.db.getMeta(a), { signer: true, presigned: true, nsec3param: '1 0 0 -' });
    assert.deepEqual(await t.db.getKeys(a), []);
    t.raw.exec(`INSERT INTO cryptokeys (domain_id, flags, active, published, content) VALUES (${a}, 257, 1, 1, 'K1'), (${a}, 256, 0, NULL, 'K2'), (${a}, 256, NULL, 0, 'K3')`);
    const keys = await t.db.getKeys(a);
    assert.deepEqual(keys.map((k) => [k.flags, k.active, k.published, k.content]), [[257, true, true, 'K1'], [256, false, true, 'K2'], [256, false, false, 'K3']]);
    t.raw.exec("UPDATE domainmetadata SET content = '0' WHERE kind = 'X-KARIDNS-SIGNER'");
    assert.equal((await t.db.getMeta(a)).signer, false);
  } finally { t.done(); }
});

test('insertKeys: active and published, in one transaction, and the write id (the log rows of the INSERT are ours)', async () => {
  const t = fresh();
  try {
    const a = id(t.raw, 'a.test');
    const before = t.raw.prepare('SELECT coalesce(max(seq), 0) AS m FROM karidns_changes').get().m;
    const w = await t.db.insertKeys(a, [{ flags: 257, content: 'KSK' }, { flags: 256, content: 'ZSK' }]);
    assert.equal(w.xid, null);
    assert.equal(w.seq_first, before + 1);
    assert.equal(w.seq_last, t.raw.prepare('SELECT max(seq) AS m FROM karidns_changes').get().m);
    assert.ok(w.seq_last >= w.seq_first);
    const keys = await t.db.getKeys(a);
    assert.deepEqual(keys.map((k) => [k.flags, k.active, k.published]), [[257, true, true], [256, true, true]]);
    // all or none
    t.raw.exec("CREATE TRIGGER bad_key BEFORE INSERT ON cryptokeys WHEN NEW.content = 'BAD' BEGIN SELECT RAISE(ABORT, 'bad key'); END");
    await assert.rejects(t.db.insertKeys(a, [{ flags: 256, content: 'X' }, { flags: 256, content: 'BAD' }]), /bad key/);
    assert.equal((await t.db.getKeys(a)).length, 2);
    // a write that logs nothing has no range
    t.raw.exec('DROP TRIGGER IF EXISTS karidns_trg_cryptokeys_ins');
    const w2 = await t.db.insertKeys(a, [{ flags: 256, content: 'Y' }]);
    assert.deepEqual(w2, { xid: null, seq_first: null, seq_last: null });
  } finally { t.done(); }
});

test('key requests', async () => {
  const t = fresh();
  try {
    const a = id(t.raw, 'a.test');
    const b = id(t.raw, 'b.test');
    t.raw.exec(`INSERT INTO karidns_key_requests (domain_id, kind, algorithm, key_type) VALUES (${a}, 'enable', 13, 'csk')`);
    t.raw.exec(`INSERT INTO karidns_key_requests (domain_id, kind, algorithm, bits, key_type) VALUES (${b}, 'add', 8, 2048, 'zsk')`);
    const reqs = await t.db.pendingRequests(10);
    assert.equal(reqs.length, 2);
    assert.deepEqual({ ...reqs[0], id: 0 }, { id: 0, domainId: a, zone: 'a.test', kind: 'enable', algorithm: 13, bits: null, keyType: 'csk', nsec: null });
    assert.equal(reqs[1].bits, 2048);
    assert.equal((await t.db.pendingRequests(1)).length, 1);
    await t.db.finishRequest(reqs[0].id, 'done', 'ok', 1700000000);
    await t.db.finishRequest(reqs[0].id, 'failed', 'second time does nothing', 1700000001);
    const row = t.raw.prepare('SELECT state, message, done_at FROM karidns_key_requests WHERE id = ?').get(reqs[0].id);
    assert.deepEqual({ ...row }, { state: 'done', message: 'ok', done_at: 1700000000 });
    assert.equal((await t.db.pendingRequests(10)).length, 1);
  } finally { t.done(); }
});

test('state: success, failure with the backoff, due, mark due, drop', async () => {
  const t = fresh();
  try {
    const a = id(t.raw, 'a.test');
    const b = id(t.raw, 'b.test');
    await t.db.recordSuccess(a, { signedAt: 1000, serial: 7, minExpire: 5000, nextDue: 4000, durationMs: 12 });
    assert.deepEqual({ ...t.raw.prepare('SELECT * FROM karidns_signer_state WHERE domain_id = ?').get(a) },
      { domain_id: a, signed_at: 1000, signed_serial: 7, min_expire: 5000, next_due: 4000, attempts: 0, last_error: null, last_duration_ms: 12 });
    assert.deepEqual(await t.db.dueZones(3999, 10), []);
    assert.deepEqual(await t.db.dueZones(4000, 10), [{ domainId: a, zone: 'a.test', attempts: 0 }]);
    const nd = (n) => 2000 + n * 100;
    assert.equal(await t.db.recordFailure(a, { error: 'boom', nextDue: nd, durationMs: 5 }), 1);
    assert.equal(await t.db.recordFailure(a, { error: 'boom 2', nextDue: nd }), 2);
    let s = t.raw.prepare('SELECT * FROM karidns_signer_state WHERE domain_id = ?').get(a);
    assert.deepEqual([s.attempts, s.last_error, s.next_due, s.last_duration_ms, s.signed_serial], [2, 'boom 2', 2200, null, 7]);
    // a zone without a state row gets one
    assert.equal(await t.db.recordFailure(b, { error: 'x', nextDue: nd }), 1);
    await t.db.recordSuccess(a, { signedAt: 3000, serial: 8, minExpire: null, nextDue: 9000, durationMs: 1 });
    s = t.raw.prepare('SELECT * FROM karidns_signer_state WHERE domain_id = ?').get(a);
    assert.deepEqual([s.attempts, s.last_error, s.min_expire, s.next_due], [0, null, null, 9000]);
    // mark due: never later than it is
    await t.db.markDue([a, b], 5000);
    assert.deepEqual(t.raw.prepare('SELECT next_due FROM karidns_signer_state ORDER BY domain_id').all().map((r) => r.next_due), [5000, 2100]);
    const c = id(t.raw, 'c.test');
    await t.db.markDue([c, 99999], 123);                         // a zone without a row gets one; an id that is no zone gets none
    assert.equal(t.raw.prepare('SELECT next_due FROM karidns_signer_state WHERE domain_id = ?').get(c).next_due, 123);
    assert.equal(t.raw.prepare('SELECT count(*) AS n FROM karidns_signer_state').get().n, 3);
    assert.deepEqual((await t.db.dueZones(10000, 2)).map((z) => z.zone), ['c.test', 'b.test']);
    await t.db.dropState(a);
    assert.equal(t.raw.prepare('SELECT count(*) AS n FROM karidns_signer_state').get().n, 2);
    // markDue rolls back as a whole
    t.raw.exec("CREATE TRIGGER bad_state BEFORE INSERT ON karidns_signer_state WHEN NEW.next_due = 777 BEGIN SELECT RAISE(ABORT, 'bad state'); END");
    t.raw.exec('DELETE FROM karidns_signer_state');
    await assert.rejects(t.db.markDue([a, b], 777), /bad state/);
    assert.equal(t.raw.prepare('SELECT count(*) AS n FROM karidns_signer_state').get().n, 0);
  } finally { t.done(); }
});

test('catch-up: signer zones without a state row, and zones that changed after they were signed', async () => {
  const t = fresh();
  try {
    const [a, b, c] = ['a.test', 'b.test', 'c.test'].map((n) => id(t.raw, n));
    const sig = (d) => t.raw.exec(`INSERT INTO domainmetadata (domain_id, kind, content) VALUES (${d}, 'X-KARIDNS-SIGNER', '1')`);
    sig(a); sig(b);
    t.raw.exec('DELETE FROM karidns_changes');
    assert.deepEqual((await t.db.catchUp()).sort(), [a, b].sort());
    await t.db.recordSuccess(a, { signedAt: 2000, serial: 1, minExpire: 9999, nextDue: 9999, durationMs: 1 });
    await t.db.recordSuccess(b, { signedAt: 2000, serial: 1, minExpire: 9999, nextDue: 9999, durationMs: 1 });
    assert.deepEqual(await t.db.catchUp(), []);
    t.raw.exec(`INSERT INTO karidns_changes (domain_id, changed_at) VALUES (${a}, 1999), (${b}, 2000), (${c}, 5000)`);
    assert.deepEqual(await t.db.catchUp(), []);                    // before or at the signing time: ours; c is no signer zone
    t.raw.exec(`INSERT INTO karidns_changes (domain_id, changed_at) VALUES (${b}, 2001)`);
    assert.deepEqual(await t.db.catchUp(), [b]);
  } finally { t.done(); }
});

test('catch-up: the serial of the SOA is compared with the one the signer wrote (a change in the second of the last signature)', async () => {
  const t = fresh();
  try {
    const [a, b, c] = ['a.test', 'b.test', 'c.test'].map((n) => id(t.raw, n));
    const soa = (d, n, serial) => t.raw.exec(`INSERT INTO records (domain_id, name, type, content, ttl) VALUES (${d}, '${n}', 'SOA', 'ns1.${n} hostmaster.${n} ${serial} 7200 3600 1209600 300', 300)`);
    soa(a, 'a.test', 7); soa(b, 'b.test', 7); soa(c, 'c.test', 12);
    t.raw.exec('DELETE FROM karidns_changes');
    for (const d of [a, b, c]) await t.db.recordSuccess(d, { signedAt: 2000, serial: 7, minExpire: 9999, nextDue: 9999, durationMs: 1 });
    assert.deepEqual(await t.db.catchUp(), [c]);                  // c.test has serial 12, the signer wrote 7; no row of the change log is after 2000
    t.raw.exec(`UPDATE records SET content = 'ns1.a.test hostmaster.a.test 8 7200 3600 1209600 300' WHERE domain_id = ${a} AND type = 'SOA'`);
    assert.deepEqual((await t.db.catchUp()).sort(), [a, c].sort());
    await t.db.recordSuccess(c, { signedAt: 2000, serial: 12, minExpire: 9999, nextDue: 9999, durationMs: 1 });
    await t.db.dropState(b);                                      // no state row, no signed_serial to compare
    t.raw.exec(`DELETE FROM domainmetadata`);
    assert.deepEqual(await t.db.catchUp(), [a]);
    await t.db.recordFailure(b, { error: 'x', nextDue: () => 5 });  // a state row with no signed_serial (never signed): not compared
    assert.deepEqual(await t.db.catchUp(), [a]);
  } finally { t.done(); }
});

test('signerZones, also for a long list', async () => {
  const t = fresh();
  try {
    const a = id(t.raw, 'a.test');
    t.raw.exec(`INSERT INTO domainmetadata (domain_id, kind, content) VALUES (${a}, 'X-KARIDNS-SIGNER', '1')`);
    const ids = Array.from({ length: 1200 }, (_, i) => i + 1);
    assert.deepEqual(await t.db.signerZones(ids), [{ id: a, name: 'a.test' }]);
    assert.deepEqual(await t.db.signerZones([]), []);
  } finally { t.done(); }
});

test('the change log: position, new rows only, a pruned log is a gap', async () => {
  const t = fresh();
  try {
    t.raw.exec('DELETE FROM karidns_changes');
    t.raw.exec('DELETE FROM sqlite_sequence');
    t.raw.exec("INSERT INTO karidns_changes (domain_id, changed_at) VALUES (1, 1), (2, 2)");
    const c0 = await t.db.changesStart();
    assert.equal(c0, 2);
    t.raw.exec("INSERT INTO karidns_changes (domain_id, changed_at) VALUES (3, 3), (1, 4)");
    const r = await t.db.changesSince(c0);
    assert.deepEqual(r.rows.map((x) => [x.domainId, x.seq, x.xid]), [[3, 3, null], [1, 4, null]]);
    assert.equal(r.cursor, 4);
    assert.equal(r.gap, false);
    const none = await t.db.changesSince(r.cursor);
    assert.deepEqual([none.rows, none.cursor, none.gap], [[], 4, false]);
    t.raw.exec('DELETE FROM karidns_changes WHERE seq <= 3');
    const g = await t.db.changesSince(2);
    assert.equal(g.gap, true);
    t.raw.exec('DELETE FROM karidns_changes');
    assert.equal((await t.db.changesSince(4)).gap, false);
    assert.equal(await t.db.changesStart(), 0);
  } finally { t.done(); }
});

test('locks are the lock file, waiting is a sleep', async () => {
  const t = fresh();
  try {
    assert.equal(await t.db.tryLock(1), true);
    await t.db.unlock(1);
    await t.db.waitForChange(5);
  } finally { t.done(); }
});

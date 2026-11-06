// The PostgreSQL side against a fake pg Client: the SQL it sends, the parameters, the mapping of the rows.  The real thing (the signer's role, RLS)
// is tests/run_signer_pg_test.sh.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PgDb, parseConninfo } from '../lib/db_pg.js';

test('conninfo: the keywords we honour', () => {
  assert.deepEqual(parseConninfo('host=/var/run/postgresql dbname=karidns user=karidns_signer\n'), { host: '/var/run/postgresql', database: 'karidns', user: 'karidns_signer' });
  assert.deepEqual(parseConninfo("host = 127.0.0.1 port=5433 dbname='my db' user=u password='p w\\'x\\\\y' application_name=ks connect_timeout=7 sslmode=disable"),
    { host: '127.0.0.1', port: 5433, database: 'my db', user: 'u', password: "p w'x\\y", application_name: 'ks', connectionTimeoutMillis: 7000 });
  assert.deepEqual(parseConninfo('sslmode=require'), { ssl: { rejectUnauthorized: false } });
  assert.deepEqual(parseConninfo('sslmode=verify-full'), { ssl: { rejectUnauthorized: true } });
  assert.deepEqual(parseConninfo('sslmode=verify-ca'), { ssl: { rejectUnauthorized: true } });
  assert.deepEqual(parseConninfo('sslmode=prefer sslmode=allow'), {});
  assert.deepEqual(parseConninfo('password=a\\ b'), { password: 'a b' });
  assert.deepEqual(parseConninfo(''), {});
});

test('conninfo: anything we cannot honour is an error, not silently ignored', () => {
  assert.throws(() => parseConninfo('service=prod'), /'service' is not supported/);
  assert.throws(() => parseConninfo('options=-csearch_path=x'), /'options' is not supported/);
  assert.throws(() => parseConninfo('port=abc'), /port is not a number/);
  assert.throws(() => parseConninfo('sslmode=maybe'), /sslmode maybe/);
  assert.throws(() => parseConninfo('host'), /'=' is expected/);
  assert.throws(() => parseConninfo('=x'), /keyword is expected/);
  assert.throws(() => parseConninfo("password='abc"), /unterminated/);
});

class FakeClient {
  static all = [];
  static script = () => ({ rows: [] });

  constructor(opts) {
    this.opts = opts;
    this.log = [];
    this.h = {};
    FakeClient.all.push(this);
  }

  on(ev, fn) { this.h[ev] = fn; }

  async connect() { this.connected = true; }

  async end() { this.ended = true; }

  async query(text, params) {
    this.log.push([text.replace(/\s+/g, ' ').trim(), params]);
    return FakeClient.script(text, params, this);
  }
}

async function open(schema, script) {
  FakeClient.all = [];
  FakeClient.script = script ?? ((text) => (/to_regclass/.test(text) ? { rows: [{ ok: true }] } : { rows: [] }));
  const fatal = [];
  const db = new PgDb({ Client: FakeClient, conn: { database: 'x' }, schema, onFatal: (e) => fatal.push(e) });
  await db.open();
  const [main, listener] = FakeClient.all;
  main.log.length = 0;
  return { db, main, listener, fatal };
}
const last = (c) => c.log[c.log.length - 1];

test('open: schema, the tables are checked, LISTEN karidns_changes on a connection of its own', async () => {
  FakeClient.all = [];
  FakeClient.script = (text) => (/to_regclass/.test(text) ? { rows: [{ ok: true }] } : { rows: [] });
  const db = new PgDb({ Client: FakeClient, conn: { database: 'x' }, schema: 'karidns' });
  await db.open();
  const [main, listener] = FakeClient.all;
  assert.equal(main.opts.database, 'x');
  assert.equal(main.log[0][0], 'SET search_path TO "karidns"');
  assert.equal(listener.log[0][0], 'SET search_path TO "karidns"');
  assert.deepEqual(main.log.filter(([t]) => /to_regclass/.test(t)).map(([, p]) => p[0]), ['karidns_signer_state', 'karidns_key_requests', 'karidns_changes']);
  assert.equal(last(listener)[0], 'LISTEN karidns_changes');
  const t = await open(undefined);
  assert.ok(!FakeClient.all.some((c) => c.log.some(([q]) => /search_path/.test(q))));
  void t;
});

test('open: a missing table is explained, with the schema', async () => {
  FakeClient.all = [];
  FakeClient.script = (text, params) => (/to_regclass/.test(text) ? { rows: [{ ok: params[0] !== 'karidns_key_requests' }] } : { rows: [] });
  const db = new PgDb({ Client: FakeClient, conn: {}, schema: 'ks' });
  await assert.rejects(db.open(), /table karidns_key_requests does not exist \(apply db\/karidns_ext\.pgsql\.sql in the schema ks\)/);
  const db2 = new PgDb({ Client: FakeClient, conn: {} });
  await assert.rejects(db2.open(), /does not exist \(apply db\/karidns_ext\.pgsql\.sql\)$/);
});

test('a connection error is fatal', async () => {
  const { main, listener, fatal } = await open(undefined);
  main.h.error(new Error('connection lost'));
  listener.h.error(new Error('connection lost too'));
  assert.equal(fatal.length, 2);
});

test('zone lock: an advisory lock per schema and zone', async () => {
  const { db, main } = await open('ks');
  FakeClient.script = () => ({ rows: [{ ok: true }] });
  assert.equal(await db.tryLock(42), true);
  assert.deepEqual(last(main), ['SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS ok', ['karidns-signer:ks:42']]);
  await db.unlock(42);
  assert.deepEqual(last(main), ['SELECT pg_advisory_unlock(hashtextextended($1, 0))', ['karidns-signer:ks:42']]);
  FakeClient.script = () => ({ rows: [{ ok: false }] });
  assert.equal(await db.tryLock(43), false);
});

test('metadata and keys', async () => {
  const { db, main } = await open();
  FakeClient.script = () => ({ rows: [{ kind: 'PRESIGNED', content: '1' }, { kind: 'NSEC3PARAM', content: '1 0 0 -' }, { kind: 'X-KARIDNS-SIGNER', content: '1' }] });
  assert.deepEqual(await db.getMeta(5), { signer: true, presigned: true, nsec3param: '1 0 0 -' });
  assert.deepEqual(last(main)[1], [5]);
  FakeClient.script = () => ({ rows: [{ kind: 'X-KARIDNS-SIGNER', content: '0' }, { kind: 'PRESIGNED', content: '0' }] });
  assert.deepEqual(await db.getMeta(5), { signer: false, presigned: false, nsec3param: null });
  FakeClient.script = () => ({ rows: [{ id: 1, flags: 257, active: true, published: true, content: 'A' }, { id: 2, flags: 256, active: false, published: null, content: 'B' }, { id: 3, flags: 256, active: null, published: false, content: 'C' }] });
  assert.deepEqual((await db.getKeys(5)).map((k) => [k.flags, k.active, k.published]), [[257, true, true], [256, false, true], [256, false, false]]);
});

test('insertKeys: one statement with arrays, and the transaction id as the write id', async () => {
  const { db, main } = await open();
  FakeClient.script = () => ({ rows: [{ xid: '9001' }] });
  const w = await db.insertKeys(7, [{ flags: 257, content: 'K1' }, { flags: 256, content: 'K2' }]);
  assert.deepEqual(w, { xid: '9001', seq_first: null, seq_last: null });
  const [text, params] = last(main);
  assert.match(text, /^INSERT INTO cryptokeys \(domain_id, flags, active, published, content\) SELECT \$1, f, true, true, c FROM unnest\(\$2::int\[\], \$3::text\[\]\)/);
  assert.match(text, /RETURNING pg_current_xact_id\(\)::text AS xid$/);
  assert.deepEqual(params, [7, [257, 256], ['K1', 'K2']]);
  FakeClient.script = () => ({ rows: [] });
  assert.equal((await db.insertKeys(7, [])).xid, null);
});

test('key requests and state', async () => {
  const { db, main } = await open();
  FakeClient.script = () => ({ rows: [{ id: 1, domainId: 2, zone: 'a.test', kind: 'enable', algorithm: 13, bits: null, keyType: 'csk', nsec: null }] });
  assert.equal((await db.pendingRequests(10))[0].zone, 'a.test');
  assert.deepEqual(last(main)[1], [10]);
  await db.finishRequest(3, 'done', 'ok');
  assert.deepEqual(last(main), ["UPDATE karidns_key_requests SET state = $2, message = $3, done_at = now() WHERE id = $1 AND state = 'pending'", [3, 'done', 'ok']]);
  FakeClient.script = () => ({ rows: [{ domainId: 2, zone: 'a.test', attempts: 1 }] });
  assert.equal((await db.dueZones(1700000000, 8)).length, 1);
  assert.deepEqual(last(main)[1], [1700000000, 8]);
  await db.recordSuccess(2, { signedAt: 10, serial: 5, minExpire: 99, nextDue: 50, durationMs: 7 });
  assert.deepEqual(last(main)[1], [2, 10, 5, 99, 50, 7]);
  assert.match(last(main)[0], /ON CONFLICT \(domain_id\) DO UPDATE SET signed_at = excluded\.signed_at/);
  await db.dropState(2);
  assert.deepEqual(last(main), ['DELETE FROM karidns_signer_state WHERE domain_id = $1', [2]]);
  await db.requestReload('a.test');
  assert.deepEqual(last(main), ['INSERT INTO karidns_reload_requests (zone) VALUES ($1)', ['a.test']]);
});

test('recordFailure: attempts + 1 and the backoff for the new count', async () => {
  const { db, main } = await open();
  FakeClient.script = (t) => (/SELECT attempts/.test(t) ? { rows: [{ attempts: 2 }] } : { rows: [] });
  assert.equal(await db.recordFailure(4, { error: 'boom', nextDue: (n) => 1000 + n, durationMs: 3 }), 3);
  assert.deepEqual(last(main)[1], [4, 1003, 3, 'boom', 3]);
  FakeClient.script = () => ({ rows: [] });
  assert.equal(await db.recordFailure(4, { error: 'again', nextDue: (n) => n }), 1);
  assert.deepEqual(last(main)[1], [4, 1, 1, 'again', null]);
});

test('markDue goes in chunks, never later than it is', async () => {
  const { db, main } = await open();
  await db.markDue(Array.from({ length: 12001 }, (_, i) => i + 1), 1234);
  assert.equal(main.log.length, 3);
  assert.equal(main.log[0][1][0].length, 5000);
  assert.equal(main.log[2][1][0].length, 2001);
  assert.equal(main.log[0][1][1], 1234);
  assert.match(main.log[0][0], /least\(karidns_signer_state\.next_due, excluded\.next_due\)/);
  assert.match(main.log[0][0], /FROM domains d WHERE d\.id = ANY/);
});

test('catch-up and signer zones', async () => {
  const { db, main } = await open();
  let n = 0;
  FakeClient.script = () => ({ rows: ++n === 1 ? [{ id: 1 }, { id: 2 }] : n === 2 ? [{ id: 2 }, { id: 3 }] : [{ id: 4 }] });
  assert.deepEqual((await db.catchUp()).sort(), [1, 2, 3, 4]);
  assert.match(main.log[0][0], /NOT EXISTS \(SELECT 1 FROM karidns_signer_state/);
  assert.match(main.log[1][0], /c\.changed_at > extract\(epoch FROM s\.signed_at\)/);
  assert.match(main.log[2][0], /split_part\(r\.content, ' ', 3\)::bigint END <> s\.signed_serial/);
  main.log.length = 0;
  FakeClient.script = () => ({ rows: [{ id: 9, name: 'z.test' }] });
  assert.deepEqual(await db.signerZones(Array.from({ length: 5001 }, (_, i) => i)), [{ id: 9, name: 'z.test' }, { id: 9, name: 'z.test' }]);
  assert.equal(main.log.length, 2);
});

test('the change log: the cursor is the xmin of a snapshot, rows are handed out once', async () => {
  const { db, main } = await open();
  FakeClient.script = () => ({ rows: [{ x: '500' }] });
  assert.equal(await db.changesStart(), '500');
  assert.match(last(main)[0], /pg_snapshot_xmin\(pg_current_snapshot\(\)\)::text/);
  const rows1 = [{ xmin: '510', seq: '1', domainId: 4, xid: '505' }, { xmin: '510', seq: '2', domainId: 5, xid: '512' }];
  FakeClient.script = () => ({ rows: rows1 });
  let r = await db.changesSince('500');
  assert.deepEqual(r.rows, [{ domainId: 4, seq: 1, xid: '505' }, { domainId: 5, seq: 2, xid: '512' }]);
  assert.equal(r.cursor, '510');
  assert.equal(r.gap, false);
  assert.deepEqual(last(main)[1], ['500']);
  // the next poll sees the rows of the open transaction (xid >= cursor) again, and one new one: only the new one is new
  FakeClient.script = () => ({ rows: [{ xmin: '513', seq: '2', domainId: 5, xid: '512' }, { xmin: '513', seq: '3', domainId: 6, xid: '513' }] });
  r = await db.changesSince('510');
  assert.deepEqual(r.rows, [{ domainId: 6, seq: 3, xid: '513' }]);
  // once the cursor passes a row's transaction it is forgotten
  assert.ok(db.seen.has('3') && !db.seen.has('1'));
  FakeClient.script = () => ({ rows: [{ xmin: '600', seq: null, domainId: null, xid: null }] });
  r = await db.changesSince('513');
  assert.deepEqual(r.rows, []);
  assert.equal(db.seen.size, 0);
  assert.equal(r.cursor, '600');
});

test('waiting for a change: a notification wakes it, so does the timeout, close releases every waiter', async () => {
  const { db, listener } = await open();
  const t0 = Date.now();
  const w = db.waitForChange(60000);
  listener.h.notification({ channel: 'karidns_changes' });
  await w;
  assert.ok(Date.now() - t0 < 5000);
  await db.waitForChange(10);
  const w2 = db.waitForChange(60000);
  await db.close();
  await w2;
  assert.ok(listener.ended);
  assert.equal(db.c, null);
  await db.close();
});

test('queries run one after the other, and a failed one does not stop the queue', async () => {
  const { db } = await open();
  const order = [];
  FakeClient.script = async (t, p) => {
    order.push(`start ${p[0]}`);
    await new Promise((r) => setTimeout(r, p[0] === 1 ? 20 : 1));
    order.push(`end ${p[0]}`);
    if (p[0] === 2) throw new Error('query failed');
    return { rows: [{ ok: true }] };
  };
  const results = await Promise.allSettled([db.query('x', [1]), db.query('x', [2]), db.query('x', [3])]);
  assert.deepEqual(order, ['start 1', 'end 1', 'start 2', 'end 2', 'start 3', 'end 3']);
  assert.deepEqual(results.map((r) => r.status), ['fulfilled', 'rejected', 'fulfilled']);
});

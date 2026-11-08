// the two backends: transactions, the actor row, parameter handling, error mapping; PostgreSQL against a fake pool

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { iso, toMs, toIso, SqliteBackend, PgBackend } from '../lib/db.js';
import { mapDbError } from '../lib/errors.js';
import { sqlite, rmDir, makeFiles } from './helpers.js';

test('timestamps: ISO text without milliseconds, from a Date or text', () => {
  assert.equal(iso(Date.UTC(2026, 10, 8, 12, 0, 5, 123)), '2026-11-08T12:00:05Z');
  assert.equal(toMs(new Date(5)), 5);
  assert.equal(toMs('1970-01-01T00:00:01Z'), 1000);
  assert.equal(toMs(null), null);
  assert.equal(toMs(undefined), null);
  assert.equal(toIso(new Date(Date.UTC(2026, 0, 1))), '2026-01-01T00:00:00Z');
  assert.equal(toIso('2026-01-01T00:00:00Z'), '2026-01-01T00:00:00Z');
  assert.equal(toIso(null), null);
});

function sqliteBackend(busyMs) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-db-'));
  makeFiles(dir);
  const b = new SqliteBackend({ sqlite, file: path.join(dir, 'zones.sqlite3'), authFile: path.join(dir, 'auth.sqlite3'), busyMs });
  b.open();
  return { b, dir, done: () => { b.close(); rmDir(dir); } };
}

test('SQLite3: $n placeholders, booleans, undefined, Date, plain rows', async () => {
  const { b, done } = sqliteBackend();
  try {
    await b.tx({ write: true }, async (tx) => {
      assert.equal(tx.dialect, 'sqlite');
      assert.equal(tx.A, 'auth.');
      assert.equal(tx.z('anything'), '');
      assert.equal(tx.ts(Date.UTC(2026, 0, 1)), '2026-01-01T00:00:00Z');
      await tx.run('INSERT INTO auth.principals (kind, name, disabled, display_name) VALUES ($1, $2, $3, $4)', ['user', 'u1', true, undefined]);
      const r = await tx.get('SELECT * FROM auth.principals WHERE name = $2 AND kind = $1', ['user', 'u1']);
      assert.equal(r.disabled, 1);
      assert.equal(r.display_name, null);
      assert.equal(Object.getPrototypeOf(r), Object.prototype);
      assert.equal((await tx.run('UPDATE auth.principals SET email = $1 WHERE id = $2', ['a@b', r.id])).changes, 1);
      assert.equal(await tx.get('SELECT 1 AS x WHERE 1 = 0'), undefined);
      const when = new Date(Date.UTC(2026, 5, 1, 0, 0, 0));
      assert.equal((await tx.get('SELECT $1 AS t', [when])).t, '2026-06-01T00:00:00Z');
      // the reuse of the prepared statements, and a cache that is emptied when it grows
      for (let i = 0; i < 520; i++) await tx.get(`SELECT ${i} AS n`);
      assert.equal((await tx.get('SELECT 7 AS n')).n, 7);
      // lists as one parameter
      const ids = await tx.all(`SELECT id FROM auth.principals WHERE ${tx.list('name', 1)}`, [tx.listParam(['u1', 'zzz'])]);
      assert.equal(ids.length, 1);
    });
  } finally {
    done();
  }
});

test('SQLite3: the actor row exists while a write runs and is gone after it, also after a failure', async () => {
  const { b, done } = sqliteBackend();
  try {
    await b.tx({ write: true, principal: 7, name: 'alice', changeSet: 'cs-1' }, async (tx) => {
      const a = await tx.get('SELECT * FROM auth.karidns_auth_actor');
      assert.deepEqual({ ...a }, { id: 1, principal_id: 7, principal_name: 'alice', change_set: 'cs-1', db_role: 'karidns-webadmin' });
      await tx.run("INSERT INTO auth.principals (kind, name) VALUES ('group', 'g1')");
    });
    assert.equal(await b.tx({}, (tx) => tx.get('SELECT count(*) AS n FROM auth.karidns_auth_actor')).then((r) => r.n), 0);
    const logged = await b.tx({}, (tx) => tx.get("SELECT principal_id, principal_name, change_set FROM auth.karidns_auth_audit WHERE table_name = 'principals' ORDER BY id DESC"));
    assert.deepEqual({ ...logged }, { principal_id: 7, principal_name: 'alice', change_set: 'cs-1' });
    await assert.rejects(b.tx({ write: true, principal: 7 }, async (tx) => {
      await tx.run("INSERT INTO auth.principals (kind, name) VALUES ('group', 'g2')");
      throw new Error('stop');
    }), /stop/);
    assert.equal((await b.tx({}, (tx) => tx.get("SELECT count(*) AS n FROM auth.principals WHERE name = 'g2'"))).n, 0, 'rolled back');
    assert.equal((await b.tx({}, (tx) => tx.get('SELECT count(*) AS n FROM auth.karidns_auth_actor'))).n, 0);
    // a read transaction writes no actor row
    await b.tx({}, async (tx) => assert.equal((await tx.get('SELECT count(*) AS n FROM auth.karidns_auth_actor')).n, 0));
  } finally {
    done();
  }
});

test('SQLite3: transactions run one at a time, in order, even when they wait for something', async () => {
  const { b, done } = sqliteBackend();
  try {
    const order = [];
    const slow = b.tx({ write: true }, async (tx) => {
      order.push('a start');
      await tx.run("INSERT INTO auth.principals (kind, name) VALUES ('group', 'first')");
      await new Promise((r) => setTimeout(r, 40));
      order.push('a end');
    });
    const quick = b.tx({ write: true }, async (tx) => {
      order.push('b start');
      assert.equal((await tx.get("SELECT count(*) AS n FROM auth.principals WHERE name = 'first'")).n, 1);
    });
    const failing = b.tx({}, async () => { throw new Error('x'); });
    await Promise.all([slow, quick, failing.catch(() => {})]);
    assert.deepEqual(order, ['a start', 'a end', 'b start']);
    assert.equal(await b.tx({}, async () => 'still works'), 'still works');
  } finally {
    done();
  }
});

test('SQLite3: a locked database is a 503 with Retry-After', async () => {
  const { b, dir, done } = sqliteBackend(50);
  const other = new sqlite.DatabaseSync(path.join(dir, 'auth.sqlite3'));
  try {
    other.exec('BEGIN EXCLUSIVE');
    const err = await b.tx({ write: true }, async (tx) => tx.run("INSERT INTO auth.principals (kind, name) VALUES ('group', 'x')")).catch((e) => e);
    assert.ok(err instanceof Error);
    const api = mapDbError(err);
    assert.equal(api.status, 503);
    assert.equal(api.headers['Retry-After'], '2');
    other.exec('ROLLBACK');
    other.close();
    assert.equal(await b.tx({ write: true }, async (tx) => (await tx.run("INSERT INTO auth.principals (kind, name) VALUES ('group', 'x')")).changes), 1);
  } finally {
    done();
  }
});

test('SQLite3: setPrincipal does nothing (there is no row level security)', async () => {
  const { b, done } = sqliteBackend();
  try {
    await b.tx({}, async (tx) => { assert.equal(await tx.setPrincipal(5), undefined); });
  } finally {
    done();
  }
});

// ---- PostgreSQL against a fake pool
class FakePool {
  static last;

  constructor(opts) {
    this.opts = opts;
    this.log = [];
    this.handlers = {};
    this.failOn = null;
    this.released = [];
    FakePool.last = this;
  }

  on(ev, fn) { this.handlers[ev] = fn; }

  async query(text, params) { this.log.push([text, params]); return { rows: [{ '?column?': 1 }] }; }

  async connect() {
    const pool = this;
    return {
      async query(text, params) {
        pool.log.push([text.replace(/\s+/g, ' ').trim(), params]);
        if (pool.failOn && pool.failOn.test(text)) throw Object.assign(new Error(`fake failure on ${text}`), { code: '42501' });
        return { rows: [{ a: 1 }, { a: 2 }], rowCount: 2 };
      },
      release(broken) { pool.released.push(broken); },
    };
  }

  async end() { this.ended = true; }
}
const FakePg = { Pool: FakePool, types: { getTypeParser: (oid) => (() => `parsed ${oid}`) } };

test('PostgreSQL: the pool, the types, the checks at open', async () => {
  const errors = [];
  const b = new PgBackend({ pg: FakePg, conn: { host: '/s', user: 'karidns_api', connectionTimeoutMillis: 3000 }, poolMax: 5, onError: (e) => errors.push(e) });
  await b.open();
  const o = FakePool.last.opts;
  assert.equal(o.host, '/s');
  assert.equal(o.max, 5);
  assert.equal(o.application_name, 'karidns-webadmin');
  assert.equal(o.connectionTimeoutMillis, 3000);
  assert.equal(o.types.getTypeParser(20), Number, 'int8 as a number');
  assert.equal(o.types.getTypeParser(25, 'text')(), 'parsed 25');
  assert.deepEqual(FakePool.last.log[0], ['SELECT 1', undefined]);
  FakePool.last.handlers.error(new Error('idle client died'));
  assert.equal(errors[0].message, 'idle client died');
  const b2 = new PgBackend({ pg: FakePg, conn: {} });
  await b2.open();
  assert.equal(FakePool.last.opts.connectionTimeoutMillis, 10000);
  FakePool.last.handlers.error(new Error('ignored by default'));
  await b.close();
  assert.equal(b.pool, null);
  await b.close();
});

test('PostgreSQL: a transaction sets the principal and the change set; a read is READ ONLY', async () => {
  const b = new PgBackend({ pg: FakePg, conn: {} });
  await b.open();
  const pool = FakePool.last;
  pool.log.length = 0;
  const r = await b.tx({ principal: 42, changeSet: 'cs-9', write: true }, async (tx) => {
    assert.equal(tx.dialect, 'pg');
    assert.equal(tx.A, 'karidns_auth.');
    assert.equal(tx.z('my_schema'), '"my_schema".');
    assert.equal(tx.ts(5).getTime(), 5);
    assert.equal(tx.list('d.name', 3, 'text'), 'd.name = ANY($3::text[])');
    assert.equal(tx.list('id', 1, 'bigint'), 'id = ANY($1::bigint[])');
    assert.deepEqual(tx.listParam(['a']), ['a']);
    assert.deepEqual(await tx.all('SELECT a', [undefined, 1]), [{ a: 1 }, { a: 2 }]);
    assert.deepEqual(await tx.get('SELECT a'), { a: 1 });
    assert.deepEqual(await tx.run('UPDATE x', [1, undefined]), { changes: 2 });
    await tx.setPrincipal(77);
    return 'done';
  });
  assert.equal(r, 'done');
  assert.deepEqual(pool.log.map((l) => l[0]), [
    'BEGIN', "SELECT set_config('karidns.principal', $1, true), set_config('karidns.change_set', $2, true), set_config('statement_timeout', '30000', true)",
    'SELECT a', 'SELECT a', 'UPDATE x', "SELECT set_config('karidns.principal', $1, true)", 'COMMIT',
  ]);
  assert.deepEqual(pool.log[1][1], ['42', 'cs-9']);
  assert.deepEqual(pool.log[2][1], [null, 1], 'undefined is NULL');
  assert.deepEqual(pool.log[5][1], ['77']);
  assert.deepEqual(pool.released, [false]);
  pool.log.length = 0;
  await b.tx({}, async () => {});
  assert.equal(pool.log[0][0], 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  assert.deepEqual(pool.log[1][1], ['', '']);
});

test('PostgreSQL: an error rolls back, the connection is given back (as broken when even the rollback fails)', async () => {
  const b = new PgBackend({ pg: FakePg, conn: {} });
  await b.open();
  const pool = FakePool.last;
  pool.log.length = 0;
  await assert.rejects(b.tx({ write: true }, async () => { throw new Error('boom'); }), /boom/);
  assert.equal(pool.log.at(-1)[0], 'ROLLBACK');
  assert.deepEqual(pool.released, [false]);
  pool.failOn = /^ROLLBACK/;
  await assert.rejects(b.tx({ write: true }, async () => { throw new Error('boom2'); }), /boom2/);
  assert.deepEqual(pool.released, [false, true]);
  pool.failOn = /^COMMIT/;
  const err = await b.tx({ write: true }, async () => 1).catch((e) => e);
  assert.equal(err.code, '42501');
  assert.equal(mapDbError(err), null, 'a privilege error is not mapped: the caller logs it as a bug');
}
);

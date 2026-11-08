// The two ways to reach the database (planning 2.2).  A backend runs a function inside a transaction and hands it a `tx` with the same small interface on
// both databases:
//
//   tx.dialect            'pg' or 'sqlite'
//   tx.A                  the prefix of the auth tables ("karidns_auth." / "auth.");  tx.z(schema)  the prefix of the zone data tables of a dataset
//   tx.all(sql, params)   rows;  tx.get()  the first row or undefined;  tx.run()  { changes }
//   tx.ts(ms)             a timestamp parameter;  tx.list(arr, ...) see below
//
// SQL text is written with $1, $2 ... placeholders (SQLite3 gets ?1, ?2 ...).  Values are bound, never pasted into the text; the only things that are pasted
// are schema names (checked by the configuration: letters, digits, underscore) and numbers the code computed itself.
//
// PostgreSQL: one pool of connections as the role karidns_api; every transaction sets karidns.principal and karidns.change_set (SET LOCAL semantics), so row
// level security knows who acts.  SQLite3: ONE connection (the zone file with the auth file attached as `auth`), so transactions are run one at a time;
// the audit triggers of the auth file read the actor row that a writing transaction puts in karidns_auth_actor first and deletes last.

export const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

// a timestamp column as unix milliseconds (pg gives a Date, SQLite3 the text we wrote, or, in the karidns_* tables of the zone file that the signer and the loader
// write, the number of seconds since the epoch)
export const toMs = (v) => (v instanceof Date ? v.getTime() : v === null || v === undefined ? null : typeof v === 'number' || typeof v === 'bigint' ? Number(v) * 1000 : Date.parse(v));
export const toIso = (v) => (v === null || v === undefined ? null : iso(toMs(v)));

const sqliteSql = (sql) => sql.replace(/\$(\d+)/g, '?$1');
const sqliteParam = (v) => (v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v instanceof Date ? iso(v.getTime()) : v);

class SqliteTx {
  constructor(db) {
    this.db = db;
    this.dialect = 'sqlite';
    this.A = 'auth.';
    this.cache = new Map();
  }

  z() { return ''; }

  // the principal of the rest of the transaction (PostgreSQL: karidns.principal, for row level security; SQLite3 has no row level security)
  async setPrincipal() {}

  ts(ms) { return iso(ms); }

  // "col IN (list)" for a list that is one parameter: SQLite3 takes it as JSON text; n is the placeholder number
  list(col, n) { return `${col} IN (SELECT value FROM json_each($${n}))`; }

  listParam(arr) { return JSON.stringify(arr); }

  stmt(sql) {
    let s = this.cache.get(sql);
    if (!s) {
      s = this.db.prepare(sqliteSql(sql));
      if (this.cache.size > 500) this.cache.clear();
      this.cache.set(sql, s);
    }
    return s;
  }

  async all(sql, params = []) { return this.stmt(sql).all(...params.map(sqliteParam)).map((r) => ({ ...r })); }

  async get(sql, params = []) {
    const r = this.stmt(sql).get(...params.map(sqliteParam));
    return r ? { ...r } : undefined;
  }

  async run(sql, params = []) { return { changes: Number(this.stmt(sql).run(...params.map(sqliteParam)).changes) }; }
}

export class SqliteBackend {
  constructor({ sqlite, file, authFile, busyMs = 5000 }) {
    this.sqlite = sqlite;
    this.file = file;
    this.authFile = authFile;
    this.busyMs = busyMs;
    this.db = null;
    this.tail = Promise.resolve();
    this.dialect = 'sqlite';
  }

  open() {
    this.db = new this.sqlite.DatabaseSync(this.file);
    this.db.exec(`PRAGMA busy_timeout = ${Number(this.busyMs)}`);
    this.db.exec('PRAGMA foreign_keys = ON');
    this.db.prepare('ATTACH DATABASE ?1 AS auth').run(this.authFile);
    // the audit triggers of the zone file (db/karidns_audit.sqlite3.sql) read who writes from a row of their own database: written with the actor row of the auth file
    this.zoneActor = Boolean(this.db.prepare("SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = 'karidns_audit_actor'").get());
    this.tx0 = new SqliteTx(this.db);
  }

  close() {
    this.db?.close();
    this.db = null;
  }

  // one transaction at a time: the connection is shared, so two requests must not interleave their statements
  tx({ principal = null, name = null, changeSet = null, write = false } = {}, fn) {
    const run = this.tail.then(async () => {
      this.db.exec(write ? 'BEGIN IMMEDIATE' : 'BEGIN');
      try {
        if (write) {
          this.db.prepare("INSERT OR REPLACE INTO auth.karidns_auth_actor (id, principal_id, principal_name, change_set, db_role) VALUES (1, ?1, ?2, ?3, 'karidns-webadmin')")
            .run(principal, name, changeSet);
          if (this.zoneActor) {
            this.db.prepare("INSERT OR REPLACE INTO main.karidns_audit_actor (id, principal_id, principal_name, change_set, db_role) VALUES (1, ?1, ?2, ?3, 'karidns-webadmin')")
              .run(principal, name, changeSet);
          }
        }
        const r = await fn(this.tx0);
        if (write) {
          this.db.exec('DELETE FROM auth.karidns_auth_actor WHERE id = 1');
          if (this.zoneActor) this.db.exec('DELETE FROM main.karidns_audit_actor WHERE id = 1');
        }
        this.db.exec('COMMIT');
        return r;
      } catch (e) {
        try { this.db.exec('ROLLBACK'); } catch { /* the transaction is gone already */ }
        throw e;
      }
    });
    this.tail = run.catch(() => {});
    return run;
  }
}

class PgTx {
  constructor(client) {
    this.c = client;
    this.dialect = 'pg';
    this.A = 'karidns_auth.';
  }

  z(schema) { return `"${schema}".`; }

  async setPrincipal(id) { await this.c.query("SELECT set_config('karidns.principal', $1, true)", [String(id)]); }

  ts(ms) { return new Date(ms); }

  list(col, n, type = 'text') { return `${col} = ANY($${n}::${type}[])`; }

  listParam(arr) { return arr; }

  async all(sql, params = []) { return (await this.c.query(sql, params.map((v) => (v === undefined ? null : v)))).rows; }

  async get(sql, params = []) { return (await this.all(sql, params))[0]; }

  async run(sql, params = []) { return { changes: (await this.c.query(sql, params.map((v) => (v === undefined ? null : v)))).rowCount }; }
}

export class PgBackend {
  // pg: the module (Pool, types); conn: the options of a connection (parseConninfo); poolMax: the most connections
  constructor({ pg, conn, poolMax = 8, onError = () => {} }) {
    this.pg = pg;
    this.conn = conn;
    this.poolMax = poolMax;
    this.onError = onError;
    this.pool = null;
    this.dialect = 'pg';
  }

  async open() {
    // bigint columns (ids, generations) come as numbers: none of them grows past 2^53
    const base = this.pg.types.getTypeParser;
    this.pool = new this.pg.Pool({
      ...this.conn,
      max: this.poolMax,
      application_name: 'karidns-webadmin',
      idleTimeoutMillis: 60000,
      connectionTimeoutMillis: this.conn.connectionTimeoutMillis ?? 10000,
      types: { getTypeParser: (oid, fmt) => (oid === 20 ? Number : base(oid, fmt)) },
    });
    this.pool.on('error', (e) => this.onError(e));
    await this.pool.query('SELECT 1');
  }

  async close() {
    await this.pool?.end();
    this.pool = null;
  }

  async tx({ principal = null, changeSet = null, write = false } = {}, fn) {
    const c = await this.pool.connect();
    let broken = false;
    try {
      await c.query(write ? 'BEGIN' : 'BEGIN READ ONLY');
      await c.query("SELECT set_config('karidns.principal', $1, true), set_config('karidns.change_set', $2, true), set_config('statement_timeout', '30000', true)",
        [principal === null ? '' : String(principal), changeSet ?? '']);
      const r = await fn(new PgTx(c));
      await c.query('COMMIT');
      return r;
    } catch (e) {
      try { await c.query('ROLLBACK'); } catch { broken = true; }
      throw e;
    } finally {
      c.release(broken);
    }
  }
}

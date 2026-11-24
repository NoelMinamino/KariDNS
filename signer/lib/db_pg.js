// PostgreSQL side of the database interface (db_sqlite.js lists it).  The npm package `pg` is the only dependency of the project; the signer's role
// (db/karidns_signer_role.pgsql.sql) may read everything, INSERT into cryptokeys, answer key requests and write karidns_signer_state; the zone data goes
// through karidns-zone.  Times travel as unix seconds (to_timestamp / extract(epoch)).
//
// One connection does all the queries, one runs LISTEN karidns_changes.  Queries are serialised (a promise chain), so nothing interleaves; every
// statement is a single statement (no transaction spans two awaits).

import { STORED_KEYS } from './keys.js';

const CHUNK = 5000;
const RETRY_DUES = 16;                  // (recordFailure; scheduler.js backoff() is constant from the 7th failure on)

export class PgDb {
  // Client: pg's Client class; conn: its options; schema: undefined or a checked schema name
  constructor({ Client, conn, schema, onFatal }) {
    this.Client = Client;
    this.conn = conn;
    this.schema = schema;
    this.onFatal = onFatal;
    this.c = null;
    this.l = null;
    this.tail = Promise.resolve();
    this.waiters = new Set();
    this.seen = new Map();              // seq -> xid of the log rows already handed out whose transaction may still be in the cursor window
    this.lockKey = (id) => `karidns-signer:${this.schema ?? ''}:${id}`;
  }

  async open() {
    this.c = new this.Client(this.conn);
    this.l = new this.Client(this.conn);
    for (const cl of [this.c, this.l]) cl.on('error', (e) => this.onFatal?.(e));
    await this.c.connect();
    await this.l.connect();
    if (this.schema) {
      const sp = `SET search_path TO "${this.schema}"`;           // the schema name was checked (config.js: letters, digits, underscore)
      await this.c.query(sp);
      await this.l.query(sp);
    }
    for (const t of ['karidns_signer_state', 'karidns_key_requests', 'karidns_changes']) {
      const r = await this.c.query('SELECT to_regclass($1) IS NOT NULL AS ok', [t]);
      if (!r.rows[0].ok) throw new Error(`table ${t} does not exist (apply db/karidns_ext.pgsql.sql${this.schema ? ` in the schema ${this.schema}` : ''})`);
    }
    this.l.on('notification', () => this.wake());
    await this.l.query('LISTEN karidns_changes');
  }

  async close() {
    for (const cl of [this.c, this.l]) {
      try { await cl?.end(); } catch { /* gone */ }
    }
    this.c = null;
    this.l = null;
    this.wake();
  }

  wake() {
    for (const w of this.waiters) w();
    this.waiters.clear();
  }

  // serialise: fn runs after the earlier calls have finished
  q(fn) {
    const p = this.tail.then(fn);
    this.tail = p.catch(() => {});
    return p;
  }

  query(text, params) {
    return this.q(() => this.c.query(text, params));
  }

  async tryLock(id) {
    const r = await this.query('SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS ok', [this.lockKey(id)]);
    return r.rows[0].ok === true;
  }

  async unlock(id) {
    await this.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [this.lockKey(id)]);
  }

  async getMeta(id) {
    const r = await this.query("SELECT upper(kind) AS kind, content FROM domainmetadata WHERE domain_id = $1 AND upper(kind) IN ('PRESIGNED', 'NSEC3PARAM', 'X-KARIDNS-SIGNER')", [id]);
    const m = { signer: false, presigned: false, nsec3param: null };
    for (const row of r.rows) {
      if (row.kind === 'X-KARIDNS-SIGNER') m.signer = row.content === '1';
      else if (row.kind === 'PRESIGNED') m.presigned = row.content === '1';
      else m.nsec3param = row.content;
    }
    return m;
  }

  async getKeys(id) {
    const r = await this.query('SELECT id, flags, active, published, content FROM cryptokeys WHERE domain_id = $1 ORDER BY id', [id]);
    return r.rows.map((k) => ({ id: k.id, flags: k.flags, active: k.active === true, published: k.published == null ? true : k.published === true, content: k.content }));
  }

  // all keys in one statement: all or none.  Returns the write id (the xid8 of the transaction), so that the change log rows of the INSERT are known as ours, and the
  // ids of the rows.  requestId: the pending request the keys are for; the same statement writes STORED_KEYS and the ids into its message (pipeline.js, review W1-L1).
  async insertKeys(id, keys, requestId = null) {
    const r = await this.query(`WITH k AS (INSERT INTO cryptokeys (domain_id, flags, active, published, content) SELECT $1, f, true, true, c FROM unnest($2::int[], $3::text[]) AS t(f, c) RETURNING id),
        ids AS (SELECT string_agg(id::text, ',' ORDER BY id) AS ids FROM k),
        n AS (UPDATE karidns_key_requests SET message = $5::text || (SELECT ids FROM ids) WHERE id = $4 AND state = 'pending' RETURNING 1)
      SELECT pg_current_xact_id()::text AS xid, (SELECT ids FROM ids) AS ids`,
    [id, keys.map((k) => k.flags), keys.map((k) => k.content), requestId, STORED_KEYS]);
    return { xid: r.rows[0]?.xid ?? null, seq_first: null, seq_last: null, ids: (r.rows[0]?.ids ?? '').split(',').filter(Boolean).map(Number) };
  }

  // the message of the latest enable request of the zone that names keys an earlier try stored (pipeline.js), or null
  async storedKeysNote(id) {
    const r = await this.query("SELECT message FROM karidns_key_requests WHERE domain_id = $1 AND kind = 'enable' AND strpos(message, $2::text) > 0 ORDER BY id DESC LIMIT 1", [id, STORED_KEYS]);
    return r.rows[0]?.message ?? null;
  }

  async pendingRequests(limit) {
    const r = await this.query(`SELECT r.id::int AS id, r.domain_id AS "domainId", d.name AS zone, r.kind, r.algorithm::int AS algorithm, r.bits, r.key_type AS "keyType", r.nsec
      FROM karidns_key_requests r JOIN domains d ON d.id = r.domain_id WHERE r.state = 'pending' ORDER BY r.id LIMIT $1`, [limit]);
    return r.rows;
  }

  async finishRequest(id, state, message) {
    await this.query("UPDATE karidns_key_requests SET state = $2, message = $3, done_at = now() WHERE id = $1 AND state = 'pending'", [id, state, message]);
  }

  async dueZones(now, limit) {
    const r = await this.query(`SELECT s.domain_id AS "domainId", d.name AS zone, s.attempts FROM karidns_signer_state s JOIN domains d ON d.id = s.domain_id
      WHERE s.next_due <= to_timestamp($1::double precision) ORDER BY s.next_due LIMIT $2`, [now, limit]);
    return r.rows;
  }

  async recordSuccess(id, s) {
    await this.query(`INSERT INTO karidns_signer_state (domain_id, signed_at, signed_serial, min_expire, next_due, attempts, last_error, last_duration_ms)
      VALUES ($1, to_timestamp($2::double precision), $3, to_timestamp($4::double precision), to_timestamp($5::double precision), 0, NULL, $6)
      ON CONFLICT (domain_id) DO UPDATE SET signed_at = excluded.signed_at, signed_serial = excluded.signed_serial, min_expire = excluded.min_expire,
        next_due = excluded.next_due, attempts = 0, last_error = NULL, last_duration_ms = excluded.last_duration_ms`,
    [id, s.signedAt, s.serial, s.minExpire, s.nextDue, s.durationMs]);
  }

  // attempts + 1, the error, and the next time from the backoff for the new count; returns the count.  One statement (review W1-L2, 0.7): the advisory lock of the
  // zone is released when the run ends, before its result is recorded, so a SELECT and a later write would let the write of another instance in between and
  // overwrite it with a stale count.  The next times of the counts 1..RETRY_DUES go as one array (the backoff stops growing long before that) and the statement
  // takes the one of the count it makes.
  async recordFailure(id, f) {
    const dues = Array.from({ length: RETRY_DUES }, (_, i) => f.nextDue(i + 1));
    const r = await this.query(`INSERT INTO karidns_signer_state AS s (domain_id, next_due, attempts, last_error, last_duration_ms) VALUES ($1, to_timestamp(($2::float8[])[1]), 1, $3, $4)
      ON CONFLICT (domain_id) DO UPDATE SET attempts = s.attempts + 1, next_due = to_timestamp(($2::float8[])[least(s.attempts + 1, ${RETRY_DUES})]),
        last_error = excluded.last_error, last_duration_ms = excluded.last_duration_ms RETURNING attempts`, [id, dues, f.error, f.durationMs ?? null]);
    return r.rows[0].attempts;
  }

  async markDue(ids, now) {
    for (let i = 0; i < ids.length; i += CHUNK) {
      await this.query(`INSERT INTO karidns_signer_state (domain_id, next_due) SELECT d.id, to_timestamp($2::double precision) FROM domains d WHERE d.id = ANY($1::int[])
        ON CONFLICT (domain_id) DO UPDATE SET next_due = least(karidns_signer_state.next_due, excluded.next_due)`, [ids.slice(i, i + CHUNK), now]);
    }
  }

  async dropState(id) {
    await this.query('DELETE FROM karidns_signer_state WHERE domain_id = $1', [id]);
  }

  async catchUp() {
    const a = await this.query(`SELECT d.id FROM domains d JOIN domainmetadata m ON m.domain_id = d.id AND upper(m.kind) = 'X-KARIDNS-SIGNER' AND m.content = '1'
      WHERE NOT EXISTS (SELECT 1 FROM karidns_signer_state s WHERE s.domain_id = d.id)`);
    const b = await this.query(`SELECT DISTINCT s.domain_id AS id FROM karidns_signer_state s JOIN karidns_changes c ON c.domain_id = s.domain_id
      WHERE s.signed_at IS NOT NULL AND c.changed_at > extract(epoch FROM s.signed_at)`);
    // the serial of the SOA is not the one the signer wrote: somebody changed the zone, also in the second of the last signature (the comparison of whole
    // seconds above cannot tell a change from the signer's own rows there)
    const c = await this.query(`SELECT s.domain_id AS id FROM karidns_signer_state s JOIN records r ON r.domain_id = s.domain_id AND r.type = 'SOA'
      WHERE s.signed_serial IS NOT NULL AND CASE WHEN split_part(r.content, ' ', 3) ~ '^[0-9]+$' THEN split_part(r.content, ' ', 3)::bigint END <> s.signed_serial`);
    return [...new Set([...a.rows, ...b.rows, ...c.rows].map((r) => r.id))];
  }

  async signerZones(ids) {
    const out = [];
    for (let i = 0; i < ids.length; i += CHUNK) {
      const r = await this.query(`SELECT d.id, d.name FROM domains d JOIN domainmetadata m ON m.domain_id = d.id AND upper(m.kind) = 'X-KARIDNS-SIGNER' AND m.content = '1'
        WHERE d.id = ANY($1::int[])`, [ids.slice(i, i + CHUNK)]);
      out.push(...r.rows);
    }
    return out;
  }

  // The cursor is the xmin of a snapshot, not a seq (dns_db_pgsql.c explains: seq is drawn when a statement ends, a row is visible when its transaction
  // commits).  Every transaction below the xmin has finished and its rows are visible, so they are final.
  async changesStart() {
    const r = await this.query('SELECT pg_snapshot_xmin(pg_current_snapshot())::text AS x');
    return r.rows[0].x;
  }

  // the rows with xid >= cursor that we have not handed out yet, and the new cursor.  One statement, so xmin and the rows share a snapshot.
  async changesSince(cursor) {
    const r = await this.query(`WITH s AS (SELECT pg_snapshot_xmin(pg_current_snapshot())::text AS xmin)
      SELECT s.xmin, c.seq::text AS seq, c.domain_id AS "domainId", c.xid::text AS xid FROM s LEFT JOIN karidns_changes c ON c.xid >= $1::xid8 ORDER BY c.seq`, [cursor]);
    const xmin = r.rows[0].xmin;
    const rows = [];
    for (const row of r.rows) {
      if (row.seq == null || this.seen.has(row.seq)) continue;
      this.seen.set(row.seq, row.xid);
      rows.push({ domainId: row.domainId, seq: Number(row.seq), xid: row.xid });
    }
    const lim = BigInt(xmin);
    for (const [seq, xid] of this.seen) if (BigInt(xid) < lim) this.seen.delete(seq);
    return { rows, cursor: xmin, gap: false };
  }

  // NOTIFY karidns_changes wakes us; the timeout is the fallback poll
  waitForChange(ms) {
    return new Promise((resolve) => {
      const t = setTimeout(() => { this.waiters.delete(done); resolve(); }, ms);
      t.unref?.();
      const done = () => { clearTimeout(t); resolve(); };
      this.waiters.add(done);
    });
  }
}

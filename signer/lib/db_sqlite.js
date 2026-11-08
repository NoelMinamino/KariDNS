// SQLite3 side of the database interface (planning 3.1).  The signer touches only the schedule (karidns_signer_state), the cryptokeys it adds, the key
// requests and the change log; the zone data goes through karidns-zone.  Built-in node:sqlite, no package.  Times are unix seconds.
//
// The interface (db_pg.js has the same):
//   open() close()  tryLock(id) unlock(id)  getMeta(id)  getKeys(id)  insertKeys(id, keys)  pendingRequests(limit)  finishRequest(id, state, message)
//   dueZones(now, limit)  recordSuccess(id, s)  recordFailure(id, f)  markDue(ids, now)  dropState(id)  catchUp()  signerZones(ids)
//   changesStart()  changesSince(cursor)  waitForChange(ms)

import fs from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

const META_KINDS = ['PRESIGNED', 'NSEC3PARAM', 'X-KARIDNS-SIGNER'];
const CHUNK = 500;

// One signer per database file: a lock file next to it holding our pid.  A file of a process that is gone is taken over.  Returns a function that
// releases the lock.
export function acquireFileLock(path, { pid = process.pid, kill = process.kill } = {}) {
  for (let tries = 0; tries < 3; tries++) {
    try {
      const fd = fs.openSync(path, 'wx', 0o600);
      fs.writeSync(fd, `${pid}\n`);
      fs.closeSync(fd);
      return () => { try { fs.unlinkSync(path); } catch { /* gone */ } };
    } catch (e) {
      if (e.code !== 'EEXIST') throw new Error(`cannot create the lock file ${path}: ${e.message}`);
    }
    let other = NaN;
    try { other = Number(fs.readFileSync(path, 'utf8').trim()); } catch { /* gone again: try to create it */ }
    if (Number.isInteger(other) && other > 0 && other !== pid) {
      let alive = true;
      try { kill(other, 0); } catch (e) { alive = e.code === 'EPERM'; }
      if (alive) throw new Error(`another karidns-signer (pid ${other}) works on this database: ${path}`);
    }
    try { fs.unlinkSync(path); } catch { /* somebody else did */ }
  }
  throw new Error(`cannot take the lock file ${path}`);
}

export class SqliteDb {
  constructor({ file, sqlite, sleepFn = sleep }) {
    this.file = file;
    this.sqlite = sqlite;
    this.sleep = sleepFn;
    this.db = null;
    this.releaseLock = null;
  }

  open() {
    this.releaseLock = acquireFileLock(`${this.file}.signer.lock`);
    try {
      this.db = new this.sqlite.DatabaseSync(this.file);
      this.db.exec('PRAGMA busy_timeout = 10000');
      for (const t of ['karidns_signer_state', 'karidns_key_requests', 'karidns_changes', 'cryptokeys', 'domainmetadata', 'domains']) {
        if (!this.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(t)) {
          throw new Error(`table ${t} does not exist in ${this.file} (apply db/karidns_ext.sqlite3.sql)`);
        }
      }
    } catch (e) {
      this.close();
      throw e;
    }
  }

  close() {
    try { this.db?.close(); } catch { /* closed */ }
    this.db = null;
    this.releaseLock?.();
    this.releaseLock = null;
  }

  // one signer per file: the lock file is the zone lock too
  async tryLock() { return true; }

  async unlock() { /* nothing */ }

  async getMeta(id) {
    const rows = this.db.prepare(`SELECT kind, content FROM domainmetadata WHERE domain_id = ? AND kind IN (${META_KINDS.map(() => '?').join(',')})`).all(id, ...META_KINDS);
    const m = { signer: false, presigned: false, nsec3param: null };
    for (const r of rows) {
      const k = r.kind.toUpperCase();
      if (k === 'X-KARIDNS-SIGNER') m.signer = r.content === '1';
      else if (k === 'PRESIGNED') m.presigned = r.content === '1';
      else if (k === 'NSEC3PARAM') m.nsec3param = r.content;
    }
    return m;
  }

  async getKeys(id) {
    return this.db.prepare('SELECT id, flags, active, published, content FROM cryptokeys WHERE domain_id = ? ORDER BY id').all(id)
      .map((r) => ({ id: r.id, flags: r.flags, active: !!r.active, published: r.published == null ? true : !!r.published, content: r.content }));
  }

  async insertKeys(id, keys) {
    const ins = this.db.prepare('INSERT INTO cryptokeys (domain_id, flags, active, published, content) VALUES (?, ?, 1, 1, ?)');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const before = this.db.prepare('SELECT coalesce(max(seq), 0) AS m FROM karidns_changes').get().m;
      for (const k of keys) ins.run(id, k.flags, k.content);
      const after = this.db.prepare('SELECT coalesce(max(seq), 0) AS m FROM karidns_changes').get().m;
      this.db.exec('COMMIT');
      return { xid: null, seq_first: after > before ? before + 1 : null, seq_last: after > before ? after : null };   // the write id: the log rows are ours
    } catch (e) {
      try { this.db.exec('ROLLBACK'); } catch { /* no transaction */ }
      throw e;
    }
  }

  async pendingRequests(limit) {
    return this.db.prepare(`SELECT r.id, r.domain_id AS domainId, d.name AS zone, r.kind, r.algorithm, r.bits, r.key_type AS keyType, r.nsec
      FROM karidns_key_requests r JOIN domains d ON d.id = r.domain_id WHERE r.state = 'pending' ORDER BY r.id LIMIT ?`).all(limit).map((r) => ({ ...r }));
  }

  async finishRequest(id, state, message, now) {
    this.db.prepare("UPDATE karidns_key_requests SET state = ?, message = ?, done_at = ? WHERE id = ? AND state = 'pending'").run(state, message, now, id);
  }

  async dueZones(now, limit) {
    return this.db.prepare(`SELECT s.domain_id AS domainId, d.name AS zone, s.attempts FROM karidns_signer_state s JOIN domains d ON d.id = s.domain_id
      WHERE s.next_due <= ? ORDER BY s.next_due LIMIT ?`).all(now, limit).map((r) => ({ ...r }));
  }

  async recordSuccess(id, s) {
    this.db.prepare(`INSERT INTO karidns_signer_state (domain_id, signed_at, signed_serial, min_expire, next_due, attempts, last_error, last_duration_ms)
      VALUES (?, ?, ?, ?, ?, 0, NULL, ?)
      ON CONFLICT (domain_id) DO UPDATE SET signed_at = excluded.signed_at, signed_serial = excluded.signed_serial, min_expire = excluded.min_expire,
        next_due = excluded.next_due, attempts = 0, last_error = NULL, last_duration_ms = excluded.last_duration_ms`)
      .run(id, s.signedAt, s.serial, s.minExpire, s.nextDue, s.durationMs);
  }

  // attempts + 1, the error, and the next time from the backoff for the new count; returns the new count
  async recordFailure(id, f) {
    const old = this.db.prepare('SELECT attempts FROM karidns_signer_state WHERE domain_id = ?').get(id);
    const attempts = (old?.attempts ?? 0) + 1;
    this.db.prepare(`INSERT INTO karidns_signer_state (domain_id, next_due, attempts, last_error, last_duration_ms) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (domain_id) DO UPDATE SET next_due = excluded.next_due, attempts = excluded.attempts, last_error = excluded.last_error,
        last_duration_ms = excluded.last_duration_ms`).run(id, f.nextDue(attempts), attempts, f.error, f.durationMs ?? null);
    return attempts;
  }

  async markDue(ids, now) {
    const st = this.db.prepare(`INSERT INTO karidns_signer_state (domain_id, next_due) SELECT id, ? FROM domains WHERE id = ?
      ON CONFLICT (domain_id) DO UPDATE SET next_due = min(next_due, excluded.next_due)`);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const id of ids) st.run(now, id);
      this.db.exec('COMMIT');
    } catch (e) {
      try { this.db.exec('ROLLBACK'); } catch { /* no transaction */ }
      throw e;
    }
  }

  async dropState(id) {
    this.db.prepare('DELETE FROM karidns_signer_state WHERE domain_id = ?').run(id);
  }

  // the zones the change log cannot tell us about (start, a log that was pruned past our position): signer zones without a state row, and zones
  // that changed after they were signed (the change log, or the serial of the SOA)
  async catchUp() {
    const a = this.db.prepare(`SELECT d.id FROM domains d JOIN domainmetadata m ON m.domain_id = d.id AND m.kind = 'X-KARIDNS-SIGNER' AND m.content = '1'
      WHERE NOT EXISTS (SELECT 1 FROM karidns_signer_state s WHERE s.domain_id = d.id)`).all();
    const b = this.db.prepare(`SELECT DISTINCT s.domain_id AS id FROM karidns_signer_state s JOIN karidns_changes c ON c.domain_id = s.domain_id
      WHERE s.signed_at IS NOT NULL AND c.changed_at > s.signed_at`).all();
    // the serial of the SOA is not the one the signer wrote (the third word of the content): somebody changed the zone, also in the second of the last signature,
    // which the comparison of whole seconds above cannot tell from the signer's own rows
    const c = this.db.prepare(`WITH s1 AS (SELECT s.domain_id AS id, s.signed_serial AS ss, substr(r.content, instr(r.content, ' ') + 1) AS t
        FROM karidns_signer_state s JOIN records r ON r.domain_id = s.domain_id AND r.type = 'SOA' WHERE s.signed_serial IS NOT NULL),
      s2 AS (SELECT id, ss, substr(t, instr(t, ' ') + 1) AS t FROM s1)
      SELECT id FROM s2 WHERE CAST(substr(t, 1, instr(t || ' ', ' ') - 1) AS INTEGER) <> ss`).all();
    return [...new Set([...a, ...b, ...c].map((r) => r.id))];
  }

  // the subset of ids that are zones of the signer (X-KARIDNS-SIGNER = 1), with their names
  async signerZones(ids) {
    const out = [];
    for (let i = 0; i < ids.length; i += CHUNK) {
      const part = ids.slice(i, i + CHUNK);
      out.push(...this.db.prepare(`SELECT d.id AS id, d.name AS name FROM domains d JOIN domainmetadata m ON m.domain_id = d.id AND m.kind = 'X-KARIDNS-SIGNER' AND m.content = '1'
        WHERE d.id IN (${part.map(() => '?').join(',')})`).all(...part).map((r) => ({ ...r })));
    }
    return out;
  }

  async changesStart() {
    return this.db.prepare('SELECT coalesce(max(seq), 0) AS m FROM karidns_changes').get().m;
  }

  // the rows after the cursor (a seq); gap: the log was pruned beyond our position
  async changesSince(cursor) {
    const rows = this.db.prepare('SELECT seq, domain_id AS domainId FROM karidns_changes WHERE seq > ? ORDER BY seq LIMIT 20000').all(cursor);
    const min = this.db.prepare('SELECT min(seq) AS m FROM karidns_changes').get().m;
    const gap = cursor > 0 && min != null && min > cursor + 1;
    return { rows: rows.map((r) => ({ domainId: r.domainId, seq: r.seq, xid: null })), cursor: rows.length ? rows[rows.length - 1].seq : cursor, gap };
  }

  // SQLite3 has no notification: poll
  async waitForChange(ms) {
    await this.sleep(ms);
  }
}

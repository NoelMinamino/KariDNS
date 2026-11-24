// The arithmetic of when a zone is looked at again (planning 3.6).  Pure; the daemon (daemon.js) holds the state.

const DAY = 86400;

// The shortest time between two signings of a zone the schedule makes (review W1-L5, 0.7), or validity - refresh - jitter when that is shorter.
export const MIN_RESIGN_INTERVAL = 3600;

// next_due = the earliest RRSIG expiration in the zone - refresh - a random part of the jitter (so a million zones spread out).  dnssec-signzone runs with
// -i refresh+jitter (argv.js), so every signature it makes has more than refresh+jitter left and the result is after `now` for any random part.  An expiration
// that is earlier (a signature that signzone keeps but does not make again, such as one of a key that was made inactive in a rollover, docs/karidns-signer.md;
// or a clock that went backwards) is not cured by signing again at once, and the run that just ended was a success, so no error backoff applies: the floor is
// MIN_RESIGN_INTERVAL from now (at most validity - refresh - jitter), never the next second.  Without an expiration (min_expire unknown, or not believable:
// plausibleExpire) the zone is looked at after validity - refresh - jitter, the time a fresh signature has until it is due.
export function nextDue({ minExpire, refresh, jitter, validity, now, rand = Math.random }) {
  const fresh = Math.max(1, validity - refresh - jitter);
  if (minExpire == null) return now + fresh;
  const part = Math.floor(rand() * jitter);
  return Math.max(minExpire - refresh - part, now + Math.min(MIN_RESIGN_INTERVAL, fresh));
}

// The earliest expiration karidns-zone import reported, if it is a time the schedule can use: an integer that is not more than a year after the end of a fresh
// signature (signatures that are kept from an earlier signer may be longer than our validity; years are not a value dnssec-signzone gives).  Else null.
export function plausibleExpire(minExpire, now, validity) {
  if (!Number.isSafeInteger(minExpire) || minExpire < 0) return null;
  return minExpire > now + validity + 366 * DAY ? null : minExpire;
}

// What the log says about an odd expiration after a successful run (raw: as reported), or null.
export function expireProblem({ raw, now, refresh, validity }) {
  if (raw == null) return null;
  if (plausibleExpire(raw, now, validity) == null) return `karidns-zone reported the earliest signature expiration ${JSON.stringify(raw).slice(0, 40)}, which is not a time to plan by: the zone is looked at again after validity - refresh - jitter`;
  if (raw - refresh > now) return null;
  const when = new Date(raw * 1000).toISOString().replace(/\.000Z$/, 'Z');
  return `the earliest signature of the zone expires at ${when}, within refresh of now, although the zone was just signed: a signature that dnssec-signzone keeps (of a key that is not active any more?) or a wrong clock; the zone is not signed again before ${MIN_RESIGN_INTERVAL} s (at most validity - refresh - jitter)`;
}

// 1 minute doubling to 1 hour (planning 3.3): attempts is the number of failures so far, at least 1
export function backoff(attempts) {
  const n = Math.max(1, attempts);
  return Math.min(3600, 60 * 2 ** Math.min(n - 1, 12));
}

// the retry delay after "the zone is busy" (exit status 4): short, doubling to one minute
export function busyDelay(times) {
  return Math.min(60, 5 * 2 ** Math.min(Math.max(times, 1) - 1, 4));
}

// How many times in a row a run may find the zone changed (exit status 3) and be repeated at once; after that the error backoff applies.
export const CHANGED_RETRIES = 3;

// The change log of the signer's zones, debounced (planning 3.6): a zone is due `debounce` seconds after its last change, but at most `max` seconds
// after the first change of the burst.  An entry keeps the log rows that reported the zone, so that the rows of our own writes can be dropped when the
// zone is flushed (a write id is known only after the run that made it).
export class Debounce {
  constructor(debounce, max = debounce * 6) {
    this.debounce = debounce;
    this.max = max;
    this.zones = new Map();               // domain id -> { first, last, rows: [{ seq, seqEnd, xid }] }
  }

  add(domainId, row, now) {
    let z = this.zones.get(domainId);
    if (!z) {
      z = { first: now, last: now, rows: [], overflow: false };
      this.zones.set(domainId, z);
    }
    z.last = now;
    // The rows are kept as few entries: PostgreSQL writes a handful of log rows per transaction (one entry per xid); SQLite3 writes a row per changed row, and a
    // write of a big zone makes ten thousands of them, in one run of consecutive seq (a single writer): one entry { seq, seqEnd } per run.
    if (row.xid != null) {
      if (z.rows.some((r) => r.xid === row.xid)) return;
    } else {
      const prev = z.rows[z.rows.length - 1];
      if (prev && prev.xid == null && row.seq === prev.seqEnd + 1) {
        prev.seqEnd = row.seq;
        return;
      }
    }
    if (z.rows.length < 256) z.rows.push({ seq: row.seq, seqEnd: row.seq, xid: row.xid });
    else z.overflow = true;                 // too many separate runs to remember: the zone is looked at, own writes or not
  }

  // the domains whose burst ended and that have a row that is not ours; `busy(id)` true keeps the entry (the zone is being signed now: the write id of
  // that run is not known yet)
  flush(now, isOwn, busy = () => false) {
    const out = [];
    for (const [id, z] of this.zones) {
      if (now - z.last < this.debounce && now - z.first < this.max) continue;
      if (busy(id)) continue;
      this.zones.delete(id);
      if (z.overflow || z.rows.some((r) => !isOwn(r))) out.push(id);
    }
    return out;
  }

  // a run of the zone starts: the rows read so far were committed before its export, so a run that signs the zone covers them (a change after the
  // export makes import --signer exit with status 3).  The entry is handed to the run; putBack() returns it when the run did not sign the zone.
  take(domainId) {
    const z = this.zones.get(domainId) ?? null;
    this.zones.delete(domainId);
    return z;
  }

  putBack(domainId, z) {
    if (!z) return;
    const cur = this.zones.get(domainId);
    if (!cur) {
      this.zones.set(domainId, z);
      return;
    }
    cur.first = Math.min(cur.first, z.first);
    cur.overflow = cur.overflow || z.overflow || z.rows.length + cur.rows.length > 256;
    cur.rows = [...z.rows, ...cur.rows].slice(0, 256);
  }

  get size() { return this.zones.size; }
}

// the rows of our own writes: PostgreSQL by xid8, SQLite3 by a range of seq (planning 3.4)
export class OwnWrites {
  constructor(cap = 4096) {
    this.cap = cap;
    this.xids = new Set();
    this.ranges = [];
  }

  add(writeId) {
    if (!writeId) return;
    if (writeId.xid != null) {
      this.xids.add(String(writeId.xid));
      if (this.xids.size > this.cap) this.xids.delete(this.xids.values().next().value);
    }
    if (writeId.seq_first != null && writeId.seq_last != null) {
      this.ranges.push([Number(writeId.seq_first), Number(writeId.seq_last)]);
      if (this.ranges.length > this.cap) this.ranges.shift();
    }
  }

  isOwn(row) {
    if (row.xid != null && this.xids.has(String(row.xid))) return true;
    if (row.seq == null) return false;
    // a run of consecutive rows (debounce) is ours when our writes together cover all of it (the import and the INSERT of the keys right after it are two writes, one run)
    const end = row.seqEnd ?? row.seq;
    for (let pos = row.seq; pos <= end;) {
      const r = this.ranges.find(([a, b]) => pos >= a && pos <= b);
      if (!r) return false;
      pos = r[1] + 1;
    }
    return true;
  }
}

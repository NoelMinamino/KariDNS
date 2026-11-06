// The arithmetic of when a zone is looked at again (planning 3.6).  Pure; the daemon (daemon.js) holds the state.

// next_due = the earliest RRSIG expiration in the zone - refresh - a random part of the jitter (so a million zones spread out), and never in the
// past: dnssec-signzone runs with -i refresh+jitter (argv.js), so every signature a run leaves has more than refresh+jitter left and the result is
// after `now` for any random part; the floor only guards against a clock that went backwards.  Without an expiration (min_expire unknown) the zone is
// looked at after validity - refresh - jitter, the time a fresh signature has until it is due.
export function nextDue({ minExpire, refresh, jitter, validity, now, rand = Math.random }) {
  if (minExpire == null) return now + Math.max(1, validity - refresh - jitter);
  const part = Math.floor(rand() * jitter);
  return Math.max(minExpire - refresh - part, now + 1);
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
    this.zones = new Map();               // domain id -> { first, last, rows: [{ seq, xid }] }
  }

  add(domainId, row, now) {
    let z = this.zones.get(domainId);
    if (!z) {
      z = { first: now, last: now, rows: [], overflow: false };
      this.zones.set(domainId, z);
    }
    z.last = now;
    if (z.rows.length < 256) z.rows.push(row);
    else z.overflow = true;                 // too many rows to remember: the zone is looked at, own writes or not
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
    return row.seq != null && this.ranges.some(([a, b]) => row.seq >= a && row.seq <= b);
  }
}

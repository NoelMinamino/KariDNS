// Token buckets in memory (planning 8.2): login attempts per address and per user name, requests per principal, writes per principal.  One process serves
// the API, so one process counts.  Keys that have been idle long enough to be full again are dropped, so an attacker cannot grow the table by sending
// many different keys.

export class Buckets {
  // rate: tokens per second; burst: the size of the bucket; max: the most keys remembered
  constructor({ rate, burst, max = 100000, now = () => Date.now() }) {
    this.rate = rate;
    this.burst = burst;
    this.max = max;
    this.now = now;
    this.map = new Map();
  }

  // -> 0 when the request may go on, else the seconds to wait (at least 1)
  take(key) {
    const t = this.now();
    let b = this.map.get(key);
    if (!b) {
      if (this.map.size >= this.max) this.sweep(t);
      b = { tokens: this.burst, at: t };
      this.map.set(key, b);
    }
    b.tokens = Math.min(this.burst, b.tokens + ((t - b.at) / 1000) * this.rate);
    b.at = t;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return 0;
    }
    return Math.max(1, Math.ceil((1 - b.tokens) / this.rate));
  }

  sweep(t) {
    for (const [k, b] of this.map) {
      if (b.tokens + ((t - b.at) / 1000) * this.rate >= this.burst) this.map.delete(k);
    }
    if (this.map.size >= this.max) this.map.clear();           // every key is busy: forgetting them all is better than refusing everybody
  }
}

// At most `limit` events per key within the last `windowMs` (a sliding window of the times themselves, at most `limit` per key).  For a thing that is held for a while,
// not paced: the sign-in states an address may have waiting at the provider (handlers/oidc.js).  take() -> true when the key is at its limit (nothing is recorded then).
// Keys whose events are all over are dropped when the table is full, so many different keys cannot grow it past `max`.
export class Window {
  constructor({ limit, windowMs, max = 100000, now = () => Date.now() }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.max = max;
    this.now = now;
    this.map = new Map();
  }

  take(key) {
    const t = this.now();
    let times = this.map.get(key);
    if (!times) {
      if (this.map.size >= this.max) this.sweep(t);
      times = [];
      this.map.set(key, times);
    }
    while (times.length && times[0] <= t - this.windowMs) times.shift();
    if (times.length >= this.limit) return true;
    times.push(t);
    return false;
  }

  sweep(t) {
    for (const [k, times] of this.map) {
      if (times[times.length - 1] <= t - this.windowMs) this.map.delete(k);
    }
    if (this.map.size >= this.max) this.map.clear();
  }
}

// The network a lock of failed logins applies to: an IPv4 address's /24, an IPv6 address's /64 (an IPv4-mapped address is IPv4).  Other text (a test's address) is
// its own network.
export function lockNetwork(ip) {
  let a = String(ip ?? '');
  const pct = a.indexOf('%');
  if (pct >= 0) a = a.slice(0, pct);
  const v4 = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/i.exec(a);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0/24`;
  const halves = a.split('::');
  if (!a.includes(':') || halves.length > 2 || a.includes('.')) return a;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right] : left;
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return a;
  return `${groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(':')}::/64`;
}

// The lock of an account after failed logins, per account and client network (audit, 0.6.2): before, ten failures from anywhere locked the account for everybody, so
// whoever knew a user name could keep its owner out.  Now `after` failures in a row from one network lock that network out of that account, for firstMs and twice as
// long for every further failure, maxMs at most; the owner still gets in from another network.  (The pace of guesses per user name is the loginUser bucket's.)  In
// memory, like the buckets: a restart forgets the locks.  An entry that is not locked and had no failure for maxMs is dropped when the table is full.
export class Lockouts {
  constructor({ after = 10, firstMs = 15 * 60 * 1000, maxMs = 24 * 3600 * 1000, max = 100000, now = () => Date.now() } = {}) {
    Object.assign(this, { after, firstMs, maxMs, max, now });
    this.map = new Map();
  }

  key(principalId, ip) { return `${principalId} ${lockNetwork(ip)}`; }

  locked(principalId, ip) {
    const e = this.map.get(this.key(principalId, ip));
    return Boolean(e?.until && e.until > this.now());
  }

  // one failure -> { failed, until } (until: the end of the lock, or null)
  fail(principalId, ip) {
    const t = this.now();
    const k = this.key(principalId, ip);
    let e = this.map.get(k);
    if (!e) {
      if (this.map.size >= this.max) this.sweep(t);
      e = { failed: 0, until: null, last: t };
      this.map.set(k, e);
    }
    e.failed += 1;
    e.last = t;
    if (e.failed >= this.after) e.until = t + Math.min(this.firstMs * 2 ** (e.failed - this.after), this.maxMs);
    return { failed: e.failed, until: e.until };
  }

  succeed(principalId, ip) { this.map.delete(this.key(principalId, ip)); }

  clear(principalId) {
    const prefix = `${principalId} `;
    for (const k of this.map.keys()) if (k.startsWith(prefix)) this.map.delete(k);
  }

  // the networks with failures for an account: [{ network, failed, locked_until (ms or null) }]
  of(principalId) {
    const prefix = `${principalId} `;
    const t = this.now();
    const out = [];
    for (const [k, e] of this.map) if (k.startsWith(prefix)) out.push({ network: k.slice(prefix.length), failed: e.failed, locked_until: e.until && e.until > t ? e.until : null });
    return out;
  }

  sweep(t) {
    for (const [k, e] of this.map) if (!(e.until && e.until > t) && e.last <= t - this.maxMs) this.map.delete(k);
    if (this.map.size >= this.max) for (const [k, e] of this.map) if (!(e.until && e.until > t)) this.map.delete(k);
    if (this.map.size >= this.max) this.map.clear();           // every entry is a lock in force: forgetting them all is better than refusing to count
  }
}

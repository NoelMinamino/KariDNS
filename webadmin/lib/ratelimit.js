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

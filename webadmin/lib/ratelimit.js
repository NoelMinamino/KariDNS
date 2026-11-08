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

// Two small limits of the write side (planning 2.1, 8.2): a bounded pool for the child processes, and a lock per zone so that the change sets of one zone go one
// after the other (the generation of the database covers other writers; this keeps our own requests from conflicting with each other).

import { ApiError } from './errors.js';

const busy = (detail) => new ApiError(503, 'busy', detail, { headers: { 'Retry-After': '2' } });

// At most `limit` jobs run at once; up to `queue` more wait; beyond that: 503 (the work is I/O and child processes, a burst must not pile them up).
export class Pool {
  constructor({ limit, queue = 64 }) {
    this.limit = limit;
    this.queue = queue;
    this.active = 0;
    this.waiting = [];
  }

  async run(fn) {
    if (this.active < this.limit) {
      this.active++;
    } else {
      if (this.waiting.length >= this.queue) throw busy('too many requests are waiting for the tools, try again');
      await new Promise((resolve) => { this.waiting.push(resolve); });         // the slot is handed over, not released
    }
    try {
      return await fn();
    } finally {
      const next = this.waiting.shift();
      if (next) next();
      else this.active--;
    }
  }
}

// One holder per key at a time, in the order of the requests; at most `waiters` wait for a key (a zone with a long queue answers 503 to the rest).
export class KeyedLock {
  constructor({ waiters = 16 } = {}) {
    this.waiters = waiters;
    this.tails = new Map();
    this.counts = new Map();
  }

  // -> release()
  async acquire(key) {
    const n = this.counts.get(key) ?? 0;
    if (n > this.waiters) throw busy('this zone has many changes waiting, try again');
    this.counts.set(key, n + 1);
    const prev = this.tails.get(key) ?? Promise.resolve();
    let release;
    const mine = new Promise((resolve) => { release = resolve; });
    const tail = prev.then(() => mine);
    this.tails.set(key, tail);
    await prev;
    return () => {
      const left = this.counts.get(key) - 1;
      if (left === 0) {
        this.counts.delete(key);
        this.tails.delete(key);
      } else {
        this.counts.set(key, left);
      }
      release();
    };
  }
}

// The daemon loop (planning 3.6): which zone is signed when.  Everything it knows about the outside comes through `deps`, so the unit tests drive it
// with a fake database, a fake pipeline and a fake clock.
//
//   deps: { db, ctx (the pipeline's context: config, run, tools, work, ...), sign(ctx, job), log, clock() -> epoch seconds, sleep(ms), rand() }
//
// The work comes from three places: the state table (next_due <= now: the zones that are due), the key requests (polled), and the change log (a
// signer zone that someone else changed is made due after a debounce; our own writes are skipped by their write id).  `workers` zones run at a time.

import { Debounce, OwnWrites, nextDue, backoff, busyDelay, CHANGED_RETRIES } from './scheduler.js';
import { zoneSettings } from './config.js';

export const REQUEST_POLL = 5;            // seconds between two looks at the key requests
export const CATCHUP_EVERY = 3600;        // seconds between two full catch-up scans (a safety net: the change log is the normal way)
export const LOCKED_DELAY = 30;           // seconds before a zone that another instance holds is tried again

export class Daemon {
  constructor({ db, ctx, sign, log, clock, sleep, rand = Math.random, tickMs = 1000, changePollMs }) {
    this.db = db;
    this.ctx = ctx;
    this.sign = sign;
    this.log = log;
    this.clock = clock;
    this.sleep = sleep;
    this.rand = rand;
    this.tickMs = tickMs;
    this.changePollMs = changePollMs;
    this.ownWrites = new OwnWrites();
    ctx.ownWrites = this.ownWrites;
    ctx.sleep = (ms) => (this.stopping ? Promise.resolve() : this.sleep(ms));          // the retries of a key INSERT do not hold up a stop
    this.debounce = new Debounce(ctx.config.settings.debounce);
    this.inflight = new Map();             // domain id -> promise
    this.notBefore = new Map();            // domain id -> epoch seconds: in memory only
    this.changed = new Map();              // domain id -> consecutive exit status 3
    this.busy = new Map();                 // domain id -> consecutive exit status 4
    this.stopping = false;
    this.cursor = null;
    this.lastRequests = 0;
    this.requests = [];                    // the pending key requests of the last poll
    this.requestsDue = false;
    this.lastCatchUp = 0;
    this.kick = null;
    this.loops = [];
    this.stats = { signed: 0, failed: 0 };
  }

  get workers() { return this.ctx.config.settings.workers; }

  wakeLoop() {
    const k = this.kick;
    this.kick = null;
    if (k) k();
  }

  async start() {
    this.cursor = await this.db.changesStart();
    await this.catchUp();
    this.loops.push(this.mainLoop(), this.changeLoop());
  }

  // stop dispatching, let the running zones finish
  async stop() {
    this.stopping = true;
    this.wakeLoop();
    this.db.wake?.();
    await Promise.allSettled([...this.inflight.values()]);
    await Promise.allSettled(this.loops);
  }

  // SIGHUP: the new settings for the zones to come; the database and the work directory stay as they are (they need a restart)
  reconfigure(config) {
    const old = this.ctx.config;
    const keep = ['database', 'conninfo-file', 'sqlite-file', 'schema', 'work-dir'];
    for (const k of keep) {
      if (config.settings[k] !== old.settings[k]) {
        this.log.warn(`the setting '${k}' changed in the configuration: it needs a restart, the old value stays`);
        config.settings[k] = old.settings[k];
      }
    }
    this.ctx.config = config;
    this.debounce.debounce = config.settings.debounce;
    this.debounce.max = config.settings.debounce * 6;
    this.lastCatchUp = 0;
    this.wakeLoop();
    this.log.info('configuration read again');
  }

  async catchUp() {
    const ids = await this.db.catchUp();
    if (ids.length) {
      await this.db.markDue(ids, this.clock());
      this.log.info(`${ids.length} zone(s) to look at after the catch-up scan`);
    }
    this.lastCatchUp = this.clock();
  }

  async ingest() {
    const { rows, cursor, gap } = await this.db.changesSince(this.cursor);
    this.cursor = cursor;
    const now = this.clock();
    for (const r of rows) this.debounce.add(r.domainId, { seq: r.seq, xid: r.xid }, now);
    if (gap) {
      this.log.warn('the change log was pruned beyond our position: scanning all zones');
      await this.catchUp();
    }
  }

  async flushChanges() {
    const ids = this.debounce.flush(this.clock(), (row) => this.ownWrites.isOwn(row), (id) => this.inflight.has(id));
    if (ids.length === 0) return;
    const zones = await this.db.signerZones(ids);
    if (zones.length) await this.db.markDue(zones.map((z) => z.id), this.clock());
  }

  // reads the change log whenever the database says something changed (PostgreSQL: NOTIFY; SQLite3: a poll)
  async changeLoop() {
    while (!this.stopping) {
      try {
        await this.db.waitForChange(this.changePollMs);
        if (this.stopping) break;
        await this.ingest();
      } catch (e) {
        this.log.error(`reading the change log failed: ${e.message}`);
        await this.sleep(5000);
      }
    }
  }

  async mainLoop() {
    while (!this.stopping) {
      try {
        await this.tick();
      } catch (e) {
        this.log.error(`scheduler: ${e.message}`);
      }
      await Promise.race([this.sleep(this.tickMs), new Promise((resolve) => { this.kick = resolve; })]);
      this.kick = null;
    }
  }

  // one pass: flush the change log, look at the key requests, start as many jobs as there are free workers
  async tick() {
    const now = this.clock();
    if (now - this.lastCatchUp >= CATCHUP_EVERY) await this.catchUp();
    await this.flushChanges();
    if (this.stopping) return;
    let free = this.workers - this.inflight.size;
    if (free <= 0) return;
    const ready = (id) => !this.inflight.has(id) && (this.notBefore.get(id) ?? 0) <= now;
    if (now - this.lastRequests >= REQUEST_POLL || this.requestsDue) {
      this.requestsDue = false;
      this.requests = await this.db.pendingRequests(50);
      this.lastRequests = now;
    }
    for (const r of this.requests) {
      if (free <= 0) break;
      if (!ready(r.domainId)) continue;
      this.start1({ domainId: r.domainId, zone: r.zone, request: r });
      this.requests = this.requests.filter((x) => x !== r);
      free--;
    }
    if (free <= 0) return;
    const due = await this.db.dueZones(now, this.workers * 4 + this.inflight.size);
    for (const z of due) {
      if (free <= 0) break;
      if (!ready(z.domainId)) continue;
      this.start1({ domainId: z.domainId, zone: z.zone, request: null });
      free--;
    }
  }

  start1(job) {
    const p = this.runJob(job).finally(() => {
      this.inflight.delete(job.domainId);
      this.wakeLoop();
    });
    this.inflight.set(job.domainId, p);
  }

  async runJob(job) {
    let out;
    try {
      out = await this.sign(this.ctx, job);
    } catch (e) {
      out = { status: 'failed', error: `unexpected error: ${e.message}`, request: job.request ? { state: 'failed', message: e.message } : null };
    }
    try {
      await this.handle(job, out);
    } catch (e) {
      this.log.error(`${job.zone}: cannot record the result (${out.status}): ${e.message}`);
      this.notBefore.set(job.domainId, this.clock() + 30);          // do not hammer a database that does not answer
    }
  }

  // one place for every outcome of a run (the callers of the pipeline's exit statuses)
  async handle(job, out) {
    const { db, log } = this;
    const id = job.domainId;
    const now = this.clock();
    switch (out.status) {
      case 'signed': {
        const z = zoneSettings(this.ctx.config, job.zone);
        this.changed.delete(id);
        this.busy.delete(id);
        this.notBefore.delete(id);
        this.stats.signed++;
        await db.recordSuccess(id, {
          // one second after the end of the run: the change log rows of our own write have changed_at of the second they were made in (PostgreSQL rounds it, SQLite3 cuts it),
          // never later than this; the scan at the start (catchUp) takes the rows after this time for the changes of somebody else
          signedAt: now + 1, serial: out.serial, minExpire: out.minExpire,
          nextDue: nextDue({ minExpire: out.minExpire, refresh: z.refresh, jitter: z.jitter, validity: z.validity, now, rand: this.rand }),
          durationMs: out.durationMs,
        });
        log.info(`signed ${job.zone}: serial ${out.serial}, ${out.durationMs} ms${job.request ? `, request ${job.request.id} ${out.request?.state}` : ''}`);
        for (const w of out.warnings ?? []) log.warn(`${job.zone}: ${w}`);
        if (out.request) await db.finishRequest(job.request.id, out.request.state, out.request.message, now);
        break;
      }
      case 'key-added':
        this.stats.signed++;
        await db.finishRequest(job.request.id, out.request.state, out.request.message, now);
        await db.markDue([id], now);                  // the next run signs with the new key
        log.info(`${job.zone}: ${out.request.message}`);
        break;
      case 'changed': {
        const n = (this.changed.get(id) ?? 0) + 1;
        this.changed.set(id, n);
        if (n <= CHANGED_RETRIES) {
          log.info(`${job.zone}: changed while it was signed, signing again`);
          this.notBefore.set(id, now);
          if (!job.request) await db.markDue([id], now);
        } else {
          this.changed.delete(id);
          await this.failed(job, { error: 'the zone kept changing while it was signed', durationMs: out.durationMs });
        }
        break;
      }
      case 'busy': {
        const n = (this.busy.get(id) ?? 0) + 1;
        this.busy.set(id, n);
        this.notBefore.set(id, now + busyDelay(n));
        log.warn(`${job.zone}: the database is busy, trying again in ${busyDelay(n)} s`);
        break;
      }
      case 'locked':
        this.notBefore.set(id, now + LOCKED_DELAY);
        break;
      case 'skipped':
        log.info(`${job.zone}: skipped (${out.reason})`);
        this.notBefore.set(id, now + 60);
        break;
      default:
        await this.failed(job, out);
    }
  }

  async failed(job, out) {
    const { db, log } = this;
    const now = this.clock();
    this.stats.failed++;
    log.error(`${job.zone}: ${out.error}`);
    if (job.request) {
      await db.finishRequest(job.request.id, 'failed', out.request?.message ?? out.error, now);
      this.notBefore.set(job.domainId, now + 10);
      return;
    }
    // the backoff is the zone's next_due in the state table: no timer of ours, so that an operator can reset it
    await db.recordFailure(job.domainId, { error: out.error, durationMs: out.durationMs, nextDue: (n) => now + backoff(n) });
    this.notBefore.delete(job.domainId);
  }

}

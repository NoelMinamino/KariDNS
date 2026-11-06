// The scheduler loop with a fake database, a fake pipeline and a clock we move by hand.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig } from '../lib/config.js';
import { Daemon, REQUEST_POLL, REQUEST_BATCH, CATCHUP_EVERY, LOCKED_DELAY } from '../lib/daemon.js';
import { backoff, busyDelay } from '../lib/scheduler.js';

const CONF = 'database = sqlite3\nsqlite-file = /db\nkarictl-config = /k\nworkers = 2\nvalidity = 14d\nrefresh = 3d\njitter = 1d\ndebounce = 5';

function make(over = {}) {
  const logs = [];
  const clock = { now: 1_000_000 };
  const calls = [];
  const db = {
    due: [],
    reqs: [],
    signer: [],
    catch: [],
    rows: [],
    cursor: 'c0',
    gap: false,
    failRecord: false,
    async changesStart() { return this.cursor; },
    async catchUp() { calls.push(['catchUp']); return this.catch; },
    async markDue(ids, now) { calls.push(['markDue', ids, now]); },
    async dueZones(now, limit) { calls.push(['dueZones', now, limit]); return this.due; },
    async pendingRequests(limit) { calls.push(['pendingRequests', limit]); return this.reqs; },
    async signerZones(ids) { calls.push(['signerZones', ids]); return this.signer.filter((z) => ids.includes(z.id)); },
    async changesSince(cursor) { calls.push(['changesSince', cursor]); if (this.failChanges) throw new Error('db down'); return { rows: this.rows.splice(0), cursor: 'c1', gap: this.gap }; },
    async waitForChange() { await new Promise((r) => setTimeout(r, 2)); },
    async recordSuccess(id, s) { calls.push(['recordSuccess', id, s]); if (this.failRecord) throw new Error('cannot write'); },
    async recordFailure(id, f) { calls.push(['recordFailure', id, f.error, f.nextDue(2) - clock.now, f.nextDue(1) - clock.now]); this.attempts = (this.attempts ?? 0) + 1; return this.attempts; },
    async finishRequest(id, state, message, now) { calls.push(['finishRequest', id, state, message, now]); },
    wake() { calls.push(['wake']); },
  };
  const signed = [];
  const outcomes = new Map();
  const ctx = { config: parseConfig(CONF) };
  const sign = async (c, job) => {
    signed.push(job);
    const o = outcomes.get(job.domainId);
    const out = typeof o === 'function' ? o(job) : o;
    if (out instanceof Error) throw out;
    return out ?? { status: 'signed', serial: 5, minExpire: clock.now + 1209600, durationMs: 9, request: null, warnings: [] };
  };
  const log = { info: (m) => logs.push(`info ${m}`), warn: (m) => logs.push(`warn ${m}`), error: (m) => logs.push(`error ${m}`) };
  const d = new Daemon({ db, ctx, sign, log, clock: () => clock.now, sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 3))), rand: () => 0, tickMs: 5, changePollMs: 5, ...over });
  return { d, db, ctx, calls, logs, clock, signed, outcomes, sign };
}
const idle = async (d) => { await Promise.allSettled([...d.inflight.values()]); };
const find = (calls, name) => calls.filter((c) => c[0] === name);

test('start: the change log position and the catch-up scan, then the loops; stop waits for the zones', async () => {
  const m = make();
  m.db.catch = [4, 5];
  await m.d.start();
  assert.equal(m.d.cursor, 'c0');
  assert.deepEqual(find(m.calls, 'markDue')[0], ['markDue', [4, 5], 1_000_000]);
  assert.ok(m.logs.some((l) => /2 zone\(s\) to look at after the catch-up scan/.test(l)));
  assert.equal(m.d.workers, 2);
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  let release;
  m.outcomes.set(1, () => new Promise((r) => { release = () => r({ status: 'signed', serial: 2, minExpire: null, durationMs: 1, request: null }); }));
  while (m.d.inflight.size === 0) await new Promise((r) => setTimeout(r, 5));
  const stopped = m.d.stop();
  await new Promise((r) => setTimeout(r, 30));
  assert.ok(m.d.inflight.size === 1, 'the running zone is not cut off');
  release();
  await stopped;
  assert.equal(m.d.inflight.size, 0);
  assert.ok(find(m.calls, 'wake').length === 1);
  assert.equal(find(m.calls, 'recordSuccess').length >= 1, true);
});

test('start without anything to catch up', async () => {
  const m = make();
  await m.d.start();
  await m.d.stop();
  assert.equal(find(m.calls, 'markDue').length, 0);
});

test('tick: up to `workers` jobs, key requests first, a zone once at a time', async () => {
  const m = make();
  m.db.reqs = [{ id: 11, domainId: 3, zone: 'req.test', kind: 'enable' }];
  m.db.due = [{ domainId: 3, zone: 'req.test', attempts: 0 }, { domainId: 1, zone: 'a.test', attempts: 0 }, { domainId: 2, zone: 'b.test', attempts: 0 }];
  let release;
  m.outcomes.set(3, () => new Promise((r) => { release = () => r({ status: 'skipped', reason: 'x' }); }));
  await m.d.tick();
  assert.deepEqual(m.signed.map((j) => [j.domainId, j.request?.id ?? null]), [[3, 11], [1, null]]);
  assert.equal(m.d.inflight.size, 2);
  assert.equal(find(m.calls, 'dueZones')[0][2], 2 * 4 + 1, 'the due list is read with a limit');
  // no free worker: nothing more is read
  const n = m.calls.length;
  await m.d.tick();
  assert.equal(m.calls.length, n + 0 + find(m.calls.slice(n), 'markDue').length);
  release();
  await idle(m.d);
});

test('tick: a zone that waits (notBefore) or runs is not started; the request list is polled every few seconds', async () => {
  const m = make();
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  m.d.notBefore.set(1, m.clock.now + 10);
  await m.d.tick();
  assert.equal(m.signed.length, 0);
  m.clock.now += 10;
  await m.d.tick();
  assert.equal(m.signed.length, 1);
  await idle(m.d);
  const polls = () => find(m.calls, 'pendingRequests').length;
  const p0 = polls();
  m.clock.now += REQUEST_POLL - 1;
  await m.d.tick();
  assert.equal(polls(), p0);
  m.clock.now += 1;
  await m.d.tick();
  assert.equal(polls(), p0 + 1);
  await idle(m.d);
  // a request whose zone waits stays in the list
  m.db.reqs = [{ id: 1, domainId: 9, zone: 'w.test', kind: 'add' }];
  m.d.notBefore.set(9, m.clock.now + 100);
  m.clock.now += REQUEST_POLL;
  m.db.due = [];
  await m.d.tick();
  assert.ok(!m.signed.some((j) => j.domainId === 9));
});

test('tick: a request that a poll listed while its job ran is not started a second time when the job is done', async () => {
  const m = make();
  m.db.reqs = [{ id: 7, domainId: 5, zone: 'r.test', kind: 'enable', algorithm: 13 }];
  let release;
  m.outcomes.set(5, () => new Promise((r) => { release = () => r({ status: 'signed', serial: 2, minExpire: null, durationMs: 1, request: { state: 'done', message: 'ok' } }); }));
  await m.d.tick();
  assert.equal(m.signed.length, 1);
  m.clock.now += REQUEST_POLL;
  await m.d.tick();                       // the poll lists the request again: it is still pending in the database while the job runs
  assert.equal(m.signed.length, 1);
  assert.equal(m.d.requests.length, 1);
  release();
  await idle(m.d);
  assert.equal(m.d.requests.length, 0);
  await m.d.tick();
  assert.equal(m.signed.length, 1, 'the zone was signed once for the one request');
});

test('tick: a full batch of key requests is followed by the next batch at once, a short one waits for the poll interval', async () => {
  const m = make();
  m.ctx.config.settings.workers = 100;
  const batch = (from, n) => Array.from({ length: n }, (_, i) => ({ id: from + i, domainId: from + i, zone: `r${from + i}.test`, kind: 'enable', algorithm: 13 }));
  m.db.reqs = batch(1, REQUEST_BATCH);
  await m.d.tick();
  assert.equal(m.signed.length, REQUEST_BATCH);
  await idle(m.d);
  const polls = () => find(m.calls, 'pendingRequests').length;
  assert.equal(polls(), 1);
  m.db.reqs = batch(1000, 3);
  await m.d.tick();                       // no time has passed: the list was full and is empty, so the database is asked again
  assert.equal(polls(), 2);
  assert.equal(m.signed.length, REQUEST_BATCH + 3);
  await idle(m.d);
  m.db.reqs = batch(2000, 3);
  await m.d.tick();                       // the last batch was short: the poll interval applies
  assert.equal(polls(), 2);
  assert.equal(m.signed.length, REQUEST_BATCH + 3);
});

test('the catch-up scan runs again every hour', async () => {
  const m = make();
  await m.d.tick();
  const n = () => find(m.calls, 'catchUp').length;
  assert.equal(n(), 1);
  m.clock.now += CATCHUP_EVERY - 1;
  await m.d.tick();
  assert.equal(n(), 1);
  m.clock.now += 1;
  m.db.catch = [8];
  await m.d.tick();
  assert.equal(n(), 2);
  assert.deepEqual(find(m.calls, 'markDue').at(-1)[1], [8]);
});

test('signed: the state with next_due from the expiration, the request answered, warnings logged', async () => {
  const m = make();
  const exp = m.clock.now + 1209600;
  m.outcomes.set(1, { status: 'signed', serial: 9, minExpire: exp, durationMs: 33, request: { state: 'done', message: 'enabled' }, warnings: ['karictl failed'] });
  m.db.reqs = [{ id: 7, domainId: 1, zone: 'a.test', kind: 'enable' }];
  m.d.changed.set(1, 2);
  m.d.busy.set(1, 2);
  m.d.notBefore.set(1, 1);
  await m.d.tick();
  await idle(m.d);
  const [, id, s] = find(m.calls, 'recordSuccess')[0];
  assert.equal(id, 1);
  assert.deepEqual(s, { signedAt: m.clock.now + 1, serial: 9, minExpire: exp, nextDue: exp - 259200, durationMs: 33 });      // rand() = 0: no jitter taken off
  assert.deepEqual(find(m.calls, 'finishRequest')[0], ['finishRequest', 7, 'done', 'enabled', m.clock.now]);
  assert.ok(m.logs.some((l) => /signed a\.test: serial 9, 33 ms, request 7 done/.test(l)));
  assert.ok(m.logs.some((l) => /warn a\.test: karictl failed/.test(l)));
  assert.equal(m.d.changed.has(1) || m.d.busy.has(1) || m.d.notBefore.has(1), false);
  assert.equal(m.d.stats.signed, 1);
});

test('signed: per-zone settings decide next_due', async () => {
  const m = make();
  m.ctx.config = parseConfig(`${CONF}\n[zone a.test]\nvalidity = 2h\nrefresh = 20m\njitter = 5m`);
  const exp = m.clock.now + 7200;
  m.outcomes.set(1, { status: 'signed', serial: 9, minExpire: exp, durationMs: 1, request: null });
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  await m.d.tick();
  await idle(m.d);
  assert.equal(find(m.calls, 'recordSuccess')[0][2].nextDue, exp - 1200);
});

test('key-added: the request is answered and the zone made due for the next run', async () => {
  const m = make();
  m.outcomes.set(4, { status: 'key-added', request: { state: 'done', message: 'key 1 added' } });
  m.db.reqs = [{ id: 3, domainId: 4, zone: 'k.test', kind: 'add' }];
  await m.d.tick();
  await idle(m.d);
  assert.deepEqual(find(m.calls, 'finishRequest')[0], ['finishRequest', 3, 'done', 'key 1 added', m.clock.now]);
  assert.deepEqual(find(m.calls, 'markDue').at(-1), ['markDue', [4], m.clock.now]);
});

test('changed (exit status 3): signed again at once, three times; then the error backoff', async () => {
  const m = make();
  m.outcomes.set(1, { status: 'changed' });
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  for (let i = 1; i <= 3; i++) {
    await m.d.tick();
    await idle(m.d);
    assert.equal(m.d.changed.get(1), i);
    assert.equal(m.d.notBefore.get(1), m.clock.now, 'at once');
  }
  assert.equal(find(m.calls, 'markDue').filter((c) => c[1][0] === 1).length, 3);
  assert.equal(find(m.calls, 'recordFailure').length, 0);
  await m.d.tick();
  await idle(m.d);
  const f = find(m.calls, 'recordFailure');
  assert.equal(f.length, 1);
  assert.equal(f[0][2], 'the zone kept changing while it was signed');
  assert.equal(m.d.changed.has(1), false);
  assert.equal(m.d.notBefore.has(1), false, 'the delay is next_due in the state table');
  assert.equal(m.d.stats.failed, 1);
});

test('changed on a request: the request stays pending, no state is written', async () => {
  const m = make();
  m.outcomes.set(1, { status: 'changed' });
  m.db.reqs = [{ id: 1, domainId: 1, zone: 'a.test', kind: 'enable' }];
  await m.d.tick();
  await idle(m.d);
  assert.equal(find(m.calls, 'markDue').length, 0);
  assert.equal(find(m.calls, 'finishRequest').length, 0);
  for (let i = 0; i < 3; i++) { m.d.changed.set(1, 3); await m.d.handle({ domainId: 1, zone: 'a.test', request: { id: 1 } }, { status: 'changed' }); }
  assert.deepEqual(find(m.calls, 'finishRequest')[0].slice(1, 3), [1, 'failed']);
  assert.equal(find(m.calls, 'recordFailure').length, 0);
});

test('busy (exit status 4): a short delay that doubles', async () => {
  const m = make();
  m.outcomes.set(1, { status: 'busy' });
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  const delays = [];
  for (let i = 0; i < 3; i++) {
    m.clock.now += 100;
    await m.d.tick();
    await idle(m.d);
    delays.push(m.d.notBefore.get(1) - m.clock.now);
  }
  assert.deepEqual(delays, [busyDelay(1), busyDelay(2), busyDelay(3)]);
  assert.deepEqual(delays, [5, 10, 20]);
  assert.ok(m.logs.some((l) => /database is busy, trying again in 10 s/.test(l)));
});

test('locked by another instance, skipped', async () => {
  const m = make();
  m.outcomes.set(1, { status: 'locked' });
  m.outcomes.set(2, { status: 'skipped', reason: 'the zone has no X-KARIDNS-SIGNER metadata' });
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }, { domainId: 2, zone: 'b.test', attempts: 0 }];
  await m.d.tick();
  await idle(m.d);
  assert.equal(m.d.notBefore.get(1), m.clock.now + LOCKED_DELAY);
  assert.equal(m.d.notBefore.get(2), m.clock.now + 60);
  assert.ok(m.logs.some((l) => /b\.test: skipped \(the zone has no X-KARIDNS-SIGNER metadata\)/.test(l)));
});

test('failed: attempts + 1, the error and the backoff; a failed request is answered', async () => {
  const m = make();
  m.outcomes.set(1, { status: 'failed', error: 'dnssec-signzone: boom', durationMs: 4 });
  m.outcomes.set(2, { status: 'failed', error: 'x', request: { state: 'failed', message: 'the request message' } });
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  m.db.reqs = [{ id: 5, domainId: 2, zone: 'b.test', kind: 'enable' }];
  await m.d.tick();
  await idle(m.d);
  const f = find(m.calls, 'recordFailure')[0];
  assert.deepEqual(f.slice(1), [1, 'dnssec-signzone: boom', backoff(2), backoff(1)]);
  assert.equal(m.d.notBefore.has(1), false);
  assert.deepEqual(find(m.calls, 'finishRequest')[0], ['finishRequest', 5, 'failed', 'the request message', m.clock.now]);
  assert.equal(m.d.notBefore.get(2), m.clock.now + 10);
  assert.ok(m.logs.some((l) => /error a\.test: dnssec-signzone: boom/.test(l)));
  // a failed request without a message of its own uses the error
  await m.d.failed({ domainId: 3, zone: 'c.test', request: { id: 6 } }, { error: 'plain error' });
  assert.equal(find(m.calls, 'finishRequest')[1][3], 'plain error');
});

test('a pipeline that throws is a failed zone; a database that cannot record the result is waited for', async () => {
  const m = make();
  m.outcomes.set(1, new Error('kaboom'));
  m.outcomes.set(2, new Error('kaboom 2'));
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  m.db.reqs = [{ id: 1, domainId: 2, zone: 'b.test', kind: 'enable' }];
  await m.d.tick();
  await idle(m.d);
  assert.match(find(m.calls, 'recordFailure')[0][2], /unexpected error: kaboom/);
  assert.equal(find(m.calls, 'finishRequest')[0][3], 'kaboom 2');
  const m2 = make();
  m2.db.failRecord = true;
  m2.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  await m2.d.tick();
  await idle(m2.d);
  assert.ok(m2.logs.some((l) => /a\.test: cannot record the result \(signed\): cannot write/.test(l)));
  assert.equal(m2.d.notBefore.get(1), m2.clock.now + 30);
});

test('the change log: a foreign change makes a signer zone due after the debounce, our own write does not', async () => {
  const m = make();
  m.db.signer = [{ id: 1, name: 'a.test' }, { id: 2, name: 'b.test' }];
  m.d.ownWrites.add({ xid: '77', seq_first: null, seq_last: null });
  m.db.rows = [{ domainId: 1, seq: 1, xid: '77' }, { domainId: 2, seq: 2, xid: '78' }, { domainId: 3, seq: 3, xid: '78' }];
  await m.d.ingest();
  assert.equal(m.d.cursor, 'c1');
  assert.equal(m.d.debounce.size, 3);
  await m.d.flushChanges();
  assert.equal(find(m.calls, 'markDue').length, 0, 'not before the debounce');
  m.clock.now += 5;
  await m.d.flushChanges();
  assert.deepEqual(find(m.calls, 'signerZones')[0][1].sort(), [2, 3]);
  assert.deepEqual(find(m.calls, 'markDue').at(-1), ['markDue', [2], m.clock.now]);
  // nothing left, nothing to do
  const n = m.calls.length;
  await m.d.flushChanges();
  assert.equal(m.calls.length, n);
  // only a non-signer zone changed
  m.db.rows = [{ domainId: 3, seq: 4, xid: '79' }];
  await m.d.ingest();
  m.clock.now += 10;
  const k = find(m.calls, 'markDue').length;
  await m.d.flushChanges();
  assert.equal(find(m.calls, 'markDue').length, k);
});

test('a zone that is being signed keeps its changes until it is done; the write of that run is then ours', async () => {
  const m = make();
  m.db.signer = [{ id: 1, name: 'a.test' }];
  m.d.inflight.set(1, Promise.resolve());
  m.db.rows = [{ domainId: 1, seq: 10, xid: null }, { domainId: 1, seq: 11, xid: null }];
  await m.d.ingest();
  m.clock.now += 100;
  await m.d.flushChanges();
  assert.equal(find(m.calls, 'markDue').length, 0);
  m.d.inflight.clear();
  m.d.ownWrites.add({ xid: null, seq_first: 10, seq_last: 11 });
  await m.d.flushChanges();
  assert.equal(find(m.calls, 'markDue').length, 0, 'only our own rows: not a change');
});

test('a pruned change log: everything is scanned again', async () => {
  const m = make();
  m.db.gap = true;
  m.db.catch = [6];
  await m.d.ingest();
  assert.ok(m.logs.some((l) => /pruned beyond our position/.test(l)));
  assert.deepEqual(find(m.calls, 'markDue').at(-1)[1], [6]);
});

test('the change loop survives a failing database', async () => {
  const m = make();
  m.db.failChanges = true;
  m.d.cursor = 'c0';
  m.d.loops.push(m.d.changeLoop());
  await new Promise((r) => setTimeout(r, 30));
  assert.ok(m.logs.some((l) => /reading the change log failed: db down/.test(l)));
  await m.d.stop();
});

test('the main loop survives a failing scheduler pass', async () => {
  const m = make();
  m.db.dueZones = async () => { throw new Error('select failed'); };
  m.d.loops.push(m.d.mainLoop());
  await new Promise((r) => setTimeout(r, 30));
  assert.ok(m.logs.some((l) => /scheduler: select failed/.test(l)));
  await m.d.stop();
});

test('no new job is started once the daemon stops', async () => {
  const m = make();
  m.d.stopping = true;
  m.db.due = [{ domainId: 1, zone: 'a.test', attempts: 0 }];
  await m.d.tick();
  assert.equal(m.signed.length, 0);
});

test('SIGHUP: new settings for the zones to come; the database and the work-dir need a restart', () => {
  const m = make();
  const next = parseConfig(`${CONF.replace('workers = 2', 'workers = 5').replace('debounce = 5', 'debounce = 10')}\nwork-dir = /elsewhere`);
  next.settings['sqlite-file'] = '/other.db';
  m.d.lastCatchUp = 12345;
  m.d.reconfigure(next);
  assert.equal(m.d.workers, 5);
  assert.equal(m.d.debounce.debounce, 10);
  assert.equal(m.d.debounce.max, 60);
  assert.equal(m.ctx.config.settings['sqlite-file'], '/db');
  assert.equal(m.ctx.config.settings['work-dir'], '/var/db/karidns-signer/work');
  assert.equal(m.logs.filter((l) => /needs a restart/.test(l)).length, 2);
  assert.ok(m.logs.some((l) => /configuration read again/.test(l)));
  assert.equal(m.d.lastCatchUp, 0);
});

test('wakeLoop with nobody waiting is fine', () => {
  const m = make();
  m.d.wakeLoop();
  let woke = false;
  m.d.kick = () => { woke = true; };
  m.d.wakeLoop();
  assert.ok(woke && m.d.kick === null);
});

test('the sleep of the pipeline (retries of a key INSERT) does not hold up a stop', async () => {
  const slept = [];
  const m = make({ sleep: async (ms) => { slept.push(ms); } });
  await m.ctx.sleep(1000);
  m.d.stopping = true;
  await m.ctx.sleep(60000);
  assert.deepEqual(slept, [1000]);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { nextDue, backoff, busyDelay, CHANGED_RETRIES, Debounce, OwnWrites } from '../lib/scheduler.js';

const T = { refresh: 302400, jitter: 86400, validity: 1209600, now: 1000000 };

test('next_due = the earliest expiration - refresh - a random part of the jitter', () => {
  const exp = T.now + 1209600;
  assert.equal(nextDue({ ...T, minExpire: exp, rand: () => 0 }), exp - 302400);
  assert.equal(nextDue({ ...T, minExpire: exp, rand: () => 0.5 }), exp - 302400 - 43200);
  assert.equal(nextDue({ ...T, minExpire: exp, rand: () => 0.999999 }), exp - 302400 - 86399);
});

test('the random part spreads 1000 zones over the whole jitter window', () => {
  const exp = T.now + 1209600;
  const due = Array.from({ length: 1000 }, () => nextDue({ ...T, minExpire: exp }));
  const lo = exp - 302400 - 86400;
  const hi = exp - 302400;
  assert.ok(due.every((d) => d >= lo && d <= hi));
  assert.ok(Math.max(...due) - Math.min(...due) > 80000);
});

test('what a run leaves is never due at once (-i refresh+jitter means more than refresh+jitter is left)', () => {
  const left = T.refresh + T.jitter + 1;
  for (const r of [0, 0.3, 0.9999]) assert.ok(nextDue({ ...T, minExpire: T.now + left, rand: () => r }) > T.now);
});

test('never in the past, and a fallback without an expiration', () => {
  assert.equal(nextDue({ ...T, minExpire: T.now, rand: () => 0 }), T.now + 1);
  assert.equal(nextDue({ ...T, minExpire: null }), T.now + 1209600 - 302400 - 86400);
  assert.equal(nextDue({ ...T, minExpire: undefined, validity: 100, refresh: 60, jitter: 60 }), T.now + 1);
});

test('backoff: 1 minute doubling to 1 hour', () => {
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 8, 20, 1000].map(backoff), [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600, 3600]);
  assert.equal(backoff(0), 60);
  assert.equal(backoff(-3), 60);
});

test('busy: a short delay doubling to one minute', () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6, 50].map(busyDelay), [5, 5, 10, 20, 40, 60, 60, 60]);
});

test('after 3 consecutive "zone changed" the error backoff applies', () => {
  assert.equal(CHANGED_RETRIES, 3);
});

const own = () => false;

test('debounce: due 5 s after the last change, at most 30 s after the first', () => {
  const d = new Debounce(5);
  assert.equal(d.max, 30);
  d.add(7, { seq: 1, xid: '10' }, 100);
  assert.deepEqual(d.flush(104, own), []);
  d.add(7, { seq: 2, xid: '11' }, 104);            // another change resets the wait
  assert.deepEqual(d.flush(108, own), []);
  assert.deepEqual(d.flush(109, own), [7]);
  assert.equal(d.size, 0);
  assert.deepEqual(d.flush(500, own), []);
  // a steady stream cannot postpone the run for ever
  d.add(8, { seq: 3, xid: '12' }, 1000);
  for (let t = 1003; t < 1030; t += 3) { d.add(8, { seq: t, xid: String(t) }, t); assert.deepEqual(d.flush(t, own), [], `t=${t}`); }
  d.add(8, { seq: 9999, xid: '9999' }, 1030);
  assert.deepEqual(d.flush(1030, own), [8]);
});

test('debounce: our own rows are skipped, a foreign row among them is not', () => {
  const w = new OwnWrites();
  w.add({ xid: '42', seq_first: null, seq_last: null });
  const d = new Debounce(5);
  d.add(1, { seq: 1, xid: '42' }, 0);
  d.add(1, { seq: 2, xid: '42' }, 1);
  d.add(2, { seq: 3, xid: '42' }, 0);
  d.add(2, { seq: 4, xid: '43' }, 0);
  assert.deepEqual(d.flush(100, (r) => w.isOwn(r)), [2]);
});

test('debounce: a zone that is being signed keeps its entry until it is done', () => {
  const d = new Debounce(5);
  d.add(1, { seq: 1, xid: '1' }, 0);
  assert.deepEqual(d.flush(100, own, (id) => id === 1), []);
  assert.equal(d.size, 1);
  assert.deepEqual(d.flush(100, own, () => false), [1]);
});

test('debounce: too many separate runs to remember means the zone is looked at, own writes or not', () => {
  const w = new OwnWrites();
  w.add({ xid: null, seq_first: 0, seq_last: 1000 });
  const d = new Debounce(5);
  for (let i = 0; i < 300; i++) d.add(1, { seq: i * 2, xid: null }, 0);      // 300 runs of one row each
  assert.deepEqual(d.flush(100, (r) => w.isOwn(r)), [1]);
});

test('debounce: the rows of one write of a big zone are one run, and our own (SQLite3: a row per changed row)', () => {
  const w = new OwnWrites();
  const d = new Debounce(5);
  for (let i = 1000; i < 101000; i++) d.add(4, { seq: i, xid: null }, 0);    // 100,000 log rows of one import --signer
  assert.equal(d.zones.get(4).rows.length, 1);
  assert.deepEqual(d.flush(100, (r) => w.isOwn(r)), [4], 'not ours yet: the write id is not known');
  for (let i = 1000; i < 101000; i++) d.add(4, { seq: i, xid: null }, 200);
  w.add({ xid: null, seq_first: 1000, seq_last: 100999 });
  assert.deepEqual(d.flush(300, (r) => w.isOwn(r)), [], 'one write, all of it ours: no new run');
  // two writes of ours one after the other (the import, then the INSERT of the keys) are one run in the log, covered by both
  w.add({ xid: null, seq_first: 101000, seq_last: 101003 });
  for (let i = 1000; i < 101004; i++) d.add(4, { seq: i, xid: null }, 350);
  assert.deepEqual(d.flush(360, (r) => w.isOwn(r)), []);
  // a foreign row right after ours joins the run, and the run is no longer within our range
  for (let i = 1000; i < 101005; i++) d.add(4, { seq: i, xid: null }, 400);
  assert.deepEqual(d.flush(500, (r) => w.isOwn(r)), [4]);
  // a foreign row before ours, and one in the middle of a gap: separate runs
  d.add(4, { seq: 999, xid: null }, 600);
  for (let i = 1000; i < 1010; i++) d.add(4, { seq: i, xid: null }, 600);
  assert.equal(d.zones.get(4).rows.length, 1, 'consecutive with the row before: still one run');
  assert.deepEqual(d.flush(700, (r) => w.isOwn(r)), [4]);
});

test('debounce: PostgreSQL rows of one transaction are one entry', () => {
  const w = new OwnWrites();
  w.add({ xid: '77', seq_first: null, seq_last: null });
  const d = new Debounce(5);
  for (let i = 0; i < 1000; i++) d.add(1, { seq: i, xid: '77' }, 0);
  assert.equal(d.zones.get(1).rows.length, 1);
  assert.deepEqual(d.flush(100, (r) => w.isOwn(r)), []);
});

test('own writes: PostgreSQL by xid8, SQLite3 by a range of seq', () => {
  const w = new OwnWrites();
  w.add({ xid: '12345', seq_first: null, seq_last: null });
  w.add({ xid: null, seq_first: 100, seq_last: 130 });
  w.add({ xid: null, seq_first: null, seq_last: null });       // a write that made no log row
  w.add(null);
  assert.ok(w.isOwn({ seq: 5, xid: '12345' }));
  assert.ok(w.isOwn({ seq: 5, xid: 12345 }));
  assert.ok(!w.isOwn({ seq: 5, xid: '12346' }));
  assert.ok(w.isOwn({ seq: 100, xid: null }));
  assert.ok(w.isOwn({ seq: 130, xid: null }));
  assert.ok(!w.isOwn({ seq: 99, xid: null }));
  assert.ok(!w.isOwn({ seq: 131, xid: null }));
  assert.ok(!w.isOwn({ xid: null }));
});

test('own writes: bounded', () => {
  const w = new OwnWrites(3);
  for (let i = 1; i <= 5; i++) w.add({ xid: String(i), seq_first: i * 10, seq_last: i * 10 + 1 });
  assert.ok(!w.isOwn({ seq: 0, xid: '1' }) && w.isOwn({ seq: 0, xid: '5' }));
  assert.ok(!w.isOwn({ seq: 10, xid: null }) && w.isOwn({ seq: 51, xid: null }));
});

test('change-log position: a change is not a change of the zone when its write id was ours (not decided by the serial)', () => {
  // the same rows, once with and once without the write id: only the registry decides
  const rows = [{ seq: 10, xid: null }, { seq: 11, xid: null }, { seq: 12, xid: null }];
  const w = new OwnWrites();
  const d = new Debounce(5);
  for (const r of rows) d.add(3, r, 0);
  assert.deepEqual(d.flush(10, (r) => w.isOwn(r)), [3]);
  w.add({ xid: null, seq_first: 10, seq_last: 12 });
  for (const r of rows) d.add(3, r, 20);
  assert.deepEqual(d.flush(30, (r) => w.isOwn(r)), []);
  d.add(3, { seq: 13, xid: null }, 40);
  assert.deepEqual(d.flush(50, (r) => w.isOwn(r)), [3]);
});

test('debounce: take() hands the rows of a zone to a run, putBack() returns them and keeps what came meanwhile', () => {
  const d = new Debounce(5);
  assert.equal(d.take(1), null);
  d.add(1, { seq: 1, xid: null }, 0);
  d.add(2, { seq: 2, xid: null }, 0);
  const z = d.take(1);
  assert.deepEqual(z.rows, [{ seq: 1, seqEnd: 1, xid: null }]);
  assert.deepEqual(d.flush(10, () => false), [2], 'the taken zone is not flushed');
  d.putBack(1, null);
  assert.equal(d.size, 0);
  d.putBack(1, z);
  assert.deepEqual(d.flush(10, () => false), [1]);
  // back next to rows that came while the run went on: the older first, the burst from the older row
  d.add(1, { seq: 1, xid: null }, 0);
  const z2 = d.take(1);
  d.add(1, { seq: 9, xid: '9' }, 8);
  d.putBack(1, z2);
  assert.deepEqual(d.zones.get(1).rows.map((r) => r.seq), [1, 9]);
  assert.equal(d.zones.get(1).first, 0);
  assert.deepEqual(d.flush(13, (r) => r.xid === '9'), [1], 'the returned row is not ours');
  // more than 256 runs together: the zone counts as overflowed
  for (let i = 0; i < 200; i++) d.add(1, { seq: 1000 + 2 * i, xid: null }, 20);
  const z3 = d.take(1);
  for (let i = 0; i < 100; i++) d.add(1, { seq: 5000 + 2 * i, xid: null }, 21);
  d.putBack(1, z3);
  assert.equal(d.zones.get(1).rows.length, 256);
  assert.equal(d.zones.get(1).overflow, true);
});

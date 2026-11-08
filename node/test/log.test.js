import test from 'node:test';
import assert from 'node:assert/strict';
import { createLogger } from '../lib/log.js';

const sink = () => { const lines = []; return { lines, write: (s) => { lines.push(s); } }; };

test('stderr: time, name, pid, level; no control characters', () => {
  const s = sink();
  const log = createLogger({ stream: s, name: 'karidns-x' });
  log.info('signed example.test');
  log.warn('slow');
  log.error('line one\nline two\u0000\u001b[31m');
  assert.match(s.lines[0], /^\d{4}-\d\d-\d\dT[\d:.]+Z karidns-x\[\d+\]: signed example\.test\n$/);
  assert.match(s.lines[1], / karidns-x\[\d+\]: warning: slow\n$/);
  assert.match(s.lines[2], /: error: line one line two \[31m\n$/);
  assert.equal(s.lines.join('').split('\n').length, 4);
  log.close();
});

function fakeLogger() {
  const written = [];
  const handlers = {};
  const stdinH = {};
  const child = { stdin: { write: (s) => { written.push(s); }, end: () => { written.push('<end>'); }, on: (e, f) => { stdinH[e] = f; } }, on: (e, f) => { handlers[e] = f; } };
  const calls = [];
  const spawnFn = (file, argv, opts) => { calls.push([file, argv, opts]); return child; };
  return { written, handlers, stdinH, calls, spawnFn };
}

test('syslog: one logger(1) child with the facility, no shell', () => {
  const f = fakeLogger();
  const s = sink();
  const log = createLogger({ target: 'daemon', stream: s, spawnFn: f.spawnFn });
  assert.deepEqual(f.calls[0].slice(0, 2), ['/usr/bin/logger', ['-t', 'karidns', '-p', 'daemon.notice']]);
  assert.equal(f.calls[0][2].shell, false);
  log.info('hello');
  log.error('bad');
  assert.deepEqual(f.written, ['hello\n', 'error: bad\n']);
  assert.equal(s.lines.length, 0);
  log.close();
  log.close();
  assert.deepEqual(f.written.slice(-1), ['<end>']);
});

test('syslog: when logger goes away the lines go to stderr', () => {
  const f = fakeLogger();
  const s = sink();
  const log = createLogger({ target: 'local3', stream: s, spawnFn: f.spawnFn });
  f.handlers.error(new Error('ENOENT'));
  log.info('after');
  assert.match(s.lines[0], /after/);
  const g = fakeLogger();
  const log2 = createLogger({ target: 'local3', stream: s, spawnFn: g.spawnFn });
  g.stdinH.error(new Error('EPIPE'));
  log2.info('after pipe');
  assert.match(s.lines[1], /after pipe/);
});

test('syslog: a logger that cannot be started falls back to stderr', () => {
  const s = sink();
  const log = createLogger({ target: 'daemon', stream: s, spawnFn: () => { throw new Error('no logger'); } });
  log.info('x');
  assert.match(s.lines[0], /x/);
});

test('the default stream is standard error', () => {
  const log = createLogger({});
  assert.equal(typeof log.info, 'function');
  log.close();
});

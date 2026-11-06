import test from 'node:test';
import assert from 'node:assert/strict';
import { runChild, childEnv, ENV, clip } from '../lib/run.js';

const NODE = process.execPath;

test('stdout, stderr and the exit status', async () => {
  const r = await runChild(NODE, ['-e', 'console.log("out"); console.error("err"); process.exit(3)']);
  assert.equal(r.code, 3);
  assert.equal(r.stdout.trim(), 'out');
  assert.equal(r.stderr.trim(), 'err');
  assert.ok(!r.timedOut && !r.truncated && !r.spawnError);
});

test('no shell: metacharacters are plain argv words', async () => {
  const words = ['a;b', '$(id)', '`id`', '*', 'x y', '', '--', '-rf', "it's", '\n'];
  const r = await runChild(NODE, ['-e', 'console.log(JSON.stringify(process.argv.slice(1)))', ...words]);
  assert.deepEqual(JSON.parse(r.stdout), words);
});

test('the environment is fixed', async () => {
  const r = await runChild(NODE, ['-e', 'console.log(JSON.stringify(process.env))'], { env: childEnv('/home/signer') });
  const env = JSON.parse(r.stdout);
  for (const [k, v] of Object.entries(ENV)) assert.equal(env[k], v);
  assert.equal(env.HOME, '/home/signer');
  assert.ok(!('SECRET_FROM_PARENT' in env));
  assert.deepEqual(childEnv(''), { ...ENV });
  assert.equal(Object.isFrozen(ENV), true);
});

test('the parent environment does not leak into a child', async () => {
  process.env.SECRET_FROM_PARENT = 'x';
  try {
    const r = await runChild(NODE, ['-e', 'console.log(process.env.SECRET_FROM_PARENT ?? "unset")']);
    assert.equal(r.stdout.trim(), 'unset');
  } finally {
    delete process.env.SECRET_FROM_PARENT;
  }
});

test('a child that runs too long is killed', async () => {
  const t0 = Date.now();
  const r = await runChild(NODE, ['-e', 'setTimeout(() => {}, 60000)'], { timeoutMs: 300 });
  assert.equal(r.timedOut, true);
  assert.ok(Date.now() - t0 < 10000);
  assert.ok(r.code !== 0);
});

test('a child that writes too much is killed and the output is cut', async () => {
  const r = await runChild(NODE, ['-e', 'const b = Buffer.alloc(65536, 97); function w() { while (process.stdout.write(b)); process.stdout.once("drain", w); } w()'], { maxOutput: 100000, timeoutMs: 20000 });
  assert.equal(r.truncated, true);
  assert.equal(r.stdout.length, 100000);
  const e = await runChild(NODE, ['-e', 'const b = Buffer.alloc(65536, 98); function w() { while (process.stderr.write(b)); process.stderr.once("drain", w); } w()'], { maxOutput: 1000, timeoutMs: 20000 });
  assert.equal(e.truncated, true);
  assert.equal(e.stderr.length, 1000);
});

test('a program that is not there', async () => {
  const r = await runChild('/nonexistent/dnssec-signzone', ['-V']);
  assert.match(r.spawnError, /ENOENT/);
  assert.equal(r.code, null);
});

test('spawn that throws', async () => {
  const r = await runChild('x', [], { spawnFn: () => { throw new Error('EACCES'); } });
  assert.equal(r.spawnError, 'EACCES');
});

test('the working directory', async () => {
  const r = await runChild(NODE, ['-e', 'console.log(process.cwd())'], { cwd: process.platform === 'win32' ? process.env.SystemRoot : '/' });
  assert.ok(r.stdout.trim().length > 0);
});

test('clip: control characters out, 1 KB at most', () => {
  assert.equal(clip('a\u0000b\u0007c\td\ne'), 'a?b?c\td\ne');
  assert.equal(clip('x'.repeat(5000)).length, 1027);
  assert.equal(clip('x'.repeat(5000), 10), 'xxxxxxxxxx...');
  assert.equal(clip('  hi  '), 'hi');
  assert.equal(clip(null), 'null');
});

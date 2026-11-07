import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkWorkDir, wipeFile, wipeDir, makeZoneDir, writeSecret, wipeStale } from '../lib/workdir.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ks-wd-'));
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });

test('the work directory must be ours and closed', () => {
  const st = (o) => ({ isDirectory: () => true, uid: 1000, mode: 0o40700, ...o });
  assert.equal(checkWorkDir('/w', st(), 1000), null);
  assert.match(checkWorkDir('/w', st({ isDirectory: () => false }), 1000), /not a directory/);
  assert.match(checkWorkDir('/w', st({ uid: 0 }), 1000), /not owned/);
  assert.match(checkWorkDir('/w', st({ mode: 0o40750 }), 1000), /mode 0750, it must be 0700/);
  assert.match(checkWorkDir('/w', st({ mode: 0o40707 }), 1000), /mode 0707/);
  assert.match(checkWorkDir('/nonexistent/w', undefined, 1000), /cannot read work-dir/);
  const d = tmp();
  try {
    if (process.platform !== 'win32') {
      fs.chmodSync(d, 0o700);
      assert.equal(checkWorkDir(d), null);
      fs.chmodSync(d, 0o755);
      assert.match(checkWorkDir(d), /must be 0700/);
    } else {
      assert.equal(typeof checkWorkDir(d), 'string');
    }
  } finally { rm(d); }
});

test('a key file is overwritten with zeros before it is unlinked', () => {
  const d = tmp();
  try {
    const f = path.join(d, 'K.private');
    fs.writeFileSync(f, 'SECRETSECRETSECRET');
    // keep the inode open: what is on disk when wipeFile has unlinked it
    const fd = fs.openSync(f, 'r');
    wipeFile(f);
    assert.ok(!fs.existsSync(f));
    const seen = Buffer.alloc(18);
    fs.readSync(fd, seen, 0, 18, 0);
    fs.closeSync(fd);
    assert.deepEqual([...seen], new Array(18).fill(0));
    wipeFile(f);                                  // already gone: no error
  } finally { rm(d); }
});

test('a big file is overwritten in blocks', () => {
  const d = tmp();
  try {
    const f = path.join(d, 'big');
    fs.writeFileSync(f, Buffer.alloc((1 << 20) + 5, 7));
    wipeFile(f);
    assert.ok(!fs.existsSync(f));
  } finally { rm(d); }
});

test('wipeFile of something that cannot be opened for writing still removes it', () => {
  if (process.platform === 'win32') return;
  const d = tmp();
  try {
    const target = path.join(d, 'target');
    fs.writeFileSync(target, 'x');
    const link = path.join(d, 'link');
    fs.symlinkSync(target, link);                // O_NOFOLLOW: the link itself is removed, its target is not touched
    wipeFile(link);
    assert.ok(!fs.existsSync(link));
    assert.equal(fs.readFileSync(target, 'utf8'), 'x');
  } finally { rm(d); }
});

test('wipeDir removes files, subdirectories and the directory; a missing one is fine', () => {
  const d = tmp();
  try {
    fs.mkdirSync(path.join(d, 'z/sub'), { recursive: true });
    fs.writeFileSync(path.join(d, 'z/a'), 'a');
    fs.writeFileSync(path.join(d, 'z/sub/b'), 'b');
    wipeDir(path.join(d, 'z'));
    assert.ok(!fs.existsSync(path.join(d, 'z')));
    wipeDir(path.join(d, 'z'));
  } finally { rm(d); }
});

test('a directory per zone and run: mode 0700, never the same twice, the name is checked', () => {
  const d = tmp();
  try {
    const a = makeZoneDir(d, 'Example.Test.');
    const b = makeZoneDir(d, 'example.test');
    assert.notEqual(a, b);
    assert.equal(path.dirname(a), d);
    assert.match(path.basename(a), new RegExp(`^example\\.test\\.${process.pid}\\.[0-9]+$`));
    if (process.platform !== 'win32') assert.equal(fs.statSync(a).mode & 0o777, 0o700);
    assert.throws(() => makeZoneDir(d, '../etc'), /zone name/);
    assert.throws(() => makeZoneDir(path.join(d, 'nope'), 'example.test'), /ENOENT/);
  } finally { rm(d); }
});

test('a name that exists is skipped', () => {
  const d = tmp();
  try {
    const a = makeZoneDir(d, 'x.test');
    const n = Number(path.basename(a).split('.').pop());
    fs.mkdirSync(path.join(d, `x.test.${process.pid}.${n + 1}`));
    const b = makeZoneDir(d, 'x.test');
    assert.equal(path.basename(b), `x.test.${process.pid}.${n + 2}`);
  } finally { rm(d); }
});

test('secrets are written exclusively with mode 0600', () => {
  const d = tmp();
  try {
    const f = path.join(d, 'k');
    writeSecret(f, 'data');
    if (process.platform !== 'win32') assert.equal(fs.statSync(f).mode & 0o777, 0o600);
    assert.throws(() => writeSecret(f, 'again'), /EEXIST/);
  } finally { rm(d); }
});

test('left-overs of a dead signer are wiped at start, a live one and other things are not touched', () => {
  const d = tmp();
  try {
    const mk = (n) => { fs.mkdirSync(path.join(d, n)); fs.writeFileSync(path.join(d, n, 'Kx.private'), 'SECRET'); };
    mk('example.test.4242.1');
    mk('other.test.4343.7');
    mk('mine.test.1.1');
    fs.mkdirSync(path.join(d, 'not-ours'));
    fs.writeFileSync(path.join(d, 'not-ours/keep'), 'x');
    fs.writeFileSync(path.join(d, 'example.test.4242.2'), 'a file, not a directory');
    const kill = (pid) => { if (pid === 4343 || pid === 1) return true; const e = new Error('ESRCH'); e.code = 'ESRCH'; throw e; };
    const wiped = wipeStale(d, { kill });
    assert.deepEqual(wiped, ['example.test.4242.1']);
    assert.ok(!fs.existsSync(path.join(d, 'example.test.4242.1')));
    assert.ok(fs.existsSync(path.join(d, 'other.test.4343.7/Kx.private')));
    assert.ok(fs.existsSync(path.join(d, 'mine.test.1.1')));
    assert.ok(fs.existsSync(path.join(d, 'not-ours/keep')));
    assert.ok(fs.existsSync(path.join(d, 'example.test.4242.2')));
    // EPERM means the process exists (another user's)
    const kill2 = () => { const e = new Error('EPERM'); e.code = 'EPERM'; throw e; };
    assert.deepEqual(wipeStale(d, { kill: kill2 }), []);
    assert.deepEqual(wipeStale(path.join(d, 'none')), []);
  } finally { rm(d); }
});

test('wipeStale with the real kill: our own pid is alive, an unused pid is not', () => {
  const d = tmp();
  try {
    fs.mkdirSync(path.join(d, `a.test.${process.pid}.1`));
    fs.mkdirSync(path.join(d, 'b.test.2147483646.1'));
    assert.deepEqual(wipeStale(d), ['b.test.2147483646.1']);
  } finally { rm(d); }
});

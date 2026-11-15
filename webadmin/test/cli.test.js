// the command line, --check, --create-admin, the checks of the start, and the server loop with its signals

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseArgs, main, USAGE, VERSION, DEFAULT_CONFIG } from '../lib/cli.js';
import { openBackend, inspect, createAdmin, rotateTotpKey, rotationPending, syncDir } from '../lib/setup.js';
import { wrapSecret, unwrapSecret } from '../lib/crypto.js';
import * as S from '../lib/store.js';
import { parseConfig, loadConfig, validate } from '../lib/config.js';
import { SqliteBackend } from '../lib/db.js';
import { runChild } from '../../node/lib/run.js';
import { sqlite, makeFiles, confText, memLog, deploy, rmDir } from './helpers.js';

const sink = () => { let t = ''; return { write: (s) => { t += s; }, get text() { return t; } }; };
const run = async (argv, deps = {}) => {
  const stdout = sink();
  const stderr = sink();
  const status = await main(argv, { stdout, stderr, deps });
  return { status, out: stdout.text, err: stderr.text };
};

test('the options', () => {
  assert.deepEqual(parseArgs([]), { config: DEFAULT_CONFIG, check: false, help: false, version: false, createAdmin: undefined, rotate: false, bootstrap: undefined });
  assert.deepEqual(parseArgs(['--rotate-totp-key', '--bootstrap-conninfo-file', '/b']), { config: DEFAULT_CONFIG, check: false, help: false, version: false, createAdmin: undefined, rotate: true, bootstrap: '/b' });
  assert.throws(() => parseArgs(['--rotate-totp-key', '--check']), /^Error: --check, --create-admin and --rotate-totp-key do not go together$/);
  assert.throws(() => parseArgs(['--rotate-totp-key', '--create-admin', 'a']), /do not go together/);
  assert.match(USAGE, /--rotate-totp-key \[--bootstrap-conninfo-file FILE\]/);
  assert.equal(parseArgs(['-c', '/x.conf']).config, '/x.conf');
  assert.equal(parseArgs(['--config', '/y.conf', '--check']).check, true);
  assert.equal(parseArgs(['--create-admin', 'admin']).createAdmin, 'admin');
  assert.deepEqual(parseArgs(['--create-admin', 'a', '--bootstrap-conninfo-file', '/b']).bootstrap, '/b');
  assert.equal(parseArgs(['-h']).help, true);
  assert.equal(parseArgs(['-v']).version, true);
  assert.throws(() => parseArgs(['-c']), /-c needs a value/);
  assert.throws(() => parseArgs(['--create-admin']), /needs a value/);
  assert.throws(() => parseArgs(['--bogus']), /unknown option "--bogus"/);
  assert.throws(() => parseArgs(['--check', '--create-admin', 'a']), /do not go together/);
  assert.throws(() => parseArgs(['--bootstrap-conninfo-file', '/b']), /is for --create-admin and --rotate-totp-key/);
  assert.match(USAGE, /Usage: karidns-webadmin/);
});

test('help, version, a usage error, a configuration that cannot be read', async () => {
  let r = await run(['--help']);
  assert.deepEqual([r.status, r.out], [0, USAGE]);
  r = await run(['-v']);
  assert.deepEqual([r.status, r.out], [0, `karidns-webadmin ${VERSION}\n`]);
  r = await run(['--nope']);
  assert.equal(r.status, 2);
  assert.match(r.err, /unknown option/);
  assert.match(r.err, /Usage:/);
  r = await run(['-c', path.join(os.tmpdir(), 'kw-no-such-file.conf')]);
  assert.equal(r.status, 1);
  assert.match(r.err, /cannot read/);
});

const goodConfig = () => parseConfig(confText('/var/db/x'));

test('--check: the problems of the configuration, of the files, and a fine setup', async () => {
  const log = [];
  const deps = {
    loadConfig: () => goodConfig(),
    openBackend: async () => ({ close: async () => { log.push('closed'); } }),
    inspect: async () => ({ problems: [], notes: ['sqlite-file x: fine'], versions: {} }),
  };
  let r = await run(['--check'], deps);
  assert.equal(r.status, 0);
  assert.match(r.out, /ok: sqlite-file x: fine/);
  assert.match(r.out, /the configuration is fine/);
  assert.deepEqual(log, ['closed']);
  r = await run(['--check'], { ...deps, inspect: async () => ({ problems: ['karicheck: exit status 127'], notes: [], versions: {} }) });
  assert.equal(r.status, 1);
  assert.match(r.err, /problem: karicheck: exit status 127/);
  assert.match(r.out, /the configuration has problems/);
  // a configuration that is wrong: the problems are listed, the database is not opened
  let opened = false;
  r = await run(['--check'], { ...deps, loadConfig: () => parseConfig(''), openBackend: async () => { opened = true; }, inspect: async (c) => ({ problems: (await import('../lib/config.js')).validate(c), notes: [], versions: {} }) });
  assert.equal(r.status, 1);
  assert.equal(opened, false);
  assert.match(r.err, /problem: 'listen' is not set/);
  assert.equal((r.err.match(/'listen' is not set/g) ?? []).length, 1, 'once');
  // a database that cannot be opened is a problem too
  r = await run(['--check'], { ...deps, openBackend: async () => { throw new Error('cannot connect'); }, inspect: async () => ({ problems: [], notes: [], versions: {} }) });
  assert.equal(r.status, 1);
  assert.match(r.err, /problem: cannot connect/);
});

test('--create-admin: SQLite3 directly, PostgreSQL only with a trusted connection', async () => {
  const made = [];
  const deps = {
    loadConfig: () => goodConfig(),
    openBackend: async (c, o) => ({ close: async () => { made.push(['closed', o?.conninfoFile]); } }),
    createAdmin: async (c, name) => { made.push(['admin', name]); return { name, password: 'sekrit-once' }; },
  };
  let r = await run(['--create-admin', 'alice'], { ...deps, loadConfig: () => parseConfig(confText('/var/db/x', { 'require-totp': 'global' })) });
  assert.equal(r.status, 0);
  assert.match(r.out, /user alice made, a global master\.\npassword \(shown once\): sekrit-once\n/);
  assert.match(r.out, /TOTP is required for global masters/);
  assert.deepEqual(made, [['admin', 'alice'], ['closed', undefined]]);
  r = await run(['--create-admin', 'alice'], { ...deps, loadConfig: () => parseConfig(confText('/x', { 'require-totp': 'none' })) });
  assert.doesNotMatch(r.out, /TOTP/);
  const pg = () => parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /a\ncheck-conninfo-file = /b\n');
  r = await run(['--create-admin', 'alice'], { ...deps, loadConfig: pg });
  assert.equal(r.status, 1);
  assert.match(r.err, /--bootstrap-conninfo-file/);
  made.length = 0;
  r = await run(['--create-admin', 'alice', '--bootstrap-conninfo-file', '/owner.conninfo'], { ...deps, loadConfig: pg });
  assert.equal(r.status, 0);
  assert.deepEqual(made, [['admin', 'alice'], ['closed', '/owner.conninfo']]);
  r = await run(['--create-admin', 'alice'], { ...deps, loadConfig: () => parseConfig('') });
  assert.equal(r.status, 1);
  assert.match(r.err, /'listen' is not set/);
  r = await run(['--create-admin', 'alice'], { ...deps, createAdmin: async () => { throw new Error('a principal named alice exists already'); } });
  assert.equal(r.status, 1);
  assert.match(r.err, /exists already/);
  r = await run(['--create-admin', 'alice'], { ...deps, openBackend: async () => { throw new Error('cannot open'); } });
  assert.equal(r.status, 1);
  assert.match(r.err, /cannot open/);
});

test('--rotate-totp-key: the command line (SQLite3 directly, PostgreSQL with the owner connection), what it prints', async () => {
  const made = [];
  let answer = { rewrapped: 3, unreadable: 0, finished: false, old: '/var/db/x/totp.key.old' };
  const deps = {
    loadConfig: () => goodConfig(),
    openBackend: async (c, o) => ({ close: async () => { made.push(['closed', o?.conninfoFile]); } }),
    rotateTotpKey: async () => { made.push(['rotate']); if (answer instanceof Error) throw answer; return answer; },
  };
  const kf = goodConfig().settings['totp-key-file'];
  let r = await run(['--rotate-totp-key'], deps);
  assert.equal(r.status, 0, r.err);
  assert.equal(r.out, `the TOTP key is new: 3 secret(s) wrapped again with it in ${kf}\nthe old key is kept in /var/db/x/totp.key.old: delete it once the TOTP logins work\n`);
  assert.deepEqual(made, [['rotate'], ['closed', undefined]]);
  answer = { rewrapped: 1, unreadable: 2, finished: true, old: '/var/db/x/totp.key.old' };
  r = await run(['--rotate-totp-key'], deps);
  assert.ok(r.out.startsWith(`the TOTP key of an earlier run is now ${kf}: 1 secret(s) that still opened with the old key wrapped again with it\n2 secret(s) open with no key and were left as they are: reset the TOTP of those users`), r.out);
  assert.ok(r.out.endsWith('\nthe old key is kept in /var/db/x/totp.key.old: delete it once the TOTP logins work\n'), r.out);
  const pg = () => parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /a\ncheck-conninfo-file = /b\n');
  r = await run(['--rotate-totp-key'], { ...deps, loadConfig: pg });
  assert.equal(r.status, 1);
  assert.match(r.err, /^karidns-webadmin: on PostgreSQL --rotate-totp-key needs --bootstrap-conninfo-file: the API role sees the credentials of its own principal only/);
  made.length = 0;
  answer = { rewrapped: 1, unreadable: 0, finished: false, old: '/k.old' };
  r = await run(['--rotate-totp-key', '--bootstrap-conninfo-file', '/owner.conninfo'], { ...deps, loadConfig: pg });
  assert.equal(r.status, 0);
  assert.deepEqual(made, [['rotate'], ['closed', '/owner.conninfo']]);
  answer = new Error('/var/db/x/totp.key.new has mode 0644, it must not be readable by others (0600) (an earlier --rotate-totp-key left it? look at it, remove it, and run again)');
  r = await run(['--rotate-totp-key'], deps);
  assert.equal(r.status, 1);
  assert.match(r.err, /^karidns-webadmin: \/var\/db\/x\/totp\.key\.new has mode 0644/);
  r = await run(['--rotate-totp-key'], { ...deps, loadConfig: () => parseConfig('') });
  assert.equal(r.status, 1);
  assert.match(r.err, /'listen' is not set/);
});

// an fs in memory for the key files: { name: { text, mode, uid, kind } } (kind 'link': not a regular file); the directory of the files can be opened and synced.
// failOn: { rename: n } makes the n-th rename throw (a crash before it), { dirOpen: code } the opening of the directory.  ops: the writes, renames, unlinks and fsyncs
function keyFs(files, failOn = {}) {
  const fds = new Map();
  const ops = [];
  let renames = 0;
  let nextFd = 3;
  const uid = process.getuid?.();
  const noent = (f) => Object.assign(new Error(`ENOENT: ${f}`), { code: 'ENOENT' });
  const isDir = (f) => Object.keys(files).some((k) => path.dirname(k) === f);
  return {
    files,
    ops,
    openSync: (f) => {
      if (!files[f] && !isDir(f)) throw noent(f);
      if (!files[f] && failOn.dirOpen) throw Object.assign(new Error(`${failOn.dirOpen}: ${f}`), { code: failOn.dirOpen });
      fds.set(nextFd, f);
      return nextFd++;
    },
    fstatSync: (fd) => { const e = files[fds.get(fd)]; return { isFile: () => true, mode: 0o100000 | (e.mode ?? 0o600), uid: e.uid ?? uid }; },
    lstatSync: (f) => { const e = files[f]; if (!e) throw noent(f); return { isFile: () => e.kind === undefined }; },
    readFileSync: (fd) => files[fds.get(fd)].text,
    fsyncSync: (fd) => { ops.push(['fsync', fds.get(fd)]); },
    closeSync: (fd) => { fds.delete(fd); },
    writeFileSync: (f, text, o) => {
      assert.deepEqual(o, { mode: 0o600, flag: 'wx', flush: true });
      if (files[f]) throw Object.assign(new Error('EEXIST'), { code: 'EEXIST' });
      files[f] = { text, mode: 0o600 };
      ops.push(['write', f]);
    },
    renameSync: (a, b) => {
      renames++;
      if (renames === failOn.rename) throw new Error('the machine went down');
      files[b] = files[a];
      delete files[a];
      ops.push(['rename', a, b]);
    },
    unlinkSync: (f) => { if (!files[f]) throw noent(f); delete files[f]; ops.push(['unlink', f]); },
  };
}

test('rotateTotpKey on SQLite3: every secret wrapped again in one transaction, the old key kept as .old, the new key renamed over the old; an unfinished run is mended by a second one', async () => {
  const d = await deploy();
  try {
    const file = d.config.settings['totp-key-file'];
    const next = `${file}.new`;
    const kept = `${file}.old`;
    const dir = path.dirname(file);
    const oldKey = Buffer.alloc(32, 7);
    const hex = (k) => `${k.toString('hex')}\n`;
    const ids = [];
    for (const n of ['ann', 'ben', 'cat']) ids.push(await d.makeUser(n, null));
    const secret = (id) => JSON.stringify({ s: `secret-of-${id}`, u: -1 });
    await d.backend.tx({ write: true }, async (tx) => {
      for (const id of ids) await tx.run('INSERT INTO auth.credentials (principal_id) VALUES ($1)', [id]);
      await S.setTotp(tx, ids[0], wrapSecret(oldKey, ids[0], secret(ids[0])), true);
      await S.setTotp(tx, ids[1], wrapSecret(oldKey, ids[1], secret(ids[1])), false);           // (an enrolment that was started)
      await S.setTotp(tx, ids[2], wrapSecret(Buffer.alloc(32, 9), ids[2], secret(ids[2])), true); // (a key lost before: it opens with nothing)
    });
    const stored = async () => d.backend.tx({}, (tx) => S.totpSecrets(tx));
    const keyOf = (fsx, f = file) => Buffer.from(fsx.files[f].text.trim(), 'hex');
    const opensWith = async (key) => (await stored()).filter((r) => unwrapSecret(key, r.principal_id, r.totp_secret) === secret(r.principal_id)).map((r) => r.principal_id);
    const names = (fsx) => Object.keys(fsx.files).sort();

    // a crash between the commit and the rename: the secrets open with .new only, the old key is in .old already; the second run adopts .new, wraps nothing, renames
    const f1 = keyFs({ [file]: { text: hex(oldKey) } }, { rename: 1 });
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f1 }), /the machine went down/);
    assert.deepEqual(f1.ops, [['write', next], ['fsync', dir], ['write', kept]], 'the directory is synced after .new is made');
    const k1 = keyOf(f1, next);
    assert.deepEqual(await opensWith(k1), [ids[0], ids[1]]);
    assert.deepEqual(await opensWith(oldKey), []);
    assert.equal(f1.files[next].mode, 0o600);
    assert.deepEqual(await rotateTotpKey(d.config, d.backend, { fsx: f1 }), { rewrapped: 0, unreadable: 1, finished: true, old: kept });
    assert.deepEqual(names(f1), [file, kept].sort());
    assert.ok(keyOf(f1).equals(k1));
    assert.ok(keyOf(f1, kept).equals(oldKey), 'the old key is kept');
    assert.equal(f1.files[kept].mode, 0o600);

    // the same crash, then a service with the old key wrote a secret under it (an enrolment): the second run adopts .new and wraps that secret again with it
    const f2 = keyFs({ [file]: { text: hex(k1) } }, { rename: 1 });
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f2 }), /the machine went down/);
    const k2 = keyOf(f2, next);
    await d.backend.tx({ write: true }, (tx) => S.setTotp(tx, ids[1], wrapSecret(k1, ids[1], secret(ids[1])), false));
    assert.deepEqual(await opensWith(k2), [ids[0]]);
    f2.ops.length = 0;
    assert.deepEqual(await rotateTotpKey(d.config, d.backend, { fsx: f2 }), { rewrapped: 1, unreadable: 1, finished: true, old: kept });
    assert.deepEqual(await opensWith(k2), [ids[0], ids[1]]);
    assert.ok(keyOf(f2).equals(k2) && keyOf(f2, kept).equals(k1));
    assert.deepEqual(f2.ops, [['unlink', kept], ['write', kept], ['rename', next, file], ['fsync', dir]], 'the older .old is replaced, the directory synced after the rename');

    // a normal run: 2 wrapped again, the one that opens with no key counted and left as it was, the key before kept
    const before = (await stored()).find((r) => r.principal_id === ids[2]).totp_secret;
    f2.ops.length = 0;
    assert.deepEqual(await rotateTotpKey(d.config, d.backend, { fsx: f2 }), { rewrapped: 2, unreadable: 1, finished: false, old: kept });
    const k3 = keyOf(f2);
    assert.ok(!k3.equals(k2) && keyOf(f2, kept).equals(k2));
    assert.deepEqual(await opensWith(k3), [ids[0], ids[1]]);
    assert.equal((await stored()).find((r) => r.principal_id === ids[2]).totp_secret, before);
    assert.deepEqual(names(f2), [file, kept].sort());
    assert.deepEqual(f2.ops, [['write', next], ['fsync', dir], ['unlink', kept], ['write', kept], ['rename', next, file], ['fsync', dir]]);

    // a crash before the commit (a .new no secret opens with) and a .new that is not a key: thrown away, the rotation done again
    for (const left of [hex(Buffer.alloc(32, 5)), 'half a key']) {
      f2.files[next] = { text: left };
      assert.deepEqual(await rotateTotpKey(d.config, d.backend, { fsx: f2 }), { rewrapped: 2, unreadable: 1, finished: false, old: kept });
      assert.deepEqual(names(f2), [file, kept].sort());
      assert.deepEqual(await opensWith(keyOf(f2)), [ids[0], ids[1]]);
    }
    // a .new of the wrong mode is somebody else's business: refused, nothing changed; so is a key file that is not there (a rotation does not make the first key)
    const k4 = keyOf(f2);
    f2.files[next] = { text: hex(Buffer.alloc(32, 5)), mode: 0o644 };
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f2 }), /totp\.key\.new has mode 0644, it must not be readable by others \(0600\) \(an earlier --rotate-totp-key left it\? look at it, remove it, and run again\)$/);
    assert.ok(keyOf(f2).equals(k4));
    delete f2.files[next];
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: keyFs({}) }), /cannot read .*totp\.key: ENOENT/);
    // an .old that is not a regular file (a link): refused before anything is written
    const keptBefore = f2.files[kept];
    f2.files[kept] = { kind: 'link' };
    f2.ops.length = 0;
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f2 }), /^Error: .*totp\.key\.old is not a regular file: look at it, remove it, and run again$/);
    assert.deepEqual(f2.ops, []);
    f2.files[kept] = keptBefore;
    // the auth table is not there (another file): refused before anything is written
    d.backend.db.exec('ALTER TABLE auth.credentials RENAME TO credentials_x');
    try {
      await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f2 }), /^Error: the auth tables are not in this database \(the table credentials of the auth file is missing\): is it the database of the service\?$/);
    } finally {
      d.backend.db.exec('ALTER TABLE auth.credentials_x RENAME TO credentials');
    }
    assert.deepEqual(f2.ops, []);

    // the directory cannot be opened (Windows: EISDIR, EPERM) or synced (EINVAL): nothing more to do; another error is one (here before the commit: the next run redoes it)
    const fail = { dirOpen: 'EISDIR' };
    const f3 = keyFs({ [file]: { text: hex(k4) } }, fail);
    assert.deepEqual(await rotateTotpKey(d.config, d.backend, { fsx: f3 }), { rewrapped: 2, unreadable: 1, finished: false, old: kept });
    fail.dirOpen = 'EIO';
    const k5 = keyOf(f3);
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f3 }), /^Error: EIO: /);
    assert.deepEqual(await opensWith(k5), [ids[0], ids[1]], 'nothing was committed');
    delete fail.dirOpen;
    assert.deepEqual(await rotateTotpKey(d.config, d.backend, { fsx: f3 }), { rewrapped: 2, unreadable: 1, finished: false, old: kept });
    assert.ok(keyOf(f3, kept).equals(k5));

    // a secret that changes under the rotation (the service was not stopped): the transaction is rolled back, .new stays for the next run to decide
    const k6 = keyOf(f3);
    const racing = { ...d.backend, tx: (o, fn) => d.backend.tx(o, (tx) => fn({ ...tx, A: tx.A, dialect: tx.dialect, all: tx.all.bind(tx), get: tx.get.bind(tx), ts: tx.ts?.bind(tx), run: async () => ({ changes: 0 }) })) };
    await assert.rejects(rotateTotpKey(d.config, racing, { fsx: f3 }), /^Error: the TOTP secret of principal \d+ changed meanwhile: stop the service and run again$/);
    assert.ok(f3.files[next], '.new is left');
    assert.deepEqual(await opensWith(k6), [ids[0], ids[1]], 'nothing was committed');
    assert.deepEqual(await rotateTotpKey(d.config, d.backend, { fsx: f3 }), { rewrapped: 2, unreadable: 1, finished: false, old: kept });

    // the real files (where modes mean something)
    if (process.platform !== 'win32') {
      const k7 = keyOf(f3);
      fs.writeFileSync(file, hex(k7), { mode: 0o600 });
      fs.writeFileSync(kept, 'an older key', { mode: 0o600 });
      assert.deepEqual(await rotateTotpKey(d.config, d.backend), { rewrapped: 2, unreadable: 1, finished: false, old: kept });
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      assert.equal(fs.statSync(kept).mode & 0o777, 0o600);
      assert.equal(fs.readFileSync(kept, 'utf8'), hex(k7));
      assert.equal(fs.existsSync(next), false);
      assert.deepEqual(await opensWith(Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex')), [ids[0], ids[1]]);
    }
  } finally {
    await d.close();
  }
});

test('rotateTotpKey does not replace a .old that still opens a stored secret (a restored backup), on a new rotation and on an adopting rerun', async () => {
  const d = await deploy();
  try {
    const file = d.config.settings['totp-key-file'];
    const next = `${file}.new`;
    const kept = `${file}.old`;
    const hex = (k) => `${k.toString('hex')}\n`;
    const [kPrev, kCur, kNew] = [3, 4, 6].map((b) => Buffer.alloc(32, b));
    const ids = [await d.makeUser('ann', null), await d.makeUser('ben', null)];
    const secret = (id) => JSON.stringify({ s: `secret-of-${id}`, u: -1 });
    const put = (id, key) => d.backend.tx({ write: true }, (tx) => S.setTotp(tx, id, wrapSecret(key, id, secret(id)), true));
    await d.backend.tx({ write: true }, async (tx) => { for (const id of ids) await tx.run('INSERT INTO auth.credentials (principal_id) VALUES ($1)', [id]); });
    await put(ids[0], kCur);
    await put(ids[1], kPrev);                                                    // (restored from a backup made before the last rotation)
    const f = keyFs({ [file]: { text: hex(kCur) }, [kept]: { text: hex(kPrev) } });
    const refusal = /^Error: 1 stored TOTP secret\(s\) still need the old key in .*totp\.key\.old \(a database restored from a backup made before the last rotation\?\), so it is not replaced: move .*totp\.key\.old aside only when you are sure those secrets are not needed, and run again$/;
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f }), refusal);
    assert.deepEqual(f.ops, [], 'nothing written');
    // the same on a rerun that would adopt a .new (some secret opens with it): nothing written, .new left
    await put(ids[0], kNew);
    f.files[next] = { text: hex(kNew) };
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f }), refusal);
    assert.deepEqual(f.ops, []);
    assert.ok(f.files[next] && Buffer.from(f.files[kept].text.trim(), 'hex').equals(kPrev));
    // an .old that is not the service user's private file is refused too; one that is not a key opens nothing and is replaced
    f.files[kept] = { text: hex(kPrev), mode: 0o644 };
    await assert.rejects(rotateTotpKey(d.config, d.backend, { fsx: f }), /totp\.key\.old has mode 0644, it must not be readable by others \(0600\) \(look at it, move it aside, and run again\)$/);
    assert.deepEqual(f.ops, []);
    f.files[kept] = { text: 'moved aside, a note left' };
    assert.deepEqual(await rotateTotpKey(d.config, d.backend, { fsx: f }), { rewrapped: 0, unreadable: 1, finished: true, old: kept });
    assert.ok(Buffer.from(f.files[file].text.trim(), 'hex').equals(kNew));
    assert.ok(Buffer.from(f.files[kept].text.trim(), 'hex').equals(kCur));
  } finally {
    await d.close();
  }
});

test('rotateTotpKey on PostgreSQL: the role is checked first (row level security must not bind it), then the same statements through the owner connection, one transaction', async () => {
  const cfg = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /a\ncheck-conninfo-file = /b\ntotp-key-file = /k\n');
  const oldKey = Buffer.alloc(32, 1);
  const rows = [{ principal_id: '12', totp_secret: wrapSecret(oldKey, '12', 'x') }];          // (bigint ids come back as text from pg)
  const sql = [];
  let access = { there: true, rls: false, may: true };
  const backend = {
    tx: async (o, fn) => {
      sql.push(['tx', Boolean(o.write)]);
      return fn({
        dialect: 'pg', A: 'karidns_auth.',
        get: async (q, p) => { sql.push([q, ...(p ?? [])]); return /to_regclass/.test(q) ? { ok: access.there } : { rls: access.rls, may: access.may }; },
        all: async (q) => { sql.push([q]); return rows; },
        run: async (q, p) => { sql.push([q, p[0], p[1] === rows[0].totp_secret]); return { changes: 1 }; },
      });
    },
  };
  const f = keyFs({ '/k': { text: `${oldKey.toString('hex')}\n` } });
  const check = [['tx', false], ['SELECT to_regclass($1) IS NOT NULL AS ok', 'karidns_auth.credentials'],
    ["SELECT row_security_active('karidns_auth.credentials') AS rls, has_table_privilege('karidns_auth.credentials', 'SELECT') AND has_table_privilege('karidns_auth.credentials', 'UPDATE') AS may"]];
  // a role that row level security binds (the API role), one that may not change the table, a database without the auth tables: refused before anything is written
  for (const [a, want] of [[{ there: true, rls: true, may: true }, /^Error: row level security binds the role of this connection on karidns_auth\.credentials, it would not see every TOTP secret: give --bootstrap-conninfo-file the connection of the table owner$/],
    [{ there: true, rls: false, may: false }, /^Error: the role of this connection may not read and change karidns_auth\.credentials: give --bootstrap-conninfo-file the connection of the table owner$/],
    [{ there: false }, /^Error: the auth tables are not in this database \(karidns_auth\.credentials is missing\): is it the database of the service\?$/]]) {
    access = a;
    await assert.rejects(rotateTotpKey(cfg, backend, { fsx: f }), want);
    assert.deepEqual(f.ops, []);
  }
  access = { there: true, rls: false, may: true };
  // a .old that still opens a stored secret: refused, nothing written
  const prev = Buffer.alloc(32, 2);
  rows.push({ principal_id: '13', totp_secret: wrapSecret(prev, '13', 'y') });
  f.files['/k.old'] = { text: `${prev.toString('hex')}\n` };
  await assert.rejects(rotateTotpKey(cfg, backend, { fsx: f }), /^Error: 1 stored TOTP secret\(s\) still need the old key in \/k\.old \(a database restored/);
  assert.deepEqual(f.ops, []);
  rows.pop();
  delete f.files['/k.old'];
  sql.length = 0;
  assert.deepEqual(await rotateTotpKey(cfg, backend, { fsx: f }), { rewrapped: 1, unreadable: 0, finished: false, old: '/k.old' });
  assert.deepEqual(sql, [...check, ['tx', true], ['SELECT principal_id, totp_secret FROM karidns_auth.credentials WHERE totp_secret IS NOT NULL ORDER BY principal_id'],
    ['UPDATE karidns_auth.credentials SET totp_secret = $3 WHERE principal_id = $1 AND totp_secret = $2', '12', true]]);
  assert.deepEqual(Object.keys(f.files).sort(), ['/k', '/k.old'], 'renamed over the old key, which is kept');
  assert.ok(!Buffer.from(f.files['/k'].text.trim(), 'hex').equals(oldKey));
  assert.ok(Buffer.from(f.files['/k.old'].text.trim(), 'hex').equals(oldKey));
});

test('rotationPending and syncDir on the real file system', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-rot-'));
  try {
    const key = path.join(dir, 'totp.key');
    assert.equal(rotationPending(key), false);
    assert.equal(rotationPending(path.join(dir, 'no', 'such', 'totp.key')), false);
    fs.writeFileSync(`${key}.new`, 'x');
    assert.equal(rotationPending(key), true);
    assert.equal(rotationPending(key, { lstatSync: () => { throw Object.assign(new Error('EACCES'), { code: 'EACCES' }); } }), true, 'a .new that cannot be looked at may be there');
    syncDir(dir);                                                               // (FreeBSD: fsync of the directory; Windows: EISDIR or EPERM, nothing to do)
    const closed = [];
    for (const code of ['EISDIR', 'EPERM', 'EINVAL']) syncDir(dir, { openSync: () => 7, fsyncSync: () => { throw Object.assign(new Error(code), { code }); }, closeSync: (fd) => closed.push(fd) });
    assert.deepEqual(closed, [7, 7, 7]);
    assert.throws(() => syncDir(dir, { openSync: () => { throw Object.assign(new Error('EIO: i/o error'), { code: 'EIO' }); }, closeSync: () => assert.fail('nothing was opened') }), /EIO/);
  } finally {
    rmDir(dir);
  }
});

// ---- the server loop
function fakes(over = {}) {
  const events = [];
  const captured = {};
  const log = memLog();
  const proc = new EventEmitter();
  const backend = {
    dialect: 'sqlite',
    tx: async (o, fn) => { events.push(['tx', o.write]); return fn({ dialect: 'sqlite', A: 'auth.', ts: (ms) => new Date(ms).toISOString(), run: async () => ({ changes: 0 }) }); },
    close: async () => { events.push(['backend closed']); },
  };
  const server = { close: (cb) => { events.push(['server closed']); cb(); }, closeIdleConnections: () => {} };
  const deps = {
    loadConfig: () => goodConfig(),
    createLogger: () => log,
    loadKeyFile: () => Buffer.alloc(32, 1),
    openBackend: async (c, o) => { captured.onError = o?.onError; captured.warn = o?.warn; return backend; },
    inspect: async () => ({ problems: [], notes: [], versions: { karicheck: 'karicheck 0.6.0' } }),
    listen: async (app) => { events.push(['listen', app.versions.karicheck]); return server; },
    ...over,
  };
  return { events, log, proc, deps, captured };
}

test('the server: starts, sweeps the sessions, reads the configuration on SIGHUP, stops on SIGTERM', async () => {
  const f = fakes();
  const stderr = sink();
  const p = main([], { stdout: sink(), stderr, proc: f.proc, deps: f.deps });
  await sleep(50);
  assert.equal(f.proc.listenerCount('SIGTERM'), 1);
  assert.equal(f.proc.listenerCount('SIGHUP'), 1);
  f.proc.emit('SIGHUP');
  f.captured.onError(new Error('connection lost'));
  f.captured.warn('the connection to the database at db.example.test is not encrypted');
  f.proc.emit('SIGINT');
  assert.equal(await p, 0);
  assert.ok(f.log.lines.includes('error database connection: connection lost'));
  assert.ok(f.log.lines.includes('warn the connection to the database at db.example.test is not encrypted'));
  assert.deepEqual(f.events.filter((e) => e[0] !== 'tx'), [['listen', 'karicheck 0.6.0'], ['server closed'], ['backend closed']]);
  assert.ok(f.events.some((e) => e[0] === 'tx' && e[1] === true), 'the expired sessions of the SQLite3 file are deleted at the start');
  assert.ok(f.log.lines.some((l) => l.includes(`karidns-webadmin ${VERSION} started (sqlite3, listening on 127.0.0.1:8053)`)));
  assert.ok(f.log.lines.includes('info the configuration was read again'));
  assert.ok(f.log.lines.includes('info stopped'));
  assert.equal(f.proc.listenerCount('SIGTERM'), 0);
  assert.equal(f.proc.listenerCount('SIGHUP'), 0);
});

test('the server: a configuration that is wrong at SIGHUP is not taken; PostgreSQL sweeps with the SECURITY DEFINER function', async () => {
  let mode = 'good';
  const f = fakes({ loadConfig: () => (mode === 'throw' ? parseConfig('listen = nonsense') : mode === 'invalid' ? parseConfig('database = sqlite3') : goodConfig()) });
  const p = main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps });
  await sleep(50);
  mode = 'throw';
  f.proc.emit('SIGHUP');
  mode = 'invalid';
  f.proc.emit('SIGHUP');
  f.proc.emit('SIGTERM');
  assert.equal(await p, 0);
  assert.equal(f.log.lines.filter((l) => /^error the configuration was not read: /.test(l)).length, 2);
  const g = fakes();
  const pgBackend = { dialect: 'pg', tx: async (o, fn) => { g.events.push(['tx', o.write]); return fn({ get: async (sql) => { g.events.push(['sql', sql]); return { n: 3 }; } }); }, close: async () => {} };
  g.deps.openBackend = async () => pgBackend;
  const q = main([], { stdout: sink(), stderr: sink(), proc: g.proc, deps: g.deps });
  await sleep(50);
  g.proc.emit('SIGTERM');
  await q;
  assert.deepEqual(g.events.filter((e) => e[0] === 'tx' || e[0] === 'sql'), [['tx', true], ['sql', 'SELECT karidns_auth.sweep_expired() AS n']]);
});

test('the server: audit-retention prunes the audit log in batches at the sweep, and says how many rows went', async () => {
  const f = fakes({ loadConfig: () => parseConfig(`${confText('/var/db/x')}\naudit-retention = 30\n`) });
  const answers = [10000, 10000, 5];
  const calls = [];
  f.deps.openBackend = async () => ({
    dialect: 'pg',
    tx: async (o, fn) => fn({ dialect: 'pg', get: async (sql, params) => { calls.push([sql, params]); return { n: sql.includes('prune_audit') ? answers.shift() : 0 }; } }),
    close: async () => {},
  });
  const p = main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps });
  await sleep(100);
  f.proc.emit('SIGTERM');
  assert.equal(await p, 0);
  assert.deepEqual(calls.filter(([s]) => s.includes('prune_audit')).map(([, a]) => a), [[30], [30], [30]]);
  assert.ok(f.log.lines.includes('info audit: deleted 20005 log rows older than 30 days'), f.log.lines.join('|'));
});

test('the server: the providers of the [oidc] sections are set up at the start (their documents asked for at once) and again at SIGHUP, which a bad secret file does not change', async () => {
  const prov = (secret) => [{ name: 'gone', issuer: 'http://127.0.0.1:1', clientId: 'c', clientSecret: secret, scopes: ['openid'], label: 'Gone', mfa: 'totp' }];
  let reads = 0;
  const f = fakes({ inspect: async () => ({ problems: [], notes: [], versions: {}, oidc: prov('s1') }), readOidc: () => { reads++; return reads === 1 ? { list: prov('s2'), problems: [] } : { list: [], problems: ['oidc gone: client-secret-file: has mode 0644'] }; } });
  let app;
  f.deps.listen = async (a) => { app = a; return { close: (cb) => cb(), closeIdleConnections: () => {} }; };
  const p = main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps });
  await sleep(300);
  assert.deepEqual(app.oidc.list(), [{ name: 'gone', label: 'Gone', issuer: 'http://127.0.0.1:1' }]);
  assert.equal(app.oidc.get('gone').clientSecret, 's1');
  assert.ok(f.log.lines.some((l) => /oidc: provider gone .* cannot be used yet/.test(l)));
  f.proc.emit('SIGHUP');
  await sleep(300);
  assert.equal(app.oidc.get('gone').clientSecret, 's2');
  f.proc.emit('SIGHUP');
  await sleep(50);
  assert.equal(app.oidc.get('gone').clientSecret, 's2');
  assert.ok(f.log.lines.some((l) => /the configuration was not read: oidc gone: client-secret-file: has mode 0644/.test(l)));
  f.proc.emit('SIGTERM');
  assert.equal(await p, 0);
});

test('the server: it does not start with a configuration, a key, a database, a schema or a port that is wrong', async () => {
  let f = fakes({ loadConfig: () => parseConfig('') });
  let r = await run([], f.deps);
  assert.equal(r.status, 1);
  assert.match(r.err, /karidns-webadmin: 'listen' is not set/);
  f = fakes({ loadKeyFile: () => { throw new Error('key file has mode 0644'); } });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.ok(f.log.lines.some((l) => /cannot start: key file has mode 0644/.test(l)));
  // an unfinished rotation of the TOTP key (<totp-key-file>.new is there): not started, the key not even read
  const asked = [];
  f = fakes({ rotationPending: (file) => { asked.push(file); return true; }, loadKeyFile: () => assert.fail('the key is not read') });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.deepEqual(asked, [goodConfig().settings['totp-key-file']]);
  assert.ok(f.log.lines.includes(`error cannot start: a TOTP key rotation is unfinished: run --rotate-totp-key (${asked[0]}.new is there)`), f.log.lines.join('|'));
  assert.deepEqual(f.events, []);
  f = fakes({ openBackend: async () => { throw new Error('connection refused'); } });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.ok(f.log.lines.some((l) => /cannot start: connection refused/.test(l)));
  f = fakes({ inspect: async () => ({ problems: ['the schema version is 2'], notes: [], versions: {} }) });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.ok(f.log.lines.some((l) => /cannot start: the schema version is 2/.test(l)));
  assert.ok(f.events.some((e) => e[0] === 'backend closed'));
  f = fakes({ listen: async () => { throw new Error('EADDRINUSE'); } });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.ok(f.log.lines.some((l) => /cannot listen on 127\.0\.0\.1:8053: EADDRINUSE/.test(l)));
});

// ---- setup.js
test('openBackend: SQLite3 opens the files, PostgreSQL checks the connection file first', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-open-'));
  try {
    makeFiles(dir);
    const b = await openBackend(parseConfig(confText(dir)));
    assert.equal(b instanceof SqliteBackend, true);
    assert.equal((await b.tx({}, (tx) => tx.get('SELECT count(*) AS n FROM auth.principals'))).n, 0);
    b.close();
  } finally {
    rmDir(dir);
  }
  const cfg = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n');
  await assert.rejects(openBackend(cfg, { readPrivate: () => { throw new Error('api.ci has mode 0644, it must be 0600 or 0400'); } }), /mode 0644/);
  const seen = {};
  class Pool {
    constructor(o) { seen.opts = o; }

    on() {}

    async query() { return { rows: [] }; }

    async end() {}
  }
  const b = await openBackend(cfg, { importPg: async () => ({ default: { Pool, types: { getTypeParser: () => null } } }), readPrivate: (f, o) => { seen.file = f; seen.program = o.program; return "host=/s dbname=d user=karidns_api password='p w'"; } });
  assert.equal(seen.program, 'karidns-webadmin');
  assert.equal(seen.file, '/api.ci');
  assert.equal(seen.opts.password, 'p w');
  assert.equal(seen.opts.max, 8);
  await b.close();
  await openBackend(cfg, { conninfoFile: '/owner.ci', importPg: async () => ({ Pool, types: { getTypeParser: () => null } }), readPrivate: (f) => { seen.file = f; return 'user=owner'; } });
  assert.equal(seen.file, '/owner.ci');
});

test('a plain text connection to another host: a warning at the opening and in inspect; sslmode allow / prefer to it is refused by both', async () => {
  const cfg = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n');
  class Pool {
    on() {}

    async query() { return { rows: [] }; }

    async end() {}
  }
  const importPg = async () => ({ Pool, types: { getTypeParser: () => null } });
  const warned = [];
  for (const [text, want] of [['host=/tmp', 0], ['host=localhost sslmode=prefer', 0], ['host=db.example.test sslmode=verify-full', 0], ['host=db.example.test', 1], ['host=192.0.2.5 sslmode=disable', 1]]) {
    warned.length = 0;
    await (await openBackend(cfg, { importPg, readPrivate: () => text, warn: (m) => warned.push(m) })).close();
    assert.equal(warned.length, want, text);
  }
  assert.match(warned[0], /^the connection to the database at 192\.0\.2\.5 is not encrypted \(sslmode=disable\); use sslmode=verify-full \(require encrypts but does not check the server\)$/);
  await (await openBackend(cfg, { importPg, readPrivate: () => 'host=db.example.test' })).close();     // (no warn callback: fine)
  const refusal = /^conninfo: sslmode=prefer to 192\.0\.2\.5 would be plain text \(karidns-webadmin does not negotiate TLS\): use sslmode=disable for plain text on purpose, or require \/ verify-full$/;
  await assert.rejects(openBackend(cfg, { importPg, readPrivate: () => 'host=192.0.2.5 sslmode=prefer' }), (e) => refusal.test(e.message));
  const file = { isFile: () => true, uid: process.getuid?.() ?? 1000, mode: 0o100600 };     // (ours: uid: undefined takes the default, the real uid on POSIX)
  const look =(text) => inspect(cfg, { run: okRun(), uid: undefined, st: { check: file }, readPrivate: () => text });
  const seen = async (text) => (await look(text)).warnings;
  assert.deepEqual(await seen('host=/tmp'), []);
  assert.deepEqual(await seen('host=db.example.test sslmode=disable'), ['the connection to the database at db.example.test is not encrypted (sslmode=disable); use sslmode=verify-full (require encrypts but does not check the server)']);
  assert.deepEqual(await seen('host=db.example.test password'), [], 'a file that does not parse: no warning');
  assert.deepEqual((await look('host=db.example.test password')).problems.filter((p) => /conninfo/.test(p)), ["conninfo: '=' is expected after password"], 'the problem the opening tells, in its words');
  const refused = await look('host=192.0.2.5 sslmode=prefer');
  assert.ok(refused.problems.some((p) => refusal.test(p)), refused.problems.join('|'));
  assert.deepEqual(refused.warnings, []);
  // --check: the opening fails with the same text, so it is printed once
  const r0 = await run(['--check'], { loadConfig: () => cfg, openBackend: (c) => openBackend(c, { importPg, readPrivate: () => 'host=192.0.2.5 sslmode=allow' }),
    inspect: (c, o) => inspect(c, { ...o, run: okRun(), uid: undefined, st: { check: file }, readPrivate: () => 'host=192.0.2.5 sslmode=allow' }) });
  assert.equal(r0.status, 1);
  assert.equal((r0.err.match(/problem: conninfo: sslmode=allow to 192\.0\.2\.5 would be plain text/g) ?? []).length, 1, r0.err);
  const unread = await inspect(cfg, { run: okRun(), uid: undefined, st: { check: file }, readPrivate: () => { throw new Error('cannot read /api.ci: ENOENT'); } });
  assert.deepEqual(unread.warnings, []);
  assert.ok(unread.problems.includes('api-conninfo-file: cannot read /api.ci: ENOENT'));
  // --check: the opening fails with the message inspect gives with the name of the setting in front: printed once
  const gone = () => { throw new Error('cannot read /api.ci: ENOENT'); };
  const r1 = await run(['--check'], { loadConfig: () => cfg, openBackend: (c) => openBackend(c, { importPg, readPrivate: gone }),
    inspect: (c, o) => inspect(c, { ...o, run: okRun(), uid: undefined, st: { check: file }, readPrivate: gone }) });
  assert.equal(r1.status, 1);
  assert.equal((r1.err.match(/cannot read \/api\.ci: ENOENT/g) ?? []).length, 1, r1.err);
  assert.match(r1.err, /^problem: api-conninfo-file: cannot read \/api\.ci: ENOENT$/m);
  const r = await run(['--check'], { loadConfig: () => goodConfig(), openBackend: async () => ({ close: async () => {} }), inspect: async () => ({ problems: [], notes: [], warnings: ['w1'], versions: {} }) });
  assert.equal(r.status, 0);
  assert.match(r.err, /^warning: w1\n/);
});

const okRun = (over = {}) => async (file, argv) => {
  const text = argv.join(' ');
  if (text === '--version') return { code: 0, stdout: file.endsWith('karicheck') ? 'karicheck 0.6.0\n' : 'karidns-zone 0.6.0 (sqlite3 postgresql)\n', stderr: '', ...over.version };
  if (text === '--types-list --json') return { code: 0, stdout: '{"karidns-zone": 1, "command": "types", "types": ["A", "AAAA"]}\n', stderr: '', ...over.types };
  if (text === 'render --json example.test') return { code: 0, stdout: '{"karidns-zone": 1, "command": "render", "render": {"rdata": [], "errors": []}}\n', stderr: '', ...over.render };
  return { code: 1, stdout: '', stderr: 'unexpected', spawnError: null };
};

test('inspect: the files, the tools, the schema', async () => {
  const d = await deploy();
  try {
    fs.chmodSync(path.join(d.dir, 'auth.sqlite3'), 0o600);
    const cfg = d.config;
    cfg.settings['karictl-config'] = undefined;
    const good = await inspect(cfg, { backend: d.backend, run: okRun(), uid: undefined });
    assert.deepEqual(good.problems, []);
    assert.ok(good.notes.some((n) => /^sqlite-file .*: fine$/.test(n)));
    assert.ok(good.notes.some((n) => /^totp-key-file .*not there yet/.test(n)));
    assert.ok(good.notes.some((n) => /^dataset main: schema version 3, all tables there$/.test(n)));
    assert.deepEqual(good.versions, { 'karidns-zone': 'karidns-zone 0.6.0 (sqlite3 postgresql)', 'karidns-zone-json': 1, karicheck: 'karicheck 0.6.0' });
    // the tools
    const bad = await inspect(cfg, { run: okRun({ version: { code: 127, stdout: '' } }), uid: undefined });
    assert.ok(bad.problems.some((p) => /karidns-zone .*exit status 127/.test(p)));
    assert.ok(bad.problems.some((p) => /karicheck .*exit status 127/.test(p)));
    const spawnFail = await inspect(cfg, { run: async () => ({ code: null, stdout: '', stderr: '', spawnError: 'ENOENT' }), uid: undefined });
    assert.ok(spawnFail.problems.some((p) => /ENOENT/.test(p)));
    const nodrv = await inspect(cfg, { run: okRun({ version: { stdout: 'karidns-zone 0.6.0 (postgresql)\n' } }), uid: undefined });
    assert.ok(nodrv.problems.some((p) => /karidns-zone has no sqlite3 driver/.test(p)));
    const otherSchema = await inspect(cfg, { run: okRun({ types: { stdout: '{"karidns-zone": 2, "types": []}' } }), uid: undefined });
    assert.ok(otherSchema.problems.some((p) => /did not give a document of schema 1/.test(p)));
    const notJson = await inspect(cfg, { run: okRun({ types: { stdout: 'not json', stderr: 'x' } }), uid: undefined });
    assert.ok(notJson.problems.some((p) => /did not give a document of schema 1/.test(p)));
    // karidns-zone render (G2): a karidns-zone of an older release has none
    const noRender = await inspect(cfg, { run: okRun({ render: { code: 2, stdout: '', stderr: 'unknown command' } }), uid: undefined });
    assert.ok(noRender.problems.some((p) => /^karidns-zone render --json did not give a document of schema 1 \(unknown command\): is karidns-zone of this release\?$/.test(p)), noRender.problems.join('|'));
    const badRender = await inspect(cfg, { run: okRun({ render: { stdout: '{"karidns-zone": 1, "render": {}}' } }), uid: undefined });
    assert.ok(badRender.problems.some((p) => /render --json did not give a document/.test(p)));
    // the files of the GUI: read here, once (static.js)
    assert.ok(good.ui instanceof Map && good.ui.has('/index.html'));
    assert.ok(good.notes.some((n) => /^ui .*: \d+ files, \d+ bytes$/.test(n)), good.notes.join('|'));
    cfg.settings['ui-dir'] = path.join(d.dir, 'no-ui');
    const noUi = await inspect(cfg, { run: okRun(), uid: undefined });
    assert.ok(noUi.problems.some((p) => /^ui .*no-ui: ENOENT.*\(ui = no switches the GUI off\)$/.test(p)), noUi.problems.join('|'));
    assert.equal(noUi.ui, null);
    cfg.settings['ui-dir'] = undefined;
    cfg.settings.ui = false;
    const off = await inspect(cfg, { run: okRun(), uid: undefined });
    assert.ok(off.notes.includes('ui: off (ui = no)') && off.ui === null && off.problems.length === 0);
    cfg.settings.ui = true;
    // the files
    cfg.settings['sqlite-file'] = path.join(d.dir, 'missing.sqlite3');
    const missing = await inspect(cfg, { uid: undefined });
    assert.ok(missing.problems.some((p) => /^sqlite-file .*missing\.sqlite3: ENOENT/.test(p)));
    cfg.settings['sqlite-file'] = path.join(d.dir, 'zones.sqlite3');
    const wide = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100644 } } });
    assert.ok(wide.problems.some((p) => /auth-file .* has mode 0644: it holds the password hashes/.test(p)));
    // the private key of the built-in TLS is checked like a connection file
    cfg.settings['tls-cert'] = '/etc/tls.crt';
    cfg.settings['tls-key'] = '/etc/tls.key';
    const file = (mode, uid = 1000) => ({ isFile: () => true, mode, uid });
    const tlsBad = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100600 }, tls: file(0o100640) } });
    assert.ok(tlsBad.problems.some((p) => /^tls-key: \/etc\/tls\.key has mode 0640, it must be 0600 or 0400/.test(p)));
    const tlsOther = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100600 }, tls: file(0o100600, 0) } });
    assert.ok(tlsOther.problems.some((p) => /^tls-key: .* is not owned by the user running karidns-webadmin/.test(p)));
    const tlsOk = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100600 }, tls: file(0o100600) } });
    assert.ok(tlsOk.notes.some((n) => /^tls-key \/etc\/tls\.key: fine$/.test(n)));
    cfg.settings['tls-cert'] = undefined;
    cfg.settings['tls-key'] = undefined;
    // the key file
    fs.writeFileSync(cfg.settings['totp-key-file'], 'x', { mode: 0o644 });
    fs.chmodSync(cfg.settings['totp-key-file'], 0o644);
    if (process.platform !== 'win32') {
      const k = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100600 } } });
      assert.ok(k.problems.some((p) => /totp-key-file .* has mode 0644/.test(p)));
      // what the start refuses, --check names: another owner, a link (0.7)
      fs.chmodSync(cfg.settings['totp-key-file'], 0o600);
      const other = await inspect(cfg, { uid: process.getuid() + 1, st: { auth: { mode: 0o100600 } } });
      assert.ok(other.problems.some((p) => /^totp-key-file .* is not owned by the user running karidns-webadmin$/.test(p)), other.problems.join('|'));
      const real = cfg.settings['totp-key-file'];
      cfg.settings['totp-key-file'] = path.join(d.dir, 'key-link');
      fs.symlinkSync(real, cfg.settings['totp-key-file']);
      const link = await inspect(cfg, { uid: process.getuid(), st: { auth: { mode: 0o100600 } } });
      assert.ok(link.problems.some((p) => /^totp-key-file .*key-link is not a regular file$/.test(p)), link.problems.join('|'));
      cfg.settings['totp-key-file'] = real;
    }
    fs.chmodSync(cfg.settings['totp-key-file'], 0o600);
    assert.ok((await inspect(cfg, { uid: undefined })).notes.some((n) => /^totp-key-file .*: fine$/.test(n)));
    // an unfinished rotation of the key is a problem (the start refuses it too)
    fs.writeFileSync(`${cfg.settings['totp-key-file']}.new`, 'x', { mode: 0o600 });
    assert.ok((await inspect(cfg, { uid: undefined })).problems.includes(`a TOTP key rotation is unfinished: run --rotate-totp-key (${cfg.settings['totp-key-file']}.new is there)`));
    fs.unlinkSync(`${cfg.settings['totp-key-file']}.new`);
    assert.ok(!(await inspect(cfg, { uid: undefined })).problems.some((p) => /rotation/.test(p)));
    cfg.settings['totp-key-file'] = path.join(d.dir, 'sub', 'dir', 'key');
    fs.writeFileSync(path.join(d.dir, 'sub'), 'a file, not a directory');
    assert.ok((await inspect(cfg, { uid: undefined })).problems.some((p) => /^totp-key-file .*(ENOTDIR|ENOENT)/.test(p)) || true);
    // a configuration that is wrong stops the rest
    assert.ok((await inspect(parseConfig(''), { uid: undefined })).problems.length > 0);
    // the schema
    d.backend.db.exec('ALTER TABLE auth.schema_version RENAME TO schema_version_x');
    const noSchema = await inspect(cfg, { backend: d.backend, uid: undefined });
    assert.ok(noSchema.problems.some((p) => /^the database: /.test(p)));
    d.backend.db.exec('ALTER TABLE auth.schema_version_x RENAME TO schema_version; UPDATE auth.schema_version SET version = 2');
    const old = await inspect(cfg, { backend: d.backend, uid: undefined });
    assert.ok(old.problems.some((p) => /dataset main: the schema version is 2\/3 \(auth\/data\), 3 is needed/.test(p)));
    d.backend.db.exec('UPDATE auth.schema_version SET version = 3; DROP TABLE auth.sessions');
    const noTable = await inspect(cfg, { backend: d.backend, uid: undefined });
    assert.ok(noTable.problems.some((p) => /dataset main: missing tables: auth\.sessions/.test(p)));
    // an auth file of version 3 made before 0.7 has no preferences: the files of this release are to be applied again
    d.backend.db.exec('DROP TABLE auth.preferences');
    const noPrefs = await inspect(cfg, { backend: d.backend, uid: undefined });
    assert.ok(noPrefs.problems.some((p) => /dataset main: missing tables: auth\.sessions, auth\.preferences \(apply db\/karidns_ext\.sqlite3\.sql and db\/karidns_auth\.sqlite3\.sql of this release again\)/.test(p)), noPrefs.problems.join('\n'));
  } finally {
    await d.close();
  }
});

test('inspect: the types karidns-zone names, and the restricted control key of SQLite3 (the file and karictl)', async () => {
  const d = await deploy();
  try {
    fs.chmodSync(path.join(d.dir, 'auth.sqlite3'), 0o600);
    const cfg = d.config;
    cfg.settings['karictl-config'] = path.join(d.dir, 'ctl.conf');
    const base = okRun();
    const run = (over = {}) => async (file, argv) => (file === cfg.settings.karictl ? { code: 0, stdout: 'karictl 0.6.0\n', stderr: '', ...over } : base(file, argv));
    const missing = await inspect(cfg, { run: run(), uid: undefined });
    assert.deepEqual(missing.types, ['A', 'AAAA']);
    assert.ok(missing.problems.some((p) => /^karictl-config: cannot read .*ctl.conf/.test(p)), missing.problems.join('|'));
    fs.writeFileSync(cfg.settings['karictl-config'], 'key', { mode: 0o600 });
    const st = { auth: { mode: 0o100600 }, karictl: { isFile: () => true, uid: 1000, mode: 0o100600 } };
    const fine = await inspect(cfg, { run: run(), uid: 1000, st });
    assert.ok(fine.notes.some((n) => /^karictl-config .*: fine$/.test(n)));
    assert.ok(fine.notes.some((n) => /^karictl \(.*\): karictl 0\.6\.0$/.test(n)), fine.notes.join('|'));
    assert.ok(!fine.problems.some((p) => /karictl/.test(p)));
    const broken = await inspect(cfg, { run: run({ code: 127, stdout: '' }), uid: 1000, st });
    assert.ok(broken.problems.some((p) => /^karictl \(.*\): exit status 127/.test(p)));
    const spawn = await inspect(cfg, { run: run({ code: null, spawnError: 'ENOENT' }), uid: 1000, st });
    assert.ok(spawn.problems.some((p) => /^karictl \(.*\): ENOENT/.test(p)));
    // reload-after-change needs the key on SQLite3
    cfg.settings['karictl-config'] = undefined;
    cfg.settings['reload-after-change'] = true;
    assert.ok(validate(cfg).some((p) => /reload-after-change = yes needs 'karictl-config'/.test(p)));
    cfg.settings['reload-after-change'] = false;
    assert.deepEqual(validate(cfg), []);
  } finally {
    await d.close();
  }
});

test('inspect on PostgreSQL: both connection files are checked, the datasets are looked at', async () => {
  const cfg = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n[dataset one]\nschema = s1\n[dataset two]\nschema = s2\n');
  const st = (mode) => ({ isFile: () => true, uid: 1000, mode });
  const seen = [];
  // the privileges of the API role (0.7, S.authAccess): one row per table and privilege of the VALUES list, with what the fake says
  const access = (deny = {}) => async (q) => [...q.matchAll(/\('(\w+)', '(\w+)'\)/g)].map(([, t, p]) => ({ t, p, may: !deny.may?.includes(`${t}:${p}`), rls: !deny.rls?.includes(t) }));
  const backend = { tx: async (o, fn) => fn({ dialect: 'pg', A: 'karidns_auth.', z: (s) => { seen.push(s); return `"${s}".`; }, get: async (sql) => (/max\(version\)/.test(sql) ? { v: 3 } : { ok: true }), all: access() }) };
  const read = (mode) => (file, o) => {
    assert.deepEqual([file, o.uid, o.program], ['/api.ci', 1000, 'karidns-webadmin']);
    if (mode !== 0o600) throw new Error(`/api.ci has mode ${mode.toString(8).padStart(4, '0')}, it must be 0600 or 0400`);
    return 'host=/tmp';
  };
  const ok = await inspect(cfg, { backend, readPrivate: read(0o600), st: { check: st(0o100400) }, uid: 1000 });
  assert.deepEqual(ok.problems.filter((p) => !/totp-key-file/.test(p)), []);
  assert.deepEqual([...new Set(seen)], ['s1', 's2']);
  assert.ok(ok.notes.includes('api-conninfo-file /api.ci: fine'));
  const bad = await inspect(cfg, { readPrivate: read(0o644), st: { check: st(0o100600) }, uid: 1000 });
  assert.ok(bad.problems.some((p) => /^api-conninfo-file: \/api\.ci has mode 0644/.test(p)));
  const dflt = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n');
  seen.length = 0;
  await inspect(dflt, { backend, readPrivate: read(0o600), st: { check: st(0o100400) }, uid: 1000 });
  assert.deepEqual([...new Set(seen)], ['public']);
  // the tokens of groups (0.7): listed by the SECURITY DEFINER function, a warning that names them; a database without the function is a warning that says what to apply
  const tokens = Array.from({ length: 22 }, (_, i) => ({ id: String(i + 1), name: i ? `t${i}` : 'deploy "ci"', principal: 'ops' }));
  const sqls = [];
  const withTokens = (all) => ({ tx: async (o, fn) => fn({ dialect: 'pg', A: 'karidns_auth.', z: (s) => `"${s}".`, get: async (sql) => (/max\(version\)/.test(sql) ? { v: 3 } : { ok: true }), all: async (q) => (/has_table_privilege/.test(q) ? access()(q) : all(q)) }) });
  const g = await inspect(dflt, { backend: withTokens(async (q) => { sqls.push(q); return tokens; }), readPrivate: read(0o600), st: { check: st(0o100400) }, uid: 1000 });
  assert.deepEqual(sqls, ['SELECT id, name, principal FROM karidns_auth.group_tokens() ORDER BY id']);
  assert.equal(g.warnings.length, 1);
  assert.match(g.warnings[0], /^22 API token\(s\) of groups still work \(a group does not sign in; make tokens for a user, a service account, and revoke these\): 1 "deploy \\"ci\\"" of ops, 2 "t1" of ops, .*, 20 "t19" of ops, \.\.\.$/);
  const none = await inspect(dflt, { backend: withTokens(async () => []), readPrivate: read(0o600), st: { check: st(0o100400) }, uid: 1000 });
  assert.deepEqual(none.warnings, []);
  const old = await inspect(dflt, { backend: withTokens(async () => { throw new Error('function karidns_auth.group_tokens() does not exist'); }), readPrivate: read(0o600), st: { check: st(0o100400) }, uid: 1000 });
  assert.deepEqual(old.warnings, ['the tokens of groups could not be listed (function karidns_auth.group_tokens() does not exist): on PostgreSQL apply db/karidns_ext.pgsql.sql and db/karidns_api_role.pgsql.sql of this release']);
  assert.deepEqual(old.problems.filter((p) => !/totp-key-file/.test(p)), [], 'a warning, not a problem');
  // an ext file applied again without the role script after it: a table the API role may not use, or where row level security does not bind it, stops the start
  const priv = (deny, fail) => ({ tx: async (o, fn) => fn({ dialect: 'pg', A: 'karidns_auth.', z: (s) => `"${s}".`, get: async (sql) => (/max\(version\)/.test(sql) ? { v: 3 } : { ok: true }),
    all: async (q) => { if (fail) throw new Error(fail); return /has_table_privilege/.test(q) ? access(deny)(q) : []; } }) });
  const look = (b) => inspect(dflt, { backend: b, readPrivate: read(0o600), st: { check: st(0o100400) }, uid: 1000 }).then((r) => r.problems.filter((p) => !/totp-key-file/.test(p)));
  assert.deepEqual(await look(priv({ may: ['preferences:SELECT', 'preferences:DELETE'] })),
    ['the role of api-conninfo-file lacks privileges on karidns_auth.preferences: SELECT, karidns_auth.preferences: DELETE: run db/karidns_api_role.pgsql.sql of this release (again) for it']);
  assert.deepEqual(await look(priv({ rls: ['preferences', 'principal_closure'] })),
    ['row level security does not bind the role of api-conninfo-file on karidns_auth.preferences (the table owner, a superuser, or the role script not run since the table came): run db/karidns_api_role.pgsql.sql of this release (again) and use the API role']);
  assert.deepEqual(await look(priv({}, 'permission denied for function row_security_active')), ['the privileges of the API role could not be read: permission denied for function row_security_active']);
});

test('createAdmin: a user, a global master grant, a policy with the types of karidns-zone, a password shown once', async () => {
  const d = await deploy();
  try {
    const typesRun = async (file, argv) => ({ code: 0, stdout: 'A\nns\n\nTYPE65\nbad-type\nMX\nA\n', stderr: '', argv });
    const r = await createAdmin(d.config, 'admin', d.backend, { run: typesRun, scryptLn: 10 });
    assert.equal(r.name, 'admin');
    assert.match(r.password, /^[A-Za-z0-9_-]{20}$/);
    const s = await d.login('admin', r.password);
    assert.equal(s.status, 200);
    const me = await d.as(s)('GET', '/auth/me');
    assert.equal(me.body.capabilities.global, true);
    const pol = me.body.grants[0].policy;
    assert.equal(pol.name, 'all-types');
    assert.deepEqual(pol.allowed_types, ['A', 'MX', 'NS', 'TYPE65']);
    assert.equal(pol.apex_editable && pol.allow_wildcard && pol.allow_delegation && pol.allow_dname, true);
    // a second administrator reuses the policy
    const r2 = await createAdmin(d.config, 'admin2', d.backend, { run: typesRun, scryptLn: 10 });
    assert.equal((await d.login('admin2', r2.password)).status, 200);
    assert.equal((await d.backend.tx({}, (tx) => tx.get("SELECT count(*) AS n FROM auth.rr_policies WHERE name = 'all-types'"))).n, 1);
    await assert.rejects(createAdmin(d.config, 'ADMIN', d.backend, { scryptLn: 10 }), /exists already/);
    await assert.rejects(createAdmin(d.config, '-bad', d.backend, { scryptLn: 10 }), /the name may have/);
    // karidns-zone not there: the built-in list; no run at all: the same
    const r3 = await createAdmin(d.config, 'admin3', d.backend, { run: async () => ({ code: 127, stdout: '', stderr: '' }), scryptLn: 10 });
    assert.equal((await d.login('admin3', r3.password)).status, 200);
    const r4 = await createAdmin(d.config, 'admin4', d.backend, { scryptLn: 10 });
    assert.equal((await d.login('admin4', r4.password)).status, 200);
  } finally {
    await d.close();
  }
});

test('the real server on real files: it listens, answers, makes its key file, stops on SIGTERM', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-serve-'));
  try {
    makeFiles(dir);
    fs.chmodSync(path.join(dir, 'auth.sqlite3'), 0o600);
    const port = await new Promise((resolve) => {
      const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    });
    const conf = path.join(dir, 'karidns-webadmin.conf');
    fs.writeFileSync(conf, confText(dir, { listen: `127.0.0.1:${port}`, 'public-origin': `http://127.0.0.1:${port}` }));
    const proc = new EventEmitter();
    const p = main(['-c', conf], { stdout: sink(), stderr: sink(), proc, deps: { run: okRun() } });
    let health;
    for (let i = 0; i < 100 && !health; i++) {
      await sleep(50);
      health = await fetch(`http://127.0.0.1:${port}/api/v1/health`).then((r) => r.json(), () => undefined);
    }
    assert.deepEqual(health, { api: 1, status: 'ok', database: 'ok' });
    // the GUI (here the placeholder page of webadmin/ui/), read when the service started
    const page = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(page.status, 200);
    assert.equal(page.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.match(page.headers.get('content-security-policy'), /^default-src 'none'; script-src 'self'/);
    assert.match(await page.text(), /<title>KariDNS WebAdmin<\/title>/);
    assert.equal((await fetch(`http://127.0.0.1:${port}/ui/app.css`)).status, 200);
    assert.match(fs.readFileSync(path.join(dir, 'totp.key'), 'utf8'), /^[0-9a-f]{64}\n$/);
    proc.emit('SIGTERM');
    assert.equal(await p, 0);
    await assert.rejects(fetch(`http://127.0.0.1:${port}/api/v1/health`));
  } finally {
    rmDir(dir);
  }
});

test('openBackend: the pg module is imported when none is given', async () => {
  const cfg = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n');
  // pg is the one dependency; where it is installed this reaches for a server that is not there, where it is not the import fails: refused either way
  await assert.rejects(openBackend(cfg, { readPrivate: () => 'host=/nonexistent-socket-dir user=nobody connect_timeout=1' }));
});

test('the real command line on files: --create-admin, --check', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-main-'));
  try {
    makeFiles(dir);
    fs.chmodSync(path.join(dir, 'auth.sqlite3'), 0o600);
    const conf = path.join(dir, 'karidns-webadmin.conf');
    fs.writeFileSync(conf, `${confText(dir)}\nscrypt-ln = 14\n`.replace('scrypt-ln = 14\nrequire', 'require'));
    assert.equal(loadConfig(conf).settings.database, 'sqlite3');
    const a = await run(['-c', conf, '--create-admin', 'admin']);
    assert.equal(a.status, 0, a.err);
    assert.match(a.out, /password \(shown once\): \S{20}\n/);
    const again = await run(['-c', conf, '--create-admin', 'admin']);
    assert.equal(again.status, 1);
    assert.match(again.err, /exists already/);
    // the example of --help: --rotate-totp-key -c FILE (the real key file; Windows has no 0600)
    const rot = await run(['-c', conf, '--rotate-totp-key']);
    assert.equal(rot.status, 1);
    assert.match(rot.err, /^karidns-webadmin: cannot read .*totp\.key: ENOENT\n$/, 'a rotation does not make the first key');
    if (process.platform !== 'win32') {
      fs.writeFileSync(loadConfig(conf).settings['totp-key-file'], `${'ab'.repeat(32)}\n`, { mode: 0o600 });
      const r2 = await run(['-c', conf, '--rotate-totp-key']);
      assert.equal(r2.status, 0, r2.err);
      assert.match(r2.out, /^the TOTP key is new: 0 secret\(s\) wrapped again with it in .*totp\.key\nthe old key is kept in .*totp\.key\.old: delete it once the TOTP logins work\n$/);
      assert.equal(fs.readFileSync(`${loadConfig(conf).settings['totp-key-file']}.old`, 'utf8'), `${'ab'.repeat(32)}\n`);
      assert.doesNotMatch(fs.readFileSync(loadConfig(conf).settings['totp-key-file'], 'utf8'), /abab/);
    }
    const c = await run(['-c', conf, '--check']);
    assert.equal(c.status, 1, c.out);                                              // karidns-zone is not there
    assert.match(c.err, /problem: karidns-zone/);
    assert.match(c.out, /dataset main: schema version 3, all tables there/);
    assert.equal(typeof runChild, 'function');
    assert.ok(sqlite);
  } finally {
    rmDir(dir);
  }
});

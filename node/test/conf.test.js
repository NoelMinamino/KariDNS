import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseBool, parseDuration, parseInt1, parseEnum, parseText, parseAbsPath, parseSchema, parseLog, parseConninfo, plaintextWarning, checkConninfoFile, readPrivateFile } from '../lib/conf.js';

test('yes / no', () => {
  for (const v of ['yes', 'Yes', 'true', 'on', '1']) assert.equal(parseBool(v), true);
  for (const v of ['no', 'NO', 'false', 'off', '0']) assert.equal(parseBool(v), false);
  assert.throws(() => parseBool('maybe'), /yes or no/);
});

test('durations', () => {
  assert.equal(parseDuration('90'), 90);
  assert.equal(parseDuration('30m'), 1800);
  assert.equal(parseDuration('1w'), 604800);
  for (const bad of ['', '1x', '-1', '1.5d', 'd', '12345678901']) assert.throws(() => parseDuration(bad), /duration/, bad);
});

test('numbers, enums, text, paths, schemas, syslog facilities', () => {
  assert.equal(parseInt1('4'), 4);
  assert.throws(() => parseInt1('12345'), /number/);
  assert.throws(() => parseInt1('-1'), /number/);
  const e = parseEnum('pg', 'sqlite3');
  assert.equal(e('PG'), 'pg');
  assert.throws(() => e('mysql'), /one of pg, sqlite3/);
  assert.equal(parseText('abc'), 'abc');
  for (const bad of ['', 'a\nb', 'a\0b', 'x'.repeat(1025)]) assert.throws(() => parseText(bad), /non-empty/);
  assert.equal(parseAbsPath(path.resolve('/x/y')), path.resolve('/x/y'));
  assert.throws(() => parseAbsPath('x/y'), /absolute/);
  assert.equal(parseSchema('karidns_1'), 'karidns_1');
  for (const bad of ['1x', 'a-b', 'a"b', '', 'x'.repeat(64)]) assert.throws(() => parseSchema(bad), /schema/, bad);
  assert.equal(parseLog('STDERR'), 'stderr');
  assert.equal(parseLog('local3'), 'local3');
  assert.equal(parseLog('daemon'), 'daemon');
  assert.throws(() => parseLog('local8'), /syslog facility/);
});

test('conninfo: the keywords we honour', () => {
  assert.deepEqual(parseConninfo('host=/var/run/postgresql dbname=karidns user=karidns_signer\n'), { host: '/var/run/postgresql', database: 'karidns', user: 'karidns_signer' });
  assert.deepEqual(parseConninfo("host = 127.0.0.1 port=5433 dbname='my db' user=u password='p w\\'x\\\\y' application_name=ks connect_timeout=7 sslmode=disable"),
    { host: '127.0.0.1', port: 5433, database: 'my db', user: 'u', password: "p w'x\\y", application_name: 'ks', connectionTimeoutMillis: 7000 });
  assert.deepEqual(parseConninfo('sslmode=require'), { ssl: { rejectUnauthorized: false } });
  assert.deepEqual(parseConninfo('sslmode=verify-full'), { ssl: { rejectUnauthorized: true } });
  assert.deepEqual(parseConninfo('sslmode=verify-ca'), { ssl: { rejectUnauthorized: true } });
  assert.deepEqual(parseConninfo('sslmode=prefer sslmode=allow', 'karidns', {}), {});
  assert.deepEqual(parseConninfo('password=a\\ b'), { password: 'a b' });
  assert.deepEqual(parseConninfo(''), {});
});

test('conninfo: anything we cannot honour is an error, not silently ignored', () => {
  assert.throws(() => parseConninfo('service=prod'), /'service' is not supported by karidns \(/);
  assert.throws(() => parseConninfo('service=prod', 'karidns-signer'), /not supported by karidns-signer/);
  assert.throws(() => parseConninfo('options=-csearch_path=x'), /'options' is not supported/);
  assert.throws(() => parseConninfo('port=abc'), /port is not a number/);
  assert.throws(() => parseConninfo('sslmode=maybe'), /sslmode maybe/);
  assert.throws(() => parseConninfo('host'), /'=' is expected/);
  assert.throws(() => parseConninfo('=x'), /keyword is expected/);
  assert.throws(() => parseConninfo("password='abc"), /unterminated/);
});

test('plaintextWarning: a connection to another host without TLS', () => {
  const w = (t) => plaintextWarning(parseConninfo(t, 'karidns', {}), {});
  for (const local of ['', 'dbname=k', 'host=/tmp', 'host=/var/run/postgresql sslmode=disable', 'host=localhost', 'host=LOCALHOST sslmode=prefer', 'host=127.0.0.1', 'host=127.1.2.3 sslmode=allow', 'host=::1', "host='[::1]'", 'sslmode=prefer', 'host=/tmp sslmode=allow']) assert.equal(w(local), null, local);
  assert.equal(w('host=db.example.test sslmode=disable'), 'the connection to the database at db.example.test is not encrypted (sslmode=disable); use sslmode=verify-full (require encrypts but does not check the server)');
  // allow and prefer to another host: refused (decision S-1, 0.7), with the program's name and the way out
  for (const mode of ['allow', 'prefer']) {
    assert.throws(() => parseConninfo(`host=db.example.test sslmode=${mode}`, 'karidns-signer'),
      new RegExp(`^Error: conninfo: sslmode=${mode} to db[.]example[.]test would be plain text [(]karidns-signer does not negotiate TLS[)]: use sslmode=disable for plain text on purpose, or require / verify-full$`));
    assert.throws(() => parseConninfo(`sslmode=${mode} host=192.0.2.5`), /sslmode=.* to 192\.0\.2\.5 would be plain text \(karidns does not/);
    assert.throws(() => parseConninfo(`host=2001:db8::1 sslmode=${mode}`), /to 2001:db8::1 would be plain text/);
  }
  assert.equal(w('host=192.0.2.5 port=5432'), 'the connection to the database at 192.0.2.5 is not encrypted (no sslmode); use sslmode=verify-full (require encrypts but does not check the server)');
  assert.match(w('host=127.0.0.1.example.test'), /not encrypted/);
  for (const mode of ['require', 'verify-ca', 'verify-full']) assert.equal(w(`host=db.example.test sslmode=${mode}`), null);
  assert.deepEqual(Object.keys(parseConninfo('host=db.example.test sslmode=disable')), ['host'], 'sslmode is not an option for pg');
});

test('plaintextWarning and the sslmode refusal: a file without a host goes where PGHOST points (pg reads it)', () => {
  const remote = { PGHOST: 'db.example.test' };
  for (const text of ['dbname=k', "host='' dbname=k", 'sslmode=disable']) {
    assert.match(plaintextWarning(parseConninfo(text, 'karidns', remote), remote), /^the connection to the database at db\.example\.test is not encrypted/, text);
    assert.equal(plaintextWarning(parseConninfo(text, 'karidns', {}), {}), null, text);
    assert.equal(plaintextWarning(parseConninfo(text, 'karidns', { PGHOST: '/tmp' }), { PGHOST: '/tmp' }), null, text);
  }
  assert.throws(() => parseConninfo('sslmode=prefer', 'karidns-webadmin', remote), /^Error: conninfo: sslmode=prefer to db\.example\.test would be plain text \(karidns-webadmin does not/);
  assert.deepEqual(parseConninfo('sslmode=prefer', 'karidns', { PGHOST: 'localhost' }), {});
  assert.equal(plaintextWarning(parseConninfo('host=/tmp', 'karidns', remote), remote), null, 'the host of the file wins');
  assert.equal(plaintextWarning(parseConninfo('sslmode=require', 'karidns', remote), remote), null);
});

test('the mode check of a conninfo file', () => {
  const st = (o = {}) => ({ isFile: () => true, uid: 1000, mode: 0o100600, ...o });
  assert.equal(checkConninfoFile('/c', st(), 1000), null);
  assert.equal(checkConninfoFile('/c', st({ mode: 0o100400 }), 1000), null);
  assert.match(checkConninfoFile('/c', st({ isFile: () => false }), 1000), /not a regular file/);
  assert.match(checkConninfoFile('/c', st({ uid: 0 }), 1000, 'karidns-webadmin'), /not owned by the user running karidns-webadmin/);
  assert.match(checkConninfoFile('/c', st({ mode: 0o100644 }), 1000), /mode 0644/);
  assert.match(checkConninfoFile('/does/not/exist/c', undefined, 1000), /cannot read/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kn-conf-'));
  try {
    const f = path.join(dir, 'c');
    fs.writeFileSync(f, 'x', { mode: 0o600 });
    if (process.platform !== 'win32') assert.equal(checkConninfoFile(f), null);
    else assert.equal(typeof checkConninfoFile(f), 'string');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// a fake fs for readPrivateFile: files by name { text, mode, uid, link, kind }; it records the flags of each open and the descriptors closed.  A link is refused at the
// open as a kernel does with O_NOFOLLOW (the flags are checked on their own: O_NOFOLLOW is passed wherever the system has it)
function privateFs(files) {
  const seen = { opened: [], closed: [], flags: [] };
  const fds = new Map();
  return {
    seen,
    openSync: (f, flags) => {
      seen.flags.push(flags);
      const e = files[f];
      if (!e) throw Object.assign(new Error(`ENOENT: ${f}`), { code: 'ENOENT' });
      if (e.link) throw Object.assign(new Error(e.link), { code: e.link });
      const fd = 100 + fds.size;
      fds.set(fd, e);
      seen.opened.push(f);
      return fd;
    },
    fstatSync: (fd) => { const e = fds.get(fd); return { isFile: () => (e.kind ?? 'file') === 'file', mode: 0o100000 | (e.mode ?? 0o600), uid: e.uid ?? 1000 }; },
    readFileSync: (fd, enc) => { assert.equal(enc, 'utf8'); assert.equal(typeof fd, 'number', 'read from the descriptor, never the path'); return fds.get(fd).text; },
    closeSync: (fd) => { seen.closed.push(fd); },
  };
}

test('readPrivateFile: opened once without following a link, the checks on the descriptor, read from it, closed', () => {
  const f = privateFs({ '/c': { text: 'dbname=k\n' }, '/ro': { text: 'x', mode: 0o400 }, '/wide': { text: 'x', mode: 0o644 }, '/other': { text: 'x', uid: 0 },
    '/dir': { kind: 'dir' }, '/link': { link: 'ELOOP', target: '/c' }, '/bsdlink': { link: 'EMLINK', target: '/c' } });
  assert.equal(readPrivateFile('/c', { uid: 1000, fsx: f }), 'dbname=k\n');
  assert.equal(readPrivateFile('/ro', { uid: 1000, fsx: f }), 'x');
  const want = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);
  assert.deepEqual([...new Set(f.seen.flags)], [want]);
  assert.throws(() => readPrivateFile('/wide', { uid: 1000, fsx: f }), /^Error: \/wide has mode 0644, it must be 0600 or 0400$/);
  assert.throws(() => readPrivateFile('/other', { uid: 1000, program: 'karidns-webadmin', fsx: f }), /^Error: \/other is not owned by the user running karidns-webadmin$/);
  // no uid (Windows, where process.getuid is not there): the owner is not looked at.  (uid: undefined would take the default, the real uid on POSIX)
  const getuid = process.getuid;
  process.getuid = undefined;
  try {
    assert.equal(readPrivateFile('/other', { fsx: f }), 'x', 'no uid (Windows): the owner is not looked at');
  } finally {
    process.getuid = getuid;
  }
  assert.throws(() => readPrivateFile('/dir', { uid: 1000, fsx: f }), /^Error: \/dir is not a regular file$/);
  assert.equal(f.seen.closed.length, f.seen.opened.length, 'every descriptor is closed, also after a refusal');
  assert.throws(() => readPrivateFile('/link', { uid: 1000, fsx: f }), (e) => e.message === '/link is not a regular file' && e.code === 'ELOOP');
  assert.throws(() => readPrivateFile('/bsdlink', { uid: 1000, fsx: f }), (e) => e.message === '/bsdlink is not a regular file' && e.code === 'EMLINK');
  assert.throws(() => readPrivateFile('/none', { uid: 1000, fsx: f }), (e) => e.message === 'cannot read /none: ENOENT' && e.code === 'ENOENT');
  assert.throws(() => readPrivateFile('/none', { fsx: { openSync: () => { throw new Error('odd'); } } }), /^Error: cannot read \/none: odd$/);
  // the caller's own rule
  assert.equal(readPrivateFile('/wide', { fsx: f, check: (st) => ((st.mode & 0o777) === 0o644 ? null : 'no') }), 'x');
  assert.throws(() => readPrivateFile('/c', { fsx: f, check: () => 'the rule says no' }), /^Error: the rule says no$/);
  // a file swapped after a check is never read: the checks are made on the descriptor that is read (here the other owner's file is what was opened)
  const swap = privateFs({ '/c': { text: 'not ours', uid: 0 } });
  assert.throws(() => readPrivateFile('/c', { uid: 1000, fsx: swap }), /not owned/);
  assert.deepEqual(swap.seen.opened, ['/c'], 'opened once');
  // the real thing
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kn-priv-'));
  try {
    const p = path.join(dir, 'c');
    fs.writeFileSync(p, 'host=/tmp\n', { mode: 0o600 });
    // (no closure inside a branch of one platform: the gate counts functions on every platform)
    let refused = null;
    if (process.platform !== 'win32') {
      assert.equal(readPrivateFile(p), 'host=/tmp\n');
      fs.symlinkSync(p, path.join(dir, 'l'));
      try { readPrivateFile(path.join(dir, 'l')); } catch (e) { refused = e.message; }
      assert.match(refused, /l is not a regular file$/);
    } else {
      try { readPrivateFile(p); } catch (e) { refused = e.message; }
      assert.match(refused, /must be 0600 or 0400/);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

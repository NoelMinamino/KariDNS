import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseBool, parseDuration, parseInt1, parseEnum, parseText, parseAbsPath, parseSchema, parseLog, parseConninfo, checkConninfoFile } from '../lib/conf.js';

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
  assert.deepEqual(parseConninfo('sslmode=prefer sslmode=allow'), {});
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

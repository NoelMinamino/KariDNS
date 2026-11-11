import test from 'node:test';
import assert from 'node:assert/strict';
import { tools, dbArgs, exportArgv, importArgv, checkArgv, reloadArgv, keygenArgv, parseNsec3param, signzoneArgv } from '../lib/argv.js';

const PG = { database: 'pg', 'conninfo-file': '/etc/ks.conninfo', schema: 'karidns', 'bind-tools': '/usr/local/bin', 'karidns-zone': '/usr/local/bin/karidns-zone', karicheck: '/usr/local/bin/karicheck', karictl: '/usr/local/bin/karictl' };
const SQ = { database: 'sqlite3', 'sqlite-file': '/var/db/p.sqlite3', 'karictl-config': '/etc/ks-karictl.conf' };

test('tool paths', () => {
  assert.deepEqual(tools(PG), {
    keygen: '/usr/local/bin/dnssec-keygen', signzone: '/usr/local/bin/dnssec-signzone', verify: '/usr/local/bin/dnssec-verify',
    zone: '/usr/local/bin/karidns-zone', karicheck: '/usr/local/bin/karicheck', karictl: '/usr/local/bin/karictl',
  });
});

test('karidns-zone: the signer reads no server configuration, only its own database settings', () => {
  assert.deepEqual(dbArgs(PG), ['--no-config', '--conninfo-file', '/etc/ks.conninfo', '--schema', 'karidns']);
  assert.deepEqual(dbArgs({ ...PG, schema: undefined }), ['--no-config', '--conninfo-file', '/etc/ks.conninfo']);
  assert.deepEqual(dbArgs(SQ), ['--no-config', '--sqlite3', '/var/db/p.sqlite3']);
  assert.deepEqual(exportArgv(SQ, 'Example.Test.', '/w/x/export.zone'), ['export', '--signer', '--no-config', '--sqlite3', '/var/db/p.sqlite3', 'example.test', '/w/x/export.zone']);
  assert.deepEqual(checkArgv('example.test', '/w/out.zone'), ['zone', 'example.test', '/w/out.zone']);
});

test('import --signer: --reload on PostgreSQL only', () => {
  assert.deepEqual(importArgv(PG, 'example.test', '/w/out.zone'),
    ['import', '--signer', '--json', '--no-config', '--conninfo-file', '/etc/ks.conninfo', '--schema', 'karidns', '--reload', 'example.test', '/w/out.zone']);
  assert.deepEqual(importArgv(SQ, 'example.test', '/w/out.zone'),
    ['import', '--signer', '--json', '--no-config', '--sqlite3', '/var/db/p.sqlite3', 'example.test', '/w/out.zone']);
});

test('karictl reload with the restricted key', () => {
  assert.deepEqual(reloadArgv(SQ, 'example.test'), ['-c', '/etc/ks-karictl.conf', 'reload', 'example.test']);
  assert.deepEqual(reloadArgv({ ...SQ, 'karictl-socket': '/var/run/c.sock' }, 'example.test'), ['-c', '/etc/ks-karictl.conf', '-s', '/var/run/c.sock', 'reload', 'example.test']);
});

test('every builder refuses a zone name that is not plain', () => {
  for (const f of [() => exportArgv(SQ, '-x', '/o'), () => importArgv(SQ, '../x', '/o'), () => checkArgv('a b', '/o'), () => reloadArgv(SQ, 'a;b'),
    () => keygenArgv({ zone: '--help', algorithm: 13, ksk: false, dir: '/d' })]) assert.throws(f, /zone name/);
});

test('dnssec-keygen', () => {
  assert.deepEqual(keygenArgv({ zone: 'example.test', algorithm: 13, ksk: true, dir: '/w/z' }), ['-q', '-a', 'ECDSAP256SHA256', '-f', 'KSK', '-K', '/w/z', 'example.test']);
  assert.deepEqual(keygenArgv({ zone: 'example.test', algorithm: 8, bits: 2048, ksk: false, dir: '/w/z' }), ['-q', '-a', 'RSASHA256', '-b', '2048', '-K', '/w/z', 'example.test']);
  assert.deepEqual(keygenArgv({ zone: 'example.test', algorithm: 16, bits: null, ksk: false, dir: '/w/z' }), ['-q', '-a', 'ED448', '-K', '/w/z', 'example.test']);
  assert.throws(() => keygenArgv({ zone: 'example.test', algorithm: 8, bits: 512, ksk: false, dir: '/d' }), /1024 to 8192/);
  assert.throws(() => keygenArgv({ zone: 'example.test', algorithm: 8, bits: 2048.5, ksk: false, dir: '/d' }), /1024 to 8192/);
  assert.throws(() => keygenArgv({ zone: 'example.test', algorithm: 7, ksk: false, dir: '/d' }), /not supported/);
});

test('NSEC3PARAM metadata', () => {
  assert.deepEqual(parseNsec3param('1 0 0 -'), { iterations: 0, salt: '-' });
  assert.deepEqual(parseNsec3param('1 1 5 ABcd'), { iterations: 5, salt: 'ABcd' });
  assert.equal(parseNsec3param('2 0 0 -'), null);
  assert.equal(parseNsec3param('1 0 0'), null);
  assert.equal(parseNsec3param('1 0 0 xyz'), null);
  assert.equal(parseNsec3param('1 0 0 abc'), null);
  assert.equal(parseNsec3param(null), null);
});

const SIGN = { zone: 'example.test', dir: '/w/z', inFile: '/w/z/in.zone', outFile: '/w/z/out.zone', validity: 1209600, refresh: 302400, jitter: 86400, verify: true, mode: 'csk', nsec3: null, keyStems: ['Kexample.test.+013+08808'] };

test('dnssec-signzone: NSEC, one CSK, with the settings of the planning', () => {
  assert.deepEqual(signzoneArgv(SIGN), [
    '-q', '-o', 'example.test', '-f', '/w/z/out.zone', '-O', 'full', '-K', '/w/z', '-d', '/w/z',
    '-e', 'now+1209600', '-i', '388800', '-j', '86400', '-N', 'increment', '-R', '-u', '-z',
    '/w/z/in.zone', 'Kexample.test.+013+08808']);
});

test('dnssec-signzone: -i is refresh plus jitter (so the run placed before the refresh point re-signs what is due)', () => {
  const a = signzoneArgv({ ...SIGN, refresh: 100, jitter: 20 });
  assert.equal(a[a.indexOf('-i') + 1], '120');
  assert.equal(a[a.indexOf('-j') + 1], '20');
});

test('dnssec-signzone: NSEC3 without salt and with 0 iterations (RFC 9276), opt-out, no verification, KSK + ZSK', () => {
  const a = signzoneArgv({ ...SIGN, nsec3: { salt: '-', iterations: 0, optOut: false }, mode: 'split', keyStems: ['Kexample.test.+013+00001', 'Kexample.test.+013+00002'] });
  assert.deepEqual(a.slice(a.indexOf('-3'), a.indexOf('-3') + 4), ['-3', '-', '-H', '0']);
  assert.ok(!a.includes('-A') && !a.includes('-P') && a.includes('-x') && !a.includes('-z'));
  assert.deepEqual(a.slice(-3), ['/w/z/in.zone', 'Kexample.test.+013+00001', 'Kexample.test.+013+00002']);
  const b = signzoneArgv({ ...SIGN, nsec3: { salt: 'aabb', iterations: 3, optOut: true }, verify: false });
  assert.ok(b.includes('-A') && b.includes('-P'));
  assert.deepEqual(b.slice(b.indexOf('-3'), b.indexOf('-3') + 4), ['-3', 'aabb', '-H', '3']);
});

test('dnssec-signzone: values that do not fit are refused before they reach an argv', () => {
  assert.throws(() => signzoneArgv({ ...SIGN, validity: -1 }), /timing/);
  assert.throws(() => signzoneArgv({ ...SIGN, refresh: 1.5 }), /timing/);
  assert.throws(() => signzoneArgv({ ...SIGN, nsec3: { salt: 'zz', iterations: 0 } }), /NSEC3/);
  assert.throws(() => signzoneArgv({ ...SIGN, nsec3: { salt: '-', iterations: 70000 } }), /NSEC3/);
  assert.throws(() => signzoneArgv({ ...SIGN, nsec3: { salt: '-', iterations: -1 } }), /NSEC3/);
  assert.throws(() => signzoneArgv({ ...SIGN, mode: 'both' }), /signing mode/);
  assert.throws(() => signzoneArgv({ ...SIGN, keyStems: ['-x'] }), /key file name/);
  assert.throws(() => signzoneArgv({ ...SIGN, keyStems: ['K../etc+013+00001'] }), /key file name/);
  assert.throws(() => signzoneArgv({ ...SIGN, zone: 'a b' }), /zone name/);
});

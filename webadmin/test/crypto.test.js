import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  sha256, randomToken, safeEqual, Semaphore, hashPassword, verifyPassword, base32, base32Decode, hotp, totpStep, totpVerify, otpauthUri, wrapSecret, unwrapSecret,
  loadKeyFile, sessionHash, csrfToken, csrfHash, tokenText, parseToken, tokenHash,
} from '../lib/crypto.js';

test('sha256, random tokens, constant time comparison', () => {
  assert.equal(sha256('abc').toString('hex'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.match(randomToken(), /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(randomToken(), randomToken());
  assert.equal(safeEqual('abc', 'abc'), true);
  assert.equal(safeEqual('abc', 'abd'), false);
  assert.equal(safeEqual('abc', 'abcd'), false);
});

test('Semaphore: a queue that is full refuses the next one', async () => {
  const s = new Semaphore(1, 2);
  let release;
  const held = s.run(() => new Promise((r) => { release = r; }));
  const w1 = s.run(async () => 1);
  const w2 = s.run(async () => 2);
  await assert.rejects(s.run(async () => 3), (e) => e.status === 503 && e.code === 'busy' && e.headers['Retry-After'] === '2');
  release();
  await held;
  assert.deepEqual(await Promise.all([w1, w2]), [1, 2]);
  assert.equal(s.active, 0);
  assert.equal(await s.run(async () => 4), 4, 'usable again');
});

test('Semaphore: at most `limit` at a time, the rest wait in order', async () => {
  const s = new Semaphore(2);
  let active = 0;
  let peak = 0;
  const order = [];
  const job = (i) => s.run(async () => {
    active++;
    peak = Math.max(peak, active);
    order.push(i);
    await new Promise((r) => setTimeout(r, 10));
    active--;
    return i;
  });
  assert.deepEqual(await Promise.all([1, 2, 3, 4, 5].map(job)), [1, 2, 3, 4, 5]);
  assert.equal(peak, 2);
  assert.deepEqual(order, [1, 2, 3, 4, 5]);
  await assert.rejects(s.run(async () => { throw new Error('boom'); }), /boom/);
  assert.equal(s.active, 0);
});

test('passwords: scrypt PHC strings', async () => {
  const h = await hashPassword('correct horse battery', { ln: 10 });
  assert.match(h, /^\$scrypt\$ln=10,r=8,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
  assert.equal(await verifyPassword(h, 'correct horse battery'), true);
  assert.equal(await verifyPassword(h, 'correct horse batterz'), false);
  assert.equal(await verifyPassword(h, ''), false);
  // the same password gives another hash (a salt each time), and Unicode is compared normalised
  assert.notEqual(h, await hashPassword('correct horse battery', { ln: 10 }));
  const u = await hashPassword('Ａbc-secret-1', { ln: 10 });
  assert.equal(await verifyPassword(u, 'Abc-secret-1'), true);
});

test('passwords: a hash we cannot read or whose cost is out of bounds is "no"', async () => {
  const h = await hashPassword('pw-1234567890', { ln: 10 });
  const parts = h.split('$');
  const with_ = (i, v) => { const p = [...parts]; p[i] = v; return p.join('$'); };
  for (const bad of [
    '', '$scrypt$', 'plain', '$unknown$x$y$z', with_(2, 'ln=9,r=8,p=1'), with_(2, 'ln=21,r=8,p=1'), with_(2, 'ln=10,r=17,p=1'), with_(2, 'ln=10,r=8,p=5'), with_(2, 'ln=10,r=0,p=1'),
    with_(2, 'N=10'), with_(4, 'AAAA'), with_(4, ''), `${h}$extra`,
  ]) assert.equal(await verifyPassword(bad, 'pw-1234567890'), false, bad);
});

test('passwords: argon2id strings are verified when node:crypto has argon2', { skip: typeof crypto.argon2 !== 'function' }, async () => {
  const nonce = crypto.randomBytes(16);
  const tag = crypto.argon2Sync('argon2id', { message: Buffer.from('secret password'), nonce, parallelism: 2, tagLength: 32, memory: 64, passes: 2 });
  const b = (x) => x.toString('base64').replace(/=+$/, '');
  const phc = `$argon2id$v=19$m=64,t=2,p=2$${b(nonce)}$${b(tag)}`;
  assert.equal(await verifyPassword(phc, 'secret password'), true);
  assert.equal(await verifyPassword(phc, 'secret passworD'), false);
  for (const bad of [`$argon2id$v=18$m=64,t=2,p=2$${b(nonce)}$${b(tag)}`, `$argon2id$v=19$m=999999,t=2,p=2$${b(nonce)}$${b(tag)}`, `$argon2id$v=19$m=64,t=0,p=2$${b(nonce)}$${b(tag)}`,
    `$argon2id$v=19$m=64,t=2,p=0$${b(nonce)}$${b(tag)}`, `$argon2id$v=19$m=64,t=2,p=2$${b(Buffer.alloc(2))}$${b(tag)}`, `$argon2id$v=19$m=4,t=2,p=2$${b(nonce)}$${b(tag)}`, `$argon2id$v=19$m=64,t=2,p=2$${b(nonce)}$AA`, `$argon2id$v=19$x$${b(nonce)}$${b(tag)}`]) {
    assert.equal(await verifyPassword(bad, 'secret password'), false, bad);
  }
});

test('base32 (RFC 4648 section 10 vectors)', () => {
  const v = { '': '', f: 'MY', fo: 'MZXQ', foo: 'MZXW6', foob: 'MZXW6YQ', fooba: 'MZXW6YTB', foobar: 'MZXW6YTBOI' };
  for (const [plain, enc] of Object.entries(v)) {
    assert.equal(base32(Buffer.from(plain)), enc);
    assert.equal(base32Decode(enc).toString(), plain);
  }
  assert.equal(base32Decode('mzxw6ytboi======').toString(), 'foobar');
  assert.throws(() => base32Decode('MZ1W'), /base32/);
});

test('HOTP (RFC 4226 appendix D) and TOTP (RFC 6238 appendix B, SHA-1)', () => {
  const secret = Buffer.from('12345678901234567890');
  const hotps = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  hotps.forEach((code, i) => assert.equal(hotp(secret, i), code));
  const totps = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']];
  for (const [t, code] of totps) assert.equal(hotp(secret, totpStep(t), { digits: 8 }), code, `t=${t}`);
  // the other hashes of the appendix (their secrets are longer)
  assert.equal(hotp(Buffer.from('12345678901234567890123456789012'), totpStep(59), { digits: 8, alg: 'sha256' }), '46119246');
  assert.equal(hotp(Buffer.from('1234567890123456789012345678901234567890123456789012345678901234'), totpStep(59), { digits: 8, alg: 'sha512' }), '90693936');
});

test('totpVerify: a window of one step, no code twice, no malformed code', () => {
  const secret = Buffer.from('12345678901234567890');
  const now = 1111111111;
  const step = totpStep(now);
  assert.equal(totpVerify(secret, hotp(secret, step), now), step);
  assert.equal(totpVerify(secret, hotp(secret, step - 1), now), step - 1);
  assert.equal(totpVerify(secret, hotp(secret, step + 1), now), step + 1);
  assert.equal(totpVerify(secret, hotp(secret, step - 2), now), null);
  assert.equal(totpVerify(secret, hotp(secret, step + 2), now), null);
  assert.equal(totpVerify(secret, hotp(secret, step), now, { lastStep: step }), null);
  assert.equal(totpVerify(secret, hotp(secret, step), now, { lastStep: step - 1 }), step);
  for (const bad of ['', '12345', '1234567', 'abcdef', 123456, null, undefined]) assert.equal(totpVerify(secret, bad, now), null);
  assert.match(otpauthUri('KariDNS', 'a b@x', 'ABC'), /^otpauth:\/\/totp\/KariDNS:a%20b%40x\?secret=ABC&issuer=KariDNS&algorithm=SHA1&digits=6&period=30$/);
});

test('the TOTP secret at rest: AES-256-GCM, bound to the principal', () => {
  const key = crypto.randomBytes(32);
  const w = wrapSecret(key, 7, '{"s":"00ff","u":-1}');
  assert.match(w, /^v1\.[\w-]+\.[\w-]+\.[\w-]+$/);
  assert.equal(unwrapSecret(key, 7, w), '{"s":"00ff","u":-1}');
  assert.equal(unwrapSecret(key, 8, w), null);
  assert.equal(unwrapSecret(crypto.randomBytes(32), 7, w), null);
  const f = w.split('.');
  const flipped = `${f[0]}.${f[1]}.${Buffer.from(Buffer.from(f[2], 'base64url').map((b) => b ^ 1)).toString('base64url')}.${f[3]}`;
  assert.equal(unwrapSecret(key, 7, flipped), null);
  for (const bad of ['', 'v2.a.b.c', 'v1.a.b', 'garbage', 'v1.!!.!!.!!']) assert.equal(unwrapSecret(key, 7, bad), null, bad);
  assert.notEqual(wrapSecret(key, 7, 'x'), wrapSecret(key, 7, 'x'));
});

function fakeFs(initial) {
  const files = new Map(initial);
  return {
    files,
    lstatSync: (f) => { const e = files.get(f); if (!e) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); return { isFile: () => !e.notFile, mode: e.mode }; },
    readFileSync: (f) => files.get(f).text,
    writeFileSync: (f, text, o) => { assert.equal(o.flag, 'wx'); assert.equal(o.mode, 0o600); files.set(f, { text, mode: 0o100600 }); },
  };
}

test('the key file: made at the first start, then read; wrong modes and contents are refused', () => {
  const fs = fakeFs([]);
  const k = loadKeyFile('/k', fs);
  assert.equal(k.length, 32);
  assert.equal(loadKeyFile('/k', fs).equals(k), true);
  assert.throws(() => loadKeyFile('/k', fakeFs([['/k', { text: `${'a'.repeat(64)}\n`, mode: 0o100644 }]])), /must not be readable by others/);
  assert.throws(() => loadKeyFile('/k', fakeFs([['/k', { text: 'abc\n', mode: 0o100600 }]])), /64 hex digits/);
  assert.throws(() => loadKeyFile('/k', fakeFs([['/k', { text: '', mode: 0o100600, notFile: true }]])), /not a regular file/);
  const broken = { lstatSync: () => { throw Object.assign(new Error('EACCES'), { code: 'EACCES' }); } };
  assert.throws(() => loadKeyFile('/k', broken), /EACCES/);
});

test('sessions and tokens: the hashes, the CSRF token derived from the cookie, kdt_<id>_<secret>', () => {
  const cookie = randomToken(32);
  assert.equal(sessionHash(cookie).length, 32);
  assert.equal(sessionHash(cookie).equals(sha256(Buffer.from(cookie, 'base64url'))), true);
  const t = csrfToken(cookie);
  assert.equal(t, csrfToken(cookie));
  assert.notEqual(t, cookie);
  assert.equal(csrfHash(t).length, 32);
  const secret = randomToken(32);
  const text = tokenText(42, secret);
  assert.deepEqual(parseToken(text), { id: 42, secret });
  for (const bad of ['', 'kdt_', 'kdt_1_short', `kdt__${secret}`, `xdt_1_${secret}`, `kdt_1_${secret}x`, `kdt_1234567890123456_${secret}`]) assert.equal(parseToken(bad), null, bad);
  assert.equal(tokenHash(secret).length, 32);
});

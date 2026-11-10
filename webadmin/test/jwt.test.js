// The ID token checks of OpenID Connect Core 3.1.3.7 (lib/jwt.js) against hostile tokens: the algorithm, the key, the claims, the time, the form.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyIdToken, importJwks, importJwk, parseJws, amrSecondFactor, TokenError, MAX_TOKEN } from '../lib/jwt.js';
import { FakeIdp, signJws, keyPair, b64 } from './fakeidp.js';

const NOW = Date.UTC(2026, 10, 9, 12, 0, 0);
const SEC = NOW / 1000;
const ISS = 'https://idp.example.test';
const CLIENT = 'kari-client';
const NONCE = 'n-0123456789abcdef';

const idp = new FakeIdp({ now: () => NOW });
const jwkOf = (alg, n = 0, kid = `k${n}`) => idp.jwk({ alg, n, kid });
const KEYS = importJwks({ keys: [jwkOf('RS256'), jwkOf('ES256'), jwkOf('EdDSA')] });
const claims = (over = {}) => ({ iss: ISS, sub: 'user-1', aud: CLIENT, exp: SEC + 300, iat: SEC - 5, nonce: NONCE, ...over });
const make = (over = {}, alg = 'RS256', n = 0, header = {}) => signJws({ alg, typ: 'JWT', kid: `k${n}`, ...header }, claims(over), { key: keyPair(alg, n).privateKey });
const check = (token, o = {}) => verifyIdToken(token, { keys: KEYS, issuer: ISS, clientId: CLIENT, nonce: NONCE, now: NOW, ...o });
const reason = (fn) => { try { fn(); } catch (e) { assert.ok(e instanceof TokenError, `not a TokenError: ${e}`); return e; } assert.fail('no error'); };
// the key ids of the three keys of KEYS are k0 for all of them (jwkOf(alg) gives kid k0)

test('a good token is accepted with each algorithm', () => {
  for (const alg of ['RS256', 'ES256', 'EdDSA']) {
    const r = check(make({}, alg, 0, {}));
    assert.equal(r.sub, 'user-1');
    assert.equal(r.iss, ISS);
  }
});

test('"none": a token without a signature is refused, with an empty signature part and with a made-up one', () => {
  const h = b64(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const p = b64(JSON.stringify(claims()));
  assert.equal(reason(() => check(`${h}.${p}.`)).reason, 'alg');            // (an empty signature)
  assert.equal(reason(() => check(`${h}.${p}.AAAA`)).reason, 'alg');
  for (const a of ['None', 'NONE', 'nOnE']) assert.equal(reason(() => check(`${b64(JSON.stringify({ alg: a }))}.${p}.AAAA`)).reason, 'alg');
});

test('HMAC: HS256 signed with the client secret, and with the public key as the secret, is refused', () => {
  const t1 = signJws({ alg: 'HS256', typ: 'JWT', kid: 'k0' }, claims(), { secret: 'kari-secret-0123' });
  assert.equal(reason(() => check(t1)).reason, 'alg');
  // the classic confusion: the RSA public key (as PEM) used as an HMAC secret
  const pem = keyPair('RS256', 0).publicKey.export({ type: 'spki', format: 'pem' });
  const t2 = signJws({ alg: 'HS256', typ: 'JWT', kid: 'k0' }, claims(), { secret: pem });
  assert.equal(reason(() => check(t2)).reason, 'alg');
  for (const a of ['HS384', 'HS512', 'RS384', 'RS512', 'PS256', 'ES384', 'ES512', 'EdDSA2', '', 'rs256']) {
    assert.equal(reason(() => check(`${b64(JSON.stringify({ alg: a, kid: 'k0' }))}.${b64(JSON.stringify(claims()))}.AAAA`)).reason, 'alg', a);
  }
  assert.equal(reason(() => check(`${b64(JSON.stringify({ kid: 'k0' }))}.${b64(JSON.stringify(claims()))}.AAAA`)).reason, 'alg');       // no alg
  assert.equal(reason(() => check(`${b64(JSON.stringify({ alg: ['RS256'] }))}.${b64(JSON.stringify(claims()))}.AAAA`)).reason, 'alg');
  assert.equal(reason(() => check(`${b64(JSON.stringify({ alg: '__proto__' }))}.${b64(JSON.stringify(claims()))}.AAAA`)).reason, 'alg');
});

test('the key: another key with the right kid, a key of another type, an unknown kid, no kid', () => {
  // signed by the second RSA key but claiming the first one's kid
  assert.equal(reason(() => check(make({}, 'RS256', 1, { kid: 'k0' }))).reason, 'bad-signature');
  // no kid, signed by a key that is not in the set: every key of the type is tried, none fits (the key set may be old: refetch)
  const e = reason(() => check(signJws({ alg: 'RS256' }, claims(), { key: keyPair('RS256', 1).privateKey })));
  assert.equal(e.reason, 'bad-signature');
  assert.equal(e.refetch, true);
  // an unknown kid asks for a fresh key set
  const u = reason(() => check(make({}, 'RS256', 0, { kid: 'rotated' })));
  assert.equal(u.reason, 'unknown-kid');
  assert.equal(u.refetch, true);
  // an ES256 token and a set with RSA keys only
  const only = importJwks({ keys: [jwkOf('RS256')] });
  assert.equal(reason(() => check(make({}, 'ES256', 0, { kid: undefined }), { keys: only })).reason, 'no-key');
  // a key that says it is for another algorithm
  const rsaForPs = importJwks({ keys: [{ ...jwkOf('RS256'), alg: 'ES256' }] });
  assert.equal(reason(() => check(make(), { keys: rsaForPs })).reason, 'unknown-kid');
  // an empty set
  assert.equal(reason(() => check(make({}, 'RS256', 0, { kid: undefined }), { keys: [] })).reason, 'no-key');
});

test('a changed token: the payload or the header after signing, a cut signature', () => {
  const [h, p, s] = make().split('.');
  const evil = b64(JSON.stringify(claims({ sub: 'admin' })));
  assert.equal(reason(() => check(`${h}.${evil}.${s}`)).reason, 'bad-signature');
  const h2 = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'k0', extra: 1 }));
  assert.equal(reason(() => check(`${h2}.${p}.${s}`)).reason, 'bad-signature');
  assert.equal(reason(() => check(`${h}.${p}.${s.slice(0, -4)}`)).reason, 'bad-signature');
  assert.equal(reason(() => check(`${h}.${p}.${s}AAAA`)).reason, 'bad-signature');
  // ES256 with a DER signature instead of R || S
  const der = crypto.sign('sha256', Buffer.from(`${b64(JSON.stringify({ alg: 'ES256', kid: 'k0' }))}.${p}`), keyPair('ES256', 0).privateKey);
  assert.equal(reason(() => check(`${b64(JSON.stringify({ alg: 'ES256', kid: 'k0' }))}.${p}.${b64(der)}`)).reason, 'bad-signature');
});

test('header: crit is refused, jku / jwk / x5u / x5c are not followed or used', () => {
  assert.equal(reason(() => check(make({}, 'RS256', 0, { crit: ['exp'] }))).reason, 'crit');
  // a jwk in the header with the attacker's own key: the token is signed with that key; the key set is the only source
  const own = keyPair('RS256', 1);
  const t = signJws({ alg: 'RS256', kid: 'k0', jwk: own.publicKey.export({ format: 'jwk' }), jku: 'http://evil.test/jwks', x5u: 'http://evil.test/x5' }, claims(), { key: own.privateKey });
  assert.equal(reason(() => check(t)).reason, 'bad-signature');
  assert.equal(reason(() => check(make({}, 'RS256', 0, { kid: 5 }))).reason, 'malformed');
});

test('iss: another issuer, a prefix, a trailing slash, a non-string, none', () => {
  for (const iss of ['https://evil.example.test', `${ISS}/`, ISS.slice(0, -1), ISS.toUpperCase(), 5, null, undefined, [ISS]]) {
    assert.equal(reason(() => check(make({ iss }))).reason, 'iss', String(iss));
  }
});

test('aud and azp', () => {
  assert.equal(check(make({ aud: [CLIENT] })).sub, 'user-1');
  assert.equal(check(make({ aud: [CLIENT, 'other'], azp: CLIENT })).sub, 'user-1');
  assert.equal(check(make({ azp: CLIENT })).sub, 'user-1');
  for (const aud of ['other', ['other'], [], [CLIENT.toUpperCase()], 5, null, undefined, { 0: CLIENT }, [CLIENT, 5], `${CLIENT} `]) {
    assert.equal(reason(() => check(make({ aud }))).reason, 'aud', JSON.stringify(aud));
  }
  assert.equal(reason(() => check(make({ aud: [CLIENT, 'other'] }))).reason, 'azp');                // several audiences and no azp
  assert.equal(reason(() => check(make({ aud: [CLIENT, 'other'], azp: 'other' }))).reason, 'azp');
  assert.equal(reason(() => check(make({ azp: 'other' }))).reason, 'azp');                           // azp names somebody else
  assert.equal(reason(() => check(make({ aud: Array.from({ length: 17 }, (_, i) => (i ? `a${i}` : CLIENT)), azp: CLIENT }))).reason, 'aud');
});

test('exp, iat and nbf, with a minute of skew', () => {
  assert.equal(check(make({ exp: SEC + 1 })).sub, 'user-1');
  assert.equal(check(make({ exp: SEC - 59 })).sub, 'user-1');                          // (inside the skew)
  assert.equal(reason(() => check(make({ exp: SEC - 60 }))).reason, 'expired');
  assert.equal(reason(() => check(make({ exp: SEC - 3600 }))).reason, 'expired');
  for (const exp of [undefined, null, '9999999999', NaN, Infinity, [SEC + 100]]) assert.equal(reason(() => check(make({ exp }))).reason, 'exp', String(exp));
  assert.equal(check(make({ iat: SEC + 59 })).sub, 'user-1');
  assert.equal(reason(() => check(make({ iat: SEC + 61 }))).reason, 'iat-future');
  assert.equal(check(make({ iat: SEC - 300 })).sub, 'user-1');
  assert.equal(check(make({ iat: SEC - 359 })).sub, 'user-1');
  assert.equal(reason(() => check(make({ iat: SEC - 361 }))).reason, 'iat-old');
  for (const iat of [undefined, '1', null]) assert.equal(reason(() => check(make({ iat }))).reason, 'iat', String(iat));
  assert.equal(reason(() => check(make({ nbf: SEC + 3600 }))).reason, 'nbf');
  assert.equal(check(make({ nbf: SEC - 10 })).sub, 'user-1');
  // a token whose time is fine now is not fine an hour later (the caller's clock)
  assert.equal(reason(() => check(make(), { now: NOW + 3600 * 1000 })).reason, 'expired');
});

test('the nonce', () => {
  for (const nonce of [undefined, null, 'other', NONCE.toUpperCase(), `${NONCE} `, 5, [NONCE]]) assert.equal(reason(() => check(make({ nonce }))).reason, 'nonce', String(nonce));
});

test('sub: a string of 1 to 255 octets without control characters', () => {
  assert.equal(check(make({ sub: 'x'.repeat(255) })).sub.length, 255);
  for (const sub of ['', 'x'.repeat(256), 'a\nb', 'a\0b', 5, null, undefined, ['a'], 'é'.repeat(128)]) assert.equal(reason(() => check(make({ sub }))).reason, 'sub', String(sub).slice(0, 20));
});

test('the form of the token', () => {
  const good = make();
  const [h, p, s] = good.split('.');
  for (const t of [undefined, null, 5, {}, '', 'a', 'a.b', `${h}.${p}`, `${good}.x`, `${h}.${p}.${s}.${s}`, `${h}..${s}`, `.${p}.${s}`, `${h}.${p}.${s}=`, `${h}.${p}.a b`, `${h}.${p}.+/+/`, ` ${good}`]) {
    reason(() => check(t));
  }
  assert.equal(reason(() => check('x'.repeat(MAX_TOKEN + 1))).reason, 'malformed');
  // not JSON, not an object
  const bad = (x) => `${b64(x)}.${p}.${s}`;
  assert.equal(reason(() => check(bad('not json'))).reason, 'malformed');
  assert.equal(reason(() => check(bad('[]'))).reason, 'malformed');
  assert.equal(reason(() => check(bad('"RS256"'))).reason, 'malformed');
  assert.equal(reason(() => check(`${h}.${b64('[1]')}.${s}`)).reason, 'malformed');
  assert.equal(reason(() => check(`${h}.${b64('null')}.${s}`)).reason, 'malformed');
  assert.throws(() => parseJws(`${h}.${p}.${'A'.repeat(2000)}`), TokenError);
});

test('the keys of a JWK Set: private, small, for encryption, of another curve, broken', () => {
  const rsa = jwkOf('RS256');
  const priv = { ...rsa, ...keyPair('RS256', 0).privateKey.export({ format: 'jwk' }), kid: 'p' };
  assert.equal(importJwk(priv), null);                                                 // d is there
  const small = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' });
  assert.equal(importJwk({ ...small, kid: 's' }), null);
  assert.equal(importJwk({ ...rsa, use: 'enc' }), null);
  assert.notEqual(importJwk({ ...rsa, use: 'sig' }), null);
  assert.equal(importJwk({ ...rsa, key_ops: ['encrypt'] }), null);
  assert.notEqual(importJwk({ ...rsa, key_ops: ['verify'] }), null);
  assert.equal(importJwk({ ...rsa, alg: 'HS256' }), null);
  assert.equal(importJwk({ kty: 'oct', k: 'AAAA' }), null);
  const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ format: 'jwk' });
  assert.equal(importJwk(p384), null);
  const x448 = crypto.generateKeyPairSync('ed448').publicKey.export({ format: 'jwk' });
  assert.equal(importJwk(x448), null);
  assert.equal(importJwk({ kty: 'RSA', n: 'AQAB', e: 'AQAB' }), null);
  assert.equal(importJwk({ kty: 'RSA', n: '!!!', e: 'AQAB' }), null);
  assert.equal(importJwk(null), null);
  assert.equal(importJwk('RSA'), null);
  assert.equal(importJwk({ ...rsa, kid: 5 }), null);
  assert.deepEqual(importJwks(null), []);
  assert.deepEqual(importJwks({ keys: 'x' }), []);
  assert.equal(importJwks({ keys: Array.from({ length: 200 }, () => rsa) }).length, 64);
});

test('random damage to a good token: only a TokenError comes out, and nothing is accepted that signs different bytes', () => {
  let seed = 0x9e3779b9;
  const rnd = (n) => { seed = (seed + 0x6d2b79f5) >>> 0; let t = seed; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return (((t ^ (t >>> 14)) >>> 0) % n); };
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=+/ "{}[]\0\n';
  let accepted = 0;
  for (const alg of ['RS256', 'ES256', 'EdDSA']) {
    const good = make({}, alg);
    const [gh, gp, gs] = good.split('.');
    for (let i = 0; i < 1500; i++) {
      let t = good;
      for (let k = 0, n = 1 + rnd(3); k < n; k++) {
        const at = rnd(t.length + 1);
        switch (rnd(4)) {
          case 0: t = t.slice(0, at) + ALPHA[rnd(ALPHA.length)] + t.slice(at + 1); break;       // replace
          case 1: t = t.slice(0, at) + ALPHA[rnd(ALPHA.length)] + t.slice(at); break;           // insert
          case 2: t = t.slice(0, at) + t.slice(at + 1); break;                                  // delete
          default: t = t.slice(0, at); break;                                                   // cut
        }
      }
      try {
        const r = check(t);
        accepted++;
        const [h, p, s] = t.split('.');
        assert.ok(h === gh && p === gp && Buffer.from(s, 'base64url').equals(Buffer.from(gs, 'base64url')), `accepted a changed token: ${t}`);
        assert.equal(r.sub, 'user-1');
      } catch (e) {
        assert.ok(e instanceof TokenError, `${e}`);
      }
    }
  }
  assert.ok(accepted >= 0);
});

test('amr: two factors', () => {
  assert.equal(amrSecondFactor(['mfa']), true);
  assert.equal(amrSecondFactor(['pwd', 'otp']), true);
  assert.equal(amrSecondFactor(['pwd', 'hwk']), true);
  assert.equal(amrSecondFactor(['pwd', 'sms']), true);
  assert.equal(amrSecondFactor(['face', 'pin']), true);
  assert.equal(amrSecondFactor(['pwd']), false);
  assert.equal(amrSecondFactor(['pwd', 'kba']), false);                // two of the same class
  assert.equal(amrSecondFactor(['otp', 'hwk']), false);
  assert.equal(amrSecondFactor(['pwd', 'user']), false);
  assert.equal(amrSecondFactor(['pwd', 'geo']), false);
  assert.equal(amrSecondFactor([]), false);
  assert.equal(amrSecondFactor(undefined), false);
  assert.equal(amrSecondFactor('mfa'), false);
  assert.equal(amrSecondFactor([5, null, 'mfa2']), false);
});

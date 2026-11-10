// The ID token of OpenID Connect (item F, milestone M5; plan 5.5, F-16, F-17): the JSON Web Signature of RFC 7515 in its compact form, the keys of a JWK Set (RFC 7517),
// and the validation that OpenID Connect Core 1.0 section 3.1.3.7 asks of a client.  Everything comes from node:crypto; a token and a key set are the provider's text, so they
// are parsed strictly and bounded.  Pure functions: no network, no clock of its own (the caller gives `now`).
//
// What is accepted: RS256 (RSASSA-PKCS1-v1_5 with SHA-256, RFC 7518 section 3.3, a key of 2048 bits or more), ES256 (ECDSA with P-256 and SHA-256, RFC 7518 section 3.4: the
// signature is the 64 octets R || S, not DER) and EdDSA with Ed25519 (RFC 8037).  What is never accepted: "none" (an unsecured JWS, RFC 7515 section 6), the HMAC algorithms
// (Core 3.1.3.7 step 8 makes the client secret their key: a secret that the provider and we share, which proves nothing about who wrote the token; a provider signs with a key
// pair), anything
// else, a token whose header has "crit" (RFC 7515 section 4.1.11: we understand no extension), and the header parameters that point at a key ("jku", "x5u", "jwk", "x5c"
// are not even looked at: the keys are the provider's JWK Set that discovery named).

import crypto from 'node:crypto';
import { safeEqual } from './crypto.js';

// reason: a short code for the log ('bad-signature', 'expired', 'nonce', ...); refetch: the key set may be out of date (an unknown kid)
export class TokenError extends Error {
  constructor(reason, { refetch = false } = {}) {
    super(reason);
    this.reason = reason;
    this.refetch = refetch;
  }
}

export const MAX_TOKEN = 16384;
const MAX_KEYS = 64;
const B64URL = /^[A-Za-z0-9_-]*$/;

// RFC 7515 section 2: base64url without padding.  A length of 4n + 1 cannot be base64.
export function b64urlDecode(s) {
  if (typeof s !== 'string' || !B64URL.test(s) || s.length % 4 === 1) throw new TokenError('malformed');
  return Buffer.from(s, 'base64url');
}

const ALGS = {
  RS256: { kty: 'RSA', hash: 'sha256' },
  ES256: { kty: 'EC', crv: 'P-256', hash: 'sha256' },
  EdDSA: { kty: 'OKP', crv: 'Ed25519', hash: null },
};
export const SUPPORTED_ALGS = Object.keys(ALGS);

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function jsonPart(part) {
  let v;
  try { v = JSON.parse(b64urlDecode(part).toString('utf8')); } catch (e) { throw e instanceof TokenError ? e : new TokenError('malformed'); }
  if (!isObject(v)) throw new TokenError('malformed');
  return v;
}

// -> { header, claims, input (the octets that are signed), signature }; throws TokenError
export function parseJws(token) {
  if (typeof token !== 'string' || token.length < 5 || token.length > MAX_TOKEN) throw new TokenError('malformed');
  const parts = token.split('.');
  if (parts.length !== 3) throw new TokenError('malformed');              // a JWE has five parts; a JWS has three
  const header = jsonPart(parts[0]);
  const claims = jsonPart(parts[1]);
  if (typeof header.alg !== 'string' || !Object.hasOwn(ALGS, header.alg)) throw new TokenError('alg');
  if (header.crit !== undefined) throw new TokenError('crit');
  if (header.kid !== undefined && (typeof header.kid !== 'string' || header.kid.length > 256)) throw new TokenError('malformed');
  const signature = b64urlDecode(parts[2]);
  if (signature.length === 0 || signature.length > 1024) throw new TokenError('malformed');
  return { header, claims, input: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), signature };
}

// One JWK -> { kid, alg, kty, crv, key } or null when it is not a key we use (wrong type, too small, for encryption, a private key, unreadable).  Only the public members are
// handed to node:crypto.
export function importJwk(jwk) {
  if (!isObject(jwk) || typeof jwk.kty !== 'string') return null;
  if (jwk.use !== undefined && jwk.use !== 'sig') return null;
  if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes('verify'))) return null;
  if (jwk.alg !== undefined && (typeof jwk.alg !== 'string' || !Object.hasOwn(ALGS, jwk.alg))) return null;
  if (jwk.kid !== undefined && (typeof jwk.kid !== 'string' || jwk.kid.length > 256)) return null;
  const str = (k) => typeof jwk[k] === 'string' && jwk[k].length > 0 && jwk[k].length <= 2048 && B64URL.test(jwk[k]);
  let pub;
  if (jwk.kty === 'RSA' && str('n') && str('e')) pub = { kty: 'RSA', n: jwk.n, e: jwk.e };
  else if (jwk.kty === 'EC' && jwk.crv === 'P-256' && str('x') && str('y')) pub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  else if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && str('x')) pub = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  else return null;
  if (jwk.d !== undefined) return null;                    // a private key in a public document
  let key;
  try { key = crypto.createPublicKey({ key: pub, format: 'jwk' }); } catch { return null; }
  if (jwk.kty === 'RSA' && !(key.asymmetricKeyDetails?.modulusLength >= 2048)) return null;
  return { kid: jwk.kid, alg: jwk.alg, kty: pub.kty, crv: pub.crv, key };
}

// the keys of a JWK Set document (RFC 7517 section 5): the usable ones, at most 64 looked at
export function importJwks(doc) {
  if (!isObject(doc) || !Array.isArray(doc.keys)) return [];
  return doc.keys.slice(0, MAX_KEYS).map(importJwk).filter(Boolean);
}

function verifySignature(alg, key, input, signature) {
  try {
    if (alg === 'RS256') return crypto.verify('sha256', input, key, signature);
    if (alg === 'ES256') return signature.length === 64 && crypto.verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, signature);
    return signature.length === 64 && crypto.verify(null, input, key, signature);                      // EdDSA (Ed25519)
  } catch {
    return false;
  }
}

const SUB_BAD = /[\0-\x1f\x7f]/;
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);

// Core 1.0 section 3.1.3.7, for an ID token that comes straight from the token endpoint over TLS and is nevertheless checked by its signature (step 6 allows the TLS check
// alone; we do both).  o: { keys (importJwks), issuer, clientId, nonce, now (ms), skewSec (60), maxAgeSec (300: iat) }.  -> { iss, sub, amr, exp, claims }; throws TokenError.
export function verifyIdToken(token, o) {
  const { header, claims, input, signature } = parseJws(token);
  const spec = ALGS[header.alg];

  // the key (Core 10.1: the kid selects it; without one every key of the right type is tried, at most four)
  let cands = o.keys.filter((k) => k.kty === spec.kty && (spec.crv === undefined || k.crv === spec.crv) && (k.alg === undefined || k.alg === header.alg));
  if (header.kid !== undefined) {
    cands = cands.filter((k) => k.kid === header.kid);
    if (cands.length === 0) throw new TokenError('unknown-kid', { refetch: true });
  } else if (cands.length === 0) {
    throw new TokenError('no-key', { refetch: true });
  }
  if (!cands.slice(0, 4).some((k) => verifySignature(header.alg, k.key, input, signature))) throw new TokenError('bad-signature', { refetch: header.kid === undefined });

  const nowSec = o.now / 1000;
  const skew = o.skewSec ?? 60;
  // step 2: the issuer, exactly
  if (typeof claims.iss !== 'string' || claims.iss !== o.issuer) throw new TokenError('iss');
  // step 3: the audience must contain our client id; step 4 and 5: azp, when present, must be our client id (Core section 2).  With several audiences we also require azp
  // (our choice, the plan's): a token made for several relying parties must name the one it was issued to
  const aud = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  if (!Array.isArray(aud) || aud.length === 0 || aud.length > 16 || !aud.every((a) => typeof a === 'string')) throw new TokenError('aud');
  if (!aud.includes(o.clientId)) throw new TokenError('aud');
  if (aud.length > 1 && claims.azp === undefined) throw new TokenError('azp');
  if (claims.azp !== undefined && claims.azp !== o.clientId) throw new TokenError('azp');
  // step 9: the current time must be before exp (a minute of skew)
  if (!isNum(claims.exp) || nowSec >= claims.exp + skew) throw new TokenError(isNum(claims.exp) ? 'expired' : 'exp');
  // step 10: iat, "Client specific": not in the future, not older than five minutes (the token was issued by the token endpoint a moment ago)
  if (!isNum(claims.iat)) throw new TokenError('iat');
  if (claims.iat > nowSec + skew) throw new TokenError('iat-future');
  if (nowSec - claims.iat > (o.maxAgeSec ?? 300) + skew) throw new TokenError('iat-old');
  if (claims.nbf !== undefined && (!isNum(claims.nbf) || claims.nbf > nowSec + skew)) throw new TokenError('nbf');
  // step 11: the nonce we sent must come back
  if (typeof claims.nonce !== 'string' || !safeEqual(claims.nonce, o.nonce)) throw new TokenError('nonce');
  // sub (Core section 2): case sensitive, not longer than 255 characters
  if (typeof claims.sub !== 'string' || claims.sub.length === 0 || Buffer.byteLength(claims.sub) > 255 || SUB_BAD.test(claims.sub)) throw new TokenError('sub');
  const amr = Array.isArray(claims.amr) ? claims.amr.filter((a) => typeof a === 'string').slice(0, 32) : [];
  return { iss: claims.iss, sub: claims.sub, amr, exp: claims.exp, claims };
}

// RFC 8176 (authentication method reference values): does the token say that two factors were used?  "mfa" says so itself.  Otherwise the methods must come from two of
// the three classes: knowledge (pwd, pin, kba), possession (otp, hwk, swk, sms, tel, sc), inherence (fpt, face, iris, retina, vbm).  "user" (presence), "geo", "mca", "rba"
// and "wia" are not factors.
const KNOWLEDGE = new Set(['pwd', 'pin', 'kba']);
const POSSESSION = new Set(['otp', 'hwk', 'swk', 'sms', 'tel', 'sc']);
const INHERENCE = new Set(['fpt', 'face', 'iris', 'retina', 'vbm']);
export function amrSecondFactor(amr) {
  if (!Array.isArray(amr)) return false;
  if (amr.includes('mfa')) return true;
  return [KNOWLEDGE, POSSESSION, INHERENCE].filter((cls) => amr.some((a) => cls.has(a))).length >= 2;
}

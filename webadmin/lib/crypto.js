// Passwords, TOTP, the wrapping of the TOTP secret, random tokens.  Everything comes from node:crypto (A-22: no package).
//
// Passwords are PHC strings.  New hashes are scrypt: $scrypt$ln=17,r=8,p=1$<salt>$<hash> (base64 without padding; N = 2^ln; about 128 MiB per hash at
// ln=17, so hashing runs two at a time: a burst of logins cannot exhaust the memory).  $argon2id$ strings are verified when node:crypto has argon2
// (Node 24.7 or newer), so a hash made elsewhere can be loaded.  The parameters of a stored hash are bounded before they are used: the table is the
// database's, and a wrong row must not make the API allocate gigabytes.

import crypto from 'node:crypto';
import { ApiError } from './errors.js';

export const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

export function safeEqual(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// at most `limit` calls of fn at a time; the rest wait in order
export class Semaphore {
  // at most `limit` calls of fn run at a time, up to `maxQueue` wait; one more is refused (503: a burst of logins must not queue up for ever)
  constructor(limit, maxQueue = Infinity) {
    this.limit = limit;
    this.maxQueue = maxQueue;
    this.active = 0;
    this.queue = [];
  }

  async run(fn) {
    if (this.active >= this.limit) {
      if (this.queue.length >= this.maxQueue) throw new ApiError(503, 'busy', 'too many password checks at once, try again', { headers: { 'Retry-After': '2' } });
      await new Promise((resolve) => this.queue.push(resolve));            // the slot is handed over: active stays as it is
    } else {
      this.active++;
    }
    try {
      return await fn();
    } finally {
      const next = this.queue.shift();
      if (next) next();
      else this.active--;
    }
  }
}

const hashing = new Semaphore(2, 64);

// (128 * 2^ln * r octets of memory: at most 1 GiB, the cost the configuration allows at its highest, scrypt-ln = 20 with r = 8; r = 16 would be 2 GiB)
const SCRYPT_BOUNDS = { ln: [10, 20], r: [1, 8], p: [1, 4] };
const b64 = (buf) => buf.toString('base64').replace(/=+$/, '');
const unb64 = (s) => Buffer.from(s, 'base64');

const scrypt = (pw, salt, ln, r, p) => new Promise((resolve, reject) => {
  crypto.scrypt(pw.normalize('NFKC'), salt, 32, { N: 2 ** ln, r, p, maxmem: 256 * r * 2 ** ln }, (err, key) => (err ? reject(err) : resolve(key)));
});

export function hashPassword(pw, { ln = 17, r = 8, p = 1, salt = crypto.randomBytes(16) } = {}) {
  return hashing.run(async () => `$scrypt$ln=${ln},r=${r},p=${p}$${b64(salt)}$${b64(await scrypt(pw, salt, ln, r, p))}`);
}

const argon2 = (opts) => new Promise((resolve, reject) => {
  crypto.argon2('argon2id', opts, (err, key) => (err ? reject(err) : resolve(key)));
});

// -> true / false; a hash we cannot read or whose parameters are out of bounds is false (never an exception: the caller treats it like a wrong password)
export function verifyPassword(phc, pw) {
  return hashing.run(async () => {
    const f = String(phc).split('$');
    try {
      if (f[1] === 'scrypt' && f.length === 5) {
        const m = /^ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})$/.exec(f[2]);
        if (!m) return false;
        const [ln, r, p] = [Number(m[1]), Number(m[2]), Number(m[3])];
        if (ln < SCRYPT_BOUNDS.ln[0] || ln > SCRYPT_BOUNDS.ln[1] || r < SCRYPT_BOUNDS.r[0] || r > SCRYPT_BOUNDS.r[1] || p < SCRYPT_BOUNDS.p[0] || p > SCRYPT_BOUNDS.p[1]) return false;
        const want = unb64(f[4]);
        return want.length === 32 && safeEqual(await scrypt(pw, unb64(f[3]), ln, r, p), want);
      }
      if (f[1] === 'argon2id' && f.length === 6 && typeof crypto.argon2 === 'function') {
        const m = /^m=(\d{1,6}),t=(\d{1,2}),p=(\d{1,2})$/.exec(f[3]);
        if (!m || f[2] !== 'v=19') return false;
        const [memory, passes, parallelism] = [Number(m[1]), Number(m[2]), Number(m[3])];
        if (memory < 8 * parallelism || memory > 262144 || passes < 1 || passes > 10 || parallelism < 1 || parallelism > 16) return false;
        const want = unb64(f[5]);
        if (want.length < 16 || want.length > 64) return false;
        return safeEqual(await argon2({ message: Buffer.from(pw.normalize('NFKC')), nonce: unb64(f[4]), parallelism, tagLength: want.length, memory, passes }), want);
      }
    } catch {
      return false;
    }
    return false;
  });
}

// ---- base32 (RFC 4648, upper case, no padding): the form a TOTP secret is shown and typed in
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32(buf) {
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of buf) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text) {
  let bits = 0;
  let acc = 0;
  const out = [];
  for (const c of text.toUpperCase().replace(/=+$/, '')) {
    const v = B32.indexOf(c);
    if (v < 0) throw new Error('not a base32 string');
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((acc >>> (bits - 8)) & 255);
      bits -= 8;
    }
    acc &= (1 << bits) - 1;
  }
  return Buffer.from(out);
}

// ---- TOTP (RFC 6238 over HOTP, RFC 4226): HMAC-SHA1 by default, 6 digits, 30 seconds
export function hotp(secret, counter, { digits = 6, alg = 'sha1' } = {}) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac(alg, secret).update(msg).digest();
  const off = h[h.length - 1] & 15;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export const totpStep = (nowSec, period = 30) => Math.floor(nowSec / period);

// -> the step the code belongs to, or null.  A code of a step at or before lastStep is refused (no replay inside the window); the window is +/- 1 step.
export function totpVerify(secret, code, nowSec, { lastStep = -1, window = 1, digits = 6 } = {}) {
  if (typeof code !== 'string' || !/^\d+$/.test(code) || code.length !== digits) return null;
  const now = totpStep(nowSec);
  let found = null;
  for (let s = now - window; s <= now + window; s++) {
    if (s > lastStep && safeEqual(hotp(secret, s, { digits }), code)) found = s;       // no early exit: the time does not tell which step matched
  }
  return found;
}

export const otpauthUri = (issuer, account, secretB32) => `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

// ---- the TOTP secret at rest: AES-256-GCM under the API's key; the principal id is the associated data, so a secret copied to another row does not open
export function wrapSecret(key, principalId, plaintext) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(`totp:${principalId}`));
  const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final()]);
  return `v1.${iv.toString('base64url')}.${ct.toString('base64url')}.${c.getAuthTag().toString('base64url')}`;
}

// -> the plaintext, or null when the text is not ours, was changed or belongs to another principal
export function unwrapSecret(key, principalId, text) {
  const f = String(text).split('.');
  if (f.length !== 4 || f[0] !== 'v1') return null;
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(f[1], 'base64url'));
    d.setAAD(Buffer.from(`totp:${principalId}`));
    d.setAuthTag(Buffer.from(f[3], 'base64url'));
    return Buffer.concat([d.update(Buffer.from(f[2], 'base64url')), d.final()]).toString('utf8');
  } catch {
    return null;
  }
}

// ---- the key file: 32 random bytes as 64 hex digits, mode 0600, made at the first start when it is missing.  fs is injected for the tests.
export function loadKeyFile(file, fs) {
  let text;
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile()) throw new Error(`${file} is not a regular file`);
    if ((st.mode & 0o077) !== 0) throw new Error(`${file} has mode ${(st.mode & 0o777).toString(8).padStart(4, '0')}, it must not be readable by others (0600)`);
    text = fs.readFileSync(file, 'utf8').trim();
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    const key = crypto.randomBytes(32);
    fs.writeFileSync(file, `${key.toString('hex')}\n`, { mode: 0o600, flag: 'wx' });
    return key;
  }
  if (!/^[0-9a-f]{64}$/i.test(text)) throw new Error(`${file} does not hold 64 hex digits`);
  return Buffer.from(text, 'hex');
}

// ---- the ids of sessions and tokens
// a session cookie value is 32 random bytes; the database holds its SHA-256; the CSRF token is derived from the cookie value (so /auth/me can show it again
// without the database keeping it), and the database holds its SHA-256 too
export const sessionHash = (cookieValue) => sha256(Buffer.from(cookieValue, 'base64url'));
export const csrfToken = (cookieValue) => crypto.createHash('sha256').update('csrf:').update(Buffer.from(cookieValue, 'base64url')).digest('base64url');
export const csrfHash = (token) => sha256(Buffer.from(token, 'base64url'));

// kdt_<id>_<secret>
export const tokenText = (id, secret) => `kdt_${id}_${secret}`;
export function parseToken(text) {
  const m = /^kdt_(\d{1,15})_([A-Za-z0-9_-]{43})$/.exec(text);
  return m ? { id: Number(m[1]), secret: m[2] } : null;
}
export const tokenHash = (secret) => sha256(Buffer.from(secret, 'utf8'));

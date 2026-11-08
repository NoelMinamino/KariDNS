// Who is asking?  (planning 3.2, 3.3, 8.3)  A request carries a session cookie (a browser) or a bearer token (automation), never both.  This file finds the
// session or the token, checks the CSRF token and the Origin of an unsafe request that carries a cookie, loads the principal and its effective grants (once,
// for the whole request) and says what the credential may do (a read-only token, a session that has not done its TOTP step yet).

import { ApiError } from './errors.js';
import { parseToken, tokenHash, sessionHash, csrfToken, csrfHash, safeEqual, randomToken } from './crypto.js';
import * as S from './store.js';
import { isGlobal } from './perm.js';

export const COOKIE = 'karidns_session';
const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

export function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

// the Set-Cookie value that makes the browser keep (or, with maxAge 0, forget) the session
export function cookieHeader(value, maxAgeSec, secure) {
  return `${COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/api/; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
}

// a new session of a principal: the cookie value (the only time it exists in clear text on our side), the CSRF token, the row
export async function newSession(app, tx, principalId, { totpOk, client }) {
  const value = randomToken(32);
  const token = csrfToken(value);
  const now = app.now();
  const expires = now + app.settings['session-max'] * 1000;
  await S.createSession(tx, { idHash: sessionHash(value), principalId, csrfHash: csrfHash(token), createdMs: now, expiresMs: expires, totpOk, client: client.slice(0, 255) });
  return { value, csrf: token, expires };
}

// does this principal have to use TOTP?  (A-10: every global master, or every user, or nobody: `require-totp`)
export function needsTotp(settings, grants) {
  const mode = settings['require-totp'];
  return mode === 'all' || (mode === 'global' && isGlobal(grants));
}

const unauthenticated = (detail, code = 'unauthenticated') => new ApiError(401, code, detail, { headers: { 'WWW-Authenticate': 'Bearer realm="karidns"' } });

// Sets ctx.auth = { kind, principal, grants, totpOk, readOnly, session | tokenId } or throws.  route: { unsafe check is by method; preTotp: allowed before the TOTP step }
export async function authenticate(app, ctx, route) {
  const { req } = ctx;
  const cookie = parseCookies(req.headers.cookie)[COOKIE];
  const authz = req.headers.authorization;
  if (cookie && authz) throw new ApiError(400, 'both-credentials', 'send either the session cookie or a bearer token, not both');
  if (!cookie && !authz) throw unauthenticated('a session cookie or a bearer token is required');
  const now = app.now();
  const failed = () => {
    const wait = app.buckets.loginIp.take(`auth:${ctx.ip}`);
    return wait ? new ApiError(429, 'rate-limited', 'too many requests with bad credentials', { headers: { 'Retry-After': String(wait) } }) : unauthenticated('the credential is not valid');
  };

  if (authz) {
    const m = /^Bearer (\S{1,200})$/.exec(authz);
    const t = m && parseToken(m[1]);
    if (!t) throw failed();
    const found = await app.backend.tx({}, async (tx) => {
      const row = await S.lookupToken(tx, t.id, tokenHash(t.secret), now);
      if (!row) return null;
      await tx.setPrincipal(row.principal_id);
      return { row, principal: await S.getPrincipal(tx, row.principal_id), grants: await S.effectiveGrants(tx, row.principal_id) };
    });
    if (!found || !found.principal || found.principal.disabled) throw failed();
    if (found.row.read_only && !SAFE.has(req.method)) throw new ApiError(403, 'read-only-token', 'this token can only read');
    if (route.sessionOnly) throw new ApiError(403, 'session-only', 'this needs a login session, not a token');
    ctx.auth = { kind: 'token', principal: found.principal, grants: found.grants, totpOk: true, readOnly: found.row.read_only, tokenId: t.id };
    app.background(() => app.backend.tx({ principal: found.principal.id, name: found.principal.name, write: true }, (tx) => S.touchToken(tx, t.id, now)));
    return;
  }

  const idHash = sessionHash(cookie);
  const found = await app.backend.tx({}, async (tx) => {
    const row = await S.lookupSession(tx, idHash, now);
    if (!row) return null;
    await tx.setPrincipal(row.principal_id);
    return { row, principal: await S.getPrincipal(tx, row.principal_id), grants: await S.effectiveGrants(tx, row.principal_id) };
  });
  // the idle time is checked here (the row's expires_at is the absolute end): last_seen alone is written on requests, and the audit log ignores that
  if (!found || !found.principal || found.principal.disabled || found.row.last_seen + app.settings['session-idle'] * 1000 < now) throw failed();
  if (!SAFE.has(req.method)) {
    const origin = req.headers.origin;
    const want = app.settings['public-origin'];
    if (!origin || origin !== want) throw new ApiError(403, 'csrf', 'the Origin header does not name this site');
    const given = req.headers['x-karidns-csrf'];
    if (typeof given !== 'string' || !safeEqual(sha(given), found.row.csrf_hash) || !safeEqual(csrfToken(cookie), given)) throw new ApiError(403, 'csrf', 'the X-KariDNS-CSRF header is missing or wrong');
  }
  if (!found.row.totp_ok && !route.preTotp) throw new ApiError(403, 'totp-required', 'this session has not done the TOTP step: enrol or confirm at /api/v1/auth/totp first');
  ctx.auth = { kind: 'session', principal: found.principal, grants: found.grants, totpOk: found.row.totp_ok, readOnly: false, idHash, cookie, csrf: csrfToken(cookie), sessionExpires: found.row.expires };
  // last_seen is written at most once a minute (every few seconds where the idle time is short): the audit log ignores it, but the database is not asked on every request
  if (found.row.last_seen + Math.min(60000, app.settings['session-idle'] * 250) < now) {
    app.background(() => app.backend.tx({ principal: found.principal.id, name: found.principal.name, write: true }, (tx) => S.touchSession(tx, idHash, now)));
  }
}

const sha = (token) => csrfHash(token);

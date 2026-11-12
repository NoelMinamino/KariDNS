// /auth/*, /tokens: logging in and out, the session, TOTP, the password, API tokens (planning 3, 4).

import crypto from 'node:crypto';
import { ApiError, forbidden, notFound, conflict } from '../errors.js';
import { shape, query, LIMIT, CURSOR } from '../validate.js';
import * as S from '../store.js';
import { hashPassword, verifyPassword, totpVerify, wrapSecret, unwrapSecret, base32, otpauthUri, randomToken, tokenText, tokenHash } from '../crypto.js';
import { newSession, cookieHeader, needsTotp, mayHaveSession } from '../session.js';
import { reply } from '../http.js';
import { isGlobal } from '../perm.js';
import { absolute } from '../names.js';
import { requireGlobal, idParam, idCursor, page, clean } from './common.js';
import { lockNetwork } from '../ratelimit.js';

const PASSWORD = { type: 'string', min: 12, max: 1024, noControl: false };

export function checkPassword(pw, name) {
  if ([...pw].length < 12) throw new ApiError(400, 'weak-password', 'the password must have at least 12 characters', { errors: [{ code: 'weak-password', severity: 'error', text: 'at least 12 characters', pointer: '/password' }] });
  if (pw.toLowerCase().includes(name.toLowerCase())) throw new ApiError(400, 'weak-password', 'the password must not contain the user name');
}

export const principalView = (p) => ({ id: p.id, kind: p.kind, name: p.name, display_name: p.display_name, email: p.email, disabled: p.disabled });

// a grant as the API shows it: the dataset by name, names absolute
export function grantView(app, g) {
  const ds = g.role === 'global_master' ? null : (app.datasetOfSchema(g.data_schema)?.name ?? g.data_schema);
  return {
    id: g.id, role: g.role, dataset: ds, zone: g.zone_name ? absolute(g.zone_name) : null, suffix: g.name_suffix ? absolute(g.name_suffix) : null,
    policy: g.policy ? policyView(g.policy) : undefined, via: g.via_name,
  };
}

export const policyView = (p) => ({
  id: p.id, name: p.name, allowed_types: p.allowed_types, allow_wildcard: p.allow_wildcard, allow_delegation: p.allow_delegation, allow_dname: p.allow_dname,
  apex_editable: p.apex_editable, ttl_min: p.ttl_min, ttl_max: p.ttl_max, max_rr: p.max_rr,
});

const secure = (app) => app.settings['public-origin'].startsWith('https:');
const clientText = (ctx) => `${ctx.ip} ${clean(ctx.req.headers['user-agent'] ?? '')}`.slice(0, 255);

// the failure of one login: counted per account and client network, and that network locked out of the account for a while once ten in a row have happened (15
// minutes, twice as long for every further failure, a day at most; ratelimit.js Lockouts).  The owner still gets in from another network (audit, 0.6.2: the lock
// used to be the account's, for everybody).  A locked network is told apart from a wrong password by nobody: both give the same answer.
function loginFailed(app, p, ip) {
  const { failed, until } = app.lockouts.fail(p.id, ip);
  if (until) app.log.warn(`auth: ${clean(p.name)} is locked from ${lockNetwork(ip)} after ${failed} failed logins`);
}

const invalid = () => new ApiError(401, 'invalid-credentials', 'the user name, the password or the code is wrong');

export async function login(ctx) {
  const { app } = ctx;
  const s = app.settings;
  const body = shape(ctx.body, {
    user: { type: 'string', required: true, min: 1, max: 255 },
    password: { type: 'string', required: true, min: 1, max: 1024, noControl: false },
    totp: { type: 'string', min: 6, max: 6, re: /^\d{6}$/ },
  });
  const origin = ctx.req.headers.origin;
  if (origin !== undefined && origin !== s['public-origin']) throw new ApiError(403, 'csrf', 'the Origin header does not name this site');
  const wait = app.buckets.loginIp.take(ctx.ip) || app.buckets.loginUser.take(body.user.toLowerCase());
  if (wait) throw new ApiError(429, 'rate-limited', 'too many login attempts', { headers: { 'Retry-After': String(wait) } });

  const found = await app.backend.tx({}, async (tx) => {
    const p = await S.principalByName(tx, body.user);
    if (!p || p.disabled || p.kind !== 'user') return null;
    await tx.setPrincipal(p.id);
    return { p, creds: await S.getCredentials(tx, p.id), grants: await S.effectiveGrants(tx, p.id) };
  });
  const now = app.now();
  const usable = found?.creds?.password_hash && mayHaveSession(found.p, found.creds, now) && !app.lockouts.locked(found.p.id, ctx.ip);
  // a name that does not exist, a disabled user, a locked one (from this network): the same work is done against the dummy hash
  const good = await verifyPassword(usable ? found.creds.password_hash : await app.dummyHash(), body.password);
  if (!usable || !good) {
    if (usable) loginFailed(app, found.p, ctx.ip);
    // (the name is logged when it is one of ours: what else was typed in the field may be a password)
    else app.log.warn(`auth: login refused for ${found ? clean(found.p.name) : 'an unknown or disabled user'} from ${ctx.ip}`);
    throw invalid();
  }
  const { p, creds, grants } = found;

  let wrapped;
  if (creds.totp_enabled) {
    if (!body.totp) throw new ApiError(401, 'totp-required', 'a TOTP code is needed');
    const sec = JSON.parse(unwrapSecret(app.key, p.id, creds.totp_secret) ?? 'null');
    const step = sec && totpVerify(Buffer.from(sec.s, 'hex'), body.totp, now / 1000, { lastStep: sec.u });
    if (step === null || step === undefined) {
      loginFailed(app, p, ctx.ip);
      throw invalid();
    }
    wrapped = wrapSecret(app.key, p.id, JSON.stringify({ s: sec.s, u: step }));
  }
  const enrolRequired = needsTotp(s, grants) && !creds.totp_enabled;
  app.lockouts.succeed(p.id, ctx.ip);
  const sess = await app.backend.tx({ principal: p.id, name: p.name, write: true }, async (tx) => {
    await S.recordLoginSuccess(tx, p.id, wrapped);
    await S.deleteExpiredSessions(tx, now, p.id);
    return newSession(app, tx, p.id, { totpOk: !enrolRequired, client: clientText(ctx) });
  });
  app.log.info(`auth: ${clean(p.name)} logged in from ${ctx.ip}`);
  return reply(200, {
    principal: principalView(p), csrf: sess.csrf, expires_at: new Date(sess.expires).toISOString(),
    totp: { enabled: creds.totp_enabled, enrollment_required: enrolRequired },
  }, { headers: { 'Set-Cookie': cookieHeader(sess.value, s['session-max'], secure(app)) } });
}

export async function logout(ctx) {
  const { app } = ctx;
  const body = shape(ctx.body ?? {}, { all: { type: 'bool' } });
  if (ctx.auth.kind !== 'session') throw new ApiError(400, 'no-session', 'there is no session to end');
  await ctx.db((tx) => (body.all ? S.deleteSessionsOf(tx, ctx.auth.principal.id) : S.deleteSession(tx, ctx.auth.idHash)), { write: true });
  return reply(204, null, { headers: { 'Set-Cookie': cookieHeader('', 0, secure(app)) } });
}

export async function me(ctx) {
  const { app, auth } = ctx;
  const groups = await ctx.db((tx) => S.groupsOf(tx, auth.principal.id));
  const global = isGlobal(auth.grants);
  // a session that has not done the TOTP step: is the person to enrol (no TOTP yet) or to give the code (a sign-in with a provider, TOTP on)?
  const step = auth.kind === 'session' && !auth.totpOk ? ((await ctx.db((tx) => S.getCredentials(tx, auth.principal.id)))?.totp_enabled ? 'verify' : 'enrol') : null;
  const grantable = auth.grants.filter((g) => g.role === 'domain_master').map((g) => ({ dataset: app.datasetOfSchema(g.data_schema)?.name ?? g.data_schema, zone: absolute(g.zone_name) }));
  return {
    principal: principalView(auth.principal),
    groups,
    tenants: groups.filter((g) => g.tenant).map((g) => ({ id: g.id, name: g.name })),
    grants: auth.grants.map((g) => grantView(app, g)),
    capabilities: { global, manage_principals: global, manage_policies: global, create_zones: global, grant_on: grantable },
    session: auth.kind === 'session'
      ? { csrf: auth.csrf, totp_ok: auth.totpOk, ...(step ? { totp_step: step } : {}), expires_at: new Date(auth.sessionExpires).toISOString(), idle_timeout: app.settings['session-idle'] }
      : { token: true, read_only: auth.readOnly },
  };
}

// A password check for the actions that ask for it again (disable TOTP, change the password).  It is a way to guess the password for whoever holds the session, so it
// has the limits of a login: the bucket of logins (5 a minute, a key of its own per principal) and the count of failures that locks the account from this network.
async function reauth(ctx, password) {
  const { app, auth } = ctx;
  const wait = app.buckets.loginUser.take(`reauth:${auth.principal.id}`);
  if (wait) throw new ApiError(429, 'rate-limited', 'too many password checks', { headers: { 'Retry-After': String(wait) } });
  const creds = await ctx.db((tx) => S.getCredentials(tx, auth.principal.id));
  if (!creds?.password_hash || !(await verifyPassword(creds.password_hash, password))) {
    if (creds?.password_hash) loginFailed(app, auth.principal, ctx.ip);
    throw forbidden('the password is wrong', 'wrong-password');
  }
  return creds;
}

export async function totp(ctx) {
  const { app, auth } = ctx;
  const body = shape(ctx.body, {
    action: { type: 'string', required: true, values: ['enroll', 'confirm', 'verify', 'disable'] },
    code: { type: 'string', min: 6, max: 6, re: /^\d{6}$/ },
    password: { type: 'string', min: 1, max: 1024, noControl: false },
  });
  const id = auth.principal.id;
  const creds = await ctx.db((tx) => S.getCredentials(tx, id));
  // TOTP is a second step for a login with a password, or with a linked identity (F-17: the sign-in with a provider asks for it too)
  if (!creds?.password_hash && !creds?.oidc_issuer) throw conflict('this user has no password and no linked identity: TOTP is a second step for those', 'no-password');

  if (body.action === 'enroll') {
    if (creds.totp_enabled) throw conflict('TOTP is on already: disable it first', 'totp-enabled');
    const secret = crypto.randomBytes(20);
    await ctx.db((tx) => S.setTotp(tx, id, wrapSecret(app.key, id, JSON.stringify({ s: secret.toString('hex'), u: -1 })), false), { write: true });
    const b32 = base32(secret);
    return { secret: b32, uri: otpauthUri('KariDNS', auth.principal.name, b32), message: 'confirm with a code: {"action":"confirm","code":"123456"}' };
  }

  if (body.action === 'confirm') {
    if (creds.totp_enabled) throw conflict('TOTP is on already', 'totp-enabled');
    if (!body.code) throw new ApiError(400, 'bad-request', 'code is required', { errors: [{ code: 'bad-request', severity: 'error', text: 'this field is required', pointer: '/code' }] });
    const sec = creds.totp_secret && JSON.parse(unwrapSecret(app.key, id, creds.totp_secret) ?? 'null');
    if (!sec) throw conflict('there is no pending enrolment: enrol first', 'no-enrolment');
    const step = totpVerify(Buffer.from(sec.s, 'hex'), body.code, app.now() / 1000);
    if (step === null) throw forbidden('the code is wrong', 'wrong-code');
    // the session is replaced by one that has done the second step (the old id is worthless from now on)
    const sess = await ctx.db(async (tx) => {
      await S.setTotp(tx, id, wrapSecret(app.key, id, JSON.stringify({ s: sec.s, u: step })), true);
      await S.deleteSession(tx, auth.idHash);
      return newSession(app, tx, id, { totpOk: true, client: clientText(ctx) });
    }, { write: true });
    return reply(200, { csrf: sess.csrf, expires_at: new Date(sess.expires).toISOString(), totp: { enabled: true, enrollment_required: false } },
      { headers: { 'Set-Cookie': cookieHeader(sess.value, app.settings['session-max'], secure(app)) } });
  }

  // verify: the code of a user whose TOTP is on, for a session that has not done the step (a sign-in with a provider cannot ask for the code on the way: the answer of the
  // provider is a redirect).  The session is replaced by one that has done it, like a confirmation does.
  if (body.action === 'verify') {
    if (!creds.totp_enabled) throw conflict('TOTP is not on', 'totp-disabled');
    if (auth.totpOk) return { csrf: auth.csrf, expires_at: new Date(auth.sessionExpires).toISOString(), totp: { enabled: true, enrollment_required: false } };
    if (!body.code) throw new ApiError(400, 'bad-request', 'code is required', { errors: [{ code: 'bad-request', severity: 'error', text: 'this field is required', pointer: '/code' }] });
    const wait = app.buckets.loginUser.take(`reauth:${id}`);
    if (wait) throw new ApiError(429, 'rate-limited', 'too many code checks', { headers: { 'Retry-After': String(wait) } });
    const sec = JSON.parse(unwrapSecret(app.key, id, creds.totp_secret) ?? 'null');
    const step = sec && totpVerify(Buffer.from(sec.s, 'hex'), body.code, app.now() / 1000, { lastStep: sec.u });
    if (step === null || step === undefined) {
      loginFailed(app, auth.principal, ctx.ip);
      throw forbidden('the code is wrong', 'wrong-code');
    }
    app.lockouts.succeed(id, ctx.ip);
    const sess = await ctx.db(async (tx) => {
      await S.recordLoginSuccess(tx, id, wrapSecret(app.key, id, JSON.stringify({ s: sec.s, u: step })));
      await S.deleteSession(tx, auth.idHash);
      return newSession(app, tx, id, { totpOk: true, client: clientText(ctx) });
    }, { write: true });
    return reply(200, { csrf: sess.csrf, expires_at: new Date(sess.expires).toISOString(), totp: { enabled: true, enrollment_required: false } },
      { headers: { 'Set-Cookie': cookieHeader(sess.value, app.settings['session-max'], secure(app)) } });
  }

  // disable: the password (where there is one) and a current code, and only where no rule makes it mandatory
  if (!creds.totp_enabled) throw conflict('TOTP is not on', 'totp-disabled');
  if (needsTotp(app.settings, auth.grants)) throw forbidden('TOTP is required for this user by the configuration (require-totp)', 'totp-required-by-policy');
  if (!body.code || (creds.password_hash && !body.password)) throw new ApiError(400, 'bad-request', creds.password_hash ? 'password and code are required' : 'code is required');
  if (creds.password_hash) {
    await reauth(ctx, body.password);
  } else {
    const wait = app.buckets.loginUser.take(`reauth:${id}`);
    if (wait) throw new ApiError(429, 'rate-limited', 'too many code checks', { headers: { 'Retry-After': String(wait) } });
  }
  const sec = JSON.parse(unwrapSecret(app.key, id, creds.totp_secret) ?? 'null');
  if (!sec || totpVerify(Buffer.from(sec.s, 'hex'), body.code, app.now() / 1000, { lastStep: sec.u }) === null) {
    loginFailed(app, auth.principal, ctx.ip);
    throw forbidden('the code is wrong', 'wrong-code');
  }
  await ctx.db(async (tx) => {
    await S.setTotp(tx, id, null, false);
    await S.deleteSessionsOf(tx, id, auth.idHash);
  }, { write: true });
  return { totp: { enabled: false } };
}

export async function password(ctx) {
  const { app, auth } = ctx;
  const body = shape(ctx.body, { current: { type: 'string', required: true, min: 1, max: 1024, noControl: false }, new: { ...PASSWORD, required: true }, all: { type: 'bool' }, tokens: { type: 'bool' } });
  checkPassword(body.new, auth.principal.name);
  await reauth(ctx, body.current);
  const hash = await hashPassword(body.new, { ln: app.settings['scrypt-ln'] });
  await ctx.db(async (tx) => {
    await S.setPassword(tx, auth.principal.id, hash, app.now());
    if (body.all) await S.deleteSessionsOf(tx, auth.principal.id, auth.idHash);
    // tokens: the person's API tokens are revoked as well (audit, 0.6.2: a token taken with the old password stayed valid); a choice of its
    // own, as tokens are often used by automation that a password change need not stop
    if (body.tokens) await S.revokeTokensOf(tx, auth.principal.id, app.now());
  }, { write: true });
  return { password: 'changed' };
}

// ---------------------------------------------------------------------------------------------------------------------------------- tokens
export async function tokensList(ctx) {
  const q = query(ctx.query, { limit: LIMIT, cursor: CURSOR, principal: { type: 'int', min: 1, max: 999999999999999 }, all: { type: 'bool' } });
  const limit = q.limit ?? 100;
  const self = ctx.auth.principal.id;
  let principalId = q.principal ?? self;
  if (q.all) { requireGlobal(ctx); principalId = null; } else if (principalId !== self) requireGlobal(ctx);
  const rows = await ctx.db((tx) => S.listTokens(tx, { principalId, after: idCursor(q.cursor), limit }));
  const p = page(rows, limit, (t) => ({ i: t.id }));
  return { tokens: p.items, next_cursor: p.next_cursor };
}

export async function tokenCreate(ctx) {
  const { app, auth } = ctx;
  const body = shape(ctx.body, {
    name: { type: 'string', required: true, min: 1, max: 255 },
    read_only: { type: 'bool' },
    days: { type: 'int', min: 1, max: 365 },
    principal: { type: 'int', min: 1, max: 999999999999999 },
  });
  const principalId = body.principal ?? auth.principal.id;
  if (principalId !== auth.principal.id) requireGlobal(ctx);
  const secret = randomToken(32);
  const now = app.now();
  const id = await ctx.db(async (tx) => {
    if (principalId !== auth.principal.id) {
      const p = await S.getPrincipal(tx, principalId);
      if (!p) throw notFound('no such principal');
      if (p.kind !== 'user') throw conflict('only a user signs in, so only a user has tokens', 'not-a-user');       // (a token of a group would be a login nobody can account for)
    }
    return S.createToken(tx, { principalId, name: body.name, secretHash: tokenHash(secret), readOnly: body.read_only ?? false, createdMs: now, expiresMs: now + (body.days ?? 90) * 86400000 });
  }, { write: true });
  const t = await ctx.db((tx) => S.getToken(tx, id));
  return reply(201, { token: tokenText(id, secret), info: t, message: 'this is the only time the token is shown' });
}

export async function tokenRevoke(ctx) {
  const id = idParam(ctx);
  const t = await ctx.db((tx) => S.getToken(tx, id));
  if (!t || (t.principal_id !== ctx.auth.principal.id && !isGlobal(ctx.auth.grants))) throw notFound('no such token');
  await ctx.db((tx) => S.revokeToken(tx, id, ctx.app.now()), { write: true });
  return reply(204, null);
}


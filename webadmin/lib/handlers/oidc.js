// /auth/providers and /auth/oidc/{name}/start and /callback: signing in with an OpenID Connect provider (item F, milestone M5; plan 5.5; F-16, F-17, F-18).
//
// These two are not calls of the API but steps of a browser's navigation: start answers with a 302 to the provider, and the provider sends the browser back to callback with a
// 302 of its own.  So whatever goes wrong is told by a redirect to the page (/#/?oidc=failed | unavailable | busy), never by a JSON document: the person is looking at the
// provider's page or at nothing.  The page shows one text per word, and the reason (an unlinked subject, a disabled user, a bad signature, a replayed state) goes to the log
// only, so the answer tells nothing to someone who is not meant to get in.
//
// The state of the flow lives in the database (F-18): the session cookie is SameSite=Strict and would not come back on the provider's cross-site redirect.  To keep the
// callback tied to the browser that began the flow (RFC 9700 section 4.7: otherwise somebody could start a flow, sign in at the provider as themselves and give the callback
// address, with their code and state, to somebody else, whose browser would then hold THEIR session), start also sets a cookie of its own, SameSite=Lax (a Lax cookie is sent
// with a top-level GET navigation from another site), HttpOnly, limited to the path of these two, ten minutes; its hash is in the state row.

import { sha256, safeEqual } from '../crypto.js';
import { notFound } from '../errors.js';
import { reply } from '../http.js';
import { parseCookies, newSession, cookieHeader, needsTotp, mayHaveSession } from '../session.js';
import { amrSecondFactor } from '../jwt.js';
import { OidcError, newSecret, pkceChallenge } from '../oidc.js';
import * as S from '../store.js';
import { clean } from './common.js';

export const BROWSER_COOKIE = 'karidns_oidc';
const COOKIE_PATH = '/api/v1/auth/oidc/';
const ROUTE = /^\/[A-Za-z0-9._~%!$&'()*+,;=:@/?-]{0,500}$/;

const secure = (app) => app.settings['public-origin'].startsWith('https:');
const redirectUri = (app, name) => `${app.settings['public-origin']}/api/v1/auth/oidc/${encodeURIComponent(name)}/callback`;
const browserCookie = (value, maxAge, secureFlag) => `${BROWSER_COOKIE}=${value}; HttpOnly; SameSite=Lax; Path=${COOKIE_PATH}; Max-Age=${maxAge}${secureFlag ? '; Secure' : ''}`;

// a return route that is safe to put after "#": a path of the page, no "//" (not that a fragment can leave the page), no control character
export const cleanRoute = (r) => (typeof r === 'string' && ROUTE.test(r) && !r.startsWith('//') ? r : '/');

const back = (app, route, headers = {}) => reply(302, null, { headers: { Location: `${app.settings['public-origin']}/#${route}`, ...headers } });
const failure = (app, why, extra = {}) => back(app, `/?oidc=${why}`, extra);

export async function providers(ctx) {
  return { providers: ctx.app.oidc.list() };
}

export async function start(ctx) {
  const { app } = ctx;
  const prov = app.oidc.get(ctx.params.name);
  if (!prov) throw notFound('no such provider');
  const route = cleanRoute(ctx.query.get('return') ?? '/');
  try {
    if (app.buckets.loginIp.take(`oidc:${ctx.ip}`)) return failure(app, 'busy');
    if (app.oidcStarts.take(ctx.ip)) return failure(app, 'busy');          // (no log line: a flood would be a flood of lines)
    const state = newSecret();
    const verifier = newSecret();
    const nonce = newSecret();
    const browser = newSecret();
    const url = await prov.authorizationUrl({ redirectUri: redirectUri(app, prov.name), state, nonce, challenge: pkceChallenge(verifier) });
    const room = await app.backend.tx({ write: true }, (tx) => S.putOidcState(tx, { stateHash: sha256(state), browserHash: sha256(browser), provider: prov.name, nonce, verifier, route, nowMs: app.now() }));
    if (!room) return failure(app, 'busy');
    return reply(302, null, { headers: { Location: url, 'Set-Cookie': browserCookie(browser, 600, secure(app)) } });
  } catch (e) {
    if (e instanceof OidcError) {
      app.log.warn(`auth: oidc ${clean(prov.name)}: no sign-in could be started: ${clean(e.message)}`);
      return failure(app, 'unavailable');
    }
    app.log.error(`${ctx.id}: oidc start: ${clean(e?.message ?? e)}`);
    return failure(app, 'unavailable');
  }
}

export async function callback(ctx) {
  const { app } = ctx;
  const prov = app.oidc.get(ctx.params.name);
  if (!prov) throw notFound('no such provider');
  const clear = { 'Set-Cookie': browserCookie('', 0, secure(app)) };
  const refuse = (why, kind = 'failed') => {
    app.log.warn(`auth: oidc ${clean(prov.name)}: sign-in refused from ${ctx.ip}: ${clean(why)}`);
    return failure(app, kind, clear);
  };
  try {
    if (app.buckets.loginIp.take(`oidc:${ctx.ip}`)) return failure(app, 'busy', clear);
    const q = ctx.query;
    const state = q.get('state');
    if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(state)) return refuse('no valid state');
    // the state is used up first, whatever else is wrong with the request (a replay finds nothing)
    const now = app.now();
    const row = await app.backend.tx({ write: true }, (tx) => S.takeOidcState(tx, sha256(state), now));
    if (!row) return refuse('the state is unknown, used or over');
    const cookie = parseCookies(ctx.req.headers.cookie)[BROWSER_COOKIE];
    if (row.provider !== prov.name) return refuse('the state belongs to another provider');
    if (!cookie || !safeEqual(sha256(cookie), Buffer.from(row.browser_hash))) return refuse('the sign-in was not started by this browser');
    if (q.get('error') !== null) return refuse(`the provider answered error=${q.get('error')}`);
    // RFC 9207: the issuer that answered, when it says (and always when it said it would)
    const meta = await prov.meta();
    const iss = q.get('iss');
    if (iss !== null ? iss !== prov.issuer : meta.issParam) return refuse('the iss parameter is missing or names another issuer');
    const code = q.get('code');
    if (typeof code !== 'string' || !/^[\x20-\x7e]{1,2048}$/.test(code)) return refuse('no valid code');

    const idToken = await prov.exchange({ code, verifier: row.verifier, redirectUri: redirectUri(app, prov.name) });
    const id = await prov.verify(idToken, row.nonce);

    // F-16: the user this (issuer, subject) is linked to; there are no accounts made by a sign-in
    const found = await app.backend.tx({}, async (tx) => {
      const pid = await S.oidcLookup(tx, id.iss, id.sub);
      if (pid === null) return null;
      await tx.setPrincipal(pid);
      return { p: await S.getPrincipal(tx, pid), creds: await S.getCredentials(tx, pid), grants: await S.effectiveGrants(tx, pid) };
    });
    if (!found) return refuse(`no user is linked to the subject ${clean(id.sub)}`);
    if (!mayHaveSession(found.p, found.creds, now)) return refuse(`${clean(found.p?.name ?? '?')} is disabled or locked`);
    const { p, creds, grants } = found;

    // F-17: the TOTP step also after a provider, unless the provider is configured to answer for it (mfa = idp) and the token says two factors were used (RFC 8176)
    const idp = prov.mfa === 'idp' && amrSecondFactor(id.amr);
    const stepNeeded = !idp && (needsTotp(app.settings, grants) || creds.totp_enabled);
    const sess = await app.backend.tx({ principal: p.id, name: p.name, write: true }, async (tx) => {
      await S.recordLoginSuccess(tx, p.id);
      await S.deleteExpiredSessions(tx, now, p.id);
      return newSession(app, tx, p.id, { totpOk: !stepNeeded, client: `${ctx.ip} oidc ${prov.name} ${clean(ctx.req.headers['user-agent'] ?? '')}`.slice(0, 255) });
    });
    app.log.info(`auth: ${clean(p.name)} logged in with ${clean(prov.name)} from ${ctx.ip}${stepNeeded ? ' (the TOTP step is still to do)' : ''}`);
    return back(app, cleanRoute(row.return_route), { 'Set-Cookie': [cookieHeader(sess.value, app.settings['session-max'], secure(app)), clear['Set-Cookie']] });
  } catch (e) {
    if (e instanceof OidcError) return refuse(e.message, e.kind);
    // the database, or a bug: it is the person's browser that is waiting, so it gets the page, not a document
    app.log.error(`${ctx.id}: oidc callback: ${clean(e?.stack ?? e?.message ?? e)}`);
    return failure(app, 'unavailable', clear);
  }
}

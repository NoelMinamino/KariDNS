// What the OpenID Connect tests share: a deployment (helpers.js deploy()) with a fake provider (fakeidp.js) configured in it, and a browser that follows the redirects by hand.
import { FakeIdp } from './fakeidp.js';
import { ORIGIN } from './helpers.js';

export const CLIENT_ID = 'kari-client';
export const CLIENT_SECRET = 'kari-secret-0123';

// the provider `name` of the deployment d, at a fake provider on the loopback address.  -> the FakeIdp (stop it with idp.stop())
export async function setupOidc(d, { name = 'idp', mfa = 'totp', label = 'Example ID', idp: idpOpts = {}, scopes = ['openid'] } = {}) {
  const idp = new FakeIdp({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, now: d.app.now, ...idpOpts });
  await idp.start();
  idp.redirectUris.add(redirectUri(name));
  d.app.oidc.configure([...(d.app.oidc.providers.values()).map((p) => ({ name: p.name, issuer: p.issuer, clientId: p.clientId, clientSecret: p.clientSecret, scopes: p.scopes, label: p.label, mfa: p.mfa })),
    { name, issuer: idp.issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, scopes, label, mfa }]);
  return idp;
}

export const redirectUri = (name) => `${ORIGIN}/api/v1/auth/oidc/${name}/callback`;

const get = (url, headers = {}) => fetch(url, { redirect: 'manual', headers });

// The browser's part of a sign-in, by hand: start -> the provider's authorization endpoint -> back to the callback (with the cookie the start set).  The service listens on
// another port than public-origin says, so the address of the callback is rewritten to the deployment's.  hook(step, ...) lets a test change what the browser does.
// -> { start, auth, cb, bc (the cookie of the browser), session (the session cookie the callback set), location (where the callback sent the browser) }
export async function browse(d, name = 'idp', { query = '', cookie, callbackQuery } = {}) {
  const r = { start: await get(`${d.base}/auth/oidc/${name}/start${query}`) };
  const set = r.start.headers.getSetCookie?.() ?? [];
  r.setCookie = set;
  r.bc = /karidns_oidc=([^;]*)/.exec(set.join('\n'))?.[1];
  const loc = r.start.headers.get('location');
  if (r.start.status !== 302 || !loc || loc.startsWith(`${ORIGIN}/`)) return finish(r);                // (a failure is a redirect to the page)
  r.auth = await get(loc);
  const back = r.auth.headers.get('location');
  if (r.auth.status !== 302 || !back) return finish(r);
  const u = new URL(back);
  const search = callbackQuery ? callbackQuery(u.searchParams) : u.search;
  const headers = {};
  const c = cookie === undefined ? r.bc : cookie;
  if (c !== undefined && c !== null) headers.Cookie = `karidns_oidc=${c}`;
  r.cb = await get(`${d.base}/auth/oidc/${name}/callback${typeof search === 'string' ? search : `?${search}`}`, headers);
  return finish(r);
}

export function finish(r) {
  const cb = r.cb ?? r.start;
  r.location = cb.headers.get('location');
  const set = cb.headers.getSetCookie?.() ?? [];
  r.session = /karidns_session=([^;]+)/.exec(set.join('\n'))?.[1];
  r.cbCookies = set;
  return r;
}

// the callback of a sign-in that went right, called again with the same state (a replay), or with other parameters
export async function callbackAgain(d, name, r, { search, cookie } = {}) {
  const u = new URL(r.auth.headers.get('location'));
  const headers = {};
  const c = cookie === undefined ? r.bc : cookie;
  if (c) headers.Cookie = `karidns_oidc=${c}`;
  return get(`${d.base}/auth/oidc/${name}/callback${search ?? u.search}`, headers);
}

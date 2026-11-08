// The integration driver of the sign-in with an OpenID Connect provider (item F, milestone M5), the same scenarios on SQLite3 and on PostgreSQL.  Not a node:test file:
// tests/run_webadmin_oidc_test.sh sets the database up, starts the real service with an [oidc idp] section and a fake provider (webadmin/test/e2e/idp.mjs, a second
// process on the loopback address) and runs this against them.
//
//   IT_BASE=http://127.0.0.1:PORT/api/v1 IT_ORIGIN=http://127.0.0.1:PORT IT_IDP=http://localhost:IPORT IT_ADMIN_PASSWORD=... IT_STATES_SQL=./states.sh node webadmin/test/it_oidc.mjs
//
// IT_STATES_SQL is a program that prints the number of rows of oidc_states (run as the owner of the tables: the API role has no right on that table).
// It prints "  [ OK ] ..." / "  [FAIL] ..." lines and exits 1 when anything failed.  The service runs with require-totp = global.

import { execFileSync } from 'node:child_process';
import { hotp, totpStep, base32Decode } from '../lib/crypto.js';

const BASE = process.env.IT_BASE;
const ORIGIN = process.env.IT_ORIGIN;
const IDP = process.env.IT_IDP;
let pass = 0;
let fails = 0;
const ok = (name) => { pass++; console.log(`  [ OK ] ${name}`); };
const bad = (name, why) => { fails++; console.log(`  [FAIL] ${name}${why ? ` (${why})` : ''}`); };
const check = (name, cond, why) => (cond ? ok(name) : bad(name, typeof why === 'function' ? why() : why));
const eq = (name, got, want) => check(name, JSON.stringify(got) === JSON.stringify(want), () => `got ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);

async function call(method, p, { body, cookie, csrf, origin } = {}) {
  const h = {};
  if (cookie) h.Cookie = `karidns_session=${cookie}`;
  if (csrf) h['X-KariDNS-CSRF'] = csrf;
  if (origin) h.Origin = origin;
  let payload;
  if (body !== undefined) { payload = JSON.stringify(body); h['Content-Type'] = 'application/json'; }
  const res = await fetch(BASE + p, { method, headers: h, body: payload });
  const text = await res.text();
  let parsed = text;
  if (/json/.test(res.headers.get('content-type') ?? '')) parsed = JSON.parse(text);
  return { status: res.status, headers: res.headers, body: parsed, text };
}
const code = (b32, step = 0) => hotp(base32Decode(b32), totpStep(Date.now() / 1000) + step);
const type = (r) => r.body?.type?.replace('urn:karidns:api:', '');
const session = (r) => {
  const m = /karidns_session=([^;]+)/.exec(r.headers.get('set-cookie') ?? '');
  const s = { cookie: m?.[1], csrf: r.body?.csrf };
  s.do = (method, p, o = {}) => call(method, p, { cookie: s.cookie, csrf: s.csrf, origin: ORIGIN, ...o });
  return s;
};
const ctl = async (c) => {
  const r = await fetch(`${IDP}/__control`, { method: 'POST', body: JSON.stringify(c) });
  if (r.status !== 200) bad('the fake provider takes its control', `${r.status} ${await r.text()}`);
};
const states = () => Number(execFileSync(process.env.IT_STATES_SQL, [], { encoding: 'utf8' }).trim());
const get = (url, headers = {}) => fetch(url, { redirect: 'manual', headers });

// the browser's part by hand: start -> the provider -> the callback with the cookie of the start.  -> { location, session: { cookie, do }, start, cb }
async function browse(query = '', { cookie } = {}) {
  const start = await get(`${BASE}/auth/oidc/idp/start${query}`);
  const set = start.headers.getSetCookie();
  const bc = /karidns_oidc=([^;]*)/.exec(set.join('\n'))?.[1];
  const to = start.headers.get('location');
  const r = { start, bc, setCookie: set };
  if (start.status !== 302 || to.startsWith(`${ORIGIN}/`)) { r.location = to; return r; }
  const auth = await get(to);
  r.auth = auth;
  const back = auth.headers.get('location');
  const c = cookie === undefined ? bc : cookie;
  const cb = await get(back, c ? { Cookie: `karidns_oidc=${c}` } : {});
  r.cb = cb;
  r.location = cb.headers.get('location');
  const m = /karidns_session=([^;]+)/.exec(cb.headers.getSetCookie().join('\n'));
  if (m) {
    r.session = { cookie: m[1] };
    const me = await call('GET', '/auth/me', { cookie: m[1] });
    r.me = me;
    r.session.csrf = me.body?.session?.csrf;
    r.session.do = (method, p, o = {}) => call(method, p, { cookie: r.session.cookie, csrf: r.session.csrf, origin: ORIGIN, ...o });
  }
  return r;
}
const FAILED = `${ORIGIN}/#/?oidc=failed`;

// ---------------------------------------------------------------------------------------------------------------------------------- the administrator and the users
console.log('-- the administrator, a user, the providers');
let admin = session(await call('POST', '/auth/login', { body: { user: 'admin', password: process.env.IT_ADMIN_PASSWORD } }));
const enrol = await admin.do('POST', '/auth/totp', { body: { action: 'enroll' } });
const conf = await admin.do('POST', '/auth/totp', { body: { action: 'confirm', code: code(enrol.body.secret) } });
eq('the administrator enrols TOTP', conf.status, 200);
const secret = enrol.body.secret;
const confirmStep = totpStep(Date.now() / 1000);
// a code for a step after the confirmation (a code is good once): the next step is inside the window the service accepts; the current one when the clock has moved on
const freshCode = () => code(secret, totpStep(Date.now() / 1000) > confirmStep ? 0 : 1);
admin = session(conf);
const prov = await call('GET', '/auth/providers');
eq('the providers are listed without a login', [prov.status, prov.body.providers.map((p) => [p.name, p.label, p.issuer === IDP])], [200, [['idp', 'Example ID', true]]]);
const bob = (await admin.do('POST', '/principals', { body: { kind: 'user', name: 'bob', display_name: 'Bob' } })).body.principal.id;
const adminId = (await admin.do('GET', '/auth/me')).body.principal.id;
eq('an issuer that is not a provider of the service is refused', (await admin.do('PUT', `/principals/${bob}/oidc`, { body: { issuer: 'https://nobody.example.test', subject: 'bob-sub' } })).body.errors?.[0]?.pointer, '/issuer');
const put = await admin.do('PUT', `/principals/${bob}/oidc`, { body: { issuer: IDP, subject: 'bob-sub' } });
eq('a global master links bob (who has no password) to an identity', [put.status, put.body.credentials.oidc.subject, put.body.credentials.password], [200, 'bob-sub', false]);
eq('...the identity belongs to one user', type(await admin.do('PUT', `/principals/${adminId}/oidc`, { body: { issuer: IDP, subject: 'bob-sub' } })), 'exists');
eq('...and the administrator links himself', (await admin.do('PUT', `/principals/${adminId}/oidc`, { body: { issuer: IDP, subject: 'admin-sub' } })).status, 200);

// ---------------------------------------------------------------------------------------------------------------------------------- a sign-in
console.log('-- the sign-in with the provider');
await ctl({ sub: 'bob-sub' });
const r1 = await browse('?return=%2Fzones');
const loc = new URL(r1.start.headers.get('location'));
check('start redirects to the provider with state, nonce and a PKCE challenge', loc.origin === IDP && loc.searchParams.get('code_challenge_method') === 'S256' && loc.searchParams.get('state')?.length === 43 && loc.searchParams.get('nonce')?.length === 43, () => String(loc));
check('...and sets the cookie of this browser (Lax, HttpOnly, short)', /karidns_oidc=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Lax; Path=\/api\/v1\/auth\/oidc\/; Max-Age=600/.test(r1.setCookie.join(';')), () => r1.setCookie.join(';'));
eq('the callback sends the browser to the page it came from', r1.location, `${ORIGIN}/#/zones`);
eq('...with a session of bob', [r1.me.status, r1.me.body.principal.name, r1.me.body.session.totp_ok], [200, 'bob', true]);
eq('...which works', (await r1.session.do('GET', '/datasets')).status, 200);
eq('the state of the sign-in is used up', states(), 0);
const replay = await get(r1.auth.headers.get('location'), { Cookie: `karidns_oidc=${r1.bc}` });
eq('the same callback again is refused', replay.headers.get('location'), FAILED);
check('...and gives no session', !/karidns_session/.test(replay.headers.get('set-cookie') ?? ''));

console.log('-- refusals: the same answer for all of them');
await ctl({ sub: 'stranger' });
eq('a subject that is linked to nobody', (await browse()).location, FAILED);
await ctl({ sub: 'bob-sub' });
const other = await browse('', { cookie: 'A'.repeat(43) });
eq('a callback from a browser that did not start the sign-in', [other.location, other.session], [FAILED, undefined]);
eq('...and when the cookie is missing', (await browse('', { cookie: null })).location, FAILED);
for (const t of ['alg-none', 'hs256', 'wrong-key', 'expired', 'nonce', 'aud', 'iss']) {
  await ctl({ tamper: t });
  const r = await browse();
  eq(`an ID token that is wrong (${t})`, [r.location, r.session], [FAILED, undefined]);
}
await ctl({ tamper: null });
await ctl({ authError: 'access_denied' });
eq('the provider says no', (await browse()).location, FAILED);
await ctl({ authError: null });
eq('...and then it works again', (await browse()).location, `${ORIGIN}/#/`);
eq('no state is left behind by all of that', states(), 0);
eq('an unknown provider is a 404', (await call('GET', '/auth/oidc/nope/start')).status, 404);

// ---------------------------------------------------------------------------------------------------------------------------------- the TOTP step
console.log('-- the TOTP step after the provider (a global master)');
await ctl({ sub: 'admin-sub' });
const a1 = await browse();
eq('the administrator gets a session that has not done the step', [a1.me.status, a1.me.body.session.totp_ok, a1.me.body.session.totp_step], [200, false, 'verify']);
eq('...and until then only /auth answers', type(await a1.session.do('GET', '/principals')), 'totp-required');
eq('a wrong code', type(await a1.session.do('POST', '/auth/totp', { body: { action: 'verify', code: '000000' } })), 'wrong-code');
const usedCode = freshCode();
const v = await a1.session.do('POST', '/auth/totp', { body: { action: 'verify', code: usedCode } });
eq('the code is accepted', v.status, 200);
const a2 = session(v);
eq('...the session is a new one and works; the old one is gone', [(await a2.do('GET', '/principals')).status, (await a1.session.do('GET', '/auth/me')).status], [200, 401]);
eq('the same code does not open another session', type(await (await browse()).session.do('POST', '/auth/totp', { body: { action: 'verify', code: usedCode } })), 'wrong-code');

// ---------------------------------------------------------------------------------------------------------------------------------- unlinking
console.log('-- unlinking, the audit log');
await ctl({ sub: 'bob-sub' });
const b2 = await browse();
eq('bob signs in again', b2.me.status, 200);
eq('the administrator removes the link', (await a2.do('DELETE', `/principals/${bob}/oidc`)).status, 204);
eq('...bob is signed out', (await b2.session.do('GET', '/auth/me')).status, 401);
eq('...and the identity signs nobody in', (await browse()).location, FAILED);
eq('removing it again is a 404', (await a2.do('DELETE', `/principals/${bob}/oidc`)).status, 404);
const audit = await a2.do('GET', '/audit?limit=200');
check('the link and its removal are in the audit log, with the subject', audit.status === 200 && JSON.stringify(audit.body).includes('bob-sub'), () => `${audit.status} ${audit.text.slice(0, 200)}`);
eq('the state table is empty at the end', states(), 0);

console.log(`\n  ${pass} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);

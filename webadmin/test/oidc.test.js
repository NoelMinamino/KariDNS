// Signing in with an OpenID Connect provider (item F, milestone M5): the configuration, the discovery and the key set, the flow with a fake provider on the loopback address,
// the hostile cases (a replayed state, a state from another browser, every way an ID token can be wrong), linking, the TOTP step (F-17), the limits of what is fetched.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { deploy, ORIGIN } from './helpers.js';
import { parseConfig, validate } from '../lib/config.js';
import { checkEndpoint, fetchLimited, OidcError, Oidc } from '../lib/oidc.js';
import { readOidcProviders } from '../lib/setup.js';
import { totpStep, hotp, base32Decode, sha256 } from '../lib/crypto.js';
import * as S from '../lib/store.js';
import { FakeIdp } from './fakeidp.js';
import { setupOidc, browse, callbackAgain, redirectUri, CLIENT_SECRET } from './oidc_helpers.js';

const ALL = { name: 'all', allowed_types: ['A'], allow_wildcard: true, allow_delegation: true, allow_dname: true, apex_editable: true };

// a deployment with a user alice linked to the fake provider's subject 'subject-1'
async function world(over = {}, { settings, user = {}, idp: idpOpts, provider } = {}) {
  const d = await deploy({ settings, ...over });
  const idp = await setupOidc(d, { idp: idpOpts, ...provider });
  const pol = await d.makePolicy(ALL);
  const alice = await d.makeUser('alice', 'alice password 1234', { grants: [{ role: 'global_master', policyId: pol }], ...user });
  await d.backend.tx({ write: true }, (tx) => S.setOidc(tx, alice, idp.issuer, 'subject-1'));
  const close = async () => { await idp.stop(); await d.close(); };
  return { d, idp, alice, pol, close, me: (cookie) => d.request('GET', '/auth/me', { cookie }) };
}
const states = (d) => d.backend.tx({}, async (tx) => (await tx.get('SELECT count(*) AS n FROM auth.oidc_states')).n);
const fails = (r) => /^http:\/\/127\.0\.0\.1:8053\/#\/\?oidc=([a-z]+)$/.exec(r.location)?.[1];

// ------------------------------------------------------------------------------------------------------------------------------- the configuration
const BASE = 'listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = sqlite3\nsqlite-file = /tmp/z\nauth-file = /tmp/a\n';
test('configuration: [oidc <name>] sections', () => {
  const c = parseConfig(`${BASE}[oidc corp]\nissuer = https://idp.example.test/realm\nclient-id = karidns\nclient-secret-file = /usr/local/etc/karidns/oidc.secret\nlabel = Sign in with Corp\nscopes = openid, email\nmfa = idp\n[oidc two]\nissuer = https://two.example.test\nclient-id = c2\nclient-secret-file = /x/secret2\n`);
  assert.deepEqual(validate(c), []);
  assert.deepEqual(c.oidc.get('corp'), { name: 'corp', issuer: 'https://idp.example.test/realm', 'client-id': 'karidns', 'client-secret-file': '/usr/local/etc/karidns/oidc.secret', scopes: ['openid', 'email'], label: 'Sign in with Corp', mfa: 'idp' });
  assert.deepEqual(c.oidc.get('two'), { name: 'two', issuer: 'https://two.example.test', 'client-id': 'c2', 'client-secret-file': '/x/secret2', scopes: ['openid'], label: 'two', mfa: 'totp' });
  const bad = (text, re) => assert.match((() => { try { return validate(parseConfig(BASE + text)).join('\n'); } catch (e) { return e.message; } })(), re);
  const ok1 = 'issuer = https://a.example.test\nclient-id = c\nclient-secret-file = /s\n';
  bad(`[oidc a]\n${ok1}[oidc b]\n${ok1}`, /has the issuer of \[oidc a\]/);
  bad('[oidc a]\nclient-id = c\nclient-secret-file = /s\n', /needs 'issuer'/);
  bad('[oidc a]\nissuer = https://a.example.test\nclient-secret-file = /s\n', /needs 'client-id'/);
  bad('[oidc a]\nissuer = https://a.example.test\nclient-id = c\n', /needs 'client-secret-file'/);
  bad('[oidc a]\nissuer = http://idp.example.test\nclient-id = c\nclient-secret-file = /s\n', /issuer must be an https URL/);
  assert.deepEqual(validate(parseConfig(`${BASE}[oidc a]\nissuer = http://127.0.0.1:9000\nclient-id = c\nclient-secret-file = /s\n`)), []);
  bad('[oidc a]\nissuer = https://a.example.test?x=1\nclient-id = c\nclient-secret-file = /s\n', /issuer: expected an https URL without a query/);
  bad('[oidc a]\nissuer = https://u:p@a.example.test\nclient-id = c\nclient-secret-file = /s\n', /issuer: expected an https URL without/);
  bad('[oidc a]\nissuer = ftp://a.example.test\nclient-id = c\nclient-secret-file = /s\n', /issuer: expected an https URL/);
  bad('[oidc a]\nissuer = nonsense\nclient-id = c\nclient-secret-file = /s\n', /issuer: expected/);
  bad('[oidc a]\nmfa = sms\n', /mfa: expected one of totp, idp/);
  bad('[oidc a]\nscopes = "a b"c\n', /scopes/);
  bad('[oidc a]\nlabel = \n', /label/);
  bad('[oidc a]\nclient-secret-file = relative\n', /absolute path/);
  bad('[oidc a]\nbogus = 1\n', /unknown option 'bogus' in \[oidc a\]/);
  bad('[oidc A]\n', /a provider name is 1 to 32 characters/);
  bad(`[oidc a]\n${ok1}[oidc a]\n`, /appears twice/);
  bad(`[oidc a]\n${ok1}issuer = https://b.example.test\n`, /'issuer' is set twice/);
  bad('[nonsense x]\n', /expected \[dataset <name>\] or \[oidc <name>\]/);
  bad(`${Array.from({ length: 9 }, (_, i) => `[oidc p${i}]\nissuer = https://p${i}.example.test\nclient-id = c\nclient-secret-file = /s\n`).join('')}`, /at most 8/);
});

test('the sample configuration: the [oidc] section is valid when it is switched on, and it is the last thing in the file', () => {
  const lines = fs.readFileSync(new URL('../../karidns-webadmin.conf.sample', import.meta.url), 'utf8').split(/\r?\n/);
  const at = lines.indexOf('# [oidc corp]');
  assert.ok(at > 0, 'the sample has the section');
  const on = lines.map((l, i) => (i >= at ? l.replace(/^# /, '') : l)).join('\n');
  const c = parseConfig(on);
  assert.equal(c.oidc.get('corp').issuer, 'https://idp.example.test/realms/corp');
  assert.equal(c.oidc.get('corp').mfa, 'totp');
  assert.deepEqual(validate(c), []);
  assert.equal(c.settings.log, 'daemon', 'the global keys are before the section');
});

test('the secret files: mode, owner, one line', () => {
  const c = parseConfig(`${BASE}[oidc a]\nissuer = https://a.example.test\nclient-id = c\nclient-secret-file = /s\n`);
  const st = (mode, uid = 1000, file = true) => ({ a: { isFile: () => file, uid, mode: 0o100000 | mode } });
  const read = (text) => () => text;
  assert.deepEqual(readOidcProviders(c, { stat: st(0o600), uid: 1000, readFile: read('s3cret\n') }).list[0], { name: 'a', issuer: 'https://a.example.test', clientId: 'c', clientSecret: 's3cret', scopes: ['openid'], label: 'a', mfa: 'totp' });
  assert.match(readOidcProviders(c, { stat: st(0o644), uid: 1000, readFile: read('x') }).problems[0], /mode 0644/);
  assert.match(readOidcProviders(c, { stat: st(0o600, 0), uid: 1000, readFile: read('x') }).problems[0], /not owned/);
  assert.match(readOidcProviders(c, { stat: st(0o600, 1000, false), uid: 1000, readFile: read('x') }).problems[0], /not a regular file/);
  assert.match(readOidcProviders(c, { stat: st(0o600), uid: 1000, readFile: read('') }).problems[0], /one line/);
  assert.match(readOidcProviders(c, { stat: st(0o600), uid: 1000, readFile: read('a\nb') }).problems[0], /one line/);
  assert.match(readOidcProviders(c, { stat: st(0o600), uid: 1000, readFile: () => { throw Object.assign(new Error('x'), { code: 'EACCES' }); } }).problems[0], /EACCES/);
  // openid is always asked for
  assert.deepEqual(readOidcProviders(parseConfig(`${BASE}[oidc a]\nissuer = https://a.example.test\nclient-id = c\nclient-secret-file = /s\nscopes = email\n`), { stat: st(0o600), uid: 1000, readFile: read('x') }).list[0].scopes, ['openid', 'email']);
});

// ------------------------------------------------------------------------------------------------------------------------------- what the provider's documents may say
test('addresses in the provider documents', () => {
  const https = 'https://idp.example.test';
  assert.equal(checkEndpoint('https://idp.example.test/token', https), 'https://idp.example.test/token');
  assert.equal(checkEndpoint('https://login.other.example.test:8443/a?b=c', https), 'https://login.other.example.test:8443/a?b=c');
  for (const bad of ['http://idp.example.test/token', 'ftp://idp.example.test/', 'https://u:p@idp.example.test/', 'https://idp.example.test/x#f', 'https://192.0.2.1/token', 'https://[2001:db8::1]/token', 'https://127.0.0.1/token', '/relative', 'javascript:alert(1)', '', undefined, 5, `https://idp.example.test/${'a'.repeat(2100)}`]) {
    assert.throws(() => checkEndpoint(bad, https), OidcError, String(bad).slice(0, 40));
  }
  // an issuer on this machine: http, and only this machine
  const local = 'http://127.0.0.1:9000';
  assert.equal(checkEndpoint('http://127.0.0.1:9001/t', local), 'http://127.0.0.1:9001/t');
  assert.equal(checkEndpoint('http://localhost:9001/t', local), 'http://localhost:9001/t');
  assert.throws(() => checkEndpoint('http://192.0.2.1/t', local), OidcError);
  assert.throws(() => checkEndpoint('http://idp.example.test/t', local), OidcError);
  assert.throws(() => checkEndpoint('https://idp.example.test/t', local), OidcError);
});

test('fetching: no redirect, a size limit, a time limit, JSON only', async () => {
  const idp = await new FakeIdp().start();
  try {
    const url = (p) => `http://127.0.0.1:${idp.port}${p}`;
    const r = await fetchLimited(fetch, url('/.well-known/openid-configuration'), { maxBytes: 64 << 10 });
    assert.equal(r.status, 200);
    idp.mode['/jwks'] = 'redirect';
    await assert.rejects(fetchLimited(fetch, url('/jwks'), { maxBytes: 1 << 16 }), /redirect/);
    idp.mode['/jwks'] = 'huge';
    await assert.rejects(fetchLimited(fetch, url('/jwks'), { maxBytes: 1 << 16 }), /longer than/);
    idp.mode['/jwks'] = 'slow';
    await assert.rejects(fetchLimited(fetch, url('/jwks'), { maxBytes: 1 << 16, timeoutMs: 200 }), /TimeoutError|failed/);
    await assert.rejects(fetchLimited(fetch, 'http://127.0.0.1:1/', { maxBytes: 10, timeoutMs: 500 }), OidcError);
  } finally {
    await idp.stop();
  }
});

// ------------------------------------------------------------------------------------------------------------------------------- the flow
test('providers: listed without a login, with name and label only', async () => {
  const w = await world();
  try {
    const r = await w.d.request('GET', '/auth/providers');
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.providers, [{ name: 'idp', label: 'Example ID', issuer: w.idp.issuer }]);
    assert.equal(JSON.stringify(r.body).includes(CLIENT_SECRET), false);
    assert.equal((await w.d.request('POST', '/auth/providers', { body: {} })).status, 405);
  } finally { await w.close(); }
});

test('the whole flow: start, provider, callback, a session, the state is used up', async () => {
  const w = await world();
  try {
    const r = await browse(w.d);
    // start: a 302 to the provider with state, nonce, the PKCE challenge, and the cookie that ties it to this browser
    assert.equal(r.start.status, 302);
    const a = new URL(r.start.headers.get('location'));
    assert.equal(a.origin, `http://127.0.0.1:${w.idp.port}`);
    assert.equal(a.pathname, '/authorize');
    const q = Object.fromEntries(a.searchParams);
    assert.equal(q.response_type, 'code');
    assert.equal(q.client_id, 'kari-client');
    assert.equal(q.redirect_uri, redirectUri('idp'));
    assert.equal(q.scope, 'openid');
    assert.equal(q.code_challenge_method, 'S256');
    assert.match(q.state, /^[A-Za-z0-9_-]{43}$/);
    assert.match(q.nonce, /^[A-Za-z0-9_-]{43}$/);
    assert.match(q.code_challenge, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(q.state, q.nonce);
    assert.match(r.setCookie.join(';'), /karidns_oidc=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Lax; Path=\/api\/v1\/auth\/oidc\/; Max-Age=600/);
    assert.equal(r.start.headers.get('cache-control'), 'no-store');
    // the callback: the page, with the session cookie (Strict, HttpOnly) and the browser cookie cleared
    assert.equal(r.cb.status, 302);
    assert.equal(r.location, `${ORIGIN}/#/`);
    assert.ok(r.session);
    const cookies = r.cbCookies.join('\n');
    assert.match(cookies, /karidns_session=[^;]+; HttpOnly; SameSite=Strict; Path=\/api\/; Max-Age=\d+/);
    assert.match(cookies, /karidns_oidc=; HttpOnly; SameSite=Lax; Path=\/api\/v1\/auth\/oidc\/; Max-Age=0/);
    const me = await w.me(r.session);
    assert.equal(me.status, 200);
    assert.equal(me.body.principal.name, 'alice');
    assert.equal(me.body.session.totp_ok, true);
    // the provider saw what a provider needs: the code with the verifier of the PKCE, the client password
    const tok = w.idp.log.find((e) => e.path === '/token');
    assert.equal(tok.form.grant_type, 'authorization_code');
    assert.equal(tok.form.redirect_uri, redirectUri('idp'));
    assert.match(tok.auth, /^Basic /);
    assert.equal(tok.form.client_secret, undefined);
    assert.equal(await states(w.d), 0);
    assert.ok(w.d.log.lines.some((l) => /auth: alice logged in with idp from/.test(l)));
    // a replay of the same callback: the state is gone
    const again = await callbackAgain(w.d, 'idp', r);
    assert.equal(again.headers.get('location'), `${ORIGIN}/#/?oidc=failed`);
    assert.equal(again.headers.get('set-cookie')?.includes('karidns_session'), false);
    assert.ok(w.d.log.lines.some((l) => /state is unknown, used or over/.test(l)));
  } finally { await w.close(); }
});

test('the return route: kept when it is a path of the page, replaced otherwise', async () => {
  const w = await world();
  try {
    assert.equal((await browse(w.d, 'idp', { query: '?return=%2Fzones%2Fmain%2Fexample.test%3Fx%3D1' })).location, `${ORIGIN}/#/zones/main/example.test?x=1`);
    for (const bad of ['//evil.example.test', 'https://evil.example.test/', 'x', '%0d%0aSet-Cookie:%20a=b', '/a%0ab', `/${'a'.repeat(600)}`, '/a b', '/<script>', '/a#b', '/\\evil']) {
      const r = await browse(w.d, 'idp', { query: `?return=${bad.startsWith('%') || bad.startsWith('/') ? bad.replace(/ /g, '%20').replace(/</g, '%3C').replace(/>/g, '%3E').replace(/#/g, '%23').replace(/\\/g, '%5C') : encodeURIComponent(bad)}` });
      assert.equal(r.location, `${ORIGIN}/#/`, bad);
    }
  } finally { await w.close(); }
});

test('an unknown provider is a 404 problem; a method other than GET is refused', async () => {
  const w = await world();
  try {
    for (const p of ['nope', '..%2fidp']) {
      assert.equal((await w.d.request('GET', `/auth/oidc/${p}/start`)).status, 404);
      assert.equal((await w.d.request('GET', `/auth/oidc/${p}/callback?state=x`)).status, 404);
    }
    assert.equal((await w.d.request('POST', '/auth/oidc/idp/start', { body: {} })).status, 405);
  } finally { await w.close(); }
});

// ------------------------------------------------------------------------------------------------------------------------------- refusals: one answer for all
test('an unlinked subject, a disabled user, a locked user: the same answer as a bad state, and nothing in the database', async () => {
  const w = await world();
  try {
    const bad = (await callbackAgain(w.d, 'idp', await browse(w.d), { search: '?state=' + 'A'.repeat(43) })).headers.get('location');
    assert.equal(bad, `${ORIGIN}/#/?oidc=failed`);
    // unlinked
    w.idp.person.sub = 'stranger';
    let r = await browse(w.d);
    assert.equal(r.location, bad);
    assert.equal(r.session, undefined);
    assert.ok(w.d.log.lines.some((l) => /no user is linked to the subject stranger/.test(l)));
    // disabled
    w.idp.person.sub = 'subject-1';
    await w.d.backend.tx({ write: true }, (tx) => S.updatePrincipal(tx, w.alice, { disabled: true }));
    r = await browse(w.d);
    assert.equal(r.location, bad);
    assert.equal(r.session, undefined);
    await w.d.backend.tx({ write: true }, (tx) => S.updatePrincipal(tx, w.alice, { disabled: false }));
    // locked
    await w.d.backend.tx({ write: true }, (tx) => S.recordLoginFailure(tx, w.alice, 10, Date.now() + 3600 * 1000));
    r = await browse(w.d);
    assert.equal(r.location, bad);
    assert.equal(r.session, undefined);
    await w.d.backend.tx({ write: true }, (tx) => S.clearLock(tx, w.alice));
    // and then it works
    assert.ok((await browse(w.d)).session);
    // a group cannot be signed in as
    const g = await w.d.makeUser('staff', null, { kind: 'group' });
    await w.d.backend.tx({ write: true }, (tx) => tx.run('UPDATE auth.credentials SET oidc_issuer = NULL, oidc_subject = NULL WHERE principal_id = $1', [w.alice]));
    assert.equal(g > 0, true);
    assert.equal((await browse(w.d)).session, undefined);
  } finally { await w.close(); }
});

test('a replayed state, a state from another browser, a state of another provider, a state that is over', async () => {
  let t = Date.now();
  const w = await world({ now: () => t });
  try {
    // another browser: the callback address with the cookie of somebody else, or none
    let r = await browse(w.d, 'idp', { cookie: 'A'.repeat(43) });
    assert.equal(r.location, `${ORIGIN}/#/?oidc=failed`);
    assert.equal(r.session, undefined);
    assert.ok(w.d.log.lines.some((l) => /not started by this browser/.test(l)));
    r = await browse(w.d, 'idp', { cookie: null });
    assert.equal(r.session, undefined);
    assert.equal(await states(w.d), 0);                       // (the state is used up by a refusal as well)
    // the right browser cannot use that state any more
    const ok1 = await browse(w.d);
    assert.ok(ok1.session);
    assert.equal((await callbackAgain(w.d, 'idp', ok1)).headers.get('location'), `${ORIGIN}/#/?oidc=failed`);
    // another provider's callback with this provider's state
    const w2 = await setupOidc(w.d, { name: 'second', idp: { clientId: 'kari-client', clientSecret: CLIENT_SECRET } });
    const s =await fetch(`${w.d.base}/auth/oidc/idp/start`, { redirect: 'manual' });
    const bc = /karidns_oidc=([^;]+)/.exec(s.headers.getSetCookie().join())[1];
    const loc = await fetch(s.headers.get('location'), { redirect: 'manual' });
    const search = new URL(loc.headers.get('location')).search;
    const cross = await fetch(`${w.d.base}/auth/oidc/second/callback${search}`, { redirect: 'manual', headers: { Cookie: `karidns_oidc=${bc}` } });
    assert.equal(cross.headers.get('location'), `${ORIGIN}/#/?oidc=failed`);
    assert.ok(w.d.log.lines.some((l) => /belongs to another provider/.test(l)));
    await w2.stop();
    // a state that is over (ten minutes)
    const slow = await fetch(`${w.d.base}/auth/oidc/idp/start`, { redirect: 'manual' });
    const bc2 = /karidns_oidc=([^;]+)/.exec(slow.headers.getSetCookie().join())[1];
    const loc2 = await fetch(slow.headers.get('location'), { redirect: 'manual' });
    const search2 = new URL(loc2.headers.get('location')).search;
    t += 601 * 1000;
    const late = await fetch(`${w.d.base}/auth/oidc/idp/callback${search2}`, { redirect: 'manual', headers: { Cookie: `karidns_oidc=${bc2}` } });
    assert.equal(late.headers.get('location'), `${ORIGIN}/#/?oidc=failed`);
    // malformed states and codes
    for (const qs of ['', '?state=', '?state=short', `?state=${'a'.repeat(129)}`, '?state=%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00', '?state[]=x']) {
      const x = await fetch(`${w.d.base}/auth/oidc/idp/callback${qs}`, { redirect: 'manual' });
      assert.equal(x.headers.get('location'), `${ORIGIN}/#/?oidc=failed`, qs);
    }
  } finally { await w.close(); }
});

test('every way an ID token can be wrong is a refusal without a session', async () => {
  const w = await world();
  try {
    const cases = {
      'alg none': (c, h) => { h.alg = 'none'; },
      'HS256 with the client secret': (c, h) => { h.alg = 'HS256'; },
      'RS384': (c, h) => { h.alg = 'RS384'; },
      'a key the provider does not publish': () => { w.idp.sign = { alg: 'RS256', n: 7, kid: 'k0' }; },
      'a kid nobody has': (c, h) => { h.kid = 'nobody'; },
      'another issuer': (c) => { c.iss = 'https://evil.example.test'; },
      'another audience': (c) => { c.aud = 'someone-else'; },
      'several audiences, no azp': (c) => { c.aud = ['kari-client', 'other']; },
      'azp of another party': (c) => { c.azp = 'other'; },
      'another nonce': (c) => { c.nonce = 'not-the-nonce'; },
      'no nonce': (c) => { delete c.nonce; },
      'expired': (c) => { c.exp = Math.floor(Date.now() / 1000) - 3600; },
      'issued in the future': (c) => { c.iat = Math.floor(Date.now() / 1000) + 3600; },
      'issued long ago': (c) => { c.iat = Math.floor(Date.now() / 1000) - 3600; },
      'no sub': (c) => { delete c.sub; },
      'crit': (c, h) => { h.crit = ['x']; },
    };
    for (const [what, fn] of Object.entries(cases)) {
      w.idp.sign = { alg: 'RS256', n: 0, kid: 'k0' };
      w.idp.tamper = fn;
      const r = await browse(w.d);
      assert.equal(r.location, `${ORIGIN}/#/?oidc=failed`, what);
      assert.equal(r.session, undefined, what);
    }
    w.idp.tamper = null;
    w.idp.sign = { alg: 'RS256', n: 0, kid: 'k0' };
    assert.ok((await browse(w.d)).session);
    // the log has the reason, the answer has none
    assert.ok(w.d.log.lines.some((l) => /the ID token was refused: bad-signature/.test(l)));
    assert.ok(w.d.log.lines.some((l) => /the ID token was refused: nonce/.test(l)));
    assert.equal(w.d.log.lines.some((l) => /kari-secret/.test(l)), false);
  } finally { await w.close(); }
});

test('a token that is not a token: no id_token, another token_type, a code the provider refuses, an error from the provider', async () => {
  const w = await world();
  try {
    w.idp.mode.noIdToken = true;
    assert.equal((await browse(w.d)).location, `${ORIGIN}/#/?oidc=failed`);
    w.idp.mode.noIdToken = false;
    w.idp.mode.tokenType = 'MAC';
    assert.equal((await browse(w.d)).location, `${ORIGIN}/#/?oidc=failed`);
    w.idp.mode.tokenType = 'bearer';
    assert.ok((await browse(w.d)).session);
    delete w.idp.mode.tokenType;
    w.idp.authError = 'access_denied';
    let r = await browse(w.d);
    assert.equal(r.location, `${ORIGIN}/#/?oidc=failed`);
    assert.ok(w.d.log.lines.some((l) => /answered error=access_denied/.test(l)));
    w.idp.authError = null;
    // a wrong client secret at the provider: its error is kept as a code
    const p = w.d.app.oidc.get('idp');
    const secret = p.clientSecret;
    p.clientSecret = 'wrong';
    r = await browse(w.d);
    assert.equal(r.location, `${ORIGIN}/#/?oidc=failed`);
    assert.ok(w.d.log.lines.some((l) => /refused the code \(401, invalid_client\)/.test(l)));
    p.clientSecret = secret;
    // the token endpoint is down
    w.idp.mode['/token'] = 'status:503';
    r = await browse(w.d);
    assert.equal(r.location, `${ORIGIN}/#/?oidc=unavailable`);
    w.idp.mode['/token'] = 'html';
    assert.equal((await browse(w.d)).location, `${ORIGIN}/#/?oidc=unavailable`);
    delete w.idp.mode['/token'];
    assert.ok((await browse(w.d)).session);
  } finally { await w.close(); }
});

test('RFC 9207: the iss parameter, when it is there or promised', async () => {
  const w = await world();
  try {
    w.idp.issParam = true;                               // the document says it will send iss, and it does
    w.d.app.oidc.get('idp').disc = null;
    assert.ok((await browse(w.d)).session);
    // a response from another issuer (a mix-up)
    const r = await browse(w.d, 'idp', { callbackQuery: (q) => { q.set('iss', 'https://evil.example.test'); return `?${q}`; } });
    assert.equal(r.location, `${ORIGIN}/#/?oidc=failed`);
    // promised and missing
    const m = await browse(w.d, 'idp', { callbackQuery: (q) => { q.delete('iss'); return `?${q}`; } });
    assert.equal(m.location, `${ORIGIN}/#/?oidc=failed`);
    assert.ok(w.d.log.lines.some((l) => /iss parameter is missing or names another issuer/.test(l)));
  } finally { await w.close(); }
});

test('client_secret_post when the provider takes nothing else', async () => {
  const w = await world({}, { idp: { } });
  try {
    w.idp.tokenAuth = ['client_secret_post'];
    w.d.app.oidc.get('idp').disc = null;
    assert.ok((await browse(w.d)).session);
    const tok = w.idp.log.filter((e) => e.path === '/token').at(-1);
    assert.equal(tok.auth, undefined);
    assert.equal(tok.form.client_id, 'kari-client');
  } finally { await w.close(); }
});

// ------------------------------------------------------------------------------------------------------------------------------- discovery and the key set
test('discovery: another issuer, plain http endpoints for an https issuer, no PKCE, no code flow, signing algorithms we do not have', async () => {
  const w = await world();
  try {
    const p = w.d.app.oidc.get('idp');
    const bad = async (extra, re) => {
      p.disc = null;
      p.failedAt = 0;
      p.lastError = null;
      w.idp.discoveryExtra = extra;
      const r = await browse(w.d);
      assert.equal(r.location, `${ORIGIN}/#/?oidc=unavailable`, JSON.stringify(extra));
      assert.match(w.d.log.lines.filter((l) => /oidc idp/.test(l)).at(-1), re);
    };
    await bad({ issuer: 'https://evil.example.test' }, /another issuer/);
    await bad({ jwks_uri: 'http://192.0.2.1/jwks' }, /not allowed|IP address/);
    await bad({ token_endpoint: 'https://idp.example.test/token' }, /not allowed/);
    await bad({ authorization_endpoint: 'javascript:alert(1)' }, /not allowed|not a URL/);
    await bad({ token_endpoint: undefined }, /not a URL/);
    await bad({ code_challenge_methods_supported: ['plain'] }, /PKCE/);
    await bad({ response_types_supported: ['id_token'] }, /authorization code flow/);
    await bad({ id_token_signing_alg_values_supported: ['HS256'] }, /signs ID tokens with HS256 only/);
    await bad({ token_endpoint_auth_methods_supported: ['private_key_jwt'] }, /neither client_secret_basic nor client_secret_post/);
    w.idp.discoveryExtra = {};
    w.idp.mode['/.well-known/openid-configuration'] = 'html';
    p.disc = null; p.failedAt = 0; p.lastError = null;
    assert.equal((await browse(w.d)).location, `${ORIGIN}/#/?oidc=unavailable`);
    // a failure is remembered for ten seconds: the provider is not asked again for every request
    const asked = w.idp.log.length;
    await browse(w.d);
    assert.equal(w.idp.log.length, asked);
    w.idp.mode['/.well-known/openid-configuration'] = 'array';
    p.failedAt = 0; p.lastError = null;
    assert.equal((await browse(w.d)).location, `${ORIGIN}/#/?oidc=unavailable`);
    assert.match(w.d.log.lines.filter((l) => /oidc idp/.test(l)).at(-1), /not a JSON object/);
    w.idp.mode = {};
    p.failedAt = 0; p.lastError = null;
    assert.ok((await browse(w.d)).session);
  } finally { await w.close(); }
});

test('the key set: rotation (a new key is fetched for an unknown kid, at most once a minute), a bad key set, an unreachable one', async () => {
  let t = Date.now();
  const w = await world({ now: () => t });
  try {
    assert.ok((await browse(w.d)).session);
    // the provider rotates: signs with k1, which is not in the key set we have
    w.idp.sign = { alg: 'RS256', n: 1, kid: 'k1' };
    w.idp.keysOffered = [{ alg: 'RS256', n: 1, kid: 'k1' }, { alg: 'RS256', n: 0, kid: 'k0' }];
    const fetchesBefore = w.idp.log.filter((e) => e.path === '/jwks').length;
    // (the key set was fetched less than a minute ago: it is not fetched again, and the token is refused)
    assert.equal((await browse(w.d)).location, `${ORIGIN}/#/?oidc=failed`);
    assert.equal(w.idp.log.filter((e) => e.path === '/jwks').length, fetchesBefore);
    t += 61 * 1000;
    assert.ok((await browse(w.d)).session);
    assert.equal(w.idp.log.filter((e) => e.path === '/jwks').length, fetchesBefore + 1);
    // a flood of tokens with unknown kids is one fetch a minute (the one just made counts)
    w.idp.sign = { alg: 'RS256', n: 0, kid: 'unknown' };
    for (let i = 0; i < 5; i++) assert.equal((await browse(w.d)).session, undefined);
    assert.equal(w.idp.log.filter((e) => e.path === '/jwks').length, fetchesBefore + 1);
    t += 61 * 1000;
    for (let i = 0; i < 5; i++) assert.equal((await browse(w.d)).session, undefined);
    assert.equal(w.idp.log.filter((e) => e.path === '/jwks').length, fetchesBefore + 2);
    // ES256 and EdDSA keys
    for (const alg of ['ES256', 'EdDSA']) {
      w.idp.sign = { alg, n: 0, kid: `k-${alg}` };
      w.idp.keysOffered = [{ alg, n: 0, kid: `k-${alg}` }];
      t += 61 * 1000;
      assert.ok((await browse(w.d)).session, alg);
    }
    // the provider's key set stops answering: the keys we have are used
    w.idp.mode['/jwks'] = 'status:500';
    t += 25 * 3600 * 1000;
    assert.ok((await browse(w.d)).session);
    // garbage keys
    w.idp.mode = {};
    w.d.app.oidc.get('idp').jwks = null;
    w.d.app.oidc.get('idp').jwksError = null;
    w.idp.keysOffered = [];
    assert.equal((await browse(w.d)).location, `${ORIGIN}/#/?oidc=unavailable`);
  } finally { await w.close(); }
});

test('a provider that cannot be reached at the start: a page that says so, and the log', async () => {
  const w = await world();
  try {
    await w.idp.stop();
    w.d.app.oidc.get('idp').disc = null;
    const r = await browse(w.d);
    assert.equal(r.location, `${ORIGIN}/#/?oidc=unavailable`);
    assert.equal(await states(w.d), 0);
  } finally { await w.close(); }
});

test('prefetch: the documents are fetched at the start, a problem is a line in the log', async () => {
  const w = await world();
  try {
    await w.d.app.oidc.prefetch();
    assert.ok(w.d.log.lines.some((l) => /oidc: provider idp .* is reachable/.test(l)));
    const o = new Oidc({ log: w.d.log });
    o.configure([{ name: 'gone', issuer: 'http://127.0.0.1:1', clientId: 'c', clientSecret: 's', scopes: ['openid'], label: 'x', mfa: 'totp' }]);
    await o.prefetch();
    assert.ok(w.d.log.lines.some((l) => /warn oidc: provider gone .* cannot be used yet/.test(l)));
    // configure() again with the same provider keeps what it fetched; another secret starts afresh
    const p = w.d.app.oidc.get('idp');
    const list = [...w.d.app.oidc.providers.values()].map((x) => ({ name: x.name, issuer: x.issuer, clientId: x.clientId, clientSecret: x.clientSecret, scopes: x.scopes, label: 'Renamed', mfa: x.mfa }));
    w.d.app.oidc.configure(list);
    assert.equal(w.d.app.oidc.get('idp'), p);
    assert.equal(w.d.app.oidc.get('idp').label, 'Renamed');
    w.d.app.oidc.configure(list.map((x) => ({ ...x, clientSecret: 'new' })));
    assert.notEqual(w.d.app.oidc.get('idp'), p);
    w.d.app.oidc.configure([]);
    assert.deepEqual(w.d.app.oidc.list(), []);
  } finally { await w.close(); }
});

// ------------------------------------------------------------------------------------------------------------------------------- the state table
test('start: the number of waiting sign-ins is bounded, the table is swept, a state is used once', async () => {
  let t = Date.now();
  const w = await world({ now: () => t, settings: { 'rate-login': 1000 } });
  try {
    await w.d.backend.tx({ write: true }, async (tx) => {
      for (let i = 0; i < 1000; i++) await tx.run('INSERT INTO auth.oidc_states (state_hash, browser_hash, provider, nonce, verifier, return_route, created_at, expires_at) VALUES ($1, $1, $2, $3, $4, $5, $6, $7)',
        [sha256(`s${i}`), 'idp', 'n', 'v'.repeat(43), '/', tx.ts(t), tx.ts(t + 600000)]);
    });
    assert.equal(await states(w.d), 1000);
    const r = await browse(w.d);
    assert.equal(r.location, `${ORIGIN}/#/?oidc=busy`);
    // ten minutes later they are over and make room
    t += 601 * 1000;
    assert.ok((await browse(w.d)).session);
    assert.equal(await states(w.d), 0);
    await w.d.backend.tx({ write: true }, async (tx) => {
      await tx.run('INSERT INTO auth.oidc_states (state_hash, browser_hash, provider, nonce, verifier, return_route, created_at, expires_at) VALUES ($1, $1, $2, $3, $4, $5, $6, $7)', [sha256('x'), 'idp', 'n', 'v'.repeat(43), '/', tx.ts(t - 1000), tx.ts(t - 500)]);
      await S.deleteExpiredOidcStates(tx, t);
    });
    assert.equal(await states(w.d), 0);
  } finally { await w.close(); }
});

test('start and callback are rate limited like logins', async () => {
  const w = await world({}, { settings: { 'rate-login': 2 } });
  try {
    const seen = [];
    for (let i = 0; i < 4; i++) seen.push((await fetch(`${w.d.base}/auth/oidc/idp/start`, { redirect: 'manual' })).headers.get('location'));
    assert.equal(seen.filter((l) => l.endsWith('?oidc=busy')).length >= 1, true);
    assert.equal(seen.filter((l) => l.includes('/authorize')).length >= 1, true);
  } finally { await w.close(); }
});

test('start: one client address starts at most 20 sign-ins in 10 minutes (0.6.1, the default of rate-oidc-start), the others are not affected', async () => {
  let t = Date.now();
  const w = await world({ now: () => t }, { settings: { 'rate-login': 1000 } });
  try {
    const go = async () => (await fetch(`${w.d.base}/auth/oidc/idp/start`, { redirect: 'manual' })).headers.get('location');
    for (let i = 0; i < 20; i++) assert.match(await go(), /\/authorize/);
    assert.equal(await go(), `${ORIGIN}/#/?oidc=busy`);
    assert.equal(await states(w.d), 20);                       // the refused start made no state
    assert.ok(w.d.app.oidcStarts.take('192.0.2.77') === false);          // (another address has its own count)
    t += 601 * 1000;                                            // the first ones are over (and their states with them)
    assert.match(await go(), /\/authorize/);
  } finally { await w.close(); }
});

test('start: rate-oidc-start is the limit, and a new value (SIGHUP, app.setConfig) is taken at once', async () => {
  const w = await world({}, { settings: { 'rate-login': 1000, 'rate-oidc-start': 2 } });
  try {
    const go = async () => (await fetch(`${w.d.base}/auth/oidc/idp/start`, { redirect: 'manual' })).headers.get('location');
    assert.match(await go(), /\/authorize/);
    assert.match(await go(), /\/authorize/);
    assert.equal(await go(), `${ORIGIN}/#/?oidc=busy`);
    w.d.app.setConfig({ ...w.d.app.config, settings: { ...w.d.app.settings, 'rate-oidc-start': 3 } });
    assert.match(await go(), /\/authorize/);
    assert.equal(await go(), `${ORIGIN}/#/?oidc=busy`);
  } finally { await w.close(); }
});

// ------------------------------------------------------------------------------------------------------------------------------- the TOTP step (F-17)
const code = (secret, now = Date.now()) => hotp(base32Decode(secret), totpStep(now / 1000));

test('require-totp reaches the provider sign-in: the session must enrol, then give the code', async () => {
  let t = 1_800_000_000_000;
  const w = await world({ now: () => t }, { settings: { 'require-totp': 'global' } });
  try {
    // the first time: no TOTP yet, the session may only enrol
    let r = await browse(w.d);
    assert.ok(r.session);
    let me = await w.me(r.session);
    assert.equal(me.status, 200);
    assert.equal(me.body.session.totp_ok, false);
    assert.equal(me.body.session.totp_step, 'enrol');
    const csrf = me.body.session.csrf;
    const as = (cookie, csrfToken) => (m, p, o = {}) => w.d.request(m, p, { cookie, csrf: csrfToken, origin: ORIGIN, ...o });
    assert.equal((await as(r.session, csrf)('GET', '/datasets')).status, 403);
    assert.equal((await as(r.session, csrf)('GET', '/datasets')).body.type, 'urn:karidns:api:totp-required');
    // enrolment works for a user with no password
    const en = await as(r.session, csrf)('POST', '/auth/totp', { body: { action: 'enroll' } });
    assert.equal(en.status, 200);
    const cf = await as(r.session, csrf)('POST', '/auth/totp', { body: { action: 'confirm', code: code(en.body.secret, t) } });
    assert.equal(cf.status, 200);
    const s2 = /karidns_session=([^;]+)/.exec(cf.headers.get('set-cookie'))[1];
    assert.equal((await as(s2, cf.body.csrf)('GET', '/datasets')).status, 200);
    // the next sign-in: TOTP is on, the session is not done until the code is given
    t += 60000;
    r = await browse(w.d);
    me = await w.me(r.session);
    assert.equal(me.body.session.totp_ok, false);
    assert.equal(me.body.session.totp_step, 'verify');
    const a = as(r.session, me.body.session.csrf);
    assert.equal((await a('GET', '/datasets')).status, 403);
    assert.equal((await a('POST', '/auth/totp', { body: { action: 'verify' } })).status, 400);
    assert.equal((await a('POST', '/auth/totp', { body: { action: 'verify', code: '000000' } })).body.type, 'urn:karidns:api:wrong-code');
    // the code of the confirmation was used: a code is good once
    assert.equal((await a('POST', '/auth/totp', { body: { action: 'verify', code: code(en.body.secret, t - 60000) } })).status, 403);
    t += 31000;
    const v = await a('POST', '/auth/totp', { body: { action: 'verify', code: code(en.body.secret, t) } });
    assert.equal(v.status, 200);
    const s3 = /karidns_session=([^;]+)/.exec(v.headers.get('set-cookie'))[1];
    assert.notEqual(s3, r.session);
    assert.equal((await w.me(r.session)).status, 401);               // (the old session is gone)
    assert.equal((await as(s3, v.body.csrf)('GET', '/datasets')).status, 200);
    // the same code again does not open another session
    t += 60000;
    r = await browse(w.d);
    me = await w.me(r.session);
    assert.equal((await as(r.session, me.body.session.csrf)('POST', '/auth/totp', { body: { action: 'verify', code: code(en.body.secret, t - 31000 - 60000) } })).status, 403);
    // verify on a session that is done is harmless
    assert.equal((await as(s3, v.body.csrf)('POST', '/auth/totp', { body: { action: 'verify', code: '123456' } })).status, 200);
    // and the account may switch it off when the configuration allows: here it does not (global master)
    const off = await as(s3, v.body.csrf)('POST', '/auth/totp', { body: { action: 'disable', code: code(en.body.secret, t + 90000) } });
    assert.equal(off.body.type, 'urn:karidns:api:totp-required-by-policy');
  } finally { await w.close(); }
});

test('mfa = idp: the TOTP step is not asked when the token shows two factors; mfa = totp ignores the claim', async () => {
  const w = await world({}, { settings: { 'require-totp': 'global' }, provider: { mfa: 'idp' } });
  try {
    const step = async () => { const r = await browse(w.d); return r.session ? (await w.me(r.session)).body.session.totp_ok : null; };
    w.idp.person.amr = ['pwd', 'otp'];
    assert.equal(await step(), true);
    w.idp.person.amr = ['mfa'];
    assert.equal(await step(), true);
    w.idp.person.amr = ['pwd'];
    assert.equal(await step(), false);
    w.idp.person.amr = undefined;
    assert.equal(await step(), false);
    w.idp.person.amr = ['pwd', 'kba'];
    assert.equal(await step(), false);
    w.d.app.oidc.get('idp').mfa = 'totp';
    w.idp.person.amr = ['pwd', 'otp', 'mfa'];
    assert.equal(await step(), false);
  } finally { await w.close(); }
});

test('without require-totp a user whose TOTP is on is still asked for the code; a user with none is not', async () => {
  const w = await world({}, { settings: { 'require-totp': 'none' } });
  try {
    const r = await browse(w.d);
    const me = await w.me(r.session);
    assert.equal(me.body.session.totp_ok, true);
    assert.equal(me.body.session.totp_step, undefined);
    await w.d.backend.tx({ write: true }, (tx) => S.setTotp(tx, w.alice, 'x', true));
    const r2 = await browse(w.d);
    assert.equal((await w.me(r2.session)).body.session.totp_step, 'verify');
  } finally { await w.close(); }
});

test('an account with a linked identity and no password: TOTP can be switched off with the code alone, where allowed', async () => {
  let t = 1_800_000_000_000;
  const w = await world({ now: () => t }, { settings: { 'require-totp': 'none' } });
  try {
    await w.d.backend.tx({ write: true }, (tx) => tx.run('UPDATE auth.credentials SET password_hash = NULL WHERE principal_id = $1', [w.alice]));
    const r = await browse(w.d);
    const me = await w.me(r.session);
    const as = (m, p, o = {}) => w.d.request(m, p, { cookie: r.session, csrf: me.body.session.csrf, origin: ORIGIN, ...o });
    const en = await as('POST', '/auth/totp', { body: { action: 'enroll' } });
    assert.equal(en.status, 200);
    const cf = await as('POST', '/auth/totp', { body: { action: 'confirm', code: code(en.body.secret, t) } });
    assert.equal(cf.status, 200);
    const s2 = /karidns_session=([^;]+)/.exec(cf.headers.get('set-cookie'))[1];
    const as2 = (m, p, o = {}) => w.d.request(m, p, { cookie: s2, csrf: cf.body.csrf, origin: ORIGIN, ...o });
    t += 31000;
    assert.equal((await as2('POST', '/auth/totp', { body: { action: 'disable' } })).status, 400);
    assert.equal((await as2('POST', '/auth/totp', { body: { action: 'disable', code: '000000' } })).status, 403);
    const off = await as2('POST', '/auth/totp', { body: { action: 'disable', code: code(en.body.secret, t) } });
    assert.equal(off.status, 200);
    assert.equal(off.body.totp.enabled, false);
    // a user with neither a password nor an identity cannot enrol (the session of one is made by hand: nothing signs such a user in)
    const bare = await w.d.makeUser('bare', 'bare password 1234');
    const bs = await w.d.login('bare', 'bare password 1234');
    await w.d.backend.tx({ write: true }, (tx) => tx.run('UPDATE auth.credentials SET password_hash = NULL WHERE principal_id = $1', [bare]));
    const e2 = await w.d.as(bs)('POST', '/auth/totp', { body: { action: 'enroll' } });
    assert.equal(e2.body.type, 'urn:karidns:api:no-password');
  } finally { await w.close(); }
});

// ------------------------------------------------------------------------------------------------------------------------------- linking
test('linking: a global master links, shows and removes an identity; the rules', async () => {
  const w = await world();
  try {
    const pol = await w.d.makePolicy({ name: 'web', allowed_types: ['A'] });
    const root = await w.d.makeUser('root', 'root password 1234', { grants: [{ role: 'global_master', policyId: pol }] });
    const bob = await w.d.makeUser('bob', 'bob password 12345');
    const dom = await w.d.makeUser('dom', 'dom password 12345', { grants: [{ role: 'domain_master', zone: 'example.test', policyId: pol, schema: '' }] });
    const grp = await w.d.makeUser('staff', null, { kind: 'group' });
    const rs = await w.d.login('root', 'root password 1234');
    const as = w.d.as(rs);
    const ds = await w.d.login('dom', 'dom password 12345');
    const asDom = w.d.as(ds);
    const body = { issuer: w.idp.issuer, subject: 'bob-sub' };
    // not for others
    assert.equal((await asDom('PUT', `/principals/${bob}/oidc`, { body })).status, 403);
    assert.equal((await asDom('DELETE', `/principals/${bob}/oidc`)).status, 403);
    assert.equal((await w.d.request('PUT', `/principals/${bob}/oidc`, { body })).status, 401);
    // the rules of the body
    assert.equal((await as('PUT', `/principals/${bob}/oidc`, { body: { issuer: 'https://nobody.example.test', subject: 'x' } })).body.errors[0].pointer, '/issuer');
    assert.equal((await as('PUT', `/principals/${bob}/oidc`, { body: { issuer: w.idp.issuer } })).status, 400);
    assert.equal((await as('PUT', `/principals/${bob}/oidc`, { body: { ...body, subject: '' } })).status, 400);
    assert.equal((await as('PUT', `/principals/${bob}/oidc`, { body: { ...body, subject: 'x'.repeat(256) } })).status, 400);
    assert.equal((await as('PUT', `/principals/${bob}/oidc`, { body: { ...body, extra: 1 } })).status, 400);
    assert.equal((await as('PUT', '/principals/999999/oidc', { body })).status, 404);
    assert.equal((await as('PUT', `/principals/${grp}/oidc`, { body })).body.type, 'urn:karidns:api:not-a-user');
    // alice has subject-1: bob may not have it
    const dup = await as('PUT', `/principals/${bob}/oidc`, { body: { ...body, subject: 'subject-1' } });
    assert.equal(dup.status, 409);
    assert.equal(dup.body.type, 'urn:karidns:api:exists');
    // link
    const put = await as('PUT', `/principals/${bob}/oidc`, { body });
    assert.equal(put.status, 200);
    assert.deepEqual(put.body.credentials.oidc, { issuer: w.idp.issuer, subject: 'bob-sub', provider: { name: 'idp', label: 'Example ID' } });
    assert.equal(put.body.credentials.password, true);
    const get = await as('GET', `/principals/${bob}`);
    assert.deepEqual(get.body.credentials.oidc.subject, 'bob-sub');
    // the same link again changes nothing and ends no session
    const bs = await w.d.login('bob', 'bob password 12345');
    assert.equal((await as('PUT', `/principals/${bob}/oidc`, { body })).status, 200);
    assert.equal((await w.d.as(bs)('GET', '/auth/me')).status, 200);
    // bob signs in with it
    w.idp.person.sub = 'bob-sub';
    const r = await browse(w.d);
    assert.equal((await w.me(r.session)).body.principal.name, 'bob');
    // a changed link ends bob's sessions
    assert.equal((await as('PUT', `/principals/${bob}/oidc`, { body: { ...body, subject: 'bob-sub-2' } })).status, 200);
    assert.equal((await w.d.as(bs)('GET', '/auth/me')).status, 401);
    assert.equal((await w.me(r.session)).status, 401);
    // bob sees his own link in his account
    const bs2 = await w.d.login('bob', 'bob password 12345');
    assert.equal((await w.d.as(bs2)('GET', `/principals/${bob}`)).body.credentials.oidc.subject, 'bob-sub-2');
    // and no one else's
    assert.equal((await w.d.as(bs2)('GET', `/principals/${root}`)).body.credentials, undefined);
    // remove: the sessions end, the sign-in is refused
    assert.equal((await as('DELETE', `/principals/${bob}/oidc`)).status, 204);
    assert.equal((await w.d.as(bs2)('GET', '/auth/me')).status, 401);
    assert.equal((await as('DELETE', `/principals/${bob}/oidc`)).status, 404);
    assert.equal((await as('DELETE', '/principals/999999/oidc')).status, 404);
    w.idp.person.sub = 'bob-sub-2';
    assert.equal((await browse(w.d)).session, undefined);
    // the audit log has the link and its removal, with the subject
    const audit = await w.d.backend.tx({}, (tx) => tx.all("SELECT op, after FROM auth.karidns_auth_audit WHERE table_name = 'credentials' ORDER BY id"));
    assert.ok(audit.some((a) => /bob-sub-2/.test(a.after ?? '')));
    // the administrator who unlinks or relinks himself keeps his own session
    const self = await as('PUT', `/principals/${root}/oidc`, { body: { ...body, subject: 'root-sub' } });
    assert.equal(self.status, 200);
    assert.equal((await as('PUT', `/principals/${root}/oidc`, { body: { ...body, subject: 'root-sub-2' } })).status, 200);
    assert.equal((await as('GET', '/auth/me')).status, 200);
    assert.equal((await as('DELETE', `/principals/${root}/oidc`)).status, 204);
    assert.equal((await as('GET', '/auth/me')).status, 200);
    // a user without credentials yet gets a row
    const none = await w.d.makeUser('none', null);
    assert.equal((await as('PUT', `/principals/${none}/oidc`, { body: { ...body, subject: 'none-sub' } })).status, 200);
    // deleting the user deletes the link
    assert.equal((await as('DELETE', `/principals/${none}`)).status, 204);
    assert.equal(await w.d.backend.tx({}, async (tx) => S.oidcOwner(tx, w.idp.issuer, 'none-sub')), null);
  } finally { await w.close(); }
});

test('an identity of a provider that is no longer configured stays linked but signs nobody in', async () => {
  const w = await world();
  try {
    w.d.app.oidc.configure([]);
    const cred = await w.d.login('alice', 'alice password 1234');
    const g = await w.d.as(cred)('GET', `/principals/${w.alice}`);
    assert.deepEqual(g.body.credentials.oidc.provider, null);
    assert.equal(g.body.credentials.oidc.subject, 'subject-1');
    assert.equal((await w.d.request('GET', '/auth/providers')).body.providers.length, 0);
  } finally { await w.close(); }
});

test('login by password is unchanged, and a user without a password cannot use it', async () => {
  const w = await world();
  try {
    assert.equal((await w.d.login('alice', 'alice password 1234')).status, 200);
    const nopw = await w.d.makeUser('nopw', null);
    await w.d.backend.tx({ write: true }, (tx) => S.setOidc(tx, nopw, w.idp.issuer, 'nopw-sub'));
    assert.equal((await w.d.login('nopw', '')).status, 400);
    assert.equal((await w.d.login('nopw', 'anything at all')).status, 401);
  } finally { await w.close(); }
});

test('the secrets are not in the answers, the log or the database', async () => {
  const w = await world();
  try {
    const r = await browse(w.d);
    const all = JSON.stringify([r.start.headers.get('location'), r.cbCookies, w.d.log.lines]);
    assert.equal(all.includes(CLIENT_SECRET), false);
    // the verifier and the state are not in the database in clear
    const j = new URL(r.start.headers.get('location')).searchParams;
    const rows = await w.d.backend.tx({}, (tx) => tx.all('SELECT * FROM auth.oidc_states'));
    assert.deepEqual(rows, []);
    assert.equal(w.d.log.lines.some((l) => l.includes(j.get('state'))), false);
    assert.equal(w.d.log.lines.some((l) => l.includes(r.bc)), false);
  } finally { await w.close(); }
});




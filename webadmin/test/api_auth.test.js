// logging in and out, sessions, CSRF, lockout, TOTP, tokens, the password: through the HTTP server, on SQLite3

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast, ORIGIN } from './helpers.js';
import { hotp, totpStep, base32Decode, randomToken, tokenText, tokenHash } from '../lib/crypto.js';
import * as S from '../lib/store.js';

const withDeploy = (opts, fn) => async () => {
  const d = await deploy(opts);
  try {
    await fn(d);
  } finally {
    await d.close();
  }
};
const code = (b32, ms, step = 0) => hotp(base32Decode(b32), totpStep(ms / 1000) + step);
const problem = (r, status, type) => {
  assert.equal(r.status, status, JSON.stringify(r.body));
  assert.equal(r.headers.get('content-type'), 'application/problem+json; charset=utf-8');
  assert.equal(r.body.type, `urn:karidns:api:${type}`, JSON.stringify(r.body));
  assert.match(r.body.request_id, /^[0-9a-f]{16}$/);
};

test('the login: a cookie, the CSRF token, the same answer for every kind of refusal', withDeploy({}, async (d) => {
  await cast(d);
  await d.makeUser('nopw', null);
  await d.makeUser('off', 'off password 12345', { disabled: true });
  await d.makeUser('grp', null, { kind: 'group' });
  const ok = await d.request('POST', '/auth/login', { body: { user: 'ROOT', password: 'correct horse battery' } });
  assert.equal(ok.status, 200);
  const cookie = ok.headers.get('set-cookie');
  assert.match(cookie, /^karidns_session=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Strict; Path=\/api\/; Max-Age=43200$/);
  assert.equal(ok.body.principal.name, 'root');
  assert.equal(ok.body.totp.enrollment_required, false);
  assert.match(ok.body.csrf, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(ok.headers.get('cache-control'), 'no-store');
  assert.equal(ok.headers.get('x-content-type-options'), 'nosniff');
  assert.match(ok.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(ok.headers.get('cross-origin-resource-policy'), 'same-origin');
  assert.equal(ok.headers.get('strict-transport-security'), null);
  const refusals = [
    ['root', 'wrong password 1234'], ['nobody', 'correct horse battery'], ['nopw', 'whatever 123456'], ['off', 'off password 12345'], ['grp', 'x'],
  ];
  const bodies = [];
  for (const [user, password] of refusals) {
    const r = await d.request('POST', '/auth/login', { body: { user, password } });
    problem(r, 401, 'invalid-credentials');
    bodies.push(JSON.stringify({ ...r.body, request_id: '' }));
  }
  assert.equal(new Set(bodies).size, 1, 'one answer for all');
  // the shape of the request
  problem(await d.request('POST', '/auth/login', { body: { user: 'root' } }), 400, 'bad-request');
  problem(await d.request('POST', '/auth/login', { body: { user: 'root', password: 'x', totp: '12' } }), 400, 'bad-request');
  problem(await d.request('POST', '/auth/login', { body: { user: 'root', password: 'x', extra: 1 } }), 400, 'bad-request');
  problem(await d.request('POST', '/auth/login', { body: { user: 'root', password: 'correct horse battery' }, origin: 'http://evil.test' }), 403, 'csrf');
  const withOrigin = await d.request('POST', '/auth/login', { body: { user: 'root', password: 'correct horse battery' }, origin: ORIGIN });
  assert.equal(withOrigin.status, 200);
  assert.ok(d.log.lines.some((l) => /auth: root logged in from 127\.0\.0\.1/.test(l)));
  assert.ok(d.log.lines.some((l) => /auth: login refused for nopw from 127\.0\.0\.1/.test(l)), 'a known name without a password is named');
  assert.ok(d.log.lines.some((l) => /auth: login refused for an unknown or disabled user from 127\.0\.0\.1/.test(l)));
  assert.ok(!d.log.lines.some((l) => /nobody|\boff\b.*refused|refused for off/.test(l)), 'a name that is not one of ours (maybe a password) is not logged');
  assert.ok(!d.log.lines.some((l) => /correct horse|wrong password/.test(l)), 'no password in the log');
}));

test('the cookie is Secure and HSTS is sent when the origin is https', withDeploy({ settings: { 'public-origin': 'https://dns.example.test' } }, async (d) => {
  await cast(d);
  const r = await d.request('POST', '/auth/login', { body: { user: 'root', password: 'correct horse battery' } });
  assert.match(r.headers.get('set-cookie'), /; Secure$/);
  assert.equal(r.headers.get('strict-transport-security'), 'max-age=31536000');
}));

test('ten failures lock the account for 15 minutes, doubling; a success resets the count', withDeploy({}, async (d) => {
  const clock = { t: Date.now() };
  d.app.now = () => clock.t;
  await cast(d);
  const bad = () => d.request('POST', '/auth/login', { body: { user: 'dom', password: 'not the password' } });
  const good = () => d.request('POST', '/auth/login', { body: { user: 'dom', password: 'dom password 12345' } });
  for (let i = 0; i < 9; i++) problem(await bad(), 401, 'invalid-credentials');
  assert.equal((await good()).status, 200);                       // the ninth failure did not lock; the success resets
  for (let i = 0; i < 10; i++) problem(await bad(), 401, 'invalid-credentials');
  problem(await good(), 401, 'invalid-credentials');              // locked: even the right password is refused
  assert.ok(d.log.lines.some((l) => /warn auth: dom is locked after 10 failed logins/.test(l)));
  const root = await d.login('root', 'correct horse battery');
  const info = await d.as(root)('GET', '/principals/2');
  assert.equal(info.body.credentials.locked, true);
  assert.equal(info.body.credentials.failed_logins, 10);
  clock.t += 14 * 60 * 1000;
  problem(await good(), 401, 'invalid-credentials');
  clock.t += 2 * 60 * 1000;
  assert.equal((await good()).status, 200);                       // 16 minutes later it opens
  // an 11th failure in a row locks for 30 minutes (the count was reset by the success, so ten again)
  for (let i = 0; i < 10; i++) await bad();
  await bad();                                                    // the lock holds: not counted
  clock.t += 16 * 60 * 1000;
  problem(await bad(), 401, 'invalid-credentials');               // an 11th failure: 30 minutes
  clock.t += 20 * 60 * 1000;
  problem(await good(), 401, 'invalid-credentials');
  clock.t += 11 * 60 * 1000;
  assert.equal((await good()).status, 200);
}));

test('login attempts are limited per address and per name', withDeploy({ settings: { 'rate-login': 3 } }, async (d) => {
  await cast(d);
  const bad = (user) => d.request('POST', '/auth/login', { body: { user, password: 'x' } });
  for (let i = 0; i < 3; i++) problem(await bad(`u${i}`), 401, 'invalid-credentials');
  const r = await bad('u4');
  problem(r, 429, 'rate-limited');
  assert.match(r.headers.get('retry-after'), /^\d+$/);
}));

test('the rate limit per name is separate from the one per address', withDeploy({ settings: { 'rate-login': 3 } }, async (d) => {
  const clock = { t: Date.now() };
  d.app.now = () => clock.t;
  d.app.setConfig({ ...d.config, settings: { ...d.config.settings, 'rate-login': 3 } });
  d.app.buckets.loginIp.now = () => clock.t;
  d.app.buckets.loginUser.now = () => clock.t;
  const bad = () => d.request('POST', '/auth/login', { body: { user: 'same', password: 'x' } });
  for (let i = 0; i < 3; i++) await bad();
  problem(await bad(), 429, 'rate-limited');
}));

test('requests without credentials, with bad ones, with both', withDeploy({ settings: { 'rate-login': 5 } }, async (d) => {
  await cast(d);
  const s = await d.login('root', 'correct horse battery');
  problem(await d.request('GET', '/auth/me'), 401, 'unauthenticated');
  assert.equal((await d.request('GET', '/auth/me')).headers.get('www-authenticate'), 'Bearer realm="karidns"');
  problem(await d.request('GET', '/auth/me', { cookie: 'bogus' }), 401, 'unauthenticated');
  problem(await d.request('GET', '/auth/me', { token: 'bogus' }), 401, 'unauthenticated');
  problem(await d.request('GET', '/auth/me', { headers: { Authorization: 'Basic abc' } }), 401, 'unauthenticated');
  problem(await d.request('GET', '/auth/me', { cookie: s.cookie, token: tokenText(1, randomToken(32)) }), 400, 'both-credentials');
  assert.equal((await d.request('GET', '/auth/me', { cookie: s.cookie })).status, 200);
  // bad credentials in a row are slowed down (the same bucket as the logins: 5 a minute per address)
  let last;
  for (let i = 0; i < 8; i++) last = await d.request('GET', '/auth/me', { token: tokenText(1, randomToken(32)) });
  problem(last, 429, 'rate-limited');
}));

test('a session: CSRF token and Origin on every unsafe request', withDeploy({}, async (d) => {
  await cast(d);
  const s = await d.login('root', 'correct horse battery');
  const me = await d.request('GET', '/auth/me', { cookie: s.cookie });
  assert.equal(me.body.session.csrf, s.csrf, 'the token can be shown again');
  const post = (o) => d.request('POST', '/principals', { cookie: s.cookie, body: { kind: 'group', name: 'g1' }, ...o });
  problem(await post({}), 403, 'csrf');
  problem(await post({ csrf: s.csrf }), 403, 'csrf');
  problem(await post({ origin: ORIGIN }), 403, 'csrf');
  problem(await post({ csrf: s.csrf, origin: 'http://evil.test' }), 403, 'csrf');
  problem(await post({ csrf: `${s.csrf.slice(0, -1)}${s.csrf.endsWith('A') ? 'B' : 'A'}`, origin: ORIGIN }), 403, 'csrf');
  problem(await post({ csrf: 'x', origin: ORIGIN }), 403, 'csrf');
  assert.equal((await post({ csrf: s.csrf, origin: ORIGIN })).status, 201);
  // another session's token does not do
  const s2 = await d.login('root', 'correct horse battery');
  problem(await post({ csrf: s2.csrf, origin: ORIGIN, body: { kind: 'group', name: 'g2' } }), 403, 'csrf');
  // a safe request needs neither
  assert.equal((await d.request('GET', '/principals', { cookie: s.cookie })).status, 200);
}));

test('sessions end: logout, logout of all, idle time, absolute time, a disabled user', withDeploy({ settings: { 'session-idle': '10m', 'session-max': '1h' } }, async (d) => {
  const clock = { t: Date.now() };
  d.app.now = () => clock.t;
  await cast(d);
  const a = d.as(await d.login('dom', 'dom password 12345'));
  const s1 = await d.login('dom', 'dom password 12345');
  const s2 = await d.login('dom', 'dom password 12345');
  const root = d.as(await d.login('root', 'correct horse battery'));
  assert.equal((await a('GET', '/auth/me')).status, 200);
  // logout
  const out = await d.as(s1)('POST', '/auth/logout', { body: {} });
  assert.equal(out.status, 204);
  assert.match(out.headers.get('set-cookie'), /^karidns_session=; .*Max-Age=0/);
  problem(await d.as(s1)('GET', '/auth/me'), 401, 'unauthenticated');
  assert.equal((await d.as(s2)('GET', '/auth/me')).status, 200);
  // logout of all
  assert.equal((await d.as(s2)('POST', '/auth/logout', { body: { all: true } })).status, 204);
  problem(await a('GET', '/auth/me'), 401, 'unauthenticated');
  // idle time: the last request counts; last_seen is written once a minute
  const t = d.as(await d.login('dom', 'dom password 12345'));
  clock.t += 9 * 60 * 1000;
  assert.equal((await t('GET', '/auth/me')).status, 200);
  await d.app.drain();
  clock.t += 9 * 60 * 1000;
  assert.equal((await t('GET', '/auth/me')).status, 200);         // 18 minutes after the login, 9 after the last request
  await d.app.drain();
  clock.t += 11 * 60 * 1000;
  problem(await t('GET', '/auth/me'), 401, 'unauthenticated');
  // absolute time
  const u = d.as(await d.login('dom', 'dom password 12345'));
  for (let i = 0; i < 6; i++) {
    clock.t += 9 * 60 * 1000;
    assert.equal((await u('GET', '/auth/me')).status, 200);
    await d.app.drain();
  }
  clock.t += 9 * 60 * 1000;                                       // 63 minutes
  problem(await u('GET', '/auth/me'), 401, 'unauthenticated');
  // a disabled user's session stops at once
  const v = d.as(await d.login('dom', 'dom password 12345'));
  const root2 = d.as(await d.login('root', 'correct horse battery'));
  assert.equal((await root2('PATCH', '/principals/2', { body: { disabled: true } })).status, 200);
  problem(await v('GET', '/auth/me'), 401, 'unauthenticated');
  // and logout without a session
  const tok = (await root2('POST', '/tokens', { body: { name: 't' } })).body.token;
  problem(await d.request('POST', '/auth/logout', { token: tok, body: {} }), 403, 'session-only');
}));

test('TOTP: required for global masters, enrolment, the second step, no code twice', withDeploy({ settings: { 'require-totp': 'global' } }, async (d) => {
  const clock = { t: Date.now() };
  d.app.now = () => clock.t;
  await cast(d);
  const first = await d.login('root', 'correct horse battery');
  assert.equal(first.status, 200);
  assert.deepEqual(first.body.totp, { enabled: false, enrollment_required: true });
  const req = d.as(first);
  // until enrolled, only /auth/* answers
  problem(await req('GET', '/principals'), 403, 'totp-required');
  assert.equal((await req('GET', '/auth/me')).body.session.totp_ok, false);
  problem(await req('POST', '/auth/totp', { body: { action: 'confirm', code: '123456' } }), 409, 'no-enrolment');
  const enrol = await req('POST', '/auth/totp', { body: { action: 'enroll' } });
  assert.equal(enrol.status, 200);
  assert.match(enrol.body.secret, /^[A-Z2-7]{32}$/);
  assert.match(enrol.body.uri, /^otpauth:\/\/totp\/KariDNS:root\?secret=/);
  problem(await req('POST', '/auth/totp', { body: { action: 'confirm', code: '000000' } }), 403, 'wrong-code');
  problem(await req('POST', '/auth/totp', { body: { action: 'confirm' } }), 400, 'bad-request');
  problem(await req('POST', '/auth/totp', { body: { action: 'disable', password: 'x', code: '123456' } }), 409, 'totp-disabled');
  const confirm = await req('POST', '/auth/totp', { body: { action: 'confirm', code: code(enrol.body.secret, clock.t) } });
  assert.equal(confirm.status, 200);
  const newCookie = /karidns_session=([^;]+)/.exec(confirm.headers.get('set-cookie'))[1];
  assert.notEqual(newCookie, first.cookie);
  problem(await req('GET', '/auth/me'), 401, 'unauthenticated');           // the old session is gone
  const second = d.as({ cookie: newCookie, csrf: confirm.body.csrf });
  assert.equal((await second('GET', '/principals')).status, 200);
  problem(await second('POST', '/auth/totp', { body: { action: 'enroll' } }), 409, 'totp-enabled');
  problem(await second('POST', '/auth/totp', { body: { action: 'confirm', code: '123456' } }), 409, 'totp-enabled');
  problem(await second('POST', '/auth/totp', { body: { action: 'disable', password: 'correct horse battery', code: code(enrol.body.secret, clock.t) } }), 403, 'totp-required-by-policy');
  // a login now needs the code
  const noCode = await d.request('POST', '/auth/login', { body: { user: 'root', password: 'correct horse battery' } });
  problem(noCode, 401, 'totp-required');
  clock.t += 30000;
  const l1 = await d.login('root', 'correct horse battery', { totp: code(enrol.body.secret, clock.t) });
  assert.equal(l1.status, 200);
  assert.deepEqual(l1.body.totp, { enabled: true, enrollment_required: false });
  assert.equal((await d.as(l1)('GET', '/principals')).status, 200);
  // the same code (or an earlier one) again: refused
  problem((await d.request('POST', '/auth/login', { body: { user: 'root', password: 'correct horse battery', totp: code(enrol.body.secret, clock.t) } })), 401, 'invalid-credentials');
  problem((await d.request('POST', '/auth/login', { body: { user: 'root', password: 'correct horse battery', totp: code(enrol.body.secret, clock.t, -1) } })), 401, 'invalid-credentials');
  // the next one works, a wrong one counts as a failed login
  assert.equal((await d.login('root', 'correct horse battery', { totp: code(enrol.body.secret, clock.t, 1) })).status, 200);
  problem(await d.request('POST', '/auth/login', { body: { user: 'root', password: 'correct horse battery', totp: '000000' } }), 401, 'invalid-credentials');
  const info = await d.as(l1)('GET', '/principals/1');
  assert.equal(info.body.credentials.failed_logins, 1);
  assert.equal(info.body.credentials.totp_enabled, true);
  // a user who is no global master is not asked for TOTP, and may enrol and disable it
  const dom = d.as(await d.login('dom', 'dom password 12345'));
  assert.equal((await dom('GET', '/auth/me')).body.session.totp_ok, true);
  const e2 = await dom('POST', '/auth/totp', { body: { action: 'enroll' } });
  assert.equal((await dom('POST', '/auth/totp', { body: { action: 'confirm', code: code(e2.body.secret, clock.t) } })).status, 200);
}));

test('TOTP: a user can switch it off again where nothing requires it', withDeploy({}, async (d) => {
  const clock = { t: Date.now() };
  d.app.now = () => clock.t;
  await cast(d);
  const s = await d.login('dom', 'dom password 12345');
  const enrol = await d.as(s)('POST', '/auth/totp', { body: { action: 'enroll' } });
  const conf = await d.as(s)('POST', '/auth/totp', { body: { action: 'confirm', code: code(enrol.body.secret, clock.t) } });
  const t = d.as({ cookie: /karidns_session=([^;]+)/.exec(conf.headers.get('set-cookie'))[1], csrf: conf.body.csrf });
  const other = await d.login('dom', 'dom password 12345', { totp: code(enrol.body.secret, clock.t, 1) });
  assert.equal(other.status, 200);
  problem(await t('POST', '/auth/totp', { body: { action: 'disable', code: '123456' } }), 400, 'bad-request');
  problem(await t('POST', '/auth/totp', { body: { action: 'disable', password: 'wrong password 12', code: '123456' } }), 403, 'wrong-password');
  problem(await t('POST', '/auth/totp', { body: { action: 'disable', password: 'dom password 12345', code: '000000' } }), 403, 'wrong-code');
  clock.t += 60000;
  const off = await t('POST', '/auth/totp', { body: { action: 'disable', password: 'dom password 12345', code: code(enrol.body.secret, clock.t) } });
  assert.equal(off.status, 200);
  assert.deepEqual(off.body.totp, { enabled: false });
  problem(await d.as(other)('GET', '/auth/me'), 401, 'unauthenticated');     // the other sessions ended
  assert.equal((await t('GET', '/auth/me')).status, 200);
  assert.equal((await d.login('dom', 'dom password 12345')).status, 200);       // no code needed any more
  // a user without a password has no second step to take
  await d.makeUser('svc', null);
  const root = d.as(await d.login('root', 'correct horse battery'));
  assert.equal(root !== null, true);
}));

test('the password: changing it asks for the old one', withDeploy({}, async (d) => {
  await cast(d);
  const a = await d.login('dom', 'dom password 12345');
  const b = await d.login('dom', 'dom password 12345');
  const change = (body, s = a) => d.as(s)('POST', '/auth/password', { body });
  problem(await change({ current: 'wrong password 12', new: 'a new password 123' }), 403, 'wrong-password');
  problem(await change({ current: 'dom password 12345', new: 'short' }), 400, 'bad-request');
  problem(await change({ current: 'dom password 12345', new: 'my DOM password!' }), 400, 'weak-password');
  problem(await change({ current: 'dom password 12345' }), 400, 'bad-request');
  assert.equal((await change({ current: 'dom password 12345', new: 'a new password 123', all: true })).status, 200);
  assert.equal((await d.as(a)('GET', '/auth/me')).status, 200);
  problem(await d.as(b)('GET', '/auth/me'), 401, 'unauthenticated');          // the other session ended
  problem(await d.request('POST', '/auth/login', { body: { user: 'dom', password: 'dom password 12345' } }), 401, 'invalid-credentials');
  assert.equal((await d.login('dom', 'a new password 123')).status, 200);
  // without all the other sessions stay
  const c = await d.login('dom', 'a new password 123');
  assert.equal((await change({ current: 'a new password 123', new: 'yet another one 12' })).status, 200);
  assert.equal((await d.as(c)('GET', '/auth/me')).status, 200);
}));

test('API tokens: made once, used as bearer, read-only, revoked, expired, listed', withDeploy({}, async (d) => {
  const clock = { t: Date.now() };
  d.app.now = () => clock.t;
  await cast(d);
  const root = d.as(await d.login('root', 'correct horse battery'));
  const dom = d.as(await d.login('dom', 'dom password 12345'));
  const made = await dom('POST', '/tokens', { body: { name: 'ci', days: 30 } });
  assert.equal(made.status, 201);
  assert.match(made.body.token, /^kdt_\d+_[A-Za-z0-9_-]{43}$/);
  assert.equal(made.body.info.name, 'ci');
  assert.equal(made.body.info.principal, 'dom');
  assert.equal(made.body.info.read_only, false);
  assert.equal(made.body.info.expires_at, new Date(clock.t + 30 * 86400000).toISOString().replace(/\.\d{3}Z$/, 'Z'));
  const tok = made.body.token;
  // as a bearer it acts as dom
  const me = await d.request('GET', '/auth/me', { token: tok });
  assert.equal(me.body.principal.name, 'dom');
  assert.deepEqual(me.body.session, { token: true, read_only: false });
  assert.equal((await d.request('GET', '/datasets/main/zones', { token: tok })).body.zones.length, 1);
  // no CSRF or Origin for a bearer; but not for making tokens, changing the password or TOTP
  assert.equal((await d.request('DELETE', `/tokens/${made.body.info.id}`, { token: 'kdt_x', csrf: undefined })).status, 401);
  problem(await d.request('POST', '/tokens', { token: tok, body: { name: 'child' } }), 403, 'session-only');
  problem(await d.request('POST', '/auth/password', { token: tok, body: { current: 'a', new: 'b' } }), 403, 'session-only');
  // read-only
  const ro = (await dom('POST', '/tokens', { body: { name: 'ro', read_only: true } })).body.token;
  assert.equal((await d.request('GET', '/principals', { token: ro })).status, 200);
  problem(await d.request('POST', '/principals', { token: ro, body: { kind: 'group', name: 'x' } }), 403, 'read-only-token');
  // listing: own tokens; a global master may list all or those of a principal
  const mine = await dom('GET', '/tokens');
  assert.deepEqual(mine.body.tokens.map((t) => t.name), ['ci', 'ro']);
  assert.equal(JSON.stringify(mine.body).includes('secret'), false);
  problem(await dom('GET', '/tokens?all=true'), 403, 'forbidden');
  problem(await dom('GET', '/tokens?principal=1'), 403, 'forbidden');
  assert.equal((await dom('GET', '/tokens?principal=2')).body.tokens.length, 2);
  assert.equal((await root('GET', '/tokens?all=true')).body.tokens.length, 2);
  assert.equal((await root('GET', '/tokens')).body.tokens.length, 0);
  const paged = await root('GET', '/tokens?all=true&limit=1');
  assert.equal(paged.body.tokens.length, 1);
  assert.equal((await root('GET', `/tokens?all=true&limit=1&cursor=${paged.body.next_cursor}`)).body.tokens[0].name, 'ro');
  // last_used_at is written once a day
  await d.app.drain();
  const used = (await dom('GET', '/tokens')).body.tokens[0].last_used_at;
  assert.ok(used);
  clock.t += 20 * 60 * 1000;
  await d.request('GET', '/auth/me', { token: tok });
  await d.app.drain();
  assert.equal((await dom('GET', '/tokens')).body.tokens[0].last_used_at, used);
  // a global master makes a token for another principal; nobody else does; the principal must exist
  const svc = await d.makeUser('svc', null);
  assert.equal((await root('POST', '/tokens', { body: { name: 'for svc', principal: svc } })).body.info.principal, 'svc');
  problem(await dom('POST', '/tokens', { body: { name: 'x', principal: svc } }), 403, 'forbidden');
  problem(await root('POST', '/tokens', { body: { name: 'x', principal: 999 } }), 404, 'not-found');
  problem(await root('POST', '/tokens', { body: { name: 'x', days: 366 } }), 400, 'bad-request');
  // revoke: the owner or a global master; others see no such token
  const other = (await root('POST', '/tokens', { body: { name: 'rootsx' } })).body.info.id;
  problem(await dom('DELETE', `/tokens/${other}`), 404, 'not-found');
  problem(await dom('DELETE', '/tokens/999'), 404, 'not-found');
  problem(await dom('DELETE', '/tokens/abc'), 404, 'not-found');
  assert.equal((await dom('DELETE', `/tokens/${made.body.info.id}`)).status, 204);
  problem(await d.request('GET', '/auth/me', { token: tok }), 401, 'unauthenticated');
  assert.equal((await root('DELETE', `/tokens/${other}`)).status, 204);
  // expiry
  clock.t += 100 * 86400000;
  problem(await d.request('GET', '/auth/me', { token: ro }), 401, 'unauthenticated');
}));

test('a disabled user: its tokens are revoked and its sessions end', withDeploy({}, async (d) => {
  await cast(d);
  const root = d.as(await d.login('root', 'correct horse battery'));
  const dom = d.as(await d.login('dom', 'dom password 12345'));
  const tok = (await dom('POST', '/tokens', { body: { name: 'ci' } })).body.token;
  assert.equal((await root('PATCH', '/principals/2', { body: { disabled: true } })).status, 200);
  problem(await d.request('GET', '/auth/me', { token: tok }), 401, 'unauthenticated');
  assert.equal((await root('PATCH', '/principals/2', { body: { disabled: false } })).status, 200);
  problem(await d.request('GET', '/auth/me', { token: tok }), 401, 'unauthenticated');          // revoked for good
  problem(await dom('GET', '/auth/me'), 401, 'unauthenticated');
  assert.equal((await d.login('dom', 'dom password 12345')).status, 200);
}));

test('a token made straight in the database, and one with a bad secret', withDeploy({}, async (d) => {
  await cast(d);
  const secret = randomToken(32);
  const id = await d.backend.tx({ write: true }, (tx) => S.createToken(tx, { principalId: 2, name: 'x', secretHash: tokenHash(secret), readOnly: false, createdMs: Date.now(), expiresMs: Date.now() + 1000000 }));
  assert.equal((await d.request('GET', '/auth/me', { token: tokenText(id, secret) })).status, 200);
  problem(await d.request('GET', '/auth/me', { token: tokenText(id, randomToken(32)) }), 401, 'unauthenticated');
}));

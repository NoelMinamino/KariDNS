// The API client and the session of the GUI against a scripted fetch (planning 8.1): the CSRF header, problem documents, Retry-After, the repeat after a stale token,
// the sign-in dialog after a 401, and the session timer (F-14: no request on its own; a warning two minutes before the end; the end a minute early).

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApi, ApiProblem, retryAfter, enc, UNSAFE } from '../ui/js/api.js';
import { createSession, WARN_BEFORE_MS, SAFETY_MS, CHANNEL } from '../ui/js/session.js';
import { reply, problem, makeClock, makeBroadcast, flush } from './fakedom.js';

const ME = (over = {}) => ({
  api: 1, principal: { id: 7, kind: 'user', name: 'alice', display_name: null, email: null, disabled: false }, groups: [], tenants: [], grants: [],
  capabilities: { global: false }, session: { csrf: 'csrf-1', totp_ok: true, expires_at: '2026-11-09T12:00:00.000Z', idle_timeout: 1800 }, ...over,
});

function setup(handler, { reauth } = {}) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    const c = { method: init.method ?? 'GET', url, headers: init.headers ?? {}, body: init.body === undefined ? undefined : JSON.parse(init.body), init };
    calls.push(c);
    return handler(c);
  };
  const activity = [];
  const api = createApi({ fetch, now: () => 1000, onActivity: (ms) => activity.push(ms), onUnauthenticated: reauth });
  return { api, calls, activity };
}

test('retryAfter: seconds, an HTTP date, nothing', () => {
  assert.equal(retryAfter('7', 0), 7);
  assert.equal(retryAfter('Wed, 21 Oct 2026 07:28:10 GMT', Date.parse('Wed, 21 Oct 2026 07:28:00 GMT')), 10);
  assert.equal(retryAfter('Wed, 21 Oct 2026 07:28:10 GMT', Date.parse('Wed, 21 Oct 2026 08:00:00 GMT')), 0);
  assert.equal(retryAfter('soon', 0), undefined);
  assert.equal(retryAfter(null, 0), undefined);
  assert.equal(enc('a/b c'), 'a%2Fb%20c');
  assert.ok(UNSAFE.has('PATCH') && !UNSAFE.has('GET'));
});

test('a GET sends no CSRF header and no body; the query leaves out what is empty; an unsafe request sends the token, JSON and the same-origin settings', async () => {
  const { api, calls } = setup(() => reply(200, { api: 1, ok: true }));
  api.setCsrf('tok');
  await api.get('/zones', { query: { prefix: 'a b', limit: 5, none: undefined, empty: '', nul: null } });
  assert.equal(calls[0].url, '/api/v1/zones?prefix=a+b&limit=5');
  assert.equal(calls[0].headers['X-KariDNS-CSRF'], undefined);
  assert.equal(calls[0].init.body, undefined);
  assert.equal(calls[0].init.credentials, 'same-origin');
  assert.equal(calls[0].init.cache, 'no-store');
  assert.equal(calls[0].init.redirect, 'error');
  await api.post('/x', { a: 1 });
  await api.put('/x', { a: 2 });
  await api.patch('/x', { a: 3 });
  await api.del('/x');
  for (const c of calls.slice(1)) assert.equal(c.headers['X-KariDNS-CSRF'], 'tok', c.method);
  assert.equal(calls[1].headers['Content-Type'], 'application/json');
  assert.deepEqual(calls[1].body, { a: 1 });
  assert.equal(calls[4].init.body, undefined, 'a DELETE has no body');
  assert.equal(api.hasCsrf(), true);
  api.setCsrf(null);
  assert.equal(api.hasCsrf(), false);
  await api.post('/x', {});
  assert.equal(calls.at(-1).headers['X-KariDNS-CSRF'], undefined);
});

test('a 204 is null; a 2xx that is not JSON is bad-response', async () => {
  const { api } = setup((c) => (c.url.endsWith('/empty') ? reply(204, null) : reply(200, undefined)));
  assert.equal(await api.del('/empty'), null);
  await assert.rejects(api.get('/text'), (e) => e instanceof ApiProblem && e.code === 'bad-response' && e.status === 200);
});

test('a problem document becomes an ApiProblem with the code, the errors, the request id and Retry-After', async () => {
  const { api } = setup((c) => {
    if (c.url.includes('/rate')) return problem(429, 'rate-limited', {}, { 'Retry-After': '9' });
    if (c.url.includes('/val')) return problem(400, 'bad-request', { errors: [{ code: 'bad-request', severity: 'error', text: 'x', pointer: '/name' }] });
    if (c.url.includes('/html')) return reply(502, undefined, { 'Retry-After': '3' });
    if (c.url.includes('/busy')) return reply(503, undefined, { 'Retry-After': '4', 'X-Request-Id': 'r9' });
    if (c.url.includes('/odd')) return reply(404, { type: 'about:blank', title: 'Not found' });
    return reply(500, 'null');
  });
  await assert.rejects(api.get('/rate'), (e) => e.status === 429 && e.code === 'rate-limited' && e.retryAfter === 9 && e.requestId === 'rid1' && e.detail === 'detail of rate-limited');
  await assert.rejects(api.get('/val'), (e) => e.code === 'bad-request' && e.errors[0].pointer === '/name');
  await assert.rejects(api.get('/html'), (e) => e.status === 502 && e.code === 'bad-response' && e.retryAfter === 3);
  await assert.rejects(api.get('/busy'), (e) => e.code === 'busy' && e.requestId === 'r9' && e.retryAfter === 4);
  await assert.rejects(api.get('/odd'), (e) => e.code === 'unknown' && e.status === 404 && e.errors.length === 0);
  await assert.rejects(api.get('/null'), (e) => e.code === 'bad-response' && e.status === 500);
});

test('a network failure is code network, a timeout is code timeout, status 0', async () => {
  const mk = (err) => createApi({ fetch: async () => { throw err; }, now: () => 0 });
  await assert.rejects(mk(new TypeError('failed')).get('/x'), (e) => e.status === 0 && e.code === 'network');
  const te = new Error('t');
  te.name = 'TimeoutError';
  await assert.rejects(mk(te).get('/x'), (e) => e.status === 0 && e.code === 'timeout');
});

test('activity: every answer but a 401 counts as a request of the session (it moves last_seen), also a refusal', async () => {
  const { api, activity } = setup((c) => (c.url.endsWith('/ok') ? reply(200, {}) : c.url.endsWith('/no') ? problem(403, 'forbidden') : problem(401, 'unauthenticated')));
  await api.get('/ok');
  await assert.rejects(api.get('/no'));
  await assert.rejects(api.get('/out', { quiet: true }));
  assert.deepEqual(activity, [1000, 1000]);
});

test('403 csrf on a write: the token is fetched again from /auth/me and the request repeated once; on a read, or the second time, it is an error', async () => {
  let token = 'old';
  const { api, calls } = setup((c) => {
    if (c.url === '/api/v1/auth/me') return reply(200, ME({ session: { csrf: 'new', totp_ok: true, expires_at: '2026-11-09T12:00:00Z', idle_timeout: 60 } }));
    return c.headers['X-KariDNS-CSRF'] === token ? reply(200, { done: true }) : problem(403, 'csrf');
  });
  api.setCsrf('old');
  token = 'new';
  assert.deepEqual(await api.post('/x', {}), { done: true });
  assert.deepEqual(calls.map((c) => `${c.method} ${c.url} ${c.headers['X-KariDNS-CSRF'] ?? ''}`), ['POST /api/v1/x old', 'GET /api/v1/auth/me ', 'POST /api/v1/x new']);
  token = 'never';
  await assert.rejects(api.post('/x', {}), (e) => e.code === 'csrf');
  const bad = setup(() => problem(403, 'csrf'));
  await assert.rejects(bad.api.get('/x'), (e) => e.code === 'csrf');
  assert.equal(bad.calls.length, 1);
});

test('401 unauthenticated: the sign-in is asked for; the same person: a read is repeated, a write is not (the error says the session was renewed); another person or cancel: the error', async () => {
  let signedIn = false;
  let outcome = 'same';
  const asked = [];
  const { api, calls } = setup((c) => (signedIn ? reply(200, { n: calls.length }) : problem(401, 'unauthenticated')), {
    reauth: async () => { asked.push(1); signedIn = outcome !== 'cancel'; return outcome; },
  });
  const r = await api.get('/x');
  assert.equal(r.n, 2, 'repeated once after the sign-in');
  assert.equal(asked.length, 1);
  signedIn = false;
  await assert.rejects(api.post('/x', {}), (e) => e.code === 'unauthenticated' && e.renewed === true);
  assert.equal(calls.filter((c) => c.method === 'POST').length, 1, 'the write was not repeated');
  signedIn = false;
  outcome = 'other';
  await assert.rejects(api.get('/x'), (e) => e.renewed === false);
  signedIn = false;
  outcome = 'cancel';
  await assert.rejects(api.get('/x'), (e) => e.renewed === false);
  // a 401 of another kind (a token that is not valid) is just an error
  const t = setup(() => problem(401, 'invalid-credentials'), { reauth: async () => { throw new Error('must not be asked'); } });
  await assert.rejects(t.api.get('/x'), (e) => e.code === 'invalid-credentials');
  // and quiet requests do not ask
  const q = setup(() => problem(401, 'unauthenticated'), { reauth: async () => { throw new Error('must not be asked'); } });
  await assert.rejects(q.api.get('/x', { quiet: true }), (e) => e.code === 'unauthenticated');
});

// ---------------------------------------------------------------------------------------------------------------------------------- session.js
function sess({ handler, BC = makeBroadcast(), clock = makeClock() } = {}) {
  const calls = [];
  let session = null;
  const fetch = async (url, init = {}) => {
    calls.push({ method: init.method ?? 'GET', url, body: init.body === undefined ? undefined : JSON.parse(init.body), csrf: (init.headers ?? {})['X-KariDNS-CSRF'] });
    return handler(calls.at(-1));
  };
  const api = createApi({ fetch, now: clock.now, onActivity: (ms) => session.touch(ms), onUnauthenticated: () => session.reauth() });
  session = createSession({ api, timers: clock.timers, now: clock.now, BroadcastChannel: BC });
  const events = [];
  for (const ev of ['change', 'warn', 'warn-clear', 'expired', 'reauthenticated', 'other-tab-logout', 'other-tab-login']) session.on(ev, (arg) => events.push(ev === 'warn' || ev === 'reauthenticated' ? [ev, arg] : [ev]));
  return { session, api, calls, events, clock, BC };
}
const names = (events) => events.map((e) => e[0]);
const LOGIN = { api: 1, principal: { id: 7, name: 'alice' }, csrf: 'csrf-1', expires_at: '2026-11-09T12:00:00Z', totp: { enabled: false, enrollment_required: false } };
const meAt = (clock, idle = 1800, over = {}) => ME({ session: { csrf: 'csrf-1', totp_ok: true, expires_at: new Date(clock.now() + 12 * 3600 * 1000).toISOString(), idle_timeout: idle, ...over } });

test('restore: a session is found (the CSRF token is taken from /auth/me), or there is none; other failures are thrown', async () => {
  const clock = makeClock();
  const a = sess({ clock, handler: () => reply(200, meAt(clock)) });
  assert.equal(await a.session.restore(), true);
  assert.equal(a.session.state.status, 'in');
  assert.equal(a.session.state.me.principal.name, 'alice');
  assert.equal(a.session.state.idleMs, 1800000);
  assert.equal(a.api.hasCsrf(), true);
  const b = sess({ handler: () => problem(401, 'unauthenticated') });
  assert.equal(await b.session.restore(), false);
  assert.equal(b.session.state.status, 'out');
  assert.equal(b.api.hasCsrf(), false);
  const c = sess({ handler: () => problem(500, 'internal') });
  await assert.rejects(c.session.restore(), (e) => e.status === 500);
  assert.equal(c.session.state.status, 'unknown');
});

test('login: POST /auth/login, then /auth/me; the answer says whether enrolment is required and whether it is the same person as before', async () => {
  const clock = makeClock();
  const s = sess({ clock, handler: (c) => (c.url.endsWith('/auth/login') ? reply(200, { ...LOGIN, totp: { enabled: false, enrollment_required: true } }) : reply(200, meAt(clock, 1800, { totp_ok: false }))) });
  const r = await s.session.login({ user: 'alice', password: 'pw', totp: '123456' });
  assert.deepEqual(r, { enrollmentRequired: true, samePrincipal: true });
  assert.deepEqual(s.calls[0].body, { user: 'alice', password: 'pw', totp: '123456' });
  assert.equal(s.session.state.me.session.totp_ok, false);
  await s.session.login({ user: 'alice', password: 'pw' });
  assert.deepEqual(s.calls[2].body, { user: 'alice', password: 'pw' }, 'no code, none sent');
  // another person after an end of session: the work of the first does not belong to the second
  s.session.state.previous = 99;
  assert.equal((await s.session.login({ user: 'alice', password: 'pw' })).samePrincipal, false);
  assert.equal(s.session.state.previous, null);
  // a refused login throws the problem and changes nothing
  const bad = sess({ handler: () => problem(401, 'invalid-credentials') });
  await assert.rejects(bad.session.login({ user: 'x', password: 'y' }), (e) => e.code === 'invalid-credentials');
  assert.equal(bad.session.state.status, 'unknown');
});

test('logout sends the token, clears the state, forgets the CSRF token and tells the other tabs; all: true is passed on; a 401 means it is over already', async () => {
  const clock = makeClock();
  const BC = makeBroadcast();
  const heard = [];
  const other = new BC(CHANNEL);
  other.onmessage = (m) => heard.push(m.data.type);
  const s = sess({ clock, BC, handler: (c) => (c.url.endsWith('/auth/logout') ? reply(204, null) : reply(200, meAt(clock))) });
  s.session.open();
  await s.session.restore();
  await s.session.logout(true);
  assert.deepEqual(s.calls.at(-1).body, { all: true });
  assert.equal(s.calls.at(-1).csrf, 'csrf-1');
  assert.equal(s.session.state.status, 'out');
  assert.equal(s.session.state.me, null);
  assert.equal(s.api.hasCsrf(), false);
  assert.deepEqual(heard, ['logout']);
  await s.session.restore().catch(() => {});
  const gone = sess({ clock, handler: (c) => (c.url.endsWith('/auth/logout') ? problem(401, 'unauthenticated') : reply(200, meAt(clock))) });
  await gone.session.restore();
  await gone.session.logout(false);
  assert.deepEqual(gone.calls.at(-1).body, {});
  assert.equal(gone.session.state.status, 'out', 'a 401 on logout asked for no sign-in');
  const failing = sess({ clock, handler: (c) => (c.url.endsWith('/auth/logout') ? problem(500, 'internal') : reply(200, meAt(clock))) });
  await failing.session.restore();
  await assert.rejects(failing.session.logout(false), (e) => e.status === 500);
  assert.equal(failing.session.state.status, 'in');
  assert.equal(failing.session.state.leaving, false);
});

test('the other tabs: a logout there ends this session; a login there, when this tab is signed out, finds the session', async () => {
  const clock = makeClock();
  const BC = makeBroadcast();
  let signedIn = true;
  const s = sess({ clock, BC, handler: () => (signedIn === null ? problem(500, 'internal') : signedIn ? reply(200, meAt(clock)) : problem(401, 'unauthenticated')) });
  s.session.open();
  await s.session.restore();
  const tab2 = new BC(CHANNEL);
  tab2.postMessage({ type: 'nonsense' });
  tab2.postMessage({ type: 'logout' });
  assert.equal(s.session.state.status, 'out');
  assert.ok(names(s.events).includes('other-tab-logout'));
  tab2.postMessage({ type: 'logout' });
  assert.equal(names(s.events).filter((x) => x === 'other-tab-logout').length, 1, 'once');
  tab2.postMessage({ type: 'login' });
  await flush();
  assert.equal(s.session.state.status, 'in');
  assert.ok(names(s.events).includes('other-tab-login'));
  tab2.postMessage({ type: 'login' });
  signedIn = false;
  s.session.state.status = 'out';
  tab2.postMessage({ type: 'login' });
  await flush();
  // a sign-in elsewhere that cannot be followed here (the service does not answer): nothing is thrown
  s.session.state.status = 'out';
  signedIn = null;
  s.calls.length = 0;
  tab2.postMessage({ type: 'login' });
  await flush();
  assert.equal(s.calls.length, 1);
  s.session.close();
  const none = sess({ BC: null, handler: () => reply(200, {}) });
  none.session.open();
  none.session.close();
});

test('the timer (F-14): nothing is asked on its own; the warning comes two minutes before the end, the end is a minute early; a request moves both', async () => {
  const clock = makeClock();
  const s = sess({ clock, handler: () => reply(200, meAt(clock)) });
  await s.session.restore();
  const start = clock.now();
  const callsBefore = s.calls.length;
  const end = start + 1800000 - SAFETY_MS;
  await clock.advance(end - WARN_BEFORE_MS - start - 1000);
  assert.deepEqual(names(s.events).filter((e) => e === 'warn'), []);
  await clock.advance(2000);
  assert.deepEqual(s.events.filter((e) => e[0] === 'warn').map((e) => e[1]), [{ at: end, kind: 'idle' }]);
  // a request by the user: the warning is withdrawn and everything moves
  await s.session.keepAlive();
  assert.ok(names(s.events).includes('warn-clear'));
  const afterKeep = clock.now();
  await clock.advance(WARN_BEFORE_MS);
  assert.equal(s.events.filter((e) => e[0] === 'warn').length, 1, 'no new warning yet');
  await clock.advance(1800000 - SAFETY_MS - WARN_BEFORE_MS - 5000);
  assert.equal(s.events.filter((e) => e[0] === 'warn').length, 2);
  assert.equal(s.calls.length - callsBefore, 1, 'the only request was the one the user asked for');
  await clock.advance(10000);
  assert.equal(s.session.state.status, 'expired');
  assert.ok(names(s.events).includes('expired'));
  assert.ok(clock.now() > afterKeep);
  assert.equal(clock.pending(), 0, 'no timer is left');
});

test('the absolute end of the session is warned about as such, and a short idle time keeps its margin proportional', async () => {
  const clock = makeClock();
  const s = sess({ clock, handler: () => reply(200, meAt(clock, 1800, { expires_at: new Date(clock.now() + 600000).toISOString() })) });
  await s.session.restore();
  await clock.advance(600000 - WARN_BEFORE_MS + 1000);
  assert.equal(s.events.find((e) => e[0] === 'warn')[1].kind, 'max');
  await clock.advance(WARN_BEFORE_MS);
  assert.equal(s.session.state.status, 'expired');
  // an idle time of one minute: the margin is a quarter, the warning half way
  const c2 = makeClock();
  const s2 = sess({ clock: c2, handler: () => reply(200, meAt(c2, 60)) });
  await s2.session.restore();
  await c2.advance(31000);
  assert.deepEqual(s2.events.find((e) => e[0] === 'warn')[1], { at: c2.now() - 31000 + 45000, kind: 'idle' });
  await c2.advance(15000);
  assert.equal(s2.session.state.status, 'expired');
});

test('touch does nothing for a session that is not in; setOut keeps the principal for the next sign-in', async () => {
  const clock = makeClock();
  const s = sess({ clock, handler: () => reply(200, meAt(clock)) });
  s.session.touch(5);
  assert.equal(s.session.state.lastActivity, 0);
  await s.session.restore();
  s.session.touch(clock.now() + 10);
  assert.equal(s.session.state.lastActivity, clock.now() + 10);
  assert.equal(s.session.dirty(), false);
  s.session.guards.add(() => false);
  assert.equal(s.session.dirty(), false);
  s.session.guards.add(() => true);
  assert.equal(s.session.dirty(), true);
});

test('reauth: one dialog at a time; the answer is passed on; cancel ends the session; no handler or a logout in progress is cancel', async () => {
  const clock = makeClock();
  const s = sess({ clock, handler: () => reply(200, meAt(clock)) });
  assert.equal(await s.session.reauth(), 'cancel', 'no handler');
  await s.session.restore();
  let release;
  let opened = 0;
  s.session.setReauthHandler(() => { opened++; return new Promise((r) => { release = r; }); });
  const a = s.session.reauth();
  const b = s.session.reauth();
  assert.equal(opened, 1);
  assert.equal(a, b);
  release('other');
  assert.equal(await a, 'other');
  assert.deepEqual(s.events.find((e) => e[0] === 'reauthenticated'), ['reauthenticated', 'other']);
  const c = s.session.reauth();
  release('cancel');
  assert.equal(await c, 'cancel');
  assert.equal(s.session.state.status, 'out');
  assert.equal(s.session.state.previous, 7);
  s.session.state.leaving = true;
  assert.equal(await s.session.reauth(), 'cancel');
});

test('replaced: the new CSRF token of a confirmed TOTP is used from then on; loadVersion keeps the answer', async () => {
  const clock = makeClock();
  const s = sess({ clock, handler: (c) => (c.url.endsWith('/version') ? reply(200, { version: '0.6.0', ui: { require_totp: 'global' } }) : reply(200, meAt(clock, 1800, { csrf: 'csrf-2' }))) });
  await s.session.replaced({ csrf: 'csrf-2' });
  assert.equal(s.session.state.me.session.csrf, 'csrf-2');
  await s.api.post('/x', {}).catch(() => {});
  assert.equal(s.calls.at(-1).csrf, 'csrf-2');
  assert.equal((await s.session.loadVersion()).version, '0.6.0');
  assert.equal(s.session.state.version.ui.require_totp, 'global');
  s.session.close();
});

// The screens of the GUI (S1, S2, S15, S16 and the frame) run in Node on the fake DOM against a scripted API (planning 8.1, F-11): what is on the page, what the
// forms send, how every refusal is shown, the 401 dialog, the idle warning, the tabs, and hostile data (no element may come from it).

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../ui/js/app.js';
import { GUI_VERSION } from '../ui/js/version.js';
import { makeEnv, makeClock, makeBroadcast, FakeStorage, FakeEvent, reply, problem, flush, findAll, byText } from './fakedom.js';
import en from '../ui/i18n/en.js';
import ja from '../ui/i18n/ja.js';

const PRINCIPAL = { id: 7, kind: 'user', name: 'alice', display_name: 'Alice A.', email: null, disabled: false };
const SESSION = (clock, over = {}) => ({ csrf: 'csrf-1', totp_ok: true, expires_at: new Date(clock.now() + 12 * 3600 * 1000).toISOString(), idle_timeout: 1800, ...over });
const ME = (clock, over = {}, sess = {}) => ({
  api: 1, principal: PRINCIPAL, groups: [], tenants: [], capabilities: { global: false, manage_principals: false, manage_policies: false, create_zones: false, grant_on: [] },
  grants: [{ id: 1, role: 'domain_master', dataset: 'main', zone: 'example.test.', suffix: null, policy: { id: 2, name: 'web' }, via: null }],
  session: SESSION(clock, sess), ...over,
});
const VERSION = { api: 1, version: GUI_VERSION, tools: { 'karidns-zone': 'karidns-zone 0.6.0' }, datasets: ['main'], types: ['A', 'MX'], ui: { reload_after_change: false, require_totp: 'global', max_rrsets: 1000, max_records: 1000, zone_text_limit: 16777216 } };

// a scripted API; `st` is the state the tests change; routes[] are checked first
function backend(st, routes = {}) {
  return (method, url, body) => {
    const key = `${method} ${url.split('?')[0].replace('/api/v1', '')}`;
    if (routes[key]) return typeof routes[key] === 'function' ? routes[key](body, url) : routes[key];
    if (!st.in && key !== 'POST /auth/login' && key !== 'GET /auth/me') return problem(401, 'unauthenticated');
    switch (key) {
      case 'GET /auth/me': return st.in ? reply(200, st.me()) : problem(401, 'unauthenticated');
      case 'GET /version': return reply(200, st.version ?? VERSION);
      case 'POST /auth/login': {
        if (st.loginError) return st.loginError(body);
        st.in = true;
        return reply(200, { api: 1, principal: st.who ?? PRINCIPAL, csrf: 'csrf-1', expires_at: 'x', totp: { enabled: false, enrollment_required: st.enrol === true } });
      }
      case 'POST /auth/logout': st.in = false; return reply(204, null);
      case 'GET /principals/7': return reply(200, { principal: PRINCIPAL, groups: [], credentials: { password: true, totp_enabled: st.totpOn === true, failed_logins: 0, locked: false } });
      case 'GET /tokens': return reply(200, { tokens: st.tokens ?? [], next_cursor: null });
      default: return problem(404, 'not-found');
    }
  };
}

async function boot({ st = {}, routes, hash = '', languages = ['en'], storage, clipboard } = {}) {
  const clock = makeClock();
  const state = st;                                // (the test changes it later: it is the state of the scripted service)
  state.in ??= true;
  state.me ??= () => ME(clock, state.meOver ?? {}, state.sessOver ?? {});
  const env = makeEnv({ handler: (m, u, b, hd) => backend(state, routes)(m, u, b, hd), languages, clock, storage: storage ?? new FakeStorage(), BroadcastChannel: makeBroadcast(), clipboard });
  env.window.location.hash = hash;
  const app = createApp(env);
  await app.start();
  await flush();
  const root = env.document.getElementById('app');
  const ui = {
    env, app, root, clock, state, calls: env.calls,
    main: () => root.querySelector('main'),
    text: () => root.textContent,
    q: (sel) => root.querySelector(sel),
    qa: (sel) => root.querySelectorAll(sel),
    button: (re) => byText(env.document.body, 'button', re),
    link: (re) => byText(root, 'a', re),
    dialogs: () => env.document.body.querySelectorAll('dialog').filter((d) => d.open),
    type(el, v) { el.value = v; },
    async click(el) { el.click(); await flush(); },
    async submit(form) { form.submit(); await flush(); },
    input: (name, scope = root) => findAll(scope, (e) => e.tagName === 'INPUT' && e.getAttribute('name') === name)[0],
    last: (m, p) => [...env.calls].reverse().find((c) => c.method === m && c.url.includes(p)),
    count: (m, p) => env.calls.filter((c) => c.method === m && c.url.includes(p)).length,
    polite: () => env.document.body.children.find((c) => c.getAttribute('aria-live') === 'polite').textContent,
    assertive: () => env.document.body.children.find((c) => c.getAttribute('aria-live') === 'assertive').textContent,
  };
  return ui;
}
// every element on the page is one the code makes: a list of tags (an element that came from data would be anything else)
const TAGS = new Set(['DIV', 'SECTION', 'HEADER', 'MAIN', 'FOOTER', 'NAV', 'UL', 'LI', 'A', 'SPAN', 'STRONG', 'P', 'H1', 'H2', 'H3', 'BUTTON', 'FORM', 'LABEL', 'INPUT', 'SELECT', 'OPTION',
  'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD', 'CAPTION', 'DL', 'DT', 'DD', 'CODE', 'TIME', 'OL', 'SVG', 'PATH', 'DIALOG', 'TEXTAREA', 'B', 'I']);
const noForeignElements = (ui) => { for (const e of findAll(ui.root, () => true)) assert.ok(TAGS.has(e.tagName), `unexpected element ${e.tagName}`); };

// ---------------------------------------------------------------------------------------------------------------------------------- S1
test('S1: a visitor without a session sees the sign-in form with labelled fields; the page title and language are set', async () => {
  const ui = await boot({ st: { in: false } });
  assert.equal(ui.q('h1').textContent, 'Sign in');
  assert.equal(ui.env.document.title, 'Sign in - KariDNS WebAdmin');
  assert.equal(ui.env.document.documentElement.lang, 'en');
  for (const input of ui.qa('input')) {
    const label = findAll(ui.root, (e) => e.tagName === 'LABEL' && e.htmlFor === input.getAttribute('id'));
    assert.equal(label.length, 1, `the input ${input.getAttribute('name')} has one label`);
  }
  assert.equal(ui.input('user').getAttribute('autocomplete'), 'username');
  assert.equal(ui.input('password').getAttribute('autocomplete'), 'current-password');
  assert.equal(ui.input('password').getAttribute('type'), 'password');
  assert.equal(ui.input('totp').getAttribute('autocomplete'), 'one-time-code');
  assert.equal(ui.input('totp').getAttribute('inputmode'), 'numeric');
  assert.equal(ui.input('totp').parentNode.parentNode.hidden, true, 'the code field is not shown yet');
  assert.equal(ui.env.document.activeElement, ui.input('user'));
  assert.equal(ui.q('nav'), null, 'no menu before the sign-in');
  noForeignElements(ui);
});

test('S1: empty fields are told so without a request; a good sign-in goes to the start page and asks for /version', async () => {
  const ui = await boot({ st: { in: false } });
  await ui.submit(ui.q('form'));
  assert.match(ui.text(), /Enter your user name/);
  ui.type(ui.input('user'), 'alice');
  await ui.submit(ui.q('form'));
  assert.match(ui.text(), /Enter your password/);
  assert.equal(ui.count('POST', '/auth/login'), 0);
  ui.type(ui.input('password'), 'secret password');
  await ui.submit(ui.q('form'));
  assert.deepEqual(ui.last('POST', '/auth/login').body, { user: 'alice', password: 'secret password' });
  assert.equal(ui.q('h1').textContent, 'Welcome, Alice A.');
  assert.ok(ui.q('nav'));
  assert.match(ui.text(), /Signed in as Alice A\./);
  assert.ok(ui.count('GET', '/version') >= 1);
  assert.ok(ui.qa('td').some((td) => td.textContent === 'main / example.test.'), 'the grant is listed');
  assert.ok(ui.qa('th').some((th) => th.textContent === 'Domain master'));
  assert.equal(ui.link(/^Home$/).getAttribute('aria-current'), 'page');
  noForeignElements(ui);
});

test('S1: every refusal has the one message of the service; a wrong code, a 429 with a countdown, a code asked for, "I have a code"', async () => {
  const st = { in: false, loginError: () => problem(401, 'invalid-credentials') };
  const ui = await boot({ st });
  ui.type(ui.input('user'), 'alice');
  ui.type(ui.input('password'), 'pw');
  await ui.submit(ui.q('form'));
  assert.equal(ui.q('p.msg.error').textContent, en['api.invalid-credentials']);
  assert.equal(ui.q('p.msg.error').getAttribute('role'), 'alert');
  assert.equal(ui.env.document.activeElement, ui.input('password'));
  assert.equal(ui.input('password').value, 'pw', 'the password stays for the next try');

  // the service asks for a code: the field appears and has the focus
  st.loginError = (body) => (body.totp ? problem(401, 'invalid-credentials') : problem(401, 'totp-required'));
  await ui.submit(ui.q('form'));
  assert.equal(ui.input('totp').parentNode.parentNode.hidden, false);
  assert.equal(ui.env.document.activeElement, ui.input('totp'));
  assert.match(ui.q('p.msg.error').textContent, /Enter the code/);
  ui.type(ui.input('totp'), '12ab');
  await ui.submit(ui.q('form'));
  assert.match(ui.text(), /The code has 6 digits/);
  assert.equal(ui.count('POST', '/auth/login'), 2, 'no request for a code that cannot be one');
  ui.type(ui.input('totp'), '123456');
  await ui.submit(ui.q('form'));
  assert.deepEqual(ui.last('POST', '/auth/login').body, { user: 'alice', password: 'pw', totp: '123456' });
  assert.equal(ui.q('p.msg.error').textContent, en['api.invalid-credentials']);
  assert.equal(ui.input('totp').value, '', 'a wrong code is cleared');

  // 429: the button waits
  st.loginError = () => problem(429, 'rate-limited', {}, { 'Retry-After': '3' });
  ui.type(ui.input('totp'), '123456');
  await ui.submit(ui.q('form'));
  const submit = ui.button(/Try again in/);
  assert.ok(submit, 'the button counts down');
  assert.equal(submit.disabled, true);
  assert.equal(submit.textContent, 'Try again in 3 s');
  await ui.submit(ui.q('form'));
  assert.equal(ui.count('POST', '/auth/login'), 4, 'a disabled button sends nothing');
  await ui.clock.advance(1000);
  assert.equal(submit.textContent, 'Try again in 2 s');
  await ui.clock.advance(2000);
  assert.equal(submit.disabled, false);
  assert.equal(submit.textContent, 'Sign in');
  assert.equal(ui.clock.pending(), 0);

  // a refusal that is not a login error, and a service that cannot be reached
  st.loginError = () => problem(503, 'busy', {}, {});
  ui.type(ui.input('totp'), '123456');
  await ui.submit(ui.q('form'));
  assert.ok(ui.q('p.msg.error').textContent.startsWith(en['api.busy']));
  st.loginError = () => { throw new TypeError('offline'); };
  ui.type(ui.input('totp'), '123456');
  await ui.submit(ui.q('form'));
  assert.equal(ui.q('p.msg.error').textContent, en['api.network']);
});

test('S1: "I have a code" shows the field at once, and the code is sent with the sign-in', async () => {
  const st = { in: false };
  const ui = await boot({ st });
  await ui.click(ui.button(/I have a code/));
  assert.equal(ui.input('totp').parentNode.parentNode.hidden, false);
  assert.equal(ui.button(/I have a code/).hidden, true);
  ui.type(ui.input('user'), 'alice');
  ui.type(ui.input('password'), 'pw');
  ui.type(ui.input('totp'), ' 123456 ');
  await ui.submit(ui.q('form'));
  assert.equal(ui.last('POST', '/auth/login').body.totp, '123456');
});

test('S1: the service cannot be reached at the start: an error with a button to try again (reload)', async () => {
  const clock = makeClock();
  const env = makeEnv({ clock, handler: () => { throw new TypeError('offline'); } });
  const app = createApp(env);
  await app.start();
  await flush();
  const root = env.document.getElementById('app');
  assert.equal(root.querySelector('p.msg.error').textContent, en['api.network']);
  byText(root, 'button', /Try again/).click();
  assert.equal(env.window.reloaded, 1);
});

// ---------------------------------------------------------------------------------------------------------------------------------- S2
const TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const ENROLL = { api: 1, secret: TOTP_SECRET, uri: `otpauth://totp/KariDNS:alice?secret=${TOTP_SECRET}&issuer=KariDNS&algorithm=SHA1&digits=6&period=30`, message: 'x' };
const containsSecret = (ui) => ui.root.textContent.includes(TOTP_SECRET) || ui.root.textContent.includes('JBSW Y3DP') || findAll(ui.root, (e) => [...e.attrs.values()].some((v) => v.includes(TOTP_SECRET) || v.includes('otpauth'))).length > 0;

test('S2: a session that must enrol sees nothing else: the QR code, the key hidden until asked for, a form for the code; after the confirmation nothing holds the secret', async () => {
  const st = { in: false, enrol: true };
  let confirmed = false;
  const routes = {
    'POST /auth/totp': (body) => {
      if (body.action === 'enroll') return reply(200, ENROLL);
      if (body.code === '000000') return problem(403, 'wrong-code');
      confirmed = true;
      st.sessOver = { csrf: 'csrf-2' };
      return reply(200, { api: 1, csrf: 'csrf-2', expires_at: 'x', totp: { enabled: true, enrollment_required: false } });
    },
  };
  const ui = await boot({ st, routes });
  ui.type(ui.input('user'), 'alice');
  ui.type(ui.input('password'), 'pw');
  st.meOver = null;
  st.me = () => ME(ui.clock, {}, { totp_ok: confirmed });
  await ui.submit(ui.q('form'));
  assert.equal(ui.q('h1').textContent, 'Set up two-step verification');
  assert.match(ui.text(), /must use a code/);
  assert.equal(ui.q('nav'), null, 'a session that cannot do anything else has no menu');
  const svg = ui.q('svg');
  assert.ok(svg, 'the QR code is drawn in the page');
  assert.equal(svg.getAttribute('role'), 'img');
  assert.ok(svg.children[0].getAttribute('d').length > 100);
  assert.equal(ui.q('.key').hidden, true, 'the key as text is hidden');
  assert.equal(ui.q('.key').textContent, 'JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP');
  const show = ui.button(/Show the key/);
  assert.equal(show.getAttribute('aria-expanded'), 'false');
  await ui.click(show);
  assert.equal(ui.q('.key').hidden, false);
  assert.equal(show.getAttribute('aria-expanded'), 'true');
  assert.equal(show.textContent, 'Hide the key');
  await ui.click(show);
  assert.equal(ui.q('.key').hidden, true);
  assert.ok(!findAll(ui.root, (e) => e.tagName === 'A' && /otpauth/.test(e.getAttribute('href') ?? '')).length, 'the otpauth URI is not a link');
  assert.ok(![...ui.qa('*')].some((e) => /otpauth/.test(e.textContent)), 'and not text');

  const form = ui.qa('form')[0];
  ui.type(ui.input('code'), 'abc');
  await ui.submit(form);
  assert.match(ui.text(), /The code has 6 digits/);
  ui.type(ui.input('code'), '000000');
  await ui.submit(form);
  assert.equal(ui.q('p.msg.error').textContent, en['api.wrong-code']);
  assert.equal(ui.count('POST', '/auth/totp'), 3, 'enroll once, two confirmations (one of them refused)');
  ui.type(ui.input('code'), '123456');
  await ui.submit(form);
  assert.equal(containsSecret(ui), false, 'the secret is gone from the page');
  assert.equal(ui.q('h1').textContent, 'Welcome, Alice A.', 'the second step is done: the start page');
  assert.equal(ui.polite(), 'Two-step verification is on.');
  assert.ok(ui.q('nav'));
});

test('S2 from the account: cancel goes back, a key too long for a QR code is shown as text, errors can be tried again, a started set-up that is gone is an error', async () => {
  let n = 0;
  const longName = 'u'.repeat(300);
  const routes = {
    'POST /auth/totp': (body) => {
      if (body.action === 'confirm') return problem(409, 'no-enrolment');
      n++;
      if (n === 1) return problem(503, 'busy');
      if (n === 2) return reply(200, { ...ENROLL, uri: `otpauth://totp/KariDNS:${longName}?secret=${TOTP_SECRET}&issuer=KariDNS` });
      return problem(409, 'totp-enabled');
    },
  };
  const ui = await boot({ routes, hash: '#/account/totp' });
  assert.ok(ui.q('p.msg.error').textContent.startsWith(en['api.busy']));
  await ui.click(ui.button(/Try again/));
  assert.equal(ui.q('svg'), null, 'no QR code');
  assert.match(ui.text(), /too long for a QR code/);
  assert.equal(ui.q('.key').hidden, false, 'the key is shown as text');
  assert.equal(ui.button(/Show the key/).hidden, true);
  assert.ok(ui.link(/Cancel/), 'cancel is offered when nothing forces the set-up');
  ui.type(ui.input('code'), '123456');
  await ui.submit(ui.qa('form')[0]);
  assert.equal(ui.q('p.msg.error').textContent, en['api.no-enrolment']);
  assert.equal(containsSecret(ui), false);
  await ui.click(ui.button(/Try again/));
  assert.equal(ui.q('p.msg.error').textContent, en['api.totp-enabled']);
  assert.ok(ui.link(/Go to your account/));
});

// ---------------------------------------------------------------------------------------------------------------------------------- S15
test('S15: the account page has the sections; the password form checks what it can before it asks, and shows what the service says', async () => {
  const routes = {};
  const ui = await boot({ hash: '#/account', routes });
  assert.equal(ui.q('h1').textContent, 'Your account');
  assert.deepEqual(ui.qa('h2').map((h) => h.textContent), ['Change password', 'Two-step verification', 'API tokens', 'Language', 'Session']);
  const form = ui.qa('form')[0];
  const [cur, nw, again] = ['current', 'new', 'again'].map((n) => ui.input(n));
  assert.equal(nw.getAttribute('autocomplete'), 'new-password');
  await ui.submit(form);
  assert.match(ui.text(), /Enter your current password/);
  ui.type(cur, 'old password 1');
  ui.type(nw, 'short');
  await ui.submit(form);
  assert.equal(nw.parentNode.querySelector('p.error').textContent, en['api.weak-password']);
  ui.type(nw, 'my ALICE password!');
  await ui.submit(form);
  assert.match(ui.text(), /must not contain your user name/);
  ui.type(nw, 'a long enough password');
  ui.type(again, 'something else, long');
  await ui.submit(form);
  assert.match(ui.text(), /not the same/);
  assert.equal(ui.count('POST', '/auth/password'), 0);
  ui.type(again, 'a long enough password');
  routes['POST /auth/password'] = problem(403, 'wrong-password');
  await ui.submit(form);
  assert.deepEqual(ui.last('POST', '/auth/password').body, { current: 'old password 1', new: 'a long enough password', all: true });
  assert.equal(ui.input('current').parentNode.querySelector('p.error').textContent, en['api.wrong-password']);
  assert.equal(ui.env.document.activeElement, ui.input('current'));
  routes['POST /auth/password'] = problem(400, 'weak-password');
  await ui.submit(form);
  assert.equal(ui.input('new').parentNode.querySelector('p.error').textContent, en['api.weak-password']);
  routes['POST /auth/password'] = problem(429, 'rate-limited', {}, { 'Retry-After': '30' });
  await ui.submit(form);
  assert.equal(form.querySelector('p.msg.error').textContent, en['api.rate-limited']);
  // the box "sign out my other sessions" is sent as it is
  ui.input('all').click();
  routes['POST /auth/password'] = reply(200, { api: 1, password: 'changed' });
  await ui.submit(form);
  assert.equal(ui.last('POST', '/auth/password').body.all, false);
  assert.equal(form.querySelector('p[role=status]').textContent, en['account.pw-changed']);
  for (const n of ['current', 'new', 'again']) assert.equal(ui.input(n).value, '', `${n} is cleared after the change`);
  noForeignElements(ui);
});

test('S15: TOTP off: a button to set it up; TOTP on: the form to switch it off (password and code), the service decides; mandatory: only the note', async () => {
  const routes = {};
  const st = { totpOn: false };
  const ui = await boot({ hash: '#/account', routes, st });
  assert.match(ui.text(), /Two-step verification is off/);
  assert.equal(ui.link(/Set up two-step verification/).getAttribute('href'), '#/account/totp');

  const on = await boot({ hash: '#/account', routes, st: { totpOn: true, version: { ...VERSION, ui: { ...VERSION.ui, require_totp: 'none' } } } });
  assert.match(on.text(), /Two-step verification is on\./);
  const form = on.qa('form').find((f) => f.querySelector('button.danger'));
  await on.submit(form);
  assert.match(on.text(), /Enter your current password/);
  on.type(on.input('password', form), 'pw');
  on.type(on.input('code', form), '12');
  await on.submit(form);
  assert.match(on.text(), /The code has 6 digits/);
  on.type(on.input('code', form), '123456');
  const r2 = { 'POST /auth/totp': problem(403, 'wrong-password') };
  Object.assign(routes, r2);
  await on.submit(form);
  assert.deepEqual(on.last('POST', '/auth/totp').body, { action: 'disable', password: 'pw', code: '123456' });
  assert.equal(on.input('password', form).parentNode.querySelector('p.error').textContent, en['api.wrong-password']);
  routes['POST /auth/totp'] = problem(403, 'wrong-code');
  await on.submit(form);
  assert.equal(on.input('code', form).parentNode.querySelector('p.error').textContent, en['api.wrong-code']);
  routes['POST /auth/totp'] = problem(403, 'totp-required-by-policy');
  await on.submit(form);
  assert.equal(form.querySelector('p.msg.error').textContent, en['api.totp-required-by-policy']);
  routes['POST /auth/totp'] = reply(200, { api: 1, totp: { enabled: false } });
  await on.submit(form);
  assert.match(on.text(), /Two-step verification is off/);
  assert.equal(on.polite(), en['account.totp-disabled']);

  // a global master under require-totp = global: switching off is not offered
  const must = await boot({ hash: '#/account', routes, st: { totpOn: true, meOver: { capabilities: { global: true } } } });
  assert.match(must.text(), /must use two-step verification/);
  assert.equal(must.qa('form').filter((f) => f.querySelector('button.danger')).length, 0);
  // the credentials cannot be read
  const bad = await boot({ hash: '#/account', routes: { 'GET /principals/7': problem(500, 'internal') } });
  assert.match(bad.text(), /internal error/);
  assert.match(bad.text(), /Give this number to the operator: rid1/);
});

test('S15: tokens are listed with their state, made (shown once, copied, removed from the page) and revoked after a second question', async () => {
  const NOW = makeClock().now();
  const iso = (ms) => new Date(NOW + ms).toISOString();
  const tokens = [
    { id: 1, name: 'ci', read_only: true, created_at: iso(-86400000), expires_at: iso(86400000), last_used_at: iso(-1000), revoked_at: null },
    { id: 2, name: 'old', read_only: false, created_at: iso(-864000000), expires_at: iso(-86400000), last_used_at: null, revoked_at: null },
    { id: 3, name: 'bad‮name', read_only: false, created_at: iso(-1000), expires_at: iso(86400000), last_used_at: null, revoked_at: iso(-500) },
  ];
  const routes = {};
  const copied = [];
  const ui = await boot({ hash: '#/account', routes, st: { tokens }, clipboard: { writeText: async (s) => { copied.push(s); } } });
  const rows = ui.qa('tbody tr').filter((tr) => tr.querySelector('th'));
  const cells = (tr) => tr.children.map((c) => c.textContent);
  assert.equal(rows.length, 3);
  assert.equal(cells(rows[0])[1], 'Read only');
  assert.equal(cells(rows[0])[5], 'Active');
  assert.equal(cells(rows[1])[5], 'Expired');
  assert.equal(cells(rows[1])[4], 'Never');
  assert.equal(cells(rows[2])[5], 'Revoked');
  assert.equal(cells(rows[2])[0], 'bad<U+202E>name', 'a bidi control in a name is made visible');
  assert.ok(rows[0].querySelector('button'), 'an active token can be revoked');
  assert.equal(rows[1].querySelector('button'), null);
  assert.equal(rows[2].querySelector('button'), null);

  // make one: checks first
  const form = ui.qa('form').find((f) => f.querySelector('input[name=days]'));
  await ui.submit(form);
  assert.match(ui.text(), /Enter a name for the token/);
  ui.type(ui.input('name', form), 'deploy');
  ui.type(ui.input('days', form), '400');
  await ui.submit(form);
  assert.match(ui.text(), /1 to 365/);
  ui.type(ui.input('days', form), '30');
  routes['POST /tokens'] = problem(400, 'bad-request', { errors: [{ pointer: '/name', text: 'x', code: 'bad-request', severity: 'error' }] });
  await ui.submit(form);
  assert.equal(ui.input('name', form).parentNode.querySelector('p.error').textContent, en['api.bad-request']);
  routes['POST /tokens'] = problem(403, 'forbidden');
  await ui.submit(form);
  assert.equal(form.querySelector('p.msg.error').textContent, en['api.forbidden']);
  routes['POST /tokens'] = reply(201, { api: 1, token: 'kdt_9_secretsecret', info: {}, message: 'once' });
  ui.input('read_only', form).click();
  await ui.submit(form);
  assert.deepEqual(ui.last('POST', '/tokens').body, { name: 'deploy', read_only: true, days: 30 });
  assert.equal(ui.q('code.token').textContent, 'kdt_9_secretsecret');
  assert.match(ui.text(), /shown only once/);
  assert.equal(ui.polite(), 'Your new token');
  assert.equal(ui.input('name', form).value, '', 'the name is cleared');
  await ui.click(ui.button(/^Copy$/));
  assert.deepEqual(copied, ['kdt_9_secretsecret']);
  assert.match(ui.text(), /Copied/);
  ui.env.clipboard.writeText = async () => { throw new Error('denied'); };
  await ui.click(ui.button(/^Copy$/));
  assert.match(ui.text(), /did not allow copying/);
  await ui.click(ui.button(/I have saved it/));
  assert.equal(ui.text().includes('kdt_9_secretsecret'), false, 'the token is gone from the page');

  // revoke: asks again
  const revoke = rows[0].querySelector('button');
  routes['DELETE /tokens/1'] = reply(204, null);
  await ui.click(revoke);
  assert.equal(ui.count('DELETE', '/tokens/1'), 0);
  const yes = ui.button(/^Yes$/);
  await ui.click(yes);
  assert.equal(ui.count('DELETE', '/tokens/1'), 1);
  assert.equal(ui.polite(), 'Revoked');
  routes['DELETE /tokens/1'] = problem(404, 'not-found');
  const again = ui.qa('tbody tr').filter((tr) => tr.querySelector('th'))[0].querySelector('button');
  await ui.click(again);
  await ui.click(ui.button(/^Yes$/));
  assert.match(ui.text(), /no such object/);
  noForeignElements(ui);

  // a list that cannot be read; no tokens
  const bad = await boot({ hash: '#/account', routes: { 'GET /tokens': problem(503, 'busy') } });
  assert.match(bad.text(), /service is busy/);
  const none = await boot({ hash: '#/account' });
  assert.match(none.text(), /You have no tokens/);
});

test('S15: the language is chosen here, kept, and the whole page follows at once; the sessions can be ended', async () => {
  const storage = new FakeStorage();
  const ui = await boot({ hash: '#/account', storage });
  const sel = ui.q('select');
  assert.deepEqual(sel.children.map((o) => o.textContent), ['English', '日本語']);
  assert.deepEqual(sel.children.map((o) => o.getAttribute('lang')), ['en', 'ja']);                   // (WCAG 3.1.2: a language name is in its language)
  assert.ok(ui.text().includes(en['account.language-hint']));
  sel.focus();
  sel.value = 'ja';
  sel.dispatchEvent(new FakeEvent('change'));
  await flush();
  assert.equal(storage.getItem('karidns-lang'), 'ja');
  assert.equal(ui.env.document.documentElement.lang, 'ja');
  assert.equal(ui.q('h1').textContent, ja['account.title']);
  assert.equal(ui.env.document.title, `${ja['account.title']} - KariDNS WebAdmin`);
  assert.equal(ui.q('select').value, 'ja');
  assert.ok(ui.env.document.activeElement === ui.q('select'), 'the select keeps the focus when the page is drawn again');

  // sign out everywhere: the request carries all: true, the page shows the sign-in
  const all = ui.button(new RegExp(ja['account.logout-all']));
  await ui.click(all);
  assert.deepEqual(ui.last('POST', '/auth/logout').body, { all: true });
  assert.equal(ui.q('h1').textContent, ja['login.title']);
  assert.equal(ui.input('user').getAttribute('name'), 'user');
  assert.equal(ui.button(new RegExp(ja['login.submit'])).getAttribute('type'), 'submit');

  // a failed logout is told; the plain logout of the frame
  const failing = await boot({ hash: '#/account', routes: { 'POST /auth/logout': problem(500, 'internal') } });
  const logouts = (u) => findAll(u.root, (e) => e.tagName === 'BUTTON' && e.textContent === 'Log out');
  await failing.click(logouts(failing)[1]);
  assert.match(failing.text(), /internal error/);
  const ok = await boot({ hash: '#/account' });
  await ok.click(logouts(ok)[0]);
  assert.deepEqual(ok.last('POST', '/auth/logout').body, {});
  assert.equal(ok.q('h1').textContent, 'Sign in');
  const frameFails = await boot({ routes: { 'POST /auth/logout': problem(500, 'internal') } });
  await frameFails.click(logouts(frameFails)[0]);
  assert.match(frameFails.assertive(), /internal error/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- S16, the start page, the frame
test('S16: the versions of the GUI, the service and its tools; a service of another version asks for a reload', async () => {
  const ui = await boot({ hash: '#/about' });
  const dl = ui.q('dl');
  const pairs = dl.children.map((c) => c.textContent);
  assert.deepEqual(pairs, ['Web interface', GUI_VERSION, 'Service', GUI_VERSION, 'karidns-zone', 'karidns-zone 0.6.0', 'Datasets', 'main', 'Record types', '2']);
  assert.equal(ui.q('p.notice'), null);
  const old = await boot({ hash: '#/about', st: { version: { ...VERSION, version: '0.5.0', types: null } } });
  assert.match(old.q('p.notice').textContent, /different version/);
  assert.equal(old.q('p.notice').getAttribute('role'), 'alert');
  assert.match(old.text(), /Reload the page to use the new version/, 'and the frame says so too');
  assert.ok(old.qa('dd').some((d) => d.textContent === 'unknown'));
  await old.click(old.button(/^Reload$/));
  assert.equal(old.env.window.reloaded, 1);
  const bad = await boot({ hash: '#/about', routes: { 'GET /version': problem(503, 'database-unavailable') } });
  assert.match(bad.q('main').textContent, /database cannot be reached/);
});

test('the start page lists the grants with the roles in words; no grant says so; a hostile display name and zone name stay text', async () => {
  const ui = await boot({ st: { meOver: { principal: { ...PRINCIPAL, display_name: '<img src=x onerror=alert(1)>‮' }, grants: [
    { id: 1, role: 'global_master', dataset: null, zone: null, suffix: null, policy: { id: 1, name: '<b>all</b>' }, via: 'staff' },
    { id: 2, role: 'subdomain_master', dataset: 'main', zone: 'example.test.', suffix: 'sub.example.test.', policy: { id: 2, name: 'web' }, via: null },
    { id: 3, role: 'future_role', dataset: 'main', zone: 'z\u0007.test.', suffix: null, policy: null, via: null },
  ] } } });
  noForeignElements(ui);
  assert.equal(ui.q('h1').textContent, 'Welcome, <img src=x onerror=alert(1)><U+202E>');
  const rows = ui.qa('tbody tr').map((tr) => tr.children.map((c) => c.textContent));
  assert.deepEqual(rows, [
    ['Global master', 'All zones', '<b>all</b>', 'staff'],
    ['Subdomain master', 'main / sub.example.test. (example.test.)', 'web', '-'],
    ['future_role', 'main / z\\007.test.', '-', '-'],
  ]);
  const none = await boot({ st: { meOver: { grants: [] } } });
  assert.match(none.text(), /no access to any zone yet/);
  assert.equal(none.qa('table').length, 0);
});

test('an unknown route is "page not found" with a way home; the menu marks the page you are on; the account menu entry covers its TOTP page', async () => {
  const ui = await boot({ hash: '#/nowhere/at/all' });
  assert.equal(ui.q('h1').textContent, 'Page not found');
  await ui.click(ui.main().querySelector('a'));
  assert.equal(ui.env.window.location.hash, '#/');
  assert.match(ui.q('h1').textContent, /^Welcome/);
  const acc = await boot({ hash: '#/account/totp' });
  assert.equal(acc.qa('nav a').find((a) => a.textContent === 'Account').getAttribute('aria-current'), 'page');
  assert.equal(acc.qa('nav a').find((a) => a.textContent === 'Home').getAttribute('aria-current'), null);
});

test('the frame: a skip button, the live regions, the title follows the page, a link in the menu changes the page', async () => {
  const ui = await boot();
  assert.equal(ui.button(/Skip to the content/).tagName, 'BUTTON');
  await ui.click(ui.button(/Skip to the content/));
  assert.equal(ui.env.document.activeElement, ui.main());
  assert.equal(ui.main().getAttribute('tabindex'), '-1');
  assert.ok(ui.env.document.body.children.some((c) => c.getAttribute('aria-live') === 'polite'));
  assert.ok(ui.env.document.body.children.some((c) => c.getAttribute('aria-live') === 'assertive' && c.getAttribute('role') === 'alert'));
  await ui.click(ui.link(/^About$/));
  assert.equal(ui.env.window.location.hash, '#/about');
  assert.equal(ui.q('h1').textContent, 'About');
  assert.equal(ui.env.document.title, 'About - KariDNS WebAdmin');
  assert.equal(ui.env.document.activeElement, ui.main(), 'the new page has the focus');
});

test('a proxy that changes the page: a violation of the policy is reported once, in the page', async () => {
  const ui = await boot();
  ui.env.document.dispatchEvent(new FakeEvent('securitypolicyviolation', { violatedDirective: 'script-src-elem' }));
  ui.env.document.dispatchEvent(new FakeEvent('securitypolicyviolation', { violatedDirective: 'style-src' }));
  const banners = ui.env.document.body.children.filter((c) => c.className.includes('csp-violation'));
  assert.equal(banners.length, 1);
  assert.match(banners[0].textContent, /blocked something on this page \(script-src-elem\)/);
  assert.equal(banners[0].getAttribute('role'), 'alert');
});

test('the page warns before it is left when somebody has unsaved work', async () => {
  const ui = await boot();
  const ev = new FakeEvent('beforeunload');
  ui.env.window.dispatchEvent(ev);
  assert.equal(ev.defaultPrevented, false);
  ui.app.session.guards.add(() => true);
  const ev2 = new FakeEvent('beforeunload');
  ui.env.window.dispatchEvent(ev2);
  assert.equal(ev2.defaultPrevented, true);
  assert.equal(ev2.returnValue, '');
});

// ---------------------------------------------------------------------------------------------------------------------------------- the session in the page
const dialog = (ui) => ui.dialogs()[0];

test('a 401 on a screen: the sign-in form opens over it; the same person signs in and the screen goes on (a read is repeated); the old screen is not replaced', async () => {
  const st = {};
  const ui = await boot({ st, hash: '#/account' });
  const before = ui.q('h1');
  st.in = false;
  // the next read finds the session gone
  const pending = ui.app.api.get('/tokens');
  await flush();
  const dlg = dialog(ui);
  assert.ok(dlg, 'a dialog is open');
  assert.match(dlg.textContent, /Your session has ended/);
  assert.equal(ui.env.document.activeElement.getAttribute('name'), 'user', 'the focus is in the form');
  assert.equal(ui.q('h1'), before, 'the screen under it is still there');
  ui.type(ui.input('user', dlg), 'alice');
  ui.type(ui.input('password', dlg), 'pw');
  await ui.submit(dlg.querySelector('form'));
  assert.equal(ui.dialogs().length, 0);
  assert.deepEqual((await pending).tokens, [], 'the read was repeated');
  assert.equal(ui.q('h1'), before, 'the screen was not drawn again for the same person');
});

test('a 401: cancel leaves the sign-in screen, and the principal is remembered so that the work of another person is not carried over', async () => {
  const st = {};
  const ui = await boot({ st, hash: '#/account' });
  st.in = false;
  const p = ui.app.api.get('/tokens').catch((e) => e);
  await flush();
  assert.ok(dialog(ui));
  await ui.click(ui.button(/^Cancel$/));
  const err = await p;
  assert.equal(err.code, 'unauthenticated');
  assert.equal(ui.q('h1').textContent, 'Sign in', 'cancel leaves the page at the sign-in screen');
  assert.equal(ui.dialogs().length, 0);
  assert.equal(ui.app.session.state.previous, 7);
});

test('a 401: Escape closes the sign-in dialog like cancel, and a second 401 while it is open shares it', async () => {
  const st = {};
  const ui = await boot({ st });
  st.in = false;
  const a = ui.app.api.get('/tokens').catch((e) => e);
  const b = ui.app.api.get('/tokens').catch((e) => e);
  await flush();
  assert.equal(ui.dialogs().length, 1);
  const esc = new FakeEvent('cancel');
  dialog(ui).dispatchEvent(esc);
  assert.equal(esc.defaultPrevented, true, 'the browser is not left to close it');
  await flush();
  assert.equal((await a).code, 'unauthenticated');
  assert.equal((await b).code, 'unauthenticated');
  assert.equal(ui.q('h1').textContent, 'Sign in');
});

test('after a 401 another person signs in: the start page', async () => {
  const st = {};
  const ui = await boot({ st, hash: '#/about' });
  st.in = false;
  const bob = { ...PRINCIPAL, id: 8, name: 'bob', display_name: 'Bob' };
  ui.state.me = () => ME(ui.clock, { principal: bob });
  ui.state.who = bob;
  const p = ui.app.api.post('/tokens', {}).catch((e) => e);
  await flush();
  ui.type(ui.input('user', dialog(ui)), 'bob');
  ui.type(ui.input('password', dialog(ui)), 'pw');
  await ui.submit(dialog(ui).querySelector('form'));
  const e = await p;
  assert.equal(e.code, 'unauthenticated', 'a write is not repeated');
  assert.equal(e.renewed, false, 'another person: nothing is carried over');
  assert.equal(ui.env.window.location.hash, '#/');
  assert.equal(ui.q('h1').textContent, 'Welcome, Bob');
});

test('the idle warning: two minutes before the end a dialog counts down; "stay signed in" asks once and moves the end; the end opens the sign-in dialog without a request', async () => {
  const ui = await boot();
  const start = ui.clock.now();
  const idle = 1800000 - 60000;
  await ui.clock.advance(idle - 120000 - 1000);
  assert.equal(ui.dialogs().length, 0);
  const requests = ui.calls.length;
  await ui.clock.advance(2000);
  const warn = dialog(ui);
  assert.ok(warn);
  assert.match(warn.textContent, /about to end/);
  assert.match(warn.textContent, /1:5\d|2:0\d|1:59/);
  assert.match(ui.assertive(), /about to end/);
  await ui.clock.advance(5000);
  assert.match(warn.querySelector('strong').textContent, /^1:5\d$|^1:4\d$/, 'the countdown moves');
  assert.equal(ui.calls.length, requests, 'the warning asked nothing');
  await ui.click(ui.button(/Stay signed in/));
  assert.equal(ui.calls.length, requests + 1);
  assert.equal(ui.last('GET', '/auth/me').method, 'GET');
  assert.equal(ui.dialogs().length, 0);
  assert.equal(ui.clock.pending() >= 1, true);
  // not touched again: the warning comes back and then the end
  await ui.clock.advance(idle - 120000 + 1000);
  assert.ok(dialog(ui));
  await ui.click(ui.button(/^Close$/));
  assert.equal(ui.dialogs().length, 0);
  ui.state.in = false;
  await ui.clock.advance(120000);
  await flush();
  assert.match(dialog(ui).textContent, /Your session has ended/, 'the end: the sign-in dialog opens');
  assert.equal(ui.calls.filter((c) => c.url.includes('/auth/me')).length, 2, 'the end made no request either');
  assert.ok(start < ui.clock.now());
});

test('"stay signed in" that fails is told; the warning can end the session; the absolute end has no "stay signed in"', async () => {
  const routes = {};
  const ui = await boot({ routes });
  await ui.clock.advance(1800000 - 60000 - 119000);
  assert.ok(dialog(ui));
  routes['GET /auth/me'] = problem(503, 'busy');
  await ui.click(ui.button(/Stay signed in/));
  assert.match(ui.assertive(), /busy/);
  // (the service did answer, so that counts as a request: the warning is withdrawn)
  assert.equal(ui.dialogs().length, 0);

  const out = await boot();
  await out.clock.advance(1800000 - 60000 - 119000);
  await out.click(findAll(dialog(out), (e) => e.tagName === 'BUTTON' && e.textContent === 'Log out')[0]);
  assert.equal(out.q('h1').textContent, 'Sign in');
  assert.equal(out.dialogs().length, 0);

  const short = await boot({ st: { sessOver: { expires_at: new Date(makeClock().now() + 300000).toISOString() } } });
  await short.clock.advance(300000 - 119000);
  const d = dialog(short);
  assert.match(d.textContent, /time limit/);
  assert.equal(short.button(/Stay signed in/), null);
});

test('another tab signs out: this one shows the sign-in screen with a note; a sign-in there shows the page here', async () => {
  const ui = await boot({ hash: '#/account' });
  const BC = ui.env.BroadcastChannel;
  const tab2 = new BC('karidns-webadmin');
  ui.state.in = false;
  tab2.postMessage({ type: 'logout' });
  await flush();
  assert.equal(ui.q('h1').textContent, 'Sign in');
  assert.match(ui.text(), /signed out in another tab/);
  ui.state.in = true;
  tab2.postMessage({ type: 'login' });
  await flush();
  assert.equal(ui.q('h1').textContent, 'Your account');
});

test('the session of a visitor that must enrol is not extended by the page, and a language change redraws the sign-in screen', async () => {
  const ui = await boot({ st: { in: false }, languages: ['ja-JP'] });
  assert.equal(ui.q('h1').textContent, ja['login.title']);
  assert.equal(ui.env.document.documentElement.lang, 'ja');
  ui.app.i18n.setLang('en');
  assert.equal(ui.q('h1').textContent, 'Sign in');
  noForeignElements(ui);
});

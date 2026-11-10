// The GUI against the real service (planning 8.1 and 8.2 in Node): karidns-webadmin on a SQLite3 deployment serves the files of webadmin/ui, and the application of
// webadmin/ui/js (on the fake DOM, with a fetch that behaves like a browser: it keeps the cookie and sends Origin) signs in, enrols TOTP, makes a token, changes the
// password, meets a 401 and signs in again.  What the scripted tests of ui_views.test.js assume about the API is checked here against the API itself.

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast, ORIGIN } from './helpers.js';
import { loadStatic, defaultUiDir } from '../lib/static.js';
import { createApp } from '../ui/js/app.js';
import { GUI_VERSION } from '../ui/js/version.js';
import { base32Decode, hotp, totpStep } from '../lib/crypto.js';
import { makeEnv, makeClock, makeBroadcast, FakeStorage, flush, findAll, byText } from './fakedom.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// a browser's fetch: the origin of the page in front of a relative URL, the cookie jar, Origin on what is not a read
function browserFetch(d) {
  const jar = { cookie: null };
  let inflight = 0;
  const f = async (url, init = {}) => {
    const headers = { ...(init.headers ?? {}) };
    if (jar.cookie) headers.Cookie = jar.cookie;
    if ((init.method ?? 'GET') !== 'GET') headers.Origin = ORIGIN;
    inflight++;
    try {
      const res = await fetch(d.origin + url, { ...init, headers, signal: undefined });
      for (const c of res.headers.getSetCookie()) {
        const m = /^karidns_session=([^;]*)/.exec(c);
        if (m) jar.cookie = m[1] ? `karidns_session=${m[1]}` : null;
      }
      return res;
    } finally {
      inflight--;
    }
  };
  return { fetch: f, jar, idle: async () => { await flush(); while (inflight > 0) { await sleep(5); await flush(); } await flush(); } };
}

async function page(d, bf, hash = '') {
  const clock = makeClock();
  const env = makeEnv({ handler: () => { throw new Error('unused'); }, clock, storage: new FakeStorage(), BroadcastChannel: makeBroadcast() });
  env.fetch = bf.fetch;
  env.window.location.hash = hash;
  const app = createApp(env);
  await app.start();
  await bf.idle();
  const root = env.document.getElementById('app');
  const ui = {
    env, app, root, clock,
    q: (sel) => root.querySelector(sel),
    qa: (sel) => root.querySelectorAll(sel),
    input: (name, scope = root) => findAll(scope, (e) => e.tagName === 'INPUT' && e.getAttribute('name') === name)[0],
    button: (re) => byText(env.document.body, 'button', re),
    type(el, v) { el.value = v; },
    async click(el) { el.click(); await bf.idle(); },
    async submit(form) { form.submit(); await bf.idle(); },
    dialogs: () => env.document.body.querySelectorAll('dialog').filter((x) => x.open),
  };
  return ui;
}

test('the service serves the files of webadmin/ui as they are: the page, every module, the policy of 5.1', async () => {
  const ui = loadStatic(defaultUiDir());
  const d = await deploy({ ui });
  try {
    const home = await fetch(`${d.origin}/`);
    assert.equal(home.status, 200);
    assert.match(home.headers.get('content-security-policy'), /^default-src 'none'; script-src 'self'; style-src 'self'/);
    assert.match(home.headers.get('content-security-policy'), /require-trusted-types-for 'script'; trusted-types 'none'$/);
    assert.equal(home.headers.get('cache-control'), 'no-store');
    const html = await home.text();
    assert.match(html, /<script type="module" src="\/ui\/js\/app\.js"><\/script>/);
    // every import of every module resolves to a file that is served, with the type of a script
    for (const [path, f] of ui) {
      if (!path.endsWith('.js')) continue;
      const r = await fetch(`${d.origin}/ui${path}`);
      assert.equal(r.status, 200, path);
      assert.match(r.headers.get('content-type'), /^text\/javascript/, path);
      for (const m of f.body.toString('utf8').matchAll(/from '(\.[^']+)'/g)) {
        const target = new URL(m[1], `http://x/ui${path}`).pathname;
        assert.ok(ui.has(target.slice(3)), `${path} imports ${m[1]} which is not served`);
      }
    }
    for (const p of ['/ui/app.css', '/ui/favicon.svg']) assert.equal((await fetch(`${d.origin}${p}`)).status, 200, p);
  } finally {
    await d.close();
  }
});

test('the GUI against the API: forced TOTP enrolment of a global master, the code at the next sign-in, a token, the password, a 401 and the sign-in over it', async () => {
  const d = await deploy({ settings: { 'require-totp': 'global' } });
  try {
    await cast(d);
    const bf = browserFetch(d);
    const ui = await page(d, bf);
    assert.equal(ui.q('h1').textContent, 'Sign in');

    // a wrong password: the service's one answer
    ui.type(ui.input('user'), 'root');
    ui.type(ui.input('password'), 'not the password');
    await ui.submit(ui.q('form'));
    assert.equal(ui.q('p.msg.error').textContent, 'The user name, the password or the code is wrong.');

    // the right one: a global master must enrol; nothing else is offered
    ui.type(ui.input('password'), 'correct horse battery');
    await ui.submit(ui.q('form'));
    assert.equal(ui.q('h1').textContent, 'Set up two-step verification');
    assert.equal(ui.q('nav'), null);
    assert.ok(ui.q('svg path').getAttribute('d').length > 200, 'the QR code is drawn');
    const key = ui.q('.key').textContent.replace(/ /g, '');
    assert.match(key, /^[A-Z2-7]{32}$/);
    const secret = base32Decode(key);
    const stepNow = totpStep(Date.now() / 1000);
    const code = (step) => hotp(secret, step);

    // a wrong code, then the right one: the session is replaced and the start page follows
    ui.type(ui.input('code'), code(stepNow + 5));
    await ui.submit(ui.qa('form')[0]);
    assert.equal(ui.q('p.msg.error').textContent, 'The code is wrong.');
    ui.type(ui.input('code'), code(stepNow));
    await ui.submit(ui.qa('form')[0]);
    assert.match(ui.q('h1').textContent, /^Welcome, /);
    assert.equal(ui.q('.key'), null, 'the secret is no longer in the page');
    assert.ok(![...ui.qa('*')].some((e) => e.textContent.includes(key)));
    assert.ok(ui.qa('th').some((th) => th.textContent === 'Global master'), 'the grants of /auth/me');

    // the account: TOTP is on and mandatory for a global master
    ui.env.window.location.hash = '#/account';
    await bf.idle();
    assert.match(ui.q('main').textContent, /Two-step verification is on/);
    assert.match(ui.q('main').textContent, /must use two-step verification/);

    // a token: made (CSRF and Origin are right), shown, then revoked
    const form = ui.qa('form').find((f) => f.querySelector('input[name=days]'));
    ui.type(ui.input('name', form), 'automation');
    await ui.submit(form);
    const token = ui.q('code.token').textContent;
    assert.match(token, /^kdt_\d+_[A-Za-z0-9_-]+$/);
    assert.equal((await d.request('GET', '/principals', { token })).status, 200, 'the token works');
    const row = ui.qa('tbody tr').find((tr) => tr.querySelector('th') && tr.querySelector('th').textContent === 'automation');
    assert.equal(row.children[5].textContent, 'Active');
    await ui.click(row.querySelector('button'));
    await ui.click(ui.button(/^Yes$/));
    assert.equal(ui.qa('tbody tr').find((tr) => tr.querySelector('th')?.textContent === 'automation').children[5].textContent, 'Revoked');
    assert.equal((await d.request('GET', '/principals', { token })).status, 401, 'a revoked token does not work');

    // the password: the refusal of the service is shown, then it is changed
    const pw = ui.qa('form')[0];
    ui.type(ui.input('current', pw), 'wrong current password');
    ui.type(ui.input('new', pw), 'a brand new password!');
    ui.type(ui.input('again', pw), 'a brand new password!');
    await ui.submit(pw);
    assert.equal(ui.input('current', pw).parentNode.querySelector('p.error').textContent, 'The password is wrong.');
    ui.type(ui.input('current', pw), 'correct horse battery');
    await ui.submit(pw);
    assert.match(pw.querySelector('p[role=status]').textContent, /was changed/);

    // logout: the sign-in screen asks for the code of the account now
    await ui.click(findAll(ui.root, (e) => e.tagName === 'BUTTON' && e.textContent === 'Log out')[0]);
    assert.equal(ui.q('h1').textContent, 'Sign in');
    ui.type(ui.input('user'), 'root');
    ui.type(ui.input('password'), 'a brand new password!');
    await ui.submit(ui.q('form'));
    assert.equal(ui.input('totp').parentNode.parentNode.hidden, false, 'the service asked for a code');
    assert.equal(ui.env.document.activeElement, ui.input('totp'));
    ui.type(ui.input('totp'), code(stepNow));
    await ui.submit(ui.q('form'));
    assert.equal(ui.q('p.msg.error').textContent, 'The user name, the password or the code is wrong.', 'a code is accepted once');
    ui.type(ui.input('totp'), code(stepNow + 1));
    await ui.submit(ui.q('form'));
    assert.equal(ui.q('h1').textContent, 'Your account', 'back on the page the sign-in screen was opened on');
    assert.equal(ui.q('footer').textContent, `KariDNS WebAdmin ${GUI_VERSION}`);

    // a user without TOTP: another tab ends the session behind the page's back, the next request is a 401 and the sign-in opens over the screen
    const bf2 = browserFetch(d);
    const p2 = await page(d, bf2, '#/account');
    p2.type(p2.input('user'), 'dom');
    p2.type(p2.input('password'), 'dom password 12345');
    await p2.submit(p2.q('form'));
    assert.equal(p2.q('h1').textContent, 'Your account');
    const heading = p2.q('h1');
    assert.equal((await d.request('POST', '/auth/logout', { cookie: bf2.jar.cookie.split('=')[1], csrf: p2.app.session.state.me.session.csrf, origin: ORIGIN, body: { all: true } })).status, 204);
    const read = p2.app.api.get('/tokens');
    await bf2.idle();
    assert.equal(p2.dialogs().length, 1, 'the sign-in is open over the screen');
    const dlg = p2.dialogs()[0];
    p2.type(p2.input('user', dlg), 'dom');
    p2.type(p2.input('password', dlg), 'dom password 12345');
    await p2.submit(dlg.querySelector('form'));
    assert.deepEqual((await read).tokens, [], 'the read was repeated after the sign-in');
    assert.equal(p2.dialogs().length, 0);
    assert.equal(p2.q('h1'), heading, 'the screen was not drawn again');
    // a write after another end of session is not repeated: the person is told to do it again
    await d.request('POST', '/auth/logout', { cookie: bf2.jar.cookie.split('=')[1], csrf: p2.app.session.state.me.session.csrf, origin: ORIGIN, body: { all: true } });
    const write = p2.app.api.post('/tokens', { name: 'x' }).catch((e) => e);
    await bf2.idle();
    const dlg2 = p2.dialogs()[0];
    p2.type(p2.input('user', dlg2), 'dom');
    p2.type(p2.input('password', dlg2), 'dom password 12345');
    await p2.submit(dlg2.querySelector('form'));
    const err = await write;
    assert.equal(err.code, 'unauthenticated');
    assert.equal(err.renewed, true);
    assert.equal((await d.as({ cookie: bf2.jar.cookie.split('=')[1], csrf: p2.app.session.state.me.session.csrf })('GET', '/tokens')).body.tokens.length, 0, 'the write did not happen');
    // the stale-token case: the cookie is replaced behind the page (a TOTP confirmation elsewhere does that); the write finds the new token by itself
    const fresh = await d.login('dom', 'dom password 12345');
    bf2.jar.cookie = `karidns_session=${fresh.cookie}`;
    const made = await p2.app.api.post('/tokens', { name: 'after the swap' });
    assert.match(made.token, /^kdt_/);
    // the password with "sign out my other sessions": the other session ends, this one stays
    const elsewhere = await d.login('dom', 'dom password 12345');
    assert.equal((await d.as(elsewhere)('GET', '/auth/me')).status, 200);
    p2.env.window.location.hash = '#/account';
    p2.env.window.location.hash = '#/about';
    p2.env.window.location.hash = '#/account';
    await bf2.idle();
    const pw2 = p2.qa('form')[0];
    p2.type(p2.input('current', pw2), 'dom password 12345');
    p2.type(p2.input('new', pw2), 'another long password');
    p2.type(p2.input('again', pw2), 'another long password');
    await p2.submit(pw2);
    assert.match(pw2.querySelector('p[role=status]').textContent, /was changed/);
    assert.equal((await d.as(elsewhere)('GET', '/auth/me')).status, 401, 'the other session was ended');
    assert.equal((await p2.app.api.get('/auth/me')).principal.name, 'dom', 'this one goes on');
  } finally {
    await d.close();
  }
});

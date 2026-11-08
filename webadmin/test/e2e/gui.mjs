// The browser scenarios of the GUI (planning 8.2, F-9): Firefox headless through geckodriver (wd.mjs), against a running karidns-webadmin on SQLite3.  Not a node:test
// file: tests/run_webadmin_gui_test.sh sets the service up and runs this.  Milestone M2: the sign-in, the TOTP enrolment, the account, the session timer, the tabs,
// the language, the keyboard, the labels, the hostile texts.  It prints "  [ OK ] ..." / "  [FAIL] ..." lines, exits 1 when anything failed and 3 when no browser could be started.
//
//   GUI_BASE=http://127.0.0.1:PORT GUI_ADMIN_PASSWORD=... GUI_DIR=work GUI_GECKODRIVER=... GUI_FIREFOX=... GUI_DRIVER_PORT=4444 node webadmin/test/e2e/gui.mjs
//
// The service runs with require-totp = global, session-idle = GUI_SESSION_IDLE (30), rate-login = 20 a minute.

import fs from 'node:fs';
import path from 'node:path';
import { hotp, totpStep, base32Decode } from '../../lib/crypto.js';
import { startBrowser, NAMED_KEYS } from './wd.mjs';
import { pageProblems, overflowProblems } from './a11y.mjs';

const BASE = process.env.GUI_BASE;
const DIR = process.env.GUI_DIR;
let pass = 0;
let fails = 0;
const ok = (name) => { pass++; console.log(`  [ OK ] ${name}`); };
const bad = (name, why) => { fails++; console.log(`  [FAIL] ${name}${why ? ` (${why})` : ''}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
class Failed extends Error {}
const must = (cond, what) => { if (!cond) throw new Failed(what); };
const eq = (got, want, what) => must(JSON.stringify(got) === JSON.stringify(want), `${what}: got ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);

// ---- the service, for the fixtures (with the token the administrator makes in the browser)
let token = null;
async function api(method, p, body) {
  const res = await fetch(`${BASE}/api/v1${p}`, { method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}
const code = (secret, step) => hotp(base32Decode(secret), step);

// ---- the browser
const started = await startBrowser({ driver: process.env.GUI_GECKODRIVER, firefox: process.env.GUI_FIREFOX, dir: DIR, port: Number(process.env.GUI_DRIVER_PORT ?? 4444) }).catch((e) => {
  console.log(`  [SKIP] the browser did not start: ${e.message}`);
  process.exit(3);
});
const b = started.browser;
fs.mkdirSync(path.join(DIR, 'shots'), { recursive: true });

const home = () => b.get(`${BASE}/`);
const h1 = async () => (await (await b.$('h1')).text()).trim();
const waitH1 = (re, o) => b.waitText('h1', re, o);
const fill = async (name, value, scope = '') => { const e = await b.$(`${scope} input[name=${name}]`); await e.clear(); await e.type(value); };
// a button or a link that looks like one, by its text
const control = async (text, scope = 'body') => {
  const r = await b.exec((t, s) => [...document.querySelector(s).querySelectorAll('button, a[href]')].find((e) => e.textContent.trim() === t && e.offsetParent !== null) ?? null, text, scope);
  must(r, `no visible control "${text}"`);
  return b.wrap(r);
};
const click = async (text, scope) => (await control(text, scope)).click();
const signIn = async (user, password, totp) => {
  await fill('user', user);
  await fill('password', password);
  if (totp) { await fill('totp', totp); }
  await click('Sign in');
};
const bodyText = () => b.exec(() => document.body.innerText);
// (the address of the page is the one it had: after the next sign-in it would show that page, so it is set to the start page here)
const logout = async () => {
  await click('Log out', 'header');
  await waitH1(/^(Sign in|ログイン)$/);
  await b.exec(() => { window.location.hash = '#/'; });
};

// the checks of 7.1 / F-22 on whatever is on the screen (a11y.mjs, shared with gui_zones.mjs)
const a11y = () => b.exec(pageProblems);
const labelsOk = async (screen) => eq(await a11y(), [], `${screen}: names and landmarks`);

const apiCalls = () => b.exec(() => performance.getEntriesByType('resource').filter((e) => e.name.includes('/api/v1/')).length);

async function scenario(name, fn) {
  try {
    await fn();
    ok(name);
  } catch (e) {
    bad(name, e.message);
    try { await b.screenshot(path.join(DIR, 'shots', `${name.replace(/[^A-Za-z0-9]+/g, '_').slice(0, 60)}.png`)); } catch { /* no picture */ }
  }
}

const S = { secret: null, step: 0 };
let exitCode = 0;
try {
  // ------------------------------------------------------------------------------------------------------------------------------------------ the page
  console.log('-- the page and the sign-in');
  await scenario('the page loads from the service alone, with the policy of the GUI and no outside request', async () => {
    await home();
    await waitH1(/^Sign in$/);
    eq(await b.title(), 'Sign in - KariDNS WebAdmin', 'title');
    const urls = await b.exec(() => performance.getEntriesByType('resource').map((e) => e.name));
    must(urls.length >= 5, `only ${urls.length} resources`);
    for (const u of urls) must(u.startsWith(`${BASE}/`), `${u} is not of the origin`);
    must(!(await b.exists('.csp-violation')), 'the page reports a violation of its policy');
    const info = await b.exec(() => ({ lang: document.documentElement.lang, tt: typeof window.trustedTypes, ua: navigator.userAgent }));
    eq(info.lang, 'en', 'lang');
    // (plan section 14, assumption 3: does this browser know Trusted Types?  Information only: the header is defence in depth)
    console.log(`  [INFO] ${info.ua}; window.trustedTypes is ${info.tt}`);
    await labelsOk('sign-in');
  });

  await scenario('a wrong password is the one message of the service; empty fields are told without a request', async () => {
    await click('Sign in');
    must(/Enter your user name/.test(await bodyText()), 'no hint for the empty form');
    await fill('user', 'admin');
    await fill('password', 'not the password at all');
    const before = await apiCalls();
    await click('Sign in');
    await b.waitText('p.msg.error', /The user name, the password or the code is wrong\./);
    eq(await apiCalls() - before, 1, 'one request for the wrong password');
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ TOTP
  console.log('-- the first sign-in of a global master: TOTP enrolment (S2)');
  await scenario('the administrator must enrol: QR code drawn in the page, the key hidden until asked for, nothing else offered', async () => {
    await fill('password', process.env.GUI_ADMIN_PASSWORD);
    await click('Sign in');
    await waitH1(/^Set up two-step verification$/);
    must(!(await b.exists('nav')), 'a menu is offered before the second step');
    const qr = await b.waitCss('svg.qr');
    must(await qr.displayed(), 'no QR code');
    const dims = await b.exec(() => { const s = document.querySelector('svg.qr'); const r = s.getBoundingClientRect(); return { w: r.width, h: r.height, path: s.querySelector('path').getAttribute('d').length, fill: getComputedStyle(s.querySelector('path')).fill }; });
    must(dims.w > 100 && dims.h > 100 && dims.path > 200, `the QR code is not drawn: ${JSON.stringify(dims)}`);
    eq(dims.fill, 'rgb(0, 0, 0)', 'dark modules');
    const key = await b.$('.key');
    must(!(await key.displayed()), 'the key is shown before it was asked for');
    must(!/[A-Z2-7]{16}/.test(await bodyText()), 'the key is in the visible text');
    await labelsOk('enrolment');
    await click('Show the key as text');
    must(await key.displayed(), 'the key did not appear');
    const shown = (await key.text()).trim();
    must(/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/.test(shown), `the key is not in groups of four: ${shown}`);
    S.secret = shown.replace(/ /g, '');
    S.step = totpStep(Date.now() / 1000);
    await click('Hide the key');
    must(!(await key.displayed()), 'the key was not hidden again');
    const uri = await b.exec(() => document.documentElement.outerHTML.includes('otpauth'));
    must(!uri, 'the otpauth URI is in the page');
  });

  await scenario('a wrong code is refused; the right one switches TOTP on and removes the secret from the page', async () => {
    await fill('code', code(S.secret, S.step + 7));
    await click('Confirm');
    await b.waitText('p.msg.error', /The code is wrong\./);
    await fill('code', code(S.secret, S.step));
    await click('Confirm');
    await waitH1(/^Welcome, /);
    must(await b.exists('nav'), 'no menu after the second step');
    const html = await b.exec((k) => document.documentElement.outerHTML.includes(k) || document.body.innerText.replace(/ /g, '').includes(k), S.secret);
    must(!html, 'the secret is still in the page');
    must(!(await b.exists('svg.qr')), 'the QR code is still in the page');
    await labelsOk('start page');
    must(/Global master/.test(await bodyText()), 'the grants are not listed');
  });

  console.log('-- the account (S15): tokens');
  await scenario('a token is made, shown once with a warning, and works; it is gone from the page when done', async () => {
    await click('Account', 'nav');
    await waitH1(/^Your account$/);
    await labelsOk('account');
    must(/must use two-step verification/.test(await bodyText()), 'a global master may switch TOTP off');
    await fill('name', 'fixtures', 'form:has(input[name=days])');
    await click('Make the token');
    const tok = await b.waitCss('code.token');
    token = (await tok.text()).trim();
    must(/^kdt_\d+_[A-Za-z0-9_-]+$/.test(token), `the token looks wrong: ${token}`);
    must(/shown only once/.test(await bodyText()), 'no warning');
    await labelsOk('account with a token shown');
    await click('I have saved it');
    await b.waitGone('code.token');
    must(!(await bodyText()).includes(token), 'the token is still in the page');
    const me = await api('GET', '/principals');
    eq(me.status, 200, 'the token works');
  });

  console.log('-- the second sign-in needs the code');
  await scenario('logout, then sign in again: the code is asked for, a code is accepted once', async () => {
    await logout();
    await fill('user', 'admin');
    await fill('password', process.env.GUI_ADMIN_PASSWORD);
    await click('Sign in');
    const field = await b.waitCss('input[name=totp]');
    must(await b.exec(() => document.activeElement && document.activeElement.name === 'totp'), 'the code field has no focus');
    await field.type(code(S.secret, S.step));
    await click('Sign in');
    await b.waitText('p.msg.error', /The user name, the password or the code is wrong\./);
    await b.waitCss('input[name=totp]');
    must((await (await b.$('input[name=totp]')).prop('value')) === '', 'a wrong code is not cleared');
    await (await b.$('input[name=totp]')).type(code(S.secret, S.step + 1));
    await click('Sign in');
    await waitH1(/^Welcome, /);
    await logout();
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ users made through the API
  console.log('-- the account of a user without TOTP: password, sessions, tabs, the keyboard');
  await scenario('fixtures: two users made with the token', async () => {
    for (const p of [
      { kind: 'user', name: 'dom', display_name: 'Dora Domain', password: 'alpha bravo charlie 12' },
      { kind: 'user', name: 'evil', display_name: '<img src=x onerror="window.__xss=1">‮revo', email: '<script>window.__xss=2</script>@example.test', password: 'delta echo foxtrot 34' },
    ]) eq((await api('POST', '/principals', p)).status, 201, `making ${p.name}`);
  });

  await scenario('the keyboard alone signs in and signs out', async () => {
    await b.exec(() => document.querySelector('input[name=user]').focus());
    await b.keys(...'dom'.split(''), NAMED_KEYS.Tab, ...'alpha bravo charlie 12'.split(''), NAMED_KEYS.Enter);
    await waitH1(/^Welcome, Dora Domain$/);
    // From the first link of the page Tab goes through the menu to the log out button, and Enter presses it.  (The first Tab starts at the brand link, not at the
    // page's start: a Tab that leaves the document for the browser's own window and comes back leaves headless Firefox where a button no longer takes Enter.)
    await b.exec(() => document.querySelector('header a.brand').focus());
    const order = [];
    let found = false;
    for (let i = 0; i < 12 && !found; i++) {
      await b.keys(NAMED_KEYS.Tab);
      const t = await b.exec(() => document.activeElement.textContent.trim());
      order.push(t);
      found = t === 'Log out';
    }
    eq(order, ['Home', 'Zones', 'Templates', 'Servers', 'Account', 'About', 'Log out'], 'the order of the keyboard');
    // the focus can be seen: the style sheet has an outline for what has the focus, and the element has a size (the check of :focus-visible itself is not made:
    // headless Firefox does not report it after a script moved the focus)
    const ring = await b.exec(() => [...document.styleSheets].some((s) => [...s.cssRules].some((r) => r.selectorText && r.selectorText.includes(':focus-visible') && /outline: (?!none)/.test(r.style.cssText))));
    must(ring, 'no style makes the focus visible');
    await b.keys(NAMED_KEYS.Enter);
    await waitH1(/^Sign in$/);
  });

  await scenario('the password: the rules, a wrong current password, a change that ends the other sessions', async () => {
    await signIn('dom', 'alpha bravo charlie 12');
    await waitH1(/^Welcome, /);
    await click('Account', 'nav');
    await waitH1(/^Your account$/);
    const form = 'form:has(input[name=again])';
    await fill('current', 'wrong current password', form);
    await fill('new', 'short', form);
    await fill('again', 'short', form);
    await click('Change password');
    must(/must have at least 12 characters/.test(await bodyText()), 'no message for a short password');
    await fill('new', 'a long enough new password', form);
    await fill('again', 'a long enough new password', form);
    await click('Change password');
    await b.waitText(`${form} p.error`, /The password is wrong./);
    await fill('current', 'alpha bravo charlie 12', form);
    await click('Change password');
    await b.waitText('p[role=status]', /The password was changed\./);
    for (const n of ['current', 'new', 'again']) eq(await (await b.$(`${form} input[name=${n}]`)).prop('value'), '', `${n} is cleared`);
  });

  await scenario('"log out everywhere" in one tab signs out the other tab at once (BroadcastChannel)', async () => {
    const tab1 = (await b.handles())[0];
    await b.newTab();
    await b.get(`${BASE}/#/account`);
    await waitH1(/^Your account$/);
    await b.switchTo(tab1);
    await click('Log out everywhere');
    await waitH1(/^Sign in$/);
    await b.exec(() => { window.location.hash = '#/'; });
    const tab2 = (await b.handles()).find((x) => x !== tab1);
    await b.switchTo(tab2);
    await waitH1(/^Sign in$/, { timeout: 5000 });
    await b.waitText('.notice', /signed out in another tab/);
    await b.closeTab();
    await b.switchTo(tab1);
  });

  console.log('-- tokens of a user, revoked');
  await scenario('a token is revoked after a second question, and stops working', async () => {
    await signIn('dom', 'a long enough new password');
    await waitH1(/^Welcome, /);
    await click('Account', 'nav');
    await waitH1(/^Your account$/);
    await fill('name', 'ci', 'form:has(input[name=days])');
    await fill('days', '5', 'form:has(input[name=days])');
    await click('Make the token');
    const t = (await (await b.waitCss('code.token')).text()).trim();
    eq((await fetch(`${BASE}/api/v1/principals`, { headers: { Authorization: `Bearer ${t}` } })).status, 200, 'the new token');
    await click('I have saved it');
    const before = await apiCalls();
    await click('Revoke');
    eq(await apiCalls(), before, 'the first click asks and sends nothing');
    await click('Yes');
    await b.waitText('tbody', /Revoked/);
    eq((await fetch(`${BASE}/api/v1/principals`, { headers: { Authorization: `Bearer ${t}` } })).status, 401, 'the revoked token');
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ the session timer
  console.log('-- the session timer (F-14): idle warning, stay signed in, the end, sign in again');
  await scenario('after 11 s without a request a warning counts down; "Stay signed in" is one request; at the end nothing is asked and the sign-in opens over the page', async () => {
    await click('Home', 'nav');
    await waitH1(/^Welcome, /);
    const n0 = await apiCalls();
    await b.waitCss('dialog[open]', { timeout: 40000 });
    must(/about to end/.test(await bodyText()), 'the warning is not the idle warning');
    eq(await apiCalls(), n0, 'the warning asked nothing');
    await labelsOk('idle warning');
    await click('Stay signed in', 'dialog[open]');
    await b.waitGone('dialog[open]');
    eq(await apiCalls(), n0 + 1, 'stay signed in is one request');
    await b.waitCss('dialog[open]', { timeout: 40000 });
    const n1 = await apiCalls();
    await b.waitText('dialog[open] h2', /session has ended/, { timeout: 40000 });
    eq(await apiCalls(), n1, 'the end of the session asked nothing');
    must(await b.exec(() => document.activeElement.closest('dialog') !== null), 'the focus is not in the dialog');
    await labelsOk('sign-in dialog');
    await fill('user', 'dom', 'dialog[open]');
    await fill('password', 'a long enough new password', 'dialog[open]');
    await click('Sign in', 'dialog[open]');
    await b.waitGone('dialog[open]');
    eq(await h1(), 'Welcome, Dora Domain', 'the page under the dialog');
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ language
  console.log('-- the language (F-6)');
  await scenario('Japanese is chosen in the account, kept over a reload, and the refusals are in Japanese', async () => {
    await click('Account', 'nav');
    await waitH1(/^Your account$/);
    await b.exec(() => document.querySelector('select').focus());
    await b.keys(NAMED_KEYS.ArrowDown);
    await waitH1(/^アカウント$/);
    eq(await b.exec(() => document.documentElement.lang), 'ja', 'lang');
    await b.refresh();
    await waitH1(/^アカウント$/);
    await labelsOk('account in Japanese');
    await click('ログアウト', 'header');
    await waitH1(/^ログイン$/);
    await b.exec(() => { window.location.hash = '#/'; });
    await fill('user', 'dom');
    await fill('password', 'wrong wrong wrong wrong');
    await click('ログイン', 'form');
    await b.waitText('p.msg.error', /ユーザー名、パスワード、またはコードが違います。/);
    await fill('password', 'a long enough new password');
    await click('ログイン', 'form');
    await waitH1(/^ようこそ、Dora Domain$/);
    await click('アカウント', 'nav');
    await b.exec(() => document.querySelector('select').focus());
    await b.keys(NAMED_KEYS.ArrowUp);
    await waitH1(/^Your account$/);
    await logout();
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ hostile texts
  console.log('-- hostile texts');
  await scenario('a display name and an e-mail address with markup and a bidi control are text, and nothing runs', async () => {
    await signIn('evil', 'delta echo foxtrot 34');
    await waitH1(/^Welcome, /);
    eq((await h1()), 'Welcome, <img src=x onerror="window.__xss=1"><U+202E>revo', 'the name as text, the bidi control made visible');
    await click('Account', 'nav');
    await waitH1(/^Your account$/);
    const r = await b.exec(() => ({ imgs: document.querySelectorAll('img').length, scripts: document.querySelectorAll('main script, header script').length, xss: window.__xss === undefined, text: document.querySelector('main').innerText }));
    eq(r.imgs, 0, 'an img element came from the data');
    eq(r.scripts, 0, 'a script element came from the data');
    must(r.xss, 'the canary was set');
    must(r.text.includes('<script>window.__xss=2</script>@example.test'), 'the e-mail address is not shown as it is');
    must(!(await b.exists('.csp-violation')), 'the policy was violated');
    await logout();
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ rate limit
  console.log('-- the rate limit (429)');
  await scenario('after too many attempts the button waits for Retry-After and then works again', async () => {
    let limited = 0;
    for (let i = 0; i < 60 && !limited; i++) {
      const r = await fetch(`${BASE}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: `nobody${i}`, password: 'x' }) });
      if (r.status === 429) limited = i + 1;
    }
    must(limited > 0, 'the service never limited the logins');
    await fill('user', 'dom');
    await fill('password', 'a long enough new password');
    await click('Sign in');
    await b.waitText('form button[type=submit]', /Try again in \d+ s/, { timeout: 5000 });
    must(!(await (await b.$('form button[type=submit]')).enabled()), 'the button is not disabled');
    must(/Too many requests/.test(await bodyText()), 'no message');
    await b.waitFor(async () => (await (await b.$('form button[type=submit]')).text()).trim() === 'Sign in', { timeout: 15000, message: 'the button to be back' });
    await click('Sign in');
    await waitH1(/^Welcome, /);
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ reflow
  console.log('-- a narrow window (WCAG 1.4.10)');
  await scenario('in 320 CSS pixels (the narrowest window, the page given that width) nothing but a table or a block of code reaches past the right edge: start page, account, sign-in', async () => {
    await b.cmd('POST', '/window/rect', { width: 320, height: 800 });
    try {
      const seen = [];
      for (const [hash, h1] of [['#/', /^Welcome, /], ['#/account', /^Your account$/]]) {
        await b.exec((x) => { window.location.hash = x; }, hash);
        await waitH1(h1);
        const r = await b.exec(overflowProblems);
        seen.push(r.window);
        eq(r.bad, [], `${hash} at ${r.width} px`);
        eq(await a11y(), [], `${hash} at ${r.width} px: names and landmarks`);
      }
      await logout();
      const r = await b.exec(overflowProblems);
      seen.push(r.window);
      eq(r.bad, [], `the sign-in at ${r.width} px`);
      console.log(`  [NOTE] the window was ${seen.join(', ')} px wide, the page was laid out in 320`);
      must(Math.max(...seen) <= 640, `the window is wider than 40rem (${seen.join(', ')} px): the media query of narrow screens does not apply`);
    } finally {
      await b.cmd('POST', '/window/rect', { width: 1280, height: 900 });
    }
  });

  // ------------------------------------------------------------------------------------------------------------------------------------------ the policy
  console.log('-- the policy of the page');
  await scenario('every resource came from the origin, and a request the policy forbids is reported in the page', async () => {
    const urls = await b.exec(() => performance.getEntriesByType('resource').map((e) => e.name));
    for (const u of urls) must(u.startsWith(`${BASE}/`), `${u} is not of the origin`);
    must(!(await b.exists('.csp-violation')), 'a violation was reported during the scenarios');
    // something that tries to load from another site (an image: img-src 'self' stops it; a script of the test runs in a sandbox of the driver, so the load is made
    // by the page): the browser reports it to the page, and the page says so
    await b.exec(() => { const i = document.createElement('img'); i.src = 'http://example.invalid/a.png'; document.body.appendChild(i); });
    await b.waitText('.csp-violation', /blocked something on this page/);
  });
} finally {
  await started.stop();
}
console.log(`\n${pass} passed, ${fails} failed`);
exitCode = fails ? 1 : 0;
process.exit(exitCode);

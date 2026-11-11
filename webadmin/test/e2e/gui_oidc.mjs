// The browser scenarios of the sign-in with an identity provider (item F, milestone M5): Firefox headless through geckodriver (wd.mjs) against a running karidns-webadmin on
// SQLite3 and a fake provider (idp.mjs) whose address is on ANOTHER SITE than the service's (the service is at 127.0.0.1, the issuer at localhost), so that the way back from
// the provider is a cross-site navigation: the session cookie is SameSite=Strict, the cookie that ties the sign-in to the browser is Lax (plan 5.5 and assumption 10).
// Not a node:test file: tests/run_webadmin_oidc_test.sh sets everything up and runs this.  It prints "  [ OK ] ..." / "  [FAIL] ..." lines, exits 1 when anything failed and
// 3 when no browser could be started.
//
//   GUI_BASE=http://127.0.0.1:PORT GUI_IDP=http://localhost:IPORT GUI_ADMIN_PASSWORD=... GUI_DIR=work GUI_GECKODRIVER=... GUI_FIREFOX=... GUI_DRIVER_PORT=4444 node gui_oidc.mjs
//
// The service runs with require-totp = none and one provider, [oidc idp] with the label "Example ID".

import fs from 'node:fs';
import path from 'node:path';
import { startBrowser, retryStale } from './wd.mjs';

const BASE = process.env.GUI_BASE;
const IDP = process.env.GUI_IDP;
const DIR = process.env.GUI_DIR;
let pass = 0;
let fails = 0;
const ok = (name) => { pass++; console.log(`  [ OK ] ${name}`); };
const bad = (name, why) => { fails++; console.log(`  [FAIL] ${name}${why ? ` (${why})` : ''}`); };
class Failed extends Error {}
const must = (cond, what) => { if (!cond) throw new Failed(what); };
const eq = (got, want, what) => must(JSON.stringify(got) === JSON.stringify(want), `${what}: got ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);

// ---- the service, for the fixtures (an administrator who signs in with the password: require-totp = none)
const loginRes = await fetch(`${BASE}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: 'admin', password: process.env.GUI_ADMIN_PASSWORD }) });
const loginBody = await loginRes.json();
const adminCookie = /karidns_session=([^;]+)/.exec(loginRes.headers.get('set-cookie'))[1];
async function api(method, p, body) {
  const res = await fetch(`${BASE}/api/v1${p}`, { method, headers: { Cookie: `karidns_session=${adminCookie}`, 'X-KariDNS-CSRF': loginBody.csrf, Origin: BASE, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}
const ctl = async (c) => { const r = await fetch(`${IDP}/__control`, { method: 'POST', body: JSON.stringify(c) }); must(r.status === 200, `the provider's control: ${r.status}`); };
const bob = (await api('POST', '/principals', { kind: 'user', name: 'bob', display_name: 'Bob Builder' })).body.principal.id;
const carol = (await api('POST', '/principals', { kind: 'user', name: 'carol', display_name: 'Carol Chan' })).body.principal.id;
const link = await api('PUT', `/principals/${bob}/oidc`, { issuer: IDP, subject: 'bob-sub' });
must(link.status === 200, `linking bob: ${link.status} ${JSON.stringify(link.body)}`);

// ---- the browser
const started = await startBrowser({ driver: process.env.GUI_GECKODRIVER, firefox: process.env.GUI_FIREFOX, dir: DIR, port: Number(process.env.GUI_DRIVER_PORT ?? 4444) }).catch((e) => {
  console.log(`  [SKIP] the browser did not start: ${e.message}`);
  process.exit(3);
});
const b = started.browser;
fs.mkdirSync(path.join(DIR, 'shots'), { recursive: true });
const h1 = async () => (await (await b.$('h1')).text()).trim();
const fill = async (name, value, scope = '') => retryStale(async () => { const e = await b.$(`${scope} input[name=${name}]`); await e.clear(); await e.type(value); });
const control = async (text, scope = 'body') => {
  const r = await b.exec((t, s) => [...document.querySelector(s).querySelectorAll('button, a[href]')].find((e) => e.textContent.trim() === t && e.offsetParent !== null) ?? null, text, scope);
  must(r, `no visible control "${text}"`);
  return b.wrap(r);
};
const click = (text, scope) => retryStale(async () => (await control(text, scope)).click());
const who = () => b.waitFor(async () => { const e = await b.$('.who span'); return (await e.text()).trim(); }, { message: 'the name of the person who is signed in' });
const waitSignedOut = () => b.waitText('h1', /^Sign in$/);
const me = () => b.execAsync(async () => { const r = await fetch('/api/v1/auth/me', { credentials: 'same-origin' }); return { status: r.status, name: r.ok ? (await r.json()).principal.name : null }; });
// the button appears when the list of providers has come (the page asks for it when the sign-in screen is drawn)
const provider = async () => { await b.waitCss('ul.providers a'); await click('Sign in with Example ID'); };
const logout = async () => { await click('Log out', 'header'); await waitSignedOut(); };
const a11y = () => b.exec(() => {
  const bad = [];
  for (const el of document.querySelectorAll('input, select, textarea')) if (!(el.labels && el.labels.length) && !el.getAttribute('aria-label')) bad.push(`input ${el.name || el.id} has no label`);
  for (const el of document.querySelectorAll('button, a[href]')) if (!(el.textContent || '').trim() && !el.getAttribute('aria-label')) bad.push('a button or link without a name');
  if (document.querySelectorAll('h1').length !== 1) bad.push(`${document.querySelectorAll('h1').length} h1`);
  return bad;
});

async function scenario(name, fn) {
  try {
    await fn();
    ok(name);
  } catch (e) {
    bad(name, e.message);
    try { await b.screenshot(path.join(DIR, 'shots', `${name.replace(/[^A-Za-z0-9]+/g, '_').slice(0, 60)}.png`)); } catch { /* no picture */ }
  }
}

try {
  console.log('-- the sign-in screen');
  await scenario('the provider is another site than the service (so the way back is a cross-site navigation)', async () => {
    must(new URL(IDP).hostname !== new URL(BASE).hostname, `${IDP} and ${BASE} are one host`);
    must(new URL(IDP).hostname === 'localhost' && new URL(BASE).hostname === '127.0.0.1', 'the test expects localhost and 127.0.0.1');
  });

  await scenario('the screen offers the provider next to the password form; its labels are fine', async () => {
    await b.get(`${BASE}/#/templates`);
    await b.waitText('h1', /^Sign in$/);
    const a = await b.waitCss('ul.providers a');
    eq((await a.text()).trim(), 'Sign in with Example ID', 'button text');
    eq(await a.attr('href'), '/api/v1/auth/oidc/idp/start?return=%2Ftemplates', 'link');
    must(await b.exists('input[name=user]'), 'the password form is there');
    eq(await a11y(), [], 'names and labels');
  });

  console.log('-- signing in at the provider');
  await scenario('a click leaves for the provider and comes back signed in, to the page that was asked for', async () => {
    await ctl({ sub: 'bob-sub' });
    await provider();
    eq(await who(), 'Signed in as Bob Builder', 'who');
    eq(await b.url(), `${BASE}/#/templates`, 'where the browser is');
    eq((await b.exec(() => document.querySelector('h1').textContent)).trim(), 'Templates', 'the page');
    must(!(await b.exists('.csp-violation')), 'the policy of the page was violated');
  });

  await scenario('the session cookie that came with the redirect from the other site is sent by the page (SameSite=Strict, plan assumption 10)', async () => {
    eq(await me(), { name: 'bob', status: 200 }, '/auth/me from the page');
    await b.refresh();
    eq(await who(), 'Signed in as Bob Builder', 'who after a reload');
  });

  await scenario('the cookie that tied the sign-in to this browser is gone, the session cookie cannot be read by the page', async () => {
    eq(await b.exec(() => document.cookie), '', 'document.cookie');
  });

  await scenario('log out; the account of a person who signs in with the provider only has no password form', async () => {
    await click('Account', 'nav');
    await b.waitText('h1', /^Your account$/);
    must(await b.exists('section[aria-labelledby=acc-oidc]'), 'the section of the identity provider');
    const t = await (await b.$('section[aria-labelledby=acc-oidc]')).text();
    must(/Example ID/.test(t) && /bob-sub/.test(t), `the section says: ${t}`);
    must(!(await b.exists('input[name=current]')), 'a password form is offered to a person with no password');
    eq(await a11y(), [], 'names and labels');
    await logout();
  });

  console.log('-- refusals');
  await scenario('an identity linked to nobody: the page says so once, with the form still there', async () => {
    await ctl({ sub: 'stranger' });
    await b.get(`${BASE}/`);
    await provider();
    await b.waitText('p.msg.error', /The sign-in with the identity provider was not accepted\./);
    eq(await b.url(), `${BASE}/#/?oidc=failed`, 'where the browser is');
    must(await b.exists('input[name=user]'), 'the password form is there');
    must(!(await b.exists('.who')), 'somebody is signed in');
    eq(await me(), { name: null, status: 401 }, '/auth/me');
  });

  await scenario('a token that is wrong is refused the same way', async () => {
    await ctl({ sub: 'bob-sub', tamper: 'wrong-key' });
    await b.get(`${BASE}/`);
    await provider();
    await b.waitText('p.msg.error', /was not accepted/);
    await ctl({ tamper: null });
    eq(await me(), { name: null, status: 401 }, '/auth/me');
  });

  await scenario('the provider says no (the person cancelled): the same text', async () => {
    await ctl({ authError: 'access_denied' });
    await b.get(`${BASE}/`);
    await provider();
    await b.waitText('p.msg.error', /was not accepted/);
    await ctl({ authError: null });
  });

  console.log('-- linking in the administration');
  await scenario('an administrator signs in with the password and links carol to an identity', async () => {
    await b.get(`${BASE}/`);
    await b.waitText('h1', /^Sign in$/);
    await fill('user', 'admin');
    await fill('password', process.env.GUI_ADMIN_PASSWORD);
    await click('Sign in', 'main');
    await b.waitText('h1', /^Welcome/);
    await b.get(`${BASE}/#/admin/principals/${carol}`);
    await b.waitText('#oi-title', /Identity at a provider/);
    must(/not linked to an identity/.test(await (await b.$('section[aria-labelledby=oi-title]')).text()), 'carol is not linked');
    await fill('subject', 'carol-sub', 'section[aria-labelledby=oi-title]');
    await click('Link the identity', 'section[aria-labelledby=oi-title]');
    await b.waitText('p.msg', /The identity was linked\./);
    await b.waitText('section[aria-labelledby=oi-title]', /carol-sub/);
    must(/Example ID/.test(await (await b.$('section[aria-labelledby=oi-title]')).text()), 'the provider is named');
    eq(await a11y(), [], 'names and labels');
    await b.get(`${BASE}/#/admin/principals/${bob}`);
    await b.waitText('section[aria-labelledby=oi-title]', /bob-sub/);
    await logout();
  });

  await scenario('carol signs in with the provider and sees her identity; her session is her own', async () => {
    await ctl({ sub: 'carol-sub' });
    await b.get(`${BASE}/`);
    await provider();
    eq(await who(), 'Signed in as Carol Chan', 'who');
    eq(await me(), { name: 'carol', status: 200 }, '/auth/me');
    await b.get(`${BASE}/#/account`);
    await b.waitText('section[aria-labelledby=acc-oidc]', /carol-sub/);
    must(!(await b.exists('input[name=current]')), 'carol has no password: no password form');
  });
} finally {
  await started.stop();
}
console.log(`\n${pass} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);

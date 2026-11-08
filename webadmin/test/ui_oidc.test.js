// Signing in with an identity provider on the fake DOM (item F, milestone M5): the buttons of the sign-in screen, what the page says when a sign-in did not work, the
// code-only TOTP step, what the account shows, and the link / unlink of an identity in the administration.  Hostile labels are text.

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootApp, reply, problem, flush, findAll, byText, meDoc, GRANT_GLOBAL, PRINCIPAL } from './ui_boot.js';
import { makeClock, FakeEvent } from './fakedom.js';
import { oidcLink, setDocument } from '../ui/js/dom.js';

const OUT = { 'GET /auth/me': () => problem(401, 'unauthenticated') };
const PROVIDERS = [{ name: 'corp', label: 'Corp ID', issuer: 'https://idp.example.test' }, { name: 'other-1', label: '<img src=x onerror=alert(1)>', issuer: 'https://two.example.test' }];
const typed = (el, v) => { el.value = v; el.dispatchEvent(new FakeEvent('input')); };
const links = (ui) => findAll(ui.root, (e) => e.tagName === 'A' && (e.getAttribute('href') ?? '').startsWith('/api/v1/auth/oidc/'));

test('S1: one button for each provider, a link that leaves for the service; labels are text', async () => {
  const ui = await bootApp({ routes: { ...OUT, 'GET /auth/providers': () => reply(200, { providers: PROVIDERS }) }, hash: '' });
  const a = links(ui);
  assert.deepEqual(a.map((e) => e.getAttribute('href')), ['/api/v1/auth/oidc/corp/start?return=%2F', '/api/v1/auth/oidc/other-1/start?return=%2F']);
  assert.deepEqual(a.map((e) => e.textContent), ['Sign in with Corp ID', 'Sign in with <img src=x onerror=alert(1)>']);
  assert.equal(findAll(ui.root, (e) => e.tagName === 'IMG').length, 0);
  assert.match(ui.text(), /Or sign in with an identity provider:/);
  assert.equal(findAll(ui.root, (e) => e.tagName === 'UL' && e.getAttribute('aria-label') === 'Identity providers').length, 1);
  // the password form is there as before
  assert.ok(ui.input('user'));
  assert.equal(ui.count('GET', '/auth/providers'), 1);
});

test('S1: the button brings the person back to the page they were at', async () => {
  const ui = await bootApp({ routes: { ...OUT, 'GET /auth/providers': () => reply(200, { providers: PROVIDERS }) }, hash: '#/zones/main/example.test' });
  assert.equal(links(ui)[0].getAttribute('href'), '/api/v1/auth/oidc/corp/start?return=%2Fzones%2Fmain%2Fexample.test');
  const home = await bootApp({ routes: { ...OUT, 'GET /auth/providers': () => reply(200, { providers: PROVIDERS }) }, hash: '#/?oidc=failed' });
  assert.equal(links(home)[0].getAttribute('href'), '/api/v1/auth/oidc/corp/start?return=%2F');
});

test('S1: no provider, no answer, a broken answer: no button and no error', async () => {
  for (const r of [reply(200, { providers: [] }), problem(404, 'not-found'), problem(500, 'internal'), reply(200, { providers: 'x' })]) {
    const ui = await bootApp({ routes: { ...OUT, 'GET /auth/providers': () => r }, hash: '' });
    assert.equal(links(ui).length, 0);
    assert.doesNotMatch(ui.text(), /identity provider/);
    assert.ok(ui.input('user'));
  }
});

test('S1: the page the service sends the browser back to when a sign-in did not work', async () => {
  const say = async (hash) => (await bootApp({ routes: { ...OUT }, hash })).qa('p.msg.error').filter((p) => !p.hidden).map((p) => p.textContent);
  assert.match((await say('#/?oidc=failed'))[0], /was not accepted/);
  assert.match((await say('#/?oidc=unavailable'))[0], /cannot be reached/);
  assert.match((await say('#/?oidc=busy'))[0], /Too many sign-in attempts/);
  assert.deepEqual(await say('#/?oidc=anything'), []);
  assert.deepEqual(await say('#/?oidc=<script>'), []);
  assert.deepEqual(await say(''), []);
  const ja = await bootApp({ routes: { ...OUT, 'GET /auth/providers': () => reply(200, { providers: PROVIDERS }) }, hash: '#/?oidc=failed', languages: ['ja'] });
  assert.match(ja.qa('p.msg.error').filter((p) => !p.hidden)[0].textContent, /受け付けられませんでした/);
  assert.equal(links(ja)[0].textContent, 'Corp ID でログイン');
});

test('the sign-in dialog after a 401 has the buttons too', async () => {
  const ui = await bootApp({ routes: { 'GET /auth/providers': () => reply(200, { providers: PROVIDERS }), 'GET /rr-policies': () => problem(401, 'unauthenticated') }, hash: '#/admin/policies' });
  await flush();
  const d = ui.dialogs()[0];
  assert.ok(d, 'the dialog is open');
  assert.equal(findAll(d, (e) => e.tagName === 'A' && (e.getAttribute('href') ?? '').startsWith('/api/v1/auth/oidc/corp/start?return=')).length, 1);
});

test('dom.oidcLink: a provider name of the configuration and a route, nothing else', () => {
  const doc = { createElement: () => ({ setAttribute(k, v) { this[k] = v; }, append() {}, addEventListener() {} }), createTextNode: (t) => t };
  setDocument(doc);
  assert.equal(oidcLink('corp', '/a b', null).href, '/api/v1/auth/oidc/corp/start?return=%2Fa%20b');
  assert.equal(oidcLink('corp', '//evil.example.test', null).href, '/api/v1/auth/oidc/corp/start?return=%2F');
  assert.equal(oidcLink('corp', undefined, null).href, '/api/v1/auth/oidc/corp/start?return=%2F');
  assert.equal(oidcLink('corp', `/${'a'.repeat(600)}`, null).href, '/api/v1/auth/oidc/corp/start?return=%2F');
  for (const bad of ['../x', 'Corp', 'a/b', '', 'a?b', 'a#b', 5, undefined, 'a'.repeat(33), '1a']) assert.throws(() => oidcLink(bad, '/', null), /not a provider name/);
});

// ------------------------------------------------------------------------------------------------------------------------------- the TOTP step after a provider
const verifyMe = () => ({ ...meDoc(makeClock()), session: { csrf: 'csrf-1', totp_ok: false, totp_step: 'verify', expires_at: new Date(1_700_000_000_000 + 3600000).toISOString(), idle_timeout: 1800 } });

test('S2: a session from a provider whose TOTP is on is asked for the code only', async () => {
  const st = { done: false };
  const ui = await bootApp({ routes: {
    'GET /auth/me': () => reply(200, st.done ? meDoc(makeClock()) : verifyMe()),
    'POST /auth/totp': (b) => {
      if (b.code === '000000') return problem(403, 'wrong-code');
      st.done = true;
      return reply(200, { api: 1, csrf: 'csrf-2', expires_at: 'x', totp: { enabled: true, enrollment_required: false } });
    },
  }, hash: '#/' });
  assert.equal(ui.q('h1').textContent, 'Two-step verification');
  assert.match(ui.text(), /You signed in with an identity provider\./);
  assert.equal(ui.count('POST', '/auth/totp'), 0, 'nothing is enrolled');
  assert.equal(ui.qa('svg').length, 0);
  assert.equal(ui.q('nav'), null, 'nothing else is offered');
  const f = ui.q('form');
  await ui.submit(f);
  assert.match(ui.text(), /The code has 6 digits\./);
  typed(ui.input('code'), '000000');
  await ui.submit(f);
  assert.match(ui.text(), /code is wrong/i);
  assert.deepEqual(ui.last('POST', '/auth/totp').body, { action: 'verify', code: '000000' });
  typed(ui.input('code'), '123456');
  await ui.submit(ui.q('form'));
  assert.deepEqual(ui.last('POST', '/auth/totp').body, { action: 'verify', code: '123456' });
  assert.ok(ui.q('nav'), 'the page is open now');
  assert.equal(ui.polite(), 'The code was accepted.');
});

// ------------------------------------------------------------------------------------------------------------------------------- the account
const LINK = { issuer: 'https://idp.example.test', subject: 'ab12<b>x</b>', provider: { name: 'corp', label: 'Corp ID' } };
const accountRoutes = (creds, extra = {}) => ({
  'GET /auth/providers': () => reply(200, { providers: PROVIDERS }),
  'GET /principals/7': () => reply(200, { principal: PRINCIPAL, groups: [], credentials: creds }),
  'GET /tokens': () => reply(200, { tokens: [], next_cursor: null }),
  ...extra,
});

test('S15: a linked identity is shown (read only); a person with no password has no password form and gives the code alone to switch the TOTP off', async () => {
  const sent = [];
  const ui = await bootApp({ routes: accountRoutes({ password: false, totp_enabled: true, failed_logins: 0, locked: false, oidc: LINK }, {
    'POST /auth/totp': (b) => { sent.push(b); return reply(200, { totp: { enabled: false } }); },
  }), hash: '#/account', me: { global: false, grants: [] } });
  const section = findAll(ui.root, (e) => e.tagName === 'SECTION' && e.getAttribute('aria-labelledby') === 'acc-oidc')[0];
  assert.ok(section);
  assert.match(section.textContent, /ProviderCorp ID/);
  assert.match(section.textContent, /Issuerhttps:\/\/idp\.example\.test/);
  assert.match(section.textContent, /Your identifier there/);
  assert.match(section.textContent, /ab12<b>x<\/b>/);
  assert.equal(findAll(section, (e) => e.tagName === 'B').length, 0);
  assert.match(section.textContent, /has no password/);
  assert.equal(ui.input('current'), undefined, 'no password form');
  assert.equal(ui.input('password'), undefined);
  const f = findAll(ui.root, (e) => e.tagName === 'FORM').find((x) => x.querySelector('input[name=code]'));
  assert.match(f.textContent, /code from your authenticator app is enough/);
  typed(ui.input('code', f), '123456');
  await ui.submit(f);
  assert.deepEqual(sent, [{ action: 'disable', code: '123456' }]);
});

test('S15: an account with a password and a link shows both; an account with neither a link nor providers shows no section', async () => {
  const both = await bootApp({ routes: accountRoutes({ password: true, totp_enabled: false, failed_logins: 0, locked: false, oidc: { ...LINK, provider: null } }), hash: '#/account', me: { global: false, grants: [] } });
  assert.ok(both.input('current'));
  assert.match(both.text(), /not set up in this service/);
  const plain = await bootApp({ routes: accountRoutes({ password: true, totp_enabled: false, failed_logins: 0, locked: false, oidc: null }, { 'GET /auth/providers': () => reply(200, { providers: [] }) }), hash: '#/account', me: { global: false, grants: [] } });
  assert.doesNotMatch(plain.text(), /Identity provider/);
  const unlinked = await bootApp({ routes: accountRoutes({ password: true, totp_enabled: false, failed_logins: 0, locked: false, oidc: null }), hash: '#/account', me: { global: false, grants: [] } });
  assert.match(unlinked.text(), /not linked to an identity provider/);
  const old = await bootApp({ routes: accountRoutes({ password: true, totp_enabled: false, failed_logins: 0, locked: false }, { 'GET /auth/providers': () => problem(404, 'not-found') }), hash: '#/account', me: { global: false, grants: [] } });
  assert.ok(old.input('current'));
});

// ------------------------------------------------------------------------------------------------------------------------------- the administration
const U2 = { id: 2, kind: 'user', name: 'bob', display_name: null, email: null, disabled: false, created_at: '2026-11-01T00:00:00Z', created_by: 1 };
const adminRoutes = (st) => ({
  'GET /datasets': () => reply(200, { datasets: [{ name: 'main', driver: 'sqlite3', views: [] }] }),
  'GET /rr-policies': () => reply(200, { policies: [], next_cursor: null }),
  'GET /grants': () => reply(200, { grants: [], next_cursor: null }),
  'GET /auth/providers': () => reply(200, { providers: PROVIDERS }),
  'GET /principals/2': () => reply(200, { principal: U2, groups: [], credentials: { password: true, totp_enabled: false, failed_logins: 0, locked: false, oidc: st.link } }),
});

test('S11: link an identity: the provider, the subject, the refusals; remove it after a question', async () => {
  const st = { link: null };
  const sent = [];
  const ui = await bootApp({ routes: {
    ...adminRoutes(st),
    'PUT /principals/2/oidc': (b) => {
      sent.push(['PUT', b]);
      if (b.subject === 'taken') return problem(409, 'exists');
      st.link = { issuer: b.issuer, subject: b.subject, provider: { name: 'corp', label: 'Corp ID' } };
      return reply(200, { credentials: { oidc: st.link } });
    },
    'DELETE /principals/2/oidc': () => { sent.push(['DELETE']); st.link = null; return reply(204, null); },
  }, hash: '#/admin/principals/2' });
  assert.match(ui.text(), /This user is not linked to an identity\./);
  const f = findAll(ui.root, (e) => e.tagName === 'FORM').find((x) => x.querySelector('input[name=subject]'));
  const opts = f.querySelectorAll('option').map((o) => [o.value, o.textContent]);
  assert.deepEqual(opts, [['https://idp.example.test', 'Corp ID'], ['https://two.example.test', '<img src=x onerror=alert(1)>']]);
  assert.equal(findAll(ui.root, (e) => e.tagName === 'IMG').length, 0);
  await ui.submit(f);
  assert.match(f.textContent, /Enter the subject\./);
  assert.equal(sent.length, 0);
  typed(ui.input('subject', f), 'taken');
  await ui.submit(f);
  assert.match(f.textContent, /exists already|already/i);
  typed(ui.input('subject', f), ' ab12 ');
  await ui.submit(f);
  assert.deepEqual(sent.at(-1), ['PUT', { issuer: 'https://idp.example.test', subject: 'ab12' }]);
  assert.match(ui.text(), /The identity was linked\./);
  // linked now: the identity is shown and can be removed after a question
  const card = findAll(ui.root, (e) => e.tagName === 'SECTION' && e.getAttribute('aria-labelledby') === 'oi-title')[0];
  assert.match(card.textContent, /ProviderCorp ID/);
  assert.match(card.textContent, /Subjectab12/);
  assert.match(card.textContent, /Linking another identity signs the user out\./);
  await ui.click(byText(card, 'button', /^Remove the link$/));
  assert.equal(sent.filter((s) => s[0] === 'DELETE').length, 0, 'asked first');
  await ui.click(byText(card, 'button', /^Yes$/));
  assert.deepEqual(sent.at(-1), ['DELETE']);
  assert.match(ui.text(), /The link was removed\./);
});

test('S11: no provider in the service: the form is not offered; a provider that is gone is named so; a failing delete is shown', async () => {
  const st = { link: { issuer: 'https://gone.example.test', subject: 's', provider: null } };
  const ui = await bootApp({ routes: { ...adminRoutes(st), 'GET /auth/providers': () => reply(200, { providers: [] }), 'DELETE /principals/2/oidc': () => problem(404, 'not-found') }, hash: '#/admin/principals/2' });
  const card = findAll(ui.root, (e) => e.tagName === 'SECTION' && e.getAttribute('aria-labelledby') === 'oi-title')[0];
  assert.match(card.textContent, /not set up in this service/);
  assert.equal(ui.input('subject'), undefined);
  await ui.click(byText(card, 'button', /^Remove the link$/));
  await ui.click(byText(card, 'button', /^Yes$/));
  assert.match(card.textContent, /not found|no such/i);
  const none = await bootApp({ routes: { ...adminRoutes({ link: null }), 'GET /auth/providers': () => reply(200, { providers: [] }) }, hash: '#/admin/principals/2' });
  assert.match(none.text(), /No identity provider is set up in the service/);
});

test('S11: a group has no identity', async () => {
  const ui = await bootApp({ routes: {
    ...adminRoutes({ link: null }),
    'GET /principals/2': () => reply(200, { principal: { ...U2, kind: 'group' }, groups: [] }),
    'GET /principals/2/members': () => reply(200, { group: { ...U2, kind: 'group' }, members: [] }),
  }, hash: '#/admin/principals/2' });
  assert.doesNotMatch(ui.text(), /Identity at a provider/);
  void GRANT_GLOBAL;
});

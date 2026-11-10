// The administration and audit screens (S11, S12) on the fake DOM against a scripted API (planning 8.1, F-11): users, groups, policies, grants, the actions on credentials,
// the grants tab of a zone for a domain master, the audit log with its filters; hostile data (no element may come from it).

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootApp, reply, problem, flush, findAll, byText, GRANT_GLOBAL, POLICY, PRINCIPAL } from './ui_boot.js';
import { FakeEvent } from './fakedom.js';

const typed = (ui, el, v) => { el.value = v; el.dispatchEvent(new FakeEvent('input')); };
const chosen = (ui, el, v) => { el.value = v; el.dispatchEvent(new FakeEvent('change')); return flush(); };
const buttonIn = (el, re) => byText(el, 'button', re);
const TAGS = new Set(['DIV', 'SECTION', 'HEADER', 'MAIN', 'FOOTER', 'NAV', 'UL', 'LI', 'A', 'SPAN', 'STRONG', 'P', 'H1', 'H2', 'H3', 'H4', 'BUTTON', 'FORM', 'LABEL', 'INPUT', 'SELECT', 'OPTION',
  'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD', 'CAPTION', 'DL', 'DT', 'DD', 'CODE', 'TIME', 'OL', 'SVG', 'PATH', 'DIALOG', 'TEXTAREA', 'B', 'I', 'EM', 'FIELDSET', 'LEGEND', 'PRE', 'DETAILS', 'SUMMARY']);
const noForeign = (ui) => { for (const e of findAll(ui.env.document.body, () => true)) assert.ok(TAGS.has(e.tagName), `unexpected element ${e.tagName}`); };
const errorsOf = (root) => findAll(root, (e) => e.tagName === 'P' && e.className === 'error' && !e.hidden).map((e) => e.textContent);
const alerts = (root) => findAll(root, (e) => e.tagName === 'P' && e.className === 'msg error' && !e.hidden).map((e) => e.textContent);
function labelled(ui) {
  for (const input of findAll(ui.root, (e) => ['INPUT', 'SELECT', 'TEXTAREA'].includes(e.tagName))) {
    const label = findAll(ui.root, (e) => e.tagName === 'LABEL' && e.htmlFor === input.getAttribute('id'));
    assert.equal(label.length, 1, `the control ${input.getAttribute('name')} has one label`);
    for (const id of (input.getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean)) assert.ok(ui.root.querySelector(`#${id}`), `${id} exists`);
  }
  for (const b of findAll(ui.root, (e) => e.tagName === 'BUTTON')) assert.ok(b.textContent.trim() !== '' || b.getAttribute('aria-label'), 'a button has a name');
  for (const a of findAll(ui.root, (e) => e.tagName === 'A')) assert.ok(a.textContent.trim() !== '' || a.getAttribute('aria-label'), 'a link has a name');
}
const form = (ui, sel) => findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector(sel));

const U = (id, name, over = {}) => ({ id, kind: 'user', name, display_name: null, email: null, disabled: false, ...over });
const G = (id, name, over = {}) => ({ id, kind: 'group', name, display_name: null, email: null, disabled: false, ...over });
const POLICIES = [
  { ...POLICY, id: 1, name: 'all-types' },
  { id: 2, name: 'web', allowed_types: ['A', 'TXT'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 60, ttl_max: 3600, max_rr: 100 },
  { id: 3, name: 'web-small', allowed_types: ['A'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 120, ttl_max: 600, max_rr: 10 },
];
const base = (over = {}) => ({
  'GET /datasets': () => reply(200, { datasets: [{ name: 'main', driver: 'sqlite3', views: [] }] }),
  'GET /rr-policies': () => reply(200, { policies: POLICIES, next_cursor: null }),
  ...over,
});
const GR = (id, principal, role, over = {}) => ({ id, principal_id: 40 + id, principal, role, dataset: role === 'global_master' ? null : 'main', zone: role === 'global_master' ? null : 'example.test.', suffix: null, policy_id: 2, policy: 'web',
  granted_by: 1, granted_at: '2026-11-09T01:00:00Z', ...over });

// ---------------------------------------------------------------------------------------------------------------------------------- the menu
test('the menu: Administration for global masters, the audit log for global and domain masters, Templates for everybody', async () => {
  const names = (ui) => findAll(ui.root, (e) => e.tagName === 'NAV' && e.getAttribute('aria-label') === 'Main menu')[0].querySelectorAll('a').map((a) => a.textContent);
  const g = await bootApp({ routes: base(), hash: '#/' });
  assert.deepEqual(names(g), ['Home', 'Zones', 'Templates', 'Servers', 'Administration', 'Audit log', 'Account', 'About']);
  const dom = await bootApp({ routes: base(), hash: '#/', me: { global: false, grants: [], } });
  assert.deepEqual(names(dom), ['Home', 'Zones', 'Templates', 'Servers', 'Account', 'About']);
  const withZone = await bootApp({ routes: base(), hash: '#/' });
  withZone.app.session.state.me.capabilities = { global: false, grant_on: [{ dataset: 'main', zone: 'example.test.' }] };
  withZone.app.render();
  assert.deepEqual(names(withZone), ['Home', 'Zones', 'Templates', 'Servers', 'Audit log', 'Account', 'About']);
  // the entry that a page belongs to is the current one
  const p = await bootApp({ routes: base({ 'GET /principals': () => reply(200, { principals: [], next_cursor: null }) }), hash: '#/admin/policies' });
  assert.equal(p.link(/^Administration$/).getAttribute('aria-current'), 'page');
  const t = await bootApp({ routes: { 'GET /templates': () => reply(200, { templates: [] }) }, hash: '#/templates' });
  assert.equal(t.link(/^Templates$/).getAttribute('aria-current'), 'page');
  const u = await bootApp({ routes: base(), hash: '#/nowhere' });
  assert.equal(findAll(u.root, (e) => e.tagName === 'A' && e.getAttribute('aria-current') === 'page').length, 0);
});

test('S11: a person who is not a global master gets a notice and no call is made', async () => {
  const me = { global: false, grants: [] };
  for (const hash of ['#/admin/users', '#/admin/groups', '#/admin/policies', '#/admin/grants', '#/admin/principals/7']) {
    const ui = await bootApp({ routes: base(), hash, me });
    assert.match(ui.text(), /Only global masters administer users, groups and policies\./, hash);
    assert.equal(ui.count('GET', '/principals'), 0, hash);
    assert.equal(ui.count('GET', '/grants'), 0, hash);
    assert.equal(ui.count('GET', '/rr-policies'), 0, hash);
  }
});

// ---------------------------------------------------------------------------------------------------------------------------------- users and groups
test('S11: users: the list, the search, the paging, hostile names as text; a new user and its refusals', async () => {
  const sent = [];
  const st = { next: 'U2' };
  const ui = await bootApp({ routes: base({
    'GET /principals': () => reply(200, { principals: [U(2, 'bob', { display_name: '<b>Bob</b>', email: 'bob@example.test' }), U(3, 'eve‮', { disabled: true })], next_cursor: st.next }),
    'POST /principals': (b) => { sent.push(b); return reply(201, { principal: U(9, b.name) }); },
  }), hash: '#/admin/users?prefix=b' });
  assert.equal(ui.q('h1').textContent, 'Administration');
  assert.equal(ui.last('GET', '/principals').url, '/api/v1/principals?kind=user&limit=100&prefix=b');
  const rows = ui.qa('table tbody tr');
  assert.deepEqual(rows[0].childNodes.map((c) => c.textContent), ['bob', '<b>Bob</b>', 'bob@example.test', 'active']);
  assert.deepEqual(rows[1].childNodes.map((c) => c.textContent), ['eve<U+202E>', '-', '-', 'disabled']);
  assert.equal(rows[0].querySelector('a').getAttribute('href'), '#/admin/principals/2');
  assert.equal(findAll(ui.root, (e) => e.tagName === 'B').length, 0);
  assert.equal(ui.link(/^Next page$/).getAttribute('href'), '#/admin/users?prefix=b&cursor=U2');
  assert.equal(ui.link(/^Users$/).getAttribute('aria-current'), 'page');
  labelled(ui);
  noForeign(ui);
  // the search
  const search = ui.q('form.search');
  typed(ui, ui.input('prefix', search), 'a b');
  await ui.submit(search);
  assert.deepEqual(errorsOf(ui.root), ['Use letters, digits and . _ @ + : - only.']);
  typed(ui, ui.input('prefix', search), 'zed');
  await ui.submit(search);
  assert.equal(ui.env.window.location.hash, '#/admin/users?prefix=zed');
  // a new user: checks first
  const f = form(ui, 'input[name=password]');
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['Enter a name.']);
  typed(ui, ui.input('name', f), 'carol');
  typed(ui, ui.input('password', f), 'short');
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['The password must have at least 12 characters and must not contain your user name.']);
  assert.equal(sent.length, 0);
  typed(ui, ui.input('password', f), 'a long enough pass');
  typed(ui, ui.input('display_name', f), 'Carol');
  typed(ui, ui.input('email', f), 'carol@example.test');
  ui.routes['GET /principals/9'] = () => reply(200, { principal: U(9, 'carol'), groups: [], credentials: { password: true, totp_enabled: false, failed_logins: 0, locked: false } });
  ui.routes['GET /grants'] = () => reply(200, { grants: [], next_cursor: null });
  await ui.submit(f);
  assert.deepEqual(sent[0], { kind: 'user', name: 'carol', display_name: 'Carol', email: 'carol@example.test', password: 'a long enough pass' });
  assert.equal(ui.env.window.location.hash, '#/admin/principals/9');
  assert.match(ui.text(), /carol was created\./);
  // refusals
  await ui.go('#/admin/users');
  const f2 = form(ui, 'input[name=password]');
  typed(ui, ui.input('name', f2), 'carol');
  typed(ui, ui.input('password', f2), 'a long enough pass');
  ui.routes['POST /principals'] = () => problem(409, 'exists');
  await ui.submit(f2);
  assert.deepEqual(errorsOf(f2), ['An object with this name exists already.']);
  ui.routes['POST /principals'] = () => problem(400, 'bad-request', { errors: [{ code: 'bad-request', severity: 'error', text: 'not an e-mail address', pointer: '/email' }, { code: 'bad-request', severity: 'error', text: 'name bad', pointer: '/name' }] });
  await ui.submit(f2);
  assert.deepEqual(errorsOf(f2), ['name bad', 'not an e-mail address']);
  ui.routes['POST /principals'] = () => problem(400, 'weak-password', { errors: [{ code: 'weak-password', severity: 'error', text: 'weak', pointer: '/password' }] });
  await ui.submit(f2);
  assert.match(errorsOf(f2).join(' '), /weak|at least 12/);
  ui.routes['POST /principals'] = () => problem(409, 'weak-password');
  await ui.submit(f2);
  assert.match(errorsOf(f2).join(' '), /at least 12 characters/);
  ui.routes['POST /principals'] = () => problem(503, 'database-unavailable');
  await ui.submit(f2);
  assert.match(alerts(f2).join(' '), /database cannot be reached/);
});

test('S11: groups: a new group has no password; the list is of groups; empty and failing lists', async () => {
  const sent = [];
  const ui = await bootApp({ routes: base({
    'GET /principals': () => reply(200, { principals: [G(5, 'ops')], next_cursor: null }),
    'POST /principals': (b) => { sent.push(b); return reply(201, { principal: G(6, b.name) }); },
  }), hash: '#/admin/groups' });
  assert.match(ui.last('GET', '/principals').url, /kind=group/);
  assert.deepEqual(ui.qa('table tbody tr')[0].childNodes.map((c) => c.textContent), ['ops', '-', 'active']);
  assert.equal(ui.input('password'), undefined);
  typed(ui, ui.input('name'), 'team');
  ui.routes['GET /principals/6'] = () => reply(200, { principal: G(6, 'team'), groups: [] });
  ui.routes['GET /principals/6/members'] = () => reply(200, { group: G(6, 'team'), members: [] });
  ui.routes['GET /grants'] = () => reply(200, { grants: [] });
  await ui.submit(form(ui, 'input[name=name]'));
  assert.deepEqual(sent[0], { kind: 'group', name: 'team' });
  assert.equal(ui.env.window.location.hash, '#/admin/principals/6');
  assert.match(ui.text(), /Group: team/);

  const none = await bootApp({ routes: base({ 'GET /principals': () => reply(200, { principals: [], next_cursor: null }) }), hash: '#/admin/groups?cursor=C' });
  assert.match(none.text(), /There are no more\./);
  assert.ok(none.link(/^First page$/));
  const empty = await bootApp({ routes: base({ 'GET /principals': () => reply(200, { principals: [], next_cursor: null }) }), hash: '#/admin/groups' });
  assert.match(empty.text(), /Nothing matches\./);
  const fail = await bootApp({ routes: base({ 'GET /principals': () => problem(500, 'internal') }), hash: '#/admin/users?prefix=<x>' });
  assert.match(fail.text(), /internal error/);
  assert.doesNotMatch(fail.last('GET', '/principals').url, /prefix/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- one user
const CREDS = { password: true, totp_enabled: true, failed_logins: 3, locked: true };
function userRoutes(st = {}, over = {}) {
  return base({
    'GET /principals/2': () => reply(200, { principal: { ...U(2, 'bob', { display_name: 'Bob <i>B</i>', email: 'bob@example.test', ...(st.p ?? {}) }), created_at: '2026-11-01T00:00:00Z', created_by: 1 }, groups: [G(5, 'ops')], credentials: st.creds ?? CREDS }),
    'GET /principals/7': () => reply(200, { principal: U(7, 'alice'), groups: [], credentials: { password: true, totp_enabled: true, failed_logins: 0, locked: false } }),
    'GET /grants': () => reply(200, { grants: st.grants ?? [GR(1, 'bob', 'domain_master'), GR(2, 'bob', 'global_master', { policy: 'all-types', policy_id: 1 })], next_cursor: null }),
    ...over,
  });
}

test('S11: one user: details, the state of its sign-in, unlock and the TOTP reset after a question, a new password, hostile text', async () => {
  const sent = [];
  const st = {};
  const ui = await bootApp({ routes: userRoutes(st, {
    'POST /principals/2/credentials': (b) => { sent.push(b); st.creds = { ...CREDS, ...(b.action === 'unlock' ? { failed_logins: 0, locked: false } : { totp_enabled: false }) }; return reply(200, { credentials: st.creds }); },
    'PUT /principals/2/password': (b) => { sent.push(['password', b]); return reply(200, { password: 'changed' }); },
  }), hash: '#/admin/principals/2' });
  assert.equal(ui.q('h2').textContent, 'User: bob');
  assert.equal(ui.env.document.title, 'User or group - KariDNS WebAdmin');
  const dls = ui.qa('dl').map((d) => d.textContent);
  assert.match(dls[0], /KindUser/);
  assert.match(dls[0], /Stateactive/);
  assert.match(dls[1], /Password setYes/);
  assert.match(dls[1], /Two-step verificationon/);
  assert.match(dls[1], /Failed sign-in attempts3/);
  assert.match(dls[1], /LockedYes/);
  assert.equal(ui.input('display_name').value, 'Bob <i>B</i>', 'a display name is a value, not markup');
  assert.equal(findAll(ui.root, (e) => e.tagName === 'I').length, 0);
  assert.equal(ui.link(/^ops$/).getAttribute('href'), '#/admin/principals/5');
  labelled(ui);
  noForeign(ui);
  // unlock
  await ui.click(ui.button(/^Unlock the account$/));
  assert.equal(sent.length, 0, 'a question first');
  await ui.click(ui.button(/^Yes$/));
  assert.deepEqual(sent[0], { action: 'unlock' });
  assert.match(ui.text(), /The account was unlocked\./);
  assert.equal(ui.button(/^Unlock the account$/), null, 'nothing to unlock any more');
  // the TOTP reset
  await ui.click(ui.button(/^Reset two-step verification$/));
  await ui.click(ui.button(/^No$/));
  assert.equal(sent.length, 1);
  await ui.click(ui.button(/^Reset two-step verification$/));
  await ui.click(ui.button(/^Yes$/));
  assert.deepEqual(sent[1], { action: 'reset-totp' });
  assert.match(ui.text(), /Two-step verification was reset and the sessions of the user ended\./);
  assert.equal(ui.button(/^Reset two-step verification$/), null);
  // a refusal of the action
  st.creds = CREDS;
  ui.app.router.refresh();
  await flush();
  ui.routes['POST /principals/2/credentials'] = () => problem(409, 'totp-disabled');
  await ui.click(ui.button(/^Reset two-step verification$/));
  await ui.click(ui.button(/^Yes$/));
  assert.match(alerts(ui.root).join(' '), /Two-step verification is not on/);
  // a new password
  const pw = form(ui, 'input[name=new_password]');
  typed(ui, ui.input('new_password'), 'short');
  await ui.submit(pw);
  assert.match(errorsOf(pw).join(' '), /at least 12 characters/);
  assert.equal(sent.length, 2);
  typed(ui, ui.input('new_password'), 'a long enough pass');
  await ui.submit(pw);
  assert.deepEqual(sent[2], ['password', { password: 'a long enough pass' }]);
  assert.match(ui.text(), /The password was set and the sessions of the user ended\./);
  ui.routes['PUT /principals/2/password'] = () => problem(400, 'weak-password');
  typed(ui, ui.input('new_password'), 'a long enough pass');
  await ui.submit(form(ui, 'input[name=new_password]'));
  assert.match(errorsOf(ui.root).join(' '), /at least 12 characters/);
  ui.routes['PUT /principals/2/password'] = () => problem(503, 'database-unavailable');
  await ui.submit(form(ui, 'input[name=new_password]'));
  assert.match(alerts(ui.root).join(' '), /database cannot be reached/);
});

test('S11: one user: save the details (and the refusals), disable; the own account cannot be disabled, deleted or have its TOTP reset', async () => {
  const sent = [];
  const ui = await bootApp({ routes: userRoutes({}, {
    'PATCH /principals/2': (b) => { sent.push(b); return reply(200, { principal: U(2, b.name) }); },
    'DELETE /principals/2': () => reply(204, null),
    'GET /principals': () => reply(200, { principals: [], next_cursor: null }),
  }), hash: '#/admin/principals/2' });
  const f = form(ui, 'input[name=display_name]');
  typed(ui, ui.input('name'), ' ');
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['Enter a name.']);
  typed(ui, ui.input('name'), 'robert');
  typed(ui, ui.input('display_name'), '');
  typed(ui, ui.input('email'), '');
  ui.input('disabled').checked = true;
  await ui.submit(f);
  assert.deepEqual(sent[0], { name: 'robert', display_name: null, email: null, disabled: true });
  assert.match(ui.text(), /Saved\./);
  ui.routes['PATCH /principals/2'] = () => problem(409, 'exists');
  await ui.submit(form(ui, 'input[name=display_name]'));
  assert.deepEqual(errorsOf(ui.root).slice(0, 1), ['An object with this name exists already.']);
  ui.routes['PATCH /principals/2'] = () => problem(400, 'bad-request', { errors: [{ code: 'bad-request', severity: 'error', text: 'bad address', pointer: '/email' }, { code: 'bad-request', severity: 'error', text: 'somewhere else', pointer: '/other' }] });
  await ui.submit(form(ui, 'input[name=display_name]'));
  assert.ok(errorsOf(ui.root).includes('bad address'));
  assert.match(alerts(ui.root).join(' '), /request was not valid/);
  // delete
  await ui.click(ui.button(/^Delete$/));
  assert.match(ui.text(), /Delete bob for good\?/);
  ui.routes['DELETE /principals/2'] = () => problem(409, 'self');
  await ui.click(buttonIn(ui.q('section.danger-zone'), /^Yes$/));
  assert.match(alerts(ui.root).join(' '), /cannot do this to yourself/);
  ui.routes['DELETE /principals/2'] = () => reply(204, null);
  await ui.click(ui.button(/^Delete$/));
  await ui.click(buttonIn(ui.q('section.danger-zone'), /^Yes$/));
  assert.equal(ui.env.window.location.hash, '#/admin/users');
  assert.match(ui.text(), /bob was deleted\./);

  // oneself (the id of the signed-in person is 7)
  const me = await bootApp({ routes: userRoutes(), hash: '#/admin/principals/7' });
  assert.equal(me.input('disabled'), undefined);
  assert.match(me.text(), /you cannot disable or delete yourself/);
  assert.equal(me.button(/^Delete$/), null);
  assert.equal(me.button(/^Reset two-step verification$/), null);
  assert.match(me.text(), /cannot reset your own two-step verification here/);
});

test('S11: one user: not found, a bad number in the address, a failing load', async () => {
  const bad = await bootApp({ routes: base(), hash: '#/admin/principals/x1' });
  assert.match(bad.text(), /There is no such user or group\./);
  assert.equal(bad.count('GET', '/principals'), 0);
  const gone = await bootApp({ routes: base({ 'GET /principals/9': () => problem(404, 'not-found') }), hash: '#/admin/principals/9' });
  assert.match(gone.text(), /no such object/);
  assert.ok(gone.link(/^Back to the users$/));
  const nocreds = await bootApp({ routes: base({ 'GET /principals/9': () => reply(200, { principal: U(9, 'nopw') }), 'GET /grants': () => reply(200, { grants: [] }) }), hash: '#/admin/principals/9' });
  assert.match(nocreds.text(), /This user has no password\./);
  assert.match(nocreds.text(), /This user is in no group\./);
  assert.match(nocreds.text(), /There is no grant\./);
});

// ---------------------------------------------------------------------------------------------------------------------------------- one group
test('S11: one group: its members (add by name, remove after a question), the grants it holds', async () => {
  const members = [U(2, 'bob', { display_name: 'Bob' }), G(8, 'inner')];
  const sent = [];
  const ui = await bootApp({ routes: base({
    'GET /principals/5': () => reply(200, { principal: G(5, 'ops'), groups: [] }),
    'GET /principals/5/members': () => reply(200, { group: G(5, 'ops'), members }),
    'GET /grants': () => reply(200, { grants: [] }),
    'GET /principals': (b, url) => reply(200, { principals: /prefix=carol/.test(url) ? [U(3, 'Carol')] : [] }),
    'POST /principals/5/members': (b) => { sent.push(b); members.push(U(3, 'Carol')); return reply(201, { member: b.member }); },
    'DELETE /principals/5/members/2': () => { members.splice(0, 1); return reply(204, null); },
  }), hash: '#/admin/principals/5' });
  assert.equal(ui.q('h2').textContent, 'Group: ops');
  assert.equal(ui.input('password'), undefined);
  assert.deepEqual(ui.qa('table').find((t) => t.querySelector('caption')?.textContent === 'Members').querySelectorAll('tbody tr').map((r) => r.childNodes.map((c) => c.textContent).slice(0, 2)), [['bob (Bob)', 'User'], ['inner', 'Group']]);
  labelled(ui);
  const f = form(ui, 'input[name=member]');
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['Enter a name.']);
  typed(ui, ui.input('member'), 'nobody');
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['No user or group has this name.']);
  typed(ui, ui.input('member'), 'carol');
  await ui.submit(f);
  assert.deepEqual(sent, [{ member: 3 }]);
  assert.match(ui.text(), /Carol was added\./);
  ui.routes['POST /principals/5/members'] = () => problem(409, 'not-a-group');
  typed(ui, ui.input('member'), 'carol');
  await ui.submit(form(ui, 'input[name=member]'));
  assert.deepEqual(errorsOf(ui.root), ['This is not a group.']);
  ui.routes['POST /principals/5/members'] = () => problem(503, 'database-unavailable');
  await ui.submit(form(ui, 'input[name=member]'));
  assert.match(alerts(ui.root).join(' '), /database cannot be reached/);
  // remove
  const bobRow = () => ui.qa('table').find((t) => t.querySelector('caption')?.textContent === 'Members').querySelectorAll('tbody tr')[0];
  await ui.click(buttonIn(bobRow(), /^Remove$/));
  assert.equal(members.length, 3);
  await ui.click(buttonIn(bobRow(), /^Yes$/));
  assert.match(ui.text(), /bob was removed\./);
  assert.equal(members.length, 2);
  ui.routes['DELETE /principals/5/members/8'] = () => problem(404, 'not-found');
  await ui.click(buttonIn(bobRow(), /^Remove$/));
  await ui.click(buttonIn(bobRow(), /^Yes$/));
  assert.match(alerts(ui.root).join(' '), /no such object/);
  const none = await bootApp({ routes: base({ 'GET /principals/5': () => reply(200, { principal: G(5, 'ops'), groups: [] }), 'GET /principals/5/members': () => reply(200, { members: [] }), 'GET /grants': () => reply(200, { grants: [] }) }), hash: '#/admin/principals/5' });
  assert.match(none.text(), /This group has no member\./);
});

// ---------------------------------------------------------------------------------------------------------------------------------- grants
test('S11: the grants of a user: the table, a new grant by role (the fields follow the role), a grant removed after a question, the refusals', async () => {
  const sent = [];
  const st = { grants: [GR(1, 'bob', 'domain_master', { zone: 'x.test.', dataset: 'main' }), GR(2, 'bob', 'subdomain_master', { suffix: 'sub.x.test.', zone: 'x.test.' }), GR(3, 'bob', 'global_master', { policy: 'all-types' })] };
  const ui = await bootApp({ routes: userRoutes(st, {
    'POST /grants': (b) => { sent.push(b); return reply(201, { grant: GR(9, 'bob', b.role) }); },
    'DELETE /grants/1': () => reply(204, null),
  }), hash: '#/admin/principals/2' });
  const trs = ui.q('table.grants').querySelectorAll('tbody tr');
  assert.deepEqual(trs.map((r) => r.childNodes.map((c) => c.textContent).slice(0, 3)), [['Domain master', 'main / x.test.', 'web'], ['Subdomain master', 'main / sub.x.test. (x.test.)', 'web'], ['Global master', 'All zones', 'all-types']]);
  labelled(ui);
  // the form: the role decides which fields show
  const f = form(ui, 'select[name=role]');
  assert.equal(ui.input('role', f).value, 'domain_master', 'the second role is the default');
  const hidden = (name) => ui.input(name, f).parentNode.hidden;
  assert.equal(hidden('suffix'), true);
  assert.equal(hidden('zone'), false);
  await chosen(ui, ui.input('role', f), 'subdomain_master');
  assert.equal(hidden('suffix'), false);
  await chosen(ui, ui.input('role', f), 'global_master');
  assert.equal(hidden('zone'), true);
  assert.equal(hidden('suffix'), true);
  assert.equal(ui.input('dataset', f), undefined, 'one dataset: no selector');
  await chosen(ui, ui.input('role', f), 'domain_master');
  // checks before anything is sent
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['Enter the zone.']);
  typed(ui, ui.input('zone', f), 'x.test');
  await chosen(ui, ui.input('role', f), 'subdomain_master');
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['Enter the suffix.']);
  typed(ui, ui.input('suffix', f), 'sub.x.test');
  await chosen(ui, ui.input('policy', f), '3');
  assert.match(f.textContent, /types: A; TTL: 120-600; max_rr: 10/);
  await ui.submit(f);
  assert.deepEqual(sent[0], { principal: 2, role: 'subdomain_master', policy: 3, zone: 'x.test', suffix: 'sub.x.test' });
  assert.equal(sent[0].dataset, undefined, 'one dataset: the service knows which');
  assert.match(ui.text(), /The grant was given\./);
  await chosen(ui, ui.input('role', form(ui, 'select[name=role]')), 'global_master');
  await ui.submit(form(ui, 'select[name=role]'));
  assert.deepEqual(sent[1], { principal: 2, role: 'global_master', policy: Number(ui.input('policy', form(ui, 'select[name=role]')).value) });
  // refusals at the field of their pointer, and as a message
  ui.routes['POST /grants'] = () => problem(400, 'bad-request', { errors: [{ code: 'bad-request', severity: 'error', text: 'the suffix is not below the zone', pointer: '/suffix' }, { code: 'bad-request', severity: 'error', text: 'zone odd', pointer: '/zone' }] });
  const g = form(ui, 'select[name=role]');
  await chosen(ui, ui.input('role', g), 'subdomain_master');
  typed(ui, ui.input('zone', g), 'x.test');
  typed(ui, ui.input('suffix', g), 'other.test');
  await ui.submit(g);
  assert.deepEqual(errorsOf(g), ['zone odd', 'the suffix is not below the zone']);
  ui.routes['POST /grants'] = () => problem(403, 'escalation');
  await ui.submit(g);
  assert.match(alerts(g).join(' '), /may not give more than you have/);
  // removing a grant: a question first
  const row = () => ui.qa('table.grants tbody tr')[0];
  await ui.click(buttonIn(row(), /^Remove$/));
  assert.equal(ui.count('DELETE', '/grants/1'), 0);
  assert.match(row().textContent, /Remove this grant\?/);
  await ui.click(buttonIn(row(), /^Yes$/));
  assert.equal(ui.count('DELETE', '/grants/1'), 1);
  assert.match(ui.text(), /The grant was removed\./);
  ui.routes['DELETE /grants/1'] = () => problem(404, 'not-found');
  await ui.click(buttonIn(row(), /^Remove$/));
  await ui.click(buttonIn(row(), /^Yes$/));
  assert.match(alerts(ui.root).join(' '), /no such object/);
});

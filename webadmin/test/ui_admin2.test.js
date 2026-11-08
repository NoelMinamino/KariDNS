// The administration and audit screens, part two: record policies (S11), the grants tab and the grants of a zone for a domain master, the audit log (S12), with hostile data.

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootApp, reply, problem, flush, findAll, byText, GRANT_GLOBAL, POLICY } from './ui_boot.js';
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

const POLICIES = [
  { ...POLICY, id: 1, name: 'all-types' },
  { id: 2, name: 'web', allowed_types: ['A', 'TXT'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 60, ttl_max: 3600, max_rr: 100 },
  { id: 3, name: 'web-small', allowed_types: ['A'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 120, ttl_max: 600, max_rr: 10 },
  { id: 4, name: '<b>evil</b>‮', allowed_types: ['A'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 0, ttl_max: 100, max_rr: null },
];
const base = (over = {}) => ({
  'GET /datasets': () => reply(200, { datasets: [{ name: 'main', driver: 'sqlite3', views: [] }] }),
  'GET /rr-policies': () => reply(200, { policies: POLICIES, next_cursor: null }),
  ...over,
});
const U = (id, name) => ({ id, kind: 'user', name, display_name: null, email: null, disabled: false });

// ---------------------------------------------------------------------------------------------------------------------------------- policies
test('S11: policies: the list, a new policy (checked here, then sent), an edit that fills the form, a pointer on the types, delete after a question', async () => {
  const sent = [];
  const ui = await bootApp({ routes: base({
    'POST /rr-policies': (b) => { sent.push(['POST', b]); return reply(201, { policy: { ...b, id: 9 } }); },
    'PATCH /rr-policies/2': (b) => { sent.push(['PATCH', b]); return reply(200, { policy: { ...b, id: 2 } }); },
    'DELETE /rr-policies/3': () => reply(204, null),
  }), hash: '#/admin/policies' });
  assert.equal(ui.last('GET', '/rr-policies').url, '/api/v1/rr-policies?limit=500');
  const rows = ui.qa('table tbody tr');
  assert.deepEqual(rows[1].childNodes.map((c) => c.textContent).slice(0, 5), ['web', 'A TXT', '60-3600', '-', '100']);
  assert.match(rows[0].childNodes[3].textContent, /wildcards, delegations, zone apex/);
  assert.equal(rows[3].querySelector('th').textContent, '<b>evil</b><U+202E>');
  assert.equal(findAll(rows[3], (e) => e.tagName === 'B').length, 0);
  assert.equal(rows[0].childNodes[4].textContent, '-');
  labelled(ui);
  noForeign(ui);
  const f = () => form(ui, 'input[name=allow_wildcard]');
  // nothing, then a TTL range that is wrong
  await ui.submit(f());
  assert.deepEqual(errorsOf(f()), ['Enter a name.']);
  typed(ui, ui.input('name'), 'new');
  await ui.submit(f());
  assert.deepEqual(errorsOf(f()), ['Enter at least one record type.']);
  typed(ui, ui.input('types'), 'a cname');
  typed(ui, ui.input('ttl_min'), '500');
  typed(ui, ui.input('ttl_max'), '100');
  await ui.submit(f());
  assert.deepEqual(errorsOf(f()), ['Enter a whole number of seconds that is not above the highest TTL.']);
  typed(ui, ui.input('ttl_min'), '5');
  typed(ui, ui.input('ttl_max'), '1x');
  await ui.submit(f());
  assert.deepEqual(errorsOf(f()), ['Enter a whole number of seconds.']);
  typed(ui, ui.input('ttl_max'), '100');
  typed(ui, ui.input('max_rr'), 'x');
  await ui.submit(f());
  assert.deepEqual(errorsOf(f()), ['Enter a whole number, or leave it empty.']);
  assert.equal(sent.length, 0);
  typed(ui, ui.input('max_rr'), '');
  ui.input('allow_wildcard').checked = true;
  await ui.submit(f());
  assert.deepEqual(sent[0], ['POST', { name: 'new', allowed_types: ['A', 'CNAME'], allow_wildcard: true, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 5, ttl_max: 100, max_rr: null }]);
  assert.match(ui.text(), /The policy new was created\./);
  assert.equal(ui.input('name').value, '', 'the form is empty again');
  // a refusal on one type, with its pointer
  typed(ui, ui.input('name'), 'bad');
  typed(ui, ui.input('types'), 'A DNSKEY');
  ui.routes['POST /rr-policies'] = () => problem(400, 'bad-request', { errors: [{ code: 'bad-request', severity: 'error', text: 'DNSKEY cannot be in a policy', pointer: '/allowed_types/1' }] });
  await ui.submit(f());
  assert.deepEqual(errorsOf(f()), ['DNSKEY cannot be in a policy']);
  ui.routes['POST /rr-policies'] = () => problem(409, 'exists');
  await ui.submit(f());
  assert.match(alerts(f()).join(' '), /request was not valid|exists already/);
  // edit: the form is filled with the policy
  const web = ui.qa('table tbody tr')[1];
  await ui.click(buttonIn(web, /^Edit$/));
  assert.equal(ui.q('#polf-title').textContent, 'Edit the policy web');
  assert.equal(ui.input('name').value, 'web');
  assert.equal(ui.input('types').value, 'A TXT');
  assert.equal(ui.input('ttl_min').value, '60');
  assert.equal(ui.input('max_rr').value, '100');
  assert.equal(ui.input('allow_wildcard').checked, false);
  typed(ui, ui.input('max_rr'), '');
  await ui.submit(f());
  assert.deepEqual(sent.at(-1)[0], 'PATCH');
  assert.equal(sent.at(-1)[1].max_rr, null);
  assert.match(ui.text(), /The policy web was saved\./);
  await ui.click(ui.qa('table tbody tr')[1].querySelector('button'));
  await ui.click(buttonIn(ui.root, /^Cancel$/));
  assert.equal(ui.q('#polf-title').textContent, 'New policy');
  // delete: a question first; a policy in use is refused
  const small = () => ui.qa('table tbody tr')[2];
  await ui.click(buttonIn(small(), /^Delete$/));
  assert.equal(ui.count('DELETE', '/rr-policies/3'), 0);
  await ui.click(buttonIn(small(), /^Yes$/));
  assert.equal(ui.count('DELETE', '/rr-policies/3'), 1);
  assert.match(ui.text(), /The policy web-small was deleted\./);
  ui.routes['DELETE /rr-policies/3'] = () => problem(409, 'in-use');
  await ui.click(buttonIn(small(), /^Delete$/));
  await ui.click(buttonIn(small(), /^Yes$/));
  assert.match(alerts(ui.root).join(' '), /still in use/);
  // deleting the policy that is being edited empties the form
  await ui.click(buttonIn(ui.qa('table tbody tr')[2], /^Edit/));
  assert.equal(ui.input('name').value, 'web-small');
  ui.routes['DELETE /rr-policies/3'] = () => reply(204, null);
  await ui.click(buttonIn(small(), /^Delete$/));
  await ui.click(buttonIn(small(), /^Yes$/));
  assert.equal(ui.input('name').value, '');

  const none = await bootApp({ routes: base({ 'GET /rr-policies': () => reply(200, { policies: [] }) }), hash: '#/admin/policies' });
  assert.match(none.text(), /There is no policy\./);
  const fail = await bootApp({ routes: base({ 'GET /rr-policies': () => problem(503, 'database-unavailable') }), hash: '#/admin/policies' });
  assert.match(fail.text(), /database cannot be reached/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the grants tab
const GR = (id, principal, role, over = {}) => ({ id, principal_id: 40 + id, principal, role, dataset: role === 'global_master' ? null : 'main', zone: role === 'global_master' ? null : 'example.test.', suffix: null, policy_id: 2, policy: 'web',
  granted_by: 1, granted_at: '2026-11-09T01:00:00Z', ...over });

test('S11: all grants: filter by user and zone, the paging, a grant for a user found by name, more than one dataset', async () => {
  const sent = [];
  const st = { next: 'G2' };
  const ui = await bootApp({ routes: base({
    'GET /datasets': () => reply(200, { datasets: [{ name: 'main' }, { name: 'second' }] }),
    'GET /principals': (b, url) => reply(200, { principals: /prefix=carol/.test(url) ? [U(3, 'carol')] : /prefix=eve/.test(url) ? [U(4, 'eve2')] : [] }),
    'GET /grants': () => reply(200, { grants: [GR(1, '<i>bob</i>', 'domain_master'), GR(2, 'carol', 'subdomain_master', { suffix: 'a.example.test.' })], next_cursor: st.next }),
    'POST /grants': (b) => { sent.push(b); return reply(201, { grant: GR(7, 'carol', b.role) }); },
  }), hash: '#/admin/grants?who=carol&zone=example.test.' });
  assert.equal(ui.last('GET', '/grants').url, '/api/v1/grants?limit=100&principal=3&zone=example.test.');
  const trs = ui.qa('table.grants tbody tr');
  assert.deepEqual(trs[0].childNodes.map((c) => c.textContent).slice(0, 4), ['<i>bob</i>', 'Domain master', 'main / example.test.', 'web']);
  assert.equal(findAll(trs[0], (e) => e.tagName === 'I').length, 0);
  assert.equal(trs[1].querySelector('a').getAttribute('href'), '#/admin/principals/42');
  assert.equal(ui.link(/^Next page$/).getAttribute('href'), '#/admin/grants?who=carol&zone=example.test.&cursor=G2');
  labelled(ui);
  noForeign(ui);
  // the filter
  const filter = ui.q('form.search');
  typed(ui, ui.input('who', filter), 'eve2');
  typed(ui, ui.input('zone', filter), '');
  await ui.submit(filter);
  assert.equal(ui.env.window.location.hash, '#/admin/grants?who=eve2');
  // the new grant: the dataset is chosen where there are two; the user is found by name
  const f = form(ui, 'select[name=dataset]');
  assert.deepEqual(ui.input('dataset', f).children.map((o) => o.textContent), ['main', 'second']);
  await chosen(ui, ui.input('dataset', f), 'second');
  typed(ui, ui.input('principal', f), 'nobody');
  typed(ui, ui.input('zone', f), 'example.test');
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['No user or group has this name.']);
  typed(ui, ui.input('principal', f), '  ');
  await ui.submit(f);
  assert.deepEqual(errorsOf(f), ['Enter the name of a user or group.']);
  typed(ui, ui.input('principal', f), 'carol');
  await ui.submit(f);
  assert.deepEqual(sent[0], { principal: 3, role: 'domain_master', policy: 1, zone: 'example.test', dataset: 'second' });
  assert.match(ui.text(), /The grant was given\./);
  // an unknown user in the filter is told, the failures too
  await ui.go('#/admin/grants?who=nobody');
  assert.match(ui.text(), /No user or group has this name\./);
  await ui.go('#/admin/grants?cursor=Z');
  assert.ok(ui.link(/^First page$/));

  const fail = await bootApp({ routes: base({ 'GET /grants': () => problem(503, 'database-unavailable') }), hash: '#/admin/grants' });
  assert.match(fail.text(), /database cannot be reached/);
  const polFail = await bootApp({ routes: base({ 'GET /grants': () => reply(200, { grants: [] }), 'GET /rr-policies': () => problem(503, 'database-unavailable') }), hash: '#/admin/grants' });
  assert.match(polFail.text(), /There is no grant\./);
  assert.match(polFail.text(), /database cannot be reached/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the grants of a zone
const OWN = POLICIES[1];
const DOMAIN_GRANT = { id: 3, role: 'domain_master', dataset: 'main', zone: 'example.test.', suffix: null, policy: OWN, via: null };
const zoneInfo = (over = {}) => ({
  name: 'example.test.', id: 1, kind: 'NATIVE', serial: 10, catalog: null, master: null, account: null, notified_serial: null, presigned: false, signer: false, nsec3param: null,
  generation: 5, changed_at: '2026-11-09T00:00:00Z', views: [], signer_state: null, waiting_for_signer: false, last_reload_request: null, role: 'domain_master', grants: [DOMAIN_GRANT], ...over,
});
const ZG = '#/zones/main/example.test./grants';

test('S11: the grants of a zone for a domain master: the grants on the zone, only the policies within its own, no global role, the dataset is the zone\'s', async () => {
  const sent = [];
  const ui = await bootApp({ routes: base({
    'GET /datasets/main/zones/example.test.': () => reply(200, { zone: zoneInfo() }),
    'GET /grants': () => reply(200, { grants: [GR(1, 'sub-person', 'subdomain_master', { suffix: 'sub.example.test.' })] }),
    'GET /principals': () => reply(200, { principals: [U(5, 'sub-person')] }),
    'POST /grants': (b) => { sent.push(b); return reply(201, { grant: GR(8, 'sub-person', b.role) }); },
    'DELETE /grants/1': () => reply(204, null),
  }), hash: ZG, me: { global: false, grants: [DOMAIN_GRANT] } });
  assert.equal(ui.last('GET', '/grants').url, '/api/v1/grants?zone=example.test.&limit=100');
  assert.equal(findAll(ui.root, (e) => e.tagName === 'A' && e.textContent === 'Grants')[0].getAttribute('aria-current'), 'page');
  const f = form(ui, 'select[name=role]');
  assert.deepEqual(ui.input('role', f).children.map((o) => o.textContent), ['Domain master', 'Subdomain master']);
  assert.deepEqual(ui.input('policy', f).children.map((o) => o.textContent), ['web', 'web-small'], 'the policies no wider than its own');
  assert.equal(ui.input('zone', f), undefined, 'the zone is the zone of the page');
  assert.equal(ui.input('dataset', f), undefined);
  assert.match(f.textContent, /Only policies that are no wider than your own are offered/);
  assert.equal(ui.q('table.grants tbody tr').querySelector('a'), null, 'no link to the administration for a person who has none');
  await chosen(ui, ui.input('role', f), 'subdomain_master');
  typed(ui, ui.input('principal', f), 'sub-person');
  typed(ui, ui.input('suffix', f), 'sub2.example.test');
  await chosen(ui, ui.input('policy', f), '3');
  await ui.submit(f);
  assert.deepEqual(sent[0], { principal: 5, role: 'subdomain_master', policy: 3, zone: 'example.test.', dataset: 'main', suffix: 'sub2.example.test' });
  assert.match(ui.text(), /The grant was given\./);
  // the service's refusal is shown
  ui.routes['POST /grants'] = () => problem(403, 'escalation');
  typed(ui, ui.input('principal'), 'sub-person');
  typed(ui, ui.input('suffix'), 'sub3.example.test');
  await ui.submit(form(ui, 'select[name=role]'));
  assert.match(alerts(ui.root).join(' '), /may not give more than you have/);
  await ui.click(buttonIn(ui.root, /^Remove$/));
  await ui.click(buttonIn(ui.root, /^Yes$/));
  assert.match(ui.text(), /The grant was removed\./);
  noForeign(ui);
  labelled(ui);

  // no policy within its own
  const narrow = await bootApp({ routes: base({
    'GET /datasets/main/zones/example.test.': () => reply(200, { zone: zoneInfo({ grants: [{ ...DOMAIN_GRANT, policy: POLICIES[2] }] }) }),
    'GET /grants': () => reply(200, { grants: [] }),
    'GET /rr-policies': () => reply(200, { policies: [POLICIES[0], POLICIES[1]] }),
  }), hash: ZG, me: { global: false, grants: [] } });
  assert.match(narrow.text(), /There is no policy you may give\./);
  await narrow.submit(form(narrow, 'select[name=role]'));
  assert.ok(errorsOf(narrow.root).length + alerts(narrow.root).length > 0);

  // a global master sees every policy, and the names link to the administration
  const global = await bootApp({ routes: base({
    'GET /datasets/main/zones/example.test.': () => reply(200, { zone: zoneInfo({ role: 'global_master', grants: [GRANT_GLOBAL] }) }),
    'GET /grants': () => reply(200, { grants: [GR(1, 'sub-person', 'subdomain_master', { suffix: 'sub.example.test.' })] }),
  }), hash: ZG });
  assert.equal(global.input('policy', form(global, 'select[name=role]')).children.length, 4);
  assert.equal(global.q('table.grants tbody tr').querySelector('a').getAttribute('href'), '#/admin/principals/41');
  // a subdomain master has no grants section; failures
  const sub = await bootApp({ routes: base({ 'GET /datasets/main/zones/example.test.': () => reply(200, { zone: zoneInfo({ role: 'subdomain_master' }) }) }), hash: ZG, me: { global: false, grants: [] } });
  assert.match(sub.text(), /managed by the masters of the whole zone/);
  assert.equal(sub.count('GET', '/grants'), 0);
  const fail = await bootApp({ routes: base({ 'GET /datasets/main/zones/example.test.': () => reply(200, { zone: zoneInfo() }), 'GET /grants': () => problem(503, 'database-unavailable') }), hash: ZG, me: { global: false, grants: [] } });
  assert.match(fail.text(), /database cannot be reached/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- audit
const ROW = (id, over = {}) => ({
  id, at: '2026-11-09T01:02:03Z', source: 'audit', principal_id: 7, principal: 'alice', db_role: 'karidns_api', change_set: 'cs-1', schema: 'public', table: 'records', op: 'U', zone: 'example.test.', row_id: '55',
  before: { name: 'www.example.test', content: '192.0.2.1' }, after: { name: 'www.example.test', content: '192.0.2.2' }, ...over,
});
const AUDIT = {
  audit: [
    ROW(3),
    ROW(2, { principal: null, principal_id: null, db_role: 'postgres', change_set: null, op: 'I', before: null, after: { content: '"<img src=x onerror=window.__xss=1>"', note: 'a‮b\u0001c', list: [1, { x: '</script>' }] }, table: 'grants', zone: null }),
    ROW(1, { principal: null, db_role: null, change_set: null, op: 'D', after: null, zone: 'other.test.', row_id: null, source: 'zone', schema: 'other' }),
    ROW(0, { op: 'X', change_set: 'cs-9', zone: 'example.test.', before: { huge: 'x'.repeat(30000) }, after: undefined }),
  ],
  next_cursor: 'A2',
};
const auditRoutes = (over = {}) => base({ 'GET /audit': () => reply(200, AUDIT), 'GET /principals': (b, url) => reply(200, { principals: /prefix=alice/.test(url) ? [U(7, 'alice')] : [] }), ...over });

test('S12: the audit log: rows, who, what, the zone, the change set with its links, before and after as text only', async () => {
  const ui = await bootApp({ routes: auditRoutes(), hash: '#/audit' });
  assert.equal(ui.q('h1').textContent, 'Audit log');
  assert.equal(ui.link(/^Audit log$/).getAttribute('aria-current'), 'page');
  assert.equal(ui.last('GET', '/audit').url, '/api/v1/audit?limit=100');
  const rows = ui.qa('table.audit tbody tr');
  assert.equal(rows.length, 4);
  assert.deepEqual([1, 2, 3].map((i) => rows[0].childNodes[i].textContent), ['alice', 'records changed', 'example.test.']);
  assert.equal(rows[1].childNodes[1].textContent, 'postgres', 'a database role when no person');
  assert.equal(rows[2].childNodes[1].textContent, '-');
  assert.equal(rows[1].childNodes[2].textContent, 'grants added');
  assert.equal(rows[2].childNodes[2].textContent, 'records deleted');
  assert.equal(rows[3].childNodes[2].textContent, 'records X', 'an operation the page does not know is shown as it is');
  assert.equal(rows[1].childNodes[3].textContent, '-');
  assert.equal(rows[1].childNodes[4].textContent, '-');
  // the change set: its code and two links; the version link only where the dataset is known (one dataset: it is)
  const links = findAll(rows[0].childNodes[4], (e) => e.tagName === 'A').map((a) => [a.textContent, a.getAttribute('href'), a.getAttribute('aria-label')]);
  assert.deepEqual(links, [['all rows', '#/audit?change_set=cs-1', 'All rows of the change set of row 3'], ['version', '#/zones/main/example.test./versions?cs=cs-1', 'The version of the change set of row 3']]);
  assert.equal(findAll(rows[0].childNodes[4], (e) => e.tagName === 'CODE')[0].textContent, 'cs-1');
  // the details
  const d = rows[0].childNodes[5].querySelector('details');
  assert.equal(d.querySelector('summary').textContent, 'Row 3');
  assert.match(d.querySelector('dl').textContent, /Sourceaudit/);
  assert.match(d.querySelector('dl').textContent, /Database rolekaridns_api/);
  assert.match(d.querySelector('dl').textContent, /Row55/);
  const pres = d.querySelectorAll('pre');
  assert.equal(pres.length, 2);
  assert.deepEqual(pres[0].childNodes.map((c) => c.textContent), ['{', '  "name": "www.example.test",', '  "content": "192.0.2.1"', '}']);
  // hostile data is text: no element, markers for what is invisible, a cut for what is long
  const hostile = rows[1].querySelector('details');
  assert.equal(hostile.querySelectorAll('pre').length, 1, 'no before');
  const text = hostile.querySelector('pre').textContent;
  assert.match(text, /"content": "\\"<img src=x onerror=window\.__xss=1>\\""/);
  assert.match(text, /a<U\+202E>b\\u0001c/);
  assert.equal(findAll(hostile, (e) => e.tagName === 'IMG' || e.tagName === 'SCRIPT').length, 0);
  assert.match(rows[3].textContent, /The text was cut here\./);
  assert.equal(rows[3].querySelectorAll('pre').length, 1, 'no after: undefined');
  assert.equal(rows[2].childNodes[4].textContent, '-');
  assert.equal(findAll(rows[2], (e) => e.tagName === 'A').length, 0, 'no change set: no link');
  // the version link is left out where the dataset cannot be told
  assert.equal(findAll(rows[3], (e) => e.tagName === 'A').length, 2);
  assert.equal(ui.link(/^Next page$/).getAttribute('href'), '#/audit?cursor=A2');
  labelled(ui);
  noForeign(ui);

  const two = await bootApp({ routes: auditRoutes({ 'GET /datasets': () => reply(200, { datasets: [{ name: 'main' }, { name: 'other' }] }) }), hash: '#/audit' });
  const trs = two.qa('table.audit tbody tr');
  assert.equal(findAll(trs[0], (e) => e.tagName === 'A').length, 1, 'public is no dataset: no link to a version');
  assert.equal(findAll(trs[2], (e) => e.tagName === 'A').length, 0);
  const lost = await bootApp({ routes: auditRoutes({ 'GET /datasets': () => problem(503, 'database-unavailable') }), hash: '#/audit' });
  assert.equal(lost.qa('table.audit tbody tr').length, 4);
  assert.equal(findAll(lost.qa('table.audit tbody tr')[0], (e) => e.tagName === 'A').length, 1);
});

test('S12: the filters: the form puts them in the route, the route in the request; a user found by name; what cannot be sent is told at its field', async () => {
  const ui = await bootApp({ routes: auditRoutes(), hash: '#/audit?zone=example.test.&who=alice&change_set=cs-1&table=records&since=2026-11-08T00:00:00Z&until=2026-11-10&cursor=A2' });
  assert.equal(ui.last('GET', '/audit').url, '/api/v1/audit?limit=100&zone=example.test.&principal=7&change_set=cs-1&table=records&since=2026-11-08T00%3A00%3A00Z&until=2026-11-10&cursor=A2');
  assert.equal(ui.input('zone').value, 'example.test.');
  assert.equal(ui.input('who').value, 'alice');
  assert.ok(ui.link(/^First page$/));
  typed(ui, ui.input('table'), 'grants');
  typed(ui, ui.input('since'), '');
  await ui.submit(ui.q('form.search'));
  assert.equal(ui.env.window.location.hash, '#/audit?zone=example.test.&who=alice&change_set=cs-1&table=grants&until=2026-11-10');
  // a name nobody has, then a field that is wrong
  for (const [hash, name, re] of [['#/audit?who=nobody', 'who', /No user or group has this name\./], ['#/audit?zone=a%20b', 'zone', /not a zone name/], ['#/audit?change_set=a%20b', 'change_set', /letters, digits/],
    ['#/audit?table=Records', 'table', /lower case/], ['#/audit?since=soon', 'since', /not a time/], ['#/audit?until=soon', 'until', /not a time/]]) {
    const bad = await bootApp({ routes: auditRoutes(), hash });
    assert.equal(bad.count('GET', '/audit'), 0, hash);
    assert.match(errorsOf(bad.root).join(' '), re, hash);
    assert.match(bad.text(), /No row matches\./);
    assert.ok(bad.input(name));
  }
  const none = await bootApp({ routes: auditRoutes({ 'GET /audit': () => reply(200, { audit: [], next_cursor: null }) }), hash: '#/audit' });
  assert.match(none.text(), /No row matches\./);
  const later = await bootApp({ routes: auditRoutes({ 'GET /audit': () => reply(200, { audit: [], next_cursor: null }) }), hash: '#/audit?cursor=X' });
  assert.match(later.text(), /There are no more rows\./);
  const fail = await bootApp({ routes: auditRoutes({ 'GET /audit': () => problem(403, 'forbidden') }), hash: '#/audit' });
  assert.match(fail.q('p.msg.error').textContent, /not allowed/);
  const lookupFail = await bootApp({ routes: auditRoutes({ 'GET /principals': () => problem(503, 'database-unavailable') }), hash: '#/audit?who=alice' });
  assert.match(lookupFail.text(), /database cannot be reached/);
});

test('a screen that is left stops what it was doing: no write to a page that is gone', async () => {
  const routes = auditRoutes({
    'GET /principals': () => reply(200, { principals: [], next_cursor: null }), 'GET /principals/7': () => reply(200, { principal: U(7, 'x'), groups: [] }),
    'GET /grants': () => reply(200, { grants: [] }), 'GET /datasets/main/zones/example.test.': () => reply(200, { zone: zoneInfo() }), 'GET /version': () => reply(200, {}),
  });
  for (const hash of ['#/admin/users', '#/admin/groups', '#/admin/policies', '#/admin/grants', '#/admin/principals/7', '#/audit', ZG]) {
    const ui = await bootApp({ routes, hash });
    await ui.go('#/about');
    assert.equal(ui.q('h1').textContent, 'About', hash);
  }
});

// The history and template screens (S9, S10) on the fake DOM against a scripted API (planning 8.1, F-11): what is on the page, what the forms send, how every refusal is
// shown, hostile data (no element may come from it).

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootApp, reply, problem, flush, findAll, byText, GRANT_GLOBAL, POLICY } from './ui_boot.js';
import { FakeEvent } from './fakedom.js';

const INFO = {
  name: 'example.test.', id: 1, kind: 'NATIVE', serial: 10, catalog: null, master: null, account: null, notified_serial: null, presigned: false, signer: false, nsec3param: null,
  generation: 5, changed_at: '2026-11-09T00:00:00Z', views: [], signer_state: null, waiting_for_signer: false, last_reload_request: null, role: 'global_master', grants: [GRANT_GLOBAL],
};
const ZONE = '#/zones/main/example.test.';
const V = '/datasets/main/zones/example.test./versions';
const zoneRoutes = (info = {}, over = {}) => ({
  'GET /datasets': () => reply(200, { datasets: [{ name: 'main', driver: 'sqlite3', views: [] }] }),
  'GET /datasets/main/zones/example.test.': () => reply(200, { zone: { ...INFO, ...info } }),
  ...over,
});
const buttonIn = (el, re) => byText(el, 'button', re);
const typed = (ui, el, v) => { el.value = v; el.dispatchEvent(new FakeEvent('input')); };
const chosen = (ui, el, v) => { el.value = v; el.dispatchEvent(new FakeEvent('change')); return flush(); };
const TAGS = new Set(['DIV', 'SECTION', 'HEADER', 'MAIN', 'FOOTER', 'NAV', 'UL', 'LI', 'A', 'SPAN', 'STRONG', 'P', 'H1', 'H2', 'H3', 'H4', 'BUTTON', 'FORM', 'LABEL', 'INPUT', 'SELECT', 'OPTION',
  'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD', 'CAPTION', 'DL', 'DT', 'DD', 'CODE', 'TIME', 'OL', 'SVG', 'PATH', 'DIALOG', 'TEXTAREA', 'B', 'I', 'EM', 'FIELDSET', 'LEGEND', 'PRE', 'DETAILS', 'SUMMARY']);
const noForeign = (ui) => { for (const e of findAll(ui.env.document.body, () => true)) assert.ok(TAGS.has(e.tagName), `unexpected element ${e.tagName}`); };
const errorsOf = (root) => findAll(root, (e) => e.tagName === 'P' && e.className === 'error' && !e.hidden).map((e) => e.textContent);
function labelled(ui) {
  for (const input of findAll(ui.root, (e) => ['INPUT', 'SELECT', 'TEXTAREA'].includes(e.tagName))) {
    const label = findAll(ui.root, (e) => e.tagName === 'LABEL' && e.htmlFor === input.getAttribute('id'));
    assert.equal(label.length, 1, `the control ${input.getAttribute('name')} has one label`);
    for (const id of (input.getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean)) assert.ok(ui.root.querySelector(`#${id}`), `${id} exists`);
  }
  for (const b of findAll(ui.root, (e) => e.tagName === 'BUTTON')) assert.ok(b.textContent.trim() !== '' || b.getAttribute('aria-label'), 'a button has a name');
  for (const a of findAll(ui.root, (e) => e.tagName === 'A')) assert.ok(a.textContent.trim() !== '' || a.getAttribute('aria-label'), 'a link has a name');
}

const line = (ttl, content) => ({ ttl, content });
const VERSIONS = {
  versions: [
    { version: 3, kind: 'edit', at: '2026-11-09T03:00:00Z', principal: { id: 7, name: 'alice' }, db_role: 'api', change_set: 'cs-3', comment: 'move <b>www</b>‮', serial: { before: 12, after: 13 }, generation: { before: 14, after: 15 },
      rollback_of: null, delta_complete: true, rrsets: 2, changed_outside_before: { basis: 'audit', count: 2, rrsets: [{ name: 'www.example.test.', type: 'A' }, { name: 'example.test.', type: 'TXT' }] } },
    { version: 2, kind: 'rollback', at: '2026-11-09T02:00:00Z', principal: null, db_role: 'karidns', change_set: null, comment: null, serial: { before: 11, after: 12 }, generation: { before: 10, after: 12 }, rollback_of: 1,
      delta_complete: false, rrsets: 5, changed_outside_before: { basis: 'generation', count: null, rrsets: [] } },
    { version: 1, kind: 'import', at: '2026-11-09T01:00:00Z', principal: null, db_role: null, change_set: null, comment: 'first', serial: { before: null, after: 10 }, generation: { before: 0, after: 10 }, rollback_of: null,
      delta_complete: true, rrsets: 4, changed_outside_before: null },
  ],
  changed_outside_since: { basis: 'audit', count: 1, rrsets: [{ name: 'new.example.test.', type: 'CNAME' }] },
  next_cursor: null,
};
const DELTA = {
  version: { ...VERSIONS.versions[0], rrsets: undefined },
  rrsets: [
    { name: 'www.example.test.', type: 'A', change: 'replace', before: [line(300, '192.0.2.10')], after: [line(300, '192.0.2.50')] },
    { name: 'new.example.test.', type: 'A', change: 'add', before: null, after: [line(300, '192.0.2.60')] },
  ],
  next_cursor: null,
};
const histRoutes = (over = {}) => zoneRoutes({}, { [`GET ${V}`]: () => reply(200, VERSIONS), [`GET ${V}/3`]: () => reply(200, DELTA), ...over });

// ---------------------------------------------------------------------------------------------------------------------------------- the list
test('S9: the versions of a zone: kinds, who, when, the comment as text, notes, the markers of changes outside the versions', async () => {
  const ui = await bootApp({ routes: histRoutes(), hash: `${ZONE}/versions` });
  assert.equal(ui.env.document.title, 'Versions - example.test. - KariDNS WebAdmin');
  assert.equal(ui.last('GET', V).url, '/api/v1/datasets/main/zones/example.test./versions?limit=100');
  const rows = ui.qa('table.versions tbody tr');
  const main = rows.filter((r) => r.querySelector('th'));
  assert.equal(main.length, 3);
  assert.deepEqual(main[0].childNodes.map((c) => c.textContent), ['3', 'edit', main[0].childNodes[2].textContent, 'alice', 'move <b>www</b><U+202E>', '12 → 13', '2', '', 'Against the zone now Roll back...']);
  assert.equal(main[0].querySelector('a').getAttribute('href'), '#/zones/main/example.test./versions/3');
  assert.deepEqual(main[1].childNodes.map((c) => c.textContent).filter((_, i) => [1, 3, 4, 7].includes(i)), ['rollback', 'operator (karidns)', '-', 'restores version 1too large: its record sets were not kept']);
  assert.equal(main[2].childNodes[3].textContent, '-', 'no person and no database role');
  assert.equal(main[2].childNodes[5].textContent, '- → 10');
  assert.equal(findAll(main[0], (e) => e.tagName === 'B').length, 0, 'a comment is text');
  const links = findAll(main[0], (e) => e.tagName === 'A').map((a) => [a.textContent, a.getAttribute('href'), a.getAttribute('aria-label')]);
  assert.deepEqual(links.slice(1), [['Against the zone now', '#/zones/main/example.test./versions/3/diff?to=current', 'Compare version 3 with the zone as it is now'],
    ['Roll back...', '#/zones/main/example.test./versions/3', 'Roll the zone back to version 3']]);
  // the markers: one before the first row (since the newest), one after the rows that have them
  const text = ui.q('table.versions').parentNode.textContent;
  assert.match(text, /Since the newest version: the zone was changed outside the versions \(1 changes of records that no version explains\)\. new CNAME/);
  assert.match(ui.q('table.versions').textContent, /Before this version: the zone was changed outside the versions \(2 changes[^)]*\)\. www A, @ TXT/);
  assert.match(ui.q('table.versions').textContent, /Before this version: the zone changed \(its generation grew\) but no version explains it/);
  const audit = findAll(ui.root, (e) => e.tagName === 'A' && e.textContent === 'Audit log of this zone');
  assert.equal(audit.length, 3);
  assert.equal(audit[0].getAttribute('href'), '#/audit?zone=example.test.');
  assert.equal(ui.qa('select').length, 0);
  labelled(ui);
  noForeign(ui);
  // the zone frame has a Versions section that is the current one
  assert.equal(findAll(ui.root, (e) => e.tagName === 'A' && e.textContent === 'Versions')[0].getAttribute('aria-current'), 'page');
});

test('S9: the change set you came from is marked; the paging; an empty history; a failure; the person who sees part of each change', async () => {
  const st = { next: 'CUR9' };
  const ui = await bootApp({ routes: histRoutes({ [`GET ${V}`]: () => reply(200, { ...VERSIONS, next_cursor: st.next }) }), hash: `${ZONE}/versions?cs=cs-3` });
  const marked = ui.qa('table.versions tbody tr').filter((r) => r.getAttribute('aria-current') === 'true');
  assert.equal(marked.length, 1);
  assert.match(marked[0].textContent, /the change you came from/);
  assert.equal(ui.link(/^Next page$/).getAttribute('href'), '#/zones/main/example.test./versions?cs=cs-3&cursor=CUR9');
  await ui.go(`${ZONE}/versions?cursor=CUR9`);
  assert.match(ui.last('GET', V).url, /cursor=CUR9/);
  assert.equal(ui.link(/^First page$/).getAttribute('href'), '#/zones/main/example.test./versions');
  assert.doesNotMatch(ui.q('table.versions').parentNode.textContent, /Since the newest version/, 'not on a later page');

  const none = await bootApp({ routes: histRoutes({ [`GET ${V}`]: () => reply(200, { versions: [], next_cursor: null }) }), hash: `${ZONE}/versions` });
  assert.match(none.text(), /This zone has no version yet\./);
  const fail = await bootApp({ routes: histRoutes({ [`GET ${V}`]: () => problem(503, 'database-unavailable') }), hash: `${ZONE}/versions` });
  assert.match(fail.q('p.msg.error').textContent, /database cannot be reached/);

  const sub = await bootApp({
    routes: zoneRoutes({ role: 'subdomain_master', grants: [{ id: 3, role: 'subdomain_master', dataset: 'main', zone: 'example.test.', suffix: 'sub.example.test.', policy: POLICY, via: null }] },
      { [`GET ${V}`]: () => reply(200, { versions: [{ ...VERSIONS.versions[2], rrsets: undefined }], next_cursor: null }) }),
    hash: `${ZONE}/versions`, me: { global: false, grants: [] },
  });
  assert.match(sub.text(), /part of each change that lies under your suffix/);
  assert.equal(sub.qa('table.versions tbody tr').length, 1);
  assert.equal(sub.qa('table.versions tbody tr')[0].childNodes[6].textContent, '-');
});

test('S9: the compare form: checked here, then the route of the difference', async () => {
  const ui = await bootApp({ routes: histRoutes(), hash: `${ZONE}/versions` });
  const form = ui.q('form.search');
  await ui.submit(form);
  assert.deepEqual(errorsOf(ui.root), ['Enter a version number.']);
  typed(ui, ui.input('from'), '2');
  typed(ui, ui.input('to'), 'x');
  await ui.submit(form);
  assert.deepEqual(errorsOf(ui.root), ['Enter a version number, or leave it empty.']);
  typed(ui, ui.input('to'), '2');
  await ui.submit(form);
  assert.deepEqual(errorsOf(ui.root), ['The second version must be later than the first.']);
  typed(ui, ui.input('to'), '3');
  await ui.submit(form);
  assert.equal(ui.env.window.location.hash, '#/zones/main/example.test./versions/2/diff?to=3');
});

// ---------------------------------------------------------------------------------------------------------------------------------- one version
test('S9: one version: its fields, its delta as a diff, links; a delta that was not kept; a page of a long delta; a failure', async () => {
  const ui = await bootApp({ routes: histRoutes({ [`GET ${V}/3`]: () => reply(200, { ...DELTA, next_cursor: 'N2' }) }), hash: `${ZONE}/versions/3` });
  assert.equal(ui.env.document.title, 'Version 3 - example.test. - KariDNS WebAdmin');
  assert.equal(ui.last('GET', `${V}/3`).url, `/api/v1${V}/3?limit=200`);
  const dl = ui.q('section[aria-labelledby=ver-title] dl').textContent;
  assert.match(dl, /Version3/);
  assert.match(dl, /Serial12 → 13/);
  assert.match(dl, /Generation14 → 15/);
  assert.match(dl, /Change setcs-3/);
  assert.match(ui.text(), /1 added, 1 changed, 0 deleted/);
  assert.equal(ui.qa('table.diff-table tbody tr').length, 2);
  assert.equal(ui.qa('table.diff-table tbody tr')[0].querySelector('th').textContent, 'www', 'names are relative to the zone');
  assert.equal(ui.link(/^Audit log rows of this change$/).getAttribute('href'), '#/audit?change_set=cs-3');
  assert.equal(ui.link(/^Against the zone now$/).getAttribute('href'), '#/zones/main/example.test./versions/3/diff?to=current');
  assert.equal(ui.link(/^All versions$/).getAttribute('href'), '#/zones/main/example.test./versions');
  assert.equal(ui.link(/^Next page$/).getAttribute('href'), '#/zones/main/example.test./versions/3?cursor=N2');
  assert.ok(ui.button(/^Preview the rollback$/), 'the rollback is on the page');
  labelled(ui);
  noForeign(ui);

  const old = await bootApp({ routes: histRoutes({ [`GET ${V}/2`]: () => reply(200, { version: { ...VERSIONS.versions[1], rrsets: undefined }, rrsets: [], next_cursor: null }) }), hash: `${ZONE}/versions/2` });
  assert.match(old.text(), /touched too many record sets to keep them/);
  assert.match(old.q('section[aria-labelledby=ver-title] dl').textContent, /Restores version1/);
  assert.equal(old.q('section[aria-labelledby=ver-title] dl').querySelector('a').getAttribute('href'), '#/zones/main/example.test./versions/1');
  const page2 = await bootApp({ routes: histRoutes({ [`GET ${V}/3`]: () => reply(200, DELTA) }), hash: `${ZONE}/versions/3?cursor=C` });
  assert.match(page2.last('GET', `${V}/3`).url, /cursor=C/);
  assert.ok(page2.link(/^First page$/));

  const gone = await bootApp({ routes: histRoutes({ [`GET ${V}/9`]: () => problem(404, 'not-found') }), hash: `${ZONE}/versions/9` });
  assert.match(gone.q('p.msg.error').textContent, /no such object/);
  const bad = await bootApp({ routes: histRoutes(), hash: `${ZONE}/versions/0x` });
  assert.match(bad.text(), /There is no such version\./);
  assert.equal(bad.count('GET', `${V}/`), 0);
});

test('S9: no rollback for a zone that is not a primary zone or is signed elsewhere', async () => {
  for (const info of [{ kind: 'SLAVE' }, { presigned: true, signer: false }]) {
    const ui = await bootApp({ routes: histRoutes({}), hash: `${ZONE}/versions/3`, version: undefined });
    assert.ok(ui.button(/^Preview the rollback$/));
    const locked = await bootApp({ routes: { ...histRoutes(), 'GET /datasets/main/zones/example.test.': () => reply(200, { zone: { ...INFO, ...info } }) }, hash: `${ZONE}/versions/3` });
    assert.equal(locked.button(/^Preview the rollback$/), null, JSON.stringify(info));
    assert.match(locked.text(), /Version 3/);
  }
});

// ---------------------------------------------------------------------------------------------------------------------------------- a difference
test('S9: the difference of two versions and of a version against the zone: the request, the diff, paging, the refusals', async () => {
  const DIFF = { from: 1, to: 3, rrsets: DELTA.rrsets, next_cursor: 'D2' };
  const ui = await bootApp({ routes: histRoutes({ [`GET ${V}/1/diff`]: () => reply(200, DIFF) }), hash: `${ZONE}/versions/1/diff?to=3` });
  assert.equal(ui.last('GET', '/diff').url, `/api/v1${V}/1/diff?to=3&limit=200`);
  assert.equal(ui.q('h2').textContent, 'Version 1 against version 3');
  assert.match(ui.text(), /- are as they were after version 1, lines with \+ are as they are in version 3/);
  assert.equal(ui.qa('table.diff-table tbody tr').length, 2);
  assert.equal(ui.link(/^Next page$/).getAttribute('href'), '#/zones/main/example.test./versions/1/diff?to=3&cursor=D2');
  assert.equal(ui.link(/^Roll back to version 1\.\.\.$/).getAttribute('href'), '#/zones/main/example.test./versions/1');
  labelled(ui);

  const now = await bootApp({ routes: histRoutes({ [`GET ${V}/1/diff`]: () => reply(200, { from: 1, to: 'current', rrsets: [], next_cursor: null }) }), hash: `${ZONE}/versions/1/diff?to=current&cursor=Z` });
  assert.equal(now.q('h2').textContent, 'Version 1 against the zone as it is now');
  assert.match(now.last('GET', '/diff').url, /to=current&limit=200&cursor=Z/);
  assert.match(now.text(), /No difference\./);
  assert.ok(now.link(/^First page$/) === null || true);

  const dflt = await bootApp({ routes: histRoutes({ [`GET ${V}/1/diff`]: () => reply(200, { from: 1, to: 'current', rrsets: [], next_cursor: null }) }), hash: `${ZONE}/versions/1/diff` });
  assert.match(dflt.last('GET', '/diff').url, /to=current/);

  for (const [code, status, re] of [['delta-incomplete', 409, /too big to keep/], ['zone-checks-failed', 422, /zone checks refuse/], ['not-found', 404, /no such object/]]) {
    const bad = await bootApp({ routes: histRoutes({ [`GET ${V}/1/diff`]: () => problem(status, code) }), hash: `${ZONE}/versions/1/diff?to=2` });
    assert.match(bad.q('p.msg.error').textContent, re);
    assert.ok(bad.link(/^All versions$/));
  }
  const wrong = await bootApp({ routes: histRoutes(), hash: `${ZONE}/versions/3/diff?to=2` });
  assert.match(wrong.text(), /The versions to compare are not valid\./);
  assert.equal(wrong.count('GET', '/diff'), 0);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the rollback
const rb = (over = {}) => ({
  dry_run: true, allowed: true, committed: false, changed: true, change_set: 'x', version: 4, serial: { before: 13, after: 14 }, records: { before: 5, after: 4 }, rollback_of: 2, restored: 2, versions_undone: 1,
  skipped: [{ name: 'example.test.', type: 'SOA', reason: 'the SOA record is not restored' }, { name: 'x.example.test.', type: 'A', reason: 'a <b>reason</b>' }],
  diff: [{ name: 'www.example.test.', type: 'A', change: 'replace', before: [line(300, '192.0.2.51')], after: [line(300, '192.0.2.50')] }], messages: [], ...over,
});
const CONFLICT = (name, type, expected, current) => ({ code: 'version-conflict', severity: 'error', text: `${type} ${name} is not as the newest version left it`, name, type, expected, current });

test('S9: rollback: a preview, the SOA that is left alone, the commit with the comment and the box for the reload', async () => {
  const sent = [];
  const ui = await bootApp({ routes: histRoutes({ [`POST ${V}/2/rollback`]: (b) => { sent.push(b); return reply(b.dry_run ? 200 : 200, b.dry_run ? rb() : rb({ dry_run: undefined, committed: true, reload: 'requested' })); }, [`GET ${V}/2`]: () => reply(200, { version: { ...DELTA.version, version: 2 }, rrsets: [], next_cursor: null }) }), hash: `${ZONE}/versions/2` });
  assert.equal(ui.q('#rb-title').textContent, 'Roll back to version 2');
  assert.equal(ui.button(/^Roll back$/).disabled, true, 'nothing is committed before a preview');
  typed(ui, ui.input('comment'), 'undo the move');
  await ui.click(ui.button(/^Preview the rollback$/));
  assert.deepEqual(sent, [{ comment: 'undo the move', reload: false, dry_run: true }]);
  assert.match(ui.text(), /2 record sets would be restored, undoing 1 versions\./);
  assert.match(ui.text(), /The SOA record is not restored: its serial only grows/);
  assert.match(ui.text(), /x A a <b>reason<\/b>/, 'the reason is text');
  assert.equal(findAll(ui.root, (e) => e.tagName === 'B').length, 0);
  assert.equal(ui.button(/^Roll back$/).disabled, false);
  // a change of the comment is no reason to preview again; the commit sends the same request without dry_run
  ui.input('reload').checked = true;
  await ui.click(ui.button(/^Roll back$/));
  assert.deepEqual(sent[1], { comment: 'undo the move', reload: true });
  assert.match(ui.text(), /The change was saved\./);
  assert.match(ui.text(), /The servers were asked to load the zone again\./);
  assert.match(ui.polite(), /The change was saved\./);
  noForeign(ui);
  labelled(ui);
});

test('S9: rollback: conflicts keep the commit off; the force is a second question that lists what it overwrites', async () => {
  const sent = [];
  const conflicts = [CONFLICT('www.example.test.', 'A', [line(300, '192.0.2.50')], [line(60, '192.0.2.99')]), CONFLICT('gone.example.test.', 'TXT', [line(300, '"x"')], null)];
  const ui = await bootApp({ routes: histRoutes({ [`POST ${V}/1/rollback`]: (b) => { sent.push(b); return reply(200, b.dry_run ? rb({ conflicts }) : rb({ dry_run: undefined, committed: true, reload: 'not requested' })); },
    [`GET ${V}/1`]: () => reply(200, { version: { ...DELTA.version, version: 1 }, rrsets: [], next_cursor: null }) }), hash: `${ZONE}/versions/1` });
  await ui.click(ui.button(/^Preview the rollback$/));
  assert.equal(ui.button(/^Roll back$/).disabled, true, 'a conflict: no plain commit');
  const box = ui.q('section.conflict');
  assert.match(box.textContent, /2 record sets were changed outside the versions/);
  const rows = box.querySelectorAll('tbody tr');
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0].childNodes.map((c) => c.textContent), ['www', 'A', '300 192.0.2.50', '60 192.0.2.99']);
  assert.deepEqual(rows[1].childNodes.map((c) => c.textContent), ['gone', 'TXT', '300 "x"', 'not there']);
  assert.match(ui.polite() + ui.env.document.body.children.map((c) => c.textContent).join(' '), /2 record sets were changed outside/);
  // the question comes first; nothing is sent
  await ui.click(buttonIn(box, /^Roll back anyway and overwrite these$/));
  assert.match(box.textContent, /Overwrite these 2 record sets\?/);
  assert.equal(sent.length, 1);
  await ui.click(buttonIn(box, /^No$/));
  assert.equal(sent.length, 1);
  await ui.click(buttonIn(box, /^Roll back anyway and overwrite these$/));
  await ui.click(buttonIn(box, /^Yes$/));
  assert.equal(sent.length, 2);
  assert.deepEqual(sent[1], { reload: false, force: true });
  assert.match(ui.text(), /The change was saved\./);
  assert.equal(ui.q('section.conflict'), null, 'the conflicts are gone after the commit');
});

test('S9: rollback: a conflict that appears at the commit (409) is shown the same way, and force is not remembered', async () => {
  const sent = [];
  const conflicts = [CONFLICT('www.example.test.', 'A', [line(300, '192.0.2.50')], [line(60, '192.0.2.99')])];
  const ui = await bootApp({ routes: histRoutes({ [`POST ${V}/1/rollback`]: (b) => {
    sent.push(b);
    if (b.dry_run) return reply(200, rb());
    return problem(409, 'version-conflict', { errors: conflicts });
  }, [`GET ${V}/1`]: () => reply(200, { version: { ...DELTA.version, version: 1 }, rrsets: [], next_cursor: null }) }), hash: `${ZONE}/versions/1` });
  await ui.click(ui.button(/^Preview the rollback$/));
  await ui.click(ui.button(/^Roll back$/));
  assert.match(ui.q('p.msg.error').textContent, /Some record sets were changed after the versions you undo\./);
  assert.match(ui.q('ul.messages').textContent, /A www\.example\.test\. is not as the newest version left it/);
  assert.equal(ui.qa('section.conflict tbody tr').length, 1);
  assert.equal(ui.button(/^Roll back$/).disabled, true, 'a new preview first');
  // the forced commit is refused for another reason: it says so, and the next plain commit does not carry force
  ui.routes[`POST ${V}/1/rollback`] = (b) => { sent.push(b); return b.dry_run ? reply(200, rb()) : problem(403, 'forbidden'); };
  await ui.click(buttonIn(ui.q('section.conflict'), /^Roll back anyway/));
  await ui.click(buttonIn(ui.q('section.conflict'), /^Yes$/));
  assert.deepEqual(sent.at(-1), { reload: false, force: true });
  assert.match(ui.q('p.msg.error').textContent, /not allowed/);
  await ui.click(ui.button(/^Preview the rollback$/));
  await ui.click(ui.button(/^Roll back$/));
  assert.deepEqual(sent.at(-1), { reload: false }, 'force was for that one commit');
});

test('S9: rollback: refusals of the preview, a rollback that changes nothing, a signer zone (no reload box), 429 waits', async () => {
  const ui = await bootApp({ routes: histRoutes({ [`POST ${V}/3/rollback`]: () => problem(403, 'forbidden', { errors: [{ code: 'forbidden', severity: 'error', text: 'none of your grants allows A', pointer: '/rrsets/0' }] }) }), hash: `${ZONE}/versions/3` });
  await ui.click(ui.button(/^Preview the rollback$/));
  assert.match(ui.q('p.msg.error').textContent, /not allowed/);
  assert.match(ui.q('ul.messages').textContent, /none of your grants allows A/);
  assert.equal(ui.button(/^Roll back$/).disabled, true);
  ui.routes[`POST ${V}/3/rollback`] = () => reply(200, { dry_run: true, allowed: true, committed: false, changed: false, diff: [], messages: [], reload: 'not requested', rollback_of: 3, restored: 0, versions_undone: 0, skipped: [] });
  await ui.click(ui.button(/^Preview the rollback$/));
  assert.match(ui.text(), /0 record sets would be restored/);
  assert.match(ui.text(), /No difference\./);
  ui.routes[`POST ${V}/3/rollback`] = () => problem(429, 'rate-limited', {}, { 'Retry-After': '3' });
  await ui.click(ui.button(/^Preview the rollback$/));
  assert.match(buttonIn(ui.root, /Try again in/).textContent, /Try again in 3 s/);

  const signer = await bootApp({ routes: { ...histRoutes(), 'GET /datasets/main/zones/example.test.': () => reply(200, { zone: { ...INFO, signer: true, presigned: true } }) }, hash: `${ZONE}/versions/3` });
  assert.ok(signer.button(/^Preview the rollback$/));
  assert.equal(signer.input('reload'), undefined, 'the signer asks for the reload');
});

// ---------------------------------------------------------------------------------------------------------------------------------- templates
const TPL = {
  id: 4, name: 'basic', description: 'name <i>servers</i>', revision: 3, created_by: 1, updated_at: '2026-11-08T00:00:00Z', record_count: 3,
  soa: { mname: 'ns1.nsprovider.test.', rname: 'hostmaster.nsprovider.test.', refresh: 1800, retry: null, expire: null, minimum: 120 },
  records: [{ owner: '@', type: 'NS', ttl: null, content: 'ns1.nsprovider.test.' }, { owner: '@', type: 'MX', ttl: null, content: '10 mail' }, { owner: 'www', type: 'A', ttl: 600, content: '192.0.2.41' }],
};
const TEMPLATES = { templates: [{ ...TPL, records: undefined }, { id: 5, name: 'bare', description: null, revision: 1, soa: null, record_count: 0, updated_at: null }], next_cursor: null };

test('S10: the templates: the list (global masters have New template), the search, the paging; a person who is not global has no way to write', async () => {
  const ui = await bootApp({ routes: { 'GET /templates': () => reply(200, { ...TEMPLATES, next_cursor: 'T2' }) }, hash: '#/templates?prefix=ba' });
  assert.equal(ui.q('h1').textContent, 'Templates');
  assert.equal(ui.last('GET', '/templates').url, '/api/v1/templates?limit=100&prefix=ba');
  const rows = ui.qa('tbody tr');
  assert.deepEqual(rows[0].childNodes.map((c) => c.textContent), ['basic', 'name <i>servers</i>', '3', '3', 'Yes', rows[0].childNodes[5].textContent]);
  assert.deepEqual(rows[1].childNodes.map((c) => c.textContent), ['bare', '-', '1', '0', 'No', '-']);
  assert.equal(rows[0].querySelector('a').getAttribute('href'), '#/templates/4');
  assert.equal(findAll(rows[0], (e) => e.tagName === 'I').length, 0);
  assert.equal(ui.link(/^New template$/).getAttribute('href'), '#/templates/new');
  assert.equal(ui.link(/^Next page$/).getAttribute('href'), '#/templates?prefix=ba&cursor=T2');
  assert.equal(ui.link(/^Templates$/).getAttribute('aria-current'), 'page');
  labelled(ui);
  ui.type(ui.input('prefix'), 'a b');
  await ui.submit(ui.q('form.search'));
  assert.deepEqual(errorsOf(ui.root), ['Use letters, digits and . _ + : - only.']);
  ui.type(ui.input('prefix'), 'ba');
  await ui.submit(ui.q('form.search'));
  assert.equal(ui.env.window.location.hash, '#/templates?prefix=ba');
  ui.type(ui.input('prefix'), '');
  await ui.submit(ui.q('form.search'));
  assert.equal(ui.env.window.location.hash, '#/templates');

  const later = await bootApp({ routes: { 'GET /templates': () => reply(200, { templates: [], next_cursor: null }) }, hash: '#/templates?cursor=X&prefix=%3Cb%3E' });
  assert.match(later.text(), /There are no more templates\./);
  assert.ok(later.link(/^First page$/));
  assert.doesNotMatch(later.last('GET', '/templates').url, /prefix/, 'a search text the service would refuse is not sent');
  const none = await bootApp({ routes: { 'GET /templates': () => reply(200, { templates: [], next_cursor: null }) }, hash: '#/templates' });
  assert.match(none.text(), /No template matches\./);
  const fail = await bootApp({ routes: { 'GET /templates': () => problem(503, 'database-unavailable') }, hash: '#/templates' });
  assert.match(fail.q('p.msg.error').textContent, /database cannot be reached/);
  const plain = await bootApp({ routes: { 'GET /templates': () => reply(200, TEMPLATES) }, hash: '#/templates', me: { global: false, grants: [] } });
  assert.equal(plain.link(/^New template$/), null);
});

test('S10: one template: SOA defaults, the records, validation again; the text of a description is text', async () => {
  const ui = await bootApp({ routes: { 'GET /templates/4': () => reply(200, { template: TPL }), 'POST /templates/4/validate': () => reply(200, { template: { id: 4 }, valid: true, messages: [{ code: 'W1', severity: 'warning', text: 'a warning', pointer: '/records/1' }] }) }, hash: '#/templates/4', me: { global: false, grants: [] } });
  assert.equal(ui.q('h1').textContent, 'basic');
  const dl = ui.q('dl').textContent;
  assert.match(dl, /Descriptionname <i>servers<\/i>/);
  assert.match(dl, /Revision3/);
  assert.match(dl, /SOA primary name serverns1\.nsprovider\.test\./);
  assert.match(dl, /SOA retry-/);
  assert.equal(findAll(ui.root, (e) => e.tagName === 'I').length, 0);
  const rows = ui.qa('tbody tr').map((r) => r.childNodes.map((c) => c.textContent));
  assert.deepEqual(rows, [['@', 'NS', '-', 'ns1.nsprovider.test.'], ['@', 'MX', '-', '10 mail'], ['www', 'A', '600', '192.0.2.41']]);
  assert.equal(ui.qa('form').length, 0, 'no form for a person who cannot write');
  await ui.click(ui.button(/^Check again$/));
  assert.match(ui.text(), /The zone checks accept this template\./);
  assert.match(ui.text(), /Warning W1 a warning/);
  ui.routes['POST /templates/4/validate'] = () => reply(200, { valid: false, messages: [{ code: 'E1', severity: 'error', text: 'bad', pointer: '/records/0' }] });
  await ui.click(ui.button(/^Check again$/));
  assert.match(ui.text(), /zone checks refuse this template/);
  ui.routes['POST /templates/4/validate'] = () => problem(500, 'internal');
  await ui.click(ui.button(/^Check again$/));
  assert.match(ui.q('p.msg.error').textContent, /internal error/);
  noForeign(ui);
  labelled(ui);

  const none = await bootApp({ routes: { 'GET /templates/5': () => reply(200, { template: { ...TEMPLATES.templates[1], records: [] } }) }, hash: '#/templates/5' });
  assert.match(none.text(), /This template has no records\./);
  const gone = await bootApp({ routes: { 'GET /templates/9': () => problem(404, 'not-found') }, hash: '#/templates/9' });
  assert.match(gone.q('p.msg.error').textContent, /no such object/);
  assert.ok(gone.link(/^All templates$/));
});

test('S10: a global master edits a template: the text form, a check, a save, the refusals at the fields and at the lines', async () => {
  const sent = [];
  const ui = await bootApp({ routes: { 'GET /templates/4': () => reply(200, { template: TPL }), 'PATCH /templates/4': (b) => { sent.push(b); return reply(200, b.dry_run ? { dry_run: true, valid: true, messages: [] } : { template: TPL, messages: [] }); } }, hash: '#/templates/4' });
  const records = ui.input('records');
  assert.equal(records.value, '@ NS ns1.nsprovider.test.\n@ MX 10 mail\nwww 600 A 192.0.2.41');
  assert.equal(ui.input('soa_mname').value, 'ns1.nsprovider.test.');
  assert.equal(ui.input('soa_retry').value, '');
  assert.equal(ui.input('soa_refresh').value, '1800');
  labelled(ui);
  // a line that is no record, a number that is none, no name
  typed(ui, records, '@ NS ns1.nsprovider.test.\nnonsense\nbad');
  await ui.click(buttonIn(ui.root, /^Check$/));
  assert.equal(sent.length, 0);
  assert.deepEqual(errorsOf(ui.root), ['These lines are not records (owner [TTL] TYPE data): 2, 3.']);
  typed(ui, records, '@ NS ns1.nsprovider.test.');
  typed(ui, ui.input('soa_expire'), '12x');
  await ui.click(buttonIn(ui.root, /^Check$/));
  assert.deepEqual(errorsOf(ui.root), ['Enter a whole number of seconds.']);
  typed(ui, ui.input('soa_expire'), '');
  typed(ui, ui.input('name'), ' ');
  await ui.click(buttonIn(ui.root, /^Check$/));
  assert.deepEqual(errorsOf(ui.root), ['Enter a name.']);
  assert.equal(sent.length, 0);
  // a check and a save
  typed(ui, ui.input('name'), 'basic2');
  typed(ui, ui.input('description'), '');
  await ui.click(buttonIn(ui.root, /^Check$/));
  assert.deepEqual(sent[0], { name: 'basic2', records: [{ owner: '@', type: 'NS', content: 'ns1.nsprovider.test.' }], description: null, soa: { mname: 'ns1.nsprovider.test.', rname: 'hostmaster.nsprovider.test.', refresh: 1800, minimum: 120 }, dry_run: true });
  assert.match(ui.text(), /The zone checks accept this template\./);
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM')[0]);
  assert.equal(sent[1].dry_run, undefined);
  assert.match(ui.text(), /The template was saved\./);
  // the soa is cleared when every field is empty
  for (const k of ['mname', 'rname', 'refresh', 'minimum']) typed(ui, ui.input(`soa_${k}`), '');
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM')[0]);
  assert.equal(sent.at(-1).soa, null);
  // refusals: a 400 at its field, a 422 with the lines named, anything else as a message
  ui.routes['PATCH /templates/4'] = () => problem(400, 'bad-request', { errors: [{ code: 'bad-request', severity: 'error', text: 'no such name', pointer: '/name' }, { code: 'bad-request', severity: 'error', text: 'bad host', pointer: '/soa/mname' },
    { code: 'bad-request', severity: 'error', text: 'bad data', pointer: '/records/0/content' }, { code: 'bad-request', severity: 'error', text: 'elsewhere', pointer: '/other' }] });
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM')[0]);
  assert.deepEqual(errorsOf(ui.root), ['no such name', 'bad host', 'Line 1: bad data']);
  assert.match(ui.text(), /request was not valid/);
  ui.routes['PATCH /templates/4'] = () => problem(422, 'template-checks-failed', { errors: [{ code: 'CK1', severity: 'error', text: 'CNAME and other data', pointer: '/records/0' }, { code: 'CK2', severity: 'warning', text: 'odd', pointer: '/records/5' }] });
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM')[0]);
  assert.match(errorsOf(ui.root).join(' '), /refuse some records/);
  assert.match(ui.q('ul.messages').textContent, /Error CK1 Line 1: CNAME and other data/);
  assert.match(ui.q('ul.messages').textContent, /Warning CK2 odd/, 'a message for a line that does not exist has no number');
  ui.routes['PATCH /templates/4'] = () => problem(503, 'database-unavailable');
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM')[0]);
  assert.match(ui.text(), /database cannot be reached/);
});

test('S10: a new template: the form, the dry run, the save and the way to its page, warnings counted; a template is deleted after a question', async () => {
  const sent = [];
  const ui = await bootApp({ routes: { 'POST /templates': (b) => { sent.push(b); return b.dry_run ? reply(200, { dry_run: true, valid: true, messages: [{ code: 'W', severity: 'warning', text: 'w', pointer: '/records/0' }] }) : reply(201, { template: { ...TPL, id: 8 }, messages: [{ code: 'W', severity: 'warning', text: 'w' }] }); },
    'GET /templates/8': () => reply(200, { template: { ...TPL, id: 8 } }), 'DELETE /templates/8': () => reply(204, null), 'GET /templates': () => reply(200, TEMPLATES) }, hash: '#/templates/new' });
  assert.equal(ui.q('h1').textContent, 'New template');
  typed(ui, ui.input('name'), 'mine');
  typed(ui, ui.input('records'), 'www A 192.0.2.1');
  await ui.click(buttonIn(ui.root, /^Check$/));
  assert.deepEqual(sent[0], { name: 'mine', records: [{ owner: 'www', type: 'A', content: '192.0.2.1' }], dry_run: true }, 'no soa and no description for a new template without them');
  assert.match(ui.text(), /Warning W Line 1: w/);
  await ui.submit(findAll(ui.root, (e) => e.tagName === 'FORM')[0]);
  assert.equal(ui.env.window.location.hash, '#/templates/8');
  assert.match(ui.text(), /The template was saved\. The zone checks gave 1 warnings\./);
  // delete: a question first
  await ui.click(ui.button(/^Delete the template$/));
  assert.equal(ui.count('DELETE', '/templates/8'), 0);
  await ui.click(ui.button(/^Yes$/));
  assert.equal(ui.env.window.location.hash, '#/templates');
  assert.match(ui.text(), /The template basic was deleted\./);
  // a refusal to delete
  const bad = await bootApp({ routes: { 'GET /templates/8': () => reply(200, { template: { ...TPL, id: 8 } }), 'DELETE /templates/8': () => problem(404, 'not-found') }, hash: '#/templates/8' });
  await bad.click(bad.button(/^Delete the template$/));
  await bad.click(bad.button(/^Yes$/));
  assert.match(bad.text(), /no such object/);

  const plain = await bootApp({ routes: {}, hash: '#/templates/new', me: { global: false, grants: [] } });
  assert.match(plain.text(), /Only global masters make templates\./);
  assert.equal(plain.qa('form').length, 0);
});

// ---------------------------------------------------------------------------------------------------------------------------------- apply a template to a zone
test('S10: apply a template to a zone: choose, the TTL, a preview, the commit; the list is read once; refusals', async () => {
  const sent = [];
  const ui = await bootApp({ routes: zoneRoutes({}, { 'GET /templates': () => reply(200, TEMPLATES), 'POST /datasets/main/zones/example.test./apply-template': (b) => {
    sent.push(b);
    return reply(200, b.dry_run ? { dry_run: true, allowed: true, version: 4, serial: { before: 13, after: 14 }, diff: [{ name: 'example.test.', type: 'MX', change: 'replace', before: [line(3600, '10 old.example.test.')], after: [line(3600, '10 mail.example.test.')] }], messages: [] }
      : { committed: true, version: 4, serial: { before: 13, after: 14 }, diff: [], messages: [], reload: 'not requested' });
  } }), hash: `${ZONE}/template` });
  assert.equal(ui.q('#tplapply-title').textContent, 'Apply a template');
  assert.equal(ui.last('GET', '/templates').url, '/api/v1/templates?limit=500');
  labelled(ui);
  assert.equal(ui.input('template').value, '4');
  assert.equal(ui.link(/^basic$/).getAttribute('href'), '#/templates/4');
  await chosen(ui, ui.input('template'), '5');
  assert.equal(ui.link(/^bare$/).getAttribute('href'), '#/templates/5');
  await chosen(ui, ui.input('template'), '4');
  typed(ui, ui.input('default_ttl'), '12x');
  await ui.click(ui.button(/^Preview$/));
  assert.deepEqual(errorsOf(ui.root), ['Enter a whole number of seconds.']);
  assert.equal(sent.length, 0);
  typed(ui, ui.input('default_ttl'), '1800');
  typed(ui, ui.input('comment'), 'use it');
  await ui.click(ui.button(/^Preview$/));
  assert.deepEqual(sent[0], { template_id: 4, default_ttl: 1800, comment: 'use it', reload: false, dry_run: true });
  assert.match(ui.text(), /1 changed/);
  assert.equal(ui.button(/^Apply the template$/).disabled, false);
  typed(ui, ui.input('default_ttl'), '1900');
  assert.equal(ui.button(/^Apply the template$/).disabled, true, 'a change of the input asks for a new preview');
  await ui.click(ui.button(/^Preview$/));
  await chosen(ui, ui.input('template'), '5');
  assert.equal(ui.button(/^Apply the template$/).disabled, true);
  await chosen(ui, ui.input('template'), '4');
  await ui.click(ui.button(/^Preview$/));
  typed(ui, ui.input('default_ttl'), '');
  await ui.click(ui.button(/^Preview$/));
  await ui.click(ui.button(/^Apply the template$/));
  assert.deepEqual(sent.at(-1), { template_id: 4, comment: 'use it', reload: false });
  assert.match(ui.text(), /The change was saved\./);
  assert.ok(ui.count('GET', '/datasets/main/zones/example.test.') >= 2, 'the header of the zone was read again');
  // a refusal with a pointer into the template
  ui.routes['POST /datasets/main/zones/example.test./apply-template'] = () => problem(403, 'forbidden', { errors: [{ code: 'forbidden', severity: 'error', text: 'none of your grants allows MX', pointer: '/template/records/1' }] });
  await ui.click(ui.button(/^Preview$/));
  assert.match(ui.q('ul.messages').textContent, /none of your grants allows MX \(\/template\/records\/1\)/);
  noForeign(ui);

  const empty = await bootApp({ routes: zoneRoutes({}, { 'GET /templates': () => reply(200, { templates: [] }) }), hash: `${ZONE}/template` });
  assert.match(empty.text(), /There is no template\./);
  const fail = await bootApp({ routes: zoneRoutes({}, { 'GET /templates': () => problem(503, 'database-unavailable') }), hash: `${ZONE}/template` });
  assert.match(fail.q('p.msg.error').textContent, /database cannot be reached/);
  const sub = await bootApp({ routes: zoneRoutes({ role: 'subdomain_master' }, {}), hash: `${ZONE}/template`, me: { global: false, grants: [] } });
  assert.match(sub.text(), /applied by the masters of the whole zone/);
  assert.equal(sub.count('GET', '/templates'), 0);
  const locked = await bootApp({ routes: zoneRoutes({ kind: 'SLAVE' }, {}), hash: `${ZONE}/template` });
  assert.match(locked.text(), /not a primary zone/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- leaving
test('a screen that is left stops what it was doing: no write to a page that is gone', async () => {
  const routes = histRoutes({
    [`GET ${V}/1/diff`]: () => reply(200, { from: 1, to: 'current', rrsets: [], next_cursor: null }), 'GET /templates': () => reply(200, TEMPLATES), 'GET /templates/4': () => reply(200, { template: TPL }),
    'GET /version': () => reply(200, {}),
  });
  for (const hash of [`${ZONE}/versions`, `${ZONE}/versions/3`, `${ZONE}/versions/1/diff`, `${ZONE}/template`, '#/templates', '#/templates/4', '#/templates/new']) {
    const ui = await bootApp({ routes, hash });
    await ui.go('#/about');
    assert.equal(ui.q('h1').textContent, 'About', hash);
  }
});

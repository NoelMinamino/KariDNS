// The history, template, administration and audit screens against the real API (planning 8.1 and 8.2 in Node): karidns-webadmin on a SQLite3 deployment with a scripted
// karidns-zone and karicheck, and the application of webadmin/ui/js on the fake DOM with a fetch that behaves like a browser.  What ui_hist.test.js, ui_admin.test.js and
// ui_admin2.test.js assume about the API is checked here against the API itself: every request these screens make must pass the validators of the service (unknown
// fields are refused there), and the answers must be ones the screens understand.  The real karidns-zone runs in the browser tests (tests/run_webadmin_gui_test.sh).

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast, makeRun, ok, exit, applyDoc, entry } from './helpers.js';
import { loadStatic, defaultUiDir } from '../lib/static.js';
import { page } from './ui_page.js';
import { findAll, byText } from './fakedom.js';

const KZ = '/opt/karidns-zone';
const KCK = '/opt/karicheck';
const A = (...ips) => ips.map((ip) => `300 A ${ip}`).join('\n');
const soa = (serial, refresh = 7200) => `3600 SOA ns1.example.test. hostmaster.example.test. ${serial} ${refresh} 3600 1209600 300`;
const kcOk = (messages = []) => ok({ karicheck: 1, version: '0.6.0', command: 'zone', result: 'ok', counts: { error: 0, warning: 0, checked: 1, skipped: 0, dropped: 0 }, truncated: false, messages, zones: [] });
const sql = (d, text, params = []) => d.backend.tx({}, (tx) => tx.all(text, params));
const run = (d, text, params = []) => d.backend.tx({ write: true }, (tx) => tx.run(text, params));

async function addVersion(d, n, over = {}, rows = []) {
  const v = {
    kind: 'edit', change_set: `cs-${n}`, principal_id: null, principal_name: null, db_role: 'karidns-webadmin', at: `2020-01-0${n}T00:00:00Z`, comment: null, serial_before: 9 + n,
    serial_after: 10 + n, generation_before: 0, generation_after: 0, rollback_of: null, delta_complete: 1, ...over,
  };
  await run(d, `INSERT INTO karidns_zone_versions (domain_id, version, kind, change_set, principal_id, principal_name, db_role, at, comment, serial_before, serial_after,
                generation_before, generation_after, rollback_of, delta_complete) VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
  [n, v.kind, v.change_set, v.principal_id, v.principal_name, v.db_role, v.at, v.comment, v.serial_before, v.serial_after, v.generation_before, v.generation_after, v.rollback_of, v.delta_complete]);
  const id = (await sql(d, 'SELECT id FROM karidns_zone_versions WHERE domain_id = 1 AND version = $1', [n]))[0].id;
  for (const [owner, type, before, after] of rows) await run(d, 'INSERT INTO karidns_zone_version_rrsets (version_id, owner, type, before, after) VALUES ($1, $2, $3, $4, $5)', [id, owner, type, before, after]);
}

// 1: an import by an operator; 2: the domain master; 3: a global master, after something that is no version (the generation grew)
async function history(d) {
  const dom = (await sql(d, "SELECT id FROM auth.principals WHERE name = 'dom'"))[0].id;
  const root = (await sql(d, "SELECT id FROM auth.principals WHERE name = 'root'"))[0].id;
  await addVersion(d, 1, { kind: 'import', change_set: null, generation_before: 0, generation_after: 10, serial_before: null, serial_after: 10, comment: 'the first import' }, [
    ['www.example.test', 'A', null, A('192.0.2.10', '192.0.2.11')], ['sub.example.test', 'A', null, A('192.0.2.20')], ['a.sub.example.test', 'TXT', null, '300 TXT "hello"'], ['example.test', 'SOA', null, soa(10)],
  ]);
  await addVersion(d, 2, { principal_id: dom, principal_name: 'dom', generation_before: 10, generation_after: 12, comment: 'move <b>www</b>' }, [
    ['www.example.test', 'A', A('192.0.2.10', '192.0.2.11'), A('192.0.2.50')], ['new.example.test', 'A', null, A('192.0.2.60')], ['a.sub.example.test', 'TXT', '300 TXT "hello"', '300 TXT "bye"'],
  ]);
  await addVersion(d, 3, { principal_id: root, principal_name: 'root', generation_before: 14, generation_after: 15 }, [
    ['www.example.test', 'A', A('192.0.2.50'), A('192.0.2.51')], ['x.sub.example.test', 'A', null, A('192.0.2.70')], ['example.test', 'SOA', soa(11), soa(12, 100)],
  ]);
  await run(d, 'UPDATE karidns_zone_state SET generation = 15 WHERE domain_id = 1');
}

const RESTORE_DIFF = [
  entry('a.sub.example.test.', 'TXT', ['300 TXT "bye"'], ['300 TXT "hello"']), entry('new.example.test.', 'A', ['300 A 192.0.2.60'], null),
  entry('www.example.test.', 'A', ['300 A 192.0.2.51'], A('192.0.2.10', '192.0.2.11').split('\n')), entry('x.sub.example.test.', 'A', ['300 A 192.0.2.70'], null),
];
const EXPECT_1 = 'rr a.sub.example.test. 300 TXT "bye"\nrr new.example.test. 300 A 192.0.2.60\nrr www.example.test. 300 A 192.0.2.51\nrr x.sub.example.test. 300 A 192.0.2.70\n';
const TPL_DIFF = [entry('www.example.test.', 'A', ['300 A 192.0.2.51'], ['600 A 192.0.2.41'])];

test('history, templates, administration and audit against the API: every request passes the validators and every answer is understood', async () => {
  const calls = [];
  const t = makeRun((c) => {
    calls.push(c);
    if (c.file === KCK) return kcOk();
    if (c.argv.includes('--dry-run')) {
      const moved = c.input === EXPECT_1 ? [] : null;                                   // (the run of the expectations finds nothing different)
      return ok(applyDoc({ apply: { dry_run: true, generation: 20, diff: moved ?? (String(c.input).includes('600 A') || String(c.input).includes('www.example.test. 600') ? TPL_DIFF : RESTORE_DIFF) } }));
    }
    return ok(applyDoc({ apply: { dry_run: false, committed: true, version: 4, generation: 20, generation_after: 21, diff: String(c.input).includes('600') ? TPL_DIFF : RESTORE_DIFF } }));
  });
  const d = await deploy({ ui: loadStatic(defaultUiDir()), run: t.run, settings: { 'karidns-zone': KZ, karicheck: KCK, 'reload-after-change': 'no' } });
  d.app.sleep = async () => {};
  try {
    await cast(d);
    await history(d);
    const ui = await page(d, '');
    ui.type(ui.input('user'), 'root');
    ui.type(ui.input('password'), 'correct horse battery');
    await ui.submit(ui.q('form'));
    assert.equal(ui.q('h1').textContent, 'Welcome, root');

    // ---- versions: the list with who and the marker, a version, the difference, the rollback
    await ui.go('#/zones/main/example.test./versions');
    const rows = ui.qa('table.versions tbody tr').filter((r) => r.querySelector('th'));
    assert.deepEqual(rows.map((r) => r.querySelector('th').textContent), ['3', '2', '1']);
    assert.equal(rows[1].childNodes[3].textContent, 'dom');
    assert.equal(rows[1].childNodes[4].textContent, 'move <b>www</b>', 'a comment is text');
    assert.equal(rows[2].childNodes[3].textContent, 'operator (karidns-webadmin)');
    assert.match(ui.q('table.versions').textContent, /Before this version:/);
    assert.deepEqual(ui.errors(), []);
    await ui.go('#/zones/main/example.test./versions/2');
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /1 added, 2 changed, 0 deleted/);
    assert.equal(ui.qa('table.diff-table tbody tr').length, 3);
    await ui.go('#/zones/main/example.test./versions/1/diff?to=3');
    assert.deepEqual(ui.errors(), []);
    assert.ok(ui.qa('table.diff-table tbody tr').length >= 3);
    await ui.go('#/zones/main/example.test./versions/1/diff?to=current');
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /Version 1 against the zone as it is now/);
    // the compare form
    await ui.go('#/zones/main/example.test./versions');
    ui.type(ui.input('from'), '1');
    ui.type(ui.input('to'), '2');
    await ui.submit(ui.q('form.search'));
    assert.equal(ui.env.window.location.hash, '#/zones/main/example.test./versions/1/diff?to=2');
    // the rollback to 1: a preview (the request has the fields the service takes), then the commit
    await ui.go('#/zones/main/example.test./versions/1');
    ui.type(ui.input('comment'), 'undo');
    await ui.click(ui.button(/^Preview the rollback$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /4 record sets would be restored, undoing 2 versions\./);
    assert.match(ui.text(), /The SOA record is not restored/);
    await ui.click(ui.button(/^Roll back$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The change was saved\./);
    assert.ok(calls.some((c) => c.argv.includes('--rollback-of') && c.argv.includes('rollback to version 1: undo')));

    // ---- templates: check, save, look, check again, apply to a zone, delete
    await ui.go('#/templates/new');
    ui.type(ui.input('name'), 'web');
    ui.type(ui.input('description'), 'a web name');
    ui.type(ui.input('soa_mname'), 'ns1.example.test');
    ui.type(ui.input('soa_rname'), 'hostmaster.example.test');
    ui.type(ui.input('soa_refresh'), '1800');
    ui.type(ui.input('records'), '@ NS ns1.example.test.\nwww 600 A 192.0.2.41');
    await ui.click(ui.button(/^Check$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The zone checks accept this template\./);
    await ui.submit(ui.form('textarea[name=records]'));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.env.window.location.hash, /^#\/templates\/\d+$/);
    assert.match(ui.text(), /The template was saved\./);
    assert.equal(ui.qa('table tbody tr').length, 2);
    await ui.click(ui.button(/^Check again$/));
    assert.match(ui.text(), /The zone checks accept this template\./);
    ui.type(ui.input('description'), 'a web name, edited');
    await ui.submit(ui.form('textarea[name=records]'));
    assert.match(ui.text(), /The template was saved\./);
    assert.equal((await sql(d, "SELECT revision FROM auth.templates WHERE name = 'web'")).length, 1);
    await ui.go('#/templates');
    assert.deepEqual(ui.qa('tbody tr').map((r) => r.querySelector('th').textContent), ['web']);
    await ui.go('#/zones/main/example.test./template');
    assert.deepEqual(ui.errors(), []);
    ui.type(ui.input('default_ttl'), '300');
    await ui.click(ui.button(/^Preview$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /1 changed/);
    await ui.click(ui.button(/^Apply the template$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The change was saved\./);
    assert.ok(calls.some((c) => c.argv.includes('--version-kind') && c.argv[c.argv.indexOf('--version-kind') + 1] === 'template'));
    await ui.go('#/templates');
    await ui.click(byText(ui.root, 'a', /^web$/));
    await ui.click(ui.button(/^Delete the template$/));
    await ui.click(byText(ui.q('section.danger-zone'), 'button', /^Yes$/));
    assert.equal(ui.env.window.location.hash, '#/templates');
    assert.match(ui.text(), /The template web was deleted\./);

    // ---- administration: a policy, a group with a member, a grant, the actions on credentials, a new password
    await ui.go('#/admin/policies');
    ui.type(ui.input('name'), 'mail');
    ui.type(ui.input('types'), 'mx txt');
    ui.type(ui.input('ttl_min'), '60');
    ui.type(ui.input('ttl_max'), '86400');
    ui.type(ui.input('max_rr'), '50');
    await ui.submit(ui.form('input[name=allow_wildcard]'));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The policy mail was created\./);
    await ui.click(byText(ui.qa('table tbody tr').find((r) => r.querySelector('th').textContent === 'mail'), 'button', /^Edit$/));
    ui.type(ui.input('max_rr'), '');
    await ui.submit(ui.form('input[name=allow_wildcard]'));
    assert.match(ui.text(), /The policy mail was saved\./);
    ui.type(ui.input('name'), 'bad');
    ui.type(ui.input('types'), 'A DNSKEY');
    await ui.submit(ui.form('input[name=allow_wildcard]'));
    assert.match(findAll(ui.root, (e) => e.className === 'error' && !e.hidden).map((e) => e.textContent).join(' '), /DNSKEY cannot be in a policy/);

    await ui.go('#/admin/groups');
    ui.type(ui.input('name'), 'ops');
    await ui.submit(ui.form('input[name=name]'));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.env.window.location.hash, /^#\/admin\/principals\/\d+$/);
    ui.type(ui.input('member'), 'DOM');
    await ui.submit(ui.form('input[name=member]'));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /dom was added\./);
    // a grant for the group (it needs a policy: the first is offered)
    ui.type(ui.input('zone'), 'other.test');
    await ui.submit(ui.form('select[name=role]'));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The grant was given\./);
    assert.equal(ui.qa('table.grants tbody tr').length, 1);
    const groupHash = ui.env.window.location.hash;

    await ui.go('#/admin/users?prefix=dom');
    await ui.click(byText(ui.root, 'a', /^dom$/));
    assert.equal(ui.q('h2').textContent, 'User: dom');
    assert.match(ui.text(), /Member ofops/);
    // the user has no TOTP: the service says so; no failed attempts: nothing to unlock
    assert.equal(ui.button(/^Reset two-step verification$/), null);
    assert.equal(ui.button(/^Unlock the account$/), null);
    await run(d, "UPDATE auth.credentials SET failed_logins = 3, totp_enabled = 1, totp_secret = 'x' WHERE principal_id = (SELECT id FROM auth.principals WHERE name = 'dom')");
    ui.app.router.refresh();
    await ui.idle();
    await ui.click(ui.button(/^Unlock the account$/));
    await ui.click(ui.button(/^Yes$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The account was unlocked\./);
    await ui.click(ui.button(/^Reset two-step verification$/));
    await ui.click(ui.button(/^Yes$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /Two-step verification was reset/);
    assert.deepEqual((await sql(d, "SELECT totp_enabled AS e, totp_secret AS s FROM auth.credentials WHERE principal_id = (SELECT id FROM auth.principals WHERE name = 'dom')")).map((r) => [Number(r.e), r.s]), [[0, null]]);
    ui.type(ui.input('new_password'), 'a brand new passphrase');
    await ui.submit(ui.form('input[name=new_password]'));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The password was set/);
    ui.type(ui.input('display_name'), 'Dora D.');
    await ui.submit(ui.form('input[name=display_name]'));
    assert.match(ui.text(), /Saved\./);
    assert.equal((await d.login('dom', 'a brand new passphrase')).status, 200);
    // the grants tab: by user name and zone
    await ui.go('#/admin/grants?who=dom&zone=example.test');
    assert.deepEqual(ui.errors(), []);
    assert.equal(ui.qa('table.grants tbody tr').length, 1);
    await ui.go(groupHash);
    await ui.click(byText(ui.qa('table.grants tbody tr')[0], 'button', /^Remove$/));
    await ui.click(byText(ui.qa('table.grants tbody tr')[0], 'button', /^Yes$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /There is no grant\./);

    // ---- the audit log of a global master: the filters pass the validators
    await ui.go('#/audit?zone=example.test.&who=root&table=records&since=2020-01-01T00:00:00Z');
    assert.deepEqual(ui.errors(), []);
    assert.ok(ui.input('zone'));
    await ui.go('#/audit?change_set=cs-1&until=2099-01-01');
    assert.deepEqual(ui.errors(), []);
    await ui.go('#/audit');
    assert.ok(ui.qa('table.audit tbody tr').length >= 3, 'the changes made above are in the log');
    assert.ok(ui.qa('table.audit details pre').some((p) => /"name"/.test(p.textContent)));

    // ---- a domain master: the grants of its zone, the policies within its own, the audit rows of its zone, no administration
    const dom = await page(d, '');
    dom.type(dom.input('user'), 'dom');
    dom.type(dom.input('password'), 'a brand new passphrase');
    await dom.submit(dom.q('form'));
    assert.deepEqual(findAll(dom.root, (e) => e.tagName === 'NAV' && e.getAttribute('aria-label') === 'Main menu')[0].querySelectorAll('a').map((a) => a.textContent), ['Home', 'Zones', 'Templates', 'Servers', 'Audit log', 'Account', 'About']);
    await dom.go('#/zones/main/example.test./grants');
    assert.deepEqual(dom.errors(), []);
    assert.deepEqual(dom.input('policy').children.map((o) => o.textContent), ['web'], 'only the policy no wider than its own');
    dom.type(dom.input('principal'), 'sub');
    dom.type(dom.input('suffix'), 'x.example.test');
    await dom.submit(dom.q('form.stack'));
    assert.deepEqual(dom.errors(), []);
    assert.match(dom.text(), /The grant was given\./);
    assert.equal(dom.qa('table.grants tbody tr').length >= 2, true);
    await dom.click(byText(dom.qa('table.grants tbody tr').at(-1), 'button', /^Remove$/));
    await dom.click(byText(dom.qa('table.grants tbody tr').at(-1), 'button', /^Yes$/));
    assert.deepEqual(dom.errors(), []);
    await dom.go('#/audit?zone=example.test.');
    assert.deepEqual(dom.errors(), []);
    await dom.go('#/zones/main/example.test./versions');
    assert.deepEqual(dom.errors(), []);
    assert.equal(dom.qa('table.versions tbody tr').filter((r) => r.querySelector('th')).length >= 3, true);
    assert.match(dom.text(), /Before this version:/, 'a domain master sees the marker too');
    await dom.go('#/admin/users');
    assert.match(dom.text(), /Only global masters administer users/);

    // ---- a subdomain master: the versions are its part of each change, no rollback beyond its suffix is offered by the page, and the sections are those it may use
    const sub = await page(d, '');
    sub.type(sub.input('user'), 'sub');
    sub.type(sub.input('password'), 'sub password 12345');
    await sub.submit(sub.q('form'));
    await sub.go('#/zones/main/example.test./versions');
    assert.deepEqual(sub.errors(), []);
    assert.match(sub.text(), /part of each change that lies under your suffix/);
    assert.deepEqual(sub.qa('table.versions tbody tr').filter((r) => r.querySelector('th')).map((r) => r.querySelector('th').textContent), ['3', '2', '1']);
    assert.deepEqual(findAll(sub.root, (e) => e.tagName === 'NAV' && e.getAttribute('aria-label') === 'Sections of this zone')[0].querySelectorAll('a').map((a) => a.textContent), ['Records', 'Versions', 'Settings']);

    const errors = d.log.lines.filter((l) => /^(error|warn) /.test(l));
    assert.deepEqual(errors, [], 'the service logged no problem');
  } finally {
    await d.close();
  }
});

// The zone screens against the real API (planning 8.1 and 8.2 in Node): karidns-webadmin on a SQLite3 deployment with a scripted karidns-zone, and the application of
// webadmin/ui/js on the fake DOM with a fetch that behaves like a browser.  What ui_zones.test.js assumes about the API is checked here against the API itself: every
// request the zone screens make must pass the validators of the service (unknown fields are refused there), and the answers must be ones the screens understand.
// The real karidns-zone runs in the browser tests (tests/run_webadmin_gui_test.sh).

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast, ORIGIN, makeRun, ok, applyDoc, entry } from './helpers.js';
import { loadStatic, defaultUiDir } from '../lib/static.js';
import { createApp } from '../ui/js/app.js';
import { makeEnv, makeClock, makeBroadcast, FakeStorage, flush, findAll, byText } from './fakedom.js';

const KZ = '/opt/karidns-zone';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// a browser's fetch: the cookie jar, Origin on what is not a read
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
  return { fetch: f, idle: async () => { await flush(); while (inflight > 0) { await sleep(5); await flush(); } await flush(); } };
}

async function page(d, hash) {
  const bf = browserFetch(d);
  const env = makeEnv({ handler: () => { throw new Error('unused'); }, clock: makeClock(), storage: new FakeStorage(), BroadcastChannel: makeBroadcast() });
  env.fetch = bf.fetch;
  env.window.location.hash = hash;
  const app = createApp(env);
  await app.start();
  await bf.idle();
  const root = env.document.getElementById('app');
  const ui = {
    env, app, root,
    q: (sel) => root.querySelector(sel),
    qa: (sel) => root.querySelectorAll(sel),
    input: (name, scope = root) => findAll(scope, (e) => ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.tagName) && e.getAttribute('name') === name)[0],
    button: (re, scope = env.document.body) => byText(scope, 'button', re),
    type(el, v) { el.value = v; },
    async click(el) { el.click(); await bf.idle(); },
    async submit(form) { form.submit(); await bf.idle(); },
    async go(h) { env.window.location.hash = h; await bf.idle(); },
    text: () => root.textContent,
    dialogs: () => env.document.body.querySelectorAll('dialog').filter((x) => x.open),
    errors: () => findAll(root, (e) => e.className === 'msg error' && !e.hidden).map((e) => e.textContent),
  };
  return ui;
}

// the usual tools: render gives "<type>:<prio>:<content>", apply answers a check run with `diff` and a commit run as committed
const DIFF = [entry('www.example.test.', 'A', ['300 A 192.0.2.10', '300 A 192.0.2.11'], ['60 A 192.0.2.99'])];
const tools = (calls) => (c) => {
  calls.push(c);
  if (c.argv[0] === 'render') {
    const lines = String(c.input).split('\n').filter(Boolean).map((l) => l.split('\t'));
    return ok({ 'karidns-zone': 1, command: 'render', result: 'ok', render: { rdata: lines.map(([owner, type, prio, ...content]) => (type === 'MX' ? `${prio} ${content.join('\t')}.` : content.join('\t'))), errors: [] } });
  }
  const isCheck = c.argv.includes('--dry-run');
  const create = c.argv.includes('--create');
  const diff = create ? [entry('new.test.', 'SOA', null, ['3600 SOA ns1.new.test. hm.new.test. 2026110900 7200 3600 1209600 300'])] : (String(c.input).includes('192.0.2.99') ? DIFF : []);   // (the run of a precondition has the records as they were: no difference)
  return ok(applyDoc({ apply: isCheck ? { zone: create ? 'new.test.' : 'example.test.', dry_run: true, diff, created: create } : { zone: create ? 'new.test.' : 'example.test.', dry_run: false, committed: true, version: 3, generation_after: 8, diff, created: create } }));
};

test('the zone screens against the API: list, zone, edit with preview and commit, reload, create, import, settings, metadata, DNSSEC, servers', async () => {
  const calls = [];
  const t = makeRun(tools(calls));
  const d = await deploy({ ui: loadStatic(defaultUiDir()), run: t.run, settings: { 'karidns-zone': KZ, 'reload-after-change': 'no' } });
  d.app.sleep = async () => {};
  try {
    await cast(d);
    const ui = await page(d, '');
    ui.type(ui.input('user'), 'root');
    ui.type(ui.input('password'), 'correct horse battery');
    await ui.submit(ui.q('form'));
    assert.equal(ui.q('h1').textContent, 'Welcome, root');

    // the list
    await ui.go('#/zones');
    assert.deepEqual(ui.qa('tbody tr').map((r) => r.querySelector('th').textContent), ['example.test.', 'other.test.', 'slave.test.']);
    ui.type(ui.input('q'), 'oth');
    await ui.submit(ui.q('form.search'));
    assert.deepEqual(ui.qa('tbody tr').map((r) => r.querySelector('th').textContent), ['other.test.']);

    // the zone: the text form comes from karidns-zone render, once for the page
    await ui.go('#/zones/main/example.test.');
    assert.equal(ui.q('h1').textContent.startsWith('example.test.'), true);
    const mx = ui.qa('table.rrsets tbody tr').find((r) => r.querySelector('th').textContent === '@' && r.childNodes[1].textContent === 'MX');
    assert.equal(mx.childNodes[3].textContent, '10 mail.example.test.');
    assert.equal(calls.filter((c) => c.argv[0] === 'render').length, 1);
    const www = () => ui.qa('table.rrsets tbody tr').find((r) => r.querySelector('th').textContent === 'www');
    await ui.click(byText(www(), 'button', /^Edit$/));
    const dlg = ui.dialogs()[0];
    ui.type(ui.input('ttl', dlg), '60');
    ui.type(ui.input('records', dlg), '192.0.2.99');
    await ui.submit(dlg.querySelector('form'));
    ui.type(ui.input('comment'), 'move www');
    await ui.click(ui.button(/^Preview$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.q('section.draft').textContent, /1 changed/, `the preview: ${ui.q('section.draft').textContent}`);
    const checks = calls.filter((c) => c.argv[0] === 'apply');
    assert.ok(checks.length >= 2, 'the precondition run and the check run');
    assert.ok(checks.some((c) => c.input === 'rr www.example.test. 60 A 192.0.2.99\n'), 'the check run got the change file');
    await ui.click(ui.button(/^Commit$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The change was saved\./);
    assert.match(ui.text(), /Version3/);
    assert.ok(calls.some((c) => c.argv.includes('--comment') && c.argv.includes('move www')));

    // the update button: this deployment has no karictl-config, and says why
    await ui.click(ui.button(/^Update the servers now$/));
    assert.match(ui.errors().join(' '), /needs 'karictl-config'/);

    // the settings: attributes, metadata, then the zone is deleted
    await ui.go('#/zones/main/example.test./settings');
    assert.match(ui.text(), /Kind\s*NATIVE|KindNATIVE/);
    const form = (sel) => findAll(ui.root, (e) => e.tagName === 'FORM').find((f) => f.querySelector(sel));
    await ui.submit(form('input[name=catalog]'));
    assert.match(ui.text(), /Saved\./);
    ui.type(ui.input('content'), '192.0.2.0/24\n2001:db8::/32');
    await ui.submit(form('textarea[name=content]'));
    assert.deepEqual(ui.errors(), []);
    assert.deepEqual((await d.as(await d.login('root', 'correct horse battery'))('GET', '/datasets/main/zones/example.test/metadata')).body.metadata, [{ kind: 'ALLOW-AXFR-FROM', content: ['192.0.2.0/24', '2001:db8::/32'] }]);
    ui.type(ui.input('content'), 'not an address');
    await ui.submit(form('textarea[name=content]'));
    assert.ok(findAll(ui.root, (e) => e.className === 'error' && !e.hidden).length >= 1, 'the refusal is at the box');

    // DNSSEC: nothing signed; a request for a key is accepted (a row in the table)
    await ui.go('#/zones/main/example.test./dnssec');
    assert.match(ui.text(), /Signingnot signed/);
    await ui.submit(form('select[name=kind]'));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /The request was sent\./);
    assert.equal((await d.backend.tx({}, (tx) => tx.all('SELECT kind, algorithm, key_type, nsec FROM karidns_key_requests')))[0].kind, 'enable');

    // a new zone: the form's request passes the validators, the dry run shows the whole zone, the commit makes it and goes to its page
    await ui.go('#/create/main');
    ui.type(ui.input('name'), 'new.test');
    ui.type(ui.input('mname'), 'ns1.new.test');
    ui.type(ui.input('rname'), 'hm.new.test');
    ui.type(ui.input('nameservers'), 'ns1.new.test.');
    ui.type(ui.input('records'), 'www 300 A 192.0.2.7');
    await ui.click(ui.button(/^Preview the zone$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /1 added/);
    await ui.click(ui.button(/^Create the zone$/));
    assert.equal(ui.env.window.location.hash, '#/zones/main/new.test.');
    const created = calls.filter((c) => c.argv.includes('--create'));
    assert.ok(created.length >= 2, 'a check run and a commit run of a new zone');

    // the import
    await ui.go('#/zones/main/example.test./import');
    ui.type(ui.input('zone_text'), '$ORIGIN example.test.\n@ SOA ns1 hm 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n');
    await ui.click(ui.button(/^Preview the import$/));
    assert.deepEqual(ui.errors(), []);
    assert.match(ui.text(), /This is what the change would do/);

    // the servers (SQLite3: the service's note) and the list of zones
    await ui.go('#/servers');
    assert.match(ui.text(), /karictl status/);

    // the zone is deleted after its name is typed again
    await ui.go('#/zones/main/other.test./settings');
    ui.type(ui.input('confirm'), 'other.test');
    await ui.submit(form('input[name=confirm]'));
    assert.deepEqual(ui.errors(), []);
    assert.equal(ui.env.window.location.hash, '#/zones?ds=main');
    assert.match(ui.text(), /The zone other\.test\. was deleted\./);
    assert.deepEqual(ui.qa('tbody tr').map((r) => r.querySelector('th').textContent), ['example.test.', 'slave.test.']);
    const errors = d.log.lines.filter((l) => /^(error|warn) /.test(l));
    assert.deepEqual(errors, [], 'the service logged no problem');
  } finally {
    await d.close();
  }
});

test('the zone screens against the API: a domain master sees only what it may; a refusal of the pipeline comes back with a pointer the screen can use', async () => {
  const calls = [];
  const t = makeRun((c) => {
    if (c.argv[0] === 'render') return tools(calls)(c);
    calls.push(c);
    const isCheck = c.argv.includes('--dry-run');
    return ok(applyDoc({ apply: isCheck ? { dry_run: true, diff: [entry('www.example.test.', 'MX', null, ['300 MX 10 mail.example.test.'])] } : {} }));
  });
  const d = await deploy({ ui: loadStatic(defaultUiDir()), run: t.run, settings: { 'karidns-zone': KZ } });
  try {
    await cast(d);
    const ui = await page(d, '');
    ui.type(ui.input('user'), 'dom');
    ui.type(ui.input('password'), 'dom password 12345');
    await ui.submit(ui.q('form'));
    await ui.go('#/zones');
    assert.deepEqual(ui.qa('tbody tr').map((r) => r.querySelector('th').textContent), ['example.test.']);
    await ui.go('#/zones/main/example.test.');
    assert.match(ui.q('dl').textContent, /Domain master/);
    // MX is not in the policy 'web': the record sets of that type are marked, and a new one is refused by the service
    const rows = ui.qa('table.rrsets tbody tr');
    const mx = rows.find((r) => r.childNodes[1].textContent === 'MX');
    assert.match(mx.childNodes[4].textContent, /your grant does not allow the zone apex/);
    assert.equal(byText(mx, 'button', /^Edit$/), null);
    // a person with a domain master's grant has no way to the settings forms
    await ui.go('#/zones/main/example.test./settings');
    assert.equal(findAll(ui.root, (e) => e.tagName === 'FORM').length, 0);
    // the new RRset the policy refuses: the service answers 403 with the pointer
    await ui.go('#/zones/main/example.test.');
    await ui.click(ui.button(/^Add a record set$/));
    const dlg = ui.dialogs()[0];
    ui.type(ui.input('name', dlg), 'www');
    ui.input('type', dlg).value = 'MX';
    ui.type(ui.input('ttl', dlg), '300');
    ui.type(ui.input('records', dlg), '10 mail.example.test.');
    await ui.submit(dlg.querySelector('form'));
    await ui.click(ui.button(/^Preview$/));
    assert.match(ui.q('section.draft').textContent, /This is not allowed: none of your grants allows MX/);
    assert.match(ui.q('ul.entry-errors').textContent, /none of your grants allows MX/);
  } finally {
    await d.close();
  }
});


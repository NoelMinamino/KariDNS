// What the GUI needs of the API (item F, M1): the text form of the records (G2, ?rdata=1, with a scripted karidns-zone render; the real one runs in
// tests/run_webadmin_write_test.sh), the search (G3: from, contains), the tagged flag (G4), the types and settings in /version (G5) and the administrator's actions on
// credentials (G6).  Through the HTTP server over SQLite3.  The files of the GUI are in static.test.js.

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast, makeRun, ok, exit } from './helpers.js';
import { hotp, totpStep, base32Decode } from '../lib/crypto.js';

const KZ = '/opt/karidns-zone';
const Z = '/datasets/main/zones/example.test';

const withCast = (fn, opts = {}) => async () => {
  const t = opts.handler ? makeRun(opts.handler) : null;
  const d = await deploy({ ...opts.deploy, ...(t ? { run: t.run, settings: { 'karidns-zone': KZ, ...opts.deploy?.settings } } : {}) });
  try {
    const c = await cast(d);
    const root = d.as(await d.login('root', 'correct horse battery'));
    const dom = d.as(await d.login('dom', 'dom password 12345'));
    const sub = d.as(await d.login('sub', 'sub password 12345'));
    await fn(d, { ...c, root, dom, sub, ids: c }, t);
  } finally {
    await d.close();
  }
};
const is = (r, status, type) => {
  assert.equal(r.status, status, JSON.stringify(r.body));
  if (type) assert.equal(r.body.type, `urn:karidns:api:${type}`, JSON.stringify(r.body));
};
const names = (r) => r.body.rrsets.map((s) => `${s.name} ${s.type}`);
const run = (d, text, params = []) => d.backend.tx({ write: true }, (tx) => tx.run(text, params));

// ---------------------------------------------------------------------------------------------------------------------------------- G2: rdata
// a karidns-zone render that answers "<<prio>|<content>>" for a record, null for a content with BAD in it, and tells how it was asked
const renderDoc = (rdata) => ok({ 'karidns-zone': 1, command: 'render', result: 'ok', render: { rdata, errors: [] } });
const renderer = (c) => {
  const lines = String(c.input).split('\n').filter(Boolean).map((l) => l.split('\t'));
  return renderDoc(lines.map(([owner, type, prio, ...content]) => (content.join('\t').includes('BAD') ? null : `${type}:${prio}:${content.join('\t')}`)));
};

test('rdata: ?rdata=1 puts the text form on every record, from one run of karidns-zone render for the page', withCast(async (d, { root, dom, sub }, t) => {
  const plain = await root('GET', `${Z}/rrsets`);
  assert.equal(t.calls.length, 0, 'without ?rdata the tool is not run');
  assert.ok(plain.body.rrsets.every((s) => s.records.every((r) => !('rdata' in r))));
  const r = await root('GET', `${Z}/rrsets?rdata=1`);
  is(r, 200);
  assert.equal(t.calls.length, 1);
  assert.equal(t.calls[0].file, KZ);
  assert.deepEqual(t.calls[0].argv, ['render', '--json', 'example.test']);
  const lines = t.calls[0].input.split('\n');
  assert.equal(lines.pop(), '', 'every line ends with LF');
  assert.deepEqual(lines.slice(0, 4), [
    'a.sub.example.test\tTXT\t0\t"hello"', 'evilsub.example.test\tA\t0\t192.0.2.30', 'example.test\tMX\t10\tmail.example.test', 'example.test\tNS\t0\tns1.example.test',
  ]);
  assert.equal(lines.length, 10, 'the disabled record too');
  const mx = r.body.rrsets.find((s) => s.type === 'MX');
  assert.deepEqual(mx.records, [{ content: '10 mail.example.test', disabled: false, ttl: 3600, rdata: 'MX:10:mail.example.test' }]);
  assert.ok(r.body.rrsets.every((s) => s.records.every((x) => typeof x.rdata === 'string')));
  assert.deepEqual(Object.keys(r.body.rrsets[0]), ['name', 'type', 'ttl', 'tagged', 'records']);
  // the same for ?rdata=true, and 0 / false are off
  assert.equal(names(await root('GET', `${Z}/rrsets?rdata=true&limit=1`)).length, 1);
  assert.equal(t.calls.length, 2);
  assert.ok(!('rdata' in (await root('GET', `${Z}/rrsets?rdata=0&limit=1`)).body.rrsets[0].records[0]));
  assert.ok(!('rdata' in (await root('GET', `${Z}/rrsets?rdata=false&limit=1`)).body.rrsets[0].records[0]));
  is(await root('GET', `${Z}/rrsets?rdata=yes`), 400, 'bad-request');
  // a subdomain master gets the text of what it sees, and the tool is asked about nothing else
  t.calls.length = 0;
  const s = await sub('GET', `${Z}/rrsets?rdata=1`);
  assert.equal(t.calls[0].input.split('\n').filter(Boolean).length, 4);
  assert.ok(!t.calls[0].input.includes('evilsub'));
  assert.equal(s.body.rrsets.length, 4);
  // nothing to render: no run
  t.calls.length = 0;
  assert.deepEqual((await dom('GET', `${Z}/rrsets?rdata=1&name=nothing.example.test`)).body.rrsets, []);
  assert.equal(t.calls.length, 0);
}, { handler: renderer }));

test('rdata: a record the tool cannot render has rdata null; a row the framing cannot carry is not sent', withCast(async (d, { root }, t) => {
  await run(d, `INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES
    (1, 'bad.example.test', 'TXT', '"BAD one"', 300, 0, 0),
    (1, 'nl.example.test', 'TXT', 'two' || char(10) || 'lines', 300, 0, 0),
    (1, 'tab.example.test', 'TXT', 'a' || char(9) || 'b', 300, 0, 0),
    (1, 'empty.example.test', 'TXT', '', 300, 0, 0),
    (1, 'null.example.test', 'MX', 'mail.example.test', 300, NULL, 0)`);
  const r = await root('GET', `${Z}/rrsets?rdata=1&from=bad&limit=100`);
  const rd = (name) => r.body.rrsets.find((s) => s.name === name).records.map((x) => x.rdata);
  assert.deepEqual(rd('bad.example.test.'), [null]);
  assert.deepEqual(rd('nl.example.test.'), [null], 'a line feed cannot be framed');
  assert.deepEqual(rd('empty.example.test.'), [null]);
  assert.ok(t.calls[0].input.includes('tab.example.test\tTXT\t0\ta\tb\n'), 'a TAB is part of the content: it is sent');
  assert.deepEqual(rd('tab.example.test.'), [null], '... and a TAB in the answer is a control character like any other (the real tool writes \\009)');
  assert.deepEqual(rd('null.example.test.'), ['MX:-:mail.example.test'], 'a NULL prio is "-"');
  const total = r.body.rrsets.reduce((n, s) => n + s.records.length, 0);
  const input = t.calls[0].input;
  assert.ok(!input.includes('two\n') && !input.includes('lines\n'), 'the row with a line feed was left out');
  assert.equal(input.split('\n').filter(Boolean).length, total - 2, 'one line for each record that can be framed (not the line feed, not the empty content)');
}, { handler: renderer }));

test('rdata: text that a change set would refuse as the content of a record is not offered as one', withCast(async (d, { root }) => {
  const r = await root('GET', `${Z}/rrsets?rdata=1&name=www.example.test`);
  assert.deepEqual(r.body.rrsets[0].records.map((x) => x.rdata), [null, null], 'a comment outside quotes; longer than a change set takes');
}, { handler: () => renderDoc(['a; b', 'x'.repeat(65536)]) }));

const FAILURES = [
  exit(0, { spawnError: 'ENOENT' }), exit(0, { timedOut: true }), exit(0, { truncated: true }), exit(1, { stderr: 'karidns-zone: boom' }), exit(0, { stdout: 'not json' }),
  renderDoc([]), renderDoc('x'), ok({ 'karidns-zone': 1, render: {} }),
];
let failure = null;
test('rdata: a tool that fails is a 500 that says nothing, and the log says what', withCast(async (d) => {
  const root = d.as(await d.login('root', 'correct horse battery'));
  for (const f of FAILURES) {
    failure = f;
    const r = await root('GET', `${Z}/rrsets?rdata=1`);
    is(r, 500, 'internal');
    assert.equal(JSON.stringify(r.body).includes('boom'), false);
  }
  assert.equal(d.log.lines.filter((l) => /^error [0-9a-f]{16}: karidns-zone render /.test(l)).length, FAILURES.length);
  assert.ok(d.log.lines.some((l) => /karidns-zone render failed \(exit status 1, no document\): karidns-zone: boom/.test(l)));
  assert.ok(d.log.lines.some((l) => /karidns-zone render failed \(exit status 0, 0 results for 10 records\)/.test(l)));
  assert.ok(d.log.lines.some((l) => /karidns-zone render did not start: ENOENT/.test(l)));
  assert.ok(d.log.lines.some((l) => /karidns-zone render ran too long/.test(l)));
  assert.ok(d.log.lines.some((l) => /karidns-zone render wrote too much/.test(l)));
}, { handler: () => failure }));


// ---------------------------------------------------------------------------------------------------------------------------------- G3: from, contains
test('search: from starts at the first owner that is >= the name, in the order of the cursor, and goes on by cursor', withCast(async (d, { root, dom, sub }) => {
  const all = names(await root('GET', `${Z}/rrsets`));
  const from = async (q, who = root) => names(await who('GET', `${Z}/rrsets?from=${q}`));
  assert.deepEqual(await from('ns1.example.test'), all.slice(all.indexOf('ns1.example.test. A')));
  assert.deepEqual(await from('NS1.Example.Test.'), all.slice(all.indexOf('ns1.example.test. A')), 'any case, a final dot is fine');
  assert.deepEqual(await from('o'), all.slice(all.indexOf('off.example.test. A')), 'a name that is not there: the next one');
  assert.deepEqual(await from('zzz'), []);
  assert.deepEqual(await from('a'), all, 'from the first');
  // with paging: the pages are the rest of the list, none twice
  const seen = [];
  let cursor = '';
  for (let i = 0; i < 20; i++) {
    const p = await root('GET', `${Z}/rrsets?from=ns1.example.test&limit=2${cursor}`);
    seen.push(...names(p));
    if (!p.body.next_cursor) break;
    cursor = `&cursor=${p.body.next_cursor}`;
  }
  assert.deepEqual(seen, all.slice(all.indexOf('ns1.example.test. A')));
  // with the other filters, and for a subdomain master (it sees what it sees, from the name on)
  assert.deepEqual(await from('b&type=a'), ['evilsub.example.test. A', 'ns1.example.test. A', 'off.example.test. A', 'sub.example.test. A', 'www.example.test. A'].filter((n) => n >= 'b'));
  assert.deepEqual(await from('b', sub), ['example.test. NS', 'example.test. SOA', 'sub.example.test. A']);   // (the apex SOA and NS are its to see, and example.test >= b)
  assert.deepEqual(names(await dom('GET', `${Z}/rrsets?from=www`)), ['www.example.test. A']);
  is(await root('GET', `${Z}/rrsets?from=bad%20name`), 400, 'bad-request');
  is(await root('GET', `${Z}/rrsets?from=`), 400, 'bad-request');
  is(await root('GET', `${Z}/rrsets?from=${'a'.repeat(256)}`), 400, 'bad-request');
}));

test('search: contains finds a part of an owner, whatever the case, and LIKE has no meaning in it', withCast(async (d, { root, dom, sub }) => {
  await run(d, `INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES
    (1, 'a_b.example.test', 'A', '192.0.2.50', 300, 0, 0), (1, 'axb.example.test', 'A', '192.0.2.51', 300, 0, 0), (1, 'MiXeD.example.test', 'A', '192.0.2.52', 300, 0, 0)`);
  const c = async (q, who = root) => names(await who('GET', `${Z}/rrsets?contains=${encodeURIComponent(q)}`));
  assert.deepEqual(await c('www'), ['www.example.test. A']);
  assert.deepEqual(await c('WWW'), ['www.example.test. A']);
  assert.deepEqual(await c('sub'), ['a.sub.example.test. TXT', 'evilsub.example.test. A', 'sub.example.test. A']);
  assert.deepEqual(await c('a_b'), ['a_b.example.test. A'], 'the underscore is an underscore, not "any character"');
  assert.deepEqual(await c('_'), ['a_b.example.test. A']);
  assert.deepEqual(await c('mixed'), ['mixed.example.test. A']);
  assert.deepEqual(await c('.sub.'), ['a.sub.example.test. TXT']);
  assert.deepEqual(await c('nothing-like-this'), []);
  assert.deepEqual(await c('sub', sub), ['a.sub.example.test. TXT', 'sub.example.test. A'], 'a subdomain master: not evilsub');
  assert.deepEqual(await c('example.test', dom), names(await dom('GET', `${Z}/rrsets`)), 'every owner has the zone name in it');
  // paged: one RRset a page
  const seen = [];
  let cursor = '';
  for (let i = 0; i < 10; i++) {
    const p = await root('GET', `${Z}/rrsets?contains=sub&limit=1${cursor}`);
    seen.push(...names(p));
    if (!p.body.next_cursor) break;
    cursor = `&cursor=${p.body.next_cursor}`;
  }
  assert.deepEqual(seen, ['a.sub.example.test. TXT', 'evilsub.example.test. A', 'sub.example.test. A']);
  // with from: both apply
  assert.deepEqual(names(await root('GET', `${Z}/rrsets?contains=sub&from=e`)), ['evilsub.example.test. A', 'sub.example.test. A']);
  is(await root('GET', `${Z}/rrsets?contains=a%25b`), 400, 'bad-request');
  is(await root('GET', `${Z}/rrsets?contains=a%20b`), 400, 'bad-request');
  is(await root('GET', `${Z}/rrsets?contains=`), 400, 'bad-request');
  is(await root('GET', `${Z}/rrsets?contains=a&contains=b`), 400, 'bad-request');
}));

test('search: zones?contains= scans the zones the principal sees', withCast(async (d, { root, dom }) => {
  const z = async (q, who = root) => (await who('GET', `/datasets/main/zones?contains=${q}`)).body.zones.map((x) => x.name);
  assert.deepEqual(await z('test'), ['example.test.', 'other.test.', 'slave.test.']);
  assert.deepEqual(await z('LAV'), ['slave.test.']);
  assert.deepEqual(await z('xample'), ['example.test.']);
  assert.deepEqual(await z('xample', dom), ['example.test.']);
  assert.deepEqual(await z('other', dom), [], 'a zone without a grant does not exist');
  assert.deepEqual(await z('nothing'), []);
  assert.deepEqual((await root('GET', '/datasets/main/zones?contains=t&kind=SLAVE')).body.zones.map((x) => x.name), ['slave.test.']);
  assert.deepEqual((await root('GET', '/datasets/main/zones?contains=test&prefix=oth')).body.zones.map((x) => x.name), ['other.test.']);
  const p1 = await root('GET', '/datasets/main/zones?contains=test&limit=2');
  assert.deepEqual(p1.body.zones.map((x) => x.name), ['example.test.', 'other.test.']);
  assert.deepEqual((await root('GET', `/datasets/main/zones?contains=test&limit=2&cursor=${p1.body.next_cursor}`)).body.zones.map((x) => x.name), ['slave.test.']);
  is(await root('GET', '/datasets/main/zones?contains=a%25'), 400, 'bad-request');
  is(await root('GET', '/datasets/main/zones?contains='), 400, 'bad-request');
}));

// ---------------------------------------------------------------------------------------------------------------------------------- G4: tagged
test('tagged: an RRset with a location / ECS tag or a tinydns attribute says so', withCast(async (d, { root, dom, sub }) => {
  const id = async (name, content) => (await d.backend.tx({}, (tx) => tx.get('SELECT id FROM records WHERE name = $1 AND content = $2', [name, content]))).id;
  await run(d, 'INSERT INTO karidns_record_tags (record_id, location_tag, ecs_tag) VALUES ($1, $2, NULL)', [await id('www.example.test', '192.0.2.11'), 'lan']);
  await run(d, 'INSERT INTO karidns_record_tinydns (record_id, ttd, loc, countdown) VALUES ($1, NULL, $2, 0)', [await id('sub.example.test', '192.0.2.20'), 'b']);
  const tagged = (r) => r.body.rrsets.filter((s) => s.tagged).map((s) => `${s.name} ${s.type}`);
  assert.deepEqual(tagged(await root('GET', `${Z}/rrsets`)), ['sub.example.test. A', 'www.example.test. A']);
  assert.ok((await root('GET', `${Z}/rrsets`)).body.rrsets.every((s) => typeof s.tagged === 'boolean'));
  assert.deepEqual(tagged(await dom('GET', `${Z}/rrsets`)), ['sub.example.test. A', 'www.example.test. A']);
  assert.deepEqual(tagged(await sub('GET', `${Z}/rrsets`)), ['sub.example.test. A'], 'a subdomain master: only what it sees');
  // a page that has none of them, and a page of one
  assert.deepEqual(tagged(await root('GET', `${Z}/rrsets?type=MX`)), []);
  assert.deepEqual(tagged(await root('GET', `${Z}/rrsets?name=www.example.test&type=A`)), ['www.example.test. A']);
  assert.deepEqual((await root('GET', `${Z}/rrsets?name=nothing.example.test`)).body.rrsets, []);
}));

// ---------------------------------------------------------------------------------------------------------------------------------- G6
const code = (b32, ms) => hotp(base32Decode(b32), totpStep(ms / 1000));

test('credentials: reset-totp switches TOTP off, ends the sessions, and is audited; unlock ends a lock', withCast(async (d, { root, dom, sub, ids }) => {
  const info = async (id) => (await root('GET', `/principals/${id}`)).body.credentials;
  // dom enrols TOTP
  const enrol = await dom('POST', '/auth/totp', { body: { action: 'enroll' } });
  const confirm = await dom('POST', '/auth/totp', { body: { action: 'confirm', code: code(enrol.body.secret, Date.now()) } });
  is(confirm, 200);
  assert.equal((await info(ids.dom)).totp_enabled, true);
  is(await d.request('POST', '/auth/login', { body: { user: 'dom', password: 'dom password 12345' } }), 401, 'totp-required');
  const open = d.as(await d.login('dom', 'dom password 12345', { totp: code(enrol.body.secret, Date.now() + 30000) }));
  is(await open('GET', '/auth/me'), 200);
  // the reset
  const r = await root('POST', `/principals/${ids.dom}/credentials`, { body: { action: 'reset-totp' } });
  is(r, 200);
  assert.deepEqual(r.body.credentials, { password: true, totp_enabled: false, failed_logins: 0, locked: false });
  is(await open('GET', '/auth/me'), 401, 'unauthenticated');                           // the sessions ended
  assert.equal((await d.login('dom', 'dom password 12345')).status, 200, 'no code is asked for any more');
  assert.equal((await info(ids.dom)).totp_enabled, false);
  is(await root('POST', `/principals/${ids.dom}/credentials`, { body: { action: 'reset-totp' } }), 409, 'totp-disabled');
  // a pending enrolment (a secret that was never confirmed) can be reset too
  const again = d.as(await d.login('dom', 'dom password 12345'));
  is(await again('POST', '/auth/totp', { body: { action: 'enroll' } }), 200);
  is(await root('POST', `/principals/${ids.dom}/credentials`, { body: { action: 'reset-totp' } }), 200);
  // the audit rows: the credentials row was updated by root, the secret is not in the log
  const audit = (await root('GET', '/audit?table=credentials&limit=50')).body.audit.filter((a) => a.op === 'U' && a.row_id === ids.dom);
  assert.ok(audit.some((a) => a.principal === 'root'));
  assert.equal(JSON.stringify(audit).includes(enrol.body.secret), false);
  // unlock: ten failures lock the account, the password is right and still refused; the unlock lets it in
  for (let i = 0; i < 10; i++) is(await d.request('POST', '/auth/login', { body: { user: 'sub', password: 'wrong password!' } }), 401, 'invalid-credentials');
  assert.equal((await info(ids.sub)).locked, true);
  assert.equal((await d.login('sub', 'sub password 12345')).status, 401);
  const u = await root('POST', `/principals/${ids.sub}/credentials`, { body: { action: 'unlock' } });
  is(u, 200);
  assert.deepEqual(u.body.credentials, { password: true, totp_enabled: false, failed_logins: 0, locked: false });
  assert.equal((await d.login('sub', 'sub password 12345')).status, 200);
  assert.ok(d.log.lines.some((l) => /^info auth: root did reset-totp for dom$/.test(l)));
  assert.ok(d.log.lines.some((l) => /^info auth: root did unlock for sub$/.test(l)));
}));

test('credentials: global masters only, not one\'s own TOTP, users with a password only, and the usual 400 / 404', withCast(async (d, { root, dom, ids }) => {
  const post = (who, id, body) => who('POST', `/principals/${id}/credentials`, { body });
  is(await post(dom, ids.root, { action: 'unlock' }), 403, 'forbidden');
  is(await post(dom, ids.dom, { action: 'unlock' }), 403, 'forbidden');
  is(await post(root, ids.root, { action: 'reset-totp' }), 409, 'self');
  is(await post(root, ids.root, { action: 'unlock' }), 200);                       // (one's own lock is not a danger)
  const group = (await root('POST', '/principals', { body: { kind: 'group', name: 'staff' } })).body.principal.id;
  is(await post(root, group, { action: 'unlock' }), 409, 'not-a-user');
  const nopw = await d.makeUser('nopw', null);
  is(await post(root, nopw, { action: 'unlock' }), 409, 'no-password');
  is(await post(root, 99999, { action: 'unlock' }), 404, 'not-found');
  is(await post(root, 'abc', { action: 'unlock' }), 404, 'not-found');
  is(await post(root, ids.dom, { action: 'explode' }), 400, 'bad-request');
  is(await post(root, ids.dom, {}), 400, 'bad-request');
  is(await post(root, ids.dom, { action: 'unlock', more: 1 }), 400, 'bad-request');
  is(await root('POST', `/principals/${ids.dom}/credentials`), 400, 'bad-request');
  is(await d.request('POST', `/principals/${ids.dom}/credentials`, { body: { action: 'unlock' } }), 401, 'unauthenticated');
}));

// The write side through the HTTP server over SQLite3, with a scripted karidns-zone and karictl (M3): change sets (the pipeline of planning 2.3), zones created,
// changed and deleted, the import, the reload, the metadata and DNSSEC.  The real karidns-zone runs in tests/run_webadmin_write_test.sh.

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { deploy, cast, makeRun, ok, exit, applyDoc, entry } from './helpers.js';
import { EventEmitter } from 'node:events';
import { listen, Router, readBody } from '../lib/http.js';

const KZ = '/opt/karidns-zone';
const KCTL = '/opt/karictl';
const CTL_CONF = '/opt/ctl.conf';
const DIFF = [entry('www.example.test.', 'A', ['300 A 192.0.2.10', '300 A 192.0.2.11'], ['300 A 192.0.2.50'])];

// the usual behaviour of the tools: a check run (--dry-run) answers with `diff`, a commit run commits it; over.check / over.commit override keys of "apply"
const standard = ({ diff = DIFF, check = {}, commit = {}, messages = [] } = {}) => (c) => {
  if (c.file === KCTL) return exit(0, { stdout: 'OK reloaded\n' });
  const isCheck = c.argv.includes('--dry-run');
  return ok(applyDoc({ messages, apply: isCheck ? { dry_run: true, diff, ...check } : { dry_run: false, committed: true, version: 3, generation_after: 8, diff, ...commit } }));
};

const withTools = (handler, fn, settings = {}) => async () => {
  const t = makeRun(handler);
  const d = await deploy({ run: t.run, settings: { 'karidns-zone': KZ, karictl: KCTL, ...settings } });
  d.realSleep = d.app.sleep;
  d.app.sleep = async () => {};
  try {
    const c = await cast(d);
    const as = async (u, p) => d.as(await d.login(u, p));
    const root = await as('root', 'correct horse battery');
    const dom = await as('dom', 'dom password 12345');
    const sub = await as('sub', 'sub password 12345');
    try {
      await fn(d, { ...c, root, dom, sub }, t);
    } catch (e) {
      const errors = d.log.lines.filter((l) => /^(error|warn) /.test(l));
      if (errors.length) e.message += `\nthe server logged: ${errors.join(' | ').slice(0, 800)}`;
      throw e;
    }
  } finally {
    await d.close();
  }
};
const is = (r, status, type) => {
  assert.equal(r.status, status, JSON.stringify(r.body));
  if (type) assert.equal(r.body.type, `urn:karidns:api:${type}`, JSON.stringify(r.body));
};
const sql = (d, text, params = []) => d.backend.tx({}, (tx) => tx.all(text, params));
const run = (d, text, params = []) => d.backend.tx({ write: true }, (tx) => tx.run(text, params));
const rr = (name, type, ttl, ...contents) => ({ name, type, changetype: 'REPLACE', ttl, records: contents.map((content) => ({ content })) });
const PATCH = '/datasets/main/zones/example.test/rrsets';
const www = (over = {}) => ({ rrsets: [rr('www.example.test', 'A', 300, '192.0.2.50')], ...over });

// ---------------------------------------------------------------------------------------------------------------------------------- the pipeline
test('a change set: the check run, the permission check, the commit run', withTools(standard(), async (d, { dom }, t) => {
  const r = await dom('PATCH', PATCH, { body: www({ comment: 'move www' }) });
  is(r, 200);
  assert.equal(t.calls.length, 2);
  const [check, commit] = t.calls;
  assert.equal(check.file, KZ);
  const file = d.config.settings['sqlite-file'];
  assert.deepEqual(check.argv, ['apply', '--dry-run', '--json', '--no-config', '--sqlite3', file, '--changes', '-', 'example.test']);
  assert.equal(check.input, 'rr www.example.test. 300 A 192.0.2.50\n');
  const cs = r.body.change_set;
  assert.match(cs, /^[0-9a-f-]{36}$/);
  assert.deepEqual(commit.argv, ['apply', '--json', '--no-config', '--sqlite3', file, '--changes', '-', '--expect-generation', '7', '--readback', 'changed', '--version-kind', 'edit',
    '--principal', String((await sql(d, "SELECT id FROM auth.principals WHERE name = 'dom'"))[0].id), '--principal-name', 'dom', '--change-set', cs, '--comment', 'move www', 'example.test']);
  assert.equal(commit.input, check.input);
  assert.equal(commit.opts.timeoutMs, 120000);
  assert.deepEqual([r.body.committed, r.body.changed, r.body.version, r.body.reload], [true, true, 3, 'not requested']);
  assert.deepEqual(r.body.generation, { before: 7, after: 8 });
  assert.deepEqual(r.body.serial, { before: 10, after: 11 });
  assert.deepEqual(r.body.diff, [{ name: 'www.example.test.', type: 'A', change: 'replace', before: [{ ttl: 300, content: '192.0.2.10' }, { ttl: 300, content: '192.0.2.11' }], after: [{ ttl: 300, content: '192.0.2.50' }] }]);
  assert.ok(d.log.lines.some((l) => l.includes(` cs=${cs}`)), 'the access line carries the change set');
}));

test('a dry run stops after the check and the permission verdict', withTools(standard(), async (d, { dom, sub }, t) => {
  const r = await dom('PATCH', PATCH, { body: www({ dry_run: true }) });
  is(r, 200);
  assert.equal(t.calls.length, 1);
  assert.deepEqual([r.body.dry_run, r.body.allowed, r.body.version], [true, true, 2]);
  assert.equal(r.body.diff.length, 1);
  // a refusal is a verdict, not an error; and it comes before any tool has run
  const out = await sub('PATCH', PATCH, { body: { dry_run: true, rrsets: [rr('www.example.test', 'A', 300, '192.0.2.50')] } });
  is(out, 200);
  assert.equal(out.body.allowed, false);
  assert.equal(out.body.denied.pointer, '/rrsets/0');
  assert.equal(t.calls.length, 1);
  assert.equal(out.body.diff, undefined, 'no diff of a change that is not allowed');
}));

test('the request is checked against the grants before any tool runs; a refusal names the RRset of the request', withTools(standard(), async (d, { sub, dom, web }, t) => {
  const body = { rrsets: [rr('a.sub.example.test', 'TXT', 300, '"ok"'), rr('evilsub.example.test', 'A', 300, '192.0.2.9')] };
  const r = await sub('PATCH', PATCH, { body });
  is(r, 403, 'forbidden');
  assert.equal(r.body.errors[0].pointer, '/rrsets/1');
  assert.match(r.body.errors[0].text, /A evilsub\.example\.test\./);
  assert.equal(t.calls.length, 0);
  // the type, the TTL and the apex of a policy
  is(await dom('PATCH', PATCH, { body: { rrsets: [rr('x.example.test', 'MX', 300, '10 mail.example.test.')] } }), 403, 'forbidden');
  is(await dom('PATCH', PATCH, { body: { rrsets: [rr('x.example.test', 'A', 59, '192.0.2.1')] } }), 403, 'forbidden');
  is(await dom('PATCH', PATCH, { body: { rrsets: [rr('example.test', 'TXT', 300, '"x"')] } }), 403, 'forbidden');
  is(await dom('PATCH', PATCH, { body: { rrsets: [{ name: 'x.example.test', type: 'MX', changetype: 'DELETE' }] } }), 403, 'forbidden');
  assert.equal(t.calls.length, 0);
  // one grant for the whole change set: two grants that each cover half are refused
  const only = await d.makePolicy({ name: 'only-a', allowed_types: ['A'], ttl_min: 0, ttl_max: 86400 });
  const txt = await d.makePolicy({ name: 'only-txt', allowed_types: ['TXT'], ttl_min: 0, ttl_max: 86400 });
  await d.makeUser('halves', 'halves password 12', { grants: [
    { role: 'domain_master', zone: 'example.test', policyId: only, schema: '' }, { role: 'domain_master', zone: 'example.test', policyId: txt, schema: '' }] });
  const halves = d.as(await d.login('halves', 'halves password 12'));
  const split = await halves('PATCH', PATCH, { body: { rrsets: [rr('a.example.test', 'A', 300, '192.0.2.1'), rr('b.example.test', 'TXT', 300, '"x"')] } });
  is(split, 403, 'forbidden');
  assert.match(split.body.errors[0].text, /no single grant/);
  assert.equal(split.body.errors[0].pointer, '/rrsets/1');
  is(await halves('PATCH', PATCH, { body: { rrsets: [rr('a.example.test', 'A', 300, '192.0.2.1')] } }), 200);
  assert.ok(web);
}));

test('the permission check runs again on the diff karidns-zone found', withTools(standard({ diff: [entry('www.example.test.', 'A', ['300 A 192.0.2.10'], ['300 A 192.0.2.50']), entry('mail.example.test.', 'MX', ['3600 MX 10 m.example.test.'], null)] }), async (d, { dom }, t) => {
  const r = await dom('PATCH', PATCH, { body: www() });
  is(r, 403, 'forbidden');
  assert.match(r.body.errors[0].text, /MX mail\.example\.test\./);
  assert.equal(r.body.errors[0].pointer, undefined, 'an RRset the request did not name has no pointer');
  assert.equal(t.calls.length, 1, 'nothing was committed');
  const dry = await dom('PATCH', PATCH, { body: www({ dry_run: true }) });
  assert.deepEqual([dry.body.allowed, dry.body.diff], [false, undefined]);
}));

test('max_rr: the records in the scope of the grant after the change (A-24)', withTools(standard({ diff: [entry('x.sub.example.test.', 'A', null, ['300 A 192.0.2.1', '300 A 192.0.2.2', '300 A 192.0.2.3'])], check: { records_after: 50 } }), async (d, { root, dom }, t) => {
  const p = await d.makePolicy({ name: 'capped', allowed_types: ['A', 'TXT'], ttl_min: 0, ttl_max: 86400, max_rr: 4 });
  await d.makeUser('capped', 'capped password 12', { grants: [{ role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policyId: p, schema: '' }] });
  const c = d.as(await d.login('capped', 'capped password 12'));
  // sub.example.test holds 2 records (sub A, a.sub TXT): 2 + 3 = 5 > 4
  const over = await c('PATCH', PATCH, { body: { rrsets: [rr('x.sub.example.test', 'A', 300, '192.0.2.1', '192.0.2.2', '192.0.2.3')] } });
  is(over, 403, 'max-rr');
  assert.match(over.body.errors[0].text, /5 records .* allows 4/);
  assert.equal(t.calls.length, 1);
  // one record fewer fits
  t.calls.length = 0;
  d.app.run = makeRun(standard({ diff: [entry('x.sub.example.test.', 'A', null, ['300 A 192.0.2.1', '300 A 192.0.2.2'])] })).run;
  is(await c('PATCH', PATCH, { body: { rrsets: [rr('x.sub.example.test', 'A', 300, '192.0.2.1', '192.0.2.2')] } }), 200);
  // a domain master's scope is the zone: the count of the check run
  const q = await d.makePolicy({ name: 'zone-capped', allowed_types: ['A'], ttl_min: 0, ttl_max: 86400, max_rr: 20 });
  await d.makeUser('zc', 'zc password 123456', { grants: [{ role: 'domain_master', zone: 'example.test', policyId: q, schema: '' }] });
  const zc = d.as(await d.login('zc', 'zc password 123456'));
  d.app.run = makeRun(standard({ diff: DIFF, check: { records_after: 21 } })).run;
  const zone = await zc('PATCH', PATCH, { body: www() });
  is(zone, 403, 'max-rr');
  assert.match(zone.body.errors[0].text, /21 records/);
  d.app.run = makeRun(standard({ diff: DIFF, check: { records_after: 20 } })).run;
  is(await zc('PATCH', PATCH, { body: www() }), 200);
  assert.ok(root && dom);
}));

test('the zone changed between the check and the commit: again, three times at most', async () => {
  let commits = 0;
  const flaky = (failures) => (c) => {
    if (c.argv.includes('--dry-run')) return ok(applyDoc({ apply: { dry_run: true, generation: 7 + commits, diff: DIFF } }));
    commits++;
    return commits <= failures ? exit(3, { stdout: JSON.stringify(applyDoc({ apply: { changed: true } })) }) : ok(applyDoc({ apply: { dry_run: false, committed: true, version: 4, generation: 7 + commits, generation_after: 9 + commits, diff: DIFF } }));
  };
  await withTools(flaky(2), async (d, { dom }, t) => {
    d.app.sleep = d.realSleep;               // the pause between two rounds is the real one here (40 to 400 ms)
    const r = await dom('PATCH', PATCH, { body: www() });
    is(r, 200);
    assert.equal(r.body.version, 4);
    assert.equal(t.calls.length, 6, 'check, commit, three times');
    assert.deepEqual(t.calls.filter((c) => c.argv.includes('--expect-generation')).map((c) => c.argv[c.argv.indexOf('--expect-generation') + 1]), ['7', '8', '9']);
  })();
  commits = 0;
  await withTools(flaky(5), async (d, { dom }, t) => {
    const r = await dom('PATCH', PATCH, { body: www() });
    is(r, 409, 'changed');
    assert.equal(t.calls.length, 6);
    assert.match(r.body.detail, /nothing was written/);
  })();
  // an exit status 3 of the check run is the same
  await withTools((c) => (c.argv.includes('--dry-run') ? exit(3, { stdout: JSON.stringify(applyDoc()) }) : exit(0)), async (d, { dom }, t) => {
    is(await dom('PATCH', PATCH, { body: www() }), 409, 'changed');
    assert.equal(t.calls.length, 3);
  })();
});

test('preconditions (A-5): an RRset that is not as the client expected stops the change', async () => {
  const expectation = (c) => c.input.startsWith('rr www.example.test. 300 A 192.0.2.10') || c.input.startsWith('delete');
  const handler = (differs, gen = 7) => (c) => {
    if (!c.argv.includes('--dry-run')) return ok(applyDoc({ apply: { dry_run: false, committed: true, diff: DIFF } }));
    if (expectation(c)) return ok(applyDoc({ apply: { generation: gen, diff: differs ? [entry('www.example.test.', 'A', ['300 A 192.0.2.99'], ['300 A 192.0.2.10'])] : [] } }));
    return ok(applyDoc({ apply: { diff: DIFF } }));
  };
  const body = { rrsets: [{ ...rr('www.example.test', 'A', 300, '192.0.2.50'), expect: [{ ttl: 300, content: '192.0.2.10' }] }] };
  await withTools(handler(false), async (d, { dom }, t) => {
    is(await dom('PATCH', PATCH, { body }), 200);
    assert.equal(t.calls.length, 3, 'the expectation, the check, the commit');
    assert.equal(t.calls[0].input, 'rr www.example.test. 300 A 192.0.2.10\n');
    assert.ok(t.calls[0].argv.includes('--dry-run'));
  })();
  await withTools(handler(true), async (d, { dom }, t) => {
    const r = await dom('PATCH', PATCH, { body });
    is(r, 409, 'precondition-failed');
    assert.equal(r.body.errors[0].pointer, '/rrsets/0/expect');
    assert.deepEqual(r.body.errors[0].current, [{ ttl: 300, content: '192.0.2.99' }]);
    assert.equal(t.calls.length, 1, 'nothing else ran');
  })();
  // "must not exist": an empty list; a DELETE with an expectation
  await withTools(handler(true), async (d, { dom }) => {
    const r = await dom('PATCH', PATCH, { body: { rrsets: [{ name: 'www.example.test', type: 'A', changetype: 'DELETE', expect: [] }] } });
    is(r, 409, 'precondition-failed');
  })();
  // an expectation run that sees another generation than the check run: the zone moved, again
  let n = 0;
  await withTools((c) => {
    if (c.argv.includes('--dry-run') && expectation(c)) return handler(false, n++ === 0 ? 8 : 7)(c);
    return handler(false)(c);
  }, async (d, { dom }, t) => {
    is(await dom('PATCH', PATCH, { body }), 200);
    assert.equal(t.calls.length, 5, 'the first round was dropped');
  })();
  // an exit status 3 or a failure of the expectation run
  await withTools((c) => (c.argv.includes('--dry-run') && expectation(c) ? exit(3) : exit(0)), async (d, { dom }) => {
    is(await dom('PATCH', PATCH, { body }), 409, 'changed');
  })();
  await withTools((c) => (c.argv.includes('--dry-run') && expectation(c) ? exit(1, { stdout: JSON.stringify(applyDoc({ messages: [{ severity: 'error', code: 'zone.syntax', text: 'standard input:2: bad', line: null }] })) }) : exit(0)), async (d, { dom }) => {
    const r = await dom('PATCH', PATCH, { body });
    is(r, 422, 'zone-checks-failed');
    assert.equal(r.body.errors[0].pointer, undefined);
  })();
});

test('nothing changes: no commit, no new serial', withTools(standard({ diff: [] }), async (d, { dom }, t) => {
  const r = await dom('PATCH', PATCH, { body: www() });
  is(r, 200);
  assert.equal(t.calls.length, 1);
  assert.deepEqual([r.body.committed, r.body.changed, r.body.diff, r.body.reload], [false, false, [], 'not requested']);
}));

test('what the tools say: the zone checks (422, with a pointer), a busy zone, a broken tool', async () => {
  const msg = (severity, code, text) => ({ severity, code, text, file: 'standard input', line: null, zone: 'example.test.', view: null });
  const body = { rrsets: [rr('a.example.test', 'A', 300, '192.0.2.1'), rr('b.example.test', 'CNAME', 300, 'x.example.test.')] };
  await withTools((c) => exit(1, { stdout: JSON.stringify(applyDoc({ messages: [msg('error', 'zone.cname-other', 'standard input:3: b.example.test. has a CNAME and other data'), msg('warning', 'zone.ttl.missing', 'w'), msg('note', 'db.import.change', 'n')] })) }), async (d, { dom }) => {
    const r = await dom('PATCH', PATCH, { body });
    is(r, 422, 'zone-checks-failed');
    assert.deepEqual(r.body.errors.map((e) => [e.code, e.severity, e.pointer]), [['zone.cname-other', 'error', '/rrsets/1/records/0'], ['zone.ttl.missing', 'warning', undefined]]);
  })();
  const fail = (code, text, extra) => exit(1, { stdout: JSON.stringify(applyDoc({ messages: [msg('error', code, text)], ...extra })) });
  await withTools(() => fail('db.apply.zone', "Zone 'example.test' has domains.type SLAVE: a change set is applied to a primary zone"), async (d, { dom }) => is(await dom('PATCH', PATCH, { body }), 409, 'zone-not-editable'))();
  await withTools(() => fail('db.apply.zone', "Zone 'example.test' is not in the database (--create makes a new zone)"), async (d, { dom }) => is(await dom('PATCH', PATCH, { body }), 404, 'not-found'))();
  await withTools(() => fail('db.apply.zone', "Zone 'example.test' exists already; --create makes a new zone"), async (d, { dom }) => is(await dom('PATCH', PATCH, { body }), 409, 'exists'))();
  await withTools(() => fail('db.apply.zone', "line 1: the SOA record of zone 'example.test' cannot be deleted"), async (d, { dom }) => is(await dom('PATCH', PATCH, { body }), 422, 'refused'))();
  await withTools(() => fail('db.apply.changes', 'standard input: line 2: bad rdata'), async (d, { dom }) => {
    const r = await dom('PATCH', PATCH, { body });
    is(r, 422, 'zone-checks-failed');
    assert.equal(r.body.errors[0].pointer, '/rrsets/1/records/0');
  })();
  await withTools(() => exit(4, { stdout: JSON.stringify(applyDoc({ apply: { busy: true } })) }), async (d, { dom }) => {
    const r = await dom('PATCH', PATCH, { body });
    is(r, 503, 'busy');
    assert.equal(r.headers.get('retry-after'), '2');
  })();
  // a broken installation or a bug is a 500 that says nothing, and the log says what
  const lines = [];
  for (const [what, result, re] of [
    ['a tool that does not start', exit(null, { spawnError: 'ENOENT' }), /did not start: ENOENT/],
    ['a tool that runs too long', exit(null, { timedOut: true }), /ran too long/],
    ['a tool that writes too much', exit(null, { truncated: true }), /wrote too much/],
    ['a usage error', exit(2, { stderr: 'karidns-zone: unknown option' }), /exit status 2.*unknown option/],
    ['no document', exit(1, { stdout: 'not json', stderr: 'boom' }), /exit status 1.*boom/],
    ['a database failure', fail('db.import.write', 'cannot write'), /db\.import\.write: cannot write/],
    ['row level security', fail('db.import.write', 'new row violates row-level security policy for table "records"'), /row level security refused what the API allowed \(a bug\)/],
  ]) {
    await withTools(() => result, async (d, { dom }) => {
      const r = await dom('PATCH', PATCH, { body });
      is(r, 500, 'internal');
      assert.equal(r.body.detail, undefined, what);
      assert.ok(d.log.lines.some((l) => re.test(l)), `${what}: ${d.log.lines.join('|')}`);
      lines.push(what);
    })();
  }
  assert.equal(lines.length, 7);
});

test('zones the API does not edit: a secondary, a zone signed elsewhere, RRsets with tags; an unknown zone', withTools(standard(), async (d, { root, dom, sub }, t) => {
  const one = (zone) => ({ rrsets: [rr(`x.${zone}`, 'A', 300, '192.0.2.1')] });
  is(await root('PATCH', '/datasets/main/zones/slave.test/rrsets', { body: one('slave.test') }), 409, 'zone-not-editable');
  is(await root('PATCH', '/datasets/main/zones/other.test/rrsets', { body: one('other.test') }), 409, 'presigned-zone');
  is(await root('PATCH', '/datasets/main/zones/ghost.test/rrsets', { body: one('ghost.test') }), 404, 'not-found');
  is(await dom('PATCH', '/datasets/main/zones/other.test/rrsets', { body: one('other.test') }), 404, 'not-found');
  is(await dom('PATCH', '/datasets/nowhere/zones/example.test/rrsets', { body: one('example.test') }), 404, 'not-found');
  assert.equal(t.calls.length, 0);
  // the tags: a location-tagged record of www.example.test
  const id = (await sql(d, "SELECT id FROM records WHERE name = 'www.example.test' AND content = '192.0.2.10'"))[0].id;
  await run(d, 'INSERT INTO karidns_record_tags (record_id, location_tag) VALUES ($1, $2)', [id, 'office']);
  const tagged = await dom('PATCH', PATCH, { body: www() });
  is(tagged, 409, 'tagged-rrset');
  assert.match(tagged.body.detail, /A www\.example\.test\./);
  is(await dom('PATCH', PATCH, { body: { rrsets: [rr('other.example.test', 'A', 300, '192.0.2.1')] } }), 200);
  const imp = await dom('POST', '/datasets/main/zones/example.test/import', { body: { zone_text: '$ORIGIN example.test.\n' } });
  is(imp, 409, 'tagged-rrset');
  assert.match(imp.body.detail, /use karidns-zone to import/);
}));

test('a signer zone: the change is made, the reload waits for the signer; SQLite3 reloads with karictl otherwise', withTools(standard(), async (d, { dom, root }, t) => {
  const reload = await dom('PATCH', PATCH, { body: www({ reload: true }) });
  is(reload, 200);
  assert.equal(reload.body.reload, 'requested');
  assert.deepEqual(t.calls[2], { file: KCTL, argv: ['-f', CTL_CONF, 'reload', 'example.test'], input: undefined, opts: { timeoutMs: 60000, maxOutput: 65536 } });
  // reload-after-change in the configuration is the default; the request can say no
  d.app.settings['reload-after-change'] = true;
  t.calls.length = 0;
  assert.equal((await dom('PATCH', PATCH, { body: www() })).body.reload, 'requested');
  assert.equal(t.calls.length, 3);
  t.calls.length = 0;
  assert.equal((await dom('PATCH', PATCH, { body: www({ reload: false }) })).body.reload, 'not requested');
  assert.equal(t.calls.length, 2);
  // a zone in views is reloaded in each view
  d.app.settings['reload-after-change'] = false;
  await run(d, "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'a'), (1, 'b')");
  t.calls.length = 0;
  await dom('PATCH', PATCH, { body: www({ reload: true }) });
  assert.deepEqual(t.calls.slice(2).map((c) => c.argv.slice(2)), [['reload', 'example.test', 'a'], ['reload', 'example.test', 'b']]);
  await run(d, "UPDATE karidns_domain_views SET view_name = '-x' WHERE view_name = 'b'");
  t.calls.length = 0;
  assert.match((await dom('PATCH', PATCH, { body: www({ reload: true }) })).body.reload, /^failed: .*not a plain name/);
  assert.equal(t.calls.length, 2, 'karictl was not run');
  await run(d, 'DELETE FROM karidns_domain_views');
  // a signer zone: the signer reloads after it has signed (S-5), the API files nothing
  await run(d, "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'X-KARIDNS-SIGNER', '1')");
  t.calls.length = 0;
  const signer = await dom('PATCH', PATCH, { body: www({ reload: true }) });
  is(signer, 200);
  assert.equal(signer.body.reload, 'waiting for the signer');
  assert.equal(t.calls.length, 2, 'no karictl');
  const z = await root('GET', '/datasets/main/zones/example.test');
  assert.equal(z.body.zone.signer, true);
}, { 'karictl-config': CTL_CONF }));


test('karictl that fails: the change is in the database, the answer says the reload did not happen', async () => {
  for (const [result, re] of [[exit(1, { stderr: 'ERROR command not allowed\n' }), /ERROR command not allowed/], [exit(null, { spawnError: 'ENOENT' }), /ENOENT/], [exit(null, { timedOut: true }), /timed out/], [exit(1), /exit status 1/]]) {
    // a global master is told why; anybody else is pointed at the log (karictl's words can hold paths of the host)
    for (const who of ['root', 'dom']) {
      await withTools((c) => (c.file === KCTL ? result : standard()(c)), async (d, cast) => {
        const r = await cast[who]('PATCH', PATCH, { body: www({ reload: true }) });
        is(r, 200);
        if (who === 'root') assert.match(r.body.reload, re);
        else {
          assert.doesNotMatch(r.body.reload, re);
          assert.match(r.body.reload, /^failed: karictl could not reload the zone \(the log of the service has the reason, request [0-9a-f]{16}\)/);
        }
        assert.match(r.body.reload, /^failed: .*the change is in the database/);
        assert.ok(d.log.lines.some((l) => /^warn .* karictl reload example\.test failed/.test(l)));
      }, { 'karictl-config': CTL_CONF })();
    }
  }
  // no restricted key configured: a request for a reload is refused before anything is written
  await withTools(standard(), async (d, { dom }, t) => {
    const r = await dom('PATCH', PATCH, { body: www({ reload: true }) });
    is(r, 400, 'bad-request');
    assert.equal(r.body.errors[0].pointer, '/reload');
    assert.equal(t.calls.length, 0);
    assert.equal((await dom('PATCH', PATCH, { body: www() })).body.reload, 'not requested');
  })();
});

test('malformed requests are 400s with a pointer; tokens and sessions are checked first', withTools(standard(), async (d, { dom, root }, t) => {
  is(await dom('PATCH', PATCH, { body: { rrsets: [rr('www.example.test', 'A', 300, '192.0.2.1; evil')] } }), 400, 'bad-request');
  is(await dom('PATCH', PATCH), 400, 'bad-request');
  is(await dom('PATCH', PATCH, { body: [] }), 400, 'bad-request');
  is(await d.request('PATCH', `/datasets/main/zones/example.test/rrsets`, { body: www() }), 401, 'unauthenticated');
  is(await d.request('PATCH', PATCH, { cookie: dom.cookie ?? 'x', body: www() }), 401);
  is(await dom('PUT', PATCH), 405, 'method-not-allowed');
  is(await dom('PATCH', '/datasets/main/zones/bad%20zone/rrsets', { body: www() }), 400, 'bad-request');
  assert.equal(t.calls.length, 0);
  // a read-only token cannot write, a token can
  const ro = (await dom('POST', '/tokens', { body: { name: 'ro', read_only: true } })).body.token;
  is(await d.request('PATCH', PATCH, { token: ro, body: www() }), 403, 'read-only-token');
  const rw = (await dom('POST', '/tokens', { body: { name: 'rw' } })).body.token;
  is(await d.request('PATCH', PATCH, { token: rw, body: www() }), 200);
  assert.ok(root);
}));

// ---------------------------------------------------------------------------------------------------------------------------------- zones
const CREATE = { name: 'New.Test', soa: { mname: 'ns1.new.test', rname: 'hostmaster.new.test' }, nameservers: ['ns1.new.test', 'ns2.example.test'], rrsets: [rr('www.new.test', 'A', 300, '192.0.2.1')] };

test('a new zone: the whole zone is checked as one and made with --create', withTools(standard({ diff: [entry('new.test.', 'SOA', null, ['3600 SOA ns1.new.test. hostmaster.new.test. 2026110800 7200 3600 1209600 300']), entry('new.test.', 'NS', null, ['3600 NS ns1.new.test.']), entry('www.new.test.', 'A', null, ['300 A 192.0.2.1'])], commit: { created: true, generation: 0 } }), async (d, { root, dom }, t) => {
  const r = await root('POST', '/datasets/main/zones', { body: { ...CREATE, reload: true } });
  is(r, 201);
  assert.equal(r.headers.get('location'), '/api/v1/datasets/main/zones/new.test.');
  assert.equal(r.body.zone, 'new.test.');
  assert.equal(r.body.committed, true);
  assert.equal(t.calls.length, 3, 'check, commit, karictl');
  const [check, commit] = t.calls;
  assert.deepEqual(check.argv.slice(-6), ['--changes', '-', '--create', '--type', 'NATIVE', 'new.test']);
  assert.ok(!commit.argv.includes('--expect-generation') && !commit.argv.includes('--version-kind') && commit.argv.includes('--create'));
  assert.match(check.input, /^rr new\.test\. 3600 SOA ns1\.new\.test\. hostmaster\.new\.test\. \d{8}00 7200 3600 1209600 300\nrr new\.test\. 3600 NS ns1\.new\.test\.\nrr new\.test\. 3600 NS ns2\.example\.test\.\nrr www\.new\.test\. 300 A 192\.0\.2\.1\n$/);
  assert.equal(t.calls[2].argv[3], 'new.test');
  // a dry run, a zone that exists, a name that is no zone name, a stranger
  t.calls.length = 0;
  const dry = await root('POST', '/datasets/main/zones', { body: { ...CREATE, dry_run: true, type: 'MASTER' } });
  is(dry, 200);
  assert.deepEqual([dry.body.dry_run, dry.body.allowed, t.calls.length, t.calls[0].argv.includes('MASTER')], [true, true, 1, true]);
  is(await root('POST', '/datasets/main/zones', { body: { ...CREATE, name: 'example.test' } }), 409, 'exists');
  const badName = await root('POST', '/datasets/main/zones', { body: { ...CREATE, name: 'a b' } });
  is(badName, 400, 'bad-request');
  assert.equal(badName.body.errors[0].pointer, '/name');
  is(await dom('POST', '/datasets/main/zones', { body: CREATE }), 403, 'forbidden');
  is(await root('POST', '/datasets/nowhere/zones', { body: CREATE }), 404, 'not-found');
  is(await root('POST', '/datasets/main/zones', { body: { name: 'x.test' } }), 400, 'bad-request');
  // the global master's policy decides: a policy without SOA cannot make a zone
  const noSoa = await d.makePolicy({ name: 'no-soa', allowed_types: ['A', 'NS'], apex_editable: true });
  await d.makeUser('weakroot', 'weakroot password 1', { grants: [{ role: 'global_master', policyId: noSoa }] });
  const weak = d.as(await d.login('weakroot', 'weakroot password 1'));
  const denied = await weak('POST', '/datasets/main/zones', { body: CREATE });
  is(denied, 403, 'forbidden');
  assert.equal(denied.body.errors[0].pointer, '/soa');
  // from a zone text
  t.calls.length = 0;
  const t2 = makeRun(standard({ diff: [entry('text.test.', 'SOA', null, ['300 SOA ns1.text.test. h.text.test. 1 2 3 4 5']), entry('text.test.', 'NS', null, ['300 NS ns1.text.test.'])] }));
  d.app.run = t2.run;
  const text = '$ORIGIN text.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n';
  const tr = await root('POST', '/datasets/main/zones', { body: { name: 'text.test', zone_text: text, type: 'MASTER' } });
  is(tr, 201);
  assert.equal(t2.calls[0].input, text);
  assert.deepEqual(t2.calls[0].argv.slice(-6), ['--zone-file', '-', '--create', '--type', 'MASTER', 'text.test']);
  assert.equal(t2.calls[0].opts.timeoutMs, 300000);
  is(await root('POST', '/datasets/main/zones', { body: { name: 'nul.test', zone_text: 'a\0b' } }), 400, 'bad-request');
}, { 'karictl-config': CTL_CONF }));


test('deleting a zone takes everything of it: rows, versions, grants, and logs who did it', withTools(standard(), async (d, { root, dom }, t) => {
  await run(d, 'CREATE TABLE comments (id INTEGER PRIMARY KEY, domain_id INTEGER, name TEXT)');
  await run(d, "INSERT INTO comments (domain_id, name) VALUES (1, 'x')");
  await run(d, "INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (1, 257, 1, 'secret')");
  await run(d, "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'ALLOW-AXFR-FROM', '192.0.2.1')");
  await run(d, 'INSERT INTO karidns_record_tags (record_id, location_tag) VALUES (4, $1)', ['office']);
  await run(d, "INSERT INTO karidns_domain_views (domain_id, view_name) VALUES (1, 'a')");
  const count = async (table) => Number((await sql(d, `SELECT count(*) AS n FROM ${table} WHERE domain_id = 1`))[0].n);
  assert.ok(await count('records') > 0 && await count('karidns_domain_views') === 1);
  // not without the name, not by the others, not what is not there
  is(await root('DELETE', '/datasets/main/zones/example.test', { body: { confirm: 'other.test' } }), 400, 'bad-request');
  is(await root('DELETE', '/datasets/main/zones/example.test', { body: {} }), 400, 'bad-request');
  is(await dom('DELETE', '/datasets/main/zones/example.test', { body: { confirm: 'example.test' } }), 403, 'forbidden');
  is(await root('DELETE', '/datasets/main/zones/ghost.test', { body: { confirm: 'ghost.test' } }), 404, 'not-found');
  assert.ok(await count('records') > 0);
  const r = await root('DELETE', '/datasets/main/zones/example.test.', { body: { confirm: 'Example.Test.', reload: true } });
  is(r, 200);
  assert.equal(r.body.deleted, 'example.test.');
  assert.equal(r.body.reload, 'requested');
  assert.deepEqual(t.calls.map((c) => c.argv), [['-f', CTL_CONF, 'reload', 'example.test', 'a']], 'the views were read before the zone went');
  for (const table of ['records', 'domainmetadata', 'cryptokeys', 'comments', 'karidns_domain_views', 'karidns_zone_state', 'karidns_zone_versions']) assert.equal(await count(table), 0, table);
  assert.equal((await sql(d, 'SELECT count(*) AS n FROM karidns_record_tags'))[0].n, 0);
  assert.equal((await sql(d, 'SELECT count(*) AS n FROM domains WHERE id = 1'))[0].n, 0);
  assert.equal((await sql(d, "SELECT count(*) AS n FROM domains WHERE name = 'other.test'"))[0].n, 1, 'the other zones stay');
  assert.equal((await sql(d, "SELECT count(*) AS n FROM auth.grants WHERE zone_name = 'example.test'"))[0].n, 0, 'the grants of the zone went with it (SQLite3: the API does it)');
  assert.equal((await sql(d, 'SELECT count(*) AS n FROM auth.grants'))[0].n, 1, 'the global master\'s stays');
  is(await dom('GET', '/datasets/main/zones/example.test'), 404, 'not-found');
  // the audit log (both files) names the principal and the change set
  const audit = await sql(d, "SELECT principal_name, change_set, db_role FROM karidns_audit_log WHERE table_name = 'records' AND op = 'D' AND zone_name = 'example.test' LIMIT 1");
  assert.deepEqual([audit[0].principal_name, audit[0].change_set, audit[0].db_role], ['root', r.body.change_set, 'karidns-webadmin']);
  const authAudit = await sql(d, "SELECT principal_name, change_set FROM auth.karidns_auth_audit WHERE table_name = 'grants' AND op = 'D' LIMIT 1");
  assert.deepEqual([authAudit[0].principal_name, authAudit[0].change_set], ['root', r.body.change_set]);
  assert.equal((await sql(d, 'SELECT count(*) AS n FROM karidns_audit_actor'))[0].n, 0, 'the actor row is gone');
  // without a reload
  const plain = await root('DELETE', '/datasets/main/zones/other.test', { body: { confirm: 'other.test' } });
  assert.equal(plain.body.reload, 'not requested');
  assert.equal(t.calls.length, 1);
}, { 'karictl-config': CTL_CONF }));


test('zone attributes: the catalog and the views', withTools(standard(), async (d, { root, dom }) => {
  await run(d, "INSERT INTO domains (name, type) VALUES ('catalog.test', 'PRODUCER')");
  const r = await root('PATCH', '/datasets/main/zones/example.test', { body: { catalog: 'Catalog.Test.' } });
  is(r, 200);
  assert.equal(r.body.catalog, 'catalog.test');
  assert.equal((await sql(d, "SELECT catalog FROM domains WHERE name = 'example.test'"))[0].catalog, 'catalog.test');
  assert.deepEqual((await root('PATCH', '/datasets/main/zones/example.test', { body: { catalog: null } })).body.catalog, null);
  is(await root('PATCH', '/datasets/main/zones/example.test', { body: { catalog: 'other.test' } }), 409, 'not-a-catalog');
  is(await root('PATCH', '/datasets/main/zones/example.test', { body: { catalog: 'a b' } }), 400, 'bad-request');
  is(await root('PATCH', '/datasets/main/zones/example.test', { body: {} }), 400, 'bad-request');
  is(await root('PATCH', '/datasets/main/zones/example.test', { body: { views: ['a'] } }), 400, 'bad-request');
  is(await dom('PATCH', '/datasets/main/zones/example.test', { body: { catalog: null } }), 403, 'forbidden');
  is(await root('PATCH', '/datasets/main/zones/ghost.test', { body: { catalog: null } }), 404, 'not-found');
  // views of the dataset
  d.app.dsByName.get('main').views.push('a', 'b');
  const v = await root('PATCH', '/datasets/main/zones/example.test', { body: { views: ['b', 'a', 'b'] } });
  is(v, 200);
  assert.deepEqual(v.body.views, ['a', 'b']);
  assert.deepEqual((await root('PATCH', '/datasets/main/zones/example.test', { body: { views: [] } })).body.views, []);
  is(await root('PATCH', '/datasets/main/zones/example.test', { body: { views: ['c'] } }), 400, 'bad-request');
}));

// ---------------------------------------------------------------------------------------------------------------------------------- import
test('import: a zone text replaces (or merges) the RRsets of the zone, for the masters of the whole zone', withTools(standard(), async (d, { root, dom, sub }, t) => {
  const url = '/datasets/main/zones/example.test/import';
  const text = '$ORIGIN example.test.\n$TTL 300\nwww A 192.0.2.50\n';
  const r = await dom('POST', url, { body: { zone_text: text, comment: 'from the old host' } });
  is(r, 200);
  assert.equal(t.calls.length, 2);
  const [check, commit] = t.calls;
  const file = d.config.settings['sqlite-file'];
  assert.deepEqual(check.argv, ['apply', '--dry-run', '--json', '--no-config', '--sqlite3', file, '--zone-file', '-', '--delete-others', 'example.test']);
  assert.equal(check.input, text);
  assert.equal(check.opts.timeoutMs, 300000);
  assert.ok(commit.argv.join(' ').includes('--zone-file - --delete-others --expect-generation 7 --readback changed --version-kind import'));
  assert.ok(commit.argv.includes('from the old host'));
  // merge
  t.calls.length = 0;
  is(await root('POST', url, { body: { zone_text: text, mode: 'merge', dry_run: true } }), 200);
  assert.ok(!t.calls[0].argv.includes('--delete-others'));
  // the permission check is on the diff: the policy of a domain master has no MX
  d.app.run = makeRun(standard({ diff: [entry('mail.example.test.', 'MX', null, ['300 MX 10 m.example.test.'])] })).run;
  const denied = await dom('POST', url, { body: { zone_text: text } });
  is(denied, 403, 'forbidden');
  assert.equal(denied.body.errors[0].pointer, undefined);
  // a subdomain master changes RRsets; a bad request; no grant; a text with a NUL
  is(await sub('POST', url, { body: { zone_text: text } }), 403, 'forbidden');
  is(await dom('POST', url, { body: {} }), 400, 'bad-request');
  is(await dom('POST', url, { body: { zone_text: text, mode: 'append' } }), 400, 'bad-request');
  is(await dom('POST', url, { body: { zone_text: 'a\0b' } }), 400, 'bad-request');
  const n0 = t.calls.length;
  for (const gen of ['$GENERATE 1-5 h$ A 192.0.2.1\n', 'www A 192.0.2.1\r\n  $generate 1-100000 x$ A 192.0.2.2\n']) {
    const g = await dom('POST', url, { body: { zone_text: gen } });
    is(g, 400, 'bad-request');
    assert.equal(g.body.errors[0].pointer, '/zone_text');
  }
  assert.equal(t.calls.length, n0, 'none of the refused texts reached a tool');
  is(await dom('POST', '/datasets/main/zones/other.test/import', { body: { zone_text: text } }), 404, 'not-found');
  is(await root('POST', '/datasets/main/zones/other.test/import', { body: { zone_text: text } }), 409, 'presigned-zone');
  // the messages of a zone text carry the line, not a pointer into rrsets
  d.app.run = makeRun(() => exit(1, { stdout: JSON.stringify(applyDoc({ messages: [{ severity: 'error', code: 'zone.syntax', text: 'x: standard input:3: nonsense', file: 'standard input', line: null }] })) })).run;
  const bad = await dom('POST', url, { body: { zone_text: text } });
  is(bad, 422, 'zone-checks-failed');
  assert.deepEqual([bad.body.errors[0].pointer, bad.body.errors[0].line], ['/zone_text', 3]);
}));

test('a body of 16 MiB is read for an import, 1 MiB for anything else', withTools(standard(), async (d, { dom }) => {
  const big = 'x'.repeat(2 << 20);
  // (the server answers 413 and closes the connection while the client is still sending: what fetch reports then may be a reset)
  const refused = await dom('PATCH', PATCH, { body: { comment: big } }).catch((e) => ({ status: 413, body: { type: 'urn:karidns:api:too-large' }, e }));
  is(refused, 413, 'too-large');
  const r = await dom('POST', '/datasets/main/zones/example.test/import', { body: { zone_text: `; ${big}\n` } });
  is(r, 200);
  // 17 MiB: the server answers 413 and closes the connection while the client is still sending (a reset is what fetch reports then)
  const over = await dom('POST', '/datasets/main/zones/example.test/import', { body: { zone_text: 'x'.repeat(17 << 20) } }).catch((e) => ({ status: 413, body: { type: 'urn:karidns:api:too-large' }, e }));
  is(over, 413, 'too-large');
}));

// ---------------------------------------------------------------------------------------------------------------------------------- reload
test('the update button: a zone, or every zone', withTools(standard(), async (d, { root, dom, sub }, t) => {
  const url = '/datasets/main/zones/example.test/reload';
  const r = await dom('POST', url);
  is(r, 200);
  assert.equal(r.body.reload, 'requested');
  assert.deepEqual(t.calls[0].argv, ['-f', CTL_CONF, 'reload', 'example.test']);
  is(await sub('POST', url), 200);
  is(await dom('POST', '/datasets/main/zones/other.test/reload'), 404, 'not-found');
  is(await root('POST', '/datasets/main/zones/ghost.test/reload'), 404, 'not-found');
  // karictl fails: an error, with the reason
  d.app.run = makeRun(() => exit(1, { stderr: 'ERROR no such zone\n' })).run;
  const failed = await root('POST', url);
  is(failed, 503, 'reload-failed');
  assert.match(failed.body.detail, /^failed: ERROR no such zone/);
  const hidden = await dom('POST', url);
  is(hidden, 503, 'reload-failed');
  assert.doesNotMatch(hidden.body.detail, /no such zone/);
  // SQLite3 reloads one named zone, never all
  is(await root('POST', '/datasets/main/reload'), 409, 'unsupported');
  is(await dom('POST', '/datasets/main/reload'), 403, 'forbidden');
  is(await root('POST', '/datasets/nowhere/reload'), 404, 'not-found');
  // a zone kept signed is reloaded by the signer
  await run(d, "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'X-KARIDNS-SIGNER', '1')");
  is(await dom('POST', url), 409, 'signer-managed');
}, { 'karictl-config': CTL_CONF }));


test('no restricted key, no reload button', withTools(standard(), async (d, { dom }) => {
  is(await dom('POST', '/datasets/main/zones/example.test/reload'), 400, 'bad-request');
}));

// ---------------------------------------------------------------------------------------------------------------------------------- metadata
test('metadata: the kinds the API writes, global masters only, audited', withTools(standard(), async (d, { root, dom, sub }) => {
  const url = '/datasets/main/zones/example.test/metadata';
  assert.deepEqual((await dom('GET', url)).body.metadata, []);
  const put = await root('PUT', `${url}/allow-axfr-from`, { body: { content: ['192.0.2.0/24', '2001:db8::/32'] } });
  is(put, 200);
  assert.deepEqual([put.body.kind, put.body.content], ['ALLOW-AXFR-FROM', ['192.0.2.0/24', '2001:db8::/32']]);
  await root('PUT', `${url}/ALSO-NOTIFY`, { body: { content: ['192.0.2.9:5353'] } });
  const list = await dom('GET', url);
  assert.deepEqual(list.body.metadata, [{ kind: 'ALLOW-AXFR-FROM', content: ['192.0.2.0/24', '2001:db8::/32'] }, { kind: 'ALSO-NOTIFY', content: ['192.0.2.9:5353'] }]);
  assert.ok(list.body.writable.includes('X-KARIDNS-PROFILE'));
  // the masters of the whole zone read them; a subdomain master does not (they are about the whole zone: audit, 0.6.2)
  is(await sub('GET', url), 403, 'forbidden');
  // replaced, not added to
  await root('PUT', `${url}/ALLOW-AXFR-FROM`, { body: { content: ['198.51.100.1'] } });
  assert.deepEqual((await sql(d, "SELECT content FROM domainmetadata WHERE kind = 'ALLOW-AXFR-FROM'")).map((r) => r.content), ['198.51.100.1']);
  // removed: a DELETE, or an empty list
  is(await root('DELETE', `${url}/ALLOW-AXFR-FROM`), 200);
  is(await root('PUT', `${url}/ALSO-NOTIFY`, { body: { content: [] } }), 200);
  assert.deepEqual((await dom('GET', url)).body.metadata, []);
  // the audit log has the change set
  const cs = put.body.change_set;
  const rows = await sql(d, 'SELECT principal_name, op, table_name FROM karidns_audit_log WHERE change_set = $1 ORDER BY id', [cs]);
  assert.deepEqual(rows.map((r) => [r.principal_name, r.op, r.table_name]), [['root', 'I', 'domainmetadata'], ['root', 'I', 'domainmetadata']]);
  // what is refused
  for (const kind of ['PRESIGNED', 'NSEC3PARAM', 'X-KARIDNS-SIGNER', 'ENABLE-LUA-RECORDS', 'nonsense']) {
    const r = await root('PUT', `${url}/${kind}`, { body: { content: ['1'] } });
    is(r, 400, 'bad-request');
    assert.equal(r.body.errors[0].pointer, '/kind');
  }
  is(await root('DELETE', `${url}/PRESIGNED`), 400, 'bad-request');
  const badValue = await root('PUT', `${url}/ALLOW-AXFR-FROM`, { body: { content: ['192.0.2.1', 'AUTO-NS'] } });
  is(badValue, 400, 'bad-request');
  assert.match(badValue.body.errors[0].text, /value 1/);
  is(await root('PUT', `${url}/ALLOW-AXFR-FROM`, { body: {} }), 400, 'bad-request');
  is(await root('PUT', `${url}/ALLOW-AXFR-FROM`, { body: { content: [''] } }), 400, 'bad-request');
  is(await dom('PUT', `${url}/ALLOW-AXFR-FROM`, { body: { content: ['192.0.2.1'] } }), 403, 'forbidden');
  is(await dom('DELETE', `${url}/ALLOW-AXFR-FROM`), 403, 'forbidden');
  is(await root('PUT', '/datasets/main/zones/ghost.test/metadata/ALSO-NOTIFY', { body: { content: [] } }), 404, 'not-found');
  is(await dom('GET', '/datasets/main/zones/other.test/metadata'), 404, 'not-found');
}));

// ---------------------------------------------------------------------------------------------------------------------------------- DNSSEC
test('DNSSEC: the keys and DS records from the DNSKEY RRset, key requests for the signer', withTools(standard(), async (d, { root, dom, sub }) => {
  const url = '/datasets/main/zones/example.test/dnssec';
  const key = '257 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==';
  await run(d, "INSERT INTO records (domain_id, name, type, content, ttl) VALUES (1, 'example.test', 'DNSKEY', $1, 3600)", [key]);
  await run(d, "INSERT INTO cryptokeys (domain_id, flags, active, published, content) VALUES (1, 257, 1, 1, 'PRIVATE')");
  const r = await dom('GET', url);
  is(r, 200);
  const x = r.body.dnssec;
  assert.deepEqual([x.signed, x.signer, x.presigned, x.waiting_for_signer], [false, false, false, false]);
  assert.deepEqual(x.keys.map((k) => [k.flags, k.algorithm, k.sep]), [[257, 5, true]]);
  assert.equal(x.keys[0].key_tag, 60486);
  assert.deepEqual(x.ds.map((s) => [s.digest_type, s.digest.length]), [[2, 64], [4, 96]]);
  assert.deepEqual(x.cryptokeys, [{ id: 1, flags: 257, active: true, published: true }]);
  assert.ok(!JSON.stringify(r.body).includes('PRIVATE'), 'no key material');
  is(await sub('GET', url), 403, 'forbidden');
  is(await dom('GET', '/datasets/main/zones/other.test/dnssec'), 404, 'not-found');
  is(await root('GET', '/datasets/main/zones/ghost.test/dnssec'), 404, 'not-found');
  // requests: enable signing
  const post = (as, body) => as('POST', `${url}/requests`, { body });
  const enable = await post(dom, { kind: 'enable', algorithm: 14, nsec: 'nsec3' });
  is(enable, 201);
  assert.deepEqual([enable.body.request.state, enable.body.request.algorithm, enable.body.request.key_type, enable.body.request.nsec, enable.body.request.kind], ['pending', 14, 'csk', 'nsec3', 'enable']);
  const me = (await sql(d, "SELECT id FROM auth.principals WHERE name = 'dom'"))[0].id;
  assert.equal(enable.body.request.requested_by, me);
  is(await post(dom, { kind: 'enable' }), 409, 'request-pending');
  assert.equal((await dom('GET', url)).body.dnssec.requests.length, 1);
  await run(d, "UPDATE karidns_key_requests SET state = 'done', done_at = '2026-11-08T00:00:00Z'");
  // enable again: the zone is not kept by the signer yet; with the metadata it is
  await run(d, "INSERT INTO domainmetadata (domain_id, kind, content) VALUES (1, 'X-KARIDNS-SIGNER', '1')");
  is(await post(root, { kind: 'enable' }), 409, 'already-signed');
  const add = await post(root, { kind: 'add', algorithm: 8, bits: 2048, key_type: 'zsk' });
  is(add, 201);
  assert.equal(add.body.request.bits, 2048);
  assert.equal((await dom('GET', url)).body.dnssec.waiting_for_signer, true, 'the signer has not signed the serial yet');
  await run(d, "UPDATE karidns_key_requests SET state = 'failed', message = 'no', done_at = '2026-11-08T00:00:00Z'");
  await run(d, "DELETE FROM domainmetadata WHERE kind = 'X-KARIDNS-SIGNER'");
  is(await post(root, { kind: 'add' }), 409, 'not-signed');
  // the checks
  is(await post(sub, { kind: 'enable' }), 403, 'forbidden');
  is(await post(dom, {}), 400, 'bad-request');
  is(await post(dom, { kind: 'rotate' }), 400, 'bad-request');
  is(await post(dom, { kind: 'enable', algorithm: 9 }), 400, 'bad-request');
  is(await post(dom, { kind: 'enable', algorithm: 12 }), 400, 'bad-request');
  is(await post(dom, { kind: 'enable', algorithm: 13, bits: 2048 }), 400, 'bad-request');
  is(await post(dom, { kind: 'enable', bits: 100 }), 400, 'bad-request');
  is(await post(dom, { kind: 'add', nsec: 'nsec' }), 400, 'bad-request');
  is(await post(dom, { kind: 'enable', key_type: 'zzz' }), 400, 'bad-request');
  is(await d.as({})('POST', `${url}/requests`, { body: { kind: 'enable' } }), 401);
  is(await post(root, { kind: 'enable' }), 201);
  is(await post(dom, { kind: 'enable' }), 409, 'request-pending');
  is(await dom('POST', '/datasets/main/zones/slave.test/dnssec/requests', { body: { kind: 'enable' } }), 404, 'not-found');
  is(await root('POST', '/datasets/main/zones/slave.test/dnssec/requests', { body: { kind: 'enable' } }), 409, 'zone-not-editable');
}));

test('readBody: the body, the limit, a stream that fails, a client that goes', async () => {
  const fake = (headers = {}) => Object.assign(new EventEmitter(), { headers, complete: false, destroyed: false, destroy() { this.destroyed = true; } });
  const a = fake();
  const p = readBody(a, 10, 1000);
  a.emit('data', Buffer.from('abc'));
  a.emit('data', Buffer.from('def'));
  a.emit('end');
  assert.equal((await p).toString(), 'abcdef');
  assert.equal(a.listenerCount('data') + a.listenerCount('error') + a.listenerCount('close') + a.listenerCount('end'), 0, 'no listener is left');
  const b = fake();
  const q = readBody(b, 4, 1000);
  b.emit('data', Buffer.from('abcde'));
  await assert.rejects(q, (e) => e.status === 413);
  // ... the rest of the body is thrown away, up to 64 MiB; an error of the stream then is nobody's business
  b.emit('data', Buffer.alloc(1 << 20));
  assert.equal(b.destroyed, false);
  b.emit('error', new Error('late'));
  b.emit('data', Buffer.alloc(64 << 20));
  assert.equal(b.destroyed, true);
  const c = fake();
  const r = readBody(c, 10, 1000);
  c.emit('error', new Error('boom'));
  await assert.rejects(r, /boom/);
  const d = fake();
  const s = readBody(d, 10, 1000);
  d.emit('close');
  await assert.rejects(s, /closed the connection/);
  await assert.rejects(readBody(fake({ 'content-length': '999' }), 10, 1000), (e) => e.status === 413);
  await assert.rejects(readBody(fake({ 'content-length': 'x' }), 10, 1000), (e) => e.status === 413);
  const e = fake();
  e.complete = true;
  const t = readBody(e, 10, 1000);
  e.emit('close');                      // a body that arrived whole and the connection closed after it is not an error
  e.emit('end');
  assert.equal((await t).length, 0);
  await assert.rejects(readBody(fake(), 10, 20), (x) => x.status === 408);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the request timeout
test('a body that does not arrive in time is a 408, a route can have more time', async () => {
  const d = await deploy();
  const router = new Router([
    { method: 'POST', path: '/slow', auth: 'none', readTimeoutMs: 150, handler: () => ({ ok: true }) },
    { method: 'POST', path: '/patient', auth: 'none', readTimeoutMs: 2000, handler: (ctx) => ({ got: ctx.body }) },
  ]);
  const server = await listen(d.app, router);
  try {
    const port = server.address().port;
    const talk = (path, parts, gap) => new Promise((resolve) => {
      const s = net.connect(port, '127.0.0.1');
      let out = '';
      s.on('data', (x) => { out += x; });
      s.on('close', () => resolve(out));
      s.write(`POST /api/v1${path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n`);
      let i = 0;
      const next = () => {
        if (i < parts.length) { s.write(parts[i++]); setTimeout(next, gap); } else setTimeout(() => s.end(), 150);
      };
      next();
    });
    const slow = await talk('/slow', ['{"a"', ':1}'], 250);
    assert.match(slow, /^HTTP\/1\.1 408 /);
    assert.match(slow, /urn:karidns:api:request-timeout/);
    assert.match(slow, /Connection: close/i);
    const patient = await talk('/patient', ['{"a"', ':1}'], 100);
    assert.match(patient, /^HTTP\/1\.1 200 /);
    assert.match(patient, /"got":\{"a":1\}/);
    // a client that goes away in the middle of a body
    const gone = await new Promise((resolve) => {
      const s = net.connect(port, '127.0.0.1');
      s.on('close', () => resolve('closed'));
      s.write('POST /api/v1/patient HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{"a"');
      setTimeout(() => s.destroy(), 100);
    });
    assert.equal(gone, 'closed');
  } finally {
    await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
    await d.close();
  }
});

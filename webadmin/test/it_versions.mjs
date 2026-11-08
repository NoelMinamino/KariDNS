// The integration driver of the history and the templates of karidns-webadmin (E, M4), the same scenarios on SQLite3 and on PostgreSQL.  Not a node:test file:
// tests/run_webadmin_versions_test.sh and tests/run_webadmin_versions_pg_test.sh start a real karidns (with karidns-dbloader), the real karidns-zone and karicheck and
// the API on a real port, and run this against them.  It writes through the API (and, for what happens outside it, through SQL), reloads, and looks at what the DNS
// server answers (`dag`).
//
//   IT_BASE=http://127.0.0.1:PORT/api/v1 IT_ORIGIN=... IT_ADMIN_PASSWORD=... IT_DNS_PORT=... IT_DAG=./dag IT_SQL=<script: SQL on stdin> IT_DB=sqlite|pg
//   node webadmin/test/it_versions.mjs
//
// The zones: example.test (a domain master `dom`, a subdomain master `sub` on sub.example.test), signed.test (kept by the signer: the metadata X-KARIDNS-SIGNER; the
// signer's own writes are made here with SQL), tpl.test (made from a template).  Prints "  [ OK ] ..." / "  [FAIL] ..." lines; exits 1 when anything failed.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';

const BASE = process.env.IT_BASE;
const ORIGIN = process.env.IT_ORIGIN;
const PORT = process.env.IT_DNS_PORT;
const DAG = process.env.IT_DAG;
const SQL = process.env.IT_SQL;
const PG = process.env.IT_DB === 'pg';
let pass = 0;
let fails = 0;
const ok = (name) => { pass++; console.log(`  [ OK ] ${name}`); };
const bad = (name, why) => { fails++; console.log(`  [FAIL] ${name}${why ? ` (${why})` : ''}`); };
const check = (name, cond, why) => (cond ? ok(name) : bad(name, typeof why === 'function' ? why() : why));
const eq = (name, got, want) => check(name, JSON.stringify(got) === JSON.stringify(want), () => `got ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// SQLite3's audit log and versions have the resolution of a second: a change "after" another is made after a pause
const tick = () => sleep(PG ? 50 : 2200);

async function call(method, p, { body, cookie, csrf, origin } = {}) {
  const h = {};
  if (cookie) h.Cookie = `karidns_session=${cookie}`;
  if (csrf) h['X-KariDNS-CSRF'] = csrf;
  if (origin) h.Origin = origin;
  let payload;
  if (body !== undefined) { payload = JSON.stringify(body); h['Content-Type'] = 'application/json'; }
  const res = await fetch(BASE + p, { method, headers: h, body: payload });
  const text = await res.text();
  let parsed = text;
  if (/json/.test(res.headers.get('content-type') ?? '')) parsed = JSON.parse(text);
  return { status: res.status, headers: res.headers, body: parsed, text };
}
async function login(user, password) {
  const r = await call('POST', '/auth/login', { body: { user, password } });
  const m = /karidns_session=([^;]+)/.exec(r.headers.get('set-cookie') ?? '');
  if (r.status !== 200) bad(`login ${user}`, `${r.status} ${r.text}`);
  const s = { cookie: m?.[1], csrf: r.body?.csrf };
  return (method, p, o = {}) => call(method, p, { cookie: s.cookie, csrf: s.csrf, origin: ORIGIN, ...o });
}
const type = (r) => r.body?.type?.replace('urn:karidns:api:', '');

// ---- SQL behind the API's back (what a signer, a script or an operator with psql does)
function sql(text) {
  const r = spawnSync(SQL, { input: text, encoding: 'utf8' });
  if (r.status !== 0) bad('SQL', `${text.slice(0, 80)}: ${r.stderr}`);
  return r.stdout.trim();
}

// ---- the DNS server
const dagArgs = (name, t) => ['@127.0.0.1', '-p', PORT, name, t, '+nohexdump', '+time=2', '+tries=1'];
const answer = (name, t = 'A') => spawnSync(DAG, [...dagArgs(name, t), '+short'], { encoding: 'utf8' }).stdout.trim().split('\n').filter(Boolean).sort().join(',');
async function waitAnswer(what, name, want, secs = 15, t = 'A') {
  const end = Date.now() + secs * 1000;
  let got;
  while (Date.now() < end) {
    got = answer(name, t);
    if (got === want) { ok(what); return true; }
    await sleep(150);
  }
  bad(what, `the server answers ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);
  return false;
}

const rr = (name, t, ttl, ...contents) => ({ name, type: t, changetype: 'REPLACE', ttl, records: contents.map((content) => ({ content })) });
const del = (name, t) => ({ name, type: t, changetype: 'DELETE' });
const contents = (rrset) => (rrset ?? []).map((x) => x.content).sort();

// ---------------------------------------------------------------------------------------------------------------------------------- the cast
console.log('-- the cast: policies, users, grants');
const admin = await login('admin', process.env.IT_ADMIN_PASSWORD);
const mk = async (p, body) => {
  const r = await admin('POST', p, { body });
  if (r.status !== 201) bad(`POST ${p}`, `${r.status} ${r.text}`);
  return r.body;
};
const web = (await mk('/rr-policies', { name: 'web', allowed_types: ['A', 'AAAA', 'CNAME', 'TXT', 'MX'], ttl_min: 30, ttl_max: 86400 })).policy.id;
const dom = (await mk('/principals', { kind: 'user', name: 'dom', password: 'Sunrise-Harbor-42' })).principal.id;
const sub = (await mk('/principals', { kind: 'user', name: 'sub', password: 'Maple-Anchor-77' })).principal.id;
await mk('/grants', { principal: dom, role: 'domain_master', zone: 'example.test', policy: web });
await mk('/grants', { principal: sub, role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policy: web });
const D = await login('dom', 'Sunrise-Harbor-42');
const U = await login('sub', 'Maple-Anchor-77');
const Z = '/datasets/main/zones/example.test';
const V = `${Z}/versions`;
const PATCH = `${Z}/rrsets`;
const versions = async (as = admin, zone = Z) => (await as('GET', `${zone}/versions?limit=500`)).body;
const rrsetOf = async (name, t, zone = Z) => (await admin('GET', `${zone}/rrsets?name=${name}&type=${t}`)).body.rrsets?.[0]?.records;
const serialOf = async (zone = Z) => (await admin('GET', zone)).body.zone.serial;

// ---------------------------------------------------------------------------------------------------------------------------------- versions written by the API and by an operator
console.log('-- the history: an operator\'s import, then changes through the API');
const v0 = await versions();
eq('the operator\'s import of the zone is version 1 (kind import, no principal)', [v0.versions.length, v0.versions[0]?.version, v0.versions[0]?.kind, v0.versions[0]?.principal, typeof v0.versions[0]?.db_role], [1, 1, 'import', null, 'string']);
check('...with its RRsets in the delta', v0.versions[0].rrsets >= 8 && v0.versions[0].delta_complete === true, () => JSON.stringify(v0.versions[0]));
const s1 = await serialOf();
const c2 = await D('PATCH', PATCH, { body: { comment: 'move www', rrsets: [rr('www.example.test', 'A', 300, '192.0.2.77')] } });
const c3 = await admin('PATCH', PATCH, { body: { comment: 'more', rrsets: [rr('new.example.test', 'A', 300, '192.0.2.60'), rr('txt.example.test', 'TXT', 300, '"hello world"'), del('evilsub.example.test', 'A')] } });
const c4 = await U('PATCH', PATCH, { body: { rrsets: [rr('a.sub.example.test', 'TXT', 300, '"bye"')] } });
eq('three changes through the API are versions 2 to 4', [c2.body.version, c3.body.version, c4.body.version], [2, 3, 4]);
const h = await versions();
eq('the list is newest first, with who and when', h.versions.map((v) => [v.version, v.kind, v.principal?.name ?? null]), [[4, 'edit', 'sub'], [3, 'edit', 'admin'], [2, 'edit', 'dom'], [1, 'import', null]]);
eq('...the change set of each is the one the answer named, the comment is kept', [h.versions[2].change_set, h.versions[1].change_set, h.versions[2].comment], [c2.body.change_set, c3.body.change_set, 'move www']);
eq('...the serial: one more with each version', h.versions.map((v) => v.serial.after).reverse(), [s1, s1 + 1, s1 + 2, s1 + 3]);
eq('...no change outside the versions so far', [h.versions.map((v) => v.changed_outside_before), h.changed_outside_since], [[null, null, null, null], null]);
const g2 = await admin('GET', `${V}/2`);
eq('the delta of version 2: the RRset before and after, as the exporter writes it', g2.body.rrsets, [{ name: 'www.example.test.', type: 'A', change: 'replace', before: [{ ttl: 300, content: '192.0.2.10' }, { ttl: 300, content: '192.0.2.11' }], after: [{ ttl: 300, content: '192.0.2.77' }] }]);
const g3 = await admin('GET', `${V}/3`);
eq('...version 3: an RRset added, one added, one deleted', g3.body.rrsets.map((x) => [x.name, x.change]), [['evilsub.example.test.', 'delete'], ['new.example.test.', 'add'], ['txt.example.test.', 'add']]);
const d14 = await admin('GET', `${V}/1/diff?to=4`);
eq('the diff of versions 1 and 4: every RRset the later versions touched, at the two ends', d14.body.rrsets.map((x) => [x.name, x.type, x.change]), [['a.sub.example.test.', 'TXT', 'replace'], ['evilsub.example.test.', 'A', 'delete'], ['new.example.test.', 'A', 'add'], ['txt.example.test.', 'TXT', 'add'], ['www.example.test.', 'A', 'replace']]);
eq('...the SOA is not in it (its serial is not versioned)', d14.body.rrsets.some((x) => x.type === 'SOA'), false);
eq('the diff of 2 and 3', (await admin('GET', `${V}/2/diff?to=3`)).body.rrsets.map((x) => x.name), ['evilsub.example.test.', 'new.example.test.', 'txt.example.test.']);
const dc = await admin('GET', `${V}/1/diff?to=current`);
eq('the diff against the zone as it is says the same (nothing changed outside the versions)', dc.body.rrsets.map((x) => [x.name, x.type, x.change, contents(x.before), contents(x.after)]), d14.body.rrsets.map((x) => [x.name, x.type, x.change, contents(x.before), contents(x.after)]));
const sv = await U('GET', `${V}?limit=500`);
eq('a subdomain master sees the versions, and of each the part under its suffix', sv.body.versions.slice(0, 3).map((v) => [v.version, v.rrsets]), [[4, 1], [3, 0], [2, 0]]);
check('...of the import its names and the apex SOA and NS', sv.body.versions[3].rrsets >= 3 && sv.body.versions[3].rrsets < v0.versions[0].rrsets, () => `${sv.body.versions[3].rrsets} of ${v0.versions[0].rrsets}`);
check('...and no marker about changes outside the versions (it cannot read the audit log)', sv.body.versions.every((v) => !('changed_outside_before' in v)) && !('changed_outside_since' in sv.body));
eq('...and a diff of its names', (await U('GET', `${V}/1/diff?to=4`)).body.rrsets.map((x) => x.name), ['a.sub.example.test.']);
eq('a zone without a grant has no history for a domain master', type(await D('GET', '/datasets/main/zones/signed.test/versions')), 'not-found');
eq('...a version that is not there', type(await admin('GET', `${V}/99`)), 'not-found');

// ---------------------------------------------------------------------------------------------------------------------------------- rollback
console.log('-- rollback: a new change set that restores the RRsets');
const dry = await admin('POST', `${V}/1/rollback`, { body: { dry_run: true } });
eq('a dry run: allowed, nothing in conflict, what would change', [dry.status, dry.body.dry_run, dry.body.allowed, dry.body.conflicts, dry.body.diff?.length, dry.body.restored], [200, true, true, undefined, 5, 5]);
eq('...and nothing was written', (await versions()).versions.length, 4);
eq('a subdomain master rolls back its own names (version 4 -> 3)', [(await U('POST', `${V}/3/rollback`, { body: { comment: 'oops' } })).status, contents(await rrsetOf('a.sub.example.test', 'TXT'))], [200, ['"hello"']]);
const h5 = (await versions()).versions[0];
eq('...version 5: kind rollback of 3, by sub, with the comment', [h5.version, h5.kind, h5.rollback_of, h5.principal.name, h5.comment], [5, 'rollback', 3, 'sub', 'rollback to version 3: oops']);
eq('...a rollback is a version like the others: the serial grew', h5.serial.after, s1 + 4);
const subAll = await U('POST', `${V}/1/rollback`, { body: {} });
eq('a subdomain master rolls back what it can see: its names are as the history left them, so there is nothing to restore (the rest of the zone is not its business)', [subAll.status, subAll.body.committed, subAll.body.restored], [200, false, 1]);
const apexTxt = await admin('PATCH', PATCH, { body: { rrsets: [rr('example.test', 'TXT', 300, '"apex"')] } });
eq('version 6: a global master writes at the apex', [apexTxt.status, apexTxt.body.version], [200, 6]);
const denied = await D('POST', `${V}/5/rollback`, { body: {} });
eq('a domain master cannot roll back an apex change (its policy has no apex): 403, the RRset named', [denied.status, type(denied), /TXT example\.test\./.test(denied.body.errors?.[0]?.text ?? '')], [403, 'forbidden', true]);
eq('...a dry run says so as a verdict', (await D('POST', `${V}/5/rollback`, { body: { dry_run: true } })).body.allowed, false);
eq('...and nothing was written', (await versions()).versions.length, 6);

console.log('-- rollback: conflicts');
await tick();
sql("UPDATE records SET content = '192.0.2.250' WHERE name = 'www.example.test' AND content = '192.0.2.77'");
await tick();
const conf = await admin('POST', `${V}/1/rollback`, { body: {} });
eq('www.example.test was changed with SQL after version 2: 409, the RRset listed with what the version left and what is there', [conf.status, type(conf), conf.body.errors?.map((e) => [e.name, e.type, contents(e.expected), contents(e.current)])], [409, 'version-conflict', [['www.example.test.', 'A', ['192.0.2.77'], ['192.0.2.250']]]]);
eq('...nothing was written', (await versions()).versions.length, 6);
const cdry = await admin('POST', `${V}/1/rollback`, { body: { dry_run: true } });
eq('...a dry run lists the conflict and shows what a forced rollback would do', [cdry.status, cdry.body.conflicts?.length, cdry.body.allowed, cdry.body.diff?.length], [200, 1, true, 5]);
const vlist = await versions();
check('the version list says the zone was changed outside the versions, and what', vlist.versions[0].changed_outside_before === null && vlist.changed_outside_since?.basis === 'audit' && vlist.changed_outside_since.rrsets?.[0]?.name === 'www.example.test.', () => JSON.stringify([vlist.versions[0].changed_outside_before, vlist.changed_outside_since]));
const dv = await versions(D);
check('...a domain master reads the audit log of its zone, so it sees the same marker; a subdomain master none', dv.changed_outside_since?.basis === 'audit' && dv.changed_outside_since.rrsets?.[0]?.name === 'www.example.test.' && !('changed_outside_since' in (await versions(U))), () => JSON.stringify(dv.changed_outside_since));
const dcur = await admin('GET', `${V}/1/diff?to=current`);
eq('...the diff against the zone shows www.example.test as it is now', contents(dcur.body.rrsets.find((x) => x.name === 'www.example.test.')?.after), ['192.0.2.250']);
const forced = await admin('POST', `${V}/1/rollback`, { body: { force: true, comment: 'back to the import', reload: true } });
eq('force: true restores it anyway', [forced.status, forced.body.committed, forced.body.version, forced.body.rollback_of, forced.body.reload], [200, true, 7, 1, 'requested']);
eq('...the zone is as the import left it (but for the SOA serial, which only grows)', [contents(await rrsetOf('www.example.test', 'A')), await rrsetOf('new.example.test', 'A'), await rrsetOf('evilsub.example.test', 'A') !== undefined, await rrsetOf('example.test', 'TXT')],
  [['192.0.2.10', '192.0.2.11'], undefined, true, undefined]);
await waitAnswer('...the server answers the old addresses after the reload', 'www.example.test', '192.0.2.10,192.0.2.11');
await waitAnswer('...evilsub.example.test is served again', 'evilsub.example.test', '192.0.2.30');
eq('...the serial', await serialOf() > s1 + 5, true);
const vl2 = await versions();
eq('...and the history says the zone was changed outside the versions before this rollback, not before the others', [vl2.versions[0].changed_outside_before?.basis, vl2.versions[0].changed_outside_before?.rrsets?.map((x) => x.name), vl2.versions.slice(1).every((v) => v.changed_outside_before === null), vl2.changed_outside_since],
  ['audit', ['www.example.test.'], true, null]);
const c8 = await admin('PATCH', PATCH, { body: { rrsets: [rr('www.example.test', 'A', 300, '192.0.2.88')] } });
const r9 = await admin('POST', `${V}/7/rollback`, { body: {} });
eq('version 8 changes www, version 9 rolls back to 7', [c8.body.version, r9.body.version, r9.body.rollback_of, contents(await rrsetOf('www.example.test', 'A'))], [8, 9, 7, ['192.0.2.10', '192.0.2.11']]);
const r10 = await admin('POST', `${V}/8/rollback`, { body: {} });
eq('a rollback of a rollback is an ordinary rollback to an earlier version (to 8: before the rollback)', [r10.body.version, r10.body.rollback_of, contents(await rrsetOf('www.example.test', 'A'))], [10, 8, ['192.0.2.88']]);
eq('the newest version is rolled back to: nothing to do', (await admin('POST', `${V}/10/rollback`, { body: {} })).body.committed, false);

// ---------------------------------------------------------------------------------------------------------------------------------- the signer
console.log('-- the signer re-signs: its writes are no change outside the versions');
await tick();
// what karidns-signer does to a signed zone: signatures, the NSEC chain, ordername / auth of the records, the serial of the SOA
sql("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.example.test', 'RRSIG', 'A 13 3 300 20350101000000 20250101000000 1 example.test. AAAA', 300, 0, false FROM domains WHERE name = 'example.test'");
sql("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.example.test', 'NSEC', 'x.example.test. A RRSIG NSEC', 300, 0, false FROM domains WHERE name = 'example.test'");
sql("UPDATE records SET ordername = 'abc', auth = true WHERE name = 'www.example.test' AND type = 'A'");
sql("UPDATE records SET content = 'ns1.example.test hostmaster.example.test 4000 7200 3600 1209600 300' WHERE type = 'SOA' AND name = 'example.test'");
await tick();
const sg = await admin('PATCH', PATCH, { body: { rrsets: [rr('after.example.test', 'A', 300, '192.0.2.99')] } });
eq('a change through the API after the signer\'s writes', [sg.status, sg.body.committed], [200, true]);
const vl3 = await versions();
eq('...the gap in the generation is there but nothing in it is a change of the RRsets: no marker', [vl3.versions[0].generation.before > vl3.versions[1].generation.after, vl3.versions[0].changed_outside_before, vl3.changed_outside_since], [true, null, null]);
eq('...and the signer\'s records are not in any version', (await admin('GET', `${V}/${vl3.versions[0].version}`)).body.rrsets.map((x) => x.type), ['A']);
eq('...the serial the API raised comes from the SOA the signer left', await serialOf() > 4000, true);

console.log('-- a zone the signer keeps signed: rollback is unsigned data, the signer signs it');
const SG = '/datasets/main/zones/signed.test';
const before = answer('www.signed.test');
const sg2 = await admin('PATCH', `${SG}/rrsets`, { body: { reload: true, rrsets: [rr('www.signed.test', 'A', 300, '192.0.2.21')] } });
eq('a change is committed and the API waits for the signer', [sg2.status, sg2.body.reload], [200, 'waiting for the signer']);
sql("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.signed.test', 'RRSIG', 'A 13 3 300 20350101000000 20250101000000 1 signed.test. AAAA', 300, 0, false FROM domains WHERE name = 'signed.test'");
const rb = await admin('POST', `${SG}/versions/1/rollback`, { body: { reload: true } });
eq('the rollback is committed; no reload request: the API says it waits for the signer', [rb.status, rb.body.committed, rb.body.reload], [200, true, 'waiting for the signer']);
eq('...the signer\'s signature is untouched, the data is back', [sql("SELECT count(*) FROM records r JOIN domains d ON d.id = r.domain_id WHERE d.name = 'signed.test' AND r.type = 'RRSIG'"), contents(await rrsetOf('www.signed.test', 'A', SG))], ['1', ['192.0.2.20']]);
await sleep(2500);
eq('...the server still serves what it served before (the signer asks for the reload when it has signed)', answer('www.signed.test'), before);
eq('...the zone says it is waiting for the signer', (await admin('GET', SG)).body.zone.waiting_for_signer, true);
if (PG) eq('...no reload request for it in the database', sql("SELECT count(*) FROM karidns_reload_requests WHERE zone = 'signed.test'"), '0');
eq('the update button refuses (S-5)', type(await admin('POST', `${SG}/reload`)), 'signer-managed');

// ---------------------------------------------------------------------------------------------------------------------------------- the real signer
if (process.env.IT_SIGNER) {
  console.log('-- the real karidns-signer signs a zone through the API, and a change and a rollback are signed again');
  const RZ = '/datasets/main/zones/real.test';
  const waitUntil = async (what, fn, secs = 90) => {
    const end = Date.now() + secs * 1000;
    while (Date.now() < end) {
      if (await fn()) { ok(what); return true; }
      await sleep(300);
    }
    bad(what, 'the condition did not come true');
    return false;
  };
  const signed = async () => { const z = (await admin('GET', RZ)).body.zone; return z.signer === true && z.waiting_for_signer === false; };
  const kr = await admin('POST', `${RZ}/dnssec/requests`, { body: { kind: 'enable', algorithm: 13 } });
  eq('keys are asked for through the API', [kr.status, kr.body.request?.state], [201, 'pending']);
  await waitUntil('the signer signs the zone (the zone info says it has signed the current serial)', signed);
  const gen = (await admin('GET', RZ)).body.zone.generation;
  const r1 = await versions(admin, RZ);
  eq('the history has the operator\'s import only: the signer\'s writes are no versions', r1.versions.map((v) => [v.version, v.kind]), [[1, 'import']]);
  eq('...the generation moved all the same, and the list calls that no change outside the versions', [gen > r1.versions[0].generation.after, r1.changed_outside_since], [true, null]);
  const sc = await admin('PATCH', `${RZ}/rrsets`, { body: { reload: true, rrsets: [rr('www.real.test', 'A', 300, '192.0.2.99')] } });
  eq('a change is version 2 and waits for the signer', [sc.status, sc.body.version, sc.body.reload], [200, 2, 'waiting for the signer']);
  await waitUntil('...the signer signs it', signed);
  await waitAnswer('...and the server serves it once it is signed', 'www.real.test', '192.0.2.99', 30);
  check('...with its signature', spawnSync(DAG, [...dagArgs('www.real.test', 'A'), '+dnssec'], { encoding: 'utf8' }).stdout.includes('RRSIG'));
  const r2 = await versions(admin, RZ);
  eq('the first signing lies between versions 1 and 2: it is no change outside the versions', [r2.versions.map((v) => v.changed_outside_before), r2.changed_outside_since], [[null, null], null]);
  const rb2 = await admin('POST', `${RZ}/versions/1/rollback`, { body: { reload: true } });
  eq('a rollback to version 1 is committed and waits for the signer', [rb2.status, rb2.body.committed, rb2.body.version, rb2.body.reload], [200, true, 3, 'waiting for the signer']);
  await waitUntil('...the signer signs it', signed);
  await waitAnswer('...and the server serves the old address', 'www.real.test', '192.0.2.2', 30);
  const r3 = await versions(admin, RZ);
  eq('...the re-signing is no change outside the versions either', [r3.versions.map((v) => [v.version, v.kind, v.changed_outside_before]), r3.changed_outside_since], [[[3, 'rollback', null], [2, 'edit', null], [1, 'import', null]], null]);
  const ex = await admin('GET', `${RZ}/export`);
  const file = `${process.env.IT_TMP}/real.test.zone`;
  fs.writeFileSync(file, ex.text);
  const vf = spawnSync(process.env.IT_VERIFY, ['-z', '-o', 'real.test', file], { encoding: 'utf8' });
  check('...BIND\'s dnssec-verify accepts the zone as the database exports it after the rollback', vf.status === 0, () => vf.stdout + vf.stderr);
  eq('the DNSSEC records are not in any version', (await admin('GET', `${RZ}/versions/3`)).body.rrsets.map((x) => x.type), ['A']);
}

// ---------------------------------------------------------------------------------------------------------------------------------- templates
console.log('-- templates');
const TPL = {
  name: 'basic', description: 'mail and web', soa: { mname: 'ns1.nsprovider.test', rname: 'hostmaster.nsprovider.test', refresh: 1800, minimum: 120 },
  records: [
    { owner: '@', type: 'NS', content: 'ns1.nsprovider.test.' }, { owner: '@', type: 'NS', content: 'ns2.nsprovider.test.' }, { owner: '@', type: 'MX', content: '10 mail' },
    { owner: 'mail', type: 'A', ttl: 600, content: '192.0.2.40' }, { owner: 'www', type: 'A', ttl: 600, content: '192.0.2.41' }, { owner: '@', type: 'TXT', content: '"v=spf1 -all"' },
    { owner: '_dmarc', type: 'TXT', content: '"v=DMARC1; p=reject"' },
  ],
};
const bt = await admin('POST', '/templates', { body: { name: 'broken', records: [{ owner: 'www', type: 'CNAME', content: 'x.example.test.' }, { owner: 'www', type: 'A', content: '192.0.2.1' }] } });
eq('a template with a CNAME beside other data is refused by karicheck: 422, the record named', [bt.status, type(bt), bt.body.errors?.some((e) => e.severity === 'error' && /cname/i.test(`${e.code} ${e.text}`))], [422, 'template-checks-failed', true]);
eq('...it was not stored', (await admin('GET', '/templates')).body.templates.length, 0);
const foo = await admin('POST', '/templates', { body: { name: 'x', records: [{ owner: '@', type: 'FOO', content: 'x' }] } });
eq('a template that uses a record type nobody knows is a 400, with a pointer', [foo.status, foo.body.errors?.[0]?.pointer], [400, '/records/0/type']);
const tc = await admin('POST', '/templates', { body: TPL });
eq('a valid template is stored (201)', [tc.status, tc.body.template.name, tc.body.template.records.length], [201, 'basic', 7]);
const tid = tc.body.template.id;
eq('...a domain master reads it, and the list', [(await D('GET', `/templates/${tid}`)).status, (await D('GET', '/templates')).body.templates.map((t) => [t.name, t.record_count])], [200, [['basic', 7]]]);
eq('...only a global master changes templates', [type(await D('POST', '/templates', { body: { name: 'mine' } })), type(await D('PATCH', `/templates/${tid}`, { body: { description: 'x' } })), type(await D('DELETE', `/templates/${tid}`))], ['forbidden', 'forbidden', 'forbidden']);
const rev0 = tc.body.template.revision;
const tu = await admin('PATCH', `/templates/${tid}`, { body: { description: 'mail, web and policy' } });
eq('an update raises the revision', [tu.status, tu.body.template.revision > rev0], [200, true]);
const tv = await admin('POST', `/templates/${tid}/validate`);
eq('validate: the stored template through karicheck again', [tv.status, tv.body.valid, tv.body.template.name], [200, true, 'basic']);

console.log('-- a zone is made from a template');
const today = new Date();
const ymd = `${today.getUTCFullYear()}${String(today.getUTCMonth() + 1).padStart(2, '0')}${String(today.getUTCDate()).padStart(2, '0')}`;
const nz = await admin('POST', '/datasets/main/zones', { body: { name: 'tpl.test', template: 'basic', comment: 'for a customer', reload: true } });
eq('POST zones with a template (the SOA values and the records are the template\'s)', [nz.status, nz.body.committed, nz.body.version, nz.body.serial?.after >= Number(`${ymd}00`)], [201, true, 1, true]);
const tz = '/datasets/main/zones/tpl.test';
eq('...the serial is the day, YYYYMMDD00 (A-17)', String(nz.body.serial?.after).startsWith(ymd) || String(nz.body.serial?.after).startsWith(String(Number(ymd) - 1)), true);
eq('...the records of the template are in the zone, relative names resolved against it', [contents(await rrsetOf('www.tpl.test', 'A', tz)), contents(await rrsetOf('tpl.test', 'MX', tz)), contents(await rrsetOf('tpl.test', 'NS', tz))], [['192.0.2.41'], ['10 mail.tpl.test'], ['ns1.nsprovider.test', 'ns2.nsprovider.test']]);
eq('...a record without TTL has the default of 3600, one with TTL its own', [(await admin('GET', `${tz}/rrsets?name=tpl.test&type=MX`)).body.rrsets[0].ttl, (await admin('GET', `${tz}/rrsets?name=www.tpl.test&type=A`)).body.rrsets[0].ttl], [3600, 600]);
const tvr = (await versions(admin, tz)).versions;
check('...version 1 is a create, and its comment names the template and its revision', tvr.length === 1 && tvr[0].kind === 'create' && tvr[0].comment.startsWith('for a customer [template "basic" (id') && tvr[0].comment.includes('revision'), () => JSON.stringify(tvr));
await waitAnswer('...the new zone is served after the reload', 'www.tpl.test', '192.0.2.41');
eq('...a template that is not there', type(await admin('POST', '/datasets/main/zones', { body: { name: 'x.test', template: 'ghost' } })), 'not-found');

console.log('-- a template is applied to a zone');
const AP = `${Z}/apply-template`;
const ad = await D('POST', AP, { body: { template: 'basic' } });
eq('a domain master cannot: the template has apex records and its policy none (403, the record of the template named)', [ad.status, type(ad), ad.body.errors?.[0]?.pointer], [403, 'forbidden', '/template/records/0']);
const adry = await admin('POST', AP, { body: { template_id: tid, dry_run: true } });
check('a dry run shows what it would overwrite', adry.status === 200 && adry.body.allowed === true && adry.body.diff.some((x) => x.name === 'example.test.' && x.type === 'NS' && x.change === 'replace') && adry.body.diff.some((x) => x.name === 'www.example.test.' && x.change === 'replace'), () => JSON.stringify(adry.body).slice(0, 400));
const nv = (await versions()).versions[0].version;
const wwwBefore = contents(await rrsetOf('www.example.test', 'A'));
const nsBefore = contents(await rrsetOf('example.test', 'NS'));
const ap = await admin('POST', AP, { body: { template: 'basic', comment: 'standard records', reload: true } });
eq('applied: a version of kind template', [ap.status, ap.body.committed, ap.body.version], [200, true, nv + 1]);
const av = (await versions()).versions[0];
check('...its comment names the template and its revision', av.kind === 'template' && av.comment.startsWith('standard records [template "basic" (id') && av.principal.name === 'admin', () => JSON.stringify(av));
eq('...the zone has the template\'s RRsets (an RRset merge: the others stay)', [contents(await rrsetOf('www.example.test', 'A')), contents(await rrsetOf('_dmarc.example.test', 'TXT')), contents(await rrsetOf('after.example.test', 'A')), contents(await rrsetOf('example.test', 'NS'))],
  [['192.0.2.41'], ['"v=DMARC1; p=reject"'], ['192.0.2.99'], ['ns1.nsprovider.test', 'ns2.nsprovider.test']]);
await waitAnswer('...and the server answers it after the reload', 'www.example.test', '192.0.2.41');
const undo = await admin('POST', `${V}/${nv}/rollback`, { body: { reload: true } });
eq('rolling back the template restores what it overwrote and removes what it added', [undo.status, undo.body.committed, contents(await rrsetOf('www.example.test', 'A')), contents(await rrsetOf('example.test', 'NS')), await rrsetOf('_dmarc.example.test', 'TXT')],
  [200, true, wwwBefore, nsBefore, undefined]);
await waitAnswer('...and the server answers the old address again', 'www.example.test', wwwBefore.join(','));
eq('a template is deleted; a zone cannot be made from it any more', [(await admin('DELETE', `/templates/${tid}`)).status, type(await admin('POST', '/datasets/main/zones', { body: { name: 'gone.test', template_id: tid } }))], [204, 'not-found']);

// ---------------------------------------------------------------------------------------------------------------------------------- the audit log has it all
console.log('-- the audit log');
const aud = (await admin('GET', `/audit?change_set=${forced.body.change_set}&limit=100`)).body.audit;
check('the rows of the forced rollback are under the principal and the change set', aud.length > 0 && aud.every((r) => r.principal === 'admin' && r.change_set === forced.body.change_set) && aud.some((r) => r.table === 'records'), () => JSON.stringify(aud.slice(0, 2)));
const ver = (await versions()).versions.find((v) => v.change_set === forced.body.change_set);
eq('...and the version row of the same change set names the same principal (the audit log and the history agree)', [ver?.version, ver?.principal?.name, ver?.kind], [forced.body.version, 'admin', 'rollback']);

console.log(`\n${pass} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);

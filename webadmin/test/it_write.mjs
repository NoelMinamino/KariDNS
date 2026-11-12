// The integration driver of the write side of karidns-webadmin (M3), the same scenarios on SQLite3 and on PostgreSQL.  Not a node:test file:
// tests/run_webadmin_write_test.sh and tests/run_webadmin_write_pg_test.sh start a real karidns (with karidns-dbloader), the real karidns-zone and the API on a
// real port, and run this against them.  It writes through the API, reloads, and looks at what the DNS server answers (`dag`).
//
//   IT_BASE=http://127.0.0.1:PORT/api/v1 IT_ORIGIN=... IT_ADMIN_PASSWORD=... IT_DNS_PORT=... IT_DAG=./dag IT_KARICTL=./karictl IT_KARICTL_CONF=... IT_DIR=...
//   IT_DB=sqlite|pg node webadmin/test/it_write.mjs
//
// The zones: example.test (a domain master `dom`, a subdomain master `sub` on sub.example.test), other.test (deleted), signed.test (kept by the signer: the
// metadata X-KARIDNS-SIGNER), big.test (BIG records, for the cost measurements).  IT_DIR/conflict.once and conflict.always make the wrapper of karidns-zone change
// example.test between the check run and the commit run.  Prints "  [ OK ] ..." / "  [FAIL] ..." lines and "  [COST] ..." lines; exits 1 when anything failed.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { hotp, totpStep, base32Decode } from '../lib/crypto.js';

const BASE = process.env.IT_BASE;
const ORIGIN = process.env.IT_ORIGIN;
const PORT = process.env.IT_DNS_PORT;
const DAG = process.env.IT_DAG;
const DIR = process.env.IT_DIR;
const PG = process.env.IT_DB === 'pg';
const BIG = Number(process.env.IT_BIG ?? 0);
let pass = 0;
let fails = 0;
const ok = (name) => { pass++; console.log(`  [ OK ] ${name}`); };
const bad = (name, why) => { fails++; console.log(`  [FAIL] ${name}${why ? ` (${why})` : ''}`); };
const check = (name, cond, why) => (cond ? ok(name) : bad(name, typeof why === 'function' ? why() : why));
const eq = (name, got, want) => check(name, JSON.stringify(got) === JSON.stringify(want), () => `got ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

// ---- the DNS server
const dagArgs = (name, t) => ['@127.0.0.1', '-p', PORT, name, t, '+nohexdump', '+time=2', '+tries=1'];
const answer = (name, t = 'A') => {
  const r = spawnSync(DAG, [...dagArgs(name, t), '+short'], { encoding: 'utf8' });
  return r.stdout.trim().split('\n').filter(Boolean).sort().join(',');
};
const status = (name, t = 'A') => /status: ([A-Z]+)/.exec(spawnSync(DAG, dagArgs(name, t), { encoding: 'utf8' }).stdout)?.[1] ?? 'none';
async function waitFor(what, fn, secs = 15) {
  const end = Date.now() + secs * 1000;
  while (Date.now() < end) {
    if (fn()) return true;
    await sleep(150);
  }
  bad(what, 'the condition did not come true');
  return false;
}
const waitAnswer = async (what, name, want, secs = 15) => {
  const end = Date.now() + secs * 1000;
  let got;
  while (Date.now() < end) {
    got = answer(name);
    if (got === want) { ok(what); return true; }
    await sleep(150);
  }
  bad(what, `the server answers ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);
  return false;
};
const serial = (zone) => Number(spawnSync(DAG, [...dagArgs(zone, 'SOA'), '+short'], { encoding: 'utf8' }).stdout.trim().split(/\s+/)[2]);

const rr = (name, t, ttl, ...contents) => ({ name, type: t, changetype: 'REPLACE', ttl, records: contents.map((content) => ({ content })) });
const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

// ---------------------------------------------------------------------------------------------------------------------------------- the cast
console.log('-- the cast: policies, users, grants');
const admin = await login('admin', process.env.IT_ADMIN_PASSWORD);
const mk = async (p, body) => {
  const r = await admin('POST', p, { body });
  if (r.status !== 201) bad(`POST ${p}`, `${r.status} ${r.text}`);
  return r.body;
};
const web = (await mk('/rr-policies', { name: 'web', allowed_types: ['A', 'AAAA', 'CNAME', 'TXT', 'MX'], ttl_min: 30, ttl_max: 86400 })).policy.id;
const capped = (await mk('/rr-policies', { name: 'capped', allowed_types: ['A', 'TXT'], ttl_min: 30, ttl_max: 86400, max_rr: 4 })).policy.id;
const dom = (await mk('/principals', { kind: 'user', name: 'dom', password: 'Sunrise-Harbor-42' })).principal.id;
const sub = (await mk('/principals', { kind: 'user', name: 'sub', password: 'Maple-Anchor-77' })).principal.id;
await mk('/grants', { principal: dom, role: 'domain_master', zone: 'example.test', policy: web });
await mk('/grants', { principal: sub, role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policy: web });
const D = await login('dom', 'Sunrise-Harbor-42');
const U = await login('sub', 'Maple-Anchor-77');
const PATCH = '/datasets/main/zones/example.test/rrsets';

// ---------------------------------------------------------------------------------------------------------------------------------- a change, a reload, the answer
console.log('-- a change set is in the DNS answer after the reload');
eq('the server answers what the database held', answer('www.example.test'), '192.0.2.10,192.0.2.11');
const before = serial('example.test');
const c1 = await D('PATCH', PATCH, { body: { comment: 'move www', reload: true, rrsets: [rr('www.example.test', 'A', 300, '192.0.2.77')] } });
eq('PATCH with reload: true: committed, the reload was asked for', [c1.status, c1.body.committed, c1.body.reload, c1.body.version], [200, true, 'requested', 2]);
await waitAnswer('...the server answers the new address', 'www.example.test', '192.0.2.77');
eq('...and the serial grew by one (the API raised it)', serial('example.test'), before + 1);
eq('the diff shows the RRset before and after', c1.body.diff, [{ name: 'www.example.test.', type: 'A', change: 'replace', before: [{ ttl: 300, content: '192.0.2.10' }, { ttl: 300, content: '192.0.2.11' }], after: [{ ttl: 300, content: '192.0.2.77' }] }]);
const c2 = await D('PATCH', PATCH, { body: { rrsets: [rr('www.example.test', 'A', 300, '192.0.2.78')] } });
eq('without reload: committed, not requested', [c2.status, c2.body.reload], [200, 'not requested']);
await sleep(2500);
eq('...the server still answers the old address', answer('www.example.test'), '192.0.2.77');
const rl = await D('POST', '/datasets/main/zones/example.test/reload');
eq('the update button', [rl.status, rl.body.reload], [200, 'requested']);
await waitAnswer('...and the server answers the new one', 'www.example.test', '192.0.2.78');
const info = (await D('GET', '/datasets/main/zones/example.test')).body.zone;
check('the zone info has the generation and the serial', info.generation > 0 && info.serial === before + 2, () => JSON.stringify(info));

// ---------------------------------------------------------------------------------------------------------------------------------- permissions
console.log('-- a write outside the grant is refused, and nothing changes');
const evil = await U('PATCH', PATCH, { body: { rrsets: [rr('evilsub.example.test', 'A', 300, '192.0.2.99'), rr('a.sub.example.test', 'A', 300, '192.0.2.98')], reload: true } });
eq('a subdomain master on evilsub.example.test: 403, the RRset named', [evil.status, type(evil), evil.body.errors?.[0]?.pointer], [403, 'forbidden', '/rrsets/0']);
eq('...the apex is refused too', type(await U('PATCH', PATCH, { body: { rrsets: [rr('example.test', 'TXT', 300, '"x"')] } })), 'forbidden');
eq('...evilsub.example.test still has its address', answer('evilsub.example.test'), '192.0.2.30');
const okSub = await U('PATCH', PATCH, { body: { rrsets: [rr('x.sub.example.test', 'A', 300, '192.0.2.40')], reload: true } });
eq('a subdomain master changes its own names', [okSub.status, okSub.body.committed], [200, true]);
await waitAnswer('...and the server answers', 'x.sub.example.test', '192.0.2.40');
eq('a domain master: a type outside the policy, a TTL outside it, the SOA', [
  type(await D('PATCH', PATCH, { body: { rrsets: [rr('m.example.test', 'SRV', 300, '1 1 1 x.example.test.')] } })),
  type(await D('PATCH', PATCH, { body: { rrsets: [rr('m.example.test', 'A', 5, '192.0.2.1')] } })),
  type(await D('PATCH', PATCH, { body: { rrsets: [rr('example.test', 'SOA', 300, 'ns1.example.test. h.example.test. 1 2 3 4 5')] } })),
], ['forbidden', 'forbidden', 'forbidden']);
const cn = await D('PATCH', PATCH, { body: { rrsets: [rr('www.example.test', 'CNAME', 300, 'other.example.test.')] } });
eq('...422, zone-checks-failed', [cn.status, type(cn), cn.body.errors?.some((e) => e.severity === 'error')], [422, 'zone-checks-failed', true]);
eq('...and nothing was written', answer('www.example.test'), '192.0.2.78');
const gp = await admin('POST', '/grants', { body: { principal: sub, role: 'subdomain_master', zone: 'example.test', suffix: 'cap.example.test', policy: capped } });
eq('max_rr: a grant with a limit', gp.status, 201);
await U('PATCH', PATCH, { body: { rrsets: [rr('a.cap.example.test', 'A', 300, '192.0.2.1', '192.0.2.2', '192.0.2.3')] } });
const over = await U('PATCH', PATCH, { body: { rrsets: [rr('b.cap.example.test', 'A', 300, '192.0.2.4', '192.0.2.5')] } });
eq('...the grant that allows 4 records refuses the fifth', [over.status, type(over)], [403, 'max-rr']);

// ---------------------------------------------------------------------------------------------------------------------------------- concurrency
console.log('-- a conflict between the check run and the commit run');
fs.writeFileSync(path.join(DIR, 'conflict.once'), '');
const logBefore = fs.existsSync(path.join(DIR, 'wrapper.log')) ? fs.readFileSync(path.join(DIR, 'wrapper.log'), 'utf8').split('\n').filter(Boolean).length : 0;
const retry = await D('PATCH', PATCH, { body: { rrsets: [rr('retry.example.test', 'A', 300, '192.0.2.60')], reload: true } });
eq('someone changes the zone in between: the API repeats the check and commits', [retry.status, retry.body.committed], [200, true]);
const logAfter = fs.readFileSync(path.join(DIR, 'wrapper.log'), 'utf8').split('\n').filter(Boolean).length;
eq('...the competing writer ran once', logAfter - logBefore, 1);
await waitAnswer('...both changes are in the database (retry.example.test is served)', 'retry.example.test', '192.0.2.60');
const noise = await D('GET', '/datasets/main/zones/example.test/rrsets?name=noise.example.test&type=TXT');
check('...and the competing writer\'s change is there too', noise.body.rrsets?.length === 1, () => noise.text);
fs.writeFileSync(path.join(DIR, 'conflict.always'), '');
const always = await D('PATCH', PATCH, { body: { rrsets: [rr('never.example.test', 'A', 300, '192.0.2.61')] } });
fs.rmSync(path.join(DIR, 'conflict.always'));
eq('the zone changes every time: 409 changed after three rounds, nothing written', [always.status, type(always)], [409, 'changed']);
eq('...never.example.test is not there', (await D('GET', '/datasets/main/zones/example.test/rrsets?name=never.example.test')).body.rrsets, []);
console.log('-- preconditions');
const pre = await D('PATCH', PATCH, { body: { rrsets: [{ ...rr('www.example.test', 'A', 300, '192.0.2.80'), expect: [{ ttl: 300, content: '192.0.2.99' }] }] } });
eq('an RRset that is not as expected: 409, with the current records', [pre.status, type(pre), pre.body.errors?.[0]?.current], [409, 'precondition-failed', [{ ttl: 300, content: '192.0.2.78' }]]);
const pre2 = await D('PATCH', PATCH, { body: { rrsets: [{ ...rr('www.example.test', 'A', 300, '192.0.2.80'), expect: [{ ttl: 300, content: '192.0.2.78' }] }] } });
eq('...as expected: committed', [pre2.status, pre2.body.committed], [200, true]);

// ---------------------------------------------------------------------------------------------------------------------------------- the signer
console.log('-- a zone kept by the signer is not reloaded by the API (S-5)');
check('signed.test is served', answer('www.signed.test') === '192.0.2.20', () => answer('www.signed.test'));
const sg = await admin('PATCH', '/datasets/main/zones/signed.test/rrsets', { body: { reload: true, rrsets: [rr('www.signed.test', 'A', 300, '192.0.2.21')] } });
eq('a change is committed and the API says it waits for the signer', [sg.status, sg.body.committed, sg.body.reload], [200, true, 'waiting for the signer']);
await sleep(3000);
eq('...the server serves the old version', answer('www.signed.test'), '192.0.2.20');
eq('the update button refuses', type(await admin('POST', '/datasets/main/zones/signed.test/reload')), 'signer-managed');
const zinfo = (await admin('GET', '/datasets/main/zones/signed.test')).body.zone;
eq('the zone info says the signer has not signed it', [zinfo.signer, zinfo.waiting_for_signer], [true, true]);
const kr = spawnSync(process.env.IT_KARICTL, ['-c', process.env.IT_KARICTL_CONF, '-s', process.env.IT_KARICTL_SOCK, 'reload', 'signed.test'], { encoding: 'utf8' });
check('the operator\'s karictl reload reads it as it is', kr.status === 0, () => kr.stdout + kr.stderr);
await waitAnswer('...and now the server serves it', 'www.signed.test', '192.0.2.21');
eq('a change of the DNSSEC types is not for the API', type(await admin('PATCH', '/datasets/main/zones/signed.test/rrsets', { body: { rrsets: [rr('signed.test', 'DNSKEY', 300, '257 3 8 AAAA')] } })), 'bad-request');

// ---------------------------------------------------------------------------------------------------------------------------------- import
console.log('-- an import replaces the zone\'s RRsets');
const text = '$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\n@ IN MX 10 mail\nmail IN A 192.0.2.40\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.50\nimp IN A 192.0.2.55\nsub IN A 192.0.2.20\n';
const dry = await D('POST', '/datasets/main/zones/example.test/import', { body: { zone_text: text, dry_run: true } });
check('a dry run shows what it would do', dry.status === 200 && dry.body.allowed === true && dry.body.diff.some((e) => e.name === 'imp.example.test.' && e.change === 'add') && dry.body.diff.some((e) => e.change === 'delete'), () => dry.text.slice(0, 400));
const imp = await D('POST', '/datasets/main/zones/example.test/import', { body: { zone_text: text, comment: 'import', reload: true } });
eq('the import', [imp.status, imp.body.committed], [200, true]);
await waitAnswer('...the new RRset is served', 'imp.example.test', '192.0.2.55');
await waitAnswer('...www is the text\'s', 'www.example.test', '192.0.2.50');
const gone = answer('retry.example.test') === '' && answer('x.sub.example.test') === '';
check('...what the text does not have is gone', gone, () => `${answer('retry.example.test')} ${answer('x.sub.example.test')}`);
eq('...the SOA is kept and the serial grew', serial('example.test') > before + 2, true);
eq('a subdomain master cannot import', type(await U('POST', '/datasets/main/zones/example.test/import', { body: { zone_text: text } })), 'forbidden');
const bad1 = await D('POST', '/datasets/main/zones/example.test/import', { body: { zone_text: '$ORIGIN example.test.\n$INCLUDE /etc/passwd\n' } });
eq('$INCLUDE in the text is refused', [bad1.status, type(bad1)], [422, 'zone-checks-failed']);
const sig = await D('POST', '/datasets/main/zones/example.test/import', { body: { zone_text: '$ORIGIN example.test.\n$TTL 60\nx IN A 192.0.2.1\nx IN RRSIG A 8 3 60 20350101000000 20250101000000 1 example.test. AAAA\n' } });
eq('DNSSEC records in the text are refused', [sig.status, type(sig)], [422, 'zone-checks-failed']);

// ---------------------------------------------------------------------------------------------------------------------------------- zones: create, delete
console.log('-- a zone is created and deleted');
const create = await admin('POST', '/datasets/main/zones', { body: { name: 'new.test', soa: { mname: 'ns1.new.test', rname: 'hostmaster.new.test' }, nameservers: ['ns1.new.test'], rrsets: [rr('ns1.new.test', 'A', 300, '192.0.2.200'), rr('www.new.test', 'A', 300, '192.0.2.201')], reload: true } });
eq('create', [create.status, create.body.committed, create.body.version, create.headers.get('location')], [201, true, 1, '/api/v1/datasets/main/zones/new.test.']);
await waitAnswer('...the new zone is served', 'www.new.test', '192.0.2.201');
eq('...a zone that exists is refused', type(await admin('POST', '/datasets/main/zones', { body: { name: 'new.test', soa: { mname: 'ns1.new.test', rname: 'h.new.test' }, nameservers: ['ns1.new.test'] } })), 'exists');
eq('...a domain master cannot create', type(await D('POST', '/datasets/main/zones', { body: { name: 'mine.test', soa: { mname: 'ns1.mine.test', rname: 'h.mine.test' }, nameservers: ['ns1.mine.test'] } })), 'forbidden');
await admin('POST', '/grants', { body: { principal: dom, role: 'domain_master', zone: 'other.test', policy: web } });
check('dom has a grant on other.test', (await D('GET', '/datasets/main/zones')).body.zones.some((z) => z.name === 'other.test.'));
const del = await admin('DELETE', '/datasets/main/zones/other.test', { body: { confirm: 'other.test.', reload: true } });
eq('delete (with the name as confirmation)', [del.status, del.body.deleted], [200, 'other.test.']);
const gone2 = await waitFor('...the server stops serving the zone', () => status('www.other.test') !== 'NOERROR', 15);
check('...the zone is gone for everybody, its grants too', gone2 && (await D('GET', '/datasets/main/zones')).body.zones.every((z) => z.name !== 'other.test.'));
eq('...and not by anyone else', type(await D('DELETE', '/datasets/main/zones/example.test', { body: { confirm: 'example.test' } })), 'forbidden');

// ---------------------------------------------------------------------------------------------------------------------------------- metadata, DNSSEC requests, the audit
console.log('-- metadata, key requests, the audit log');
const meta = await admin('PUT', '/datasets/main/zones/example.test/metadata/ALLOW-AXFR-FROM', { body: { content: ['192.0.2.0/24'] } });
eq('metadata: ALLOW-AXFR-FROM', [meta.status, (await D('GET', '/datasets/main/zones/example.test/metadata')).body.metadata.map((m) => m.kind)], [200, ['ALLOW-AXFR-FROM']]);
const keyreq = await D('POST', '/datasets/main/zones/example.test/dnssec/requests', { body: { kind: 'enable', algorithm: 13 } });
eq('a domain master asks the signer for keys', [keyreq.status, keyreq.body.request?.state], [201, 'pending']);
eq('...one request at a time', type(await D('POST', '/datasets/main/zones/example.test/dnssec/requests', { body: { kind: 'enable' } })), 'request-pending');
eq('...a subdomain master cannot', type(await U('POST', '/datasets/main/zones/example.test/dnssec/requests', { body: { kind: 'enable' } })), 'forbidden');
const dn = await D('GET', '/datasets/main/zones/example.test/dnssec');
eq('the DNSSEC view: no keys yet, the pending request, not signed', [dn.status, dn.body.dnssec?.keys, dn.body.dnssec?.requests?.map((r) => r.state), dn.body.dnssec?.signed], [200, [], ['pending'], false]);
const dns2 = await admin('GET', '/datasets/main/zones/signed.test/dnssec');
eq('...a zone the signer keeps', [dns2.status, dns2.body.dnssec?.signer, dns2.body.dnssec?.signed], [200, true, true]);
eq('...not for a subdomain master', type(await U('GET', '/datasets/main/zones/example.test/dnssec')), 'forbidden');
const aud = (await admin('GET', `/audit?change_set=${c1.body.change_set}&limit=100`)).body.audit;
check('the audit log has the rows of the change set under the principal', aud.length > 0 && aud.every((r) => r.principal === 'dom' && r.change_set === c1.body.change_set) && aud.some((r) => r.table === 'records' && r.op === 'D'), () => JSON.stringify(aud.slice(0, 2)));
if (PG) check('...and the database role of the API', aud.every((r) => r.db_role === process.env.IT_API_ROLE), () => aud[0]?.db_role);

// ---------------------------------------------------------------------------------------------------------------------------------- the server side of the GUI (item F, M1)
console.log('-- the web interface: the text form of the records (G2), search (G3), tagged (G4), /version (G5), credentials (G6), the files (G1)');
const RT = '/datasets/main/zones/rt.test';
// every page of a list
const allPages = async (who, p) => {
  const out = [];
  let cursor = '';
  for (let i = 0; i < 200; i++) {
    const r = await who('GET', `${p}${p.includes('?') ? '&' : '?'}limit=500${cursor}`);
    if (r.status !== 200) { bad(`GET ${p}`, `${r.status} ${r.text.slice(0, 200)}`); break; }
    out.push(...r.body.rrsets);
    if (!r.body.next_cursor) break;
    cursor = `&cursor=${r.body.next_cursor}`;
  }
  return out;
};
const rt = await allPages(admin, `${RT}/rrsets?rdata=1`);
const flat = rt.flatMap((s) => s.records.map((r) => ({ s, r })));
check('rt.test: every record has rdata', rt.length === 37 && flat.length === 42 && flat.every(({ r }) => typeof r.rdata === 'string' && r.rdata.length > 0), () => JSON.stringify(flat.filter(({ r }) => typeof r.rdata !== 'string').map(({ s }) => `${s.name} ${s.type}`)));
check('...none is tagged', rt.every((s) => s.tagged === false));
const rdOf = (name, t) => rt.find((s) => s.name === name && s.type === t)?.records.map((r) => r.rdata);
eq('...an MX: the priority in front, the name absolute', rdOf('rt.test.', 'MX'), ['10 mail.rt.test.', '20 mail2.rt.test.']);
eq('...the null MX has the root name, not "@"', rdOf('nomail.rt.test.', 'MX'), ['0 .']);
eq('...an SRV with no target', rdOf('_no._tcp.rt.test.', 'SRV'), ['0 0 0 .']);
eq('...an SRV', rdOf('_sip._tcp.rt.test.', 'SRV'), ['10 60 5060 sip.rt.test.', '20 0 5060 sip2.rt.test.']);
eq('...a NAPTR with the root as its replacement', rdOf('naptr.rt.test.', 'NAPTR'), ['100 10 "u" "E2U+sip" "!^.*$!sip:info@example.test!" .']);
eq('...a CNAME', rdOf('www.rt.test.', 'CNAME'), ['web.rt.test.']);
eq('...strings with quotes and a backslash', rdOf('txt.rt.test.', 'TXT'), ['"hello world" "second" "with \\"quotes\\" and \\\\ backslash"']);
eq('...a semicolon inside quotes', rdOf('semi.rt.test.', 'TXT'), ['"a;b" "(paren)"']);
eq('...the stored content is as before (names without the dot)', rt.find((s) => s.name === 'rt.test.' && s.type === 'MX').records.map((r) => r.content), ['10 mail.rt.test', '20 mail2.rt.test']);

// the round trip: every RRset read (but the SOA, below), sent back as the change set with its own records as `expect`: nothing differs, nothing is written
const body = (over = {}) => ({
  rrsets: rt.filter((s) => s.type !== 'SOA').map((s) => ({
    name: s.name, type: s.type, changetype: 'REPLACE', ttl: s.ttl, records: s.records.map((r) => ({ content: r.rdata })), expect: s.records.map((r) => ({ ttl: r.ttl, content: r.rdata })),
  })),
  ...over,
});
const dryRt = await admin('PATCH', `${RT}/rrsets`, { body: body({ dry_run: true }) });
eq('round trip, dry run: allowed, no difference', [dryRt.status, dryRt.body.allowed, dryRt.body.diff], [200, true, []]);
if (dryRt.status !== 200) console.log(`         ${dryRt.text.slice(0, 1500)}`);
const realRt = await admin('PATCH', `${RT}/rrsets`, { body: body({ comment: 'round trip' }) });
eq('round trip, for real: nothing changed, nothing written', [realRt.status, realRt.body.committed, realRt.body.changed, realRt.body.diff], [200, false, false, []]);
eq('...the serial and the generation are as they were', [(await admin('GET', RT)).body.zone.serial], [1]);
// the SOA is the exception: a change set that names it writes it with the next serial, so sending it back is a change and an `expect` on it never matches
const soaRt = rt.find((s) => s.type === 'SOA');
const soaBack = await admin('PATCH', `${RT}/rrsets`, { body: { dry_run: true, rrsets: [{ name: soaRt.name, type: 'SOA', changetype: 'REPLACE', ttl: soaRt.ttl, records: [{ content: soaRt.records[0].rdata }] }] } });
eq('the SOA sent back is a change (the serial grows), as documented', [soaBack.status, soaBack.body.diff.map((d) => d.type), soaBack.body.serial.after], [200, ['SOA'], soaBack.body.serial.before + 1]);
// a change made from what was read: the MX priority
const mxNew = await admin('PATCH', `${RT}/rrsets`, { body: { rrsets: [{ name: 'rt.test.', type: 'MX', changetype: 'REPLACE', ttl: 300, records: [{ content: '15 mail.rt.test.' }, { content: rdOf('rt.test.', 'MX')[1] }], expect: rt.find((s) => s.name === 'rt.test.' && s.type === 'MX').records.map((r) => ({ ttl: r.ttl, content: r.rdata })) }] } });
eq('an edit made from rdata: the diff shows the one record that changed', [mxNew.status, mxNew.body.diff.map((d) => [d.before.map((x) => x.content), d.after.map((x) => x.content)])], [200, [[['10 mail.rt.test.', '20 mail2.rt.test.'], ['15 mail.rt.test.', '20 mail2.rt.test.']]]]);
eq('...and rdata shows it', (await admin('GET', `${RT}/rrsets?rdata=1&name=rt.test&type=MX`)).body.rrsets[0].records.map((r) => r.rdata), ['15 mail.rt.test.', '20 mail2.rt.test.']);
// a stale expectation made from content (the stored form) is what rdata exists to avoid
const stale = await admin('PATCH', `${RT}/rrsets`, { body: { rrsets: [{ name: 'rt.test.', type: 'MX', changetype: 'REPLACE', ttl: 300, records: [{ content: '15 mail.rt.test.' }], expect: [{ ttl: 300, content: '15 mail' }] }] } });
eq('...an expect made from the stored content does not match', type(stale), 'precondition-failed');

// G3
const contains = (await admin('GET', `${RT}/rrsets?contains=MAIL`)).body.rrsets.map((s) => `${s.name} ${s.type}`);
eq('contains: any case, owners only', contains, ['mail.rt.test. A', 'mail2.rt.test. A', 'nomail.rt.test. MX']);
const fromWeb = (await admin('GET', `${RT}/rrsets?from=web&limit=2`)).body;
eq('from: the first owner >= web, and a cursor', [fromWeb.rrsets.map((s) => s.name), Boolean(fromWeb.next_cursor)], [['web.rt.test.', 'web.rt.test.'], true]);
eq('zones?contains=', (await admin('GET', '/datasets/main/zones?contains=RT.')).body.zones.map((z) => z.name), ['rt.test.']);
eq('...a domain master sees its own zones only', (await D('GET', '/datasets/main/zones?contains=test')).body.zones.map((z) => z.name).sort(), ['example.test.']);
// G5
const ver = (await admin('GET', '/version')).body;
check('/version has the record types and the settings of the GUI', ['A', 'MX', 'TXT', 'SRV'].every((t) => ver.types.includes(t)) && !ver.types.includes('RRSIG') && ver.ui.max_rrsets === 1000 && ver.ui.require_totp === 'none' && ver.ui.zone_text_limit === 16777216, () => JSON.stringify(ver).slice(0, 300));

// G6 on a user of its own (the sessions of the others are used below)
const gu = (await mk('/principals', { kind: 'user', name: 'guiuser', password: 'Quartz-Lantern-9081' })).principal.id;
const G1 = await login('guiuser', 'Quartz-Lantern-9081');
const en = await G1('POST', '/auth/totp', { body: { action: 'enroll' } });
const nowMs = Date.now();
const code = (b32, step) => hotp(base32Decode(b32), totpStep(nowMs / 1000) + step);
const cf = await G1('POST', '/auth/totp', { body: { action: 'confirm', code: code(en.body.secret, 0) } });
eq('a user enrols TOTP', [cf.status, cf.body.totp], [200, { enabled: true, enrollment_required: false }]);
const noCode = await call('POST', '/auth/login', { body: { user: 'guiuser', password: 'Quartz-Lantern-9081' } });
eq('...the login asks for the code', type(noCode), 'totp-required');
const l3 = await call('POST', '/auth/login', { body: { user: 'guiuser', password: 'Quartz-Lantern-9081', totp: code(en.body.secret, 1) } });
const s3 = /karidns_session=([^;]+)/.exec(l3.headers.get('set-cookie') ?? '')?.[1];
const G3 = (method, p, o = {}) => call(method, p, { cookie: s3, csrf: l3.body?.csrf, origin: ORIGIN, ...o });
eq('...and a login with the code works', [l3.status, (await G3('GET', '/auth/me')).status], [200, 200]);
const reset = await admin('POST', `/principals/${gu}/credentials`, { body: { action: 'reset-totp' } });
eq('an administrator resets it', [reset.status, reset.body.credentials], [200, { password: true, totp_enabled: false, failed_logins: 0, locked: false, locked_networks: [], oidc: null }]);
eq('...the user\'s session ended', (await G3('GET', '/auth/me')).status, 401);
const relog = await call('POST', '/auth/login', { body: { user: 'guiuser', password: 'Quartz-Lantern-9081' } });
eq('...and the login needs no code', [relog.status, relog.body.totp], [200, { enabled: false, enrollment_required: false }]);
eq('...not one\'s own TOTP', type(await admin('POST', `/principals/${(await admin('GET', '/auth/me')).body.principal.id}/credentials`, { body: { action: 'reset-totp' } })), 'self');
eq('...a domain master may not', type(await D('POST', `/principals/${gu}/credentials`, { body: { action: 'unlock' } })), 'forbidden');
for (let i = 0; i < 10; i++) await call('POST', '/auth/login', { body: { user: 'guiuser', password: 'wrong password 1234' } });
eq('ten failures lock the account', (await call('POST', '/auth/login', { body: { user: 'guiuser', password: 'Quartz-Lantern-9081' } })).status, 401);
eq('...an administrator sees it', (await admin('GET', `/principals/${gu}`)).body.credentials.locked, true);
const un = await admin('POST', `/principals/${gu}/credentials`, { body: { action: 'unlock' } });
eq('...and unlocks it', [un.status, un.body.credentials.locked, un.body.credentials.failed_logins], [200, false, 0]);
eq('...the user is in again', (await call('POST', '/auth/login', { body: { user: 'guiuser', password: 'Quartz-Lantern-9081' } })).status, 200);
const ca = (await admin('GET', '/audit?table=credentials&limit=100')).body.audit.filter((r) => r.op === 'U' && (r.row_id === gu || r.after?.principal_id === gu));       // (PostgreSQL has no row_id for a row without an id column)
check('...the credentials rows of the audit log name the administrator', ca.some((r) => r.principal === 'admin'), () => JSON.stringify(ca.slice(0, 2)));

// G1: the files
const origin = new URL(BASE).origin;
const page = await fetch(`${origin}/`);
const csp = page.headers.get('content-security-policy') ?? '';
check('GET / is the page, with the policy of the GUI', page.status === 200 && /^text\/html/.test(page.headers.get('content-type')) && csp.startsWith("default-src 'none'; script-src 'self'") && page.headers.get('cache-control') === 'no-store' && page.headers.get('x-frame-options') === 'DENY', () => `${page.status} ${csp}`);
const css = await fetch(`${origin}/ui/app.css`);
const css2 = await fetch(`${origin}/ui/app.css`, { headers: { 'If-None-Match': css.headers.get('etag') } });
eq('/ui/ files: an ETag, and a 304 for it', [css.status, css.headers.get('cache-control'), css2.status], [200, 'no-cache', 304]);
eq('...nothing outside the files', [(await fetch(`${origin}/ui/../etc/passwd`)).status, (await fetch(`${origin}/ui/%2e%2e/etc/passwd`)).status, (await fetch(`${origin}/etc/passwd`)).status], [404, 404, 404]);


// ---------------------------------------------------------------------------------------------------------------------------------- cost (planning 2.3, assumption 13.7)
console.log('-- the cost of a change set');
const time = async (fn) => {
  const t0 = process.hrtime.bigint();
  const r = await fn();
  return { ms: Number(process.hrtime.bigint() - t0) / 1e6, r };
};
const small = [];
const smallDry = [];
for (let i = 0; i < 5; i++) {
  smallDry.push((await time(() => D('PATCH', PATCH, { body: { dry_run: true, rrsets: [rr('cost.example.test', 'A', 300, `192.0.2.${100 + i}`)] } }))).ms);
  const t = await time(() => D('PATCH', PATCH, { body: { rrsets: [rr('cost.example.test', 'A', 300, `192.0.2.${100 + i}`)] } }));
  if (t.r.status !== 200) bad('a cost run', t.r.text);
  small.push(t.ms);
}
console.log(`  [COST] ${PG ? 'PostgreSQL' : 'SQLite3'}, a small zone (example.test, about 15 records): dry run median ${median(smallDry).toFixed(0)} ms, check + commit median ${median(small).toFixed(0)} ms`);
check('a change set of a small zone takes under 5 seconds', median(small) < 5000, () => `${median(small)} ms`);
if (BIG > 0) {
  const bigSet = [];
  const bigDry = [];
  const BP = '/datasets/main/zones/big.test/rrsets';
  for (let i = 0; i < 3; i++) {
    bigDry.push((await time(() => admin('PATCH', BP, { body: { dry_run: true, rrsets: [rr('cost.big.test', 'A', 300, `192.0.2.${100 + i}`)] } }))).ms);
    const t = await time(() => admin('PATCH', BP, { body: { rrsets: [rr('cost.big.test', 'A', 300, `192.0.2.${100 + i}`)] } }));
    if (t.r.status !== 200) bad('a cost run on the big zone', t.r.text);
    bigSet.push(t.ms);
  }
  console.log(`  [COST] ${PG ? 'PostgreSQL' : 'SQLite3'}, a zone of ${BIG} records, a global master: dry run median ${median(bigDry).toFixed(0)} ms, check + commit median ${median(bigSet).toFixed(0)} ms`);
  const bigSub = [];
  const subBig = await mk('/principals', { kind: 'user', name: 'bigsub', password: 'Granite-Pine-1357' });
  await mk('/grants', { principal: subBig.principal.id, role: 'subdomain_master', zone: 'big.test', suffix: 'sub1.big.test', policy: web });
  const BS = await login('bigsub', 'Granite-Pine-1357');
  for (let i = 0; i < 3; i++) {
    const t = await time(() => BS('PATCH', BP, { body: { rrsets: [rr('cost.sub1.big.test', 'A', 300, `192.0.2.${100 + i}`)] } }));
    if (t.r.status !== 200) bad('a cost run of a subdomain master on the big zone', t.r.text);
    bigSub.push(t.ms);
  }
  console.log(`  [COST] ${PG ? 'PostgreSQL' : 'SQLite3'}, a zone of ${BIG} records, a subdomain master (the check role reads the whole zone, RLS the part): check + commit median ${median(bigSub).toFixed(0)} ms`);
  check('a change set of the big zone takes under 60 seconds', median(bigSet) < 60000 && median(bigSub) < 60000, () => `${median(bigSet)} / ${median(bigSub)} ms`);
  const rd = (await time(() => admin('GET', `${BP}?limit=500`)));
  console.log(`  [COST] ${PG ? 'PostgreSQL' : 'SQLite3'}, GET rrsets of the big zone, one page of 500 RRsets as a global master: ${rd.ms.toFixed(0)} ms`);
  // paging as a domain master and as a subdomain master (planning A-23: on PostgreSQL row level security tests every row of the page again): the first 20 pages of 500
  // RRsets of the zone, the median of a page and the time of all 20, against the same as a global master
  const domBig = await mk('/principals', { kind: 'user', name: 'bigdom', password: 'Granite-Pine-2468' });
  await mk('/grants', { principal: domBig.principal.id, role: 'domain_master', zone: 'big.test', policy: web });
  const BD = await login('bigdom', 'Granite-Pine-2468');
  const walk = async (who, path, pages) => {
    const ms = [];
    let cursor = '';
    let rrsets = 0;
    for (let i = 0; i < pages; i++) {
      const t = await time(() => who('GET', `${path}?limit=500${cursor}`));
      if (t.r.status !== 200) { bad('paging the big zone', t.r.text); break; }
      ms.push(t.ms);
      rrsets += t.r.body.rrsets.length;
      if (!t.r.body.next_cursor) break;
      cursor = `&cursor=${t.r.body.next_cursor}`;
    }
    return { ms, rrsets, total: ms.reduce((a, b) => a + b, 0) };
  };
  const label = PG ? 'PostgreSQL' : 'SQLite3';
  const pagesOf = Math.min(20, Math.ceil(BIG / 500));
  const gm = await walk(admin, BP, pagesOf);
  const dm = await walk(BD, BP, pagesOf);
  const sm = await walk(BS, BP, pagesOf);
  console.log(`  [COST] ${label}, ${gm.ms.length} pages of 500 RRsets of the big zone (${gm.rrsets} RRsets): global master median ${median(gm.ms).toFixed(0)} ms a page (${gm.total.toFixed(0)} ms in all), domain master median ${median(dm.ms).toFixed(0)} ms a page (${dm.total.toFixed(0)} ms in all, ${(dm.total / gm.total).toFixed(1)} times)`);
  console.log(`  [COST] ${label}, a subdomain master (the names under sub1.big.test, half of the zone): ${sm.ms.length} pages, ${sm.rrsets} RRsets, median ${median(sm.ms).toFixed(0)} ms a page (${sm.total.toFixed(0)} ms in all)`);
  check('the domain master reads as many RRsets as the global master', dm.rrsets === gm.rrsets, () => `${dm.rrsets} / ${gm.rrsets}`);
  // item F: what the reads of the GUI cost on the big zone (G2 rdata, G3 from / contains) and on a database of many zones
  const med = async (fn, n = 3) => {
    const xs = [];
    for (let i = 0; i < n; i++) xs.push((await time(fn)).ms);
    return median(xs);
  };
  const cost = async (what, who, p) => {
    let last;
    const ms = await med(async () => { last = await who('GET', p); return last; });
    if (last.status !== 200) bad(what, `${last.status} ${last.text.slice(0, 200)}`);
    console.log(`  [COST] ${label}, ${what}: median ${ms.toFixed(0)} ms (${last.body.rrsets?.length ?? last.body.zones?.length} items)`);
    return { ms, body: last.body };
  };
  const plain = await cost('a page of 500 RRsets of the big zone, global master', admin, `${BP}?limit=500`);
  const rend = await cost('...the same with rdata=1 (one run of karidns-zone render for the page)', admin, `${BP}?limit=500&rdata=1`);
  check('...every record of the page has rdata', rend.body.rrsets.every((s) => s.records.every((r) => typeof r.rdata === 'string')));
  await cost('from= the middle of the zone, a page of 500', admin, `${BP}?limit=500&from=h10000`);
  const rare = await cost('contains= a rare text (h12345, a scan of the whole zone)', admin, `${BP}?limit=500&contains=h12345`);
  check('...it finds the owners that have it', rare.body.rrsets.length > 0 && rare.body.rrsets.every((s) => s.name.includes('h12345')) || BIG < 24690, () => rare.body.rrsets.length);
  await cost('contains= a text that is not there (the worst case: the whole zone scanned, nothing found)', admin, `${BP}?limit=500&contains=nomatchxyz`);
  await cost('contains= a text half of the zone has (sub1), the first page of 500', admin, `${BP}?limit=500&contains=sub1`);
  await cost('contains= a text that is not there, domain master (on PostgreSQL row level security tests the rows)', BD, `${BP}?limit=500&contains=nomatchxyz`);
  await cost('contains= a text that is not there, subdomain master', BS, `${BP}?limit=500&contains=nomatchxyz`);
  const ZONES = Number(process.env.IT_ZONES ?? 0);
  if (ZONES > 0) {
    console.log(`  [COST] ${label}, ${ZONES} more zones in the database`);
    const zl = await cost('zones?limit=100, global master', admin, '/datasets/main/zones?limit=100');
    const zc = await cost('zones?contains= a text a few zones have (z0099), global master', admin, '/datasets/main/zones?limit=100&contains=z0099');
    const zn = await cost('zones?contains= a text no zone has, global master (the whole list scanned)', admin, '/datasets/main/zones?limit=100&contains=nomatchxyz');
    const zp = await cost('zones?prefix= (the comparison)', admin, '/datasets/main/zones?limit=100&prefix=z0099');
    check('...the zones that have the text are found', zc.body.zones.length > 0 && zc.body.zones.every((z) => z.name.includes('z0099')) && zn.body.zones.length === 0 && zl.body.zones.length === 100 && zp.body.zones.length > 0);
    await cost('zones?contains= a text no zone has, a domain master (two zones)', BD, '/datasets/main/zones?limit=100&contains=nomatchxyz');
  }
}

console.log(`\n${pass} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);

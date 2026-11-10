// The integration driver of karidns-webadmin (M2: authentication and the read side), the same scenarios on SQLite3 and on PostgreSQL.  Not a node:test file:
// tests/run_webadmin_test.sh and tests/run_webadmin_pg_test.sh set the database up (zones example.test and other.test imported by karidns-zone), start the
// real server on a real port and run this against it.
//
//   IT_BASE=http://127.0.0.1:PORT/api/v1 IT_ORIGIN=http://127.0.0.1:PORT IT_ADMIN_PASSWORD=... IT_SESSION_IDLE=8 node webadmin/test/it.mjs
//
// It prints "  [ OK ] ..." / "  [FAIL] ..." lines and exits 1 when anything failed.  The server runs with require-totp = global, session-idle = IT_SESSION_IDLE and
// rate-login = 60 a minute.

import { hotp, totpStep, base32Decode } from '../lib/crypto.js';

const BASE = process.env.IT_BASE;
const ORIGIN = process.env.IT_ORIGIN;
const IDLE = Number(process.env.IT_SESSION_IDLE ?? 8);
let pass = 0;
let fails = 0;
const ok = (name) => { pass++; console.log(`  [ OK ] ${name}`); };
const bad = (name, why) => { fails++; console.log(`  [FAIL] ${name}${why ? ` (${why})` : ''}`); };
const check = (name, cond, why) => (cond ? ok(name) : bad(name, typeof why === 'function' ? why() : why));
const eq = (name, got, want) => check(name, JSON.stringify(got) === JSON.stringify(want), () => `got ${JSON.stringify(got)}, wanted ${JSON.stringify(want)}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function call(method, p, { body, cookie, csrf, token, headers = {}, origin } = {}) {
  const h = { ...headers };
  if (cookie) h.Cookie = `karidns_session=${cookie}`;
  if (token) h.Authorization = `Bearer ${token}`;
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
const code = (b32, step = 0) => hotp(base32Decode(b32), totpStep(Date.now() / 1000) + step);
const type = (r) => r.body?.type?.replace('urn:karidns:api:', '');

async function login(user, password, extra = {}) {
  const r = await call('POST', '/auth/login', { body: { user, password, ...extra } });
  const m = /karidns_session=([^;]+)/.exec(r.headers.get('set-cookie') ?? '');
  const s = { r, status: r.status, cookie: m?.[1], csrf: r.body?.csrf };
  s.do = (method, p, o = {}) => call(method, p, { cookie: s.cookie, csrf: s.csrf, origin: ORIGIN, ...o });
  return s;
}
const names = (r) => r.body.rrsets.map((x) => `${x.name} ${x.type}`);

// ---------------------------------------------------------------------------------------------------------------------------------- the administrator
console.log('-- the administrator: health, TOTP enrolment, the second step');
const h = await call('GET', '/health');
eq('health needs no login', [h.status, h.body.status], [200, 'ok']);
eq('no credential: 401', (await call('GET', '/principals')).status, 401);
let admin = await login('admin', process.env.IT_ADMIN_PASSWORD);
eq('the first login of a global master asks for TOTP enrolment', [admin.status, admin.r.body.totp], [200, { enabled: false, enrollment_required: true }]);
eq('...and until then only /auth answers', type(await admin.do('GET', '/principals')), 'totp-required');
const enrol = await admin.do('POST', '/auth/totp', { body: { action: 'enroll' } });
check('enrolment gives a secret', /^[A-Z2-7]{32}$/.test(enrol.body.secret));
const conf = await admin.do('POST', '/auth/totp', { body: { action: 'confirm', code: code(enrol.body.secret) } });
eq('confirming with a code', conf.status, 200);
const secret = enrol.body.secret;
admin = { do: (m, p, o = {}) => call(m, p, { cookie: /karidns_session=([^;]+)/.exec(conf.headers.get('set-cookie'))[1], csrf: conf.body.csrf, origin: ORIGIN, ...o }) };
eq('the old session is gone, the new one works', [(await call('GET', '/auth/me', { cookie: 'x' })).status, (await admin.do('GET', '/principals')).status], [401, 200]);
const version = await admin.do('GET', '/version');
check('/version names the tools', /karidns-zone/.test(version.body.tools['karidns-zone']) && /karicheck/.test(version.body.tools.karicheck), () => JSON.stringify(version.body));
const noCode = await call('POST', '/auth/login', { body: { user: 'admin', password: process.env.IT_ADMIN_PASSWORD } });
eq('a login now needs the code', type(noCode), 'totp-required');
await sleep(1100);
const twice = await login('admin', process.env.IT_ADMIN_PASSWORD, { totp: code(secret, 1) });
eq('a login with the code works', twice.status, 200);
eq('the same code is not taken twice', type((await call('POST', '/auth/login', { body: { user: 'admin', password: process.env.IT_ADMIN_PASSWORD, totp: code(secret, 1) } }))), 'invalid-credentials');

// ---------------------------------------------------------------------------------------------------------------------------------- users, policies, grants
console.log('-- users, groups, policies, grants');
const mk = async (path, body) => {
  const r = await admin.do('POST', path, { body });
  if (r.status !== 201) bad(`POST ${path}`, `${r.status} ${r.text}`);
  return r.body;
};
const web = (await mk('/rr-policies', { name: 'web', allowed_types: ['A', 'AAAA', 'CNAME', 'TXT'], ttl_min: 60, ttl_max: 86400 })).policy.id;
const narrow = (await mk('/rr-policies', { name: 'narrow', allowed_types: ['A'], ttl_min: 120, ttl_max: 3600 })).policy.id;
const wide = (await mk('/rr-policies', { name: 'wide', allowed_types: ['A', 'MX', 'NS'], allow_delegation: true, apex_editable: true })).policy.id;
const dom = (await mk('/principals', { kind: 'user', name: 'dom', password: 'Sunrise-Harbor-42' })).principal.id;
const sub = (await mk('/principals', { kind: 'user', name: 'sub', password: 'Maple-Anchor-77' })).principal.id;
const nobody = (await mk('/principals', { kind: 'user', name: 'nobody', password: 'Violet-Lantern-9' })).principal.id;
const team = (await mk('/principals', { kind: 'group', name: 'team' })).principal.id;
const victim = (await mk('/principals', { kind: 'user', name: 'victim', password: 'Cobalt-Ranger-31' })).principal.id;
eq('a name is unique whatever its case', (await admin.do('POST', '/principals', { body: { kind: 'group', name: 'TEAM' } })).status, 409);
eq('a member of a group', (await admin.do('POST', `/principals/${team}/members`, { body: { member: nobody } })).status, 201);
await mk('/grants', { principal: dom, role: 'domain_master', dataset: 'main', zone: 'example.test', policy: web });
await mk('/grants', { principal: sub, role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policy: web });
await mk('/grants', { principal: team, role: 'domain_master', zone: 'other.test', policy: web });
const grants = await admin.do('GET', '/grants');
eq('three grants (and the administrator\'s own)', grants.body.grants.length, 4);
eq('a policy in use is not deleted', (await admin.do('DELETE', `/rr-policies/${web}`)).status, 409);

// ---------------------------------------------------------------------------------------------------------------------------------- reading
console.log('-- reading: what each principal sees');
const D = await login('dom', 'Sunrise-Harbor-42');
const U = await login('sub', 'Maple-Anchor-77');
const N = await login('nobody', 'Violet-Lantern-9');
eq('the zone list of a global master', (await admin.do('GET', '/datasets/main/zones')).body.zones.map((z) => z.name), ['example.test.', 'other.test.']);
eq('...of a domain master', (await D.do('GET', '/datasets/main/zones')).body.zones.map((z) => [z.name, z.role]), [['example.test.', 'domain_master']]);
eq('...of a subdomain master', (await U.do('GET', '/datasets/main/zones')).body.zones.map((z) => [z.name, z.role]), [['example.test.', 'subdomain_master']]);
eq('...of a member of a group that has a grant', (await N.do('GET', '/datasets/main/zones')).body.zones.map((z) => [z.name, z.role]), [['other.test.', 'domain_master']]);
const info = (await D.do('GET', '/datasets/main/zones/example.test.')).body.zone;
check('zone info: kind, serial, generation', info.kind === 'NATIVE' && info.serial > 0 && info.generation > 0, () => JSON.stringify(info));
eq('a zone without a grant is 404, like one that does not exist', [(await D.do('GET', '/datasets/main/zones/other.test')).status, (await D.do('GET', '/datasets/main/zones/ghost.test')).status], [404, 404]);
const all = names(await D.do('GET', '/datasets/main/zones/example.test/rrsets?limit=500'));
check('a domain master reads the whole zone', all.includes('www.example.test. A') && all.includes('evilsub.example.test. A') && all.includes('example.test. SOA'), () => all.join());
const mine = names(await U.do('GET', '/datasets/main/zones/example.test/rrsets?limit=500'));
check('a subdomain master reads its suffix and the apex SOA and NS', mine.includes('sub.example.test. A') && mine.includes('a.sub.example.test. TXT') && mine.includes('example.test. SOA') && mine.includes('example.test. NS'), () => mine.join());
check('...and nothing else: not evilsub (the label boundary), not www, not the MX', !mine.some((n) => /^(evilsub|www)\./.test(n) || n === 'example.test. MX'), () => mine.join());
const seen = [];
let cursor = '';
for (let i = 0; i < 50; i++) {
  const r = await admin.do('GET', `/datasets/main/zones/example.test/rrsets?limit=2${cursor}`);
  seen.push(...names(r));
  if (!r.body.next_cursor) break;
  cursor = `&cursor=${r.body.next_cursor}`;
}
check('paging by two walks the zone once, in order', seen.length === all.length && new Set(seen).size === seen.length && JSON.stringify(seen) === JSON.stringify([...seen].sort()), () => seen.join());
const www = (await admin.do('GET', '/datasets/main/zones/example.test/rrsets?name=www.example.test&type=a')).body.rrsets[0];
check('an RRset with its records and TTL', www && www.records.length >= 1 && www.ttl > 0, () => JSON.stringify(www));
eq('an unknown dataset is 404', (await admin.do('GET', '/datasets/nowhere/zones')).status, 404);
const exp = await admin.do('GET', '/datasets/main/zones/example.test/export');
check('the export (karidns-zone, canonical order)', exp.status === 200 && /^\$ORIGIN example\.test\./m.test(exp.text) && /www/.test(exp.text) && /text\/plain/.test(exp.headers.get('content-type')), () => `${exp.status} ${exp.text.slice(0, 200)}`);
eq('...a domain master may export, a subdomain master may not, a stranger finds no zone', [(await D.do('GET', '/datasets/main/zones/example.test/export')).status, (await U.do('GET', '/datasets/main/zones/example.test/export')).status, (await N.do('GET', '/datasets/main/zones/example.test/export')).status], [200, 403, 404]);

eq('principals: a global master lists all of them', (await admin.do('GET', '/principals?limit=500')).body.principals.map((p) => p.name).filter((n) => n !== 'admin'), ['dom', 'sub', 'nobody', 'team', 'victim']);
eq('...a domain master itself and the holders of a grant on its zone, a member only itself and its group (paged by one)', [(await D.do('GET', '/principals')).body.principals.map((p) => p.name), (await N.do('GET', '/principals?limit=1')).body.principals.map((p) => p.name), (await N.do('GET', `/principals?limit=1&cursor=${(await N.do('GET', '/principals?limit=1')).body.next_cursor}`)).body.principals.map((p) => p.name)], [['dom', 'sub'], ['nobody'], ['team']]);
eq('...anybody else is 404, as is a principal that does not exist', [(await D.do('GET', `/principals/${sub}`)).status, (await N.do('GET', `/principals/${victim}`)).status, (await N.do('GET', '/principals/999999')).status, (await N.do('GET', `/principals/${team}`)).status], [200, 404, 404, 200]);
eq('...the members of a group: of its own groups only', [(await N.do('GET', `/principals/${team}/members`)).body.members.map((m) => m.name), (await U.do('GET', `/principals/${team}/members`)).status], [['nobody'], 404]);
eq('policies: all for a global master, those of the own grants for the others', [(await admin.do('GET', '/rr-policies?limit=500')).body.policies.length, (await D.do('GET', '/rr-policies')).body.policies.map((p) => p.name), (await N.do('GET', '/rr-policies')).body.policies.map((p) => p.name)], [4, ['web', 'narrow'], ['web', 'narrow']]);
eq('...another policy is 404', [(await D.do('GET', `/rr-policies/${wide}`)).status, (await D.do('GET', `/rr-policies/${web}`)).status], [404, 200]);

// ---------------------------------------------------------------------------------------------------------------------------------- escalation
const dgrp = (await mk('/principals', { kind: 'group', name: 'dgrp' })).principal.id;
for (const m of [dom, victim]) await admin.do('POST', `/principals/${dgrp}/members`, { body: { member: m } });
eq('a domain master sees its group, the members of it and the holders on its zone (short form), no stranger', [(await D.do('GET', '/principals')).body.principals.map((p) => p.name), Object.keys((await D.do('GET', `/principals/${victim}`)).body.principal).sort(), (await D.do('GET', `/principals/${nobody}`)).status, (await D.do('GET', `/principals/${dgrp}/members`)).body.members.map((m) => m.name), (await D.do('GET', `/principals/${team}/members`)).status], [['dom', 'sub', 'victim', 'dgrp'], ['display_name', 'id', 'kind', 'name'], 404, ['dom', 'victim'], 404]);
eq('...and grants to those it sees only', [(await D.do('POST', '/grants', { body: { principal: nobody, role: 'subdomain_master', zone: 'example.test', suffix: 'zz.example.test', policy: narrow } })).status, (await D.do('POST', '/grants', { body: { principal: 999999, role: 'subdomain_master', zone: 'example.test', suffix: 'zz.example.test', policy: narrow } })).status], [404, 404]);

console.log('-- grants: no escalation');
const g1 = await D.do('POST', '/grants', { body: { principal: victim, role: 'subdomain_master', zone: 'example.test', suffix: 'cust.example.test', policy: narrow } });
eq('a domain master grants inside its zone with a narrower policy', g1.status, 201);
eq('...not with a wider policy', type(await D.do('POST', '/grants', { body: { principal: victim, role: 'subdomain_master', zone: 'example.test', suffix: 'x.example.test', policy: wide } })), 'escalation');
eq('...not on another zone', type(await D.do('POST', '/grants', { body: { principal: victim, role: 'domain_master', zone: 'other.test', policy: narrow } })), 'escalation');
eq('...not a global master', type(await D.do('POST', '/grants', { body: { principal: victim, role: 'global_master', policy: narrow } })), 'escalation');
eq('a subdomain master grants nothing', type(await U.do('POST', '/grants', { body: { principal: victim, role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policy: narrow } })), 'escalation');
eq('a domain master sees the grants on its zone, not those on others', (await D.do('GET', '/grants')).body.grants.map((g) => `${g.principal}:${g.zone}`), ['dom:example.test.', 'sub:example.test.', 'victim:example.test.']);
eq('...and removes the one it made', (await D.do('DELETE', `/grants/${g1.body.grant.id}`)).status, 204);
eq('only a global master writes principals and policies', [type(await D.do('POST', '/principals', { body: { kind: 'group', name: 'x' } })), type(await D.do('POST', '/rr-policies', { body: { name: 'x', allowed_types: [] } }))], ['forbidden', 'forbidden']);

// ---------------------------------------------------------------------------------------------------------------------------------- audit
console.log('-- the audit log');
const audit = (await admin.do('GET', '/audit?limit=500')).body.audit;
check('a global master reads the log: who, what, redacted', audit.some((r) => r.table === 'principals' && r.after?.name === 'dom' && r.principal === 'admin' && r.op === 'I')
  && audit.some((r) => r.table === 'credentials' && r.after?.password_hash === '<redacted>') && !JSON.stringify(audit).includes('$scrypt$'), () => `${audit.length} rows`);
const dAudit = (await D.do('GET', '/audit?limit=500')).body.audit;
check('a domain master reads the rows of its zone only', dAudit.length > 0 && dAudit.every((r) => r.zone === 'example.test.'), () => JSON.stringify(dAudit.map((r) => r.zone)));
check('...among them the grants made on it', dAudit.some((r) => r.table === 'grants' && r.op === 'I' && r.principal === 'dom'), () => JSON.stringify(dAudit.map((r) => [r.table, r.op, r.principal])));
eq('a subdomain master reads none', (await U.do('GET', '/audit?limit=500')).body.audit, []);

console.log('-- the filters of the lists (every statement they make runs on this database)');
const f = async (p) => (await admin.do('GET', p));
const za = await f('/audit?zone=example.test&limit=50');
check('audit by zone', za.status === 200 && za.body.audit.length > 0 && za.body.audit.every((r) => r.zone === 'example.test.'), () => `${za.status} ${za.text.slice(0, 200)}`);
const pa = await f(`/audit?principal=${dom}&limit=50`);
check('audit by principal, table and time', pa.status === 200 && pa.body.audit.every((r) => r.principal_id === dom)
  && (await f('/audit?table=grants&limit=50')).body.audit.every((r) => r.table === 'grants')
  && (await f('/audit?since=2000-01-01T00:00:00Z&until=2999-01-01T00:00:00Z&limit=3')).body.audit.length === 3
  && (await f('/audit?since=2999-01-01T00:00:00Z')).body.audit.length === 0, () => `${pa.status} ${pa.text.slice(0, 200)}`);
const cs = audit.find((r) => r.change_set);
check('audit by change set (where the log has one)', !cs || (await f(`/audit?change_set=${cs.change_set}`)).body.audit.every((r) => r.change_set === cs.change_set));
const gp = await f(`/grants?principal=${dom}&zone=example.test`);
check('grants by principal and zone', gp.status === 200 && gp.body.grants.length === 1 && gp.body.grants[0].principal === 'dom', () => gp.text);
eq('principals by kind and prefix', (await f('/principals?kind=group&prefix=TEA')).body.principals.map((p) => p.name), ['team']);
eq('policies, paged', (await f('/rr-policies?limit=1')).body.policies.length, 1);
eq('zones by prefix, kind and signed', [(await f('/datasets/main/zones?prefix=oth&kind=NATIVE&signed=false')).body.zones.map((z) => z.name), (await f('/datasets/main/zones?signed=true')).body.zones], [['other.test.'], []]);
const one = await f('/datasets/main/zones/example.test/rrsets?name=sub.example.test&type=A');
eq('RRsets by name and type', names(one), ['sub.example.test. A']);
const tl = await f('/tokens?all=true&limit=5');
check('tokens, all of them', tl.status === 200 && Array.isArray(tl.body.tokens), () => tl.text);

// ---------------------------------------------------------------------------------------------------------------------------------- tokens, CSRF
console.log('-- tokens, CSRF and Origin');
const tok = await D.do('POST', '/tokens', { body: { name: 'ci', days: 10 } });
eq('a token is made once', [tok.status, /^kdt_\d+_[\w-]{43}$/.test(tok.body.token)], [201, true]);
eq('...and acts as its principal', (await call('GET', '/datasets/main/zones', { token: tok.body.token })).body.zones.map((z) => z.name), ['example.test.']);
const ro = (await D.do('POST', '/tokens', { body: { name: 'ro', read_only: true } })).body.token;
eq('a read-only token reads and cannot write', [(await call('GET', '/principals', { token: ro })).status, type(await call('POST', '/principals', { token: ro, body: { kind: 'group', name: 'z' } }))], [200, 'read-only-token']);
eq('a token makes no token', type(await call('POST', '/tokens', { token: tok.body.token, body: { name: 'child' } })), 'session-only');
eq('cookie and token together are refused', type(await call('GET', '/auth/me', { cookie: D.cookie, token: tok.body.token })), 'both-credentials');
eq('a revoked token is dead', [(await D.do('DELETE', `/tokens/${tok.body.info.id}`)).status, (await call('GET', '/auth/me', { token: tok.body.token })).status], [204, 401]);
const post = (o) => call('POST', '/principals', { cookie: D.cookie, body: { kind: 'group', name: 'csrf-test' }, ...o });
eq('an unsafe request needs the CSRF token and the Origin', [type(await post({})), type(await post({ csrf: D.csrf })), type(await post({ csrf: D.csrf, origin: 'http://evil.test' }))], ['csrf', 'csrf', 'csrf']);

// ---------------------------------------------------------------------------------------------------------------------------------- lockout, expiry, disabling
console.log('-- lockout, expiry, a disabled user');
for (let i = 0; i < 10; i++) await call('POST', '/auth/login', { body: { user: 'victim', password: 'not the password' } });
eq('ten failures lock the account: the right password is refused too', type(await call('POST', '/auth/login', { body: { user: 'victim', password: 'Cobalt-Ranger-31' } })), 'invalid-credentials');
eq('...as seen by an administrator', (await admin.do('GET', `/principals/${victim}`)).body.credentials.locked, true);
const dis = await login('sub', 'Maple-Anchor-77');
const disTok = (await dis.do('POST', '/tokens', { body: { name: 'x' } })).body.token;
eq('an administrator disables a user', (await admin.do('PATCH', `/principals/${sub}`, { body: { disabled: true } })).status, 200);
eq('...its session and its token stop at once, and it cannot log in', [(await dis.do('GET', '/auth/me')).status, (await call('GET', '/auth/me', { token: disTok })).status, (await call('POST', '/auth/login', { body: { user: 'sub', password: 'Maple-Anchor-77' } })).status], [401, 401, 401]);
const D2 = await login('dom', 'Sunrise-Harbor-42');
eq('a password is changed with the old one', [type(await D2.do('POST', '/auth/password', { body: { current: 'wrong password 12', new: 'a new password 123' } })), (await D2.do('POST', '/auth/password', { body: { current: 'Sunrise-Harbor-42', new: 'a new password 123' } })).status, (await login('dom', 'a new password 123')).status], ['wrong-password', 200, 200]);

// a session that is not used is over after session-idle seconds (the server runs with 8)
const idle = await login('dom', 'a new password 123');
eq('a session works', (await idle.do('GET', '/auth/me')).status, 200);
await sleep((IDLE + 1) * 1000);
eq(`a session unused for ${IDLE} seconds is over`, (await idle.do('GET', '/auth/me')).status, 401);

// ---------------------------------------------------------------------------------------------------------------------------------- rate limit
console.log('-- rate limits');
let limited = 0;
for (let i = 0; i < 90 && !limited; i++) {
  const r = await call('POST', '/auth/login', { body: { user: `nobody${i}`, password: 'x' } });
  if (r.status === 429) limited = i + 1;
}
check('login attempts are limited (rate-login = 60 a minute)', limited > 0 && limited <= 90, () => `no 429 in 90 attempts`);
const after = await call('POST', '/auth/login', { body: { user: 'dom', password: 'Sunrise-Harbor-42' } });
eq('...with a Retry-After', [after.status, /^\d+$/.test(after.headers.get('retry-after') ?? '')], [429, true]);

console.log(`\n${pass} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);

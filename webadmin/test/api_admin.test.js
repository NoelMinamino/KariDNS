// principals, groups, policies, grants: through the HTTP server, on SQLite3 (where the API's checks are the only checks)

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast } from './helpers.js';

const withCast = (fn, opts) => async () => {
  const d = await deploy(opts);
  try {
    const c = await cast(d);
    const root = d.as(await d.login('root', 'correct horse battery'));
    const dom = d.as(await d.login('dom', 'dom password 12345'));
    const sub = d.as(await d.login('sub', 'sub password 12345'));
    await fn(d, { ...c, root, dom, sub });
  } finally {
    await d.close();
  }
};
const is = (r, status, type) => {
  assert.equal(r.status, status, JSON.stringify(r.body));
  if (type) assert.equal(r.body.type, `urn:karidns:api:${type}`, JSON.stringify(r.body));
};

test('principals: listing, paging, filters', withCast(async (d, { root, dom }) => {
  const all = await root('GET', '/principals');
  assert.deepEqual(all.body.principals.map((p) => p.name), ['root', 'dom', 'sub']);
  assert.equal(all.body.next_cursor, null);
  const p1 = await root('GET', '/principals?limit=2');
  assert.equal(p1.body.principals.length, 2);
  assert.ok(p1.body.next_cursor);
  const p2 = await root('GET', `/principals?limit=2&cursor=${p1.body.next_cursor}`);
  assert.deepEqual(p2.body.principals.map((p) => p.name), ['sub']);
  await root('POST', '/principals', { body: { kind: 'group', name: 'Customers' } });
  assert.deepEqual((await root('GET', '/principals?kind=group')).body.principals.map((p) => p.name), ['Customers']);
  assert.deepEqual((await root('GET', '/principals?prefix=CUST')).body.principals.map((p) => p.name), ['Customers']);
  is(await root('GET', '/principals?kind=robot'), 400, 'bad-request');
  is(await root('GET', '/principals?cursor=zzz'), 400, 'bad-request');
}));

test('principals: create, read, change, delete; only a global master writes', withCast(async (d, { root, dom }) => {
  is(await dom('POST', '/principals', { body: { kind: 'group', name: 'x' } }), 403, 'forbidden');
  const made = await root('POST', '/principals', { body: { kind: 'user', name: 'alice@example.test', display_name: 'Alice', email: 'alice@example.test', password: 'alice password 12' } });
  is(made, 201);
  assert.equal(made.body.principal.name, 'alice@example.test');
  assert.equal(made.body.principal.display_name, 'Alice');
  assert.equal(JSON.stringify(made.body).includes('password'), false);
  const id = made.body.principal.id;
  assert.equal((await d.login('alice@example.test', 'alice password 12')).status, 200);
  // names are unique whatever their case
  is(await root('POST', '/principals', { body: { kind: 'group', name: 'ALICE@example.test' } }), 409, 'exists');
  // validation
  is(await root('POST', '/principals', { body: { kind: 'group', name: 'g', password: 'a password of 12 or more' } }), 400, 'bad-request');
  is(await root('POST', '/principals', { body: { kind: 'user', name: 'bob', password: 'short' } }), 400, 'bad-request');
  is(await root('POST', '/principals', { body: { kind: 'user', name: 'bob', password: 'bob is my password' } }), 400, 'weak-password');
  is(await root('POST', '/principals', { body: { kind: 'user', name: '-bad' } }), 400, 'bad-request');
  is(await root('POST', '/principals', { body: { kind: 'user', name: 'a b' } }), 400, 'bad-request');
  is(await root('POST', '/principals', { body: { kind: 'robot', name: 'r' } }), 400, 'bad-request');
  is(await root('POST', '/principals', { body: { kind: 'user', name: 'e', email: 'not an address' } }), 400, 'bad-request');
  // reading: credentials only for a global master and for oneself
  const asRoot = await root('GET', `/principals/${id}`);
  assert.deepEqual(asRoot.body.credentials, { password: true, totp_enabled: false, failed_logins: 0, locked: false, oidc: null });
  assert.equal(asRoot.body.principal.created_by, 1);
  assert.equal((await dom('GET', `/principals/${id}`)).body.credentials, undefined);
  assert.notEqual((await dom('GET', '/principals/2')).body.credentials, undefined);
  assert.deepEqual((await root('GET', '/principals/3')).body.credentials, { password: true, totp_enabled: false, failed_logins: 0, locked: false, oidc: null });
  const group = (await root('POST', '/principals', { body: { kind: 'group', name: 'nocreds' } })).body.principal.id;
  assert.deepEqual((await root('GET', `/principals/${group}`)).body.credentials, { password: false, totp_enabled: false, failed_logins: 0, locked: false, oidc: null });
  is(await root('GET', '/principals/999'), 404, 'not-found');
  is(await root('GET', '/principals/x'), 404, 'not-found');
  // changing
  const patched = await root('PATCH', `/principals/${id}`, { body: { display_name: null, email: 'a@example.test', name: 'alice2' } });
  assert.equal(patched.body.principal.name, 'alice2');
  assert.equal(patched.body.principal.display_name, null);
  is(await root('PATCH', `/principals/${id}`, { body: { name: 'root' } }), 409, 'exists');
  is(await root('PATCH', '/principals/999', { body: { name: 'zz' } }), 404, 'not-found');
  is(await root('PATCH', '/principals/999', { body: {} }), 404, 'not-found');
  is(await root('PATCH', '/principals/1', { body: { disabled: true } }), 409, 'self');
  is(await dom('PATCH', `/principals/${id}`, { body: { name: 'x' } }), 403, 'forbidden');
  is(await root('PATCH', `/principals/${id}`, { body: { unknown: 1 } }), 400, 'bad-request');
  // the password reset ends the user's sessions and revokes its API tokens (audit, 0.6.2)
  const s = await d.login('alice2', 'alice password 12');
  const tok = (await d.as(s)('POST', '/tokens', { body: { name: 'ci' } })).body.token;
  assert.equal((await d.request('GET', '/auth/me', { token: tok })).status, 200);
  is(await root('PUT', `/principals/${id}/password`, { body: { password: 'alice2 is the name' } }), 400, 'weak-password');
  is(await root('PUT', `/principals/${id}/password`, { body: { password: 'a brand new password' } }), 200);
  is(await d.as(s)('GET', '/auth/me'), 401, 'unauthenticated');
  is(await d.request('GET', '/auth/me', { token: tok }), 401, 'unauthenticated');
  assert.equal((await d.login('alice2', 'a brand new password')).status, 200);
  is(await root('PUT', `/principals/${group}/password`, { body: { password: 'a brand new password' } }), 409, 'not-a-user');
  is(await root('PUT', '/principals/999/password', { body: { password: 'a brand new password' } }), 404, 'not-found');
  is(await dom('PUT', `/principals/${id}/password`, { body: { password: 'a brand new password' } }), 403, 'forbidden');
  // a user without a password gets one from the administrator
  const svc = await d.makeUser('svc', null);
  is(await root('PUT', `/principals/${svc}/password`, { body: { password: 'service password 1' } }), 200);
  assert.equal((await d.login('svc', 'service password 1')).status, 200);
  // deleting
  is(await dom('DELETE', `/principals/${id}`), 403, 'forbidden');
  is(await root('DELETE', '/principals/1'), 409, 'self');
  is(await root('DELETE', `/principals/${id}`), 204);
  is(await root('DELETE', `/principals/${id}`), 404, 'not-found');
  is(await root('GET', `/principals/${id}`), 404, 'not-found');
}));

test('groups: members, nesting, no cycle, users have no members', withCast(async (d, { root, dom }) => {
  const mk = async (name) => (await root('POST', '/principals', { body: { kind: 'group', name } })).body.principal.id;
  const [a, b, c] = [await mk('ga'), await mk('gb'), await mk('gc')];
  is(await root('POST', `/principals/${a}/members`, { body: { member: 2 } }), 201);
  is(await root('POST', `/principals/${a}/members`, { body: { member: 2 } }), 409);
  is(await root('POST', `/principals/${a}/members`, { body: { member: 999 } }), 404, 'not-found');
  is(await root('POST', `/principals/${a}/members`, { body: {} }), 400, 'bad-request');
  is(await root('POST', '/principals/999/members', { body: { member: 2 } }), 404, 'not-found');
  is(await root('POST', '/principals/2/members', { body: { member: 3 } }), 409, 'not-a-group');
  is(await dom('POST', `/principals/${a}/members`, { body: { member: 3 } }), 403, 'forbidden');
  // nesting: b is in a, c is in b; a in c would close the circle
  is(await root('POST', `/principals/${a}/members`, { body: { member: b } }), 201);
  is(await root('POST', `/principals/${b}/members`, { body: { member: c } }), 201);
  const cycle = await root('POST', `/principals/${c}/members`, { body: { member: a } });
  is(cycle, 409, 'refused');
  assert.match(cycle.body.detail, /cycle/);
  const list = await dom('GET', `/principals/${a}/members`);
  assert.deepEqual(list.body.members.map((m) => m.name), ['dom', 'gb']);
  assert.equal(list.body.group.name, 'ga');
  is(await dom('GET', '/principals/2/members'), 409, 'not-a-group');
  is(await dom('GET', '/principals/999/members'), 404, 'not-found');
  // the memberships show in the principal and in /auth/me
  const info = await root('GET', '/principals/2');
  assert.deepEqual(info.body.groups.map((g) => g.name), ['ga']);
  assert.equal(info.body.groups[0].tenant, true);
  const nested = await root('GET', `/principals/${c}`);
  assert.deepEqual(nested.body.groups.map((g) => [g.name, g.depth, g.tenant]), [['gb', 1, false], ['ga', 2, true]]);
  const me = await dom('GET', '/auth/me');
  assert.deepEqual(me.body.tenants, [{ id: a, name: 'ga' }]);
  // removing
  is(await dom('DELETE', `/principals/${a}/members/2`), 403, 'forbidden');
  is(await root('DELETE', `/principals/${a}/members/2`), 204);
  is(await root('DELETE', `/principals/${a}/members/2`), 404, 'not-found');
  is(await root('DELETE', `/principals/2/members/3`), 409, 'not-a-group');
  assert.equal((await root('GET', `/principals/${a}/members`)).body.members.length, 1);
}));

test('policies: create, normalise, validate, change, delete', withCast(async (d, { root, dom }) => {
  const made = await root('POST', '/rr-policies', { body: { name: 'mail', allowed_types: ['mx', 'TXT', 'a', 'A'], ttl_min: 300, max_rr: 20 } });
  is(made, 201);
  assert.deepEqual(made.body.policy, {
    id: made.body.policy.id, name: 'mail', allowed_types: ['A', 'MX', 'TXT'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false,
    ttl_min: 300, ttl_max: 2147483647, max_rr: 20,
  });
  const id = made.body.policy.id;
  is(await dom('POST', '/rr-policies', { body: { name: 'x', allowed_types: [] } }), 403, 'forbidden');
  is(await root('POST', '/rr-policies', { body: { name: 'mail', allowed_types: [] } }), 409, 'exists');
  is(await root('POST', '/rr-policies', { body: { allowed_types: [] } }), 400, 'bad-request');
  is(await root('POST', '/rr-policies', { body: { name: 'x' } }), 400, 'bad-request');
  is(await root('POST', '/rr-policies', { body: { name: 'x', allowed_types: ['A'], ttl_min: 10, ttl_max: 5 } }), 400, 'bad-request');
  is(await root('POST', '/rr-policies', { body: { name: 'x', allowed_types: ['A b'] } }), 400, 'bad-request');
  for (const bad of ['RRSIG', 'dnskey', 'NSEC3PARAM', 'TYPE46', 'type0048', 'TYPE2', 'TYPE6', 'TYPE39', 'ANY', 'AXFR', 'OPT', 'TSIG']) {
    const r = await root('POST', '/rr-policies', { body: { name: 'x', allowed_types: ['A', bad] } });
    is(r, 400, 'bad-request');
    assert.equal(r.body.errors[0].pointer, '/allowed_types/1', bad);
  }
  assert.equal((await root('POST', '/rr-policies', { body: { name: 'generic', allowed_types: ['TYPE65'] } })).status, 201);
  assert.equal((await root('GET', `/rr-policies/${id}`)).body.policy.name, 'mail');
  is(await root('GET', '/rr-policies/999'), 404, 'not-found');
  const list = await root('GET', '/rr-policies?limit=2');
  assert.equal(list.body.policies.length, 2);
  assert.deepEqual((await root('GET', `/rr-policies?limit=2&cursor=${list.body.next_cursor}`)).body.policies.map((p) => p.name), ['mail', 'generic']);
  // changing: one field, the types, the limits together
  assert.equal((await root('PATCH', `/rr-policies/${id}`, { body: { max_rr: null, allow_wildcard: true } })).body.policy.max_rr, null);
  assert.deepEqual((await root('PATCH', `/rr-policies/${id}`, { body: { allowed_types: ['mx'] } })).body.policy.allowed_types, ['MX']);
  assert.equal((await root('PATCH', `/rr-policies/${id}`, { body: { name: 'mail2' } })).body.policy.name, 'mail2');
  assert.equal((await root('PATCH', `/rr-policies/${id}`, { body: {} })).body.policy.name, 'mail2');
  is(await root('PATCH', `/rr-policies/${id}`, { body: { ttl_max: 100 } }), 400, 'bad-request');       // below ttl_min 300
  is(await root('PATCH', `/rr-policies/${id}`, { body: { allowed_types: ['RRSIG'] } }), 400, 'bad-request');
  is(await root('PATCH', '/rr-policies/999', { body: { name: 'z' } }), 404, 'not-found');
  is(await dom('PATCH', `/rr-policies/${id}`, { body: { name: 'z' } }), 403, 'forbidden');
  // a policy in use is not deleted
  assert.equal((await root('DELETE', '/rr-policies/2')).status, 409);
  is(await root('DELETE', `/rr-policies/${id}`), 204);
  is(await root('DELETE', `/rr-policies/${id}`), 404, 'not-found');
  is(await dom('DELETE', '/rr-policies/1'), 403, 'forbidden');
}));

// who may read which principals and policies (perm.js principalsScope / policiesScope): a global master all; everyone else (a domain master for now too) itself, its groups, the
// members of its groups and the policies of its own grants, the rest is 404
test('principals and policies: a global master reads all, everyone else only its own; paging over the filtered list', withCast(async (d, { root, dom, sub, web, all }) => {
  const viaTeam = await d.makePolicy({ name: 'via-team', allowed_types: ['TXT'] });
  const secret = await d.makePolicy({ name: 'secret', allowed_types: ['MX'] });
  const narrowP = await d.makePolicy({ name: 'narrow', allowed_types: ['A'], ttl_min: 120, ttl_max: 3600 });         // (no wider than web: a domain master could use it)
  const zonePol = await d.makePolicy({ name: 'zone-pol', allowed_types: ['MX'] });                               // (wider, but used by a grant on example.test)
  const grant = (policyId) => [{ role: 'subdomain_master', zone: 'other.test', suffix: 'a.other.test', policyId, schema: '' }];
  const team = await d.makeUser('team', null, { kind: 'group', grants: grant(viaTeam) });
  const hidden = await d.makeUser('hidden', null, { kind: 'group', grants: grant(secret) });
  const colleague = await d.makeUser('colleague', 'colleague password 1', {});
  const holder = await d.makeUser('holder', null, { grants: [{ role: 'subdomain_master', zone: 'example.test', suffix: 'h.example.test', policyId: zonePol, schema: '' }] });
  const dg = await d.makeUser('dg', null, { kind: 'group' });
  const dgm = await d.makeUser('dgm', 'dgm password 12345', {});
  for (const m of [2, dgm]) is(await root('POST', `/principals/${dg}/members`, { body: { member: m } }), 201);
  const subId = 3;
  const gs = [];
  for (const n of ['g1', 'x1', 'g2', 'x2', 'g3', 'x3', 'g4']) gs.push(await d.makeUser(n, null, { kind: n[0] === 'g' ? 'group' : 'user' }));
  for (const g of [team, ...gs.filter((_, i) => i % 2 === 0)]) is(await root('POST', `/principals/${g}/members`, { body: { member: subId } }), 201);
  is(await root('POST', `/principals/${team}/members`, { body: { member: colleague } }), 201);
  is(await root('POST', `/principals/${hidden}/members`, { body: { member: colleague } }), 201);
  // a global master: everything, in full
  const rootAll = await root('GET', '/principals?limit=500');
  assert.equal(rootAll.body.principals.length, 3 + 2 + 1 + 7 + 3);
  assert.ok(rootAll.body.principals.every((p) => 'email' in p && 'disabled' in p));
  assert.equal((await root('GET', '/rr-policies?limit=500')).body.policies.length, 6);
  is(await root('GET', `/principals/${hidden}`), 200);
  is(await root('GET', `/rr-policies/${secret}`), 200);
  // sub: itself and its five groups, in id order, in pages of two (none short, none empty); itself and its groups in full
  const names = [];
  let cursor = '';
  for (let i = 0; i < 10; i++) {
    const r = await sub('GET', `/principals?limit=2${cursor}`);
    is(r, 200);
    if (r.body.next_cursor) assert.equal(r.body.principals.length, 2);
    names.push(...r.body.principals.map((p) => p.name));
    assert.ok(r.body.principals.every((p) => 'email' in p && 'disabled' in p));
    if (!r.body.next_cursor) break;
    cursor = `&cursor=${r.body.next_cursor}`;
  }
  assert.deepEqual(names, ['sub', 'team', 'g1', 'g2', 'g3', 'g4']);
  assert.deepEqual((await sub('GET', '/principals?kind=group&prefix=G')).body.principals.map((p) => p.name), ['g1', 'g2', 'g3', 'g4']);
  assert.deepEqual((await sub('GET', '/principals?prefix=col')).body.principals, [], 'a search finds nothing outside its reach');
  // a domain master is in no group: only itself
  // a domain master of example.test: itself, its group and the members of its group, the holders of a grant on its zone; the others in the short form
  const domAll = await dom('GET', '/principals');
  assert.deepEqual(domAll.body.principals.map((p) => p.name), ['dom', 'sub', 'holder', 'dg', 'dgm']);
  assert.deepEqual(domAll.body.principals.map((p) => 'email' in p), [true, false, false, true, false]);
  assert.deepEqual(Object.keys(domAll.body.principals[1]).sort(), ['display_name', 'id', 'kind', 'name']);
  assert.deepEqual((await dom('GET', '/principals?prefix=ho')).body.principals.map((p) => p.name), ['holder']);
  assert.deepEqual((await dom('GET', '/principals?prefix=col')).body.principals, []);
  assert.deepEqual((await dom('GET', '/principals?kind=group')).body.principals.map((p) => p.name), ['dg']);
  const dp1 = await dom('GET', '/principals?limit=2');
  const dp2 = await dom('GET', `/principals?limit=2&cursor=${dp1.body.next_cursor}`);
  const dp3 = await dom('GET', `/principals?limit=2&cursor=${dp2.body.next_cursor}`);
  assert.deepEqual([dp1, dp2, dp3].map((r) => r.body.principals.map((p) => p.name)), [['dom', 'sub'], ['holder', 'dg'], ['dgm']]);
  assert.equal(dp3.body.next_cursor, null);
  is(await dom('GET', `/principals/${holder}`), 200);
  assert.deepEqual(Object.keys((await dom('GET', `/principals/${holder}`)).body.principal).sort(), ['display_name', 'id', 'kind', 'name']);
  is(await dom('GET', `/principals/${colleague}`), 404, 'not-found');
  is(await dom('GET', '/principals/1'), 404, 'not-found');
  assert.deepEqual((await dom('GET', `/principals/${dg}/members`)).body.members.map((m) => [m.name, 'email' in m]), [['dgm', false], ['dom', true]]);
  // granting: to a principal it sees; an outsider is as good as not there
  is(await dom('POST', '/grants', { body: { principal: dgm, role: 'subdomain_master', zone: 'example.test', suffix: 'x.example.test', policy: narrowP } }), 201);
  const out1 = await dom('POST', '/grants', { body: { principal: colleague, role: 'subdomain_master', zone: 'example.test', suffix: 'y.example.test', policy: narrowP } });
  const out2 = await dom('POST', '/grants', { body: { principal: 99999, role: 'subdomain_master', zone: 'example.test', suffix: 'y.example.test', policy: narrowP } });
  is(out1, 404, 'not-found');
  assert.deepEqual({ ...out1.body, request_id: 0 }, { ...out2.body, request_id: 0 });
  is(await root('POST', '/grants', { body: { principal: colleague, role: 'subdomain_master', zone: 'example.test', suffix: 'y.example.test', policy: narrowP } }), 201);
  assert.deepEqual((await dom('GET', '/principals?prefix=col')).body.principals.map((p) => p.name), ['colleague'], 'a holder on its zone is in the set');
  // one principal: its own and its groups' are there, anybody else's (existing or not) is the same 404
  is(await sub('GET', `/principals/${subId}`), 200);
  is(await sub('GET', `/principals/${team}`), 200);
  const no = await sub('GET', `/principals/${hidden}`);
  const none = await sub('GET', '/principals/99999');
  is(no, 404, 'not-found');
  assert.deepEqual({ ...no.body, request_id: 0 }, { ...none.body, request_id: 0 });
  is(await sub('GET', `/principals/${colleague}`), 404, 'not-found');
  is(await dom('GET', `/principals/${hidden}`), 404, 'not-found');
  is(await dom('GET', '/principals/2'), 200);
  // the members of a group: of its own groups only; the others than itself and its groups are shown in short
  const mem = await sub('GET', `/principals/${team}/members`);
  is(mem, 200);
  assert.deepEqual(mem.body.members.map((m) => m.name), ['colleague', 'sub']);
  assert.deepEqual(Object.keys(mem.body.members[0]).sort(), ['display_name', 'id', 'kind', 'name']);
  assert.ok('email' in mem.body.members[1], 'itself in full');
  is(await sub('GET', `/principals/${hidden}/members`), 404, 'not-found');
  is(await sub('GET', '/principals/99999/members'), 404, 'not-found');
  is(await dom('GET', `/principals/${team}/members`), 404, 'not-found');
  // policies: those of its own grants, direct or through a group
  const own = async (as, q = '') => (await as('GET', `/rr-policies?limit=1${q}`));
  const first = await own(sub);
  assert.deepEqual(first.body.policies.map((p) => p.name), ['web']);
  const second = await own(sub, `&cursor=${first.body.next_cursor}`);
  assert.deepEqual(second.body.policies.map((p) => p.name), ['via-team']);
  assert.equal(second.body.next_cursor, null);
  // a domain master: the policies of its grants, of the grants on its zone and those no wider than its own
  const dpol = await dom('GET', '/rr-policies?limit=1');
  assert.deepEqual(dpol.body.policies.map((p) => p.name), ['web']);
  const dpol2 = await dom('GET', `/rr-policies?limit=1&cursor=${dpol.body.next_cursor}`);
  const dpol3 = await dom('GET', `/rr-policies?limit=1&cursor=${dpol2.body.next_cursor}`);
  assert.deepEqual([dpol2, dpol3].map((r) => r.body.policies.map((p) => p.name)), [['narrow'], ['zone-pol']]);
  assert.equal(dpol3.body.next_cursor, null);
  is(await dom('GET', `/rr-policies/${zonePol}`), 200);
  is(await dom('GET', `/rr-policies/${narrowP}`), 200);
  is(await dom('GET', `/rr-policies/${secret}`), 404, 'not-found');
  is(await dom('GET', `/rr-policies/${viaTeam}`), 404, 'not-found');
  is(await sub('GET', `/rr-policies/${web}`), 200);
  is(await sub('GET', `/rr-policies/${viaTeam}`), 200);
  const hp = await sub('GET', `/rr-policies/${secret}`);
  is(hp, 404, 'not-found');
  assert.deepEqual({ ...hp.body, request_id: 0 }, { ...(await sub('GET', '/rr-policies/99999')).body, request_id: 0 });
  is(await dom('GET', `/rr-policies/${all}`), 404, 'not-found');
}));

test('grants: a global master makes any grant', withCast(async (d, { root, all, web }) => {
  const svc = await d.makeUser('svc', null);
  const g1 = await root('POST', '/grants', { body: { principal: svc, role: 'domain_master', zone: 'Other.TEST.', policy: web } });
  is(g1, 201);
  assert.deepEqual({ ...g1.body.grant, id: 0, granted_at: 0 }, {
    id: 0, principal_id: svc, principal: 'svc', role: 'domain_master', dataset: 'main', zone: 'other.test.', suffix: null, policy_id: web, policy: 'web', granted_by: 1, granted_at: 0,
  });
  const g2 = await root('POST', '/grants', { body: { principal: svc, role: 'subdomain_master', dataset: 'main', zone: 'example.test', suffix: 'Deep.Sub.example.test.', policy: web } });
  assert.equal(g2.body.grant.suffix, 'deep.sub.example.test.');
  const g3 = await root('POST', '/grants', { body: { principal: svc, role: 'global_master', policy: all } });
  assert.equal(g3.body.grant.dataset, null);
  assert.equal((await d.login('svc', null)).status, 400);
  // validation
  const bad = (body) => root('POST', '/grants', { body: { principal: svc, policy: web, ...body } });
  is(await bad({ role: 'global_master', zone: 'example.test' }), 400, 'bad-request');
  is(await bad({ role: 'global_master', dataset: 'main' }), 400, 'bad-request');
  is(await bad({ role: 'global_master', suffix: 'x.test' }), 400, 'bad-request');
  is(await bad({ role: 'domain_master' }), 400, 'bad-request');
  is(await bad({ role: 'domain_master', zone: 'example.test', suffix: 'x.example.test' }), 400, 'bad-request');
  is(await bad({ role: 'subdomain_master', zone: 'example.test' }), 400, 'bad-request');
  is(await bad({ role: 'subdomain_master', zone: 'example.test', suffix: 'evil.test' }), 400, 'bad-request');
  is(await bad({ role: 'subdomain_master', zone: 'example.test', suffix: 'badexample.test' }), 400, 'bad-request');
  is(await bad({ role: 'subdomain_master', zone: 'example.test', suffix: 'a b.example.test' }), 400, 'bad-request');
  is(await bad({ role: 'domain_master', zone: 'bad zone!' }), 400, 'bad-request');
  is(await bad({ role: 'domain_master', zone: 'example.test', dataset: 'nowhere' }), 400, 'bad-request');
  is(await bad({ role: 'robot', zone: 'example.test' }), 400, 'bad-request');
  is(await bad({ role: 'domain_master', zone: 'example.test', principal: 999 }), 404, 'not-found');
  is(await bad({ role: 'domain_master', zone: 'example.test', policy: 999 }), 404, 'not-found');
  // listing, filters, paging
  const list = await root('GET', '/grants');
  assert.equal(list.body.grants.length, 3 + 3);
  assert.deepEqual((await root('GET', `/grants?principal=${svc}`)).body.grants.map((g) => g.id), [g1.body.grant.id, g2.body.grant.id, g3.body.grant.id]);
  assert.deepEqual((await root('GET', '/grants?zone=other.test.')).body.grants.map((g) => g.id), [g1.body.grant.id]);
  const p1 = await root('GET', '/grants?limit=4');
  assert.equal(p1.body.grants.length, 4);
  assert.equal((await root('GET', `/grants?limit=4&cursor=${p1.body.next_cursor}`)).body.grants.length, 2);
  is(await root('GET', '/grants?zone=bad zone!'), 400, 'bad-request');
  // deleting
  is(await root('DELETE', `/grants/${g1.body.grant.id}`), 204);
  is(await root('DELETE', `/grants/${g1.body.grant.id}`), 404, 'not-found');
  is(await root('DELETE', '/grants/x'), 404, 'not-found');
}));

test('grants: no escalation (rule 2); who sees which grants', withCast(async (d, { root, dom, sub, all, web }) => {
  const svc = await d.makeUser('svc', null);
  const team = await d.makeUser('tg', null, { kind: 'group' });           // (a domain master grants to the principals it sees: those of its groups, here)
  for (const m of [2, svc]) is(await root('POST', `/principals/${team}/members`, { body: { member: m } }), 201);
  const narrow = await root('POST', '/rr-policies', { body: { name: 'narrow', allowed_types: ['A'], ttl_min: 120, ttl_max: 3600 } });
  const narrowId = narrow.body.policy.id;
  // a domain master grants inside its zone, with a policy no wider than its own
  const ok = await dom('POST', '/grants', { body: { principal: svc, role: 'subdomain_master', zone: 'example.test', suffix: 'cust.example.test', policy: narrowId } });
  is(ok, 201);
  assert.equal(ok.body.grant.granted_by, 2);
  is(await dom('POST', '/grants', { body: { principal: svc, role: 'domain_master', zone: 'example.test', policy: web } }), 201);
  // too wide, another zone, a global grant, a role that is not its own to give
  is(await dom('POST', '/grants', { body: { principal: svc, role: 'subdomain_master', zone: 'example.test', suffix: 'x.example.test', policy: all } }), 403, 'escalation');
  is(await dom('POST', '/grants', { body: { principal: svc, role: 'domain_master', zone: 'other.test', policy: narrowId } }), 403, 'escalation');
  is(await dom('POST', '/grants', { body: { principal: svc, role: 'global_master', policy: narrowId } }), 403, 'escalation');
  // a subdomain master grants nothing
  is(await sub('POST', '/grants', { body: { principal: svc, role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policy: narrowId } }), 403, 'escalation');
  // who sees what: dom sees its own grant and every grant on its zone; sub only its own; svc has some on example.test and one elsewhere
  const other = await root('POST', '/grants', { body: { principal: svc, role: 'domain_master', zone: 'other.test', policy: web } });
  const names = async (as) => (await as('GET', '/grants')).body.grants.map((g) => `${g.principal}:${g.role}:${g.zone}`);
  assert.deepEqual(await names(dom), ['dom:domain_master:example.test.', 'sub:subdomain_master:example.test.', 'svc:subdomain_master:example.test.', 'svc:domain_master:example.test.']);
  assert.deepEqual(await names(sub), ['sub:subdomain_master:example.test.']);
  assert.equal((await names(root)).length, 3 + 3);
  const page = await dom('GET', '/grants?limit=2');
  assert.equal(page.body.grants.length, 2);
  assert.equal((await dom('GET', `/grants?limit=2&cursor=${page.body.next_cursor}`)).body.grants.length, 2);
  assert.deepEqual((await dom('GET', `/grants?principal=${svc}`)).body.grants.map((g) => g.zone), ['example.test.', 'example.test.']);
  assert.deepEqual((await dom('GET', '/grants?zone=other.test')).body.grants, []);
  // removing: a domain master removes what it could make, on its zone; what it cannot see does not exist for it
  is(await dom('DELETE', `/grants/${other.body.grant.id}`), 404, 'not-found');
  is(await sub('DELETE', `/grants/${ok.body.grant.id}`), 404, 'not-found');
  is(await dom('DELETE', `/grants/${ok.body.grant.id}`), 204);
  // its own grant is its own to see, not to remove
  const own = (await dom('GET', '/grants?principal=2')).body.grants[0];
  is(await dom('DELETE', `/grants/${own.id}`), 204);                 // a domain master may remove a grant it could make (its own is such a grant)
  const wideGrant = await root('POST', '/grants', { body: { principal: svc, role: 'domain_master', zone: 'example.test', policy: all } });
  is(await dom('DELETE', `/grants/${wideGrant.body.grant.id}`), 404, 'not-found');     // dom lost its grant: the zone is not its any more
}));

// a domain master of two zones sees the holders of both, but grants on one zone only to the principals of that zone (itself, its groups and their members, the holders
// of a grant on that zone): the zones stay apart (decided 2026-11-10)
test('a domain master of two zones grants on a zone only to the principals of that zone', withCast(async (d, { root, web }) => {
  const domId = (await root('GET', '/principals?prefix=dom')).body.principals.find((p) => p.name === 'dom').id;
  is(await root('POST', '/grants', { body: { principal: domId, role: 'domain_master', zone: 'other.test', policy: web } }), 201);
  const onlyB = await d.makeUser('onlyb', null, { grants: [{ role: 'subdomain_master', zone: 'other.test', suffix: 'b.other.test', policyId: web, schema: '' }] });
  const dom2 = d.as(await d.login('dom', 'dom password 12345'));
  assert.ok((await dom2('GET', '/principals?prefix=onlyb')).body.principals.some((p) => p.name === 'onlyb'), 'a holder on its other zone is seen');
  const onA = await dom2('POST', '/grants', { body: { principal: onlyB, role: 'subdomain_master', zone: 'example.test', suffix: 'q.example.test', policy: web } });
  const none = await dom2('POST', '/grants', { body: { principal: 99999, role: 'subdomain_master', zone: 'example.test', suffix: 'q.example.test', policy: web } });
  is(onA, 404, 'not-found');
  assert.deepEqual({ ...onA.body, request_id: 0 }, { ...none.body, request_id: 0 }, 'the same answer as for nobody');
  is(await dom2('POST', '/grants', { body: { principal: onlyB, role: 'subdomain_master', zone: 'other.test', suffix: 'c.other.test', policy: web } }), 201, undefined);
  is(await dom2('POST', '/grants', { body: { principal: 3, role: 'subdomain_master', zone: 'other.test', suffix: 'd.other.test', policy: web } }), 404, 'not-found');   // (sub: a holder on example.test only)
  is(await dom2('POST', '/grants', { body: { principal: domId, role: 'subdomain_master', zone: 'other.test', suffix: 'e.other.test', policy: web } }), 201);     // (itself)
}));

test('a domain master of a zone with a wide policy may remove a wider grant than it can see', withCast(async (d, { root }) => {
  const svc = await d.makeUser('svc', null);
  const wide = await d.makePolicy({ name: 'wide', allowed_types: ['A', 'TXT', 'CNAME'], ttl_min: 0, ttl_max: 86400 });
  const web = await d.makePolicy({ name: 'web2', allowed_types: ['A'], ttl_min: 60, ttl_max: 86400 });
  const boss = await d.makeUser('boss', 'boss password 1234', { grants: [{ role: 'domain_master', zone: 'example.test', policyId: web, schema: '' }] });
  const bossAs = d.as(await d.login('boss', 'boss password 1234'));
  const g = await root('POST', '/grants', { body: { principal: svc, role: 'domain_master', zone: 'example.test', policy: wide } });
  // visible (it is on boss's zone) but not removable: the policy is wider than boss's
  is(await bossAs('DELETE', `/grants/${g.body.grant.id}`), 403, 'escalation');
  assert.ok(boss);
}));

test('grants through groups count: the group is the grantee', withCast(async (d, { root, web }) => {
  const g = (await root('POST', '/principals', { body: { kind: 'group', name: 'team' } })).body.principal.id;
  await root('POST', `/principals/${g}/members`, { body: { member: 3 } });
  await root('POST', '/grants', { body: { principal: g, role: 'domain_master', zone: 'other.test', policy: web } });
  const sub = d.as(await d.login('sub', 'sub password 12345'));
  assert.deepEqual((await sub('GET', '/datasets/main/zones')).body.zones.map((z) => z.name), ['example.test.', 'other.test.']);
  assert.deepEqual((await sub('GET', '/grants')).body.grants.map((x) => `${x.principal}:${x.zone}`), ['sub:example.test.', 'team:other.test.']);
  // disabling the group takes its grants away
  await root('PATCH', `/principals/${g}`, { body: { disabled: true } });
  assert.deepEqual((await sub('GET', '/datasets/main/zones')).body.zones.map((z) => z.name), ['example.test.']);
  // and so does removing the member
  await root('PATCH', `/principals/${g}`, { body: { disabled: false } });
  await root('DELETE', `/principals/${g}/members/3`);
  assert.deepEqual((await sub('GET', '/datasets/main/zones')).body.zones.map((z) => z.name), ['example.test.']);
}));

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
  const all = await dom('GET', '/principals');
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
  // the password reset ends the user's sessions
  const s = await d.login('alice2', 'alice password 12');
  is(await root('PUT', `/principals/${id}/password`, { body: { password: 'alice2 is the name' } }), 400, 'weak-password');
  is(await root('PUT', `/principals/${id}/password`, { body: { password: 'a brand new password' } }), 200);
  is(await d.as(s)('GET', '/auth/me'), 401, 'unauthenticated');
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
  assert.equal((await dom('GET', `/rr-policies/${id}`)).body.policy.name, 'mail');
  is(await dom('GET', '/rr-policies/999'), 404, 'not-found');
  const list = await dom('GET', '/rr-policies?limit=2');
  assert.equal(list.body.policies.length, 2);
  assert.deepEqual((await dom('GET', `/rr-policies?limit=2&cursor=${list.body.next_cursor}`)).body.policies.map((p) => p.name), ['mail', 'generic']);
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

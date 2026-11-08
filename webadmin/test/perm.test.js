import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { canonType, isDnssecType, rrOk, rrVisible, zoneGrant, isGlobal, grantsOn, policySubset, mayGrant, maySetGrant, auditVisible } from '../lib/perm.js';

const vectors = JSON.parse(fs.readFileSync(new URL('../../tests/auth_vectors.json', import.meta.url), 'utf8'));

// the effective grants of the user 'u' of a case: the grants of u and of the groups it is in (directly or through groups) that are not disabled
function effective(c) {
  if (c.user_disabled) return [];
  const groups = new Map((c.groups ?? []).map((g) => [g.name, g]));
  const holders = new Set(['u']);
  for (let changed = true; changed;) {
    changed = false;
    for (const g of groups.values()) {
      if (!holders.has(g.name) && g.members.some((m) => holders.has(m))) { holders.add(g.name); changed = true; }
    }
  }
  return c.grants.filter((g) => g.to === 'u' || (holders.has(g.to) && !groups.get(g.to).disabled))
    .map((g) => ({ role: g.role, data_schema: g.schema, zone_name: g.zone, name_suffix: g.suffix, policy: vectors.policies[g.policy] }));
}

for (const c of vectors.cases) {
  test(`vectors: ${c.name}`, () => {
    const grants = effective(c);
    for (const k of c.checks) {
      const p = vectors.policies;
      let got;
      switch (k.fn) {
        case 'rr_ok': got = rrOk(grants, { schema: k.schema, zone: k.zone, name: k.name, type: k.type, ttl: k.ttl }) !== null; break;
        case 'rr_visible': got = rrVisible(grants, { schema: k.schema, zone: k.zone, name: k.name, type: k.type }); break;
        case 'zone_grant': got = zoneGrant(grants, k.schema, k.zone); break;
        case 'is_global': got = isGlobal(grants); break;
        case 'policy_subset': got = policySubset(p[k.sub], p[k.sup]); break;
        case 'may_grant': got = mayGrant(grants, { role: k.role, schema: k.schema, zone: k.zone, policy: p[k.policy] }); break;
        default: assert.fail(`unknown check ${k.fn}`);
      }
      assert.equal(got, k.expect, JSON.stringify(k));
    }
  });
}

test('types: the generic forms of NS, SOA, DNAME and the DNSSEC types read as the name', () => {
  assert.equal(canonType(' a '), 'A');
  assert.equal(canonType('type0002'), 'NS');
  assert.equal(canonType('TYPE6'), 'SOA');
  assert.equal(canonType('TYPE39'), 'DNAME');
  assert.equal(canonType('TYPE46'), 'RRSIG');
  assert.equal(canonType('TYPE65'), 'TYPE65');
  assert.equal(canonType('TYPE123456'), 'TYPE123456');
  assert.equal(canonType(null), null);
  assert.equal(canonType(undefined), null);
  for (const t of ['RRSIG', 'nsec', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY', 'TYPE50', 'type0059']) assert.equal(isDnssecType(t), true, t);
  for (const t of ['A', 'DS', 'TYPE65', null, '']) assert.equal(isDnssecType(t), false, String(t));
});

test('zoneGrant ranks the roles; grantsOn lists the grants of a zone strongest first', () => {
  const pol = vectors.policies.web;
  const g = (role, zone, suffix = null, schema = 's') => ({ role, data_schema: role === 'global_master' ? null : schema, zone_name: zone, name_suffix: suffix, policy: pol });
  const sub = g('subdomain_master', 'z.test', 'a.z.test');
  const dom = g('domain_master', 'z.test');
  const glob = g('global_master', null);
  assert.equal(zoneGrant([sub, dom], 's', 'z.test'), 'domain_master');
  assert.equal(zoneGrant([dom, sub], 's', 'Z.TEST'), 'domain_master');
  assert.equal(zoneGrant([sub, glob, dom], 's', 'z.test'), 'global_master');
  assert.equal(zoneGrant([sub], 's', 'z.test'), 'subdomain_master');
  assert.equal(zoneGrant([sub], 's', 'other.test'), null);
  assert.deepEqual(grantsOn([sub, dom, glob, g('domain_master', 'o.test')], 's', 'z.test').map((x) => x.role), ['global_master', 'domain_master', 'subdomain_master']);
  assert.deepEqual(grantsOn([sub], 'x', 'z.test'), []);
});

test('rrOk returns the grant that allowed the record', () => {
  const [web, all] = [vectors.policies.web, vectors.policies.all];
  const a = { role: 'domain_master', data_schema: 's', zone_name: 'z.test', name_suffix: null, policy: web };
  const b = { role: 'domain_master', data_schema: 's', zone_name: 'z.test', name_suffix: null, policy: all };
  assert.equal(rrOk([a, b], { schema: 's', zone: 'z.test', name: 'z.test', type: 'MX', ttl: 300 }), b);
  assert.equal(rrOk([a, b], { schema: 's', zone: 'z.test', name: 'w.z.test', type: 'A', ttl: 300 }), a);
  assert.equal(rrOk([], { schema: 's', zone: 'z.test', name: 'w.z.test', type: 'A', ttl: 300 }), null);
});

test('maySetGrant: a global master may anything, a domain master what mayGrant says', () => {
  const [web, all] = [vectors.policies.web, vectors.policies.all];
  const glob = { role: 'global_master', data_schema: null, zone_name: null, name_suffix: null, policy: web };
  const dom = { role: 'domain_master', data_schema: 's', zone_name: 'z.test', name_suffix: null, policy: web };
  assert.equal(maySetGrant([glob], { role: 'global_master', schema: null, zone: null, policy: all }), true);
  assert.equal(maySetGrant([dom], { role: 'subdomain_master', schema: 's', zone: 'z.test', policy: web }), true);
  assert.equal(maySetGrant([dom], { role: 'subdomain_master', schema: 's', zone: 'z.test', policy: all }), false);
  assert.equal(maySetGrant([], { role: 'domain_master', schema: 's', zone: 'z.test', policy: web }), false);
  // SQLite3: the schema is '' (not null)
  const dom3 = { ...dom, data_schema: '' };
  assert.equal(maySetGrant([dom3], { role: 'domain_master', schema: '', zone: 'z.test', policy: web }), true);
});

test('audit rows: a global master sees all, a domain master the rows of its zones', () => {
  const pol = vectors.policies.web;
  const dom = { role: 'domain_master', data_schema: 's', zone_name: 'z.test', name_suffix: null, policy: pol };
  const sub = { role: 'subdomain_master', data_schema: 's', zone_name: 'z.test', name_suffix: 'a.z.test', policy: pol };
  const glob = { role: 'global_master', data_schema: null, zone_name: null, name_suffix: null, policy: pol };
  assert.equal(auditVisible([glob], { schema: 'x', zone: null }), true);
  assert.equal(auditVisible([dom], { schema: 's', zone: 'z.test' }), true);
  assert.equal(auditVisible([dom], { schema: 's', zone: 'o.test' }), false);
  assert.equal(auditVisible([dom], { schema: 's', zone: null }), false);
  assert.equal(auditVisible([dom], { schema: 's', zone: undefined }), false);
  assert.equal(auditVisible([sub], { schema: 's', zone: 'z.test' }), false);
});

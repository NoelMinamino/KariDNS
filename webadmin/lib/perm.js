// The permission rules in JavaScript (planning 3.3).  One rule set, three implementations: the SQL functions karidns_auth.rr_ok / rr_visible / zone_grant /
// is_global / policy_subset / may_grant (db/karidns_ext.pgsql.sql), this file, and, on SQLite3, this file alone.  tests/auth_vectors.json holds cases that
// both implementations must answer alike (webadmin/test/perm.test.js runs them here, tests/run_webadmin_pg_test.sh against the SQL functions): if you
// change a rule, change it in both and add a vector.
//
// Names are canonical (lower case, no final dot: the form PowerDNS stores and the grants hold).  A "grant" is an effective grant of the principal: a row of
// grants whose principal is the user or a group the user is in (directly or through groups) that is not disabled, with its rr_policy attached as `policy`:
//   { role, data_schema, zone_name, name_suffix, policy: { allowed_types, allow_wildcard, allow_delegation, allow_dname, apex_editable, ttl_min, ttl_max, max_rr } }
// On SQLite3 data_schema is '' (one zone file per API instance) for every grant; a global master's grant has no schema.

const DNSSEC = new Set(['RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY']);
const GENERIC = { 2: 'NS', 6: 'SOA', 39: 'DNAME', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 50: 'NSEC3', 51: 'NSEC3PARAM', 59: 'CDS', 60: 'CDNSKEY' };
const WILDCARD = /(^|[.])[*]([.]|$)/;
const RANK = { global_master: 0, domain_master: 1, subdomain_master: 2 };

// the type upper case and trimmed, with the generic form of NS, SOA, DNAME and the DNSSEC types read as the name; null stays null (canon_type)
export function canonType(t) {
  if (t === null || t === undefined) return null;
  const u = String(t).trim().toUpperCase();
  const m = /^TYPE0*([0-9]{1,5})$/.exec(u);
  return m ? (GENERIC[Number(m[1])] ?? u) : u;
}

export const isDnssecType = (t) => DNSSEC.has(canonType(t) ?? '');

const underName = (n, base) => n === base || n.endsWith(`.${base}`);

// May the principal WRITE this record?  Returns the grant that allows it (the first of `grants` that does), or null.  An empty non-terminal (type null or '')
// is a bare name: it needs the scope, never the apex, and the wildcard rule; type and TTL do not matter.
export function rrOk(grants, { schema, zone, name, type, ttl }) {
  if (!zone || !name) return null;
  const z = zone.toLowerCase();
  const n = name.toLowerCase();
  if (!underName(n, z)) return null;
  const t = canonType(type) || null;
  for (const g of grants) {
    const inScope = g.role === 'global_master'
      || (g.data_schema === schema && g.zone_name === z
          && (g.role === 'domain_master' || n === g.name_suffix || n.endsWith(`.${g.name_suffix}`)));
    if (!inScope) continue;
    const p = g.policy;
    if (WILDCARD.test(n) && !p.allow_wildcard) continue;
    if (t === null) {
      if (n !== z) return g;
      continue;
    }
    if (!p.allowed_types.includes(t) || DNSSEC.has(t)) continue;
    const ttlv = ttl ?? 0;
    if (ttlv < p.ttl_min || ttlv > p.ttl_max) continue;
    if (t === 'NS' && n !== z && !p.allow_delegation) continue;
    if (t === 'DNAME' && !p.allow_dname) continue;
    if (n === z && !(p.apex_editable && g.role !== 'subdomain_master')) continue;
    if (t === 'SOA' && !(n === z && g.role === 'global_master' && p.apex_editable)) continue;
    return g;
  }
  return null;
}

// May the principal READ this record?  The name must be inside the zone for every grant; then a global master sees every such row, a domain master the rows
// of its (schema, zone), a subdomain master the rows of its suffix; the SOA and the apex NS are visible to every grant on the zone.  A bare name is
// visible by its name alone.
export function rrVisible(grants, { schema, zone, name, type }) {
  if (!zone || !name) return false;
  const z = zone.toLowerCase();
  const n = name.toLowerCase();
  if (!underName(n, z)) return false;
  const t = canonType(type);
  return grants.some((g) => g.role === 'global_master'
    || (g.data_schema === schema && g.zone_name === z
        && (g.role === 'domain_master' || underName(n, g.name_suffix) || (n === z && (t === 'SOA' || t === 'NS')))));
}

// The strongest effective grant on a zone: its role, or null.  A global master has a grant on every zone.
export function zoneGrant(grants, schema, zone) {
  let best = null;
  const z = zone.toLowerCase();
  for (const g of grants) {
    if (g.role === 'global_master' || (g.data_schema === schema && g.zone_name === z)) {
      if (best === null || RANK[g.role] < RANK[best]) best = g.role;
    }
  }
  return best;
}

export const isGlobal = (grants) => grants.some((g) => g.role === 'global_master');

// The grants that apply to one zone (a global master's included), strongest first
export function grantsOn(grants, schema, zone) {
  const z = zone.toLowerCase();
  return grants.filter((g) => g.role === 'global_master' || (g.data_schema === schema && g.zone_name === z)).sort((a, b) => RANK[a.role] - RANK[b.role]);
}

// is policy `sub` no wider than policy `sup`?  (types a subset, each flag not more, ttl_min not lower, ttl_max not higher, max_rr not higher; null = no limit)
export function policySubset(sub, sup) {
  return sub.allowed_types.every((t) => sup.allowed_types.includes(t))
    && (!sub.allow_wildcard || sup.allow_wildcard)
    && (!sub.allow_delegation || sup.allow_delegation)
    && (!sub.allow_dname || sup.allow_dname)
    && (!sub.apex_editable || sup.apex_editable)
    && sub.ttl_min >= sup.ttl_min && sub.ttl_max <= sup.ttl_max
    && (sup.max_rr === null || (sub.max_rr !== null && sub.max_rr <= sup.max_rr));
}

// may the principal (not a global master) make, change or remove a grant of this shape?  It must be a domain master of the same (schema, zone) with a
// policy at least as wide, and the grant must be a domain_master or subdomain_master one.  A subdomain master therefore never grants.
export function mayGrant(grants, { role, schema, zone, policy }) {
  return (role === 'domain_master' || role === 'subdomain_master') && schema !== null && schema !== undefined && zone !== null && zone !== undefined
    && grants.some((g) => g.role === 'domain_master' && g.data_schema === schema && g.zone_name === zone && policySubset(policy, g.policy));
}

// May the principal make, change or remove this grant?  A global master may do anything (the operator's rule of the trigger on grants).
export const maySetGrant = (grants, grant) => isGlobal(grants) || mayGrant(grants, grant);

// Which audit_log rows does the principal see?  A global master all, a domain master of the row's zone those of the zone (audit_visible).  `schema` is the
// data schema of the row; for a row about a grant (table karidns_auth.grants) it is the schema the grant names.
export const auditVisible = (grants, { schema, zone }) => isGlobal(grants) || (zone !== null && zone !== undefined && zoneGrant(grants, schema, zone) === 'domain_master');

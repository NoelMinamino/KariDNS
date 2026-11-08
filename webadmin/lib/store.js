// Every SQL statement of the API (planning 2.2), as functions of a `tx` (db.js).  The text is the same for PostgreSQL and SQLite3 except where a `tx.dialect`
// branch says otherwise (arrays of record types, row level security, the lookup functions of sessions and tokens).  Rows come out normalised: booleans are
// booleans, timestamps are ISO text, ids are numbers.  Nothing here decides who may do what: the handlers do that with perm.js (and on PostgreSQL row
// level security checks the same rows again).

import { toIso, toMs } from './db.js';

const bool = (v) => v === true || v === 1;

// a statement under construction: add() binds a value and returns its placeholder
class Q {
  constructor() { this.params = []; }

  add(v) { this.params.push(v); return `$${this.params.length}`; }

  // "col IN list" where the list is one parameter (tx.list: an array on PostgreSQL, JSON text on SQLite3)
  list(tx, col, arr, type) { return tx.list(col, this.params.push(tx.listParam(arr)), type); }
}

// "name = x OR name = x." : PowerDNS stores a zone name without the final dot, but a database may hold it with
const zoneNames = (zone) => [zone, `${zone}.`];

const principal = (r) => ({ id: r.id, kind: r.kind, name: r.name, display_name: r.display_name, email: r.email, disabled: bool(r.disabled), created_at: toIso(r.created_at), created_by: r.created_by });
const PCOLS = 'p.id, p.kind, p.name, p.display_name, p.email, p.disabled, p.created_at, p.created_by';

// ---------------------------------------------------------------------------------------------------------------------------------- principals
export async function principalByName(tx, name) {
  const r = await tx.get(`SELECT ${PCOLS} FROM ${tx.A}principals p WHERE lower(p.name) = lower($1)`, [name]);
  return r && principal(r);
}

export async function getPrincipal(tx, id) {
  const r = await tx.get(`SELECT ${PCOLS} FROM ${tx.A}principals p WHERE p.id = $1`, [id]);
  return r && principal(r);
}

export async function listPrincipals(tx, { kind, prefix, after = 0, limit }) {
  const q = new Q();
  const w = [`p.id > ${q.add(after)}`];
  if (kind) w.push(`p.kind = ${q.add(kind)}`);
  if (prefix) w.push(`substr(lower(p.name), 1, ${prefix.length}) = ${q.add(prefix.toLowerCase())}`);
  return (await tx.all(`SELECT ${PCOLS} FROM ${tx.A}principals p WHERE ${w.join(' AND ')} ORDER BY p.id LIMIT ${q.add(limit + 1)}`, q.params)).map(principal);
}

export async function createPrincipal(tx, { kind, name, display_name = null, email = null, disabled = false, createdBy = null }) {
  return (await tx.get(`INSERT INTO ${tx.A}principals (kind, name, display_name, email, disabled, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [kind, name, display_name, email, disabled, createdBy])).id;
}

// patch: { name, display_name, email, disabled } (only the keys present change)
export async function updatePrincipal(tx, id, patch) {
  const q = new Q();
  const set = Object.entries(patch).map(([k, v]) => `${k} = ${q.add(v)}`);
  if (set.length === 0) return 0;
  return (await tx.run(`UPDATE ${tx.A}principals SET ${set.join(', ')} WHERE id = ${q.add(id)}`, q.params)).changes;
}

export async function deletePrincipal(tx, id) {
  return (await tx.run(`DELETE FROM ${tx.A}principals WHERE id = $1`, [id])).changes;
}

// the groups a principal is in, directly or through groups (nearest first) and, of those, the tenants (the groups that are in no group)
export async function groupsOf(tx, id) {
  const rows = await tx.all(`SELECT gp.id, gp.name, c.depth, NOT EXISTS (SELECT 1 FROM ${tx.A}memberships m WHERE m.member_id = gp.id) AS tenant
                               FROM ${tx.A}principal_closure c JOIN ${tx.A}principals gp ON gp.id = c.group_id
                              WHERE c.member_id = $1 AND c.group_id <> $1 ORDER BY c.depth, gp.name`, [id]);
  return rows.map((r) => ({ id: r.id, name: r.name, depth: r.depth, tenant: bool(r.tenant) }));
}

export async function membersOf(tx, groupId) {
  return (await tx.all(`SELECT ${PCOLS} FROM ${tx.A}memberships m JOIN ${tx.A}principals p ON p.id = m.member_id WHERE m.group_id = $1 ORDER BY p.name`, [groupId])).map(principal);
}

export const addMember = (tx, groupId, memberId) => tx.run(`INSERT INTO ${tx.A}memberships (member_id, group_id) VALUES ($1, $2)`, [memberId, groupId]);
export async function removeMember(tx, groupId, memberId) {
  return (await tx.run(`DELETE FROM ${tx.A}memberships WHERE member_id = $1 AND group_id = $2`, [memberId, groupId])).changes;
}

// ---------------------------------------------------------------------------------------------------------------------------------- credentials
export async function getCredentials(tx, id) {
  const r = await tx.get(`SELECT password_hash, totp_secret, totp_enabled, failed_logins, locked_until, password_changed_at FROM ${tx.A}credentials WHERE principal_id = $1`, [id]);
  return r && { password_hash: r.password_hash, totp_secret: r.totp_secret, totp_enabled: bool(r.totp_enabled), failed_logins: r.failed_logins, locked_until: toMs(r.locked_until), password_changed_at: toIso(r.password_changed_at) };
}

// UPDATE first: an INSERT ... ON CONFLICT would need the right to insert (a global master's) even when the row is there
export async function setPassword(tx, id, hash, nowMs) {
  const r = await tx.run(`UPDATE ${tx.A}credentials SET password_hash = $2, password_changed_at = $3, failed_logins = 0, locked_until = NULL WHERE principal_id = $1`, [id, hash, tx.ts(nowMs)]);
  if (r.changes === 0) await tx.run(`INSERT INTO ${tx.A}credentials (principal_id, password_hash, password_changed_at) VALUES ($1, $2, $3)`, [id, hash, tx.ts(nowMs)]);
}

export const setTotp = (tx, id, wrapped, enabled) => tx.run(`UPDATE ${tx.A}credentials SET totp_secret = $2, totp_enabled = $3 WHERE principal_id = $1`, [id, wrapped, enabled]);

export const recordLoginFailure = (tx, id, failed, lockedUntilMs) => tx.run(`UPDATE ${tx.A}credentials SET failed_logins = $2, locked_until = $3 WHERE principal_id = $1`,
  [id, failed, lockedUntilMs === null ? null : tx.ts(lockedUntilMs)]);

// a login that worked: the counters are reset (and the TOTP secret is written again when the step it used was remembered in it)
export async function recordLoginSuccess(tx, id, wrappedTotp) {
  if (wrappedTotp !== undefined) await tx.run(`UPDATE ${tx.A}credentials SET failed_logins = 0, locked_until = NULL, totp_secret = $2 WHERE principal_id = $1`, [id, wrappedTotp]);
  else await tx.run(`UPDATE ${tx.A}credentials SET failed_logins = 0, locked_until = NULL WHERE principal_id = $1 AND (failed_logins <> 0 OR locked_until IS NOT NULL)`, [id]);
}

// ---------------------------------------------------------------------------------------------------------------------------------- sessions, tokens
export const createSession = (tx, s) => tx.run(`INSERT INTO ${tx.A}sessions (id_hash, principal_id, csrf_hash, created_at, last_seen, expires_at, totp_ok, client) VALUES ($1, $2, $3, $4, $4, $5, $6, $7)`,
  [s.idHash, s.principalId, s.csrfHash, tx.ts(s.createdMs), tx.ts(s.expiresMs), s.totpOk, s.client]);

// -> { principal_id, csrf_hash, created, last_seen, expires, totp_ok } of an unexpired session of a principal that is not disabled, else undefined.
// PostgreSQL: through the function that finds it before a principal is known (the policy shows a principal its own sessions only)
export async function lookupSession(tx, idHash, nowMs) {
  const r = tx.dialect === 'pg'
    ? await tx.get(`SELECT principal_id, csrf_hash, created_at, last_seen, expires_at, totp_ok FROM ${tx.A}session_lookup($1)`, [idHash])
    : await tx.get(`SELECT s.principal_id, s.csrf_hash, s.created_at, s.last_seen, s.expires_at, s.totp_ok FROM ${tx.A}sessions s
                      JOIN ${tx.A}principals p ON p.id = s.principal_id AND NOT p.disabled WHERE s.id_hash = $1 AND s.expires_at > $2`, [idHash, tx.ts(nowMs)]);
  return r && { principal_id: r.principal_id, csrf_hash: Buffer.from(r.csrf_hash), created: toMs(r.created_at), last_seen: toMs(r.last_seen), expires: toMs(r.expires_at), totp_ok: bool(r.totp_ok) };
}

export const touchSession = (tx, idHash, nowMs) => tx.run(`UPDATE ${tx.A}sessions SET last_seen = $2 WHERE id_hash = $1`, [idHash, tx.ts(nowMs)]);
export const deleteSession = (tx, idHash) => tx.run(`DELETE FROM ${tx.A}sessions WHERE id_hash = $1`, [idHash]);
// (the optional condition is a statement of its own: PostgreSQL cannot tell the type of a parameter that is only compared with NULL)
export const deleteSessionsOf = (tx, principalId, exceptHash = null) => (exceptHash === null
  ? tx.run(`DELETE FROM ${tx.A}sessions WHERE principal_id = $1`, [principalId])
  : tx.run(`DELETE FROM ${tx.A}sessions WHERE principal_id = $1 AND id_hash <> $2`, [principalId, exceptHash]));
export const deleteExpiredSessions = (tx, nowMs, principalId = null) => (principalId === null
  ? tx.run(`DELETE FROM ${tx.A}sessions WHERE expires_at < $1`, [tx.ts(nowMs)])
  : tx.run(`DELETE FROM ${tx.A}sessions WHERE expires_at < $1 AND principal_id = $2`, [tx.ts(nowMs), principalId]));

export async function createToken(tx, t) {
  return (await tx.get(`INSERT INTO ${tx.A}api_tokens (principal_id, name, secret_hash, read_only, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [t.principalId, t.name, t.secretHash, t.readOnly, tx.ts(t.createdMs), tx.ts(t.expiresMs)])).id;
}

export async function lookupToken(tx, id, secretHash, nowMs) {
  const r = tx.dialect === 'pg'
    ? await tx.get(`SELECT principal_id, read_only, expires_at FROM ${tx.A}api_token_lookup($1, $2)`, [id, secretHash])
    : await tx.get(`SELECT t.principal_id, t.read_only, t.expires_at FROM ${tx.A}api_tokens t JOIN ${tx.A}principals p ON p.id = t.principal_id AND NOT p.disabled
                     WHERE t.id = $1 AND t.secret_hash = $2 AND t.revoked_at IS NULL AND t.expires_at > $3`, [id, secretHash, tx.ts(nowMs)]);
  return r && { principal_id: r.principal_id, read_only: bool(r.read_only), expires: toMs(r.expires_at) };
}

// last_used_at is written at most once a day per token (every write is an audit row)
export const touchToken = (tx, id, nowMs) => tx.run(`UPDATE ${tx.A}api_tokens SET last_used_at = $2 WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < $3)`, [id, tx.ts(nowMs), tx.ts(nowMs - 86400000)]);

const token = (r) => ({ id: r.id, principal_id: r.principal_id, principal: r.principal_name, name: r.name, read_only: bool(r.read_only), created_at: toIso(r.created_at), expires_at: toIso(r.expires_at), last_used_at: toIso(r.last_used_at), revoked_at: toIso(r.revoked_at) });

export async function listTokens(tx, { principalId = null, after = 0, limit }) {
  const q = new Q();
  const w = [`t.id > ${q.add(after)}`];
  if (principalId !== null) w.push(`t.principal_id = ${q.add(principalId)}`);
  return (await tx.all(`SELECT t.id, t.principal_id, p.name AS principal_name, t.name, t.read_only, t.created_at, t.expires_at, t.last_used_at, t.revoked_at
                          FROM ${tx.A}api_tokens t JOIN ${tx.A}principals p ON p.id = t.principal_id WHERE ${w.join(' AND ')} ORDER BY t.id LIMIT ${q.add(limit + 1)}`, q.params)).map(token);
}

export async function getToken(tx, id) {
  const r = await tx.get(`SELECT t.id, t.principal_id, p.name AS principal_name, t.name, t.read_only, t.created_at, t.expires_at, t.last_used_at, t.revoked_at
                            FROM ${tx.A}api_tokens t JOIN ${tx.A}principals p ON p.id = t.principal_id WHERE t.id = $1`, [id]);
  return r && token(r);
}

export const revokeToken = (tx, id, nowMs) => tx.run(`UPDATE ${tx.A}api_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, [id, tx.ts(nowMs)]);
export const revokeTokensOf = (tx, principalId, nowMs) => tx.run(`UPDATE ${tx.A}api_tokens SET revoked_at = $2 WHERE principal_id = $1 AND revoked_at IS NULL`, [principalId, tx.ts(nowMs)]);

// ---------------------------------------------------------------------------------------------------------------------------------- policies and grants
const policy = (r, types) => ({
  id: r.id, name: r.name, allowed_types: types, allow_wildcard: bool(r.allow_wildcard), allow_delegation: bool(r.allow_delegation), allow_dname: bool(r.allow_dname),
  apex_editable: bool(r.apex_editable), ttl_min: r.ttl_min, ttl_max: r.ttl_max, max_rr: r.max_rr,
});
const PFLAGS = 'allow_wildcard, allow_delegation, allow_dname, apex_editable, ttl_min, ttl_max, max_rr';

// ids: undefined = all; else the rows with these ids.  after / limit page by id.
export async function listPolicies(tx, { ids, after = 0, limit = 100000 } = {}) {
  const q = new Q();
  const w = [`id > ${q.add(after)}`];
  if (ids) w.push(q.list(tx, 'id', ids, 'bigint'));
  const rows = await tx.all(`SELECT id, name, ${PFLAGS}${tx.dialect === 'pg' ? ', allowed_types' : ''} FROM ${tx.A}rr_policies WHERE ${w.join(' AND ')} ORDER BY id LIMIT ${q.add(limit)}`, q.params);
  if (tx.dialect === 'pg') return rows.map((r) => policy(r, r.allowed_types));
  const types = new Map();
  if (rows.length) {
    for (const t of await tx.all(`SELECT policy_id, type FROM ${tx.A}rr_policy_types WHERE ${tx.list('policy_id', 1)} ORDER BY type`, [tx.listParam(rows.map((r) => r.id))])) {
      if (!types.has(t.policy_id)) types.set(t.policy_id, []);
      types.get(t.policy_id).push(t.type);
    }
  }
  return rows.map((r) => policy(r, types.get(r.id) ?? []));
}

export async function getPolicy(tx, id) {
  return (await listPolicies(tx, { ids: [id], after: -1 }))[0];
}

async function setPolicyTypes(tx, id, types) {
  if (tx.dialect === 'pg') {
    await tx.run(`UPDATE ${tx.A}rr_policies SET allowed_types = $2::text[] WHERE id = $1`, [id, types]);
    return;
  }
  await tx.run(`DELETE FROM ${tx.A}rr_policy_types WHERE policy_id = $1`, [id]);
  for (const t of types) await tx.run(`INSERT INTO ${tx.A}rr_policy_types (policy_id, type) VALUES ($1, $2)`, [id, t]);
}

// p: { name, allowed_types, allow_wildcard, allow_delegation, allow_dname, apex_editable, ttl_min, ttl_max, max_rr }
export async function createPolicy(tx, p, createdBy) {
  const id = (await tx.get(`INSERT INTO ${tx.A}rr_policies (name, ${tx.dialect === 'pg' ? 'allowed_types, ' : ''}${PFLAGS}, created_by) VALUES ($1, ${tx.dialect === 'pg' ? '$2::text[], ' : ''}$3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
    [p.name, tx.dialect === 'pg' ? p.allowed_types : null, p.allow_wildcard, p.allow_delegation, p.allow_dname, p.apex_editable, p.ttl_min, p.ttl_max, p.max_rr, createdBy])).id;
  if (tx.dialect !== 'pg') await setPolicyTypes(tx, id, p.allowed_types);
  return id;
}

export async function updatePolicy(tx, id, patch) {
  const q = new Q();
  const set = Object.entries(patch).filter(([k]) => k !== 'allowed_types').map(([k, v]) => `${k} = ${q.add(v)}`);
  let changes = 0;
  if (set.length) changes = (await tx.run(`UPDATE ${tx.A}rr_policies SET ${set.join(', ')} WHERE id = ${q.add(id)}`, q.params)).changes;
  if (patch.allowed_types) {
    await setPolicyTypes(tx, id, patch.allowed_types);
    changes = 1;
  }
  return changes;
}

export async function deletePolicy(tx, id) {
  return (await tx.run(`DELETE FROM ${tx.A}rr_policies WHERE id = $1`, [id])).changes;
}

// The grants a principal holds, directly or through the groups it is in (disabled groups count for nothing, as in rr_ok), each with its policy attached:
// the input of every check in perm.js.  data_schema is '' on SQLite3 and for a global master it is null on PostgreSQL.
export async function effectiveGrants(tx, principalId) {
  const rows = await tx.all(`SELECT g.id, g.role, g.data_schema, g.zone_name, g.name_suffix, g.rr_policy_id, g.principal_id AS via, gp.name AS via_name
                               FROM ${tx.A}principal_closure c
                               JOIN ${tx.A}principals gp ON gp.id = c.group_id AND NOT gp.disabled
                               JOIN ${tx.A}grants g ON g.principal_id = c.group_id
                              WHERE c.member_id = $1 ORDER BY g.id`, [principalId]);
  const policies = new Map((await listPolicies(tx, { ids: [...new Set(rows.map((r) => r.rr_policy_id))] })).map((p) => [p.id, p]));
  return rows.map((r) => ({
    id: r.id, role: r.role, data_schema: tx.dialect === 'sqlite' ? '' : r.data_schema, zone_name: r.zone_name, name_suffix: r.name_suffix,
    via: r.via, via_name: r.via_name, policy: policies.get(r.rr_policy_id),
  }));
}

const grant = (r) => ({
  id: r.id, principal_id: r.principal_id, principal: r.principal_name, role: r.role, data_schema: r.data_schema, zone_name: r.zone_name, name_suffix: r.name_suffix,
  rr_policy_id: r.rr_policy_id, rr_policy: r.policy_name, granted_by: r.granted_by, granted_at: toIso(r.granted_at),
});
const GSEL = `g.id, g.principal_id, p.name AS principal_name, g.role, g.data_schema, g.zone_name, g.name_suffix, g.rr_policy_id, rp.name AS policy_name, g.granted_by, g.granted_at`;
const GFROM = (tx) => `${tx.A}grants g JOIN ${tx.A}principals p ON p.id = g.principal_id JOIN ${tx.A}rr_policies rp ON rp.id = g.rr_policy_id`;

// principalId, zone: filters (optional).  visible: { principals, zones } = only the grants of these principals or on these zones (a principal that is not a global
// master sees its own grants and those on the zones it is domain master of)
export async function listGrants(tx, { principalId, zone, visible, after = 0, limit }) {
  const q = new Q();
  const w = [`g.id > ${q.add(after)}`];
  if (principalId !== undefined) w.push(`g.principal_id = ${q.add(principalId)}`);
  if (zone) w.push(`g.zone_name = ${q.add(zone)}`);
  if (visible) w.push(`(${q.list(tx, 'g.principal_id', visible.principals, 'bigint')} OR ${q.list(tx, 'g.zone_name', visible.zones)})`);
  return (await tx.all(`SELECT ${GSEL} FROM ${GFROM(tx)} WHERE ${w.join(' AND ')} ORDER BY g.id LIMIT ${q.add(limit)}`, q.params)).map(grant);
}

export async function getGrant(tx, id) {
  const r = await tx.get(`SELECT ${GSEL} FROM ${GFROM(tx)} WHERE g.id = $1`, [id]);
  return r && grant(r);
}

export async function createGrant(tx, g) {
  return (await tx.get(`INSERT INTO ${tx.A}grants (principal_id, role, data_schema, zone_name, name_suffix, rr_policy_id, granted_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
    [g.principalId, g.role, tx.dialect === 'sqlite' ? null : g.schema, g.zone, g.suffix, g.policyId, g.grantedBy])).id;
}

export async function deleteGrant(tx, id) {
  return (await tx.run(`DELETE FROM ${tx.A}grants WHERE id = $1`, [id])).changes;
}

// ---------------------------------------------------------------------------------------------------------------------------------- zones
// a column of the SOA's content: "mname rname serial refresh ..." -> the serial
export function soaSerial(content) {
  const m = /^\s*\S+\s+\S+\s+(\d{1,10})(?:\s|$)/.exec(content ?? '');
  return m ? Number(m[1]) : null;
}

const SOA = (Z) => `(SELECT r.content FROM ${Z}records r WHERE r.domain_id = d.id AND upper(r.type) = 'SOA' ORDER BY r.id LIMIT 1)`;
const META = (Z, kind) => `EXISTS (SELECT 1 FROM ${Z}domainmetadata m WHERE m.domain_id = d.id AND upper(m.kind) = '${kind}' AND m.content = '1')`;
const noDot = (n) => (n.endsWith('.') ? n.slice(0, -1) : n);

const zoneRow = (r) => ({
  id: r.id, name: noDot(r.name).toLowerCase(), kind: r.type, catalog: r.catalog ?? null, serial: soaSerial(r.soa),
  presigned: bool(r.presigned), signer: bool(r.signer),
});

// names: the zones to list (a principal that is not a global master sees the zones it has a grant on), or null for all
export async function listZones(tx, schema, { names, prefix, kind, signed, after, limit }) {
  const Z = tx.z(schema);
  const q = new Q();
  const w = ['1 = 1'];
  if (names) w.push(q.list(tx, 'd.name', names.flatMap(zoneNames)));
  if (after !== undefined) w.push(`d.name > ${q.add(after)}`);
  if (prefix) w.push(`substr(lower(d.name), 1, ${prefix.length}) = ${q.add(prefix.toLowerCase())}`);
  if (kind) w.push(`d.type = ${q.add(kind)}`);
  if (signed === true) w.push(`(${META(Z, 'PRESIGNED')} OR ${META(Z, 'X-KARIDNS-SIGNER')})`);
  if (signed === false) w.push(`NOT (${META(Z, 'PRESIGNED')} OR ${META(Z, 'X-KARIDNS-SIGNER')})`);
  const rows = await tx.all(`SELECT d.id, d.name, d.type, d.catalog, ${SOA(Z)} AS soa, ${META(Z, 'PRESIGNED')} AS presigned, ${META(Z, 'X-KARIDNS-SIGNER')} AS signer
                               FROM ${Z}domains d WHERE ${w.join(' AND ')} ORDER BY d.name LIMIT ${q.add(limit + 1)}`, q.params);
  return rows.map((r) => ({ ...zoneRow(r), raw: r.name }));
}

export async function zoneId(tx, schema, zone) {
  return (await tx.get(`SELECT d.id FROM ${tx.z(schema)}domains d WHERE d.name IN ($1, $2)`, zoneNames(zone)))?.id;
}

// one zone with what the info document shows; undefined when there is no such zone (or, on PostgreSQL, the principal may not see it)
export async function getZone(tx, schema, zone) {
  const Z = tx.z(schema);
  const r = await tx.get(`SELECT d.id, d.name, d.type, d.master, d.catalog, d.account, d.notified_serial, ${SOA(Z)} AS soa, ${META(Z, 'PRESIGNED')} AS presigned, ${META(Z, 'X-KARIDNS-SIGNER')} AS signer
                            FROM ${Z}domains d WHERE d.name IN ($1, $2)`, zoneNames(zone));
  if (!r) return undefined;
  const z = { ...zoneRow(r), master: r.master ?? null, account: r.account ?? null, notified_serial: r.notified_serial ?? null };
  const gen = await tx.get(`SELECT generation, changed_at FROM ${Z}karidns_zone_state WHERE domain_id = $1`, [z.id]);
  z.generation = gen ? gen.generation : 0;
  z.changed_at = gen && gen.changed_at ? new Date(Number(gen.changed_at) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') : null;
  z.views = (await tx.all(`SELECT view_name FROM ${Z}karidns_domain_views WHERE domain_id = $1 ORDER BY view_name`, [z.id])).map((v) => v.view_name);
  const nsec3 = await tx.get(`SELECT content FROM ${Z}domainmetadata WHERE domain_id = $1 AND upper(kind) = 'NSEC3PARAM' ORDER BY id LIMIT 1`, [z.id]);
  z.nsec3param = nsec3 ? nsec3.content : null;
  const ss = await tx.get(`SELECT signed_at, signed_serial, min_expire, next_due, attempts, last_error, last_duration_ms FROM ${Z}karidns_signer_state WHERE domain_id = $1`, [z.id]);
  z.signer_state = ss ? { signed_at: toIso(ss.signed_at), signed_serial: ss.signed_serial, min_expire: toIso(ss.min_expire), next_due: toIso(ss.next_due), attempts: ss.attempts, last_error: ss.last_error ?? null, last_duration_ms: ss.last_duration_ms } : null;
  if (tx.dialect === 'pg') {
    const rr = await tx.get(`SELECT max(generation) AS g, max(requested_at) AS at FROM ${Z}karidns_reload_requests WHERE zone IS NULL OR lower(zone) IN ($1, $2)`, zoneNames(noDot(r.name).toLowerCase()));
    z.last_reload_request = rr && rr.g !== null ? { generation: rr.g, at: toIso(rr.at) } : null;
  } else {
    z.last_reload_request = null;
  }
  return z;
}

// How RRsets are read (planning 2.2, A-23): by domain_id, the RRsets in (name, type) order after the cursor, `limit` of them plus one to know whether there is more.
// visibility: null = every row of the zone; else { zone, suffixes: [...] } = the names under these suffixes and the apex SOA / NS (a subdomain master).
export async function listRRsets(tx, schema, domainId, { zone, name, type, visibility, after, limit }) {
  const Z = tx.z(schema);
  const q = new Q();
  const id = q.add(domainId);
  const w = [`k.domain_id = ${id}`, "k.type IS NOT NULL AND k.type <> ''", 'k.name IS NOT NULL'];
  const sfx = (col, s) => `(${col} = ${q.add(s)} OR substr(${col}, length(${col}) - ${s.length}) = ${q.add(`.${s}`)})`;
  w.push(sfx('k.name', zone));
  if (name) w.push(`k.name = ${q.add(name)}`);
  if (type) w.push(`upper(k.type) = ${q.add(type)}`);
  if (visibility) {
    const alts = visibility.suffixes.map((s) => sfx('k.name', s));
    alts.push(`(k.name = ${q.add(zone)} AND upper(k.type) IN ('SOA', 'NS'))`);
    w.push(`(${alts.join(' OR ')})`);
  }
  if (after) w.push(`(k.name > ${q.add(after.name)} OR (k.name = ${q.add(after.name)} AND upper(k.type) > ${q.add(after.type)}))`);
  const rows = await tx.all(`SELECT r.id, r.name, upper(r.type) AS type, r.ttl, r.content, r.prio, r.disabled FROM ${Z}records r
                              WHERE r.domain_id = ${id} AND (r.name, upper(r.type)) IN
                                    (SELECT k.name, upper(k.type) FROM ${Z}records k WHERE ${w.join(' AND ')} GROUP BY k.name, upper(k.type) ORDER BY k.name, upper(k.type) LIMIT ${q.add(limit + 1)})
                              ORDER BY r.name, upper(r.type), r.id`, q.params);
  return rows.map((r) => ({ id: r.id, name: r.name.toLowerCase(), type: r.type, ttl: r.ttl, content: r.content, prio: r.prio, disabled: bool(r.disabled) }));
}

// ---------------------------------------------------------------------------------------------------------------------------------- audit, servers
const auditRow = (r, source) => ({
  id: r.id, at: toIso(r.at), source, db_role: r.db_role, principal_id: r.principal_id, principal: r.principal_name, change_set: r.change_set, data_schema: r.data_schema,
  table: r.table_name, op: r.op, zone: r.zone_name, row_id: r.row_id,
  before: typeof r.before === 'string' ? JSON.parse(r.before) : (r.before ?? null), after: typeof r.after === 'string' ? JSON.parse(r.after) : (r.after ?? null),
});
const ACOLS = 'id, at, db_role, principal_id, principal_name, change_set, data_schema, table_name, op, zone_name, row_id, before, after';

// The audit rows, newest first.  PostgreSQL: the one table karidns_auth.audit_log (row level security shows each principal its own).  SQLite3: the log of the
// zone file (source 'zone') and the log of the auth file (source 'auth'), merged; the order is (at, source, id) and the cursor { at, rank, id } continues it.
// f: { zone, principalId, changeSet, table, since, until } (ms for since / until); after: the cursor or undefined.
export async function listAudit(tx, f, after, limit) {
  const sources = tx.dialect === 'pg' ? [['pg', `${tx.A}audit_log`, 0]] : [['zone', 'karidns_audit_log', 0], ['auth', `${tx.A}karidns_auth_audit`, 1]];
  let out = [];
  for (const [source, table, rank] of sources) {
    const q = new Q();
    const w = ['1 = 1'];
    if (f.zone) w.push(`zone_name = ${q.add(f.zone)}`);
    if (f.principalId !== undefined) w.push(`principal_id = ${q.add(f.principalId)}`);
    if (f.changeSet) w.push(`change_set = ${q.add(f.changeSet)}`);
    if (f.table) w.push(`table_name = ${q.add(f.table)}`);
    if (f.since !== undefined) w.push(`at >= ${q.add(tx.ts(f.since))}`);
    if (f.until !== undefined) w.push(`at <= ${q.add(tx.ts(f.until))}`);
    if (after) {
      const at = q.add(tx.ts(toMs(after.at)));
      if (tx.dialect === 'pg') w.push(`id < ${q.add(after.id)}`);
      else if (rank < after.rank) w.push(`at < ${at}`);               // the rows of this second that come first are before the cursor
      else if (rank > after.rank) w.push(`at <= ${at}`);              // ... those that come later are after it
      else w.push(`(at < ${at} OR (at = ${at} AND id < ${q.add(after.id)}))`);
    }
    const rows = await tx.all(`SELECT ${ACOLS} FROM ${table} WHERE ${w.join(' AND ')} ORDER BY ${tx.dialect === 'pg' ? 'id' : 'at'} DESC, id DESC LIMIT ${q.add(limit + 1)}`, q.params);
    out = out.concat(rows.map((r) => ({ ...auditRow(r, source === 'pg' ? 'audit' : source), rank })));
  }
  if (tx.dialect !== 'pg') out.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : a.rank - b.rank || b.id - a.id));
  return out;
}

export async function serverStatus(tx, schema) {
  if (tx.dialect !== 'pg') return [];
  const rows = await tx.all(`SELECT server_id, generation, applied_at, ok, failed_zones FROM ${tx.z(schema)}karidns_server_status ORDER BY server_id`);
  return rows.map((r) => ({ server_id: r.server_id, generation: r.generation, applied_at: toIso(r.applied_at), ok: bool(r.ok), failed_zones: r.failed_zones }));
}

// the tables of the list that are not there (the startup check); 'auth.x' is a table of the auth schema / file, the others belong to the dataset
export async function missingTables(tx, schema, tables) {
  const missing = [];
  for (const t of tables) {
    const isAuth = t.startsWith('auth.');
    const name = isAuth ? t.slice(5) : t;
    const found = tx.dialect === 'pg'
      ? await tx.get('SELECT to_regclass($1) IS NOT NULL AS ok', [`${isAuth ? 'karidns_auth' : `"${schema}"`}.${name}`])
      : await tx.get(`SELECT count(*) AS ok FROM ${isAuth ? 'auth.' : ''}sqlite_master WHERE type = 'table' AND name = $1`, [name]);
    if (!found.ok) missing.push(t);
  }
  return missing;
}

export async function schemaVersions(tx, schema) {
  const auth = await tx.get(`SELECT max(version) AS v FROM ${tx.A}schema_version`);
  const data = await tx.get(`SELECT max(version) AS v FROM ${tx.z(schema)}karidns_schema_version`);
  return { auth: auth?.v ?? null, data: data?.v ?? null };
}

// ---------------------------------------------------------------------------------------------------------------------------------- writing zones (M3)
// What a change needs to know of the zone before it runs the tools: its id, type, and whether it is signed (by the signer, or presigned elsewhere).
export async function zoneFacts(tx, schema, zone) {
  const Z = tx.z(schema);
  const r = await tx.get(`SELECT d.id, d.name, d.type, d.catalog, ${META(Z, 'PRESIGNED')} AS presigned, ${META(Z, 'X-KARIDNS-SIGNER')} AS signer
                            FROM ${Z}domains d WHERE d.name IN ($1, $2)`, zoneNames(zone));
  return r && { id: r.id, name: noDot(r.name).toLowerCase(), kind: r.type, catalog: r.catalog ?? null, presigned: bool(r.presigned), signer: bool(r.signer) };
}

// The RRsets (name, type) among `pairs` ([{ name, type }], canonical names, upper-case types) that carry a location / ECS tag or a tinydns attribute (A-18: the API
// does not edit those).  pairs undefined: whether the zone has any (the answer is then at most one entry).
export async function taggedRRsets(tx, schema, domainId, pairs) {
  const Z = tx.z(schema);
  const q = new Q();
  const id = q.add(domainId);
  const w = [`r.domain_id = ${id}`, `(EXISTS (SELECT 1 FROM ${Z}karidns_record_tags t WHERE t.record_id = r.id) OR EXISTS (SELECT 1 FROM ${Z}karidns_record_tinydns t WHERE t.record_id = r.id))`];
  if (pairs) w.push(q.list(tx, 'r.name', [...new Set(pairs.map((p) => p.name))]));
  const rows = await tx.all(`SELECT DISTINCT r.name, upper(r.type) AS type FROM ${Z}records r WHERE ${w.join(' AND ')} ORDER BY 1, 2 LIMIT ${pairs ? 100000 : 1}`, q.params);
  const wanted = pairs && new Set(pairs.map((p) => `${p.name} ${p.type}`));
  return rows.map((r) => ({ name: r.name.toLowerCase(), type: r.type })).filter((r) => !wanted || wanted.has(`${r.name} ${r.type}`));
}

// the enabled records at or below a name of the zone (max_rr counts them, A-24)
export async function countUnder(tx, schema, domainId, name) {
  const Z = tx.z(schema);
  const r = await tx.get(`SELECT count(*) AS n FROM ${Z}records r WHERE r.domain_id = $1 AND r.type IS NOT NULL AND r.type <> '' AND r.disabled IS NOT TRUE
                            AND (r.name = $2 OR substr(r.name, length(r.name) - $3) = $4)`, [domainId, name, name.length, `.${name}`]);
  return Number(r.n);
}

// Delete a zone and everything of it.  PostgreSQL: the foreign keys cascade.  SQLite3: the PowerDNS tables have no foreign keys (the reduced schema of the tests
// has none either), so the rows are deleted here, children first; the karidns_* tables cascade (the connection runs foreign_keys = ON); and the grants of the zone
// in the auth file go too (a trigger cannot reach across the two files; on PostgreSQL a trigger on domains deletes them).
export async function deleteZone(tx, schema, id, zone) {
  const Z = tx.z(schema);
  if (tx.dialect === 'sqlite') {
    for (const t of ['records', 'domainmetadata', 'cryptokeys']) await tx.run(`DELETE FROM ${t} WHERE domain_id = $1`, [id]);
    const comments = await tx.get("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'comments'");
    if (comments) await tx.run('DELETE FROM comments WHERE domain_id = $1', [id]);
    await tx.run('DELETE FROM domains WHERE id = $1', [id]);
    await tx.run(`DELETE FROM ${tx.A}grants WHERE zone_name = $1`, [zone]);
    return;
  }
  await tx.run(`DELETE FROM ${Z}domains WHERE id = $1`, [id]);
}

// a reload request for a zone (PostgreSQL: every loader on the database reloads it, planning 2.5); zone undefined: every zone of the schema
export const requestReload = (tx, schema, zone) => (zone === undefined
  ? tx.run(`INSERT INTO ${tx.z(schema)}karidns_reload_requests DEFAULT VALUES`)
  : tx.run(`INSERT INTO ${tx.z(schema)}karidns_reload_requests (zone) VALUES ($1)`, [zone]));

// the zones of the dataset that the signer keeps signed (a reload of every zone would publish their unsigned changes)
export async function signerZoneCount(tx, schema) {
  const Z = tx.z(schema);
  return Number((await tx.get(`SELECT count(*) AS n FROM ${Z}domainmetadata m WHERE upper(m.kind) = 'X-KARIDNS-SIGNER' AND m.content = '1'`)).n);
}

export async function listMetadata(tx, schema, domainId) {
  return (await tx.all(`SELECT upper(kind) AS kind, content FROM ${tx.z(schema)}domainmetadata WHERE domain_id = $1 ORDER BY upper(kind), id`, [domainId])).map((r) => ({ kind: r.kind, content: r.content }));
}

// the rows of one kind replaced by `values` (none: removed)
export async function setMetadata(tx, schema, domainId, kind, values) {
  const Z = tx.z(schema);
  await tx.run(`DELETE FROM ${Z}domainmetadata WHERE domain_id = $1 AND upper(kind) = $2`, [domainId, kind]);
  for (const v of values) await tx.run(`INSERT INTO ${Z}domainmetadata (domain_id, kind, content) VALUES ($1, $2, $3)`, [domainId, kind, v]);
}

export async function setCatalog(tx, schema, domainId, catalog) {
  await tx.run(`UPDATE ${tx.z(schema)}domains SET catalog = $2 WHERE id = $1`, [domainId, catalog]);
}

export async function producerZone(tx, schema, name) {
  const r = await tx.get(`SELECT d.type FROM ${tx.z(schema)}domains d WHERE d.name IN ($1, $2)`, zoneNames(name));
  return r?.type === 'PRODUCER';
}

export async function setViews(tx, schema, domainId, views) {
  const Z = tx.z(schema);
  await tx.run(`DELETE FROM ${Z}karidns_domain_views WHERE domain_id = $1`, [domainId]);
  for (const v of views) await tx.run(`INSERT INTO ${Z}karidns_domain_views (domain_id, view_name) VALUES ($1, $2)`, [domainId, v]);
}

// the DNSKEY RRset of the apex, and the key rows the API may read (never the key material)
export async function dnskeyRecords(tx, schema, domainId, zone) {
  return (await tx.all(`SELECT ttl, content FROM ${tx.z(schema)}records WHERE domain_id = $1 AND name = $2 AND upper(type) = 'DNSKEY' AND disabled IS NOT TRUE ORDER BY id`, [domainId, zone]))
    .map((r) => ({ ttl: r.ttl, content: r.content }));
}

export async function cryptoKeys(tx, schema, domainId) {
  return (await tx.all(`SELECT id, flags, active, published FROM ${tx.z(schema)}cryptokeys WHERE domain_id = $1 ORDER BY id`, [domainId]))
    .map((r) => ({ id: r.id, flags: r.flags, active: bool(r.active), published: bool(r.published) }));
}

const keyRequest = (r) => ({
  id: r.id, kind: r.kind, algorithm: r.algorithm, bits: r.bits ?? null, key_type: r.key_type, nsec: r.nsec ?? null, state: r.state, message: r.message ?? null,
  requested_by: r.requested_by ?? null, created_at: toIso(r.created_at), done_at: toIso(r.done_at),
});

export async function listKeyRequests(tx, schema, domainId, limit = 20) {
  return (await tx.all(`SELECT id, kind, algorithm, bits, key_type, nsec, state, message, requested_by, created_at, done_at FROM ${tx.z(schema)}karidns_key_requests
                         WHERE domain_id = $1 ORDER BY id DESC LIMIT $2`, [domainId, limit])).map(keyRequest);
}

// -> the id of the request.  The columns are the ones the API's role may insert (the state and the answer keep their defaults).
export async function insertKeyRequest(tx, schema, domainId, k, requestedBy) {
  const r = await tx.get(`INSERT INTO ${tx.z(schema)}karidns_key_requests (domain_id, kind, algorithm, bits, key_type, nsec, requested_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
    [domainId, k.kind, k.algorithm, k.bits ?? null, k.key_type, k.nsec ?? null, requestedBy]);
  return r.id;
}

export async function pendingKeyRequest(tx, schema, domainId) {
  const r = await tx.get(`SELECT id FROM ${tx.z(schema)}karidns_key_requests WHERE domain_id = $1 AND state = 'pending'`, [domainId]);
  return r?.id;
}

export async function zoneViews(tx, schema, domainId) {
  return (await tx.all(`SELECT view_name FROM ${tx.z(schema)}karidns_domain_views WHERE domain_id = $1 ORDER BY view_name`, [domainId])).map((v) => v.view_name);
}

// the hourly sweep on PostgreSQL: the API role cannot see the sessions of the other principals, so a SECURITY DEFINER function deletes the expired ones
export async function sweepExpired(tx) {
  return Number((await tx.get('SELECT karidns_auth.sweep_expired() AS n')).n);
}

// ---------------------------------------------------------------------------------------------------------------------------------- zone versions (M4)
// The history of a zone (planning 6): karidns_zone_versions and karidns_zone_version_rrsets, written by karidns-zone in the transaction of a change.  The API only
// reads them.  `visibility` is that of listRRsets: null = every row; else { zone, suffixes } = the names under these suffixes and the apex SOA / NS (a subdomain
// master).  On PostgreSQL row level security shows the same rows; on SQLite3 this condition is the only filter.
const sfxCond = (q, col, s) => `(${col} = ${q.add(s)} OR substr(${col}, length(${col}) - ${s.length}) = ${q.add(`.${s}`)})`;
function visCond(q, ownerCol, typeCol, visibility) {
  if (!visibility) return '1 = 1';
  const alts = visibility.suffixes.map((s) => sfxCond(q, ownerCol, s));
  alts.push(`(${ownerCol} = ${q.add(visibility.zone)} AND upper(${typeCol}) IN ('SOA', 'NS'))`);
  return `(${alts.join(' OR ')})`;
}

const versionHeader = (r) => ({
  version: r.version, kind: r.kind, at: toIso(r.at), principal_id: r.principal_id ?? null, principal: r.principal_name ?? null, db_role: r.db_role ?? null,
  change_set: r.change_set ?? null, comment: r.comment ?? null, serial_before: r.serial_before ?? null, serial_after: r.serial_after ?? null,
  generation_before: Number(r.generation_before), generation_after: Number(r.generation_after), rollback_of: r.rollback_of ?? null, delta_complete: bool(r.delta_complete),
  id: r.id, ...(r.n === undefined ? {} : { rrsets: Number(r.n) }),
});
const VSEL = 'v.id, v.version, v.kind, v.at, v.principal_id, v.principal_name, v.db_role, v.change_set, v.comment, v.serial_before, v.serial_after, v.generation_before, v.generation_after, v.rollback_of, v.delta_complete';

// The newest `limit` + 1 versions older than `before` (a version number), newest first, each with the number of RRsets of its delta that the principal sees.  The
// extra one is the next page's first, and the predecessor of the last one shown.
export async function listVersions(tx, schema, domainId, { before, limit, zone, visibility }) {
  const Z = tx.z(schema);
  const q = new Q();
  const id = q.add(domainId);
  const upto = q.add(before ?? 2147483647);
  const cnt = `SELECT count(*) FROM ${Z}karidns_zone_version_rrsets r WHERE r.version_id = v.id AND ${visCond(q, 'r.owner', 'r.type', visibility && { ...visibility, zone })}`;
  const rows = await tx.all(`SELECT ${VSEL}, (${cnt}) AS n FROM ${Z}karidns_zone_versions v WHERE v.domain_id = ${id} AND v.version < ${upto} ORDER BY v.version DESC LIMIT ${q.add(limit + 1)}`, q.params);
  return rows.map(versionHeader);
}

export async function getVersion(tx, schema, domainId, version, { zone, visibility } = {}) {
  const Z = tx.z(schema);
  const q = new Q();
  const cnt = `SELECT count(*) FROM ${Z}karidns_zone_version_rrsets r WHERE r.version_id = v.id AND ${visCond(q, 'r.owner', 'r.type', visibility && { ...visibility, zone })}`;
  const r = await tx.get(`SELECT ${VSEL}, (${cnt}) AS n FROM ${Z}karidns_zone_versions v WHERE v.domain_id = ${q.add(domainId)} AND v.version = ${q.add(version)}`, q.params);
  return r && versionHeader(r);
}

// the delta of one version, `limit` + 1 RRsets after the cursor { name, type }, in (owner, type) order: [{ owner, type, before, after }] (the lines are LF separated text)
export async function versionRRsets(tx, schema, versionId, { zone, visibility, after, limit }) {
  const Z = tx.z(schema);
  const q = new Q();
  const w = [`r.version_id = ${q.add(versionId)}`, visCond(q, 'r.owner', 'r.type', visibility && { ...visibility, zone })];
  if (after) w.push(`(r.owner > ${q.add(after.name)} OR (r.owner = ${q.add(after.name)} AND r.type > ${q.add(after.type)}))`);
  return tx.all(`SELECT r.owner, r.type, r.before, r.after FROM ${Z}karidns_zone_version_rrsets r WHERE ${w.join(' AND ')} ORDER BY r.owner, r.type LIMIT ${q.add(limit + 1)}`, q.params);
}

// How many RRset rows the versions in (from, to] hold that the principal sees (to undefined: up to the newest): the size of a fold, checked before it is read
export async function versionRowCount(tx, schema, domainId, from, to, { zone, visibility }) {
  const Z = tx.z(schema);
  const q = new Q();
  const w = [`v.domain_id = ${q.add(domainId)}`, `v.version > ${q.add(from)}`];
  if (to !== undefined) w.push(`v.version <= ${q.add(to)}`);
  const r = await tx.get(`SELECT count(*) AS n FROM ${Z}karidns_zone_version_rrsets r JOIN ${Z}karidns_zone_versions v ON v.id = r.version_id
                           WHERE ${w.join(' AND ')} AND ${visCond(q, 'r.owner', 'r.type', visibility && { ...visibility, zone })}`, q.params);
  return Number(r.n);
}

// The versions in (from, to] with their RRset rows, in the order the history happened: -> { headers: [{ version, delta_complete }], rows: [{ version, owner, type,
// before, after }] }.  Headers of versions without a visible RRset are there too (a version that did not touch the principal's names is still a version).
export async function versionsBetween(tx, schema, domainId, from, to, { zone, visibility }) {
  const Z = tx.z(schema);
  const q = new Q();
  const w = [`v.domain_id = ${q.add(domainId)}`, `v.version > ${q.add(from)}`];
  if (to !== undefined) w.push(`v.version <= ${q.add(to)}`);
  const headers = (await tx.all(`SELECT v.version, v.delta_complete FROM ${Z}karidns_zone_versions v WHERE ${w.join(' AND ')} ORDER BY v.version`, q.params))
    .map((r) => ({ version: r.version, delta_complete: bool(r.delta_complete) }));
  const q2 = new Q();
  const w2 = [`v.domain_id = ${q2.add(domainId)}`, `v.version > ${q2.add(from)}`];
  if (to !== undefined) w2.push(`v.version <= ${q2.add(to)}`);
  const rows = await tx.all(`SELECT v.version, r.owner, r.type, r.before, r.after FROM ${Z}karidns_zone_version_rrsets r JOIN ${Z}karidns_zone_versions v ON v.id = r.version_id
                              WHERE ${w2.join(' AND ')} AND ${visCond(q2, 'r.owner', 'r.type', visibility && { ...visibility, zone })} ORDER BY v.version, r.owner, r.type`, q2.params);
  return { headers, rows };
}

export async function zoneGeneration(tx, schema, domainId) {
  const r = await tx.get(`SELECT generation FROM ${tx.z(schema)}karidns_zone_state WHERE domain_id = $1`, [domainId]);
  return r ? Number(r.generation) : 0;
}

// the change sets of the versions of a zone (their audit rows are no outside changes)
export async function versionChangeSets(tx, schema, domainId) {
  return (await tx.all(`SELECT change_set FROM ${tx.z(schema)}karidns_zone_versions WHERE domain_id = $1 AND change_set IS NOT NULL`, [domainId])).map((r) => r.change_set);
}

const DNSSEC_LIST = "'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY'";
const json = (v) => (typeof v === 'string' ? JSON.parse(v) : v ?? null);

// Rows of the audit log that changed a record of the zone between two versions.  `since` and `until` are version ids (`until` undefined: up to now): the window is between
// their times, the end of a version that was made by the API (`sinceIncl` / `untilIncl`: it has a change set) included, so that a change by somebody else in the same second
// (SQLite3's audit log has no finer time) is looked at too: the rows of the API's own transaction carry its change set and are left out by that.  The end of a version
// without a change set (an operator's) is excluded: its rows cannot be told from others'.  Left out too: the rows of every change set in `exclude` (the versions'), the DNSSEC
// types (the signer's), an update that changed nothing but ordername / auth (the signer's), and the summary rows (no detail to judge).  -> { any, rows }: `any` is whether the
// audit log has any row of this zone in the window (when none, the log cannot tell what happened), `rows` are { op, before, after } for the JavaScript to judge the rest (an
// SOA update that changed the serial alone).
export async function auditRecordChanges(tx, schema, zone, { since, sinceIncl = false, until, untilIncl = false, exclude }) {
  const sqlite = tx.dialect === 'sqlite';
  if (sqlite && !(await tx.get("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'karidns_audit_log'"))) return { any: false, rows: [] };
  const Z = tx.z(schema);
  const q = new Q();
  const w = [`a.zone_name IN (${q.add(zone)}, ${q.add(`${zone}.`)})`, `a.at ${sinceIncl ? '>=' : '>'} (SELECT v.at FROM ${Z}karidns_zone_versions v WHERE v.id = ${q.add(since)})`];
  if (!sqlite) w.push(`a.data_schema = ${q.add(schema)}`);
  if (until !== undefined) w.push(`a.at ${untilIncl ? '<=' : '<'} (SELECT v.at FROM ${Z}karidns_zone_versions v WHERE v.id = ${q.add(until)})`);
  w.push(sqlite ? `(a.change_set IS NULL OR a.change_set NOT IN (SELECT value FROM json_each(${q.add(JSON.stringify(exclude))})))`
    : `(a.change_set IS NULL OR NOT (a.change_set = ANY(${q.add(exclude)}::text[])))`);
  const table = sqlite ? 'karidns_audit_log' : 'karidns_auth.audit_log';
  const any = await tx.get(`SELECT 1 AS ok FROM ${table} a WHERE ${w.join(' AND ')} LIMIT 1`, q.params);
  const body = sqlite
    ? `a.table_name = 'records' AND json_extract(coalesce(a.after, a.before), '$.summary') IS NULL
       AND upper(json_extract(coalesce(a.after, a.before), '$.type')) NOT IN (${DNSSEC_LIST})
       AND (a.op <> 'U' OR json_extract(a.before, '$.name') IS NOT json_extract(a.after, '$.name') OR json_extract(a.before, '$.type') IS NOT json_extract(a.after, '$.type')
            OR json_extract(a.before, '$.content') IS NOT json_extract(a.after, '$.content') OR json_extract(a.before, '$.ttl') IS NOT json_extract(a.after, '$.ttl')
            OR json_extract(a.before, '$.prio') IS NOT json_extract(a.after, '$.prio') OR json_extract(a.before, '$.disabled') IS NOT json_extract(a.after, '$.disabled'))`
    : `a.table_name = 'records' AND (coalesce(a.after, a.before) ->> 'summary') IS NULL
       AND upper(coalesce(a.after, a.before) ->> 'type') NOT IN (${DNSSEC_LIST})
       AND (a.op <> 'U' OR (a.before - 'ordername' - 'auth') IS DISTINCT FROM (a.after - 'ordername' - 'auth'))`;
  const rows = await tx.all(`SELECT a.op, a.before, a.after FROM ${table} a WHERE ${w.join(' AND ')} AND ${body} ORDER BY a.id LIMIT 2000`, q.params);
  return { any: Boolean(any), rows: rows.map((r) => ({ op: r.op, before: json(r.before), after: json(r.after) })) };
}

// ---------------------------------------------------------------------------------------------------------------------------------- zone templates (M4)
// karidns_auth.templates / template_records (planning 5.2): readable by every principal, written by global masters (row level security on PostgreSQL).
const SOA_COLS = ['soa_mname', 'soa_rname', 'soa_refresh', 'soa_retry', 'soa_expire', 'soa_minimum'];
const template = (r) => ({
  id: r.id, name: r.name, description: r.description ?? null, revision: r.revision,
  soa: SOA_COLS.every((c) => r[c] === null || r[c] === undefined) ? null : { mname: r.soa_mname ?? null, rname: r.soa_rname ?? null, refresh: r.soa_refresh ?? null, retry: r.soa_retry ?? null, expire: r.soa_expire ?? null, minimum: r.soa_minimum ?? null },
  created_by: r.created_by ?? null, updated_at: toIso(r.updated_at), ...(r.n === undefined ? {} : { record_count: Number(r.n) }),
});
const TCOLS = (A) => `t.id, t.name, t.description, t.revision, ${SOA_COLS.map((c) => `t.${c}`).join(', ')}, t.created_by, t.updated_at`;

export async function listTemplates(tx, { prefix, after = 0, limit }) {
  const q = new Q();
  const w = [`t.id > ${q.add(after)}`];
  if (prefix) w.push(`substr(lower(t.name), 1, ${prefix.length}) = ${q.add(prefix.toLowerCase())}`);
  return (await tx.all(`SELECT ${TCOLS()}, (SELECT count(*) FROM ${tx.A}template_records x WHERE x.template_id = t.id) AS n FROM ${tx.A}templates t WHERE ${w.join(' AND ')} ORDER BY t.id LIMIT ${q.add(limit + 1)}`, q.params)).map(template);
}

async function withRecords(tx, t) {
  if (!t) return undefined;
  const recs = await tx.all(`SELECT ordinal, owner, type, ttl, content FROM ${tx.A}template_records WHERE template_id = $1 ORDER BY ordinal`, [t.id]);
  return { ...template(t), records: recs.map((r) => ({ owner: r.owner, type: r.type, ttl: r.ttl ?? null, content: r.content })) };
}

export async function getTemplate(tx, id) {
  return withRecords(tx, await tx.get(`SELECT ${TCOLS()} FROM ${tx.A}templates t WHERE t.id = $1`, [id]));
}

export async function getTemplateByName(tx, name) {
  return withRecords(tx, await tx.get(`SELECT ${TCOLS()} FROM ${tx.A}templates t WHERE t.name = $1`, [name]));
}

const soaValues = (soa) => [soa?.mname ?? null, soa?.rname ?? null, soa?.refresh ?? null, soa?.retry ?? null, soa?.expire ?? null, soa?.minimum ?? null];

async function putRecords(tx, id, records) {
  await tx.run(`DELETE FROM ${tx.A}template_records WHERE template_id = $1`, [id]);
  let i = 0;
  for (const r of records) await tx.run(`INSERT INTO ${tx.A}template_records (template_id, ordinal, owner, type, ttl, content) VALUES ($1, $2, $3, $4, $5, $6)`, [id, i++, r.owner, r.type, r.ttl ?? null, r.content]);
}

// t: { name, description, soa: { mname, rname, refresh, retry, expire, minimum } | null, records: [{ owner, type, ttl, content }] } -> the id
export async function createTemplate(tx, t, createdBy) {
  const id = (await tx.get(`INSERT INTO ${tx.A}templates (name, description, ${SOA_COLS.join(', ')}, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
    [t.name, t.description ?? null, ...soaValues(t.soa), createdBy])).id;
  await putRecords(tx, id, t.records);
  return id;
}

// patch: any of name, description, soa (null clears), records (the whole list); -> the number of templates changed (0: there is none)
export async function updateTemplate(tx, id, patch) {
  const q = new Q();
  const set = [];
  if (patch.name !== undefined) set.push(`name = ${q.add(patch.name)}`);
  if (patch.description !== undefined) set.push(`description = ${q.add(patch.description)}`);
  if (patch.soa !== undefined) SOA_COLS.forEach((c, i) => set.push(`${c} = ${q.add(soaValues(patch.soa)[i])}`));
  if (set.length === 0) set.push('name = name');
  const n = (await tx.run(`UPDATE ${tx.A}templates SET ${set.join(', ')} WHERE id = ${q.add(id)}`, q.params)).changes;
  if (n && patch.records !== undefined) await putRecords(tx, id, patch.records);
  return n;
}

export async function deleteTemplate(tx, id) {
  return (await tx.run(`DELETE FROM ${tx.A}templates WHERE id = $1`, [id])).changes;
}

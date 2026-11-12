// /principals, /rr-policies, /grants: users, groups, memberships, record policies and grants (planning 3.3, 4).  Changing is for global masters, except grants, which a
// domain master may make inside its zone with a policy no wider than its own (no escalation, rule 2 of the plan).  Reading (0.6.0):
//   a global master reads everything;
//   a domain master (a domain_master grant on some zone, Z = those zones) sees itself and its groups (directly or through groups) in full, and in the short form (id, kind,
//     name, display_name) the members of those groups and every principal holding a grant on a zone of Z; and the policies of its own grants, of the grants on Z and those it
//     could use for a new grant (no wider than its own: mayGrant); it grants only to the principals it sees (any other is 404, as if it did not exist);
//   everyone else sees itself and the groups it is in, and the policies of its own grants;
//   anything outside that is a 404, so that nothing is told about whether it exists (perm.js principalsScope / policiesScope decide which rule applies).
// The filter is part of the SQL (store.js), so that a page is never short or empty because rows were dropped after the paging.

import { ApiError, badRequest, forbidden, notFound, conflict } from '../errors.js';
import { shape, query, LIMIT, CURSOR } from '../validate.js';
import * as S from '../store.js';
import { hashPassword } from '../crypto.js';
import { reply } from '../http.js';
import { isGlobal, zoneGrant, maySetGrant, mayGrant, principalsScope, policiesScope, domainZones } from '../perm.js';
import { canonicalZone, canonicalOwner, inZone, absolute } from '../names.js';
import { requireGlobal, idParam, idCursor, page, clean } from './common.js';
import { checkPassword, principalView, policyView } from './auth.js';

const PASSWORD = { type: 'string', min: 12, max: 1024, noControl: false };
const ID = { type: 'int', min: 1, max: 999999999999999 };

// ---------------------------------------------------------------------------------------------------------------------------------- principals
// what a principal sees of a member of one of its groups that is neither itself nor one of its groups (principalsScope decides who sees more)
const reducedView = (p) => ({ id: p.id, kind: p.kind, name: p.name, display_name: p.display_name });

// -> { global, own, scope }.  own = the ids of the principal itself and of the groups it is in (directly or through groups), whom it sees in full; scope = the part for
// the SQL of S.listPrincipals (principalsScope in perm.js decides), undefined for a global master (everything)
async function reach(ctx, tx) {
  const kind = principalsScope(ctx.auth.grants);
  if (kind === 'all') return { global: true, own: null, scope: undefined };
  const self = ctx.auth.principal.id;
  const groups = (await S.groupsOf(tx, self)).map((g) => g.id);
  const own = new Set([self, ...groups]);
  return { global: false, own, scope: { ids: [...own], groups: kind === 'domain' ? groups : [], zones: kind === 'domain' ? domainZones(ctx.auth.grants) : [] } };
}

// may the principal see this one at all?  (the same condition as the list)
async function canSeePrincipal(tx, reached, id) {
  if (reached.global || reached.own.has(id)) return true;
  return (await S.listPrincipals(tx, { id, scope: reached.scope, after: 0, limit: 1 })).length > 0;
}
const viewIn = (r, p) => (r.global || r.own.has(p.id) ? principalView(p) : reducedView(p));

export async function principalsList(ctx) {
  const q = query(ctx.query, { limit: LIMIT, cursor: CURSOR, kind: { type: 'string', values: ['user', 'group'] }, prefix: { type: 'string', min: 1, max: 64 } });
  const limit = q.limit ?? 100;
  const { r, rows } = await ctx.db(async (tx) => {
    const reached = await reach(ctx, tx);
    return { r: reached, rows: await S.listPrincipals(tx, { kind: q.kind, prefix: q.prefix, scope: reached.scope, after: idCursor(q.cursor), limit }) };
  });
  const p = page(rows, limit, (x) => ({ i: x.id }));
  return { principals: p.items.map((x) => viewIn(r, x)), next_cursor: p.next_cursor };
}

export async function principalCreate(ctx) {
  const { app, auth } = ctx;
  requireGlobal(ctx);
  const body = shape(ctx.body, {
    kind: { type: 'string', required: true, values: ['user', 'group'] },
    name: { type: 'string', required: true, min: 1, max: 255, re: /^[A-Za-z0-9][A-Za-z0-9._@+:-]*$/, reText: 'letters, digits and . _ @ + : - (not first)' },
    display_name: { type: 'string', max: 255, nullable: true },
    email: { type: 'string', max: 255, nullable: true, re: /^[^\s@]+@[^\s@]+$/, reText: 'an e-mail address' },
    password: PASSWORD,
    disabled: { type: 'bool' },
  });
  if (body.password !== undefined && body.kind !== 'user') throw badRequest('only a user has a password', '/password');
  if (body.password !== undefined) checkPassword(body.password, body.name);
  const hash = body.password === undefined ? null : await hashPassword(body.password, { ln: app.settings['scrypt-ln'] });
  const id = await ctx.db(async (tx) => {
    const pid = await S.createPrincipal(tx, { ...body, createdBy: auth.principal.id });
    if (hash) await S.setPassword(tx, pid, hash, app.now());
    return pid;
  }, { write: true });
  return reply(201, { principal: principalView(await ctx.db((tx) => S.getPrincipal(tx, id))) });
}

// what an administrator (and the user itself) may know of the credentials: no hash, no secret
// (oidc: the identity the user is linked to, with the provider's name and label when a configured provider has that issuer: the issuer and the subject are not secrets, and the
// person it belongs to sees them in the account, an administrator in the administration)
const credentialsView = (c, now, app) => {
  if (!c) return { password: false, totp_enabled: false, failed_logins: 0, locked: false, oidc: null };
  const prov = c.oidc_issuer ? app.oidc.byIssuer(c.oidc_issuer) : undefined;
  return {
    password: Boolean(c.password_hash), totp_enabled: c.totp_enabled, failed_logins: c.failed_logins, locked: Boolean(c.locked_until && c.locked_until > now),
    oidc: c.oidc_issuer ? { issuer: c.oidc_issuer, subject: c.oidc_subject, provider: prov ? { name: prov.name, label: prov.label } : null } : null,
  };
};

export async function principalGet(ctx) {
  const id = idParam(ctx);
  const self = id === ctx.auth.principal.id;
  const r = await ctx.db(async (tx) => {
    const reached = await reach(ctx, tx);
    const p = await S.getPrincipal(tx, id);
    if (!p || !(await canSeePrincipal(tx, reached, id))) return null;
    if (!reached.global && !reached.own.has(id)) return { p, reduced: true };
    return { p, groups: await S.groupsOf(tx, id), creds: reached.global || self ? ((await S.getCredentials(tx, id)) ?? null) : undefined };
  });
  if (!r) throw notFound('no such principal');
  if (r.reduced) return { principal: reducedView(r.p) };
  const out = { principal: { ...principalView(r.p), created_at: r.p.created_at, created_by: r.p.created_by }, groups: r.groups };
  if (r.creds !== undefined) out.credentials = credentialsView(r.creds, ctx.app.now(), ctx.app);
  return out;
}

// G6: what an administrator does for a user who cannot get in: reset-totp (a lost device: TOTP off, the secret gone, the sessions end; the next login enrols again where
// require-totp says so) and unlock (the account was locked by failed logins: the count and the lock go, the password stays).  Global masters only (F-15); one's own TOTP
// is switched off from the account (password and code), not reset by oneself.  The credentials triggers of the database write the audit rows.
export async function principalCredentials(ctx) {
  requireGlobal(ctx);
  const id = idParam(ctx);
  const body = shape(ctx.body, { action: { type: 'string', required: true, values: ['reset-totp', 'unlock'] } });
  if (body.action === 'reset-totp' && id === ctx.auth.principal.id) throw conflict('you cannot reset your own TOTP here: switch it off from your account (password and code), or ask another global master', 'self');
  const r = await ctx.db(async (tx) => {
    const p = await S.getPrincipal(tx, id);
    if (!p) return null;
    if (p.kind !== 'user') throw conflict('only a user has credentials', 'not-a-user');
    const c = await S.getCredentials(tx, id);
    if (!c) throw conflict('this user has no password, so no credentials to change', 'no-password');
    if (body.action === 'unlock') {
      await S.clearLock(tx, id);
    } else {
      if (!c.totp_enabled && !c.totp_secret) throw conflict('TOTP is not on for this user', 'totp-disabled');
      await S.setTotp(tx, id, null, false);
      await S.deleteSessionsOf(tx, id);
    }
    return { p, creds: await S.getCredentials(tx, id) };
  }, { write: true });
  if (!r) throw notFound('no such principal');
  ctx.app.log.info(`auth: ${clean(ctx.auth.principal.name)} did ${body.action} for ${clean(r.p.name)}`);
  return { credentials: credentialsView(r.creds, ctx.app.now(), ctx.app) };
}

// G7 (F-16): a global master links a user to an identity at a provider, (issuer, subject), or removes the link.  The subject is what the provider's ID token says in `sub` (the
// service logs it when a sign-in finds no user, so the administrator can copy it).  The issuer must be one of the configured providers'.  A user has one identity; a pair
// belongs to one user.  A changed or removed link ends the user's sessions (not the administrator's own): whoever came in through the old identity must not stay in.
export async function principalOidcPut(ctx) {
  requireGlobal(ctx);
  const id = idParam(ctx);
  const body = shape(ctx.body, {
    issuer: { type: 'string', required: true, min: 1, max: 255 },
    subject: { type: 'string', required: true, min: 1, max: 255 },
  });
  if (!ctx.app.oidc.byIssuer(body.issuer)) throw badRequest('no configured provider has this issuer', '/issuer');
  const r = await ctx.db(async (tx) => {
    const p = await S.getPrincipal(tx, id);
    if (!p) return null;
    if (p.kind !== 'user') throw conflict('only a user signs in', 'not-a-user');
    const owner = await S.oidcOwner(tx, body.issuer, body.subject);
    if (owner !== null && owner !== id) throw conflict('this identity is linked to another user', 'exists');
    const before = await S.getCredentials(tx, id);
    await S.setOidc(tx, id, body.issuer, body.subject);
    if (before?.oidc_issuer && (before.oidc_issuer !== body.issuer || before.oidc_subject !== body.subject)) await S.deleteSessionsOf(tx, id, ctx.auth.principal.id === id ? (ctx.auth.idHash ?? null) : null);
    return { p, creds: await S.getCredentials(tx, id) };
  }, { write: true });
  if (!r) throw notFound('no such principal');
  ctx.app.log.info(`auth: ${clean(ctx.auth.principal.name)} linked ${clean(r.p.name)} to ${clean(body.issuer)} subject ${clean(body.subject)}`);
  return { credentials: credentialsView(r.creds, ctx.app.now(), ctx.app) };
}

export async function principalOidcDelete(ctx) {
  requireGlobal(ctx);
  const id = idParam(ctx);
  const r = await ctx.db(async (tx) => {
    const p = await S.getPrincipal(tx, id);
    if (!p) return 'principal';
    if (!(await S.clearOidc(tx, id))) return 'link';
    await S.deleteSessionsOf(tx, id, ctx.auth.principal.id === id ? (ctx.auth.idHash ?? null) : null);
    return p;
  }, { write: true });
  if (r === 'principal') throw notFound('no such principal');
  if (r === 'link') throw notFound('this user is not linked to an identity');
  ctx.app.log.info(`auth: ${clean(ctx.auth.principal.name)} removed the identity link of ${clean(r.name)}`);
  return reply(204, null);
}

export async function principalUpdate(ctx) {
  const id = idParam(ctx);
  requireGlobal(ctx);
  const body = shape(ctx.body, {
    name: { type: 'string', min: 1, max: 255, re: /^[A-Za-z0-9][A-Za-z0-9._@+:-]*$/, reText: 'letters, digits and . _ @ + : - (not first)' },
    display_name: { type: 'string', max: 255, nullable: true },
    email: { type: 'string', max: 255, nullable: true, re: /^[^\s@]+@[^\s@]+$/, reText: 'an e-mail address' },
    disabled: { type: 'bool' },
  });
  if (id === ctx.auth.principal.id && body.disabled === true) throw conflict('you cannot disable yourself', 'self');
  const changed = await ctx.db(async (tx) => {
    const n = await S.updatePrincipal(tx, id, body);
    if (n && body.disabled === true) {
      await S.deleteSessionsOf(tx, id);
      await S.revokeTokensOf(tx, id, ctx.app.now());
    }
    return n;
  }, { write: true });
  if (!changed && Object.keys(body).length) throw notFound('no such principal');
  const p = await ctx.db((tx) => S.getPrincipal(tx, id));
  if (!p) throw notFound('no such principal');
  return { principal: principalView(p) };
}

export async function principalDelete(ctx) {
  const id = idParam(ctx);
  requireGlobal(ctx);
  if (id === ctx.auth.principal.id) throw conflict('you cannot delete yourself', 'self');
  const n = await ctx.db((tx) => S.deletePrincipal(tx, id), { write: true });
  if (!n) throw notFound('no such principal');
  return reply(204, null);
}

// an administrator sets the password of a user (the user's sessions end and its API tokens are revoked: a token stolen with the old
// password would stay valid until it expires otherwise; audit, 0.6.2)
export async function principalPassword(ctx) {
  const id = idParam(ctx);
  requireGlobal(ctx);
  const body = shape(ctx.body, { password: { ...PASSWORD, required: true } });
  const p = await ctx.db((tx) => S.getPrincipal(tx, id));
  if (!p) throw notFound('no such principal');
  if (p.kind !== 'user') throw conflict('only a user has a password', 'not-a-user');
  checkPassword(body.password, p.name);
  const hash = await hashPassword(body.password, { ln: ctx.app.settings['scrypt-ln'] });
  await ctx.db(async (tx) => {
    await S.setPassword(tx, id, hash, ctx.app.now());
    await S.deleteSessionsOf(tx, id);
    await S.revokeTokensOf(tx, id, ctx.app.now());
  }, { write: true });
  return { password: 'changed' };
}

async function groupOf(ctx, tx) {
  const g = await S.getPrincipal(tx, idParam(ctx));
  if (!g) throw notFound('no such principal');
  if (g.kind !== 'group') throw conflict('this is not a group: only a group has members', 'not-a-group');
  return g;
}

export async function membersList(ctx) {
  const r = await ctx.db(async (tx) => {
    const reached = await reach(ctx, tx);
    if (!(await canSeePrincipal(tx, reached, idParam(ctx)))) throw notFound('no such principal');       // (a group it does not see: it is not told whether it exists)
    const g = await groupOf(ctx, tx);
    return { reached, group: g, members: await S.membersOf(tx, g.id) };
  });
  return { group: viewIn(r.reached, r.group), members: r.members.map((m) => viewIn(r.reached, m)) };
}

export async function memberAdd(ctx) {
  requireGlobal(ctx);
  const body = shape(ctx.body, { member: { ...ID, required: true } });
  await ctx.db(async (tx) => {
    const g = await groupOf(ctx, tx);
    if (!(await S.getPrincipal(tx, body.member))) throw notFound('no such principal');
    await S.addMember(tx, g.id, body.member);
  }, { write: true });
  return reply(201, { member: body.member });
}

export async function memberRemove(ctx) {
  requireGlobal(ctx);
  const mid = idParam(ctx, 'mid');
  const n = await ctx.db(async (tx) => S.removeMember(tx, (await groupOf(ctx, tx)).id, mid), { write: true });
  if (!n) throw notFound('this principal is not a member');
  return reply(204, null);
}

// ---------------------------------------------------------------------------------------------------------------------------------- policies
const META_TYPES = new Set(['RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY', 'ANY', 'AXFR', 'IXFR', 'OPT', 'TSIG', 'TKEY', 'MAILA', 'MAILB']);
const TTL = { type: 'int', min: 0, max: 2147483647 };
const POLICY = {
  name: { type: 'string', min: 1, max: 255 },
  allowed_types: { type: 'array', max: 200, items: { type: 'string', min: 1, max: 32, re: /^[A-Za-z][A-Za-z0-9]*$/ } },
  allow_wildcard: { type: 'bool' },
  allow_delegation: { type: 'bool' },
  allow_dname: { type: 'bool' },
  apex_editable: { type: 'bool' },
  ttl_min: TTL,
  ttl_max: TTL,
  max_rr: { type: 'int', min: 0, max: 1000000000, nullable: true },
};

// the types of a policy: upper case, once each, none of the DNSSEC types (the signer owns them) and none of the meta types, also not as TYPEnnn (the database checks again)
function policyTypes(list) {
  const out = [...new Set(list.map((t) => t.toUpperCase()))].sort();
  out.forEach((t, i) => {
    if (META_TYPES.has(t) || /^TYPE0*(2|6|39|46|47|48|50|51|59|60)$/.test(t)) {
      throw new ApiError(400, 'bad-request', `${t} cannot be in a policy: the DNSSEC types belong to the signer and the meta types are no data`, { errors: [{ code: 'bad-request', severity: 'error', text: `${t} cannot be in a policy`, pointer: `/allowed_types/${i}` }] });
    }
  });
  return out;
}

export async function policiesList(ctx) {
  const q = query(ctx.query, { limit: LIMIT, cursor: CURSOR });
  const limit = q.limit ?? 100;
  const rows = await ctx.db(async (tx) => S.listPolicies(tx, { ids: await visiblePolicies(ctx, tx), after: idCursor(q.cursor), limit: limit + 1 }));
  const p = page(rows, limit, (r) => ({ i: r.id }));
  return { policies: p.items.map(policyView), next_cursor: p.next_cursor };
}

// undefined = all policies (policiesScope); else the ids of the policies of the principal's own grants and, for a domain master, of the grants on its zones and of the
// policies it could use for a new grant in them (what the grant form offers: mayGrant, the same test the creation applies)
async function visiblePolicies(ctx, tx) {
  const grants = ctx.auth.grants;
  const kind = policiesScope(grants);
  if (kind === 'all') return undefined;
  const ids = new Set(grants.map((g) => g.policy?.id).filter((i) => i !== undefined));
  if (kind === 'domain') {
    for (const i of await S.policyIdsOnZones(tx, domainZones(grants))) ids.add(i);
    for (const p of await S.listPolicies(tx)) if (!ids.has(p.id) && grants.some((g) => g.role === 'domain_master' && mayGrant(grants, { role: 'subdomain_master', schema: g.data_schema, zone: g.zone_name, policy: p }))) ids.add(p.id);
  }
  return [...ids];
}

export async function policyGet(ctx) {
  const id = idParam(ctx);
  const p = await ctx.db(async (tx) => {
    const ids = await visiblePolicies(ctx, tx);
    return ids && !ids.includes(id) ? undefined : S.getPolicy(tx, id);
  });
  if (!p) throw notFound('no such policy');
  return { policy: policyView(p) };
}

export async function policyCreate(ctx) {
  requireGlobal(ctx);
  const body = shape(ctx.body, { ...POLICY, name: { ...POLICY.name, required: true }, allowed_types: { ...POLICY.allowed_types, required: true } });
  const p = {
    allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 0, ttl_max: 2147483647, max_rr: null, ...body, allowed_types: policyTypes(body.allowed_types),
  };
  if (p.ttl_min > p.ttl_max) throw badRequest('ttl_min is higher than ttl_max', '/ttl_min');
  const id = await ctx.db((tx) => S.createPolicy(tx, p, ctx.auth.principal.id), { write: true });
  return reply(201, { policy: policyView(await ctx.db((tx) => S.getPolicy(tx, id))) });
}

export async function policyUpdate(ctx) {
  requireGlobal(ctx);
  const id = idParam(ctx);
  const body = shape(ctx.body, POLICY);
  if (body.allowed_types) body.allowed_types = policyTypes(body.allowed_types);
  const p = await ctx.db(async (tx) => {
    const old = await S.getPolicy(tx, id);
    if (!old) return null;
    if ((body.ttl_min ?? old.ttl_min) > (body.ttl_max ?? old.ttl_max)) throw badRequest('ttl_min is higher than ttl_max', '/ttl_min');
    await S.updatePolicy(tx, id, body);
    return S.getPolicy(tx, id);
  }, { write: true });
  if (!p) throw notFound('no such policy');
  return { policy: policyView(p) };
}

export async function policyDelete(ctx) {
  requireGlobal(ctx);
  const n = await ctx.db((tx) => S.deletePolicy(tx, idParam(ctx)), { write: true });
  if (!n) throw notFound('no such policy');
  return reply(204, null);
}

// ---------------------------------------------------------------------------------------------------------------------------------- grants
const gview = (app, g) => ({
  id: g.id, principal_id: g.principal_id, principal: g.principal, role: g.role,
  dataset: g.data_schema === null ? (g.zone_name ? 'main' : null) : (app.datasetOfSchema(g.data_schema)?.name ?? g.data_schema),
  zone: g.zone_name ? absolute(g.zone_name) : null, suffix: g.name_suffix ? absolute(g.name_suffix) : null, policy_id: g.rr_policy_id, policy: g.rr_policy,
  granted_by: g.granted_by, granted_at: g.granted_at,
});

// a grant's data_schema as perm.js compares it ('' on SQLite3)
const schemaOf = (ctx, g) => (ctx.app.backend.dialect === 'sqlite' ? '' : g.data_schema);

// Which grants does the principal see?  A global master all of them; otherwise its own, those of the groups it is in, and those on the zones it is domain
// master of (karidns_auth's policy on grants says the same).  -> { visible: the part for the SQL (null = all), canSee(grant): the exact test }
async function grantFilter(ctx, tx) {
  const { auth } = ctx;
  if (isGlobal(auth.grants)) return { visible: undefined, canSee: () => true };
  const mine = new Set([auth.principal.id, ...(await S.groupsOf(tx, auth.principal.id)).map((g) => g.id)]);
  const zones = [...new Set(auth.grants.filter((g) => g.role === 'domain_master').map((g) => g.zone_name))];
  return {
    visible: { principals: [...mine], zones },
    canSee: (g) => mine.has(g.principal_id) || Boolean(g.zone_name && zoneGrant(auth.grants, schemaOf(ctx, g), g.zone_name) === 'domain_master'),
  };
}

export async function grantsList(ctx) {
  const { app, auth } = ctx;
  const q = query(ctx.query, { limit: LIMIT, cursor: CURSOR, principal: ID, zone: { type: 'string', min: 1, max: 255 } });
  const limit = q.limit ?? 100;
  let zone;
  if (q.zone !== undefined) {
    try { zone = canonicalZone(q.zone); } catch (e) { throw badRequest(e.message, '?zone'); }
  }
  const { rows, canSee } = await ctx.db(async (tx) => {
    const f = await grantFilter(ctx, tx);
    return { canSee: f.canSee, rows: await S.listGrants(tx, { principalId: q.principal, zone, visible: f.visible, after: idCursor(q.cursor), limit: limit + 1 }) };
  });
  const p = page(rows, limit, (r) => ({ i: r.id }));
  const items = p.items.filter(canSee);
  return { grants: items.map((g) => gview(app, g)), next_cursor: p.next_cursor };
}

export async function grantCreate(ctx) {
  const { app, auth } = ctx;
  const body = shape(ctx.body, {
    principal: { ...ID, required: true },
    role: { type: 'string', required: true, values: ['global_master', 'domain_master', 'subdomain_master'] },
    dataset: { type: 'string', max: 32 },
    zone: { type: 'string', min: 1, max: 255 },
    suffix: { type: 'string', min: 1, max: 255 },
    policy: { ...ID, required: true },
  });
  let ds = null;
  let zone = null;
  let suffix = null;
  if (body.role === 'global_master') {
    for (const f of ['dataset', 'zone', 'suffix']) if (body[f] !== undefined) throw badRequest('a global master grant has no dataset, zone or suffix', `/${f}`);
  } else {
    if (body.zone === undefined) throw badRequest('this role needs a zone', '/zone');
    if (body.role === 'subdomain_master' && body.suffix === undefined) throw badRequest('a subdomain master needs a suffix', '/suffix');
    if (body.role === 'domain_master' && body.suffix !== undefined) throw badRequest('a domain master has no suffix', '/suffix');
    ds = body.dataset === undefined && app.datasets.length === 1 ? app.datasets[0] : app.dataset(body.dataset);
    if (!ds) throw badRequest(body.dataset === undefined ? 'the dataset is required' : 'no such dataset', '/dataset');
    try { zone = canonicalZone(body.zone); } catch (e) { throw badRequest(e.message, '/zone'); }
    if (body.suffix !== undefined) {
      try { suffix = canonicalOwner(body.suffix); } catch (e) { throw badRequest(e.message, '/suffix'); }
      if (!inZone(suffix, zone)) throw badRequest('the suffix is not the zone or a name below it', '/suffix');
    }
  }
  const id = await ctx.db(async (tx) => {
    const target = await S.getPrincipal(tx, body.principal);
    if (!target) throw notFound('no such principal');
    const pol = await S.getPolicy(tx, body.policy);
    if (!pol) throw notFound('no such policy');
    if (!maySetGrant(auth.grants, { role: body.role, schema: ds ? ds.schema : null, zone, policy: pol })) {
      throw forbidden('you may only grant on a zone you are domain master of, with a policy no wider than your own (a global master may grant anything)', 'escalation');
    }
    // A domain master grants only to the principals it sees FOR THIS ZONE: itself, its groups and their members, and the holders of a grant on this zone (not
    // those of its other zones: a master of several zones keeps them apart; decided 2026-11-10).  maySetGrant above made sure it is domain master of this zone.
    const reached = await reach(ctx, tx);
    if (!reached.global) reached.scope = { ...reached.scope, zones: [{ schema: ds.schema, zone }] };
    if (!(await canSeePrincipal(tx, reached, body.principal))) throw notFound('no such principal');
    return S.createGrant(tx, { principalId: body.principal, role: body.role, schema: ds ? ds.schema : null, zone, suffix, policyId: body.policy, grantedBy: auth.principal.id });
  }, { write: true });
  return reply(201, { grant: gview(app, await ctx.db((tx) => S.getGrant(tx, id))) });
}

export async function grantDelete(ctx) {
  const { auth } = ctx;
  const id = idParam(ctx);
  await ctx.db(async (tx) => {
    const g = await S.getGrant(tx, id);
    if (!g || !(await grantFilter(ctx, tx)).canSee(g)) throw notFound('no such grant');
    const pol = await S.getPolicy(tx, g.rr_policy_id);
    if (!maySetGrant(auth.grants, { role: g.role, schema: schemaOf(ctx, g), zone: g.zone_name, policy: pol })) throw forbidden('you may not remove this grant', 'escalation');
    await S.deleteGrant(tx, id);
  }, { write: true });
  return reply(204, null);
}


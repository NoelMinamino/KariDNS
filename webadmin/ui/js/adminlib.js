// adminlib.js: the logic of the administration and audit screens that needs no DOM (planning 3 S11, S12): a record policy from its form and the hint "no wider than mine",
// the lookup of a user or group by name, the filters of the audit log and its rows.  Everything here is a hint for the person: the service decides (5.4) - above all the
// rule against escalation (a domain master grants only on its own zone with a policy no wider than its own: 403 `escalation`).

// ---------------------------------------------------------------------------------------------------------------------------------- policies
// "a, aaaa  mx" -> ['A', 'AAAA', 'MX'] (upper case, once each, in the order typed)
export const parseTypes = (text) => [...new Set(String(text ?? '').split(/[\s,]+/).filter(Boolean).map((s) => s.toUpperCase()))];

const INT = /^\d{1,10}$/;

// the form of a policy (strings and booleans) -> { body } for POST / PATCH /rr-policies, or { error: field } for the first field that cannot be sent.  An empty max_rr is
// "no limit" (null); an empty TTL bound is left out (the service's defaults: 0 and 2147483647).
export function policyBody(v) {
  const name = String(v.name ?? '').trim();
  if (name === '') return { error: 'name' };
  const types = parseTypes(v.types);
  if (types.length === 0) return { error: 'types' };
  const body = { name, allowed_types: types, allow_wildcard: v.wildcard === true, allow_delegation: v.delegation === true, allow_dname: v.dname === true, apex_editable: v.apex === true };
  for (const [k, field] of [['ttl_min', 'ttl_min'], ['ttl_max', 'ttl_max']]) {
    const s = String(v[k] ?? '').trim();
    if (s === '') continue;
    if (!INT.test(s) || Number(s) > 2147483647) return { error: field };
    body[field] = Number(s);
  }
  if ((body.ttl_min ?? 0) > (body.ttl_max ?? 2147483647)) return { error: 'ttl_min' };
  const m = String(v.max_rr ?? '').trim();
  if (m === '') body.max_rr = null;
  else if (!INT.test(m) || Number(m) > 1000000000) return { error: 'max_rr' };
  else body.max_rr = Number(m);
  return { body };
}

// is policy `sub` no wider than `sup`?  The rule of perm.js policySubset (types a subset, each flag not more, ttl_min not lower, ttl_max not higher, max_rr not higher,
// null = no limit).  Used only to offer a domain master the policies it may grant; the service decides.
export function policyWithin(sub, sup) {
  if (!sup) return true;
  return sub.allowed_types.every((t) => sup.allowed_types.includes(t))
    && (!sub.allow_wildcard || sup.allow_wildcard)
    && (!sub.allow_delegation || sup.allow_delegation)
    && (!sub.allow_dname || sup.allow_dname)
    && (!sub.apex_editable || sup.apex_editable)
    && sub.ttl_min >= sup.ttl_min && sub.ttl_max <= sup.ttl_max
    && (sup.max_rr === null || sup.max_rr === undefined || (sub.max_rr !== null && sub.max_rr !== undefined && sub.max_rr <= sup.max_rr));
}

// ---------------------------------------------------------------------------------------------------------------------------------- principals
// the user or group with exactly this name (names are unique whatever the case), or null.  GET /principals is readable by everybody; its prefix is at most 64 characters.
export async function lookupPrincipal(api, name, kind) {
  const n = String(name ?? '').trim();
  if (n === '') return null;
  const r = await api.get('/principals', { query: { prefix: n.slice(0, 64), kind, limit: 100 } });
  const lc = n.toLowerCase();
  return r.principals.find((p) => String(p.name).toLowerCase() === lc) ?? null;
}

// the name of a principal for a list: the name, and the display name when there is one
export const principalLabel = (p) => (p.display_name ? `${p.name} (${p.display_name})` : String(p.name));

// ---------------------------------------------------------------------------------------------------------------------------------- audit
export const TABLE_NAME = /^[a-z_]+$/;
export const CHANGE_SET = /^[A-Za-z0-9._:-]+$/;

// a time typed as ISO 8601 -> the text to send, or null when it is not a time (the service reads Date.parse as well)
export const whenText = (s) => { const t = String(s ?? '').trim(); return t !== '' && Number.isFinite(Date.parse(t)) && t.length <= 40 ? t : null; };

// the route's query -> { query } for GET /audit (principal is the id, found by the caller), or { error: the name of the first field that cannot be sent }
export function auditQuery(q, principalId) {
  const out = { limit: 100 };
  const zone = String(q.zone ?? '').trim();
  if (zone !== '') {
    if (!/^[A-Za-z0-9_.*-]+$/.test(zone) || zone.length > 255) return { error: 'zone' };
    out.zone = zone;
  }
  if (principalId !== undefined && principalId !== null) out.principal = principalId;
  const cs = String(q.change_set ?? '').trim();
  if (cs !== '') {
    if (!CHANGE_SET.test(cs) || cs.length > 64) return { error: 'change_set' };
    out.change_set = cs;
  }
  const table = String(q.table ?? '').trim();
  if (table !== '') {
    if (!TABLE_NAME.test(table) || table.length > 64) return { error: 'table' };
    out.table = table;
  }
  for (const k of ['since', 'until']) {
    const s = String(q[k] ?? '').trim();
    if (s === '') continue;
    if (whenText(s) === null) return { error: k };
    out[k] = s;
  }
  if (q.cursor) out.cursor = q.cursor;
  return { query: out };
}

// The dataset an audit row belongs to, for a link to the versions of its zone: the only dataset when there is one, else the one whose name the row's schema equals;
// null when it cannot be told.
export function datasetOfRow(datasets, schema) {
  if (datasets.length === 1) return datasets[0].name;
  return datasets.find((d) => d.name === schema)?.name ?? null;
}

export const JSON_SHOWN = 20000;

// a JSON value as the lines of its pretty-printed text (shown as text, never parsed again: the log's `before` / `after` are hostile); a value longer than JSON_SHOWN
// characters is cut, and `cut` says so
export function jsonLines(value) {
  let text;
  try { text = JSON.stringify(value, null, 2); } catch { text = undefined; }
  if (text === undefined) return { lines: [], cut: false };
  const cut = text.length > JSON_SHOWN;
  return { lines: (cut ? text.slice(0, JSON_SHOWN) : text).split('\n'), cut };
}

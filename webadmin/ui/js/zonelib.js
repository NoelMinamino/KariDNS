// zonelib.js: the logic of the zone screens that needs no DOM (planning 4.1): names relative to a zone and back, the lines of a records box, the reasons why an RRset
// is shown but not edited (planning 3, S4), the API paths, the remaining time of a signature.  Everything here is a hint for the person: the service decides (5.4).

import { enc } from './api.js';

// the types a zone's signer makes; a change set never takes them (D-SIGNER).  The list of lib/perm.js.
export const DNSSEC_TYPES = new Set(['RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY']);

export const stripDot = (n) => String(n).replace(/\.$/, '');
export const lower = (n) => String(n).toLowerCase();

// ---------------------------------------------------------------------------------------------------------------------------------- paths
export const zonePath = (ds, zone) => `/datasets/${enc(ds)}/zones/${enc(zone)}`;
export const datasetPath = (ds) => `/datasets/${enc(ds)}`;

// ---------------------------------------------------------------------------------------------------------------------------------- names
// "www.example.test." in "example.test." -> "www"; the apex -> "@"; a name outside the zone is left as it is
export function relName(name, zone) {
  const n = lower(name);
  const z = lower(zone);
  if (n === z) return '@';
  if (n.endsWith(`.${z}`)) return String(name).slice(0, n.length - z.length - 1);
  return String(name);
}

// What a person typed as an owner -> the absolute name in the zone, or null when it cannot be one.  "@" is the apex; a name that ends with a dot is absolute; a name that
// is the zone or ends with the zone's name is taken as absolute; anything else is relative to the zone.  U-labels become A-labels (the service takes no non-ASCII).
export function absName(input, zone) {
  let s = String(input ?? '').trim();
  if (s === '') return null;
  if (s === '@') return lower(zone);
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(s)) {
    try { s = new URL('http://' + s).hostname; } catch { return null; }
    if (s === '') return null;
  }
  s = lower(s);
  // (what an owner name may hold: letters, digits, - and _, a * label and /; the service checks it again and says where)
  if (!/^[a-z0-9_.*/-]+$/.test(s)) return null;
  const z = lower(zone);
  if (s.endsWith('.')) return s;
  const bare = stripDot(z);
  if (s === bare || s.endsWith(`.${bare}`)) return `${s}.`;
  return `${s}.${z}`;
}

// ---------------------------------------------------------------------------------------------------------------------------------- records
// the text of a records box -> the records, one per line (blank lines are nothing)
export const recordLines = (text) => String(text ?? '').split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '');
export const recordsText = (lines) => lines.join('\n');

// A line "owner [ttl] TYPE rdata" (the shape of a zone file without $-lines) -> { owner, ttl, type, content } or null.  The owner is "@" or a name; a TTL is digits.
export function parseRecordLine(line) {
  const m = /^(\S+)\s+(?:(\d{1,10})\s+)?([A-Za-z][A-Za-z0-9]*)\s+(\S[\s\S]*)$/.exec(line.trim());
  return m ? { owner: m[1], ttl: m[2] === undefined ? undefined : Number(m[2]), type: m[3].toUpperCase(), content: m[4].trim() } : null;
}

// the RRset of a record as the loaded page has it: what the person edits (the text a change set takes, `rdata`; else the stored content)
export const rdataOf = (rec) => (typeof rec.rdata === 'string' ? rec.rdata : rec.content);

// the records of an RRset as { ttl, content } for a precondition (`expect`): the text a change set takes, with the TTL each record has
export const expectOf = (rr) => rr.records.map((r) => ({ ttl: r.ttl ?? rr.ttl ?? 0, content: rdataOf(r) }));

// ---------------------------------------------------------------------------------------------------------------------------------- what may be edited
// the WILDCARD rule of lib/perm.js
const WILDCARD = /(^|[.])[*]([.]|$)/;

// May a holder of grant g write this RRset?  The rules of perm.js grantAllows for the grants of GET .../zones/{zone} (names absolute).  A hint, never a decision.
function grantAllows(g, z, n, t, ttl) {
  const p = g.policy;
  if (!p) return true;
  const sfx = g.suffix ? lower(stripDot(g.suffix)) : null;
  if (g.role === 'subdomain_master' && sfx !== null && !(n === sfx || n.endsWith(`.${sfx}`))) return false;
  if (WILDCARD.test(n) && !p.allow_wildcard) return false;
  if (!p.allowed_types.includes(t) || DNSSEC_TYPES.has(t)) return false;
  if (ttl < p.ttl_min || ttl > p.ttl_max) return false;
  if (t === 'NS' && n !== z && !p.allow_delegation) return false;
  if (t === 'DNAME' && !p.allow_dname) return false;
  if (n === z && !(p.apex_editable && g.role !== 'subdomain_master')) return false;
  if (t === 'SOA' && !(n === z && g.role === 'global_master' && p.apex_editable)) return false;
  return true;
}

// -> null when some grant allows the RRset, else the first reason that fits: 'scope' (outside the suffix), 'apex', 'type' (not in the policy), 'policy' (TTL, wildcard, ...)
export function policyReason(grants, zone, name, type, ttl) {
  const z = lower(stripDot(zone));
  const n = lower(stripDot(name));
  const t = String(type).toUpperCase();
  if (!Array.isArray(grants) || grants.length === 0) return null;
  if (grants.some((g) => grantAllows(g, z, n, t, ttl ?? 0))) return null;
  const inScope = grants.filter((g) => g.role !== 'subdomain_master' || !g.suffix || n === lower(stripDot(g.suffix)) || n.endsWith(`.${lower(stripDot(g.suffix))}`));
  if (inScope.length === 0) return 'scope';
  if (n === z && !inScope.some((g) => g.role !== 'subdomain_master' && (g.policy?.apex_editable ?? true))) return 'apex';
  if (!inScope.some((g) => (g.policy?.allowed_types ?? [t]).includes(t))) return 'type';
  return 'policy';
}

// Why this RRset of a page is shown but not edited, or null when it can be: 'zone-kind', 'presigned', 'dnssec', 'tagged', 'soa' (edited in its own form), 'no-text' (a
// record has no text form, G2), 'disabled' (a record is switched off), 'unknown-type', or what policyReason says.  zone: the document of GET .../zones/{zone}; types:
// the list of GET /version (null when the service did not say).
export function editReason(rr, zone, types) {
  if (!['NATIVE', 'MASTER'].includes(String(zone.kind).toUpperCase())) return 'zone-kind';
  if (zone.presigned && !zone.signer) return 'presigned';
  const type = String(rr.type).toUpperCase();
  if (DNSSEC_TYPES.has(type)) return 'dnssec';
  if (rr.tagged === true) return 'tagged';
  if (type === 'SOA') return 'soa';
  if (rr.records.some((r) => typeof r.rdata !== 'string')) return 'no-text';
  if (rr.records.some((r) => r.disabled === true)) return 'disabled';
  if (Array.isArray(types) && !types.includes(type) && !/^TYPE\d{1,5}$/.test(type)) return 'unknown-type';
  return policyReason(zone.grants, zone.name, rr.name, type, rr.ttl);
}

// May a new RRset of this type be added at all?  (the zone: is it one whose records are edited; the type: one the service takes)
export function zoneEditable(zone) {
  if (!['NATIVE', 'MASTER'].includes(String(zone.kind).toUpperCase())) return 'zone-kind';
  if (zone.presigned && !zone.signer) return 'presigned';
  return null;
}

// the TTL range the strongest grant allows: [min, max] or null
export function ttlRange(grants) {
  const p = (grants ?? []).find((g) => g.policy)?.policy;
  return p ? [p.ttl_min, p.ttl_max] : null;
}

// the types a person may choose for a new RRset: the service's list without the DNSSEC types and the SOA, narrowed to the policy of the grants when there is one
export function addableTypes(types, grants) {
  const base = Array.isArray(types) ? types.filter((t) => !DNSSEC_TYPES.has(t) && t !== 'SOA') : [];
  const allowed = new Set((grants ?? []).flatMap((g) => g.policy?.allowed_types ?? []));
  return allowed.size === 0 ? base : base.filter((t) => allowed.has(t));
}

// ---------------------------------------------------------------------------------------------------------------------------------- times
// the time left until an ISO time: { sec, past } and the text "3 d 4 h", "2 h 5 min", "40 s" (numbers and unit letters need no catalog)
export function remaining(iso, nowMs) {
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return null;
  const sec = Math.round((at - nowMs) / 1000);
  const past = sec < 0;
  let s = Math.abs(sec);
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const hh = Math.floor(s / 3600);
  s -= hh * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  const text = d > 0 ? `${d} d ${hh} h` : hh > 0 ? `${hh} h ${m} min` : m > 0 ? `${m} min ${s} s` : `${s} s`;
  return { sec, past, text };
}

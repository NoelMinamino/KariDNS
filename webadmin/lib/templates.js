// Zone data templates (planning 5): the request body of a template turned into what is stored, the zone text that `karicheck` validates, and the messages of
// karicheck turned back into pointers into the template.  Pure functions.  Turning a template into the RRsets of a zone is changes.js (templateRRsets).
//
// A template is a name, a description, SOA defaults for a zone made from it, and a list of records whose owners are relative to the zone: '@' is the apex, 'www' is
// www.<zone>.  The RDATA is in the presentation format of the zone parser; a name in it that is not absolute is relative to the zone it is copied into.  DNSSEC
// records and the SOA are not in a template (the signer's, and the SOA has its own fields).

import { badRequest } from './errors.js';
import { shape } from './validate.js';
import { contentProblem, recordType, hostName } from './changes.js';
import { canonicalOwner } from './names.js';
import { isDnssecType } from './perm.js';

export const MAX_TEMPLATE_RECORDS = 1000;
export const TEMPLATE_NAME = /^[A-Za-z0-9][A-Za-z0-9._+:-]*$/;

const SOA_FIELDS = {
  mname: { type: 'string', min: 1, max: 255 },
  rname: { type: 'string', min: 1, max: 255 },
  refresh: { type: 'int', min: 1, max: 2147483647 },
  retry: { type: 'int', min: 1, max: 2147483647 },
  expire: { type: 'int', min: 1, max: 2147483647 },
  minimum: { type: 'int', min: 0, max: 2147483647 },
};
const RECORD_FIELDS = {
  owner: { type: 'string', required: true, min: 1, max: 253 },
  type: { type: 'string', required: true, min: 1, max: 32, re: /^[A-Za-z][A-Za-z0-9-]*$/, reText: 'a record type name' },
  ttl: { type: 'int', min: 0, max: 2147483647 },
  content: { type: 'string', required: true, min: 1, max: 65535, noControl: true },
};
const FIELDS = (required) => ({
  name: { type: 'string', required, min: 1, max: 255, re: TEMPLATE_NAME, reText: 'letters, digits and . _ + : - (not first)' },
  description: { type: 'string', max: 1024, nullable: true },
  soa: { type: 'object', nullable: true, fields: SOA_FIELDS },
  records: { type: 'array', max: MAX_TEMPLATE_RECORDS, items: { type: 'object', fields: RECORD_FIELDS } },
  dry_run: { type: 'bool' },
});

// One record of a template: the owner relative (no final dot), the type upper case and not SOA or a DNSSEC type, the RDATA safe in a zone file.
function recordOf(r, i, types) {
  const at = `/records/${i}`;
  let owner = r.owner;
  if (owner !== '@') {
    if (owner.endsWith('.')) throw badRequest("the owner is relative to the zone: no final dot ('@' is the apex)", `${at}/owner`);
    try { owner = canonicalOwner(owner); } catch (e) { throw badRequest(e.message, `${at}/owner`); }
  }
  const type = recordType(r.type, types, `${at}/type`);
  if (type === 'SOA') throw badRequest('the SOA of a zone made from a template comes from the soa fields', `${at}/type`);
  if (isDnssecType(type)) throw badRequest('DNSSEC records are the signer\'s: they are not in a template', `${at}/type`);
  const why = contentProblem(r.content);
  if (why) throw badRequest(why, `${at}/content`);
  return { owner, type, ttl: r.ttl ?? null, content: r.content };
}

// The records of one RRset have one TTL (RFC 2181 section 5.2): all given and equal, or none given.
function ttlProblem(records) {
  const seen = new Map();
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const key = `${r.owner} ${r.type}`;
    const first = seen.get(key);
    if (first === undefined) seen.set(key, { ttl: r.ttl });
    else if (first.ttl !== r.ttl) throw badRequest(`the records of ${r.type} ${r.owner} do not all have the same TTL (RFC 2181 section 5.2)`, `/records/${i}/ttl`);
  }
}

// -> { name?, description?, soa?, records?, dryRun }; only what the body has (a PATCH changes only that).  create: name is required.  soa: null clears the defaults.
export function parseTemplate(body, { types, create = false } = {}) {
  const b = shape(body, FIELDS(create));
  const out = { dryRun: b.dry_run === true };
  if (b.name !== undefined) out.name = b.name;
  if (b.description !== undefined) out.description = b.description;
  if (b.soa !== undefined) {
    const s = b.soa;
    out.soa = s === null ? null : {
      mname: s.mname === undefined ? null : hostName(s.mname, '/soa/mname'), rname: s.rname === undefined ? null : hostName(s.rname, '/soa/rname'),
      refresh: s.refresh ?? null, retry: s.retry ?? null, expire: s.expire ?? null, minimum: s.minimum ?? null,
    };
  }
  if (b.records !== undefined) {
    out.records = b.records.map((r, i) => recordOf(r, i, types));
    ttlProblem(out.records);
  } else if (create) {
    out.records = [];
  }
  return out;
}

// The zone text karicheck reads for a template (planning 5.3): the template's records under a name that is never a real zone (RFC 6761: .invalid), with an SOA of
// its own and, when the template has no NS at the apex, a name server outside the zone (so that no glue is asked for).  -> { text, base }: record i is line
// base + 1 + i of the text.
export function templateZoneText(records) {
  const lines = ['$ORIGIN template.invalid.', '$TTL 3600', '@ IN SOA ns.nameserver.invalid. hostmaster.template.invalid. 1 7200 3600 1209600 300'];
  if (!records.some((r) => r.owner === '@' && r.type === 'NS')) lines.push('@ IN NS ns.nameserver.invalid.');
  const base = lines.length;
  for (const r of records) lines.push(`${r.owner} ${r.ttl === null || r.ttl === undefined ? '' : `${r.ttl} `}IN ${r.type} ${r.content}`);
  return { text: `${lines.join('\n')}\n`, base };
}

// The comment of the version a template makes (planning 5.1: the template and its revision are all that is left of the link): "<comment> [template "<name>" (id N,
// revision R)]", the comment cut when the whole would pass the 1024 octets a version keeps.
export function templateComment(tpl, comment) {
  const note = `template "${tpl.name}" (id ${tpl.id}, revision ${tpl.revision})`;
  if (!comment) return note;
  let c = comment;
  while (c.length > 0 && Buffer.byteLength(`${c} [${note}]`) > 1024) c = c.slice(0, -1);
  return c.length > 0 ? `${c} [${note}]` : note;
}

// The messages of `karicheck --json zone` about that text as the API shows them: the ones about the synthetic lines (the first `base`) are dropped, the others point at
// the record they are about (`/records/<i>`); a message without a line is kept.  -> [{ code, severity, text, pointer? }] (errors and warnings)
export function templateMessages(messages, base) {
  const out = [];
  for (const m of messages ?? []) {
    if (m.severity !== 'error' && m.severity !== 'warning') continue;
    const e = { code: String(m.code), severity: m.severity, text: String(m.text) };
    if (Number.isInteger(m.line)) {
      if (m.line <= base) continue;
      e.pointer = `/records/${m.line - base - 1}`;
    }
    out.push(e);
  }
  return out;
}

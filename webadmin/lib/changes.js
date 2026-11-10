// Change sets (planning 2.3, 4.1, 8.1): the request body of PATCH .../rrsets and of zone creation turned into what karidns-zone reads (the change file of
// docs/karidns-zone.md, A-4), and the documents karidns-zone prints turned back into what the API shows.  Pure functions.
//
// Names reach the change file as absolute names made by names.js; a record's text is checked here for the characters that could end its line or hide the rest
// of it (the parser of the change file checks them again: a mistake here is not a hole), but what the record MEANS is karidns-zone's to judge.

import { badRequest, conflict } from './errors.js';
import { shape } from './validate.js';
import { canonicalOwner, inZone, absolute } from './names.js';

export const MAX_RRSETS = 1000;
export const MAX_RECORDS = 1000;
export const ZONE_TEXT_LIMIT = 16 << 20;           // a zone text travels in a JSON string: the body of an import and of a zone made from a text (routes.js)

const CONTENT = { type: 'string', required: true, min: 1, max: 65535, noControl: true };
const TYPE = { type: 'string', required: true, min: 1, max: 32, re: /^[A-Za-z][A-Za-z0-9-]*$/, reText: 'a record type name' };
const COMMENT = { type: 'string', max: 1024 };
const RRSET_FIELDS = {
  name: { type: 'string', required: true, min: 1, max: 255 },
  type: TYPE,
  changetype: { type: 'string', required: true, values: ['REPLACE', 'DELETE'] },
  ttl: { type: 'int', min: 0, max: 2147483647 },
  records: { type: 'array', max: MAX_RECORDS, items: { type: 'object', fields: { content: CONTENT } } },
  expect: { type: 'array', max: MAX_RECORDS, items: { type: 'object', fields: { ttl: { type: 'int', required: true, min: 0, max: 2147483647 }, content: CONTENT } } },
};
export const CHANGE_SPEC = {
  comment: COMMENT,
  dry_run: { type: 'bool' },
  reload: { type: 'bool' },
  rrsets: { type: 'array', required: true, min: 1, max: MAX_RRSETS, items: { type: 'object', fields: RRSET_FIELDS } },
};

// Why the text of a record cannot be written to a change file, or null.  The characters the zone-file syntax gives a meaning outside quotes: ';' (a comment), '(' and
// ')' (a group), '$' first (a directive); an open quote swallows the rest.  Control characters (CR, LF, NUL, TAB too) never.  A backslash takes the next character
// literally, inside quotes or not (the tokenizer of pdns_text_check() in dns_pdns_reader.c, which judges the same text again in karidns-zone: the two must agree, so that
// `\"` does not open a quote here and close nothing there).
export function contentProblem(text) {
  if (/[\0-\x1f\x7f]/.test(text)) return 'control characters are not allowed';
  if (text.startsWith('$')) return "the text must not start with '$' (a directive)";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\') {
      if (i === text.length - 1) return 'the text ends with a backslash';
      i++;
    } else if (c === '"') {
      quoted = !quoted;
    } else if (!quoted) {
      if (c === ';') return "a ';' outside quotes starts a comment";
      if (c === '(' || c === ')') return 'parentheses outside quotes are not allowed';
    }
  }
  return quoted ? 'a quote is not closed' : null;
}

// a record type as the API takes it: upper case; a name karidns-zone knows (types: its --types-list, when we have it) or TYPEnnn
export function recordType(t, types, pointer) {
  const u = t.toUpperCase();
  if (types && !types.has(u) && !/^TYPE\d{1,5}$/.test(u)) throw badRequest(`${u} is not a record type that can be written (karidns-zone --types-list names them)`, pointer);
  return u;
}

function recordText(text, pointer) {
  const why = contentProblem(text);
  if (why) throw badRequest(why, pointer);
  return text;
}

// One RRset of a request; ops 'replace' (ttl, records) or 'delete'.  zone: canonical.
function rrsetOf(r, i, zone, types) {
  const at = `/rrsets/${i}`;
  let name;
  try { name = canonicalOwner(r.name); } catch (e) { throw badRequest(e.message, `${at}/name`); }
  if (!inZone(name, zone)) throw badRequest('the name is not in the zone', `${at}/name`);
  const out = { name, type: recordType(r.type, types, `${at}/type`), op: r.changetype === 'DELETE' ? 'delete' : 'replace', ttl: null, records: [], expect: null };
  if (out.op === 'delete') {
    if (r.ttl !== undefined) throw badRequest('a DELETE has no ttl', `${at}/ttl`);
    if (r.records !== undefined) throw badRequest('a DELETE has no records', `${at}/records`);
  } else {
    if (r.ttl === undefined) throw badRequest('a REPLACE needs a ttl', `${at}/ttl`);
    if (r.records === undefined || r.records.length === 0) throw badRequest('a REPLACE needs at least one record (use DELETE to remove the RRset)', `${at}/records`);
    out.ttl = r.ttl;
    out.records = r.records.map((x, j) => recordText(x.content, `${at}/records/${j}/content`));
  }
  if (r.expect !== undefined) out.expect = r.expect.map((x, j) => ({ ttl: x.ttl, content: recordText(x.content, `${at}/expect/${j}/content`) }));
  return out;
}

// -> { comment, dryRun, reload, rrsets: [{ name, type, op, ttl, records: [text], expect: null | [{ ttl, content }] }] }; reload: true / false / undefined (not said)
export function parseChangeSet(body, zone, { types } = {}) {
  const b = shape(body, CHANGE_SPEC);
  const seen = new Set();
  const rrsets = b.rrsets.map((r, i) => {
    const x = rrsetOf(r, i, zone, types);
    const key = `${x.name} ${x.type}`;
    if (seen.has(key)) throw badRequest('this RRset is named twice in the change set', `/rrsets/${i}`);
    seen.add(key);
    return x;
  });
  return { comment: b.comment, dryRun: b.dry_run === true, reload: b.reload, rrsets };
}

// The change file of the RRsets (docs/karidns-zone.md "The change file"), one line per operation, and the maps from the lines of what karidns-zone reports back to
// the request: `ops[k]` is the pointer data of line k + 1 of the change file, `rr[k]` that of the k-th rr line (line k + 2 of the zone text it makes).  label(i): where
// the i-th RRset comes from in the request: { path, records } (the JSON pointer of the RRset, and the name of its list of records: '' = the path itself is the list)
export const rrsetLabel = (i) => ({ path: `/rrsets/${i}`, records: 'records' });
export function renderChangeFile(rrsets, label = rrsetLabel) {
  const lines = [];
  const ops = [];
  const rr = [];
  rrsets.forEach((r, i) => {
    const l = label(i);
    if (r.op === 'delete') {
      lines.push(`delete ${absolute(r.name)} ${r.type}`);
      ops.push({ ...l });
    } else {
      r.records.forEach((content, j) => {
        lines.push(`rr ${absolute(r.name)} ${r.ttls?.[j] ?? r.ttl} ${r.type} ${content}`);
        ops.push({ ...l, record: j });
        rr.push({ ...l, record: j });
      });
    }
  });
  return { text: `${lines.join('\n')}\n`, ops, rr, label };
}

// The change file of the preconditions (A-5): the RRset as the client expects it, or, with an empty list, its deletion.  Run as a dry run, an RRset that is as
// expected is not in the diff; one that is not, is.  -> { text, index: [the request index of each RRset in it] } or null when no RRset has an expectation
export function renderExpectations(rrsets) {
  const lines = [];
  const index = [];
  rrsets.forEach((r, i) => {
    if (r.expect === null) return;
    index.push(i);
    if (r.expect.length === 0) lines.push(`delete ${absolute(r.name)} ${r.type}`);
    else for (const e of r.expect) lines.push(`rr ${absolute(r.name)} ${e.ttl} ${r.type} ${e.content}`);
  });
  return lines.length ? { text: `${lines.join('\n')}\n`, index } : null;
}

// ---------------------------------------------------------------------------------------------------------------------------------- what karidns-zone says
// "<ttl> <TYPE> <rdata>" (a canonical line of an RRset) -> { ttl, content }
export function parseLine(line) {
  const m = /^(\d+) (\S+) ([\s\S]*)$/.exec(line);
  return m ? { ttl: Number(m[1]), content: m[3] } : { ttl: null, content: line };
}

// The diff of the document `apply` (docs/karidns-zone.md) as the API shows it: names absolute, the records as { ttl, content }
export function showDiff(diff) {
  const side = (lines) => (lines === null || lines === undefined ? null : lines.map(parseLine));
  return diff.map((e) => ({ name: e.owner, type: e.type, change: e.change, before: side(e.before), after: side(e.after) }));
}

// the diff as the permission check sees it (perm.js chooseGrant): name canonical, the TTLs of the records removed and written
export function diffItems(diff) {
  return diff.map((e) => ({
    name: e.owner.replace(/\.$/, '').toLowerCase(),
    type: e.type,
    ttls: [...(e.before ?? []), ...(e.after ?? [])].map((l) => parseLine(l).ttl ?? 0),
  }));
}

const pointerOf = (p) => (p.record === undefined || p.records === undefined ? p.path : p.records === '' ? `${p.path}/${p.record}` : `${p.path}/${p.records}/${p.record}`);

// The messages of a run (severity error or warning) as the errors[] of a problem document or the messages[] of an answer.  maps: { ops, rr } of renderChangeFile;
// without them (a zone text) the line is passed on.  A message about a line of the zone text of the rr lines (line 1 is $ORIGIN) or of the change file points
// into the request.
export function mapMessages(messages, maps) {
  const out = [];
  for (const m of messages ?? []) {
    if (m.severity !== 'error' && m.severity !== 'warning') continue;
    const e = { code: String(m.code), severity: m.severity, text: String(m.text) };
    // the message names its line in its text ("standard input: line 3: ..." for the change file, "standard input:4: ..." for the zone text made from its rr lines)
    const ops = /^standard input: line (\d+): /.exec(e.text);
    const at = /(?:standard input|[^\s:]+):(\d+): /.exec(e.text);
    if (maps) {
      const hit = ops ? maps.ops[Number(ops[1]) - 1] : at ? maps.rr[Number(at[1]) - 2] : undefined;
      if (hit && pointerOf(hit)) e.pointer = pointerOf(hit);
    } else if (at) {
      e.pointer = '/zone_text';
      e.line = Number(at[1]);
    }
    out.push(e);
  }
  return out;
}

// the pointer of the RRset of a diff entry in the request (label: see renderChangeFile), undefined for none (an RRset the request did not name: the SOA of a zone text)
export function entryIndex(rrsets, entry) {
  const name = entry.owner.replace(/\.$/, '').toLowerCase();
  return rrsets.findIndex((r) => r.name === name && r.type === entry.type);
}

export function entryPointer(rrsets, entry, label = rrsetLabel) {
  const i = entryIndex(rrsets, entry);
  return i < 0 ? undefined : label(i).path;
}

// ---------------------------------------------------------------------------------------------------------------------------------- a new zone
const ymd = (d) => `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`;

const HOST = /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$/;
export const hostName = (v, pointer) => {
  if (!HOST.test(v) || v.length > 254) throw badRequest('a host name (letters, digits, - and _, labels separated by dots) is expected', pointer);
  return v.toLowerCase().replace(/\.$/, '');
};

export const CREATE_SPEC = {
  name: { type: 'string', required: true, min: 1, max: 255 },
  type: { type: 'string', values: ['NATIVE', 'MASTER'] },
  soa: {
    type: 'object',
    fields: {
      mname: { type: 'string', min: 1, max: 255 },
      rname: { type: 'string', min: 1, max: 255 },
      serial: { type: 'int', min: 1, max: 4294967295 },
      refresh: { type: 'int', min: 1, max: 2147483647 },
      retry: { type: 'int', min: 1, max: 2147483647 },
      expire: { type: 'int', min: 1, max: 2147483647 },
      minimum: { type: 'int', min: 0, max: 2147483647 },
      ttl: { type: 'int', min: 0, max: 2147483647 },
    },
  },
  nameservers: { type: 'array', min: 1, max: 16, items: { type: 'string', min: 1, max: 255 } },
  ns_ttl: { type: 'int', min: 0, max: 2147483647 },
  rrsets: { type: 'array', max: MAX_RRSETS, items: { type: 'object', fields: RRSET_FIELDS } },
  zone_text: { type: 'string', min: 1, max: 16 << 20, noControl: false },
  template: { type: 'string', min: 1, max: 255 },
  template_id: { type: 'int', min: 1, max: 999999999999999 },
  default_ttl: { type: 'int', min: 0, max: 2147483647 },
  comment: COMMENT,
  dry_run: { type: 'bool' },
  reload: { type: 'bool' },
};

// POST .../zones -> { name, kind, text | rrsets, soa..., comment, dryRun, reload }.  Either a zone text (karidns-zone's parser reads it), or the SOA and the name
// servers (and more RRsets) of the request, which become the rr lines of the whole new zone.  With a template (by name or id: the handler loads it) the SOA values
// and the name servers may come from the template instead.  The serial of a new zone is the day, YYYYMMDD00 (A-17), unless given.
export function parseCreate(body, { types, now = new Date() } = {}) {
  const b = shape(body, CREATE_SPEC);
  const kind = b.type ?? 'NATIVE';
  const common = { kind, comment: b.comment, dryRun: b.dry_run === true, reload: b.reload };
  const usesTemplate = b.template !== undefined || b.template_id !== undefined;
  if (b.template !== undefined && b.template_id !== undefined) throw badRequest('give the template by name or by id, not both', '/template_id');
  if (b.zone_text !== undefined) {
    for (const k of ['soa', 'nameservers', 'rrsets', 'ns_ttl', 'template', 'template_id', 'default_ttl']) if (b[k] !== undefined) throw badRequest('a zone text brings its own SOA, name servers and records', `/${k}`);
    return { ...common, name: b.name, zoneText: b.zone_text };
  }
  if (!usesTemplate) {
    if (b.soa === undefined) throw badRequest('the SOA values (mname, rname) are needed, or a zone_text', '/soa');
    for (const k of ['mname', 'rname']) if (b.soa[k] === undefined) throw badRequest(`the SOA ${k} is needed (or a template that has one)`, `/soa/${k}`);
    if (b.nameservers === undefined) throw badRequest('at least one name server is needed, or a zone_text', '/nameservers');
  }
  return {
    ...common, name: b.name, soa: b.soa, nameservers: b.nameservers, nsTtl: b.ns_ttl, rrsets: b.rrsets, types, today: ymd(now),
    template: b.template, templateId: b.template_id, defaultTtl: b.default_ttl,
  };
}

// why a record of a template (owner relative to the zone, RDATA) cannot be written to a change file, or null
function templateRecordProblem(r) {
  if (r.owner !== '@') {
    if (r.owner.endsWith('.')) return 'the owner has a final dot';
    try { canonicalOwner(r.owner); } catch (e) { return e.message; }
  }
  return contentProblem(r.content);
}

// The RRsets of a template for the zone `zone` (canonical): one RRset per (owner, type), the owner '@' being the apex, the others relative to the zone; a record
// without a TTL gets `defaultTtl`.  RDATA keeps its names as they are: a relative name resolves against the zone when karidns-zone reads it, as in a zone file.
// -> parseChangeSet-shaped RRsets with `first`, the index of the first record of the template in each
export function templateRRsets(tpl, zone, defaultTtl) {
  const groups = new Map();
  tpl.records.forEach((r, i) => {
    // (the template was checked when it was saved, but the database can be written to by others: what is copied into a change file is checked as a request's text)
    const problem = templateRecordProblem(r);
    if (problem) throw conflict(`record ${i} of the template is not fit to be copied (${problem}): validate the template`, 'template-invalid');
    const name = r.owner === '@' ? zone : `${r.owner}.${zone}`;
    const key = `${name} ${r.type}`;
    let g = groups.get(key);
    if (!g) {
      g = { name, type: r.type, op: 'replace', ttl: 0, ttls: [], records: [], expect: null, first: i };
      groups.set(key, g);
    }
    g.records.push(r.content);
    g.ttls.push(r.ttl ?? defaultTtl);
  });
  return [...groups.values()].map((g) => ({ name: g.name, type: g.type, op: 'replace', ttl: Math.min(...g.ttls), records: g.records, expect: null, first: g.first }));
}

// where the RRsets of a template come from: the template, whose record number is `first`
export const templateLabel = (rrsets) => (i) => ({ path: `/template/records/${rrsets[i].first}` });

// the RRsets of the new zone `zone` (canonical) -> { rrsets (as parseChangeSet makes them), serial, label }.  tpl: the template (S.getTemplate), when the request names one: its
// SOA values are the defaults of the request's, its records are in the zone unless the request has an RRset of the same name and type (or name servers: the apex NS)
export function createRRsets(c, zone, tpl) {
  const s = c.soa ?? {};
  const t = tpl?.soa ?? {};
  const mname = s.mname ?? t.mname;
  const rname = s.rname ?? t.rname;
  if (mname === undefined || mname === null) throw badRequest('the SOA mname is needed: in the request or in the template', '/soa/mname');
  if (rname === undefined || rname === null) throw badRequest('the SOA rname is needed: in the request or in the template', '/soa/rname');
  const defaultTtl = c.defaultTtl ?? 3600;
  const ttl = s.ttl ?? defaultTtl;
  const soa = [hostName(mname, '/soa/mname'), hostName(rname, '/soa/rname')].map(absolute).join(' ');
  const serial = s.serial ?? Number(`${c.today}00`);
  const rrsets = [{
    name: zone, type: 'SOA', op: 'replace', ttl, expect: null,
    records: [`${soa} ${serial} ${s.refresh ?? t.refresh ?? 7200} ${s.retry ?? t.retry ?? 3600} ${s.expire ?? t.expire ?? 1209600} ${s.minimum ?? t.minimum ?? 300}`],
  }];
  const labels = [{ path: '/soa' }];
  if (c.nameservers !== undefined) {
    rrsets.push({
      name: zone, type: 'NS', op: 'replace', ttl: c.nsTtl ?? ttl, expect: null,
      records: c.nameservers.map((n, i) => absolute(hostName(n, `/nameservers/${i}`))),
    });
    labels.push({ path: '/nameservers', records: '' });
  }
  const more = (c.rrsets ?? []).map((r, i) => {
    if (r.changetype !== 'REPLACE') throw badRequest('a new zone has nothing to delete', `/rrsets/${i}/changetype`);
    return rrsetOf(r, i, zone, c.types);
  });
  const seen = new Set(rrsets.map((x) => `${x.name} ${x.type}`));
  more.forEach((x, i) => {
    const key = `${x.name} ${x.type}`;
    if (seen.has(key)) throw badRequest('this RRset is made from the SOA and nameservers of the request, or named twice', `/rrsets/${i}`);
    seen.add(key);
  });
  const own = new Set(seen);
  const fromTemplate = tpl ? templateRRsets(tpl, zone, defaultTtl).filter((x) => !own.has(`${x.name} ${x.type}`)) : [];
  const label = templateLabel(fromTemplate);
  fromTemplate.forEach((_, i) => labels.push(label(i)));
  more.forEach((_, i) => labels.push({ path: `/rrsets/${i}`, records: 'records' }));
  return { rrsets: [...rrsets, ...fromTemplate, ...more], serial, label: (i) => labels[i] };
}

// where the RRsets of createRRsets come from in the request (without a template): the SOA and the name servers have their own fields, the others are rrsets[i - 2]
export const createLabel = (i) => (i === 0 ? { path: '/soa' } : i === 1 ? { path: '/nameservers', records: '' } : { path: `/rrsets/${i - 2}`, records: 'records' });

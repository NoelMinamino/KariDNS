// histlib.js: the logic of the history and template screens that needs no DOM (planning 3 S9, S10): the paths, the compare form, the marker "changed outside the versions",
// the conflicts of a rollback, and the text form of a template (planning 5).  Everything here is a hint for the person: the service decides (5.4).

import { zonePath, parseRecordLine } from './zonelib.js';

// ---------------------------------------------------------------------------------------------------------------------------------- versions
export const versionsPath = (ds, zone) => `${zonePath(ds, zone)}/versions`;
export const versionPath = (ds, zone, n) => `${versionsPath(ds, zone)}/${Number(n)}`;
export const isVersionNo = (s) => /^[1-9][0-9]{0,8}$/.test(String(s ?? '').trim());

// the compare form: from (a version number), to (a later number, "current" or empty = the zone as it is) -> { from, to } | { error: 'from' | 'to' | 'order' }
export function parseCompare(from, to) {
  const a = String(from ?? '').trim();
  const b = String(to ?? '').trim().toLowerCase();
  if (!isVersionNo(a)) return { error: 'from' };
  if (b === '' || b === 'current') return { from: Number(a), to: 'current' };
  if (!isVersionNo(b)) return { error: 'to' };
  if (Number(b) <= Number(a)) return { error: 'order' };
  return { from: Number(a), to: Number(b) };
}

// "changed outside the versions" (planning 6.2, docs "Changes outside the versions") as the list gives it -> null (none) or { basis: 'audit' | 'generation', count, rrsets }
export function outsideOf(m) {
  if (m === null || m === undefined || typeof m !== 'object') return null;
  return {
    basis: m.basis === 'audit' ? 'audit' : 'generation',
    count: Number.isInteger(m.count) ? m.count : null,
    rrsets: (Array.isArray(m.rrsets) ? m.rrsets : []).filter((r) => r && typeof r.name === 'string' && typeof r.type === 'string'),
  };
}

// the conflicts of a rollback (the dry run's `conflicts`, or the errors[] of a 409 `version-conflict`) -> [{ name, type, expected: [{ ttl, content }], current: [...] | null }]
export function conflictsOf(list) {
  const lines = (a) => (Array.isArray(a) ? a.filter((x) => x && typeof x.content === 'string') : null);
  return (Array.isArray(list) ? list : []).filter((c) => c && c.code === 'version-conflict' && typeof c.name === 'string' && typeof c.type === 'string')
    .map((c) => ({ name: c.name, type: c.type, expected: lines(c.expected) ?? [], current: lines(c.current) }));
}

// ---------------------------------------------------------------------------------------------------------------------------------- templates
// one record of a template as a line of the text box: "owner [ttl] TYPE content" (the shape of a zone file without $-lines; the owner relative to the zone, "@" the apex)
export const templateLine = (r) => `${r.owner} ${r.ttl === null || r.ttl === undefined ? '' : `${r.ttl} `}${r.type} ${r.content}`;
export const templateText = (records) => (Array.isArray(records) ? records : []).map(templateLine).join('\n');

// the text box -> { records: [{ owner, type, ttl?, content }], lines: [the number (from 1) of the source line of each record], bad: [line numbers that are no record] }
// (blank lines and lines that begin with ";" are nothing; the number of a record in `records` is the pointer /records/<i> the service uses)
export function parseTemplateText(text) {
  const records = [];
  const lines = [];
  const bad = [];
  String(text ?? '').split(/\r?\n/).forEach((raw, i) => {
    const l = raw.trim();
    if (l === '' || l.startsWith(';')) return;
    const r = parseRecordLine(l);
    if (r === null) { bad.push(i + 1); return; }
    const rec = { owner: r.owner, type: r.type, content: r.content };
    if (r.ttl !== undefined) rec.ttl = r.ttl;
    records.push(rec);
    lines.push(i + 1);
  });
  return { records, lines, bad };
}

export const SOA_FIELDS = ['mname', 'rname', 'refresh', 'retry', 'expire', 'minimum'];
const SOA_NUMBERS = new Set(['refresh', 'retry', 'expire', 'minimum']);

// the six SOA fields of the form (strings) -> { soa } (null when every field is empty: no defaults) or { error: the name of the first field that is not a number }
export function soaOf(values) {
  const out = {};
  for (const k of SOA_FIELDS) {
    const v = String(values[k] ?? '').trim();
    if (v === '') continue;
    if (SOA_NUMBERS.has(k)) {
      if (!/^\d{1,10}$/.test(v) || Number(v) > 2147483647) return { error: k };
      out[k] = Number(v);
    } else {
      out[k] = v;
    }
  }
  return { soa: Object.keys(out).length === 0 ? null : out };
}

// the messages of the service about the records of a template carry /records/<i>; the text gets the number of the line of that record in the text box in front
// (label(n) is the words, e.g. "Line 3: ")
export function withLineNumbers(errors, lines, label) {
  return (errors ?? []).map((e) => {
    const m = typeof e.pointer === 'string' ? /^\/records\/(\d{1,4})(\/|$)/.exec(e.pointer) : null;
    const line = m ? lines[Number(m[1])] : undefined;
    return line === undefined ? e : { ...e, text: `${label(line)}${e.text}` };
  });
}

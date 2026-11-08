// The arithmetic of the history of a zone (planning 6): what a version changed, what changed between two versions, what a rollback has to restore, and which
// changes of the audit log are not explained by a version.  Pure functions: the rows of karidns_zone_version_rrsets in, documents out.
//
// A row is { version, owner, type, before, after }: the RRset `owner` / `type` (owner canonical: lower case, no final dot) as canonical lines "<ttl> <TYPE> <rdata>"
// joined by LF before and after the version, null = absent (docs/karidns-zone.md "Versions").  The DNSSEC types are never in a version (the signer's output), and a
// change of the SOA serial alone is not one either (a rollback always raises the serial, CK-8).

import { conflict } from './errors.js';
import { parseLine, contentProblem } from './changes.js';
import { absolute, canonicalOwner } from './names.js';
import { canonType, isDnssecType } from './perm.js';

export const MAX_FOLD_ROWS = 50000;                    // RRset rows a fold reads at most (50 versions of 1000 RRsets); more is refused before it is read
export const OUTSIDE_SHOWN = 10;                       // RRsets named in a "changed outside the versions" marker

const side = (text) => (text === null || text === undefined ? null : text.split('\n').map(parseLine));

// "<ttl> SOA mname rname serial ..." without the serial (and the names compared as the database stores them: lower case, no final dot)
function soaWithoutSerial(line) {
  const w = line.split(' ');
  if (w.length < 9) return line;
  return [w[0], w[1], w[2].toLowerCase().replace(/\.$/, ''), w[3].toLowerCase().replace(/\.$/, ''), ...w.slice(5)].join(' ');
}

// are two states of an RRset the same?  Lines in any order; an SOA without regard to its serial
export function sameState(type, a, b) {
  if (a === null || b === null) return a === b;
  const lines = (t) => t.split('\n');
  const norm = (t) => (type === 'SOA' ? lines(t).map(soaWithoutSerial) : lines(t)).sort().join('\n');
  return norm(a) === norm(b);
}

const byName = (x, y) => (x.owner < y.owner ? -1 : x.owner > y.owner ? 1 : x.type < y.type ? -1 : x.type > y.type ? 1 : 0);

// The rows of consecutive versions (in the order of the versions, then owner, type) folded to one entry per RRset: `first` is the RRset before the first version that
// touched it (its state before the range), `last` after the last one (its state after the range).  -> [{ owner, type, first, last, versions: [numbers] }]
export function fold(rows) {
  const m = new Map();
  for (const r of rows) {
    const key = `${r.owner}\n${r.type}`;
    const e = m.get(key);
    if (e === undefined) m.set(key, { owner: r.owner, type: r.type, first: r.before, last: r.after, versions: [r.version] });
    else {
      e.last = r.after;
      e.versions.push(r.version);
    }
  }
  return [...m.values()].sort(byName);
}

// the entries that differ at the two ends: { owner, type, before, after } (the lines; showEntry makes the document).  An SOA that differs in the serial alone is no
// difference.
export function diffEntries(entries) {
  return entries.filter((e) => !sameState(e.type, e.first, e.last)).map((e) => ({ owner: e.owner, type: e.type, before: e.first, after: e.last }));
}

// one RRset of a version (or the result of a check run) as the API shows it
export function showEntry(owner, type, before, after) {
  return { name: absolute(owner), type, change: before === null ? 'add' : after === null ? 'delete' : 'replace', before: side(before), after: side(after) };
}

// What a rollback has to do: every RRset the versions after the target touched goes back to the state before the first of them.  The RRsets are those of a change set
// (changes.js parseChangeSet: op replace / delete, ttl, ttls, records as RDATA text), with the expectation (A-5) that each is now as the last version left it, unless
// `force`.  The apex SOA is left out: its serial is monotonic and raised by every change, and its other fields are the zone's parameters, changed on purpose (PATCH);
// `skipped` names what was left out.  zone: canonical.
export function rollbackRRsets(entries, zone, { force }) {
  const rrsets = [];
  const skipped = [];
  for (const e of entries) {
    if (e.type === 'SOA' && e.owner === zone) {
      skipped.push({ name: absolute(e.owner), type: 'SOA', reason: 'the SOA record is not restored by a rollback (its serial only grows); change it with a change set' });
      continue;
    }
    const target = side(e.first);
    // what is written back to a change file is what the history holds, so it is checked as a request's text is: a name, a TTL and RDATA that cannot end their line
    try { canonicalOwner(e.owner); } catch { throw conflict(`the history holds an RRset of ${e.type} with a name the API cannot write back`, 'cannot-restore'); }
    const expected = force ? null : (side(e.last) ?? []);
    if ([...(target ?? []), ...(expected ?? [])].some((x) => x.ttl === null || contentProblem(x.content) !== null)) {
      throw conflict(`the history of ${e.type} ${absolute(e.owner)} is not in a form the API can write back`, 'cannot-restore');
    }
    const r = { name: e.owner, type: e.type, op: target === null ? 'delete' : 'replace', ttl: null, ttls: null, records: [], expect: null };
    if (target !== null) {
      r.ttls = target.map((x) => x.ttl);
      r.ttl = Math.min(...r.ttls);
      r.records = target.map((x) => x.content);
    }
    if (expected) r.expect = expected.map((x) => ({ ttl: x.ttl, content: x.content }));
    rrsets.push(r);
  }
  return { rrsets, skipped };
}

// ---------------------------------------------------------------------------------------------------------------------------------- changes outside the versions
// "mname rname serial refresh retry expire minimum" without the serial
const soaContentKey = (c) => {
  const w = String(c ?? '').trim().split(/\s+/);
  return w.length < 7 ? String(c) : [w[0].toLowerCase().replace(/\.$/, ''), w[1].toLowerCase().replace(/\.$/, ''), ...w.slice(3)].join(' ');
};

// The audit rows (store.js auditRecordChanges) that are changes of the zone's RRsets, judged: an update of the SOA that changed the serial alone is not one (the signer
// raises it), nor is a record of a DNSSEC type.  -> { count, rrsets: [{ name, type }] } (the distinct RRsets, the first few)
export function outsideChanges(rows) {
  const seen = new Map();
  let count = 0;
  for (const r of rows) {
    const row = r.after ?? r.before;
    const type = canonType(row?.type);
    if (!row || !type || isDnssecType(type)) continue;
    if (r.op === 'U' && type === 'SOA' && r.before && r.after && soaContentKey(r.before.content) === soaContentKey(r.after.content) && r.before.ttl === r.after.ttl
        && Boolean(r.before.disabled) === Boolean(r.after.disabled)) continue;
    count++;
    const name = String(row.name ?? '').toLowerCase().replace(/\.$/, '');
    const key = `${name}\n${type}`;
    if (!seen.has(key) && seen.size < OUTSIDE_SHOWN) seen.set(key, { name: absolute(name), type });
  }
  return { count, rrsets: [...seen.values()] };
}

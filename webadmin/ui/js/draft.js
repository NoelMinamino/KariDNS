// draft.js: the change set that is being put together (planning 3 S5, F-13).  A draft is a list of entries, one per RRset (name and type): an RRset added, replaced
// or deleted, with the records as they were when the person loaded them (the precondition, G2).  It lives in memory only: no storage of the browser holds zone
// data.  It survives a new sign-in of the same person and is dropped for another one (5.3); a warning is given before the page is left while one exists.

let seq = 0;

// an entry for the RRset `rr` of a page (name, type, ttl, records with rdata) replaced by `ttl` and `records` (strings)
export const replaceEntry = (rr, ttl, records, expect) => ({
  id: `e${++seq}`, op: 'replace', name: rr.name, type: rr.type, ttl, records: [...records], expect, before: expect,
});
// a new RRset: it must not exist yet (`expect` is the empty list)
export const addEntry = (name, type, ttl, records) => ({ id: `e${++seq}`, op: 'add', name, type, ttl, records: [...records], expect: [], before: [] });
export const deleteEntry = (rr, expect) => ({ id: `e${++seq}`, op: 'delete', name: rr.name, type: rr.type, ttl: null, records: [], expect, before: expect });
// the SOA is written with the next serial whatever it holds, so there is no precondition on it (the manual of the API: "the SOA is the exception")
export const soaEntry = (rr, records) => ({
  id: `e${++seq}`, op: 'soa', name: rr.name, type: 'SOA', ttl: rr.ttl, records: [...records], expect: null, before: rr.records.map((r) => ({ ttl: r.ttl ?? rr.ttl ?? 0, content: r.rdata ?? r.content })),
});

export const entryKey = (e) => `${e.name} ${e.type}`;

// the RRset of the request for an entry
export function rrsetOf(e) {
  if (e.op === 'delete') return { name: e.name, type: e.type, changetype: 'DELETE', expect: e.expect };
  const r = { name: e.name, type: e.type, changetype: 'REPLACE', ttl: e.ttl, records: e.records.map((content) => ({ content })) };
  if (e.expect !== null) r.expect = e.expect;
  return r;
}

// one draft: the entries of one zone
function createDraft() {
  let entries = [];
  const listeners = [];
  let revision = 0;
  const changed = () => { revision++; for (const fn of [...listeners]) fn(); };
  return {
    get entries() { return entries; },
    get revision() { return revision; },
    get size() { return entries.length; },
    find: (name, type) => entries.find((e) => e.name === name && e.type === type),
    // an entry replaces the one for the same RRset (the position is kept: the order of the request is the order of the draft)
    put(e) {
      const i = entries.findIndex((x) => x.name === e.name && x.type === e.type);
      if (i >= 0) entries = entries.map((x, j) => (j === i ? e : x)); else entries = [...entries, e];
      changed();
    },
    remove(id) {
      if (!entries.some((e) => e.id === id)) return;
      entries = entries.filter((e) => e.id !== id);
      changed();
    },
    clear() {
      if (entries.length === 0) return;
      entries = [];
      changed();
    },
    // "keep mine": the RRset is as `current` says now ({ ttl, content } records, or null when it is gone); my records stay and the precondition is the present state
    rebase(id, current) {
      const cur = current === null || current === undefined ? [] : current.map((c) => ({ ttl: c.ttl, content: c.content }));
      entries = entries.map((e) => {
        if (e.id !== id) return e;
        const op = e.op === 'add' && cur.length > 0 ? 'replace' : e.op === 'replace' && cur.length === 0 ? 'add' : e.op;
        return { ...e, op, expect: e.op === 'soa' ? null : cur, before: cur };
      });
      changed();
    },
    // -> { body, order }: the request (a change set) and the ids of the entries in the order the service numbers them (pointers /rrsets/N)
    request({ comment, reload, dryRun }) {
      const body = { rrsets: entries.map(rrsetOf) };
      if (typeof comment === 'string' && comment.trim() !== '') body.comment = comment.trim();
      if (reload !== undefined) body.reload = reload === true;
      if (dryRun === true) body.dry_run = true;
      return { body, order: entries.map((e) => e.id) };
    },
    onChange(fn) { listeners.push(fn); },
    offChange(fn) { const i = listeners.indexOf(fn); if (i >= 0) listeners.splice(i, 1); },
  };
}

// the drafts of all zones of this tab
export function createDrafts() {
  const zones = new Map();
  const key = (ds, zone) => `${ds}\n${String(zone).toLowerCase()}`;
  const store = {
    of(ds, zone) {
      const k = key(ds, zone);
      if (!zones.has(k)) zones.set(k, createDraft());
      return zones.get(k);
    },
    count: () => [...zones.values()].reduce((n, d) => n + d.size, 0),
    dirty: () => store.count() > 0,
    clear() { for (const d of zones.values()) d.clear(); },
  };
  return store;
}

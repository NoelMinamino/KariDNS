import { plain } from './format.js';

// pointer.js: where an error of the service belongs on the screen (planning 4.4, 10: one module for every form).  The service points at the cause with a JSON
// pointer (RFC 6901) into the request: "/rrsets/3/records/0", "/soa/mname", "/zone_text".  A form keeps a map from pointers to its fields; the change set draft keeps
// the order of the entries it sent.  What cannot be placed is returned, and the screen shows it as a general message.

// "/rrsets/3/records/0" -> ['rrsets', '3', 'records', '0'] (the escapes ~1 and ~0 undone); null for no pointer, [] for the whole document
export function segments(pointer) {
  if (typeof pointer !== 'string' || !pointer.startsWith('/')) return pointer === '' ? [] : null;
  return pointer.slice(1).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
}

// the entry of a draft an error is about -> { index, record } (record: the number of the record in it, or null) or null when it is about something else
export function entryOf(pointer) {
  const s = segments(pointer);
  if (!s || s[0] !== 'rrsets' || !/^\d{1,4}$/.test(s[1] ?? '')) return null;
  const record = s[2] === 'records' && /^\d{1,4}$/.test(s[3] ?? '') ? Number(s[3]) : null;
  return { index: Number(s[1]), record };
}

// errors[] (or messages[]) of an answer, with the order of the entries that were sent -> { byEntry: Map(id -> [{ ...error, record }]), loose: [error] }
export function placeOnEntries(errors, order) {
  const byEntry = new Map();
  const loose = [];
  for (const e of errors ?? []) {
    const at = entryOf(e.pointer);
    const id = at === null ? undefined : order[at.index];
    if (id === undefined) { loose.push(e); continue; }
    if (!byEntry.has(id)) byEntry.set(id, []);
    byEntry.get(id).push({ ...e, record: at.record });
  }
  return { byEntry, loose };
}

// errors with a map { '/zone_text': field, '/soa/mname': field, ... } of objects that have setError(text): an error goes to the field with the longest pointer that is
// the error's pointer or starts it (on a segment boundary); a field gets all its errors joined; -> the errors no field took
export function placeOnFields(errors, map) {
  const keys = Object.keys(map).sort((a, b) => b.length - a.length);
  const got = new Map();
  const loose = [];
  for (const e of errors ?? []) {
    const p = typeof e.pointer === 'string' ? e.pointer : null;
    const k = p === null ? undefined : keys.find((x) => p === x || p.startsWith(`${x}/`));
    if (k === undefined) { loose.push(e); continue; }
    if (!got.has(k)) got.set(k, []);
    got.get(k).push(plain(e.text));
  }
  for (const [k, texts] of got) map[k].setError(texts.join(' '));
  return loose;
}

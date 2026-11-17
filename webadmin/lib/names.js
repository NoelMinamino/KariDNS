// Names in the API (planning 8.1).  In the API a name is absolute with the final dot ("www.example.test."); in the database (PowerDNS) and in the grants it
// is canonical: lower case, no final dot.  Zone names are the plain LDH names of node/lib/names.js (they reach argv words and file names); an owner name
// may also hold '_' (service labels), '*' (a whole label: a wildcard) and '/' (RFC 2317 reverse zones), 1 to 63 octets a label, 253 in all.  Backslash
// escapes and non-ASCII octets are refused in 0.6.0 (A-labels only).

import { canonicalZone } from '../../node/lib/names.js';

const OWNER_LABEL = /^(?:\*|[a-z0-9_/](?:[a-z0-9_/-]{0,61}[a-z0-9_/])?)$/;

export { canonicalZone };

// -> the canonical owner name (lower case, no final dot) or throws Error
export function canonicalOwner(name) {
  if (typeof name !== 'string') throw new Error('name is not a string');
  let n = name.toLowerCase();
  if (n.endsWith('.')) n = n.slice(0, -1);
  if (n.length === 0) throw new Error('name is empty');
  if (n.length > 253) throw new Error('name is longer than 253 octets');
  for (const label of n.split('.')) {
    if (!OWNER_LABEL.test(label)) throw new Error(`name ${JSON.stringify(name.slice(0, 80))} has a label that is not allowed (letters, digits, '-', '_', '/', a lone '*'; 1 to 63 octets; no empty label)`);
  }
  return n;
}

// the name is the zone or below it, at a label boundary (both canonical)
export const inZone = (name, zone) => name === zone || name.endsWith(`.${zone}`);

// canonical -> absolute, as the API shows it
export const absolute = (name) => (name === '' ? '.' : `${name}.`);

// PowerDNS stores the name without the final dot, but a database may hold it with: the canonical form either way
export const dbName = (name) => (name.endsWith('.') ? name.slice(0, -1) : name).toLowerCase();

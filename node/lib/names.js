// Zone names that may reach a file name or an argv.  The database stores canonical names (lower case, no final dot, db/karidns_ext.pgsql.sql
// karidns_auth.is_canonical_name); the signer accepts a stricter subset: LDH labels plus the underscore, no label longer than 63 octets (RFC 1035
// section 2.3.4), at most 253 octets in all, no label that starts with a hyphen (an argv word must never look like an option).  A name outside this
// set (non-ASCII octets, '*', '/', ...) is refused with a message; IDN zones are stored in their A-label (punycode) form.

const LABEL = '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?';
const NAME_RE = new RegExp(`^${LABEL}(?:[.]${LABEL})*$`);

// Returns the canonical name (lower case, no final dot) or throws an Error that says why not.
export function canonicalZone(name) {
  if (typeof name !== 'string') throw new Error('zone name is not a string');
  let n = name.toLowerCase();
  if (n.endsWith('.')) n = n.slice(0, -1);
  if (n.length === 0) throw new Error('zone name is empty (the root zone is not signed by karidns-signer)');
  if (n.length > 253) throw new Error('zone name is longer than 253 octets');
  if (!NAME_RE.test(n)) throw new Error(`zone name ${JSON.stringify(name.slice(0, 80))} is not a plain LDH name (letters, digits, hyphen, underscore; labels of 1 to 63 octets)`);
  return n;
}

// The zone metadata the API writes (A-19): global masters only, an allowlist of the kinds that settings of a database zone come from ([`karidns(8)`], "Settings of
// database zones"), each value checked by the rules of the loader's reader (dns_pdns_reader.c) so that what the API accepts is not ignored with a warning later.
// Never: PRESIGNED, NSEC3PARAM and X-KARIDNS-SIGNER (the signer's), X-KARIDNS-FORMAT (the importer's), ENABLE-LUA-RECORDS, AXFR-MASTER-TSIG (a secondary's) and the
// other X-KARIDNS-* options.

import net from 'node:net';

export const MAX_ROWS = 64;

// an IPv4 / IPv6 address or a prefix a/n (the reader's acl_addr_ok, then the parser of the server decides)
function addrOrPrefix(s) {
  const parts = s.split('/');
  if (parts.length > 2 || !net.isIP(parts[0])) return false;
  if (parts.length === 1) return true;
  return /^\d{1,3}$/.test(parts[1]) && Number(parts[1]) <= (net.isIPv4(parts[0]) ? 32 : 128);
}

// ALSO-NOTIFY: an address, "a.b.c.d:port" or "[v6]:port"
function notifyEntry(s) {
  if (net.isIP(s)) return true;
  const m = /^(?:\[([0-9a-fA-F:.]+)\]|([0-9.]+)):(\d{1,5})$/.exec(s);
  return Boolean(m) && (m[1] ? net.isIPv6(m[1]) : net.isIPv4(m[2])) && Number(m[3]) >= 1 && Number(m[3]) <= 65535;
}

const keyName = (s) => /^[A-Za-z0-9._-]{1,255}$/.test(s) && !['any', 'none', 'localhost', 'localnets'].includes(s.replace(/\.$/, '').toLowerCase()) && !net.isIP(s);

function ecsList(s) {
  const toks = s.split(/[\s,]+/).filter(Boolean);
  return toks.length > 0 && toks.length <= 1024 && toks.every((t) => addrOrPrefix(t.startsWith('!') ? t.slice(1) : t));
}

// kind -> { check(value) -> bool, what: for the error text, single: at most one row }
export const KINDS = {
  'ALLOW-AXFR-FROM': { check: addrOrPrefix, what: 'an IP address or prefix (a.b.c.d/n)' },
  'ALLOW-DNSUPDATE-FROM': { check: addrOrPrefix, what: 'an IP address or prefix (a.b.c.d/n)' },
  'TSIG-ALLOW-AXFR': { check: keyName, what: 'the name of a TSIG key (letters, digits, . _ -)' },
  'TSIG-ALLOW-DNSUPDATE': { check: keyName, what: 'the name of a TSIG key (letters, digits, . _ -)' },
  'ALSO-NOTIFY': { check: notifyEntry, what: 'an address, address:port or [address]:port' },
  'X-KARIDNS-PROFILE': { check: (s) => /^[A-Za-z0-9._-]{1,64}$/.test(s), what: 'a profile name (letters, digits, . _ -, 64 at most)', single: true },
  'X-KARIDNS-ECS-TRUSTED-RESOLVERS': { check: ecsList, what: 'addresses and prefixes separated by commas or blanks, a leading ! excludes' },
};

// the kind of the path, upper case, if it is one the API writes; else null
export function metaKind(text) {
  const k = String(text).toUpperCase();
  return Object.hasOwn(KINDS, k) ? k : null;
}

// -> the problem of the values (a string) or null
export function metaProblem(kind, values) {
  const k = KINDS[kind];
  if (values.length > MAX_ROWS) return `at most ${MAX_ROWS} values`;
  if (k.single && values.length > 1) return `${kind} takes one value`;
  const i = values.findIndex((v) => !k.check(v));
  return i < 0 ? null : `value ${i} is not ${k.what}`;
}

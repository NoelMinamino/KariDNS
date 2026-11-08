// The DS records of a signed zone, from the public keys in its DNSKEY RRset (planning 4 ".../dnssec", 4.9: non-secret values may be computed in the web tier).  The
// API never reads cryptokeys.content; the DNSKEY records are ordinary records of the zone.
//   key tag        RFC 4034 appendix B (not for algorithm 1, RSA/MD5: obsolete)
//   DS             RFC 4034 section 5.1: key tag, algorithm, digest type, digest = H(owner name in canonical wire form | DNSKEY RDATA); RFC 4509 digest type 2
//                  (SHA-256), RFC 6605 digest type 4 (SHA-384); RFC 4034 section 6.2: the owner name in lower case

import crypto from 'node:crypto';

const DIGESTS = { 1: 'sha1', 2: 'sha256', 4: 'sha384' };

// the owner name in wire format (RFC 1035 section 3.1), lower case; the name is a canonical zone name (letters, digits, '-', '_' and dots)
export function wireName(name) {
  const labels = name.replace(/\.$/, '').toLowerCase().split('.').filter(Boolean);
  return Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'latin1')])), Buffer.from([0])]);
}

// RFC 4034 appendix B.1
export function keyTag(rdata) {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) ac += i & 1 ? rdata[i] : rdata[i] << 8;
  ac += (ac >>> 16) & 0xffff;
  return ac & 0xffff;
}

// "256 3 13 <base64>" (the presentation form; the base64 may hold blanks) -> { flags, protocol, algorithm, rdata } or null
export function parseDnskey(content) {
  const m = /^\s*(\d{1,5})\s+(\d{1,3})\s+(\d{1,3})\s+([A-Za-z0-9+/=\s]+?)\s*$/.exec(content ?? '');
  if (!m) return null;
  const [flags, protocol, algorithm] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const b64 = m[4].replace(/\s+/g, '');
  if (flags > 65535 || protocol > 255 || algorithm > 255 || b64.length === 0 || b64.length % 4 === 1) return null;
  const key = Buffer.from(b64, 'base64');
  if (key.length === 0) return null;
  const head = Buffer.alloc(4);
  head.writeUInt16BE(flags, 0);
  head[2] = protocol;
  head[3] = algorithm;
  return { flags, protocol, algorithm, rdata: Buffer.concat([head, key]) };
}

// the DS digest of a key: uppercase hex
export function dsDigest(zone, rdata, digestType) {
  const h = DIGESTS[digestType];
  if (!h) throw new Error(`no such digest type ${digestType}`);
  return crypto.createHash(h).update(wireName(zone)).update(rdata).digest('hex').toUpperCase();
}

// The keys of the DNSKEY RRset with their key tags and, for a key with the SEP bit (RFC 4034 section 2.1.1: a key signing key), the DS records to put in the parent
// zone (digest types 2 and 4).  records: [{ ttl, content }] of the apex.  A record that is not a DNSKEY the parser reads is skipped.
export function dnskeyView(zone, records) {
  const keys = [];
  const ds = [];
  for (const r of records) {
    const k = parseDnskey(r.content);
    if (!k) continue;
    const tag = k.algorithm === 1 ? null : keyTag(k.rdata);
    const sep = (k.flags & 1) === 1;
    keys.push({ flags: k.flags, protocol: k.protocol, algorithm: k.algorithm, key_tag: tag, sep, zone_key: (k.flags & 0x100) !== 0, ttl: r.ttl });
    if (sep && tag !== null) {
      for (const dt of [2, 4]) ds.push({ key_tag: tag, algorithm: k.algorithm, digest_type: dt, digest: dsDigest(zone, k.rdata, dt), text: `${tag} ${k.algorithm} ${dt} ${dsDigest(zone, k.rdata, dt)}` });
    }
  }
  return { keys, ds };
}

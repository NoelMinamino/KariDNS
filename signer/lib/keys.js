// Keys: the ISC `Private-key-format: v1.x` text that cryptokeys.content holds (PowerDNS stores it so) <-> the K<zone>+<alg>+<tag>.private / .key files that
// dnssec-signzone reads (planning 3.5).  The public key is computed from the private text with node:crypto (key arithmetic only: signing stays in
// dnssec-signzone):
//   RSA 8, 10         RFC 3110 section 2: exponent length (1 octet, or 0 and 2 octets), exponent, modulus; no leading zero octets
//   ECDSA 13, 14      RFC 6605 section 4: x | y, each as long as the curve's field (32 / 48 octets), without the 0x04 of the uncompressed point
//   Ed25519 15        RFC 8080 section 3: the 32 octet public key of RFC 8032
//   Ed448 16          RFC 8080 section 3: the 57 octet public key of RFC 8032
// Key tag: RFC 4034 appendix B.  Algorithms 5 and 7 (RSA/SHA-1) are refused: RFC 8624 section 3.1 says MUST NOT sign with them.

import crypto from 'node:crypto';
import { canonicalZone } from '../../node/lib/names.js';

export const ALGORITHMS = new Map([
  [8, { name: 'RSASHA256', kind: 'rsa' }],
  [10, { name: 'RSASHA512', kind: 'rsa' }],
  [13, { name: 'ECDSAP256SHA256', kind: 'ec', curve: 'prime256v1', size: 32 }],
  [14, { name: 'ECDSAP384SHA384', kind: 'ec', curve: 'secp384r1', size: 48 }],
  [15, { name: 'ED25519', kind: 'ed', type: 'ed25519', size: 32, pkcs8: '302e020100300506032b657004220420' }],
  [16, { name: 'ED448', kind: 'ed', type: 'ed448', size: 57, pkcs8: '3047020100300506032b6571043b0439' }],
]);

// the BIND names (dnssec-keygen -a) of the algorithms the signer generates
export function algorithmName(alg) {
  const a = ALGORITHMS.get(alg);
  if (!a) throw new Error(`algorithm ${alg} is not supported (8, 10, 13, 14, 15 and 16 are)`);
  return a.name;
}

// the fields of a private key file that belong to the key itself (everything else, such as the timing lines Created/Publish/Activate, is dropped: the
// columns `active` and `published` of cryptokeys decide what a key does)
const KEY_FIELDS = {
  rsa: ['Modulus', 'PublicExponent', 'PrivateExponent', 'Prime1', 'Prime2', 'Exponent1', 'Exponent2', 'Coefficient'],
  ec: ['PrivateKey'],
  ed: ['PrivateKey'],
};

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

function b64(v, what) {
  if (!B64.test(v) || v.length > 16384 || v.length % 4 !== 0) throw new Error(`${what} is not base64`);
  return Buffer.from(v, 'base64');
}

// text -> { version, algorithm, fields: Map(name -> Buffer) }; throws Error with a message that never contains key material
export function parsePrivate(text) {
  if (typeof text !== 'string' || text.length === 0) throw new Error('the key has no content');
  if (text.length > 65536) throw new Error('the key content is too long');
  const raw = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '') continue;
    const m = /^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*?)[ \t]*$/.exec(line);
    if (!m) throw new Error('the key content is not in the private key file format (Key: value lines)');
    if (!raw.has(m[1])) raw.set(m[1], m[2]);
  }
  const fmt = /^v1\.([0-9]+)$/.exec(raw.get('Private-key-format') ?? '');
  if (!fmt) throw new Error('the key content has no "Private-key-format: v1.x" line');
  const am = /^([0-9]{1,3})(?:[ \t]*\(.*\))?$/.exec(raw.get('Algorithm') ?? '');
  if (!am) throw new Error('the key content has no "Algorithm:" line');
  const algorithm = Number(am[1]);
  const alg = ALGORITHMS.get(algorithm);
  if (!alg) {
    if (algorithm === 5 || algorithm === 7) throw new Error(`algorithm ${algorithm} (RSA/SHA-1) is refused: RFC 8624 says MUST NOT sign with it`);
    throw new Error(`algorithm ${algorithm} is not supported (8, 10, 13, 14, 15 and 16 are)`);
  }
  const fields = new Map();
  for (const f of KEY_FIELDS[alg.kind]) {
    if (!raw.has(f)) throw new Error(`the key content has no "${f}:" line`);
    fields.set(f, b64(raw.get(f), `"${f}:"`));
  }
  return { version: `v1.${fmt[1]}`, algorithm, fields };
}

const stripZeros = (b) => {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
};

// the public key field of the DNSKEY RDATA
export function publicKey(parsed) {
  const alg = ALGORITHMS.get(parsed.algorithm);
  const f = parsed.fields;
  if (alg.kind === 'rsa') {
    const e = stripZeros(f.get('PublicExponent'));
    const n = stripZeros(f.get('Modulus'));
    if (e.length === 0 || e.length > 65535 || n.length < 64) throw new Error('the RSA key is too short');
    const head = e.length <= 255 ? Buffer.from([e.length]) : Buffer.from([0, e.length >> 8, e.length & 0xff]);
    return Buffer.concat([head, e, n]);
  }
  const d = f.get('PrivateKey');
  if (alg.kind === 'ec') {
    const dd = stripZeros(d);
    if (dd.length > alg.size) throw new Error('the ECDSA private key is too long for the curve');
    const priv = Buffer.concat([Buffer.alloc(alg.size - dd.length), dd]);
    const ecdh = crypto.createECDH(alg.curve);
    ecdh.setPrivateKey(priv);
    const point = ecdh.getPublicKey();                     // 0x04 | x | y
    return point.subarray(1);
  }
  if (d.length !== alg.size) throw new Error(`the ${alg.name} private key must be ${alg.size} octets`);
  const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from(alg.pkcs8, 'hex'), d]), format: 'der', type: 'pkcs8' });
  return Buffer.from(crypto.createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url');
}

// RFC 4034 appendix B: the key tag of DNSKEY RDATA (the algorithm is not RSAMD5 here)
export function keyTag(flags, protocol, algorithm, pub) {
  const rdata = Buffer.concat([Buffer.from([flags >> 8, flags & 0xff, protocol, algorithm]), pub]);
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) ac += (i & 1) ? rdata[i] : rdata[i] << 8;
  ac += (ac >>> 16) & 0xffff;
  return ac & 0xffff;
}

// The private key file we write for dnssec-signzone / the text we store in cryptokeys: only the key fields.
export function privateText(parsed) {
  const alg = ALGORITHMS.get(parsed.algorithm);
  const lines = [`Private-key-format: ${parsed.version}`, `Algorithm: ${parsed.algorithm} (${alg.name})`];
  for (const f of KEY_FIELDS[alg.kind]) lines.push(`${f}: ${parsed.fields.get(f).toString('base64')}`);
  return lines.join('\n') + '\n';
}

// A key of a zone from a cryptokeys row: everything the pipeline needs to write the files and to decide what the key does.
//   row: { flags, content }  (flags 256 = ZSK, 257 = KSK / CSK)
export function loadKey(zone, row) {
  const name = canonicalZone(zone);
  if (row.flags !== 256 && row.flags !== 257) throw new Error(`the key has flags ${row.flags}, 256 or 257 is expected`);
  const parsed = parsePrivate(row.content);
  const pub = publicKey(parsed);
  const tag = keyTag(row.flags, 3, parsed.algorithm, pub);
  const base = `K${name}.+${String(parsed.algorithm).padStart(3, '0')}+${String(tag).padStart(5, '0')}`;
  const rdata = `${row.flags} 3 ${parsed.algorithm} ${pub.toString('base64')}`;
  return {
    base,                                   // the file name stem, also the argument for dnssec-signzone
    tag,
    algorithm: parsed.algorithm,
    flags: row.flags,
    dnskey: `${name}. IN DNSKEY ${rdata}\n`,           // the .key file, the line appended to the zone
    private: privateText(parsed),           // the .private file
  };
}

// dnssec-keygen output (a stem K<zone>.+<alg>+<tag>) -> its three numbers; the stem must be for the zone we asked
export function parseKeyStem(stdout, zone) {
  const name = canonicalZone(zone);
  const stem = stdout.trim().split(/\r?\n/).pop() ?? '';
  const m = /^K(.+)\.\+([0-9]{3})\+([0-9]{5})$/.exec(stem);
  if (!m || m[1].toLowerCase() !== name) throw new Error('dnssec-keygen printed an unexpected key name');
  return { stem, algorithm: Number(m[2]), tag: Number(m[3]) };
}

// Key arithmetic against real keys: signer/test/fixtures/keys.json holds the output of dnssec-keygen 9.20 (the .private and .key files) and of PowerDNS 5.1
// (cryptokeys.content, pdnsutil export-zone-dnskey and the key tag pdnsutil shows).  Our public key, key tag and file names must be theirs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ALGORITHMS, algorithmName, parsePrivate, publicKey, keyTag, privateText, loadKey, parseKeyStem } from '../lib/keys.js';

const FX = JSON.parse(fs.readFileSync(new URL('./fixtures/keys.json', import.meta.url), 'utf8'));
// "257 3 13 base64" (the .key file wraps the base64 in groups of 56 characters)
const rdataOf = (line) => {
  const w = line.trim().split(/\s+/).slice(line.includes(' IN ') ? 3 : 2);
  return `${w[0]} ${w[1]} ${w[2]} ${w.slice(3).join('')}`;
};
const keyRR = (text) => rdataOf(text.split('\n').find((l) => / DNSKEY /.test(l) && !l.startsWith(';')));

test('the fixtures cover every algorithm, both flags, and both makers', () => {
  const algs = new Set([...FX.bind, ...FX.powerdns].map((k) => k.algorithm));
  assert.deepEqual([...algs].sort((a, b) => a - b), [8, 10, 13, 14, 15, 16]);
  assert.ok(FX.bind.some((k) => k.flags === 257) && FX.bind.some((k) => k.flags === 256));
  assert.ok(FX.powerdns.some((k) => k.flags === 257) && FX.powerdns.some((k) => k.flags === 256));
  assert.ok(FX.bind.length >= 8 && FX.powerdns.length >= 6);
});

for (const k of FX.bind) {
  test(`dnssec-keygen ${k.file}: key tag, file name and DNSKEY RR are the same`, () => {
    const key = loadKey('example.test', { flags: k.flags, content: k.private });
    assert.equal(key.tag, k.tag);
    assert.equal(key.algorithm, k.algorithm);
    assert.equal(key.base, k.file);
    assert.equal(rdataOf(key.dnskey), keyRR(k.key));
    assert.equal(key.dnskey, `example.test. IN DNSKEY ${keyRR(k.key)}\n`);
  });

  test(`dnssec-keygen ${k.file}: the private file we write has the key fields only and parses to the same key`, () => {
    const key = loadKey('example.test', { flags: k.flags, content: k.private });
    assert.ok(!/Created|Publish|Activate/.test(key.private));
    assert.ok(key.private.startsWith('Private-key-format: v1.3\n'));
    const again = loadKey('example.test', { flags: k.flags, content: key.private });
    assert.equal(again.tag, k.tag);
    assert.equal(again.private, key.private);
    // every field of the original that is key material is in ours
    const keyLines = k.private.split('\n').filter((l) => /^(Modulus|PublicExponent|PrivateExponent|Prime1|Prime2|Exponent1|Exponent2|Coefficient|PrivateKey):/.test(l));
    for (const l of keyLines) assert.ok(key.private.includes(l), l.slice(0, 20));
  });
}

for (const k of FX.powerdns) {
  test(`PowerDNS key ${k.id} (algorithm ${k.algorithm}, flags ${k.flags}): key tag and DNSKEY RR are PowerDNS's`, () => {
    assert.match(k.content, /^Private-key-format: v1\.2\n/);
    const key = loadKey('example.test', { flags: k.flags, content: k.content });
    assert.equal(key.tag, k.tag);
    assert.equal(key.algorithm, k.algorithm);
    assert.equal(rdataOf(key.dnskey), rdataOf(k.dnskey));
    assert.ok(key.private.startsWith('Private-key-format: v1.2\n'));
  });
}

test('algorithm names for dnssec-keygen', () => {
  assert.equal(algorithmName(8), 'RSASHA256');
  assert.equal(algorithmName(10), 'RSASHA512');
  assert.equal(algorithmName(13), 'ECDSAP256SHA256');
  assert.equal(algorithmName(14), 'ECDSAP384SHA384');
  assert.equal(algorithmName(15), 'ED25519');
  assert.equal(algorithmName(16), 'ED448');
  assert.throws(() => algorithmName(7), /not supported/);
  assert.equal(ALGORITHMS.size, 6);
});

test('RFC 4034 appendix B: the key tag sums the RDATA', () => {
  // flags 256, protocol 3, algorithm 13, 4 bytes of key: hand computed
  const pub = Buffer.from([1, 2, 3, 4]);
  const rdata = [1, 0, 3, 13, 1, 2, 3, 4];
  let ac = 0;
  rdata.forEach((b, i) => { ac += (i & 1) ? b : b << 8; });
  ac += (ac >>> 16) & 0xffff;
  assert.equal(keyTag(256, 3, 13, pub), ac & 0xffff);
  // the carry is folded in
  assert.equal(keyTag(0xffff, 0xff, 0xff, Buffer.alloc(40, 0xff)), keyTag(0xffff, 0xff, 0xff, Buffer.alloc(40, 0xff)));
  const big = Buffer.alloc(300, 0xff);
  let s = 0;
  [0xff, 0xff, 0xff, 0xff, ...big].forEach((b, i) => { s += (i & 1) ? b : b << 8; });
  s += (s >>> 16) & 0xffff;
  assert.equal(keyTag(0xffff, 0xff, 0xff, big), s & 0xffff);
});

test('refused: SHA-1 RSA (RFC 8624), unknown algorithms, damaged text', () => {
  assert.throws(() => parsePrivate('Private-key-format: v1.2\nAlgorithm: 5 (RSASHA1)\n'), /RFC 8624/);
  assert.throws(() => parsePrivate('Private-key-format: v1.2\nAlgorithm: 7 (NSEC3RSASHA1)\n'), /RFC 8624/);
  assert.throws(() => parsePrivate('Private-key-format: v1.2\nAlgorithm: 12 (ECCGOST)\n'), /algorithm 12 is not supported/);
  assert.throws(() => parsePrivate(''), /no content/);
  assert.throws(() => parsePrivate(null), /no content/);
  assert.throws(() => parsePrivate('x'.repeat(70000)), /too long/);
  assert.throws(() => parsePrivate('this is not a key\n'), /not in the private key file format/);
  assert.throws(() => parsePrivate('Algorithm: 13 (ECDSAP256SHA256)\nPrivateKey: AAAA\n'), /Private-key-format/);
  assert.throws(() => parsePrivate('Private-key-format: v2.0\nAlgorithm: 13\n'), /Private-key-format/);
  assert.throws(() => parsePrivate('Private-key-format: v1.2\nPrivateKey: AAAA\n'), /no "Algorithm:" line/);
  assert.throws(() => parsePrivate('Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\n'), /no "PrivateKey:" line/);
  assert.throws(() => parsePrivate('Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: not base64!\n'), /not base64/);
  assert.throws(() => parsePrivate('Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: AAA\n'), /not base64/);
  assert.throws(() => parsePrivate('Private-key-format: v1.2\nAlgorithm: 8 (RSASHA256)\nModulus: AAAA\n'), /no "PublicExponent:" line/);
  // the error text never repeats key material
  try {
    parsePrivate('Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: SECRETSECRET!\n');
    assert.fail('should throw');
  } catch (e) {
    assert.ok(!e.message.includes('SECRETSECRET'));
  }
});

test('refused: flags other than 256 and 257, bad zone names, wrong key sizes', () => {
  const ec = FX.bind.find((k) => k.algorithm === 13);
  assert.throws(() => loadKey('example.test', { flags: 0, content: ec.private }), /flags 0/);
  assert.throws(() => loadKey('ex/ample', { flags: 256, content: ec.private }), /zone name/);
  const mk = (alg, name, b64) => parsePrivate(`Private-key-format: v1.2\nAlgorithm: ${alg} (${name})\nPrivateKey: ${b64}\n`);
  assert.throws(() => publicKey(mk(15, 'ED25519', Buffer.alloc(31, 1).toString('base64'))), /must be 32 octets/);
  assert.throws(() => publicKey(mk(16, 'ED448', Buffer.alloc(32, 1).toString('base64'))), /must be 57 octets/);
  assert.throws(() => publicKey(mk(13, 'ECDSAP256SHA256', Buffer.alloc(33, 1).toString('base64'))), /too long/);
  const rsa = (n, e) => parsePrivate(`Private-key-format: v1.2\nAlgorithm: 8 (RSASHA256)\nModulus: ${n.toString('base64')}\nPublicExponent: ${e.toString('base64')}\nPrivateExponent: AAAA\nPrime1: AAAA\nPrime2: AAAA\nExponent1: AAAA\nExponent2: AAAA\nCoefficient: AAAA\n`);
  assert.throws(() => publicKey(rsa(Buffer.alloc(16, 7), Buffer.from([1, 0, 1]))), /too short/);
});

test('RFC 3110: leading zeros are removed, a long exponent has the 3 octet length form', () => {
  const rsa = (n, e) => parsePrivate(`Private-key-format: v1.2\nAlgorithm: 8 (RSASHA256)\nModulus: ${n.toString('base64')}\nPublicExponent: ${e.toString('base64')}\nPrivateExponent: AAAA\nPrime1: AAAA\nPrime2: AAAA\nExponent1: AAAA\nExponent2: AAAA\nCoefficient: AAAA\n`);
  const n = Buffer.alloc(128, 0x55);
  const pub = publicKey(rsa(Buffer.concat([Buffer.from([0, 0]), n]), Buffer.from([0, 1, 0, 1])));
  assert.deepEqual([...pub.subarray(0, 4)], [3, 1, 0, 1]);
  assert.equal(pub.length, 1 + 3 + 128);
  const e = Buffer.alloc(300, 0x03);
  const long = publicKey(rsa(n, e));
  assert.deepEqual([...long.subarray(0, 3)], [0, 1, 44]);
  assert.equal(long.length, 3 + 300 + 128);
});

test('ECDSA: a private scalar written without its leading zeros gives the same key', () => {
  const d31 = Buffer.alloc(31, 0x42);
  const mk = (d) => parsePrivate(`Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: ${d.toString('base64')}\n`);
  assert.deepEqual(publicKey(mk(d31)), publicKey(mk(Buffer.concat([Buffer.from([0]), d31]))));
});

test('privateText keeps the version of the text and drops what is not key material', () => {
  const k = FX.powerdns.find((x) => x.algorithm === 13);
  const t = privateText(parsePrivate(`${k.content}Created: 20260101000000\nActivate: 20260101000000\nSomethingElse: x\n`));
  assert.equal(t, k.content.replace(/\r/g, ''));
});

test('dnssec-keygen output names the key', () => {
  assert.deepEqual(parseKeyStem('Kexample.test.+013+08808\n', 'Example.Test.'), { stem: 'Kexample.test.+013+08808', algorithm: 13, tag: 8808 });
  assert.throws(() => parseKeyStem('Kother.test.+013+08808\n', 'example.test'), /unexpected key name/);
  assert.throws(() => parseKeyStem('hello\n', 'example.test'), /unexpected key name/);
  assert.throws(() => parseKeyStem('', 'example.test'), /unexpected key name/);
});

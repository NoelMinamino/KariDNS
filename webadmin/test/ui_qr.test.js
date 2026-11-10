// qr.js against libqrencode (F-5): webadmin/test/qr_fixtures.json holds the symbols qrencode 4.1.1 draws for 45 texts (every version 1 to 10 at M and L, shortest and
// longest text of each, otpauth:// URIs, non-ASCII), made once by qr_fixtures_gen.mjs.  The module must draw the same modules, with the same mask.  Also the format
// information and version information as ISO/IEC 18004 defines them, the limits, and the SVG.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { FakeDocument } from './fakedom.js';
import * as dom from '../ui/js/dom.js';
import { encode, encodeBest, qrSvg, penalty, MAX_VERSION } from '../ui/js/qr.js';

const fx = JSON.parse(fs.readFileSync(new URL('qr_fixtures.json', import.meta.url), 'utf8'));
const rowsOf = (s) => {
  let bits = '';
  for (const ch of s.hex) bits += parseInt(ch, 16).toString(2).padStart(4, '0');
  return Array.from({ length: s.size }, (_, r) => bits.slice(r * s.size, (r + 1) * s.size));
};
const asRows = (qr) => qr.modules.map((r) => Array.from(r).join(''));

// the mask in the format information of a symbol (first copy), by the placement of ISO/IEC 18004 figure 25
function maskOf(rows) {
  const g = (r, c) => Number(rows[r][c]);
  let bits = 0;
  for (let i = 0; i <= 5; i++) bits |= g(i, 8) << i;
  bits |= (g(7, 8) << 6) | (g(8, 8) << 7) | (g(8, 7) << 8);
  for (let i = 9; i < 15; i++) bits |= g(8, 14 - i) << i;
  return ((bits ^ 0x5412) >>> 10) & 7;
}

test('the fixtures are what they say: 45 symbols, every version at both levels', () => {
  assert.equal(fx.symbols.length, 45);
  assert.match(fx.version, /qrencode/);
  const versions = (lvl) => new Set(fx.symbols.filter((s) => s.level === lvl).map((s) => (s.size - 17) / 4));
  assert.deepEqual([...versions('M')].sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.deepEqual([...versions('L')].sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
});

test('the symbols are the same as libqrencode draws: the data, the error correction, the interleaving, the patterns and the mask', () => {
  for (const s of fx.symbols) {
    const qr = encode(s.text, { level: s.level });
    const label = `${s.level} v${(s.size - 17) / 4} ${Buffer.byteLength(s.text)} octets`;
    assert.equal(qr.size, s.size, label);
    assert.equal(qr.version, (s.size - 17) / 4, label);
    assert.deepEqual(asRows(qr), rowsOf(s), label);
    assert.equal(qr.mask, maskOf(rowsOf(s)), `${label}: the mask libqrencode chose`);
  }
});

test('every one of the eight masks can be forced: the function patterns do not change, the data modules do', () => {
  const s = fx.symbols.find((x) => x.level === 'M' && x.size === 45);
  const base = encode(s.text, { level: 'M', mask: 0 });
  for (let m = 1; m < 8; m++) {
    const q = encode(s.text, { level: 'M', mask: m });
    assert.equal(q.mask, m);
    // the timing pattern, the finder pattern and the dark module do not depend on the mask
    assert.equal(Array.from(q.modules[6]).slice(8, 30).join(''), Array.from(base.modules[6]).slice(8, 30).join(''), `timing row, mask ${m}`);
    assert.deepEqual(Array.from(q.modules[0]).slice(0, 7), Array.from(base.modules[0]).slice(0, 7));
    assert.equal(q.modules[q.size - 8][8], 1, 'the dark module');
    assert.notDeepEqual(asRows(q), asRows(base), `mask ${m} differs from mask 0`);
  }
});

test('the version information of version 7 and over is the one of ISO/IEC 18004 annex D (BCH(18,6))', () => {
  const known = { 7: 0x07c94, 8: 0x085bc, 9: 0x09a99, 10: 0x0a4d3 };      // (table D.1)
  for (const [v, bits] of Object.entries(known)) {
    const s = fx.symbols.find((x) => (x.size - 17) / 4 === Number(v));
    const rows = rowsOf(s);
    let got = 0;
    for (let i = 0; i < 18; i++) got |= Number(rows[Math.floor(i / 3)][s.size - 11 + (i % 3)]) << i;
    assert.equal(got, bits, `version ${v}`);
  }
});

test('the limits: 213 octets at M and 271 at L fit version 10, one more does not; M is tried first', () => {
  assert.equal(encode('x'.repeat(213), { level: 'M' }).version, MAX_VERSION);
  assert.throws(() => encode('x'.repeat(214), { level: 'M' }), RangeError);
  assert.equal(encode('x'.repeat(271), { level: 'L' }).version, MAX_VERSION);
  assert.throws(() => encode('x'.repeat(272), { level: 'L' }), RangeError);
  assert.equal(encodeBest('x'.repeat(100)).level, 'M');
  assert.equal(encodeBest('x'.repeat(250)).level, 'L');
  assert.throws(() => encodeBest('x'.repeat(272)), RangeError);
  assert.equal(encodeBest('').version, 1);
  assert.equal(encode('é'.repeat(100), { level: 'M' }).version <= MAX_VERSION, true, 'octets, not characters, are counted');
  assert.throws(() => encode('é'.repeat(110), { level: 'M' }), RangeError);
});

test('the otpauth:// URI of the service for a user name of ordinary length fits at level M', () => {
  const uri = `otpauth://totp/KariDNS:${encodeURIComponent('administrator')}?secret=${'A'.repeat(32)}&issuer=KariDNS&algorithm=SHA1&digits=6&period=30`;
  const qr = encodeBest(uri);
  assert.equal(qr.level, 'M');
  assert.ok(qr.version <= 10);
});

test('penalty counts runs, 2x2 blocks, finder-like patterns and the dark share', () => {
  const blank = Array.from({ length: 21 }, () => new Uint8Array(21));
  // all light: 21 runs of 21 in the rows and the columns (3 + 16 each), 400 blocks of 3, 0% dark (10 for every 5% from 50: 50% away is 100)
  assert.equal(penalty(blank), 42 * 19 + 400 * 3 + 100);
  const q = encode('hello', { level: 'M', mask: 3 });
  assert.ok(penalty(q.modules) > 0);
});

test('qrSvg draws the dark modules as one path in a viewBox with a quiet zone, named for screen readers', () => {
  dom.setDocument(new FakeDocument());
  const qr = encode('hello', { level: 'M' });
  const svg = qrSvg(qr, 'the code');
  assert.equal(svg.getAttribute('role'), 'img');
  assert.equal(svg.getAttribute('aria-label'), 'the code');
  assert.equal(svg.getAttribute('viewBox'), `0 0 ${qr.size + 8} ${qr.size + 8}`);
  const d = svg.children[0].getAttribute('d');
  // the area of the path is the number of dark modules
  let area = 0;
  for (const m of d.matchAll(/M(\d+) (\d+)h(\d+)v1h-\3z/g)) area += Number(m[3]);
  let dark = 0;
  for (const row of qr.modules) for (const v of row) dark += v;
  assert.equal(area, dark);
  assert.equal(d.replace(/M\d+ \d+h\d+v1h-\d+z/g, ''), '', 'nothing but rectangles');
});

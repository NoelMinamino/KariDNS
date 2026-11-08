// qr.js: a QR Code encoder for the TOTP enrolment screen (F-5, planning 5.3): the secret is drawn in the page and never sent to another site, so the encoder is ours.
// ISO/IEC 18004: byte mode, error correction level M (L when the text does not fit), versions 1 to 10 (up to 213 octets at M, 271 at L: the otpauth:// URI of
// KariDNS is about 112 octets plus the user name).  A longer text throws RangeError and the screen shows the key as text only.  The tests compare the symbols with
// the ones libqrencode makes (webadmin/test/qr_fixtures.json, generated once).

import { svg } from './dom.js';

// error correction: [data codewords, EC codewords per block, [[blocks, data codewords per block], ...]] per version 1..10 (ISO/IEC 18004 table 9)
const BLOCKS = {
  M: [[16, 10, [[1, 16]]], [28, 16, [[1, 28]]], [44, 26, [[1, 44]]], [64, 18, [[2, 32]]], [86, 24, [[2, 43]]], [108, 16, [[4, 27]]], [124, 18, [[4, 31]]],
    [154, 22, [[2, 38], [2, 39]]], [182, 22, [[3, 36], [2, 37]]], [216, 26, [[4, 43], [1, 44]]]],
  L: [[19, 7, [[1, 19]]], [34, 10, [[1, 34]]], [55, 15, [[1, 55]]], [80, 20, [[1, 80]]], [108, 26, [[1, 108]]], [136, 18, [[2, 68]]], [156, 20, [[2, 78]]],
    [194, 24, [[2, 97]]], [232, 30, [[2, 116]]], [274, 18, [[2, 68], [2, 69]]]],
};
const FORMAT_BITS = { L: 1, M: 0 };
const ALIGN = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
export const MAX_VERSION = 10;

// ---- GF(256), x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x;
  LOG[x] = i;
  x <<= 1;
  if (x & 0x100) x ^= 0x11d;
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

// the remainder of data(x) * x^n divided by the generator polynomial of degree n
function rsRemainder(data, n) {
  let gen = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gen[j];
      next[j + 1] ^= mul(gen[j], EXP[i]);
    }
    gen = next;
  }
  const rem = new Array(n).fill(0);
  for (const b of data) {
    const f = b ^ rem[0];
    rem.shift();
    rem.push(0);
    for (let i = 0; i < n; i++) rem[i] ^= mul(gen[i + 1], f);
  }
  return rem;
}

// the number of octets of text a version holds (byte mode: 4 bits of mode, 8 or 16 of count)
const capacity = (version, level) => Math.floor((BLOCKS[level][version - 1][0] * 8 - 4 - (version < 10 ? 8 : 16)) / 8);

function dataCodewords(bytes, version, level) {
  const total = BLOCKS[level][version - 1][0];
  const bits = [];
  const put = (value, n) => { for (let i = n - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
  put(0b0100, 4);
  put(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, total * 8 - bits.length));
  while (bits.length % 8) bits.push(0);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let pad = 0xec; out.length < total; pad ^= 0xec ^ 0x11) out.push(pad);
  return out;
}

// the data blocks and their EC blocks, interleaved (ISO/IEC 18004 section 7.6)
function interleave(data, version, level) {
  const [, ecLen, groups] = BLOCKS[level][version - 1];
  const blocks = [];
  let at = 0;
  for (const [count, size] of groups) {
    for (let i = 0; i < count; i++) {
      const d = data.slice(at, at + size);
      at += size;
      blocks.push({ d, ec: rsRemainder(d, ecLen) });
    }
  }
  const out = [];
  const longest = Math.max(...blocks.map((b) => b.d.length));
  for (let i = 0; i < longest; i++) for (const b of blocks) if (i < b.d.length) out.push(b.d[i]);
  for (let i = 0; i < ecLen; i++) for (const b of blocks) out.push(b.ec[i]);
  return out;
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

// ---- the function patterns
function blank(version) {
  const size = 17 + 4 * version;
  const m = Array.from({ length: size }, () => new Uint8Array(size));
  const fn = Array.from({ length: size }, () => new Uint8Array(size));
  const set = (r, c, dark) => { m[r][c] = dark ? 1 : 0; fn[r][c] = 1; };

  for (let i = 0; i < size; i++) {                         // timing
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]]) {         // finders with their separators
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = r0 + dr;
        const c = c0 + dc;
        if (r < 0 || c < 0 || r >= size || c >= size) continue;
        const d = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
        set(r, c, d !== 2 && d !== 4);
      }
    }
  }
  const pos = ALIGN[version - 1];
  for (const r of pos) {
    for (const c of pos) {
      if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue;                // (the three that would sit on a finder)
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
    }
  }
  for (let i = 0; i < 9; i++) { fn[8][i] = 1; fn[i][8] = 1; }              // reserved: the format information
  for (let i = 0; i < 8; i++) { fn[8][size - 1 - i] = 1; fn[size - 1 - i][8] = 1; }
  if (version >= 7) {                                                       // reserved: the version information
    for (let i = 0; i < 6; i++) for (let j = 0; j < 3; j++) { fn[i][size - 11 + j] = 1; fn[size - 11 + j][i] = 1; }
  }
  return { size, m, fn, set };
}

function drawFormat(q, level, mask) {
  const data = (FORMAT_BITS[level] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i) => ((bits >>> i) & 1) === 1;
  const { size, set } = q;
  for (let i = 0; i <= 5; i++) set(i, 8, bit(i));
  set(7, 8, bit(6));
  set(8, 8, bit(7));
  set(8, 7, bit(8));
  for (let i = 9; i < 15; i++) set(8, 14 - i, bit(i));
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, bit(i));
  for (let i = 8; i < 15; i++) set(size - 15 + i, 8, bit(i));
  set(size - 8, 8, true);                                                   // the dark module
}

function drawVersion(q, version) {
  if (version < 7) return;
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  const bits = (version << 12) | rem;
  for (let i = 0; i < 18; i++) {
    const dark = ((bits >>> i) & 1) === 1;
    const a = q.size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    q.set(b, a, dark);
    q.set(a, b, dark);
  }
}

// the codewords as bits in the zigzag of ISO/IEC 18004 section 7.7.3 (the remainder bits stay 0)
function place(q, codewords) {
  const { size, m, fn } = q;
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let v = 0; v < size; v++) {
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        const r = ((right + 1) & 2) === 0 ? size - 1 - v : v;                  // (upward in the pairs 1, 3, ... counted from the right edge)
        if (fn[r][c]) continue;
        m[r][c] = i < codewords.length * 8 ? (codewords[i >>> 3] >>> (7 - (i & 7))) & 1 : 0;
        i++;
      }
    }
  }
}

// The penalty of a masked symbol, ISO/IEC 18004 section 7.8.3.1, counted as libqrencode counts it (so that the mask chosen is the same one): N1 3 + (n - 5) for a
// run of n >= 5 in a row or column; N2 3 for each 2x2 block of one colour; N3 40 for 1:1:3:1:1 (dark, light, dark, light, dark, in any scale) with light of four
// times the unit on one side or the edge of the symbol on that side; N4 10 for every 5% the dark share is away from 50% (rounded to a whole percent first).
export function penalty(m) {
  const size = m.length;
  let score = 0;
  const lines = [];
  for (let r = 0; r < size; r++) lines.push(m[r]);
  for (let c = 0; c < size; c++) lines.push(m.map((row) => row[c]));
  for (const line of lines) {
    // runs alternate light, dark, light, ...; the first is light, of length 0 when the line starts dark
    const runs = [];
    let color = 0;
    let n = 0;
    for (const v of line) {
      if (v === color) { n++; } else { runs.push(n); color = v; n = 1; }
    }
    runs.push(n);
    for (let i = 0; i < runs.length; i++) {
      if (runs[i] >= 5) score += 3 + (runs[i] - 5);
      if (i % 2 === 1 && i >= 3 && i < runs.length - 2 && runs[i] % 3 === 0) {
        const f = runs[i] / 3;
        if (runs[i - 2] === f && runs[i - 1] === f && runs[i + 1] === f && runs[i + 2] === f && (i === 3 || runs[i - 3] >= 4 * f || i + 4 >= runs.length || runs[i + 3] >= 4 * f)) score += 40;
      }
    }
  }
  for (let r = 0; r + 1 < size; r++) for (let c = 0; c + 1 < size; c++) if (m[r][c] === m[r][c + 1] && m[r][c] === m[r + 1][c] && m[r][c] === m[r + 1][c + 1]) score += 3;
  let dark = 0;
  for (const row of m) for (const v of row) dark += v;
  const total = size * size;
  const percent = Math.floor(Math.floor((200 * dark + total) / total) / 2);
  return score + Math.floor(Math.abs(percent - 50) / 5) * 10;
}

// -> { version, level, mask, size, modules: Uint8Array[] (1 = dark) }.  level 'M' or 'L'; mask 0..7 to force one (the tests do), else the one with the lowest penalty.
// RangeError when the text does not fit version 10 at that level.
export function encode(textValue, { level = 'M', mask } = {}) {
  const bytes = new TextEncoder().encode(textValue);
  let version = 1;
  while (version <= MAX_VERSION && bytes.length > capacity(version, level)) version++;
  if (version > MAX_VERSION) throw new RangeError('the text is too long for a QR code of this encoder');
  const codewords = interleave(dataCodewords(bytes, version, level), version, level);
  const base = blank(version);
  place(base, codewords);
  let best = null;
  for (let k = 0; k < 8; k++) {
    if (mask !== undefined && k !== mask) continue;
    const q = { size: base.size, m: base.m.map((row) => Uint8Array.from(row)), fn: base.fn, set: null };
    q.set = (r, c, dark) => { q.m[r][c] = dark ? 1 : 0; };
    for (let r = 0; r < q.size; r++) for (let c = 0; c < q.size; c++) if (!q.fn[r][c] && MASKS[k](r, c)) q.m[r][c] ^= 1;
    drawFormat(q, level, k);
    drawVersion(q, version);
    const score = penalty(q.m);
    if (best === null || score < best.score) best = { score, mask: k, modules: q.m };
  }
  return { version, level, mask: best.mask, size: base.size, modules: best.modules };
}

// M if the text fits, else L; RangeError when it fits neither
export function encodeBest(textValue) {
  try {
    return encode(textValue, { level: 'M' });
  } catch (e) {
    if (!(e instanceof RangeError)) throw e;
    return encode(textValue, { level: 'L' });
  }
}

// the symbol as an <svg> (dark modules as one path, a quiet zone of 4 modules around it; the colours are the stylesheet's); label: for screen readers
export function qrSvg(qr, label) {
  const margin = 4;
  let d = '';
  for (let r = 0; r < qr.size; r++) {
    for (let c = 0; c < qr.size; c++) {
      if (!qr.modules[r][c]) continue;
      let w = 1;
      while (c + w < qr.size && qr.modules[r][c + w]) w++;
      d += `M${c + margin} ${r + margin}h${w}v1h-${w}z`;
      c += w - 1;
    }
  }
  const n = qr.size + 2 * margin;
  return svg('svg', { viewBox: `0 0 ${n} ${n}`, role: 'img', 'aria-label': label, class: 'qr', 'shape-rendering': 'crispEdges' }, svg('path', { d }));
}

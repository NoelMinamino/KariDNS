// qr_fixtures_gen.mjs: makes webadmin/test/qr_fixtures.json, the symbols libqrencode draws for a set of texts, which qr.test.js compares the encoder of the GUI with
// (F-5).  Run once, where `qrencode` (libqrencode 4.x) is installed:   node webadmin/test/qr_fixtures_gen.mjs > webadmin/test/qr_fixtures.json
// Every version from 1 to 10 at levels M and L, the text as short as it can be for that version and as long as it can be (padding, the largest block counts),
// and otpauth:// URIs as the service makes them.  A symbol is stored as hex of its rows (row by row, most significant bit first, 0 padding at the end of the whole).

import { execFileSync } from 'node:child_process';

// octets a version holds in byte mode (ISO/IEC 18004 table 7: 8 bits of count up to version 9, 16 from 10)
const CAP = { M: [14, 26, 42, 62, 84, 106, 122, 152, 180, 213], L: [17, 32, 53, 78, 106, 134, 154, 192, 230, 271] };

// text of n octets: letters, digits and punctuation in an order that does not repeat (and a few non-ASCII characters, kept whole)
let seed = 12345;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; };
const ALPHA = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/?&=._-%@+ ';
function textOf(n) {
  let s = '';
  while (Buffer.byteLength(s) < n) s += ALPHA[rnd() % ALPHA.length];
  return s;
}

const items = [];
for (const level of ['M', 'L']) {
  CAP[level].forEach((cap, i) => {
    const lo = i === 0 ? 1 : CAP[level][i - 1] + 1;
    for (const n of new Set([lo, cap])) items.push({ level, text: textOf(n) });
  });
}
const secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
for (const name of ['admin', 'alice@example.test', 'a-rather-long-user.name+with:many_parts@mail.example.test']) {
  items.push({ level: 'M', text: `otpauth://totp/KariDNS:${encodeURIComponent(name)}?secret=${secret}&issuer=KariDNS&algorithm=SHA1&digits=6&period=30` });
}
items.push({ level: 'M', text: 'Grüße, 日本語' });
items.push({ level: 'L', text: 'x' });

const out = items.map(({ level, text }) => {
  // -8: byte mode only; -m 0: no quiet zone; ASCII: two characters a module ("##" dark)
  const txt = execFileSync('qrencode', ['-t', 'ASCII', '-m', '0', '-8', '-l', level, '-o', '-'], { input: text }).toString('latin1');
  const rows = txt.split('\n').filter((l) => l.length > 0).map((l) => {
    let r = '';
    for (let i = 0; i < l.length; i += 2) r += l[i] === '#' ? '1' : '0';
    return r;
  });
  const size = rows.length;
  if (!rows.every((r) => r.length === size)) throw new Error(`not square for ${JSON.stringify(text)}`);
  const bits = rows.join('').padEnd(Math.ceil((size * size) / 4) * 4, '0');
  let hex = '';
  for (let i = 0; i < bits.length; i += 4) hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  return { level, text, size, hex };
});
console.log(JSON.stringify({ generator: 'qrencode', version: execFileSync('qrencode', ['--version']).toString().split('\n')[0], symbols: out }, null, 1));

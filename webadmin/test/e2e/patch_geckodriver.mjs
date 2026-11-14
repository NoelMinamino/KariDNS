// patch_geckodriver.mjs <in> <out>: makes a COPY of geckodriver that a FreeBSD 15.0 userland can start.
//
// The geckodriver package is built on 15.1, and it asks libc for the version FBSD_1.9 (posix_spawn_file_actions_addchdir, a symbol it uses only when it finds it).  The
// userland of the build host's jail is 15.0, whose libc has no FBSD_1.9: ld-elf.so.1 refuses to start the program.  This changes the one entry of the
// version-needed table that names FBSD_1.9 into FBSD_1.8; the symbol is then looked up under that version, is not found, and, being weak, is null (Rust's std takes
// the fork path).  Nothing else is changed.  Where geckodriver starts as it is (a 15.1 host, the CI VM), this is not needed and run_webadmin_gui_test.sh does not do it.

import fs from 'node:fs';

const [inFile, outFile] = process.argv.slice(2);
if (!inFile || !outFile) { console.error('usage: node patch_geckodriver.mjs <geckodriver> <patched copy>'); process.exit(2); }
const b = Buffer.from(fs.readFileSync(inFile));

const elfHash = (s) => {
  let h = 0;
  for (const c of Buffer.from(s)) {
    h = ((h << 4) + c) >>> 0;
    const g = h & 0xf0000000;
    if (g) h ^= g >>> 24;
    h &= ~g;
    h >>>= 0;
  }
  return h >>> 0;
};

if (b.readUInt32BE(0) !== 0x7f454c46 || b[4] !== 2 || b[5] !== 1) throw new Error('not a 64-bit little-endian ELF file');
const shoff = Number(b.readBigUInt64LE(0x28));
const shentsize = b.readUInt16LE(0x3a);
const shnum = b.readUInt16LE(0x3c);
const sh = (i) => {
  const o = shoff + i * shentsize;
  return { type: b.readUInt32LE(o + 4), offset: Number(b.readBigUInt64LE(o + 0x18)), size: Number(b.readBigUInt64LE(o + 0x20)), link: b.readUInt32LE(o + 0x28) };
};
const SHT_GNU_verneed = 0x6ffffffe;
let verneed = null;
for (let i = 0; i < shnum; i++) if (sh(i).type === SHT_GNU_verneed) verneed = sh(i);
if (!verneed) throw new Error('no version-needed table');
const str = sh(verneed.link);
const name = (off) => { let e = str.offset + off; while (b[e] !== 0) e++; return b.toString('latin1', str.offset + off, e); };

const auxes = [];
for (let o = verneed.offset; ;) {
  const cnt = b.readUInt16LE(o + 2);
  let a = o + b.readUInt32LE(o + 8);
  for (let k = 0; k < cnt; k++) {
    auxes.push({ at: a, name: name(b.readUInt32LE(a + 8)) });
    a += b.readUInt32LE(a + 12);
  }
  const next = b.readUInt32LE(o + 12);
  if (!next) break;
  o += next;
}
const from = auxes.find((x) => x.name === 'FBSD_1.9');
const to = auxes.find((x) => x.name === 'FBSD_1.8');
if (!from) { console.error('nothing to do: the program does not need FBSD_1.9'); fs.copyFileSync(inFile, outFile); process.exit(0); }
if (!to) throw new Error('the program has no FBSD_1.8 entry to take the string from');
b.writeUInt32LE(elfHash('FBSD_1.8'), from.at);
b.writeUInt32LE(b.readUInt32LE(to.at + 8), from.at + 8);
fs.writeFileSync(outFile, b, { mode: 0o755 });
console.log(`${outFile}: FBSD_1.9 -> FBSD_1.8`);

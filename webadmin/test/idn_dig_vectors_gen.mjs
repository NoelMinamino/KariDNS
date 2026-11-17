// idn_dig_vectors_gen.mjs: makes webadmin/test/idn_dig_vectors.json, the name dig +idnin sends for each of a set of names, which idn.test.js compares
// webadmin/lib/idn.js with.  Run once, where dig (BIND 9.20 with libidn2) is installed and a UTF-8 locale exists:
//   node webadmin/test/idn_dig_vectors_gen.mjs > webadmin/test/idn_dig_vectors.json
// dig is asked with +qr towards a port nobody listens on: the name of the query it prints is what it would send.  "dig": null when dig sends the UTF-8 octets
// (it did not convert the name: they show as \DDD escapes).  "display": what dig +idnout shows for an A-label.

import { execFile, spawnSync } from 'node:child_process';
import dgram from 'node:dgram';
import { promisify } from 'node:util';

const NAMES = [
  // mapping (UTS #46): case, width, the dots of UTS #46, compatibility characters, deviation characters (non-transitional: kept)
  '例え.test', '日本語.example', 'ＷＷＷ.例え.ＴＥＳＴ', '例え。test', 'www．例え．test', 'www｡例え.test', 'Ab.例え.test', '例え.test.',
  'straße.example', 'faß.example', 'ẞ.example', 'ΣΑΣ.example', 'ς.example', 'İstanbul.example', 'ﬁ.example', 'ⅷ.example', '①.example', 'ǅ.example', 'ͅ.example',
  'café.example', 'café.example', '⁠a.example', 'a­.example', '〆.test', 'ー.test', '々.test', 'ヴ.test', 'ｶﾞ.test', '㍿.test',
  // labels that are not letters: service labels, wildcards, the last label of digits, an IDN top label
  '_dmarc.例え.test', '*.例え.test', '例.123', '1.例', 'a_b.例え.test',
  // ASCII labels and A-labels inside a Unicode name, and on their own
  'xn--r8jz45g.test', 'XN--R8JZ45G.TEST', 'xn--zz.test', 'xn--a.test', 'xn--zz.例え.test', 'xn--n3h.例え.test', 'a-.例え.test', '-a.例え.test', 'ab--c.例え.test',
  // code points IDNA2008 disallows: dig falls back to the transitional mapping, for the whole name
  '☃.example', '😀.example', '♥.example', 'ᄀ.example', 'ᆨ.example', '܀.example', 'straße.☃.example', 'ß☃.example', 'ς.♥.example', 'ᄀß.example', '☃.a١.example',
  // the hyphens, the bidi rule, the joiners, a leading combining mark, the length: dig sends the octets
  '-例.test', '例-.test', 'ab--例.test', 'aשלום.example', '١٢٣.example', 'a١.example', 'a١.☃.example', 'a‍b.example', 'a‍b.☃.example', '́a.example',
  `例${'l'.repeat(60)}.test`, '⒈.example', '㈱.test', 'a b.test',
  // right to left, the joiners in context, the CONTEXTO code points (not checked on lookup)
  'שלום.example', 'مثال.example', 'مثال١.example', 'क्‍ष.example', 'ソフト・バンク.test', 'a・b.test', 'l·l.example', 'a·b.example', '١۱.example',
  // scripts mixed
  'аpple.example', 'abcテスト.test', 'テスト한국.test',
];

// A-labels to show (dig +idnout): valid ones, ones that do not decode, ones whose U-label breaks a rule of IDNA2008
const SHOWN = ['xn--r8jz45g.test', 'XN--R8JZ45G.test', 'www.xn--r8jz45g.test', 'xn--zz.test', 'xn--a.test', 'xn--ab---3u6f.test', 'xn----lb7a.test', 'xn--n3h.example',
  'xn--strae-oqa.example', 'xn--fa-hia.example', 'xn--9hbcd.example', 'xn--a-bqc.example', 'xn--ab-3n4a.test', 'xn--pple-43d.example', '_dmarc.xn--r8jz45g.test'];

const run = promisify(execFile);
const ENV = { env: { ...process.env, LC_ALL: 'en_US.UTF-8' }, encoding: 'utf8' };
async function question(args) {
  let text = '';
  try { text = (await run('dig', args, ENV)).stdout; } catch (e) { text = String(e.stdout ?? ''); }
  const lines = text.split('\n');
  const at = lines.findIndex((l) => l.startsWith(';; QUESTION SECTION:'));
  if (at < 0) throw new Error(`dig printed no question (${args.join(' ')})`);
  return lines[at + 1].replace(/^;/, '').split(/\s+/)[0];
}

const vectors = [];
for (const name of NAMES) {
  const sent = await question(['+idnin', '+noidnout', '+qr', '+tries=1', '+timeout=1', '-p', '1', '@127.0.0.1', '-q', name, 'A']);
  vectors.push({ name, dig: /\\\d{3}/.test(sent) ? null : sent.replace(/\.$/, name.endsWith('.') ? '.' : '') });
}
// (a responder on the loopback that answers each query with the query itself: dig shows the name of the question section)
const echo = dgram.createSocket('udp4');
echo.on('message', (m, peer) => { const b = Buffer.from(m); b[2] |= 0x80; echo.send(b, peer.port, peer.address); });
await new Promise((resolve) => { echo.bind(0, '127.0.0.1', resolve); });
const display = [];
for (const name of SHOWN) display.push({ name, dig: (await question(['+idnout', '+noidnin', '+tries=1', '+timeout=2', '-p', String(echo.address().port), '@127.0.0.1', '-q', name, 'A'])).replace(/\.$/, '') });
echo.close();
const v = spawnSync('dig', ['-v'], { encoding: 'utf8' });
process.stdout.write(`${JSON.stringify({ dig: `${v.stdout}${v.stderr}`.trim(), vectors, display }, null, 1)}\n`);

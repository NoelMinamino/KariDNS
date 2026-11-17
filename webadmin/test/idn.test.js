// idn.js (0.7): names typed in Unicode -> the A-labels dig +idnin sends, compared with what dig 9.20 sent on the build host (idn_dig_vectors.json, made by
// idn_dig_vectors_gen.mjs), the U-label form compared with what dig +idnout shows, the derived property of RFC 5892 and the warnings.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { toAscii, asciiName, toUnicode, idnaProperty } from '../lib/idn.js';
import { canonicalOwner, canonicalZone, unicodeOf } from '../lib/names.js';

const V = JSON.parse(fs.readFileSync(new URL('./idn_dig_vectors.json', import.meta.url), 'utf8'));
const codes = (name) => toAscii(name).warnings.map((w) => w.code);

test('every name dig converts gets the same octets (up to the case of ASCII letters); every name dig does not is refused or said to be one dig does not convert', () => {
  assert.ok(V.vectors.length >= 80, 'the vectors are there');
  for (const { name, dig } of V.vectors) {
    if (dig !== null) {
      const r = toAscii(name);
      assert.equal(r.dig, true, name);
      assert.equal(r.name.toLowerCase(), dig.toLowerCase(), name);
      continue;
    }
    let r = null;
    try { r = toAscii(name); canonicalOwner(r.name); } catch { continue; }      // no A-label form, or one the database cannot hold: refused
    assert.equal(r.dig, false, name);
    assert.ok(r.warnings.some((w) => w.code === 'idn-not-dig'), name);
  }
});

test('the U-label form is what dig +idnout shows; a label that does not decode back to itself stays an A-label', () => {
  for (const { name, dig } of V.display) {
    // (dig shows xn--a as an empty label: it is no A-label, the page shows it as it is)
    const want = name === 'xn--a.test' ? name : dig;
    assert.equal(toUnicode(name) ?? name, want, name);
  }
  assert.equal(toUnicode('www.example.test.'), undefined);
  assert.equal(toUnicode('xn--zz.test'), undefined);
  assert.equal(toUnicode(42), undefined);
  assert.equal(unicodeOf('www.xn--r8jz45g.test.'), 'www.例え.test.');
});

test('the warnings: each rule, said once a label, and none for a plain name', () => {
  assert.deepEqual(codes('www.example.test'), []);
  assert.deepEqual(codes('例え.test'), []);
  assert.deepEqual(codes('xn--zz.test'), ['idn-bad-alabel']);
  assert.deepEqual(codes('☃.☃.example'), ['idn-disallowed']);
  assert.deepEqual(codes('straße.☃.example'), ['idn-disallowed', 'idn-transitional']);
  assert.deepEqual(codes('ab--例.test'), ['idn-hyphen', 'idn-not-dig']);
  assert.deepEqual(codes('a-.例.test'), ['idn-hyphen', 'idn-not-dig']);
  assert.deepEqual(codes('١٢٣.example'), ['idn-bidi', 'idn-not-dig']);
  assert.deepEqual(codes('a・b.test'), ['idn-contexto']);
  assert.deepEqual(codes('a·b.example'), ['idn-contexto']);
  assert.deepEqual(codes('l·l.example'), []);
  assert.deepEqual(codes('͵α.example'), []);
  assert.deepEqual(codes('͵a.example'), ['idn-contexto', 'idn-mixed-script']);
  assert.deepEqual(codes('א׳.example'), []);
  assert.deepEqual(codes('аpple.example'), ['idn-mixed-script']);
  assert.deepEqual(codes('aᚠ.example'), ['idn-mixed-script']);
  assert.deepEqual(codes('ᚠᚡ.example'), [], 'a script that is not asked about is one script');
  assert.deepEqual(codes('abcテスト漢字.test'), []);
  assert.deepEqual(codes('مثال١.example'), []);
  assert.deepEqual(codes('مثال۱.example'), [], 'the extended Arabic-Indic digits alone');
  assert.deepEqual(codes('a b.例.test').includes('idn-not-dig'), true);
  const w = toAscii('☃.example').warnings[0];
  assert.match(w.message, /^the label "☃" has a code point that IDNA2008 does not allow/);
  assert.throws(() => toAscii(7), /not a string/);
  assert.throws(() => toAscii('a‍b.test'), /no A-label form/);
  assert.throws(() => toAscii('⒈.example'), /no A-label form/);
});

test('asciiName adds the warnings of a name to a list once; canonicalOwner and canonicalZone take Unicode', () => {
  const into = [];
  assert.equal(asciiName('☃.example', into), 'xn--n3h.example');
  asciiName('☃.example', into);
  assert.equal(into.length, 1);
  assert.equal(asciiName('www.example.test'), 'www.example.test');
  const w = [];
  assert.equal(canonicalOwner('ＷＷＷ.例え.ＴＥＳＴ.', w), 'www.xn--r8jz45g.test');
  assert.equal(canonicalZone('例え.test.', w), 'xn--r8jz45g.test');
  assert.deepEqual(w, []);
  assert.throws(() => canonicalZone(5), /not a string/);
  assert.throws(() => canonicalOwner(`例${'l'.repeat(60)}.test`), /not allowed/);
  assert.throws(() => canonicalOwner('㈱.test'), /not allowed/);
});

test('the derived property of RFC 5892 (section 3), rule by rule', () => {
  const p = (c) => idnaProperty(c);
  assert.equal(p(0xdf), 'PVALID', 'F: an exception');
  assert.equal(p(0xb7), 'CONTEXTO');
  assert.equal(p(0x663), 'CONTEXTO');
  assert.equal(p(0x6f3), 'CONTEXTO');
  assert.equal(p(0x640), 'DISALLOWED');
  assert.equal(p(0x378), 'UNASSIGNED', 'J');
  assert.equal(p(0xfdd0), 'DISALLOWED', 'a noncharacter is not unassigned (C)');
  assert.equal(p(0x61), 'PVALID', 'K: LDH');
  assert.equal(p(0x2d), 'PVALID');
  assert.equal(p(0x200d), 'CONTEXTJ', 'H');
  assert.equal(p(0x41), 'DISALLOWED', 'B: unstable');
  assert.equal(p(0x13f8), 'DISALLOWED', 'B: a small Cherokee letter folds to the capital');
  assert.equal(p(0x20), 'DISALLOWED', 'C');
  assert.equal(p(0x20d0), 'DISALLOWED', 'D');
  assert.equal(p(0x1100), 'DISALLOWED', 'I');
  assert.equal(p(0x3042), 'PVALID', 'A');
  assert.equal(p(0x2603), 'DISALLOWED', 'a symbol');
});

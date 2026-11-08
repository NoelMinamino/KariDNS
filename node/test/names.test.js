import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalZone } from '../lib/names.js';

test('canonical names: lower case, one final dot removed', () => {
  assert.equal(canonicalZone('Example.TEST.'), 'example.test');
  assert.equal(canonicalZone('_dmarc.example.test'), '_dmarc.example.test');
  assert.equal(canonicalZone('xn--bcher-kva.example'), 'xn--bcher-kva.example');
  assert.equal(canonicalZone('a'), 'a');
});

test('names that could reach an argv or a path as something else are refused', () => {
  const bad = ['.', '-x.test', 'a/b.test', '../x', 'a b.test', 'a\nb.test', 'ex*mple.test', 'exämple.test', 'a..b', '.a', 'a.-b.test', 'a-.test',
    `${'x'.repeat(64)}.test`, `${'a.'.repeat(130)}test`];
  for (const b of bad) assert.throws(() => canonicalZone(b), Error, JSON.stringify(b));
  assert.throws(() => canonicalZone(42), /not a string/);
  assert.throws(() => canonicalZone(''), /empty/);
  assert.throws(() => canonicalZone(`${'a'.repeat(60)}.`.repeat(5)), /253/);
});

test('a label of 63 octets is fine', () => {
  assert.equal(canonicalZone(`${'a'.repeat(63)}.test`), `${'a'.repeat(63)}.test`);
});

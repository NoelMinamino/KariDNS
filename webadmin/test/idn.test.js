// idn.js (0.7): names in Unicode through `karidns-zone idn` (a scripted tool here; tests/run_karidns_zone_idn_test.sh compares the real one with dig 9.20):
// which names are asked about, one run for all, the warnings, the 400s, a tool without libidn2, a broken tool, and the pre-pass over the fields of a route.

import test from 'node:test';
import assert from 'node:assert/strict';
import { needsIdn, asciiNames, unicodeNames, idnPrepass } from '../lib/idn.js';
import { idnRun, isIdnCall } from './idn_fake.js';

function ctxOf({ unavailable = false, broken = null } = {}) {
  const calls = [];
  const errors = [];
  const app = {
    settings: { 'karidns-zone': '/opt/karidns-zone' },
    log: { error: (l) => errors.push(l) },
    runTool: async (file, argv, opts) => {
      calls.push({ file, argv, input: opts.input });
      assert.ok(isIdnCall({ argv }));
      return broken ?? idnRun(opts.input, { unavailable });
    },
  };
  return { app, id: 'r1', calls, errors, params: {}, query: new URLSearchParams(), body: undefined };
}
const codes = (m, n) => m.get(n).warnings.map((w) => w.code);

test('needsIdn: non-ASCII or an xn-- label, on one line of the input of the tool', () => {
  assert.equal(needsIdn('例え.test'), true);
  assert.equal(needsIdn('www.XN--r8jz45g.test'), true);
  assert.equal(needsIdn('www.example.test'), false);
  assert.equal(needsIdn('axn--b.test'), false);
  assert.equal(needsIdn('例\tえ'), false);
  assert.equal(needsIdn(''), false);
  assert.equal(needsIdn(7), false);
});

test('asciiNames: one run of the tool for every name, the A-labels, the warnings, a name dig does not convert is a 400 at its pointer', async () => {
  const ctx = ctxOf();
  const m = await asciiNames(ctx, ['例え.test', 'www.example.test', '例え.test', '☃.EXAMPLE.test.', 'a・b.test', 'аpple.example.test', 'xn--zz.test', 'xn--r8jz45g.test']);
  assert.equal(ctx.calls.length, 1);
  assert.deepEqual(ctx.calls[0].argv, ['idn', '--json']);
  assert.equal(ctx.calls[0].input, 'a\t例え.test\na\t☃.EXAMPLE.test.\na\ta・b.test\na\tаpple.example.test\na\txn--zz.test\na\txn--r8jz45g.test\n', 'each once, ASCII names only with xn--');
  assert.equal(m.get('例え.test').ascii, 'xn--r8jz45g.test');
  assert.deepEqual(codes(m, '例え.test'), []);
  assert.deepEqual(codes(m, '☃.EXAMPLE.test.'), ['idn-disallowed', 'idn-transitional']);
  assert.deepEqual(codes(m, 'a・b.test'), ['idn-contexto']);
  assert.deepEqual(codes(m, 'аpple.example.test'), ['idn-mixed-script']);
  assert.deepEqual(codes(m, 'xn--zz.test'), ['idn-bad-alabel']);
  assert.deepEqual(codes(m, 'xn--r8jz45g.test'), []);
  assert.equal(m.has('www.example.test'), false);
  assert.match(m.get('☃.EXAMPLE.test.').warnings[0].message, /^"☃\.EXAMPLE\.test\." has a code point that IDNA2008 does not allow/);
  assert.equal((await asciiNames(ctx, ['www.example.test'])).size, 0);
  assert.equal(ctx.calls.length, 1, 'no run for plain names');
  await assert.rejects(asciiNames(ctx, ['-例.test'], () => '/name'), (e) => e.status === 400 && e.errors[0].pointer === '/name' && /dig \+idnin would send \(libidn2: string has forbidden bi-directional/.test(e.errors[0].text ?? e.message));
});

test('the CONTEXTO rules and the scripts: warnings only (dig converts such names)', async () => {
  const cases = [['l·l', []], ['a·b', ['idn-contexto']], ['͵α', []], ['͵a', ['idn-contexto', 'idn-mixed-script']], ['א׳', []], ['a׳', ['idn-contexto', 'idn-mixed-script']],
    ['١۱', ['idn-contexto']], ['۱١', ['idn-contexto']], ['テスト・ガイド', []], ['abcテスト漢字', []], ['ᚠᚡ', []], ['aᚠ', ['idn-mixed-script']]];
  const names = cases.map(([l]) => `${l}.test`);
  const ctx = ctxOf();
  ctx.app.runTool = async (f, argv, opts) => {
    const lines = opts.input.split('\n').filter(Boolean);
    return { code: 0, stdout: JSON.stringify({ idn: lines.map(() => ({ ascii: 'xn--x.test', transitional: false, error: null, reason: null })) }), stderr: '' };
  };
  const m = await asciiNames(ctx, names);
  cases.forEach(([l, want], i) => assert.deepEqual(codes(m, names[i]), want, l));
});

test('unicodeNames: the U-label form of the names with an xn-- label, nothing for the others', async () => {
  const ctx = ctxOf();
  const m = await unicodeNames(ctx, ['xn--r8jz45g.test.', 'www.example.test.', 'xn--zz.example.test.', '例え.test.']);
  assert.deepEqual([...m], [['xn--r8jz45g.test.', '例え.test.']]);
  assert.equal(ctx.calls[0].input, 'u\txn--r8jz45g.test.\nu\txn--zz.example.test.\n');
  assert.equal((await unicodeNames(ctx, ['www.example.test.'])).size, 0);
  assert.equal(ctx.calls.length, 1);
});

test('a karidns-zone without libidn2: Unicode is refused with the reason, A-labels are shown as they are; a broken tool is a 500, logged', async () => {
  const ctx = ctxOf({ unavailable: true });
  await assert.rejects(asciiNames(ctx, ['例え.test'], () => '?name'), (e) => e.status === 400 && /built without libidn2/.test(e.errors[0].text ?? e.message));
  assert.equal((await asciiNames(ctx, ['xn--zz.test'])).size, 0, 'an ASCII name needs no conversion');
  assert.equal((await unicodeNames(ctx, ['xn--r8jz45g.test.'])).size, 0);
  for (const broken of [{ code: 1, stdout: '', stderr: 'boom' }, { code: 0, stdout: '{"idn": []}', stderr: '' }, { spawnError: 'ENOENT' }, { timedOut: true }, { truncated: true, code: 0, stdout: '' }]) {
    const b = ctxOf({ broken });
    await assert.rejects(asciiNames(b, ['例え.test']), (e) => e.status === 500);
    assert.match(b.errors[0], /^r1: karidns-zone idn /);
  }
});

test('idnPrepass: the path, the query and the body fields of a route become A-labels; the warnings once each', async () => {
  const ctx = ctxOf();
  ctx.params = { ds: 'main', zone: '例え.test.' };
  ctx.query = new URLSearchParams({ name: 'ＷＷＷ.例え.test', contains: 'ウェブ', from: 'www' });
  ctx.body = { name: 'ß☃.test', rrsets: [{ name: '☃.EXAMPLE.test.' }, { name: 'www.example.test' }, { name: 7 }, { name: '☃.EXAMPLE.test.' }], records: 'not an array', other: '例え.test' };
  await idnPrepass(ctx, { params: ['zone', 'ds'], query: ['name', 'contains', 'from', 'missing'], body: ['name', 'rrsets.*.name', 'records.*.owner', 'nothing.*.x'] });
  assert.equal(ctx.calls.length, 1);
  assert.deepEqual(ctx.params, { ds: 'main', zone: 'xn--r8jz45g.test.' });
  assert.deepEqual([...ctx.query], [['name', 'www.xn--r8jz45g.test'], ['contains', 'xn--gckc5l'], ['from', 'www']]);
  assert.deepEqual(ctx.body.rrsets.map((r) => r.name), ['xn--n3h.example.test.', 'www.example.test', 7, 'xn--n3h.example.test.']);
  assert.equal(ctx.body.name, 'xn--ss-gsx.test');
  assert.equal(ctx.body.other, '例え.test', 'a field the route does not name is left alone');
  assert.deepEqual(ctx.idnWarnings.map((w) => `${w.code} ${w.label}`), ['idn-disallowed ß☃.test', 'idn-transitional ß☃.test', 'idn-disallowed ☃.EXAMPLE.test.', 'idn-transitional ☃.EXAMPLE.test.']);
  // a name the tool cannot convert: the pointer of its field
  const bad = ctxOf();
  bad.body = { rrsets: [{ name: 'www.example.test' }, { name: '-例.test' }] };
  await assert.rejects(idnPrepass(bad, { body: ['rrsets.*.name'] }), (e) => e.status === 400 && e.errors[0].pointer === '/rrsets/1/name');
  const plain = ctxOf();
  plain.params = { zone: 'xn--r8jz45g.test' };
  await idnPrepass(plain, { params: ['zone'] });
  assert.equal(plain.calls.length, 0, 'an ASCII zone in the path runs no tool');
  assert.deepEqual(plain.idnWarnings, []);
});

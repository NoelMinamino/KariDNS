// idnui.js and dom.outsideLink (0.7): both forms of a name, the warnings in the language of the page, the field that shows what a name becomes (GET /idn), the
// A-labels of a draft, and the link to ldns.jp (on, off; no Referer, no opener; the query encoded).

import test from 'node:test';
import assert from 'node:assert/strict';
import { FakeDocument, FakeEvent, flush } from './fakedom.js';
import * as dom from '../ui/js/dom.js';
import { createI18n } from '../ui/js/i18n.js';
import { field } from '../ui/js/widgets.js';
import { ApiProblem } from '../ui/js/api.js';
import { nameNodes, warningList, looksIdn, idnHint, asciiOf, ldnsLink } from '../ui/js/idnui.js';
import en from '../ui/i18n/en.js';
import ja from '../ui/i18n/ja.js';

dom.setDocument(new FakeDocument());
const { h } = dom;
const text = (n) => (Array.isArray(n) ? n.map(text).join('') : n.textContent);

const IDN = {
  '例え.test': { ascii: 'xn--r8jz45g.test', unicode: '例え.test', warnings: [], dig: true },
  '☃.example.test.': { ascii: 'xn--n3h.example.test.', unicode: '☃.example.test.', warnings: [{ code: 'idn-disallowed', label: '☃', message: 'm' }], dig: true },
};
function makeCtx({ ldns = { url: 'https://ldns.jp/', resolver: 'cloudflare' }, lang = 'en' } = {}) {
  const asked = [];
  const api = {
    async get(path, { query }) {
      asked.push([path, query.name]);
      if (IDN[query.name]) return IDN[query.name];
      throw new ApiProblem({ status: 400, code: 'bad-request', title: 't', detail: 'no A-label form' });
    },
  };
  return { asked, api, i18n: createI18n({ catalogs: { en, ja }, languages: [lang] }), session: { state: { version: { ui: { ldns } } } } };
}

test('nameNodes: the U-labels over the A-labels, or the name alone', () => {
  const both = nameNodes('xn--r8jz45g.test.', '例え.test.');
  assert.equal(both.className, 'idn');
  assert.deepEqual(both.childNodes.map((c) => [c.className, c.textContent]), [['ulabel', '例え.test.'], ['alabel', 'xn--r8jz45g.test.']]);
  assert.equal(text(nameNodes('www.example.test.', undefined)), 'www.example.test.');
  assert.equal(text(nameNodes('a.test.', 'a.test.')), 'a.test.');
  assert.equal(text(nameNodes('a‮b.test.', null)), 'a<U+202E>b.test.', 'hostile text is made visible');
});

test('warningList: each code in the language of the page, an unknown code in the words of the service, nothing for no warnings', () => {
  const ctx = makeCtx({ lang: 'ja' });
  const list = warningList(ctx.i18n.t, [{ code: 'idn-contexto', label: 'a・b' }, { code: 'idn-new', label: 'x', message: 'the label "x" is new' }, null]);
  assert.equal(list.childNodes.length, 3);
  assert.match(list.childNodes[0].textContent, /^ラベル a・b に、IDNA2008 が/);
  assert.equal(list.childNodes[1].textContent, 'the label "x" is new');
  assert.equal(list.childNodes[2].textContent, '');
  assert.equal(warningList(ctx.i18n.t, []), null);
  assert.equal(warningList(ctx.i18n.t, undefined), null);
  for (const code of ['idn-disallowed', 'idn-bad-alabel', 'idn-contexto', 'idn-mixed-script', 'idn-transitional']) {
    assert.ok(!warningList(ctx.i18n.t, [{ code, label: 'L' }]).textContent.includes('idn.'), code);
  }
});

test('idnHint: after the typing stops and when the field is left, the name the service stores and its warnings; an error; nothing for a plain name', async () => {
  const ctx = makeCtx();
  const f = field({ label: 'Name', name: 'name' });
  const hint = idnHint(ctx, f, (s) => (s.trim() === '' ? null : `${s.trim()}.example.test.`));
  assert.ok(f.node.childNodes.includes(hint.node));
  f.input.value = '☃';
  f.input.dispatchEvent(new FakeEvent('input'));
  f.input.dispatchEvent(new FakeEvent('blur'));
  await flush();
  assert.match(hint.node.textContent, /^Stored as xn--n3h\.example\.test\./);
  assert.match(hint.node.textContent, /IDNA2008 does not allow/);
  f.input.value = 'www';
  await hint.check();
  assert.equal(hint.node.textContent, '', 'an ASCII name is not asked about');
  f.input.value = 'a‍b';
  await hint.check();
  assert.equal(hint.node.childNodes[0].className, 'error');
  assert.deepEqual(ctx.asked.map((a) => a[1]), ['☃.example.test.', 'a‍b.example.test.']);
  // the default: the text of the field, trimmed; the timer of the typing
  const g = field({ label: 'Zone', name: 'zone' });
  const hint2 = idnHint(ctx, g);
  g.input.value = ' 例え.test ';
  g.input.dispatchEvent(new FakeEvent('input'));
  await new Promise((r) => { setTimeout(r, 350); });
  await flush();
  assert.match(hint2.node.textContent, /xn--r8jz45g\.test/);
});

test('looksIdn and asciiOf: only a name with non-ASCII code points is asked about', async () => {
  assert.equal(looksIdn('xn--r8jz45g.test'), true);
  assert.equal(looksIdn('例え.test'), true);
  assert.equal(looksIdn('www.example.test'), false);
  assert.equal(looksIdn(null), false);
  const ctx = makeCtx();
  assert.equal(await asciiOf(ctx, 'www.example.test.'), 'www.example.test.');
  assert.equal(await asciiOf(ctx, '☃.example.test.'), 'xn--n3h.example.test.');
  await assert.rejects(asciiOf(ctx, 'a‍b.example.test.'), ApiProblem);
});

test('ldnsLink: the name and type to ldns.jp in a new tab, without Referer or opener; nothing when the service has it off', () => {
  const a = ldnsLink(makeCtx(), 'www.xn--r8jz45g.test.', 'AAAA');
  assert.equal(a.getAttribute('href'), 'https://ldns.jp/?q=www.xn--r8jz45g.test&t=AAAA&c=dig&r=cloudflare&auto=1');
  assert.equal(a.getAttribute('target'), '_blank');
  assert.equal(a.getAttribute('rel'), 'noopener noreferrer');
  assert.match(a.getAttribute('title'), /public resolver cloudflare/);
  assert.equal(a.getAttribute('aria-label'), 'Look up www.xn--r8jz45g.test AAAA on ldns.jp (opens a new tab)');
  assert.equal(ldnsLink(makeCtx(), '.', 'NS').getAttribute('href'), 'https://ldns.jp/?q=.&t=NS&c=dig&r=cloudflare&auto=1');
  assert.equal(ldnsLink(makeCtx({ ldns: null }), 'a.test.', 'A'), null);
  assert.equal(ldnsLink(makeCtx({ ldns: { resolver: 'google' } }), 'a.test.', 'A'), null);
  const odd = dom.outsideLink('https://ldns.jp/', { q: 'a&b=c' }, null, 'x');
  assert.equal(odd.getAttribute('href'), 'https://ldns.jp/?q=a%26b%3Dc');
  for (const base of ['http://ldns.jp/', 'https://ldns.jp/x', 'javascript:alert(1)//', 'https://ldns.jp', 7]) assert.throws(() => dom.outsideLink(base, {}, null), /only an https origin/, String(base));
  assert.equal(h('p', null, ldnsLink(makeCtx(), 'a.test.', 'A')).childNodes[0].textContent, 'ldns.jp');
});

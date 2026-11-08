// The DOM-free parts of the GUI and dom.js on the fake DOM (planning 8.1): dom.js, format.js (hostile text made visible), router.js (hostile names), i18n.js, widgets.js.

import test from 'node:test';
import assert from 'node:assert/strict';
import { FakeDocument, FakeWindow } from './fakedom.js';
import * as dom from '../ui/js/dom.js';
import { segments, plain, render, clip, formatTime, timeNode, duration } from '../ui/js/format.js';
import { parse, href, createRouter } from '../ui/js/router.js';
import { createI18n, LANG_KEY } from '../ui/js/i18n.js';
import { field, checkbox, select, message, busy, confirmButton, problemNodes, problemText, uid } from '../ui/js/widgets.js';
import { ApiProblem } from '../ui/js/api.js';
import en from '../ui/i18n/en.js';
import ja from '../ui/i18n/ja.js';

const doc = new FakeDocument();
dom.setDocument(doc);
const { h } = dom;

// ---------------------------------------------------------------------------------------------------------------------------------- dom.js
test('h makes elements: text is a text node, attributes come from the list, events are listeners, children are flattened', () => {
  let clicked = 0;
  const el = h('button', { class: ['primary', false, 'big'], id: 'b', type: 'button', disabled: true, 'aria-label': 'go', 'data-x': '1', on: { click: () => clicked++ } },
    'a < b & c', 7, null, undefined, false, [h('b', null, 'x'), ['y']]);
  assert.equal(el.tagName, 'BUTTON');
  assert.equal(el.className, 'primary big');
  assert.equal(el.getAttribute('id'), 'b');
  assert.equal(el.disabled, true);
  assert.equal(el.getAttribute('aria-label'), 'go');
  assert.equal(el.getAttribute('data-x'), '1');
  assert.equal(el.textContent, 'a < b & c7xy');
  assert.equal(el.childNodes[0].nodeType, 3, 'text, not markup');
  el.disabled = false;
  el.click();
  assert.equal(clicked, 1);
  const lab = h('label', { for: 'in1' }, 'L');
  assert.equal(lab.htmlFor, 'in1');
  const inp = h('input', { value: 'v', readonly: true, checked: true, hidden: false });
  assert.equal(inp.value, 'v');
  assert.equal(inp.readOnly, true);
  assert.equal(inp.checked, true);
});

test('h refuses an attribute that is not on the list (href, src, style, on*, srcdoc), also with data in the name', () => {
  for (const bad of ['href', 'src', 'style', 'onclick', 'srcdoc', 'formaction', 'data-X', 'aria-1', 'xlink:href']) {
    assert.throws(() => h('a', { [bad]: 'javascript:alert(1)' }), /may not be set/, bad);
  }
  assert.ok(h('p', { title: 't', 'data-ok': 'x' }));
});

test('link accepts hash routes only', () => {
  const a = dom.link('#/zones/main/example.test', { class: 'x' }, 'zone');
  assert.equal(a.getAttribute('href'), '#/zones/main/example.test');
  for (const bad of ['javascript:alert(1)', 'https://example.test/', '/x', '', null, 5]) assert.throws(() => dom.link(bad, null, 'x'), /only hash routes/);
});

test('fileLink accepts the paths of the API only, made of encoded parts, and marks the link as a download', () => {
  const a = dom.fileLink('/api/v1/datasets/main/zones/example.test./export', { class: 'x' }, 'export');
  assert.equal(a.getAttribute('href'), '/api/v1/datasets/main/zones/example.test./export');
  assert.equal(a.getAttribute('download'), '');
  assert.ok(dom.fileLink(`/api/v1/datasets/${encodeURIComponent("a b!*'()")}/zones/x/export`, null, 'x'));
  for (const bad of ['javascript:alert(1)', 'https://example.test/api/v1/x', '/api/v1/', '/api/v1/a b', '/api/v1/a?b=c', '/api/v1/a#b', '//example.test/api/v1/x', '/x', '', null, 5]) assert.throws(() => dom.fileLink(bad, null, 'x'), /only API paths/, String(bad));
});

test('svg makes namespaced elements with a list of attributes; fill and clear replace the children; the document helpers', () => {
  const s = dom.svg('svg', { viewBox: '0 0 3 3', role: 'img', 'aria-label': 'qr' }, dom.svg('path', { d: 'M0 0h1v1h-1z' }));
  assert.equal(s.namespaceURI, 'http://www.w3.org/2000/svg');
  assert.equal(s.children[0].getAttribute('d'), 'M0 0h1v1h-1z');
  assert.throws(() => dom.svg('svg', { onload: 'x' }), /may not be set/);
  assert.equal(dom.svg('g').children.length, 0);
  const box = h('div', null, 'old');
  dom.fill(box, 'new', null, h('i', null, 'i'));
  assert.equal(box.textContent, 'newi');
  dom.clear(box);
  assert.equal(box.childNodes.length, 0);
  assert.equal(dom.text(5).data, '5');
  dom.setTitle('T');
  assert.equal(doc.title, 'T');
  dom.setLang('ja');
  assert.equal(doc.documentElement.lang, 'ja');
  assert.equal(dom.getDocument(), doc);
});

test('openDialog shows a modal and removes it from the page when it is closed', () => {
  const dlg = h('dialog', null, 'x');
  dom.openDialog(dlg);
  assert.equal(dlg.open, true);
  assert.equal(dlg.parentNode, doc.body);
  dlg.close();
  assert.equal(dlg.parentNode, null);
});

// ---------------------------------------------------------------------------------------------------------------------------------- format.js
test('segments: control characters as \\DDD, bidi / zero-width / format / separator characters as <U+XXXX>, the rest as text', () => {
  const s = segments('a\tb‮c​d\u007fe\u0085f gh\ud800i');
  assert.deepEqual(s.map((x) => x.text), ['a', '\\009', 'b', '<U+202E>', 'c', '<U+200B>', 'd', '\\127', 'e', '\\133', 'f', '<U+2028>', 'g', '<U+E000>', 'h', '<U+D800>', 'i']);
  assert.deepEqual(s.map((x) => x.kind).filter((k) => k !== 'text'), ['ctl', 'fmt', 'fmt', 'ctl', 'ctl', 'fmt', 'fmt', 'fmt']);
  assert.deepEqual(segments(null), []);
  assert.deepEqual(segments('plain text, 日本語 and emoji \u{1F600}').map((x) => x.kind), ['text']);
  assert.equal(plain('x‮y'), 'x<U+202E>y');
});

test('render: text nodes and span.marker only; markup in the data stays text', () => {
  const nodes = render('<img src=x onerror=alert(1)>‮"');
  const box = h('p', null, nodes);
  assert.equal(box.textContent, '<img src=x onerror=alert(1)><U+202E>"');
  assert.deepEqual(box.children.map((c) => `${c.tagName}.${c.className}`), ['SPAN.marker fmt']);
  assert.equal(box.children.length, 1, 'no element came from the data');
});

test('clip, formatTime, timeNode, duration', () => {
  assert.equal(clip('abcdef', 3), 'abc…');
  assert.equal(clip('abc', 3), 'abc');
  assert.equal(clip(null, 3), '');
  assert.equal(clip('\u{1F600}\u{1F600}\u{1F600}', 2), '\u{1F600}\u{1F600}…');
  const iso = '2026-11-08T12:34:56.000Z';
  assert.match(formatTime(iso, 'en'), /2026/);
  assert.match(formatTime(iso, 'ja'), /2026/);
  assert.equal(formatTime('not a time', 'en'), 'not a time');
  assert.equal(formatTime(5, 'en'), '5');
  assert.equal(formatTime(iso, 'xx-invalid-locale-tag-'), new Date(iso).toISOString(), 'a locale the browser refuses');
  const t = timeNode(iso, 'en');
  assert.equal(t.tagName, 'TIME');
  assert.equal(t.getAttribute('datetime'), iso);
  assert.equal(t.getAttribute('title'), iso);
  assert.equal(timeNode(5, 'en').getAttribute('datetime'), null);
  assert.equal(duration(125), '2:05');
  assert.equal(duration(9), '0:09');
  assert.equal(duration(-4), '0:00');
});

// ---------------------------------------------------------------------------------------------------------------------------------- router.js
const TABLE = [{ name: 'home', pattern: '/' }, { name: 'zone', pattern: '/zones/:ds/:zone' }, { name: 'zones', pattern: '/zones' }, { name: 'account', pattern: '/account' }];

test('parse: routes, parameters, the query, and everything that is not a route', () => {
  assert.deepEqual(parse('', TABLE), { name: 'home', params: {}, query: {} });
  assert.deepEqual(parse('#/', TABLE), { name: 'home', params: {}, query: {} });
  assert.deepEqual(parse('#/zones/main/example.test?from=www&x=a%26b', TABLE), { name: 'zone', params: { ds: 'main', zone: 'example.test' }, query: { from: 'www', x: 'a&b' } });
  assert.equal(parse('#/zones', TABLE).name, 'zones');
  for (const bad of ['#/nothing', '#/zones/main', '#/zones/main/a/b', '#zones', '#/zones//x', '#/%E0%A4%A', '#/zones/main/%zz']) assert.equal(parse(bad, TABLE).name, 'notfound', bad);
  assert.equal(parse(undefined, TABLE).name, 'home');
});

test('href and parse round trip hostile parts: nothing is left unescaped, nothing is an exception', () => {
  const hostile = ['a/b', 'x?y#z', 'sp ace', '%41', '../..', '<script>', 'café.test', '‮', 'a&b=c', "q'\"", '\\'];
  for (const zone of hostile) {
    const link = href('zone', { ds: 'main', zone }, undefined, TABLE);
    assert.match(link, /^#\/zones\/main\/[A-Za-z0-9%._~!*()'-]+$/, link);
    assert.deepEqual(parse(link, TABLE).params, { ds: 'main', zone }, zone);
  }
  assert.equal(href('zones', {}, { prefix: 'a b', empty: '', none: undefined, nul: null }, TABLE), '#/zones?prefix=a+b');
  assert.equal(href('home', {}, undefined, TABLE), '#/');
  assert.throws(() => href('nope', {}, {}, TABLE), /no route/);
  assert.throws(() => href('zone', { ds: 'x' }, {}, TABLE), /needs zone/);
});

test('createRouter: goes to routes, reports every change, starts with the current one', () => {
  const win = new FakeWindow(new FakeDocument());
  const seen = [];
  const r = createRouter(win, TABLE, (route) => seen.push(route.name));
  r.start();
  assert.deepEqual(seen, ['home']);
  r.go('zone', { ds: 'main', zone: 'a/b' });
  assert.equal(win.location.hash, '#/zones/main/a%2Fb');
  assert.deepEqual(seen, ['home', 'zone']);
  assert.equal(r.current().params.zone, 'a/b');
  r.refresh();
  assert.equal(seen.length, 3);
  assert.equal(r.href('account'), '#/account');
  assert.equal(r.table, TABLE);
  win.location.hash = '#/garbage';
  assert.equal(seen.at(-1), 'notfound');
});

// ---------------------------------------------------------------------------------------------------------------------------------- i18n.js
const store = (init) => ({ m: { ...init }, getItem(k) { return this.m[k] ?? null; }, setItem(k, v) { this.m[k] = v; } });
const mk = (opts = {}) => createI18n({ catalogs: { en, ja }, ...opts });

test('i18n picks the language: the stored one, then navigator.languages by primary subtag, then English', () => {
  assert.equal(mk({ storage: store({ [LANG_KEY]: 'ja' }), languages: ['en-US'] }).lang, 'ja');
  assert.equal(mk({ storage: store({ [LANG_KEY]: 'xx' }), languages: ['ja-JP', 'en'] }).lang, 'ja');
  assert.equal(mk({ storage: store(), languages: ['fr-FR', 'JA'] }).lang, 'ja');
  assert.equal(mk({ storage: store(), languages: ['fr', 'de'] }).lang, 'en');
  assert.equal(mk({}).lang, 'en');
  assert.equal(mk({ storage: { getItem() { throw new Error('refused'); } }, languages: ['ja'] }).lang, 'ja');
});

test('t fills placeholders; parts keeps nodes; an unknown id is the id; a missing id in one language falls back to English', () => {
  const i = mk({});
  assert.equal(i.t('login.wait', { seconds: 5 }), 'Try again in 5 s');
  assert.equal(i.t('login.wait'), 'Try again in {seconds} s');
  assert.equal(i.t('no.such.id'), 'no.such.id');
  const b = h('b', null, 'N');
  const p = i.parts('app.signed-in', { name: b });
  assert.equal(p[0], 'Signed in as ');
  assert.equal(p[1], b);
  const j = createI18n({ catalogs: { en: { a: 'A {x}', only: 'EN only' }, ja: { a: 'ア {x} 。' } }, languages: ['ja'] });
  assert.equal(j.t('a', { x: '<b>' }), 'ア <b> 。', 'filled as text');
  assert.equal(j.t('only'), 'EN only');
  assert.equal(j.has('only'), true);
  assert.equal(j.has('nope'), false);
});

test('setLang changes the messages, keeps the choice, tells the listeners; an unknown language and a refused store are ignored', () => {
  const s = store();
  const i = mk({ storage: s, languages: ['en'] });
  const heard = [];
  i.onChange((l) => heard.push(l));
  i.setLang('ja');
  assert.equal(i.t('app.logout'), en['app.logout'] === ja['app.logout'] ? en['app.logout'] : ja['app.logout']);
  assert.equal(s.m[LANG_KEY], 'ja');
  i.setLang('xx');
  assert.equal(i.lang, 'ja');
  assert.deepEqual(heard, ['ja']);
  assert.deepEqual(i.languages, ['en', 'ja']);
  const bad = mk({ storage: { getItem: () => null, setItem() { throw new Error('refused'); } } });
  bad.setLang('ja');
  assert.equal(bad.lang, 'ja');
});

test('errorText: the message of the code, else the detail of the service, else a general text', () => {
  const i = mk({});
  assert.equal(i.errorText(new ApiProblem({ status: 401, code: 'invalid-credentials' })), en['api.invalid-credentials']);
  assert.equal(i.errorText(new ApiProblem({ status: 418, code: 'teapot', detail: 'I am a teapot' })), 'I am a teapot');
  assert.equal(i.errorText(new ApiProblem({ status: 418, code: 'teapot', detail: 'a‮b\u0007' })), 'a<U+202E>b\\007', 'the detail of the service is text with its odd characters made visible');
  assert.equal(i.errorText(new ApiProblem({ status: 418, code: 'teapot' })), en['err.unknown']);
  i.setLang('ja');
  assert.equal(i.errorText(new ApiProblem({ status: 0, code: 'network' })), ja['api.network']);
});

// ---------------------------------------------------------------------------------------------------------------------------------- widgets.js
test('field: a label for the input, a hint and an error tied by aria-describedby, setError marks the input', () => {
  const f = field({ label: 'Name', name: 'n', required: true, hint: 'a hint', autocomplete: 'username', maxlength: 5 });
  const label = f.node.querySelector('label');
  const input = f.input;
  assert.equal(label.htmlFor, input.getAttribute('id'));
  assert.match(label.textContent, /^Name/);
  assert.equal(input.getAttribute('autocomplete'), 'username');
  const ids = input.getAttribute('aria-describedby').split(' ');
  assert.equal(ids.length, 2);
  for (const id of ids) assert.ok(f.node.querySelector(`#${id}`), id);
  f.setError('bad');
  assert.equal(input.getAttribute('aria-invalid'), 'true');
  assert.equal(f.node.querySelector('p.error').textContent, 'bad');
  assert.equal(f.node.querySelector('p.error').hidden, false);
  f.setError(null);
  assert.equal(input.getAttribute('aria-invalid'), 'false');
  assert.equal(f.node.querySelector('p.error').hidden, true);
  f.focus();
  assert.equal(doc.activeElement, input);
  const t = field({ label: 'Text', kind: 'textarea', rows: 3 });
  assert.equal(t.input.tagName, 'TEXTAREA');
  assert.equal(t.input.getAttribute('aria-describedby').split(' ').length, 1);
  assert.notEqual(uid(), uid());
});

test('checkbox, select, message', () => {
  const c = checkbox({ label: 'Yes', checked: true, name: 'c' });
  assert.equal(c.input.checked, true);
  assert.equal(c.node.querySelector('label').htmlFor, c.input.getAttribute('id'));
  const s = select({ label: 'Lang', options: [{ value: 'en', label: 'English' }, { value: 'ja', label: 'JA' }], value: 'ja' });
  assert.equal(s.input.value, 'ja');
  assert.equal(s.input.children.length, 2);
  const m = message('error');
  assert.equal(m.node.getAttribute('role'), 'alert');
  assert.equal(m.node.hidden, true);
  m.set('boom');
  assert.equal(m.node.textContent, 'boom');
  assert.equal(m.node.hidden, false);
  m.setNodes('a ', h('code', null, 'b'));
  assert.equal(m.node.textContent, 'a b');
  m.setNodes();
  assert.equal(m.node.hidden, true);
  assert.equal(message().node.getAttribute('role'), 'status');
});

test('busy runs the work once with the button disabled, and enables it after, also after a failure', async () => {
  const b = h('button', null, 'go');
  let n = 0;
  let release;
  const first = busy(b, () => { n++; return new Promise((r) => { release = r; }); });
  assert.equal(b.disabled, true);
  assert.equal(await busy(b, () => { n++; }), undefined, 'a second click while it runs does nothing');
  release('done');
  assert.equal(await first, 'done');
  assert.equal(b.disabled, false);
  assert.equal(n, 1);
  await assert.rejects(busy(b, () => { throw new Error('x'); }), /x/);
  assert.equal(b.disabled, false);
});

test('confirmButton asks again before it acts', () => {
  let did = 0;
  const w = confirmButton({ label: 'Revoke', confirmLabel: 'Sure?', yes: 'Yes', no: 'No', onConfirm: () => did++ });
  const [first, ask] = w.children;
  const [, yes, no] = [ask.children[0], ask.children[1], ask.children[2]];
  assert.equal(ask.hidden, true);
  first.click();
  assert.equal(first.hidden, true);
  assert.equal(ask.hidden, false);
  assert.equal(did, 0);
  no.click();
  assert.equal(ask.hidden, true);
  assert.equal(first.hidden, false);
  first.click();
  yes.click();
  assert.equal(did, 1);
});

test('problemNodes: the message, the texts of errors[] when the code has none, the request id of a 500', () => {
  const i = mk({});
  const p500 = new ApiProblem({ status: 500, code: 'internal', requestId: 'abc123' });
  assert.equal(problemText(i, p500), `${en['api.internal']} Give this number to the operator: abc123`);
  const unknown = new ApiProblem({ status: 400, code: 'strange', detail: 'd', errors: [{ text: 'bad <b>' }, { text: 'worse' }] });
  assert.equal(problemText(i, unknown), 'd bad <b>; worse');
  const plainErr = new ApiProblem({ status: 401, code: 'invalid-credentials', requestId: 'zz' });
  assert.deepEqual(problemNodes(i, plainErr), [en['api.invalid-credentials']]);
  assert.match(problemText(i, new ApiProblem({ status: 0, code: 'network', requestId: 'q' })), /q$/);
});

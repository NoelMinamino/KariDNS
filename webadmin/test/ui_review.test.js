// The self-review of milestone M6 (planning 5, CLAUDE.md Rule 4): what the review of webadmin/ui found, as tests.
// 1. A name that is "." or ".." (or its %2e spelling) is taken out of an address by the browser, so a request built from it would reach another resource.
// 2. A string that is given to a message is hostile text: its invisible and reordering characters are made visible in every message, flash and aria-label alike.
// 3. The colours of the style sheet: WCAG 2.1 AA contrast (1.4.3 text 4.5:1, 1.4.11 the borders of controls and the focus ring 3:1) in both colour schemes.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FakeDocument } from './fakedom.js';
import * as dom from '../ui/js/dom.js';
import { parse, href } from '../ui/js/router.js';
import { createApi } from '../ui/js/api.js';
import { createI18n } from '../ui/js/i18n.js';
import { ROUTES } from '../ui/js/app.js';
import { reply } from './fakedom.js';
import en from '../ui/i18n/en.js';
import ja from '../ui/i18n/ja.js';

dom.setDocument(new FakeDocument());

// ---------------------------------------------------------------------------------------------------------------------------------- dot parts
test('a route part that is "." or ".." is not found, in every spelling; other parts with dots are fine', () => {
  for (const bad of ['#/zones/main/..', '#/zones/main/.', '#/zones/main/%2e%2e', '#/zones/main/%2E', '#/zones/%2e%2E/example.test', '#/zones/main/..%2Freloads', '#/admin/principals/..']) {
    const r = parse(bad, ROUTES);
    // ("..%2Freloads" is one part, "../reloads": not a dot part itself, and "/" in it is encoded again when it is used; it must still never become a request path)
    if (bad.endsWith('..%2Freloads')) { assert.equal(r.name, 'zone'); continue; }
    assert.equal(r.name, 'notfound', bad);
  }
  assert.equal(parse('#/zones/main/a..b', ROUTES).params.zone, 'a..b');
  assert.equal(parse('#/zones/main/...', ROUTES).params.zone, '...');
  assert.equal(parse('#/zones/main/example.test', ROUTES).name, 'zone');
  // a link made from such a name leads to "not found", it does not throw (a list of zones shows what the service says)
  assert.equal(parse(href('zone', { ds: 'main', zone: '..' }, undefined, ROUTES), ROUTES).name, 'notfound');
});

test('the API client makes no request for an address with a "." or ".." part; the same part inside a name is fine', async () => {
  const calls = [];
  const api = createApi({ fetch: async (u) => { calls.push(u); return reply(200, { api: 1 }); } });
  for (const p of ['/datasets/main/zones/..', '/datasets/main/zones/../reload', '/datasets/./zones', '/datasets/main/zones/%2e%2e/reload', '/datasets/main/zones/.%2E/x', '/..', '/a/%2E']) {
    await assert.rejects(api.get(p), (e) => e.name === 'ApiProblem' && e.status === 400 && e.code === 'bad-request', p);
    await assert.rejects(api.post(p, {}), (e) => e.code === 'bad-request', p);
  }
  assert.equal(calls.length, 0);
  for (const p of ['/datasets/main/zones/a..b', '/datasets/main/zones/...', '/datasets/main/zones/example.test/rrsets', '/templates/12']) await api.get(p);
  assert.equal(calls.length, 4);
});

test('the link to a file refuses a "." or ".." part as well', () => {
  assert.ok(dom.fileLink('/api/v1/datasets/main/zones/example.test/export', {}, 'x'));
  assert.ok(dom.fileLink('/api/v1/datasets/main/zones/a..b/export', {}, 'x'));
  for (const p of ['/api/v1/datasets/main/zones/../export', '/api/v1/datasets/main/zones/%2e%2e/export', '/api/v1/./x', '/api/v1/x/..']) assert.throws(() => dom.fileLink(p, {}, 'x'), /only API paths/, p);
});

// ---------------------------------------------------------------------------------------------------------------------------------- text in messages
test('a string given to a message is shown with its controls, bidi and zero-width characters made visible; numbers and nodes are not touched', () => {
  const i18n = createI18n({ catalogs: { en: { m: 'user {name} has {n} grants {x}', p: 'plain' } }, fallback: 'en' });
  const node = dom.h('b', null, 'node');
  const parts = i18n.parts('m', { name: 'al‮ice\u0007', n: 3, x: node });
  assert.deepEqual(parts, ['user ', 'al<U+202E>ice\\007', ' has ', 3, ' grants ', node]);
  assert.equal(i18n.t('m', { name: '​x\u0000', n: 1, x: 'ok' }), 'user <U+200B>x\\000 has 1 grants ok');
  // a text that was made visible already is the same text again
  const once = i18n.t('m', { name: 'a‮b', n: 1, x: '' });
  assert.equal(i18n.t('m', { name: once, n: 1, x: '' }).includes('<U+202E>'), true);
  // a name that only looks like a placeholder name of Object.prototype is not found in the parameters
  assert.equal(i18n.t('p', { constructor: 'x' }), 'plain');
  const inherited = createI18n({ catalogs: { en: { q: '{constructor} {toString}' } }, fallback: 'en' });
  assert.equal(inherited.t('q'), '{constructor} {toString}');
});

// ---------------------------------------------------------------------------------------------------------------------------------- contrast
const css = fs.readFileSync(fileURLToPath(new URL('../ui/app.css', import.meta.url)), 'utf8').replace(/\r\n/g, '\n');
const vars = (block) => Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)].map((m) => [m[1], m[2]]));
const light = vars(css.slice(css.indexOf(':root {'), css.indexOf('@media (prefers-color-scheme: dark)')));
const darkStart = css.indexOf('@media (prefers-color-scheme: dark)');
const dark = { ...light, ...vars(css.slice(darkStart, css.indexOf('* { box-sizing')) ) };

const lum = (hex) => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const ratio = (a, b) => { const x = lum(a); const y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };

// foreground / background pairs of the style sheet: [text colour, background, where]
const TEXT = [
  ['text', 'bg', 'body'], ['text', 'panel', 'cards, tables, dialogs'], ['text', 'notice-bg', 'notices, markers, new diff lines'], ['text', 'error-bg', 'old diff lines'],
  ['muted', 'bg', 'footer, hints'], ['muted', 'panel', 'hints, reasons'], ['muted', 'notice-bg', 'hints in notices'], ['muted', 'error-bg', 'hints in errors'],
  ['accent', 'bg', 'links'], ['accent', 'panel', 'links in cards'], ['accent', 'notice-bg', 'links in notices'], ['accent-text', 'accent', 'primary buttons'],
  ['danger', 'bg', 'errors'], ['danger', 'panel', 'errors, danger buttons'], ['danger', 'error-bg', 'error messages'], ['danger', 'notice-bg', 'errors in notices'],
];
// the edges that identify a control or its state (1.4.11), against what is around them
const NON_TEXT = [
  ['focus', 'bg', 'focus ring'], ['focus', 'panel', 'focus ring in cards'], ['focus', 'notice-bg', 'focus ring in notices'], ['focus', 'error-bg', 'focus ring in errors'],
  ['muted', 'bg', 'border of fields'], ['muted', 'panel', 'border of buttons'], ['accent', 'panel', 'selected row, primary button'], ['accent', 'bg', 'selected tab'],
  ['danger', 'panel', 'invalid field, danger button'], ['danger', 'bg', 'invalid field'], ['notice-line', 'panel', 'the frame of a secret'], ['notice-line', 'notice-bg', 'the bar of a notice'],
];

test('the colours of the style sheet were read (both schemes, every name)', () => {
  for (const name of ['bg', 'panel', 'text', 'muted', 'line', 'accent', 'accent-text', 'danger', 'notice-bg', 'notice-line', 'error-bg', 'focus']) {
    assert.match(light[name] ?? '', /^#[0-9a-f]{6}$/i, `light ${name}`);
    assert.match(dark[name] ?? '', /^#[0-9a-f]{6}$/i, `dark ${name}`);
  }
  assert.notEqual(light.bg, dark.bg);
});

for (const [scheme, p] of [['light', light], ['dark', dark]]) {
  test(`WCAG 1.4.3: text has at least 4.5:1 (${scheme})`, () => {
    for (const [fg, bg, where] of TEXT) assert.ok(ratio(p[fg], p[bg]) >= 4.5, `${scheme}: ${fg} on ${bg} (${where}) is ${ratio(p[fg], p[bg]).toFixed(2)}`);
  });
  test(`WCAG 1.4.11: the edges of controls and the focus ring have at least 3:1 (${scheme})`, () => {
    for (const [fg, bg, where] of NON_TEXT) assert.ok(ratio(p[fg], p[bg]) >= 3, `${scheme}: ${fg} on ${bg} (${where}) is ${ratio(p[fg], p[bg]).toFixed(2)}`);
  });
}

test('the style sheet keeps what the checklist relies on: a visible focus, reduced motion, hidden, no fixed pixel font size, wrapping long words', () => {
  assert.match(css, /:focus-visible\s*\{\s*outline:\s*3px solid var\(--focus\)/);
  assert.match(css, /@media \(prefers-reduced-motion: no-preference\)/);
  assert.match(css, /\[hidden\]\s*\{\s*display:\s*none\s*!important/);
  assert.ok(!/font-size:\s*\d+(\.\d+)?px/.test(css), 'a font size in pixels does not follow the setting of the browser');
  assert.match(css, /overflow-wrap:\s*anywhere/);
  assert.ok(!/outline:\s*(none|0)\b/.test(css.replace(/main \{[^}]*\}/g, '')), 'outline is removed only from main (programmatic focus)');
});

// ---------------------------------------------------------------------------------------------------------------------------------- label in name
test('WCAG 2.5.3: the accessible name of a control with a longer label (<id>-of) contains the text that is seen (<id>), in both languages', () => {
  let pairs = 0;
  for (const [lang, c] of [['en', en], ['ja', ja]]) {
    for (const id of Object.keys(c).filter((k) => k.endsWith('-of') && k.slice(0, -3) in c)) {
      const seen = c[id.slice(0, -3)].replace(/[.…]+$/, '').toLowerCase();
      assert.ok(c[id].toLowerCase().includes(seen), `${lang} ${id}: "${c[id]}" does not contain "${c[id.slice(0, -3)]}"`);
      pairs++;
    }
  }
  assert.ok(pairs >= 10, `only ${pairs} pairs were checked`);
});

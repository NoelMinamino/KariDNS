// The files of the GUI (webadmin/ui) as text (planning 8.1): no HTML-string sink, no eval, no inline script, style or handler, no outside origin, only dom.js makes
// elements; every module can be loaded (so that the coverage gate sees it); the version of the files is the package's.  Also the catalogs (F-6, 7.2).

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ROOT, docApiCodes } from './helpers.js';
import { loadStatic } from '../lib/static.js';
import en from '../ui/i18n/en.js';
import ja from '../ui/i18n/ja.js';
import { GUI_VERSION } from '../ui/js/version.js';

const UI = fileURLToPath(new URL('webadmin/ui/', ROOT));
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
const files = walk(UI);
const rel = (f) => path.relative(UI, f).split(path.sep).join('/');
const js = files.filter((f) => f.endsWith('.js'));
const read = (f) => fs.readFileSync(f, 'utf8');

test('the directory is one the service accepts (names, types, sizes) and has the page', () => {
  const map = loadStatic(UI);
  assert.ok(map.has('/index.html') && map.has('/app.css') && map.has('/js/app.js') && map.has('/i18n/en.js') && map.has('/i18n/ja.js'));
});

test('no HTML-string sink, eval, string timer, javascript: URL, style assignment or data-driven href / src in the scripts', () => {
  const forbidden = [
    /\binnerHTML\b/, /\bouterHTML\b/, /\binsertAdjacentHTML\b/, /\bdocument\.write/, /\beval\s*\(/, /\bnew Function\b/, /\bFunction\s*\(/, /\bset(Timeout|Interval)\s*\(\s*['"`]/,
    /javascript:/i, /setAttribute\(\s*['"]on/, /\.style\b/, /\bcssText\b/, /\.href\s*=/, /\.src\s*=/, /\.srcdoc\b/, /\bdocument\.cookie\b/, /\bsessionStorage\b/,
    /\bXMLHttpRequest\b/, /\bWebSocket\b/, /\bimport\s*\(/, /\bpostMessage\(\s*[^)]*,\s*['"]\*['"]/, /\bnew Worker\b/, /\bwindow\.open\b/,
  ];
  for (const f of js) {
    const src = read(f).replace(/\/\/.*$/gm, '');                       // (comments may name them)
    for (const re of forbidden) assert.ok(!re.test(src), `${rel(f)} matches ${re}`);
  }
});

test('only dom.js makes elements; the stores of the browser are touched in two places', () => {
  for (const f of js) {
    const src = read(f).replace(/\/\/.*$/gm, '');
    if (rel(f) !== 'js/dom.js') assert.ok(!/createElement|createTextNode|createDocumentFragment|\bDOMParser\b|\binsertBefore\b/.test(src), `${rel(f)} makes nodes itself`);
    if (!['js/app.js', 'js/i18n.js'].includes(rel(f))) assert.ok(!/localStorage/.test(src), `${rel(f)} uses localStorage`);
  }
  // what is kept in localStorage: the language (i18n.js) and nothing else
  const keys = [...read(path.join(UI, 'js/i18n.js')).matchAll(/(?:getItem|setItem)\(([^,)]+)/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(keys)], ['LANG_KEY']);
});

test('the page has no inline script, style or handler, and no file names an outside address', () => {
  const html = read(path.join(UI, 'index.html'));
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  assert.ok(scripts.length >= 1);
  for (const [, attrs, body] of scripts) assert.ok(/\bsrc="\/ui\/[^"]+"/.test(attrs) && body.trim() === '', 'every script is a file of the GUI');
  assert.ok(!/<style\b/i.test(html) && !/\sstyle\s*=/i.test(html) && !/\son[a-z]+\s*=/i.test(html), 'no inline style or event handler');
  for (const f of files) {
    const src = read(f);
    const urls = [...src.matchAll(/https?:\/\/[^\s"'`)<>]+/g)].map((m) => m[0]);
    // (the namespace of SVG is a name, not an address that is loaded)
    for (const u of urls) assert.ok(u === 'http://www.w3.org/2000/svg', `${rel(f)} names ${u}`);
  }
  const css = read(path.join(UI, 'app.css'));
  assert.ok(!/@import|url\(/i.test(css), 'the stylesheet loads nothing');
});

test('every module of the GUI can be imported (the coverage gate sees all of them) and the version is the package\'s', async () => {
  for (const f of js.filter((x) => !x.includes(`${path.sep}i18n${path.sep}`))) await import(pathToFileURL(f).href);
  const pkg = JSON.parse(read(fileURLToPath(new URL('webadmin/package.json', ROOT))));
  assert.equal(GUI_VERSION, pkg.version);
});

// ---------------------------------------------------------------------------------------------------------------------------------- catalogs
const placeholders = (s) => [...s.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();

test('both catalogs have the same ids and the same placeholders, and no message is empty', () => {
  assert.deepEqual(Object.keys(en).sort(), Object.keys(ja).sort());
  for (const id of Object.keys(en)) {
    assert.ok(en[id].trim() && ja[id].trim(), `${id} is empty`);
    assert.deepEqual(placeholders(en[id]), placeholders(ja[id]), `${id}: the placeholders differ`);
    assert.ok(!/<[a-z]/i.test(en[id]) && !/<[a-z]/i.test(ja[id]), `${id}: a message is text, not HTML`);
  }
});

test('every error code of docs/karidns-api.md has a message in both languages (F-6), and so do the codes the client makes up', () => {
  const codes = docApiCodes();
  assert.ok(codes.size > 40);
  for (const c of [...codes, 'network', 'timeout', 'bad-response', 'unknown']) {
    assert.ok(en[`api.${c}`], `api.${c} in English`);
    assert.ok(ja[`api.${c}`], `api.${c} in Japanese`);
  }
  // and no message for a code that does not exist
  for (const id of Object.keys(en).filter((k) => k.startsWith('api.'))) assert.ok(codes.has(id.slice(4)) || ['network', 'timeout', 'bad-response', 'unknown'].includes(id.slice(4)), `${id} is not a code`);
});

// the ids that views build with a template string
const DYNAMIC = [/^role\./, /^home\.h-/, /^account\.tok-(h-|ro$|rw$|active$|revoked$|expired$)/, /^warn\./, /^api\./];

test('every message id a view asks for exists, and every message is used', () => {
  const source = js.map(read).join('\n');
  const asked = new Set([...source.matchAll(/\b(?:t|parts|has)\(\s*'([a-z0-9._-]+)'/g)].map((m) => m[1]));
  for (const id of asked) assert.ok(id in en, `the views ask for ${id}`);
  for (const id of Object.keys(en)) {
    const used = source.includes(`'${id}'`) || DYNAMIC.some((re) => re.test(id));
    assert.ok(used, `${id} is in the catalog and used nowhere`);
  }
});

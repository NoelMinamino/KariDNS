// The files of the GUI (static.js; item F, M1): read once at the start, served from memory under / and /ui/, with the headers of planning 5.1, GET and HEAD only,
// nothing but the files that were read.  The GUI itself comes in M2; the placeholder page of webadmin/ui/ is what is served until then.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { deploy, rmDir } from './helpers.js';
import { loadStatic, serveStatic, defaultUiDir, GUI_HEADERS, MAX_FILES, MAX_BYTES } from '../lib/static.js';
import { parseConfig, validate } from '../lib/config.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kw-ui-'));
const put = (dir, rel, text = 'x') => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), text);
};
const withUi = (files, fn, opts = {}) => async () => {
  const dir = tmp();
  for (const [rel, text] of Object.entries(files)) put(dir, rel, text);
  const d = await deploy({ ui: loadStatic(dir), ...opts });
  try {
    await fn(d, dir);
  } finally {
    await d.close();
    rmDir(dir);
  }
};
const FILES = {
  'index.html': '<!DOCTYPE html><html><head><script type="module" src="/ui/js/app.js"></script></head><body>page</body></html>',
  'app.css': 'body { margin: 0 }',
  'js/app.js': 'export const x = 1;',
  'js/views/zone.mjs': 'export default 2;',
  'img/logo.svg': '<svg xmlns="http://www.w3.org/2000/svg"/>',
  'img/logo.png': 'png', 'favicon.ico': 'ico', 'manifest.json': '{}', 'robots.txt': 'x',
};
const get = (d, p, opts = {}) => fetch(`${d.origin}${p}`, opts);
// a request line as written, which fetch would normalize
const raw = (d, p, method = 'GET') => new Promise((resolve, reject) => {
  const req = http.request({ host: '127.0.0.1', port: new URL(d.origin).port, path: p, method }, (res) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
  });
  req.on('error', reject);
  req.end();
});

test('loadStatic: the files, their types and strong entity tags, in nested directories', () => {
  const dir = tmp();
  try {
    for (const [rel, text] of Object.entries(FILES)) put(dir, rel, text);
    const ui = loadStatic(dir);
    assert.deepEqual([...ui.keys()].sort(), ['/app.css', '/favicon.ico', '/img/logo.png', '/img/logo.svg', '/index.html', '/js/app.js', '/js/views/zone.mjs', '/manifest.json', '/robots.txt']);
    assert.equal(ui.get('/index.html').type, 'text/html; charset=utf-8');
    assert.equal(ui.get('/app.css').type, 'text/css; charset=utf-8');
    assert.equal(ui.get('/js/app.js').type, 'text/javascript; charset=utf-8');
    assert.equal(ui.get('/js/views/zone.mjs').type, 'text/javascript; charset=utf-8');
    assert.equal(ui.get('/img/logo.svg').type, 'image/svg+xml');
    assert.equal(ui.get('/img/logo.png').type, 'image/png');
    assert.equal(ui.get('/favicon.ico').type, 'image/vnd.microsoft.icon');
    assert.equal(ui.get('/manifest.json').type, 'application/json; charset=utf-8');
    assert.equal(ui.get('/robots.txt').type, 'text/plain; charset=utf-8');
    assert.match(ui.get('/app.css').etag, /^"[0-9a-f]{32}"$/);
    assert.notEqual(ui.get('/app.css').etag, ui.get('/js/app.js').etag);
    assert.ok(Buffer.isBuffer(ui.get('/app.css').body));
    assert.equal(ui.get('/app.css').body.toString(), 'body { margin: 0 }');
    // the same bytes, the same tag; the files are in memory: a change on disk is not seen
    const tag = ui.get('/app.css').etag;
    fs.writeFileSync(path.join(dir, 'app.css'), 'changed');
    assert.equal(ui.get('/app.css').body.toString(), 'body { margin: 0 }');
    assert.equal(loadStatic(dir).get('/app.css').etag === tag, false);
  } finally {
    rmDir(dir);
  }
});

test('loadStatic: what is refused (the service does not start; ui = no is the way out)', () => {
  const bad = (files, re, mutate) => {
    const dir = tmp();
    try {
      put(dir, 'index.html', '<html></html>');
      for (const [rel, text] of Object.entries(files)) put(dir, rel, text);
      mutate?.(dir);
      assert.throws(() => loadStatic(dir), re);
    } finally {
      rmDir(dir);
    }
  };
  bad({ 'a b.css': 'x' }, /\/a b\.css: the name must be letters, digits/);
  bad({ '.hidden': 'x' }, /\/\.hidden: the name must be/);
  bad({ 'sub/.git/x.js': 'x' }, /\/sub\/\.git: the name must be/);
  bad({ 'café.css': 'x' }, /the name must be/);
  bad({ 'a.exe': 'x' }, /\/a\.exe: no content type is known for this extension/);
  bad({ noextension: 'x' }, /\/noextension: no content type/);
  bad({ 'woff/font.woff2': 'x' }, /no content type is known/);
  bad({}, /there is no index\.html/, (dir) => fs.rmSync(path.join(dir, 'index.html')));
  bad({ 'big.txt': 'x'.repeat(MAX_BYTES) }, /more than 8 MiB in all/);
  const deep = Array.from({ length: 10 }, (_, i) => `d${i}`).join('/');
  bad({ [`${deep}/x.js`]: 'x' }, /nested more than 8 deep/);
  bad(Object.fromEntries(Array.from({ length: MAX_FILES }, (_, i) => [`f${i}.js`, ''])), new RegExp(`more than ${MAX_FILES} files`));
  assert.throws(() => loadStatic(path.join(os.tmpdir(), 'kw-no-such-ui-dir')), /ENOENT/);
});

test('loadStatic: a link, a special file, and a file that is not one when it is opened', () => {
  const dir = tmp();
  try {
    put(dir, 'index.html', '<html></html>');
    put(dir, 'real.txt', 'x');
    let linked = false;
    try { fs.symlinkSync(path.join(dir, 'real.txt'), path.join(dir, 'link.txt')); linked = true; } catch { /* no right to make links here */ }
    if (linked) assert.throws(() => loadStatic(dir), /\/link\.txt: not a regular file/);
    // the entry types and the descriptor, with a file system that lies
    const lie = (over) => ({ ...fs, ...over });
    const ent = (name, kind) => ({ name, isFile: () => kind === 'file', isDirectory: () => kind === 'dir' });
    assert.throws(() => loadStatic('/x', { fsx: lie({ readdirSync: () => [ent('sock.txt', 'other'), ent('index.html', 'file')] }) }), /\/sock\.txt: not a regular file/);
    assert.throws(() => loadStatic('/x', { fsx: lie({ readdirSync: () => [ent('index.html', 'file')], openSync: () => 99, fstatSync: () => ({ isFile: () => false, size: 0 }), closeSync: () => {} }) }), /\/index\.html: not a regular file/);
    const closed = [];
    const ok = lie({ readdirSync: () => [ent('index.html', 'file')], openSync: () => 7, fstatSync: () => ({ isFile: () => true, size: 3 }), readFileSync: () => Buffer.from('abc'), closeSync: (fd) => closed.push(fd) });
    assert.equal(loadStatic('/x', { fsx: ok }).get('/index.html').body.toString(), 'abc');
    assert.deepEqual(closed, [7], 'the descriptor is closed');
    // a failure in the middle closes it too
    closed.length = 0;
    assert.throws(() => loadStatic('/x', { fsx: lie({ ...ok, readFileSync: () => { throw new Error('read failed'); } }) }), /read failed/);
    assert.deepEqual(closed, [7]);
  } finally {
    rmDir(dir);
  }
});

test('the placeholder GUI of webadmin/ui/ loads, and has no inline script or style', () => {
  const ui = loadStatic(defaultUiDir());
  assert.ok(ui.has('/index.html') && ui.has('/app.css') && ui.has('/js/app.js'));
  const page = ui.get('/index.html').body.toString();
  assert.match(page, /^<!DOCTYPE html>/);
  assert.doesNotMatch(page, /<script(?![^>]*\bsrc=)[^>]*>/i, 'every script has a src');
  assert.doesNotMatch(page, /<style\b/i);
  assert.doesNotMatch(page, /\sstyle=|\son[a-z]+=/i);
  assert.doesNotMatch(page, /https?:\/\//i, 'nothing from another site');
});

test('GET /: the page, with the headers of the GUI and no cache', withUi(FILES, async (d) => {
  const r = await get(d, '/');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(await r.text(), FILES['index.html']);
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.match(r.headers.get('etag'), /^"[0-9a-f]{32}"$/);
  assert.equal(r.headers.get('content-length'), String(Buffer.byteLength(FILES['index.html'])));
  // 5.1
  for (const [k, v] of Object.entries(GUI_HEADERS)) assert.equal(r.headers.get(k), v, k);
  const csp = r.headers.get('content-security-policy');
  assert.match(csp, /^default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'$/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|\*|https?:|data:/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(r.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.equal(r.headers.get('cross-origin-resource-policy'), 'same-origin');
  assert.equal(r.headers.get('permissions-policy'), 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  assert.match(r.headers.get('x-request-id'), /^[0-9a-f]{16}$/);
  assert.equal(r.headers.get('strict-transport-security'), null, 'http');
  assert.ok(!r.headers.has('set-cookie'));
  // the page also under /ui/
  assert.equal(await (await get(d, '/ui/index.html')).text(), FILES['index.html']);
  // a query string is not part of the name
  assert.equal((await get(d, '/?x=1')).status, 200);
  assert.equal((await get(d, '/ui/app.css?v=3')).status, 200);
}));

test('the other files: types, entity tags, no-cache, 304', withUi(FILES, async (d) => {
  for (const [p, type] of [['/ui/app.css', 'text/css; charset=utf-8'], ['/ui/js/app.js', 'text/javascript; charset=utf-8'], ['/ui/js/views/zone.mjs', 'text/javascript; charset=utf-8'], ['/ui/img/logo.svg', 'image/svg+xml'],
    ['/ui/img/logo.png', 'image/png'], ['/ui/favicon.ico', 'image/vnd.microsoft.icon'], ['/ui/manifest.json', 'application/json; charset=utf-8'], ['/ui/robots.txt', 'text/plain; charset=utf-8']]) {
    const r = await get(d, p);
    assert.equal(r.status, 200, p);
    assert.equal(r.headers.get('content-type'), type, p);
    assert.equal(r.headers.get('cache-control'), 'no-cache', p);
    assert.equal(r.headers.get('content-security-policy'), GUI_HEADERS['Content-Security-Policy']);
    await r.arrayBuffer();
  }
  const first = await get(d, '/ui/app.css');
  const etag = first.headers.get('etag');
  assert.equal(await first.text(), FILES['app.css']);
  for (const inm of [etag, `W/${etag}`, `"zzz", ${etag}`, '*']) {
    const r = await get(d, '/ui/app.css', { headers: { 'If-None-Match': inm } });
    assert.equal(r.status, 304, inm);
    assert.equal(await r.text(), '');
    assert.equal(r.headers.get('etag'), etag);
    assert.equal(r.headers.get('cache-control'), 'no-cache');
    assert.equal(r.headers.get('content-length'), null, 'no length in a 304');
    assert.equal(r.headers.get('content-security-policy'), GUI_HEADERS['Content-Security-Policy']);
  }
  assert.equal((await get(d, '/ui/app.css', { headers: { 'If-None-Match': '"nope"' } })).status, 200);
  assert.equal((await get(d, '/ui/app.css', { headers: { 'If-None-Match': `${etag.slice(0, -1)}0"` } })).status, 200);
  // the page is never answered with a 304: it must always be read again
  const page = await get(d, '/', { headers: { 'If-None-Match': (await get(d, '/')).headers.get('etag') } });
  assert.equal(page.status, 200);
  await page.arrayBuffer();
}));

test('HEAD answers like GET without the body; the other methods are 405 with Allow', withUi(FILES, async (d) => {
  const h = await raw(d, '/ui/app.css', 'HEAD');
  assert.equal(h.status, 200);
  assert.equal(h.body, '');
  assert.equal(h.headers['content-length'], String(Buffer.byteLength(FILES['app.css'])));
  assert.equal(h.headers['content-type'], 'text/css; charset=utf-8');
  assert.equal((await raw(d, '/', 'HEAD')).headers['cache-control'], 'no-store');
  assert.equal((await raw(d, '/nothing', 'HEAD')).status, 404);
  for (const [method, p] of [['POST', '/'], ['PUT', '/ui/app.css'], ['DELETE', '/ui/js/app.js'], ['PATCH', '/ui/index.html'], ['OPTIONS', '/']]) {
    const r = await fetch(`${d.origin}${p}`, { method, body: ['POST', 'PUT', 'PATCH'].includes(method) ? '{}' : undefined, headers: { 'Content-Type': 'application/json' } });
    assert.equal(r.status, 405, `${method} ${p}`);
    assert.equal(r.headers.get('allow'), 'GET, HEAD');
    assert.equal((await r.json()).type, 'urn:karidns:api:method-not-allowed');
  }
  // (a method on a path that is not a file is a 404, as before)
  assert.equal((await fetch(`${d.origin}/ui/missing.js`, { method: 'POST', body: '{}' })).status, 404);
}));

test('only the files that were read: 404 for anything else, no way out of the map', withUi(FILES, async (d) => {
  for (const p of ['/ui/missing.js', '/ui/', '/ui', '/index.html', '/app.css', '/other', '/favicon.ico', '/ui//app.css', '/ui/js/', '/ui/js', '/ui/img', '/robots.txt', '/UI/app.css', '/ui/APP.CSS']) {
    const r = await raw(d, p);
    assert.equal(r.status, 404, p);
    assert.equal(JSON.parse(r.body).type, 'urn:karidns:api:not-found', p);
    assert.equal(r.headers['content-type'], 'application/problem+json; charset=utf-8');
    assert.equal(r.headers['cache-control'], 'no-store');
  }
  // traversal, in every spelling; the file system is never asked
  for (const p of ['/ui/../etc/passwd', '/ui/../../etc/passwd', '/ui/%2e%2e/%2e%2e/etc/passwd', '/ui/..%2f..%2fetc%2fpasswd', '/ui/js/../../index.html', '/%2e%2e/index.html', '/ui/%2e%2e%2f',
    '/ui/js/..%5c..%5capp.css', '/ui/app.css%00', '/ui/app.css%2f', '/ui/%61pp.css', '/ui/./app.css/..', '/ui/js/%2e%2e/app.css', '\\ui\\app.css', '/ui/app.css/', '//ui/app.css']) {
    const r = await raw(d, p);
    assert.ok([200, 301, 400, 404].includes(r.status), `${p}: ${r.status}`);
    // 200 only for a name that the map has after the URL parser normalizes it, never for something outside
    if (r.status === 200) assert.ok(Object.values(FILES).includes(r.body), p);
  }
  assert.equal((await raw(d, '/ui/../etc/passwd')).status, 404);
  assert.equal((await raw(d, '/ui/%2e%2e/%2e%2e/etc/passwd')).status, 404);
  assert.equal((await raw(d, '/ui/js/../../index.html')).status, 404);
  assert.equal((await raw(d, '/ui/%61pp.css')).status, 404, 'an escape is not decoded: the names have no % in them');
  // the API is where it was, and a path under /api/v1/ that does not exist is the API's 404
  assert.equal((await get(d, '/api/v1/health')).status, 200);
  const nf = await get(d, '/api/v1/nothing');
  assert.equal(nf.status, 404);
  assert.equal((await nf.json()).type, 'urn:karidns:api:not-found');
  assert.equal(nf.headers.get('content-security-policy'), "default-src 'self'; frame-ancestors 'none'", 'the API keeps its own policy');
}));

test('HSTS on https, as on the API; the log names the request', withUi(FILES, async (d) => {
  const r = await get(d, '/ui/app.css');
  assert.equal(r.headers.get('strict-transport-security'), 'max-age=31536000');
  await r.arrayBuffer();
  assert.ok(d.log.lines.some((l) => /^info \S+ [0-9a-f]{16} - GET the GUI 200 \d+ms$/.test(l)), d.log.lines.join('|'));
}, { settings: { 'public-origin': 'https://dns.example.test' } }));

test('no GUI (ui = no): / and /ui/ are 404, the API is untouched', async () => {
  const d = await deploy();
  try {
    assert.equal(d.app.ui, null);
    for (const p of ['/', '/ui/app.css', '/ui/index.html']) {
      const r = await get(d, p);
      assert.equal(r.status, 404, p);
      assert.equal((await r.json()).type, 'urn:karidns:api:not-found');
    }
    assert.equal((await get(d, '/api/v1/health')).status, 200);
  } finally {
    await d.close();
  }
});

test('serveStatic: a request line that is not a path', () => {
  const ui = new Map([['/index.html', { body: Buffer.from('x'), type: 'text/html', etag: '"e"' }]]);
  assert.equal(serveStatic(ui, { url: 'http://[bad/', method: 'GET', headers: {} }), null);
  assert.equal(serveStatic(ui, { url: '*', method: 'OPTIONS', headers: {} }), null);
  assert.equal(serveStatic(ui, { url: '/', method: 'GET', headers: {} }).status, 200);
  assert.equal(serveStatic(ui, { url: 'http://example.test/', method: 'GET', headers: {} }).status, 200, 'the absolute form of a proxy request');
});

test('the settings ui and ui-dir', () => {
  assert.equal(parseConfig('').settings.ui, true);
  assert.equal(parseConfig('').settings['ui-dir'], undefined);
  assert.equal(parseConfig('ui = no').settings.ui, false);
  assert.equal(parseConfig('ui = yes\nui-dir = /srv/gui').settings['ui-dir'], '/srv/gui');
  assert.throws(() => parseConfig('ui = maybe'), /line 1: ui: expected yes or no/);
  assert.throws(() => parseConfig('ui-dir = gui'), /line 1: ui-dir: /);
  const base = 'listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = sqlite3\nsqlite-file = /a\nauth-file = /b\n';
  assert.deepEqual(validate(parseConfig(`${base}ui-dir = /srv/gui`)), []);
  assert.deepEqual(validate(parseConfig(`${base}ui = no`)), []);
  assert.ok(validate(parseConfig(`${base}ui = no\nui-dir = /srv/gui`)).some((p) => /'ui-dir' names the files of the GUI, and ui = no switches the GUI off/.test(p)));
});

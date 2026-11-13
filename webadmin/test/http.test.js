// the HTTP layer: the router, the limits, the headers, the client address, the rate limits, errors that are bugs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { spawnSync } from 'node:child_process';
import { Router, reply, Reply, clientAddress, listen, closeServer, dispatch, reloadTls } from '../lib/http.js';
import { ApiError } from '../lib/errors.js';
import { deploy, cast } from './helpers.js';

const withDeploy = (opts, fn) => async () => {
  const d = await deploy(opts);
  try {
    await fn(d);
  } finally {
    await d.close();
  }
};
const is = (r, status, type) => {
  assert.equal(r.status, status, JSON.stringify(r.body));
  if (type) assert.equal(r.body.type, `urn:karidns:api:${type}`, JSON.stringify(r.body));
};

test('the router: parameters, methods, decoding', () => {
  const h = () => {};
  const r = new Router([
    { method: 'GET', path: '/a/:x/b', handler: h }, { method: 'POST', path: '/a/:x/b', handler: h }, { method: 'GET', path: '/plain.txt', handler: h, auth: 'none' },
    { method: 'GET', path: '/a/:x', handler: h },
  ]);
  assert.equal(r.match('GET', '/a/q/b').route.handler, h);
  assert.deepEqual(r.match('GET', '/a/q/b').params, { x: 'q' });
  assert.deepEqual(r.match('GET', '/a/a%20b%2Fc/b').params, { x: 'a b/c' });
  assert.equal(r.match('GET', '/a/q/b').route.auth, 'user');
  assert.equal(r.match('GET', '/plain.txt').route.auth, 'none');
  assert.equal(r.match('GET', '/plainXtxt'), null, 'a dot in a path is a dot');
  assert.deepEqual(r.match('DELETE', '/a/q/b'), { allow: ['GET', 'POST'] });
  assert.equal(r.match('GET', '/nothing'), null);
  assert.equal(r.match('GET', '/a/q/b/'), null);
  assert.equal(r.match('GET', '/a//b'), null);
  assert.throws(() => r.match('GET', '/a/%ZZ/b'), (e) => e instanceof ApiError && e.status === 400);
  assert.throws(() => r.match('GET', '/a/%00/b'), (e) => e instanceof ApiError && e.status === 400);
  assert.throws(() => r.match('GET', '/a/%1f/b'), (e) => e instanceof ApiError && e.status === 400);
  assert.equal(reply(204, null) instanceof Reply, true);
});

test('the client address: the peer, or what a trusted proxy says', () => {
  const req = (peer, xff) => ({ socket: { remoteAddress: peer }, headers: xff === undefined ? {} : { 'x-forwarded-for': xff } });
  assert.equal(clientAddress(req('192.0.2.1'), []), '192.0.2.1');
  assert.equal(clientAddress(req('::ffff:192.0.2.1'), []), '192.0.2.1');
  assert.equal(clientAddress(req(undefined), []), 'local');
  assert.equal(clientAddress(req('192.0.2.1', '198.51.100.9'), []), '192.0.2.1', 'an untrusted peer cannot say who it is');
  assert.equal(clientAddress(req('10.0.0.1', '198.51.100.9'), ['10.0.0.1']), '198.51.100.9');
  assert.equal(clientAddress(req('10.0.0.1', '203.0.113.1, 198.51.100.9, 10.0.0.2'), ['10.0.0.1', '10.0.0.2']), '198.51.100.9', 'the first from the right that is not a proxy');
  assert.equal(clientAddress(req('10.0.0.1', '10.0.0.2'), ['10.0.0.1', '10.0.0.2']), '10.0.0.1');
  assert.equal(clientAddress(req('10.0.0.1'), ['10.0.0.1']), '10.0.0.1');
  assert.equal(clientAddress(req('10.0.0.1', '::ffff:198.51.100.9'), ['10.0.0.1']), '198.51.100.9');
  // a proxy on the UNIX socket has no address: `local` names it (and nothing that connects over TCP is ever `local`)
  assert.equal(clientAddress(req(undefined, '198.51.100.9'), ['local']), '198.51.100.9');
  assert.equal(clientAddress(req(undefined, '198.51.100.9'), ['127.0.0.1']), 'local', 'the socket peer is not trusted unless local is named');
  assert.equal(clientAddress(req('192.0.2.1', '198.51.100.9'), ['local']), '192.0.2.1');
});

test('what is not the API, and the wrong method', withDeploy({}, async (d) => {
  const raw = (p, method = 'GET') => new Promise((resolve, reject) => {
    const port = new URL(d.base).port;
    const r = http.request({ host: '127.0.0.1', port, path: p, method }, (res) => {
      let t = '';
      res.on('data', (c) => { t += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(t) }));
    });
    r.on('error', reject);
    r.end();
  });
  is(await raw('/'), 404, 'not-found');
  is(await raw('/api/v2/health'), 404, 'not-found');
  is(await raw('/api/v1'), 404, 'not-found');
  is(await raw('//evil.test/api/v1/health'), 404, 'not-found');
  is(await raw('/api/v1/nothing'), 404, 'not-found');
  const m = await raw('/api/v1/health', 'POST');
  is(m, 405, 'method-not-allowed');
  assert.equal(m.headers.allow, 'GET');
  is(await raw('/api/v1/datasets/%ZZ/zones'), 400, 'bad-request');
  is(await d.request('GET', '/health%00'), 404, 'not-found');
  const x = await d.request('GET', '/nothing');
  assert.match(x.headers.get('x-request-id'), /^[0-9a-f]{16}$/);
  assert.equal(x.body.request_id, x.headers.get('x-request-id'));
}));

test('bodies: media type, JSON, size', withDeploy({}, async (d) => {
  await cast(d);
  const s = d.as(await d.login('root', 'correct horse battery'));
  is(await s('POST', '/principals', { raw: '{"kind":"group","name":"g"}', headers: { 'Content-Type': 'text/plain' } }), 415, 'unsupported-media-type');
  is(await s('POST', '/principals', { raw: '{"kind":"group","name":"g"}' }), 415, 'unsupported-media-type');
  is(await s('POST', '/principals', { raw: '{"kind":', headers: { 'Content-Type': 'application/json' } }), 400, 'malformed-json');
  is(await s('POST', '/principals', { raw: 'null', headers: { 'Content-Type': 'application/json' } }), 400, 'bad-request');
  assert.equal((await s('POST', '/principals', { raw: '{"kind":"group","name":"g1"}', headers: { 'Content-Type': 'application/json; charset=UTF-8' } })).status, 201);
  assert.equal((await s('POST', '/principals', { raw: '{"kind":"group","name":"g2"}', headers: { 'Content-Type': 'application/json;charset="utf-8"' } })).status, 201);
  is(await s('POST', '/principals', { raw: '{"kind":"group","name":"g3"}', headers: { 'Content-Type': 'application/json; charset=latin1' } }), 415, 'unsupported-media-type');
  // an empty body on a POST is a shape error, not a media type error
  is(await s('POST', '/principals'), 400, 'bad-request');
  // size: 1 MiB; the login takes 16 KiB
  const big = JSON.stringify({ kind: 'group', name: 'g', display_name: 'x'.repeat(2 << 20) });
  is(await s('POST', '/principals', { raw: big, headers: { 'Content-Type': 'application/json' } }), 413, 'too-large');
  is(await d.request('POST', '/auth/login', { raw: JSON.stringify({ user: 'a', password: 'b'.repeat(20000) }), headers: { 'Content-Type': 'application/json' } }), 413, 'too-large');
  // without a Content-Length (chunked) the limit holds as well
  const port = new URL(d.base).port;
  const chunked = await new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, path: '/api/v1/auth/login', method: 'POST', headers: { 'Content-Type': 'application/json' } }, (res) => {
      let t = '';
      res.on('data', (c) => { t += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(t) }));
    });
    r.on('error', reject);
    r.write('{"user":"a","password":"');
    r.write('x'.repeat(20000));
    r.end('"}');
  });
  assert.equal(chunked.status, 413);
  // a Content-Length that is not a number
  const bad = await new Promise((resolve) => {
    const r = http.request({ host: '127.0.0.1', port, path: '/api/v1/auth/login', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': '2' } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    r.on('error', () => resolve('error'));
    r.setHeader('Content-Length', '0x10');
    r.end();
  });
  assert.ok([400, 413, 'error'].includes(bad));
}));

test('request rates: per principal, and writes more strictly', withDeploy({ settings: { 'rate-api': 2, 'rate-write': 1 } }, async (d) => {
  await cast(d);
  const s = d.as(await d.login('root', 'correct horse battery'));
  const codes = [];
  for (let i = 0; i < 6; i++) codes.push((await s('GET', '/auth/me')).status);
  assert.deepEqual(codes.slice(0, 4), [200, 200, 200, 200]);
  assert.ok(codes.includes(429), codes.join());
  const r = await s('GET', '/auth/me');
  if (r.status === 429) {
    is(r, 429, 'rate-limited');
    assert.match(r.headers.get('retry-after'), /^\d+$/);
  }
  // another principal has its own bucket
  const other = d.as(await d.login('dom', 'dom password 12345'));
  assert.equal((await other('GET', '/auth/me')).status, 200);
}));

test('writes are limited more strictly than reads', withDeploy({ settings: { 'rate-api': 1000, 'rate-write': 1 } }, async (d) => {
  await cast(d);
  const s = d.as(await d.login('root', 'correct horse battery'));
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await s('POST', '/principals', { body: { kind: 'group', name: `g${i}` } })).status);
  assert.deepEqual(codes.slice(0, 2), [201, 201]);
  assert.ok(codes.includes(429), codes.join());
  assert.equal((await s('GET', '/principals')).status, 200);
}));

test('a bug is a 500 that says nothing; a privilege error of the database is logged as a bug; busy is a 503', withDeploy({}, async (d) => {
  const routes = new Router([
    { method: 'GET', path: '/boom', auth: 'none', handler: () => { throw new Error('secret detail: /etc/shadow'); } },
    { method: 'GET', path: '/rls', auth: 'none', handler: () => { throw Object.assign(new Error('new row violates row-level security policy'), { code: '42501' }); } },
    { method: 'GET', path: '/busy', auth: 'none', handler: () => { throw Object.assign(new Error('x'), { code: '40001' }); } },
    { method: 'GET', path: '/api-error', auth: 'none', handler: () => { throw new ApiError(409, 'custom', 'a custom conflict', { headers: { 'X-Custom': '1' } }); } },
    { method: 'GET', path: '/array', auth: 'none', handler: () => reply(200, [1, 2]) },
    { method: 'GET', path: '/nothing', auth: 'none', handler: () => reply(204, null) },
    { method: 'GET', path: '/async-boom', auth: 'none', handler: async () => { throw new TypeError('async secret'); } },
  ]);
  const server = await listen(d.app, routes);
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/v1`;
    const get = async (p) => { const r = await fetch(base + p); return { status: r.status, text: await r.text(), headers: r.headers }; };
    const boom = await get('/boom');
    assert.equal(boom.status, 500);
    assert.equal(boom.text.includes('secret'), false);
    assert.equal(JSON.parse(boom.text).type, 'urn:karidns:api:internal');
    assert.ok(d.log.lines.some((l) => /^error [0-9a-f]{16}: Error: secret detail/.test(l)));
    assert.equal((await get('/async-boom')).status, 500);
    const rls = await get('/rls');
    assert.equal(rls.status, 500);
    assert.ok(d.log.lines.some((l) => /row level security refused what the API allowed \(a bug\)/.test(l)));
    const busy = await get('/busy');
    assert.equal(busy.status, 503);
    assert.equal(busy.headers.get('retry-after'), '2');
    const ae = await get('/api-error');
    assert.equal(ae.status, 409);
    assert.equal(ae.headers.get('x-custom'), '1');
    assert.equal(ae.headers.get('content-type'), 'application/problem+json; charset=utf-8');
    assert.equal((await get('/array')).text, '[1,2]');
    const none = await get('/nothing');
    assert.equal(none.status, 204);
    assert.equal(none.text, '');
    assert.equal(none.headers.get('content-type'), null);
  } finally {
    await closeServer(server);
  }
}));

test('the access log: one line, the route template, no query string, no body, no secrets', withDeploy({}, async (d) => {
  await cast(d);
  const s = d.as(await d.login('root', 'correct horse battery'));
  d.log.lines.length = 0;
  await s('GET', '/datasets/main/zones/example.test/rrsets?name=www.example.test&type=A');
  await s('POST', '/principals', { body: { kind: 'user', name: 'secretname', password: 'secretpassword1' } });
  const text = d.log.lines.join('\n');
  assert.match(text, /^info 127\.0\.0\.1 [0-9a-f]{16} root GET \/datasets\/:ds\/zones\/:zone\/rrsets 200 \d+ms$/m);
  assert.match(text, /root POST \/principals 201 /);
  assert.equal(/secretpassword1|name=www|session=|csrf/i.test(text), false);
  d.log.lines.length = 0;
  await d.request('GET', '/nothing/at/all');
  assert.match(d.log.lines[0], / - GET - 404 /);
}));

test('a UNIX socket', { skip: process.platform === 'win32' }, withDeploy({}, async (d) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-sock-'));
  const sock = path.join(dir, 'api.sock');
  const s = d.app.settings.listen;
  d.app.settings.listen = sock;
  fs.writeFileSync(sock, 'a stale file that is not a socket');
  try {
    await assert.rejects(listen(d.app, new Router([])), /EADDRINUSE|EEXIST|listen/);
    fs.rmSync(sock);
    const server = await listen(d.app, new Router([{ method: 'GET', path: '/health', auth: 'none', handler: () => ({ ok: true }) }]));
    assert.equal(fs.statSync(sock).mode & 0o777, 0o660);
    const res = await new Promise((resolve, reject) => {
      http.get({ socketPath: sock, path: '/api/v1/health' }, (r) => { let t = ''; r.on('data', (c) => { t += c; }); r.on('end', () => resolve(t)); }).on('error', reject);
    });
    assert.deepEqual(JSON.parse(res), { api: 1, ok: true });
    await closeServer(server);
    // a socket left by a dead server is replaced
    const again = await listen(d.app, new Router([]));
    await closeServer(again);
  } finally {
    d.app.settings.listen = s;
    fs.rmSync(dir, { recursive: true, force: true });
  }
}));

test('dispatch outside the server: the client address of a request through a trusted proxy', withDeploy({ settings: { 'trusted-proxy': '127.0.0.1', 'rate-login': 2 } }, async (d) => {
  // the proxy is the peer (127.0.0.1); the logins of two clients behind it are counted apart
  const login = (xff, user) => d.request('POST', '/auth/login', { body: { user, password: 'x' }, headers: { 'X-Forwarded-For': xff } });
  await login('198.51.100.1', 'a'); await login('198.51.100.1', 'b');
  assert.equal((await login('198.51.100.1', 'c')).status, 429);
  assert.equal((await login('198.51.100.2', 'd')).status, 401);
  assert.equal(typeof dispatch, 'function');
}));

const OPENSSL = spawnSync('openssl', ['version']);

test('built-in TLS: tls-cert and tls-key, TLS 1.2 or newer', { skip: OPENSSL.status !== 0 && 'openssl is not installed' }, withDeploy({}, async (d) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-tls-'));
  try {
    const key = path.join(dir, 'k.pem');
    const crt = path.join(dir, 'c.pem');
    const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', crt, '-days', '2', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost']);
    assert.equal(made.status, 0, String(made.stderr));
    d.app.settings['tls-cert'] = crt;
    d.app.settings['tls-key'] = key;
    d.app.settings['public-origin'] = 'https://localhost';
    const server = await listen(d.app, new Router([{ method: 'GET', path: '/health', auth: 'none', handler: () => ({ tls: true }) }]));
    try {
      const get = (extra = {}) => new Promise((resolve, reject) => {
        https.get({ host: '127.0.0.1', port: server.address().port, path: '/api/v1/health', ca: fs.readFileSync(crt), servername: 'localhost', ...extra }, (r) => {
          let t = '';
          const protocol = r.socket.getProtocol();
          r.on('data', (c) => { t += c; });
          r.on('end', () => resolve({ body: JSON.parse(t), hsts: r.headers['strict-transport-security'], protocol }));
        }).on('error', reject);
      });
      const r = await get();
      assert.deepEqual(r.body, { api: 1, tls: true });
      assert.equal(r.hsts, 'max-age=31536000');
      assert.match(r.protocol, /^TLSv1\.[23]$/);
      await assert.rejects(get({ maxVersion: 'TLSv1.1', minVersion: 'TLSv1' }));
      await assert.rejects(get({ ca: undefined }), /self-signed|unable to verify|certificate/i);
    } finally {
      await closeServer(server, 200);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}));

test('built-in TLS: SIGHUP reads the certificate and key again (reloadTls); a file that cannot be read changes nothing; a plain server is left alone', { skip: OPENSSL.status !== 0 && 'openssl is not installed' }, withDeploy({}, async (d) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-tls2-'));
  try {
    const make = (name) => {
      const key = path.join(dir, `${name}.key`);
      const crt = path.join(dir, `${name}.crt`);
      const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', crt, '-days', '2', '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost']);
      assert.equal(made.status, 0, String(made.stderr));
      return { key, crt };
    };
    const a = make('a');
    const b = make('b');
    d.app.settings['tls-cert'] = path.join(dir, 'live.crt');
    d.app.settings['tls-key'] = path.join(dir, 'live.key');
    d.app.settings['public-origin'] = 'https://localhost';
    fs.copyFileSync(a.crt, d.app.settings['tls-cert']);
    fs.copyFileSync(a.key, d.app.settings['tls-key']);
    const server = await listen(d.app, new Router([{ method: 'GET', path: '/health', auth: 'none', handler: () => ({ tls: true }) }]));
    try {
      const fingerprint = () => new Promise((resolve, reject) => {
        const req = https.get({ host: '127.0.0.1', port: server.address().port, path: '/api/v1/health', rejectUnauthorized: false, agent: false }, (r) => {
          const fp = r.socket.getPeerCertificate().fingerprint256;
          r.resume();
          r.on('end', () => resolve(fp));
        });
        req.on('error', reject);
      });
      const first = await fingerprint();
      assert.match(first, /^[0-9A-F:]{95}$/);
      fs.copyFileSync(b.crt, d.app.settings['tls-cert']);
      fs.copyFileSync(b.key, d.app.settings['tls-key']);
      assert.equal(await fingerprint(), first, 'nothing changes until the files are read again');
      assert.equal(reloadTls(server, d.app.settings), true);
      const second = await fingerprint();
      assert.notEqual(second, first);
      fs.rmSync(d.app.settings['tls-cert']);
      assert.throws(() => reloadTls(server, d.app.settings), /ENOENT/);
      assert.equal(await fingerprint(), second, 'the certificate in use stays');
      assert.equal(reloadTls(server, { ...d.app.settings, 'tls-cert': undefined }), false);
    } finally {
      await closeServer(server, 200);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(reloadTls({}, { 'tls-cert': '/x', 'tls-key': '/y' }), false);        // (a server without TLS)
}));

test('closing the server: idle connections at once, the others after the grace time', async () => {
  const calls = [];
  let done;
  const stubborn = { close: (cb) => { done = cb; }, closeIdleConnections: () => calls.push('idle'), closeAllConnections: () => { calls.push('all'); done(); } };
  await closeServer(stubborn, 10);
  assert.deepEqual(calls, ['idle', 'all']);
  const quick = { close: (cb) => setImmediate(cb), closeIdleConnections: () => calls.push('idle2'), closeAllConnections: () => calls.push('all2') };
  await closeServer(quick, 10000);
  assert.deepEqual(calls, ['idle', 'all', 'idle2']);
});

test('an answer that cannot be sent does not take the process down', withDeploy({}, async (d) => {
  const routes = new Router([{ method: 'GET', path: '/bad-header', auth: 'none', handler: () => { throw new ApiError(400, 'x', 'd', { headers: { 'X-Bad': 'a\nb' } }); } }]);
  const server = await listen(d.app, routes);
  try {
    await assert.rejects(fetch(`http://127.0.0.1:${server.address().port}/api/v1/bad-header`));
    assert.ok(d.log.lines.some((l) => /^error dispatch failed: /.test(l)));
  } finally {
    await closeServer(server);
  }
}));

test('background work: its failure is logged, never thrown; drain waits for it', withDeploy({}, async (d) => {
  let done = false;
  d.app.background(async () => { await new Promise((r) => setTimeout(r, 20)); done = true; });
  d.app.background(() => { throw new Error('the touch failed'); });
  await d.app.drain();
  assert.equal(done, true);
  assert.ok(d.log.lines.includes('warn background work failed: the touch failed'));
  assert.equal(d.app.pending.size, 0);
}));

test('/health gives up on a database that does not answer', withDeploy({}, async (d) => {
  d.app.healthTimeoutMs = 30;
  d.backend.tx = () => new Promise(() => {});
  const r = await d.request('GET', '/health');
  assert.equal(r.status, 503);
  assert.equal(r.body.database, 'error');
}));

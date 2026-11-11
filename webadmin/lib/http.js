// The HTTP server (planning 2.1, 4.2, 8.2): node:http, one process.  Limits on the headers, the body and the time a request may take; the route table; the
// authentication and the rate limits before a handler runs; problem+json for every error; the security headers on every answer.

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { ApiError, problem, mapDbError } from './errors.js';
import { authenticate } from './session.js';
import { listenHost } from './config.js';
import { serveStatic } from './static.js';

export const PREFIX = '/api/v1';
const BODY_LIMIT = 1 << 20;
const REQUEST_MS = 30000;                   // a request body is received within this time ...
const IMPORT_MS = 300000;                   // ... a zone import within this (planning 8.2); the server's requestTimeout is the larger
const JSON_TYPE = /^application\/json\s*(?:;\s*charset\s*=\s*"?utf-?8"?\s*)?$/i;
const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// What a handler returns when it wants more than a 200 with a JSON object: reply(201, {...}, { headers }) or reply(200, null, { text, type })
export class Reply {
  constructor(status, body, { headers = {}, text, type } = {}) {
    this.status = status;
    this.body = body;
    this.headers = headers;
    this.text = text;
    this.type = type;
  }
}
export const reply = (status, body, extra) => new Reply(status, body, extra);

// route: { method, path: '/datasets/:ds/zones/:zone', handler, auth: 'user' (default) | 'none', preTotp, sessionOnly, bodyLimit, readTimeoutMs }
export { IMPORT_MS };
export class Router {
  constructor(routes) {
    this.routes = routes.map((r) => {
      const names = [];
      const re = new RegExp(`^${r.path.split('/').map((seg) => {
        if (seg.startsWith(':')) {
          names.push(seg.slice(1));
          return '([^/]+)';
        }
        return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      }).join('/')}$`);
      return { auth: 'user', ...r, re, names, template: `${r.method} ${r.path}` };
    });
  }

  // -> { route, params } | { allow: [methods] } | null
  match(method, path) {
    const allow = [];
    for (const r of this.routes) {
      const m = r.re.exec(path);
      if (!m) continue;
      if (r.method === method) {
        const params = {};
        for (let i = 0; i < r.names.length; i++) {
          let v;
          try { v = decodeURIComponent(m[i + 1]); } catch { throw new ApiError(400, 'bad-request', 'the path is not valid'); }
          if (/[\0-\x1f\x7f]/.test(v)) throw new ApiError(400, 'bad-request', 'the path is not valid');
          params[r.names[i]] = v;
        }
        return { route: r, params };
      }
      allow.push(r.method);
    }
    return allow.length ? { allow } : null;
  }
}

// What is left of a body that is too large is read and thrown away (64 MiB at most, then the connection goes): a client that is still sending when the 413 comes
// gets the answer, not a reset (the connection is kept open for that: closing it right after the answer resets it).
function discard(req) {
  let n = 0;
  req.on('data', (chunk) => {
    n += chunk.length;
    if (n > 64 << 20) req.destroy();
  });
  req.on('error', () => {});
}

// The body, at most `limit` octets, received within `timeoutMs` (30 s; a zone import has 300 s: the route says so).  The server's own requestTimeout is the longest of
// these; this deadline is the one an ordinary request gets.
export function readBody(req, limit, timeoutMs = REQUEST_MS) {
  const declared = req.headers['content-length'];
  if (declared !== undefined && (!/^\d{1,12}$/.test(declared) || Number(declared) > limit)) {
    discard(req);
    return Promise.reject(new ApiError(413, 'too-large', `the body is limited to ${limit} octets`));
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const done = (fn, v) => {
      clearTimeout(timer);
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('close', onClose);
      fn(v);
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > limit) {
        done(reject, new ApiError(413, 'too-large', `the body is limited to ${limit} octets`));
        discard(req);
      } else {
        chunks.push(chunk);
      }
    };
    const onEnd = () => done(resolve, Buffer.concat(chunks));
    const onError = (e) => done(reject, e);
    const onClose = () => { if (!req.complete) done(reject, new Error('the client closed the connection')); };
    const timer = setTimeout(() => done(reject, new ApiError(408, 'request-timeout', `the request was not received within ${Math.round(timeoutMs / 1000)} seconds`, { headers: { Connection: 'close' } })), timeoutMs);
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('close', onClose);
  });
}

// The client's address: the peer's, unless the peer is a configured trusted proxy, then the first address from the right of X-Forwarded-For that is not
// a trusted proxy itself
export function clientAddress(req, trusted) {
  const strip = (a) => (a ?? 'local').replace(/^::ffff:/, '');
  const peer = strip(req.socket.remoteAddress);
  if (!trusted.includes(peer)) return peer;
  const xff = String(req.headers['x-forwarded-for'] ?? '').split(',').map((s) => strip(s.trim())).filter(Boolean);
  for (let i = xff.length - 1; i >= 0; i--) if (!trusted.includes(xff[i])) return xff[i];
  return peer;
}

const SECURITY = {
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  // (M6 review: another site may not load an answer of the API as a resource, with or without a cookie; the files of the GUI have it from static.js as well)
  'Cross-Origin-Resource-Policy': 'same-origin',
};

function send(ctx, status, headers, payload) {
  const { res, app } = ctx;
  if (res.headersSent) { res.end(); return; }
  const extra = { ...SECURITY, 'X-Request-Id': ctx.id, ...headers };
  if (app.settings['public-origin'].startsWith('https:')) extra['Strict-Transport-Security'] = 'max-age=31536000';
  ctx.status = status;
  // (no Content-Length in a 204 or a 304: RFC 9110 section 8.6 and 15.4.5; a HEAD answer keeps the length of the body it does not send)
  res.writeHead(status, status === 204 || status === 304 ? extra : { ...extra, 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

function sendReply(ctx, r) {
  if (r.text !== undefined) return send(ctx, r.status, { 'Content-Type': r.type ?? 'text/plain; charset=utf-8', ...r.headers }, r.text);
  const body = r.body === null || r.body === undefined ? '' : JSON.stringify(Array.isArray(r.body) ? r.body : { api: 1, ...r.body });
  return send(ctx, r.status, { ...(body ? { 'Content-Type': 'application/json; charset=utf-8' } : {}), ...r.headers }, body);
}

function sendError(ctx, e) {
  const { app } = ctx;
  let err = e;
  if (!(err instanceof ApiError)) {
    const mapped = mapDbError(e);
    if (mapped) err = mapped;
    else if (e?.code === '42501') app.log.error(`${ctx.id}: row level security refused what the API allowed (a bug): ${String(e.message).slice(0, 300)}`);
    else app.log.error(`${ctx.id}: ${String(e?.stack ?? e?.message ?? e).split('\n').slice(0, 4).join(' | ').slice(0, 600)}`);
  }
  send(ctx, err instanceof ApiError ? err.status : 500, { 'Content-Type': 'application/problem+json; charset=utf-8', ...(err instanceof ApiError ? err.headers : {}) }, JSON.stringify(problem(err, ctx.id)));
}

export async function dispatch(app, router, req, res) {
  const ctx = { app, req, res, id: crypto.randomBytes(8).toString('hex'), method: req.method, started: Date.now(), auth: null, params: {}, route: null, status: 0, changeSet: null };
  ctx.ip = clientAddress(req, app.settings['trusted-proxy']);
  // a handler's way to the database: a transaction as the principal of the request
  ctx.db = (fn, { write = false, changeSet = null } = {}) => app.backend.tx({ principal: ctx.auth?.principal.id ?? null, name: ctx.auth?.principal.name ?? null, changeSet, write }, fn);
  try {
    if (!req.url.startsWith(`${PREFIX}/`)) {
      // the files of the GUI (static.js), when the service has them: no login, no database, answered from memory
      const page = app.ui ? serveStatic(app.ui, req) : null;
      if (!page) throw new ApiError(404, 'not-found', 'there is nothing here; the API is under /api/v1/');
      ctx.route = { template: `${req.method} the GUI` };
      sendReply(ctx, new Reply(page.status, null, { text: page.body, type: page.type, headers: page.headers }));       // (text may be a Buffer: only its length and bytes are used)
      return;
    }
    const url = new URL(req.url, 'http://localhost');
    ctx.query = url.searchParams;
    const m = router.match(req.method, url.pathname.slice(PREFIX.length));
    if (!m) throw new ApiError(404, 'not-found', 'no such resource');
    if (m.allow) throw new ApiError(405, 'method-not-allowed', 'this resource does not take that method', { headers: { Allow: [...new Set(m.allow)].join(', ') } });
    ctx.route = m.route;
    ctx.params = m.params;
    if (m.route.auth === 'user') {
      await authenticate(app, ctx, m.route);
      const who = ctx.auth.principal.id;
      const wait = app.buckets.api.take(who) || (UNSAFE.has(req.method) ? app.buckets.write.take(who) : 0);
      if (wait) throw new ApiError(429, 'rate-limited', 'too many requests', { headers: { 'Retry-After': String(wait) } });
    }
    if (UNSAFE.has(req.method)) {
      const raw = await readBody(req, m.route.bodyLimit ?? BODY_LIMIT, m.route.readTimeoutMs);
      if (raw.length) {
        if (!JSON_TYPE.test(req.headers['content-type'] ?? '')) throw new ApiError(415, 'unsupported-media-type', 'the body must be application/json (UTF-8)');
        try { ctx.body = JSON.parse(raw.toString('utf8')); } catch { throw new ApiError(400, 'malformed-json', 'the body is not valid JSON'); }
      }
    }
    const result = await m.route.handler(ctx);
    sendReply(ctx, result instanceof Reply ? result : new Reply(200, result));
  } catch (e) {
    sendError(ctx, e);
  } finally {
    app.log.info(`${ctx.ip} ${ctx.id} ${ctx.auth ? ctx.auth.principal.name : '-'} ${req.method} ${ctx.route?.template.slice(req.method.length + 1) ?? '-'} ${ctx.status} ${Date.now() - ctx.started}ms${ctx.changeSet ? ` cs=${ctx.changeSet}` : ''}`);
  }
}

const tlsMaterial = (s, fsx) => ({ cert: fsx.readFileSync(s['tls-cert']), key: fsx.readFileSync(s['tls-key']), minVersion: 'TLSv1.2' });

// SIGHUP (0.6.1): the next connections use the certificate and key now in the files (tls.Server.setSecureContext; the connections that are open keep theirs), so a
// renewed certificate needs no restart.  Throws when a file cannot be read: the caller keeps the old settings and the old certificate.  Does nothing for a server that
// listens without TLS (switching TLS on or off, like the listen address, needs a restart).  -> true when the files were read.
export function reloadTls(server, settings, { fsx = fs } = {}) {
  if (typeof server.setSecureContext !== 'function' || !settings['tls-cert']) return false;
  server.setSecureContext(tlsMaterial(settings, fsx));
  return true;
}

// -> the listening server.  Limits against slow and large requests: 16 KiB of headers, 10 s for them, 30 s for the body of a request (readBody; the server's own
// requestTimeout is 300 s because a zone import may take that), 5 s keep-alive, 256 sockets.
export async function listen(app, router, { fsx = fs } = {}) {
  const s = app.settings;
  // dispatch answers every error itself; what it cannot (the connection is gone) must not take the process down
  const handler = (req, res) => {
    dispatch(app, router, req, res).catch((e) => {
      app.log.error(`dispatch failed: ${String(e?.message ?? e).slice(0, 200)}`);
      res.destroy();
    });
  };
  const opts = { maxHeaderSize: 16384, keepAliveTimeout: 5000, headersTimeout: 10000, requestTimeout: IMPORT_MS };
  const server = s['tls-cert']
    ? https.createServer({ ...opts, ...tlsMaterial(s, fsx) }, handler)
    : http.createServer(opts, handler);
  server.maxConnections = 256;
  const host = listenHost(s.listen);
  if (host === null) {
    try { if (fsx.lstatSync(s.listen).isSocket()) fsx.unlinkSync(s.listen); } catch { /* not there */ }
  }
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    const done = () => { server.off('error', reject); resolve(); };
    if (host === null) server.listen(s.listen, done);
    else server.listen(Number(/:(\d+)$/.exec(s.listen)[1]), host, done);
  });
  if (host === null) fsx.chmodSync(s.listen, 0o660);
  return server;
}

// Stop accepting; idle connections go at once, the requests that are running get graceMs to finish, then every connection is closed (a client that never finishes
// a TLS handshake would hold the process for ever)
export function closeServer(server, graceMs = 10000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => server.closeAllConnections(), graceMs);
    timer.unref();
    server.close(() => { clearTimeout(timer); resolve(); });
    server.closeIdleConnections();
  });
}

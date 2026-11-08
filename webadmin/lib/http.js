// The HTTP server (planning 2.1, 4.2, 8.2): node:http, one process.  Limits on the headers, the body and the time a request may take; the route table; the
// authentication and the rate limits before a handler runs; problem+json for every error; the security headers on every answer.

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { ApiError, problem, mapDbError } from './errors.js';
import { authenticate } from './session.js';
import { listenHost } from './config.js';

export const PREFIX = '/api/v1';
const BODY_LIMIT = 1 << 20;
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

// route: { method, path: '/datasets/:ds/zones/:zone', handler, auth: 'user' (default) | 'none', preTotp, sessionOnly, bodyLimit }
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

async function readBody(req, limit) {
  const declared = req.headers['content-length'];
  if (declared !== undefined && (!/^\d{1,12}$/.test(declared) || Number(declared) > limit)) throw new ApiError(413, 'too-large', `the body is limited to ${limit} octets`, { headers: { Connection: 'close' } });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new ApiError(413, 'too-large', `the body is limited to ${limit} octets`, { headers: { Connection: 'close' } });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
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
};

function send(ctx, status, headers, payload) {
  const { res, app } = ctx;
  if (res.headersSent) { res.end(); return; }
  const extra = { ...SECURITY, 'X-Request-Id': ctx.id, ...headers };
  if (app.settings['public-origin'].startsWith('https:')) extra['Strict-Transport-Security'] = 'max-age=31536000';
  ctx.status = status;
  res.writeHead(status, { ...extra, 'Content-Length': Buffer.byteLength(payload) });
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
    if (!req.url.startsWith(`${PREFIX}/`)) throw new ApiError(404, 'not-found', 'there is nothing here; the API is under /api/v1/');
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
      const raw = await readBody(req, m.route.bodyLimit ?? BODY_LIMIT);
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

// -> the listening server.  Limits against slow and large requests: 16 KiB of headers, 10 s for them, 30 s for a request, 5 s keep-alive, 256 sockets.
export async function listen(app, router, { fsx = fs } = {}) {
  const s = app.settings;
  // dispatch answers every error itself; what it cannot (the connection is gone) must not take the process down
  const handler = (req, res) => {
    dispatch(app, router, req, res).catch((e) => {
      app.log.error(`dispatch failed: ${String(e?.message ?? e).slice(0, 200)}`);
      res.destroy();
    });
  };
  const opts = { maxHeaderSize: 16384, keepAliveTimeout: 5000, headersTimeout: 10000, requestTimeout: 30000 };
  const server = s['tls-cert']
    ? https.createServer({ ...opts, cert: fsx.readFileSync(s['tls-cert']), key: fsx.readFileSync(s['tls-key']), minVersion: 'TLSv1.2' }, handler)
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

// A fake OpenID Connect provider on the loopback address, for the unit tests, the integration tests of both databases and the browser tests (plan 8.1; no network).  It
// serves the discovery document, the JWK Set, the authorization endpoint (which signs the user in at once as the person `idp.person` says) and the token endpoint (which checks
// the client password, the code, the redirect URI and the PKCE verifier like a provider does).  Every part can be spoiled: `idp.tamper` changes the claims or the header of the
// next ID token, `idp.sign` chooses the key and algorithm, `idp.mode` makes an endpoint misbehave. 

import crypto from 'node:crypto';
import http from 'node:http';

export const b64 = (buf) => Buffer.from(buf).toString('base64url');

// a compact JWS made by hand (also for the hostile tokens of the tests: alg none, HS256, a wrong key ...)
export function signJws(header, claims, { key, alg = header.alg, secret } = {}) {
  const input = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(claims))}`;
  let sig = Buffer.alloc(0);
  if (alg === 'RS256') sig = crypto.sign('sha256', Buffer.from(input), key);
  else if (alg === 'ES256') sig = crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' });
  else if (alg === 'EdDSA') sig = crypto.sign(null, Buffer.from(input), key);
  else if (alg === 'HS256') sig = crypto.createHmac('sha256', secret).update(input).digest();
  return `${input}.${b64(sig)}`;
}

const pair = {
  RS256: () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }),
  ES256: () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }),
  EdDSA: () => crypto.generateKeyPairSync('ed25519'),
};
const cache = {};
// key pairs are made once per process (an RSA key takes a moment)
export function keyPair(alg, n = 0) {
  const k = `${alg}${n}`;
  cache[k] ??= pair[alg]();
  return cache[k];
}

// ways to spoil the next ID token, by name (POST /__control {"tamper": "expired"} of the program e2e/idp.mjs; the unit tests set idp.tamper themselves)
export const TAMPERS = {
  'alg-none': (c, h) => { h.alg = 'none'; },
  hs256: (c, h) => { h.alg = 'HS256'; },
  'wrong-key': () => {},                                   // (control() changes the key that signs)
  expired: (c) => { c.exp = Math.floor(Date.now() / 1000) - 3600; },
  nonce: (c) => { c.nonce = 'not-the-nonce'; },
  aud: (c) => { c.aud = 'someone-else'; },
  iss: (c) => { c.iss = 'https://evil.example.test'; },
};

export class FakeIdp {
  // issuerHost: the host name the issuer is written with (the socket is always 127.0.0.1); path: a path in the issuer
  constructor({ clientId = 'kari-client', clientSecret = 'kari-secret-0123', issuerHost = '127.0.0.1', path = '', now = () => Date.now() } = {}) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.issuerHost = issuerHost;
    this.path = path;
    this.now = now;
    this.person = { sub: 'subject-1', amr: undefined };      // who the authorization endpoint signs in
    this.sign = { alg: 'RS256', n: 0, kid: 'k0' };           // the key that signs
    this.keysOffered = [{ alg: 'RS256', n: 0, kid: 'k0' }];  // the keys of the JWK Set
    this.codes = new Map();                                  // code -> the request it belongs to
    this.tamper = null;                                      // (claims, header, ctx) -> void: spoils the next ID token
    this.mode = {};                                          // endpoint -> 'status:NNN' | 'redirect' | 'html' | 'huge' | 'slow'
    this.discoveryExtra = {};
    this.log = [];                                           // the requests it saw: { method, path, query?, form?, auth? }
    this.authParams = null;                                  // the last authorization request
    this.issParam = false;                                   // add iss= to the authorization response
    this.authError = null;                                   // answer the authorization request with this error code
    this.tokenAuth = ['client_secret_basic'];
  }

  get issuer() { return `http://${this.issuerHost}:${this.port}${this.path}`; }

  get redirectUris() { return this.redirects ??= new Set(); }

  async start(port = 0, host = '127.0.0.1') {
    this.server = http.createServer((req, res) => { this.handle(req, res).catch((e) => { res.statusCode = 500; res.end(String(e)); }); });
    await new Promise((resolve) => { this.server.listen(port, host, resolve); });
    this.port = this.server.address().port;
    return this;
  }

  async stop() {
    this.server.closeAllConnections();
    await new Promise((resolve) => { this.server.close(resolve); });
  }

  jwk({ alg, n, kid }) {
    const j = keyPair(alg, n).publicKey.export({ format: 'jwk' });
    return { ...j, kid, use: 'sig', alg };
  }

  discovery() {
    const base = `http://${this.issuerHost}:${this.port}${this.path}`;
    return {
      issuer: this.issuer, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, jwks_uri: `${base}/jwks`,
      response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256', 'ES256', 'EdDSA'],
      token_endpoint_auth_methods_supported: this.tokenAuth, code_challenge_methods_supported: ['S256'], scopes_supported: ['openid', 'profile'],
      ...(this.issParam ? { authorization_response_iss_parameter_supported: true } : {}), ...this.discoveryExtra,
    };
  }

  // the ID token for a code record (nonce) with the claims of `idp.person`, spoiled by idp.tamper
  idToken(ctx = {}) {
    const t = Math.floor(this.now() / 1000);
    const claims = { iss: this.issuer, sub: this.person.sub, aud: this.clientId, exp: t + 300, iat: t, nonce: ctx.nonce, ...(this.person.amr ? { amr: this.person.amr } : {}), ...(this.person.extra ?? {}) };
    const header = { alg: this.sign.alg, typ: 'JWT', kid: this.sign.kid };
    this.tamper?.(claims, header, ctx);
    return signJws(header, claims, { key: keyPair(this.sign.alg, this.sign.n).privateKey, alg: header.alg === this.sign.alg ? this.sign.alg : header.alg, secret: this.clientSecret });
  }

  // the control of a provider run as a program: who signs in, what the token says, how it is spoiled
  control(c) {
    if ('sub' in c) this.person.sub = c.sub;
    if ('amr' in c) this.person.amr = c.amr ?? undefined;
    if ('authError' in c) this.authError = c.authError;
    if ('issParam' in c) this.issParam = Boolean(c.issParam);
    if ('tamper' in c) {
      if (c.tamper !== null && !Object.hasOwn(TAMPERS, c.tamper)) throw new Error(`no such tamper ${c.tamper}`);
      this.tamper = c.tamper === null ? null : TAMPERS[c.tamper];
      this.sign = c.tamper === 'wrong-key' ? { alg: 'RS256', n: 7, kid: 'k0' } : { alg: 'RS256', n: 0, kid: 'k0' };
    }
  }

  async handle(req, res) {
    const u = new URL(req.url, 'http://x');
    const route = u.pathname.slice(this.path.length);
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString('utf8');
    const entry = { method: req.method, path: route, query: Object.fromEntries(u.searchParams), form: body ? Object.fromEntries(new URLSearchParams(body)) : undefined, auth: req.headers.authorization };
    this.log.push(entry);
    const json = (status, doc, headers = {}) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }); res.end(JSON.stringify(doc)); };
    const m = this.mode[route];
    if (m?.startsWith('status:')) { res.writeHead(Number(m.slice(7))); res.end('no'); return; }
    if (m === 'redirect') { res.writeHead(302, { Location: `http://${this.issuerHost}:${this.port}${this.path}${route}` }); res.end(); return; }
    if (m === 'html') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html>'); return; }
    if (m === 'array') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('[1]'); return; }
    if (m === 'huge') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(`{"x":"${'a'.repeat(2 << 20)}"}`); return; }
    if (m === 'slow') { return; }                                     // never answers

    if (route === '/__control' && req.method === 'POST' && this.controllable) {
      try { this.control(JSON.parse(body)); json(200, { ok: true }); } catch (e) { json(400, { error: String(e.message) }); }
      return;
    }
    if (route === '/.well-known/openid-configuration') { json(200, this.discovery()); return; }
    if (route === '/jwks') { json(200, { keys: this.keysOffered.map((k) => this.jwk(k)) }); return; }

    if (route === '/authorize') {
      const q = entry.query;
      this.authParams = q;
      if (q.response_type !== 'code' || q.client_id !== this.clientId || !q.state || !q.nonce || q.code_challenge_method !== 'S256' || !q.code_challenge || !(q.scope ?? '').split(' ').includes('openid')) {
        json(400, { error: 'invalid_request' });
        return;
      }
      if (!this.redirectUris.has(q.redirect_uri)) { json(400, { error: 'invalid_redirect_uri' }); return; }
      const to = new URL(q.redirect_uri);
      to.searchParams.set('state', q.state);
      if (this.issParam) to.searchParams.set('iss', this.issuer);
      if (this.authError) {
        to.searchParams.set('error', this.authError);
      } else {
        const code = crypto.randomBytes(16).toString('hex');
        this.codes.set(code, { nonce: q.nonce, challenge: q.code_challenge, redirect: q.redirect_uri, used: false, person: { ...this.person } });
        to.searchParams.set('code', code);
      }
      res.writeHead(302, { Location: to.href });
      res.end();
      return;
    }

    if (route === '/token' && req.method === 'POST') {
      const f = entry.form ?? {};
      let id = f.client_id;
      let secret = f.client_secret;
      if (req.headers.authorization?.startsWith('Basic ')) {
        const [i, s] = Buffer.from(req.headers.authorization.slice(6), 'base64').toString().split(':');
        id = decodeURIComponent(i.replace(/\+/g, ' '));
        secret = decodeURIComponent(s.replace(/\+/g, ' '));
      }
      if (id !== this.clientId || secret !== this.clientSecret) { json(401, { error: 'invalid_client' }); return; }
      const rec = this.codes.get(f.code);
      if (f.grant_type !== 'authorization_code' || !rec || rec.used) { json(400, { error: 'invalid_grant' }); return; }
      rec.used = true;
      if (f.redirect_uri !== rec.redirect) { json(400, { error: 'invalid_grant' }); return; }
      if (crypto.createHash('sha256').update(f.code_verifier ?? '', 'ascii').digest('base64url') !== rec.challenge) { json(400, { error: 'invalid_grant' }); return; }
      const saved = this.person;
      this.person = rec.person;
      try {
        json(200, { access_token: 'at-' + crypto.randomBytes(8).toString('hex'), token_type: this.mode.tokenType ?? 'Bearer', expires_in: 300, ...(this.mode.noIdToken ? {} : { id_token: this.idToken({ nonce: rec.nonce }) }) });
      } finally {
        this.person = saved;
      }
      return;
    }
    res.writeHead(404);
    res.end();
  }
}


// OpenID Connect providers (item F, milestone M5; plan 5.5): the discovery document and the JWK Set of each provider, fetched with limits and cached; the authorization
// request (code flow with PKCE, RFC 7636); the exchange of the code; the check of the ID token (jwt.js).  The provider's documents are the text of another party: they are
// read with a size and a time limit, never followed through a redirect, and every address in them is checked before it is used.  No package: the global fetch of Node.
//
// Sources: OpenID Connect Core 1.0 (3.1.2.1 the request, 3.1.3.1 the token request, 3.1.3.3 the response, 3.1.3.7 the checks), OpenID Connect Discovery 1.0 (section 4: the
// document is at <issuer>/.well-known/openid-configuration and its `issuer` must be the issuer it was fetched for; section 3: the fields), RFC 6749 (the token request, 2.3.1 the
// client password), RFC 7636 (PKCE), RFC 9207 (the `iss` parameter of the authorization response).

import crypto from 'node:crypto';
import { Semaphore } from './crypto.js';
import { importJwks, verifyIdToken, SUPPORTED_ALGS, TokenError } from './jwt.js';

// kind: 'unavailable' (the provider could not be reached or spoke nonsense: try later) or 'failed' (the provider said no, or the token was not acceptable)
export class OidcError extends Error {
  constructor(kind, detail) {
    super(detail);
    this.kind = kind;
  }
}

const FETCH_MS = 10000;
const DISCOVERY_MAX = 64 << 10;
const JWKS_MAX = 256 << 10;
const TOKEN_MAX = 128 << 10;
const DISCOVERY_TTL_MS = 24 * 3600 * 1000;
const JWKS_TTL_MS = 24 * 3600 * 1000;
const JWKS_MIN_GAP_MS = 60000;           // plan 5.5: a key set is fetched again for an unknown kid at most once a minute
const RETRY_GAP_MS = 10000;              // after a failure the provider is left alone for this long

const isLoopbackHost = (h) => h === 'localhost' || h === '[::1]' || /^127\.\d+\.\d+\.\d+$/.test(h);
const isIpLiteral = (h) => h.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(h);

// An address from the provider's document (or the issuer): absolute, https (http only when the issuer itself is an http address on this machine, as the tests use), no
// credentials, no fragment, and a name, not an IP address (an https provider cannot send us to a machine of our own network by number).  -> the URL as text.
export function checkEndpoint(text, issuer) {
  let u;
  try { u = new URL(text); } catch { throw new OidcError('unavailable', 'an address in the provider document is not a URL'); }
  if (typeof text !== 'string' || text.length > 2048) throw new OidcError('unavailable', 'an address in the provider document is too long');
  const iss = new URL(issuer);
  const local = iss.protocol === 'http:';                 // (config.js: http only for this machine)
  if (local ? !(u.protocol === 'http:' || u.protocol === 'https:') || !isLoopbackHost(u.hostname) : u.protocol !== 'https:') {
    throw new OidcError('unavailable', `the provider document names ${u.protocol}//${u.host}, which is not allowed for this issuer`);
  }
  if (u.username || u.password || u.hash) throw new OidcError('unavailable', 'an address in the provider document has credentials or a fragment');
  if (!local && isIpLiteral(u.hostname)) throw new OidcError('unavailable', 'an address in the provider document is an IP address');
  return u.href;
}

// One GET or POST with a time and a size limit and no redirect.  -> { status, text }.  Anything wrong with the transport is OidcError('unavailable').
export async function fetchLimited(doFetch, url, { method = 'GET', headers = {}, body, maxBytes, timeoutMs = FETCH_MS } = {}) {
  let res;
  try {
    res = await doFetch(url, { method, headers: { Accept: 'application/json', ...headers }, body, redirect: 'manual', credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new OidcError('unavailable', `${method} ${new URL(url).host}: ${e?.cause?.code ?? e?.name ?? 'failed'}`);
  }
  if (res.status >= 300 && res.status < 400) {
    try { await res.body?.cancel(); } catch { /* the stream is gone already */ }
    throw new OidcError('unavailable', `${new URL(url).host} answered with a redirect (${res.status}), which is not followed`);
  }
  const chunks = [];
  let size = 0;
  try {
    if (res.body) {
      for await (const chunk of res.body) {
        size += chunk.length;
        if (size > maxBytes) {
          throw new OidcError('unavailable', `${new URL(url).host}: the answer is longer than ${maxBytes} octets`);
        }
        chunks.push(chunk);
      }
    }
  } catch (e) {
    throw e instanceof OidcError ? e : new OidcError('unavailable', `${new URL(url).host}: the answer was cut off`);
  }
  return { status: res.status, type: res.headers.get('content-type') ?? '', text: Buffer.concat(chunks).toString('utf8') };
}

const json = (r, what) => {
  if (!/^application\/(?:[a-z0-9.+-]+\+)?json\b/i.test(r.type)) throw new OidcError('unavailable', `${what} is not JSON (${r.type.slice(0, 40) || 'no content type'})`);
  try {
    const v = JSON.parse(r.text);
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
    return v;
  } catch {
    throw new OidcError('unavailable', `${what} is not a JSON object`);
  }
};

const formEncode = (o) => new URLSearchParams(o).toString();
// RFC 6749 section 2.3.1: the client id and secret are form-urlencoded before they are joined and encoded in base64
const basicAuth = (id, secret) => `Basic ${Buffer.from(`${encodeURIComponent(id).replace(/%20/g, '+')}:${encodeURIComponent(secret).replace(/%20/g, '+')}`).toString('base64')}`;

class Provider {
  // c: { name, issuer, clientId, clientSecret, scopes, label, mfa }
  constructor(c, mgr) {
    Object.assign(this, c);
    this.mgr = mgr;
    this.disc = null;                 // { doc, at }
    this.jwks = null;                 // { keys, at }
    this.discPending = null;
    this.jwksPending = null;
    this.failedAt = 0;
    this.jwksTriedAt = 0;
    this.lastError = null;
  }

  // the discovery document, once and then once a day; a failure is remembered for ten seconds so that a provider that is down is not asked for every request
  meta() {
    const now = this.mgr.now();
    if (this.disc && now - this.disc.at < DISCOVERY_TTL_MS) return Promise.resolve(this.disc.doc);
    if (this.discPending) return this.discPending;
    if (now - this.failedAt < RETRY_GAP_MS && this.lastError) return this.disc ? Promise.resolve(this.disc.doc) : Promise.reject(this.lastError);
    this.discPending = this.loadMeta().then((doc) => {
      this.disc = { doc, at: this.mgr.now() };
      this.lastError = null;
      return doc;
    }, (e) => {
      this.failedAt = this.mgr.now();
      this.lastError = e;
      if (this.disc) return this.disc.doc;                    // a stale document is better than none
      throw e;
    }).finally(() => { this.discPending = null; });
    return this.discPending;
  }

  async loadMeta() {
    const url = `${this.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
    const r = await fetchLimited(this.mgr.fetch, checkEndpoint(url, this.issuer), { maxBytes: DISCOVERY_MAX });
    if (r.status !== 200) throw new OidcError('unavailable', `discovery answered ${r.status}`);
    const d = json(r, 'the discovery document');
    // Discovery section 4.3: the issuer in the document must be identical to the one it was fetched for
    if (d.issuer !== this.issuer) throw new OidcError('unavailable', 'the discovery document names another issuer');
    const doc = {
      authorization_endpoint: checkEndpoint(d.authorization_endpoint, this.issuer),
      token_endpoint: checkEndpoint(d.token_endpoint, this.issuer),
      jwks_uri: checkEndpoint(d.jwks_uri, this.issuer),
      issParam: d.authorization_response_iss_parameter_supported === true,
      auth: 'basic',
    };
    if (Array.isArray(d.response_types_supported) && !d.response_types_supported.includes('code')) throw new OidcError('unavailable', 'the provider does not offer the authorization code flow');
    // PKCE with S256 is not optional here
    if (Array.isArray(d.code_challenge_methods_supported) && !d.code_challenge_methods_supported.includes('S256')) throw new OidcError('unavailable', 'the provider does not offer PKCE with S256');
    if (Array.isArray(d.id_token_signing_alg_values_supported) && !d.id_token_signing_alg_values_supported.some((a) => SUPPORTED_ALGS.includes(a))) {
      throw new OidcError('unavailable', `the provider signs ID tokens with ${d.id_token_signing_alg_values_supported.slice(0, 8).join(', ')} only; this service takes ${SUPPORTED_ALGS.join(', ')}`);
    }
    const methods = d.token_endpoint_auth_methods_supported;
    if (Array.isArray(methods) && !methods.includes('client_secret_basic')) {
      if (methods.includes('client_secret_post')) doc.auth = 'post';
      else throw new OidcError('unavailable', 'the token endpoint takes neither client_secret_basic nor client_secret_post');
    }
    return doc;
  }

  // the keys; refetched when asked to (an unknown kid) if the last fetch was more than a minute ago, and once a day
  async keys({ refetch = false } = {}) {
    const now = this.mgr.now();
    if (this.jwks && !(refetch && now - this.jwksTriedAt >= JWKS_MIN_GAP_MS) && now - this.jwks.at < JWKS_TTL_MS) return this.jwks.keys;
    if (this.jwksPending) return this.jwksPending;
    if (this.jwks && now - this.jwksTriedAt < JWKS_MIN_GAP_MS) return this.jwks.keys;
    if (!this.jwks && this.jwksError && now - this.jwksTriedAt < RETRY_GAP_MS) throw this.jwksError;
    this.jwksTriedAt = now;
    this.jwksPending = (async () => {
      const meta = await this.meta();
      const r = await fetchLimited(this.mgr.fetch, meta.jwks_uri, { maxBytes: JWKS_MAX });
      if (r.status !== 200) throw new OidcError('unavailable', `the key set answered ${r.status}`);
      const keys = importJwks(json(r, 'the key set'));
      if (keys.length === 0) throw new OidcError('unavailable', 'the key set has no key this service can use');
      this.jwks = { keys, at: this.mgr.now() };
      this.jwksError = null;
      return keys;
    })().finally(() => { this.jwksPending = null; });
    try {
      return await this.jwksPending;
    } catch (e) {
      this.jwksError = e;
      if (this.jwks) return this.jwks.keys;
      throw e;
    }
  }

  // the address to send the browser to (Core 3.1.2.1)
  async authorizationUrl({ redirectUri, state, nonce, challenge }) {
    const meta = await this.meta();
    const u = new URL(meta.authorization_endpoint);
    const p = { response_type: 'code', client_id: this.clientId, redirect_uri: redirectUri, scope: this.scopes.join(' '), state, nonce, code_challenge: challenge, code_challenge_method: 'S256' };
    for (const [k, v] of Object.entries(p)) u.searchParams.set(k, v);
    return u.href;
  }

  // the code for the ID token (Core 3.1.3.1, RFC 6749 section 4.1.3, RFC 7636 section 4.5) -> the ID token as text
  async exchange({ code, verifier, redirectUri }) {
    const meta = await this.meta();
    const form = { grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: verifier };
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (meta.auth === 'basic') headers.Authorization = basicAuth(this.clientId, this.clientSecret);
    else { form.client_id = this.clientId; form.client_secret = this.clientSecret; }
    const r = await this.mgr.limit.run(() => fetchLimited(this.mgr.fetch, meta.token_endpoint, { method: 'POST', headers, body: formEncode(form), maxBytes: TOKEN_MAX }));
    let doc;
    try { doc = json(r, 'the token response'); } catch (e) {
      if (r.status >= 500) throw new OidcError('unavailable', `the token endpoint answered ${r.status}`);
      throw e;
    }
    if (r.status !== 200) {
      // RFC 6749 section 5.2: {"error": "invalid_grant"}; only the code of the error is kept (it is the provider's text)
      const err = typeof doc.error === 'string' && /^[A-Za-z0-9_.-]{1,40}$/.test(doc.error) ? doc.error : 'unknown';
      throw new OidcError(r.status >= 500 ? 'unavailable' : 'failed', `the token endpoint refused the code (${r.status}, ${err})`);
    }
    // Core 3.1.3.3: token_type Bearer, and the ID token
    if (typeof doc.token_type !== 'string' || doc.token_type.toLowerCase() !== 'bearer') throw new OidcError('failed', 'the token response has another token_type than Bearer');
    if (typeof doc.id_token !== 'string' || doc.id_token === '') throw new OidcError('failed', 'the token response has no ID token');
    return doc.id_token;
  }

  // Core 3.1.3.7: -> { sub, amr, ... }; the key set is fetched again once if the token names a key it does not have
  async verify(idToken, nonce) {
    const args = { issuer: this.issuer, clientId: this.clientId, nonce, now: this.mgr.now() };
    const refused = (e) => new OidcError('failed', `the ID token was refused: ${e instanceof TokenError ? e.reason : 'error'}`);
    try {
      return verifyIdToken(idToken, { ...args, keys: await this.keys() });
    } catch (e) {
      if (!(e instanceof TokenError)) throw e;                   // (the key set could not be had: unavailable)
      if (!e.refetch) throw refused(e);
      let keys;
      try { keys = await this.keys({ refetch: true }); } catch { throw refused(e); }
      try { return verifyIdToken(idToken, { ...args, keys }); } catch (e2) { throw refused(e2); }
    }
  }
}

// The providers of a running service.  configure() takes the list the configuration and the secret files gave; a provider that has not changed keeps what it fetched.
export class Oidc {
  constructor({ fetch = globalThis.fetch, now = Date.now, log = null } = {}) {
    this.fetch = fetch;
    this.now = now;
    this.log = log;
    this.providers = new Map();
    this.limit = new Semaphore(8, 32);             // token requests in flight: a burst of callbacks does not become a burst towards the provider
  }

  // list: [{ name, issuer, clientId, clientSecret, scopes, label, mfa }]
  configure(list) {
    const next = new Map();
    for (const c of list) {
      const old = this.providers.get(c.name);
      const same = old && old.issuer === c.issuer && old.clientId === c.clientId && old.clientSecret === c.clientSecret;
      if (same) Object.assign(old, { scopes: c.scopes, label: c.label, mfa: c.mfa });
      next.set(c.name, same ? old : new Provider(c, this));
    }
    this.providers = next;
  }

  get(name) { return this.providers.get(name); }

  list() { return [...this.providers.values()].map((p) => ({ name: p.name, label: p.label, issuer: p.issuer })); }

  byIssuer(issuer) { return [...this.providers.values()].find((p) => p.issuer === issuer); }

  // the documents of every provider, now, so that a problem is in the log at the start and the first sign-in is fast.  Never throws.
  async prefetch() {
    await Promise.all([...this.providers.values()].map(async (p) => {
      try {
        await p.meta();
        await p.keys();
        this.log?.info(`oidc: provider ${p.name} (${p.issuer}) is reachable`);
      } catch (e) {
        this.log?.warn(`oidc: provider ${p.name} (${p.issuer}) cannot be used yet: ${String(e.message).slice(0, 200)}`);
      }
    }));
  }
}

// ---- the values of one flow
export const newSecret = () => crypto.randomBytes(32).toString('base64url');
export const pkceChallenge = (verifier) => crypto.createHash('sha256').update(verifier, 'ascii').digest('base64url');

// api.js: the client of /api/v1 (planning 4.4).  Same origin, so the browser sends the session cookie itself; an unsafe request carries the CSRF token (kept in
// memory only) and the browser adds Origin.  Every answer that is not 2xx is an RFC 9457 problem document and becomes an ApiProblem; a network failure or an
// answer that is not JSON becomes one too (code "network", "timeout", "bad-response"), so a view handles one kind of error.

export const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
export const enc = encodeURIComponent;

export class ApiProblem extends Error {
  // status 0: no answer (network, timeout)
  constructor({ status, code, title, detail, errors, requestId, retryAfter }) {
    super(detail ?? title ?? code);
    this.name = 'ApiProblem';
    this.status = status;
    this.code = code;
    this.title = title;
    this.detail = detail;
    this.errors = Array.isArray(errors) ? errors : [];
    this.requestId = requestId;
    this.retryAfter = retryAfter;
    this.renewed = false;                      // set when the user signed in again after a 401: the request itself was not repeated
  }
}

// Retry-After: delta-seconds (RFC 9110 section 10.2.3) or an HTTP date -> seconds, or undefined
export function retryAfter(value, nowMs) {
  if (value === null || value === undefined) return undefined;
  if (/^\d{1,9}$/.test(value)) return Number(value);
  const t = Date.parse(value);
  return Number.isNaN(t) ? undefined : Math.max(0, Math.ceil((t - nowMs) / 1000));
}

// the code of a problem document: "urn:karidns:api:<code>" -> code
const codeOf = (type) => (typeof type === 'string' && type.startsWith('urn:karidns:api:') ? type.slice('urn:karidns:api:'.length) : 'unknown');

// opts: { fetch, base, now, onUnauthenticated(): Promise<'same'|'other'|'cancel'>, onActivity(ms), timeoutMs }
export function createApi(opts) {
  const { fetch: doFetch, base = '/api/v1', now = Date.now, onUnauthenticated, onActivity, timeoutMs = 60000 } = opts;
  let csrf = null;

  async function once(method, path, { body, query }) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
    const qs = params.toString();
    const url = base + path + (qs ? `?${qs}` : '');
    const headers = { Accept: 'application/json, application/problem+json' };
    const init = { method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(timeoutMs) };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    if (UNSAFE.has(method) && csrf) headers['X-KariDNS-CSRF'] = csrf;
    let res;
    try {
      res = await doFetch(url, init);
    } catch (e) {
      throw new ApiProblem({ status: 0, code: e?.name === 'TimeoutError' ? 'timeout' : 'network' });
    }
    if (res.status !== 401) onActivity?.(now());
    const rid = res.headers.get('X-Request-Id') ?? undefined;
    if (res.status === 204) return null;
    let doc;
    try { doc = await res.json(); } catch { doc = undefined; }
    if (res.ok) {
      if (doc === undefined) throw new ApiProblem({ status: res.status, code: 'bad-response', requestId: rid });
      return doc;
    }
    if (doc === undefined || typeof doc !== 'object' || doc === null) {
      throw new ApiProblem({ status: res.status, code: res.status === 429 || res.status === 503 ? 'busy' : 'bad-response', requestId: rid, retryAfter: retryAfter(res.headers.get('Retry-After'), now()) });
    }
    throw new ApiProblem({
      status: res.status, code: codeOf(doc.type), title: doc.title, detail: doc.detail, errors: doc.errors, requestId: doc.request_id ?? rid,
      retryAfter: retryAfter(res.headers.get('Retry-After'), now()),
    });
  }

  // quiet: no sign-in dialog and no repeat after a 401 / stale token (the login, the first look at /auth/me, the logout: the caller handles the refusal)
  async function request(method, path, { body, query, quiet = false } = {}) {
    try {
      return await once(method, path, { body, query });
    } catch (e) {
      if (!(e instanceof ApiProblem) || quiet) throw e;
      // a stale CSRF token (the session was replaced in another tab): ask for the current one and repeat the request once; nothing was done by the refused one
      if (e.status === 403 && e.code === 'csrf' && UNSAFE.has(method)) {
        const me = await once('GET', '/auth/me', {});
        csrf = me?.session?.csrf ?? csrf;
        return once(method, path, { body, query });
      }
      if (e.status === 401 && e.code === 'unauthenticated' && onUnauthenticated) {
        const outcome = await onUnauthenticated();
        // the same person signed in again: a read is repeated; a write is not (the user decides again), the caller is told
        if (outcome === 'same' && !UNSAFE.has(method)) return once(method, path, { body, query });
        e.renewed = outcome === 'same';
      }
      throw e;
    }
  }

  return {
    get: (path, o) => request('GET', path, o),
    post: (path, body, o) => request('POST', path, { ...o, body }),
    put: (path, body, o) => request('PUT', path, { ...o, body }),
    patch: (path, body, o) => request('PATCH', path, { ...o, body }),
    del: (path, o) => request('DELETE', path, o),
    setCsrf(token) { csrf = token ?? null; },
    hasCsrf: () => csrf !== null,
  };
}

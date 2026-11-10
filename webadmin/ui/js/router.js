// router.js: hash routes (F-4): "#/zones/main/example.test" is the route "zones" with ds = main and zone = example.test.  Zone names never reach the server's or a
// proxy's log, and the static server needs no fallback.  Links are built here only, from encodeURIComponent of each part (5.2 rule 2); a part that does not decode
// makes the route "notfound", never an exception.  Pure functions, no DOM.

// patterns: [{ name, pattern: '/zones/:ds/:zone' }] -> { name, params, query } | { name: 'notfound' }
export function parse(hash, table) {
  const raw = String(hash ?? '').replace(/^#/, '');
  const [pathPart, ...qs] = raw.split('?');
  const path = pathPart === '' ? '/' : pathPart;
  if (!path.startsWith('/')) return { name: 'notfound', params: {}, query: {} };
  const segs = path === '/' ? [] : path.slice(1).split('/');
  const decoded = [];
  for (const s of segs) {
    try { decoded.push(decodeURIComponent(s)); } catch { return { name: 'notfound', params: {}, query: {} }; }
  }
  // a part that is "." or ".." would be taken out of the path of a request by the browser (RFC 3986 section 5.2.4; the URL standard does so for %2e too), so that
  // /datasets/main/zones/.. + /reload would reach /datasets/main/reload: there is no such zone name, and no such route
  if (decoded.some((d) => d === '.' || d === '..')) return { name: 'notfound', params: {}, query: {} };
  for (const r of table) {
    const pat = r.pattern === '/' ? [] : r.pattern.slice(1).split('/');
    if (pat.length !== decoded.length) continue;
    const params = {};
    if (pat.every((p, i) => (p.startsWith(':') ? ((params[p.slice(1)] = decoded[i]), decoded[i] !== '') : p === decoded[i]))) {
      return { name: r.name, params, query: Object.fromEntries(new URLSearchParams(qs.join('?'))) };
    }
  }
  return { name: 'notfound', params: {}, query: {} };
}

// -> "#/zones/main/example.test?x=1" for ('zones', { ds, zone }, { x: 1 }); an unknown route is an Error (a bug in the caller, not data)
export function href(name, params, query, table) {
  const r = table.find((e) => e.name === name);
  if (!r) throw new Error(`router: no route ${name}`);
  const path = r.pattern === '/' ? '/' : r.pattern.replace(/:([a-z_]+)/g, (_, k) => {
    if (params?.[k] === undefined) throw new Error(`router: ${name} needs ${k}`);
    return encodeURIComponent(String(params[k]));
  });
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== null && v !== '') q.set(k, String(v));
  const qs = q.toString();
  return `#${path}${qs ? `?${qs}` : ''}`;
}

// the router of a page: win has location.hash and addEventListener('hashchange'); on(route) is called for every change, with the first call at start()
export function createRouter(win, table, on) {
  const current = () => parse(win.location.hash, table);
  return {
    table,
    current,
    href: (name, params, query) => href(name, params, query, table),
    go(name, params, query) { win.location.hash = href(name, params, query, table); },
    // the same place again (a language change, a re-login)
    refresh() { on(current()); },
    start() {
      win.addEventListener('hashchange', () => on(current()));
      on(current());
    },
  };
}

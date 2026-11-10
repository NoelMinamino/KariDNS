// ui_boot.js: the GUI on the fake DOM against a scripted API, for the tests of the zone screens (ui_zones.test.js).  `routes` maps "METHOD /path" (without /api/v1 and
// without the query) to a reply or a function (body, url) -> reply; /auth/me, /version and a sign-in are there already.

import { createApp } from '../ui/js/app.js';
import { GUI_VERSION } from '../ui/js/version.js';
import { makeEnv, makeClock, makeBroadcast, FakeStorage, reply, problem, flush, findAll, byText } from './fakedom.js';

export const POLICY = {
  id: 1, name: 'all-types', allowed_types: ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'SRV', 'TXT'], allow_wildcard: true, allow_delegation: true, allow_dname: false, apex_editable: true,
  ttl_min: 0, ttl_max: 2147483647, max_rr: null,
};
export const PRINCIPAL = { id: 7, kind: 'user', name: 'alice', display_name: 'Alice A.', email: null, disabled: false };
export const GRANT_GLOBAL = { id: 1, role: 'global_master', dataset: null, zone: null, suffix: null, policy: POLICY, via: null };
export const VERSION = {
  api: 1, version: GUI_VERSION, tools: { 'karidns-zone': 'karidns-zone 0.6.0' }, datasets: ['main'], types: ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'SRV', 'TXT'],
  ui: { reload_after_change: false, require_totp: 'none', max_rrsets: 1000, max_records: 1000, zone_text_limit: 1024 },
};

export const meDoc = (clock, { grants = [GRANT_GLOBAL], global = true } = {}) => ({
  api: 1, principal: PRINCIPAL, groups: [], tenants: [], capabilities: { global, manage_principals: global, manage_policies: global, create_zones: global, grant_on: [] }, grants,
  session: { csrf: 'csrf-1', totp_ok: true, expires_at: new Date(clock.now() + 12 * 3600 * 1000).toISOString(), idle_timeout: 1800 },
});

export async function bootApp({ routes = {}, hash = '', me = {}, version = VERSION, languages = ['en'], storage } = {}) {
  const clock = makeClock();
  const st = { in: true };
  const handler = (method, url, body) => {
    const key = `${method} ${url.split('?')[0].replace('/api/v1', '')}`;
    const hit = routes[key];
    if (hit !== undefined) return typeof hit === 'function' ? hit(body, url) : hit;
    switch (key) {
      case 'GET /auth/me': return st.in ? reply(200, meDoc(clock, me)) : problem(401, 'unauthenticated');
      case 'GET /version': return reply(200, version);
      case 'POST /auth/logout': st.in = false; return reply(204, null);
      default: return problem(404, 'not-found');
    }
  };
  const env = makeEnv({ handler, languages, clock, storage: storage ?? new FakeStorage(), BroadcastChannel: makeBroadcast() });
  env.window.location.hash = hash;
  const app = createApp(env);
  await app.start();
  await flush();
  const root = env.document.getElementById('app');
  const ui = {
    env, app, root, clock, st, routes, calls: env.calls,
    text: () => root.textContent,
    q: (sel) => root.querySelector(sel),
    qa: (sel) => root.querySelectorAll(sel),
    button: (re, scope = env.document.body) => byText(scope, 'button', re),
    link: (re) => byText(root, 'a', re),
    dialogs: () => env.document.body.querySelectorAll('dialog').filter((d) => d.open),
    type(el, v) { el.value = v; },
    async click(el) { el.click(); await flush(); },
    async submit(form) { form.submit(); await flush(); },
    async go(h) { env.window.location.hash = h; await flush(); },
    input: (name, scope = root) => findAll(scope, (e) => ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.tagName) && e.getAttribute('name') === name)[0],
    last: (m, p) => [...env.calls].reverse().find((c) => c.method === m && c.url.includes(p)),
    count: (m, p) => env.calls.filter((c) => c.method === m && c.url.includes(p)).length,
    polite: () => env.document.body.children.find((c) => c.getAttribute('aria-live') === 'polite').textContent,
  };
  return ui;
}

export { reply, problem, flush, findAll, byText };

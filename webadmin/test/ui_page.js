// ui_page.js: the GUI on the fake DOM against the REAL service (a deployment of helpers.js), with a fetch that behaves like a browser: the cookie jar, Origin on what is not a
// read.  Shared by the tests that run the screens against the API (ui_zones_server.test.js, ui_hist_server.test.js).

import { ORIGIN } from './helpers.js';
import { createApp } from '../ui/js/app.js';
import { makeEnv, makeClock, makeBroadcast, FakeStorage, flush, findAll, byText } from './fakedom.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// a browser's fetch: the cookie jar, Origin on what is not a read
export function browserFetch(d) {
  const jar = { cookie: null };
  let inflight = 0;
  const f = async (url, init = {}) => {
    const headers = { ...(init.headers ?? {}) };
    if (jar.cookie) headers.Cookie = jar.cookie;
    if ((init.method ?? 'GET') !== 'GET') headers.Origin = ORIGIN;
    inflight++;
    try {
      const res = await fetch(d.origin + url, { ...init, headers, signal: undefined });
      for (const c of res.headers.getSetCookie()) {
        const m = /^karidns_session=([^;]*)/.exec(c);
        if (m) jar.cookie = m[1] ? `karidns_session=${m[1]}` : null;
      }
      return res;
    } finally {
      inflight--;
    }
  };
  return { fetch: f, idle: async () => { await flush(); while (inflight > 0) { await sleep(5); await flush(); } await flush(); } };
}

// the page at `hash`, started; -> a handle with the helpers the tests use
export async function page(d, hash) {
  const bf = browserFetch(d);
  const env = makeEnv({ handler: () => { throw new Error('unused'); }, clock: makeClock(), storage: new FakeStorage(), BroadcastChannel: makeBroadcast() });
  env.fetch = bf.fetch;
  env.window.location.hash = hash;
  const app = createApp(env);
  await app.start();
  await bf.idle();
  const root = env.document.getElementById('app');
  const ui = {
    env, app, root, idle: bf.idle,
    q: (sel) => root.querySelector(sel),
    qa: (sel) => root.querySelectorAll(sel),
    input: (name, scope = root) => findAll(scope, (e) => ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.tagName) && e.getAttribute('name') === name)[0],
    button: (re, scope = env.document.body) => byText(scope, 'button', re),
    link: (re) => byText(root, 'a', re),
    type(el, v) { el.value = v; },
    async click(el) { el.click(); await bf.idle(); },
    async submit(f) { f.submit(); await bf.idle(); },
    async go(h) { env.window.location.hash = h; await bf.idle(); },
    text: () => root.textContent,
    dialogs: () => env.document.body.querySelectorAll('dialog').filter((x) => x.open),
    errors: () => findAll(root, (e) => e.className === 'msg error' && !e.hidden).map((e) => e.textContent),
    form: (sel) => findAll(root, (e) => e.tagName === 'FORM').find((f) => f.querySelector(sel)),
  };
  return ui;
}

// app.js: the page.  createApp(env) wires the parts together (env is the browser: window, document, fetch, storage, BroadcastChannel, timers, clipboard; the tests give
// a fake one); the last lines start it when there is a real window.  Planning 4: hash routes, one API client, one session, the views of the screens.

import { h, link, fill, setDocument, setTitle, setLang, openDialog } from './dom.js';
import { createApi } from './api.js';
import { createSession } from './session.js';
import { createRouter } from './router.js';
import { createI18n } from './i18n.js';
import { duration, plain, render as renderText } from './format.js';
import { GUI_VERSION } from './version.js';
import { loginForm } from './views/login.js';
import { totpView } from './views/totp.js';
import { accountView } from './views/account.js';
import { aboutView } from './views/about.js';
import { homeView } from './views/home.js';
import { zonesView } from './views/zones.js';
import { zoneView } from './views/zone.js';
import { zoneImportView } from './views/zoneimport.js';
import { zoneSettingsView } from './views/zonesettings.js';
import { dnssecView } from './views/dnssec.js';
import { zoneCreateView } from './views/zonecreate.js';
import { serversView } from './views/servers.js';
import { createDrafts } from './draft.js';
import en from '../i18n/en.js';
import ja from '../i18n/ja.js';

export const ROUTES = [
  { name: 'home', pattern: '/' },
  { name: 'zones', pattern: '/zones' },
  { name: 'create', pattern: '/create/:ds' },
  { name: 'zone', pattern: '/zones/:ds/:zone' },
  { name: 'zone-import', pattern: '/zones/:ds/:zone/import' },
  { name: 'zone-settings', pattern: '/zones/:ds/:zone/settings' },
  { name: 'zone-dnssec', pattern: '/zones/:ds/:zone/dnssec' },
  { name: 'servers', pattern: '/servers' },
  { name: 'account', pattern: '/account' },
  { name: 'totp', pattern: '/account/totp' },
  { name: 'about', pattern: '/about' },
];
// the menu: [route, message id]; the zone pages belong to "Zones"
const NAV = [['home', 'nav.home'], ['zones', 'nav.zones'], ['servers', 'nav.servers'], ['account', 'nav.account'], ['about', 'nav.about']];
const IN_ZONES = new Set(['zones', 'zone', 'zone-import', 'zone-settings', 'zone-dnssec', 'create']);
const noop = () => {};

export function createApp(env) {
  const { window: win, document: doc, timers, now } = env;
  setDocument(doc);
  const i18n = createI18n({ catalogs: { en, ja }, storage: env.storage, languages: env.languages ?? [] });
  const t = i18n.t;
  let session = null;
  const api = createApi({ fetch: env.fetch, now, onActivity: (ms) => session.touch(ms), onUnauthenticated: () => session.reauth() });
  session = createSession({ api, timers, now, BroadcastChannel: env.BroadcastChannel ?? null });

  let route = null;                               // the current route, once the router has started
  let view = null;                                // the view on the screen: { node, dispose?, focus? }
  let startError = null;                          // the first request failed (no network)
  let notice = null;                              // a text shown above the sign-in form ("you were signed out in another tab")
  let drawnKey = null;
  let warnDialog = null;
  const politeEl = h('div', { class: 'sr-only', 'aria-live': 'polite', role: 'status' });
  const assertiveEl = h('div', { class: 'sr-only', 'aria-live': 'assertive', role: 'alert' });
  const root = doc.getElementById('app');

  const drafts = createDrafts();                  // the change sets being put together (F-13: memory only)
  session.guards.add(() => drafts.dirty());       // a page that is left with a draft asks first
  const ctx = {
    api, session, i18n, now, timers, drafts,
    flash: null,                                  // a text the next screen shows once
    router: null,
    announce(msg, level = 'polite') {
      const el = level === 'assertive' ? assertiveEl : politeEl;
      el.textContent = '';
      el.textContent = msg;
    },
    copy: (s) => env.clipboard.writeText(s),
  };
  const router = createRouter(win, ROUTES, (r) => { route = r; render(); });
  ctx.router = router;

  // ---------------------------------------------------------------- the screen
  const status = () => session.state.status;
  const authed = () => status() === 'in' || status() === 'expired';
  const forced = () => authed() && session.state.me.session?.totp_ok === false;

  function swap(next) {
    view?.dispose?.();
    view = next;
  }

  function brand() {
    return link(router.href('home'), { class: 'brand' }, t('app.name'));
  }

  function shell(title, content) {
    setTitle(`${title} - ${t('app.name')}`);
    const main = h('main', { id: 'main', tabindex: '-1' }, content);
    const skip = h('button', { type: 'button', class: 'skip', on: { click: () => main.focus() } }, t('app.skip'));
    const head = [brand()];
    if (authed() && !forced()) {
      const cur = route?.name;
      head.push(h('nav', { 'aria-label': t('nav.label') }, h('ul', null, NAV.map(([name, id]) => h('li', null, link(router.href(name), { 'aria-current': cur === name || (name === 'account' && cur === 'totp') || (name === 'zones' && IN_ZONES.has(cur)) ? 'page' : undefined }, t(id)))))));
    }
    if (authed()) {
      const me = session.state.me.principal;
      head.push(h('div', { class: 'who' }, h('span', null, ...i18n.parts('app.signed-in', { name: h('strong', null, renderText(me.display_name ?? me.name)) })),
        h('button', { type: 'button', on: { click: () => session.logout(false).catch((e) => ctx.announce(i18n.errorText(e), 'assertive')) } }, t('app.logout'))));
    }
    const banners = [];
    const v = session.state.version;
    if (v && v.version !== GUI_VERSION) banners.push(h('p', { class: 'banner', role: 'alert' }, t('app.reload'), ' ', h('button', { type: 'button', on: { click: () => win.location.reload() } }, t('app.reload-now'))));
    fill(root, skip, h('header', { class: 'top' }, head), banners, main, h('footer', null, t('app.footer', { version: GUI_VERSION })));
    return main;
  }

  function mount(title, v) {
    swap(v);
    const main = shell(title, v.node);
    if (v.focus) v.focus(); else main.focus();
  }

  function loginScreen() {
    const form = loginForm(ctx, { onDone: async (r) => {
      notice = null;
      if (!r.enrollmentRequired) await session.loadVersion().catch(noop);
      render();
    } });
    const card = h('section', { class: 'card narrow', 'aria-labelledby': 'login-title' }, h('h1', { id: 'login-title' }, t('login.title')), notice ? h('p', { class: 'notice', role: 'status' }, notice) : null, form.node);
    mount(t('login.title'), { node: card, focus: form.focus, dispose: form.dispose });
  }

  function simple(title, ...content) {
    mount(title, { node: h('section', { class: 'card' }, h('h1', null, title), content) });
  }

  function render() {
    drawnKey = keyOf();
    if (startError) {
      simple(t('app.name'), h('p', { class: 'msg error', role: 'alert' }, i18n.errorText(startError)), h('button', { type: 'button', on: { click: () => win.location.reload() } }, t('common.try-again')));
      return;
    }
    if (route === null || status() === 'unknown') {
      simple(t('app.name'), h('p', { role: 'status' }, t('common.loading')));
      return;
    }
    if (!authed()) { loginScreen(); return; }
    if (forced()) { const v = totpView(ctx, { forced: true }); mount(t('totp.title'), v); return; }
    switch (route.name) {
      case 'home': mount(t('nav.home'), homeView(ctx)); break;
      case 'zones': mount(t('zones.title'), zonesView(ctx, route)); break;
      case 'create': mount(t('create.title', { ds: plain(route.params.ds) }), zoneCreateView(ctx, route)); break;
      case 'zone': mount(plain(route.params.zone), zoneView(ctx, route)); break;
      case 'zone-import': mount(`${t('zone.sec-import')} - ${plain(route.params.zone)}`, zoneImportView(ctx, route)); break;
      case 'zone-settings': mount(`${t('zone.sec-settings')} - ${plain(route.params.zone)}`, zoneSettingsView(ctx, route)); break;
      case 'zone-dnssec': mount(`${t('zone.sec-dnssec')} - ${plain(route.params.zone)}`, dnssecView(ctx, route)); break;
      case 'servers': mount(t('servers.title'), serversView(ctx)); break;
      case 'account': mount(t('account.title'), accountView(ctx)); break;
      case 'totp': mount(t('totp.title'), totpView(ctx)); break;
      case 'about': mount(t('about.title'), aboutView(ctx)); break;
      default: simple(t('app.not-found'), h('p', null, link(router.href('home'), null, t('nav.home'))));
    }
  }

  // what decides whether the screen must be drawn again when the session changes (not a refresh of the same session)
  const keyOf = () => `${status() === 'expired' ? 'in' : status()}/${session.state.me?.principal.id}/${session.state.me?.session?.totp_ok}`;

  // ---------------------------------------------------------------- dialogs
  // a 401 anywhere: the sign-in form over the current screen; resolves 'same' (the same person: the work goes on), 'other' or 'cancel'
  function signInAgain() {
    return new Promise((resolve) => {
      let done = false;
      let form = null;
      const dlg = h('dialog', { class: 'modal', 'aria-labelledby': 'reauth-title' });
      const finish = (outcome) => {
        if (done) return;
        done = true;
        form.dispose();
        dlg.close();
        resolve(outcome);
      };
      form = loginForm(ctx, { onDone: (r) => finish(r.samePrincipal ? 'same' : 'other'), onCancel: () => finish('cancel') });
      fill(dlg, h('h2', { id: 'reauth-title' }, t('reauth.title')), h('p', null, t('reauth.text')), form.node);
      dlg.addEventListener('cancel', (ev) => { ev.preventDefault(); finish('cancel'); });
      openDialog(dlg);
      form.focus();
    });
  }
  session.setReauthHandler(signInAgain);

  function closeWarning() {
    if (warnDialog) { warnDialog.stop(); warnDialog.dlg.close(); }
    warnDialog = null;
  }

  // two minutes before the end of the session: how long is left, and "stay signed in" (one request, because the person asked)
  function warn({ at, kind }) {
    closeWarning();
    const left = h('strong', null, duration((at - now()) / 1000));
    const stay = h('button', { type: 'button', class: 'primary', on: { click: () => session.keepAlive().then(closeWarning, (e) => ctx.announce(i18n.errorText(e), 'assertive')) } }, t('warn.stay'));
    const dlg = h('dialog', { class: 'modal', 'aria-labelledby': 'warn-title' },
      h('h2', { id: 'warn-title' }, t(kind === 'max' ? 'warn.title-max' : 'warn.title')),
      h('p', null, ...i18n.parts(kind === 'max' ? 'warn.text-max' : 'warn.text', { left })),
      h('div', { class: 'actions' }, kind === 'max' ? null : stay, h('button', { type: 'button', on: { click: () => session.logout(false).catch(noop) } }, t('app.logout')), h('button', { type: 'button', on: { click: closeWarning } }, t('common.close'))));
    const iv = timers.setInterval(() => { left.textContent = duration((at - now()) / 1000); }, 1000);
    warnDialog = { dlg, stop: () => timers.clearInterval(iv) };
    dlg.addEventListener('close', () => { if (warnDialog?.dlg === dlg) { warnDialog.stop(); warnDialog = null; } });
    openDialog(dlg);
    ctx.announce(t(kind === 'max' ? 'warn.title-max' : 'warn.title'), 'assertive');
  }

  // ---------------------------------------------------------------- start
  session.on('change', () => {
    if (route === null) return;
    if (keyOf() !== drawnKey) {
      closeWarning();
      render();
      // the version is asked once per session, when the second step is done (before it the service answers 403)
      if (status() === 'in' && !forced() && !session.state.version) session.loadVersion().catch(noop);
    }
  });
  session.on('warn', warn);
  session.on('warn-clear', closeWarning);
  session.on('expired', () => { closeWarning(); session.reauth(); });
  // (the same person: the screen stays as it is, with what is on it; another person: it was redrawn for them by the change of the session, and starts at home)
  session.on('reauthenticated', (outcome) => { if (outcome === 'other') { drafts.clear(); router.go('home'); } });
  session.on('logout', () => drafts.clear());
  session.on('other-tab-logout', () => { drafts.clear(); notice = t('login.other-tab'); closeWarning(); render(); });
  session.on('other-tab-login', () => render());
  i18n.onChange((lang) => { setLang(lang); render(); });

  win.addEventListener('beforeunload', (ev) => {
    if (session.dirty()) { ev.preventDefault(); ev.returnValue = ''; }
  });
  // a proxy that injects a script, or a stylesheet from another place, breaks the page's policy (5.1): say so
  let cspShown = false;
  doc.addEventListener('securitypolicyviolation', (ev) => {
    if (cspShown) return;
    cspShown = true;
    doc.body.append(h('p', { class: 'banner csp-violation', role: 'alert' }, t('app.csp', { directive: String(ev.violatedDirective ?? '') })));
  });

  async function start() {
    setLang(i18n.lang);
    doc.body.append(politeEl, assertiveEl);
    session.open();
    render();
    try {
      if (await session.restore() && !forced()) await session.loadVersion().catch(noop);
    } catch (e) {
      startError = e;
    }
    router.start();
  }

  return { start, render, ctx, i18n, session, api, router };
}

// the page: start when there is one (the tests import this module without)
if (typeof window !== 'undefined' && window.document?.getElementById('app')) {
  let storage = null;
  try { storage = window.localStorage; } catch { /* storage is refused: the language choice lasts for the page only */ }
  createApp({
    window, document: window.document, fetch: window.fetch.bind(window), storage, BroadcastChannel: window.BroadcastChannel,
    timers: { setTimeout: window.setTimeout.bind(window), clearTimeout: window.clearTimeout.bind(window), setInterval: window.setInterval.bind(window), clearInterval: window.clearInterval.bind(window) },
    now: Date.now, clipboard: window.navigator.clipboard, languages: window.navigator.languages,
  }).start();
}

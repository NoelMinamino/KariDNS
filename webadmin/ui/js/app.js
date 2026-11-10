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
import { versionsView, versionView, versionDiffView } from './views/versions.js';
import { templatesView, templateView, templateNewView } from './views/templates.js';
import { zoneTemplateView } from './views/zonetemplate.js';
import { principalsView, policiesView, grantsView } from './views/admin.js';
import { principalView } from './views/adminprincipal.js';
import { zoneGrantsView } from './views/zonegrants.js';
import { auditView } from './views/audit.js';
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
  { name: 'zone-versions', pattern: '/zones/:ds/:zone/versions' },
  { name: 'zone-version', pattern: '/zones/:ds/:zone/versions/:n' },
  { name: 'zone-diff', pattern: '/zones/:ds/:zone/versions/:n/diff' },
  { name: 'zone-template', pattern: '/zones/:ds/:zone/template' },
  { name: 'zone-grants', pattern: '/zones/:ds/:zone/grants' },
  { name: 'templates', pattern: '/templates' },
  { name: 'template-new', pattern: '/templates/new' },
  { name: 'template', pattern: '/templates/:id' },
  { name: 'admin-users', pattern: '/admin/users' },
  { name: 'admin-groups', pattern: '/admin/groups' },
  { name: 'admin-policies', pattern: '/admin/policies' },
  { name: 'admin-grants', pattern: '/admin/grants' },
  { name: 'admin-principal', pattern: '/admin/principals/:id' },
  { name: 'audit', pattern: '/audit' },
  { name: 'servers', pattern: '/servers' },
  { name: 'account', pattern: '/account' },
  { name: 'totp', pattern: '/account/totp' },
  { name: 'about', pattern: '/about' },
];
// the menu: [route, message id]; the zone pages belong to "Zones"
// (the third is who sees the entry: everybody, global masters only, or the people who may read the audit log: global masters and domain masters)
const NAV = [['home', 'nav.home'], ['zones', 'nav.zones'], ['templates', 'nav.templates'], ['servers', 'nav.servers'], ['admin-users', 'nav.admin', 'global'], ['audit', 'nav.audit', 'audit'],
  ['account', 'nav.account'], ['about', 'nav.about']];
const IN_ZONES = new Set(['zones', 'zone', 'zone-import', 'zone-settings', 'zone-dnssec', 'zone-versions', 'zone-version', 'zone-diff', 'zone-template', 'zone-grants', 'create']);
// the entry of the menu a route belongs to
const sectionOf = (r) => (IN_ZONES.has(r) ? 'zones' : r === 'totp' ? 'account' : r.startsWith('admin-') ? 'admin-users' : r.startsWith('template') ? 'templates' : r);
const mayShow = (who, caps) => who === undefined || (who === 'global' ? caps?.global === true : caps?.global === true || (caps?.grant_on ?? []).length > 0);
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
  let providersAsked = null;
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
    // the identity providers of the service (GET /auth/providers, no login needed): [{ name, label }], asked once per page; a failure is no providers
    providers() {
      providersAsked ??= api.get('/auth/providers', { quiet: true }).then((r) => (Array.isArray(r?.providers) ? r.providers : []), () => { providersAsked = null; return []; });
      return providersAsked;
    },
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
      const caps = session.state.me.capabilities;
      head.push(h('nav', { 'aria-label': t('nav.label') }, h('ul', null, NAV.filter(([, , who]) => mayShow(who, caps)).map(([name, id]) => h('li', null, link(router.href(name), { 'aria-current': cur !== undefined && sectionOf(cur) === name ? 'page' : undefined }, t(id)))))));
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

  // where a sign-in with an identity provider comes back to: the place the person was at ("/zones/main/example.test"), the start page when that is where they are
  const returnRoute = () => (route === null || route.name === 'home' || route.name === 'notfound' ? '/' : String(win.location.hash ?? '').replace(/^#/, '') || '/');

  function loginScreen() {
    const form = loginForm(ctx, { route: returnRoute(), onDone: async (r) => {
      notice = null;
      if (!r.enrollmentRequired) await session.loadVersion().catch(noop);
      render();
    } });
    // the page the service sends the browser to when a sign-in with an identity provider did not work (/#/?oidc=failed): one text for each of three words
    const why = route?.query?.oidc;
    const oidcFailure = why === 'failed' || why === 'unavailable' || why === 'busy' ? h('p', { class: 'msg error', role: 'alert' }, t(`login.oidc-${why}`)) : null;
    const card = h('section', { class: 'card narrow', 'aria-labelledby': 'login-title' }, h('h1', { id: 'login-title' }, t('login.title')), notice ? h('p', { class: 'notice', role: 'status' }, notice) : null, oidcFailure, form.node);
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
      case 'zone-versions': mount(`${t('zone.sec-versions')} - ${plain(route.params.zone)}`, versionsView(ctx, route)); break;
      case 'zone-version': mount(`${t('versions.one-title', { n: plain(route.params.n) })} - ${plain(route.params.zone)}`, versionView(ctx, route)); break;
      case 'zone-diff': mount(`${t('zone.sec-versions')} - ${plain(route.params.zone)}`, versionDiffView(ctx, route)); break;
      case 'zone-template': mount(`${t('zone.sec-template')} - ${plain(route.params.zone)}`, zoneTemplateView(ctx, route)); break;
      case 'zone-grants': mount(`${t('zone.sec-grants')} - ${plain(route.params.zone)}`, zoneGrantsView(ctx, route)); break;
      case 'templates': mount(t('tpl.title'), templatesView(ctx, route)); break;
      case 'template-new': mount(t('tpl.new'), templateNewView(ctx)); break;
      case 'template': mount(t('tpl.one'), templateView(ctx, route)); break;
      case 'admin-users': mount(t('admin.users'), principalsView(ctx, route, 'user')); break;
      case 'admin-groups': mount(t('admin.groups'), principalsView(ctx, route, 'group')); break;
      case 'admin-policies': mount(t('admin.policies'), policiesView(ctx)); break;
      case 'admin-grants': mount(t('admin.grants'), grantsView(ctx, route)); break;
      case 'admin-principal': mount(t('admin.principal'), principalView(ctx, route)); break;
      case 'audit': mount(t('audit.title'), auditView(ctx, route)); break;
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
      form = loginForm(ctx, { route: returnRoute(), onDone: (r) => finish(r.samePrincipal ? 'same' : 'other'), onCancel: () => finish('cancel') });
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
  // (the screen is drawn again in the new language.  A control the person was using keeps the focus: the language is chosen with the arrow keys of a select, and a focus
  // that jumps to the top of the page after the first key is a keyboard trap in effect, WCAG 2.4.3 / 3.2.2)
  i18n.onChange((lang) => {
    setLang(lang);
    const name = doc.activeElement?.getAttribute?.('name');
    render();
    if (typeof name === 'string' && /^[a-z_]+$/.test(name)) doc.querySelector(`[name=${name}]`)?.focus();
  });

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

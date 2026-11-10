// S11: administration (planning 3): users, groups, record policies and grants, for global masters.  Everything the page shows is what the service answers; the
// service refuses what a person may not do (403), and the page hides it as a hint.  A domain master has no menu entry here: it manages the grants of its zones from the
// "Grants" section of the zone (zonegrants.js).

import { h, link, fill } from '../dom.js';
import { render } from '../format.js';
import { field, checkbox, message, problemNodes, confirmButton, busy, isGlobal } from '../widgets.js';
import { placeOnFields } from '../pointer.js';
import { policyBody, lookupPrincipal } from '../adminlib.js';
import { grantsTable, grantForm } from './grants.js';

const PASSWORD_MIN = 12;
const SEARCH = /^[A-Za-z0-9._@+:-]+$/;
const TABS = [['admin-users', 'admin.users'], ['admin-groups', 'admin.groups'], ['admin-policies', 'admin.policies'], ['admin-grants', 'admin.grants']];

// the frame: the title, the tabs, and the content under them.  A person who is not a global master gets a notice and no call is made.
export function adminFrame(ctx, active, ...content) {
  const { i18n, router } = ctx;
  const t = i18n.t;
  const nav = h('nav', { 'aria-label': t('admin.sections') }, h('ul', { class: 'tabs' }, TABS.map(([name, id]) => h('li', null, link(router.href(name), { 'aria-current': name === active ? 'page' : undefined }, t(id))))));
  return h('div', { class: 'stack' }, h('section', { class: 'card', 'aria-labelledby': 'admin-title' }, h('h1', { id: 'admin-title' }, t('admin.title')), nav), isGlobal(ctx) ? content : h('p', { class: 'notice' }, t('admin.global-only')));
}

const flashOf = (ctx) => { const f = ctx.flash ?? null; ctx.flash = null; return f; };

// ---------------------------------------------------------------------------------------------------------------------------------- users and groups
// kind: 'user' | 'group'
export function principalsView(ctx, { query }, kind) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const tab = kind === 'user' ? 'admin-users' : 'admin-groups';
  const box = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const flash = flashOf(ctx);
  let alive = true;

  function createForm() {
    const name = field({ label: t('admin.f-name'), name: 'name', required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('admin.f-name-hint') });
    const display = field({ label: t('admin.f-display'), name: 'display_name', maxlength: 255 });
    const email = field({ label: t('admin.f-email'), name: 'email', maxlength: 255, spellcheck: false, autocapitalize: 'none', inputmode: 'email' });
    const password = kind === 'user' ? field({ label: t('admin.f-password'), type: 'password', name: 'password', required: true, autocomplete: 'new-password', maxlength: 1024, hint: t('admin.f-password-hint', { min: PASSWORD_MIN }) }) : null;
    const err = message('error');
    const submit = h('button', { type: 'submit', class: 'primary' }, t(kind === 'user' ? 'admin.create-user' : 'admin.create-group'));
    const form = h('form', { class: 'stack', novalidate: true }, h('div', { class: 'grid' }, name.node, display.node, email.node, password?.node), err.node, h('div', { class: 'actions' }, submit));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(submit, async () => {
        err.set(null);
        for (const f of [name, display, email, password]) f?.setError(null);
        if (name.input.value.trim() === '') { name.setError(t('admin.need-name')); name.focus(); return; }
        if (password && [...password.input.value].length < PASSWORD_MIN) { password.setError(t('api.weak-password')); password.focus(); return; }
        const body = { kind, name: name.input.value.trim() };
        if (display.input.value.trim() !== '') body.display_name = display.input.value.trim();
        if (email.input.value.trim() !== '') body.email = email.input.value.trim();
        if (password) body.password = password.input.value;
        try {
          const r = await api.post('/principals', body);
          ctx.flash = t('admin.created', { name: r.principal.name });
          router.go('admin-principal', { id: String(r.principal.id) });
        } catch (e) {
          const map = { '/name': name, '/display_name': display, '/email': email };
          if (password) map['/password'] = password;
          const loose = e.errors?.length ? placeOnFields(e.errors, map) : [];
          if (e.code === 'weak-password') password?.setError(i18n.errorText(e));
          else if (e.code === 'conflict' || e.status === 409) name.setError(i18n.errorText(e));
          else if (!e.errors?.length || loose.length) err.setNodes(...problemNodes(i18n, e));
        }
      });
    });
    return h('section', { class: 'card', 'aria-labelledby': 'pc-title' }, h('h2', { id: 'pc-title' }, t(kind === 'user' ? 'admin.new-user' : 'admin.new-group')), form);
  }

  function draw(r) {
    const q = field({ label: t('admin.search'), name: 'prefix', value: query.prefix ?? '', maxlength: 64, spellcheck: false, autocapitalize: 'none' });
    const form = h('form', { class: 'search', novalidate: true }, q.node, h('div', { class: 'actions' }, h('button', { type: 'submit' }, t('admin.find'))));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      q.setError(null);
      const s = q.input.value.trim();
      if (s !== '' && !SEARCH.test(s)) { q.setError(t('admin.bad-search')); q.focus(); return; }
      router.go(tab, undefined, { prefix: s });
    });
    const rows = r.principals.map((p) => h('tr', null,
      h('th', { scope: 'row' }, link(router.href('admin-principal', { id: String(p.id) }), null, render(p.name))),
      h('td', null, p.display_name ? render(p.display_name) : '-'),
      kind === 'user' ? h('td', null, p.email ? render(p.email) : '-') : null,
      h('td', null, p.disabled ? h('span', { class: 'badge warn' }, t('admin.disabled')) : t('admin.active'))));
    const next = r.next_cursor ? router.href(tab, undefined, { ...query, cursor: r.next_cursor }) : null;
    const first = query.cursor ? router.href(tab, undefined, { ...query, cursor: undefined }) : null;
    fill(box, flash ? h('p', { class: 'msg ok', role: 'status' }, flash) : null, form,
      r.principals.length === 0 ? h('p', null, t(query.cursor ? 'admin.no-more' : 'admin.none')) : h('table', null, h('caption', { class: 'sr-only' }, t(kind === 'user' ? 'admin.users' : 'admin.groups')),
        h('thead', null, h('tr', null, h('th', { scope: 'col' }, t('admin.h-name')), h('th', { scope: 'col' }, t('admin.h-display')), kind === 'user' ? h('th', { scope: 'col' }, t('admin.h-email')) : null, h('th', { scope: 'col' }, t('admin.h-state')))),
        h('tbody', null, rows)),
      next || first ? h('p', { class: 'actions pager' }, first ? link(first, null, t('admin.first')) : null, next ? link(next, { class: 'button' }, t('admin.next')) : null) : null);
  }

  if (isGlobal(ctx)) {
    api.get('/principals', { query: { kind, limit: 100, cursor: query.cursor, prefix: SEARCH.test(query.prefix ?? '') ? query.prefix : undefined } }).then((r) => { if (alive) draw(r); },
      (e) => { if (alive) fill(box, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e))); });
  }
  return { node: adminFrame(ctx, tab, h('section', { class: 'card', 'aria-labelledby': 'pl-title' }, h('h2', { id: 'pl-title' }, t(kind === 'user' ? 'admin.users' : 'admin.groups')), box), createForm()), dispose() { alive = false; } };
}

// ---------------------------------------------------------------------------------------------------------------------------------- policies
export function policiesView(ctx) {
  const { api, i18n } = ctx;
  const t = i18n.t;
  const list = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const formBox = h('div');
  const flash = flashOf(ctx);
  let alive = true;
  let policies = [];
  let editing = null;                              // the policy being edited, or null for a new one
  let said = flash;

  function form() {
    const p = editing;
    const name = field({ label: t('pol.f-name'), name: 'name', value: p?.name ?? '', required: true, maxlength: 255 });
    const types = field({ label: t('pol.f-types'), name: 'types', value: (p?.allowed_types ?? []).join(' '), required: true, maxlength: 4000, spellcheck: false, autocapitalize: 'characters', hint: t('pol.f-types-hint') });
    const wildcard = checkbox({ label: t('pol.f-wildcard'), name: 'allow_wildcard', checked: p?.allow_wildcard === true });
    const delegation = checkbox({ label: t('pol.f-delegation'), name: 'allow_delegation', checked: p?.allow_delegation === true });
    const dname = checkbox({ label: t('pol.f-dname'), name: 'allow_dname', checked: p?.allow_dname === true });
    const apex = checkbox({ label: t('pol.f-apex'), name: 'apex_editable', checked: p?.apex_editable === true });
    const ttlMin = field({ label: t('pol.f-ttl-min'), name: 'ttl_min', value: p ? String(p.ttl_min) : '', inputmode: 'numeric', maxlength: 10, hint: t('pol.f-ttl-hint') });
    const ttlMax = field({ label: t('pol.f-ttl-max'), name: 'ttl_max', value: p ? String(p.ttl_max) : '', inputmode: 'numeric', maxlength: 10 });
    const maxRr = field({ label: t('pol.f-max-rr'), name: 'max_rr', value: p?.max_rr === null || p?.max_rr === undefined ? '' : String(p.max_rr), inputmode: 'numeric', maxlength: 10, hint: t('pol.f-max-rr-hint') });
    const err = message('error');
    const ok = message('status');
    const submit = h('button', { type: 'submit', class: 'primary' }, t(p ? 'pol.save' : 'pol.create'));
    const fields = { name, types, ttl_min: ttlMin, ttl_max: ttlMax, max_rr: maxRr };
    const f = h('form', { class: 'stack', novalidate: true }, name.node, types.node,
      h('fieldset', null, h('legend', null, t('pol.f-allow')), wildcard.node, delegation.node, dname.node, apex.node),
      h('div', { class: 'grid' }, ttlMin.node, ttlMax.node, maxRr.node), err.node, ok.node,
      h('div', { class: 'actions' }, submit, p ? h('button', { type: 'button', on: { click: () => { editing = null; drawForm(); } } }, t('pol.cancel')) : null));
    f.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(submit, async () => {
        err.set(null);
        for (const x of Object.values(fields)) x.setError(null);
        const r = policyBody({ name: name.input.value, types: types.input.value, wildcard: wildcard.input.checked, delegation: delegation.input.checked, dname: dname.input.checked, apex: apex.input.checked, ttl_min: ttlMin.input.value, ttl_max: ttlMax.input.value, max_rr: maxRr.input.value });
        if (r.error) { fields[r.error].setError(t(`pol.bad-${r.error}`)); fields[r.error].focus(); return; }
        try {
          if (p) await api.patch(`/rr-policies/${p.id}`, r.body); else await api.post('/rr-policies', r.body);
          said = t(p ? 'pol.saved' : 'pol.created', { name: r.body.name });
          ctx.announce(said);
          editing = null;
          drawForm();
          load();
        } catch (e) {
          // the pointer /allowed_types/3 belongs to the types box
          const errs = (e.errors ?? []).map((x) => (typeof x.pointer === 'string' && x.pointer.startsWith('/allowed_types') ? { ...x, pointer: '/allowed_types' } : x));
          const loose = errs.length ? placeOnFields(errs, { '/name': name, '/allowed_types': types, '/ttl_min': ttlMin, '/ttl_max': ttlMax, '/max_rr': maxRr }) : [];
          if (!errs.length || loose.length) err.setNodes(...problemNodes(i18n, e));
        }
      });
    });
    return h('section', { class: 'card', 'aria-labelledby': 'polf-title' }, h('h2', { id: 'polf-title' }, p ? t('pol.edit-title', { name: p.name }) : t('pol.new')), f);
  }
  function drawForm() { fill(formBox, form()); }

  function drawList() {
    const del = message('error');
    const rows = policies.map((p) => h('tr', null,
      h('th', { scope: 'row' }, render(p.name)),
      h('td', null, render((p.allowed_types ?? []).join(' '))),
      h('td', null, `${p.ttl_min}-${p.ttl_max}`),
      h('td', null, [p.allow_wildcard ? t('policy.wildcard') : null, p.allow_delegation ? t('policy.delegation') : null, p.allow_dname ? t('policy.dname') : null, p.apex_editable ? t('policy.apex') : null].filter(Boolean).join(', ') || '-'),
      h('td', null, p.max_rr === null || p.max_rr === undefined ? '-' : String(p.max_rr)),
      h('td', { class: 'actions-cell' },
        h('button', { type: 'button', 'aria-label': t('pol.edit-of', { name: p.name }), on: { click: () => { editing = p; drawForm(); } } }, t('pol.edit')), ' ',
        confirmButton({ label: t('pol.delete'), confirmLabel: t('pol.delete-ask'), yes: t('common.yes'), no: t('common.no'), onConfirm: async () => {
          del.set(null);
          try {
            await api.del(`/rr-policies/${p.id}`);
            said = t('pol.deleted', { name: p.name });
            ctx.announce(said);
            if (editing?.id === p.id) { editing = null; drawForm(); }
            load();
          } catch (e) {
            del.setNodes(...problemNodes(i18n, e));
          }
        } }))));
    fill(list, said ? h('p', { class: 'msg ok', role: 'status' }, said) : null,
      policies.length === 0 ? h('p', null, t('pol.none')) : h('table', null, h('caption', { class: 'sr-only' }, t('admin.policies')),
        h('thead', null, h('tr', null, ...['name', 'types', 'ttl', 'flags', 'max-rr', 'actions'].map((k) => h('th', { scope: 'col' }, t(`pol.h-${k}`))))), h('tbody', null, rows)),
      del.node);
  }

  async function load() {
    try {
      const r = await api.get('/rr-policies', { query: { limit: 500 } });
      if (!alive) return;
      policies = r.policies;
      drawList();
    } catch (e) {
      if (alive) fill(list, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
    }
  }
  if (isGlobal(ctx)) { load(); drawForm(); }
  return { node: adminFrame(ctx, 'admin-policies', h('section', { class: 'card', 'aria-labelledby': 'pols-title' }, h('h2', { id: 'pols-title' }, t('admin.policies')), h('p', null, t('pol.intro')), list), formBox), dispose() { alive = false; } };
}

// ---------------------------------------------------------------------------------------------------------------------------------- all grants
export function grantsView(ctx, { query }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const box = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const formBox = h('div');
  let alive = true;

  async function load() {
    try {
      let principal;
      if (query.who) {
        principal = await lookupPrincipal(api, query.who);
        if (!alive) return;
        if (!principal) { fill(box, filterForm(), h('p', { class: 'msg error', role: 'alert' }, t('grants.no-principal'))); return; }
      }
      const zone = String(query.zone ?? '').trim();
      const r = await api.get('/grants', { query: { limit: 100, cursor: query.cursor, principal: principal?.id, zone: zone === '' ? undefined : zone } });
      if (!alive) return;
      const next = r.next_cursor ? router.href('admin-grants', undefined, { ...query, cursor: r.next_cursor }) : null;
      const first = query.cursor ? router.href('admin-grants', undefined, { ...query, cursor: undefined }) : null;
      fill(box, filterForm(), grantsTable(ctx, r.grants, { adminLinks: true, onDeleted: load }),
        next || first ? h('p', { class: 'actions pager' }, first ? link(first, null, t('admin.first')) : null, next ? link(next, { class: 'button' }, t('admin.next')) : null) : null);
    } catch (e) {
      if (alive) fill(box, filterForm(), h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
    }
  }

  function filterForm() {
    const who = field({ label: t('grants.f-principal'), name: 'who', value: query.who ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none' });
    const zone = field({ label: t('grants.f-zone'), name: 'zone', value: query.zone ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none' });
    const form = h('form', { class: 'search', novalidate: true }, who.node, zone.node, h('div', { class: 'actions' }, h('button', { type: 'submit' }, t('grants.filter'))));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      router.go('admin-grants', undefined, { who: who.input.value.trim(), zone: zone.input.value.trim() });
    });
    return form;
  }

  if (isGlobal(ctx)) {
    load();
    Promise.all([api.get('/rr-policies', { query: { limit: 500 } }), api.get('/datasets')]).then(([p, d]) => {
      if (!alive) return;
      fill(formBox, h('section', { class: 'card', 'aria-labelledby': 'gf-title' }, h('h2', { id: 'gf-title' }, t('grants.new')),
        grantForm(ctx, { policies: p.policies, datasets: d.datasets, roles: ['global_master', 'domain_master', 'subdomain_master'], own: null, onDone: load }).node));
    }, (e) => { if (alive) fill(formBox, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e))); });
  }
  return { node: adminFrame(ctx, 'admin-grants', h('section', { class: 'card', 'aria-labelledby': 'gl-title' }, h('h2', { id: 'gl-title' }, t('admin.grants')), box), formBox), dispose() { alive = false; } };
}


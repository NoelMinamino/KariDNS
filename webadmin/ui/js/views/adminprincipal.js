// S11: one user or group (planning 3): its attributes, for a user the state of its sign-in (password, two-step verification, failed attempts, the lock) with the
// administrator's actions (F-15: reset the TOTP of a user who lost the device, unlock an account) and a new password, the groups it is in; for a group its members; for
// both the grants it holds.  The service refuses what a person may not do (one cannot disable, delete or reset the TOTP of oneself: 409 `self`); the page hides those.

import { h, link, fill } from '../dom.js';
import { render, plain, timeNode } from '../format.js';
import { field, checkbox, select, message, problemNodes, confirmButton, busy, isGlobal } from '../widgets.js';
import { placeOnFields } from '../pointer.js';
import { lookupPrincipal, principalLabel } from '../adminlib.js';
import { grantsTable, grantForm } from './grants.js';
import { adminFrame } from './admin.js';

const PASSWORD_MIN = 12;
const ID = /^[1-9][0-9]{0,14}$/;

export function principalView(ctx, { params }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const me = ctx.session.state.me.principal;
  const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const flash = ctx.flash ?? null;
  ctx.flash = null;
  let said = flash;
  let alive = true;

  if (!ID.test(params.id)) return { node: adminFrame(ctx, null, h('p', { class: 'msg error', role: 'alert' }, t('admin.not-found'))) };
  const id = Number(params.id);
  const self = id === me.id;

  const say = (text) => { said = text; ctx.announce(text); return load(); };

  // ---------------------------------------------------------------------------------------------------------------------------- attributes
  function attributes(p, extra) {
    const name = field({ label: t('admin.f-name'), name: 'name', value: p.name, required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('admin.f-name-hint') });
    const display = field({ label: t('admin.f-display'), name: 'display_name', value: p.display_name ?? '', maxlength: 255 });
    const email = p.kind === 'user' ? field({ label: t('admin.f-email'), name: 'email', value: p.email ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none', inputmode: 'email' }) : null;
    const disabled = self ? null : checkbox({ label: t('admin.f-disabled'), name: 'disabled', checked: p.disabled === true });
    const err = message('error');
    const submit = h('button', { type: 'submit', class: 'primary' }, t('admin.save'));
    const form = h('form', { class: 'stack', novalidate: true }, h('div', { class: 'grid' }, name.node, display.node, email?.node), disabled?.node,
      disabled ? h('p', { class: 'hint' }, t('admin.disable-hint')) : h('p', { class: 'hint' }, t('admin.self-hint')), err.node, h('div', { class: 'actions' }, submit));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(submit, async () => {
        err.set(null);
        for (const f of [name, display, email]) f?.setError(null);
        if (name.input.value.trim() === '') { name.setError(t('admin.need-name')); name.focus(); return; }
        const patch = { name: name.input.value.trim(), display_name: display.input.value.trim() === '' ? null : display.input.value.trim() };
        if (email) patch.email = email.input.value.trim() === '' ? null : email.input.value.trim();
        if (disabled) patch.disabled = disabled.input.checked;
        try {
          await api.patch(`/principals/${id}`, patch);
          await say(t('admin.saved'));
        } catch (e) {
          const map = { '/name': name, '/display_name': display };
          if (email) map['/email'] = email;
          const loose = e.errors?.length ? placeOnFields(e.errors, map) : [];
          if (e.status === 409 && e.code !== 'self') name.setError(i18n.errorText(e));
          else if (!e.errors?.length || loose.length) err.setNodes(...problemNodes(i18n, e));
        }
      });
    });
    const dl = [
      [t('admin.h-kind'), t(p.kind === 'user' ? 'admin.kind-user' : 'admin.kind-group')],
      [t('admin.h-state'), p.disabled ? t('admin.disabled') : t('admin.active')],
      extra.created_at ? [t('admin.created-at'), timeNode(extra.created_at, i18n.lang)] : null,
    ].filter(Boolean);
    return h('section', { class: 'card', 'aria-labelledby': 'pr-title' }, h('h2', { id: 'pr-title' }, t('admin.account')),
      h('dl', null, dl.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])), form);
  }

  // ---------------------------------------------------------------------------------------------------------------------------- sign-in (users)
  function signIn(p, creds) {
    const err = message('error');
    const act = async (action, text) => {
      err.set(null);
      try {
        await api.post(`/principals/${id}/credentials`, { action });
        await say(text);
      } catch (e) {
        err.setNodes(...problemNodes(i18n, e));
      }
    };
    const rows = creds ? [
      [t('admin.c-password'), t(creds.password ? 'common.yes' : 'common.no')],
      [t('admin.c-totp'), t(creds.totp_enabled ? 'admin.c-totp-on' : 'admin.c-totp-off')],
      [t('admin.c-failed'), String(creds.failed_logins)],
      [t('admin.c-locked'), t(creds.locked ? 'common.yes' : 'common.no')],
      // 0.6.2: the lock is per network; the networks that are locked out of the account now
      ...(creds.locked_networks?.length ? [[t('admin.c-locked-nets'), creds.locked_networks.map((n) => n.network).join(', ')]] : []),
    ] : [];
    const pw = field({ label: t('admin.f-newpw'), type: 'password', name: 'new_password', autocomplete: 'new-password', maxlength: 1024, hint: t('admin.f-newpw-hint', { min: PASSWORD_MIN }) });
    const pwForm = h('form', { class: 'stack', novalidate: true }, pw.node, h('div', { class: 'actions' }, h('button', { type: 'submit' }, t('admin.set-password'))));
    pwForm.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(pwForm.querySelector('button'), async () => {
        err.set(null);
        pw.setError(null);
        if ([...pw.input.value].length < PASSWORD_MIN) { pw.setError(t('api.weak-password')); pw.focus(); return; }
        try {
          await api.put(`/principals/${id}/password`, { password: pw.input.value });
          pw.input.value = '';
          await say(t('admin.password-set'));
        } catch (e) {
          if (e.code === 'weak-password') pw.setError(i18n.errorText(e));
          else err.setNodes(...problemNodes(i18n, e));
        }
      });
    });
    const canUnlock = creds && (creds.locked || creds.failed_logins > 0);
    const canReset = creds && creds.totp_enabled && !self;
    return h('section', { class: 'card', 'aria-labelledby': 'cr-title' }, h('h2', { id: 'cr-title' }, t('admin.signin')),
      creds ? h('dl', null, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])) : h('p', null, t('admin.no-creds')),
      h('div', { class: 'actions' },
        canUnlock ? confirmButton({ label: t('admin.unlock'), confirmLabel: t('admin.unlock-ask'), yes: t('common.yes'), no: t('common.no'), cls: '', onConfirm: () => act('unlock', t('admin.unlocked')) }) : null,
        canReset ? confirmButton({ label: t('admin.reset-totp'), confirmLabel: t('admin.reset-totp-ask'), yes: t('common.yes'), no: t('common.no'), onConfirm: () => act('reset-totp', t('admin.totp-reset')) }) : null),
      creds && creds.totp_enabled && self ? h('p', { class: 'hint' }, t('admin.self-totp')) : null,
      err.node, h('h3', null, t('admin.password')), pwForm);
  }

  // ---------------------------------------------------------------------------------------------------------------------------- identity at a provider (users, F-16)
  // A global master links a user to (issuer, subject) or removes the link; nobody is made by a sign-in.  The issuers are those of the providers the service has
  // (GET /auth/providers); the service refuses any other.
  function identity(p, creds) {
    const err = message('error');
    const link = creds?.oidc ?? null;
    const box = h('section', { class: 'card', 'aria-labelledby': 'oi-title' }, h('h2', { id: 'oi-title' }, t('admin.oidc-title')), h('p', { class: 'hint' }, t('admin.oidc-intro')));
    const act = async (fn, text) => {
      err.set(null);
      try {
        await fn();
        await say(text);
      } catch (e) {
        err.setNodes(...problemNodes(i18n, e));
      }
    };
    if (link) {
      box.append(h('dl', null,
        h('dt', null, t('admin.oidc-provider')), h('dd', null, link.provider ? render(link.provider.label) : t('admin.oidc-gone')),
        h('dt', null, t('account.oidc-issuer')), h('dd', null, h('code', null, render(link.issuer))),
        h('dt', null, t('admin.oidc-subject')), h('dd', null, h('code', null, render(link.subject)))),
      h('p', { class: 'actions' }, confirmButton({ label: t('admin.oidc-unlink'), confirmLabel: t('admin.oidc-unlink-ask'), yes: t('common.yes'), no: t('common.no'), onConfirm: () => act(() => api.del(`/principals/${id}/oidc`), t('admin.oidc-unlinked')) })));
    } else {
      box.append(h('p', null, t('admin.oidc-none')));
    }
    const slot = h('div');
    box.append(slot, err.node);
    (ctx.providers?.() ?? Promise.resolve([])).then((list) => {
      if (!alive) return;
      if (list.length === 0) { fill(slot, link ? null : h('p', { class: 'hint' }, t('admin.oidc-no-providers'))); return; }
      const which = select({ label: t('admin.oidc-provider'), name: 'provider', value: link?.issuer ?? list[0].issuer, options: list.map((x) => ({ value: x.issuer, label: plain(x.label) })) });
      const subject = field({ label: t('admin.oidc-subject'), name: 'subject', value: '', required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('admin.oidc-subject-hint') });
      const submit = h('button', { type: 'submit' }, t('admin.oidc-link'));
      const form = h('form', { class: 'stack', novalidate: true }, h('h3', null, t('admin.oidc-link')), which.node, subject.node, link ? h('p', { class: 'hint' }, t('admin.oidc-change-note')) : null, h('div', { class: 'actions' }, submit));
      form.addEventListener('submit', (ev) => {
        ev.preventDefault();
        busy(submit, async () => {
          subject.setError(null);
          err.set(null);
          const s = subject.input.value.trim();
          if (s === '') { subject.setError(t('admin.oidc-need-subject')); subject.focus(); return; }
          try {
            await api.put(`/principals/${id}/oidc`, { issuer: which.input.value, subject: s });
            await say(t('admin.oidc-linked'));
          } catch (e) {
            if (e.status === 409 || e.status === 400) subject.setError(i18n.errorText(e)); else err.setNodes(...problemNodes(i18n, e));
          }
        });
      });
      fill(slot, form);
    });
    return box;
  }

  // ---------------------------------------------------------------------------------------------------------------------------- groups and members
  function groupsOf(groups) {
    return h('section', { class: 'card', 'aria-labelledby': 'gr-title' }, h('h2', { id: 'gr-title' }, t('admin.in-groups')),
      groups.length === 0 ? h('p', null, t('admin.in-no-group')) : h('ul', null, groups.map((g) => h('li', null, link(router.href('admin-principal', { id: String(g.id) }), null, render(g.name))))));
  }

  function members(g, list) {
    const err = message('error');
    const who = field({ label: t('admin.f-member'), name: 'member', maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('admin.f-member-hint') });
    const add = h('button', { type: 'submit' }, t('admin.add-member'));
    const form = h('form', { class: 'search', novalidate: true }, who.node, h('div', { class: 'actions' }, add));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      busy(add, async () => {
        err.set(null);
        who.setError(null);
        if (who.input.value.trim() === '') { who.setError(t('admin.need-member')); who.focus(); return; }
        try {
          const m = await lookupPrincipal(api, who.input.value);
          if (!m) { who.setError(t('grants.no-principal')); who.focus(); return; }
          await api.post(`/principals/${id}/members`, { member: m.id });
          await say(t('admin.member-added', { name: m.name }));
        } catch (e) {
          if (e.status === 409 || e.status === 400) who.setError(i18n.errorText(e)); else err.setNodes(...problemNodes(i18n, e));
        }
      });
    });
    const rows = list.map((m) => h('tr', null,
      h('th', { scope: 'row' }, link(router.href('admin-principal', { id: String(m.id) }), null, render(principalLabel(m)))),
      h('td', null, t(m.kind === 'user' ? 'admin.kind-user' : 'admin.kind-group')),
      h('td', null, confirmButton({ label: t('admin.remove-member'), confirmLabel: t('admin.remove-member-ask'), yes: t('common.yes'), no: t('common.no'), onConfirm: async () => {
        err.set(null);
        try {
          await api.del(`/principals/${id}/members/${m.id}`);
          await say(t('admin.member-removed', { name: m.name }));
        } catch (e) {
          err.setNodes(...problemNodes(i18n, e));
        }
      } }))));
    return h('section', { class: 'card', 'aria-labelledby': 'mem-title' }, h('h2', { id: 'mem-title' }, t('admin.members')), h('p', { class: 'hint' }, t('admin.members-hint')),
      list.length === 0 ? h('p', null, t('admin.no-members')) : h('table', null, h('caption', { class: 'sr-only' }, t('admin.members')),
        h('thead', null, h('tr', null, ...['name', 'kind', 'actions'].map((k) => h('th', { scope: 'col' }, t(`admin.m-${k}`))))), h('tbody', null, rows)),
      form, err.node);
  }

  // ---------------------------------------------------------------------------------------------------------------------------- grants
  function grants(p, list, policies, datasets) {
    return h('section', { class: 'card', 'aria-labelledby': 'gt-title' }, h('h2', { id: 'gt-title' }, t('admin.p-grants')),
      grantsTable(ctx, list, { who: false, onDeleted: () => say(t('grants.deleted')) }),
      h('h3', null, t('grants.new')),
      grantForm(ctx, { policies, datasets, roles: ['global_master', 'domain_master', 'subdomain_master'], principal: { id: p.id, name: p.name }, own: null, onDone: () => say(t('grants.added')) }).node);
  }

  function danger(p) {
    const err = message('error');
    return h('section', { class: 'card danger-zone', 'aria-labelledby': 'dl-title' }, h('h2', { id: 'dl-title' }, t('admin.delete-title')), h('p', null, t('admin.delete-text')),
      h('p', { class: 'actions' }, confirmButton({ label: t('admin.delete'), confirmLabel: t('admin.delete-ask', { name: plain(p.name) }), yes: t('common.yes'), no: t('common.no'), onConfirm: async () => {
        err.set(null);
        try {
          await api.del(`/principals/${id}`);
          ctx.flash = t('admin.deleted', { name: plain(p.name) });
          router.go(p.kind === 'user' ? 'admin-users' : 'admin-groups');
        } catch (e) {
          err.setNodes(...problemNodes(i18n, e));
        }
      } })), err.node);
  }

  async function load() {
    try {
      const r = await api.get(`/principals/${id}`);
      if (!alive) return;
      const p = r.principal;
      const [list, policies, datasets, mem] = await Promise.all([
        api.get('/grants', { query: { principal: id, limit: 100 } }),
        api.get('/rr-policies', { query: { limit: 500 } }),
        api.get('/datasets'),
        p.kind === 'group' ? api.get(`/principals/${id}/members`) : Promise.resolve(null),
      ]);
      if (!alive) return;
      fill(body,
        said ? h('p', { class: 'msg ok', role: 'status' }, said) : null,
        h('h2', null, t(p.kind === 'user' ? 'admin.kind-user' : 'admin.kind-group'), ': ', render(p.name)),
        attributes(p, r.principal),
        p.kind === 'user' ? [signIn(p, r.credentials ?? null), identity(p, r.credentials ?? null)] : members(p, mem.members),
        p.kind === 'user' ? groupsOf(r.groups ?? []) : null,
        grants(p, list.grants, policies.policies, datasets.datasets),
        self ? null : danger(p));
      said = null;
    } catch (e) {
      if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)), h('p', null, link(router.href('admin-users'), null, t('admin.back'))));
    }
  }
  if (isGlobal(ctx)) load();
  return { node: adminFrame(ctx, null, body), dispose() { alive = false; } };
}

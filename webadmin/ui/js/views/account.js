// S15: the account of the person who is signed in (planning 3): password, TOTP, API tokens, language, sign out.  The service decides everything (the password rules,
// whether TOTP may be switched off, who may make tokens); this screen shows what it answers.

import { h, link, fill } from '../dom.js';
import { render, timeNode } from '../format.js';
import { field, checkbox, select, message, problemNodes, busy, confirmButton, uid } from '../widgets.js';

const PASSWORD_MIN = 12;

// is TOTP mandatory for this person?  (the service's require-totp: global masters, everybody, or nobody; the service refuses a switch-off anyway)
export function totpRequired(ctx) {
  const mode = ctx.session.state.version?.ui?.require_totp;
  return mode === 'all' || (mode === 'global' && ctx.session.state.me?.capabilities?.global === true);
}

function passwordSection(ctx) {
  const { api, i18n, session } = ctx;
  const t = i18n.t;
  const name = session.state.me.principal.name;
  const current = field({ label: t('account.pw-current'), type: 'password', name: 'current', autocomplete: 'current-password', required: true, maxlength: 1024 });
  const next = field({ label: t('account.pw-new'), type: 'password', name: 'new', autocomplete: 'new-password', required: true, maxlength: 1024, hint: t('account.pw-rules', { min: PASSWORD_MIN }) });
  const again = field({ label: t('account.pw-again'), type: 'password', name: 'again', autocomplete: 'new-password', required: true, maxlength: 1024 });
  const others = checkbox({ label: t('account.pw-others'), checked: true, name: 'all' });
  const msg = message('status');
  const err = message('error');
  const submit = h('button', { type: 'submit', class: 'primary' }, t('account.pw-change'));
  const form = h('form', { class: 'stack', novalidate: true }, current.node, next.node, again.node, others.node, err.node, msg.node, h('div', { class: 'actions' }, submit));
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    for (const f of [current, next, again]) f.setError(null);
    err.set(null);
    msg.set(null);
    const n = next.input.value;
    if (!current.input.value) { current.setError(t('account.pw-need-current')); current.focus(); return; }
    // (the service checks these again; they are only here so that the person need not wait for an answer)
    if ([...n].length < PASSWORD_MIN) { next.setError(t('api.weak-password')); next.focus(); return; }
    if (n.toLowerCase().includes(name.toLowerCase())) { next.setError(t('account.pw-has-name')); next.focus(); return; }
    if (n !== again.input.value) { again.setError(t('account.pw-mismatch')); again.focus(); return; }
    busy(submit, async () => {
      try {
        await api.post('/auth/password', { current: current.input.value, new: n, all: others.input.checked });
        current.input.value = '';
        next.input.value = '';
        again.input.value = '';
        msg.set(t('account.pw-changed'));
      } catch (e) {
        if (e.code === 'weak-password') next.setError(i18n.errorText(e));
        else if (e.code === 'wrong-password') { current.setError(i18n.errorText(e)); current.focus(); } else err.setNodes(...problemNodes(i18n, e));
      }
    });
  });
  return h('section', { class: 'card', 'aria-labelledby': 'acc-pw' }, h('h2', { id: 'acc-pw' }, t('account.password')), form);
}

function totpSection(ctx, creds) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const box = h('section', { class: 'card', 'aria-labelledby': 'acc-totp' });
  const err = message('error');
  const draw = (on) => {
    fill(box, h('h2', { id: 'acc-totp' }, t('account.totp')));
    if (!on) {
      box.append(h('p', null, t('account.totp-off')), h('p', null, link(router.href('totp'), { class: 'button primary' }, t('account.totp-setup'))));
      return;
    }
    box.append(h('p', null, t('account.totp-on')));
    if (totpRequired(ctx)) {
      box.append(h('p', { class: 'notice' }, t('account.totp-mandatory')));
      return;
    }
    // (a person with no password, who signs in with an identity provider, gives the code alone)
    const hasPassword = creds?.password !== false;
    const pw = field({ label: t('account.pw-current'), type: 'password', name: 'password', autocomplete: 'current-password', required: true, maxlength: 1024 });
    const code = field({ label: t('totp.code'), name: 'code', autocomplete: 'one-time-code', inputmode: 'numeric', maxlength: 6, required: true });
    const go = h('button', { type: 'submit', class: 'danger' }, t('account.totp-disable'));
    const form = h('form', { class: 'stack', novalidate: true }, h('h3', null, t('account.totp-disable-title')), hasPassword ? pw.node : h('p', { class: 'hint' }, t('account.totp-code-only')), code.node, err.node, h('div', { class: 'actions' }, go));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      err.set(null);
      pw.setError(null);
      code.setError(null);
      if (hasPassword && !pw.input.value) { pw.setError(t('account.pw-need-current')); pw.focus(); return; }
      if (!/^\d{6}$/.test(code.input.value.trim())) { code.setError(t('totp.bad-code')); code.focus(); return; }
      busy(go, async () => {
        try {
          await api.post('/auth/totp', { action: 'disable', ...(hasPassword ? { password: pw.input.value } : {}), code: code.input.value.trim() });
          ctx.announce(t('account.totp-disabled'));
          draw(false);
        } catch (e) {
          if (e.code === 'wrong-password') pw.setError(i18n.errorText(e));
          else if (e.code === 'wrong-code') code.setError(i18n.errorText(e));
          else err.setNodes(...problemNodes(i18n, e));
        }
      });
    });
    box.append(form);
  };
  draw(creds?.totp_enabled === true);
  return box;
}

// The identity provider the account is linked to (read only: a global master links and unlinks it, F-16).  -> a node, or null when there is nothing to say (not linked, and
// the service has no provider).
async function oidcSection(ctx, creds) {
  const { i18n } = ctx;
  const t = i18n.t;
  const link = creds?.oidc ?? null;
  if (!link && (await ctx.providers?.() ?? []).length === 0) return null;
  const rows = link ? [
    [t('account.oidc-provider'), link.provider ? render(link.provider.label) : t('account.oidc-unknown')],
    [t('account.oidc-issuer'), h('code', null, render(link.issuer))],
    [t('account.oidc-subject'), h('code', null, render(link.subject))],
  ] : [];
  return h('section', { class: 'card', 'aria-labelledby': 'acc-oidc' }, h('h2', { id: 'acc-oidc' }, t('account.oidc-title')),
    link ? [h('p', null, t('account.oidc-linked')), h('dl', null, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]))] : h('p', null, t('account.oidc-none')),
    creds?.password === false ? h('p', { class: 'notice' }, t('account.oidc-nopw')) : null);
}

function tokenState(tok, nowMs) {
  if (tok.revoked_at) return 'revoked';
  return Date.parse(tok.expires_at) <= nowMs ? 'expired' : 'active';
}

function tokensSection(ctx) {
  const { api, i18n, now } = ctx;
  const t = i18n.t;
  const box = h('section', { class: 'card', 'aria-labelledby': 'acc-tokens' });
  const list = h('div');
  const shown = h('div');
  const err = message('error');

  async function load() {
    try {
      const r = await api.get('/tokens', { query: { limit: 500 } });
      const rows = r.tokens.map((tok) => {
        const state = tokenState(tok, now());
        return h('tr', null,
          h('th', { scope: 'row' }, render(tok.name)),
          h('td', null, t(tok.read_only ? 'account.tok-ro' : 'account.tok-rw')),
          h('td', null, timeNode(tok.created_at, i18n.lang)),
          h('td', null, timeNode(tok.expires_at, i18n.lang)),
          h('td', null, tok.last_used_at ? timeNode(tok.last_used_at, i18n.lang) : t('account.tok-never')),
          h('td', null, t(`account.tok-${state}`)),
          h('td', null, state === 'active'
            ? confirmButton({ label: t('account.tok-revoke'), confirmLabel: t('account.tok-revoke-ask'), yes: t('common.yes'), no: t('common.no'), onConfirm: () => revoke(tok) })
            : null));
      });
      fill(list, r.tokens.length === 0 ? h('p', null, t('account.tok-none')) : h('table', null,
        h('caption', { class: 'sr-only' }, t('account.tokens')),
        h('thead', null, h('tr', null, ...['name', 'access', 'created', 'expires', 'used', 'state', 'action'].map((k) => h('th', { scope: 'col' }, t(`account.tok-h-${k}`))))),
        h('tbody', null, rows)));
    } catch (e) {
      fill(list, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
    }
  }

  async function revoke(tok) {
    err.set(null);
    try {
      await api.del(`/tokens/${tok.id}`);
      ctx.announce(t('account.tok-revoked'));
      await load();
    } catch (e) {
      err.setNodes(...problemNodes(i18n, e));
    }
  }

  const name = field({ label: t('account.tok-name'), name: 'name', required: true, maxlength: 255, spellcheck: false });
  const days = field({ label: t('account.tok-days'), type: 'number', name: 'days', value: '90', inputmode: 'numeric', hint: t('account.tok-days-hint') });
  const ro = checkbox({ label: t('account.tok-readonly'), checked: false, name: 'read_only' });
  const make = h('button', { type: 'submit', class: 'primary' }, t('account.tok-create'));
  const form = h('form', { class: 'stack', novalidate: true }, h('h3', null, t('account.tok-new')), name.node, days.node, ro.node, err.node, h('div', { class: 'actions' }, make));
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    err.set(null);
    name.setError(null);
    days.setError(null);
    const d = Number(days.input.value);
    if (!name.input.value.trim()) { name.setError(t('account.tok-need-name')); name.focus(); return; }
    if (!Number.isInteger(d) || d < 1 || d > 365) { days.setError(t('account.tok-bad-days')); days.focus(); return; }
    busy(make, async () => {
      try {
        const r = await api.post('/tokens', { name: name.input.value.trim(), read_only: ro.input.checked, days: d });
        name.input.value = '';
        showToken(r.token);
        await load();
      } catch (e) {
        if (e.code === 'bad-request' && e.errors.some((x) => x.pointer === '/name')) name.setError(i18n.errorText(e));
        else err.setNodes(...problemNodes(i18n, e));
      }
    });
  });

  // the token is shown once: here, with a button to copy it and a warning; it is removed from the page when the person is done (and with the screen)
  function showToken(token) {
    let secret = token;
    const id = uid('tok');
    const status = message('status');
    const done = h('button', { type: 'button', on: { click: () => { secret = null; fill(shown); } } }, t('account.tok-done'));
    const copy = h('button', { type: 'button', on: { click: async () => {
      try {
        await ctx.copy(secret);
        status.set(t('account.tok-copied'));
      } catch {
        status.set(t('account.tok-copy-failed'));
      }
    } } }, t('account.tok-copy'));
    fill(shown, h('div', { class: 'secret', role: 'group', 'aria-labelledby': id },
      h('h3', { id }, t('account.tok-shown')),
      h('p', { class: 'notice' }, t('account.tok-once')),
      h('p', null, h('code', { class: 'token' }, token)),
      h('div', { class: 'actions' }, copy, done), status.node));
    ctx.announce(t('account.tok-shown'));
  }

  fill(box, h('h2', { id: 'acc-tokens' }, t('account.tokens')), h('p', null, t('account.tok-intro')), list, shown, form);
  load();
  return { node: box, dispose() { fill(shown); } };
}

function languageSection(ctx) {
  const { i18n } = ctx;
  const t = i18n.t;
  const labels = { en: 'English', ja: '日本語' };
  const sel = select({ label: t('account.language'), options: i18n.languages.map((l) => ({ value: l, label: labels[l] ?? l })), value: i18n.lang, name: 'language' });
  sel.input.addEventListener('change', () => i18n.setLang(sel.input.value));
  return h('section', { class: 'card', 'aria-labelledby': 'acc-lang' }, h('h2', { id: 'acc-lang' }, t('account.language-title')), sel.node);
}

function sessionSection(ctx) {
  const { i18n, session } = ctx;
  const t = i18n.t;
  const s = session.state;
  const err = message('error');
  const out = (all) => (ev) => {
    busy(ev.currentTarget, async () => {
      try { await session.logout(all); } catch (e) { err.setNodes(...problemNodes(i18n, e)); }
    });
  };
  return h('section', { class: 'card', 'aria-labelledby': 'acc-sess' },
    h('h2', { id: 'acc-sess' }, t('account.session')),
    h('dl', null,
      h('dt', null, t('account.sess-ends')), h('dd', null, s.expiresAt ? timeNode(new Date(s.expiresAt).toISOString(), i18n.lang) : '-'),
      h('dt', null, t('account.sess-idle')), h('dd', null, t('account.sess-idle-value', { minutes: Math.round(s.idleMs / 60000) }))),
    err.node,
    h('div', { class: 'actions' },
      h('button', { type: 'button', on: { click: out(false) } }, t('account.logout')),
      h('button', { type: 'button', on: { click: out(true) } }, t('account.logout-all'))),
    h('p', { class: 'hint' }, t('account.logout-all-hint')));
}

// -> { node, dispose }
export function accountView(ctx) {
  const { api, i18n, session } = ctx;
  const t = i18n.t;
  const me = session.state.me;
  const p = me.principal;
  const root = h('div', { class: 'stack' });
  const head = h('section', { class: 'card', 'aria-labelledby': 'acc-title' },
    h('h1', { id: 'acc-title' }, t('account.title')),
    h('dl', null,
      h('dt', null, t('account.name')), h('dd', null, render(p.name)),
      p.display_name ? [h('dt', null, t('account.display')), h('dd', null, render(p.display_name))] : null,
      p.email ? [h('dt', null, t('account.email')), h('dd', null, render(p.email))] : null));
  const totpSlot = h('div');
  const oidcSlot = h('div');
  const pwSlot = h('div', null, passwordSection(ctx));
  const tokens = tokensSection(ctx);
  fill(root, head, pwSlot, oidcSlot, totpSlot, tokens.node, languageSection(ctx), sessionSection(ctx));
  // whether TOTP is on, whether there is a password and the identity the account is linked to are in the credentials of the principal itself
  api.get(`/principals/${p.id}`).then(async (r) => {
    if (r.credentials?.password === false) fill(pwSlot);                           // (nothing to change: the account signs in with an identity provider)
    const oidc = await oidcSection(ctx, r.credentials);
    if (oidc) fill(oidcSlot, oidc);
    fill(totpSlot, totpSection(ctx, r.credentials));
  }, (e) => fill(totpSlot, h('section', { class: 'card' }, h('h2', null, t('account.totp')), h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)))));
  return { node: root, dispose: tokens.dispose };
}

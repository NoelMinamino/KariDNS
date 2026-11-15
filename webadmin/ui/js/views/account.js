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
  const tokens = checkbox({ label: t('account.pw-tokens'), checked: false, name: 'tokens' });
  const msg = message('status');
  const err = message('error');
  const submit = h('button', { type: 'submit', class: 'primary' }, t('account.pw-change'));
  const form = h('form', { class: 'stack', novalidate: true }, current.node, next.node, again.node, others.node, tokens.node, err.node, msg.node, h('div', { class: 'actions' }, submit));
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
        await api.post('/auth/password', { current: current.input.value, new: n, all: others.input.checked, tokens: tokens.input.checked });
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
  // (the name of a language is written in that language: WCAG 3.1.2; the choice is applied at once, which the hint says first: 3.2.2)
  const sel = select({ label: t('account.language'), options: i18n.languages.map((l) => ({ value: l, label: labels[l] ?? l, lang: l })), value: i18n.lang, name: 'language' });
  sel.input.addEventListener('change', () => i18n.setLang(sel.input.value));
  return h('section', { class: 'card', 'aria-labelledby': 'acc-lang' }, h('h2', { id: 'acc-lang' }, t('account.language-title')), sel.node, h('p', { class: 'hint' }, t('account.language-hint')));
}

// The idle times a person may choose for its sessions (PUT /auth/idle-timeout): these, where they are not longer than the service's session-idle, and 1, 2 and 3 minutes
// where none of these fits (a session-idle under five minutes).  The API takes any whole number of seconds from 60 to session-idle; a time set that way (not one of
// these) is offered as well, so that the screen shows what is in force.  With a session-idle of a minute or less there is nothing shorter to choose.
export const IDLE_CHOICES_MIN = [5, 10, 15, 30, 60];
const IDLE_SHORT_MIN = [1, 2, 3];

export function idleText(t, sec) {
  if (sec % 60 === 0) return sec === 60 ? t('account.idle-minute') : t('account.idle-minutes', { minutes: sec / 60 });
  return sec === 1 ? t('account.idle-second') : t('account.idle-seconds', { seconds: sec });
}

// -> the options of the select: the service's default first (value ''), then the times in seconds; [] when nothing shorter than the default can be chosen
export function idleOptions(t, max, choice) {
  const fit = (list) => list.map((m) => m * 60).filter((s) => s <= max);
  const secs = max <= 60 ? [] : fit(IDLE_CHOICES_MIN).length ? fit(IDLE_CHOICES_MIN) : fit(IDLE_SHORT_MIN);
  if (choice && !secs.includes(choice)) secs.push(choice);
  if (secs.length === 0) return [];
  return [{ value: '', label: t('account.idle-default', { time: idleText(t, max) }) },
    ...secs.sort((a, b) => a - b).map((s) => ({ value: String(s), label: s > max ? t('account.idle-over', { time: idleText(t, s) }) : idleText(t, s) }))];
}

// "Sign out after inactivity": the person's own idle time, shorter than the service's (the service enforces it; session.setIdle moves the countdown at once)
function idleForm(ctx, shown) {
  const { api, i18n, session } = ctx;
  const t = i18n.t;
  const ss = session.state.me.session;
  const max = ss.idle_timeout_max ?? ss.idle_timeout;
  const choice = ss.idle_timeout_choice ?? null;
  const options = idleOptions(t, max, choice);
  const title = h('h3', null, t('account.idle-title'));
  if (options.length === 0) return h('div', null, title, h('p', { class: 'hint' }, t('account.idle-none', { time: idleText(t, max) })));
  const sel = select({ label: t('account.idle-label'), options, value: choice ? String(choice) : '', name: 'idle_timeout', hint: t('account.idle-hint', { time: idleText(t, max) }) });
  const msg = message('status');
  const err = message('error');
  const save = h('button', { type: 'submit' }, t('account.idle-save'));
  const form = h('form', { class: 'stack', novalidate: true }, title, sel.node, err.node, msg.node, h('div', { class: 'actions' }, save));
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    err.set(null);
    msg.set(null);
    busy(save, async () => {
      try {
        const r = await api.put('/auth/idle-timeout', { idle_timeout: sel.input.value ? Number(sel.input.value) : null });
        session.setIdle(r);
        shown.textContent = idleText(t, r.idle_timeout);
        msg.set(t('account.idle-saved', { time: idleText(t, r.idle_timeout) }));
      } catch (e) {
        err.setNodes(...problemNodes(i18n, e));
      }
    });
  });
  return form;
}

function sessionSection(ctx) {
  const { i18n, session } = ctx;
  const t = i18n.t;
  const s = session.state;
  const err = message('error');
  const idleShown = h('dd', null, idleText(t, Math.round(s.idleMs / 1000)));
  const out = (all) => (ev) => {
    busy(ev.currentTarget, async () => {
      try { await session.logout(all); } catch (e) { err.setNodes(...problemNodes(i18n, e)); }
    });
  };
  return h('section', { class: 'card', 'aria-labelledby': 'acc-sess' },
    h('h2', { id: 'acc-sess' }, t('account.session')),
    h('dl', null,
      h('dt', null, t('account.sess-ends')), h('dd', null, s.expiresAt ? timeNode(new Date(s.expiresAt).toISOString(), i18n.lang) : '-'),
      h('dt', null, t('account.sess-idle')), idleShown),
    err.node,
    h('div', { class: 'actions' },
      h('button', { type: 'button', on: { click: out(false) } }, t('account.logout')),
      h('button', { type: 'button', on: { click: out(true) } }, t('account.logout-all'))),
    h('p', { class: 'hint' }, t('account.logout-all-hint')),
    idleForm(ctx, idleShown));
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

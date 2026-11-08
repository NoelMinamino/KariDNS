// S1: the sign-in form (planning 3).  The same form is the login screen and the dialog that opens over the current screen after a 401.  The code field appears when
// the service asks for it (401 totp-required) or when the user says they have one.  The service gives one answer for every refusal (wrong name, wrong password,
// disabled, locked, wrong code), and so does this screen.  A 429 disables the button until Retry-After has passed.

import { h, fill, oidcLink } from '../dom.js';
import { field, message, problemNodes } from '../widgets.js';
import { render } from '../format.js';

// -> { node, focus(), dispose() }.  onDone(result) is called after a sign-in ({ enrollmentRequired, samePrincipal }); a form given onCancel has a Cancel button (the dialog).
// Below the form: one button for every identity provider the service has (GET /auth/providers; none when it has none or cannot be asked).  A button is a link that leaves the
// page for the provider; route is the place to come back to.
export function loginForm(ctx, { onDone, onCancel, route = '/' }) {
  const { i18n, session, timers } = ctx;
  const t = i18n.t;
  const user = field({ label: t('login.user'), name: 'user', autocomplete: 'username', required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none' });
  const password = field({ label: t('login.password'), type: 'password', name: 'password', autocomplete: 'current-password', required: true, maxlength: 1024 });
  const code = field({ label: t('login.code'), name: 'totp', autocomplete: 'one-time-code', inputmode: 'numeric', maxlength: 6, hint: t('login.code-hint') });
  const codeRow = h('div', { hidden: true }, code.node);
  const haveCode = h('button', { type: 'button', class: 'link', on: { click: () => showCode() } }, t('login.have-code'));
  const error = message('error');
  const submit = h('button', { type: 'submit', class: 'primary' }, t('login.submit'));
  const form = h('form', { class: 'stack', novalidate: true, 'aria-label': t('login.title') }, user.node, password.node, codeRow, error.node, h('div', { class: 'actions' }, submit, onCancel ? h('button', { type: 'button', on: { click: onCancel } }, t('common.cancel')) : null, haveCode));
  let waiting = null;                                     // the countdown of a 429
  let running = false;
  let alive = true;
  const oidc = h('div', { class: 'stack oidc', hidden: true });
  ctx.providers?.().then((list) => {
    if (!alive || list.length === 0) return;
    fill(oidc, h('p', { class: 'hint' }, t('login.or')), h('ul', { class: 'providers', role: 'group', 'aria-label': t('login.oidc-group') },
      list.map((p) => h('li', null, oidcLink(p.name, route, { class: 'button' }, ...i18n.parts('login.oidc-button', { label: render(p.label) }))))));
    oidc.hidden = false;
  });

  function showCode() {
    codeRow.hidden = false;
    haveCode.hidden = true;
    code.focus();
  }

  function stopWaiting() {
    if (waiting !== null) timers.clearInterval(waiting);
    waiting = null;
    submit.disabled = false;
    submit.textContent = t('login.submit');
  }

  // the button waits `seconds`, counting down in its label
  function wait(seconds) {
    stopWaiting();
    let left = Math.max(1, seconds);
    submit.disabled = true;
    const tick = () => {
      if (left <= 0) { stopWaiting(); return; }
      submit.textContent = t('login.wait', { seconds: left });
      left -= 1;
    };
    tick();
    waiting = timers.setInterval(tick, 1000);
  }

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (running || submit.disabled) return;
    error.set(null);
    user.setError(null);
    password.setError(null);
    code.setError(null);
    const u = user.input.value.trim();
    const pw = password.input.value;
    const c = code.input.value.trim();
    if (!u) { user.setError(t('login.need-user')); user.focus(); return; }
    if (!pw) { password.setError(t('login.need-password')); password.focus(); return; }
    if (!codeRow.hidden && !/^\d{6}$/.test(c)) { code.setError(t('login.bad-code')); code.focus(); return; }
    running = true;
    submit.disabled = true;
    try {
      const r = await session.login({ user: u, password: pw, totp: codeRow.hidden ? undefined : c });
      password.input.value = '';
      code.input.value = '';
      onDone(r);
    } catch (e) {
      if (e.code === 'totp-required') {
        showCode();
        error.set(t('login.code-needed'));
      } else if (e.status === 429 && e.retryAfter) {
        error.setNodes(...problemNodes(i18n, e));
        wait(e.retryAfter);
        running = false;
        return;
      } else {
        error.setNodes(...problemNodes(i18n, e));
        if (!codeRow.hidden) { code.input.value = ''; code.focus(); } else password.focus();
      }
    }
    running = false;
    if (waiting === null) submit.disabled = false;
  });

  return { node: h('div', null, form, oidc), focus: () => user.focus(), dispose: () => { alive = false; stopWaiting(); } };
}

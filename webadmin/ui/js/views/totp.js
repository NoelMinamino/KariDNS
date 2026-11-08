// S2: TOTP enrolment (planning 3, 5.3).  POST /auth/totp {enroll} gives the secret and the otpauth:// URI; the QR code is drawn here by our own encoder (the secret
// goes to no other site), the text form of the key is hidden until the user asks, and after the confirmation every element that held the secret is removed and the
// variables are cleared.  The URI itself is never put in the page as text.

import { h, link, fill } from '../dom.js';
import { encodeBest, qrSvg } from '../qr.js';
import { field, message, problemNodes, busy } from '../widgets.js';

// "ABCD EFGH ..." for typing it into an app by hand
const groups = (secret) => secret.replace(/(.{4})/g, '$1 ').trim();

// -> { node, focus() }.  forced: the session cannot do anything else until TOTP is on (the sign-in said enrollment_required)
export function totpView(ctx, { forced = false } = {}) {
  const { api, i18n, session, router } = ctx;
  const t = i18n.t;
  const root = h('section', { class: 'card narrow', 'aria-labelledby': 'totp-title' });
  const error = message('error');
  let secret = null;
  let uri = null;

  function wipe() {
    secret = null;
    uri = null;
    fill(root);
  }

  function failed(e, retry) {
    fill(root, h('h1', { id: 'totp-title' }, t('totp.title')), h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)),
      e.code === 'totp-enabled' ? h('p', null, link(router.href('account'), null, t('totp.to-account'))) : h('button', { type: 'button', on: { click: retry } }, t('common.try-again')));
  }

  function show(r) {
    secret = r.secret;
    uri = r.uri;
    let qr = null;
    try { qr = encodeBest(uri); } catch (e) { if (!(e instanceof RangeError)) throw e; }
    const keyText = h('p', { class: 'key', hidden: true }, h('code', { 'aria-label': t('totp.key-label') }, groups(secret)));
    const toggle = h('button', { type: 'button', 'aria-expanded': 'false', on: { click: () => {
      keyText.hidden = !keyText.hidden;
      toggle.textContent = keyText.hidden ? t('totp.show-key') : t('totp.hide-key');
      toggle.setAttribute('aria-expanded', String(!keyText.hidden));
    } } }, t('totp.show-key'));
    if (!qr) { keyText.hidden = false; toggle.hidden = true; }
    const code = field({ label: t('totp.code'), name: 'code', autocomplete: 'one-time-code', inputmode: 'numeric', maxlength: 6, required: true, hint: t('totp.code-hint') });
    const confirm = h('button', { type: 'submit', class: 'primary' }, t('totp.confirm'));
    const form = h('form', { class: 'stack', novalidate: true }, code.node, error.node, h('div', { class: 'actions' }, confirm,
      forced ? null : link(router.href('account'), { class: 'button' }, t('common.cancel'))));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      error.set(null);
      code.setError(null);
      const c = code.input.value.trim();
      if (!/^\d{6}$/.test(c)) { code.setError(t('totp.bad-code')); code.focus(); return; }
      busy(confirm, async () => {
        try {
          const done = await api.post('/auth/totp', { action: 'confirm', code: c });
          wipe();
          await session.replaced(done);
          fill(root, h('h1', { id: 'totp-title' }, t('totp.title')), h('p', { class: 'msg', role: 'status' }, t('totp.done')),
            link(router.href('home'), { class: 'button primary' }, t('common.continue')));
          ctx.announce(t('totp.done'));
        } catch (e) {
          if (e.code === 'no-enrolment') { failed(e, start); return; }
          error.setNodes(...problemNodes(i18n, e));
          code.focus();
        }
      });
    });
    fill(root,
      h('h1', { id: 'totp-title' }, t('totp.title')),
      forced ? h('p', { class: 'notice' }, t('totp.required')) : null,
      h('ol', { class: 'steps' },
        h('li', null, h('p', null, t('totp.step-scan')), qr ? qrSvg(qr, t('totp.qr-label')) : h('p', { class: 'notice' }, t('totp.no-qr')), h('p', null, toggle), keyText),
        h('li', null, h('p', null, t('totp.step-confirm')), form)),
      h('p', { class: 'hint' }, t('totp.once')));
    code.focus();
  }

  async function start() {
    fill(root, h('h1', { id: 'totp-title' }, t('totp.title')), h('p', { role: 'status' }, t('common.loading')));
    try {
      show(await api.post('/auth/totp', { action: 'enroll' }));
    } catch (e) {
      failed(e, start);
    }
  }

  start();
  return { node: root, dispose: wipe };
}

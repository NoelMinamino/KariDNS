// S13: DNSSEC of one zone (planning 3), display only plus requests (D-SIGNER, 4.9): the keys with their key tags, the DS records to put in the parent zone (copy
// buttons), what the signer is doing (when it signed, when it is due again, how long the signatures last), and the key requests with their state.  A request asks
// karidns-signer to start signing the zone ("enable") or for one more key ("add"); the signer answers it.

import { h, fill } from '../dom.js';
import { render, timeNode } from '../format.js';
import { field, select, message, problemNodes } from '../widgets.js';
import { zonePath, remaining, zoneEditable } from '../zonelib.js';
import { zoneFrame } from './zoneframe.js';

// DNSSEC algorithm numbers (RFC 8624 section 3.1; RFC 4034 appendix A.1 for RSASHA256's number 8)
export const ALGORITHMS = { 8: 'RSASHA256', 10: 'RSASHA512', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448' };

export function dnssecView(ctx, { params }) {
  const { api, i18n, now } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone-dnssec' }, (info) => {
    if (info.role === 'subdomain_master') return { node: h('p', { class: 'notice' }, t('dnssec.not-allowed')) };
    const path = zonePath(ds, info.name);
    const box = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
    let alive = true;
    const sent = message('status');

    const when = (iso) => (iso ? timeNode(iso, i18n.lang) : '-');
    const left = (iso) => {
      const r = iso ? remaining(iso, now()) : null;
      return r === null ? '-' : [t(r.past ? 'dnssec.ago' : 'dnssec.in', { span: r.text }), ' (', timeNode(iso, i18n.lang), ')'];
    };

    function copyButton(text) {
      const note = h('span', { class: 'hint', role: 'status' });
      return h('span', null, h('button', { type: 'button', on: { click: async () => {
        try { await ctx.copy(text); note.textContent = t('account.tok-copied'); } catch { note.textContent = t('account.tok-copy-failed'); }
      } } }, t('dnssec.copy')), ' ', note);
    }

    function status(d) {
      const st = d.signer_state;
      const rows = [
        [t('dnssec.signing'), t(d.signer ? 'dnssec.by-signer' : d.presigned ? 'dnssec.presigned' : 'dnssec.unsigned')],
        d.nsec3param ? ['NSEC3PARAM', render(d.nsec3param)] : null,
        [t('zone.serial'), String(d.serial ?? '-')],
        d.signer ? [t('dnssec.waiting'), t(d.waiting_for_signer ? 'common.yes' : 'common.no')] : null,
        st ? [t('dnssec.signed-at'), when(st.signed_at)] : null,
        st ? [t('dnssec.signed-serial'), String(st.signed_serial ?? '-')] : null,
        st ? [t('dnssec.next-due'), left(st.next_due)] : null,
        st ? [t('dnssec.min-expire'), left(st.min_expire)] : null,
        st ? [t('dnssec.attempts'), String(st.attempts ?? 0)] : null,
      ].filter(Boolean);
      return h('section', { class: 'card', 'aria-labelledby': 'dnssec-title' }, h('h2', { id: 'dnssec-title' }, t('dnssec.title')),
        h('dl', null, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
        st?.last_error ? h('div', { class: 'notice' }, h('strong', null, t('dnssec.last-error')), ' ', h('code', { class: 'pre' }, render(st.last_error))) : null);
    }

    function keys(d) {
      const rows = d.keys.map((k) => h('tr', null,
        h('th', { scope: 'row' }, k.key_tag === null ? '-' : String(k.key_tag)),
        h('td', null, t(k.sep ? 'dnssec.ksk' : 'dnssec.zsk')),
        h('td', null, `${k.algorithm}${ALGORITHMS[k.algorithm] ? ` ${ALGORITHMS[k.algorithm]}` : ''}`),
        h('td', null, `${k.flags}`),
        h('td', null, k.ttl === null || k.ttl === undefined ? '-' : String(k.ttl))));
      const dsRows = d.ds.map((x) => h('tr', null,
        h('th', { scope: 'row' }, String(x.key_tag)),
        h('td', null, `${x.algorithm} / ${x.digest_type}`),
        h('td', null, h('code', null, render(x.text))),
        h('td', null, copyButton(`${info.name} IN DS ${x.text}`))));
      return h('section', { class: 'card', 'aria-labelledby': 'keys-title' }, h('h2', { id: 'keys-title' }, t('dnssec.keys')),
        d.keys.length === 0 ? h('p', null, t('dnssec.no-keys')) : h('table', null, h('caption', { class: 'sr-only' }, t('dnssec.keys')),
          h('thead', null, h('tr', null, ...['tag', 'role', 'algorithm', 'flags', 'ttl'].map((k) => h('th', { scope: 'col' }, t(`dnssec.h-${k}`))))), h('tbody', null, rows)),
        h('h3', null, t('dnssec.ds')), h('p', { class: 'hint' }, t('dnssec.ds-hint')),
        d.ds.length === 0 ? h('p', null, t('dnssec.no-ds')) : h('table', null, h('caption', { class: 'sr-only' }, t('dnssec.ds')),
          h('thead', null, h('tr', null, ...['tag', 'algdigest', 'ds', 'copy'].map((k) => h('th', { scope: 'col' }, t(`dnssec.h-${k}`))))), h('tbody', null, dsRows)));
    }

    function requests(d) {
      const rows = d.requests.map((r) => h('tr', null,
        h('th', { scope: 'row' }, String(r.id)),
        h('td', null, render(r.kind)),
        h('td', null, `${r.algorithm}${r.bits ? `/${r.bits}` : ''} ${r.key_type}${r.nsec ? ` ${r.nsec}` : ''}`),
        h('td', null, render(r.state)),
        h('td', null, r.message ? render(r.message) : '-'),
        h('td', null, when(r.created_at)),
        h('td', null, when(r.done_at))));
      return h('section', { class: 'card', 'aria-labelledby': 'req-title' }, h('h2', { id: 'req-title' }, t('dnssec.requests')),
        d.requests.length === 0 ? h('p', null, t('dnssec.no-requests')) : h('table', null, h('caption', { class: 'sr-only' }, t('dnssec.requests')),
          h('thead', null, h('tr', null, ...['id', 'kind', 'what', 'state', 'message', 'created', 'done'].map((k) => h('th', { scope: 'col' }, t(`dnssec.h-r-${k}`))))), h('tbody', null, rows)));
    }

    function requestForm(d) {
      if (zoneEditable(info) !== null) return h('p', { class: 'notice' }, t('dnssec.no-requests-here'));
      const kind = select({ label: t('dnssec.r-kind'), name: 'kind', options: d.signer ? [{ value: 'add', label: t('dnssec.r-add') }] : [{ value: 'enable', label: t('dnssec.r-enable') }], value: d.signer ? 'add' : 'enable' });
      const alg = select({ label: t('dnssec.r-alg'), name: 'algorithm', options: Object.entries(ALGORITHMS).map(([n, name]) => ({ value: n, label: `${n} ${name}` })), value: '13' });
      const bits = field({ label: t('dnssec.r-bits'), name: 'bits', inputmode: 'numeric', maxlength: 4, hint: t('dnssec.r-bits-hint') });
      const type = select({ label: t('dnssec.r-type'), name: 'key_type', options: ['csk', 'ksk', 'zsk'].map((x) => ({ value: x, label: x })), value: 'csk' });
      const nsec = d.signer ? null : select({ label: t('dnssec.r-nsec'), name: 'nsec', options: [{ value: 'nsec3', label: 'NSEC3' }, { value: 'nsec', label: 'NSEC' }], value: 'nsec3' });
      const err = message('error');
      const go = h('button', { type: 'submit', class: 'primary' }, t('dnssec.r-send'));
      const bitsRow = h('div', { hidden: true }, bits.node);
      const rsa = () => ['8', '10'].includes(alg.input.value);
      alg.input.addEventListener('change', () => { bitsRow.hidden = !rsa(); });
      const form = h('form', { class: 'stack', novalidate: true }, h('p', null, t('dnssec.r-intro')), kind.node, alg.node, bitsRow, type.node, nsec?.node, err.node, h('div', { class: 'actions' }, go));
      form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        err.set(null);
        sent.set(null);
        bits.setError(null);
        const body = { kind: kind.input.value, algorithm: Number(alg.input.value), key_type: type.input.value };
        if (nsec) body.nsec = nsec.input.value;
        if (rsa() && bits.input.value.trim() !== '') {
          const n = Number(bits.input.value.trim());
          if (!/^\d{4}$/.test(bits.input.value.trim()) || n < 1024 || n > 8192) { bits.setError(t('dnssec.r-bad-bits')); bits.focus(); return; }
          body.bits = n;
        }
        go.disabled = true;
        try {
          await api.post(`${path}/dnssec/requests`, body);
          sent.set(t('dnssec.r-sent'));
          ctx.announce(t('dnssec.r-sent'));
          await load();
        } catch (e) {
          err.setNodes(...problemNodes(i18n, e));
        } finally {
          go.disabled = false;
        }
      });
      return h('section', { class: 'card', 'aria-labelledby': 'rform-title' }, h('h2', { id: 'rform-title' }, t('dnssec.r-title')), form);
    }

    async function load() {
      try {
        const d = (await api.get(`${path}/dnssec`)).dnssec;
        if (!alive) return;
        fill(box, status(d), keys(d), requests(d), sent.node, requestForm(d),
          h('p', null, h('button', { type: 'button', on: { click: () => load() } }, t('dnssec.refresh'))));
      } catch (e) {
        if (alive) fill(box, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
      }
    }
    load();
    return { node: box, dispose() { alive = false; } };
  });
}

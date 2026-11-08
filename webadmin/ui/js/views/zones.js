// S3: the zones the person has a grant on (planning 3): a dataset selector (hidden when there is one), a search (a part of the name or its start, the kind, signed or
// not), the role per zone, and paging by cursor ("next", no totals).  For a global master also the way to a new zone and the reload of a whole dataset.

import { h, link, fill } from '../dom.js';
import { render } from '../format.js';
import { field, select, message, problemNodes, confirmButton, isGlobal } from '../widgets.js';
import { datasetPath } from '../zonelib.js';
import { reloadText } from './change.js';

const KINDS = ['NATIVE', 'MASTER', 'SLAVE', 'PRODUCER', 'CONSUMER'];
const SEARCH = /^[A-Za-z0-9_.-]+$/;

export function zonesView(ctx, { query }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const root = h('section', { class: 'card', 'aria-labelledby': 'zones-title' }, h('h1', { id: 'zones-title' }, t('zones.title')), body);
  const global = isGlobal(ctx);
  const flash = ctx.flash ?? null;                     // what the screen before left to say ("the zone was deleted")
  ctx.flash = null;
  let alive = true;

  function badges(z) {
    return [
      z.signer ? h('span', { class: 'badge' }, t('zone.b-signer')) : null,
      z.presigned && !z.signer ? h('span', { class: 'badge' }, t('zone.b-presigned')) : null,
      z.catalog ? h('span', { class: 'badge' }, t('zones.b-catalog', { catalog: z.catalog })) : null,
    ];
  }

  function draw(datasets, ds, r) {
    const q = field({ label: t('zones.search'), name: 'q', value: query.q ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none' });
    const mode = select({ label: t('zones.mode'), name: 'mode', options: [{ value: 'contains', label: t('zones.mode-contains') }, { value: 'prefix', label: t('zones.mode-prefix') }], value: query.mode === 'prefix' ? 'prefix' : 'contains' });
    const kind = select({ label: t('zones.kind'), name: 'kind', options: [{ value: '', label: t('zones.any') }, ...KINDS.map((k) => ({ value: k, label: k }))], value: KINDS.includes(query.kind) ? query.kind : '' });
    const signed = select({ label: t('zones.signed'), name: 'signed', options: [{ value: '', label: t('zones.any') }, { value: 'true', label: t('zones.signed-yes') }, { value: 'false', label: t('zones.signed-no') }], value: ['true', 'false'].includes(query.signed) ? query.signed : '' });
    const dsSel = datasets.length > 1 ? select({ label: t('zones.dataset'), name: 'ds', options: datasets.map((d) => ({ value: d.name, label: d.name })), value: ds }) : null;
    const form = h('form', { class: 'search', novalidate: true }, dsSel?.node, q.node, mode.node, kind.node, signed.node, h('div', { class: 'actions' }, h('button', { type: 'submit', class: 'primary' }, t('zones.find'))));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      q.setError(null);
      const text = q.input.value.trim();
      if (text !== '' && !SEARCH.test(text)) { q.setError(t('zones.bad-search')); q.focus(); return; }
      router.go('zones', undefined, { ds: dsSel ? dsSel.input.value : ds, q: text, mode: mode.input.value, kind: kind.input.value, signed: signed.input.value });
    });
    const rows = r.zones.map((z) => h('tr', null,
      h('th', { scope: 'row' }, link(router.href('zone', { ds, zone: z.name }), null, render(z.name))),
      h('td', null, t(`role.${z.role}`)),
      h('td', null, render(z.kind)),
      h('td', null, z.serial === null || z.serial === undefined ? '-' : String(z.serial)),
      h('td', null, badges(z))));
    const next = r.next_cursor ? link(router.href('zones', undefined, { ...query, ds, cursor: r.next_cursor }), { class: 'button' }, t('zones.next')) : null;
    const first = query.cursor ? link(router.href('zones', undefined, { ...query, ds, cursor: undefined }), null, t('zones.first')) : null;
    fill(body, flash ? h('p', { class: 'msg ok', role: 'status' }, flash) : null, form,
      global ? dataset(ds) : null,
      r.zones.length === 0 ? h('p', null, t(query.cursor ? 'zones.no-more' : 'zones.none')) : h('table', null,
        h('caption', { class: 'sr-only' }, t('zones.caption')),
        h('thead', null, h('tr', null, ...['name', 'role', 'kind', 'serial', 'flags'].map((k) => h('th', { scope: 'col' }, t(`zones.h-${k}`))))),
        h('tbody', null, rows)),
      next || first ? h('p', { class: 'actions pager' }, first, next) : null);
  }

  // what a global master does with a whole dataset: make a zone in it, reload every zone of it (PostgreSQL)
  function dataset(ds) {
    const msg = message('status');
    const err = message('error');
    const ask = confirmButton({ label: t('zones.reload-all'), confirmLabel: t('zones.reload-all-ask'), yes: t('common.yes'), no: t('common.no'), cls: '', onConfirm: async () => {
      err.set(null);
      msg.set(null);
      try {
        const r = await api.post(`${datasetPath(ds)}/reload`, {});
        msg.set(reloadText(ctx, r.reload));
      } catch (e) {
        err.setNodes(...problemNodes(i18n, e));
      }
    } });
    return h('div', { class: 'actions' }, link(router.href('create', { ds }), { class: 'button' }, t('zones.new')), ask, msg.node, err.node);
  }

  async function load() {
    try {
      const datasets = (await api.get('/datasets')).datasets;
      if (!alive) return;
      if (datasets.length === 0) { fill(body, h('p', null, t('zones.no-datasets'))); return; }
      const ds = datasets.some((d) => d.name === query.ds) ? query.ds : datasets[0].name;
      const text = query.q ?? '';
      const r = await api.get(`${datasetPath(ds)}/zones`, {
        query: {
          limit: 100, cursor: query.cursor, kind: KINDS.includes(query.kind) ? query.kind : undefined, signed: ['true', 'false'].includes(query.signed) ? query.signed : undefined,
          [query.mode === 'prefix' ? 'prefix' : 'contains']: SEARCH.test(text) ? text : undefined,
        },
      });
      if (alive) draw(datasets, ds, r);
    } catch (e) {
      if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
    }
  }
  load();
  return { node: root, dispose() { alive = false; } };
}

// S8: the settings of one zone (planning 3): its attributes, the metadata it has, and (for global masters) the catalog and views it is in, the metadata the service
// writes, and deleting the zone.  Everybody with a grant reads; the service refuses the rest, and the form for it is not offered.

import { h, fill } from '../dom.js';
import { render } from '../format.js';
import { field, select, checkbox, message, problemNodes, confirmButton } from '../widgets.js';
import { zonePath, datasetPath, recordLines } from '../zonelib.js';
import { placeOnFields } from '../pointer.js';
import { zoneFrame } from './zoneframe.js';
import { reloadText } from './change.js';

export function zoneSettingsView(ctx, { params }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone-settings' }, (info, frame) => {
    const global = ctx.session.state.me.capabilities?.global === true;
    const path = zonePath(ds, info.name);
    const box = h('div', { class: 'stack' });
    let alive = true;

    // ---------------------------------------------------------------------------------------------------------- attributes
    function attributes(views) {
      const rows = [
        [t('settings.kind'), render(info.kind)],
        [t('settings.catalog'), info.catalog ? render(info.catalog) : '-'],
        [t('settings.views'), info.views?.length ? render(info.views.join(', ')) : '-'],
        info.master ? [t('settings.masters'), render(info.master)] : null,
        info.account ? [t('settings.account'), render(info.account)] : null,
        info.nsec3param ? ['NSEC3PARAM', render(info.nsec3param)] : null,
      ].filter(Boolean);
      const parts = [h('h2', { id: 'attr-title' }, t('settings.attributes')), h('dl', null, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]))];
      if (global) {
        const catalog = field({ label: t('settings.catalog'), name: 'catalog', value: info.catalog ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('settings.catalog-hint') });
        const boxes = views.map((v) => ({ name: v, cb: checkbox({ label: v, name: `view-${v}`, checked: info.views?.includes(v) === true }) }));
        const err = message('error');
        const ok = message('status');
        const save = h('button', { type: 'submit', class: 'primary' }, t('settings.save'));
        const form = h('form', { class: 'stack', novalidate: true }, catalog.node,
          boxes.length ? h('fieldset', null, h('legend', null, t('settings.views')), boxes.map((b) => b.cb.node)) : null, err.node, ok.node, h('div', { class: 'actions' }, save));
        form.addEventListener('submit', async (ev) => {
          ev.preventDefault();
          err.set(null);
          ok.set(null);
          catalog.setError(null);
          const body = { catalog: catalog.input.value.trim() === '' ? null : catalog.input.value.trim() };
          if (boxes.length) body.views = boxes.filter((b) => b.cb.input.checked).map((b) => b.name);
          save.disabled = true;
          try {
            const r = await api.patch(path, body);
            info.catalog = r.catalog;
            info.views = r.views;
            ok.set(t('settings.saved'));
            ctx.announce(t('settings.saved'));
            frame.refresh();
          } catch (e) {
            const loose = e.errors?.length ? placeOnFields(e.errors, { '/catalog': catalog, '/views': catalog }) : [];
            if (e.code === 'not-a-catalog') catalog.setError(i18n.errorText(e));
            else if (loose.length || !e.errors?.length) err.setNodes(...problemNodes(i18n, e));
          } finally {
            save.disabled = false;
          }
        });
        parts.push(h('h3', null, t('settings.change')), form);
      }
      return h('section', { class: 'card', 'aria-labelledby': 'attr-title' }, parts);
    }

    // ---------------------------------------------------------------------------------------------------------- metadata
    const metaBox = h('section', { class: 'card', 'aria-labelledby': 'meta-title' }, h('h2', { id: 'meta-title' }, t('settings.metadata')), h('p', { role: 'status' }, t('common.loading')));
    const metaOk = message('status');                 // outside the redrawn part: it says "saved" after the list was read again
    let metaKind = null;                                  // the kind that was chosen, kept over the redraw

    function drawMeta(m) {
      const kinds = m.writable ?? [];
      const rows = m.metadata.map((x) => h('tr', null, h('th', { scope: 'row' }, render(x.kind)), h('td', null, x.content.map((c) => h('div', null, render(c)))),
        h('td', null, kinds.includes(x.kind) ? t('settings.m-writable') : t('settings.m-readonly'))));
      const parts = [h('h2', { id: 'meta-title' }, t('settings.metadata')),
        m.metadata.length === 0 ? h('p', null, t('settings.m-none')) : h('table', null, h('caption', { class: 'sr-only' }, t('settings.metadata')),
          h('thead', null, h('tr', null, ...['kind', 'values', 'access'].map((k) => h('th', { scope: 'col' }, t(`settings.m-h-${k}`))))), h('tbody', null, rows))];
      if (global && kinds.length > 0) {
        const sel = select({ label: t('settings.m-kind'), name: 'kind', options: kinds.map((k) => ({ value: k, label: k })), value: kinds.includes(metaKind) ? metaKind : kinds[0] });
        const values = field({ label: t('settings.m-values'), name: 'content', kind: 'textarea', rows: 4, spellcheck: false, autocapitalize: 'none', hint: t('settings.m-values-hint') });
        const err = message('error');
        const fill1 = () => { values.input.value = (m.metadata.find((x) => x.kind === sel.input.value)?.content ?? []).join('\n'); };
        sel.input.addEventListener('change', () => { metaKind = sel.input.value; fill1(); });
        fill1();
        async function send(fn) {
          err.set(null);
          metaOk.set(null);
          values.setError(null);
          try {
            await fn();
            await loadMeta();
            metaOk.set(t('settings.saved'));
            ctx.announce(t('settings.saved'));
          } catch (e) {
            const loose = e.errors?.length ? placeOnFields(e.errors, { '/content': values }) : [];
            if (!e.errors?.length || loose.length) err.setNodes(...problemNodes(i18n, e));
          }
        }
        const save = h('button', { type: 'submit', class: 'primary' }, t('settings.save'));
        const form = h('form', { class: 'stack', novalidate: true }, h('h3', null, t('settings.m-set')), sel.node, values.node, err.node, metaOk.node,
          h('div', { class: 'actions' }, save,
            confirmButton({ label: t('settings.m-delete'), confirmLabel: t('settings.m-delete-ask'), yes: t('common.yes'), no: t('common.no'), onConfirm: () => send(() => api.del(`${path}/metadata/${encodeURIComponent(sel.input.value)}`)) })));
        form.addEventListener('submit', (ev) => {
          ev.preventDefault();
          send(() => api.put(`${path}/metadata/${encodeURIComponent(sel.input.value)}`, { content: recordLines(values.input.value) }));
        });
        parts.push(form);
      }
      fill(metaBox, parts);
    }

    async function loadMeta() {
      try {
        const m = await api.get(`${path}/metadata`);
        if (alive) drawMeta(m);
      } catch (e) {
        if (alive) fill(metaBox, h('h2', { id: 'meta-title' }, t('settings.metadata')), h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
      }
    }

    // ---------------------------------------------------------------------------------------------------------- delete
    function danger() {
      const confirm = field({ label: t('settings.del-confirm'), name: 'confirm', required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('settings.del-hint', { zone: info.name }) });
      const reload = checkbox({ label: t('flow.reload'), name: 'reload', checked: ctx.session.state.version?.ui?.reload_after_change === true });
      const err = message('error');
      const del = h('button', { type: 'submit', class: 'danger' }, t('settings.del'));
      const form = h('form', { class: 'stack', novalidate: true }, confirm.node, reload.node, err.node, h('div', { class: 'actions' }, del));
      form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        err.set(null);
        confirm.setError(null);
        if (confirm.input.value.trim().toLowerCase().replace(/\.$/, '') !== info.name.toLowerCase().replace(/\.$/, '')) { confirm.setError(t('settings.del-mismatch')); confirm.focus(); return; }
        del.disabled = true;
        try {
          const r = await api.del(path, { body: { confirm: confirm.input.value.trim(), reload: reload.input.checked } });
          ctx.drafts.of(ds, info.name).clear();
          ctx.announce(t('settings.deleted', { zone: info.name }));
          ctx.flash = t('settings.deleted-state', { zone: info.name, state: reloadText(ctx, r.reload) });
          router.go('zones', undefined, { ds });
        } catch (e) {
          err.setNodes(...problemNodes(i18n, e));
        } finally {
          del.disabled = false;
        }
      });
      return h('section', { class: 'card danger-zone', 'aria-labelledby': 'del-title' }, h('h2', { id: 'del-title' }, t('settings.del-title')), h('p', null, t('settings.del-text')), form);
    }

    (async () => {
      let views = [];
      if (global) {
        try { views = (await api.get('/datasets')).datasets.find((d) => d.name === ds)?.views ?? []; } catch { /* the form is offered without views */ }
      }
      if (!alive) return;
      fill(box, attributes(views), metaBox, global ? danger() : null);
      loadMeta();
    })();
    return { node: box, dispose() { alive = false; } };
  });
}

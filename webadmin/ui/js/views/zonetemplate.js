// S10, "apply to a zone" (planning 3; A-17): every record set of a template REPLACES the zone's record set of the same name and type; the zone's other record sets stay.  It
// is a change set like any other, so there is a preview (a dry run) and the same refusals; the copy is the only link between a zone and a template (the version names the
// template and its revision).  To undo it, roll back to the version before.

import { h, link, fill } from '../dom.js';
import { render } from '../format.js';
import { field, select, problemNodes } from '../widgets.js';
import { zonePath, zoneEditable } from '../zonelib.js';
import { changeFlow } from './change.js';
import { zoneFrame } from './zoneframe.js';

export function zoneTemplateView(ctx, { params }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone-template' }, (info, frame) => {
    const locked = zoneEditable(info);
    if (info.role === 'subdomain_master') return { node: h('p', { class: 'notice' }, t('tpl.apply-not-allowed')) };
    if (locked !== null) return { node: h('section', { class: 'card' }, h('p', { class: 'notice' }, t(`reason.${locked}`))) };
    const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
    let alive = true;
    let flow = null;

    function draw(list) {
      if (list.length === 0) { fill(body, h('p', null, t('tpl.apply-none'))); return; }
      const pick = select({ label: t('tpl.apply-pick'), name: 'template', options: list.map((x) => ({ value: String(x.id), label: x.name })), value: String(list[0].id) });
      const ttl = field({ label: t('tpl.apply-ttl'), name: 'default_ttl', value: '3600', inputmode: 'numeric', maxlength: 10, hint: t('tpl.apply-ttl-hint') });
      const view = h('p', null, h('span', { class: 'hint' }, t('tpl.apply-view')), ' ', link(router.href('template', { id: String(list[0].id) }), null, render(list[0].name)));
      const refreshLink = () => fill(view, h('span', { class: 'hint' }, t('tpl.apply-view')), ' ', link(router.href('template', { id: pick.input.value }), null, render(list.find((x) => String(x.id) === pick.input.value)?.name ?? '')));
      flow = changeFlow(ctx, {
        zone: info.name,
        reloadable: !info.signer,
        reloadDefault: ctx.session.state.version?.ui?.reload_after_change === true,
        previewLabel: t('tpl.apply-preview'),
        commitLabel: t('tpl.apply-commit'),
        check: () => {
          ttl.setError(null);
          const s = ttl.input.value.trim();
          if (s !== '' && (!/^\d{1,10}$/.test(s) || Number(s) > 2147483647)) { ttl.setError(t('tpl.bad-number')); ttl.focus(); return true; }
          return false;
        },
        run: (dry, v) => {
          const b = { template_id: Number(pick.input.value) };
          if (ttl.input.value.trim() !== '') b.default_ttl = Number(ttl.input.value.trim());
          if (v.comment.trim() !== '') b.comment = v.comment.trim();
          if (v.reload !== undefined) b.reload = v.reload;
          if (dry) b.dry_run = true;
          return api.post(`${zonePath(ds, info.name)}/apply-template`, b);
        },
        onCommitted: () => frame.refresh(),
      });
      pick.input.addEventListener('change', () => { refreshLink(); flow.invalidate(); });
      ttl.input.addEventListener('input', () => flow.invalidate());
      fill(body, pick.node, view, ttl.node, flow.node);
    }

    api.get('/templates', { query: { limit: 500 } }).then((r) => { if (alive) draw(r.templates); },
      (e) => { if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e))); });
    return {
      node: h('section', { class: 'card', 'aria-labelledby': 'tplapply-title' }, h('h2', { id: 'tplapply-title' }, t('tpl.apply-title')), h('p', null, t('tpl.apply-intro')), body),
      dispose() { alive = false; flow?.dispose(); },
    };
  });
}

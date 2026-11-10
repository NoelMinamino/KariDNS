// S12: the audit log (planning 3): who changed what and when, newest first, with the filters of the API (zone, user or group, change set, table, since, until) and paging
// by cursor.  A global master reads all of it, a domain master the rows of its zones.  The `before` and `after` of a row are the database's rows as JSON: they are shown as
// text, pretty-printed, and never interpreted (what is in them was written by others: it is hostile like any zone data).  A change set links to the versions of its zone
// where there is a version.

import { h, link, fill } from '../dom.js';
import { render, plain, timeNode } from '../format.js';
import { field, problemNodes } from '../widgets.js';
import { auditQuery, lookupPrincipal, datasetOfRow, jsonLines } from '../adminlib.js';

const OPS = new Set(['I', 'U', 'D']);

function jsonBlock(t, label, value) {
  if (value === null || value === undefined) return null;
  const j = jsonLines(value);
  return h('div', null, h('p', { class: 'hint' }, label),
    h('pre', { class: 'json' }, j.lines.map((l) => h('div', null, render(l)))),
    j.cut ? h('p', { class: 'hint' }, t('audit.cut')) : null);
}

export function auditView(ctx, { query }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const root = h('section', { class: 'card', 'aria-labelledby': 'audit-title' }, h('h1', { id: 'audit-title' }, t('audit.title')), h('p', null, t('audit.intro')), body);
  let alive = true;

  const fields = {
    zone: field({ label: t('audit.f-zone'), name: 'zone', value: query.zone ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none' }),
    who: field({ label: t('audit.f-who'), name: 'who', value: query.who ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none' }),
    change_set: field({ label: t('audit.f-change-set'), name: 'change_set', value: query.change_set ?? '', maxlength: 64, spellcheck: false, autocapitalize: 'none' }),
    table: field({ label: t('audit.f-table'), name: 'table', value: query.table ?? '', maxlength: 64, spellcheck: false, autocapitalize: 'none', hint: t('audit.f-table-hint') }),
    since: field({ label: t('audit.f-since'), name: 'since', value: query.since ?? '', maxlength: 40, spellcheck: false, autocapitalize: 'none', hint: t('audit.f-time-hint') }),
    until: field({ label: t('audit.f-until'), name: 'until', value: query.until ?? '', maxlength: 40, spellcheck: false, autocapitalize: 'none' }),
  };
  const form = h('form', { class: 'search', novalidate: true }, Object.values(fields).map((f) => f.node), h('div', { class: 'actions' }, h('button', { type: 'submit', class: 'primary' }, t('audit.filter'))));
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const q = {};
    for (const [k, f] of Object.entries(fields)) q[k] = f.input.value.trim();
    router.go('audit', undefined, q);
  });
  const result = h('div', { class: 'stack' });
  fill(body, form, result);

  function row(r, datasets) {
    const ds = r.zone ? datasetOfRow(datasets, r.schema) : null;
    const who = r.principal ? render(r.principal) : (r.db_role ? render(r.db_role) : '-');
    return h('tr', null,
      h('td', null, timeNode(r.at, i18n.lang)),
      h('td', null, who),
      h('td', null, render(r.table), ' ', OPS.has(r.op) ? t(`audit.op-${r.op}`) : render(r.op)),
      h('td', null, r.zone ? render(r.zone) : '-'),
      h('td', null, r.change_set ? [h('code', null, render(r.change_set)), ' ',
        link(router.href('audit', undefined, { change_set: r.change_set }), { 'aria-label': t('audit.same-change-of', { id: plain(r.id) }) }, t('audit.same-change')),
        ds ? [' ', link(router.href('zone-versions', { ds, zone: r.zone }, { cs: r.change_set }), { 'aria-label': t('audit.version-of', { id: plain(r.id) }) }, t('audit.version'))] : null] : '-'),
      h('td', null, h('details', null, h('summary', null, t('audit.details', { id: plain(r.id) })),
        h('dl', null, [[t('audit.d-source'), render(r.source ?? '-')], [t('audit.d-role'), r.db_role ? render(r.db_role) : '-'], [t('audit.d-row'), r.row_id === null || r.row_id === undefined ? '-' : render(String(r.row_id))]]
          .map(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
        jsonBlock(t, t('audit.before'), r.before), jsonBlock(t, t('audit.after'), r.after))));
  }

  async function load() {
    for (const f of Object.values(fields)) f.setError(null);
    try {
      let principalId;
      if (query.who) {
        const p = await lookupPrincipal(api, query.who);
        if (!alive) return;
        if (!p) { fields.who.setError(t('grants.no-principal')); fill(result, h('p', null, t('audit.none'))); return; }
        principalId = p.id;
      }
      const q = auditQuery(query, principalId);
      if (q.error) { fields[q.error].setError(t(`audit.bad-${q.error}`)); fill(result, h('p', null, t('audit.none'))); return; }
      const [r, d] = await Promise.all([api.get('/audit', { query: q.query }), api.get('/datasets').catch(() => ({ datasets: [] }))]);
      if (!alive) return;
      const next = r.next_cursor ? router.href('audit', undefined, { ...query, cursor: r.next_cursor }) : null;
      const first = query.cursor ? router.href('audit', undefined, { ...query, cursor: undefined }) : null;
      fill(result,
        r.audit.length === 0 ? h('p', null, t(query.cursor ? 'audit.no-more' : 'audit.none')) : h('table', { class: 'audit' }, h('caption', { class: 'sr-only' }, t('audit.title')),
          h('thead', null, h('tr', null, ...['when', 'who', 'what', 'zone', 'change-set', 'details'].map((k) => h('th', { scope: 'col' }, t(`audit.h-${k}`))))),
          h('tbody', null, r.audit.map((x) => row(x, d.datasets)))),
        next || first ? h('p', { class: 'actions pager' }, first ? link(first, null, t('audit.first')) : null, next ? link(next, { class: 'button' }, t('audit.next')) : null) : null);
    } catch (e) {
      if (alive) fill(result, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
    }
  }
  load();
  return { node: root, dispose() { alive = false; } };
}

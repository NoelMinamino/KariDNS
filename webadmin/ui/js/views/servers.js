// S14: the servers (planning 3): per dataset and server the generation that has been applied, whether every zone loaded, and the zones that did not (the service shows a
// person the lines of its own zones only).  SQLite3 has no such table: the service says so and the page shows its note.  Refreshed when the person asks.

import { h, fill } from '../dom.js';
import { render, timeNode } from '../format.js';
import { problemNodes } from '../widgets.js';

export function serversView(ctx) {
  const { api, i18n } = ctx;
  const t = i18n.t;
  const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const root = h('section', { class: 'card', 'aria-labelledby': 'servers-title' }, h('h1', { id: 'servers-title' }, t('servers.title')), body);
  let alive = true;

  async function load() {
    try {
      const r = await api.get('/servers');
      if (!alive) return;
      const rows = r.servers.map((s) => h('tr', null,
        h('th', { scope: 'row' }, render(s.server_id)),
        h('td', null, render(s.dataset)),
        h('td', null, String(s.generation)),
        h('td', null, s.applied_at ? timeNode(s.applied_at, i18n.lang) : '-'),
        h('td', null, t(s.ok ? 'servers.ok' : 'servers.failed')),
        h('td', null, s.failed_zones.length === 0 ? '-' : s.failed_zones.map((l) => h('div', null, render(l))))));
      fill(body,
        r.servers.length === 0 ? h('p', null, t('servers.none')) : h('table', null, h('caption', { class: 'sr-only' }, t('servers.title')),
          h('thead', null, h('tr', null, ...['server', 'dataset', 'generation', 'applied', 'state', 'zones'].map((k) => h('th', { scope: 'col' }, t(`servers.h-${k}`))))), h('tbody', null, rows)),
        r.note ? h('p', { class: 'notice' }, render(r.note)) : null,
        h('p', null, h('button', { type: 'button', on: { click: () => load() } }, t('servers.refresh'))));
    } catch (e) {
      if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)), h('button', { type: 'button', on: { click: () => load() } }, t('common.try-again')));
    }
  }
  load();
  return { node: root, dispose() { alive = false; } };
}

// S16: About (planning 3): the versions of the service and of the tools it runs, and of these files.  A difference between the service's version and the GUI's own
// means the page is old: "reload the page" (4.4).

import { h, fill } from '../dom.js';
import { render } from '../format.js';
import { GUI_VERSION } from '../version.js';
import { problemNodes } from '../widgets.js';

export function aboutView(ctx) {
  const { api, i18n, session } = ctx;
  const t = i18n.t;
  const body = h('div', null, h('p', { role: 'status' }, t('common.loading')));
  const root = h('section', { class: 'card', 'aria-labelledby': 'about-title' }, h('h1', { id: 'about-title' }, t('about.title')), body);
  api.get('/version').then((v) => {
    session.state.version = v;
    const rows = [
      [t('about.gui'), GUI_VERSION],
      [t('about.service'), v.version],
      ...Object.entries(v.tools ?? {}).map(([k, val]) => [k, val]),
      [t('about.datasets'), (v.datasets ?? []).join(', ')],
      [t('about.types'), v.types ? String(v.types.length) : t('about.unknown')],
    ];
    fill(body,
      v.version !== GUI_VERSION ? h('p', { class: 'notice', role: 'alert' }, t('about.mismatch')) : null,
      h('dl', null, rows.map(([k, val]) => [h('dt', null, render(k)), h('dd', null, render(val))])));
  }, (e) => fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e))));
  return { node: root };
}

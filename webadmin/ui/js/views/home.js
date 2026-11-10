// The start page after the sign-in: who you are and what you may do (the effective grants of GET /auth/me, planning 2), and the way to the zones (S3).

import { h, link } from '../dom.js';
import { render } from '../format.js';

const ROLES = ['global_master', 'domain_master', 'subdomain_master'];

export function homeView(ctx) {
  const { i18n, session, router } = ctx;
  const t = i18n.t;
  const me = session.state.me;
  const p = me.principal;
  const scope = (g) => {
    if (g.role === 'global_master') return t('home.scope-all');
    return [g.dataset, g.suffix ? `${g.suffix} (${g.zone})` : g.zone].filter(Boolean).join(' / ');
  };
  const rows = me.grants.map((g) => h('tr', null,
    h('th', { scope: 'row' }, ROLES.includes(g.role) ? t(`role.${g.role}`) : render(g.role)),
    h('td', null, render(scope(g))),
    h('td', null, g.policy ? render(g.policy.name) : '-'),
    h('td', null, g.via ? render(g.via) : '-')));
  return {
    node: h('div', { class: 'stack' },
      h('section', { class: 'card', 'aria-labelledby': 'home-title' },
        h('h1', { id: 'home-title' }, ...i18n.parts('home.title', { name: h('span', null, render(p.display_name ?? p.name)) })),
        h('p', null, t('home.intro')),
        h('p', { class: 'actions' }, link(router.href('zones'), { class: 'button primary' }, t('nav.zones')), link(router.href('account'), { class: 'button' }, t('nav.account')))),
      h('section', { class: 'card', 'aria-labelledby': 'home-access' },
        h('h2', { id: 'home-access' }, t('home.access')),
        me.grants.length === 0 ? h('p', null, t('home.no-grants')) : h('table', null,
          h('thead', null, h('tr', null, ...['role', 'scope', 'policy', 'via'].map((k) => h('th', { scope: 'col' }, t(`home.h-${k}`))))),
          h('tbody', null, rows)))),
  };
}

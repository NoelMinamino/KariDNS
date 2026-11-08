// S11, the "Grants" section of a zone (planning 3): who holds a grant on this zone, and the form to give one.  A domain master may give domain-master and subdomain-master
// grants on ITS zone with a record policy no wider than its own; a global master may give any.  The service enforces it (403 `escalation`, a grant one cannot see is
// 404); the page lists the policies it believes are within the person's own and shows the service's refusal otherwise.

import { h, fill } from '../dom.js';
import { problemNodes, isGlobal } from '../widgets.js';
import { zoneFrame } from './zoneframe.js';
import { grantsTable, grantForm } from './grants.js';

export function zoneGrantsView(ctx, { params }) {
  const { api, i18n } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone-grants' }, (info) => {
    if (info.role === 'subdomain_master') return { node: h('p', { class: 'notice' }, t('grants.not-allowed')) };
    const own = info.role === 'domain_master' ? (info.grants.find((g) => g.role === 'domain_master')?.policy ?? null) : null;
    const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
    let alive = true;
    let said = null;                               // what was done last (the lists are drawn again after it)
    const done = (text) => () => { said = text; return load(); };

    async function load() {
      try {
        const [list, policies] = await Promise.all([api.get('/grants', { query: { zone: info.name, limit: 100 } }), api.get('/rr-policies', { query: { limit: 500 } })]);
        if (!alive) return;
        fill(body,
          said ? h('p', { class: 'msg ok', role: 'status' }, said) : null,
          grantsTable(ctx, list.grants, { adminLinks: isGlobal(ctx), onDeleted: done(t('grants.deleted')) }),
          h('h3', null, t('grants.new')),
          grantForm(ctx, { policies: policies.policies, datasets: [], roles: ['domain_master', 'subdomain_master'], zone: info.name, dataset: ds, own, onDone: done(t('grants.added')) }).node);
        said = null;
      } catch (e) {
        if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
      }
    }
    load();
    return { node: h('section', { class: 'card', 'aria-labelledby': 'zg-title' }, h('h2', { id: 'zg-title' }, t('grants.zone-title')), h('p', null, t('grants.zone-text')), body), dispose() { alive = false; } };
  });
}

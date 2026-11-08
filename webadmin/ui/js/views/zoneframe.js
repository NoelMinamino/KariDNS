// The frame every screen of one zone shares (planning 3 S4): the name, what kind of zone it is, its serial and generation, the signer's state, my role and policy, and
// the sections (records, import, settings, DNSSEC) as links.  The zone's document is read here; the section is built from it.

import { h, link, fill, fileLink } from '../dom.js';
import { render, timeNode } from '../format.js';
import { problemNodes } from '../widgets.js';
import { zonePath } from '../zonelib.js';

const SECTIONS = [
  ['zone', 'zone.sec-records', () => true],
  ['zone-import', 'zone.sec-import', (role) => role !== 'subdomain_master'],
  ['zone-settings', 'zone.sec-settings', () => true],
  ['zone-dnssec', 'zone.sec-dnssec', (role) => role !== 'subdomain_master'],
];

// the policy of a grant in one line: the types, the TTL range, the flags that are set, max_rr
export function policyLine(t, p) {
  if (!p) return '-';
  const flags = [p.allow_wildcard ? t('policy.wildcard') : null, p.allow_delegation ? t('policy.delegation') : null, p.allow_dname ? t('policy.dname') : null, p.apex_editable ? t('policy.apex') : null].filter(Boolean);
  return [
    `${t('policy.types')}: ${(p.allowed_types ?? []).join(', ') || '-'}`,
    `${t('policy.ttl')}: ${p.ttl_min}-${p.ttl_max}`,
    flags.length ? `${t('policy.flags')}: ${flags.join(', ')}` : null,
    p.max_rr === null || p.max_rr === undefined ? null : `max_rr: ${p.max_rr}`,
  ].filter(Boolean).join('; ');
}

// -> { node, dispose(), refresh() }.  build(info, frame) -> { node, dispose?() } is the section; it is built when the zone's document has arrived.
export function zoneFrame(ctx, { ds, zone, active }, build) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const head = h('div');
  const content = h('div', { class: 'stack' });
  const root = h('div', { class: 'stack' }, head, content);
  let info = null;
  let inner = null;
  let alive = true;

  function drawHead() {
    const role = info.role;
    const params = { ds, zone: info.name };
    const nav = h('nav', { 'aria-label': t('zone.sections') }, h('ul', { class: 'tabs' }, SECTIONS.filter(([, , show]) => show(role)).map(([name, id]) => h('li', null,
      link(router.href(name, params), { 'aria-current': name === active ? 'page' : undefined }, t(id))))
      , role === 'subdomain_master' ? null : h('li', null, fileLink(`/api/v1${zonePath(ds, info.name)}/export`, { class: 'export' }, t('zone.export')))));
    const badges = [
      h('span', { class: 'badge' }, render(info.kind)),
      info.signer ? h('span', { class: 'badge' }, t('zone.b-signer')) : null,
      info.presigned && !info.signer ? h('span', { class: 'badge' }, t('zone.b-presigned')) : null,
      info.waiting_for_signer ? h('span', { class: 'badge warn' }, t('zone.b-waiting')) : null,
    ];
    const ss = info.signer_state;
    const rows = [
      [t('zone.serial'), String(info.serial ?? '-')],
      [t('zone.generation'), String(info.generation)],
      [t('zone.changed'), info.changed_at ? timeNode(info.changed_at, i18n.lang) : '-'],
      [t('zone.role'), [t(`role.${role}`), ...(role === 'subdomain_master' && info.grants.find((g) => g.suffix) ? [' ', h('code', null, render(info.grants.find((g) => g.suffix).suffix))] : [])]],
      [t('zone.policy'), render(policyLine(t, info.grants.find((g) => g.policy)?.policy))],
      info.signer ? [t('zone.signed-serial'), ss?.signed_serial === null || ss?.signed_serial === undefined ? t('zone.not-signed-yet') : String(ss.signed_serial)] : null,
      info.last_reload_request ? [t('zone.last-reload'), [`#${info.last_reload_request.generation} `, timeNode(info.last_reload_request.at, i18n.lang)]] : null,
    ].filter(Boolean);
    fill(head, h('section', { class: 'card', 'aria-labelledby': 'zone-title' },
      h('h1', { id: 'zone-title' }, render(info.name), ' ', badges),
      h('dl', null, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
      nav));
  }

  // the document again (after a change: the serial, the generation)
  async function refresh() {
    try {
      const r = await api.get(zonePath(ds, zone));
      if (!alive) return;
      Object.assign(info, r.zone);
      drawHead();
    } catch { /* the old header stays; the next action shows the problem */ }
  }

  api.get(zonePath(ds, zone)).then((r) => {
    if (!alive) return;
    info = r.zone;
    drawHead();
    inner = build(info, { refresh });
    fill(content, inner.node);
  }, (e) => {
    if (!alive) return;
    fill(head, h('section', { class: 'card' }, h('h1', null, render(zone)), h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)), h('p', null, link(router.href('zones'), null, t('zone.back')))));
  });
  fill(content, h('p', { role: 'status' }, t('common.loading')));
  return { node: root, dispose() { alive = false; inner?.dispose?.(); }, refresh };
}

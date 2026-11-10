// S9: the history of a zone (planning 3): the versions newest first (who, when, the comment, the serial, how many record sets, and the marker "changed outside the
// versions" for the masters of the whole zone), one version's delta, the difference between two versions or one version and the zone as it is, and the rollback.  The
// service keeps the newest 100 versions of a zone, so the list is one page; a subdomain master sees the part of each change under its suffix.  Comments and names are
// written by others: they are drawn as text only.

import { h, link, fill } from '../dom.js';
import { render, plain, timeNode } from '../format.js';
import { field, problemNodes } from '../widgets.js';
import { relName } from '../zonelib.js';
import { versionsPath, versionPath, outsideOf, parseCompare, isVersionNo } from '../histlib.js';
import { zoneFrame } from './zoneframe.js';
import { diffView } from './change.js';
import { rollbackPanel } from './rollback.js';

const KINDS = new Set(['create', 'edit', 'template', 'import', 'rollback']);
const PAGE = 200;

const kindText = (t, k) => (KINDS.has(k) ? t(`vkind.${k}`) : render(k));

// who made a version: the person, else the database role of an operator's tool (an import by karidns-zone), else nobody known
function whoNode(t, v) {
  if (v.principal) return render(v.principal.name);
  return v.db_role ? t('versions.operator', { role: plain(v.db_role) }) : '-';
}

// the marker "the zone was changed outside the versions": what the audit log says, or only that the generation grew
function outsideNode(ctx, m, zone, where) {
  const o = outsideOf(m);
  if (o === null) return null;
  const { i18n, router } = ctx;
  const t = i18n.t;
  const names = o.rrsets.map((r) => h('code', null, render(`${relName(r.name, zone)} ${r.type}`)));
  return h('p', { class: 'notice outside' },
    h('strong', null, t(where)), ' ',
    o.basis === 'audit' ? t('versions.outside-audit', { count: o.count ?? 0 }) : t('versions.outside-generation'),
    names.length === 0 ? null : [' ', names.flatMap((n, i) => (i === 0 ? [n] : [', ', n]))],
    ' ', link(router.href('audit', undefined, { zone }), null, t('versions.see-audit')));
}

// ---------------------------------------------------------------------------------------------------------------------------------- the list
export function versionsView(ctx, { params, query }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone-versions' }, (info) => {
    const zname = info.name;
    const whole = info.role !== 'subdomain_master';
    const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
    let alive = true;

    // the compare form: version a against a later version or the zone as it is
    const from = field({ label: t('versions.cmp-from'), name: 'from', inputmode: 'numeric', maxlength: 9, autocomplete: 'off' });
    const to = field({ label: t('versions.cmp-to'), name: 'to', maxlength: 9, autocomplete: 'off', hint: t('versions.cmp-hint') });
    const cmp = h('form', { class: 'search', novalidate: true }, from.node, to.node, h('div', { class: 'actions' }, h('button', { type: 'submit' }, t('versions.cmp'))));
    cmp.addEventListener('submit', (ev) => {
      ev.preventDefault();
      from.setError(null);
      to.setError(null);
      const r = parseCompare(from.input.value, to.input.value);
      if (r.error === 'from') { from.setError(t('versions.cmp-bad-from')); from.focus(); return; }
      if (r.error === 'to') { to.setError(t('versions.cmp-bad-to')); to.focus(); return; }
      if (r.error === 'order') { to.setError(t('versions.cmp-order')); to.focus(); return; }
      router.go('zone-diff', { ds, zone: zname, n: String(r.from) }, { to: String(r.to) });
    });

    function row(v) {
      const hit = query.cs !== undefined && query.cs !== '' && v.change_set === query.cs;
      const notes = [
        v.rollback_of !== null && v.rollback_of !== undefined ? t('versions.restores', { n: v.rollback_of }) : null,
        v.delta_complete === false ? t('versions.too-large') : null,
        hit ? t('versions.from-audit') : null,
      ].filter(Boolean);
      const main = h('tr', { class: hit ? 'hit' : '', 'aria-current': hit ? 'true' : undefined },
        h('th', { scope: 'row' }, link(router.href('zone-version', { ds, zone: zname, n: String(v.version) }), null, String(v.version))),
        h('td', null, kindText(t, v.kind)),
        h('td', null, timeNode(v.at, i18n.lang)),
        h('td', null, whoNode(t, v)),
        h('td', null, v.comment ? render(v.comment) : '-'),
        h('td', null, `${v.serial?.before ?? '-'} → ${v.serial?.after ?? '-'}`),
        h('td', null, v.rrsets === undefined ? '-' : String(v.rrsets)),
        h('td', null, notes.map((n) => h('div', null, n))),
        h('td', { class: 'actions-cell' },
          link(router.href('zone-diff', { ds, zone: zname, n: String(v.version) }, { to: 'current' }), { 'aria-label': t('versions.vs-now-of', { n: v.version }) }, t('versions.vs-now')), ' ',
          link(router.href('zone-version', { ds, zone: zname, n: String(v.version) }), { 'aria-label': t('versions.rollback-row-of', { n: v.version }) }, t('versions.rollback-row'))));
      const mark = outsideNode(ctx, v.changed_outside_before, zname, 'versions.outside-before');
      return mark ? [main, h('tr', { class: 'outside-row' }, h('td', { colspan: 9 }, mark))] : main;
    }

    function draw(r) {
      const next = r.next_cursor ? router.href('zone-versions', { ds, zone: zname }, { ...query, cursor: r.next_cursor }) : null;
      const first = query.cursor ? router.href('zone-versions', { ds, zone: zname }, { ...query, cursor: undefined }) : null;
      fill(body,
        whole ? null : h('p', { class: 'notice' }, t('versions.sub-note')),
        !query.cursor ? outsideNode(ctx, r.changed_outside_since, zname, 'versions.outside-since') : null,
        r.versions.length === 0 ? h('p', null, t('versions.none')) : h('table', { class: 'versions' },
          h('caption', { class: 'sr-only' }, t('versions.caption')),
          h('thead', null, h('tr', null, ...['no', 'kind', 'when', 'who', 'comment', 'serial', 'rrsets', 'notes', 'actions'].map((k) => h('th', { scope: 'col' }, t(`versions.h-${k}`))))),
          h('tbody', null, r.versions.map(row))),
        next || first ? h('p', { class: 'actions pager' }, first ? link(first, null, t('versions.first')) : null, next ? link(next, { class: 'button' }, t('versions.next')) : null) : null,
        h('p', { class: 'hint' }, t('versions.keeps')));
    }

    api.get(versionsPath(ds, zname), { query: { limit: 100, cursor: query.cursor } }).then((r) => { if (alive) draw(r); },
      (e) => { if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e))); });
    const node = h('section', { class: 'card', 'aria-labelledby': 'vers-title' }, h('h2', { id: 'vers-title' }, t('versions.title')), h('p', null, t('versions.intro')), cmp, body);
    return { node, dispose() { alive = false; } };
  });
}

// ---------------------------------------------------------------------------------------------------------------------------------- one version
export function versionView(ctx, { params, query }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone-versions' }, (info, frame) => {
    const zname = info.name;
    const back = link(router.href('zone-versions', { ds, zone: zname }), null, t('versions.back'));
    if (!isVersionNo(params.n)) return { node: h('section', { class: 'card' }, h('p', { class: 'msg error', role: 'alert' }, t('versions.not-found')), h('p', null, back)) };
    const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
    let alive = true;
    let panel = null;

    function draw(r) {
      const v = r.version;
      const rows = [
        [t('versions.h-no'), String(v.version)],
        [t('versions.h-kind'), kindText(t, v.kind)],
        [t('versions.h-when'), timeNode(v.at, i18n.lang)],
        [t('versions.h-who'), whoNode(t, v)],
        [t('versions.h-comment'), v.comment ? render(v.comment) : '-'],
        [t('versions.h-serial'), `${v.serial?.before ?? '-'} → ${v.serial?.after ?? '-'}`],
        [t('versions.generation'), `${v.generation?.before ?? '-'} → ${v.generation?.after ?? '-'}`],
        v.rollback_of !== null && v.rollback_of !== undefined ? [t('versions.rollback-of'), link(router.href('zone-version', { ds, zone: zname, n: String(v.rollback_of) }), null, String(v.rollback_of))] : null,
        v.change_set ? [t('versions.change-set'), h('code', null, render(v.change_set))] : null,
      ].filter(Boolean);
      const next = r.next_cursor ? router.href('zone-version', params, { ...query, cursor: r.next_cursor }) : null;
      const first = query.cursor ? router.href('zone-version', params, { ...query, cursor: undefined }) : null;
      fill(body,
        h('dl', null, rows.map(([k, val]) => [h('dt', null, k), h('dd', null, val)])),
        h('p', { class: 'actions' }, back, link(router.href('zone-diff', { ds, zone: zname, n: String(v.version) }, { to: 'current' }), { class: 'button' }, t('versions.vs-now')),
          v.change_set ? link(router.href('audit', undefined, { change_set: v.change_set }), null, t('versions.see-audit-cs')) : null),
        h('h3', null, t('versions.delta')),
        v.delta_complete === false ? h('p', { class: 'notice' }, t('versions.too-large-text')) : diffView(ctx, r.rrsets, zname),
        next || first ? h('p', { class: 'actions pager' }, first ? link(first, null, t('versions.first')) : null, next ? link(next, { class: 'button' }, t('versions.next')) : null) : null);
    }

    api.get(versionPath(ds, zname, params.n), { query: { limit: PAGE, cursor: query.cursor } }).then((r) => { if (alive) draw(r); },
      (e) => { if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)), h('p', null, back)); });
    if (info.kind && ['NATIVE', 'MASTER'].includes(String(info.kind).toUpperCase()) && !(info.presigned && !info.signer)) {
      panel = rollbackPanel(ctx, { ds, zone: zname, info, n: params.n, frame });
    }
    const node = h('div', { class: 'stack' },
      h('section', { class: 'card', 'aria-labelledby': 'ver-title' }, h('h2', { id: 'ver-title' }, t('versions.one-title', { n: params.n })), body),
      panel ? panel.node : null);
    return { node, dispose() { alive = false; panel?.dispose(); } };
  });
}

// ---------------------------------------------------------------------------------------------------------------------------------- a difference
export function versionDiffView(ctx, { params, query }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone-versions' }, (info) => {
    const zname = info.name;
    const back = link(router.href('zone-versions', { ds, zone: zname }), null, t('versions.back'));
    const cmp = parseCompare(params.n, query.to ?? 'current');
    if (cmp.error) return { node: h('section', { class: 'card' }, h('p', { class: 'msg error', role: 'alert' }, t('versions.cmp-bad')), h('p', null, back)) };
    const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
    let alive = true;
    const toText = cmp.to === 'current' ? t('versions.now') : t('versions.version-n', { n: cmp.to });
    const title = t('versions.diff-title', { from: cmp.from, to: toText });

    function draw(r) {
      const next = r.next_cursor ? router.href('zone-diff', params, { ...query, cursor: r.next_cursor }) : null;
      const first = query.cursor ? router.href('zone-diff', params, { ...query, cursor: undefined }) : null;
      fill(body,
        h('p', null, t('versions.diff-text', { from: cmp.from, to: toText })),
        diffView(ctx, r.rrsets, zname),
        next || first ? h('p', { class: 'actions pager' }, first ? link(first, null, t('versions.first')) : null, next ? link(next, { class: 'button' }, t('versions.next')) : null) : null,
        h('p', null, back, ' ', link(router.href('zone-version', { ds, zone: zname, n: String(cmp.from) }), null, t('versions.rollback-link', { n: cmp.from }))));
    }

    api.get(`${versionPath(ds, zname, cmp.from)}/diff`, { query: { to: String(cmp.to), limit: PAGE, cursor: query.cursor } }).then((r) => { if (alive) draw(r); },
      (e) => { if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)), h('p', null, back)); });
    return { node: h('section', { class: 'card', 'aria-labelledby': 'diff-title' }, h('h2', { id: 'diff-title' }, title), body), dispose() { alive = false; } };
  });
}

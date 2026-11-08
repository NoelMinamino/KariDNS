// S4 and S5: the records of one zone (planning 3).  The RRsets are read a page at a time with their text form (?rdata=1, G2) and shown with the reason when one cannot be
// edited here.  Editing collects a draft in memory (F-13); the panel under the table previews it as a dry run and commits it.  Zone data is hostile text (5.2): it is
// drawn through format.js only.

import { h, link, fill } from '../dom.js';
import { render, plain } from '../format.js';
import { field, select, problemNodes } from '../widgets.js';
import { zonePath, relName, editReason, zoneEditable, addableTypes, rdataOf } from '../zonelib.js';
import { zoneFrame } from './zoneframe.js';
import { reloadControl } from './reload.js';
import { openEditor, draftDelete } from './editor.js';
import { draftPanel } from './draftpanel.js';
import { diffView, messageList, summaryList } from './change.js';

const SIZES = [25, 50, 100, 250, 500];
const OPS = { add: 'draft.op-add', replace: 'draft.op-replace', delete: 'draft.op-delete', soa: 'draft.op-soa' };

export function zoneView(ctx, { params, query }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone' }, (info, frame) => {
    const zname = info.name;
    const draft = ctx.drafts.of(ds, zname);
    const types = ctx.session.state.version?.types ?? null;
    const lockedBy = zoneEditable(info);
    const limit = SIZES.includes(Number(query.n)) ? Number(query.n) : 100;
    const reload = reloadControl(ctx, { ds, zone: zname, signer: info.signer });
    const result = h('div');
    const tableBox = h('div');
    const panelBox = h('div');
    let page = { rrsets: [], next_cursor: null };
    let seq = 0;
    let alive = true;
    let panel = null;

    // ------------------------------------------------------------------------------------------------------------ the table
    function reasonNode(reason) {
      return reason === null ? null : h('span', { class: 'reason' }, t(`reason.${reason}`));
    }

    function rowNode(rr) {
      const reason = editReason(rr, info, types);
      const entry = draft.find(rr.name, rr.type);
      const isGlobal = info.role === 'global_master';
      const which = { name: plain(relName(rr.name, zname)), type: plain(rr.type) };
      const actions = [];
      if (entry) {
        actions.push(h('button', { type: 'button', 'aria-label': t('draft.undo-of', which), on: { click: () => draft.remove(entry.id) } }, t('draft.undo')));
      } else if (reason === null) {
        actions.push(h('button', { type: 'button', 'aria-label': t('rr.edit-of', which), on: { click: () => openEditor(ctx, { kind: 'replace', zone: zname, info, draft, types: [], rr }) } }, t('rr.edit')),
          h('button', { type: 'button', 'aria-label': t('rr.delete-of', which), on: { click: () => draftDelete(draft, rr) } }, t('rr.delete')));
      } else if (reason === 'soa' && isGlobal) {
        actions.push(h('button', { type: 'button', on: { click: () => openEditor(ctx, { kind: 'soa', zone: zname, info, draft, types: [], rr }) } }, t('rr.edit-soa')));
      }
      return h('tr', { class: entry ? `drafted op-${entry.op}` : '' },
        h('th', { scope: 'row', title: plain(rr.name) }, h('code', null, render(relName(rr.name, zname)))),
        h('td', null, render(rr.type)),
        h('td', null, rr.ttl === null ? '-' : String(rr.ttl)),
        h('td', null, rr.records.map((rec) => h('div', { class: 'rec' }, render(rdataOf(rec)), rec.disabled ? [' ', h('em', null, t('rr.disabled'))] : null))),
        h('td', null, entry ? h('strong', null, t(OPS[entry.op])) : reasonNode(reason)),
        h('td', { class: 'actions-cell' }, actions));
    }

    // an RRset that is only in the draft (a new one) is listed in the panel; the table shows what the service has
    function drawTable() {
      if (!alive) return;
      const nextHref = page.next_cursor ? router.href('zone', { ds, zone: zname }, { ...query, cursor: page.next_cursor }) : null;
      const firstHref = query.cursor ? router.href('zone', { ds, zone: zname }, { ...query, cursor: undefined }) : null;
      fill(tableBox,
        page.rrsets.length === 0 ? h('p', null, t('rr.none')) : h('table', { class: 'rrsets' },
          h('caption', { class: 'sr-only' }, t('rr.caption')),
          h('thead', null, h('tr', null, ...['name', 'type', 'ttl', 'records', 'state', 'actions'].map((k) => h('th', { scope: 'col' }, t(`rr.h-${k}`))))),
          h('tbody', null, page.rrsets.map(rowNode))),
        nextHref || firstHref ? h('p', { class: 'actions pager' }, firstHref ? link(firstHref, null, t('rr.first')) : null, nextHref ? link(nextHref, { class: 'button' }, t('rr.next')) : null) : null);
    }

    async function loadPage() {
      const mine = ++seq;
      fill(tableBox, h('p', { role: 'status' }, t('common.loading')));
      try {
        const r = await api.get(`${zonePath(ds, zname)}/rrsets`, { query: { rdata: 1, limit, cursor: query.cursor, contains: query.contains, from: query.from, type: query.type } });
        if (!alive || mine !== seq) return;
        page = r;
        drawTable();
      } catch (e) {
        if (alive && mine === seq) fill(tableBox, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
      }
    }

    // ------------------------------------------------------------------------------------------------------------ the search
    const contains = field({ label: t('rr.search-contains'), name: 'contains', value: query.contains ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none' });
    const from = field({ label: t('rr.search-from'), name: 'from', value: query.from ?? '', maxlength: 255, spellcheck: false, autocapitalize: 'none' });
    const type = field({ label: t('rr.search-type'), name: 'type', value: query.type ?? '', maxlength: 32, spellcheck: false, autocapitalize: 'characters' });
    const size = select({ label: t('rr.search-size'), name: 'n', options: SIZES.map((n) => ({ value: String(n), label: String(n) })), value: String(limit) });
    const search = h('form', { class: 'search', novalidate: true }, contains.node, from.node, type.node, size.node, h('div', { class: 'actions' }, h('button', { type: 'submit' }, t('rr.search'))));
    search.addEventListener('submit', (ev) => {
      ev.preventDefault();
      router.go('zone', { ds, zone: zname }, { contains: contains.input.value.trim(), from: from.input.value.trim(), type: type.input.value.trim(), n: size.input.value });
    });

    // ------------------------------------------------------------------------------------------------------------ the draft
    function committed(r) {
      fill(result, h('section', { class: 'card', 'aria-labelledby': 'last-title' }, h('h2', { id: 'last-title' }, t('result.last')),
        h('p', { class: 'msg ok', role: 'status' }, t(r.committed === false ? 'result.nothing' : 'result.committed')), summaryList(ctx, r, true), messageList(ctx, r.messages), diffView(ctx, r.diff ?? [], zname)));
      if (r.reload === 'requested') reload.watch();
      frame.refresh();
      loadPage();
    }

    if (lockedBy === null) {
      panel = draftPanel(ctx, {
        ds, zone: zname, info, draft, types: addableTypes(types, info.grants), reloadDefault: ctx.session.state.version?.ui?.reload_after_change === true,
        onCommitted: committed, onRefresh: loadPage,
      });
      fill(panelBox, panel.node);
    }
    draft.onChange(drawTable);

    const add = lockedBy === null ? h('button', { type: 'button', class: 'primary', on: { click: () => openEditor(ctx, { kind: 'add', zone: zname, info, draft, types: addableTypes(types, info.grants) }) } }, t('rr.add')) : null;
    const note = lockedBy === null ? null : h('p', { class: 'notice' }, t(`reason.${lockedBy}`));

    loadPage();
    const node = h('div', { class: 'stack' },
      h('section', { class: 'card', 'aria-labelledby': 'update-title' }, h('h2', { id: 'update-title' }, t('reload.title')), reload.node),
      result,
      h('section', { class: 'card', 'aria-labelledby': 'rr-title' }, h('h2', { id: 'rr-title' }, t('rr.title')), note, search, add, tableBox),
      panelBox);
    return {
      node,
      dispose() {
        alive = false;
        draft.offChange(drawTable);
        reload.dispose();
        panel?.dispose();
      },
    };
  });
}

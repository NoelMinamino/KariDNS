// The change set being put together for a zone (planning 3 S5 and S5a, F-13): the entries of the draft with an undo each, the preview (a dry run), the commit, and what
// follows a refusal: a precondition that no longer holds (409, per RRset: what I loaded, what is there now, what I want, "take theirs" or "keep mine"), a change that
// is not allowed (403, which RRset), a zone check that refuses (422, which record), the zone that kept changing (409 changed).

import { h, fill } from '../dom.js';
import { render, plain } from '../format.js';
import { relName, zonePath } from '../zonelib.js';
import { placeOnEntries, entryOf } from '../pointer.js';
import { lineText } from '../diffmodel.js';
import { changeFlow } from './change.js';
import { openEditor } from './editor.js';

const OPS = { add: 'draft.op-add', replace: 'draft.op-replace', delete: 'draft.op-delete', soa: 'draft.op-soa' };

// -> { node, dispose() }.  o: { ds, zone, info, draft, types, reloadDefault, onCommitted(r), onRefresh() (load the page of RRsets again) }
export function draftPanel(ctx, o) {
  const { api, i18n } = ctx;
  const t = i18n.t;
  const { draft, zone } = o;
  const list = h('ul', { class: 'draft-list' });
  const conflictBox = h('div', { class: 'stack' });
  const box = h('section', { class: 'card draft', 'aria-labelledby': 'draft-title' });
  let order = [];                                   // the ids of the entries in the order of the last request (pointers /rrsets/N)
  let errors = new Map();                           // entry id -> errors of the service
  let conflicts = [];                               // [{ id, current }]

  const flow = changeFlow(ctx, {
    zone,
    reloadable: !o.info.signer,
    reloadDefault: o.reloadDefault,
    check: () => {
      errors = new Map();
      conflicts = [];
      drawList();
      return false;
    },
    run: (dry, v) => {
      const r = draft.request({ comment: v.comment, reload: v.reload, dryRun: dry });
      order = r.order;
      return api.patch(`${zonePath(o.ds, zone)}/rrsets`, r.body);
    },
    place: (errs) => {
      const placed = placeOnEntries(errs, order);
      errors = placed.byEntry;
      drawList();
      return placed.loose;
    },
    onProblem: (e) => {
      if (e.code !== 'precondition-failed') return false;
      conflicts = (e.errors ?? []).map((x) => ({ id: order[entryOf(x.pointer)?.index], current: x.current ?? null })).filter((c) => c.id !== undefined);
      drawConflicts();
      return true;
    },
    onCommitted: (r) => {
      draft.clear();
      o.onCommitted(r);
    },
  });

  function recordsBlock(recs, cls) {
    return h('div', { class: `rec-block ${cls}` }, recs.length === 0 ? h('em', null, t('draft.none')) : recs.map((r) => h('div', { class: 'line' }, render(typeof r === 'string' ? r : lineText(r)))));
  }

  function entryNode(e) {
    const errs = errors.get(e.id) ?? [];
    const which = { name: plain(relName(e.name, zone)), type: plain(e.type) };
    return h('li', { class: `entry op-${e.op}` },
      h('div', { class: 'entry-head' },
        h('strong', null, t(OPS[e.op])), ' ', h('code', { title: plain(e.name) }, render(relName(e.name, zone))), ' ', render(e.type), e.ttl === null ? null : ` (TTL ${e.ttl})`,
        ' ',
        e.op === 'delete' ? null : h('button', { type: 'button', class: 'link', 'aria-label': t('draft.edit-of', which), on: { click: () => edit(e) } }, t('draft.edit')), ' ',
        h('button', { type: 'button', class: 'link', 'aria-label': t('draft.undo-of', which), on: { click: () => draft.remove(e.id) } }, t('draft.undo'))),
      e.op === 'delete' ? null : recordsBlock(e.records, 'new'),
      errs.length === 0 ? null : h('ul', { class: 'entry-errors', role: 'alert' }, errs.map((x) => h('li', null,
        x.record === null ? null : [h('strong', null, t('draft.record', { n: x.record + 1 })), ' '], h('code', null, render(x.code ?? '')), ' ', render(x.text ?? '')))));
  }

  function edit(e) {
    openEditor(ctx, { kind: e.op === 'soa' ? 'soa' : 'replace', zone, info: o.info, draft, types: o.types, entry: e });
  }

  function drawList() {
    fill(list, draft.entries.map(entryNode));
  }

  function conflictNode(c) {
    const e = draft.entries.find((x) => x.id === c.id);
    return h('div', { class: 'conflict card' },
      h('h3', null, h('code', null, render(relName(e.name, zone))), ' ', render(e.type)),
      h('div', { class: 'three' },
        h('div', null, h('h4', null, t('conflict.loaded')), recordsBlock(e.before, 'old')),
        h('div', null, h('h4', null, t('conflict.now')), recordsBlock(c.current ?? [], 'now')),
        h('div', null, h('h4', null, t('conflict.mine')), e.op === 'delete' ? h('em', null, t('draft.op-delete')) : recordsBlock(e.records, 'new'))),
      h('div', { class: 'actions' },
        h('button', { type: 'button', on: { click: () => resolve(c, 'theirs') } }, t('conflict.take-theirs')),
        h('button', { type: 'button', class: 'primary', on: { click: () => resolve(c, 'mine') } }, t('conflict.keep-mine'))));
  }

  function resolve(c, how) {
    conflicts = conflicts.filter((x) => x !== c);
    if (how === 'theirs') {
      draft.remove(c.id);
      o.onRefresh();
    } else {
      draft.rebase(c.id, c.current);
    }
    ctx.announce(t('conflict.resolved'));
    drawConflicts();
  }

  function drawConflicts() {
    const live = conflicts.filter((c) => draft.entries.some((e) => e.id === c.id));
    conflicts = live;
    fill(conflictBox, live.length === 0 ? null : [
      h('p', { class: 'msg error', role: 'alert' }, t('api.precondition-failed')),
      h('p', null, t('conflict.help')),
      live.map(conflictNode),
    ]);
  }

  function draw() {
    const n = draft.size;
    fill(box,
      h('h2', { id: 'draft-title' }, t('draft.title'), n > 0 ? ` (${n})` : ''),
      n === 0 ? h('p', { class: 'hint' }, t('draft.hint')) : [
        list,
        h('p', null, h('button', { type: 'button', class: 'link', on: { click: () => draft.clear() } }, t('draft.discard'))),
        conflictBox,
        flow.node,
      ]);
    if (n > 0) drawList();
  }

  const onChange = () => {
    flow.invalidate();
    if (draft.size === 0) { errors = new Map(); conflicts = []; }
    draw();
    drawConflicts();
  };
  draft.onChange(onChange);
  draw();
  return { node: box, dispose() { draft.offChange(onChange); flow.dispose(); } };
}

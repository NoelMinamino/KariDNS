// S9, the rollback of a zone to a version (planning 3, 6.4 of the API manual): a dry run first (the diff, the conflicts, the SOA that is left alone), then the commit.  A
// conflict is a record set that was changed after the versions that would be undone, by something that is not a version: the commit is refused (409 `version-conflict`)
// unless `force`, and `force` is a second question that lists what it overwrites.  The service decides everything; this shows what it answers.

import { h, fill } from '../dom.js';
import { render, plain } from '../format.js';
import { confirmButton } from '../widgets.js';
import { relName } from '../zonelib.js';
import { lineText } from '../diffmodel.js';
import { versionPath, conflictsOf } from '../histlib.js';
import { changeFlow } from './change.js';

const linesOf = (recs) => recs.map((r) => h('div', { class: 'line' }, render(lineText(r))));

// -> { node, dispose() }.  frame: the zone frame (its header is read again after a commit)
export function rollbackPanel(ctx, { ds, zone, info, n, frame }) {
  const { api, i18n } = ctx;
  const t = i18n.t;
  const notes = h('div', { class: 'stack' });
  const conflictBox = h('div');
  let force = false;

  function showNotes(r) {
    const skipped = Array.isArray(r.skipped) ? r.skipped : [];
    fill(notes,
      Number.isInteger(r.restored) ? h('p', null, t('rollback.summary', { restored: r.restored, versions: r.versions_undone ?? 0 })) : null,
      skipped.length === 0 ? null : h('ul', { class: 'messages' }, skipped.map((s) => h('li', null,
        h('code', null, render(`${relName(String(s.name), zone)} ${s.type}`)), ' ', s.type === 'SOA' ? t('rollback.skipped-soa') : render(s.reason ?? '')))));
  }

  function showConflicts(list) {
    if (list.length === 0) { fill(conflictBox); return; }
    const rows = list.map((c) => h('tr', { class: 'conflict' },
      h('th', { scope: 'row', title: plain(c.name) }, h('code', null, render(relName(c.name, zone)))),
      h('td', null, render(c.type)),
      h('td', null, linesOf(c.expected)),
      h('td', null, c.current === null ? h('em', null, t('rollback.not-there')) : linesOf(c.current))));
    const ask = confirmButton({
      label: t('rollback.force'), confirmLabel: t('rollback.force-ask', { count: list.length }), yes: t('common.yes'), no: t('common.no'),
      onConfirm: async () => {
        force = true;
        try { await flow.commit(); } finally { force = false; }
      },
    });
    fill(conflictBox, h('section', { class: 'card conflict', 'aria-labelledby': 'rb-conflicts' },
      h('h3', { id: 'rb-conflicts' }, t('rollback.conflicts-title', { count: list.length })),
      h('p', null, t('rollback.conflicts-text')),
      h('table', null, h('caption', { class: 'sr-only' }, t('rollback.conflicts-title', { count: list.length })),
        h('thead', null, h('tr', null, ...['name', 'type', 'expected', 'now'].map((k) => h('th', { scope: 'col' }, t(`rollback.h-${k}`))))), h('tbody', null, rows)),
      h('p', { class: 'actions' }, ask)));
    ctx.announce(t('rollback.conflicts-title', { count: list.length }), 'assertive');
  }

  const flow = changeFlow(ctx, {
    zone,
    reloadable: !info.signer,
    reloadDefault: ctx.session.state.version?.ui?.reload_after_change === true,
    previewLabel: t('rollback.preview'),
    commitLabel: t('rollback.commit'),
    run: (dry, v) => {
      const b = {};
      if (v.comment.trim() !== '') b.comment = v.comment.trim();
      if (v.reload !== undefined) b.reload = v.reload;
      if (dry) b.dry_run = true;
      else if (force) b.force = true;
      return api.post(`${versionPath(ds, zone, n)}/rollback`, b);
    },
    // a conflict makes the commit wait: the person decides in the box below (force), or looks again
    blockCommit: (r) => conflictsOf(r.conflicts).length > 0,
    onPreview: (r) => { showNotes(r); showConflicts(conflictsOf(r.conflicts)); },
    onProblem: (e) => {
      fill(notes);
      showConflicts(e.code === 'version-conflict' ? conflictsOf(e.errors) : []);
      return false;
    },
    onCommitted: (r) => { showNotes(r); showConflicts([]); frame.refresh(); },
  });

  return {
    node: h('section', { class: 'card', 'aria-labelledby': 'rb-title' }, h('h2', { id: 'rb-title' }, t('rollback.title', { n })), h('p', null, t('rollback.intro')), notes, flow.node, conflictBox),
    dispose: () => flow.dispose(),
  };
}

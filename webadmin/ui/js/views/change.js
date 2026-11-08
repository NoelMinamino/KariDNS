// The parts every screen that changes zone data shares (planning 3 S5, S6, S7; F-21): the diff of a change set in pages of 200 RRsets, the messages of the zone checks,
// the summary of a result, and the flow "preview, then commit" with a comment, the reload box, the refusals of the service and the wait that Retry-After asks for.
// The service decides everything; this shows what it answers.

import { h, fill } from '../dom.js';
import { render, plain } from '../format.js';
import { field, checkbox, message, problemNodes } from '../widgets.js';
import { diffCounts, diffPage, lineText } from '../diffmodel.js';
import { relName } from '../zonelib.js';

const SIGN = { add: '+', replace: '~', delete: '-' };

const lines = (recs, sign, cls) => (recs ?? []).map((r) => h('div', { class: `line ${cls}` }, h('span', { class: 'sign' }, sign), ' ', render(lineText(r))));

// the diff [{ name, type, change, before, after }] as a table, 200 RRsets a page; names are relative to `zone` when it is given.  Additions and removals are told by
// their sign and by a word, not by colour (planning 5.2 rule 4).
export function diffView(ctx, diff, zone) {
  const t = ctx.i18n.t;
  let page = 0;
  const box = h('div', { class: 'diff' });
  function draw() {
    const p = diffPage(diff, page);
    const c = diffCounts(diff);
    const rows = p.items.map((e) => h('tr', { class: `change-${e.change}` },
      h('th', { scope: 'row', title: plain(e.name) }, render(zone ? relName(e.name, zone) : e.name)),
      h('td', null, render(e.type)),
      h('td', null, h('span', { class: 'sign' }, SIGN[e.change] ?? '?'), ' ', t(`diff.${e.change in SIGN ? e.change : 'replace'}`)),
      h('td', null, lines(e.before, '-', 'old'), lines(e.after, '+', 'new'))));
    const pager = p.pages > 1 ? h('div', { class: 'actions pager' },
      h('button', { type: 'button', disabled: p.page === 0, on: { click: () => { page = p.page - 1; draw(); } } }, t('diff.prev')),
      h('span', { role: 'status' }, t('diff.showing', { from: p.from, to: p.to, total: p.total })),
      h('button', { type: 'button', disabled: p.page >= p.pages - 1, on: { click: () => { page = p.page + 1; draw(); } } }, t('diff.next'))) : null;
    fill(box,
      h('p', null, t('diff.counts', { add: c.add, replace: c.replace, delete: c.delete })),
      diff.length === 0 ? h('p', null, t('diff.none')) : h('table', { class: 'diff-table' },
        h('caption', { class: 'sr-only' }, t('diff.caption')),
        h('thead', null, h('tr', null, ...['name', 'type', 'change', 'records'].map((k) => h('th', { scope: 'col' }, t(`diff.h-${k}`))))),
        h('tbody', null, rows)),
      pager);
  }
  draw();
  return box;
}

// the messages of the zone checks (errors and warnings, with their karicheck codes and the text of the tool, planning 7.2) as a list; null when there are none
export function messageList(ctx, msgs) {
  if (!msgs || msgs.length === 0) return null;
  const t = ctx.i18n.t;
  return h('ul', { class: 'messages' }, msgs.map((m) => h('li', { class: m.severity === 'error' ? 'error' : 'warning' },
    h('strong', null, t(m.severity === 'error' ? 'msg.error' : 'msg.warning')), ' ', h('code', null, render(m.code ?? '')), ' ', render(m.text ?? ''),
    m.pointer ? [' ', h('span', { class: 'pointer' }, `(${plain(m.pointer)})`)] : null)));
}

// the state of a reload as the service words it -> text
export function reloadText(ctx, state) {
  const t = ctx.i18n.t;
  const s = String(state ?? '');
  if (s === 'requested') return t('reload.requested');
  if (s === 'not requested') return t('reload.not-requested');
  if (s === 'waiting for the signer') return t('reload.waiting');
  if (s.startsWith('failed')) return t('reload.failed', { why: plain(s.replace(/^failed:?\s*/, '')) });
  return plain(s);
}

// the numbers of an answer: version, serial, records, reload
export function summaryList(ctx, r, committed) {
  const t = ctx.i18n.t;
  const rows = [];
  if (r.version !== undefined) rows.push([t(committed ? 'result.version' : 'result.version-would'), String(r.version)]);
  if (r.serial) rows.push([t('result.serial'), `${r.serial.before ?? '-'} → ${r.serial.after}`]);
  if (r.records) rows.push([t('result.records'), `${r.records.before} → ${r.records.after}`]);
  if (committed && r.reload !== undefined) rows.push([t('result.reload'), reloadText(ctx, r.reload)]);
  return h('dl', null, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
}

// A flow "preview, then commit".  o:
//   run(dry, { comment, reload }) -> the answer of the service (an ApiProblem is thrown)
//   zone               the zone's absolute name, for names in the diff (or null)
//   reloadable         show the "reload now" box (a signer zone has none: the signer asks for the reload); reloadDefault its default
//   check()            local checks before a request; true = stop (the screen has said why)
//   place(errors)      puts the errors that belong to a field or an entry there; -> the errors left over (default: all)
//   onProblem(e, phase) -> true when the screen handled the refusal itself (the conflicts of a draft)
//   onPreview(r), onCommitted(r)
//   previewLabel, commitLabel, previewOnly: no commit button
// -> { node, invalidate(), reset() }.  invalidate(): the thing that was previewed has changed, so the commit waits for a new preview.
export function changeFlow(ctx, o) {
  const { i18n, timers } = ctx;
  const t = i18n.t;
  const comment = field({ label: t('flow.comment'), name: 'comment', maxlength: 1024, hint: t('flow.comment-hint') });
  const reload = o.reloadable ? checkbox({ label: t('flow.reload'), name: 'reload', checked: o.reloadDefault === true }) : null;
  const err = message('error');
  const out = h('div', { class: 'stack', 'aria-live': 'polite' });
  const previewBtn = h('button', { type: 'button', class: o.previewOnly ? 'primary' : '', on: { click: () => go(true) } }, o.previewLabel ?? t('flow.preview'));
  const commitBtn = o.previewOnly ? null : h('button', { type: 'button', class: 'primary', disabled: true, on: { click: () => go(false) } }, o.commitLabel ?? t('flow.commit'));
  let previewed = false;
  let running = false;
  let waitLeft = 0;
  let waiter = null;

  function sync() {
    previewBtn.disabled = running || waitLeft > 0;
    if (commitBtn) commitBtn.disabled = running || waitLeft > 0 || !previewed;
  }

  // Retry-After: both buttons wait, counting down in the preview button's label
  function hold(seconds) {
    if (waiter !== null) timers.clearInterval(waiter);
    waitLeft = Math.max(1, seconds);
    const label = o.previewLabel ?? t('flow.preview');
    const tick = () => {
      if (waitLeft <= 0) {
        timers.clearInterval(waiter);
        waiter = null;
        previewBtn.textContent = label;
      } else {
        previewBtn.textContent = t('flow.wait', { seconds: waitLeft });
        waitLeft -= 1;
      }
      sync();
    };
    tick();
    waiter = timers.setInterval(tick, 1000);
  }

  function reset() {
    previewed = false;
    fill(out);
    err.set(null);
    sync();
  }

  function invalidate() {
    if (!previewed && out.childNodes.length === 0) return;
    reset();
  }

  function showProblem(e, phase) {
    if (o.onProblem?.(e, phase) === true) return;
    const errors = e.errors ?? [];
    const loose = o.place ? o.place(errors) : errors;
    err.setNodes(...problemNodes(ctx.i18n, e));
    const list = messageList(ctx, loose);
    if (list) fill(out, list);
    if (e.retryAfter) hold(e.retryAfter);
  }

  function showResult(r, committed) {
    const kids = [];
    if (committed) {
      kids.push(h('p', { class: 'msg ok', role: 'status' }, t(r.committed === false ? 'result.nothing' : 'result.committed')));
    } else {
      kids.push(h('p', { class: 'msg ok', role: 'status' }, t('result.preview')));
    }
    kids.push(summaryList(ctx, r, committed), messageList(ctx, r.messages));
    if (r.conflicts?.length) kids.push(messageList(ctx, r.conflicts));
    kids.push(diffView(ctx, r.diff ?? [], o.zone));
    fill(out, kids);
  }

  async function go(dry) {
    if (running) return;
    err.set(null);
    if (dry) fill(out);
    if (o.check?.() === true) return;
    running = true;
    sync();
    try {
      const r = await o.run(dry, { comment: comment.input.value, reload: reload ? reload.input.checked : undefined });
      if (dry && r.allowed === false) {
        o.place?.([r.denied]);
        err.setNodes(t('flow.denied'), ' ', plain(r.denied?.text ?? ''));
        previewed = false;
      } else if (dry) {
        previewed = true;
        showResult(r, false);
        o.onPreview?.(r);
      } else {
        previewed = false;
        showResult(r, true);
        ctx.announce(t(r.committed === false ? 'result.nothing' : 'result.committed'));
        o.onCommitted?.(r);
      }
    } catch (e) {
      previewed = false;
      showProblem(e, dry ? 'preview' : 'commit');
    } finally {
      running = false;
      sync();
    }
  }

  const node = h('div', { class: 'stack flow' },
    comment.node, reload?.node, err.node,
    h('div', { class: 'actions' }, previewBtn, commitBtn),
    out);
  return { node, invalidate, reset, dispose() { if (waiter !== null) timers.clearInterval(waiter); waiter = null; } };
}

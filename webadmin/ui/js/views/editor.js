// The editor of one RRset (planning 3 S5): a dialog with the TTL and the records, one record a line in the text a change set takes (zone-file syntax, G2: names are
// absolute, MX and SRV carry their priority).  OK puts an entry into the draft of the zone; nothing is sent.  A new RRset also asks for its name and type; the SOA has
// its own form with a warning, because every change set that names it writes the next serial.

import { h, openDialog } from '../dom.js';
import { render } from '../format.js';
import { field, select, message } from '../widgets.js';
import { absName, relName, recordLines, recordsText, rdataOf, expectOf, ttlRange } from '../zonelib.js';
import { replaceEntry, addEntry, deleteEntry, soaEntry } from '../draft.js';

const TTL_MAX = 2147483647;
const sameRecords = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// kind: 'add' | 'replace' | 'soa'.  rr: the RRset of the page (replace, soa) or the draft entry being changed (an `entry` is given then).  Calls ctx.drafts' draft.put.
export function openEditor(ctx, { kind, zone, info, draft, types, rr, entry }) {
  const t = ctx.i18n.t;
  const range = ttlRange(info.grants);
  const adding = kind === 'add';
  const name = adding ? field({ label: t('edit.name'), name: 'name', required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('edit.name-hint') }) : null;
  const typeSel = adding && types.length > 0 ? select({ label: t('edit.type'), name: 'type', options: types.map((x) => ({ value: x, label: x })), value: types.includes('A') ? 'A' : types[0] }) : null;
  const typeText = adding && !typeSel ? field({ label: t('edit.type'), name: 'type', required: true, maxlength: 32, spellcheck: false, autocapitalize: 'characters' }) : null;
  const ttlHint = range ? t('edit.ttl-range', { min: range[0], max: range[1] }) : undefined;
  const ttl = field({ label: t('edit.ttl'), name: 'ttl', required: true, inputmode: 'numeric', maxlength: 10, hint: ttlHint, value: entry?.ttl ?? rr?.ttl ?? '' });
  const startLines = entry ? entry.records : (rr?.records ?? []).map(rdataOf);
  const records = field({ label: t(kind === 'soa' ? 'edit.soa-record' : 'edit.records'), name: 'records', kind: 'textarea', rows: kind === 'soa' ? 2 : 7, required: true, spellcheck: false, autocapitalize: 'none',
    hint: t(kind === 'soa' ? 'edit.soa-hint' : 'edit.records-hint'), value: recordsText(startLines) });
  const err = message('error');
  const ok = h('button', { type: 'submit', class: 'primary' }, t('edit.ok'));
  const cancel = h('button', { type: 'button', on: { click: () => dlg.close() } }, t('common.cancel'));
  const form = h('form', { class: 'stack', novalidate: true },
    kind === 'soa' ? h('p', { class: 'notice' }, t('edit.soa-warning')) : null,
    name?.node, typeSel?.node, typeText?.node, ttl.node, records.node, err.node, h('div', { class: 'actions' }, ok, cancel));
  const dlg = h('dialog', { class: 'modal wide', 'aria-labelledby': 'edit-title' },
    h('h2', { id: 'edit-title' }, t(adding ? 'edit.title-add' : kind === 'soa' ? 'edit.title-soa' : 'edit.title'), ...(adding ? [] : [' ', h('code', null, render(relName((rr ?? entry).name, zone))), ' ', render((rr ?? entry).type)])), form);

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    for (const f of [name, typeText, ttl, records]) f?.setError(null);
    err.set(null);
    let owner = null;
    if (adding) {
      owner = absName(name.input.value, zone);
      if (owner === null) { name.setError(t('edit.bad-name')); name.focus(); return; }
    }
    const type = adding ? (typeSel ? typeSel.input.value : typeText.input.value.trim().toUpperCase()) : (rr ?? entry).type;
    if (adding && !/^[A-Z][A-Z0-9-]{0,31}$/.test(type)) { typeText.setError(t('edit.bad-type')); typeText.focus(); return; }
    const seconds = /^\d{1,10}$/.test(ttl.input.value.trim()) ? Number(ttl.input.value.trim()) : -1;
    if (seconds < 0 || seconds > TTL_MAX) { ttl.setError(t('edit.bad-ttl')); ttl.focus(); return; }
    const lines = recordLines(records.input.value);
    if (lines.length === 0) { records.setError(t('edit.no-records')); records.focus(); return; }
    if (kind === 'soa' && lines.length !== 1) { records.setError(t('edit.one-soa')); records.focus(); return; }
    if (kind === 'replace' && !entry && sameRecords(lines, (rr.records ?? []).map(rdataOf)) && seconds === rr.ttl) { err.set(t('edit.unchanged')); return; }
    if (adding) draft.put(addEntry(owner, type, seconds, lines));
    else if (entry) draft.put({ ...entry, ttl: seconds, records: lines });
    else if (kind === 'soa') draft.put({ ...soaEntry(rr, lines), ttl: seconds });
    else draft.put(replaceEntry(rr, seconds, lines, expectOf(rr)));
    dlg.close();
  });
  openDialog(dlg);
  (name ?? ttl).focus();
  return dlg;
}

// deleting an RRset is a draft entry at once (nothing is sent); the page shows it and the person can undo it
export const draftDelete = (draft, rr) => draft.put(deleteEntry(rr, expectOf(rr)));

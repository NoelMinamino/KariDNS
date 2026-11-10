// S10: zone templates (planning 3, 5 of the API manual).  Everybody reads them; global masters write them.  A template is a named set of records whose owners are relative to
// the zone ("@" is the apex), with defaults for the SOA of a zone made from it.  It is COPIED into a zone (a new zone, or "apply" in the zone's Template section): nothing
// links the zone to the template afterwards.  The records are written one a line, "owner [ttl] TYPE data", and checked by the zone checks (karicheck) before they are stored.

import { h, link, fill } from '../dom.js';
import { render, plain, timeNode } from '../format.js';
import { field, message, problemNodes, confirmButton, busy, isGlobal } from '../widgets.js';
import { placeOnFields } from '../pointer.js';
import { templateText, parseTemplateText, soaOf, withLineNumbers, SOA_FIELDS } from '../histlib.js';
import { messageList } from './change.js';

const SEARCH = /^[A-Za-z0-9._+:-]+$/;

// ---------------------------------------------------------------------------------------------------------------------------------- the list
export function templatesView(ctx, { query }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const root = h('section', { class: 'card', 'aria-labelledby': 'tpls-title' }, h('h1', { id: 'tpls-title' }, t('tpl.title')), h('p', null, t('tpl.intro')), body);
  const flash = ctx.flash ?? null;
  ctx.flash = null;
  let alive = true;

  function draw(r) {
    const q = field({ label: t('tpl.search'), name: 'prefix', value: query.prefix ?? '', maxlength: 64, spellcheck: false, autocapitalize: 'none' });
    const form = h('form', { class: 'search', novalidate: true }, q.node, h('div', { class: 'actions' }, h('button', { type: 'submit' }, t('tpl.find'))));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      q.setError(null);
      const s = q.input.value.trim();
      if (s !== '' && !SEARCH.test(s)) { q.setError(t('tpl.bad-search')); q.focus(); return; }
      router.go('templates', undefined, { prefix: s });
    });
    const rows = r.templates.map((x) => h('tr', null,
      h('th', { scope: 'row' }, link(router.href('template', { id: String(x.id) }), null, render(x.name))),
      h('td', null, x.description ? render(x.description) : '-'),
      h('td', null, String(x.revision)),
      h('td', null, x.record_count === undefined ? '-' : String(x.record_count)),
      h('td', null, x.soa ? t('common.yes') : t('common.no')),
      h('td', null, x.updated_at ? timeNode(x.updated_at, i18n.lang) : '-')));
    const next = r.next_cursor ? router.href('templates', undefined, { ...query, cursor: r.next_cursor }) : null;
    const first = query.cursor ? router.href('templates', undefined, { ...query, cursor: undefined }) : null;
    fill(body, flash ? h('p', { class: 'msg ok', role: 'status' }, flash) : null, form,
      isGlobal(ctx) ? h('p', null, link(router.href('template-new'), { class: 'button primary' }, t('tpl.new'))) : null,
      r.templates.length === 0 ? h('p', null, t(query.cursor ? 'tpl.no-more' : 'tpl.none')) : h('table', null, h('caption', { class: 'sr-only' }, t('tpl.title')),
        h('thead', null, h('tr', null, ...['name', 'description', 'revision', 'records', 'soa', 'updated'].map((k) => h('th', { scope: 'col' }, t(`tpl.h-${k}`))))), h('tbody', null, rows)),
      next || first ? h('p', { class: 'actions pager' }, first ? link(first, null, t('tpl.first')) : null, next ? link(next, { class: 'button' }, t('tpl.next')) : null) : null);
  }

  api.get('/templates', { query: { limit: 100, cursor: query.cursor, prefix: SEARCH.test(query.prefix ?? '') ? query.prefix : undefined } }).then((r) => { if (alive) draw(r); },
    (e) => { if (alive) fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e))); });
  return { node: root, dispose() { alive = false; } };
}

// ---------------------------------------------------------------------------------------------------------------------------------- the form (global masters)
// tpl: the template as the service gave it, or null for a new one.  -> { node }
function templateForm(ctx, tpl, { onSaved }) {
  const { api, i18n } = ctx;
  const t = i18n.t;
  const name = field({ label: t('tpl.f-name'), name: 'name', value: tpl?.name ?? '', required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('tpl.f-name-hint') });
  const description = field({ label: t('tpl.f-description'), name: 'description', value: tpl?.description ?? '', maxlength: 1024 });
  const soa = Object.fromEntries(SOA_FIELDS.map((k) => [k, field({
    label: t(`tpl.soa-${k}`), name: `soa_${k}`, value: tpl?.soa?.[k] === null || tpl?.soa?.[k] === undefined ? '' : String(tpl.soa[k]), maxlength: k === 'mname' || k === 'rname' ? 255 : 10,
    spellcheck: false, autocapitalize: 'none', inputmode: k === 'mname' || k === 'rname' ? undefined : 'numeric',
  })]));
  const records = field({ label: t('tpl.f-records'), name: 'records', kind: 'textarea', rows: 12, value: templateText(tpl?.records), spellcheck: false, autocapitalize: 'none', hint: t('tpl.f-records-hint') });
  const err = message('error');
  const ok = message('status');
  const out = h('div', { class: 'stack' });
  const check = h('button', { type: 'button' }, t('tpl.check'));
  const save = h('button', { type: 'submit', class: 'primary' }, t(tpl ? 'tpl.save' : 'tpl.create'));
  const map = { '/name': name, '/description': description, ...Object.fromEntries(SOA_FIELDS.map((k) => [`/soa/${k}`, soa[k]])), '/soa': soa.mname, '/records': records };
  const form = h('form', { class: 'stack', novalidate: true }, name.node, description.node,
    h('fieldset', null, h('legend', null, t('tpl.f-soa')), h('p', { class: 'hint' }, t('tpl.f-soa-hint')), h('div', { class: 'grid' }, SOA_FIELDS.map((k) => soa[k].node))),
    records.node, err.node, ok.node, h('div', { class: 'actions' }, check, save), out);

  async function send(dry) {
    err.set(null);
    ok.set(null);
    fill(out);
    for (const f of [name, description, records, ...Object.values(soa)]) f.setError(null);
    const parsed = parseTemplateText(records.input.value);
    if (name.input.value.trim() === '') { name.setError(t('tpl.need-name')); name.focus(); return; }
    if (parsed.bad.length > 0) { records.setError(t('tpl.bad-lines', { lines: parsed.bad.join(', ') })); records.focus(); return; }
    const s = soaOf(Object.fromEntries(SOA_FIELDS.map((k) => [k, soa[k].input.value])));
    if (s.error) { soa[s.error].setError(t('tpl.bad-number')); soa[s.error].focus(); return; }
    const body = { name: name.input.value.trim(), records: parsed.records };
    const d = description.input.value.trim();
    if (d !== '' || tpl) body.description = d === '' ? null : d;
    if (s.soa !== null) body.soa = s.soa; else if (tpl) body.soa = null;
    if (dry) body.dry_run = true;
    try {
      const r = tpl ? await api.patch(`/templates/${tpl.id}`, body) : await api.post('/templates', body);
      const warnings = withLineNumbers(r.messages ?? [], parsed.lines, (n) => t('tpl.line', { n }));
      if (dry) {
        ok.set(t('tpl.valid'));
        fill(out, messageList(ctx, warnings));
        ctx.announce(t('tpl.valid'));
      } else {
        onSaved(r.template, warnings.length);
      }
    } catch (e) {
      const errors = withLineNumbers(e.errors ?? [], parsed.lines, (n) => t('tpl.line', { n }));
      if (e.code === 'template-checks-failed') {
        records.setError(t('tpl.records-bad'));
        err.setNodes(...problemNodes(i18n, { ...e, errors: [] }));
        fill(out, messageList(ctx, errors));
        return;
      }
      const loose = errors.length ? placeOnFields(errors, map) : [];
      if (!errors.length || loose.length) err.setNodes(...problemNodes(i18n, e));
    }
  }
  form.addEventListener('submit', (ev) => { ev.preventDefault(); busy(save, () => send(false)); });
  check.addEventListener('click', () => busy(check, () => send(true)));
  return { node: form };
}

// ---------------------------------------------------------------------------------------------------------------------------------- one template
export function templateView(ctx, { params }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const body = h('div', { class: 'stack' }, h('p', { role: 'status' }, t('common.loading')));
  const root = h('div', { class: 'stack' }, body);
  const flash = ctx.flash ?? null;
  ctx.flash = null;
  let alive = true;
  const back = link(router.href('templates'), null, t('tpl.back'));

  function draw(tpl) {
    const soaRows = tpl.soa ? SOA_FIELDS.map((k) => [t(`tpl.soa-${k}`), tpl.soa[k] === null || tpl.soa[k] === undefined ? '-' : render(String(tpl.soa[k]))]) : [];
    const result = h('div', { class: 'stack' });
    const vErr = message('error');
    const validate = h('button', { type: 'button' }, t('tpl.validate'));
    validate.addEventListener('click', () => busy(validate, async () => {
      vErr.set(null);
      try {
        const r = await api.post(`/templates/${tpl.id}/validate`, {});
        fill(result, h('p', { class: r.valid ? 'msg ok' : 'msg error', role: r.valid ? 'status' : 'alert' }, t(r.valid ? 'tpl.valid' : 'tpl.invalid')), messageList(ctx, r.messages));
        ctx.announce(t(r.valid ? 'tpl.valid' : 'tpl.invalid'));
      } catch (e) {
        vErr.setNodes(...problemNodes(i18n, e));
      }
    }));
    const recs = (tpl.records ?? []).map((r) => h('tr', null,
      h('th', { scope: 'row' }, h('code', null, render(r.owner))), h('td', null, render(r.type)), h('td', null, r.ttl === null || r.ttl === undefined ? '-' : String(r.ttl)), h('td', null, h('span', { class: 'rec' }, render(r.content)))));
    const info = h('section', { class: 'card', 'aria-labelledby': 'tpl-title' },
      h('h1', { id: 'tpl-title' }, render(tpl.name)),
      flash ? h('p', { class: 'msg ok', role: 'status' }, flash) : null,
      h('dl', null, [
        [t('tpl.h-description'), tpl.description ? render(tpl.description) : '-'],
        [t('tpl.h-revision'), String(tpl.revision)],
        [t('tpl.h-updated'), tpl.updated_at ? timeNode(tpl.updated_at, i18n.lang) : '-'],
        ...soaRows,
      ].map(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
      h('h2', null, t('tpl.records')),
      recs.length === 0 ? h('p', null, t('tpl.no-records')) : h('table', null, h('caption', { class: 'sr-only' }, t('tpl.records')),
        h('thead', null, h('tr', null, ...['owner', 'type', 'ttl', 'content'].map((k) => h('th', { scope: 'col' }, t(`tpl.r-${k}`))))), h('tbody', null, recs)),
      h('p', { class: 'hint' }, t('tpl.how-used')),
      h('p', { class: 'actions' }, validate, back), vErr.node, result);
    const parts = [info];
    if (isGlobal(ctx)) {
      const form = templateForm(ctx, tpl, { onSaved: (saved, warnings) => {
        ctx.flash = warnings > 0 ? t('tpl.saved-warnings', { count: warnings }) : t('tpl.saved');
        ctx.announce(t('tpl.saved'));
        router.refresh();
      } });
      const del = message('error');
      const ask = confirmButton({ label: t('tpl.delete'), confirmLabel: t('tpl.delete-ask'), yes: t('common.yes'), no: t('common.no'), onConfirm: async () => {
        del.set(null);
        try {
          await api.del(`/templates/${tpl.id}`);
          ctx.flash = t('tpl.deleted', { name: plain(tpl.name) });
          router.go('templates');
        } catch (e) {
          del.setNodes(...problemNodes(i18n, e));
        }
      } });
      parts.push(h('section', { class: 'card', 'aria-labelledby': 'tpl-edit' }, h('h2', { id: 'tpl-edit' }, t('tpl.edit')), form.node),
        h('section', { class: 'card danger-zone', 'aria-labelledby': 'tpl-del' }, h('h2', { id: 'tpl-del' }, t('tpl.delete-title')), h('p', null, t('tpl.delete-text')), h('p', { class: 'actions' }, ask), del.node));
    }
    fill(root, parts);
  }

  api.get(`/templates/${encodeURIComponent(params.id)}`).then((r) => { if (alive) draw(r.template); },
    (e) => { if (alive) fill(root, h('section', { class: 'card' }, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)), h('p', null, back))); });
  return { node: root, dispose() { alive = false; } };
}

// a new template
export function templateNewView(ctx) {
  const { i18n, router } = ctx;
  const t = i18n.t;
  const back = link(router.href('templates'), null, t('tpl.back'));
  if (!isGlobal(ctx)) return { node: h('section', { class: 'card' }, h('h1', null, t('tpl.new')), h('p', { class: 'notice' }, t('tpl.global-only')), h('p', null, back)) };
  const form = templateForm(ctx, null, { onSaved: (saved, warnings) => {
    ctx.flash = warnings > 0 ? t('tpl.saved-warnings', { count: warnings }) : t('tpl.saved');
    router.go('template', { id: String(saved.id) });
  } });
  return { node: h('section', { class: 'card', 'aria-labelledby': 'tpl-new' }, h('h1', { id: 'tpl-new' }, t('tpl.new')), h('p', null, t('tpl.new-text')), form.node, h('p', null, back)) };
}

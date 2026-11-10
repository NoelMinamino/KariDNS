// S6: a new zone (planning 3), for global masters.  Three ways: a form (SOA values, name servers, more records), a template that is copied (its values are the
// defaults of the form's), or a zone text (a file or pasted).  The dry run shows the whole new zone; the commit makes it and goes to its page.

import { h, fill, link } from '../dom.js';
import { render } from '../format.js';
import { field, select, message, problemNodes } from '../widgets.js';
import { datasetPath, absName, recordLines, parseRecordLine } from '../zonelib.js';
import { placeOnFields } from '../pointer.js';
import { changeFlow } from './change.js';
import { zoneTextInput } from './zonetext.js';

const SOA_FIELDS = ['refresh', 'retry', 'expire', 'minimum', 'ttl'];

// the lines "owner [ttl] TYPE rdata" -> RRsets of a change set (REPLACE), grouped by name and type; the TTL of the first line of a group is the RRset's.  -> { rrsets } | { error, line }
export function rrsetsFromLines(text, zone) {
  const groups = new Map();
  const lines = recordLines(text);
  for (const [i, line] of lines.entries()) {
    const r = parseRecordLine(line);
    const owner = r && absName(r.owner, zone);
    if (!r || !owner) return { error: 'line', line: i + 1 };
    const key = `${owner} ${r.type}`;
    if (!groups.has(key)) groups.set(key, { name: owner, type: r.type, changetype: 'REPLACE', ttl: r.ttl ?? 3600, records: [] });
    groups.get(key).records.push({ content: r.content });
  }
  return { rrsets: [...groups.values()] };
}

export function zoneCreateView(ctx, { params }) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  const body = h('div', { class: 'stack' });
  const root = h('section', { class: 'card', 'aria-labelledby': 'create-title' }, h('h1', { id: 'create-title' }, t('create.title', { ds })), body);
  let alive = true;
  let flow = null;

  async function load() {
    let templates = [];
    try {
      templates = (await api.get('/templates', { query: { limit: 500 } })).templates;
    } catch (e) {
      if (!alive) return;
      fill(body, h('p', { class: 'msg error', role: 'alert' }, ...problemNodes(i18n, e)));
      return;
    }
    if (alive) draw(templates);
  }

  function draw(templates) {
    const name = field({ label: t('create.name'), name: 'name', required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('create.name-hint') });
    const kind = select({ label: t('create.kind'), name: 'type', options: [{ value: 'NATIVE', label: 'NATIVE' }, { value: 'MASTER', label: 'MASTER' }], value: 'NATIVE' });
    const how = select({ label: t('create.how'), name: 'how', options: [{ value: 'form', label: t('create.how-form') }, { value: 'template', label: t('create.how-template') }, { value: 'text', label: t('create.how-text') }], value: 'form' });
    const tplSel = select({ label: t('create.template'), name: 'template', options: templates.map((x) => ({ value: x.name, label: x.name })), value: templates[0]?.name });
    const tplErr = message('error');
    const tplInfo = h('p', { class: 'hint' });
    const mname = field({ label: t('create.mname'), name: 'mname', maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('create.mname-hint') });
    const rname = field({ label: t('create.rname'), name: 'rname', maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('create.rname-hint') });
    const nums = Object.fromEntries(SOA_FIELDS.map((k) => [k, field({ label: t(`create.${k}`), name: k, inputmode: 'numeric', maxlength: 10 })]));
    const ns = field({ label: t('create.ns'), name: 'nameservers', kind: 'textarea', rows: 3, spellcheck: false, autocapitalize: 'none', hint: t('create.ns-hint') });
    const more = field({ label: t('create.more'), name: 'records', kind: 'textarea', rows: 5, spellcheck: false, autocapitalize: 'none', hint: t('create.more-hint') });
    const text = zoneTextInput(ctx, { label: t('create.text'), hint: t('create.text-hint') });
    const soaBox = h('fieldset', null, h('legend', null, t('create.soa')), mname.node, rname.node, h('div', { class: 'grid' }, SOA_FIELDS.map((k) => nums[k].node)));
    const formBox = h('div', { class: 'stack' }, soaBox, ns.node, more.node);
    const tplBox = h('div', { class: 'stack' }, tplSel.node, tplErr.node, tplInfo);
    const textBox = h('div', { hidden: true }, text.node);

    const mode = () => how.input.value;
    function showHow() {
      tplBox.hidden = mode() !== 'template';
      formBox.hidden = mode() === 'text';
      textBox.hidden = mode() !== 'text';
      const tpl = templates.find((x) => x.name === tplSel.input.value);
      fill(tplInfo, mode() === 'template' && tpl ? [tpl.description ? render(tpl.description) : null, ' ', t('create.tpl-records', { n: tpl.record_count })] : null);
      flow?.invalidate();
    }
    how.input.addEventListener('change', showHow);
    tplSel.input.addEventListener('change', showHow);
    tplBox.hidden = true;

    const fields = { '/name': name, '/soa/mname': mname, '/soa/rname': rname, '/nameservers': ns, '/rrsets': more, '/zone_text': text, '/template': { setError: (x) => tplErr.set(x) } };
    for (const k of SOA_FIELDS) fields[`/soa/${k}`] = nums[k];
    fields['/soa'] = mname;

    // the name of the zone being made, absolute: the records of the extra box are relative to it
    const zoneName = () => {
      const n = name.input.value.trim().toLowerCase().replace(/\.$/, '');
      return n === '' ? '.' : `${n}.`;
    };

    function request(dry, v) {
      const b = { name: name.input.value.trim(), type: kind.input.value };
      if (v.comment.trim() !== '') b.comment = v.comment.trim();
      if (v.reload !== undefined) b.reload = v.reload;
      if (dry) b.dry_run = true;
      if (mode() === 'text') return { ...b, zone_text: text.text() };
      const soa = {};
      if (mname.input.value.trim() !== '') soa.mname = mname.input.value.trim();
      if (rname.input.value.trim() !== '') soa.rname = rname.input.value.trim();
      for (const k of SOA_FIELDS) if (nums[k].input.value.trim() !== '') soa[k] = Number(nums[k].input.value.trim());
      if (Object.keys(soa).length > 0) b.soa = soa;
      const servers = recordLines(ns.input.value);
      if (servers.length > 0) b.nameservers = servers;
      const extra = rrsetsFromLines(more.input.value, zoneName()).rrsets ?? [];
      if (extra.length > 0) b.rrsets = extra;
      if (mode() === 'template') b.template = tplSel.input.value;
      return b;
    }

    function check() {
      for (const f of [name, mname, rname, ns, more]) f.setError(null);
      text.setError(null);
      for (const k of SOA_FIELDS) nums[k].setError(null);
      let bad = null;
      const fail = (f, msg) => { f.setError(msg); bad ??= f; };
      if (name.input.value.trim() === '') fail(name, t('create.need-name'));
      if (mode() === 'text') {
        const p = text.problem();
        if (p) fail(text, p);
      } else {
        for (const k of SOA_FIELDS) {
          const s = nums[k].input.value.trim();
          if (s !== '' && !/^\d{1,10}$/.test(s)) fail(nums[k], t('create.bad-number'));
        }
        const parsed = rrsetsFromLines(more.input.value, zoneName());
        if (parsed.error) fail(more, t('create.bad-line', { n: parsed.line }));
        if (mode() === 'form') {
          if (mname.input.value.trim() === '') fail(mname, t('create.need-mname'));
          if (rname.input.value.trim() === '') fail(rname, t('create.need-rname'));
          if (recordLines(ns.input.value).length === 0) fail(ns, t('create.need-ns'));
        }
      }
      bad?.focus();
      return bad !== null;
    }

    flow = changeFlow(ctx, {
      zone: null,
      reloadable: true,
      reloadDefault: ctx.session.state.version?.ui?.reload_after_change === true,
      previewLabel: t('create.preview'),
      commitLabel: t('create.commit'),
      check,
      run: (dry, v) => api.post(`${datasetPath(ds)}/zones`, request(dry, v)),
      place: (errs) => placeOnFields(errs, fields),
      onCommitted: (r) => router.go('zone', { ds, zone: r.zone }),
    });
    for (const f of [name, mname, rname, ns, more, ...Object.values(nums)]) f.input.addEventListener('input', () => flow.invalidate());
    text.node.addEventListener('input', () => flow.invalidate());
    showHow();
    fill(body, name.node, kind.node, how.node, tplBox, formBox, textBox, flow.node, h('p', null, link(router.href('zones', undefined, { ds }), null, t('create.back'))));
  }

  load();
  return { node: root, dispose() { alive = false; flow?.dispose(); } };
}

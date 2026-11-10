// S7: import a zone text into a zone (planning 3), for the masters of the whole zone.  The text is typed, pasted or read from a file chosen here (strict UTF-8, the size
// checked before it is sent).  "Replace" makes the zone the text's; "merge" replaces only the RRsets the text has.  The preview is a dry run; its diff is shown in pages
// of 200 RRsets (F-21).  Export is a plain link in the frame of the zone.

import { h } from '../dom.js';
import { select } from '../widgets.js';
import { zonePath } from '../zonelib.js';
import { placeOnFields } from '../pointer.js';
import { changeFlow } from './change.js';
import { zoneFrame } from './zoneframe.js';
import { zoneTextInput } from './zonetext.js';

export function zoneImportView(ctx, { params }) {
  const { api, i18n } = ctx;
  const t = i18n.t;
  const ds = params.ds;
  return zoneFrame(ctx, { ds, zone: params.zone, active: 'zone-import' }, (info, frame) => {
    if (info.role === 'subdomain_master') return { node: h('p', { class: 'notice' }, t('import.not-allowed')) };
    const mode = select({ label: t('import.mode'), name: 'mode', options: [{ value: 'replace', label: t('import.replace') }, { value: 'merge', label: t('import.merge') }], value: 'replace' });
    const text = zoneTextInput(ctx, { label: t('import.text'), hint: t('import.text-hint') });
    const flow = changeFlow(ctx, {
      zone: info.name,
      reloadable: !info.signer,
      reloadDefault: ctx.session.state.version?.ui?.reload_after_change === true,
      previewLabel: t('import.preview'),
      commitLabel: t('import.commit'),
      check: () => {
        const p = text.problem();
        text.setError(p);
        if (p) text.focus();
        return p !== null;
      },
      run: (dry, v) => {
        const b = { zone_text: text.text(), mode: mode.input.value };
        if (v.comment.trim() !== '') b.comment = v.comment.trim();
        if (v.reload !== undefined) b.reload = v.reload;
        if (dry) b.dry_run = true;
        return api.post(`${zonePath(ds, info.name)}/import`, b);
      },
      place: (errs) => placeOnFields(errs, { '/zone_text': text }),
      onCommitted: () => frame.refresh(),
    });
    mode.input.addEventListener('change', () => flow.invalidate());
    text.node.addEventListener('input', () => flow.invalidate());
    const node = h('section', { class: 'card', 'aria-labelledby': 'import-title' }, h('h2', { id: 'import-title' }, t('import.title')),
      h('p', null, t('import.intro')), mode.node, text.node, flow.node);
    return { node, dispose: () => flow.dispose() };
  });
}

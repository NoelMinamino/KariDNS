// A box for a zone text (a zone file, BIND format) that is typed, pasted or read from a file chosen on this machine (planning 3 S6 and S7).  A file is decoded as
// strict UTF-8: a file in another encoding is refused with the hint to write the bytes as \DDD, because the service takes JSON, which is Unicode.  The size is checked
// before anything is sent (the service says its limit in GET /version, G5).

import { h } from '../dom.js';
import { field } from '../widgets.js';

const DEFAULT_LIMIT = 16 << 20;

// -> { node, text(), setError(text|null), focus(), problem() }; problem() is the text of what keeps the zone text from being sent, or null
export function zoneTextInput(ctx, { label, hint, name = 'zone_text' }) {
  const t = ctx.i18n.t;
  const limit = ctx.session.state.version?.ui?.zone_text_limit ?? DEFAULT_LIMIT;
  const box = field({ label, name, kind: 'textarea', rows: 12, spellcheck: false, autocapitalize: 'none', hint });
  const fileId = `${name}-file`;
  const file = h('input', { id: fileId, type: 'file', name: `${name}_file` });
  const fileErr = h('p', { class: 'error', hidden: true, role: 'alert' });
  const size = (s) => new TextEncoder().encode(s).length;

  file.addEventListener('change', async () => {
    fileErr.hidden = true;
    const f = file.files?.[0];
    if (!f) return;
    if (f.size > limit) { fileErr.textContent = t('zonetext.too-large', { mib: Math.floor(limit / 1048576) }); fileErr.hidden = false; return; }
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(await f.arrayBuffer());
      box.input.value = text;
      box.setError(null);
    } catch {
      fileErr.textContent = t('zonetext.not-utf8');
      fileErr.hidden = false;
    }
  });

  return {
    node: h('div', { class: 'stack' }, box.node, h('div', { class: 'field' }, h('label', { for: fileId }, t('zonetext.file')), file, fileErr)),
    text: () => box.input.value,
    setError: (x) => box.setError(x),
    focus: () => box.focus(),
    // -> an error text when the text cannot be sent, else null
    problem() {
      const s = box.input.value;
      if (s.trim() === '') return t('zonetext.empty');
      if (size(s) > limit) return t('zonetext.too-large', { mib: Math.floor(limit / 1048576) });
      return null;
    },
  };
}

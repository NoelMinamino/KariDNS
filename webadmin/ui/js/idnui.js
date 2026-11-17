// idnui.js: internationalized names on the screens (0.7).  The service turns a name typed in Unicode into A-labels the way dig +idnin does and gives the U-label
// form of what it stores (`unicode` beside a name; GET /idn for a field); the page only shows both forms and the warnings.  It also makes the link of a name to
// ldns.jp when the service allows it (GET /version ui.ldns): ldns.jp looks the name up through a public resolver from the browser.

import { h, fill, outsideLink } from './dom.js';
import { render } from './format.js';
import { problemNodes } from './widgets.js';
import { stripDot } from './zonelib.js';

// the warning codes of the service -> the message of the page (an unknown code shows the service's English text)
const WARNING_TEXT = {
  'idn-disallowed': 'idn.w-disallowed', 'idn-bad-alabel': 'idn.w-bad-alabel',
  'idn-contexto': 'idn.w-contexto', 'idn-mixed-script': 'idn.w-mixed-script', 'idn-transitional': 'idn.w-transitional',
};

// a name and its U-label form: the U-labels first, the A-labels under them (both are hostile text: format.js); just the name when it has no U-label form
export function nameNodes(name, unicode) {
  if (typeof unicode !== 'string' || unicode === '' || unicode === name) return render(name);
  return h('span', { class: 'idn' }, h('span', { class: 'ulabel', lang: 'und' }, render(unicode)), h('span', { class: 'alabel' }, render(name)));
}

// the IDN warnings of a reply -> a list, or null when there are none
export function warningList(t, warnings) {
  if (!Array.isArray(warnings) || warnings.length === 0) return null;
  return h('ul', { class: 'msgs idn-warnings' }, warnings.map((w) => h('li', { class: 'warning' }, render(WARNING_TEXT[w?.code] ? t(WARNING_TEXT[w.code], { label: String(w.label ?? '') }) : String(w?.message ?? '')))));
}

// a name that is worth asking the service about: it has non-ASCII code points or an A-label
export const looksIdn = (s) => typeof s === 'string' && (/[^\x00-\x7f]/.test(s) || /(^|\.)xn--/i.test(s));

// What a field of a name becomes, shown under it while the person types (300 ms after the last key, and when the field is left): the name the service stores and
// its warnings.  toName: the text of the field -> the name to ask about (null: nothing to show).  -> { node, check() } (check: at once, for the tests and a submit).
export function idnHint(ctx, f, toName = (s) => s.trim()) {
  const node = h('div', { class: 'hint idn-hint', 'aria-live': 'polite' });
  f.node.append(node);
  let timer = null;
  let seq = 0;
  async function check() {
    clearTimeout(timer);
    const mine = ++seq;
    const name = toName(f.input.value);
    if (!looksIdn(name)) { fill(node); return; }
    try {
      const r = await ctx.api.get('/idn', { query: { name } });
      if (mine === seq) fill(node, h('p', null, ctx.i18n.t('idn.stored'), ' ', h('code', null, render(r.ascii))), warningList(ctx.i18n.t, r.warnings));
    } catch (e) {
      if (mine === seq) fill(node, h('p', { class: 'error' }, ...problemNodes(ctx.i18n, e)));
    }
  }
  f.input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(check, 300); });
  f.input.addEventListener('blur', check);
  return { node, check };
}

// a name in the A-label form the service stores: asked of the service when it has non-ASCII code points (the same conversion as the write would make), else as it is
export async function asciiOf(ctx, name) {
  if (!/[^\x00-\x7f]/.test(name)) return name;
  return (await ctx.api.get('/idn', { query: { name } })).ascii;
}

// the link of a name and type to ldns.jp, or null when the service has it off (ldns-link = no)
export function ldnsLink(ctx, name, type) {
  const l = ctx.session.state.version?.ui?.ldns;
  if (!l || typeof l.url !== 'string') return null;
  const t = ctx.i18n.t;
  const q = stripDot(name) || '.';
  return outsideLink(l.url, { q, t: type, c: 'dig', r: String(l.resolver), auto: '1' }, { class: 'outside', title: t('ldns.title', { resolver: String(l.resolver) }), 'aria-label': t('ldns.link-of', { name: q, type }) }, t('ldns.link'));
}

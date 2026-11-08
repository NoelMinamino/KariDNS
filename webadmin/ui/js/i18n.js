// i18n.js: the messages of the GUI in the user's language (F-6).  A catalog is a plain object { id: 'text with {name} placeholders' } (ui/i18n/en.js, ja.js).  Text is
// filled in as text: parts() returns strings and nodes, never HTML.  The API's error codes are the basis of the error messages: id "api.<code>" for every code of
// docs/karidns-api.md; a code without a message falls back to the API's own (English) detail.  Record data, names and codes are never translated.

import { plain } from './format.js';

export const LANG_KEY = 'karidns-lang';

const PLACEHOLDER = /\{([a-z_]+)\}/g;

// opts: { catalogs: { en, ja }, fallback: 'en', storage, languages: navigator.languages }
export function createI18n({ catalogs, fallback = 'en', storage, languages = [] }) {
  const known = Object.keys(catalogs);
  const listeners = [];

  function detect() {
    let saved = null;
    try { saved = storage?.getItem(LANG_KEY) ?? null; } catch { /* storage may be refused */ }
    if (saved && known.includes(saved)) return saved;
    for (const l of languages) {
      const primary = String(l).toLowerCase().split('-')[0];
      if (known.includes(primary)) return primary;
    }
    return fallback;
  }

  let lang = detect();

  // the message with its placeholders replaced: an array of strings and of whatever the caller gave (nodes included)
  function parts(id, params = {}) {
    const msg = catalogs[lang]?.[id] ?? catalogs[fallback]?.[id] ?? id;
    const out = [];
    let last = 0;
    for (const m of msg.matchAll(PLACEHOLDER)) {
      if (m.index > last) out.push(msg.slice(last, m.index));
      out.push(m[1] in params ? params[m[1]] : m[0]);
      last = m.index + m[0].length;
    }
    if (last < msg.length) out.push(msg.slice(last));
    return out;
  }

  const t = (id, params) => parts(id, params).map(String).join('');
  const has = (id) => id in (catalogs[lang] ?? {}) || id in (catalogs[fallback] ?? {});

  // the message for an ApiProblem: the catalog's text of its code, else the API's detail, else a general text
  const errorText = (p) => (has(`api.${p.code}`) ? t(`api.${p.code}`) : p.detail ? plain(p.detail) : t('err.unknown'));

  return {
    get lang() { return lang; },
    languages: known,
    t,
    parts,
    has,
    errorText,
    setLang(l) {
      if (!known.includes(l)) return;
      lang = l;
      try { storage?.setItem(LANG_KEY, l); } catch { /* the choice lasts for this page only */ }
      for (const fn of listeners) fn(l);
    },
    onChange(fn) { listeners.push(fn); },
  };
}

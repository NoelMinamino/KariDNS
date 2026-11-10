// format.js: text from the API (zone data, names, comments, error texts) is hostile (planning 5.2).  Characters that are invisible or reorder what is around
// them are made visible before display: C0 / C1 controls and DEL as \DDD (decimal, as a zone file writes them), bidi controls, zero-width and other format
// characters, line and paragraph separators, private-use and lone surrogate code points as <U+XXXX> in a distinct style.  The result is text nodes only.

import { h, text } from './dom.js';

// format (Cf: bidi controls U+202A-202E, U+2066-2069, U+200B-200F, U+FEFF, ...), line / paragraph separators, private use, surrogates (a lone one)
const MARK = /^[\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}]$/u;

// -> [{ kind: 'text' | 'ctl' | 'fmt', text }] (runs of ordinary characters are one segment)
export function segments(value) {
  const out = [];
  let run = '';
  const flush = () => {
    if (run) out.push({ kind: 'text', text: run });
    run = '';
  };
  for (const ch of String(value ?? '')) {
    const cp = ch.codePointAt(0);
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) {
      flush();
      out.push({ kind: 'ctl', text: `\\${String(cp).padStart(3, '0')}` });
    } else if (MARK.test(ch)) {
      flush();
      out.push({ kind: 'fmt', text: `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>` });
    } else {
      run += ch;
    }
  }
  flush();
  return out;
}

// the visible form as a string (for title attributes, aria-labels, a text that is not put in an element)
export const plain = (value) => segments(value).map((s) => s.text).join('');

// the visible form as nodes: text, and a span.marker for each made-visible character
export function render(value) {
  return segments(value).map((s) => (s.kind === 'text' ? text(s.text) : h('span', { class: `marker ${s.kind}` }, s.text)));
}

// at most n characters (code points), with an ellipsis; the cut is not inside a surrogate pair
export function clip(value, n) {
  const chars = [...String(value ?? '')];
  return chars.length > n ? `${chars.slice(0, n).join('')}…` : chars.join('');
}

// a time from the API (ISO 8601, UTC) in the user's locale with the time zone shown; the ISO text on hover.  An unreadable value is shown as text.
export function formatTime(iso, lang) {
  const d = new Date(iso);
  if (typeof iso !== 'string' || Number.isNaN(d.getTime())) return plain(iso);
  try {
    return new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'medium', timeZoneName: 'short' }).format(d);
  } catch {
    return d.toISOString();
  }
}

export function timeNode(iso, lang) {
  const shown = formatTime(iso, lang);
  return h('time', { datetime: typeof iso === 'string' ? plain(iso) : undefined, title: plain(iso) }, shown);
}

// a number of seconds as "2 min 5 s" style text, in numbers and unit letters that need no catalog
export function duration(sec) {
  const s = Math.max(0, Math.round(sec));
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}:${String(s % 60).padStart(2, '0')}` : `0:${String(s).padStart(2, '0')}`;
}

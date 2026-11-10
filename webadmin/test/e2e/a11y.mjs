// a11y.mjs: the checks of planning 7.1 / F-22 that a script can make on whatever is on the screen, shared by the drivers (gui.mjs, gui_zones.mjs: one copy, Rule 4).
// pageProblems runs IN THE PAGE (b.exec(pageProblems)), so it uses nothing of this file; it returns the list of problems (empty: none).  What a script cannot judge (reading
// order, whether a text makes sense, the behaviour with a screen reader) is the manual checklist of docs/karidns-webadmin-gui-checklist.md.
//
// WCAG 2.1 success criteria covered here: 1.1.1 (an image has a name), 1.3.1 (headers of tables, labels, one level of heading at a time), 1.3.5 (autocomplete on password
// fields), 2.4.2 (a title), 2.4.3 (no positive tabindex), 2.5.3 (the name of a control contains its visible text), 3.1.1 (the language of the page), 3.3.2 (labels),
// 4.1.1 (no duplicate ids; the ids that are referred to exist), 4.1.2 (every button, link, field, dialog and landmark has a name), 4.1.3 (the live regions exist).

export function pageProblems() {
  const bad = [];
  const label = (el) => (el.getAttribute('aria-label') || '').trim();
  const visible = (el) => el.getClientRects().length > 0;
  const nameOf = (el) => {
    const lb = el.getAttribute('aria-labelledby');
    if (lb) return lb.split(' ').map((id) => (document.getElementById(id)?.textContent || '').trim()).join(' ').trim();
    return label(el);
  };
  for (const el of document.querySelectorAll('input, select, textarea')) {
    if (el.type === 'hidden') continue;
    if (!(el.labels && el.labels.length) && !nameOf(el)) bad.push(`input ${el.name || el.id} has no label`);
    if (el.type === 'password' && !el.getAttribute('autocomplete')) bad.push(`password field ${el.name} has no autocomplete`);
  }
  for (const el of document.querySelectorAll('button, a[href]')) {
    if (!(el.textContent || '').trim() && !label(el)) bad.push('a button or link without a name');
    // 2.5.3: when the name is not the visible text, it contains it
    const seen = (el.textContent || '').trim().replace(/[.…]+$/, '').toLowerCase();
    if (label(el) && seen && !label(el).toLowerCase().includes(seen)) bad.push(`the name "${label(el)}" does not contain the visible text "${seen}"`);
  }
  for (const el of document.querySelectorAll('svg[role=img], img')) if (!label(el) && !el.getAttribute('alt')) bad.push('an image without a name');
  for (const el of document.querySelectorAll('dialog[open]')) if (!nameOf(el)) bad.push('an open dialog without a name');
  for (const el of document.querySelectorAll('nav')) if (!nameOf(el)) bad.push('a nav without a name');
  const heads = [...document.querySelectorAll('h1, h2, h3, h4, h5, h6')].filter(visible);
  if (document.querySelectorAll('h1').length !== 1) bad.push(`${document.querySelectorAll('h1').length} h1`);
  let level = 0;
  for (const hd of heads) {
    const n = Number(hd.tagName[1]);
    if (level && n > level + 1) bad.push(`the heading "${hd.textContent.trim().slice(0, 30)}" jumps from h${level} to h${n}`);
    level = n;
  }
  const lang = document.documentElement.lang;
  if (!['en', 'ja'].includes(lang)) bad.push(`lang is "${lang}"`);
  if (!document.title.trim()) bad.push('no title');
  if (!document.querySelector('main')) bad.push('no main');
  if (!document.querySelector('header')) bad.push('no banner');
  if (document.querySelector('[tabindex]:not([tabindex="0"]):not([tabindex="-1"])')) bad.push('a positive tabindex');
  for (const t of document.querySelectorAll('table')) {
    if (!t.querySelector('th')) bad.push('a table without header cells');
    for (const th of t.querySelectorAll('th')) if (!th.getAttribute('scope')) bad.push(`a header cell without scope ("${th.textContent.trim().slice(0, 20)}")`);
  }
  for (const live of ['polite', 'assertive']) if (!document.querySelector(`[aria-live=${live}]`)) bad.push(`no ${live} live region`);
  const ids = [...document.querySelectorAll('[id]')].map((e) => e.id);
  for (const id of new Set(ids.filter((x, i) => ids.indexOf(x) !== i))) bad.push(`duplicate id ${id}`);
  for (const attr of ['aria-describedby', 'aria-labelledby', 'aria-controls']) {
    for (const el of document.querySelectorAll(`[${attr}]`)) for (const id of el.getAttribute(attr).split(' ')) if (!document.getElementById(id)) bad.push(`${attr} ${id} does not exist`);
  }
  return bad;
}

// 1.4.10 (reflow): with the page laid out in `w` CSS pixels (320: the criterion), nothing except a data table, a block of code or a drawing reaches past the right edge.
// Firefox will not make a window narrower than about 490 pixels, so the root element is given the width instead (the window is as narrow as it goes, so that the one
// media query of the style sheet, max-width 40rem, applies as it does on a phone).  In the page, like pageProblems.
export function overflowProblems(w = 320) {
  const bad = [];
  const root = document.documentElement;
  const before = root.style.width;
  root.style.width = `${w}px`;
  try {
    for (const el of document.querySelectorAll('main *, header *, footer *')) {
      if (!el.getClientRects().length) continue;
      if (el.closest('table, pre, svg')) continue;
      const r = el.getBoundingClientRect();
      if (r.right > w + 1) bad.push(`${el.tagName.toLowerCase()}${el.className ? `.${String(el.className).split(' ')[0]}` : ''} "${(el.textContent || '').trim().slice(0, 24)}" ends at ${Math.round(r.right)} of ${w}`);
    }
  } finally {
    root.style.width = before;
  }
  return { width: w, window: window.innerWidth, bad: bad.slice(0, 12) };
}

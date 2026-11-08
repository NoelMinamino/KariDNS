// widgets.js: the small parts every screen uses (planning 7.1): a labelled field (a real <label for>, hint and error tied with aria-describedby), a checkbox, a select,
// a message line, a button that is disabled while its work runs, a two-step confirmation, and the text of an error from the API.

import { h, fill } from './dom.js';
import { plain, render } from './format.js';

let seq = 0;
export const uid = (prefix = 'f') => `${prefix}${++seq}`;

// -> { node, input, setError(text | null), focus() }.  kind: 'input' (default) | 'textarea'
export function field({ label, type = 'text', name, value, autocomplete, hint, required = false, maxlength, minlength, inputmode, spellcheck, autocapitalize, kind = 'input', rows }) {
  const id = uid('in');
  const hintNode = hint ? h('p', { class: 'hint', id: `${id}-hint` }, hint) : null;
  const err = h('p', { class: 'error', id: `${id}-err`, hidden: true });
  const props = {
    id, name, value, autocomplete, required, maxlength, minlength, inputmode, spellcheck, autocapitalize, rows,
    'aria-describedby': [hintNode ? `${id}-hint` : null, `${id}-err`].filter(Boolean).join(' '),
  };
  if (kind === 'input') props.type = type;
  const input = h(kind, props);
  const node = h('div', { class: 'field' }, h('label', { for: id }, label, required ? h('span', { class: 'req', 'aria-hidden': 'true' }, ' *') : null), input, hintNode, err);
  return {
    node,
    input,
    setError(text) {
      err.hidden = !text;
      err.textContent = text ?? '';
      input.setAttribute('aria-invalid', text ? 'true' : 'false');
    },
    focus() { input.focus(); },
  };
}

export function checkbox({ label, checked = false, name }) {
  const id = uid('cb');
  const input = h('input', { id, type: 'checkbox', name, checked });
  return { node: h('div', { class: 'check' }, input, h('label', { for: id }, label)), input };
}

// options: [{ value, label }]
export function select({ label, options, value, name }) {
  const id = uid('sel');
  const input = h('select', { id, name }, options.map((o) => h('option', { value: o.value, selected: o.value === value }, o.label)));
  input.value = value;
  return { node: h('div', { class: 'field' }, h('label', { for: id }, label), input), input };
}

// a line of text that screen readers announce when it changes: kind 'error' (assertive) or 'status' (polite)
export function message(kind = 'status') {
  const node = h('p', { class: kind === 'error' ? 'msg error' : 'msg', role: kind === 'error' ? 'alert' : 'status', hidden: true });
  return {
    node,
    set(text) { node.hidden = !text; node.textContent = text ?? ''; },
    setNodes(...kids) { node.hidden = kids.length === 0; fill(node, ...kids); },
  };
}

// runs fn() with the button disabled until it is done (a double click is one request)
export async function busy(button, fn) {
  if (button.disabled) return undefined;
  button.disabled = true;
  try {
    return await fn();
  } finally {
    button.disabled = false;
  }
}

// a button that asks again before it acts: the first click shows "Really? [Yes] [No]" in its place; yes calls onConfirm
export function confirmButton({ label, confirmLabel, yes, no, onConfirm, cls = 'danger' }) {
  const wrap = h('span', { class: 'confirm' });
  const first = h('button', { type: 'button', class: cls }, label);
  const yesButton = h('button', { type: 'button', class: cls, on: { click: () => { reset(); onConfirm(); } } }, yes);
  const ask = h('span', { hidden: true }, h('span', { class: 'ask' }, confirmLabel, ' '), yesButton, ' ', h('button', { type: 'button', on: { click: () => reset() } }, no));
  function reset() { ask.hidden = true; first.hidden = false; first.focus(); }
  first.addEventListener('click', () => { first.hidden = true; ask.hidden = false; yesButton.focus(); });
  wrap.append(first, ask);
  return wrap;
}

// the text of an ApiProblem for a person: the message of its code, the request id of a 500 and the texts of errors[] (these are the service's, shown as plain text)
export function problemNodes(i18n, p) {
  const out = [i18n.errorText(p)];
  if (p.errors?.length && !i18n.has(`api.${p.code}`)) out.push(' ', p.errors.map((e) => plain(e.text)).join('; '));
  if (p.requestId && (p.status >= 500 || p.status === 0 || p.code === 'unknown')) out.push(' ', ...i18n.parts('err.request-id', { id: h('code', null, render(p.requestId)) }));
  return out;
}

export const problemText = (i18n, p) => problemNodes(i18n, p).map((n) => (typeof n === 'string' ? n : n.textContent)).join('');

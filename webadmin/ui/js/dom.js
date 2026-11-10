// dom.js: the ONLY module that creates elements (planning 4.1, 5.2).  Text reaches the page as text nodes, never as HTML; an attribute is set from a fixed list
// of names (never href, src, style or on* from data); events are added with addEventListener.  The views use nothing of the DOM but what is here and a small
// subset (textContent, append, replaceChildren, classList, focus, dialogs), so the fake DOM of the tests (test/fakedom.js) can run them in Node (F-11).

let doc = globalThis.document;

// the document the elements are made in (the page's own; the tests give their fake)
export const setDocument = (d) => { doc = d; };
export const getDocument = () => doc;

const SVG_NS = 'http://www.w3.org/2000/svg';

// properties that are set as properties (the live state of a control), by the name used in a call to h()
const BOOL = new Set(['disabled', 'hidden', 'checked', 'readonly', 'required', 'selected', 'multiple', 'open', 'autofocus']);
const PROP_NAME = { readonly: 'readOnly' };
// attributes that data may not decide, but code may set through h(): a fixed list
const ATTRS = new Set([
  'id', 'type', 'name', 'value', 'title', 'role', 'lang', 'dir', 'tabindex', 'autocomplete', 'inputmode', 'maxlength', 'minlength', 'min', 'max', 'step', 'rows', 'cols',
  'placeholder', 'scope', 'colspan', 'rowspan', 'spellcheck', 'autocapitalize', 'enterkeyhint', 'datetime', 'size', 'wrap', 'novalidate',
]);
const SVG_ATTRS = new Set(['viewBox', 'd', 'width', 'height', 'role', 'class', 'aria-label', 'aria-hidden', 'focusable', 'shape-rendering', 'preserveAspectRatio']);
const DATA_OR_ARIA = /^(data-[a-z0-9-]+|aria-[a-z]+)$/;

const isNode = (c) => c !== null && typeof c === 'object' && typeof c.nodeType === 'number';

// the children as nodes: a string or a number is a text node, null / undefined / false are nothing, an array is flattened
function append(parent, kids) {
  for (const c of kids) {
    if (c === null || c === undefined || c === false || c === true) continue;
    if (Array.isArray(c)) append(parent, c);
    else if (isNode(c)) parent.append(c);
    else parent.append(doc.createTextNode(String(c)));
  }
}

function setProps(el, props) {
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null) continue;
    if (k === 'on') {
      for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    } else if (BOOL.has(k)) {
      el[PROP_NAME[k] ?? k] = Boolean(v);
    } else if (k === 'class') {
      el.className = Array.isArray(v) ? v.filter(Boolean).join(' ') : String(v);
    } else if (k === 'for') {
      el.htmlFor = String(v);
    } else if (k === 'value') {
      el.value = String(v);
    } else if (ATTRS.has(k) || DATA_OR_ARIA.test(k)) {
      el.setAttribute(k, String(v));
    } else {
      throw new Error(`dom.h: the attribute ${k} may not be set`);
    }
  }
}

// h('button', { class: 'primary', on: { click: fn } }, 'text', child, [more]) -> the element
export function h(tag, props, ...kids) {
  const el = doc.createElement(tag);
  if (props) setProps(el, props);
  append(el, kids);
  return el;
}

// a link to a place of the page: only a hash route built by the router (starts with "#/"), never a URL from data
export function link(href, props, ...kids) {
  if (typeof href !== 'string' || !href.startsWith('#/')) throw new Error('dom.link: only hash routes');
  const el = h('a', props, ...kids);
  el.setAttribute('href', href);
  return el;
}

// a link to a file the API serves (the export of a zone): a path under /api/v1/ that the code built from encoded parts, never a URL from data.  The browser saves it
// (the service answers with Content-Disposition: attachment); the session cookie goes with it because the address is the page's own origin.
export function fileLink(path, props, ...kids) {
  // (no "." or ".." part: the browser would take it out of the address, see api.js)
  if (typeof path !== 'string' || !/^\/api\/v1\/[A-Za-z0-9._~%/!*'()-]+$/.test(path) || /\/(?:\.|%2e){1,2}(?=\/|$)/i.test(path)) throw new Error('dom.fileLink: only API paths');
  const el = h('a', props, ...kids);
  el.setAttribute('href', path);
  el.setAttribute('download', '');
  return el;
}

// the button that starts a sign-in with an identity provider: a link to /api/v1/auth/oidc/<name>/start, a plain navigation (the service answers with a redirect to the
// provider).  The name is a provider's name as the configuration allows it; the route is the hash route to come back to ("/zones/main/example.test"), put into the
// query as one encoded value.  Never a URL from data.
export function oidcLink(name, route, props, ...kids) {
  if (typeof name !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(name)) throw new Error('dom.oidcLink: not a provider name');
  const back = typeof route === 'string' && route.length <= 500 && route.startsWith('/') && !route.startsWith('//') && !/[\0-\x1f\x7f]/.test(route) ? route : '/';
  const el = h('a', props, ...kids);
  el.setAttribute('href', `/api/v1/auth/oidc/${name}/start?return=${encodeURIComponent(back)}`);
  return el;
}

// a drawing: svg('svg', { viewBox: '0 0 10 10' }, svg('path', { d: '...' }))
export function svg(tag, attrs, ...kids) {
  const el = doc.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (!SVG_ATTRS.has(k)) throw new Error(`dom.svg: the attribute ${k} may not be set`);
    el.setAttribute(k, String(v));
  }
  append(el, kids);
  return el;
}

export const text = (s) => doc.createTextNode(String(s));

// the children of a node replaced by these
export function fill(node, ...kids) {
  node.replaceChildren();
  append(node, kids);
  return node;
}

export const clear = (node) => { node.replaceChildren(); };

export const setTitle = (s) => { doc.title = s; };
export const setLang = (lang) => { doc.documentElement.lang = lang; };

// a modal dialog (focus is trapped and returned by the browser, 7.1); removed from the page when it is closed
export function openDialog(dialog, parent = doc.body) {
  parent.append(dialog);
  dialog.addEventListener('close', () => dialog.remove());
  dialog.showModal();
  return dialog;
}

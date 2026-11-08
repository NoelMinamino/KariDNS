// fakedom.js: the part of the DOM that webadmin/ui/js/dom.js and the views use, so that the views run under Node (F-11): elements with attributes, classes, children,
// text, events that bubble, forms (a click on a submit button submits), dialogs, a focus, a document with a body and a title, a window with a location.hash that fires
// hashchange.  Also the fakes of the rest of the environment of createApp: a clock with timers you advance by hand, BroadcastChannel, localStorage, and fetch.

export class FakeEvent {
  constructor(type, init = {}) { Object.assign(this, init); this.type = type; this.defaultPrevented = false; this.target = null; }
  preventDefault() { this.defaultPrevented = true; }
}

class FakeNode {
  constructor() { this.parentNode = null; this.childNodes = []; }
  get firstChild() { return this.childNodes[0] ?? null; }
  remove() { if (this.parentNode) { this.parentNode.childNodes = this.parentNode.childNodes.filter((c) => c !== this); this.parentNode = null; } }
}

export class FakeText extends FakeNode {
  constructor(data) { super(); this.nodeType = 3; this.data = data; }
  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v); }
}

const matchOne = (el, sel) => {
  // tag#id.class[attr=value]
  const re = /^([a-z0-9-]+|\*)?(#[A-Za-z0-9_-]+)?((?:\.[A-Za-z0-9_-]+)*)((?:\[[^\]]+\])*)$/i;
  const m = re.exec(sel);
  if (!m) throw new Error(`fakedom: selector not supported: ${sel}`);
  if (m[1] && m[1] !== '*' && el.tagName.toLowerCase() !== m[1].toLowerCase()) return false;
  if (m[2] && el.getAttribute('id') !== m[2].slice(1)) return false;
  for (const c of m[3].split('.').filter(Boolean)) if (!el.classList.contains(c)) return false;
  for (const a of m[4].matchAll(/\[([a-z-]+)(?:=("?)([^\]"]*)\2)?\]/gi)) {
    if (!el.hasAttribute(a[1])) return false;
    if (a[3] !== undefined && el.getAttribute(a[1]) !== a[3]) return false;
  }
  return true;
};

export class FakeElement extends FakeNode {
  constructor(doc, tag, ns) {
    super();
    this.nodeType = 1;
    this.ownerDocument = doc;
    this.tagName = tag.toUpperCase();
    this.namespaceURI = ns ?? 'http://www.w3.org/1999/xhtml';
    this.attrs = new Map();
    this.listeners = new Map();
    this.open = false;
    this.disabled = false;
    this.hidden = false;
    this.checked = false;
    this.value = '';
    this.selected = false;
    const self = this;
    this.classList = {
      contains: (c) => self.className.split(/\s+/).includes(c),
      add: (c) => { if (!self.classList.contains(c)) self.className = `${self.className} ${c}`.trim(); },
      remove: (c) => { self.className = self.className.split(/\s+/).filter((x) => x && x !== c).join(' '); },
    };
  }

  get className() { return this.attrs.get('class') ?? ''; }
  set className(v) { this.attrs.set('class', String(v)); }
  get htmlFor() { return this.attrs.get('for') ?? ''; }
  set htmlFor(v) { this.attrs.set('for', String(v)); }
  get id() { return this.attrs.get('id') ?? ''; }
  get children() { return this.childNodes.filter((c) => c.nodeType === 1); }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) { this.replaceChildren(String(v) === '' ? [] : new FakeText(String(v))); }
  setAttribute(n, v) { this.attrs.set(n, String(v)); if (n === 'value') this.value = String(v); }
  getAttribute(n) { return this.attrs.has(n) ? this.attrs.get(n) : null; }
  hasAttribute(n) { return this.attrs.has(n); }
  removeAttribute(n) { this.attrs.delete(n); }

  append(...kids) {
    for (const k of kids.flat()) {
      const node = typeof k === 'string' ? new FakeText(k) : k;
      if (node.parentNode) node.remove();
      node.parentNode = this;
      this.childNodes.push(node);
    }
  }

  replaceChildren(...kids) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    this.append(...kids);
  }

  addEventListener(type, fn) { (this.listeners.get(type) ?? this.listeners.set(type, []).get(type)).push(fn); }
  removeEventListener(type, fn) { this.listeners.set(type, (this.listeners.get(type) ?? []).filter((f) => f !== fn)); }

  // bubbles to the parents, up to the document
  dispatchEvent(ev) {
    ev.target ??= this;
    for (let n = this; n; n = n.parentNode ?? (n === n.ownerDocument?.body ? n.ownerDocument : null)) {
      ev.currentTarget = n;
      for (const fn of [...(n.listeners?.get(ev.type) ?? [])]) fn(ev);
      if (ev.noBubble) break;
    }
    return !ev.defaultPrevented;
  }

  focus() { this.ownerDocument.activeElement = this; }

  // a click: a checkbox toggles, a submit button submits its form (unless disabled), a link to a hash route goes there
  click() {
    if (this.disabled || this.hidden) return;
    if (this.tagName === 'INPUT' && this.getAttribute('type') === 'checkbox') this.checked = !this.checked;
    const ok = this.dispatchEvent(new FakeEvent('click'));
    if (!ok) return;
    if (this.tagName === 'BUTTON' && (this.getAttribute('type') ?? 'submit') === 'submit') {
      for (let n = this.parentNode; n; n = n.parentNode) if (n.tagName === 'FORM') { n.submit(); break; }
    }
    if (this.tagName === 'A' && this.getAttribute('href')?.startsWith('#')) this.ownerDocument.defaultView.location.hash = this.getAttribute('href');
  }

  submit() { const ev = new FakeEvent('submit', { noBubble: false }); this.dispatchEvent(ev); }

  showModal() { this.open = true; this.ownerDocument.activeElement = this; }
  close() { if (!this.open) return; this.open = false; this.dispatchEvent(new FakeEvent('close', { noBubble: true })); }

  querySelectorAll(sel) {
    const parts = sel.trim().split(/\s+/);
    const out = [];
    const walk = (el, depth) => {
      for (const c of el.children) {
        if (matchOne(c, parts[depth])) {
          if (depth === parts.length - 1) out.push(c); else walk(c, depth + 1);
        }
        walk(c, depth);
      }
    };
    walk(this, 0);
    return [...new Set(out)];
  }

  querySelector(sel) { return this.querySelectorAll(sel)[0] ?? null; }
}

export class FakeDocument {
  constructor() {
    this.listeners = new Map();
    this.activeElement = null;
    this.title = '';
    this.defaultView = null;
    this.documentElement = new FakeElement(this, 'html');
    this.body = new FakeElement(this, 'body');
    this.documentElement.append(this.body);
    const app = new FakeElement(this, 'div');
    app.setAttribute('id', 'app');
    this.body.append(app);
  }

  createElement(tag) { return new FakeElement(this, tag); }
  createElementNS(ns, tag) { return new FakeElement(this, tag, ns); }
  createTextNode(s) { return new FakeText(String(s)); }
  getElementById(id) { return this.body.querySelectorAll(`#${id}`)[0] ?? null; }
  addEventListener(type, fn) { (this.listeners.get(type) ?? this.listeners.set(type, []).get(type)).push(fn); }
  dispatchEvent(ev) { for (const fn of this.listeners.get(ev.type) ?? []) fn(ev); }
}

export class FakeWindow {
  constructor(doc) {
    this.document = doc;
    doc.defaultView = this;
    this.listeners = new Map();
    this.reloaded = 0;
    let hash = '';
    const self = this;
    this.location = {
      get hash() { return hash; },
      set hash(v) { const next = String(v).startsWith('#') ? String(v) : `#${v}`; if (next !== hash) { hash = next; self.dispatchEvent(new FakeEvent('hashchange')); } },
      reload() { self.reloaded++; },
    };
  }

  addEventListener(type, fn) { (this.listeners.get(type) ?? this.listeners.set(type, []).get(type)).push(fn); }
  dispatchEvent(ev) { for (const fn of this.listeners.get(ev.type) ?? []) fn(ev); }
}

// a clock and timers that run when the test says so
export function makeClock(start = 1_700_000_000_000) {
  let t = start;
  let seq = 0;
  const jobs = new Map();
  const timers = {
    setTimeout(fn, ms) { jobs.set(++seq, { at: t + ms, fn, every: null }); return seq; },
    clearTimeout(id) { jobs.delete(id); },
    setInterval(fn, ms) { jobs.set(++seq, { at: t + ms, fn, every: ms }); return seq; },
    clearInterval(id) { jobs.delete(id); },
  };
  return {
    timers,
    now: () => t,
    pending: () => jobs.size,
    // moves the clock, running what falls due on the way, in order
    async advance(ms) {
      const end = t + ms;
      for (;;) {
        const due = [...jobs.entries()].filter(([, j]) => j.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        const [id, job] = due;
        t = Math.max(t, job.at);
        if (job.every) job.at += job.every; else jobs.delete(id);
        job.fn();
        await flush();
      }
      t = end;
    },
  };
}

// lets the promises that are waiting run
export const flush = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };

export class FakeStorage {
  constructor(init = {}) { this.m = new Map(Object.entries(init)); }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { this.m.set(k, String(v)); }
}

// BroadcastChannel: instances of one name hear each other (not themselves)
export function makeBroadcast() {
  const all = new Map();
  return class FakeBroadcastChannel {
    constructor(name) { this.name = name; this.onmessage = null; (all.get(name) ?? all.set(name, new Set()).get(name)).add(this); }
    postMessage(data) { for (const c of all.get(this.name)) if (c !== this) c.onmessage?.({ data }); }
    close() { all.get(this.name).delete(this); }
  };
}

// a Response as much as api.js uses it
export function reply(status, body, headers = {}) {
  const h = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    status, ok: status >= 200 && status < 300,
    headers: { get: (k) => h.get(k.toLowerCase()) ?? null },
    json: async () => { if (body === undefined || body === null) throw new SyntaxError('no body'); return typeof body === 'string' ? JSON.parse(body) : body; },
  };
}

export const problem = (status, code, extra = {}, headers = {}) => reply(status, { api: 1, type: `urn:karidns:api:${code}`, title: 't', status, detail: `detail of ${code}`, request_id: 'rid1', ...extra }, { 'content-type': 'application/problem+json', ...headers });

// helpers for the tests
export const textOf = (el) => el.textContent;
export function findAll(root, pred) {
  const out = [];
  const walk = (n) => { for (const c of n.childNodes) { if (c.nodeType === 1) { if (pred(c)) out.push(c); walk(c); } } };
  walk(root);
  return out;
}
export const byText = (root, tag, re) => findAll(root, (e) => e.tagName === tag.toUpperCase() && re.test(e.textContent))[0] ?? null;
export function everyElement(root) { return findAll(root, () => true); }

// the whole environment for createApp: calls go to handler(method, url, body, headers) -> a reply() or problem()
export function makeEnv({ handler, languages = ['en'], storage = new FakeStorage(), clock = makeClock(), BroadcastChannel = makeBroadcast(), clipboard } = {}) {
  const document = new FakeDocument();
  const window = new FakeWindow(document);
  const calls = [];
  const fetch = async (url, init = {}) => {
    const call = { method: init.method ?? 'GET', url, headers: init.headers ?? {}, body: init.body === undefined ? undefined : JSON.parse(init.body) };
    calls.push(call);
    return handler(call.method, url, call.body, call.headers);
  };
  return { window, document, fetch, storage, BroadcastChannel, timers: clock.timers, now: clock.now, languages, clipboard: clipboard ?? { writeText: async () => {} }, clock, calls };
}

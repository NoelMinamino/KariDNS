// Internationalized names (0.7): a name typed in Unicode becomes the A-labels the database holds, exactly as dig +idnin converts it, and a stored name is shown
// with its U-labels as dig +idnout shows it.  The conversion is libidn2's, through `karidns-zone idn --json` (docs/karidns-zone.md "idn"): the IDNA code of
// Node differs between builds of Node (the ada library it is built with), and the stored name must not depend on the host.  One run of the tool a request.
//
// The routes name the fields that hold names (routes.js `idn`); the pre-pass below replaces each of them that holds non-ASCII code points with its A-labels
// before the handler runs, so the rest of the service (names.js) still takes ASCII names only.  A name dig would not convert has no A-label form: 400.  The
// warnings (a code point IDNA2008 does not allow, the transitional mapping, a CONTEXTO rule, scripts mixed, an xn-- label that is no A-label) go into the
// reply of a write.

import { ApiError, badRequest } from './errors.js';

const NON_ASCII = /[^\x00-\x7f]/;
const XN = /(^|\.)xn--/i;
const DOTS = /[.。．｡]/;
const LINE_SAFE = /^[^\0-\x1f\x7f]{1,1024}$/;

// a value that the tool is asked about: a string with non-ASCII code points (to convert) or with an xn-- label (to check), that fits a line of its input
export const needsIdn = (s) => typeof s === 'string' && LINE_SAFE.test(s) && (NON_ASCII.test(s) || XN.test(s));

// Runs the tool once for [[kind 'a' | 'u', name], ...] -> its answers in order, or null: this karidns-zone has no libidn2.  A tool that fails otherwise is a
// broken installation: 500, logged.
async function runIdn(ctx, lines) {
  const { app } = ctx;
  const r = await app.runTool(app.settings['karidns-zone'], ['idn', '--json'], { input: lines.map(([k, n]) => `${k}\t${n}\n`).join(''), timeoutMs: 30000, maxOutput: 16 << 20 });
  let doc = null;
  try { doc = JSON.parse(r.stdout); } catch { /* reported below */ }
  if (doc?.messages?.some?.((m) => m?.code === 'db.idn.unavailable')) return null;
  const list = doc?.idn;
  if (r.spawnError || r.timedOut || r.truncated || r.code !== 0 || !Array.isArray(list) || list.length !== lines.length) {
    const why = r.spawnError ? `did not start: ${r.spawnError}` : r.timedOut ? 'ran too long' : r.truncated ? 'wrote too much' : `failed (exit status ${r.code}): ${String(r.stderr).slice(0, 200).replace(/\s+/g, ' ')}`;
    app.log.error(`${ctx.id}: karidns-zone idn ${why}`);
    throw new ApiError(500, 'internal');
  }
  return list;
}

// RFC 5892 appendix A.3 to A.9: the CONTEXTO rules, checked at registration (RFC 5891 4.2.3.3), not on lookup: libidn2 and dig convert such a name
const SCRIPT = (name) => new RegExp(`^\\p{Script=${name}}$`, 'u');
const GREEK = SCRIPT('Greek');
const HEBREW = SCRIPT('Hebrew');
const KANA_HAN = /^[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}]$/u;
function contextoOk(chars) {
  return chars.every((c, i) => {
    switch (c) {
      case '·': return chars[i - 1] === 'l' && chars[i + 1] === 'l';
      case '͵': return chars[i + 1] !== undefined && GREEK.test(chars[i + 1]);
      case '׳': case '״': return chars[i - 1] !== undefined && HEBREW.test(chars[i - 1]);
      case '・': return chars.some((d) => KANA_HAN.test(d));
      default:
        if (/[٠-٩]/.test(c)) return !chars.some((d) => /[۰-۹]/.test(d));
        if (/[۰-۹]/.test(c)) return !chars.some((d) => /[٠-٩]/.test(d));
        return true;
    }
  });
}

// UTS #39 section 5.2, Highly Restrictive: one script a label, or Latin with Han and Hiragana / Katakana, with Han and Hangul, or with Han and Bopomofo.  The
// scripts asked about are the common ones of names; a letter of any other script counts as one script of its own.  (A warning only: it depends on the Unicode
// data of the JavaScript engine, the stored name does not.)
const SCRIPTS = ['Latin', 'Greek', 'Cyrillic', 'Armenian', 'Georgian', 'Hebrew', 'Arabic', 'Syriac', 'Thaana', 'Devanagari', 'Bengali', 'Gurmukhi', 'Gujarati', 'Oriya',
  'Tamil', 'Telugu', 'Kannada', 'Malayalam', 'Sinhala', 'Thai', 'Lao', 'Tibetan', 'Myanmar', 'Khmer', 'Mongolian', 'Ethiopic', 'Cherokee', 'Hangul', 'Hiragana',
  'Katakana', 'Bopomofo', 'Han'].map((s) => [s, SCRIPT(s)]);
const NEUTRAL = /^[\p{Script=Common}\p{Script=Inherited}]$/u;
const ALLOWED_MIXES = [['Latin', 'Han', 'Hiragana', 'Katakana'], ['Latin', 'Han', 'Hangul'], ['Latin', 'Han', 'Bopomofo']];
function singleScript(chars) {
  const seen = new Set(chars.filter((c) => !NEUTRAL.test(c)).map((c) => SCRIPTS.find(([, re]) => re.test(c))?.[0] ?? 'other'));
  return seen.size <= 1 || ALLOWED_MIXES.some((m) => [...seen].every((s) => m.includes(s)));
}

const MESSAGES = {
  'idn-disallowed': 'has a code point that IDNA2008 does not allow (RFC 5892); dig converts the name with the transitional mapping of UTS #46, and most registries refuse such a name',
  'idn-transitional': 'is converted with the transitional mapping of UTS #46, as dig does then (ß becomes ss, ς σ; ZWJ and ZWNJ go)',
  'idn-contexto': 'has a code point whose CONTEXTO rule it does not keep (RFC 5892 appendix A); dig converts the name, registration refuses it (RFC 5891 4.2.3.3)',
  'idn-mixed-script': 'mixes scripts (UTS #39 5.2, Highly Restrictive): a look-alike of another name may hide in it',
  'idn-bad-alabel': 'has an xn-- label that is no A-label, or one whose U-label breaks a rule of IDNA2008; dig sends it as it is',
};
const warning = (code, label) => ({ code, label, message: `${JSON.stringify(label)} ${MESSAGES[code]}` });

// the warnings of one name and the tool's answer for it
function warningsOf(name, r) {
  const out = [];
  if (!NON_ASCII.test(name)) {
    if (r.error) out.push(warning('idn-bad-alabel', name));
    return out;
  }
  if (r.transitional) out.push(warning('idn-disallowed', name), warning('idn-transitional', name));
  for (const label of name.toLowerCase().split(DOTS).filter((l) => NON_ASCII.test(l))) {
    const chars = [...label];
    if (!contextoOk(chars)) out.push(warning('idn-contexto', label));
    if (!singleScript(chars)) out.push(warning('idn-mixed-script', label));
  }
  return out;
}

// names -> Map(name -> { ascii, warnings }) for the names needsIdn() takes; throws a 400 (at `pointerOf(name)`) for a name dig would not convert, or when this
// karidns-zone has no libidn2 and a name is not ASCII
export async function asciiNames(ctx, names, pointerOf) {
  const todo = [...new Set(names.filter(needsIdn))];
  const out = new Map();
  if (todo.length === 0) return out;
  const list = await runIdn(ctx, todo.map((n) => ['a', n]));
  todo.forEach((name, i) => {
    const r = list?.[i];
    if (!r) {
      if (NON_ASCII.test(name)) throw badRequest('this karidns-zone was built without libidn2: write the name with its A-labels (xn--...)', pointerOf?.(name));
      return;
    }
    if (typeof r.ascii !== 'string') {
      throw badRequest(`the name ${JSON.stringify(name.slice(0, 80))} has no A-label form that dig +idnin would send (libidn2: ${String(r.reason ?? r.error ?? 'refused').slice(0, 120)})`, pointerOf?.(name));
    }
    out.set(name, { ascii: r.ascii, warnings: warningsOf(name, r) });
  });
  return out;
}

// stored or absolute names -> Map(name -> its U-label form) for those with an xn-- label that libidn2 decodes (as dig +idnout shows them); empty without libidn2
export async function unicodeNames(ctx, names) {
  const todo = [...new Set(names.filter((n) => needsIdn(n) && !NON_ASCII.test(n)))];
  const out = new Map();
  if (todo.length === 0) return out;
  const list = await runIdn(ctx, todo.map((n) => ['u', n]));
  todo.forEach((name, i) => { if (typeof list?.[i]?.unicode === 'string') out.set(name, list[i].unicode); });
  return out;
}

// The fields of a route that hold names (routes.js): { params: [names], query: [names], body: ['name', 'rrsets.*.name', ...] } -> each value that holds
// non-ASCII code points replaced with its A-labels; ctx.idnWarnings: the warnings of all of them (each once).  The checks of the fields come later, in the handler.
export async function idnPrepass(ctx, spec) {
  const slots = [];
  // (a path or a query is only converted: an ASCII name there is not asked about, so a page of an IDN zone runs no tool)
  for (const k of spec.params ?? []) if (typeof ctx.params?.[k] === 'string' && NON_ASCII.test(ctx.params[k])) slots.push({ value: ctx.params[k], pointer: undefined, set: (v) => { ctx.params[k] = v; } });
  for (const k of spec.query ?? []) {
    const v = ctx.query?.get(k);
    if (typeof v === 'string' && NON_ASCII.test(v)) slots.push({ value: v, pointer: `?${k}`, set: (x) => { ctx.query.set(k, x); } });
  }
  const walk = (obj, parts, at) => {
    if (obj === null || typeof obj !== 'object') return;
    const [head, ...rest] = parts;
    const keys = head === '*' ? (Array.isArray(obj) ? obj.keys() : []) : [head];
    for (const key of keys) {
      if (rest.length) walk(obj[key], rest, `${at}/${key}`);
      else if (typeof obj[key] === 'string') slots.push({ value: obj[key], pointer: `${at}/${key}`, set: (v) => { obj[key] = v; } });
    }
  };
  for (const path of spec.body ?? []) walk(ctx.body, path.split('.'), '');
  const map = await asciiNames(ctx, slots.map((s) => s.value), (name) => slots.find((s) => s.value === name)?.pointer);
  const warnings = [];
  for (const s of slots) {
    const r = map.get(s.value);
    if (!r) continue;
    s.set(r.ascii);
    for (const w of r.warnings) if (!warnings.some((x) => x.code === w.code && x.label === w.label)) warnings.push(w);
  }
  ctx.idnWarnings = warnings;
}

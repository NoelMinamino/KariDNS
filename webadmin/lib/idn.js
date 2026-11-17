// Internationalized names (0.7): a name typed in Unicode becomes the A-labels the database holds, the way dig +idnin turns it into the name it sends (BIND 9.20
// with libidn2: IDNA2008 with the UTS #46 non-transitional mapping; when the first problem libidn2 finds is a code point IDNA2008 disallows, the whole name
// again with the transitional mapping; any other problem: dig sends the UTF-8 octets).  Node's url.domainToASCII does the mapping and the punycode (WHATWG URL:
// UTS #46 non-transitional, no CheckHyphens, no length check); what it leaves out or does differently is here: a label of digits last (WHATWG takes the name
// for an IPv4 address), the fallback of dig to the transitional mapping, and the checks of IDNA2008 (RFC 5891 4.2.3, RFC 5892, RFC 5893).  Those only give
// warnings (the user, 2026-11-17): a name is refused only when it has no A-label form at all.  webadmin/test/idn_dig_vectors.json holds what dig 9.20 sends.
//
// The properties of RFC 5892 come from the regular expressions of JavaScript (General_Category, Changes_When_NFKC_Casefolded, ...); Bidi_Class has none, so the
// bidi rule of RFC 5893 judges by scripts and digit ranges, an approximation.  It decides warnings and whether dig would send the name unconverted; the A-label of
// a name dig converts is the mapping's (Node's), not the approximation's.

import { domainToASCII, domainToUnicode } from 'node:url';

const DOTS = /[.。．｡]/;                   // the label separators of UTS #46 section 4 (step 2)
const ASCII = /^[\x00-\x7f]*$/;

// RFC 5892 section 2.6: the exceptions (P: PVALID, O: CONTEXTO, D: DISALLOWED)
const EXCEPTIONS = new Map([
  [0xdf, 'P'], [0x3c2, 'P'], [0x6fd, 'P'], [0x6fe, 'P'], [0xf0b, 'P'], [0x3007, 'P'],
  [0xb7, 'O'], [0x375, 'O'], [0x5f3, 'O'], [0x5f4, 'O'], [0x30fb, 'O'],
  [0x640, 'D'], [0x7fa, 'D'], [0x302e, 'D'], [0x302f, 'D'], [0x3031, 'D'], [0x3032, 'D'], [0x3033, 'D'], [0x3034, 'D'], [0x3035, 'D'], [0x303b, 'D'],
]);
for (let c = 0x660; c <= 0x669; c++) EXCEPTIONS.set(c, 'O');
for (let c = 0x6f0; c <= 0x6f9; c++) EXCEPTIONS.set(c, 'O');

const inRanges = (c, ranges) => ranges.some(([a, b]) => c >= a && c <= b);
const IGNORABLE_BLOCKS = [[0x20d0, 0x20ff], [0x1d100, 0x1d1ff], [0x1d200, 0x1d24f]];                                   // RFC 5892 2.4 (D)
const OLD_HANGUL_JAMO = [[0x1100, 0x115f], [0xa960, 0xa97c], [0x1160, 0x11a7], [0xd7b0, 0xd7c6], [0x11a8, 0x11ff], [0xd7cb, 0xd7fb]];  // 2.9 (I): L, V, T
const CHEROKEE_SMALL = [[0x13f8, 0x13fd], [0xab70, 0xabbf]];   // their case folding is the capital letter: Unstable (B)
const UNASSIGNED = /^\p{Cn}$/u;
const NONCHARACTER = /^\p{Noncharacter_Code_Point}$/u;
const UNSTABLE = /^\p{Changes_When_NFKC_Casefolded}$/u;
const IGNORABLE = /^[\p{Default_Ignorable_Code_Point}\p{White_Space}\p{Noncharacter_Code_Point}]$/u;
const LETTER_DIGIT = /^[\p{Ll}\p{Lu}\p{Lo}\p{Nd}\p{Lm}\p{Mn}\p{Mc}]$/u;

// RFC 5892 section 3: the derived property of one code point -> 'PVALID' | 'CONTEXTJ' | 'CONTEXTO' | 'DISALLOWED' | 'UNASSIGNED'
export function idnaProperty(cp) {
  const e = EXCEPTIONS.get(cp);
  if (e) return e === 'P' ? 'PVALID' : e === 'O' ? 'CONTEXTO' : 'DISALLOWED';
  const s = String.fromCodePoint(cp);
  if (UNASSIGNED.test(s) && !NONCHARACTER.test(s)) return 'UNASSIGNED';
  if (/^[a-z0-9-]$/.test(s)) return 'PVALID';
  if (cp === 0x200c || cp === 0x200d) return 'CONTEXTJ';
  if (UNSTABLE.test(s) || inRanges(cp, CHEROKEE_SMALL) || IGNORABLE.test(s) || inRanges(cp, IGNORABLE_BLOCKS) || inRanges(cp, OLD_HANGUL_JAMO)) return 'DISALLOWED';
  return LETTER_DIGIT.test(s) ? 'PVALID' : 'DISALLOWED';
}

// RFC 5893 section 1.4: the Bidi_Class of a code point, as far as the rule needs it (an approximation by script: see the head of the file)
const RTL_SCRIPTS = ['Hebrew', 'Arabic', 'Syriac', 'Thaana', 'Nko', 'Samaritan', 'Mandaic', 'Adlam', 'Hanifi_Rohingya', 'Mende_Kikakui', 'Yezidi', 'Imperial_Aramaic',
  'Phoenician', 'Kharoshthi', 'Old_South_Arabian', 'Old_North_Arabian', 'Avestan', 'Inscriptional_Parthian', 'Inscriptional_Pahlavi', 'Psalter_Pahlavi', 'Old_Turkic',
  'Old_Hungarian', 'Manichaean', 'Nabataean', 'Palmyrene', 'Hatran', 'Lydian', 'Meroitic_Cursive', 'Meroitic_Hieroglyphs', 'Cypriot', 'Old_Sogdian', 'Sogdian', 'Elymaic',
  'Chorasmian', 'Old_Uyghur'];
const RTL = new RegExp(`^[${RTL_SCRIPTS.map((s) => `\\p{Script=${s}}`).join('')}]$`, 'u');
const AN = [[0x600, 0x605], [0x660, 0x669], [0x66b, 0x66c], [0x6dd, 0x6dd], [0x890, 0x891], [0x8e2, 0x8e2], [0x10d30, 0x10d39], [0x10e60, 0x10e7e]];
const EN = [[0x30, 0x39], [0x6f0, 0x6f9]];
const NSM = /^[\p{Mn}\p{Me}]$/u;
function bidiClass(cp) {
  if (inRanges(cp, AN)) return 'AN';
  if (inRanges(cp, EN)) return 'EN';
  const s = String.fromCodePoint(cp);
  if (NSM.test(s)) return 'NSM';
  if (cp === 0x2d) return 'ES';
  if (RTL.test(s)) return 'R';
  if (/^[\p{S}\p{P}]$/u.test(s)) return 'ON';
  return 'L';
}

// RFC 5893 section 2, for a label that has a right-to-left character (R, AL, AN): true when the label keeps the rule
function bidiOk(cps) {
  const cls = cps.map(bidiClass);
  if (!cls.some((c) => c === 'R' || c === 'AN')) return true;
  const last = [...cls].reverse().find((c) => c !== 'NSM');
  if (cls[0] === 'R') {                                                            // rules 2, 3, 4
    return cls.every((c) => c !== 'L') && ['R', 'EN', 'AN'].includes(last) && !(cls.includes('EN') && cls.includes('AN'));
  }
  return false;                                                                    // rule 1: a label with AN must start with L, R or AL; L then AN breaks rule 5
}

// RFC 5892 appendix A.3 to A.9: the CONTEXTO rules (checked at registration, RFC 5891 4.2.3.3; libidn2 does not check them on lookup, nor does dig)
const script = (cp, name) => SCRIPT_OF.get(name).test(String.fromCodePoint(cp));
function contextoOk(cps) {
  return cps.every((c, i) => {
    switch (c) {
      case 0xb7: return cps[i - 1] === 0x6c && cps[i + 1] === 0x6c;
      case 0x375: return cps[i + 1] !== undefined && script(cps[i + 1], 'Greek');
      case 0x5f3: case 0x5f4: return cps[i - 1] !== undefined && script(cps[i - 1], 'Hebrew');
      case 0x30fb: return cps.some((d) => script(d, 'Hiragana') || script(d, 'Katakana') || script(d, 'Han'));
      default:
        if (c >= 0x660 && c <= 0x669) return !cps.some((d) => d >= 0x6f0 && d <= 0x6f9);
        if (c >= 0x6f0 && c <= 0x6f9) return !cps.some((d) => d >= 0x660 && d <= 0x669);
        return true;
    }
  });
}

// UTS #39 section 5.2, Highly Restrictive: one script a label, or Latin with Han and Hiragana/Katakana, with Han and Hangul, or with Han and Bopomofo.  The scripts
// asked about are the common ones of names; a letter of any other script counts as one script of its own ("other").
const SCRIPTS = ['Latin', 'Greek', 'Cyrillic', 'Armenian', 'Georgian', 'Hebrew', 'Arabic', 'Syriac', 'Thaana', 'Devanagari', 'Bengali', 'Gurmukhi', 'Gujarati', 'Oriya',
  'Tamil', 'Telugu', 'Kannada', 'Malayalam', 'Sinhala', 'Thai', 'Lao', 'Tibetan', 'Myanmar', 'Khmer', 'Mongolian', 'Ethiopic', 'Cherokee', 'Hangul', 'Hiragana',
  'Katakana', 'Bopomofo', 'Han'];
const SCRIPT_RE = SCRIPTS.map((s) => [s, new RegExp(`^\\p{Script=${s}}$`, 'u')]);
const SCRIPT_OF = new Map(SCRIPT_RE);
const NEUTRAL = /^[\p{Script=Common}\p{Script=Inherited}]$/u;
const ALLOWED_MIXES = [['Latin', 'Han', 'Hiragana', 'Katakana'], ['Latin', 'Han', 'Hangul'], ['Latin', 'Han', 'Bopomofo']];
function singleScript(cps) {
  const seen = new Set();
  for (const c of cps) {
    const s = String.fromCodePoint(c);
    if (NEUTRAL.test(s)) continue;
    seen.add(SCRIPT_RE.find(([, re]) => re.test(s))?.[0] ?? 'other');
  }
  return seen.size <= 1 || ALLOWED_MIXES.some((m) => [...seen].every((s) => m.includes(s)));
}

const MESSAGES = {
  'idn-disallowed': 'has a code point that IDNA2008 does not allow (RFC 5892); dig converts the name with the transitional mapping of UTS #46, and most registries refuse such a label',
  'idn-unassigned': 'has a code point that this version of Unicode does not assign (RFC 5892); dig does not convert the name',
  'idn-hyphen': "starts or ends with '-' or has '--' in its third and fourth place (RFC 5891 4.2.3.1); dig does not convert the name",
  'idn-bidi': 'does not keep the bidi rule (RFC 5893); dig does not convert the name',
  'idn-bad-alabel': 'is an xn-- label that is no A-label (it does not decode, or not back to itself); dig sends it as it is',
  'idn-contexto': 'has a code point whose CONTEXTO rule it does not keep (RFC 5892 appendix A); dig converts the name, registration refuses it (RFC 5891 4.2.3.3)',
  'idn-mixed-script': 'mixes scripts (UTS #39 5.2, Highly Restrictive): a look-alike of another name may hide in it',
  'idn-transitional': 'is converted with the transitional mapping of UTS #46, as dig does when a label has a code point IDNA2008 does not allow (ß becomes ss, ς σ; ZWJ and ZWNJ go)',
  'idn-not-dig': 'is not converted by dig +idnin (it sends the UTF-8 octets): the name is stored with the A-labels of the UTS #46 mapping',
};
const warning = (code, label) => ({ code, label, message: `the label ${JSON.stringify(label)} ${MESSAGES[code]}` });

// A-label -> its U-label, or null: not an xn-- label, or one that does not decode back to itself (such a label is shown as it is, like dig +idnout)
function decode(label) {
  if (!/^xn--/i.test(label)) return null;
  const u = domainToUnicode(`${label}.x`);
  if (!u.endsWith('.x')) return null;
  const out = u.slice(0, -2);
  return out !== '' && !out.includes('.') && domainToASCII(`${out}.x`) === `${label.toLowerCase()}.x` ? out : null;
}

// a label with non-ASCII code points -> its ASCII form (an A-label, or plain: 'ⅷ' -> 'viii'), or null: UTS #46 refuses it, or it maps to more than one label.
// The '.x' keeps a label of digits from being the last of the name (WHATWG would read the name as an IPv4 address).
function mapLabel(label) {
  const a = domainToASCII(`${label}.x`);
  if (!a.endsWith('.x')) return null;
  const out = a.slice(0, -2);
  return out === '' || out.includes('.') ? null : out;
}

// UTS #46 section 4.1: the deviation characters the transitional mapping maps differently (ẞ maps to ß first)
const transitional = (label) => label.replace(/[ßẞ]/g, 'ss').replace(/ς/g, 'σ').replace(/[‌‍]/g, '');

// RFC 5891 4.2.3.1: '-' first or last, or '--' in the third and fourth place (an A-label has them: it is not asked)
const hyphenProblem = (l) => (l[2] === '-' && l[3] === '-') || l.startsWith('-') || l.endsWith('-');

// The labels of a name in one mapping -> { labels (ASCII), problems: [{ code, label, lib }] in the order libidn2 meets them (lib: libidn2 reports it; code null:
// no warning of its own, the name is refused later or dig only sends it unconverted) } or null: a label has no ASCII form.  An ASCII label stays as it is; in a
// name with non-ASCII code points libidn2 still holds it to the hyphen rule and to letters, digits, '-', '_' and '*' (pc200: 'a-', '-a', 'ab--c', 'a b'); an
// xn-- label is judged by what it decodes to.
function convert(labels, trans, unicode) {
  const out = [];
  const problems = [];
  for (const label of labels) {
    let ascii = label;
    let u = null;
    if (!ASCII.test(label)) {
      ascii = mapLabel(trans ? transitional(label) : label);
      if (ascii === null) return null;
      u = decode(ascii);
      if (ascii.length > 63) problems.push({ code: null, label, lib: true });
    } else if (/^xn--/i.test(label)) {
      u = decode(label);
      if (u === null) problems.push({ code: 'idn-bad-alabel', label, lib: true });
    } else if (unicode) {
      if (hyphenProblem(label)) problems.push({ code: 'idn-hyphen', label, lib: true });
      if (!/^[A-Za-z0-9_*-]*$/.test(label)) problems.push({ code: null, label, lib: true });
    }
    out.push(ascii);
    if (u === null) continue;
    const cps = [...u].map((c) => c.codePointAt(0));
    const props = cps.map(idnaProperty);
    if (hyphenProblem(u)) problems.push({ code: 'idn-hyphen', label: u, lib: true });
    if (/[\0-,./:-@[-`{-\x7f]/.test(u)) problems.push({ code: null, label: u, lib: true });   // ASCII other than letters, digits and '-' ('㈱' -> '(株)')
    if (props.includes('DISALLOWED')) problems.push({ code: 'idn-disallowed', label: u, lib: true });
    if (props.includes('UNASSIGNED')) problems.push({ code: 'idn-unassigned', label: u, lib: true });
    if (!bidiOk(cps)) problems.push({ code: 'idn-bidi', label: u, lib: true });
    if (!contextoOk(cps)) problems.push({ code: 'idn-contexto', label: u, lib: false });
    if (!singleScript(cps)) problems.push({ code: 'idn-mixed-script', label: u, lib: false });
  }
  return { labels: out, problems };
}

// what libidn2 still checks in the transitional mapping (pc200, libidn2 2.3.8: the hyphens and the A-labels; not the disallowed code points nor the bidi rule)
const TRANSITIONAL_CHECKS = new Set(['idn-hyphen', 'idn-bad-alabel', 'idn-unassigned']);

// A name as typed (Unicode or not, a final dot or not) -> { name: its ASCII form (the final dot kept, ASCII labels as typed), warnings: [{ code, label, message }],
// dig: true when dig +idnin sends this name (the same octets, up to the case of ASCII letters) }.  Throws an Error when the name has no ASCII form.
export function toAscii(text) {
  if (typeof text !== 'string') throw new Error('name is not a string');
  const labels = text.split(DOTS);
  const unicode = !ASCII.test(text);
  const nt = convert(labels, false, unicode);
  const tr = unicode ? convert(labels, true, true) : null;
  const first = nt?.problems.find((p) => p.lib);
  let r = nt;
  let dig = !unicode || (nt !== null && first === undefined);
  const extra = [];
  if (unicode && first?.code === 'idn-disallowed' && tr && !tr.problems.some((p) => p.lib && (p.code === null || TRANSITIONAL_CHECKS.has(p.code)))) {
    r = tr;
    dig = true;
    if (nt === null || tr.labels.join('.') !== nt.labels.join('.')) extra.push(warning('idn-transitional', text));
  }
  if (r === null) throw new Error(`name ${JSON.stringify(text.slice(0, 80))} has no A-label form (UTS #46 refuses a label of it)`);
  const warnings = [...new Map(r.problems.filter((p) => p.code !== null).map((p) => [`${p.code} ${p.label}`, warning(p.code, p.label)])).values(), ...extra];
  if (unicode && !dig) warnings.push(warning('idn-not-dig', text));
  return { name: r.labels.join('.'), warnings, dig };
}

// toAscii(text).name, its warnings pushed onto `into` (an array) when one is given
export function asciiName(text, into) {
  const r = toAscii(text);
  if (into) into.push(...r.warnings.filter((w) => !into.some((x) => x.code === w.code && x.label === w.label)));
  return r.name;
}

// An ASCII name (as stored, or absolute) -> the same with each A-label that decodes back to itself in its U-label form; undefined when nothing changes
export function toUnicode(name) {
  if (typeof name !== 'string' || !/(^|\.)xn--/i.test(name)) return undefined;
  const out = name.split('.').map((l) => decode(l) ?? l).join('.');
  return out === name ? undefined : out;
}

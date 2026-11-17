// A scripted `karidns-zone idn --json` for the tests (the real one is compared with dig by tests/run_karidns_zone_idn_test.sh): answers from a table of what
// libidn2 gives for these names (taken from the real tool on the build host), the shape of docs/karidns-zone.md "idn".

const A = {
  '例え.test': 'xn--r8jz45g.test',
  '例え.test.': 'xn--r8jz45g.test.',
  '例え': 'xn--r8jz45g',
  'ＷＷＷ.例え.test': 'www.xn--r8jz45g.test',
  'ＷＷＷ.例え.test.': 'www.xn--r8jz45g.test.',
  'ウェブ': 'xn--gckc5l',
  'ウェブ.example.test': 'xn--gckc5l.example.test',
  'メール': 'xn--4dkua4c',
  'a・b.test': 'xn--ab-3n4a.test',
  'аpple.example.test': 'xn--pple-43d.example.test',
  'www.例え.test': 'www.xn--r8jz45g.test',
  'sub.例え.test': 'sub.xn--r8jz45g.test',
};
const TRANSITIONAL = { '☃.EXAMPLE.test.': 'xn--n3h.example.test.', 'ß☃.test': 'xn--ss-gsx.test', '☃': 'xn--n3h' };
const U = { 'xn--r8jz45g.test.': '例え.test.', 'xn--r8jz45g.test': '例え.test', 'www.xn--r8jz45g.test.': 'www.例え.test.', 'www.xn--r8jz45g.test': 'www.例え.test',
  'xn--gckc5l.xn--r8jz45g.test.': 'ウェブ.例え.test.', 'xn--ss-gsx.test.': 'ß☃.test.' };
const BAD_ALABEL = new Set(['xn--zz.test', 'xn--zz.example.test']);

// one answer for one line
function answer(kind, name) {
  if (kind === 'u') return { unicode: U[name] ?? null };
  if (!/[^\x00-\x7f]/.test(name)) {
    return BAD_ALABEL.has(name) ? { ascii: name, transitional: false, error: 'IDN2_PUNYCODE_BAD_INPUT', reason: 'punycode bad input' } : { ascii: name, transitional: false, error: null, reason: null };
  }
  if (A[name]) return { ascii: A[name], transitional: false, error: null, reason: null };
  if (TRANSITIONAL[name]) return { ascii: TRANSITIONAL[name], transitional: true, error: null, reason: null };
  return { ascii: null, transitional: false, error: 'IDN2_BIDI', reason: 'string has forbidden bi-directional properties' };
}

// a run of the tool (the shape of runChild's result) for the input of `karidns-zone idn --json`; `unavailable`: a build without libidn2
export function idnRun(input, { unavailable = false } = {}) {
  if (unavailable) {
    return { code: 1, signal: null, stdout: JSON.stringify({ 'karidns-zone': '0.7', messages: [{ code: 'db.idn.unavailable', severity: 'error', text: 'no libidn2' }] }), stderr: '', truncated: false, timedOut: false, spawnError: null };
  }
  const idn = String(input).split('\n').filter(Boolean).map((l) => answer(l[0], l.slice(2)));
  return { code: 0, signal: null, stdout: JSON.stringify({ 'karidns-zone': '0.7', idn, messages: [] }), stderr: '', truncated: false, timedOut: false, spawnError: null };
}

export const isIdnCall = (c) => c.argv?.[0] === 'idn' && c.argv?.[1] === '--json';

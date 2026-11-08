// Hand-written validators for the fixed request shapes (planning 8.1; one dependency only, so no schema library).  A spec says what each field of an
// object may be; unknown fields are refused, so a typo is not silently ignored.  A mistake is a 400 with a JSON pointer to the field.

import { ApiError } from './errors.js';

const fail = (pointer, text) => new ApiError(400, 'bad-request', `${pointer || '/'}: ${text}`, { errors: [{ code: 'bad-request', severity: 'error', text, pointer }] });

const CTRL = /[\0-\x1f\x7f]/;

// spec: { field: { type: 'string'|'int'|'bool'|'array'|'object', required, nullable, min, max, re, values, items (a spec of one element), noControl (default true) } }
// -> a new plain object with the fields that were given (a missing optional field is left out)
export function shape(input, spec, pointer = '') {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw fail(pointer, 'an object is expected');
  for (const k of Object.keys(input)) {
    if (!Object.hasOwn(spec, k)) throw fail(`${pointer}/${k}`, 'this field is not known');
  }
  const out = {};
  for (const [k, s] of Object.entries(spec)) {
    const p = `${pointer}/${k}`;
    if (!Object.hasOwn(input, k) || input[k] === undefined) {
      if (s.required) throw fail(p, 'this field is required');
      continue;
    }
    const v = input[k];
    if (v === null) {
      if (!s.nullable) throw fail(p, 'null is not allowed');
      out[k] = null;
      continue;
    }
    out[k] = value(v, s, p);
  }
  return out;
}

export function value(v, s, p) {
  switch (s.type) {
    case 'string': {
      if (typeof v !== 'string') throw fail(p, 'a string is expected');
      if (s.noControl !== false && CTRL.test(v)) throw fail(p, 'control characters are not allowed');
      const len = Buffer.byteLength(v, 'utf8');
      if (len < (s.min ?? 0) || len > (s.max ?? 1024)) throw fail(p, `the length must be ${s.min ?? 0} to ${s.max ?? 1024} octets`);
      if (s.re && !s.re.test(v)) throw fail(p, s.reText ?? 'the value has a form that is not allowed');
      if (s.values && !s.values.includes(v)) throw fail(p, `one of ${s.values.join(', ')} is expected`);
      return v;
    }
    case 'int':
      if (!Number.isSafeInteger(v)) throw fail(p, 'an integer is expected');
      if (v < (s.min ?? 0) || v > (s.max ?? 2147483647)) throw fail(p, `the value must be ${s.min ?? 0} to ${s.max ?? 2147483647}`);
      return v;
    case 'bool':
      if (typeof v !== 'boolean') throw fail(p, 'true or false is expected');
      return v;
    case 'array': {
      if (!Array.isArray(v)) throw fail(p, 'an array is expected');
      if (v.length < (s.min ?? 0) || v.length > (s.max ?? 1000)) throw fail(p, `the array must have ${s.min ?? 0} to ${s.max ?? 1000} elements`);
      return v.map((x, i) => value(x, s.items, `${p}/${i}`));
    }
    default:
      throw new Error(`validate: unknown type ${s.type}`);
  }
}

// a query string -> an object of the parameters that are allowed (spec as above, but the values are strings that are converted: int, bool)
export function query(params, spec) {
  const out = {};
  for (const k of params.keys()) {
    if (!Object.hasOwn(spec, k)) throw fail(`?${k}`, 'this parameter is not known');
    if (params.getAll(k).length > 1) throw fail(`?${k}`, 'this parameter is given more than once');
  }
  for (const [k, s] of Object.entries(spec)) {
    if (!params.has(k)) {
      if (s.required) throw fail(`?${k}`, 'this parameter is required');
      continue;
    }
    const raw = params.get(k);
    if (s.type === 'int') {
      if (!/^\d{1,10}$/.test(raw)) throw fail(`?${k}`, 'an integer is expected');
      out[k] = value(Number(raw), s, `?${k}`);
    } else if (s.type === 'bool') {
      if (raw !== 'true' && raw !== 'false') throw fail(`?${k}`, 'true or false is expected');
      out[k] = raw === 'true';
    } else {
      out[k] = value(raw, s, `?${k}`);
    }
  }
  return out;
}

// the opaque cursor of a list: base64url JSON of whatever the list needs to continue (an id, a name, a pair).  An invalid cursor is a 400.
export const encodeCursor = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
export function decodeCursor(text, check) {
  let obj;
  try {
    obj = JSON.parse(Buffer.from(text, 'base64url').toString('utf8'));
  } catch {
    throw fail('?cursor', 'the cursor is not valid');
  }
  let ok = false;
  try { ok = check(obj); } catch { /* a cursor of another shape */ }
  if (!ok) throw fail('?cursor', 'the cursor is not valid');
  return obj;
}

export const LIMIT = { type: 'int', min: 1, max: 500 };
export const CURSOR = { type: 'string', min: 1, max: 512, re: /^[A-Za-z0-9_-]+$/ };

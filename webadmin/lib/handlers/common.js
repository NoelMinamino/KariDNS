// What several handlers need: route-level checks, path parameters, pages.

import { ApiError, badRequest, forbidden, notFound } from '../errors.js';
import { isGlobal } from '../perm.js';
import { canonicalZone } from '../names.js';
import { encodeCursor, decodeCursor } from '../validate.js';

export function requireGlobal(ctx) {
  if (!isGlobal(ctx.auth.grants)) throw forbidden('only a global master may do this');
}

export function dataset(ctx) {
  const d = ctx.app.dataset(ctx.params.ds);
  if (!d) throw notFound('no such dataset');
  return d;
}

// the zone of the path, canonical (no final dot); a name that is no plain LDH name is a 400
export function zoneParam(ctx) {
  try {
    return canonicalZone(ctx.params.zone);
  } catch (e) {
    throw badRequest(e.message);
  }
}

// a numeric id of the path; anything else cannot be an object of ours: 404
export function idParam(ctx, name = 'id') {
  const v = ctx.params[name];
  if (!/^\d{1,15}$/.test(v)) throw notFound('no such object');
  return Number(v);
}

export const idCursor = (text) => (text === undefined ? 0 : decodeCursor(text, (o) => Number.isSafeInteger(o?.i) && o.i >= 0).i);

// rows fetched with limit + 1 -> { items, next_cursor }
export function page(rows, limit, key) {
  const more = rows.length > limit;
  const items = rows.slice(0, limit);
  return { items, next_cursor: more ? encodeCursor(key(items[items.length - 1])) : null };
}

export const clean = (s) => String(s).replace(/[\0-\x1f\x7f]+/g, ' ').slice(0, 80);

export { ApiError };

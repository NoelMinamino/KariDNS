// diffmodel.js: the diff of a change set as the service gives it (a dry run, a commit, an import, a new zone) made ready for the screen (planning 3 S5 / S7, F-21).  The
// service answers with the whole diff; the page shows it in pages of 200 RRsets.  Pure functions.

export const DIFF_PAGE = 200;

// { add, replace, delete } counts of a diff ([{ name, type, change, before, after }])
export function diffCounts(diff) {
  const c = { add: 0, replace: 0, delete: 0 };
  for (const e of diff) if (e.change in c) c[e.change]++;
  return c;
}

// page number `page` (from 0, clamped) of `size` RRsets -> { items, page, pages, from, to, total }; from and to count from 1, as a person reads "1-200 of 350"
export function diffPage(diff, page, size = DIFF_PAGE) {
  const total = diff.length;
  const pages = Math.max(1, Math.ceil(total / size));
  const p = Math.min(Math.max(0, page), pages - 1);
  const items = diff.slice(p * size, (p + 1) * size);
  return { items, page: p, pages, from: total === 0 ? 0 : p * size + 1, to: p * size + items.length, total };
}

// "300 192.0.2.1" for a record of a diff
export const lineText = (rec) => `${rec.ttl ?? '?'} ${rec.content}`;

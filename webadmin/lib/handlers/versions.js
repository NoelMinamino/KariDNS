// The history of a zone (planning 6): the versions, one version's delta, the diff between two versions (or one version and now), and the rollback to a version
// as a change set of its own.  The versions are written by karidns-zone in the transaction of each change; this file only reads them, and the rollback goes
// through the same pipeline as every other change set (pipeline.js), so it is validated, checked against the grants, versioned and, on request, reloaded.

import { badRequest, conflict, notFound } from '../errors.js';
import { shape, query, LIMIT, CURSOR, decodeCursor } from '../validate.js';
import * as S from '../store.js';
import { rrVisible } from '../perm.js';
import { renderChangeFile, renderExpectations, parseLine } from '../changes.js';
import { runChange, checkDiff } from '../pipeline.js';
import { fold, diffEntries, showEntry, rollbackRRsets, outsideChanges, MAX_FOLD_ROWS } from '../versions.js';
import { dataset, zoneParam, zoneGrants, idParam, page } from './common.js';
import { loadFacts, editable, wantReload } from './write.js';

const EDIT_MS = 120000;
const VERSION_CURSOR = (o) => Number.isSafeInteger(o?.v) && o.v >= 1;
const RR_CURSOR = (o) => typeof o?.n === 'string' && typeof o?.t === 'string' && o.n.length <= 255 && o.t.length <= 32;

// what the principal sees of the history: everything of the zone for the masters of the whole zone; for a subdomain master the names under its suffixes (and the apex
// SOA and NS), as in the RRsets it reads.  null = everything.
const visibilityOf = (gs) => (gs.some((g) => g.role !== 'subdomain_master') ? null : { suffixes: [...new Set(gs.map((g) => g.name_suffix))] });

const principalOf = (v) => (v.principal_id === null && v.principal === null ? null : { id: v.principal_id, name: v.principal });
const view = (v) => ({
  version: v.version, kind: v.kind, at: v.at, principal: principalOf(v), db_role: v.db_role, change_set: v.change_set, comment: v.comment,
  serial: { before: v.serial_before, after: v.serial_after }, generation: { before: v.generation_before, after: v.generation_after }, rollback_of: v.rollback_of,
  delta_complete: v.delta_complete, ...(v.rrsets === undefined ? {} : { rrsets: v.rrsets }),
});

// An unexplained change of the zone between two versions (planning 6.2): the generation grew in between although no version says why.  The audit log tells what it
// was; a change of nothing but DNSSEC records and the SOA serial (the signer re-signing) is no change of the RRsets.  -> null (none), or { basis: 'audit', count,
// rrsets } / { basis: 'generation' } (the audit log has no row of the zone in the window, so it cannot tell)
async function outsideMarker(tx, ds, facts, prev, next, exclude) {
  const a = await S.auditRecordChanges(tx, ds.schema, facts.name, {
    since: prev.id, sinceIncl: prev.change_set !== null, until: next?.id, untilIncl: next !== undefined && next.change_set !== null, exclude,
  });
  const found = outsideChanges(a.rows);
  if (found.count > 0) return { basis: 'audit', count: found.count, rrsets: found.rrsets };
  return a.any ? null : { basis: 'generation', count: null, rrsets: [] };
}

// GET .../versions?limit=&cursor=: newest first.  `changed_outside_before` on a version: the zone was changed by something other than a version between the version
// before it and this one; `changed_outside_since` (first page): since the newest version.  Only for the masters of the whole zone (a subdomain master cannot read the
// audit log, and sees only part of each delta).
export async function list(ctx) {
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  const q = query(ctx.query, { limit: LIMIT, cursor: CURSOR });
  const limit = q.limit ?? 100;
  const before = q.cursor === undefined ? undefined : decodeCursor(q.cursor, VERSION_CURSOR).v;
  const visibility = visibilityOf(gs);
  const r = await ctx.db(async (tx) => {
    const facts = await S.zoneFacts(tx, ds.schema, zone);
    if (!facts) return null;
    const rows = await S.listVersions(tx, ds.schema, facts.id, { before, limit, zone, visibility });
    const out = { facts, rows, marks: new Map(), tail: null };
    if (visibility === null && rows.length > 0) {
      const exclude = await S.versionChangeSets(tx, ds.schema, facts.id);
      for (let i = 0; i < Math.min(rows.length - 1, limit); i++) {
        if (rows[i].generation_before > rows[i + 1].generation_after) out.marks.set(rows[i].version, await outsideMarker(tx, ds, facts, rows[i + 1], rows[i], exclude));
      }
      if (before === undefined && (await S.zoneGeneration(tx, ds.schema, facts.id)) > rows[0].generation_after) out.tail = await outsideMarker(tx, ds, facts, rows[0], undefined, exclude);
    }
    return out;
  });
  if (r === null) throw notFound('no such zone');
  const p = page(r.rows, limit, (v) => ({ v: v.version }));
  const versions = p.items.map((v) => ({ ...view(v), ...(visibility === null ? { changed_outside_before: r.marks.get(v.version) ?? null } : {}) }));
  return { versions, ...(visibility === null && before === undefined ? { changed_outside_since: r.tail } : {}), next_cursor: p.next_cursor };
}

// GET .../versions/{n}: the version and its delta, `limit` RRsets a page, in (name, type) order
export async function get(ctx) {
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  const n = idParam(ctx, 'n');
  const q = query(ctx.query, { limit: LIMIT, cursor: CURSOR });
  const limit = q.limit ?? 100;
  const cur = q.cursor === undefined ? undefined : decodeCursor(q.cursor, RR_CURSOR);
  const visibility = visibilityOf(gs);
  const r = await ctx.db(async (tx) => {
    const id = await S.zoneId(tx, ds.schema, zone);
    if (id === undefined) return null;
    const v = await S.getVersion(tx, ds.schema, id, n, { zone, visibility });
    if (!v) return { none: true };
    return { v, rows: await S.versionRRsets(tx, ds.schema, v.id, { zone, visibility, after: cur && { name: cur.n, type: cur.t }, limit }) };
  });
  if (r === null) throw notFound('no such zone');
  if (r.none) throw notFound('no such version (it may have been pruned: a zone keeps its newest 100)');
  const p = page(r.rows, limit, (x) => ({ n: x.owner, t: x.type }));
  const rrsets = p.items.filter((x) => rrVisible(gs, { schema: ds.schema, zone, name: x.owner, type: x.type })).map((x) => showEntry(x.owner, x.type, x.before, x.after));
  return { version: view(r.v), rrsets, next_cursor: p.next_cursor };
}

// The versions after `from` (up to `to`, when given) folded to the RRsets they touched, as far as the principal sees them.  Refused when a version in the range was too
// big to keep its RRsets (a delta that is not complete cannot be crossed) or when the range holds more RRsets than a fold reads.
async function foldRange(ctx, ds, zone, gs, facts, from, to) {
  const visibility = visibilityOf(gs);
  const r = await ctx.db(async (tx) => {
    const base = await S.getVersion(tx, ds.schema, facts.id, from, { zone, visibility });
    if (!base) throw notFound('no such version (it may have been pruned: a zone keeps its newest 100)');
    if (to !== undefined && !(await S.getVersion(tx, ds.schema, facts.id, to, { zone, visibility }))) throw notFound('no such version');
    if ((await S.versionRowCount(tx, ds.schema, facts.id, from, to, { zone, visibility })) > MAX_FOLD_ROWS) {
      throw conflict(`the versions after ${from} touched more than ${MAX_FOLD_ROWS} RRsets: ask for a shorter range`, 'too-large');
    }
    return S.versionsBetween(tx, ds.schema, facts.id, from, to, { zone, visibility });
  });
  const incomplete = r.headers.find((h) => !h.delta_complete);
  if (incomplete) throw conflict(`version ${incomplete.version} changed too many RRsets to keep them (delta_complete is false): the history cannot be followed across it`, 'delta-incomplete');
  const rows = r.rows.filter((x) => rrVisible(gs, { schema: ds.schema, zone, name: x.owner, type: x.type }));
  return { entries: fold(rows), versions: r.headers.length };
}

// GET .../versions/{a}/diff?to={b}|current: what changed between version a (the zone as it was after it) and version b, or the zone as it is now.  For every RRset
// the versions after a touched: its records at the first end and at the second; the RRsets that are the same at both are not listed.  `to=current` asks the zone
// (a check run of karidns-zone), so it also shows what was changed outside the versions.
export async function diff(ctx) {
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  const a = idParam(ctx, 'n');
  const q = query(ctx.query, { to: { type: 'string', min: 1, max: 9, re: /^(?:[0-9]{1,9}|current)$/, reText: 'a version number or current' }, limit: LIMIT, cursor: CURSOR });
  const limit = q.limit ?? 100;
  const to = q.to === undefined || q.to === 'current' ? 'current' : Number(q.to);
  if (to !== 'current' && to <= a) throw badRequest('to must be a later version than the one in the path', '?to');
  const cur = q.cursor === undefined ? undefined : decodeCursor(q.cursor, RR_CURSOR);
  const facts = await loadFacts(ctx, ds, zone);
  const { entries } = await foldRange(ctx, ds, zone, gs, facts, a, to === 'current' ? undefined : to);
  let out;
  if (to !== 'current') {
    out = diffEntries(entries);
  } else {
    // the state at a of every RRset touched since, written as a change: the check run says what that would change in the zone as it is; seen from a, the zone is
    // the "after" of the difference and the state at a its "before"
    const plan = rollbackRRsets(entries.filter((e) => !(e.type === 'SOA' && e.owner === zone)), zone, { force: true });
    out = [];
    if (plan.rrsets.length > 0) {
      const maps = renderChangeFile(plan.rrsets, () => ({}));
      for (const e of await checkDiff(ctx, { ds, zone, maps, timeoutMs: EDIT_MS })) {
        const owner = e.owner.replace(/\.$/, '').toLowerCase();
        if (rrVisible(gs, { schema: ds.schema, zone, name: owner, type: e.type })) out.push({ owner, type: e.type, before: e.after === null ? null : e.after.join('\n'), after: e.before === null ? null : e.before.join('\n') });
      }
    }
  }
  out.sort((x, y) => (x.owner < y.owner ? -1 : x.owner > y.owner ? 1 : x.type < y.type ? -1 : x.type > y.type ? 1 : 0));
  const rest = cur ? out.filter((x) => x.owner > cur.n || (x.owner === cur.n && x.type > cur.t)) : out;
  const p = page(rest.slice(0, limit + 1), limit, (x) => ({ n: x.owner, t: x.type }));
  return { from: a, to, rrsets: p.items.map((x) => showEntry(x.owner, x.type, x.before, x.after)), next_cursor: p.next_cursor };
}

// the conflict of a rollback (planning 6.4 step 2): an RRset that is not as the newest version of it left it - something else changed it, so restoring it would
// undo that too.  e: the entry of the check run (before = the RRset now); rr: the RRset of the plan (expect = how the version left it)
const CONFLICT = {
  code: 'version-conflict',
  detail: 'RRsets were changed after the versions that would be undone, by something other than a version: nothing was written (force: true restores them anyway)',
  error: (e, rr) => ({
    code: 'version-conflict', severity: 'error', text: `${e.type} ${e.owner} is not as the newest version left it`, name: e.owner, type: e.type,
    expected: rr.expect, current: e.before === null ? null : e.before.map(parseLine),
  }),
};

// POST .../versions/{n}/rollback {comment?, dry_run?, force?, reload?}: a change set that restores every RRset the versions after n touched to its state at n.  A
// new version of kind `rollback` (rollback_of n), the serial raised, validated and checked against the grants like any change set: the caller needs one grant that allows
// every RRset restored.  An RRset that was changed after the newest version that touched it is a conflict (409; the dry run lists them in `conflicts`), unless `force`.
export async function rollback(ctx) {
  const { app } = ctx;
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  const n = idParam(ctx, 'n');
  const body = shape(ctx.body, { comment: { type: 'string', max: 900 }, dry_run: { type: 'bool' }, force: { type: 'bool' }, reload: { type: 'bool' } });
  const facts = await loadFacts(ctx, ds, zone);
  editable(facts);
  const want = wantReload(app, body.reload);
  let info = { restored: 0, versions_undone: 0, skipped: [] };
  const build = async () => {
    const { entries, versions } = await foldRange(ctx, ds, zone, gs, facts, n, undefined);
    const plan = rollbackRRsets(entries, zone, { force: body.force === true });
    info = { restored: plan.rrsets.length, versions_undone: versions, skipped: plan.skipped };
    if (plan.rrsets.length === 0) return { none: true };
    const label = () => ({});
    return { rrsets: plan.rrsets, label, maps: renderChangeFile(plan.rrsets, label), expectations: renderExpectations(plan.rrsets) };
  };
  const comment = body.comment ? `rollback to version ${n}: ${body.comment}` : `rollback to version ${n}`;
  const out = await runChange(ctx, { ds, zone, facts, kind: 'rollback', rollbackOf: n, build, conflict: CONFLICT, comment, dryRun: body.dry_run === true, want, timeoutMs: EDIT_MS });
  return { ...out, rollback_of: n, ...info };
}

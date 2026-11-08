// The pipeline of one change set (planning 2.3): the check run, the permission check of the whole diff against ONE grant, the commit run with the generation the
// check run saw, the retries when the zone changed in between, the preconditions, and the reload.  Used by PATCH .../rrsets, the import and the creation of a zone.
//
//   1  preconditions (A-5), when the request has `expect`: a dry run of the expected RRsets; one that shows a difference is not as expected -> 409
//   2  the check run: karidns-zone apply --dry-run as the check role (a trusted session that sees the whole zone) -> the generation and the diff
//   3  the permission check on the diff (perm.js chooseGrant): one grant must allow every RRset, old and new records, and max_rr (A-24)
//   4  the commit run: karidns-zone apply as the API's role (row level security checks every row again), --expect-generation, the principal, the change set
//   5  exit status 3 ("the zone changed") -> again from 1, three times at most, with a small random pause; the permission check runs again on the new diff
//   6  the reload (explicit by default, A-6; never for a zone the signer keeps signed, S-5)
// One change set per zone at a time in this process (app.locks); the tools run in the pool (app.pool).

import crypto from 'node:crypto';
import { ApiError, conflict, notFound } from './errors.js';
import { checkArgv, commitArgv, reloadArgv } from './tools.js';
import { chooseGrant, isGlobal } from './perm.js';
import { showDiff, diffItems, mapMessages, entryPointer, entryIndex, parseLine } from './changes.js';
import { absolute, inZone } from './names.js';
import { clip } from '../../node/lib/run.js';
import * as S from './store.js';

const MAX_ATTEMPTS = 3;
const NOT_A_BUG = /^(zone\.|db\.import\.(rows|serial|checks|strict|verify)$|db\.apply\.changes$)/;

// -> { code, doc }: one run of karidns-zone apply.  A tool that did not run, ran too long or wrote too much is a 500 (logged); the JSON document is parsed here.
async function runApply(ctx, argv, input, timeoutMs) {
  const { app } = ctx;
  const r = await app.runTool(app.settings['karidns-zone'], argv, { input, timeoutMs, maxOutput: 64 << 20 });
  if (r.spawnError || r.timedOut || r.truncated) {
    app.log.error(`${ctx.id}: karidns-zone apply ${r.spawnError ? `did not start: ${r.spawnError}` : r.timedOut ? 'ran too long' : 'wrote too much'}`);
    throw new ApiError(500, 'internal');
  }
  let doc = null;
  try { doc = JSON.parse(r.stdout); } catch { /* not a document: reported below if it matters */ }
  return { code: r.code, doc, stderr: r.stderr };
}

// A run that did not give a document of the success: -> the ApiError to throw.  Exit status 1 is a refusal of the change (422, or what the message says), 4 is a busy
// zone (503), anything else a bug or a broken installation (500, logged; row level security that refuses what the API allowed is named as the bug it is).
function failure(ctx, run, maps) {
  const { app } = ctx;
  const msgs = run.doc?.messages ?? [];
  const errs = msgs.filter((m) => m.severity === 'error');
  if (run.code === 4) return new ApiError(503, 'busy', 'the zone is locked by another writer or the database is busy, try again', { headers: { 'Retry-After': '2' } });
  if (run.code === 1 && run.doc) {
    const zoneErr = errs.find((m) => m.code === 'db.apply.zone');
    if (zoneErr) {
      const t = String(zoneErr.text);
      if (/exists already/.test(t)) return new ApiError(409, 'exists', 'the zone exists already');
      if (/is not in the database/.test(t)) return notFound('no such zone');
      if (/domains\.type/.test(t)) return conflict('the zone is not a primary zone; its records are not edited here', 'zone-not-editable');
      return new ApiError(422, 'refused', clip(t, 300), { errors: mapMessages(msgs, maps) });
    }
    if (errs.some((m) => NOT_A_BUG.test(m.code))) {
      const errors = mapMessages(msgs, maps);
      return new ApiError(422, 'zone-checks-failed', 'the zone checks refuse this change', { errors });
    }
  }
  const text = clip(errs.map((m) => `${m.code}: ${m.text}`).join(' | ') || run.stderr || `exit status ${run.code}`, 400).replace(/\s+/g, ' ');
  if (/row-level security|permission denied|42501/i.test(text)) app.log.error(`${ctx.id}: row level security refused what the API allowed (a bug): ${text}`);
  else app.log.error(`${ctx.id}: karidns-zone apply failed (exit status ${run.code}): ${text}`);
  return new ApiError(500, 'internal');
}

// the permission error of a refused change, with the pointer into the request when the RRset came from it
function denial(d, entries, pointers) {
  const e = entries[d.index] ?? { name: '?', type: '?' };
  const what = `${e.type} ${absolute(e.name)}`;
  let text;
  if (d.reason === 'max-rr') text = `this change would leave ${d.count} records in the scope of the grant, which allows ${d.limit} (max_rr)`;
  else if (d.reason === 'rrset') text = `none of your grants allows ${what} as the change sets it`;
  else text = `${what}: every RRset of the change set is allowed by one of your grants or another, but no single grant allows them all (one grant must allow the whole change set)`;
  const err = { code: d.reason === 'max-rr' ? 'max-rr' : 'not-permitted', severity: 'error', text };
  const pointer = pointers?.[d.index];
  if (pointer) err.pointer = pointer;
  return new ApiError(403, d.reason === 'max-rr' ? 'max-rr' : 'forbidden', text, { errors: [err] });
}

// The permission check on the request itself (before any tool runs): the names, types and TTLs it sets, and the types it deletes.  Without it a principal could
// learn what an RRset outside its scope holds by sending the same RRset back and seeing whether the change shows in the diff.
function precheck(ctx, spec) {
  const items = spec.rrsets.map((r) => ({ name: r.name, type: r.type, ttls: r.op === 'delete' ? null : (r.ttls ?? [r.ttl]) }));
  const r = chooseGrant(ctx.auth.grants, { schema: spec.ds.schema, zone: spec.zone, items });
  if (r.denied) return denial(r.denied, items, spec.rrsets.map((_, i) => spec.label(i).path));
  return null;
}

// the records of the scope of a grant after the change (A-24): the zone for a global or domain master; for a subdomain master the records at or below its suffix
// now (counted in the database) and what the diff adds and removes
async function scopeCounts(ctx, spec, diff, records_after) {
  const sfx = new Map();
  for (const g of ctx.auth.grants) {
    if (g.role !== 'subdomain_master' || g.data_schema !== spec.ds.schema || g.zone_name !== spec.zone || g.policy.max_rr === null || sfx.has(g.name_suffix)) continue;
    sfx.set(g.name_suffix, await ctx.db((tx) => S.countUnder(tx, spec.ds.schema, spec.facts.id, g.name_suffix)));
  }
  return (g) => {
    if (g.policy.max_rr === null) return null;
    if (g.role !== 'subdomain_master') return records_after;
    let n = sfx.get(g.name_suffix) ?? 0;
    for (const e of diff) {
      const name = e.owner.replace(/\.$/, '').toLowerCase();
      if (inZone(name, g.name_suffix)) n += (e.after?.length ?? 0) - (e.before?.length ?? 0);
    }
    return n;
  };
}

// The reload after a change: 'not requested', 'requested', 'waiting for the signer' or 'failed: ...'.  PostgreSQL: the request was committed with the data (--reload);
// SQLite3: karictl with the restricted key, once per view the zone is in.
export async function reloadState(ctx, { ds, zone, facts, want, views = [], deleted = false }) {
  const { app } = ctx;
  if (!want) return 'not requested';
  if (facts?.signer && !deleted) return 'waiting for the signer';
  if (app.backend.dialect === 'pg') return 'requested';
  // a view name goes to karictl as a word of its own: only a plain name (the database could hold any text; a name that looks like an option is not passed on)
  if (views.some((v) => !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(v))) return 'failed: the zone is in a view whose name is not a plain name, so karictl is not asked';
  const list = views.length ? views : [undefined];
  for (const v of list) {
    const r = await app.runTool(app.settings.karictl, reloadArgv(app.settings, zone, v), { timeoutMs: 60000, maxOutput: 1 << 16 });
    if (r.spawnError || r.timedOut || r.code !== 0) {
      const why = clip(r.spawnError ?? (r.timedOut ? 'timed out' : (r.stderr || r.stdout || `exit status ${r.code}`)), 200).replace(/\s+/g, ' ');
      app.log.warn(`${ctx.id}: karictl reload ${zone} failed: ${why}`);
      // what karictl says can hold paths of the host (the control socket, the program): a global master is told, everybody else is pointed at the log
      const shown = isGlobal(ctx.auth.grants) ? why : `karictl could not reload the zone (the log of the service has the reason, request ${ctx.id})`;
      return `failed: ${shown} (the change is in the database; the server serves the old version until it is reloaded)`;
    }
  }
  return 'requested';
}

// -> the response of a change set.  spec:
//   ds, zone (canonical), facts (zoneFacts; null for a new zone), grants via ctx.auth
//   create, zoneType            a new zone (the rr lines are the whole zone)
//   kind                        the version row: edit, import, template, rollback (create is chosen by `create`)
//   rrsets, label, maps         the parsed RRsets of the request and where they come from; maps = renderChangeFile(): the change file (text)
//   zoneText, deleteOthers      instead of rrsets: a zone text (import)
//   expectations                renderExpectations(rrsets) or null
//   conflict                    { code, detail, error(entry, rrset) }: what an expectation that does not hold is called (default: precondition-failed, A-5); a dry run
//                               then reports them in `conflicts` and goes on instead of failing (a rollback, planning 6.4)
//   rollbackOf                  the version a rollback restores (kind rollback)
//   build                       instead of rrsets / label / maps / expectations: async () => { rrsets, label, maps, expectations } | { none: true }, called with
//                               the zone locked at the start of each round (a rollback reads the history there, so a change set of this process cannot slip in between)
//   comment, dryRun, want       a comment for the version; a dry run; whether to reload afterwards
//   timeoutMs                   for the tool runs
export async function runChange(ctx, spec) {
  const { app, auth } = ctx;
  const s = app.settings;
  const changeSet = crypto.randomUUID();
  ctx.changeSet = changeSet;
  const isText = spec.zoneText !== undefined;
  const argSpec = { zone: spec.zone, text: isText, deleteOthers: spec.deleteOthers, create: spec.create, zoneType: spec.zoneType };

  if (!isText && !spec.build) {
    const bad = precheck(ctx, spec);
    if (bad) {
      if (!spec.dryRun) throw bad;
      return { dry_run: true, allowed: false, denied: bad.errors[0] };
    }
  }

  // A-18: an RRset with location / ECS tags or tinydns attributes is not edited here (the change file cannot carry them, and a replacement would drop them); a zone
  // text may touch any RRset, so a zone that has any is not imported into
  const tagged = async (rrsets) => {
    if (spec.create) return;
    const pairs = isText ? undefined : rrsets.map((r) => ({ name: r.name, type: r.type }));
    const hits = await ctx.db((tx) => S.taggedRRsets(tx, spec.ds.schema, spec.facts.id, pairs));
    if (hits.length) {
      throw conflict(isText ? 'the zone has RRsets with location / ECS tags or tinydns attributes, which the API does not edit: use karidns-zone to import into it'
        : `${hits[0].type} ${absolute(hits[0].name)} carries location / ECS tags or tinydns attributes, which the API does not edit: use karidns-zone`, 'tagged-rrset');
    }
  };
  if (!spec.build) await tagged(spec.rrsets);

  const release = await app.locks.acquire(`${spec.ds.name}/${spec.zone}`);
  try {
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) await app.sleep(Math.floor(40 + app.random() * 120 * attempt));
      let cur = spec;
      if (spec.build) {
        const b = await spec.build();
        if (b.none) return { committed: false, changed: false, change_set: changeSet, diff: [], messages: [], reload: 'not requested', ...(spec.dryRun ? { dry_run: true, allowed: true } : {}) };
        await tagged(b.rrsets);
        cur = { ...spec, ...b };
      }
      const r = await once(ctx, cur, { changeSet, input: cur.zoneText ?? cur.maps.text, isText, maps: isText ? null : cur.maps, argSpec, s, auth });
      if (!r.retry) return r.value;
    }
  } finally {
    release();
  }
  throw conflict('the zone keeps changing under this request (another writer, the signer?); nothing was written, try again', 'changed');
}

async function once(ctx, spec, c) {
  const { app } = ctx;
  const { s } = c;
  let expectGeneration = null;
  let conflicts = null;
  // 1. the preconditions
  if (spec.expectations) {
    const er = await runApply(ctx, checkArgv(s, spec.ds, { zone: spec.zone, text: false }), spec.expectations.text, spec.timeoutMs);
    if (er.code === 3) return { retry: true };
    if (er.code !== 0 || !er.doc?.apply) throw failure(ctx, er, { ops: [], rr: [] });
    expectGeneration = er.doc.apply.generation;
    const failed = er.doc.apply.diff.map((e) => ({ e, i: spec.expectations.index.find((k) => k === entryIndex(spec.rrsets, e)) })).filter((x) => x.i !== undefined);
    if (failed.length) {
      const cf = spec.conflict;
      const errors = failed.map(({ e, i }) => (cf ? cf.error(e, spec.rrsets[i]) : {
        code: 'precondition-failed', severity: 'error', text: `${e.type} ${e.owner} is not as expected`, pointer: `${spec.label(i).path}/expect`,
        current: e.before === null ? null : e.before.map(parseLine),
      }));
      if (!cf || !spec.dryRun) throw new ApiError(409, cf?.code ?? 'precondition-failed', cf?.detail ?? 'an RRset is not as the request expected; nothing was written', { errors });
      conflicts = errors;
    }
  }
  // 2. the check run
  const chk = await runApply(ctx, checkArgv(s, spec.ds, c.argSpec), c.input, spec.timeoutMs);
  if (chk.code === 3) return { retry: true };
  if (chk.code !== 0 || !chk.doc?.apply) throw failure(ctx, chk, c.maps);
  const ap = chk.doc.apply;
  if (expectGeneration !== null && expectGeneration !== ap.generation) return { retry: true };
  const messages = mapMessages(chk.doc.messages, c.maps);
  // 3. the permission check on the diff
  const entries = diffItems(ap.diff);
  let verdict = null;
  const scopeAfter = await scopeCounts(ctx, spec, ap.diff, ap.records_after);
  const picked = chooseGrant(ctx.auth.grants, { schema: spec.ds.schema, zone: spec.zone, items: entries, scopeAfter });
  if (picked.denied) {
    const ptrs = ap.diff.map((e) => entryPointer(c.isText ? [] : spec.rrsets, e, spec.label));
    verdict = denial(picked.denied, entries, ptrs);
  }
  if (spec.dryRun) {
    const extra = conflicts ? { conflicts } : {};
    if (verdict) return { value: { dry_run: true, allowed: false, denied: verdict.errors[0], ...extra, messages } };
    return { value: { dry_run: true, allowed: true, ...summary(ap), diff: showDiff(ap.diff), ...extra, messages } };
  }
  if (verdict) throw verdict;
  if (!spec.create && ap.diff.length === 0) {
    return { value: { committed: false, changed: false, change_set: c.changeSet, ...summary(ap), diff: [], messages, reload: 'not requested' } };
  }
  // 4. the commit run
  const reload = spec.want && !(spec.facts?.signer);
  const cm = await runApply(ctx, commitArgv(s, spec.ds, {
    zone: spec.zone, text: c.isText, deleteOthers: spec.deleteOthers, create: spec.create, zoneType: spec.zoneType, generation: ap.generation, principal: ctx.auth.principal,
    changeSet: c.changeSet, kind: spec.kind, rollbackOf: spec.rollbackOf, comment: spec.comment, reload,
  }), c.input, spec.timeoutMs);
  if (cm.code === 3) return { retry: true };
  if (cm.code !== 0 || !cm.doc?.apply) throw failure(ctx, cm, c.maps);
  const done = cm.doc.apply;
  const views = !spec.create && app.backend.dialect === 'sqlite' && spec.want ? await ctx.db((tx) => S.zoneViews(tx, spec.ds.schema, spec.facts.id)) : [];
  const state = await reloadState(ctx, { ds: spec.ds, zone: spec.zone, facts: spec.facts, want: spec.want, views });
  return { value: { committed: true, changed: true, change_set: c.changeSet, ...summary(done), diff: showDiff(done.diff), messages: mapMessages(cm.doc.messages, c.maps), reload: state } };
}

const summary = (ap) => ({ version: ap.version, generation: { before: ap.generation, after: ap.generation_after }, serial: ap.serial, records: { before: ap.records_before, after: ap.records_after } });

// The diff a change file would make to the zone as it is now: a check run (the check role, a dry run) and nothing else - no grants are looked at, nothing is written.
// For the views of the history (`GET .../versions/{n}/diff?to=current`).  A change file whose result the zone checks refuse is a 422 like any other.
export async function checkDiff(ctx, { ds, zone, maps, timeoutMs }) {
  const r = await runApply(ctx, checkArgv(ctx.app.settings, ds, { zone, text: false }), maps.text, timeoutMs);
  if (r.code !== 0 || !r.doc?.apply) throw failure(ctx, r, maps);
  return r.doc.apply.diff;
}

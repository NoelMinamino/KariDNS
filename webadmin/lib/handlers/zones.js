// /datasets, the zones and their RRsets, the export, the audit log, the servers, /health and /version (the read side of planning 4).  A zone the principal has
// no grant on does not exist for it: 404, not 403 (A-25), so that zone names do not leak.

import { ApiError, badRequest, forbidden, notFound } from '../errors.js';
import { query, LIMIT, CURSOR, decodeCursor, encodeCursor } from '../validate.js';
import * as S from '../store.js';
import { reply } from '../http.js';
import { isGlobal, zoneGrant, rrVisible, auditVisible } from '../perm.js';
import { canonicalOwner, inZone, absolute } from '../names.js';
import { exportArgv, renderArgv } from '../tools.js';
import { contentProblem, MAX_RRSETS, MAX_RECORDS, ZONE_TEXT_LIMIT } from '../changes.js';
import { VERSION } from '../app.js';
import { dataset, zoneParam, zoneGrants, page } from './common.js';
import { grantView } from './auth.js';

// A global master sees every dataset; anyone else the datasets it has a grant in (audit, 0.6.2: the names and the PostgreSQL schemas of the
// other datasets were listed to everyone)
export function datasets(ctx) {
  const { app } = ctx;
  const gs = ctx.auth.grants;
  const shown = isGlobal(gs) ? app.datasets : app.datasets.filter((d) => gs.some((g) => g.data_schema === d.schema));
  return {
    datasets: shown.map((d) => ({ name: d.name, driver: app.backend.dialect === 'pg' ? 'postgresql' : 'sqlite3', schema: d.schema || undefined, views: d.views })),
  };
}

const NAME_CURSOR = (o) => typeof o?.n === 'string' && o.n.length <= 255;

export async function zonesList(ctx) {
  const ds = dataset(ctx);
  const q = query(ctx.query, {
    limit: LIMIT, cursor: CURSOR, prefix: { type: 'string', min: 1, max: 255, re: /^[A-Za-z0-9_.-]+$/ }, contains: { type: 'string', min: 1, max: 255, re: /^[A-Za-z0-9_.-]+$/ },
    kind: { type: 'string', values: ['NATIVE', 'MASTER', 'SLAVE', 'PRODUCER', 'CONSUMER'] }, signed: { type: 'bool' },
  });
  const limit = q.limit ?? 100;
  const gs = ctx.auth.grants.filter((g) => g.role === 'global_master' || g.data_schema === ds.schema);
  if (gs.length === 0) return { zones: [], next_cursor: null };
  const names = isGlobal(gs) ? null : [...new Set(gs.map((g) => g.zone_name))];
  const after = q.cursor === undefined ? undefined : decodeCursor(q.cursor, NAME_CURSOR).n;
  const rows = await ctx.db((tx) => S.listZones(tx, ds.schema, { names, prefix: q.prefix, contains: q.contains, kind: q.kind, signed: q.signed, after, limit }));
  const p = page(rows, limit, (r) => ({ n: r.raw }));
  const zones = [];
  for (const z of p.items) {
    const role = zoneGrant(gs, ds.schema, z.name);
    if (role) zones.push({ name: absolute(z.name), kind: z.kind, serial: z.serial, presigned: z.presigned, signer: z.signer, catalog: z.catalog, role });
  }
  return { zones, next_cursor: p.next_cursor };
}

export async function zoneGet(ctx) {
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  const z = await ctx.db((tx) => S.getZone(tx, ds.schema, zone));
  if (!z) throw notFound('no such zone');
  return {
    zone: {
      name: absolute(z.name), id: z.id, kind: z.kind, serial: z.serial, catalog: z.catalog, master: z.master, account: z.account, notified_serial: z.notified_serial,
      presigned: z.presigned, signer: z.signer, nsec3param: z.nsec3param, generation: z.generation, changed_at: z.changed_at, views: z.views,
      signer_state: z.signer_state, waiting_for_signer: z.signer && (z.signer_state?.signed_serial ?? null) !== z.serial, last_reload_request: z.last_reload_request,
      role: gs[0].role, grants: gs.map((g) => grantView(ctx.app, g)),
    },
  };
}

// MX and SRV keep their priority in a column of its own: the content as a zone file shows it has the priority in front, unless the content has it already
function recordText(type, content, prio) {
  const words = String(content ?? '').trim().split(/\s+/).filter(Boolean).length;
  if ((type === 'MX' && words === 1) || (type === 'SRV' && words === 3)) return `${prio ?? 0} ${content}`;
  return content;
}

const RR_CURSOR = (o) => typeof o?.n === 'string' && typeof o?.t === 'string' && o.n.length <= 255 && o.t.length <= 32;
const OWNER_TEXT = { type: 'string', min: 1, max: 255, re: /^[A-Za-z0-9_.*/-]+$/, reText: 'letters, digits and . _ * / - (a part of a name; a final dot is not needed)' };

// G2: the records of these RRsets as the text a change set takes (karidns-zone render: the loader's reader and the zone-file writer, one run for the page).  A record
// that cannot be rendered (the reader refuses it, a type that has no other form, a text a change set would refuse) gets rdata null: the client shows the stored content
// and treats the RRset as one it does not edit.  A tool that fails is not that: it is a broken installation (500, logged).
async function addRdata(ctx, zone, sets) {
  const { app } = ctx;
  const recs = sets.flatMap((s) => s.records.map((rec, i) => ({ rec, row: s.rows[i], owner: s.name, type: s.type })));
  for (const x of recs) x.rec.rdata = null;
  // a field the line framing cannot carry is not sent (the reader would refuse such a record anyway): a TAB or LF in an owner or a type, LF or NUL in a content
  const ok = recs.filter((x) => !/[\t\n\0]/.test(x.owner) && !/[\t\n\0]/.test(x.type) && typeof x.row.content === 'string' && x.row.content.length > 0 && !/[\n\0]/.test(x.row.content));
  if (ok.length === 0) return;
  const input = ok.map((x) => `${x.owner}\t${x.type}\t${Number.isSafeInteger(x.row.prio) ? x.row.prio : '-'}\t${x.row.content}\n`).join('');
  const r = await app.runTool(app.settings['karidns-zone'], renderArgv(zone), { input, timeoutMs: 60000, maxOutput: 64 << 20 });
  let doc = null;
  try { doc = JSON.parse(r.stdout); } catch { /* reported below */ }
  const list = doc?.render?.rdata;
  if (r.spawnError || r.timedOut || r.truncated || r.code !== 0 || !Array.isArray(list) || list.length !== ok.length) {
    const why = r.spawnError ? `did not start: ${r.spawnError}` : r.timedOut ? 'ran too long' : r.truncated ? 'wrote too much' : `failed (exit status ${r.code}, ${list ? `${list.length} results for ${ok.length} records` : 'no document'}): ${String(r.stderr).slice(0, 200).replace(/\s+/g, ' ')}`;
    app.log.error(`${ctx.id}: karidns-zone render ${why}`);
    throw new ApiError(500, 'internal');
  }
  // (the text is judged again by the rules of a change set: what the API would refuse as the content of a record is not offered as one)
  ok.forEach((x, i) => { if (typeof list[i] === 'string' && list[i].length <= 65535 && contentProblem(list[i]) === null) x.rec.rdata = list[i]; });
}

export async function rrsetsList(ctx) {
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  const q = query(ctx.query, {
    limit: LIMIT, cursor: CURSOR, name: { type: 'string', min: 1, max: 255 }, type: { type: 'string', min: 1, max: 32, re: /^[A-Za-z][A-Za-z0-9]*$/ },
    from: OWNER_TEXT, contains: OWNER_TEXT, rdata: { type: 'bool' },
  });
  const limit = q.limit ?? 100;
  let name;
  if (q.name !== undefined) {
    try { name = canonicalOwner(q.name); } catch (e) { throw badRequest(e.message, '?name'); }
    if (!inZone(name, zone)) throw badRequest('the name is not in the zone', '?name');
  }
  // G3: the first owner to list, as stored (lower case, no final dot), and a part of an owner (any case)
  const from = q.from === undefined ? undefined : q.from.toLowerCase().replace(/\.$/, '');
  const contains = q.contains === undefined ? undefined : q.contains.toLowerCase();
  const cur = q.cursor === undefined ? undefined : decodeCursor(q.cursor, RR_CURSOR);
  const after = cur && { name: cur.n, type: cur.t };
  // a global or domain master reads the whole zone; a subdomain master the names under its suffixes (and the apex SOA and NS)
  const whole = gs.some((g) => g.role !== 'subdomain_master');
  const visibility = whole ? null : { suffixes: [...new Set(gs.map((g) => g.name_suffix))] };
  const found = await ctx.db(async (tx) => {
    const id = await S.zoneId(tx, ds.schema, zone);
    if (id === undefined) return null;
    const rows = await S.listRRsets(tx, ds.schema, id, { zone, name, type: q.type?.toUpperCase(), visibility, after, limit, from, contains });
    // G4: the RRsets with a location / ECS tag or a tinydns attribute are read-only (A-18); the page says which
    const pairs = [...new Map(rows.map((r) => [`${r.name} ${r.type}`, { name: r.name, type: r.type }])).values()];
    const tagged = pairs.length ? new Set((await S.taggedRRsets(tx, ds.schema, id, pairs)).map((t) => `${t.name} ${t.type}`)) : new Set();
    return { rows, tagged };
  });
  if (found === null) throw notFound('no such zone');
  // the rows are in (name, type) order; `limit` RRsets are given, a further one only shows that there is more
  const sets = [];
  for (const r of found.rows) {
    const last = sets[sets.length - 1];
    if (last && last.name === r.name && last.type === r.type) last.rows.push(r);
    else sets.push({ name: r.name, type: r.type, rows: [r] });
  }
  const more = sets.length > limit;
  const shown = sets.slice(0, limit);
  const visible = shown.filter((s) => rrVisible(gs, { schema: ds.schema, zone, name: s.name, type: s.type }));
  const rrsets = visible.map((s) => {
    const ttls = s.rows.map((r) => r.ttl).filter((t) => t !== null);
    s.records = s.rows.map((r) => ({ content: recordText(s.type, r.content, r.prio), disabled: r.disabled, ttl: r.ttl }));
    return { name: absolute(s.name), type: s.type, ttl: ttls.length ? Math.min(...ttls) : null, tagged: found.tagged.has(`${s.name} ${s.type}`), records: s.records };
  });
  if (q.rdata === true) await addRdata(ctx, zone, visible);
  const lastShown = shown[shown.length - 1];
  return { rrsets, next_cursor: more ? encodeCursor({ n: lastShown.name, t: lastShown.type }) : null };
}

// The zone as a zone file (karidns-zone export: canonical order, what the server serves).  It reads the whole zone, so it is for the masters of the whole zone.
export async function zoneExport(ctx) {
  const { app } = ctx;
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  if (gs[0].role === 'subdomain_master') throw forbidden('a subdomain master sees part of the zone only; the export is for the masters of the whole zone');
  // (in the pool like every other run of a tool: at most `workers` exports at a time, up to 256 MiB each in memory, the rest wait or get a 503)
  const r = await app.runTool(app.settings['karidns-zone'], exportArgv(app.settings, ds, zone), { timeoutMs: 120000, maxOutput: 256 << 20 });
  if (r.spawnError || r.timedOut || r.truncated) throw new ApiError(500, 'internal', 'the export failed');
  if (r.code !== 0) {
    if (/no such zone|not found|does not exist|not in the database/i.test(r.stderr)) throw notFound('no such zone');
    app.log.error(`${ctx.id}: karidns-zone export ${zone} failed (status ${r.code}): ${r.stderr.slice(0, 300).replace(/\s+/g, ' ')}`);
    throw new ApiError(500, 'internal', 'the export failed');
  }
  return reply(200, null, { text: r.stdout, type: 'text/plain; charset=utf-8', headers: { 'Content-Disposition': `attachment; filename="${zone}.zone"` } });
}

const AUDIT_CURSOR = (o) => typeof o?.a === 'string' && Number.isFinite(Date.parse(o.a)) && (o.r === 0 || o.r === 1) && Number.isSafeInteger(o.i) && o.i >= 0;
const when = (text, name) => {
  const ms = Date.parse(text);
  if (!Number.isFinite(ms)) throw badRequest('a time like 2026-11-08T12:00:00Z is expected', `?${name}`);
  return ms;
};

// the data schema of an audit row as the grants name it: the zone file's rows say 'main', the grants of the auth schema name theirs in the row itself
function rowSchema(ctx, r) {
  if (ctx.app.backend.dialect === 'sqlite') return '';
  if (r.table === 'grants' && r.data_schema === 'karidns_auth') return (r.after ?? r.before)?.data_schema ?? null;
  return r.data_schema;
}

export async function auditList(ctx) {
  const q = query(ctx.query, {
    limit: LIMIT, cursor: CURSOR, zone: { type: 'string', min: 1, max: 255 }, principal: { type: 'int', min: 1, max: 999999999999999 },
    change_set: { type: 'string', min: 1, max: 64, re: /^[A-Za-z0-9._:-]+$/ }, table: { type: 'string', min: 1, max: 64, re: /^[a-z_]+$/ },
    since: { type: 'string', min: 1, max: 40 }, until: { type: 'string', min: 1, max: 40 },
  });
  const limit = q.limit ?? 100;
  let zone;
  if (q.zone !== undefined) {
    try { zone = canonicalOwner(q.zone); } catch (e) { throw badRequest(e.message, '?zone'); }
  }
  const f = {
    zone, principalId: q.principal, changeSet: q.change_set, table: q.table,
    since: q.since === undefined ? undefined : when(q.since, 'since'), until: q.until === undefined ? undefined : when(q.until, 'until'),
  };
  const cursorOf = (r) => encodeCursor({ a: r.at, r: r.rank, i: r.id });
  let cur = q.cursor === undefined ? undefined : decodeCursor(q.cursor, AUDIT_CURSOR);
  if (cur) cur = { at: cur.a, rank: cur.r, id: cur.i };
  // a principal that is not a global master may see few of the rows: they are looked at in chunks (100 rows at least) until a page is full or the log ends
  const scan = isGlobal(ctx.auth.grants) ? limit : Math.max(limit, 100);
  const items = [];
  let exhausted = false;
  for (let pass = 0; pass < 20 && items.length < limit; pass++) {
    // the database shows what the principal may see (PostgreSQL), and the API checks again whatever the database is
    const rows = await ctx.db((tx) => S.listAudit(tx, f, cur, scan));
    const scanned = rows.slice(0, scan);
    for (const r of scanned) if (auditVisible(ctx.auth.grants, { schema: rowSchema(ctx, r), zone: r.zone })) items.push(r);
    if (rows.length <= scan) { exhausted = true; break; }
    cur = { at: scanned[scan - 1].at, rank: scanned[scan - 1].rank, id: scanned[scan - 1].id };
  }
  const shown = items.slice(0, limit);
  let next = null;
  if (items.length > limit) next = cursorOf(shown[limit - 1]);
  else if (!exhausted) next = cursorOf(cur);
  return {
    audit: shown.map((r) => ({
      id: r.id, at: r.at, source: r.source, principal_id: r.principal_id, principal: r.principal, db_role: r.db_role, change_set: r.change_set, schema: r.data_schema,
      table: r.table, op: r.op, zone: r.zone ? absolute(r.zone) : null, row_id: r.row_id, before: r.before, after: r.after,
    })),
    next_cursor: next,
  };
}

// the lines "zone: reason" of failed_zones that concern a zone the principal has a grant on (a global master sees all)
function failedLines(ctx, ds, text) {
  const lines = String(text ?? '').split('\n').filter(Boolean);
  if (isGlobal(ctx.auth.grants)) return lines;
  return lines.filter((l) => {
    const z = l.split(':')[0].trim().toLowerCase().replace(/\.$/, '');
    return zoneGrant(ctx.auth.grants, ds.schema, z) !== null;
  });
}

export async function serversList(ctx) {
  const { app } = ctx;
  const servers = [];
  for (const ds of app.datasets) {
    if (!ctx.auth.grants.some((g) => g.role === 'global_master' || g.data_schema === ds.schema)) continue;
    const rows = await ctx.db((tx) => S.serverStatus(tx, ds.schema));
    for (const r of rows) servers.push({ dataset: ds.name, server_id: r.server_id, generation: r.generation, applied_at: r.applied_at, ok: r.ok, failed_zones: failedLines(ctx, ds, r.failed_zones) });
  }
  let note;
  if (app.backend.dialect === 'sqlite') note = 'a SQLite3 deployment has no server status table: ask the server with karictl status';
  return { servers, note };
}

// No login is needed, so a caller must not cost a database connection each: the callers that arrive while a check is running wait for that one.
export async function health(ctx) {
  const { app } = ctx;
  app.healthCheck ??= (async () => {
    try {
      await Promise.race([
        app.backend.tx({}, (tx) => tx.get('SELECT 1 AS ok')),
        new Promise((_, reject) => { setTimeout(() => reject(new Error('timeout')), app.healthTimeoutMs).unref(); }),
      ]);
      return true;
    } catch {
      return false;
    } finally {
      app.healthCheck = null;
    }
  })();
  const ok = await app.healthCheck;
  return reply(ok ? 200 : 503, { status: ok ? 'ok' : 'unavailable', database: ok ? 'ok' : 'error' });
}

// G5: what a client (the GUI) needs to follow the service: the record types a change set takes (karidns-zone's own list; null when the service could not ask) and the
// settings and limits that change what a form should offer
export function version(ctx) {
  const { app } = ctx;
  const s = app.settings;
  return {
    version: VERSION, tools: app.versions, datasets: app.datasets.map((d) => d.name), types: app.types ? [...app.types].sort() : null,
    ui: { reload_after_change: s['reload-after-change'], require_totp: s['require-totp'], max_rrsets: MAX_RRSETS, max_records: MAX_RECORDS, zone_text_limit: ZONE_TEXT_LIMIT },
  };
}

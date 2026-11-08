// The write side of /datasets (planning 4, 4.1, 5.4, 7): change sets (PATCH .../rrsets), the creation, update and deletion of zones, the import of a zone text, the
// reload, the zone metadata the API may write, and DNSSEC (the DS records, key requests).  The zone data itself is written by karidns-zone (pipeline.js); what is
// written here is the rest: the SQL of the zone-level operations, and the decisions about who may.

import crypto from 'node:crypto';
import { ApiError, badRequest, conflict, forbidden, notFound } from '../errors.js';
import { shape } from '../validate.js';
import * as S from '../store.js';
import { reply } from '../http.js';
import { parseChangeSet, parseCreate, createRRsets, renderChangeFile, renderExpectations, rrsetLabel } from '../changes.js';
import { runChange, reloadState } from '../pipeline.js';
import { canonicalZone, absolute } from '../names.js';
import { templateComment } from '../templates.js';
import { dnskeyView } from '../dnssec.js';
import { KINDS, metaKind, metaProblem, MAX_ROWS } from '../meta.js';
import { dataset, zoneParam, zoneGrants, requireGlobal } from './common.js';

const EDIT_MS = 120000;            // the tools may take this long for one change set (a large zone is read twice)
const IMPORT_RUN_MS = 300000;      // ... and this long for an import

export async function loadFacts(ctx, ds, zone) {
  const facts = await ctx.db((tx) => S.zoneFacts(tx, ds.schema, zone));
  if (!facts) throw notFound('no such zone');
  return facts;
}

// A zone whose records the API edits: a primary zone, not signed elsewhere (A-26).  A zone the signer keeps signed is fine: its data are edited, the signer signs.
export function editable(facts) {
  if (!['NATIVE', 'MASTER'].includes(String(facts.kind).toUpperCase())) throw conflict(`the zone is a ${facts.kind} zone: its records are not edited here`, 'zone-not-editable');
  if (facts.presigned && !facts.signer) {
    throw conflict('the zone is signed elsewhere (PRESIGNED, not kept by karidns-signer): a change would publish records without valid signatures; sign it elsewhere and import it with karidns-zone', 'presigned-zone');
  }
}

// Reload after the change?  `requested` is the request's own wish; else the configuration's (reload-after-change).  A SQLite3 deployment reloads with karictl, which
// needs its restricted key: a request for a reload that cannot be done is refused before anything is written.
export function wantReload(app, requested) {
  const s = app.settings;
  const want = requested ?? s['reload-after-change'];
  if (want && s.database === 'sqlite3' && !s['karictl-config']) {
    if (requested === true) throw badRequest("a reload needs 'karictl-config' (the restricted control key) on SQLite3; this deployment has none", '/reload');
    return false;
  }
  return Boolean(want);
}

export const noChangeSet = (ctx) => {
  ctx.changeSet = crypto.randomUUID();
  return ctx.changeSet;
};

// ---------------------------------------------------------------------------------------------------------------------------------- change sets
export async function rrsetsPatch(ctx) {
  const { app } = ctx;
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  zoneGrants(ctx, ds, zone);
  const ch = parseChangeSet(ctx.body, zone, { types: app.types });
  const facts = await loadFacts(ctx, ds, zone);
  editable(facts);
  const want = wantReload(app, ch.reload);
  return runChange(ctx, {
    ds, zone, facts, kind: 'edit', rrsets: ch.rrsets, label: rrsetLabel, maps: renderChangeFile(ch.rrsets), expectations: renderExpectations(ch.rrsets),
    comment: ch.comment, dryRun: ch.dryRun, want, timeoutMs: EDIT_MS,
  });
}

// A zone text goes to the zone-file parser of the server.  $INCLUDE is refused there (standard input has no directory).  $GENERATE is refused here: a line of 30
// octets makes up to 100,000 records, so a text of a few megabytes could make more records than any host has memory for before a limit of the zone is checked.
const NO_NUL = (text, pointer) => {
  if (text.includes('\0')) throw badRequest('the zone text has a NUL character', pointer);
  if (/(^|[\r\n])[ \t]*\$GENERATE\b/i.test(text)) throw badRequest('$GENERATE is not accepted: write the records out', pointer);
  return text;
};

// POST .../import {zone_text, mode: replace | merge, comment, dry_run, reload}: the RRsets of a zone text (BIND format; $INCLUDE refused; plain records only) become
// the zone's: merge replaces those RRsets, replace also deletes the RRsets the text does not have.  The SOA of the zone is kept when the text's differs only in the
// serial.  For the masters of the whole zone: a subdomain master's import would also reveal, by its diff, what lies outside its suffix.
export async function importZone(ctx) {
  const { app } = ctx;
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  if (gs[0].role === 'subdomain_master') throw forbidden('a subdomain master changes RRsets, not the whole zone: use PATCH .../rrsets');
  const body = shape(ctx.body, {
    zone_text: { type: 'string', required: true, min: 1, max: 16 << 20, noControl: false },
    mode: { type: 'string', values: ['replace', 'merge'] },
    comment: { type: 'string', max: 1024 },
    dry_run: { type: 'bool' },
    reload: { type: 'bool' },
  });
  NO_NUL(body.zone_text, '/zone_text');
  const facts = await loadFacts(ctx, ds, zone);
  editable(facts);
  return runChange(ctx, {
    ds, zone, facts, kind: 'import', zoneText: body.zone_text, deleteOthers: (body.mode ?? 'replace') === 'replace', comment: body.comment, dryRun: body.dry_run === true,
    want: wantReload(app, body.reload), timeoutMs: IMPORT_RUN_MS,
  });
}

// ---------------------------------------------------------------------------------------------------------------------------------- zones
export async function zoneCreate(ctx) {
  const { app } = ctx;
  requireGlobal(ctx);
  const ds = dataset(ctx);
  const c = parseCreate(ctx.body, { types: app.types });
  let zone;
  try { zone = canonicalZone(c.name); } catch (e) { throw badRequest(e.message, '/name'); }
  if (await ctx.db((tx) => S.zoneId(tx, ds.schema, zone)) !== undefined) throw new ApiError(409, 'exists', 'a zone of this name exists already');
  const want = wantReload(app, c.reload);
  const base = { ds, zone, facts: null, create: true, zoneType: c.kind, kind: 'create', comment: c.comment, dryRun: c.dryRun, want, timeoutMs: EDIT_MS };
  let spec;
  if (c.zoneText !== undefined) {
    spec = { ...base, zoneText: NO_NUL(c.zoneText, '/zone_text'), timeoutMs: IMPORT_RUN_MS };
  } else {
    // a template: copied into the zone (planning 5.4); the version keeps its name, id and revision in the comment
    let tpl;
    if (c.templateId !== undefined || c.template !== undefined) {
      tpl = await ctx.db((tx) => (c.templateId !== undefined ? S.getTemplate(tx, c.templateId) : S.getTemplateByName(tx, c.template)));
      if (!tpl) throw notFound('no such template');
    }
    const made = createRRsets(c, zone, tpl);
    spec = { ...base, rrsets: made.rrsets, label: made.label, maps: renderChangeFile(made.rrsets, made.label), ...(tpl ? { comment: templateComment(tpl, c.comment) } : {}) };
  }
  const r = await runChange(ctx, spec);
  if (!r.committed) return r;
  return reply(201, { zone: absolute(zone), ...r }, { headers: { Location: `/api/v1/datasets/${ds.name}/zones/${absolute(zone)}` } });
}

// PATCH .../zones/{zone} {catalog, views}: the attributes of the zone itself (global masters).  catalog: the PRODUCER zone whose member list the zone is in (null: none);
// views: the views of the dataset the zone is in (none given: every view)
export async function zonePatch(ctx) {
  requireGlobal(ctx);
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const body = shape(ctx.body, {
    catalog: { type: 'string', min: 1, max: 255, nullable: true },
    views: { type: 'array', max: 64, items: { type: 'string', min: 1, max: 64 } },
  });
  if (Object.keys(body).length === 0) throw badRequest('nothing to change: give catalog or views', '/');
  let catalog;
  if (typeof body.catalog === 'string') {
    try { catalog = canonicalZone(body.catalog); } catch (e) { throw badRequest(e.message, '/catalog'); }
  }
  for (const [i, v] of (body.views ?? []).entries()) {
    if (!ds.views.includes(v)) throw badRequest(`${JSON.stringify(v)} is not a view of this dataset (${ds.views.join(', ') || 'none are configured'})`, `/views/${i}`);
  }
  const facts = await loadFacts(ctx, ds, zone);
  const changeSet = noChangeSet(ctx);
  await ctx.db(async (tx) => {
    if (catalog !== undefined && !(await S.producerZone(tx, ds.schema, catalog))) throw conflict('the catalog must be a PRODUCER zone of this dataset', 'not-a-catalog');
    if (body.catalog !== undefined) await S.setCatalog(tx, ds.schema, facts.id, body.catalog === null ? null : catalog);
    if (body.views !== undefined) await S.setViews(tx, ds.schema, facts.id, [...new Set(body.views)]);
  }, { write: true, changeSet });
  const now = await ctx.db(async (tx) => ({ f: await S.zoneFacts(tx, ds.schema, zone), views: await S.zoneViews(tx, ds.schema, facts.id) }));
  return { zone: absolute(zone), catalog: now.f.catalog, views: now.views, change_set: changeSet };
}

// DELETE .../zones/{zone} {confirm: "<the zone's name>", reload}: the zone and everything of it (records, metadata, keys, versions, grants on it).  Global masters.
export async function zoneDelete(ctx) {
  const { app } = ctx;
  requireGlobal(ctx);
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const body = shape(ctx.body, { confirm: { type: 'string', required: true, min: 1, max: 255 }, reload: { type: 'bool' } });
  if (body.confirm.toLowerCase().replace(/\.$/, '') !== zone) throw badRequest('confirm must be the name of the zone, as in the path', '/confirm');
  const facts = await loadFacts(ctx, ds, zone);
  const want = wantReload(app, body.reload);
  const changeSet = noChangeSet(ctx);
  const release = await app.locks.acquire(`${ds.name}/${zone}`);
  let views = [];
  try {
    if (want && app.backend.dialect === 'sqlite') views = await ctx.db((tx) => S.zoneViews(tx, ds.schema, facts.id));
    await ctx.db(async (tx) => {
      await S.deleteZone(tx, ds.schema, facts.id, zone);
      if (want && tx.dialect === 'pg') await S.requestReload(tx, ds.schema, zone);
    }, { write: true, changeSet });
  } finally {
    release();
  }
  const state = await reloadState(ctx, { ds, zone, facts, want, views, deleted: true });
  return { deleted: absolute(zone), change_set: changeSet, reload: state };
}

// ---------------------------------------------------------------------------------------------------------------------------------- reload
const reloadFailed = (state) => new ApiError(503, 'reload-failed', state, { headers: { 'Retry-After': '5' } });

// POST .../zones/{zone}/reload: the "update" button.  A zone the signer keeps signed is reloaded by the signer after it has signed (S-5): an unsigned change must not be
// published by a reload from here.
export async function reloadZone(ctx) {
  const { app } = ctx;
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  zoneGrants(ctx, ds, zone);
  const facts = await loadFacts(ctx, ds, zone);
  if (facts.signer) throw conflict('the zone is kept signed by karidns-signer: the signer asks for the reload when it has signed the change (S-5)', 'signer-managed');
  wantReload(app, true);                                     // refuses (400) a SQLite3 deployment that has no karictl-config
  const changeSet = noChangeSet(ctx);
  let views = [];
  if (app.backend.dialect === 'sqlite') views = await ctx.db((tx) => S.zoneViews(tx, ds.schema, facts.id));
  else await ctx.db((tx) => S.requestReload(tx, ds.schema, zone), { write: true, changeSet });
  const state = await reloadState(ctx, { ds, zone, facts, want: true, views });
  if (state.startsWith('failed')) throw reloadFailed(state);
  return { zone: absolute(zone), change_set: changeSet, reload: state };
}

// POST .../datasets/{ds}/reload: every zone of the dataset (global masters; PostgreSQL).  Refused while a zone of the dataset is kept signed by the signer: a reload of
// every zone reads them as they are, which would publish their unsigned changes.  SQLite3: the restricted key reloads one named zone, never all.
export async function reloadAll(ctx) {
  const { app } = ctx;
  requireGlobal(ctx);
  const ds = dataset(ctx);
  if (app.backend.dialect !== 'pg') throw conflict('on SQLite3 the control key reloads one named zone: reload the zones one at a time', 'unsupported');
  const changeSet = noChangeSet(ctx);
  await ctx.db(async (tx) => {
    if ((await S.signerZoneCount(tx, ds.schema)) > 0) {
      throw conflict('a zone of this dataset is kept signed by karidns-signer, and a reload of every zone would publish its unsigned changes: reload the other zones one by one', 'signer-zones');
    }
    await S.requestReload(tx, ds.schema);
  }, { write: true, changeSet });
  return { dataset: ds.name, change_set: changeSet, reload: 'requested' };
}

// ---------------------------------------------------------------------------------------------------------------------------------- metadata
export async function metadataList(ctx) {
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  zoneGrants(ctx, ds, zone);
  const facts = await loadFacts(ctx, ds, zone);
  const rows = await ctx.db((tx) => S.listMetadata(tx, ds.schema, facts.id));
  const kinds = [];
  for (const r of rows) {
    const last = kinds[kinds.length - 1];
    if (last?.kind === r.kind) last.content.push(r.content);
    else kinds.push({ kind: r.kind, content: [r.content] });
  }
  return { metadata: kinds, writable: Object.keys(KINDS) };
}

async function writeMetadata(ctx, kindText, values) {
  requireGlobal(ctx);
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const kind = metaKind(kindText);
  if (!kind) throw badRequest(`${JSON.stringify(String(kindText).slice(0, 40))} is not metadata the API writes (${Object.keys(KINDS).join(', ')})`, '/kind');
  const bad = metaProblem(kind, values);
  if (bad) throw badRequest(bad, '/content');
  const facts = await loadFacts(ctx, ds, zone);
  const changeSet = noChangeSet(ctx);
  await ctx.db((tx) => S.setMetadata(tx, ds.schema, facts.id, kind, values), { write: true, changeSet });
  return { zone: absolute(zone), kind, content: values, change_set: changeSet };
}

export function metadataPut(ctx) {
  const body = shape(ctx.body, { content: { type: 'array', required: true, max: MAX_ROWS + 1, items: { type: 'string', min: 1, max: 4096 } } });
  return writeMetadata(ctx, ctx.params.kind, body.content);
}

export function metadataDelete(ctx) {
  return writeMetadata(ctx, ctx.params.kind, []);
}

// ---------------------------------------------------------------------------------------------------------------------------------- DNSSEC
const ALGORITHMS = [8, 10, 13, 14, 15, 16];

// GET .../dnssec: the keys (from the DNSKEY RRset, with key tags), the DS records for the parent zone, what the signer is doing, and the key requests.  For the
// masters of the zone.
export async function dnssecGet(ctx) {
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  if (gs[0].role === 'subdomain_master') throw forbidden('DNSSEC is for the masters of the whole zone');
  const r = await ctx.db(async (tx) => {
    const z = await S.getZone(tx, ds.schema, zone);
    if (!z) return null;
    return { z, dnskey: await S.dnskeyRecords(tx, ds.schema, z.id, zone), cryptokeys: await S.cryptoKeys(tx, ds.schema, z.id), requests: await S.listKeyRequests(tx, ds.schema, z.id) };
  });
  if (!r) throw notFound('no such zone');
  const view = dnskeyView(zone, r.dnskey);
  return {
    dnssec: {
      zone: absolute(zone), signed: r.z.signer || r.z.presigned, signer: r.z.signer, presigned: r.z.presigned, nsec3param: r.z.nsec3param, signer_state: r.z.signer_state,
      waiting_for_signer: r.z.signer && (r.z.signer_state?.signed_serial ?? null) !== r.z.serial, serial: r.z.serial,
      keys: view.keys, ds: view.ds, cryptokeys: r.cryptokeys, requests: r.requests,
    },
  };
}

// POST .../dnssec/requests {kind: enable | add, algorithm, bits, key_type, nsec}: asks karidns-signer to start signing the zone ('enable') or to make one more key
// ('add').  The signer answers in the request's state.  One request per zone at a time.
export async function dnssecRequest(ctx) {
  const { auth } = ctx;
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  const gs = zoneGrants(ctx, ds, zone);
  if (gs[0].role === 'subdomain_master') throw forbidden('only a global or domain master asks for keys');
  const b = shape(ctx.body, {
    kind: { type: 'string', required: true, values: ['enable', 'add'] },
    algorithm: { type: 'int', min: 8, max: 16 },
    bits: { type: 'int', min: 1024, max: 8192 },
    key_type: { type: 'string', values: ['csk', 'ksk', 'zsk'] },
    nsec: { type: 'string', values: ['nsec3', 'nsec'] },
  });
  const k = { kind: b.kind, algorithm: b.algorithm ?? 13, bits: b.bits, key_type: b.key_type ?? 'csk', nsec: b.nsec };
  if (!ALGORITHMS.includes(k.algorithm)) throw badRequest(`the algorithm must be one of ${ALGORITHMS.join(', ')}`, '/algorithm');
  if (k.bits !== undefined && ![8, 10].includes(k.algorithm)) throw badRequest('bits is for the RSA algorithms (8 and 10)', '/bits');
  if (k.nsec !== undefined && k.kind !== 'enable') throw badRequest('nsec is for an enable request', '/nsec');
  const facts = await loadFacts(ctx, ds, zone);
  editable(facts);
  if (k.kind === 'enable' && facts.signer) throw conflict('the zone is kept signed by karidns-signer already', 'already-signed');
  if (k.kind === 'add' && !facts.signer) throw conflict('the zone is not kept signed by karidns-signer: ask to enable signing first', 'not-signed');
  const changeSet = noChangeSet(ctx);
  const made = await ctx.db(async (tx) => {
    if (await S.pendingKeyRequest(tx, ds.schema, facts.id)) throw conflict('a request for this zone is waiting for the signer', 'request-pending');
    await S.insertKeyRequest(tx, ds.schema, facts.id, k, auth.principal.id);
    return (await S.listKeyRequests(tx, ds.schema, facts.id, 1))[0];
  }, { write: true, changeSet });
  return reply(201, { request: made, change_set: changeSet });
}

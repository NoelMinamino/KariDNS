// Zone templates (planning 5): /templates (everyone reads, global masters write), the validation of a template with karicheck, and "apply a template to a zone"
// (a change set of REPLACE operations).  Making a zone from a template is POST /datasets/{ds}/zones with `template` (handlers/write.js).

import { ApiError, badRequest, notFound } from '../errors.js';
import { shape, query, LIMIT, CURSOR } from '../validate.js';
import * as S from '../store.js';
import { reply } from '../http.js';
import { renderChangeFile, templateRRsets, templateLabel } from '../changes.js';
import { runChange } from '../pipeline.js';
import { parseTemplate, templateZoneText, templateMessages, templateComment } from '../templates.js';
import { clip } from '../../../node/lib/run.js';
import { dataset, zoneParam, zoneGrants, requireGlobal, idParam, idCursor, page } from './common.js';
import { loadFacts, editable, wantReload, noChangeSet } from './write.js';

const EDIT_MS = 120000;

// Validate the records of a template (planning 5.3): `karicheck --json zone template.invalid -` on the zone text they make.  -> the messages (errors and warnings),
// each pointing at the record it is about.  A karicheck that did not run, or did not answer with a document, is a 500 (logged).
export async function checkRecords(ctx, records) {
  const { app } = ctx;
  const { text, base } = templateZoneText(records);
  const r = await app.runTool(app.settings.karicheck, ['--json', 'zone', 'template.invalid', '-'], { input: text, timeoutMs: 30000, maxOutput: 8 << 20 });
  let doc = null;
  try { doc = JSON.parse(r.stdout); } catch { /* reported below */ }
  if (r.spawnError || r.timedOut || r.truncated || !doc || !Array.isArray(doc.messages)) {
    app.log.error(`${ctx.id}: karicheck did not check the template (${r.spawnError ?? (r.timedOut ? 'timed out' : r.truncated ? 'wrote too much' : `exit status ${r.code}: ${clip(r.stderr || r.stdout, 200).replace(/\s+/g, ' ')}`)})`);
    throw new ApiError(500, 'internal');
  }
  return templateMessages(doc.messages, base);
}

const refused = (messages) => new ApiError(422, 'template-checks-failed', 'the zone checks refuse this template', { errors: messages });
const hasErrors = (messages) => messages.some((m) => m.severity === 'error');

const view = (t) => ({
  id: t.id, name: t.name, description: t.description, revision: t.revision, soa: t.soa, created_by: t.created_by, updated_at: t.updated_at,
  ...(t.record_count === undefined ? {} : { record_count: t.record_count }), ...(t.records === undefined ? {} : { records: t.records }),
});

// GET /templates?prefix=&limit=&cursor=
export async function list(ctx) {
  const q = query(ctx.query, { limit: LIMIT, cursor: CURSOR, prefix: { type: 'string', min: 1, max: 64 } });
  const limit = q.limit ?? 100;
  const rows = await ctx.db((tx) => S.listTemplates(tx, { prefix: q.prefix, after: idCursor(q.cursor), limit }));
  const p = page(rows, limit, (t) => ({ i: t.id }));
  return { templates: p.items.map(view), next_cursor: p.next_cursor };
}

export async function get(ctx) {
  const t = await ctx.db((tx) => S.getTemplate(tx, idParam(ctx)));
  if (!t) throw notFound('no such template');
  return { template: view(t) };
}

// POST /templates {name, description?, soa?, records?, dry_run?}: global masters.  The records are checked (karicheck) before they are stored; errors are a 422,
// warnings come back in `messages`.  dry_run: only the checks.
export async function create(ctx) {
  requireGlobal(ctx);
  const t = parseTemplate(ctx.body, { types: ctx.app.types, create: true });
  const messages = await checkRecords(ctx, t.records);
  if (hasErrors(messages)) throw refused(messages);
  if (t.dryRun) return { dry_run: true, valid: true, messages };
  const id = await ctx.db((tx) => S.createTemplate(tx, t, ctx.auth.principal.id), { write: true, changeSet: noChangeSet(ctx) });
  return reply(201, { template: view(await ctx.db((tx) => S.getTemplate(tx, id))), messages }, { headers: { Location: `/api/v1/templates/${id}` } });
}

// PATCH /templates/{id}: any of name, description, soa (null clears), records (the whole list).  The revision grows.
export async function update(ctx) {
  requireGlobal(ctx);
  const id = idParam(ctx);
  const t = parseTemplate(ctx.body, { types: ctx.app.types });
  const { dryRun, ...patch } = t;
  if (Object.keys(patch).length === 0) throw badRequest('nothing to change: give name, description, soa or records', '/');
  const old = await ctx.db((tx) => S.getTemplate(tx, id));
  if (!old) throw notFound('no such template');
  const messages = await checkRecords(ctx, patch.records ?? old.records);
  if (hasErrors(messages)) throw refused(messages);
  if (dryRun) return { dry_run: true, valid: true, messages };
  const n = await ctx.db((tx) => S.updateTemplate(tx, id, patch), { write: true, changeSet: noChangeSet(ctx) });
  if (!n) throw notFound('no such template');
  return { template: view(await ctx.db((tx) => S.getTemplate(tx, id))), messages };
}

export async function remove(ctx) {
  requireGlobal(ctx);
  const n = await ctx.db((tx) => S.deleteTemplate(tx, idParam(ctx)), { write: true, changeSet: noChangeSet(ctx) });
  if (!n) throw notFound('no such template');
  return reply(204, null);
}

// POST /templates/{id}/validate: the stored template through karicheck again (a new release of karicheck knows more).  Always 200: { valid, messages }.
export async function validate(ctx) {
  const t = await ctx.db((tx) => S.getTemplate(tx, idParam(ctx)));
  if (!t) throw notFound('no such template');
  const messages = await checkRecords(ctx, t.records);
  return { template: { id: t.id, name: t.name, revision: t.revision }, valid: !hasErrors(messages), messages };
}

// POST .../zones/{zone}/apply-template {template | template_id, default_ttl?, comment?, dry_run?, reload?} (A-17): the template's RRsets replace those of the zone
// with the same name and type (an RRset merge: the zone's other RRsets stay), as a change set that the caller's grants must allow as a whole.  The SOA fields of the
// template are for a zone that is made from it, not for this.  The version has the kind `template`; its comment names the template and its revision.
export async function applyTemplate(ctx) {
  const { app } = ctx;
  const ds = dataset(ctx);
  const zone = zoneParam(ctx);
  zoneGrants(ctx, ds, zone);
  const b = shape(ctx.body, {
    template: { type: 'string', min: 1, max: 255 }, template_id: { type: 'int', min: 1, max: 999999999999999 }, default_ttl: { type: 'int', min: 0, max: 2147483647 },
    comment: { type: 'string', max: 700 }, dry_run: { type: 'bool' }, reload: { type: 'bool' },
  });
  if ((b.template === undefined) === (b.template_id === undefined)) throw badRequest('name the template: template (its name) or template_id, not both', b.template === undefined ? '/template' : '/template_id');
  const facts = await loadFacts(ctx, ds, zone);
  editable(facts);
  const tpl = await ctx.db((tx) => (b.template_id !== undefined ? S.getTemplate(tx, b.template_id) : S.getTemplateByName(tx, b.template)));
  if (!tpl) throw notFound('no such template');
  const rrsets = templateRRsets(tpl, zone, b.default_ttl ?? 3600);
  if (rrsets.length === 0) throw badRequest('the template has no records', '/template');
  const label = templateLabel(rrsets);
  return runChange(ctx, {
    ds, zone, facts, kind: 'template', rrsets, label, maps: renderChangeFile(rrsets, label), expectations: null, comment: templateComment(tpl, b.comment),
    dryRun: b.dry_run === true, want: wantReload(app, b.reload), timeoutMs: EDIT_MS,
  });
}

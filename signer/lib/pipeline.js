// One zone (planning 3.3), and the two key requests (3.5).  signZone() never throws: every outcome is a value.
//
//   { status: 'signed', serial, minExpire, writeId, durationMs, request, warnings }    request: null, or { state, message } for the key request this run answers
//   { status: 'changed' }   karidns-zone found the zone changed since the export (exit status 3): sign again
//   { status: 'busy' }      karidns-zone found the zone locked or the database busy (exit status 4): try again soon
//   { status: 'locked' }    another signer instance holds the zone
//   { status: 'skipped', reason }   the zone is not (or no longer) the signer's
//   { status: 'failed', error, request }
//   { status: 'key-added', request }   (a key request of kind add)
//
// The work directory of the zone is wiped on every path (finally), the keys are never logged, and a key that was generated for an `enable` request
// stays on disk until it is in cryptokeys (planning 3.5).

import fs from 'node:fs';
import path from 'node:path';
import fsp from 'node:fs/promises';
import readline from 'node:readline';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { setTimeout as sleepMs } from 'node:timers/promises';
import { canonicalZone } from './names.js';
import { zoneSettings } from './config.js';
import { loadKey, parseKeyStem } from './keys.js';
import { makeZoneDir, wipeDir, wipeFile, writeSecret } from './workdir.js';
import { clip } from './run.js';
import { checkArgv, exportArgv, importArgv, keygenArgv, parseNsec3param, reloadArgv, signzoneArgv } from './argv.js';

export class PipelineError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind;                   // 'changed' | 'busy' | 'failed'
  }
}

const fail = (m) => new PipelineError('failed', m);

// the SQLSTATE 40001 and 40P01 messages of PostgreSQL
export const TRANSIENT_DB_ERROR = /could not serialize access|deadlock detected/;

// seconds between the attempts to INSERT the keys of a zone that is signed already (about ten minutes in all)
export const KEY_RETRY_DELAYS = [1, 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60, 60, 60, 60];

// the apex DNSKEY lines of an export: `@ [ttl] [IN] DNSKEY ...` (the exporter writes one record per line, the apex as @)
const APEX_DNSKEY = /^@\s+(?:[0-9]+\s+)?(?:IN\s+)?DNSKEY\s/i;

// The export without its DNSKEY records, followed by the DNSKEY line of every key the zone has (active or published): dnssec-signzone 9.20 reads the
// keys of the zone from the DNSKEY RRset of the input, and a key that was removed from cryptokeys must not stay in the zone.  Returns the number of
// DNSKEY lines dropped.
export async function prepareInput(src, dst, dnskeyLines) {
  const fh = await fsp.open(dst, 'wx', 0o600);              // exclusive: never into an existing file or through a link
  let dropped = 0;
  async function* filter(source) {
    const rl = readline.createInterface({ input: Readable.from(source), crlfDelay: Infinity });
    for await (const line of rl) {
      if (APEX_DNSKEY.test(line)) {
        dropped++;
        continue;
      }
      yield `${line}\n`;
    }
    for (const l of dnskeyLines) yield l;
  }
  try {
    await pipeline(fs.createReadStream(src, { encoding: 'utf8' }), filter, fh.createWriteStream());
  } catch (e) {
    try { await fh.close(); } catch { /* closed by the stream already */ }
    throw e;
  }
  return dropped;
}

// what to pass to dnssec-signzone for the active keys: KSK and ZSK -> -x (only the KSKs sign the DNSKEY RRset); a CSK or a ZSK alone -> -z
export function signingMode(active) {
  if (active.length === 0) throw fail('the zone has no active key');
  if (!active.some((k) => k.flags === 257)) throw fail('the zone has no active key-signing key (flags 257): the DS record at the parent needs one');
  return active.some((k) => k.flags === 256) ? 'split' : 'csk';
}

// the keys a request of kind enable asks for: a CSK, or a KSK and a ZSK
export function requestedKeys(request) {
  if (request.kind === 'enable') return request.keyType === 'csk' ? [true] : [true, false];
  return [request.keyType !== 'zsk'];
}

function jsonOf(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// the message of a failed karidns-zone / karicheck run: the first error of its JSON document, else its standard error
function toolMessage(name, r) {
  if (r.spawnError) return `${name} could not be started: ${r.spawnError}`;
  if (r.timedOut) return `${name} timed out`;
  if (r.truncated) return `${name} wrote too much output`;
  const doc = jsonOf(r.stdout);
  const m = doc?.messages?.find((x) => x.severity === 'error');
  const text = m ? `${m.code}: ${m.text}` : (r.stderr.trim() || r.stdout.trim() || `exit status ${r.code}${r.signal ? ` (${r.signal})` : ''}`);
  return `${name}: ${clip(text)}`;
}

// ctx: { config (parsed), db, run(file, argv, opts), log, tools, work, clock(), sleep(ms) }
export async function generateKeys(ctx, dir, zone, request) {
  const out = [];
  for (const ksk of requestedKeys(request)) {
    const argv = keygenArgv({ zone, algorithm: request.algorithm, bits: request.bits ?? undefined, ksk, dir });
    const r = await ctx.run(ctx.tools.keygen, argv, { cwd: dir, timeoutMs: 600000 });
    if (r.code !== 0) throw fail(toolMessage('dnssec-keygen', r));
    const stem = parseKeyStem(r.stdout, zone);
    const flags = ksk ? 257 : 256;
    const content = fs.readFileSync(path.join(dir, `${stem.stem}.private`), 'utf8');
    // dnssec-keygen's files (with timing metadata) go; the pipeline writes its own from the key, like for every other key
    wipeFile(path.join(dir, `${stem.stem}.private`));
    wipeFile(path.join(dir, `${stem.stem}.key`));
    const key = loadKey(zone, { flags, content });
    // the tag we compute from the private key must be the one dnssec-keygen put in the file name (RFC 4034 appendix B)
    if (key.tag !== stem.tag || key.algorithm !== stem.algorithm) throw fail(`the key tag computed for the new key (${key.tag}) is not the one dnssec-keygen chose (${stem.tag})`);
    out.push({ flags, content: key.private, key });
  }
  return out;
}

// INSERT the keys of a zone that is signed already: retry with the same key files (the caller keeps them) until it works or the delays run out
export async function insertKeysWithRetry(ctx, domainId, keys, delays = KEY_RETRY_DELAYS) {
  let lastError = null;
  for (let i = 0; i <= delays.length; i++) {
    try {
      // the INSERT writes change log rows (a trigger on cryptokeys); they are ours, not a reason to sign the zone again
      ctx.ownWrites?.add(await ctx.db.insertKeys(domainId, keys));
      return null;
    } catch (e) {
      lastError = e;
      ctx.log.warn(`cannot store the keys of domain ${domainId} (try ${i + 1}): ${clip(e.message)}`);
    }
    if (i < delays.length) await ctx.sleep(delays[i] * 1000);
  }
  return lastError;
}

export async function signZone(ctx, job) {
  const t0 = Date.now();
  let zone;
  let settings;
  try {
    zone = canonicalZone(job.zone);
    settings = zoneSettings(ctx.config, zone);
  } catch (e) {
    return { status: 'failed', error: clip(e.message), request: job.request ? { state: 'failed', message: clip(e.message) } : null };
  }
  let locked = false;
  let dir = null;
  try {
    locked = await ctx.db.tryLock(job.domainId);
    if (!locked) return { status: 'locked' };
    dir = makeZoneDir(ctx.work, zone);
    return await runZone(ctx, job, zone, settings, dir, t0);
  } catch (e) {
    const durationMs = Date.now() - t0;
    if (e instanceof PipelineError && (e.kind === 'changed' || e.kind === 'busy')) return { status: e.kind };
    const message = clip(e instanceof PipelineError ? e.message : `unexpected error: ${e.message}`);
    return { status: 'failed', error: message, durationMs, request: job.request ? { state: 'failed', message } : null };
  } finally {
    if (dir) {
      wipeDir(dir);
      if (fs.existsSync(dir)) ctx.log.error(`cannot remove the work directory ${dir}: key files may be left in it`);
    }
    if (locked) {
      try { await ctx.db.unlock(job.domainId); } catch (e) { ctx.log.warn(`cannot release the lock of ${zone}: ${clip(e.message)}`); }
    }
  }
}

async function runZone(ctx, job, zone, settings, dir, t0) {
  const { db } = ctx;
  const req = job.request ?? null;
  const cfgDb = ctx.config.settings;
  const meta = await db.getMeta(job.domainId);
  if (req?.kind === 'add') return addKey(ctx, job, zone, dir, meta);
  if (!meta.signer && req?.kind !== 'enable') {
    await db.dropState(job.domainId);
    return { status: 'skipped', reason: 'the zone has no X-KARIDNS-SIGNER metadata' };
  }
  const rows = await db.getKeys(job.domainId);
  const warnings = [];
  let generated = [];
  if (req?.kind === 'enable' && !meta.signer) {
    if (rows.length > 0 && !meta.presigned) {
      throw fail('the zone has cryptokeys rows but no PRESIGNED metadata: the server does not serve such a zone (online signing is not supported); remove the keys, or sign the zone with them first');
    }
    if (rows.length === 0) generated = await generateKeys(ctx, dir, zone, req);
  }

  // the keys: the rows that are active or published, and the ones just generated (active and published)
  const keys = [];
  for (const r of rows) {
    if (!r.active && !r.published) continue;
    let k;
    try {
      k = loadKey(zone, r);
    } catch (e) {
      throw fail(`cryptokeys row ${r.id}: ${e.message}`);
    }
    keys.push({ ...k, active: r.active, published: r.published });
  }
  for (const g of generated) keys.push({ ...g.key, active: true, published: true });
  const names = new Set(keys.map((k) => k.base));
  if (names.size !== keys.length) throw fail('two keys of the zone have the same algorithm and key tag');
  const active = keys.filter((k) => k.active);
  const mode = signingMode(active);

  // NSEC or NSEC3: a zone that is signed already keeps its chain (the NSEC3PARAM metadata); a first signing follows the request
  let nsec3;
  if (meta.signer || meta.presigned) {
    nsec3 = null;
    if (meta.nsec3param) {
      const p = parseNsec3param(meta.nsec3param);
      if (!p) throw fail(`the NSEC3PARAM metadata "${clip(meta.nsec3param, 80)}" is not a form karidns-signer reproduces (hash algorithm 1)`);
      nsec3 = { ...p, optOut: settings['nsec3-opt-out'] };
    }
  } else {
    nsec3 = req.nsec === 'nsec' ? null : { salt: '-', iterations: 0, optOut: settings['nsec3-opt-out'] };
  }

  for (const k of active) {
    writeSecret(path.join(dir, `${k.base}.key`), k.dnskey);
    writeSecret(path.join(dir, `${k.base}.private`), k.private);
  }
  const timeoutMs = cfgDb.timeout * 1000;
  const exp = path.join(dir, 'export.zone');
  const inp = path.join(dir, 'in.zone');
  const out = path.join(dir, 'out.zone');

  let r = await ctx.run(ctx.tools.zone, exportArgv(cfgDb, zone, exp), { cwd: dir, timeoutMs });
  if (r.code !== 0) throw fail(toolMessage('karidns-zone export', r));
  await prepareInput(exp, inp, keys.map((k) => k.dnskey));

  const signArgv = signzoneArgv({
    zone, dir, inFile: inp, outFile: out, validity: settings.validity, refresh: settings.refresh, jitter: settings.jitter,
    verify: settings.verify, mode, nsec3, keyStems: active.map((k) => k.base),
  });
  r = await ctx.run(ctx.tools.signzone, signArgv, { cwd: dir, timeoutMs });
  if (r.code !== 0) throw fail(toolMessage('dnssec-signzone', r));

  r = await ctx.run(ctx.tools.karicheck, checkArgv(zone, out), { cwd: dir, timeoutMs });
  if (r.code !== 0) throw fail(toolMessage('karicheck', r));

  r = await ctx.run(ctx.tools.zone, importArgv(cfgDb, zone, out), { cwd: dir, timeoutMs });
  if (r.code === 3) throw new PipelineError('changed', 'the zone changed while it was signed');
  if (r.code === 4) throw new PipelineError('busy', 'the database is busy');
  // PostgreSQL gives up one of two transactions that touch the same rows (REPEATABLE READ: the pruning of karidns_reload_requests by two importers at once;
  // a deadlock): nothing was written, and the next try works.  Not an error of the zone.
  if (r.code !== 0 && TRANSIENT_DB_ERROR.test(`${r.stdout}\n${r.stderr}`)) throw new PipelineError('busy', 'the database rolled the write back (concurrent update)');
  if (r.code !== 0) throw fail(toolMessage('karidns-zone import', r));
  const sg = jsonOf(r.stdout)?.signer;
  if (!sg || sg.committed !== true || !Number.isInteger(sg.serial)) throw fail('karidns-zone import --signer gave no usable result');
  const minExpire = Number.isFinite(sg.earliest_expire_epoch) ? sg.earliest_expire_epoch : null;
  const writeId = sg.write_id ?? null;
  // from here on the zone is signed: whatever goes wrong now is a warning, the run has succeeded
  ctx.ownWrites?.add(writeId);

  // PostgreSQL: import --signer --reload has put the reload request in the transaction of the signature; SQLite3 has no request table
  if (cfgDb.database === 'sqlite3') {
    const w = await reloadZone(ctx, zone, dir);
    if (w) warnings.push(w);
  }

  let request = req ? { state: 'done', message: generated.length ? `signing enabled: ${generated.map((g) => `key ${g.key.tag} (algorithm ${g.key.algorithm}, flags ${g.key.flags})`).join(', ')}` : (meta.signer ? 'the zone was signed already' : 'signing enabled with the zone\'s keys') } : null;
  if (generated.length) {
    const err = await insertKeysWithRetry(ctx, job.domainId, generated, ctx.keyRetryDelays);
    if (err) {
      const m = `the zone was signed, but its new keys could not be stored (${clip(err.message, 200)}) and are lost: request an additional key (kind add) to replace the DNSKEYs`;
      warnings.push(m);
      request = { state: 'failed', message: m };
    } else {
      // The INSERT is in the change log (a trigger on cryptokeys), after the reload above: the loader would take it for a change of the zone, which waits for the signer.
      // A reload after the INSERT covers it (a one-zone reload covers the rows it has read) and changes nothing that is served.
      const w = await reloadZone(ctx, zone, dir);
      if (w) warnings.push(w);
    }
  }
  return { status: 'signed', serial: sg.serial, minExpire, writeId, durationMs: Date.now() - t0, request, warnings };
}

// Ask the server to read the zone again: PostgreSQL through a row of karidns_reload_requests (the first request is made by import --signer --reload, in the
// transaction of the signature), SQLite3 through karictl and the restricted key of the signer.  A failure is a message (the zone is signed; the server serves the
// old version until the next reload), not an error.
async function reloadZone(ctx, zone, dir) {
  const s = ctx.config.settings;
  try {
    if (s.database === 'pg') {
      await ctx.db.requestReload(zone);
      return null;
    }
    const rr = await ctx.run(ctx.tools.karictl, reloadArgv(s, zone), { cwd: dir, timeoutMs: 60000 });
    if (rr.code === 0) return null;
    return `karictl reload ${zone} failed (the server serves the old version until it is reloaded): ${clip(rr.spawnError ?? (rr.stderr || rr.stdout || `exit status ${rr.code}`), 300)}`;
  } catch (e) {
    return `the reload request for ${zone} failed (the server serves the old version until it is reloaded): ${clip(e.message, 300)}`;
  }
}

// kind add: one more key for a zone the signer signs.  The next run of the zone picks it up (the daemon makes the zone due).
async function addKey(ctx, job, zone, dir, meta) {
  const req = job.request;
  if (!meta.signer) throw fail('the zone is not signed by karidns-signer (no X-KARIDNS-SIGNER metadata): request kind enable first');
  const generated = await generateKeys(ctx, dir, zone, req);
  const err = await insertKeysWithRetry(ctx, job.domainId, generated, ctx.keyRetryDelays);
  if (err) throw fail(`the new key could not be stored: ${clip(err.message, 200)}`);
  return { status: 'key-added', request: { state: 'done', message: `key ${generated[0].key.tag} (algorithm ${generated[0].key.algorithm}, flags ${generated[0].key.flags}) added` } };
}

export const defaultSleep = (ms) => sleepMs(ms);

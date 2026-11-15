// Opening the database, the checks of `--check` and of the start (planning 4.3, 9), and `--create-admin`.

import fs from 'node:fs';
import path from 'node:path';
import { validate } from './config.js';
import { checkConninfoFile, parseConninfo, plaintextWarning, readPrivateFile } from '../../node/lib/conf.js';
import { loadSqlite } from '../../node/lib/sqlite.js';
import { clip } from '../../node/lib/run.js';
import { SqliteBackend, PgBackend } from './db.js';
import * as S from './store.js';
import crypto from 'node:crypto';
import { hashPassword, randomToken, readKeyFile, writeKeyFile, wrapSecret, unwrapSecret } from './crypto.js';
import { typesArgv, renderArgv } from './tools.js';
import { loadStatic, defaultUiDir } from './static.js';

const PROGRAM = 'karidns-webadmin';

// the tables the API relies on: the auth tables (schema version 3, with the tables of items D and E and the preferences of 0.7) and the zone data tables of a dataset
export const AUTH_TABLES = ['auth.principals', 'auth.credentials', 'auth.memberships', 'auth.principal_closure', 'auth.rr_policies', 'auth.grants', 'auth.sessions',
  'auth.api_tokens', 'auth.preferences', 'auth.templates', 'auth.template_records', 'auth.oidc_states', 'auth.schema_version'];
export const DATA_TABLES = ['domains', 'records', 'domainmetadata', 'cryptokeys', 'karidns_schema_version', 'karidns_zone_state', 'karidns_zone_versions', 'karidns_zone_version_rrsets',
  'karidns_domain_views', 'karidns_signer_state', 'karidns_key_requests', 'karidns_record_tags', 'karidns_record_tinydns', 'karidns_zone_tagdefs'];

// -> a backend, opened.  conninfoFile overrides the file of the configuration (--create-admin and --rotate-totp-key use a trusted role of its own).  readPrivate:
// node/lib/conf.js readPrivateFile (the file is read once, the checks made on its descriptor), injected for the tests.
export async function openBackend(config, { conninfoFile, importPg = () => import('pg'), importSqlite = loadSqlite, readPrivate = readPrivateFile, onError, warn } = {}) {
  const s = config.settings;
  if (s.database === 'sqlite3') {
    const b = new SqliteBackend({ sqlite: await importSqlite(), file: s['sqlite-file'], authFile: s['auth-file'] });
    b.open();
    return b;
  }
  const file = conninfoFile ?? s['api-conninfo-file'];
  const text = readPrivate(file, { program: PROGRAM });
  const mod = await importPg();
  const conn = parseConninfo(text, PROGRAM);
  const w = plaintextWarning(conn);
  if (w) warn?.(w);
  const b = new PgBackend({ pg: mod.Pool ? mod : mod.default, conn, poolMax: Math.max(4, config.settings.workers * 2), onError });
  await b.open();
  return b;
}

const firstLine = (r) => (r.stdout || r.stderr).trim().split(/\r?\n/)[0] ?? '';

// What the start and --check look at.  -> { problems, notes, warnings, versions }.  backend: an opened backend (its schema is checked) or undefined.
export async function inspect(config, { backend, run, st = {}, uid = process.getuid?.(), readPrivate = readPrivateFile, now = Date.now } = {}) {
  const s = config.settings;
  const problems = validate(config);
  const notes = [];
  const warnings = [];
  const versions = {};
  let types = null;                         // the record types karidns-zone's change file takes (its own list, planning 8.1)
  let ui = null;                            // the files of the GUI (static.js), read here once and kept by the service
  if (problems.length) return { problems, notes, warnings, versions, types, ui };

  const checkFile = (what, file, stat) => {
    const p = checkConninfoFile(file, stat, uid, PROGRAM);
    if (p) problems.push(`${what}: ${p}`);
    else notes.push(`${what} ${file}: fine`);
  };
  if (s.database === 'pg') {
    // (read once, the checks made on its descriptor.  A text that does not parse, or asks for sslmode allow / prefer to another host, is the problem the opening tells
    // in the same words, so --check shows it once.)  The check role's file is read by karidns-zone, which checks it itself: here only its mode.
    let text;
    try { text = readPrivate(s['api-conninfo-file'], { uid, program: PROGRAM }); } catch (e) { problems.push(`api-conninfo-file: ${e.message}`); }
    if (text !== undefined) {
      notes.push(`api-conninfo-file ${s['api-conninfo-file']}: fine`);
      try {
        const w = plaintextWarning(parseConninfo(text, PROGRAM));
        if (w) warnings.push(w);
      } catch (e) { problems.push(e.message); }
    }
    checkFile('check-conninfo-file', s['check-conninfo-file'], st.check);
  } else {
    for (const [what, file] of [['sqlite-file', s['sqlite-file']], ['auth-file', s['auth-file']]]) {
      try {
        fs.accessSync(file, fs.constants.R_OK | fs.constants.W_OK);
        notes.push(`${what} ${file}: fine`);
      } catch (e) {
        problems.push(`${what} ${file}: ${e.code ?? e.message}`);
      }
    }
    if (s['karictl-config']) checkFile('karictl-config', s['karictl-config'], st.karictl);       // the restricted control key: a secret like a connection file
    const p = st.auth ?? (() => { try { return fs.lstatSync(s['auth-file']); } catch { return null; } })();
    if (p && uid !== undefined && (p.mode & 0o077) !== 0) problems.push(`auth-file ${s['auth-file']} has mode ${(p.mode & 0o777).toString(8).padStart(4, '0')}: it holds the password hashes, it must be 0600`);
  }
  // the private key of the built-in TLS: a secret like a connection file (planning 8.4: the service user's, mode 0600)
  if (s['tls-key']) checkFile('tls-key', s['tls-key'], st.tls);
  try {
    const st2 = fs.lstatSync(s['totp-key-file']);
    // (what the start's readKeyFile refuses: a link or another kind of file, another owner, access for others)
    if (uid !== undefined && !st2.isFile()) problems.push(`totp-key-file ${s['totp-key-file']} is not a regular file`);
    else if (uid !== undefined && (st2.mode & 0o077) !== 0) problems.push(`totp-key-file ${s['totp-key-file']} has mode ${(st2.mode & 0o777).toString(8).padStart(4, '0')}: it must be 0600`);
    else if (uid !== undefined && st2.uid !== uid) problems.push(`totp-key-file ${s['totp-key-file']} is not owned by the user running ${PROGRAM}`);
    else notes.push(`totp-key-file ${s['totp-key-file']}: fine`);
  } catch (e) {
    if (e.code === 'ENOENT') notes.push(`totp-key-file ${s['totp-key-file']}: not there yet, it is made at the first start`);
    else problems.push(`totp-key-file ${s['totp-key-file']}: ${e.code ?? e.message}`);
  }
  if (rotationPending(s['totp-key-file'])) problems.push(rotationPendingProblem(s['totp-key-file']));

  // the providers: the secret files are read here (the service starts with what this found); the providers themselves are not asked
  const providers = readOidcProviders(config, { uid, readPrivate });
  problems.push(...providers.problems);
  for (const p of providers.list) notes.push(`oidc ${p.name} (${p.issuer}): client id and secret read, mfa = ${p.mfa}, redirect URI ${s['public-origin']}/api/v1/auth/oidc/${p.name}/callback`);

  if (s.ui) {
    const dir = s['ui-dir'] ?? defaultUiDir();
    try {
      ui = loadStatic(dir);
      notes.push(`ui ${dir}: ${ui.size} files, ${[...ui.values()].reduce((n, f) => n + f.body.length, 0)} bytes`);
    } catch (e) {
      problems.push(`ui ${dir}: ${e.message} (ui = no switches the GUI off)`);
    }
  } else {
    notes.push('ui: off (ui = no)');
  }

  if (run) {
    const want = s.database === 'pg' ? 'postgresql' : 'sqlite3';
    const z = await run(s['karidns-zone'], ['--version'], { timeoutMs: 10000, maxOutput: 8192 });
    if (z.spawnError || z.code !== 0) problems.push(`karidns-zone (${s['karidns-zone']}): ${z.spawnError ?? `exit status ${z.code}`}`);
    else if (!firstLine(z).includes(want)) problems.push(`karidns-zone has no ${want} driver (${clip(firstLine(z), 120)})`);
    else {
      versions['karidns-zone'] = clip(firstLine(z), 120);
      notes.push(`karidns-zone (${s['karidns-zone']}): ${versions['karidns-zone']}`);
      // the JSON schema number of its documents (planning 4.3): a tool that speaks another one is refused
      const t = await run(s['karidns-zone'], typesArgv(), { timeoutMs: 10000, maxOutput: 1 << 16 });
      let doc = null;
      try { doc = JSON.parse(t.stdout); } catch { /* reported below */ }
      if (doc?.['karidns-zone'] !== 1 || !Array.isArray(doc.types)) problems.push(`karidns-zone --types-list --json did not give a document of schema 1 (${clip(t.stdout || t.stderr, 120)})`);
      else {
        versions['karidns-zone-json'] = doc['karidns-zone'];
        types = doc.types.filter((x) => typeof x === 'string').map((x) => x.toUpperCase());
      }
      // `render` (G2, the GUI): a karidns-zone of an older release does not have it, and GET .../rrsets?rdata=1 would fail on every call
      const r = await run(s['karidns-zone'], renderArgv('example.test'), { timeoutMs: 10000, maxOutput: 1 << 16, input: '' });
      let rdoc = null;
      try { rdoc = JSON.parse(r.stdout); } catch { /* reported below */ }
      if (rdoc?.['karidns-zone'] !== 1 || !Array.isArray(rdoc.render?.rdata)) problems.push(`karidns-zone render --json did not give a document of schema 1 (${clip(r.stdout || r.stderr, 120)}): is karidns-zone of this release?`);
    }
    const k = await run(s.karicheck, ['--version'], { timeoutMs: 10000, maxOutput: 8192 });
    if (k.spawnError || k.code !== 0) problems.push(`karicheck (${s.karicheck}): ${k.spawnError ?? `exit status ${k.code}`}`);
    else {
      versions.karicheck = clip(firstLine(k), 120);
      notes.push(`karicheck (${s.karicheck}): ${versions.karicheck}`);
    }
    // SQLite3 has no reload requests: a reload runs karictl with the restricted key of karictl-config
    if (s.database === 'sqlite3' && s['karictl-config']) {
      const c = await run(s.karictl, ['--version'], { timeoutMs: 10000, maxOutput: 8192 });
      if (c.spawnError || c.code !== 0) problems.push(`karictl (${s.karictl}): ${c.spawnError ?? `exit status ${c.code}`}`);
      else notes.push(`karictl (${s.karictl}): ${clip(firstLine(c), 120)}`);
    }
  }

  if (backend) {
    try {
      const datasets = config.settings.database === 'pg' ? [...(config.datasets.size ? config.datasets.values() : [{ name: 'main', schema: 'public' }])] : [{ name: 'main', schema: '' }];
      for (const d of datasets) {
        const r = await backend.tx({}, async (tx) => ({ v: await S.schemaVersions(tx, d.schema), missing: await S.missingTables(tx, d.schema, [...AUTH_TABLES, ...DATA_TABLES, ...(s.database === 'pg' ? ['karidns_reload_requests'] : [])]) }));
        if (r.v.auth !== 3 || r.v.data !== 3) problems.push(`dataset ${d.name}: the schema version is ${r.v.auth}/${r.v.data} (auth/data), 3 is needed: apply db/karidns_ext.*.sql and db/karidns_auth.sqlite3.sql of this release`);
        else if (r.missing.length) {
          // (a version 3 schema made by an earlier release lacks the tables added since: the files of this release add them when they are applied again)
          problems.push(`dataset ${d.name}: missing tables: ${r.missing.join(', ')} (apply ${s.database === 'pg' ? 'db/karidns_ext.pgsql.sql, then db/karidns_api_role.pgsql.sql,' : 'db/karidns_ext.sqlite3.sql and db/karidns_auth.sqlite3.sql'} of this release again)`);
        }
        else notes.push(`dataset ${d.name}: schema version 3, all tables there`);
      }
    } catch (e) {
      problems.push(`the database: ${e.message}`);
    }
    // PostgreSQL: the role of api-conninfo-file has what db/karidns_api_role.pgsql.sql gives it on the auth tables, and row level security binds it there (an ext file
    // applied again without the role script after it leaves a new table the role may not use: the service would start and fail every request)
    if (!problems.length && s.database === 'pg') {
      try {
        const a = await backend.tx({}, (tx) => S.authAccess(tx));
        if (a.lacking.length) problems.push(`the role of api-conninfo-file lacks privileges on ${a.lacking.join(', ')}: run db/karidns_api_role.pgsql.sql of this release (again) for it`);
        if (a.noRls.length) problems.push(`row level security does not bind the role of api-conninfo-file on ${a.noRls.join(', ')} (the table owner, a superuser, or the role script not run since the table came): run db/karidns_api_role.pgsql.sql of this release (again) and use the API role`);
      } catch (e) {
        problems.push(`the privileges of the API role could not be read: ${clip(e.message, 200)}`);
      }
    }
    // tokens of groups (0.7: POST /tokens makes tokens for users only): the ones made before still work, so they are named here for their owner to replace
    if (!problems.length) {
      try {
        const g = await backend.tx({}, (tx) => S.groupTokens(tx, now()));
        if (g.length) warnings.push(`${g.length} API token(s) of groups still work (a group does not sign in; make tokens for a user, a service account, and revoke these): ${g.slice(0, 20).map((t) => `${t.id} ${JSON.stringify(t.name)} of ${t.principal}`).join(', ')}${g.length > 20 ? ', ...' : ''}`);
      } catch (e) {
        warnings.push(`the tokens of groups could not be listed (${clip(e.message, 120)}): on PostgreSQL apply db/karidns_ext.pgsql.sql and db/karidns_api_role.pgsql.sql of this release`);
      }
    }
  }
  return { problems, notes, warnings, versions, types, ui, oidc: providers.list };
}

// The [oidc] sections as the service uses them: the client secret is read from its file (a secret like a connection file: the service user's, mode 0600 or 0400; read once,
// the checks made on its descriptor).  -> { list: [{ name, issuer, clientId, clientSecret, scopes, label, mfa }], problems }.  Nothing is fetched here: --check does not
// touch the providers.
export function readOidcProviders(config, { readPrivate = readPrivateFile, uid = process.getuid?.() } = {}) {
  const list = [];
  const problems = [];
  for (const o of config.oidc?.values() ?? []) {
    let secret;
    try { secret = readPrivate(o['client-secret-file'], { uid, program: PROGRAM }).replace(/\r?\n$/, ''); } catch (e) { problems.push(`oidc ${o.name}: client-secret-file: ${e.message}`); continue; }
    if (secret.length === 0 || secret.length > 1024 || /[\0-\x1f\x7f]/.test(secret)) { problems.push(`oidc ${o.name}: client-secret-file ${o['client-secret-file']} must hold the secret on one line (1 to 1024 characters)`); continue; }
    list.push({ name: o.name, issuer: o.issuer, clientId: o['client-id'], clientSecret: secret, scopes: o.scopes.includes('openid') ? o.scopes : ['openid', ...o.scopes], label: o.label, mfa: o.mfa });
  }
  return { list, problems };
}

// A rotation of the TOTP key that has not finished leaves <totp-key-file>.new: the service does not start then, --check names it (the secrets may open with that key only).
export const rotationPendingProblem = (file) => `a TOTP key rotation is unfinished: run --rotate-totp-key (${file}.new is there)`;
export function rotationPending(file, fsx = fs) {
  try {
    fsx.lstatSync(`${file}.new`);
    return true;
  } catch (e) {
    return e.code !== 'ENOENT' && e.code !== 'ENOTDIR';
  }
}

// fsync(2) of a directory, so that a rename or a new file in it survives a crash.  Windows cannot open a directory (EISDIR, EPERM) and some file systems refuse the call
// (EINVAL): nothing more can be done there.
export function syncDir(dir, fsx = fs) {
  let fd;
  try {
    fd = fsx.openSync(dir, 'r');
    fsx.fsyncSync(fd);
  } catch (e) {
    if (e.code !== 'EISDIR' && e.code !== 'EPERM' && e.code !== 'EINVAL') throw e;
  } finally {
    if (fd !== undefined) fsx.closeSync(fd);
  }
}

// Before a rotation writes anything: the connection sees every row of the credentials (PostgreSQL: row level security does not bind its role, and it may read and change
// the table), and the auth tables are there at all (the database of the service).  A role that RLS binds would see none of the secrets, wrap none, and the rename would
// leave every stored secret under a key that is gone.
async function checkRotationAccess(backend) {
  await backend.tx({}, async (tx) => {
    if ((await S.missingTables(tx, '', ['auth.credentials'])).length) {
      throw new Error(`the auth tables are not in this database (${tx.dialect === 'pg' ? 'karidns_auth.credentials' : `the table credentials of the auth file`} is missing): is it the database of the service?`);
    }
    if (tx.dialect !== 'pg') return;
    const r = await tx.get(`SELECT row_security_active('karidns_auth.credentials') AS rls, has_table_privilege('karidns_auth.credentials', 'SELECT') AND has_table_privilege('karidns_auth.credentials', 'UPDATE') AS may`);
    if (r.rls) throw new Error('row level security binds the role of this connection on karidns_auth.credentials, it would not see every TOTP secret: give --bootstrap-conninfo-file the connection of the table owner');
    if (!r.may) throw new Error('the role of this connection may not read and change karidns_auth.credentials: give --bootstrap-conninfo-file the connection of the table owner');
  });
}

// Every stored secret that opens with `from` wrapped again with `to`, in one transaction, each with a compare-and-swap update.  A secret that opens with `to` already is
// left (an earlier run wrapped it); one that opens with neither is left and counted.  -> { rewrapped, unreadable }
async function rewrapAll(backend, from, to) {
  let rewrapped = 0;
  let unreadable = 0;
  await backend.tx({ write: true }, async (tx) => {
    for (const r of await S.totpSecrets(tx)) {
      if (unwrapSecret(to, r.principal_id, r.totp_secret) !== null) continue;
      const plain = unwrapSecret(from, r.principal_id, r.totp_secret);
      if (plain === null) { unreadable++; continue; }
      const done = await S.replaceTotp(tx, r.principal_id, r.totp_secret, wrapSecret(to, r.principal_id, plain));
      if (done.changes !== 1) throw new Error(`the TOTP secret of principal ${r.principal_id} changed meanwhile: stop the service and run again`);
      rewrapped++;
    }
  });
  return { rewrapped, unreadable };
}

// karidns-webadmin --rotate-totp-key (decision S-2, 0.7; the service is stopped): a new key in <totp-key-file>.new (0600, O_EXCL), every stored TOTP secret wrapped again
// with it in one transaction, the old key kept as <totp-key-file>.old (0600; an older .old is replaced), then the new file renamed over the old and the directory synced.
// A run that died after its commit left .new with secrets wrapped by it, and a service started meanwhile may have written secrets under the old key (the start refuses
// while .new is there, but an older release or a service that was never stopped does not): a second run that finds some secret opening with .new adopts .new, wraps
// the secrets that still open with the old key again with it, keeps .old and renames.  A .new that no secret opens with (a run that died before its commit) or that is
// not a key is discarded and the rotation done again.  A secret that opens with neither key (a key lost before) is left as it is and counted: its user enrols again.
// The old key file is never destroyed: it stays as .old for the operator to delete once the logins work, and an .old that still opens a stored secret is not replaced
// (refused before anything is written, on a new rotation and on an adopting rerun alike).
// -> { rewrapped, unreadable, finished, old } (finished: an earlier run's key was adopted; old: the path of the kept key).
export async function rotateTotpKey(config, backend, { fsx = fs, uid } = {}) {
  const file = config.settings['totp-key-file'];
  const next = `${file}.new`;
  const kept = `${file}.old`;
  const old = readKeyFile(file, fsx, uid);                      // (it must be there: the first start makes it, a rotation does not)
  await checkRotationAccess(backend);
  // .old: a regular file there is the key of an earlier rotation (replaced); a link or another kind of file is somebody else's business (refused, before anything is written)
  const keptThere = () => {
    let st;
    try { st = fsx.lstatSync(kept); } catch (e) { if (e.code === 'ENOENT') return false; throw e; }
    if (!st.isFile()) throw new Error(`${kept} is not a regular file: look at it, remove it, and run again`);
    return true;
  };
  const finish = () => {
    if (keptThere()) fsx.unlinkSync(kept);
    writeKeyFile(kept, old, fsx);                               // (O_EXCL, 0600: the old key is never destroyed, only renamed over)
    fsx.renameSync(next, file);
    syncDir(path.dirname(file), fsx);
  };
  // an .old that still opens a stored secret (a database restored from a backup made before the last rotation) is the only key of that secret: never replaced.  (An .old
  // with the key of the file itself is the copy an unfinished run made; one that is not a key opens nothing.)
  if (keptThere()) {
    let prev = null;
    try {
      prev = readKeyFile(kept, fsx, uid);
    } catch (e) {
      if (!e.badKey) throw new Error(`${e.message} (look at it, move it aside, and run again)`);
    }
    if (prev && !prev.equals(old)) {
      const n = (await backend.tx({}, (tx) => S.totpSecrets(tx))).filter((r) => unwrapSecret(prev, r.principal_id, r.totp_secret) !== null).length;
      if (n) throw new Error(`${n} stored TOTP secret(s) still need the old key in ${kept} (a database restored from a backup made before the last rotation?), so it is not replaced: move ${kept} aside only when you are sure those secrets are not needed, and run again`);
    }
  }
  let pending = null;
  try {
    pending = readKeyFile(next, fsx, uid);
  } catch (e) {
    if (!e.badKey && e.code !== 'ENOENT') throw new Error(`${e.message} (an earlier --rotate-totp-key left it? look at it, remove it, and run again)`);
    if (e.badKey) fsx.unlinkSync(next);
  }
  if (pending) {
    const rows = await backend.tx({}, (tx) => S.totpSecrets(tx));
    if (rows.some((r) => unwrapSecret(pending, r.principal_id, r.totp_secret) !== null)) {
      const r = await rewrapAll(backend, old, pending);
      finish();
      return { ...r, finished: true, old: kept };
    }
    fsx.unlinkSync(next);
  }
  const key = crypto.randomBytes(32);
  writeKeyFile(next, key, fsx);
  syncDir(path.dirname(file), fsx);
  // (a failure leaves .new where it is: whether the commit happened is what the next run looks at, never a guess made here)
  const r = await rewrapAll(backend, old, key);
  finish();
  return { ...r, finished: false, old: kept };
}

const FALLBACK_TYPES =['A', 'AAAA', 'AFSDB', 'CAA', 'CNAME', 'DNAME', 'DS', 'HINFO', 'HTTPS', 'LOC', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI'];

// karidns-webadmin --create-admin NAME: a user with a global_master grant and the policy "all-types" (every type karidns-zone's change file takes), a
// password made here and printed once.  -> { name, password, created: { principal, policy } }
export async function createAdmin(config, name, backend, { run, scryptLn = config.settings['scrypt-ln'] } = {}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,254}$/.test(name)) throw new Error('the name may have letters, digits and . _ @ + : - (not first)');
  let types = FALLBACK_TYPES;
  if (run) {
    const r = await run(config.settings['karidns-zone'], ['--types-list'], { timeoutMs: 10000, maxOutput: 1 << 16 });
    const list = r.code === 0 ? r.stdout.split(/\r?\n/).map((t) => t.trim().toUpperCase()).filter((t) => /^[A-Z][A-Z0-9]*$/.test(t)) : [];
    if (list.length) types = [...new Set(list)].sort();
  }
  const password = randomToken(15);
  const hash = await hashPassword(password, { ln: scryptLn });
  const now = Date.now();
  const made = await backend.tx({ write: true }, async (tx) => {
    if (await S.principalByName(tx, name)) throw new Error(`a principal named ${name} exists already`);
    const row = await tx.get(`SELECT id FROM ${tx.A}rr_policies WHERE name = 'all-types'`);
    const policy = row ? row.id : await S.createPolicy(tx, { name: 'all-types', allowed_types: types, allow_wildcard: true, allow_delegation: true, allow_dname: true, apex_editable: true, ttl_min: 0, ttl_max: 2147483647, max_rr: null }, null);
    const principal = await S.createPrincipal(tx, { kind: 'user', name, display_name: 'administrator', createdBy: null });
    await S.setPassword(tx, principal, hash, now);
    await S.createGrant(tx, { principalId: principal, role: 'global_master', schema: null, zone: null, suffix: null, policyId: policy, grantedBy: null });
    return { principal, policy };
  });
  return { name, password, created: made };
}

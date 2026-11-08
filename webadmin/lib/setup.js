// Opening the database, the checks of `--check` and of the start (planning 4.3, 9), and `--create-admin`.

import fs from 'node:fs';
import { validate } from './config.js';
import { checkConninfoFile, parseConninfo } from '../../node/lib/conf.js';
import { loadSqlite } from '../../node/lib/sqlite.js';
import { clip } from '../../node/lib/run.js';
import { SqliteBackend, PgBackend } from './db.js';
import * as S from './store.js';
import { hashPassword, randomToken } from './crypto.js';
import { typesArgv } from './tools.js';

const PROGRAM = 'karidns-webadmin';

// the tables the API relies on: the auth tables (schema version 3, with the tables of items D and E) and the zone data tables of a dataset
export const AUTH_TABLES = ['auth.principals', 'auth.credentials', 'auth.memberships', 'auth.principal_closure', 'auth.rr_policies', 'auth.grants', 'auth.sessions',
  'auth.api_tokens', 'auth.templates', 'auth.template_records', 'auth.schema_version'];
export const DATA_TABLES = ['domains', 'records', 'domainmetadata', 'cryptokeys', 'karidns_schema_version', 'karidns_zone_state', 'karidns_zone_versions', 'karidns_zone_version_rrsets',
  'karidns_domain_views', 'karidns_signer_state', 'karidns_key_requests', 'karidns_record_tags', 'karidns_record_tinydns', 'karidns_zone_tagdefs'];

// -> a backend, opened.  conninfoFile overrides the file of the configuration (--create-admin uses a trusted role of its own).
export async function openBackend(config, { conninfoFile, importPg = () => import('pg'), importSqlite = loadSqlite, readFile = fs.readFileSync, checkConninfo = checkConninfoFile, onError } = {}) {
  const s = config.settings;
  if (s.database === 'sqlite3') {
    const b = new SqliteBackend({ sqlite: await importSqlite(), file: s['sqlite-file'], authFile: s['auth-file'] });
    b.open();
    return b;
  }
  const file = conninfoFile ?? s['api-conninfo-file'];
  const problem = checkConninfo(file, undefined, undefined, PROGRAM);
  if (problem) throw new Error(problem);
  const mod = await importPg();
  const b = new PgBackend({ pg: mod.Pool ? mod : mod.default, conn: parseConninfo(readFile(file, 'utf8'), PROGRAM), poolMax: Math.max(4, config.settings.workers * 2), onError });
  await b.open();
  return b;
}

const firstLine = (r) => (r.stdout || r.stderr).trim().split(/\r?\n/)[0] ?? '';

// What the start and --check look at.  -> { problems, notes, versions }.  backend: an opened backend (its schema is checked) or undefined.
export async function inspect(config, { backend, run, st = {}, uid = process.getuid?.() } = {}) {
  const s = config.settings;
  const problems = validate(config);
  const notes = [];
  const versions = {};
  let types = null;                         // the record types karidns-zone's change file takes (its own list, planning 8.1)
  if (problems.length) return { problems, notes, versions, types };

  const checkFile = (what, file, stat) => {
    const p = checkConninfoFile(file, stat, uid, PROGRAM);
    if (p) problems.push(`${what}: ${p}`);
    else notes.push(`${what} ${file}: fine`);
  };
  if (s.database === 'pg') {
    checkFile('api-conninfo-file', s['api-conninfo-file'], st.api);
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
  try {
    const st2 = fs.lstatSync(s['totp-key-file']);
    if (uid !== undefined && (st2.mode & 0o077) !== 0) problems.push(`totp-key-file ${s['totp-key-file']} has mode ${(st2.mode & 0o777).toString(8).padStart(4, '0')}: it must be 0600`);
    else notes.push(`totp-key-file ${s['totp-key-file']}: fine`);
  } catch (e) {
    if (e.code === 'ENOENT') notes.push(`totp-key-file ${s['totp-key-file']}: not there yet, it is made at the first start`);
    else problems.push(`totp-key-file ${s['totp-key-file']}: ${e.code ?? e.message}`);
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
        else if (r.missing.length) problems.push(`dataset ${d.name}: missing tables: ${r.missing.join(', ')}`);
        else notes.push(`dataset ${d.name}: schema version 3, all tables there`);
      }
    } catch (e) {
      problems.push(`the database: ${e.message}`);
    }
  }
  return { problems, notes, versions, types };
}

const FALLBACK_TYPES = ['A', 'AAAA', 'AFSDB', 'CAA', 'CNAME', 'DNAME', 'DS', 'HINFO', 'HTTPS', 'LOC', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI'];

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

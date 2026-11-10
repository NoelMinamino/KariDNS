// A whole deployment for the tests: a SQLite3 zone file and auth file made from the SQL files of the repository, the App on them, and the HTTP server on a
// port of 127.0.0.1.  The password hashes are cheap here (scrypt-ln 14, the lowest the configuration takes).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadSqlite } from '../../node/lib/sqlite.js';
import { createLogger } from '../../node/lib/log.js';
import { runChild } from '../../node/lib/run.js';
import { parseConfig } from '../lib/config.js';
import { App } from '../lib/app.js';
import { SqliteBackend } from '../lib/db.js';
import { Router, listen, closeServer } from '../lib/http.js';
import { ROUTES } from '../lib/routes.js';
import { hashPassword } from '../lib/crypto.js';
import * as S from '../lib/store.js';

export const ROOT = new URL('../../', import.meta.url);
const sqlOf = (rel) => fs.readFileSync(new URL(rel, ROOT), 'utf8');
export const sqlite = await loadSqlite();
export const ORIGIN = 'http://127.0.0.1:8053';

export const rmDir = (d) => { try { fs.rmSync(d, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 }); } catch { /* Windows keeps files open a little longer */ } };

export const memLog = () => {
  const lines = [];
  return { lines, info: (m) => lines.push(`info ${m}`), warn: (m) => lines.push(`warn ${m}`), error: (m) => lines.push(`error ${m}`), close: () => {} };
};

export const ZONE = `
INSERT INTO domains (name, type) VALUES ('example.test', 'NATIVE'), ('other.test', 'NATIVE'), ('slave.test', 'SLAVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) VALUES
 (1, 'example.test', 'SOA', 'ns1.example.test hostmaster.example.test 10 7200 3600 1209600 300', 3600, 0, 0),
 (1, 'example.test', 'NS', 'ns1.example.test', 3600, 0, 0),
 (1, 'ns1.example.test', 'A', '192.0.2.1', 3600, 0, 0),
 (1, 'www.example.test', 'A', '192.0.2.10', 300, 0, 0),
 (1, 'www.example.test', 'A', '192.0.2.11', 300, 0, 0),
 (1, 'example.test', 'MX', 'mail.example.test', 3600, 10, 0),
 (1, 'sub.example.test', 'A', '192.0.2.20', 300, 0, 0),
 (1, 'a.sub.example.test', 'TXT', '"hello"', 300, 0, 0),
 (1, 'evilsub.example.test', 'A', '192.0.2.30', 300, 0, 0),
 (1, 'off.example.test', 'A', '192.0.2.40', 300, 0, 1),
 (2, 'other.test', 'SOA', 'ns1.other.test hostmaster.other.test 5 7200 3600 1209600 300', 3600, 0, 0),
 (2, 'other.test', 'NS', 'ns1.other.test', 3600, 0, 0),
 (2, 'www.other.test', 'A', '198.51.100.1', 300, 0, 0);
INSERT INTO domainmetadata (domain_id, kind, content) VALUES (2, 'PRESIGNED', '1');
`;

// the configuration text of a test deployment
export const confText = (dir, settings = {}) => {
  const s = {
    listen: '127.0.0.1:8053',
    'public-origin': ORIGIN,
    database: 'sqlite3',
    'sqlite-file': path.join(dir, 'zones.sqlite3'),
    'auth-file': path.join(dir, 'auth.sqlite3'),
    'totp-key-file': path.join(dir, 'totp.key'),
    'karidns-zone': path.join(dir, 'no-karidns-zone'),
    'scrypt-ln': 14,
    'require-totp': 'none',
    'rate-login': 1000,
    'rate-api': 1000,
    'rate-write': 1000,
    ...settings,
  };
  return Object.entries(s).map(([k, v]) => `${k} = ${v}`).join('\n');
};

// The two files are made once per process (the SQL is slow to apply: triggers, fsync) and copied for every deployment.
let template;
export function makeFiles(dir) {
  if (!template) {
    template = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-template-'));
    const z = new sqlite.DatabaseSync(path.join(template, 'zones.sqlite3'));
    for (const f of ['tests/db/pdns_schema.sqlite3.sql', 'db/karidns_ext.sqlite3.sql', 'db/karidns_audit.sqlite3.sql']) z.exec(sqlOf(f));
    z.exec(ZONE);
    z.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    z.close();
    const a = new sqlite.DatabaseSync(path.join(template, 'auth.sqlite3'));
    a.exec(sqlOf('db/karidns_auth.sqlite3.sql'));
    a.close();
    process.on('exit', () => { try { fs.rmSync(template, { recursive: true, force: true }); } catch { /* left in the temporary directory */ } });
  }
  for (const f of ['zones.sqlite3', 'auth.sqlite3']) fs.copyFileSync(path.join(template, f), path.join(dir, f));
}

// A running deployment: { app, backend, server, base, dir, request(), login(), close() }.  settings: more (or other) lines of the configuration; now: a clock.
export async function deploy({ settings, now, run = runChild, key = Buffer.alloc(32, 7), ui = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-'));
  makeFiles(dir);
  const config = parseConfig(confText(dir, settings));
  config.settings.listen = '127.0.0.1:0';                       // any free port (the file format takes 1 to 65535)
  config.settings['scrypt-ln'] = 10;                         // the file format takes 14 to 20; 10 is enough to test with
  const backend = new SqliteBackend({ sqlite, file: config.settings['sqlite-file'], authFile: config.settings['auth-file'] });
  backend.open();
  const log = memLog();
  const app = new App({ config, backend, log, run, key, now, ui });
  const server = await listen(app, new Router(ROUTES));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const base = `${origin}/api/v1`;
  const d = { app, backend, server, base, origin, dir, log, config };

  // fetch with JSON in and out: -> { status, headers, body (parsed JSON, or text for text/plain), text }
  d.request = async (method, p, { body, cookie, token, csrf, origin, headers = {}, raw } = {}) => {
    const h = { ...headers };
    if (cookie) h.Cookie = `karidns_session=${cookie}`;
    if (token) h.Authorization = `Bearer ${token}`;
    if (csrf) h['X-KariDNS-CSRF'] = csrf;
    if (origin) h.Origin = origin;
    let payload;
    if (raw !== undefined) payload = raw;
    else if (body !== undefined) { payload = JSON.stringify(body); h['Content-Type'] = 'application/json'; }
    const res = await fetch(base + p, { method, headers: h, body: payload });
    const text = await res.text();
    let parsed = text;
    if (/json/.test(res.headers.get('content-type') ?? '')) parsed = JSON.parse(text);
    return { status: res.status, headers: res.headers, body: parsed, text };
  };

  // a user with a password (and grants, if given) made straight in the database; -> its id
  d.makeUser = async (name, password, { kind = 'user', grants = [], disabled = false } = {}) => {
    const hash = password ? await hashPassword(password, { ln: 10 }) : null;
    return backend.tx({ write: true }, async (tx) => {
      const id = await S.createPrincipal(tx, { kind, name, disabled });
      if (hash) await S.setPassword(tx, id, hash, Date.now());
      for (const g of grants) await S.createGrant(tx, { principalId: id, grantedBy: null, schema: null, zone: null, suffix: null, ...g });
      return id;
    });
  };
  d.makePolicy = (p) => backend.tx({ write: true }, (tx) => S.createPolicy(tx, {
    name: 'p', allowed_types: ['A'], allow_wildcard: false, allow_delegation: false, allow_dname: false, apex_editable: false, ttl_min: 0, ttl_max: 2147483647, max_rr: null, ...p,
  }, null));

  // log in; -> { cookie, csrf, status, body }
  d.login = async (user, password, extraBody = {}) => {
    const r = await d.request('POST', '/auth/login', { body: { user, password, ...extraBody } });
    const m = /karidns_session=([^;]+)/.exec(r.headers.get('set-cookie') ?? '');
    return { status: r.status, body: r.body, cookie: m?.[1], csrf: r.body?.csrf };
  };
  // a request with a session
  d.as = (s) => (method, p, o = {}) => d.request(method, p, { cookie: s.cookie, csrf: s.csrf, origin: ORIGIN, ...o });
  d.close = async () => {
    await closeServer(server);
    await app.drain();
    backend.close();
    rmDir(dir);
  };
  return d;
}

// ---- a scripted karidns-zone / karictl: `run` has the shape of node/lib/run.js runChild; fn(call, n) -> a result (see ok(), exit()); the calls are recorded
export const exit = (code, over = {}) => ({ code, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false, spawnError: null, ...over });
export const ok = (doc) => exit(0, { stdout: JSON.stringify(doc) });
export function makeRun(fn) {
  const calls = [];
  const run = async (file, argv, opts = {}) => {
    const call = { file, argv: [...argv], input: opts.input, opts };
    calls.push(call);
    return fn(call, calls.length);
  };
  return { run, calls };
}

// the document of `karidns-zone --json apply` (docs/karidns-zone.md); over.apply overrides the keys of "apply"
export const applyDoc = (over = {}) => ({
  'karidns-zone': 1, version: '0.6.0', command: 'apply', result: 'ok', counts: { error: 0, warning: 0, checked: 1, skipped: 0, dropped: 0 }, truncated: false,
  messages: over.messages ?? [], zones: [],
  apply: {
    zone: 'example.test.', dry_run: true, committed: false, changed: false, busy: false, created: false, generation: 7, generation_after: 7, serial: { before: 10, after: 11 },
    serial_bumped: true, version: 2, delta_complete: true, records_before: 9, records_after: 9, warnings: 0, diff: [], ...over.apply,
  },
});
export const entry = (owner, type, before, after) => ({ owner, type, change: before === null ? 'add' : after === null ? 'delete' : 'replace', before, after });

// the standard cast: root (global master), a domain master of example.test, a subdomain master of sub.example.test
export async function cast(d) {
  const all = await d.makePolicy({ name: 'all', allowed_types: ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'SRV', 'DNAME'], allow_wildcard: true, allow_delegation: true, allow_dname: true, apex_editable: true });
  const web = await d.makePolicy({ name: 'web', allowed_types: ['A', 'AAAA', 'CNAME', 'TXT'], ttl_min: 60, ttl_max: 86400 });
  const root = await d.makeUser('root', 'correct horse battery', { grants: [{ role: 'global_master', policyId: all }] });
  const dom = await d.makeUser('dom', 'dom password 12345', { grants: [{ role: 'domain_master', zone: 'example.test', policyId: web, schema: '' }] });
  const sub = await d.makeUser('sub', 'sub password 12345', { grants: [{ role: 'subdomain_master', zone: 'example.test', suffix: 'sub.example.test', policyId: web, schema: '' }] });
  return { all, web, root, dom, sub };
}

// the error codes of the table in docs/karidns-api.md (a code is a word in backticks at the start of an entry: the explanations in parentheses may name other things in
// backticks), for docs.test.js and for the catalogs of the GUI (i18n.test.js)
export function docApiCodes() {
  const text = fs.readFileSync(new URL('docs/karidns-api.md', ROOT), 'utf8');
  const table = text.slice(text.indexOf('| Status | Codes |'), text.indexOf('## ENDPOINTS'));
  if (table.length < 100) throw new Error('the table of codes was not found');
  const out = new Set();
  for (const row of table.split('\n').filter((l) => /^\| \d/.test(l))) {
    const cell = row.split('|')[2];
    for (const entry of cell.replace(/\([^)]*\)/g, '').split(/[,;:]/)) {
      const m = /^\s*`([a-z]+(?:-[a-z]+)*)`\s*$/.exec(entry);
      if (m) out.add(m[1]);
    }
  }
  return out;
}

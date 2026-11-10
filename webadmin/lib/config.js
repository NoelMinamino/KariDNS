// The configuration file of karidns-webadmin (planning 9): lines `key = value`, `#` comments, `[dataset <name>]` sections.  The same format as the signer's;
// the value parsers are the shared ones (node/lib/conf.js).  parseConfig() is pure (text in, object out); loadConfig() reads the file.

import fs from 'node:fs';
import os from 'node:os';
import { parseBool, parseDuration, parseInt1, parseEnum, parseAbsPath, parseSchema, parseLog } from '../../node/lib/conf.js';

const parseListen = (v) => {
  if (v.startsWith('/')) return parseAbsPath(v);
  const m = /^(?:\[([0-9a-fA-F:.]+)\]|([A-Za-z0-9.-]+)):(\d{1,5})$/.exec(v);
  if (!m || Number(m[3]) < 1 || Number(m[3]) > 65535) throw new Error(`expected host:port, [ipv6]:port or the absolute path of a UNIX socket, got ${JSON.stringify(v)}`);
  return v;
};

// scheme://host[:port], no path: the value of the Origin header a browser sends for the page
const parseOrigin = (v) => {
  let u;
  try { u = new URL(v); } catch { throw new Error(`expected an origin like https://dns.example.test, got ${JSON.stringify(v)}`); }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.origin !== v) throw new Error(`expected an origin like https://dns.example.test (scheme, host and port only), got ${JSON.stringify(v)}`);
  return v;
};

// IP addresses, and `local`: the peer of a UNIX socket (it has no address; a proxy that connects to `listen = /path/to/socket` is trusted by naming it)
const parseAddresses = (v) => {
  const out = v.split(',').map((s) => s.trim()).filter(Boolean);
  for (const a of out) if (a !== 'local' && !/^[0-9a-fA-F:.]+$/.test(a)) throw new Error(`expected a list of IP addresses (or local, for a UNIX socket), got ${JSON.stringify(a)}`);
  return out;
};

const parseNames = (v) => {
  const out = v.split(',').map((s) => s.trim()).filter(Boolean);
  for (const a of out) if (!/^[A-Za-z0-9_-]{1,64}$/.test(a)) throw new Error(`expected a list of names, got ${JSON.stringify(a)}`);
  return out;
};

const parseScryptLn = (v) => {
  const n = parseInt1(v);
  if (n < 14 || n > 20) throw new Error('expected 14 to 20 (the cost of a password hash is 2^n; 17 is the default)');
  return n;
};

const GLOBAL_KEYS = {
  listen: parseListen,
  'tls-cert': parseAbsPath,
  'tls-key': parseAbsPath,
  'public-origin': parseOrigin,
  'trusted-proxy': parseAddresses,
  database: parseEnum('pg', 'sqlite3'),
  'api-conninfo-file': parseAbsPath,
  'check-conninfo-file': parseAbsPath,
  'sqlite-file': parseAbsPath,
  'auth-file': parseAbsPath,
  'karidns-zone': parseAbsPath,
  karicheck: parseAbsPath,
  karictl: parseAbsPath,
  'karictl-config': parseAbsPath,
  workers: parseInt1,
  'reload-after-change': parseBool,
  'require-totp': parseEnum('global', 'all', 'none'),
  'session-idle': parseDuration,
  'session-max': parseDuration,
  'totp-key-file': parseAbsPath,
  'rate-login': parseInt1,
  'rate-api': parseInt1,
  'rate-write': parseInt1,
  'scrypt-ln': parseScryptLn,
  ui: parseBool,
  'ui-dir': parseAbsPath,
  log: parseLog,
};

const DATASET_KEYS = { schema: parseSchema, views: parseNames };

// [oidc <name>] (item F, milestone M5): one OpenID Connect provider.  The issuer is compared with the `iss` claim as a string, so it is kept exactly as written.
const parseIssuer = (v) => {
  let u;
  try { u = new URL(v); } catch { throw new Error(`expected the issuer identifier, an https URL, got ${JSON.stringify(v)}`); }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.search || u.hash || u.username || u.password || v.includes('#') || v.includes('?') || v.length > 255) {
    throw new Error(`expected an https URL without a query, a fragment or credentials, got ${JSON.stringify(v)}`);
  }
  return v;
};
// RFC 6749 section 3.3: a scope token is printable ASCII without space, double quote and backslash
const parseScopes = (v) => {
  const out = v.split(/[\s,]+/).filter(Boolean);
  if (out.length === 0 || out.length > 16 || out.some((s) => !/^[\x21\x23-\x5b\x5d-\x7e]{1,64}$/.test(s))) throw new Error(`expected up to 16 scope names separated by spaces, got ${JSON.stringify(v)}`);
  return out;
};
const parseLabel = (v) => {
  if (v.length === 0 || [...v].length > 64 || /[\0-\x1f\x7f-\x9f]/.test(v)) throw new Error('expected 1 to 64 characters without control characters');
  return v;
};
const parseClientId = (v) => {
  if (v.length === 0 || v.length > 255 || /[^\x21-\x7e]/.test(v)) throw new Error('expected the client id: printable ASCII without spaces, at most 255 characters');
  return v;
};
const OIDC_KEYS = { issuer: parseIssuer, 'client-id': parseClientId, 'client-secret-file': parseAbsPath, scopes: parseScopes, label: parseLabel, mfa: parseEnum('totp', 'idp') };

export function defaults() {
  return {
    listen: undefined,
    'tls-cert': undefined,
    'tls-key': undefined,
    'public-origin': undefined,
    'trusted-proxy': [],
    database: undefined,
    'api-conninfo-file': undefined,
    'check-conninfo-file': undefined,
    'sqlite-file': undefined,
    'auth-file': undefined,
    'karidns-zone': '/usr/local/bin/karidns-zone',
    karicheck: '/usr/local/bin/karicheck',
    karictl: '/usr/local/bin/karictl',
    'karictl-config': undefined,
    workers: Math.max(1, Math.min(4, os.cpus().length)),
    'reload-after-change': false,
    'require-totp': 'global',
    'session-idle': 1800,
    'session-max': 12 * 3600,
    'totp-key-file': '/var/db/karidns-webadmin/totp.key',
    'rate-login': 5,
    'rate-api': 20,
    'rate-write': 2,
    'scrypt-ln': 17,
    ui: true,
    'ui-dir': undefined,
    log: 'stderr',
  };
}

// text -> { settings, datasets: Map(name -> { schema, views }), oidc: Map(name -> { issuer, client-id, client-secret-file, scopes, label, mfa }) }; throws Error("line N: ...")
// on the first mistake.  validate() checks what the whole must satisfy.
export function parseConfig(text) {
  const settings = defaults();
  const datasets = new Map();
  const oidc = new Map();
  let section = null;
  const seen = new Set();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const where = `line ${i + 1}`;
    const line = lines[i].trim();
    if (line === '' || line.startsWith('#')) continue;
    let m = /^\[\s*dataset\s+(\S+)\s*\]$/i.exec(line);
    if (m) {
      if (!/^[a-z][a-z0-9_-]{0,31}$/.test(m[1])) throw new Error(`${where}: a dataset name is 1 to 32 characters: lower case letters, digits, '-' and '_', starting with a letter`);
      if (datasets.has(m[1])) throw new Error(`${where}: dataset section '${m[1]}' appears twice`);
      section = { name: m[1], schema: undefined, views: [], seen: new Set(), table: DATASET_KEYS };
      datasets.set(m[1], section);
      continue;
    }
    m = /^\[\s*oidc\s+(\S+)\s*\]$/i.exec(line);
    if (m) {
      if (!/^[a-z][a-z0-9_-]{0,31}$/.test(m[1])) throw new Error(`${where}: a provider name is 1 to 32 characters: lower case letters, digits, '-' and '_', starting with a letter`);
      if (oidc.has(m[1])) throw new Error(`${where}: oidc section '${m[1]}' appears twice`);
      section = { name: m[1], issuer: undefined, 'client-id': undefined, 'client-secret-file': undefined, scopes: ['openid'], label: m[1], mfa: 'totp', seen: new Set(), table: OIDC_KEYS, oidc: true };
      oidc.set(m[1], section);
      continue;
    }
    if (line.startsWith('[')) throw new Error(`${where}: expected [dataset <name>] or [oidc <name>]`);
    m = /^([A-Za-z0-9-]+)\s*=\s*(.*)$/.exec(line);
    if (!m) throw new Error(`${where}: expected 'key = value'`);
    const key = m[1].toLowerCase();
    let value = m[2].trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '');
    const table = section ? section.table : GLOBAL_KEYS;
    const fn = table[key];
    if (!fn) throw new Error(`${where}: unknown option '${key}'${section ? ` in [${section.oidc ? 'oidc' : 'dataset'} ${section.name}]` : ''}`);
    const seenKeys = section ? section.seen : seen;
    if (seenKeys.has(key)) throw new Error(`${where}: '${key}' is set twice`);
    seenKeys.add(key);
    let v;
    try { v = fn(value); } catch (e) { throw new Error(`${where}: ${key}: ${e.message}`); }
    if (section) section[key] = v;
    else settings[key] = v;
  }
  for (const d of [...datasets.values(), ...oidc.values()]) { delete d.seen; delete d.table; delete d.oidc; }
  return { settings, datasets, oidc };
}

const isLoopbackHost = (h) => h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '[::1]' || /^127\.\d+\.\d+\.\d+$/.test(h);

// the host of a `listen` value: null for a UNIX socket
export function listenHost(listen) {
  if (listen.startsWith('/')) return null;
  const m = /^(?:\[(.*)\]|(.*)):\d+$/.exec(listen);
  return m[1] ?? m[2];
}

// -> the list of problems (empty when fine)
export function validate(cfg) {
  const s = cfg.settings;
  const problems = [];
  if (!s.listen) problems.push("'listen' is not set (127.0.0.1:8053, say, or the absolute path of a UNIX socket)");
  if (!s['public-origin']) problems.push("'public-origin' is not set (the origin a browser sees: https://dns.example.test)");
  if (s.workers < 1 || s.workers > 64) problems.push('workers must be 1 to 64');
  if (s['session-idle'] < 1) problems.push('session-idle must be at least 1 second');
  if (s['session-max'] < s['session-idle']) problems.push('session-max must not be shorter than session-idle');
  if (Boolean(s['tls-cert']) !== Boolean(s['tls-key'])) problems.push("'tls-cert' and 'tls-key' go together");
  if (s['ui-dir'] && !s.ui) problems.push("'ui-dir' names the files of the GUI, and ui = no switches the GUI off");
  if (s.listen) {
    const host = listenHost(s.listen);
    if (host !== null && !isLoopbackHost(host) && !s['tls-cert']) problems.push(`listen ${s.listen} is not a loopback address: plain HTTP is only allowed on 127.0.0.1, ::1 or a UNIX socket (put a TLS proxy in front, or set tls-cert and tls-key)`);
  }
  if (s['public-origin']) {
    const u = new URL(s['public-origin']);
    if (u.protocol === 'http:' && !isLoopbackHost(u.hostname)) problems.push('public-origin must be an https origin (http is only for localhost)');
  }
  if (!s.database) problems.push("'database' is not set (pg or sqlite3)");
  else if (s.database === 'pg') {
    if (!s['api-conninfo-file']) problems.push("database = pg needs 'api-conninfo-file' (the connection of the role karidns_api)");
    if (!s['check-conninfo-file']) problems.push("database = pg needs 'check-conninfo-file' (the connection of the check role: it reads a whole zone for the export and the dry runs)");
    if (s['sqlite-file'] || s['auth-file']) problems.push("'sqlite-file' and 'auth-file' are for database = sqlite3");
  } else {
    if (!s['sqlite-file']) problems.push("database = sqlite3 needs 'sqlite-file'");
    if (!s['auth-file']) problems.push("database = sqlite3 needs 'auth-file' (the file with the users and grants: db/karidns_auth.sqlite3.sql)");
    if (s['api-conninfo-file'] || s['check-conninfo-file']) problems.push("'api-conninfo-file' and 'check-conninfo-file' are for database = pg");
    if (s['reload-after-change'] && !s['karictl-config']) problems.push("reload-after-change = yes needs 'karictl-config' on SQLite3 (a SQLite3 database has no reload requests: the API runs `karictl reload <zone>` with a restricted control key)");
    if (cfg.datasets.size) problems.push('database = sqlite3 has one dataset (main): there are no [dataset] sections');
  }
  for (const d of cfg.datasets.values()) if (!d.schema) problems.push(`[dataset ${d.name}] needs 'schema'`);
  const issuers = new Map();
  for (const o of cfg.oidc?.values() ?? []) {
    for (const k of ['issuer', 'client-id', 'client-secret-file']) if (!o[k]) problems.push(`[oidc ${o.name}] needs '${k}'`);
    if (o.issuer) {
      const u = new URL(o.issuer);
      if (u.protocol === 'http:' && !isLoopbackHost(u.hostname)) problems.push(`[oidc ${o.name}] issuer must be an https URL (http is only for a provider on this machine: localhost, 127.0.0.1, ::1)`);
      if (issuers.has(o.issuer)) problems.push(`[oidc ${o.name}] has the issuer of [oidc ${issuers.get(o.issuer)}]: an identity is linked to an issuer, so a provider may be configured once`);
      else issuers.set(o.issuer, o.name);
    }
  }
  if (cfg.oidc?.size > 8) problems.push('at most 8 [oidc] sections');
  return problems;
}

// the datasets as the API uses them: [{ name, schema, views }]; schema is '' for SQLite3 (the grants' data_schema there)
export function datasetList(cfg) {
  if (cfg.settings.database === 'sqlite3') return [{ name: 'main', schema: '', views: [] }];
  if (cfg.datasets.size === 0) return [{ name: 'main', schema: 'public', views: [] }];
  return [...cfg.datasets.values()].map((d) => ({ name: d.name, schema: d.schema, views: d.views }));
}

export function loadConfig(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    throw new Error(`cannot read ${file}: ${e.message}`);
  }
  return parseConfig(text);
}

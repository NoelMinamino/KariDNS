// The configuration file of karidns-signer (planning 3.8): lines `key = value`, `#` comments, `[zone <name>]` sections for per-zone values.
// Parsed here, no dependency.  parseConfig() is pure (text in, object out); loadConfig() reads the file; checkConninfoFile() is the permission check
// the loader and karidns-zone apply to a conninfo file (a regular file owned by the user, mode 0600 or 0400).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalZone } from './names.js';

const DAY = 86400;

const parseBool = (v) => {
  const s = v.toLowerCase();
  if (s === 'yes' || s === 'true' || s === 'on' || s === '1') return true;
  if (s === 'no' || s === 'false' || s === 'off' || s === '0') return false;
  throw new Error(`expected yes or no, got ${JSON.stringify(v)}`);
};

// A duration in seconds: digits and an optional unit s, m, h, d, w (a bare number is seconds).
export function parseDuration(v) {
  const m = /^(\d{1,9})([smhdw]?)$/.exec(v);
  if (!m) throw new Error(`expected a duration like 90, 30m, 14d, got ${JSON.stringify(v)}`);
  const unit = { '': 1, s: 1, m: 60, h: 3600, d: DAY, w: 7 * DAY }[m[2]];
  return Number(m[1]) * unit;
}

const parseInt1 = (v) => {
  if (!/^\d{1,4}$/.test(v)) throw new Error(`expected a number, got ${JSON.stringify(v)}`);
  return Number(v);
};

const parseEnum = (...values) => (v) => {
  const s = v.toLowerCase();
  if (!values.includes(s)) throw new Error(`expected one of ${values.join(', ')}, got ${JSON.stringify(v)}`);
  return s;
};

const parseText = (v) => {
  if (v.length === 0 || v.length > 1024 || /[\0-\x1f\x7f]/.test(v)) throw new Error('expected a non-empty string without control characters');
  return v;
};

const parseAbsPath = (v) => {
  parseText(v);
  if (!path.isAbsolute(v)) throw new Error(`expected an absolute path, got ${JSON.stringify(v)}`);
  return v;
};

const parseSchema = (v) => {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(v)) throw new Error(`expected a schema name (letters, digits, underscore), got ${JSON.stringify(v)}`);
  return v;
};

const parseLog = (v) => {
  const s = v.toLowerCase();
  if (s === 'stderr') return 'stderr';
  if (/^(kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|local[0-7])$/.test(s)) return s;
  throw new Error(`expected stderr or a syslog facility (daemon, local0 ... local7, ...), got ${JSON.stringify(v)}`);
};

// the keys that can also be set per zone
const ZONE_KEYS = {
  validity: parseDuration,
  refresh: parseDuration,
  jitter: parseDuration,
  verify: parseBool,
  'nsec3-opt-out': parseBool,
};

const GLOBAL_KEYS = {
  ...ZONE_KEYS,
  database: parseEnum('pg', 'sqlite3'),
  'conninfo-file': parseAbsPath,
  'sqlite-file': parseAbsPath,
  schema: parseSchema,
  'work-dir': parseAbsPath,
  workers: parseInt1,
  'karidns-zone': parseAbsPath,
  karicheck: parseAbsPath,
  'bind-tools': parseAbsPath,
  karictl: parseAbsPath,
  'karictl-config': parseAbsPath,
  'karictl-socket': parseAbsPath,
  debounce: parseDuration,
  timeout: parseDuration,
  log: parseLog,
};

export function defaults() {
  return {
    database: undefined,
    'conninfo-file': undefined,
    'sqlite-file': undefined,
    schema: undefined,
    'work-dir': '/var/db/karidns-signer/work',
    workers: Math.max(1, Math.floor(os.cpus().length / 2)),
    'karidns-zone': '/usr/local/bin/karidns-zone',
    karicheck: '/usr/local/bin/karicheck',
    'bind-tools': '/usr/local/bin',
    karictl: '/usr/local/bin/karictl',
    'karictl-config': undefined,
    'karictl-socket': undefined,
    validity: 14 * DAY,
    refresh: Math.floor(3.5 * DAY),
    jitter: DAY,
    verify: true,
    'nsec3-opt-out': false,
    debounce: 5,
    timeout: 1800,
    log: 'stderr',
  };
}

function parseValue(table, key, value, where) {
  const fn = table[key];
  if (!fn) throw new Error(`${where}: unknown option '${key}'`);
  try {
    return fn(value);
  } catch (e) {
    throw new Error(`${where}: ${key}: ${e.message}`);
  }
}

// text -> { settings (the defaults with the file's global values), zones: Map(zone name -> {key: value}) }; throws Error("line N: ...") on the first
// mistake.  Checks the values of the file only; validate() checks what the whole must satisfy.
export function parseConfig(text) {
  const settings = defaults();
  const zones = new Map();
  let section = null;                // null: global; else the Map of the zone's own values
  const seen = new Set();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const where = `line ${i + 1}`;
    const line = lines[i].trim();
    if (line === '' || line.startsWith('#')) continue;
    let m = /^\[\s*zone\s+(\S+)\s*\]$/i.exec(line);
    if (m) {
      let name;
      try { name = canonicalZone(m[1]); } catch (e) { throw new Error(`${where}: ${e.message}`); }
      if (zones.has(name)) throw new Error(`${where}: zone section '${name}' appears twice`);
      section = new Map();
      zones.set(name, section);
      continue;
    }
    if (line.startsWith('[')) throw new Error(`${where}: expected [zone <name>]`);
    m = /^([A-Za-z0-9-]+)\s*=\s*(.*)$/.exec(line);
    if (!m) throw new Error(`${where}: expected 'key = value'`);
    const key = m[1].toLowerCase();
    let value = m[2].trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '');
    if (section ? section.has(key) : seen.has(key)) throw new Error(`${where}: '${key}' is set twice`);
    if (!section) seen.add(key);
    const v = parseValue(section ? ZONE_KEYS : GLOBAL_KEYS, key, value, where);
    if (section) section.set(key, v);
    else settings[key] = v;
  }
  return { settings, zones };
}

// The settings of one zone: the global values with the zone's own on top; checked as a whole (a refresh interval must leave the signatures a life).
export function zoneSettings(cfg, zone) {
  const out = { ...cfg.settings };
  const own = cfg.zones.get(zone);
  if (own) for (const [k, v] of own) out[k] = v;
  if (out.refresh <= 0) throw new Error(`refresh must be more than 0${own ? ` (zone ${zone})` : ''}`);
  if (out.validity < 60) throw new Error(`validity must be at least 60 seconds${own ? ` (zone ${zone})` : ''}`);
  if (out.refresh + out.jitter >= out.validity) {
    throw new Error(`refresh (${out.refresh}s) plus jitter (${out.jitter}s) must be less than validity (${out.validity}s)${own ? ` (zone ${zone})` : ''}: otherwise every signature is due again at once`);
  }
  return out;
}

// What the whole configuration must satisfy (the daemon and --check call it).  Returns the list of problems (empty when fine).
export function validate(cfg) {
  const s = cfg.settings;
  const problems = [];
  if (s.workers < 1 || s.workers > 256) problems.push('workers must be 1 to 256');
  if (s.timeout < 10) problems.push('timeout must be at least 10 seconds');
  if (!s.database) problems.push("'database' is not set (pg or sqlite3)");
  else if (s.database === 'pg') {
    if (!s['conninfo-file']) problems.push("database = pg needs 'conninfo-file'");
    if (s['sqlite-file']) problems.push("'sqlite-file' is for database = sqlite3");
  } else {
    if (!s['sqlite-file']) problems.push("database = sqlite3 needs 'sqlite-file'");
    if (s['conninfo-file']) problems.push("'conninfo-file' is for database = pg");
    if (s.schema) problems.push("'schema' is for database = pg");
    if (!s['karictl-config']) problems.push("database = sqlite3 needs 'karictl-config': a SQLite3 database has no reload requests, the signer runs `karictl reload <zone>` with a restricted control key (allow-commands { reload-zone; })");
  }
  for (const zone of [undefined, ...cfg.zones.keys()]) {
    try { zoneSettings(cfg, zone); } catch (e) { problems.push(e.message); }
  }
  return problems;
}

export function loadConfig(path) {
  let text;
  try {
    text = fs.readFileSync(path, 'utf8');
  } catch (e) {
    throw new Error(`cannot read ${path}: ${e.message}`);
  }
  return parseConfig(text);
}

// The check karidns-zone and the loader apply to a conninfo file: a regular file (no symbolic link) owned by the user running us, mode 0600 or 0400.
// Returns null when fine, else the reason.
export function checkConninfoFile(path, st, uid = process.getuid?.()) {
  if (!st) {
    try { st = fs.lstatSync(path); } catch (e) { return `cannot read ${path}: ${e.code ?? e.message}`; }
  }
  if (!st.isFile()) return `${path} is not a regular file`;
  if (uid !== undefined && st.uid !== uid) return `${path} is not owned by the user running karidns-signer`;
  const mode = st.mode & 0o777;
  if (mode !== 0o600 && mode !== 0o400) return `${path} has mode ${mode.toString(8).padStart(4, '0')}, it must be 0600 or 0400`;
  return null;
}

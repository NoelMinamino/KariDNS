// The configuration file of karidns-signer (planning 3.8): lines `key = value`, `#` comments, `[zone <name>]` sections for per-zone values.
// Parsed here, no dependency.  parseConfig() is pure (text in, object out); loadConfig() reads the file; checkConninfoFile() is the permission check
// the loader and karidns-zone apply to a conninfo file (a regular file owned by the user, mode 0600 or 0400).

import fs from 'node:fs';
import os from 'node:os';
import { canonicalZone } from '../../node/lib/names.js';
import { parseBool, parseDuration, parseInt1, parseEnum, parseAbsPath, parseSchema, parseLog, checkConninfoFile as checkConninfo } from '../../node/lib/conf.js';

const DAY = 86400;

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

// The check karidns-zone and the loader apply to a conninfo file (node/lib/conf.js).  Returns null when fine, else the reason.
export const checkConninfoFile = (file, st, uid = process.getuid?.()) => checkConninfo(file, st, uid, 'karidns-signer');

// What the configuration files of karidns-signer and karidns-webadmin have in common (A-20: one copy, imported by both): the parsers of a value
// (a duration, a yes/no, a path, a schema name, a syslog facility), the connection file of a PostgreSQL database (parsed and checked the way karidns-zone and
// the loader do it), the check of such a file's mode, and the one read of a private file after that check.  No dependency.

import fs from 'node:fs';
import path from 'node:path';

const DAY = 86400;

export const parseBool = (v) => {
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

export const parseInt1 = (v) => {
  if (!/^\d{1,4}$/.test(v)) throw new Error(`expected a number, got ${JSON.stringify(v)}`);
  return Number(v);
};

export const parseEnum = (...values) => (v) => {
  const s = v.toLowerCase();
  if (!values.includes(s)) throw new Error(`expected one of ${values.join(', ')}, got ${JSON.stringify(v)}`);
  return s;
};

export const parseText = (v) => {
  if (v.length === 0 || v.length > 1024 || /[\0-\x1f\x7f]/.test(v)) throw new Error('expected a non-empty string without control characters');
  return v;
};

export const parseAbsPath = (v) => {
  parseText(v);
  if (!path.isAbsolute(v)) throw new Error(`expected an absolute path, got ${JSON.stringify(v)}`);
  return v;
};

export const parseSchema = (v) => {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(v)) throw new Error(`expected a schema name (letters, digits, underscore), got ${JSON.stringify(v)}`);
  return v;
};

export const parseLog = (v) => {
  const s = v.toLowerCase();
  if (s === 'stderr') return 'stderr';
  if (/^(kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|local[0-7])$/.test(s)) return s;
  throw new Error(`expected stderr or a syslog facility (daemon, local0 ... local7, ...), got ${JSON.stringify(v)}`);
};

// The libpq connection string of a conninfo file (key = value pairs, values may be 'single quoted' with \' and \\) -> the options of pg's Client.
// Only the keywords we can honour are accepted; any other is an error, so that nothing in the file is silently ignored.  env: where pg finds PGHOST when the file names no
// host (injected for the tests).
export function parseConninfo(text, program = 'karidns', env = process.env) {
  const out = {};
  let i = 0;
  const s = text.trim();
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    const k = /^[A-Za-z_][A-Za-z0-9_]*/.exec(s.slice(i));
    if (!k) throw new Error(`conninfo: a keyword is expected at offset ${i}`);
    const key = k[0];
    i += key.length;
    while (i < s.length && /\s/.test(s[i])) i++;
    if (s[i] !== '=') throw new Error(`conninfo: '=' is expected after ${key}`);
    i++;
    while (i < s.length && /\s/.test(s[i])) i++;
    let val = '';
    if (s[i] === "'") {
      i++;
      for (;;) {
        if (i >= s.length) throw new Error('conninfo: an unterminated quoted value');
        const c = s[i++];
        if (c === "'") break;
        if (c === '\\' && i < s.length) val += s[i++];
        else val += c;
      }
    } else {
      while (i < s.length && !/\s/.test(s[i])) {
        if (s[i] === '\\' && i + 1 < s.length) i++;
        val += s[i++];
      }
    }
    out[key] = val;
  }
  const cfg = {};
  for (const [k, v] of Object.entries(out)) {
    switch (k) {
      case 'host': cfg.host = v; break;
      case 'port': {
        if (!/^\d{1,5}$/.test(v)) throw new Error('conninfo: port is not a number');
        cfg.port = Number(v);
        break;
      }
      case 'dbname': cfg.database = v; break;
      case 'user': cfg.user = v; break;
      case 'password': cfg.password = v; break;
      case 'application_name': cfg.application_name = v; break;
      case 'connect_timeout': cfg.connectionTimeoutMillis = Number(v) * 1000; break;
      case 'sslmode':
        if (v === 'require') cfg.ssl = { rejectUnauthorized: false };
        else if (v === 'verify-ca' || v === 'verify-full') cfg.ssl = { rejectUnauthorized: true };
        else if (v !== 'disable' && v !== 'allow' && v !== 'prefer') throw new Error(`conninfo: sslmode ${v} is not known`);
        break;
      default:
        throw new Error(`conninfo: the keyword '${k}' is not supported by ${program} (host, port, dbname, user, password, sslmode, connect_timeout, application_name are)`);
    }
  }
  // pg has no fallback negotiation: allow and prefer mean no TLS at all, which a reader of the file does not expect; to another host that is refused (decision S-1, 0.7)
  const host = hostOf(cfg, env);
  if ((out.sslmode === 'allow' || out.sslmode === 'prefer') && !isLocalHost(host)) {
    throw new Error(`conninfo: sslmode=${out.sslmode} to ${host} would be plain text (${program} does not negotiate TLS): use sslmode=disable for plain text on purpose, or require / verify-full`);
  }
  Object.defineProperty(cfg, 'sslmode', { value: out.sslmode ?? '', enumerable: false });   // (for plaintextWarning; not an option of pg)
  return cfg;
}

// The host pg connects to: the file's, else PGHOST (pg takes the variable for an empty host too), else its default localhost.
const hostOf = (conn, env) => conn.host || env.PGHOST || '';

// Local: no host, a Unix socket directory, localhost, 127.0.0.0/8, ::1.
const isLocalHost = (host) => host === '' || host.startsWith('/') || host.toLowerCase() === 'localhost' || /^127(\.\d{1,3}){3}$/.test(host) || host === '::1' || host === '[::1]';

// pg has no fallback negotiation: sslmode disable and none mean no TLS at all (allow and prefer to another host are refused by parseConninfo).  -> a warning when that is
// a connection to another host (the file's, else PGHOST of env), else null.
export function plaintextWarning(conn, env = process.env) {
  if (conn.ssl) return null;
  const host = hostOf(conn, env);
  if (isLocalHost(host)) return null;
  const mode = conn.sslmode;
  return `the connection to the database at ${host} is not encrypted (${mode ? `sslmode=${mode}` : 'no sslmode'}); use sslmode=verify-full (require encrypts but does not check the server)`;
}

// The check karidns-zone and the loader apply to a conninfo file: a regular file (no symbolic link) owned by the user running us, mode 0600 or 0400.
// Returns null when fine, else the reason.
export function checkConninfoFile(file, st, uid = process.getuid?.(), program = 'karidns') {
  if (!st) {
    try { st = fs.lstatSync(file); } catch (e) { return `cannot read ${file}: ${e.code ?? e.message}`; }
  }
  if (!st.isFile()) return `${file} is not a regular file`;
  if (uid !== undefined && st.uid !== uid) return `${file} is not owned by the user running ${program}`;
  const mode = st.mode & 0o777;
  if (mode !== 0o600 && mode !== 0o400) return `${file} has mode ${mode.toString(8).padStart(4, '0')}, it must be 0600 or 0400`;
  return null;
}

// (0 where the system has no such flag: Windows)
const O_NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const O_NONBLOCK = fs.constants.O_NONBLOCK ?? 0;

// A private file (a conninfo file, a client secret, a key) read once (TOCTOU, 0.7): opened without following a symbolic link and without waiting on a FIFO, the checks made on
// fstat(2) of that descriptor, the text read from it; the path is never opened again after the check.  check(st) -> null or the reason (default: checkConninfoFile's rule,
// regular, ours, 0600 or 0400).  -> the text; throws Error(the reason), with the code of a failed open (ENOENT, ...).  fsx is injected for the tests.
export function readPrivateFile(file, { uid = process.getuid?.(), program = 'karidns', check, fsx = fs } = {}) {
  let fd;
  try {
    fd = fsx.openSync(file, fs.constants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  } catch (e) {
    // (O_NOFOLLOW on a link: ELOOP; FreeBSD says EMLINK)
    if (e.code === 'ELOOP' || e.code === 'EMLINK') throw Object.assign(new Error(`${file} is not a regular file`), { code: e.code });
    throw Object.assign(new Error(`cannot read ${file}: ${e.code ?? e.message}`), { code: e.code });
  }
  try {
    const st = fsx.fstatSync(fd);
    const bad = check ? check(st) : checkConninfoFile(file, st, uid, program);
    if (bad) throw new Error(bad);
    return fsx.readFileSync(fd, 'utf8');
  } finally {
    fsx.closeSync(fd);
  }
}

// A configuration file of karidns-signer or karidns-webadmin (0.7 review W1-L4, W4-L1): no secret in it, but it is policy (the tools the signer runs, the database,
// trusted-proxy, require-totp, ...), so it gets the checks of the other files a service reads: a regular file (no symbolic link), owned by root or by the user running
// us, and nobody else may change it (no write bit for the group or others; reading is fine).  -> null or the reason, with the command that fixes it.
export function checkConfigFile(file, st, uid = process.getuid?.(), program = 'karidns') {
  if (!st.isFile()) return `${file} is not a regular file`;
  if (uid !== undefined && st.uid !== 0 && st.uid !== uid) return `${file} belongs to uid ${st.uid}, not to root or to the user running ${program}: chown root ${file}`;
  const mode = st.mode & 0o777;
  if (mode & 0o022) return `${file} has mode ${mode.toString(8).padStart(4, '0')}: the group or other users can change it; chmod go-w ${file}`;
  return null;
}

// The text of a configuration file, read once like a private file (no link followed, no wait on a FIFO, the checks on fstat(2) of the descriptor) under
// checkConfigFile's rule.  Throws Error(the reason).
export function readConfigFile(file, { uid = process.getuid?.(), program = 'karidns', fsx = fs } = {}) {
  try {
    return readPrivateFile(file, { uid, program, fsx, check: (st) => checkConfigFile(file, st, uid, program) });
  } catch (e) {
    if (e.code === 'ELOOP' || e.code === 'EMLINK') throw new Error(`${file} is a symbolic link: point ${program} at the file itself (-c)`);
    throw e;
  }
}

// What the configuration files of karidns-signer and karidns-webadmin have in common (A-20: one copy, imported by both): the parsers of a value
// (a duration, a yes/no, a path, a schema name, a syslog facility), the connection file of a PostgreSQL database (parsed and checked the way karidns-zone and
// the loader do it), and the check of such a file's mode.  No dependency.

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
// Only the keywords we can honour are accepted; any other is an error, so that nothing in the file is silently ignored.
export function parseConninfo(text, program = 'karidns') {
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
  Object.defineProperty(cfg, 'sslmode', { value: out.sslmode ?? '', enumerable: false });   // (for plaintextWarning; not an option of pg)
  return cfg;
}

// pg has no fallback negotiation: sslmode disable, allow, prefer and none all mean no TLS at all.  -> a warning when that is a connection to another host, else null.
// Local: no host, a Unix socket directory, localhost, 127.0.0.0/8, ::1.
export function plaintextWarning(conn) {
  if (conn.ssl) return null;
  const host = conn.host ?? '';
  if (host === '' || host.startsWith('/') || host.toLowerCase() === 'localhost' || /^127(\.\d{1,3}){3}$/.test(host) || host === '::1' || host === '[::1]') return null;
  const mode = conn.sslmode;
  return `the connection to the database at ${host} is not encrypted (${mode ? `sslmode=${mode}` : 'no sslmode'}); use sslmode=require or verify-full`;
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

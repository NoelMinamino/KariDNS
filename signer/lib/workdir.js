// The work directory (planning 3.9): <work>/<zone>.<pid>/ with mode 0700, files 0600; key files are overwritten before they are unlinked; the left-overs
// of a process that died (kill -9) are wiped at the next start.  <work> itself must be ours and closed to others.

import fs from 'node:fs';
import path from 'node:path';
import { canonicalZone } from '../../node/lib/names.js';

// null when <work> is a directory of ours with no access for group and other, else the reason
export function checkWorkDir(dir, st, uid = process.getuid?.()) {
  if (!st) {
    try { st = fs.lstatSync(dir); } catch (e) { return `cannot read work-dir ${dir}: ${e.code ?? e.message}`; }
  }
  if (!st.isDirectory()) return `work-dir ${dir} is not a directory`;
  if (uid !== undefined && st.uid !== uid) return `work-dir ${dir} is not owned by the user running karidns-signer`;
  if ((st.mode & 0o077) !== 0) return `work-dir ${dir} has mode ${(st.mode & 0o777).toString(8).padStart(4, '0')}, it must be 0700`;
  return null;
}

// overwrite a file with zeros (same length), flush it, then unlink it.  Never throws for a file that is gone.
export function wipeFile(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
  } catch (e) {
    if (e.code === 'ENOENT') return;
    try { fs.unlinkSync(file); } catch { /* nothing more to do */ }
    return;
  }
  try {
    const len = fs.fstatSync(fd).size;
    const zeros = Buffer.alloc(Math.min(len, 1 << 20));
    for (let off = 0; off < len; off += zeros.length) fs.writeSync(fd, zeros, 0, Math.min(zeros.length, len - off), off);
    fs.fsyncSync(fd);
  } catch { /* the unlink below is what matters */ } finally {
    fs.closeSync(fd);
  }
  try { fs.unlinkSync(file); } catch { /* gone */ }
}

// wipe every entry of a directory, then the directory.  Symbolic links are unlinked, never followed.
export function wipeDir(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) wipeDir(p);
    else wipeFile(p);
  }
  try { fs.rmdirSync(dir); } catch { /* not empty or gone: the caller notices */ }
}

let seq = 0;

// <work>/<zone>.<pid>.<n>, 0700, exclusive
export function makeZoneDir(work, zone) {
  const name = canonicalZone(zone);
  for (let tries = 0; tries < 100; tries++) {
    const dir = path.join(work, `${name}.${process.pid}.${++seq}`);
    try {
      fs.mkdirSync(dir, { mode: 0o700 });
      return dir;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
    }
  }
  throw new Error(`cannot make a directory for ${name} in the work-dir`);
}

// write a file that only we can read (exclusive: never into an existing file or through a link)
export function writeSecret(file, data) {
  fs.writeFileSync(file, data, { mode: 0o600, flag: 'wx' });
}

function pidAlive(pid, kill = process.kill) {
  try {
    kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

// At start: wipe the zone directories of processes that are gone (kill -9 leaves them).  Only entries that are directories named like ours
// (<zone>.<pid>.<n>) are touched, so a work-dir that was pointed at some other directory of ours loses nothing else; a directory whose pid is alive
// (another instance on the same work-dir) is left alone.  Returns the names that were wiped.
export function wipeStale(work, { kill = process.kill } = {}) {
  let entries;
  try {
    entries = fs.readdirSync(work, { withFileTypes: true });
  } catch {
    return [];
  }
  const wiped = [];
  for (const e of entries) {
    const m = /^[a-z0-9_.-]+\.([0-9]+)\.[0-9]+$/.exec(e.name);
    if (!m || !e.isDirectory()) continue;
    if (pidAlive(Number(m[1]), kill)) continue;
    wipeDir(path.join(work, e.name));
    wiped.push(e.name);
  }
  return wiped;
}

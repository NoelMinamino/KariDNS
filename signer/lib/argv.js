// The argv of every child process (planning 3.3).  Pure functions: the settings and the paths in, an array of words out.  No word is ever built from
// text that was not validated (zone names: names.js; numbers: formatted here), and no word is passed through a shell.

import path from 'node:path';
import { canonicalZone } from './names.js';
import { algorithmName } from './keys.js';

export function tools(cfg) {
  const bind = cfg['bind-tools'];
  return {
    keygen: path.posix.join(bind, 'dnssec-keygen'),
    signzone: path.posix.join(bind, 'dnssec-signzone'),
    verify: path.posix.join(bind, 'dnssec-verify'),
    zone: cfg['karidns-zone'],
    karicheck: cfg.karicheck,
    karictl: cfg.karictl,
  };
}

// the database words of karidns-zone: never the configuration of the server, only what the signer's own file says
export function dbArgs(cfg) {
  if (cfg.database === 'sqlite3') return ['--no-config', '--sqlite3', cfg['sqlite-file']];
  const a = ['--no-config', '--conninfo-file', cfg['conninfo-file']];
  if (cfg.schema) a.push('--schema', cfg.schema);
  return a;
}

// export --signer: the zone as the input of dnssec-signzone (the NSEC3 chain and its signatures left out: a zone that was changed since it was signed has no complete chain, and the plain export refuses it)
export function exportArgv(cfg, zone, outFile) {
  return ['export', '--signer', ...dbArgs(cfg), canonicalZone(zone), outFile];
}

// import --signer; --reload only on PostgreSQL (the reload request is committed with the data); SQLite3 has no request table: karictl does it
export function importArgv(cfg, zone, file) {
  return ['import', '--signer', '--json', ...dbArgs(cfg), ...(cfg.database === 'pg' ? ['--reload'] : []), canonicalZone(zone), file];
}

export function checkArgv(zone, file) {
  return ['zone', canonicalZone(zone), file];
}

// karictl with the restricted key of the signer (allow-commands { reload-zone; }): its own configuration file, optionally the socket
export function reloadArgv(cfg, zone) {
  return ['-c', cfg['karictl-config'], ...(cfg['karictl-socket'] ? ['-s', cfg['karictl-socket']] : []), 'reload', canonicalZone(zone)];
}

// dnssec-keygen -q -a <alg> [-b <bits>] [-f KSK] -K <dir> <zone>; prints the key's file name stem on standard output
export function keygenArgv({ zone, algorithm, bits, ksk, dir }) {
  const a = ['-q', '-a', algorithmName(algorithm)];
  if (bits != null) {
    if (!Number.isInteger(bits) || bits < 1024 || bits > 8192) throw new Error('RSA key size must be 1024 to 8192');
    a.push('-b', String(bits));
  }
  if (ksk) a.push('-f', 'KSK');
  a.push('-K', dir, canonicalZone(zone));
  return a;
}

// The NSEC3PARAM metadata of a zone ("1 0 0 -": hash algorithm, flags, iterations, salt) -> { iterations, salt } for -3 / -H; null for a form
// we do not produce.  The salt is kept as the zone has it (hex or "-"), so a re-sign does not change the chain.
export function parseNsec3param(text) {
  const m = /^\s*1\s+[01]\s+(\d{1,5})\s+(-|(?:[0-9a-fA-F]{2}){1,255})\s*$/.exec(text ?? '');
  return m ? { iterations: Number(m[1]), salt: m[2] } : null;
}

// dnssec-signzone.  mode: 'csk' (-z: the KSK-flag keys sign everything) or 'split' (-x: only the KSKs sign the DNSKEY RRset);
// nsec3: null (NSEC) or { salt, iterations, optOut }.  -i is refresh + jitter, so that the run which the scheduler places up to `jitter` before the
// refresh point re-signs the signatures that are due (scheduler.js); -R drops the signatures of keys that are gone from the zone (a retired key, still published, keeps the signatures it made until they expire; -Q would drop them but also those of keys whose files carry no timing metadata, and signs everything again every run).
export function signzoneArgv({ zone, dir, inFile, outFile, validity, refresh, jitter, verify, mode, nsec3, keyStems }) {
  for (const n of [validity, refresh, jitter]) if (!Number.isInteger(n) || n < 0) throw new Error('bad signature timing');
  const a = ['-q', '-o', canonicalZone(zone), '-f', outFile, '-O', 'full', '-K', dir, '-d', dir,
    '-e', `now+${validity}`, '-i', String(refresh + jitter), '-j', String(jitter), '-N', 'increment', '-R'];
  if (nsec3) {
    if (!/^(-|([0-9a-fA-F]{2}){1,255})$/.test(nsec3.salt) || !Number.isInteger(nsec3.iterations) || nsec3.iterations < 0 || nsec3.iterations > 65535) throw new Error('bad NSEC3 parameters');
    a.push('-3', nsec3.salt, '-H', String(nsec3.iterations));
    if (nsec3.optOut) a.push('-A');
  }
  if (!verify) a.push('-P');
  if (mode === 'csk') a.push('-z');
  else if (mode === 'split') a.push('-x');
  else throw new Error(`unknown signing mode ${mode}`);
  a.push(inFile);
  for (const k of keyStems) {
    if (!/^K[a-z0-9_.-]+\.\+[0-9]{3}\+[0-9]{5}$/.test(k)) throw new Error('bad key file name');
    a.push(k);
  }
  return a;
}

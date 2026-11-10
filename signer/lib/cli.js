// karidns-signer: the command line (bin/karidns-signer.js calls main()).  Options, --check, the daemon with its signals.

import fs from 'node:fs';
import { setTimeout as sleepMs } from 'node:timers/promises';
import { loadConfig, validate, checkConninfoFile } from './config.js';
import { tools } from './argv.js';
import { runChild, clip } from '../../node/lib/run.js';
import { createLogger } from '../../node/lib/log.js';
import { checkWorkDir, wipeStale } from './workdir.js';
import { Daemon } from './daemon.js';
import { signZone } from './pipeline.js';
import { SqliteDb } from './db_sqlite.js';
import { loadSqlite } from '../../node/lib/sqlite.js';
import { PgDb } from './db_pg.js';
import { parseConninfo, plaintextWarning } from '../../node/lib/conf.js';
import { packageVersion } from '../../node/lib/version.js';

export const VERSION = packageVersion(new URL('../package.json', import.meta.url));
export const DEFAULT_CONFIG = '/usr/local/etc/karidns/karidns-signer.conf';

export const USAGE = `Usage: karidns-signer [-c config] [--check]
       karidns-signer --version | -h | --help

Keeps the zones of a KariDNS database (PostgreSQL or SQLite3) signed: zones with the metadata X-KARIDNS-SIGNER = 1 are signed again when their
signatures near their end and when someone changes them, and the key requests in karidns_key_requests are answered.  It runs BIND's
dnssec-keygen and dnssec-signzone, karidns-zone (export, import --signer) and karicheck; the zone data never goes through this program.

  -c, --config FILE   the configuration file (default ${DEFAULT_CONFIG})
      --check         read the configuration, check the permissions of the files and the versions of the tools, and exit (0 = fine, 1 = a problem)
  -v, --version       print the version
  -h, --help          print this text

Signals: SIGTERM and SIGINT finish the zones that are running and stop; SIGHUP reads the configuration again (the database and the work-dir
stay as they are).  The configuration is described in docs/karidns-signer.md.

Example:
  karidns-signer --check -c /usr/local/etc/karidns/karidns-signer.conf
`;

// -> { config, check, help, version } or throws Error(usage message)
export function parseArgs(argv) {
  const o = { config: DEFAULT_CONFIG, check: false, help: false, version: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-c' || a === '--config') {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a file name`);
      o.config = argv[++i];
    } else if (a === '--check') o.check = true;
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else throw new Error(`unknown option ${JSON.stringify(a.slice(0, 40))}`);
  }
  return o;
}

// --check: the permissions of the files and the tools' versions.  Returns { problems, notes, warnings }.
export async function checkSetup(config, { run = runChild, st = {}, nodeVersion = process.versions.node, readFile = fs.readFileSync } = {}) {
  const s = config.settings;
  const problems = validate(config);
  const notes = [];
  const warnings = [];
  if (problems.length) return { problems, notes, warnings };
  const t = tools(s);
  const wd = checkWorkDir(s['work-dir'], st.work);
  if (wd) problems.push(wd);
  else notes.push(`work-dir ${s['work-dir']}: fine`);
  if (s.database === 'pg') {
    const c = checkConninfoFile(s['conninfo-file'], st.conninfo);
    if (c) problems.push(c);
    else {
      notes.push(`conninfo-file ${s['conninfo-file']}: fine`);
      try {
        const w = plaintextWarning(parseConninfo(readFile(s['conninfo-file'], 'utf8'), 'karidns-signer'));
        if (w) warnings.push(w);
      } catch { /* (a file that cannot be read or parsed is the start's problem to tell) */ }
    }
  } else {
    if ((nodeVersion.split('.').map(Number)[0] ?? 0) < 22) problems.push(`database = sqlite3 needs Node 22.13 or newer (this is ${nodeVersion})`);
    try {
      fs.accessSync(s['sqlite-file'], fs.constants.R_OK | fs.constants.W_OK);
      notes.push(`sqlite-file ${s['sqlite-file']}: fine`);
    } catch (e) {
      problems.push(`sqlite-file ${s['sqlite-file']}: ${e.code ?? e.message}`);
    }
  }
  const probes = [
    ['dnssec-keygen', t.keygen, ['-V']],
    ['dnssec-signzone', t.signzone, ['-V']],
    ['karidns-zone', t.zone, ['--version']],
    ['karicheck', t.karicheck, ['--version']],
    ...(s.database === 'sqlite3' ? [['karictl', t.karictl, ['--version']]] : []),
  ];
  for (const [name, file, args] of probes) {
    const r = await run(file, args, { timeoutMs: 10000, maxOutput: 8192 });
    const out = (r.stdout || r.stderr).trim().split(/\r?\n/)[0] ?? '';
    if (r.spawnError || (r.code !== 0 && !(name === 'karictl' && out))) problems.push(`${name} (${file}): ${r.spawnError ?? `exit status ${r.code}`}`);
    else notes.push(`${name} (${file}): ${clip(out, 120)}`);
    if (name === 'karidns-zone' && !r.spawnError) {
      const want = s.database === 'pg' ? 'postgresql' : 'sqlite3';
      if (!out.includes(want)) problems.push(`karidns-zone has no ${want} driver (${clip(out, 120)})`);
    }
  }
  return { problems, notes, warnings };
}

export async function openDb(config, { onFatal, warn, importPg, importSqlite = loadSqlite, readFile = fs.readFileSync, checkConninfo = checkConninfoFile } = {}) {
  const s = config.settings;
  let db;
  if (s.database === 'sqlite3') {
    db = new SqliteDb({ file: s['sqlite-file'], sqlite: await importSqlite() });
    db.open();
  } else {
    const problem = checkConninfo(s['conninfo-file']);
    if (problem) throw new Error(problem);
    const pg = await (importPg ? importPg() : import('pg'));
    const Client = pg.Client ?? pg.default.Client;
    const conn = parseConninfo(readFile(s['conninfo-file'], 'utf8'), 'karidns-signer');
    const w = plaintextWarning(conn);
    if (w) warn?.(w);
    db = new PgDb({ Client, conn, schema: s.schema, onFatal });
    await db.open();
  }
  return db;
}

// The daemon.  io: { stdout, stderr, proc (signals), deps }.  Resolves with the exit status after SIGTERM / SIGINT.
export async function main(argv, io = {}) {
  const { stdout = process.stdout, stderr = process.stderr, proc = process, deps = {} } = io;
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    stderr.write(`karidns-signer: ${e.message}\n${USAGE}`);
    return 2;
  }
  if (opts.help) { stdout.write(USAGE); return 0; }
  if (opts.version) { stdout.write(`karidns-signer ${VERSION}\n`); return 0; }
  let config;
  try {
    config = (deps.loadConfig ?? loadConfig)(opts.config);
  } catch (e) {
    stderr.write(`karidns-signer: ${e.message}\n`);
    return 1;
  }
  if (opts.check) {
    const { problems, notes, warnings = [] } = await (deps.checkSetup ?? checkSetup)(config);
    for (const n of notes) stdout.write(`ok: ${n}\n`);
    for (const w of warnings) stderr.write(`warning: ${w}\n`);
    for (const p of problems) stderr.write(`problem: ${p}\n`);
    stdout.write(problems.length ? 'karidns-signer: the configuration has problems\n' : 'karidns-signer: the configuration is fine\n');
    return problems.length ? 1 : 0;
  }
  const problems = validate(config);
  const s = config.settings;
  if (problems.length === 0) {
    const wd = (deps.checkWorkDir ?? checkWorkDir)(s['work-dir']);
    if (wd) problems.push(wd);
  }
  if (problems.length) {
    for (const p of problems) stderr.write(`karidns-signer: ${p}\n`);
    return 1;
  }
  const log = (deps.createLogger ?? createLogger)({ target: s.log, name: 'karidns-signer' });
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });
  let daemon = null;
  const fatal = (e) => {
    log.error(`fatal: ${e.message}`);
    resolveDone(1);
  };
  let db;
  try {
    db = await (deps.openDb ?? openDb)(config, { onFatal: fatal, warn: (m) => log.warn(m) });
  } catch (e) {
    log.error(`cannot open the database: ${e.message}`);
    log.close();
    return 1;
  }
  const wiped = (deps.wipeStale ?? wipeStale)(s['work-dir']);
  if (wiped.length) log.warn(`wiped ${wiped.length} work directory(ies) of a signer that died`);
  const ctx = {
    config, db, log, tools: tools(s), work: s['work-dir'],
    run: runChild,
  };
  daemon = new Daemon({
    db, ctx, sign: signZone, log, clock: () => Math.floor(Date.now() / 1000), sleep: sleepMs,
    changePollMs: s.database === 'pg' ? 30000 : 2000,
  });
  const onTerm = () => { log.info('stopping: the running zones are finished first'); resolveDone(0); };
  const onHup = () => {
    try {
      const next = (deps.loadConfig ?? loadConfig)(opts.config);
      const bad = validate(next);
      if (bad.length) throw new Error(bad.join('; '));
      daemon.reconfigure(next);
    } catch (e) {
      log.error(`the configuration was not read: ${e.message}`);
    }
  };
  proc.on('SIGTERM', onTerm);
  proc.on('SIGINT', onTerm);
  proc.on('SIGHUP', onHup);
  let status = 1;
  try {
    await daemon.start();
    log.info(`karidns-signer ${VERSION} started (${s.database}, ${s.workers} worker(s))`);
    status = await done;
  } catch (e) {
    log.error(`fatal: ${e.message}`);
  } finally {
    await daemon.stop();                       // the handlers stay until the zones are finished: a second SIGTERM must not kill the signer in the middle of a zone
    await db.close();
    proc.off('SIGTERM', onTerm);
    proc.off('SIGINT', onTerm);
    proc.off('SIGHUP', onHup);
    log.info('stopped');
    log.close();
  }
  return status;
}

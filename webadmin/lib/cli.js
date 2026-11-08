// karidns-webadmin: the command line (bin/karidns-webadmin.js calls main()).  Options, --check, --create-admin, the server with its signals.

import fs from 'node:fs';
import { loadConfig, validate } from './config.js';
import { runChild } from '../../node/lib/run.js';
import { createLogger } from '../../node/lib/log.js';
import { App, VERSION } from './app.js';
import { Router, listen, closeServer } from './http.js';
import { ROUTES } from './routes.js';
import { openBackend, inspect, createAdmin } from './setup.js';
import { loadKeyFile } from './crypto.js';
import * as S from './store.js';

export { VERSION };
export const DEFAULT_CONFIG = '/usr/local/etc/karidns/karidns-webadmin.conf';

export const USAGE = `Usage: karidns-webadmin [-c config] [--check]
       karidns-webadmin [-c config] --create-admin NAME [--bootstrap-conninfo-file FILE]
       karidns-webadmin --version | -h | --help

The HTTP API of a KariDNS database (PostgreSQL or SQLite3): logins, users, groups and grants, the zones and their records, under /api/v1/.
Zone data is read from the database and exported by karidns-zone; who may see and change what is decided here and, on PostgreSQL, again by row level security.

  -c, --config FILE                 the configuration file (default ${DEFAULT_CONFIG})
      --check                       read the configuration, check the files and their modes, the tools and the database schema, and exit (0 = fine, 1 = a problem)
      --create-admin NAME           make a user NAME with a global master grant and print its one-time password (run it once, as the service user)
      --bootstrap-conninfo-file F   PostgreSQL only: the connection of a role that row level security does not bind (the table owner), for --create-admin
  -v, --version                     print the version
  -h, --help                        print this text

Signals: SIGTERM and SIGINT finish the requests that are running and stop; SIGHUP reads the configuration again (rates, timeouts, the origin; not the database
or the address).  The configuration is described in docs/karidns-api.md.

Example:
  karidns-webadmin --check -c /usr/local/etc/karidns/karidns-webadmin.conf
`;

// -> { config, check, help, version, createAdmin, bootstrap } or throws Error(usage message)
export function parseArgs(argv) {
  const o = { config: DEFAULT_CONFIG, check: false, help: false, version: false, createAdmin: undefined, bootstrap: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '-c' || a === '--config') o.config = need();
    else if (a === '--check') o.check = true;
    else if (a === '--create-admin') o.createAdmin = need();
    else if (a === '--bootstrap-conninfo-file') o.bootstrap = need();
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else throw new Error(`unknown option ${JSON.stringify(a.slice(0, 40))}`);
  }
  if (o.check && o.createAdmin !== undefined) throw new Error('--check and --create-admin do not go together');
  if (o.bootstrap !== undefined && o.createAdmin === undefined) throw new Error('--bootstrap-conninfo-file is for --create-admin');
  return o;
}

// The server.  io: { stdout, stderr, proc (signals), deps }.  Resolves with the exit status after SIGTERM / SIGINT.
export async function main(argv, io = {}) {
  const { stdout = process.stdout, stderr = process.stderr, proc = process, deps = {} } = io;
  const d = { loadConfig, openBackend, inspect, createAdmin, createLogger, loadKeyFile: (f) => loadKeyFile(f, fs), listen, run: runChild, ...deps };
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    stderr.write(`karidns-webadmin: ${e.message}\n${USAGE}`);
    return 2;
  }
  if (opts.help) { stdout.write(USAGE); return 0; }
  if (opts.version) { stdout.write(`karidns-webadmin ${VERSION}\n`); return 0; }
  let config;
  try {
    config = d.loadConfig(opts.config);
  } catch (e) {
    stderr.write(`karidns-webadmin: ${e.message}\n`);
    return 1;
  }
  const bad = validate(config);

  if (opts.createAdmin !== undefined) {
    if (bad.length) { for (const p of bad) stderr.write(`karidns-webadmin: ${p}\n`); return 1; }
    if (config.settings.database === 'pg' && !opts.bootstrap) {
      stderr.write('karidns-webadmin: on PostgreSQL --create-admin needs --bootstrap-conninfo-file: the API role cannot make the first user (row level security); use the connection of the table owner\n');
      return 1;
    }
    let backend;
    try {
      backend = await d.openBackend(config, { conninfoFile: opts.bootstrap });
      const r = await d.createAdmin(config, opts.createAdmin, backend, { run: d.run });
      stdout.write(`user ${r.name} made, a global master.\npassword (shown once): ${r.password}\n`);
      if (config.settings['require-totp'] !== 'none') stdout.write('TOTP is required for global masters: the first login must enrol (POST /api/v1/auth/totp).\n');
      return 0;
    } catch (e) {
      stderr.write(`karidns-webadmin: ${e.message}\n`);
      return 1;
    } finally {
      await backend?.close();
    }
  }

  if (opts.check) {
    let backend;
    let r;
    try {
      if (!bad.length) backend = await d.openBackend(config).catch((e) => { bad.push(e.message); });
      r = await d.inspect(config, { backend, run: d.run });
    } finally {
      await backend?.close();
    }
    for (const n of r.notes) stdout.write(`ok: ${n}\n`);
    for (const p of [...bad.filter((b) => !r.problems.includes(b)), ...r.problems]) stderr.write(`problem: ${p}\n`);
    const fine = r.problems.length === 0 && bad.length === 0;
    stdout.write(fine ? 'karidns-webadmin: the configuration is fine\n' : 'karidns-webadmin: the configuration has problems\n');
    return fine ? 0 : 1;
  }

  if (bad.length) {
    for (const p of bad) stderr.write(`karidns-webadmin: ${p}\n`);
    return 1;
  }
  const s = config.settings;
  const log = d.createLogger({ target: s.log, name: 'karidns-webadmin' });
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });
  let backend;
  let key;
  try {
    key = d.loadKeyFile(s['totp-key-file']);
    backend = await d.openBackend(config, { onError: (e) => log.error(`database connection: ${e.message}`) });
  } catch (e) {
    log.error(`cannot start: ${e.message}`);
    log.close();
    return 1;
  }
  const checked = await d.inspect(config, { backend, run: d.run });
  if (checked.problems.length) {
    for (const p of checked.problems) log.error(`cannot start: ${p}`);
    await backend.close();
    log.close();
    return 1;
  }
  const app = new App({ config, backend, log, run: d.run, key });
  app.versions = checked.versions;
  let server;
  try {
    server = await d.listen(app, new Router(ROUTES));
  } catch (e) {
    log.error(`cannot listen on ${s.listen}: ${e.message}`);
    await backend.close();
    log.close();
    return 1;
  }
  // expired sessions and tokens: on SQLite3 there is no row level security, so the API deletes them all at the start and every hour; on PostgreSQL a principal
  // deletes its own at its login (the API role cannot see the rows of the others)
  const sweep = () => {
    if (backend.dialect === 'sqlite') app.background(() => backend.tx({ write: true }, (tx) => S.deleteExpiredSessions(tx, app.now())));
  };
  sweep();
  const timer = setInterval(sweep, 3600000);
  timer.unref();
  const onTerm = () => { log.info('stopping'); resolveDone(0); };
  const onHup = () => {
    try {
      const next = d.loadConfig(opts.config);
      const problems = validate(next);
      if (problems.length) throw new Error(problems.join('; '));
      app.setConfig(next);
      log.info('the configuration was read again');
    } catch (e) {
      log.error(`the configuration was not read: ${e.message}`);
    }
  };
  proc.on('SIGTERM', onTerm);
  proc.on('SIGINT', onTerm);
  proc.on('SIGHUP', onHup);
  log.info(`karidns-webadmin ${VERSION} started (${s.database}, listening on ${s.listen})`);
  const status = await done;
  clearInterval(timer);
  await closeServer(server);
  await app.drain();
  await backend.close();
  proc.off('SIGTERM', onTerm);
  proc.off('SIGINT', onTerm);
  proc.off('SIGHUP', onHup);
  log.info('stopped');
  log.close();
  return status;
}

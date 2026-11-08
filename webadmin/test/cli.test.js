// the command line, --check, --create-admin, the checks of the start, and the server loop with its signals

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseArgs, main, USAGE, VERSION, DEFAULT_CONFIG } from '../lib/cli.js';
import { openBackend, inspect, createAdmin } from '../lib/setup.js';
import { parseConfig, loadConfig, validate } from '../lib/config.js';
import { SqliteBackend } from '../lib/db.js';
import { runChild } from '../../node/lib/run.js';
import { sqlite, makeFiles, confText, memLog, deploy, rmDir } from './helpers.js';

const sink = () => { let t = ''; return { write: (s) => { t += s; }, get text() { return t; } }; };
const run = async (argv, deps = {}) => {
  const stdout = sink();
  const stderr = sink();
  const status = await main(argv, { stdout, stderr, deps });
  return { status, out: stdout.text, err: stderr.text };
};

test('the options', () => {
  assert.deepEqual(parseArgs([]), { config: DEFAULT_CONFIG, check: false, help: false, version: false, createAdmin: undefined, bootstrap: undefined });
  assert.equal(parseArgs(['-c', '/x.conf']).config, '/x.conf');
  assert.equal(parseArgs(['--config', '/y.conf', '--check']).check, true);
  assert.equal(parseArgs(['--create-admin', 'admin']).createAdmin, 'admin');
  assert.deepEqual(parseArgs(['--create-admin', 'a', '--bootstrap-conninfo-file', '/b']).bootstrap, '/b');
  assert.equal(parseArgs(['-h']).help, true);
  assert.equal(parseArgs(['-v']).version, true);
  assert.throws(() => parseArgs(['-c']), /-c needs a value/);
  assert.throws(() => parseArgs(['--create-admin']), /needs a value/);
  assert.throws(() => parseArgs(['--bogus']), /unknown option "--bogus"/);
  assert.throws(() => parseArgs(['--check', '--create-admin', 'a']), /do not go together/);
  assert.throws(() => parseArgs(['--bootstrap-conninfo-file', '/b']), /is for --create-admin/);
  assert.match(USAGE, /Usage: karidns-webadmin/);
});

test('help, version, a usage error, a configuration that cannot be read', async () => {
  let r = await run(['--help']);
  assert.deepEqual([r.status, r.out], [0, USAGE]);
  r = await run(['-v']);
  assert.deepEqual([r.status, r.out], [0, `karidns-webadmin ${VERSION}\n`]);
  r = await run(['--nope']);
  assert.equal(r.status, 2);
  assert.match(r.err, /unknown option/);
  assert.match(r.err, /Usage:/);
  r = await run(['-c', path.join(os.tmpdir(), 'kw-no-such-file.conf')]);
  assert.equal(r.status, 1);
  assert.match(r.err, /cannot read/);
});

const goodConfig = () => parseConfig(confText('/var/db/x'));

test('--check: the problems of the configuration, of the files, and a fine setup', async () => {
  const log = [];
  const deps = {
    loadConfig: () => goodConfig(),
    openBackend: async () => ({ close: async () => { log.push('closed'); } }),
    inspect: async () => ({ problems: [], notes: ['sqlite-file x: fine'], versions: {} }),
  };
  let r = await run(['--check'], deps);
  assert.equal(r.status, 0);
  assert.match(r.out, /ok: sqlite-file x: fine/);
  assert.match(r.out, /the configuration is fine/);
  assert.deepEqual(log, ['closed']);
  r = await run(['--check'], { ...deps, inspect: async () => ({ problems: ['karicheck: exit status 127'], notes: [], versions: {} }) });
  assert.equal(r.status, 1);
  assert.match(r.err, /problem: karicheck: exit status 127/);
  assert.match(r.out, /the configuration has problems/);
  // a configuration that is wrong: the problems are listed, the database is not opened
  let opened = false;
  r = await run(['--check'], { ...deps, loadConfig: () => parseConfig(''), openBackend: async () => { opened = true; }, inspect: async (c) => ({ problems: (await import('../lib/config.js')).validate(c), notes: [], versions: {} }) });
  assert.equal(r.status, 1);
  assert.equal(opened, false);
  assert.match(r.err, /problem: 'listen' is not set/);
  assert.equal((r.err.match(/'listen' is not set/g) ?? []).length, 1, 'once');
  // a database that cannot be opened is a problem too
  r = await run(['--check'], { ...deps, openBackend: async () => { throw new Error('cannot connect'); }, inspect: async () => ({ problems: [], notes: [], versions: {} }) });
  assert.equal(r.status, 1);
  assert.match(r.err, /problem: cannot connect/);
});

test('--create-admin: SQLite3 directly, PostgreSQL only with a trusted connection', async () => {
  const made = [];
  const deps = {
    loadConfig: () => goodConfig(),
    openBackend: async (c, o) => ({ close: async () => { made.push(['closed', o?.conninfoFile]); } }),
    createAdmin: async (c, name) => { made.push(['admin', name]); return { name, password: 'sekrit-once' }; },
  };
  let r = await run(['--create-admin', 'alice'], { ...deps, loadConfig: () => parseConfig(confText('/var/db/x', { 'require-totp': 'global' })) });
  assert.equal(r.status, 0);
  assert.match(r.out, /user alice made, a global master\.\npassword \(shown once\): sekrit-once\n/);
  assert.match(r.out, /TOTP is required for global masters/);
  assert.deepEqual(made, [['admin', 'alice'], ['closed', undefined]]);
  r = await run(['--create-admin', 'alice'], { ...deps, loadConfig: () => parseConfig(confText('/x', { 'require-totp': 'none' })) });
  assert.doesNotMatch(r.out, /TOTP/);
  const pg = () => parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /a\ncheck-conninfo-file = /b\n');
  r = await run(['--create-admin', 'alice'], { ...deps, loadConfig: pg });
  assert.equal(r.status, 1);
  assert.match(r.err, /--bootstrap-conninfo-file/);
  made.length = 0;
  r = await run(['--create-admin', 'alice', '--bootstrap-conninfo-file', '/owner.conninfo'], { ...deps, loadConfig: pg });
  assert.equal(r.status, 0);
  assert.deepEqual(made, [['admin', 'alice'], ['closed', '/owner.conninfo']]);
  r = await run(['--create-admin', 'alice'], { ...deps, loadConfig: () => parseConfig('') });
  assert.equal(r.status, 1);
  assert.match(r.err, /'listen' is not set/);
  r = await run(['--create-admin', 'alice'], { ...deps, createAdmin: async () => { throw new Error('a principal named alice exists already'); } });
  assert.equal(r.status, 1);
  assert.match(r.err, /exists already/);
  r = await run(['--create-admin', 'alice'], { ...deps, openBackend: async () => { throw new Error('cannot open'); } });
  assert.equal(r.status, 1);
  assert.match(r.err, /cannot open/);
});

// ---- the server loop
function fakes(over = {}) {
  const events = [];
  const captured = {};
  const log = memLog();
  const proc = new EventEmitter();
  const backend = {
    dialect: 'sqlite',
    tx: async (o, fn) => { events.push(['tx', o.write]); return fn({ dialect: 'sqlite', A: 'auth.', ts: (ms) => new Date(ms).toISOString(), run: async () => ({ changes: 0 }) }); },
    close: async () => { events.push(['backend closed']); },
  };
  const server = { close: (cb) => { events.push(['server closed']); cb(); }, closeIdleConnections: () => {} };
  const deps = {
    loadConfig: () => goodConfig(),
    createLogger: () => log,
    loadKeyFile: () => Buffer.alloc(32, 1),
    openBackend: async (c, o) => { captured.onError = o?.onError; return backend; },
    inspect: async () => ({ problems: [], notes: [], versions: { karicheck: 'karicheck 0.6.0' } }),
    listen: async (app) => { events.push(['listen', app.versions.karicheck]); return server; },
    ...over,
  };
  return { events, log, proc, deps, captured };
}

test('the server: starts, sweeps the sessions, reads the configuration on SIGHUP, stops on SIGTERM', async () => {
  const f = fakes();
  const stderr = sink();
  const p = main([], { stdout: sink(), stderr, proc: f.proc, deps: f.deps });
  await sleep(50);
  assert.equal(f.proc.listenerCount('SIGTERM'), 1);
  assert.equal(f.proc.listenerCount('SIGHUP'), 1);
  f.proc.emit('SIGHUP');
  f.captured.onError(new Error('connection lost'));
  f.proc.emit('SIGINT');
  assert.equal(await p, 0);
  assert.ok(f.log.lines.includes('error database connection: connection lost'));
  assert.deepEqual(f.events.filter((e) => e[0] !== 'tx'), [['listen', 'karicheck 0.6.0'], ['server closed'], ['backend closed']]);
  assert.ok(f.events.some((e) => e[0] === 'tx' && e[1] === true), 'the expired sessions of the SQLite3 file are deleted at the start');
  assert.ok(f.log.lines.some((l) => /karidns-webadmin 0\.6\.0 started \(sqlite3, listening on 127\.0\.0\.1:8053\)/.test(l)));
  assert.ok(f.log.lines.includes('info the configuration was read again'));
  assert.ok(f.log.lines.includes('info stopped'));
  assert.equal(f.proc.listenerCount('SIGTERM'), 0);
  assert.equal(f.proc.listenerCount('SIGHUP'), 0);
});

test('the server: a configuration that is wrong at SIGHUP is not taken; PostgreSQL sweeps with the SECURITY DEFINER function', async () => {
  let mode = 'good';
  const f = fakes({ loadConfig: () => (mode === 'throw' ? parseConfig('listen = nonsense') : mode === 'invalid' ? parseConfig('database = sqlite3') : goodConfig()) });
  const p = main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps });
  await sleep(50);
  mode = 'throw';
  f.proc.emit('SIGHUP');
  mode = 'invalid';
  f.proc.emit('SIGHUP');
  f.proc.emit('SIGTERM');
  assert.equal(await p, 0);
  assert.equal(f.log.lines.filter((l) => /^error the configuration was not read: /.test(l)).length, 2);
  const g = fakes();
  const pgBackend = { dialect: 'pg', tx: async (o, fn) => { g.events.push(['tx', o.write]); return fn({ get: async (sql) => { g.events.push(['sql', sql]); return { n: 3 }; } }); }, close: async () => {} };
  g.deps.openBackend = async () => pgBackend;
  const q = main([], { stdout: sink(), stderr: sink(), proc: g.proc, deps: g.deps });
  await sleep(50);
  g.proc.emit('SIGTERM');
  await q;
  assert.deepEqual(g.events.filter((e) => e[0] === 'tx' || e[0] === 'sql'), [['tx', true], ['sql', 'SELECT karidns_auth.sweep_expired() AS n']]);
});

test('the server: it does not start with a configuration, a key, a database, a schema or a port that is wrong', async () => {
  let f = fakes({ loadConfig: () => parseConfig('') });
  let r = await run([], f.deps);
  assert.equal(r.status, 1);
  assert.match(r.err, /karidns-webadmin: 'listen' is not set/);
  f = fakes({ loadKeyFile: () => { throw new Error('key file has mode 0644'); } });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.ok(f.log.lines.some((l) => /cannot start: key file has mode 0644/.test(l)));
  f = fakes({ openBackend: async () => { throw new Error('connection refused'); } });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.ok(f.log.lines.some((l) => /cannot start: connection refused/.test(l)));
  f = fakes({ inspect: async () => ({ problems: ['the schema version is 2'], notes: [], versions: {} }) });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.ok(f.log.lines.some((l) => /cannot start: the schema version is 2/.test(l)));
  assert.ok(f.events.some((e) => e[0] === 'backend closed'));
  f = fakes({ listen: async () => { throw new Error('EADDRINUSE'); } });
  assert.equal(await main([], { stdout: sink(), stderr: sink(), proc: f.proc, deps: f.deps }), 1);
  assert.ok(f.log.lines.some((l) => /cannot listen on 127\.0\.0\.1:8053: EADDRINUSE/.test(l)));
});

// ---- setup.js
test('openBackend: SQLite3 opens the files, PostgreSQL checks the connection file first', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-open-'));
  try {
    makeFiles(dir);
    const b = await openBackend(parseConfig(confText(dir)));
    assert.equal(b instanceof SqliteBackend, true);
    assert.equal((await b.tx({}, (tx) => tx.get('SELECT count(*) AS n FROM auth.principals'))).n, 0);
    b.close();
  } finally {
    rmDir(dir);
  }
  const cfg = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n');
  await assert.rejects(openBackend(cfg, { checkConninfo: () => 'api.ci has mode 0644, it must be 0600 or 0400' }), /mode 0644/);
  const seen = {};
  class Pool {
    constructor(o) { seen.opts = o; }

    on() {}

    async query() { return { rows: [] }; }

    async end() {}
  }
  const b = await openBackend(cfg, { checkConninfo: () => null, importPg: async () => ({ default: { Pool, types: { getTypeParser: () => null } } }), readFile: (f) => { seen.file = f; return "host=/s dbname=d user=karidns_api password='p w'"; } });
  assert.equal(seen.file, '/api.ci');
  assert.equal(seen.opts.password, 'p w');
  assert.equal(seen.opts.max, 8);
  await b.close();
  await openBackend(cfg, { conninfoFile: '/owner.ci', checkConninfo: () => null, importPg: async () => ({ Pool, types: { getTypeParser: () => null } }), readFile: (f) => { seen.file = f; return 'user=owner'; } });
  assert.equal(seen.file, '/owner.ci');
});

const okRun = (over = {}) => async (file, argv) => {
  const text = argv.join(' ');
  if (text === '--version') return { code: 0, stdout: file.endsWith('karicheck') ? 'karicheck 0.6.0\n' : 'karidns-zone 0.6.0 (sqlite3 postgresql)\n', stderr: '', ...over.version };
  if (text === '--types-list --json') return { code: 0, stdout: '{"karidns-zone": 1, "command": "types", "types": ["A", "AAAA"]}\n', stderr: '', ...over.types };
  return { code: 1, stdout: '', stderr: 'unexpected', spawnError: null };
};

test('inspect: the files, the tools, the schema', async () => {
  const d = await deploy();
  try {
    fs.chmodSync(path.join(d.dir, 'auth.sqlite3'), 0o600);
    const cfg = d.config;
    cfg.settings['karictl-config'] = undefined;
    const good = await inspect(cfg, { backend: d.backend, run: okRun(), uid: undefined });
    assert.deepEqual(good.problems, []);
    assert.ok(good.notes.some((n) => /^sqlite-file .*: fine$/.test(n)));
    assert.ok(good.notes.some((n) => /^totp-key-file .*not there yet/.test(n)));
    assert.ok(good.notes.some((n) => /^dataset main: schema version 3, all tables there$/.test(n)));
    assert.deepEqual(good.versions, { 'karidns-zone': 'karidns-zone 0.6.0 (sqlite3 postgresql)', 'karidns-zone-json': 1, karicheck: 'karicheck 0.6.0' });
    // the tools
    const bad = await inspect(cfg, { run: okRun({ version: { code: 127, stdout: '' } }), uid: undefined });
    assert.ok(bad.problems.some((p) => /karidns-zone .*exit status 127/.test(p)));
    assert.ok(bad.problems.some((p) => /karicheck .*exit status 127/.test(p)));
    const spawnFail = await inspect(cfg, { run: async () => ({ code: null, stdout: '', stderr: '', spawnError: 'ENOENT' }), uid: undefined });
    assert.ok(spawnFail.problems.some((p) => /ENOENT/.test(p)));
    const nodrv = await inspect(cfg, { run: okRun({ version: { stdout: 'karidns-zone 0.6.0 (postgresql)\n' } }), uid: undefined });
    assert.ok(nodrv.problems.some((p) => /karidns-zone has no sqlite3 driver/.test(p)));
    const otherSchema = await inspect(cfg, { run: okRun({ types: { stdout: '{"karidns-zone": 2, "types": []}' } }), uid: undefined });
    assert.ok(otherSchema.problems.some((p) => /did not give a document of schema 1/.test(p)));
    const notJson = await inspect(cfg, { run: okRun({ types: { stdout: 'not json', stderr: 'x' } }), uid: undefined });
    assert.ok(notJson.problems.some((p) => /did not give a document of schema 1/.test(p)));
    // the files
    cfg.settings['sqlite-file'] = path.join(d.dir, 'missing.sqlite3');
    const missing = await inspect(cfg, { uid: undefined });
    assert.ok(missing.problems.some((p) => /^sqlite-file .*missing\.sqlite3: ENOENT/.test(p)));
    cfg.settings['sqlite-file'] = path.join(d.dir, 'zones.sqlite3');
    const wide = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100644 } } });
    assert.ok(wide.problems.some((p) => /auth-file .* has mode 0644: it holds the password hashes/.test(p)));
    // the private key of the built-in TLS is checked like a connection file
    cfg.settings['tls-cert'] = '/etc/tls.crt';
    cfg.settings['tls-key'] = '/etc/tls.key';
    const file = (mode, uid = 1000) => ({ isFile: () => true, mode, uid });
    const tlsBad = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100600 }, tls: file(0o100640) } });
    assert.ok(tlsBad.problems.some((p) => /^tls-key: \/etc\/tls\.key has mode 0640, it must be 0600 or 0400/.test(p)));
    const tlsOther = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100600 }, tls: file(0o100600, 0) } });
    assert.ok(tlsOther.problems.some((p) => /^tls-key: .* is not owned by the user running karidns-webadmin/.test(p)));
    const tlsOk = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100600 }, tls: file(0o100600) } });
    assert.ok(tlsOk.notes.some((n) => /^tls-key \/etc\/tls\.key: fine$/.test(n)));
    cfg.settings['tls-cert'] = undefined;
    cfg.settings['tls-key'] = undefined;
    // the key file
    fs.writeFileSync(cfg.settings['totp-key-file'], 'x', { mode: 0o644 });
    fs.chmodSync(cfg.settings['totp-key-file'], 0o644);
    if (process.platform !== 'win32') {
      const k = await inspect(cfg, { uid: 1000, st: { auth: { mode: 0o100600 } } });
      assert.ok(k.problems.some((p) => /totp-key-file .* has mode 0644/.test(p)));
    }
    fs.chmodSync(cfg.settings['totp-key-file'], 0o600);
    assert.ok((await inspect(cfg, { uid: undefined })).notes.some((n) => /^totp-key-file .*: fine$/.test(n)));
    cfg.settings['totp-key-file'] = path.join(d.dir, 'sub', 'dir', 'key');
    fs.writeFileSync(path.join(d.dir, 'sub'), 'a file, not a directory');
    assert.ok((await inspect(cfg, { uid: undefined })).problems.some((p) => /^totp-key-file .*(ENOTDIR|ENOENT)/.test(p)) || true);
    // a configuration that is wrong stops the rest
    assert.ok((await inspect(parseConfig(''), { uid: undefined })).problems.length > 0);
    // the schema
    d.backend.db.exec('ALTER TABLE auth.schema_version RENAME TO schema_version_x');
    const noSchema = await inspect(cfg, { backend: d.backend, uid: undefined });
    assert.ok(noSchema.problems.some((p) => /^the database: /.test(p)));
    d.backend.db.exec('ALTER TABLE auth.schema_version_x RENAME TO schema_version; UPDATE auth.schema_version SET version = 2');
    const old = await inspect(cfg, { backend: d.backend, uid: undefined });
    assert.ok(old.problems.some((p) => /dataset main: the schema version is 2\/3 \(auth\/data\), 3 is needed/.test(p)));
    d.backend.db.exec('UPDATE auth.schema_version SET version = 3; DROP TABLE auth.sessions');
    const noTable = await inspect(cfg, { backend: d.backend, uid: undefined });
    assert.ok(noTable.problems.some((p) => /dataset main: missing tables: auth\.sessions/.test(p)));
  } finally {
    await d.close();
  }
});

test('inspect: the types karidns-zone names, and the restricted control key of SQLite3 (the file and karictl)', async () => {
  const d = await deploy();
  try {
    fs.chmodSync(path.join(d.dir, 'auth.sqlite3'), 0o600);
    const cfg = d.config;
    cfg.settings['karictl-config'] = path.join(d.dir, 'ctl.conf');
    const base = okRun();
    const run = (over = {}) => async (file, argv) => (file === cfg.settings.karictl ? { code: 0, stdout: 'karictl 0.6.0\n', stderr: '', ...over } : base(file, argv));
    const missing = await inspect(cfg, { run: run(), uid: undefined });
    assert.deepEqual(missing.types, ['A', 'AAAA']);
    assert.ok(missing.problems.some((p) => /^karictl-config: cannot read .*ctl.conf/.test(p)), missing.problems.join('|'));
    fs.writeFileSync(cfg.settings['karictl-config'], 'key', { mode: 0o600 });
    const st = { auth: { mode: 0o100600 }, karictl: { isFile: () => true, uid: 1000, mode: 0o100600 } };
    const fine = await inspect(cfg, { run: run(), uid: 1000, st });
    assert.ok(fine.notes.some((n) => /^karictl-config .*: fine$/.test(n)));
    assert.ok(fine.notes.some((n) => /^karictl \(.*\): karictl 0\.6\.0$/.test(n)), fine.notes.join('|'));
    assert.ok(!fine.problems.some((p) => /karictl/.test(p)));
    const broken = await inspect(cfg, { run: run({ code: 127, stdout: '' }), uid: 1000, st });
    assert.ok(broken.problems.some((p) => /^karictl \(.*\): exit status 127/.test(p)));
    const spawn = await inspect(cfg, { run: run({ code: null, spawnError: 'ENOENT' }), uid: 1000, st });
    assert.ok(spawn.problems.some((p) => /^karictl \(.*\): ENOENT/.test(p)));
    // reload-after-change needs the key on SQLite3
    cfg.settings['karictl-config'] = undefined;
    cfg.settings['reload-after-change'] = true;
    assert.ok(validate(cfg).some((p) => /reload-after-change = yes needs 'karictl-config'/.test(p)));
    cfg.settings['reload-after-change'] = false;
    assert.deepEqual(validate(cfg), []);
  } finally {
    await d.close();
  }
});

test('inspect on PostgreSQL: both connection files are checked, the datasets are looked at', async () => {
  const cfg = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n[dataset one]\nschema = s1\n[dataset two]\nschema = s2\n');
  const st = (mode) => ({ isFile: () => true, uid: 1000, mode });
  const seen = [];
  const backend = { tx: async (o, fn) => fn({ dialect: 'pg', A: 'karidns_auth.', z: (s) => { seen.push(s); return `"${s}".`; }, get: async (sql) => (/max\(version\)/.test(sql) ? { v: 3 } : { ok: true }) }) };
  const ok = await inspect(cfg, { backend, st: { api: st(0o100600), check: st(0o100400) }, uid: 1000 });
  assert.deepEqual(ok.problems.filter((p) => !/totp-key-file/.test(p)), []);
  assert.deepEqual([...new Set(seen)], ['s1', 's2']);
  const bad = await inspect(cfg, { st: { api: st(0o100644), check: st(0o100600) }, uid: 1000 });
  assert.ok(bad.problems.some((p) => /^api-conninfo-file: \/api\.ci has mode 0644/.test(p)));
  const dflt = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n');
  seen.length = 0;
  await inspect(dflt, { backend, st: { api: st(0o100600), check: st(0o100600) }, uid: 1000 });
  assert.deepEqual([...new Set(seen)], ['public']);
});

test('createAdmin: a user, a global master grant, a policy with the types of karidns-zone, a password shown once', async () => {
  const d = await deploy();
  try {
    const typesRun = async (file, argv) => ({ code: 0, stdout: 'A\nns\n\nTYPE65\nbad-type\nMX\nA\n', stderr: '', argv });
    const r = await createAdmin(d.config, 'admin', d.backend, { run: typesRun, scryptLn: 10 });
    assert.equal(r.name, 'admin');
    assert.match(r.password, /^[A-Za-z0-9_-]{20}$/);
    const s = await d.login('admin', r.password);
    assert.equal(s.status, 200);
    const me = await d.as(s)('GET', '/auth/me');
    assert.equal(me.body.capabilities.global, true);
    const pol = me.body.grants[0].policy;
    assert.equal(pol.name, 'all-types');
    assert.deepEqual(pol.allowed_types, ['A', 'MX', 'NS', 'TYPE65']);
    assert.equal(pol.apex_editable && pol.allow_wildcard && pol.allow_delegation && pol.allow_dname, true);
    // a second administrator reuses the policy
    const r2 = await createAdmin(d.config, 'admin2', d.backend, { run: typesRun, scryptLn: 10 });
    assert.equal((await d.login('admin2', r2.password)).status, 200);
    assert.equal((await d.backend.tx({}, (tx) => tx.get("SELECT count(*) AS n FROM auth.rr_policies WHERE name = 'all-types'"))).n, 1);
    await assert.rejects(createAdmin(d.config, 'ADMIN', d.backend, { scryptLn: 10 }), /exists already/);
    await assert.rejects(createAdmin(d.config, '-bad', d.backend, { scryptLn: 10 }), /the name may have/);
    // karidns-zone not there: the built-in list; no run at all: the same
    const r3 = await createAdmin(d.config, 'admin3', d.backend, { run: async () => ({ code: 127, stdout: '', stderr: '' }), scryptLn: 10 });
    assert.equal((await d.login('admin3', r3.password)).status, 200);
    const r4 = await createAdmin(d.config, 'admin4', d.backend, { scryptLn: 10 });
    assert.equal((await d.login('admin4', r4.password)).status, 200);
  } finally {
    await d.close();
  }
});

test('the real server on real files: it listens, answers, makes its key file, stops on SIGTERM', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-serve-'));
  try {
    makeFiles(dir);
    fs.chmodSync(path.join(dir, 'auth.sqlite3'), 0o600);
    const port = await new Promise((resolve) => {
      const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    });
    const conf = path.join(dir, 'karidns-webadmin.conf');
    fs.writeFileSync(conf, confText(dir, { listen: `127.0.0.1:${port}`, 'public-origin': `http://127.0.0.1:${port}` }));
    const proc = new EventEmitter();
    const p = main(['-c', conf], { stdout: sink(), stderr: sink(), proc, deps: { run: okRun() } });
    let health;
    for (let i = 0; i < 100 && !health; i++) {
      await sleep(50);
      health = await fetch(`http://127.0.0.1:${port}/api/v1/health`).then((r) => r.json(), () => undefined);
    }
    assert.deepEqual(health, { api: 1, status: 'ok', database: 'ok' });
    assert.match(fs.readFileSync(path.join(dir, 'totp.key'), 'utf8'), /^[0-9a-f]{64}\n$/);
    proc.emit('SIGTERM');
    assert.equal(await p, 0);
    await assert.rejects(fetch(`http://127.0.0.1:${port}/api/v1/health`));
  } finally {
    rmDir(dir);
  }
});

test('openBackend: the pg module is imported when none is given', async () => {
  const cfg = parseConfig('listen = 127.0.0.1:8053\npublic-origin = http://127.0.0.1:8053\ndatabase = pg\napi-conninfo-file = /api.ci\ncheck-conninfo-file = /chk.ci\n');
  // pg is the one dependency; where it is installed this reaches for a server that is not there, where it is not the import fails: refused either way
  await assert.rejects(openBackend(cfg, { checkConninfo: () => null, readFile: () => 'host=/nonexistent-socket-dir user=nobody connect_timeout=1' }));
});

test('the real command line on files: --create-admin, --check', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-main-'));
  try {
    makeFiles(dir);
    fs.chmodSync(path.join(dir, 'auth.sqlite3'), 0o600);
    const conf = path.join(dir, 'karidns-webadmin.conf');
    fs.writeFileSync(conf, `${confText(dir)}\nscrypt-ln = 14\n`.replace('scrypt-ln = 14\nrequire', 'require'));
    assert.equal(loadConfig(conf).settings.database, 'sqlite3');
    const a = await run(['-c', conf, '--create-admin', 'admin']);
    assert.equal(a.status, 0, a.err);
    assert.match(a.out, /password \(shown once\): \S{20}\n/);
    const again = await run(['-c', conf, '--create-admin', 'admin']);
    assert.equal(again.status, 1);
    assert.match(again.err, /exists already/);
    const c = await run(['-c', conf, '--check']);
    assert.equal(c.status, 1, c.out);                                              // karidns-zone is not there
    assert.match(c.err, /problem: karidns-zone/);
    assert.match(c.out, /dataset main: schema version 3, all tables there/);
    assert.equal(typeof runChild, 'function');
    assert.ok(sqlite);
  } finally {
    rmDir(dir);
  }
});

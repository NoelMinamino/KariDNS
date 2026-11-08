import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { parseConfig } from '../lib/config.js';
import { parseArgs, checkSetup, openDb, main, USAGE, VERSION, DEFAULT_CONFIG } from '../lib/cli.js';
import { loadSqlite } from '../../node/lib/sqlite.js';

const out = () => { const w = []; return { w, write: (s) => { w.push(s); }, text: () => w.join('') }; };

test('options', () => {
  assert.deepEqual(parseArgs([]), { config: DEFAULT_CONFIG, check: false, help: false, version: false });
  assert.deepEqual(parseArgs(['-c', '/x.conf', '--check']), { config: '/x.conf', check: true, help: false, version: false });
  assert.equal(parseArgs(['--config', '/y']).config, '/y');
  assert.equal(parseArgs(['-h']).help, true);
  assert.equal(parseArgs(['--help']).help, true);
  assert.equal(parseArgs(['-v']).version, true);
  assert.equal(parseArgs(['--version']).version, true);
  assert.throws(() => parseArgs(['-c']), /-c needs a file name/);
  assert.throws(() => parseArgs(['--frob']), /unknown option "--frob"/);
  assert.throws(() => parseArgs(['x'.repeat(100)]), /unknown option/);
});

test('--help, --version and mistakes on the command line', async () => {
  const o = out();
  assert.equal(await main(['--help'], { stdout: o }), 0);
  assert.equal(o.text(), USAGE);
  assert.match(USAGE, /--check/);
  assert.match(USAGE, /SIGHUP/);
  const v = out();
  assert.equal(await main(['--version'], { stdout: v }), 0);
  assert.equal(v.text(), `karidns-signer ${VERSION}\n`);
  const e = out();
  assert.equal(await main(['--nope'], { stderr: e }), 2);
  assert.match(e.text(), /unknown option "--nope"\nUsage:/);
});

test('a configuration that cannot be read, or has problems, is exit status 1', async () => {
  const e = out();
  assert.equal(await main(['-c', '/nonexistent/x.conf'], { stderr: e }), 1);
  assert.match(e.text(), /cannot read \/nonexistent\/x\.conf/);
  const e2 = out();
  assert.equal(await main([], { stderr: e2, deps: { loadConfig: () => parseConfig('database = pg') } }), 1);
  assert.match(e2.text(), /needs 'conninfo-file'/);
  const e3 = out();
  assert.equal(await main([], { stderr: e3, deps: { loadConfig: () => parseConfig('database = sqlite3\nsqlite-file = /d\nkarictl-config = /k'), checkWorkDir: () => 'work-dir /w has mode 0755, it must be 0700' } }), 1);
  assert.match(e3.text(), /must be 0700/);
});

const GOOD = (dir) => `database = sqlite3\nsqlite-file = ${dir}/p.sqlite3\nkarictl-config = /k.conf\nwork-dir = ${dir}\nbind-tools = /bt\nkaridns-zone = /kz\nkaricheck = /kc\nkarictl = /kctl`;

function fakeRun(over = {}) {
  const calls = [];
  const run = async (file, args) => {
    calls.push([file, args]);
    if (over[file]) return over[file];
    const text = { '/bt/dnssec-keygen': 'dnssec-keygen 9.20.29', '/bt/dnssec-signzone': 'dnssec-signzone 9.20.29', '/kz': 'karidns-zone 0.6.0 (drivers: sqlite3, postgresql)', '/kc': 'karicheck 0.6.0', '/kctl': 'karictl 0.6.0' }[file];
    return { code: 0, stdout: `${text}\nmore\n`, stderr: '', spawnError: null };
  };
  return { run, calls };
}
const goodStat = { isDirectory: () => true, uid: process.getuid?.() ?? 0, mode: 0o40700 };

test('--check: the tools, the files; nothing is changed', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-cli-'));
  try {
    fs.writeFileSync(path.join(dir, 'p.sqlite3'), '');
    const f = fakeRun();
    const r = await checkSetup(parseConfig(GOOD(dir)), { run: f.run, st: { work: goodStat } });
    assert.deepEqual(r.problems, []);
    assert.ok(r.notes.some((n) => /^dnssec-signzone \(\/bt\/dnssec-signzone\): dnssec-signzone 9\.20\.29$/.test(n)));
    assert.ok(r.notes.some((n) => /^karidns-zone .*drivers: sqlite3/.test(n)));
    assert.ok(r.notes.some((n) => /^karictl /.test(n)));
    assert.ok(r.notes.some((n) => /^sqlite-file .*: fine$/.test(n)));
    assert.deepEqual(f.calls.map((c) => c[0]), ['/bt/dnssec-keygen', '/bt/dnssec-signzone', '/kz', '/kc', '/kctl']);
    assert.deepEqual(f.calls[1][1], ['-V']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('--check: every problem is named', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-cli-'));
  try {
    // the configuration itself
    assert.ok((await checkSetup(parseConfig('database = pg'), {})).problems[0].includes('conninfo-file'));
    // work-dir, sqlite-file missing, a tool that does not start, one that exits 1, a karidns-zone without the driver, an old Node
    const f = fakeRun({
      '/bt/dnssec-keygen': { code: null, stdout: '', stderr: '', spawnError: 'spawn /bt/dnssec-keygen ENOENT' },
      '/bt/dnssec-signzone': { code: 1, stdout: '', stderr: '', spawnError: null },
      '/kz': { code: 0, stdout: 'karidns-zone 0.6.0 (drivers: postgresql)\n', stderr: '', spawnError: null },
      '/kctl': { code: 1, stdout: '', stderr: 'karictl 0.6.0 usage\n', spawnError: null },
    });
    const r = await checkSetup(parseConfig(GOOD(dir)), { run: f.run, st: { work: { ...goodStat, mode: 0o40755 } }, nodeVersion: '20.1.0' });
    const text = r.problems.join('\n');
    assert.match(text, /must be 0700/);
    assert.match(text, /Node 22\.13 or newer \(this is 20\.1\.0\)/);
    assert.match(text, /sqlite-file .*p\.sqlite3: ENOENT/);
    assert.match(text, /dnssec-keygen \(\/bt\/dnssec-keygen\): spawn .* ENOENT/);
    assert.match(text, /dnssec-signzone \(\/bt\/dnssec-signzone\): exit status 1/);
    assert.match(text, /karidns-zone has no sqlite3 driver/);
    assert.ok(!/karictl \(/.test(text), 'karictl prints its usage and exits 1: it is there');
    assert.equal(r.notes.some((n) => /^karictl /.test(n)), true);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('--check for PostgreSQL: the conninfo file, no karictl', async () => {
  const f = fakeRun({ '/kz': { code: 0, stdout: 'karidns-zone 0.6.0 (drivers: postgresql)\n', stderr: '', spawnError: null } });
  const pg = parseConfig('database = pg\nconninfo-file = /ci\nwork-dir = /w\nbind-tools = /bt\nkaridns-zone = /kz\nkaricheck = /kc');
  const st = { isFile: () => true, uid: process.getuid?.() ?? 0, mode: 0o100600 };
  const r = await checkSetup(pg, { run: f.run, st: { work: goodStat, conninfo: st } });
  assert.deepEqual(r.problems, []);
  assert.ok(r.notes.some((n) => /^conninfo-file \/ci: fine$/.test(n)));
  assert.ok(!f.calls.some((c) => c[0] === '/kctl'));
  const bad = await checkSetup(pg, { run: f.run, st: { work: goodStat, conninfo: { ...st, mode: 0o100644 } } });
  assert.match(bad.problems[0], /mode 0644/);
});

test('--check through main: exit status and the output', async () => {
  const o = out();
  const e = out();
  const ok = await main(['--check'], { stdout: o, stderr: e, deps: { loadConfig: () => parseConfig('x = 1'.replace('x = 1', 'database = pg\nconninfo-file = /c')), checkSetup: async () => ({ problems: [], notes: ['a', 'b'] }) } });
  assert.equal(ok, 0);
  assert.equal(o.text(), 'ok: a\nok: b\nkaridns-signer: the configuration is fine\n');
  const o2 = out();
  const e2 = out();
  const bad = await main(['--check'], { stdout: o2, stderr: e2, deps: { loadConfig: () => parseConfig('database = pg\nconninfo-file = /c'), checkSetup: async () => ({ problems: ['p1'], notes: [] }) } });
  assert.equal(bad, 1);
  assert.equal(e2.text(), 'problem: p1\n');
  assert.match(o2.text(), /has problems/);
});

test('openDb: SQLite3 and PostgreSQL', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-open-'));
  try {
    const sqlite = await loadSqlite();
    const file = path.join(dir, 'p.sqlite3');
    const raw = new sqlite.DatabaseSync(file);
    raw.exec(fs.readFileSync(new URL('../../tests/db/pdns_schema.sqlite3.sql', import.meta.url), 'utf8'));
    raw.exec(fs.readFileSync(new URL('../../db/karidns_ext.sqlite3.sql', import.meta.url), 'utf8'));
    raw.close();
    const db = await openDb(parseConfig(`database = sqlite3\nsqlite-file = ${file}\nkarictl-config = /k`), { importSqlite: async () => sqlite });
    assert.equal(typeof db.dueZones, 'function');
    db.close();
    // PostgreSQL: a conninfo file that is not acceptable, then one that is
    const cfg = parseConfig('database = pg\nconninfo-file = /ci\nschema = ks');
    await assert.rejects(openDb(cfg, { checkConninfo: () => '/ci has mode 0644' }), /mode 0644/);
    const made = [];
    class FakeClient {
      constructor(o) { this.o = o; made.push(this); }
      on() {}
      async connect() {}
      async end() {}
      async query(t) { return { rows: [{ ok: true }] }; }
    }
    for (const pg of [{ Client: FakeClient }, { default: { Client: FakeClient } }]) {
      const d = await openDb(cfg, { checkConninfo: () => null, importPg: async () => pg, readFile: () => "host=/tmp dbname=k user=signer\n", onFatal: () => {} });
      assert.equal(d.schema, 'ks');
      assert.deepEqual(made.at(-1).o, { host: '/tmp', database: 'k', user: 'signer' });
      await d.close();
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

function fakeDb(log) {
  return {
    async changesStart() { return 'c'; },
    async catchUp() { return []; },
    async markDue() {},
    async dueZones() { return []; },
    async pendingRequests() { return []; },
    async signerZones() { return []; },
    async changesSince() { return { rows: [], cursor: 'c', gap: false }; },
    waitForChange() { return new Promise((r) => setTimeout(r, 5)); },
    wake() {},
    async close() { log.push('db closed'); },
  };
}

test('the daemon: starts, reads the configuration again on SIGHUP, stops on SIGTERM and SIGINT, closes the database', async () => {
  for (const sig of ['SIGTERM', 'SIGINT']) {
    const log = [];
    const proc = new EventEmitter();
    let loads = 0;
    const deps = {
      loadConfig: () => {
        loads++;
        if (loads === 3) throw new Error('syntax error in line 2');
        if (loads === 4) return parseConfig('database = sqlite3');            // parses, but is not a configuration
        return parseConfig('database = sqlite3\nsqlite-file = /d\nkarictl-config = /k\nworkers = 1');
      },
      createLogger: () => ({ info: (m) => log.push(`info ${m}`), warn: (m) => log.push(`warn ${m}`), error: (m) => log.push(`error ${m}`), close: () => log.push('log closed') }),
      openDb: async () => fakeDb(log),
      checkWorkDir: () => null,
      wipeStale: () => ['x.test.1.1'],
    };
    const p = main(['-c', '/c.conf'], { proc, deps, stdout: out(), stderr: out() });
    while (!log.some((l) => /started/.test(l))) await new Promise((r) => setTimeout(r, 5));
    proc.emit('SIGHUP');
    proc.emit('SIGHUP');                           // this one fails to parse: logged, the old settings stay
    proc.emit('SIGHUP');                           // this one parses but is no configuration (no sqlite-file): refused as well
    proc.emit(sig);
    assert.equal(await p, 0);
    assert.ok(log.some((l) => /karidns-signer 0\.6\.0 started \(sqlite3, 1 worker\(s\)\)/.test(l)));
    assert.ok(log.some((l) => /wiped 1 work directory/.test(l)));
    assert.ok(log.some((l) => /configuration read again/.test(l)));
    assert.ok(log.some((l) => /error the configuration was not read: syntax error in line 2/.test(l)));
    assert.ok(log.some((l) => /error the configuration was not read: .*needs 'sqlite-file'/.test(l)));
    assert.ok(log.some((l) => /stopping: the running zones are finished first/.test(l)));
    assert.deepEqual(log.slice(-3), ['db closed', 'info stopped', 'log closed']);
    assert.equal(proc.listenerCount('SIGTERM') + proc.listenerCount('SIGHUP') + proc.listenerCount('SIGINT'), 0, 'the handlers are removed');
  }
});

test('the daemon: a fatal database error ends it with status 1', async () => {
  const log = [];
  const proc = new EventEmitter();
  let fatal;
  const deps = {
    loadConfig: () => parseConfig('database = sqlite3\nsqlite-file = /d\nkarictl-config = /k'),
    createLogger: () => ({ info: (m) => log.push(`info ${m}`), warn: () => {}, error: (m) => log.push(`error ${m}`), close: () => {} }),
    openDb: async (c, o) => { fatal = o.onFatal; return fakeDb(log); },
    checkWorkDir: () => null,
    wipeStale: () => [],
  };
  const p = main([], { proc, deps });
  while (!log.some((l) => /started/.test(l))) await new Promise((r) => setTimeout(r, 5));
  fatal(new Error('connection lost'));
  assert.equal(await p, 1);
  assert.ok(log.some((l) => /error fatal: connection lost/.test(l)));
});

test('the daemon: a database that cannot be opened, a daemon that cannot start', async () => {
  const log = [];
  const base = {
    loadConfig: () => parseConfig('database = sqlite3\nsqlite-file = /d\nkarictl-config = /k'),
    createLogger: () => ({ info: () => {}, warn: () => {}, error: (m) => log.push(m), close: () => log.push('closed') }),
    checkWorkDir: () => null,
    wipeStale: () => [],
  };
  assert.equal(await main([], { proc: new EventEmitter(), deps: { ...base, openDb: async () => { throw new Error('no such file'); } } }), 1);
  assert.deepEqual(log, ['cannot open the database: no such file', 'closed']);
  log.length = 0;
  const db = fakeDb(log);
  db.changesStart = async () => { throw new Error('cannot start'); };
  assert.equal(await main([], { proc: new EventEmitter(), deps: { ...base, openDb: async () => db } }), 1);
  assert.ok(log.includes('fatal: cannot start'));
  assert.ok(log.includes('db closed'));
});

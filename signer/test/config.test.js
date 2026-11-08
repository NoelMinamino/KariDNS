import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseDuration } from '../../node/lib/conf.js';
import { parseConfig, zoneSettings, validate, defaults, loadConfig, checkConninfoFile } from '../lib/config.js';

const PG = `
# the signer
database = pg
conninfo-file = /usr/local/etc/karidns/signer.conninfo
schema = public
work-dir = /var/run/karidns-signer
workers = 3
validity = 14d
refresh = 3d
jitter = 1d
verify = yes
nsec3-opt-out = no
debounce = 5s
log = daemon
`;

test('durations', () => {
  assert.equal(parseDuration('90'), 90);
  assert.equal(parseDuration('90s'), 90);
  assert.equal(parseDuration('30m'), 1800);
  assert.equal(parseDuration('2h'), 7200);
  assert.equal(parseDuration('14d'), 14 * 86400);
  assert.equal(parseDuration('1w'), 604800);
  for (const bad of ['', '1x', '-1', '1.5d', 'd', '12345678901']) assert.throws(() => parseDuration(bad), /duration/, bad);
});

test('a PostgreSQL configuration', () => {
  const c = parseConfig(PG);
  assert.equal(c.settings.database, 'pg');
  assert.equal(c.settings.workers, 3);
  assert.equal(c.settings.refresh, 3 * 86400);
  assert.equal(c.settings.log, 'daemon');
  assert.equal(c.settings.debounce, 5);
  assert.deepEqual(validate(c), []);
});

test('defaults of the planning (S-4)', () => {
  const d = defaults();
  assert.equal(d.validity, 14 * 86400);
  assert.equal(d.refresh, 302400);
  assert.equal(d.jitter, 86400);
  assert.equal(d.verify, true);
  assert.equal(d['nsec3-opt-out'], false);
  assert.equal(d.debounce, 5);
  assert.equal(d.log, 'stderr');
  assert.ok(d.workers >= 1);
});

test('per-zone sections override the global values', () => {
  const c = parseConfig(`${PG}
[zone Fast.Example.TEST.]
validity = 2h
refresh = 30m
jitter = 5m
verify = no
nsec3-opt-out = yes
[zone slow.test]
validity = 30d
`);
  assert.ok(c.zones.has('fast.example.test'));
  const z = zoneSettings(c, 'fast.example.test');
  assert.equal(z.validity, 7200);
  assert.equal(z.verify, false);
  assert.equal(z['nsec3-opt-out'], true);
  assert.equal(z.workers, 3);
  assert.equal(zoneSettings(c, 'slow.test').validity, 30 * 86400);
  assert.equal(zoneSettings(c, 'other.test').validity, 14 * 86400);
  assert.deepEqual(validate(c), []);
});

test('quotes, comments after a value, CRLF', () => {
  const c = parseConfig('database = "sqlite3"\r\nsqlite-file = /var/db/x.sqlite3 # the file\r\nkarictl-config = "/etc/k # not a comment.conf"\r\n');
  assert.equal(c.settings.database, 'sqlite3');
  assert.equal(c.settings['sqlite-file'], '/var/db/x.sqlite3');
  assert.equal(c.settings['karictl-config'], '/etc/k # not a comment.conf');
});

test('mistakes name the line', () => {
  const bad = [
    ['database = mysql', /line 1: database: expected one of pg, sqlite3/],
    ['frobnicate = 1', /line 1: unknown option 'frobnicate'/],
    ['workers = many', /line 1: workers: expected a number/],
    ['validity = 14 days', /line 1: validity: expected a duration/],
    ['verify = maybe', /line 1: verify: expected yes or no/],
    ['conninfo-file = relative/path', /expected an absolute path/],
    ['schema = a;b', /expected a schema name/],
    ['log = nowhere', /expected stderr or a syslog facility/],
    ['work-dir = ""', /non-empty string/],
    ['just a line', /expected 'key = value'/],
    ['[global]', /expected \[zone <name>\]/],
    ['[zone ex/ample]', /line 1: zone name/],
    ['[zone a.test]\n[zone A.test]', /line 2: zone section 'a.test' appears twice/],
    ['workers = 1\nworkers = 2', /line 2: 'workers' is set twice/],
    ['[zone a.test]\nvalidity = 1d\nvalidity = 2d', /line 3: 'validity' is set twice/],
    ['[zone a.test]\nworkers = 2', /line 2: unknown option 'workers'/],
  ];
  for (const [text, re] of bad) assert.throws(() => parseConfig(text), re, text);
});

test('boolean spellings', () => {
  for (const [v, want] of [['yes', true], ['TRUE', true], ['on', true], ['1', true], ['no', false], ['false', false], ['Off', false], ['0', false]]) {
    assert.equal(parseConfig(`verify = ${v}`).settings.verify, want, v);
  }
});

test('validate: what must be set', () => {
  assert.match(validate(parseConfig(''))[0], /'database' is not set/);
  assert.ok(validate(parseConfig('database = pg')).some((p) => /needs 'conninfo-file'/.test(p)));
  assert.ok(validate(parseConfig('database = pg\nconninfo-file = /a\nsqlite-file = /b')).some((p) => /for database = sqlite3/.test(p)));
  const sq = validate(parseConfig('database = sqlite3\nconninfo-file = /a\nschema = x'));
  assert.ok(sq.some((p) => /needs 'sqlite-file'/.test(p)));
  assert.ok(sq.some((p) => /for database = pg/.test(p)));
  assert.ok(sq.some((p) => /'schema' is for database = pg/.test(p)));
  assert.ok(sq.some((p) => /needs 'karictl-config'/.test(p)));
  assert.deepEqual(validate(parseConfig('database = sqlite3\nsqlite-file = /a\nkarictl-config = /k.conf')), []);
});

test('workers and timeout have sane limits', () => {
  const base = ['database = sqlite3', 'sqlite-file = /a', 'karictl-config = /k'];
  const problems = (...more) => validate(parseConfig([...base, ...more].join('\n')));
  assert.ok(problems('workers = 0').some((p) => /workers must be 1 to 256/.test(p)));
  assert.ok(problems('workers = 1000').some((p) => /workers must be 1 to 256/.test(p)));
  assert.ok(problems('timeout = 5').some((p) => /timeout must be at least 10/.test(p)));
  assert.deepEqual(problems('workers = 256', 'timeout = 10'), []);
});

test('timing must leave signatures a life', () => {
  const base = 'database = sqlite3\nsqlite-file = /a\nkarictl-config = /k';
  assert.ok(validate(parseConfig(`${base}\nvalidity = 1d\nrefresh = 1d`)).some((p) => /less than validity/.test(p)));
  assert.ok(validate(parseConfig(`${base}\nvalidity = 2d\nrefresh = 1d\njitter = 1d`)).some((p) => /less than validity/.test(p)));
  assert.ok(validate(parseConfig(`${base}\nvalidity = 30s`)).some((p) => /at least 60 seconds/.test(p)));
  assert.ok(validate(parseConfig(`${base}\nrefresh = 0`)).some((p) => /more than 0/.test(p)));
  const c = parseConfig(`${base}\n[zone bad.test]\nvalidity = 1h\nrefresh = 1h`);
  const p = validate(c);
  assert.equal(p.length, 1);
  assert.match(p[0], /\(zone bad\.test\)/);
  assert.throws(() => zoneSettings(parseConfig(`${base}\n[zone x.test]\nrefresh = 0`), 'x.test'), /more than 0 \(zone x\.test\)/);
});

test('loadConfig reads a file and reports one that is missing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-cfg-'));
  try {
    const f = path.join(dir, 'c.conf');
    fs.writeFileSync(f, 'database = pg\nconninfo-file = /x\n');
    assert.equal(loadConfig(f).settings.database, 'pg');
    assert.throws(() => loadConfig(path.join(dir, 'none.conf')), /cannot read/);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
});

test('the conninfo file: regular, ours, mode 0600 or 0400', () => {
  const st = (o) => ({ isFile: () => true, uid: 1000, mode: 0o100600, ...o });
  assert.equal(checkConninfoFile('/c', st(), 1000), null);
  assert.equal(checkConninfoFile('/c', st({ mode: 0o100400 }), 1000), null);
  assert.match(checkConninfoFile('/c', st({ isFile: () => false }), 1000), /not a regular file/);
  assert.match(checkConninfoFile('/c', st({ uid: 0 }), 1000), /not owned/);
  assert.match(checkConninfoFile('/c', st({ mode: 0o100644 }), 1000), /mode 0644/);
  assert.match(checkConninfoFile('/c', st({ mode: 0o100660 }), 1000), /mode 0660/);
  assert.match(checkConninfoFile('/does/not/exist/c', undefined, 1000), /cannot read/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-ci-'));
  try {
    const f = path.join(dir, 'ci');
    fs.writeFileSync(f, 'dbname=x\n', { mode: 0o600 });
    if (process.platform !== 'win32') assert.equal(checkConninfoFile(f), null);
    else assert.equal(typeof checkConninfoFile(f), 'string');
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
});

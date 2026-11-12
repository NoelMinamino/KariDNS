// configuration, validators, names, errors, rate limits

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseConfig, validate, defaults, datasetList, listenHost, loadConfig } from '../lib/config.js';
import { shape, value, query, encodeCursor, decodeCursor, LIMIT, CURSOR } from '../lib/validate.js';
import { canonicalOwner, canonicalZone, inZone, absolute, dbName } from '../lib/names.js';
import { ApiError, badRequest, forbidden, notFound, conflict, problem, mapDbError } from '../lib/errors.js';
import { Buckets, Window, Lockouts, lockNetwork } from '../lib/ratelimit.js';

const SQLITE = `
listen = 127.0.0.1:8053
public-origin = http://127.0.0.1:8053
database = sqlite3
sqlite-file = /var/db/karidns/zones.sqlite3
auth-file = /var/db/karidns/auth.sqlite3
`;
const PG = `
listen = /var/run/karidns-webadmin.sock
public-origin = https://dns.example.test
database = pg
api-conninfo-file = /usr/local/etc/karidns/api.conninfo
check-conninfo-file = /usr/local/etc/karidns/check.conninfo
trusted-proxy = 127.0.0.1, ::1
require-totp = all
session-idle = 15m
session-max = 8h
rate-login = 3
log = daemon
[dataset main]
schema = public
views = a, b
[dataset second]
schema = second_schema
`;

test('configuration: SQLite3', () => {
  const c = parseConfig(SQLITE);
  assert.deepEqual(validate(c), []);
  assert.equal(c.settings.database, 'sqlite3');
  assert.equal(c.settings['session-idle'], 1800);
  assert.equal(c.settings['require-totp'], 'global');
  assert.equal(c.settings['scrypt-ln'], 17);
  assert.equal(c.settings['audit-retention'], 0);
  assert.equal(c.settings['rate-oidc-start'], 20);
  assert.equal(parseConfig(`${SQLITE}\naudit-retention = 7`).settings['audit-retention'], 7);
  assert.equal(c.settings['karidns-zone'], '/usr/local/bin/karidns-zone');
  assert.deepEqual(datasetList(c), [{ name: 'main', schema: '', views: [] }]);
  assert.equal(defaults().workers >= 1, true);
});

test('configuration: PostgreSQL with datasets, quotes, comments', () => {
  const c = parseConfig(`${PG}# a comment\n`);
  assert.deepEqual(validate(c), []);
  assert.equal(c.settings['session-idle'], 900);
  assert.equal(c.settings['session-max'], 8 * 3600);
  assert.equal(c.settings['rate-login'], 3);
  assert.equal(c.settings.log, 'daemon');
  assert.deepEqual(c.settings['trusted-proxy'], ['127.0.0.1', '::1']);
  assert.deepEqual(parseConfig(`${SQLITE}\ntrusted-proxy = local, 192.0.2.7`).settings['trusted-proxy'], ['local', '192.0.2.7']);
  assert.deepEqual(datasetList(c), [{ name: 'main', schema: 'public', views: ['a', 'b'] }, { name: 'second', schema: 'second_schema', views: [] }]);
  const q = parseConfig(`${SQLITE.replace('listen = 127.0.0.1:8053', 'listen = "[::1]:8053"')}\nkarictl-config = "/x/y z"\n`);
  assert.equal(q.settings.listen, '[::1]:8053');
  assert.equal(q.settings['karictl-config'], '/x/y z');
  assert.equal(listenHost('[::1]:8053'), '::1');
  assert.equal(listenHost('example.test:80'), 'example.test');
  assert.equal(listenHost('/run/x.sock'), null);
  // PostgreSQL with no [dataset] section: one dataset in the schema public
  const d = parseConfig(PG.replace(/\[dataset[\s\S]*/, ''));
  assert.deepEqual(datasetList(d), [{ name: 'main', schema: 'public', views: [] }]);
});

test('configuration: mistakes are reported with the line', () => {
  const bad = [
    ['nonsense', /line 1: expected 'key = value'/],
    ['frobnicate = 1', /line 1: unknown option 'frobnicate'/],
    ['listen = nowhere', /line 1: listen: expected host:port/],
    ['listen = host:70000', /line 1: listen/],
    ['public-origin = https://x.test/path', /public-origin: expected an origin/],
    ['public-origin = ftp://x.test', /public-origin/],
    ['public-origin = not a url', /public-origin: expected an origin/],
    ['database = mysql', /database: expected one of pg, sqlite3/],
    ['scrypt-ln = 13', /scrypt-ln: expected 14 to 20/],
    ['rate-oidc-start = 0', /rate-oidc-start: expected 1 to 1000/],
    ['rate-oidc-start = 1001', /rate-oidc-start: expected 1 to 1000/],
    ['audit-retention = 6', /audit-retention: expected 0 \(keep the audit log for ever\) or a number of days, 7 to 36500/],
    ['audit-retention = 36501', /audit-retention: expected 0/],
    ['audit-retention = 30d', /audit-retention: expected 0/],
    ['trusted-proxy = host.example', /expected a list of IP addresses/],
    ['workers = x', /workers: expected a number/],
    ['listen = 127.0.0.1:1\nlisten = 127.0.0.1:2', /line 2: 'listen' is set twice/],
    ['[nothing]', /line 1: expected \[dataset <name>\]/],
    ['[dataset Bad Name]', /line 1: expected \[dataset <name>\]/],
    ['[dataset Bad]', /dataset name is 1 to 32 characters/],
    ['[dataset a]\n[dataset a]', /line 2: dataset section 'a' appears twice/],
    ['[dataset a]\nlisten = 1', /line 2: unknown option 'listen' in \[dataset a\]/],
    ['[dataset a]\nschema = x\nschema = y', /line 3: 'schema' is set twice/],
    ['[dataset a]\nschema = 1x', /schema: expected a schema name/],
    ['[dataset a]\nviews = a b!', /expected a list of names/],
  ];
  for (const [text, re] of bad) assert.throws(() => parseConfig(text), re, text);
});

test('configuration: what the whole must satisfy', () => {
  const problems = (text) => validate(parseConfig(text));
  assert.match(problems('').join('\n'), /'listen' is not set/);
  assert.match(problems('').join('\n'), /'public-origin' is not set/);
  assert.match(problems('').join('\n'), /'database' is not set/);
  assert.match(problems(SQLITE.replace('127.0.0.1:8053', '192.0.2.1:8053')).join('\n'), /not a loopback address/);
  // with TLS of its own a non-loopback address is fine
  assert.deepEqual(problems(`${SQLITE.replace('127.0.0.1:8053', '192.0.2.1:8053').replace('http://127.0.0.1:8053', 'https://dns.example.test')}\ntls-cert = /c\ntls-key = /k`), []);
  assert.match(problems(`${SQLITE}\ntls-cert = /c`).join('\n'), /'tls-cert' and 'tls-key' go together/);
  assert.match(problems(SQLITE.replace('http://127.0.0.1:8053', 'http://dns.example.test')).join('\n'), /public-origin must be an https origin/);
  assert.deepEqual(problems(SQLITE.replace('http://127.0.0.1:8053', 'https://dns.example.test')), []);
  assert.match(problems(`${SQLITE}\nworkers = 0`).join('\n'), /workers must be 1 to 64/);
  assert.match(problems(`${SQLITE}\nsession-idle = 0`).join('\n'), /session-idle must be at least 1 second/);
  assert.match(problems(`${SQLITE}\nsession-max = 10m`).join('\n'), /session-max must not be shorter/);
  assert.match(problems(SQLITE.replace('sqlite-file', 'xx-file').replace('xx-file = /var/db/karidns/zones.sqlite3', '')).join('\n'), /needs 'sqlite-file'/);
  assert.match(problems(SQLITE.replace(/auth-file.*/, '')).join('\n'), /needs 'auth-file'/);
  assert.match(problems(`${SQLITE}\napi-conninfo-file = /x`).join('\n'), /are for database = pg/);
  assert.match(problems(`${SQLITE}\n[dataset a]\nschema = x`).join('\n'), /one dataset \(main\)/);
  assert.match(problems(PG.replace(/api-conninfo-file.*/, '')).join('\n'), /needs 'api-conninfo-file'/);
  assert.match(problems(PG.replace(/check-conninfo-file.*/, '')).join('\n'), /needs 'check-conninfo-file'/);
  assert.match(problems(`${PG.replace(/\[dataset[\s\S]*/, '')}\nsqlite-file = /x`).join('\n'), /are for database = sqlite3/);
  assert.match(problems(`${PG}\n[dataset third]`).join('\n'), /\[dataset third\] needs 'schema'/);
  // a UNIX socket and a loopback name need no TLS
  assert.deepEqual(problems(PG), []);
  assert.deepEqual(problems(SQLITE.replace('127.0.0.1:8053', 'localhost:8053')), []);
});

test('the sample configuration is a good configuration, also with the SQLite3 lines for the PostgreSQL ones', () => {
  // (a checkout with CRLF line ends, as on Windows with core.autocrlf, must not change what the patterns below see)
  const sample = fs.readFileSync(new URL('../../karidns-webadmin.conf.sample', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const c = parseConfig(sample);
  assert.deepEqual(validate(c), []);
  assert.equal(c.settings.database, 'pg');
  // the commented lines of the sections are valid when switched on
  const on = sample.split('\n').map((l) => l.replace(/^# ((?:database = sqlite3|sqlite-file|auth-file|\[dataset|schema|views|require-totp|session-|totp-key-file|rate-|scrypt-ln|karidns-zone|karicheck|trusted-proxy)[^\n]*)$/, '$1')).join('\n');
  const lite = parseConfig(on.replace('database = pg\n', '').replace(/^api-conninfo-file.*\n|^check-conninfo-file.*\n/gm, '').replace(/^\[dataset main\]\n|^schema = public\n|^views = .*\n/gm, ''));
  assert.deepEqual(validate(lite), []);
  assert.equal(lite.settings.database, 'sqlite3');
});

test('loadConfig reads a file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kw-conf-'));
  try {
    const f = path.join(dir, 'c.conf');
    fs.writeFileSync(f, SQLITE);
    assert.equal(loadConfig(f).settings.database, 'sqlite3');
    assert.throws(() => loadConfig(path.join(dir, 'missing.conf')), /cannot read/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const throwsPointer = (fn, pointer) => {
  try { fn(); } catch (e) {
    assert.ok(e instanceof ApiError, String(e));
    assert.equal(e.status, 400);
    assert.equal(e.errors[0].pointer, pointer);
    return;
  }
  assert.fail('did not throw');
};

test('validators: objects, unknown fields, required fields, nulls', () => {
  const spec = { name: { type: 'string', required: true, min: 1, max: 5 }, n: { type: 'int', min: 1, max: 9 }, ok: { type: 'bool' }, note: { type: 'string', nullable: true } };
  assert.deepEqual(shape({ name: 'abc', n: 3, ok: false, note: null }, spec), { name: 'abc', n: 3, ok: false, note: null });
  assert.deepEqual(shape({ name: 'abc', n: undefined }, spec), { name: 'abc' });
  throwsPointer(() => shape(null, spec), '');
  throwsPointer(() => shape([], spec), '');
  throwsPointer(() => shape('x', spec), '');
  throwsPointer(() => shape({ name: 'a', extra: 1 }, spec), '/extra');
  throwsPointer(() => shape({}, spec), '/name');
  throwsPointer(() => shape({ name: null }, spec), '/name');
  throwsPointer(() => shape({ name: 'abcdef' }, spec), '/name');
  throwsPointer(() => shape({ name: '' }, spec), '/name');
  throwsPointer(() => shape({ name: 5 }, spec), '/name');
  throwsPointer(() => shape({ name: 'a\nb' }, spec), '/name');
  throwsPointer(() => shape({ name: 'a', n: 0 }, spec), '/n');
  throwsPointer(() => shape({ name: 'a', n: 1.5 }, spec), '/n');
  throwsPointer(() => shape({ name: 'a', n: '3' }, spec), '/n');
  throwsPointer(() => shape({ name: 'a', ok: 'yes' }, spec), '/ok');
  throwsPointer(() => shape({ __proto__x: 1, name: 'a' }, spec), '/__proto__x');
  assert.deepEqual(shape({ name: 'a\nb' }, { name: { type: 'string', noControl: false } }), { name: 'a\nb' });
  assert.deepEqual(shape({}, {}), {});
});

test('validators: arrays, patterns, enumerations, pointers into nested values', () => {
  const spec = { l: { type: 'array', max: 2, items: { type: 'string', re: /^[a-z]+$/, reText: 'lower case' } }, e: { type: 'string', values: ['a', 'b'] }, s: { type: 'string', re: /^x$/ } };
  assert.deepEqual(shape({ l: ['a', 'b'], e: 'a' }, spec), { l: ['a', 'b'], e: 'a' });
  throwsPointer(() => shape({ l: 'a' }, spec), '/l');
  throwsPointer(() => shape({ l: ['a', 'b', 'c'] }, spec), '/l');
  throwsPointer(() => shape({ l: ['a', 'B'] }, spec), '/l/1');
  throwsPointer(() => shape({ e: 'c' }, spec), '/e');
  throwsPointer(() => shape({ s: 'y' }, spec), '/s');
  throwsPointer(() => shape({ l: [] }, { l: { type: 'array', min: 1, items: { type: 'int' } } }), '/l');
  assert.throws(() => value(1, { type: 'float' }, '/x'), /unknown type/);
});

test('validators: a query string', () => {
  const spec = { limit: LIMIT, cursor: CURSOR, flag: { type: 'bool' }, who: { type: 'string', required: true, max: 5 } };
  assert.deepEqual(query(new URLSearchParams('limit=5&flag=true&who=bob'), spec), { limit: 5, flag: true, who: 'bob' });
  assert.deepEqual(query(new URLSearchParams('who=x&flag=false'), spec), { who: 'x', flag: false });
  const pointer = (qs) => { try { query(new URLSearchParams(qs), spec); } catch (e) { return e.errors[0].pointer; } return null; };
  assert.equal(pointer('who=x&limit=0'), '?limit');
  assert.equal(pointer('who=x&limit=501'), '?limit');
  assert.equal(pointer('who=x&limit=abc'), '?limit');
  assert.equal(pointer('who=x&limit=1&limit=2'), '?limit');
  assert.deepEqual(query(new URLSearchParams('who=x&flag=1'), spec), { who: 'x', flag: true });                     // (1 and 0 are true and false: ?rdata=1)
  assert.deepEqual(query(new URLSearchParams('who=x&flag=0'), spec), { who: 'x', flag: false });
  assert.equal(pointer('who=x&flag=2'), '?flag');
  assert.equal(pointer('who=x&flag=yes'), '?flag');
  assert.equal(pointer('who=x&nope=1'), '?nope');
  assert.equal(pointer('limit=1'), '?who');
  assert.equal(pointer('who=toolong'), '?who');
  assert.equal(pointer('who=x&cursor=a%20b'), '?cursor');
});

test('cursors', () => {
  const c = encodeCursor({ i: 5 });
  assert.match(c, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(decodeCursor(c, (o) => o.i === 5), { i: 5 });
  throwsPointer(() => decodeCursor('!!!', () => true), '?cursor');
  throwsPointer(() => decodeCursor(c, () => false), '?cursor');
  throwsPointer(() => decodeCursor(Buffer.from('null').toString('base64url'), (o) => o.i === 5), '?cursor');
});

test('names: owners, zones, containment', () => {
  assert.equal(canonicalOwner('WWW.Example.TEST.'), 'www.example.test');
  assert.equal(canonicalOwner('*.example.test'), '*.example.test');
  assert.equal(canonicalOwner('_dmarc._tcp.example.test'), '_dmarc._tcp.example.test');
  assert.equal(canonicalOwner('1/24.2.0.192.in-addr.arpa'), '1/24.2.0.192.in-addr.arpa');
  assert.equal(canonicalOwner('a'), 'a');
  for (const bad of ['', '.', 'a..b', '-a.test', 'a-.test', 'b*.test', 'a b.test', 'a\nb', 'exämple.test', 'a\\.b', `${'x'.repeat(64)}.test`, `${'a.'.repeat(130)}test`, '*']) {
    if (bad === '*') { assert.equal(canonicalOwner(bad), '*'); continue; }
    assert.throws(() => canonicalOwner(bad), Error, JSON.stringify(bad));
  }
  assert.throws(() => canonicalOwner(5), /not a string/);
  assert.throws(() => canonicalOwner(''), /empty/);
  assert.throws(() => canonicalOwner('a.'.repeat(130)), /253/);
  assert.equal(canonicalZone('Example.TEST.'), 'example.test');
  assert.equal(inZone('example.test', 'example.test'), true);
  assert.equal(inZone('www.example.test', 'example.test'), true);
  assert.equal(inZone('wwwexample.test', 'example.test'), false);
  assert.equal(inZone('example.test.evil', 'example.test'), false);
  assert.equal(absolute('example.test'), 'example.test.');
  assert.equal(absolute(''), '.');
  assert.equal(dbName('Example.Test.'), 'example.test');
  assert.equal(dbName('example.test'), 'example.test');
});

test('problem documents', () => {
  const p = problem(new ApiError(409, 'exists', 'already there', { errors: [{ code: 'x', severity: 'error', text: 't', pointer: '/a' }] }), 'abc');
  assert.deepEqual(p, { api: 1, type: 'urn:karidns:api:exists', title: 'Conflict', status: 409, detail: 'already there', request_id: 'abc', errors: [{ code: 'x', severity: 'error', text: 't', pointer: '/a' }] });
  assert.deepEqual(problem(new Error('secret detail'), 'r1'), { api: 1, type: 'urn:karidns:api:internal', title: 'Internal error', status: 500, request_id: 'r1' });
  assert.deepEqual(problem(new ApiError(500, 'internal', 'do not show'), 'r2').detail, undefined);
  assert.equal(problem(new ApiError(418, 'teapot'), 'r').title, 'Error');
  assert.equal(badRequest('x').status, 400);
  assert.equal(badRequest('x', '/p').errors[0].pointer, '/p');
  assert.equal(forbidden('x').code, 'forbidden');
  assert.equal(notFound().status, 404);
  assert.equal(conflict('x').code, 'conflict');
  assert.equal(new ApiError(400, 'c').message, 'c');
});

test('database errors become API errors, or null', () => {
  assert.equal(mapDbError({ code: '23505', message: 'duplicate' }).code, 'exists');
  assert.equal(mapDbError({ code: '23503', message: 'fk' }).code, 'in-use');
  assert.equal(mapDbError({ code: '23001', message: 'restrict' }).code, 'in-use');
  assert.equal(mapDbError({ code: '23514', message: 'new row violates check constraint "grants_scope"' }).detail, 'the value violates the constraint grants_scope');
  assert.equal(mapDbError({ code: '23514', message: 'karidns_auth.memberships: this membership would make a cycle' }).detail, 'this membership would make a cycle');
  assert.equal(mapDbError({ code: '23514', message: 'something' }).detail, 'the value violates a constraint of the database');
  for (const code of ['40001', '40P01', '55P03']) assert.equal(mapDbError({ code, message: 'x' }).headers['Retry-After'], '2');
  assert.equal(mapDbError({ code: '57014', message: 'x' }).headers['Retry-After'], '5');
  assert.equal(mapDbError({ message: 'database is locked' }).status, 503);
  for (const message of ['timeout exceeded when trying to connect', 'Connection terminated unexpectedly', 'connect ECONNREFUSED 127.0.0.1:5432', 'the database system is shutting down']) assert.equal(mapDbError({ message }).code, 'database-unavailable', message);
  for (const code of ['57P01', '08006', '53300']) assert.equal(mapDbError({ code, message: 'x' }).headers['Retry-After'], '5', code);
  assert.equal(mapDbError({ message: 'UNIQUE constraint failed: principals.name' }).code, 'exists');
  assert.equal(mapDbError({ message: 'FOREIGN KEY constraint failed' }).code, 'in-use');
  assert.equal(mapDbError({ message: 'CHECK constraint failed: grants_scope' }).status, 422);
  assert.equal(mapDbError({ message: 'karidns_auth.memberships: the group is not a group (a user has no members)' }).status, 409);
  assert.equal(mapDbError({ code: '42501', message: 'permission denied' }), null);
  assert.equal(mapDbError(new Error('other')), null);
  assert.equal(mapDbError(undefined), null);
});

test('token buckets use the clock of the process unless they are given one', () => {
  const b = new Buckets({ rate: 1000, burst: 1 });
  assert.equal(b.take('k'), 0);
  assert.equal(b.take('k') >= 0, true);
});

test('sliding window: at most `limit` per key within the window, a refused event is not recorded, the table does not grow', () => {
  let t = 1000;
  const w = new Window({ limit: 2, windowMs: 100, max: 3, now: () => t });
  assert.deepEqual([w.take('a'), w.take('a'), w.take('a')], [false, false, true]);
  assert.equal(w.take('b'), false);                    // another key has its own count
  t += 99;
  assert.equal(w.take('a'), true);                     // (the refused one at +0 was not recorded: the oldest event leaves at +100)
  t += 1;
  assert.deepEqual([w.take('a'), w.take('a'), w.take('a')], [false, false, true]);
  // the sweep drops the keys whose events are over; if every key is busy they are all forgotten
  w.take('c');
  assert.equal(w.map.size, 3);
  t += 1000;
  w.take('d');
  assert.equal(w.map.size, 1);
  const busy = new Window({ limit: 1, windowMs: 100000, max: 2, now: () => t });
  busy.take('1'); busy.take('2'); busy.take('3');
  assert.equal(busy.map.size, 1);
  assert.equal(new Window({ limit: 1, windowMs: 10 }).take('x'), false);        // the clock of the process
});

test('token buckets: a burst, a refill, the wait, and the table does not grow', () => {
  let t = 0;
  const b = new Buckets({ rate: 1, burst: 3, max: 4, now: () => t });
  assert.deepEqual([b.take('a'), b.take('a'), b.take('a')], [0, 0, 0]);
  assert.equal(b.take('a'), 1);
  assert.equal(b.take('b'), 0);                       // another key has its own bucket
  t += 1000;
  assert.equal(b.take('a'), 0);
  assert.equal(b.take('a'), 1);
  t += 10000;
  assert.equal(b.take('a'), 0);                       // refilled up to the burst, not beyond
  assert.equal(b.take('a'), 0);
  assert.equal(b.take('a'), 0);
  assert.equal(b.take('a'), 1);
  const slow = new Buckets({ rate: 0.1, burst: 1, now: () => t });
  assert.equal(slow.take('x'), 0);
  assert.equal(slow.take('x'), 10);
  // the sweep: idle keys that are full again are dropped; if every key is busy they are all forgotten
  b.take('c'); b.take('d');
  assert.equal(b.map.size, 4);
  t += 100000;
  b.take('e');
  assert.equal(b.map.size, 1);
  const busy = new Buckets({ rate: 0.001, burst: 1, max: 2, now: () => t });
  busy.take('1'); busy.take('2'); busy.take('1');
  busy.take('3');
  assert.equal(busy.map.size, 1);
});

test('the network of a login lock: IPv4 /24, IPv6 /64, other text as it is', () => {
  assert.equal(lockNetwork('192.0.2.77'), '192.0.2.0/24');
  assert.equal(lockNetwork('::ffff:198.51.100.9'), '198.51.100.0/24');
  assert.equal(lockNetwork('2001:db8:1:2::5'), '2001:db8:1:2::/64');
  assert.equal(lockNetwork('2001:DB8:0001:0002:ffff:0:0:1'), '2001:db8:1:2::/64');
  assert.equal(lockNetwork('2001:db8::1'), '2001:db8:0:0::/64');
  assert.equal(lockNetwork('::1'), '0:0:0:0::/64');
  assert.equal(lockNetwork('fe80::1%em0'), 'fe80:0:0:0::/64');
  for (const odd of ['local', '', '1:2:3', '1::2::3', '::ffff:1.2.3.4.5', '2001:db8::zz', '1:2:3:4:5:6:7:8:9']) assert.equal(lockNetwork(odd), odd);
  assert.equal(lockNetwork(undefined), '');
});

test('login locks per account and network: ten failures, doubling, a day at most; success, clear, the table does not grow', () => {
  let t = 0;
  const l = new Lockouts({ after: 3, firstMs: 1000, maxMs: 4000, max: 3, now: () => t });
  assert.deepEqual([l.fail(1, '192.0.2.1'), l.fail(1, '192.0.2.2')], [{ failed: 1, until: null }, { failed: 2, until: null }]);
  assert.deepEqual(l.fail(1, '192.0.2.3'), { failed: 3, until: 1000 });          // the same /24: locked
  assert.equal(l.locked(1, '192.0.2.200'), true);
  assert.equal(l.locked(1, '192.0.3.1'), false);                                // another network
  assert.equal(l.locked(2, '192.0.2.1'), false);                                // another account
  assert.deepEqual([l.fail(1, '192.0.2.1').until, l.fail(1, '192.0.2.1').until, l.fail(1, '192.0.2.1').until], [2000, 4000, 4000]);
  assert.deepEqual(l.of(1), [{ network: '192.0.2.0/24', failed: 6, locked_until: 4000 }]);
  t = 4000;
  assert.equal(l.locked(1, '192.0.2.1'), false);                                // the lock ends
  assert.deepEqual(l.of(1), [{ network: '192.0.2.0/24', failed: 6, locked_until: null }]);
  l.succeed(1, '192.0.2.9');
  assert.deepEqual(l.of(1), []);
  l.fail(1, '2001:db8::1');
  l.fail(2, '2001:db8::1');
  l.clear(1);
  assert.deepEqual([l.of(1), l.of(2).length], [[], 1]);
  // the sweep: quiet entries go first, then those that are not locked, then everything
  t = 10000;
  l.fail(3, '198.51.100.1');
  l.fail(4, '198.51.100.1');
  t = 20000;
  l.fail(5, '198.51.100.1');                                                    // full: the entries quiet for maxMs are dropped
  assert.equal(l.map.size, 1);
  for (const p of [6, 7]) for (let i = 0; i < 3; i++) l.fail(p, '203.0.113.1');
  l.fail(8, '203.0.113.1');                                                     // full again: the one that is not locked goes
  assert.deepEqual([...l.map.keys()].sort(), ['6 203.0.113.0/24', '7 203.0.113.0/24', '8 203.0.113.0/24']);
  for (let i = 0; i < 3; i++) l.fail(8, '203.0.113.1');
  l.fail(9, '203.0.113.1');                                                     // every entry is locked: all are forgotten
  assert.deepEqual([...l.map.keys()], ['9 203.0.113.0/24']);
  const real = new Lockouts();                                                  // the defaults and the clock of the process
  assert.deepEqual(real.fail(1, '192.0.2.1'), { failed: 1, until: null });
  assert.equal(real.locked(1, '192.0.2.1'), false);
});

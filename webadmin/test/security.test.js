// The findings of the security self-review of M5 (planning 8, CLAUDE.md rule 4): each test is a case that was open before the fix.

import test from 'node:test';
import assert from 'node:assert/strict';
import { deploy, cast, exit } from './helpers.js';
import { versionParam } from '../lib/handlers/common.js';
import { ApiError } from '../lib/errors.js';
import { encodeCursor } from '../lib/validate.js';
import { hotp, totpStep, base32Decode } from '../lib/crypto.js';

const withDeploy = (opts, fn) => async () => {
  const d = await deploy(opts);
  try {
    await cast(d);
    await fn(d);
  } finally {
    await d.close();
  }
};
const type = (r, status, code) => {
  assert.equal(r.status, status, JSON.stringify(r.body));
  assert.equal(r.body.type, `urn:karidns:api:${code}`, JSON.stringify(r.body));
};

test('the export runs in the pool of tools like every other run: at most `workers` at a time, the rest wait', async () => {
  let active = 0;
  let most = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const run = async () => {
    active++;
    most = Math.max(most, active);
    await gate;
    active--;
    return exit(0, { stdout: '$ORIGIN example.test.\n' });
  };
  await withDeploy({ run, settings: { workers: 1 } }, async (d) => {
    const root = d.as(await d.login('root', 'correct horse battery'));
    const calls = [1, 2, 3].map(() => root('GET', '/datasets/main/zones/example.test/export'));
    await new Promise((resolve) => { setTimeout(resolve, 150); });
    assert.equal(most, 1, 'one export runs, the others wait for it');
    release();
    for (const r of await Promise.all(calls)) assert.equal(r.status, 200);
    assert.equal(most, 1);
  })();
});

test('the pool is full (64 waiting): an export is a 503, not another child process', withDeploy({}, async (d) => {
  const root = d.as(await d.login('root', 'correct horse battery'));
  d.app.pool.limit = 1;
  d.app.pool.active = 1;                                          // a run is going on that never ends in this test
  d.app.pool.waiting = new Array(64).fill(() => {});
  const r = await root('GET', '/datasets/main/zones/example.test/export');
  type(r, 503, 'busy');
  assert.equal(r.headers.get('retry-after'), '2');
}));

test('asking for the password again (change it, switch TOTP off) is a way to guess it: the limits of a login apply', withDeploy({ settings: { 'rate-login': 3 } }, async (d) => {
  const dom = d.as(await d.login('dom', 'dom password 12345'));
  const wrong = () => dom('POST', '/auth/password', { body: { current: 'not the password 1', new: 'a brand new password 1' } });
  type(await wrong(), 403, 'wrong-password');
  type(await wrong(), 403, 'wrong-password');
  type(await wrong(), 403, 'wrong-password');
  const slow = await wrong();
  type(slow, 429, 'rate-limited');
  assert.match(slow.headers.get('retry-after'), /^\d+$/);
  // even the right password has to wait: the bucket is empty, so the answer does not say whether the guess was right
  type(await dom('POST', '/auth/password', { body: { current: 'dom password 12345', new: 'a brand new password 1' } }), 429, 'rate-limited');
}));

test('wrong passwords at the password form count towards the lock of the account, as at the login', withDeploy({}, async (d) => {
  const dom = d.as(await d.login('dom', 'dom password 12345'));
  for (let i = 0; i < 10; i++) type(await dom('POST', '/auth/password', { body: { current: `not the password ${i}`, new: 'a brand new password 1' } }), 403, 'wrong-password');
  // the account is locked: a login with the right password is refused like any other
  type(await d.request('POST', '/auth/login', { body: { user: 'dom', password: 'dom password 12345' } }), 401, 'invalid-credentials');
  const creds = await d.as(await d.login('root', 'correct horse battery'))('GET', '/principals/2');
  assert.equal(creds.body.credentials.locked, true);
  assert.equal(creds.body.credentials.failed_logins, 10);
  assert.ok(d.log.lines.some((l) => /^warn auth: dom is locked after 10 failed logins/.test(l)));
}));

test('a wrong TOTP code when switching TOTP off counts as a failed login too', withDeploy({}, async (d) => {
  const dom = d.as(await d.login('dom', 'dom password 12345'));
  const e = await dom('POST', '/auth/totp', { body: { action: 'enroll' } });
  assert.equal(e.status, 200);
  const conf = await dom('POST', '/auth/totp', { body: { action: 'confirm', code: hotp(base32Decode(e.body.secret), totpStep(Date.now() / 1000)) } });
  assert.equal(conf.status, 200);
  const t = d.as({ cookie: /karidns_session=([^;]+)/.exec(conf.headers.get('set-cookie'))[1], csrf: conf.body.csrf });
  type(await t('POST', '/auth/totp', { body: { action: 'disable', password: 'dom password 12345', code: '000000' } }), 403, 'wrong-code');
  const root = d.as(await d.login('root', 'correct horse battery'));
  assert.equal((await root('GET', '/principals/2')).body.credentials.failed_logins, 1);
}));

test('/health: callers that arrive while a check runs wait for that one (no login, so no database connection each)', withDeploy({}, async (d) => {
  let n = 0;
  const real = d.backend.tx.bind(d.backend);
  d.backend.tx = async (o, fn) => {
    n++;
    await new Promise((resolve) => { setTimeout(resolve, 100); });
    return real(o, fn);
  };
  const all = await Promise.all(Array.from({ length: 25 }, () => d.request('GET', '/health')));
  for (const r of all) assert.equal(r.status, 200);
  assert.ok(n >= 1 && n <= 3, `${n} checks for 25 requests`);
  // and the next one is a new check (the answer is never older than a request that is in flight)
  const before = n;
  assert.equal((await d.request('GET', '/health')).status, 200);
  assert.equal(n, before + 1);
}));

test('a version number is a 32 bit integer: a longer one is no version (PostgreSQL would answer it with an error, a 500)', withDeploy({}, async (d) => {
  assert.equal(versionParam({ params: { n: '123456789' } }), 123456789);
  for (const bad of ['1234567890', '99999999999999', 'x', '-1', '1e3']) {
    assert.throws(() => versionParam({ params: { n: bad } }), (e) => e instanceof ApiError && e.status === 404, bad);
  }
  const root = d.as(await d.login('root', 'correct horse battery'));
  for (const [m, p] of [['GET', '/versions/12345678901'], ['GET', '/versions/12345678901/diff'], ['POST', '/versions/12345678901/rollback']]) {
    type(await root(m, `/datasets/main/zones/example.test${p}`, m === 'POST' ? { body: {} } : {}), 404, 'not-found');
  }
  // the cursor of the list is checked as well
  for (const v of [2147483648, 99999999999, 0, -1, 1.5]) {
    type(await root('GET', `/datasets/main/zones/example.test/versions?cursor=${encodeCursor({ v })}`), 400, 'bad-request');
  }
  assert.equal((await root('GET', `/datasets/main/zones/example.test/versions?cursor=${encodeCursor({ v: 2147483647 })}`)).status, 200);
}));

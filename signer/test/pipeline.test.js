// One zone through the pipeline with fake tools: what is run, in which order, with which argv, which files exist at that moment, what is written to
// the database, and that nothing is left in the work directory on any path.  The real tools are tests/run_signer_test.sh.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseConfig } from '../lib/config.js';
import { tools } from '../lib/argv.js';
import { OwnWrites } from '../lib/scheduler.js';
import { loadKey } from '../lib/keys.js';
import { signZone, prepareInput, signingMode, requestedKeys, generateKeys, insertKeysWithRetry, storedKeyIds, PipelineError, KEY_RETRY_DELAYS, defaultSleep } from '../lib/pipeline.js';

const FX = JSON.parse(fs.readFileSync(new URL('./fixtures/keys.json', import.meta.url), 'utf8'));
const POOL = (alg) => FX.bind.filter((k) => k.algorithm === alg);
const KSK = POOL(13)[0];                     // any private key will do; flags are the row's
const ZSK = POOL(13)[1];
const SECRETS = FX.bind.map((k) => /PrivateKey: (\S+)/.exec(k.private)?.[1]).filter(Boolean);

const SQLITE_CONF = 'database = sqlite3\nsqlite-file = /db/p.sqlite3\nkarictl-config = /etc/k.conf\nvalidity = 14d\nrefresh = 3d\njitter = 1d';
const PG_CONF = 'database = pg\nconninfo-file = /etc/c.conninfo\nschema = karidns\n';

const EXIT0 = { export: 0, signzone: 0, karicheck: 0, import: 0, karictl: 0, keygen: 0 };
const NS3 = '1 0 0 -';
const EXPORT_UNSIGNED = '$ORIGIN example.test.\n$TTL 300\n@ NS ns1\n@ SOA ns1 hostmaster 1 7200 3600 1209600 300\nns1 A 192.0.2.1\n';
const EXPORT_SIGNED = `${EXPORT_UNSIGNED}@ DNSKEY 256 3 13 OLDKEYOLDKEYOLDKEY\n@ 0 DNSKEY 257 3 13 OLDKEY2\nsub DNSKEY 257 3 13 BELOWAPEX\n@ RRSIG DNSKEY 13 2 300 20300101000000 20200101000000 1 example.test. AAAA\n`;

const importJson = (o = {}) => JSON.stringify({ 'karidns-zone': 1, signer: { zone: 'example.test', changed: false, committed: true, serial: 2, old_serial: 1, earliest_expire_epoch: 1795141752, write_id: { xid: null, seq_first: 11, seq_last: 42 }, ...o } });

function setup(conf = SQLITE_CONF, over = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-pl-'));
  const config = parseConfig(conf);
  const calls = [];
  const logs = [];
  const state = {
    meta: { signer: true, presigned: true, nsec3param: NS3 },
    keys: [],
    locked: true,
    inserted: [],
    insertFails: 0,
    dropped: 0,
    unlocked: 0,
    exportText: EXPORT_SIGNED,
    exit: { ...EXIT0 },
    importOut: importJson(),
    stderr: {},
    seen: [],
    keygenCount: 0,
    ...over,
  };
  const t = tools(config.settings);
  const db = {
    async tryLock() { return state.locked; },
    async unlock() { state.unlocked++; if (state.unlockFails) throw new Error('lock gone'); },
    async getMeta() { if (state.metaFails) throw new Error('database went away'); return state.meta; },
    async getKeys() { return state.keys; },
    async dropState() { state.dropped++; },
    async insertKeys(id, keys, requestId) {
      if (state.insertFails > 0) { state.insertFails--; throw new Error('connection reset'); }
      state.inserted.push(...keys);
      state.insertedAfter = calls.map((c) => c.name);                   // what had run when the keys were stored
      state.insertedFor = requestId;
      return { xid: 'X1', seq_first: null, seq_last: null, ids: keys.map((_, i) => 40 + i) };
    },
    async storedKeysNote() { return state.note ?? null; },
  };
  const run = async (file, argv, opts) => {
    const name = Object.entries(t).find(([, v]) => v === file)?.[0];
    calls.push({ name, argv, opts, files: fs.existsSync(opts.cwd) ? fs.readdirSync(opts.cwd).sort() : [] });
    const res = (code, stdout = '', stderr = '') => ({ code, signal: null, stdout, stderr, truncated: false, timedOut: false, spawnError: null });
    if (state.spawnError === name) return { ...res(null), spawnError: 'spawn ENOENT' };
    const code = state.exit[name] ?? 0;
    switch (name) {
      case 'keygen': {
        if (code) return res(code, '', 'dnssec-keygen: fatal: bad algorithm');
        const alg = Object.entries({ RSASHA256: 8, ECDSAP256SHA256: 13, ED25519: 15 }).find(([n]) => n === argv[argv.indexOf('-a') + 1])[1];
        const pool = POOL(alg);
        const f = pool[state.keygenCount++ % pool.length];
        const zone = argv[argv.length - 1];
        const tag = state.badTag ? 1 : loadKey(zone, { flags: argv.includes('-f') ? 257 : 256, content: f.private }).tag;
        const stem = `K${zone}.+${String(alg).padStart(3, '0')}+${String(tag).padStart(5, '0')}`;
        fs.writeFileSync(path.join(argv[argv.indexOf('-K') + 1], `${stem}.private`), f.private);
        return res(0, `${stem}\n`);
      }
      case 'zone':
        if (argv[0] === 'export') {
          if (state.exit.export) return res(state.exit.export, '', 'export failed: cryptokeys');
          fs.writeFileSync(argv[argv.length - 1], state.exportText);
          return res(0);
        }
        state.seen.push(['import', argv, fs.readFileSync(argv[argv.length - 1], 'utf8')]);
        return state.exit.import ? res(state.exit.import, state.importErr ?? '', 'import failed') : res(0, state.importOut);
      case 'signzone': {
        if (code) return res(code, '', state.stderr.signzone ?? 'dnssec-signzone: fatal: boom');
        const stems = argv.filter((a) => /^K.+\+\d{3}\+\d{5}$/.test(a));
        state.seen.push(['sign', argv, fs.readFileSync(argv[argv.length - 1 - stems.length], 'utf8')]);
        fs.writeFileSync(argv[argv.indexOf('-f') + 1], '; signed zone\n');
        return res(0);
      }
      case 'karicheck':
        return code ? res(code, 'zone.dnssec.thing: error', '') : res(0, 'ok\n');
      case 'karictl':
        return code ? res(code, '', 'ERROR command not allowed') : res(0, 'OK zone example.test\n');
      default:
        throw new Error(`unexpected tool ${file}`);
    }
  };
  const ctx = {
    config, db, run, work, tools: t,
    log: { info: (m) => logs.push(`info ${m}`), warn: (m) => logs.push(`warn ${m}`), error: (m) => logs.push(`error ${m}`) },
    ownWrites: new OwnWrites(),
    sleep: async (ms) => { state.slept = [...(state.slept ?? []), ms]; },
    keyRetryDelays: [1, 2, 4],
  };
  return { ctx, state, calls, logs, work, done: () => fs.rmSync(work, { recursive: true, force: true }) };
}

const JOB = { domainId: 7, zone: 'example.test', request: null };
const ENABLE = { id: 5, kind: 'enable', algorithm: 13, bits: null, keyType: 'csk', nsec: null };
const row = (k, flags, active = true, published = true) => ({ id: 1, flags, active, published, content: k.private });
const names = (calls) => calls.map((c) => c.name);
const empty = (work) => assert.deepEqual(fs.readdirSync(work), [], 'the work directory is empty');
const noSecrets = (...texts) => { for (const t of texts) for (const s of SECRETS) assert.ok(!String(t).includes(s), 'key material in a message'); };

test('a zone that is signed already: export, sign, check, import; the keys are in files only while it runs', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257), row(ZSK, 256)] });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'signed', out.error);
    assert.equal(out.serial, 2);
    assert.equal(out.minExpire, 1795141752);
    assert.deepEqual(out.writeId, { xid: null, seq_first: 11, seq_last: 42 });
    assert.equal(out.request, null);
    assert.deepEqual(names(s.calls), ['zone', 'signzone', 'karicheck', 'zone', 'karictl']);
    const [exp, sign, check, imp, reload] = s.calls;
    assert.deepEqual(exp.argv.slice(0, 5), ['export', '--signer', '--no-config', '--sqlite3', '/db/p.sqlite3']);
    assert.equal(exp.opts.timeoutMs, 1800000);
    // the key files exist when dnssec-signzone runs
    assert.ok(sign.files.includes(`${loadKey('example.test', { flags: 257, content: KSK.private }).base}.private`));
    assert.ok(sign.files.some((f) => f.endsWith('.key')) && sign.files.includes('in.zone') && sign.files.includes('export.zone'));
    assert.ok(sign.argv.includes('-x') && sign.argv.includes('-3') && !sign.argv.includes('-P'));
    assert.equal(sign.argv[sign.argv.indexOf('-i') + 1], String(3 * 86400 + 86400));
    assert.equal(sign.argv[sign.argv.indexOf('-e') + 1], 'now+1209600');
    assert.deepEqual(check.argv, ['zone', 'example.test', check.argv[2]]);
    assert.ok(check.argv[2].endsWith('out.zone'));
    assert.deepEqual(imp.argv.slice(0, 3), ['import', '--signer', '--json']);
    assert.ok(!imp.argv.includes('--reload'));
    assert.deepEqual(reload.argv, ['-c', '/etc/k.conf', 'reload', 'example.test']);
    // the input of dnssec-signzone: the export without its apex DNSKEYs, then the DNSKEY of every key
    const inText = s.state.seen.find((x) => x[0] === 'sign')[2];
    assert.ok(inText.includes('sub DNSKEY 257 3 13 BELOWAPEX'), 'a DNSKEY below the apex stays');
    assert.ok(!inText.includes('OLDKEY'));
    assert.ok(inText.includes('@ RRSIG DNSKEY'));
    assert.equal(inText.split('\n').filter((l) => /^example\.test\. IN DNSKEY /.test(l)).length, 2);
    // our own writes are known
    assert.ok(s.ctx.ownWrites.isOwn({ seq: 20, xid: null }));
    assert.equal(s.state.unlocked, 1);
    empty(s.work);
    noSecrets(...s.logs, JSON.stringify(out));
  } finally { s.done(); }
});

test('PostgreSQL: --reload in the import, no karictl', async () => {
  const s = setup(PG_CONF, { keys: [row(KSK, 257)] });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'signed', out.error);
    assert.deepEqual(names(s.calls), ['zone', 'signzone', 'karicheck', 'zone']);
    const imp = s.calls[3].argv;
    assert.ok(imp.includes('--reload') && imp.includes('--conninfo-file') && imp.includes('--schema'));
    assert.ok(s.calls[1].argv.includes('-z'), 'one key with the KSK flag: a CSK');
    empty(s.work);
  } finally { s.done(); }
});

test('keys: published only -> its DNSKEY in the zone, no file, not passed; neither active nor published -> ignored (even broken)', async () => {
  const s = setup(SQLITE_CONF, {
    keys: [row(KSK, 257), row(ZSK, 256, false, true), { id: 3, flags: 256, active: false, published: false, content: 'rubbish that must not be parsed' }],
  });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'signed', out.error);
    const sign = s.calls.find((c) => c.name === 'signzone');
    const stems = sign.argv.filter((a) => /^K.+\+\d{3}\+\d{5}$/.test(a));
    assert.deepEqual(stems, [loadKey('example.test', { flags: 257, content: KSK.private }).base]);
    assert.ok(sign.argv.includes('-z'));
    assert.equal(sign.files.filter((f) => f.endsWith('.private')).length, 1);
    const inText = s.state.seen.find((x) => x[0] === 'sign')[2];
    assert.ok(inText.includes(loadKey('example.test', { flags: 256, content: ZSK.private }).dnskey), 'the published key is in the zone');
    empty(s.work);
  } finally { s.done(); }
});

test('first signing (request enable, no keys, a CSK): keys generated, signed, checked, stored, and only then imported; NSEC3 with no salt and 0 iterations', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'signed', out.error);
    assert.deepEqual(names(s.calls), ['keygen', 'zone', 'signzone', 'karicheck', 'zone', 'karictl']);   // one reload: the INSERT was before the import
    assert.deepEqual(s.calls[0].argv.slice(0, 5), ['-q', '-a', 'ECDSAP256SHA256', '-f', 'KSK']);
    const sign = s.calls[2].argv;
    assert.deepEqual(sign.slice(sign.indexOf('-3'), sign.indexOf('-3') + 4), ['-3', '-', '-H', '0']);
    assert.ok(sign.includes('-z'));
    // review W1-L1 (0.7): the key is in cryptokeys before the import makes its DNSKEY servable (it used to be stored after the import: a crash in between lost it),
    // the request named in the same write; what is stored is the sanitized private key
    assert.deepEqual(s.state.insertedAfter, ['keygen', 'zone', 'signzone', 'karicheck']);
    assert.equal(s.state.insertedFor, 5);
    assert.equal(s.state.inserted.length, 1);
    assert.equal(s.state.inserted[0].flags, 257);
    assert.match(s.state.inserted[0].content, /^Private-key-format: v1\.3\nAlgorithm: 13 \(ECDSAP256SHA256\)\nPrivateKey: \S+\n$/);
    assert.ok(!/Created|Publish|Activate/.test(s.state.inserted[0].content));
    assert.equal(out.request.state, 'done');
    assert.match(out.request.message, /signing enabled: key \d+ \(algorithm 13, flags 257\)/);
    assert.ok(s.ctx.ownWrites.isOwn({ seq: 5, xid: 'X1' }), 'the change log rows of the key INSERT are ours');
    const inText = s.state.seen.find((x) => x[0] === 'sign')[2];
    assert.equal(inText.split('\n').filter((l) => / IN DNSKEY 257 3 13 /.test(l)).length, 1);
    empty(s.work);
    noSecrets(...s.logs, JSON.stringify(out));
  } finally { s.done(); }
});

test('first signing with a KSK and a ZSK, and NSEC when asked for', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: { ...ENABLE, keyType: 'ksk', nsec: 'nsec', algorithm: 8, bits: 2048 } });
    assert.equal(out.status, 'signed', out.error);
    assert.deepEqual(names(s.calls).slice(0, 2), ['keygen', 'keygen']);
    assert.deepEqual(s.calls[0].argv.slice(0, 7), ['-q', '-a', 'RSASHA256', '-b', '2048', '-f', 'KSK']);
    assert.ok(!s.calls[1].argv.includes('-f'));
    const sign = s.calls.find((c) => c.name === 'signzone').argv;
    assert.ok(sign.includes('-x') && !sign.includes('-3'));
    assert.deepEqual(s.state.inserted.map((k) => k.flags), [257, 256]);
    empty(s.work);
  } finally { s.done(); }
});

test('first signing with an opt-out setting', async () => {
  const s = setup(`${SQLITE_CONF}\nnsec3-opt-out = yes`, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED });
  try {
    await signZone(s.ctx, { ...JOB, request: ENABLE });
    assert.ok(s.calls.find((c) => c.name === 'signzone').argv.includes('-A'));
  } finally { s.done(); }
});

test('request enable for a zone with keys but not signed: refused, nothing is run', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, keys: [row(KSK, 257)] });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'failed');
    assert.match(out.error, /cryptokeys rows but no PRESIGNED metadata/);
    assert.equal(out.request.state, 'failed');
    assert.deepEqual(s.calls, []);
    empty(s.work);
  } finally { s.done(); }
});

test('request enable for a presigned zone that has keys: they are used, none are made', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: true, nsec3param: null }, keys: [row(KSK, 257)] });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'signed', out.error);
    assert.ok(!names(s.calls).includes('keygen'));
    assert.equal(out.request.message, "signing enabled with the zone's keys");
    assert.ok(!s.calls.find((c) => c.name === 'signzone').argv.includes('-3'), 'NSEC: the zone has no NSEC3PARAM');
    assert.deepEqual(s.state.inserted, []);
  } finally { s.done(); }
});

test('request enable for a zone the signer signs already is answered done', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)] });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'signed', out.error);
    assert.deepEqual(out.request, { state: 'done', message: 'the zone was signed already' });
  } finally { s.done(); }
});

test('a zone that is not the signer\'s (and no request): skipped, its state row dropped', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null } });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'skipped');
    assert.equal(s.state.dropped, 1);
    assert.deepEqual(s.calls, []);
    empty(s.work);
  } finally { s.done(); }
});

test('another instance holds the zone: nothing happens, no directory is made', async () => {
  const s = setup(SQLITE_CONF, { locked: false, keys: [row(KSK, 257)] });
  try {
    assert.deepEqual(await signZone(s.ctx, JOB), { status: 'locked' });
    assert.equal(s.state.unlocked, 0);
    assert.deepEqual(s.calls, []);
  } finally { s.done(); }
});

test('a zone name that is not plain: refused before any directory or process', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)] });
  try {
    const out = await signZone(s.ctx, { ...JOB, zone: '../../etc' });
    assert.equal(out.status, 'failed');
    assert.match(out.error, /zone name/);
    assert.deepEqual(s.calls, []);
    const out2 = await signZone(s.ctx, { ...JOB, zone: 'a b.test', request: ENABLE });
    assert.equal(out2.request.state, 'failed');
    empty(s.work);
  } finally { s.done(); }
});

test('a broken key: failed, nothing exported, nothing written, directory empty, no key material in the message', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257), { id: 2, flags: 256, active: true, published: true, content: `Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: ${'SECRETSECRET'}!\n` }] });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'failed');
    assert.match(out.error, /not base64/);
    assert.ok(!out.error.includes('SECRETSECRET'));
    assert.deepEqual(s.calls, []);
    assert.equal(s.state.unlocked, 1);
    empty(s.work);
  } finally { s.done(); }
});

test('keys that cannot sign: none active, no KSK, the same key twice, a SHA-1 key', async () => {
  for (const [keys, re] of [
    [[], /no active key/],
    [[row(KSK, 257, false, true)], /no active key/],
    [[row(ZSK, 256)], /no active key-signing key/],
    [[row(KSK, 257), { ...row(KSK, 257), id: 9 }], /same algorithm and key tag/],
    [[{ id: 1, flags: 257, active: true, published: true, content: 'Private-key-format: v1.2\nAlgorithm: 5 (RSASHA1)\n' }], /RFC 8624/],
  ]) {
    const s = setup(SQLITE_CONF, { keys });
    try {
      const out = await signZone(s.ctx, JOB);
      assert.equal(out.status, 'failed');
      assert.match(out.error, re);
      assert.deepEqual(s.calls, []);
      empty(s.work);
    } finally { s.done(); }
  }
});

test('an NSEC3PARAM we cannot reproduce', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], meta: { signer: true, presigned: true, nsec3param: '1 0 10 zz' } });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'failed');
    assert.match(out.error, /NSEC3PARAM metadata/);
    empty(s.work);
  } finally { s.done(); }
});

test('NSEC3PARAM metadata with salt and iterations is kept', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], meta: { signer: true, presigned: true, nsec3param: '1 0 5 AABB' } });
  try {
    await signZone(s.ctx, JOB);
    const a = s.calls.find((c) => c.name === 'signzone').argv;
    assert.deepEqual(a.slice(a.indexOf('-3'), a.indexOf('-3') + 4), ['-3', 'AABB', '-H', '5']);
  } finally { s.done(); }
});

test('a zone with settings of its own, verify off', async () => {
  const s = setup(`${SQLITE_CONF}\n[zone example.test]\nvalidity = 2h\nrefresh = 20m\njitter = 5m\nverify = no`, { keys: [row(KSK, 257)] });
  try {
    await signZone(s.ctx, JOB);
    const a = s.calls.find((c) => c.name === 'signzone').argv;
    assert.equal(a[a.indexOf('-e') + 1], 'now+7200');
    assert.equal(a[a.indexOf('-i') + 1], '1500');
    assert.ok(a.includes('-P'));
  } finally { s.done(); }
});

test('every tool that fails fails the zone, with its message, and nothing after it runs', async () => {
  const cases = [
    ['export', { export: 1 }, /karidns-zone export: export failed: cryptokeys/, ['zone']],
    ['signzone', { signzone: 1 }, /dnssec-signzone: dnssec-signzone: fatal: boom/, ['zone', 'signzone']],
    ['karicheck', { karicheck: 1 }, /karicheck: .*zone\.dnssec\.thing: error/, ['zone', 'signzone', 'karicheck']],
    ['import', { import: 1 }, /karidns-zone import: import failed/, ['zone', 'signzone', 'karicheck', 'zone']],
  ];
  for (const [name, exit, re, ran] of cases) {
    const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], exit: { ...EXIT0, ...exit } });
    try {
      const out = await signZone(s.ctx, JOB);
      assert.equal(out.status, 'failed', name);
      assert.match(out.error, re, name);
      assert.deepEqual(names(s.calls), ran, name);
      assert.deepEqual(s.state.inserted, []);
      assert.equal(s.state.unlocked, 1);
      empty(s.work);
    } finally { s.done(); }
  }
});

test('dnssec-signzone: its message is cut to 1 KB, control characters removed', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], exit: { signzone: 1 }, stderr: { signzone: `bad\u0000\u0007 ${'x'.repeat(5000)}` } });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'failed');
    assert.ok(out.error.length < 1100);
    assert.ok(!/[\u0000-\u0008]/.test(out.error));
  } finally { s.done(); }
});

test('a tool that cannot be started', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], spawnError: 'signzone' });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.match(out.error, /dnssec-signzone could not be started: spawn ENOENT/);
  } finally { s.done(); }
  const s2 = setup(SQLITE_CONF, { keys: [row(KSK, 257)], spawnError: 'zone' });
  try {
    const out = await signZone(s2.ctx, JOB);
    assert.match(out.error, /karidns-zone export could not be started: spawn ENOENT/);
  } finally { s2.done(); }
});

test('exit status 3 is "changed", 4 is "busy": not errors, and the zone is not written', async () => {
  for (const [code, status] of [[3, 'changed'], [4, 'busy']]) {
    const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], exit: { ...EXIT0, import: code } });
    try {
      assert.deepEqual(await signZone(s.ctx, JOB), { status });
      assert.deepEqual(s.state.inserted, []);
      assert.ok(!names(s.calls).includes('karictl'));
      assert.equal(s.state.unlocked, 1);
      empty(s.work);
    } finally { s.done(); }
  }
});

test('a write that PostgreSQL rolled back for a concurrent update is "busy", not an error', async () => {
  for (const text of ['ERROR:  could not serialize access due to concurrent delete (changed concurrently)', 'ERROR:  deadlock detected']) {
    const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], exit: { ...EXIT0, import: 1 }, importErr: `{"messages":[{"severity":"error","code":"db.import.write","text":"adding a reload request: ${text}"}]}` });
    try {
      assert.deepEqual(await signZone(s.ctx, JOB), { status: 'busy' });
      assert.deepEqual(s.state.inserted, []);
      empty(s.work);
    } finally { s.done(); }
  }
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], exit: { ...EXIT0, import: 1 }, importErr: '{"messages":[{"severity":"error","code":"db.import.write","text":"permission denied for table records"}]}' });
  try {
    assert.equal((await signZone(s.ctx, JOB)).status, 'failed');
  } finally { s.done(); }
});

test('exit status 3 of the first signing: the new keys stay stored, and the next try of the request signs with them (review W1-L1)', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED, exit: { ...EXIT0, import: 3 } });
  let stored;
  try {
    assert.deepEqual(await signZone(s.ctx, { ...JOB, request: ENABLE }), { status: 'changed' });
    assert.equal(s.state.inserted.length, 1, 'stored before the import');
    stored = s.state.inserted[0];
    empty(s.work);
  } finally { s.done(); }
  // the next run: the zone has that row and no PRESIGNED; the request's message names it (the database wrote it with the INSERT): no new key, signed with it
  const again = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED, keys: [{ id: 40, flags: 257, active: true, published: true, content: stored.content }], note: 'stored keys: cryptokeys 40' });
  try {
    const out = await signZone(again.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'signed', out.error);
    assert.ok(!names(again.calls).includes('keygen'));
    assert.deepEqual(again.state.inserted, []);
    assert.deepEqual(out.request, { state: 'done', message: 'signing enabled with the keys an earlier try stored (cryptokeys 40)' });
    const sign = again.calls.find((c) => c.name === 'signzone').argv;
    assert.ok(sign.includes('-3'), 'the request decides the chain (NSEC3), as for a first signing');
    empty(again.work);
  } finally { again.done(); }
  // a note that names other rows than the zone has (a key added by hand, a row deleted) is not a reason to sign: refused as before
  for (const [note, keys] of [['stored keys: cryptokeys 40', [row(KSK, 257), { ...row(ZSK, 256), id: 40 }]], ['stored keys: cryptokeys 41', [{ ...row(KSK, 257), id: 40 }]], ['done', [{ ...row(KSK, 257), id: 40 }]]]) {
    const x = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, keys, note });
    try {
      const out = await signZone(x.ctx, { ...JOB, request: ENABLE });
      assert.equal(out.status, 'failed');
      assert.match(out.error, /cryptokeys rows but no PRESIGNED metadata/);
      assert.deepEqual(x.calls, []);
    } finally { x.done(); }
  }
});

test('the import fails after the new keys are stored: the request says which rows hold them, and the zone is not signed (review W1-L1)', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED, exit: { ...EXIT0, import: 1 } });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: { ...ENABLE, keyType: 'ksk' } });
    assert.equal(out.status, 'failed');
    assert.equal(out.error, 'the zone is not signed, the new keys are kept (stored keys: cryptokeys 40,41; a new enable request of the zone signs with them): karidns-zone import: import failed');
    assert.equal(out.request.message, out.error, 'the answer of the request carries the note: a new request finds the rows by it');
    assert.equal(s.state.inserted.length, 2);
    assert.ok(!names(s.calls).includes('karictl'));
    empty(s.work);
    noSecrets(...s.logs, JSON.stringify(out));
  } finally { s.done(); }
  // the keys of an earlier try, and something unexpected (not a PipelineError) on the way
  const t = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED, keys: [{ ...row(KSK, 257), id: 40 }], note: 'the zone is not signed, the new keys are kept (stored keys: cryptokeys 40; a new ...' });
  t.ctx.run = async () => { throw new Error('kaboom'); };
  try {
    const out = await signZone(t.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.error, 'the zone is not signed, the new keys are kept (stored keys: cryptokeys 40; a new enable request of the zone signs with them): unexpected error: kaboom');
  } finally { t.done(); }
  // "changed" and "busy" keep their meaning (the request stays pending and is tried again)
  const b = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED, keys: [{ ...row(KSK, 257), id: 40 }], note: 'stored keys: cryptokeys 40', exit: { ...EXIT0, import: 4 } });
  try {
    assert.deepEqual(await signZone(b.ctx, { ...JOB, request: ENABLE }), { status: 'busy' });
  } finally { b.done(); }
});

test('storedKeyIds: the ids of the note, only when they are exactly the rows', () => {
  const rows = (...ids) => ids.map((id) => ({ id }));
  assert.deepEqual(storedKeyIds('stored keys: cryptokeys 12,3', rows(3, 12)), [3, 12]);
  assert.deepEqual(storedKeyIds('x (stored keys: cryptokeys 7; y)', rows('7')), [7], 'pg may give ids as text');
  assert.equal(storedKeyIds(null, rows(1)), null);
  assert.equal(storedKeyIds('stored keys: cryptokeys ', rows(1)), null);
  assert.equal(storedKeyIds('stored keys: cryptokeys 1', rows(1, 2)), null);
  assert.equal(storedKeyIds('stored keys: cryptokeys 1,2', rows(1)), null);
});

test('a result of karidns-zone that is not usable is an error', async () => {
  for (const out of ['not json', '{}', importJson({ committed: false }), importJson({ serial: 'x' })]) {
    const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], importOut: out });
    try {
      const r = await signZone(s.ctx, JOB);
      assert.equal(r.status, 'failed', out);
      assert.match(r.error, /gave no usable result/);
    } finally { s.done(); }
  }
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], importOut: importJson({ earliest_expire_epoch: undefined, write_id: undefined }) });
  try {
    const r = await signZone(s.ctx, JOB);
    assert.equal(r.status, 'signed');
    assert.equal(r.minExpire, null);
    assert.equal(r.writeId, null);
  } finally { s.done(); }
});

test('the message of a failed import is the first error of its JSON document', async () => {
  const doc = JSON.stringify({ messages: [{ severity: 'warning', code: 'w', text: 'ignore' }, { severity: 'error', code: 'db.import.signer', text: 'the file is not signed' }] });
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], exit: { ...EXIT0, import: 1 }, importErr: doc });
  try {
    const r = await signZone(s.ctx, JOB);
    assert.match(r.error, /karidns-zone import: db\.import\.signer: the file is not signed/);
  } finally { s.done(); }
});

test('tool failures with no output at all, a timeout, too much output', async () => {
  const bare = (o) => ({ code: 5, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false, spawnError: null, ...o });
  const run = (o) => async (file, argv, opts) => {
    if (file === tools(parseConfig(SQLITE_CONF).settings).zone && argv[0] === 'export') return bare(o);
    throw new Error('not reached');
  };
  for (const [o, re] of [[{}, /exit status 5/], [{ signal: 'SIGSEGV' }, /exit status 5 \(SIGSEGV\)/], [{ timedOut: true }, /timed out/], [{ truncated: true }, /wrote too much/]]) {
    const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)] });
    try {
      s.ctx.run = run(o);
      const r = await signZone(s.ctx, JOB);
      assert.match(r.error, re);
    } finally { s.done(); }
  }
});

test('karictl failing is a warning: the zone is signed', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)], exit: { ...EXIT0, karictl: 3 } });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'signed', out.error);
    assert.equal(out.warnings.length, 1);
    assert.match(out.warnings[0], /karictl reload example\.test failed .*not allowed/);
  } finally { s.done(); }
});

test('the keys of a signed zone are stored with retries, with the same key files', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED, insertFails: 2 });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'signed', out.error);
    assert.equal(out.request.state, 'done');
    assert.deepEqual(s.state.slept, [1000, 2000]);
    assert.equal(s.state.inserted.length, 1);
    assert.equal(names(s.calls).filter((n) => n === 'keygen').length, 1, 'no second key was made');
    assert.equal(s.logs.filter((l) => /cannot store the keys/.test(l)).length, 2);
    empty(s.work);
  } finally { s.done(); }
});

test('the keys cannot be stored at all: nothing is written, the zone is not signed, the request fails (review W1-L1: no DNSKEY without its key)', async () => {
  const s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED, insertFails: 99 });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'failed');
    assert.equal(out.request.state, 'failed');
    assert.match(out.request.message, /^the new keys could not be stored \(connection reset\): nothing was written, the zone is not signed; file the request again$/);
    assert.deepEqual(names(s.calls), ['keygen', 'zone', 'signzone', 'karicheck'], 'no import');
    assert.deepEqual(s.state.slept, [1000, 2000, 4000]);
    empty(s.work);
    noSecrets(...s.logs, JSON.stringify(out));
  } finally { s.done(); }
});

test('a key request of kind add: a key is made and stored, the zone is signed by the next run', async () => {
  const s = setup(SQLITE_CONF, { keys: [row(KSK, 257)] });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: { id: 8, kind: 'add', algorithm: 13, bits: null, keyType: 'zsk', nsec: null } });
    assert.equal(out.status, 'key-added');
    assert.equal(out.request.state, 'done');
    assert.match(out.request.message, /^key \d+ \(algorithm 13, flags 256\) added$/);
    assert.deepEqual(names(s.calls), ['keygen']);
    assert.ok(!s.calls[0].argv.includes('-f'));
    assert.deepEqual(s.state.inserted.map((k) => k.flags), [256]);
    empty(s.work);
    // a KSK
    const s2 = setup(SQLITE_CONF, { keys: [] });
    try {
      const o2 = await signZone(s2.ctx, { ...JOB, request: { id: 9, kind: 'add', algorithm: 15, bits: null, keyType: 'ksk', nsec: null } });
      assert.equal(o2.status, 'key-added');
      assert.deepEqual(s2.calls[0].argv.slice(0, 5), ['-q', '-a', 'ED25519', '-f', 'KSK']);
    } finally { s2.done(); }
  } finally { s.done(); }
});

test('add for a zone that is not the signer\'s, a key that cannot be stored, keygen failing, a wrong key tag', async () => {
  const add = { id: 8, kind: 'add', algorithm: 13, bits: null, keyType: 'csk', nsec: null };
  let s = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null } });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: add });
    assert.equal(out.status, 'failed');
    assert.match(out.error, /request kind enable first/);
    assert.deepEqual(s.calls, []);
  } finally { s.done(); }
  s = setup(SQLITE_CONF, { insertFails: 99 });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: add });
    assert.equal(out.status, 'failed');
    assert.match(out.error, /the new key could not be stored/);
    empty(s.work);
  } finally { s.done(); }
  s = setup(SQLITE_CONF, { exit: { ...EXIT0, keygen: 1 } });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: add });
    assert.match(out.error, /dnssec-keygen: dnssec-keygen: fatal: bad algorithm/);
  } finally { s.done(); }
  s = setup(SQLITE_CONF, { badTag: true });
  try {
    const out = await signZone(s.ctx, { ...JOB, request: add });
    assert.match(out.error, /key tag computed for the new key \(\d+\) is not the one dnssec-keygen chose \(1\)/);
    assert.deepEqual(s.state.inserted, []);
    empty(s.work);
  } finally { s.done(); }
});

test('an exception inside is an outcome, and the lock is released', async () => {
  const s = setup(SQLITE_CONF, { metaFails: true });
  try {
    const out = await signZone(s.ctx, JOB);
    assert.equal(out.status, 'failed');
    assert.match(out.error, /unexpected error: database went away/);
    assert.equal(s.state.unlocked, 1);
    empty(s.work);
  } finally { s.done(); }
  const s2 = setup(SQLITE_CONF, { keys: [row(KSK, 257)], unlockFails: true });
  try {
    const out = await signZone(s2.ctx, JOB);
    assert.equal(out.status, 'signed', out.error);
    assert.ok(s2.logs.some((l) => /cannot release the lock of example\.test: lock gone/.test(l)));
  } finally { s2.done(); }
});

test('prepareInput: the apex DNSKEY lines go, the rest stays, then the new DNSKEY lines', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-pi-'));
  try {
    const src = path.join(dir, 'src');
    fs.writeFileSync(src, '$ORIGIN example.test.\n@ DNSKEY 257 3 13 AAA\n@ 300 IN DNSKEY 256 3 13 BBB\n@ dnskey 256 3 13 CCC\nns1 DNSKEY 1 3 13 DDD\n@ NS ns1\n@ RRSIG DNSKEY 13 2 300 1 2 3 example.test. EEE\nfoo TXT "@ DNSKEY 1 3 13 not a record"\n');
    const dropped = await prepareInput(src, path.join(dir, 'dst'), ['example.test. IN DNSKEY 257 3 13 NEW\n']);
    assert.equal(dropped, 3);
    assert.equal(fs.readFileSync(path.join(dir, 'dst'), 'utf8'),
      '$ORIGIN example.test.\nns1 DNSKEY 1 3 13 DDD\n@ NS ns1\n@ RRSIG DNSKEY 13 2 300 1 2 3 example.test. EEE\nfoo TXT "@ DNSKEY 1 3 13 not a record"\nexample.test. IN DNSKEY 257 3 13 NEW\n');
    await assert.rejects(prepareInput(path.join(dir, 'nope'), path.join(dir, 'dst2'), []), /ENOENT/);
    await assert.rejects(prepareInput(src, path.join(dir, 'dst'), []), /EEXIST/);
    // a big export does not need to fit in one chunk
    const big = path.join(dir, 'big');
    fs.writeFileSync(big, 'host IN A 192.0.2.1\n'.repeat(300000));
    await prepareInput(big, path.join(dir, 'bigout'), []);
    assert.equal(fs.statSync(path.join(dir, 'bigout')).size, fs.statSync(big).size);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('signing mode and requested keys', () => {
  const k = (flags) => ({ flags });
  assert.equal(signingMode([k(257)]), 'csk');
  assert.equal(signingMode([k(257), k(257)]), 'csk');
  assert.equal(signingMode([k(257), k(256)]), 'split');
  assert.throws(() => signingMode([]), PipelineError);
  assert.throws(() => signingMode([k(256)]), /no active key-signing key/);
  assert.deepEqual(requestedKeys({ kind: 'enable', keyType: 'csk' }), [true]);
  assert.deepEqual(requestedKeys({ kind: 'enable', keyType: 'ksk' }), [true, false]);
  assert.deepEqual(requestedKeys({ kind: 'enable', keyType: 'zsk' }), [true, false]);
  assert.deepEqual(requestedKeys({ kind: 'add', keyType: 'csk' }), [true]);
  assert.deepEqual(requestedKeys({ kind: 'add', keyType: 'ksk' }), [true]);
  assert.deepEqual(requestedKeys({ kind: 'add', keyType: 'zsk' }), [false]);
});

test('the retry delays add up to about ten minutes; the default sleep sleeps', async () => {
  assert.ok(KEY_RETRY_DELAYS.reduce((a, b) => a + b, 0) >= 600);
  const t0 = Date.now();
  await defaultSleep(10);
  assert.ok(Date.now() - t0 >= 5);
});

test('insertKeysWithRetry and generateKeys directly', async () => {
  const s = setup(SQLITE_CONF, { insertFails: 1 });
  try {
    assert.deepEqual(await insertKeysWithRetry(s.ctx, 1, [{ flags: 256, content: 'x' }], [0]), { error: null, ids: [40] });
    assert.equal(s.state.insertedFor, null, 'no request: no note');
    s.state.insertFails = 5;
    const { error: err } = await insertKeysWithRetry(s.ctx, 1, [{ flags: 256, content: 'x' }], []);
    assert.match(err.message, /connection reset/);
    const dir = fs.mkdtempSync(path.join(s.work, 'g-'));
    const keys = await generateKeys(s.ctx, dir, 'example.test', { kind: 'enable', keyType: 'ksk', algorithm: 13, bits: null });
    assert.deepEqual(keys.map((k) => k.flags), [257, 256]);
    assert.equal(keys[0].key.algorithm, 13);
    fs.rmSync(dir, { recursive: true });
  } finally { s.done(); }
});


test('a first signing reloads the zone once: the INSERT of the keys was before the import, whose reload covers it', async () => {
  // PostgreSQL: import --signer --reload has the request, nothing else
  const pg = setup(PG_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED });
  try {
    const out = await signZone(pg.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'signed', out.error);
    assert.deepEqual(names(pg.calls), ['keygen', 'zone', 'signzone', 'karicheck', 'zone']);
    assert.ok(pg.calls[4].argv.includes('--reload'));
    assert.deepEqual(out.warnings, []);
  } finally { pg.done(); }
  // SQLite3: karictl once; a failure is a warning, and a karictl that cannot be run at all as well
  const sq = setup(SQLITE_CONF, { meta: { signer: false, presigned: false, nsec3param: null }, exportText: EXPORT_UNSIGNED, exit: { ...EXIT0, karictl: 3 } });
  try {
    const out = await signZone(sq.ctx, { ...JOB, request: ENABLE });
    assert.equal(out.status, 'signed');
    assert.equal(out.request.state, 'done');
    assert.equal(out.warnings.length, 1);
    assert.equal(names(sq.calls).filter((n) => n === 'karictl').length, 1);
  } finally { sq.done(); }
  const sq2 = setup(SQLITE_CONF, { keys: [row(KSK, 257)] });
  const run = sq2.ctx.run;
  sq2.ctx.run = async (file, argv, opts) => { if (file === sq2.ctx.tools.karictl) throw new Error('no such tool'); return run(file, argv, opts); };
  try {
    const out = await signZone(sq2.ctx, JOB);
    assert.equal(out.status, 'signed');
    assert.match(out.warnings[0], /the reload request for example\.test failed .*: no such tool/);
  } finally { sq2.done(); }
});

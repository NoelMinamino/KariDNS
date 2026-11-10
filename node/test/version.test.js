import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { packageVersion } from '../lib/version.js';

const top = (p) => new URL(`../../${p}`, import.meta.url);
const VERSION = fs.readFileSync(top('VERSION'), 'utf8').trim();

test('packageVersion: the version of package.json, equal to the file VERSION', () => {
  assert.equal(packageVersion(top('signer/package.json')), VERSION);
  assert.equal(packageVersion(top('webadmin/package.json')), VERSION);
});

test('packageVersion: refuses a package.json without a version x.y.z', () => {
  for (const text of ['{}', '{"version": 6}', '{"version": "0.6"}', '{"version": "0.6.0-rc1"}']) {
    assert.throws(() => packageVersion('x/package.json', () => text), /no version x\.y\.z/);
  }
  assert.equal(packageVersion('x/package.json', () => '{"version": "10.20.30"}'), '10.20.30');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { loadSqlite } from '../lib/sqlite.js';

test('loadSqlite: no ExperimentalWarning line, the original emitWarning is back, a missing module is explained', async () => {
  const before = process.emitWarning;
  const sqlite = await loadSqlite();
  assert.equal(typeof sqlite.DatabaseSync, 'function');
  assert.equal(process.emitWarning, before);
  await assert.rejects(loadSqlite(() => Promise.reject(new Error('no such module'))), /needs node:sqlite \(Node 22\.13 or newer\): no such module/);
  assert.equal(process.emitWarning, before);
  // the filter passes other warnings through, and an object-form ExperimentalWarning about something else
  const emit = process.emitWarning;
  let passed = 0;
  process.emitWarning = () => { passed++; };
  try {
    await loadSqlite(async () => {
      process.emitWarning('SQLite is an experimental feature', 'ExperimentalWarning');
      process.emitWarning('SQLite is an experimental feature', { type: 'ExperimentalWarning' });
      process.emitWarning('something else', 'ExperimentalWarning');
      process.emitWarning('SQLite deprecated', 'DeprecationWarning');
      return sqlite;
    });
  } finally {
    process.emitWarning = emit;
  }
  assert.equal(passed, 2);
});

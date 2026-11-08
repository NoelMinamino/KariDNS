// The error codes of docs/karidns-api.md and the codes the code can answer with must be the same set: a code that is thrown but not written down, or written down and
// never thrown (a typo, a code that went away), fails here.  The codes are read from the source: every `new ApiError(status, 'code', ...)`, `conflict(detail, 'code')`,
// `forbidden(detail, 'code')`, and the defaults of those helpers.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, docApiCodes } from './helpers.js';

const LIB = new URL('../lib/', import.meta.url);
const sources = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? sources(new URL(`${e.name}/`, dir)) : e.name.endsWith('.js') ? [new URL(e.name, dir)] : []));

// the arguments of the call whose '(' is at src[open]: the text of each top-level argument (strings and template literals are skipped over, so their commas and
// parentheses do not count)
function args(src, open) {
  const out = [];
  let depth = 0;
  let start = open + 1;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === "'" || c === '"' || c === '`') {
      for (i++; i < src.length && src[i] !== c; i++) if (src[i] === '\\') i++;
    } else if (c === '(' || c === '[' || c === '{') {
      depth++;
    } else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) { out.push(src.slice(start, i)); return out; }
    } else if (c === ',' && depth === 1) {
      out.push(src.slice(start, i));
      start = i + 1;
    }
  }
  throw new Error('no end of the call');
}

const literals = (text) => [...text.matchAll(/'([a-z]+(?:-[a-z]+)*)'/g)].map((m) => m[1]);

function codesInCode() {
  // the default of unauthenticated() in session.js, which takes its code as a parameter; the code of the conflict object that handlers/versions.js gives the pipeline
  const codes = new Set(['unauthenticated', 'version-conflict']);
  assert.ok(fs.readFileSync(new URL('handlers/versions.js', LIB), 'utf8').includes("code: 'version-conflict'"));
  for (const f of sources(LIB)) {
    const src = fs.readFileSync(f, 'utf8');
    for (const m of src.matchAll(/new ApiError\(/g)) {
      const a = args(src, m.index + m[0].length - 1);
      for (const c of literals(a[1] ?? '')) codes.add(c);
    }
    for (const [name, dflt] of [['conflict', 'conflict'], ['forbidden', 'forbidden']]) {
      for (const m of src.matchAll(new RegExp(`(?<![A-Za-z.])${name}\\(`, 'g'))) {
        if (/export (const|function) /.test(src.slice(Math.max(0, m.index - 20), m.index))) continue;       // the definition
        const a = args(src, m.index + m[0].length - 1);
        if (a.length < 2) codes.add(dflt);
        else for (const c of literals(a[1])) codes.add(c);
      }
    }
    if (/\bbadRequest\(/.test(src)) codes.add('bad-request');
    if (/\bnotFound\(/.test(src)) codes.add('not-found');
  }
  return codes;
}

const codesInDocs = docApiCodes;

test('every error code the API can answer with is in the table of docs/karidns-api.md, and every code of the table exists', () => {
  const code = codesInCode();
  const docs = codesInDocs();
  assert.ok(code.size > 40 && docs.size > 40, `${code.size} codes in the code, ${docs.size} in the docs`);
  assert.deepEqual([...code].filter((c) => !docs.has(c)).sort(), [], 'thrown, not documented');
  assert.deepEqual([...docs].filter((c) => !code.has(c) && c !== 'internal').sort(), [], 'documented, never thrown');
});

test('the manuals name every file of the package and the rc script variable names that the rc script reads', () => {
  const rc = fs.readFileSync(new URL('packaging/freebsd/rc.d/karidns_webadmin', ROOT), 'utf8');
  const manual = fs.readFileSync(new URL('docs/karidns-webadmin.md', ROOT), 'utf8');
  for (const v of ['karidns_webadmin_enable', 'karidns_webadmin_config', 'karidns_webadmin_user', 'karidns_webadmin_flags']) {
    assert.ok(rc.includes(`: \${${v}:=`), `${v} has a default in the rc script`);
    assert.ok(manual.includes(v), `${v} is in the manual`);
  }
  for (const p of ['/usr/local/sbin/karidns-webadmin', '/usr/local/etc/rc.d/karidns_webadmin', '/usr/local/etc/karidns/karidns-webadmin.conf.sample', '/usr/local/libexec/karidns-webadmin/']) {
    assert.ok(manual.includes(p), `${p} is in the manual`);
  }
  // every setting of the configuration file is in the reference
  const api = fs.readFileSync(new URL('docs/karidns-api.md', ROOT), 'utf8');
  const conf = fs.readFileSync(new URL('webadmin/lib/config.js', ROOT), 'utf8');
  const keys = [...conf.slice(conf.indexOf('const GLOBAL_KEYS'), conf.indexOf('const DATASET_KEYS')).matchAll(/^\s+'?([a-z-]+)'?:/gm)].map((m) => m[1]);
  assert.ok(keys.length >= 25, `${keys.length} settings`);
  for (const k of keys) assert.ok(api.includes(`\`${k}\``), `the setting ${k} is in the table of docs/karidns-api.md`);
});

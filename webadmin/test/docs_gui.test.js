// The user manual of the web interface and its checklist (docs/karidns-webadmin-gui.md, docs/karidns-webadmin-gui-checklist.md; plan F-19, F-22) are kept in step with the
// screens: every message the manual quotes is a message of the catalog, every term of the glossary is a term of the interface in that language, every menu entry and section is
// named, the examples are valid and use only the names reserved for documentation, every link goes somewhere, the checklist names every success criterion of WCAG 2.1 A and AA
// and the tests it points at, and the package holds both files.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ROOT } from './helpers.js';
import en from '../ui/i18n/en.js';
import ja from '../ui/i18n/ja.js';
import { parseRecordLine } from '../ui/js/zonelib.js';
import { contentProblem } from '../lib/changes.js';

const read = (rel) => fs.readFileSync(new URL(rel, ROOT), 'utf8').replace(/\r\n/g, '\n');
const MANUAL = read('docs/karidns-webadmin-gui.md');
const CHECK = read('docs/karidns-webadmin-gui-checklist.md');
const enText = Object.values(en);
const jaText = Object.values(ja);

// the lines of a section "## NAME" up to the next "## "
const section = (md, name) => {
  const m = new RegExp(`^## ${name}\\n([\\s\\S]*?)(?=^## |\\Z)`, 'm').exec(md);
  assert.ok(m, `no section ${name}`);
  return m[1];
};
// the rows of the first table of a block: arrays of cells
const rows = (block) => block.split('\n').filter((l) => /^\|.*\|$/.test(l)).slice(2).map((l) => l.slice(1, -1).split(/(?<!\\)\|/).map((c) => c.trim()));

test('both files exist, are linked from the README and the service manual, and are in the package', () => {
  for (const f of ['docs/karidns-webadmin-gui.md', 'docs/karidns-webadmin-gui-checklist.md']) {
    assert.ok(fs.existsSync(new URL(f, ROOT)), f);
    const base = f.slice('docs/'.length);
    assert.ok(read('docs/karidns-webadmin.md').includes(`(${base})`), `docs/karidns-webadmin.md links ${base}`);
    assert.ok(read('packaging/freebsd/build_webadmin_pkg.sh').includes(`docs/${base}`), `the package script installs ${base}`);
  }
  assert.ok(read('README.md').includes('(docs/karidns-webadmin-gui.md)'), 'README links the manual');
  assert.ok(read('README.md').includes('(docs/karidns-webadmin-gui-checklist.md)'), 'README links the checklist');
  assert.ok(MANUAL.includes('(karidns-webadmin-gui-checklist.md)') && CHECK.includes('(karidns-webadmin-gui.md)'), 'they link each other');
});

test('every relative link of the two files goes to a file that exists', () => {
  for (const md of [MANUAL, CHECK]) {
    const links = [...md.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)].map((m) => m[1]).filter((l) => !/^[a-z]+:/.test(l));
    assert.ok(links.length >= 3);
    for (const l of links) assert.ok(fs.existsSync(new URL(`docs/${l}`, ROOT)), `link to ${l}`);
  }
});

test('the examples use only names and addresses reserved for documentation', () => {
  for (const [name, md] of [['manual', MANUAL], ['checklist', CHECK]]) {
    const text = md.replace(/\]\([^)]*\)/g, ']').replace(/`[a-z0-9.-]+\.(md|js|mjs|sh|c|conf|sample)`/g, '');
    // host names: a name ending in a real top-level domain
    const real = [...text.matchAll(/\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\.(?:com|net|org|jp|io|dev|info|biz|co|uk|de|fr|ru|cn|us|eu|app|cloud|tokyo|xyz|local)\b/gi)].map((m) => m[0]);
    assert.deepEqual(real, [], `${name}: a name that may be real`);
    for (const m of text.matchAll(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g)) {
      assert.ok(m[0].startsWith('192.0.2.') || m[0].startsWith('198.51.100.') || m[0].startsWith('203.0.113.') || m[0] === '127.0.0.1', `${name}: the address ${m[0]}`);
    }
    for (const m of text.matchAll(/\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b/gi)) {
      if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(m[0]) || /^\d{4}-/.test(m[0])) continue;
      assert.ok(/^2001:db8:/i.test(m[0]), `${name}: the IPv6 address ${m[0]}`);
    }
  }
});

test('the record examples are lines the interface accepts (name [ttl] TYPE data, data that a change takes)', () => {
  const blocks = [...MANUAL.matchAll(/```records\n([\s\S]*?)```/g)].map((m) => m[1]);
  assert.ok(blocks.length >= 3);
  let lines = 0;
  for (const b of blocks) {
    for (const line of b.split('\n').filter(Boolean)) {
      const r = parseRecordLine(line);
      assert.ok(r, `not a record line: ${line}`);
      assert.equal(contentProblem(r.content), null, `the data of ${line}`);
      assert.match(r.type, /^(A|AAAA|MX|NS|SRV|TXT|CNAME)$/, line);
      lines++;
    }
  }
  assert.ok(lines >= 8);
});

test('every message the manual quotes in its table is a message of the interface, word for word', () => {
  const table = rows(section(MANUAL, 'MESSAGES AND WHAT TO DO'));
  assert.ok(table.length >= 25, `${table.length} rows`);
  for (const [msg, advice] of table) {
    const m = /^`(.+)`$/.exec(msg);
    assert.ok(m, `the first cell is a quoted message: ${msg}`);
    assert.ok(enText.includes(m[1]), `not a message of the English catalog: ${m[1]}`);
    assert.ok(advice.length > 10, `advice for ${m[1]}`);
  }
  // the messages of the refusals a person meets every day are among them
  for (const id of ['api.invalid-credentials', 'api.precondition-failed', 'api.forbidden', 'api.rate-limited', 'api.unauthenticated', 'api.zone-checks-failed', 'api.version-conflict', 'login.oidc-failed']) {
    assert.ok(table.some(([msg]) => msg === `\`${en[id]}\``), `${id} is in the table`);
  }
});

test('the glossary: each term is a word of the interface in its language', () => {
  const g = rows(section(MANUAL, 'GLOSSARY'));
  assert.ok(g.length >= 25, `${g.length} terms`);
  for (const [e, j, meaning] of g) {
    const term = e.replace(/\s*\(.*\)$/, '').toLowerCase();
    assert.ok(enText.some((x) => x.toLowerCase().includes(term)), `English term "${e}" is in no message of the interface`);
    assert.ok(jaText.some((x) => x.includes(j)), `Japanese term "${j}" is in no message of the Japanese interface`);
    assert.ok(meaning.length > 10, e);
  }
  for (const must of ['zone', 'record set', 'change set', 'preview', 'commit', 'version', 'rollback', 'grant', 'record policy', 'global master', 'domain master', 'subdomain master', 'template']) {
    assert.ok(g.some(([e]) => e.toLowerCase().startsWith(must)), `the glossary has ${must}`);
  }
});

test('the manual names every entry of the menu and every section of a zone, in the words of the interface', () => {
  for (const id of ['nav.home', 'nav.zones', 'nav.templates', 'nav.servers', 'nav.admin', 'nav.audit', 'nav.account', 'nav.about', 'zone.sec-records', 'zone.sec-versions', 'zone.sec-import',
    'zone.sec-template', 'zone.sec-settings', 'zone.sec-dnssec', 'zone.sec-grants', 'zone.export', 'reload.button', 'flow.preview', 'flow.commit', 'conflict.take-theirs', 'conflict.keep-mine',
    'rollback.preview', 'rollback.force', 'account.tok-done', 'account.logout-all', 'settings.del', 'admin.unlock', 'admin.reset-totp', 'admin.oidc-link', 'draft.undo', 'edit.ok']) {
    assert.ok(MANUAL.includes(en[id].replace(/\.\.\.$/, '')), `the manual does not name "${en[id]}" (${id})`);
  }
  for (const heading of ['SIGNING IN', 'ZONES', 'CHANGING RECORDS', 'VERSIONS AND ROLLBACK', 'TEMPLATES', 'DNSSEC', 'ADMINISTRATION', 'AUDIT LOG', 'YOUR ACCOUNT', 'ACCESSIBILITY', 'MEASUREMENTS']) section(MANUAL, heading);
});

test('the note on bytes: the manual says what the page shows for a byte that is not ASCII and for a control character', () => {
  assert.match(MANUAL, /`\\195\\169`/);
  assert.match(MANUAL, /\\DDD/);
  assert.match(MANUAL, /<U\+202E>/);
});

// ---------------------------------------------------------------------------------------------------------------------------------- the checklist
const WCAG21_AA = ('1.1.1 1.2.1 1.2.2 1.2.3 1.2.4 1.2.5 1.3.1 1.3.2 1.3.3 1.3.4 1.3.5 1.4.1 1.4.2 1.4.3 1.4.4 1.4.5 1.4.10 1.4.11 1.4.12 1.4.13 2.1.1 2.1.2 2.1.4 2.2.1 2.2.2 2.3.1 '
  + '2.4.1 2.4.2 2.4.3 2.4.4 2.4.5 2.4.6 2.4.7 2.5.1 2.5.2 2.5.3 2.5.4 3.1.1 3.1.2 3.2.1 3.2.2 3.2.3 3.2.4 3.3.1 3.3.2 3.3.3 3.3.4 4.1.1 4.1.2 4.1.3').split(' ');

test('the checklist has a row for every success criterion of WCAG 2.1 A and AA, each Met or Not applicable', () => {
  const t = rows(section(CHECK, '1. THE WCAG 2.1 AA CHECKLIST'));
  const seen = new Set();
  for (const [sc, name, status, how] of t) {
    const range = /^(\d\.\d\.\d+) to (\d\.\d\.\d+)$/.exec(sc);
    if (range) {
      const [a, z] = [range[1], range[2]].map((x) => Number(x.split('.')[2]));
      for (let n = a; n <= z; n++) seen.add(`${range[1].slice(0, range[1].lastIndexOf('.') + 1)}${n}`);
    } else {
      assert.match(sc, /^\d\.\d\.\d+$/, sc);
      seen.add(sc);
    }
    assert.ok(name.length > 3 && how.length > 8, sc);
    assert.match(status, /^(Met|Not applicable)$/, `${sc}: ${status}`);
  }
  assert.deepEqual(WCAG21_AA.filter((x) => !seen.has(x)), [], 'criteria without a row');
  assert.deepEqual([...seen].filter((x) => !WCAG21_AA.includes(x)), [], 'rows that are not criteria of A or AA');
});

test('the tests the checklist points at exist, and the script checks it claims are in a11y.mjs', () => {
  for (const f of ['webadmin/test/ui_review.test.js', 'webadmin/test/e2e/a11y.mjs', 'webadmin/test/ui_views.test.js', 'webadmin/test/ui_scan.test.js', 'tests/run_webadmin_gui_test.sh', 'tests/run_webadmin_gui_pg_test.sh']) {
    assert.ok(fs.existsSync(new URL(f, ROOT)), f);
    assert.ok(CHECK.includes(f.split('/').pop()), `the checklist names ${f}`);
  }
  const a11y = read('webadmin/test/e2e/a11y.mjs');
  for (const claim of ['has no label', 'autocomplete', 'does not contain the visible text', 'jumps from', 'a header cell without scope', 'duplicate id', 'live region', 'an open dialog without a name', 'a nav without a name', 'an image without a name', 'no title', 'overflowProblems']) {
    assert.ok(a11y.includes(claim), `a11y.mjs has the check "${claim}"`);
  }
  // the unit test that the checklist calls the contrast test really tests the pairs it says it does
  const review = read('webadmin/test/ui_review.test.js');
  assert.equal([...review.slice(review.indexOf('const TEXT'), review.indexOf('const NON_TEXT')).matchAll(/\['[a-z-]+', '[a-z-]+', '[^']+'\]/g)].length, 16, 'the 16 text pairs');
  assert.equal([...review.slice(review.indexOf('const NON_TEXT')).matchAll(/\['[a-z-]+', '[a-z-]+', '[^']+'\]/g)].length, 12, 'the 12 non-text pairs');
});

test('the manual of the web interface and the service manual agree on the list of browsers', () => {
  const svc = read('docs/karidns-webadmin.md');
  for (const md of [MANUAL, svc, CHECK]) assert.match(md, /Safari 17/);
  assert.match(MANUAL, /Firefox ESR, Chrome and Edge/);
});

test('the files exist where the fileURLToPath of the test finds them', () => {
  assert.ok(fs.existsSync(fileURLToPath(new URL('docs/karidns-webadmin-gui.md', ROOT))));
});

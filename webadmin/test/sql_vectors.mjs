// The permission vectors (tests/auth_vectors.json) against the SQL functions of db/karidns_ext.pgsql.sql: the other implementation of the rules perm.js has.
// Not a node:test file (it needs a PostgreSQL server): tests/run_webadmin_pg_test.sh runs it.
//
//   node webadmin/test/sql_vectors.mjs CONNINFO-FILE      the connection of the table owner, to a database with db/karidns_ext.pgsql.sql applied
//
// Every case is made in a transaction of its own (policies, a user 'u', groups, memberships, grants), the checks run as that user, and the transaction is
// rolled back.  Prints "  [ OK ] case" / "  [FAIL] case: check" lines; the exit status is 1 when a check differs.

import fs from 'node:fs';
import pg from 'pg';
import { parseConninfo } from '../../node/lib/conf.js';

const vectors = JSON.parse(fs.readFileSync(new URL('../../tests/auth_vectors.json', import.meta.url), 'utf8'));
const client = new pg.Client(parseConninfo(fs.readFileSync(process.argv[2], 'utf8'), 'sql_vectors'));
await client.connect();

const q = async (sql, params) => (await client.query(sql, params)).rows;
let failures = 0;
let checks = 0;

for (const c of vectors.cases) {
  let bad = 0;
  await client.query('BEGIN');
  try {
    const pid = {};
    for (const [name, p] of Object.entries(vectors.policies)) {
      pid[name] = (await q(`INSERT INTO karidns_auth.rr_policies (name, allowed_types, allow_wildcard, allow_delegation, allow_dname, apex_editable, ttl_min, ttl_max, max_rr)
                            VALUES ($1, $2::text[], $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
        [`vec_${name}`, p.allowed_types, p.allow_wildcard, p.allow_delegation, p.allow_dname, p.apex_editable, p.ttl_min, p.ttl_max, p.max_rr]))[0].id;
    }
    const id = {};
    id.u = (await q("INSERT INTO karidns_auth.principals (kind, name, disabled) VALUES ('user', 'vec_u', $1) RETURNING id", [Boolean(c.user_disabled)]))[0].id;
    for (const g of c.groups ?? []) id[g.name] = (await q("INSERT INTO karidns_auth.principals (kind, name, disabled) VALUES ('group', $1, $2) RETURNING id", [`vec_${g.name}`, g.disabled]))[0].id;
    for (const g of c.groups ?? []) for (const m of g.members) await q('INSERT INTO karidns_auth.memberships (member_id, group_id) VALUES ($1, $2)', [id[m], id[g.name]]);
    for (const g of c.grants) {
      await q('INSERT INTO karidns_auth.grants (principal_id, role, data_schema, zone_name, name_suffix, rr_policy_id) VALUES ($1, $2, $3, $4, $5, $6)',
        [id[g.to], g.role, g.schema, g.zone, g.suffix, pid[g.policy]]);
    }
    await q("SELECT set_config('karidns.principal', $1, true)", [String(id.u)]);
    for (const k of c.checks) {
      let rows;
      switch (k.fn) {
        case 'rr_ok': rows = await q('SELECT karidns_auth.rr_ok($1::text, $2::text, $3::text, $4::text, $5::integer) AS v', [k.schema, k.zone, k.name, k.type, k.ttl]); break;
        case 'rr_visible': rows = await q('SELECT karidns_auth.rr_visible($1::text, $2::text, $3::text, $4::text) AS v', [k.schema, k.zone, k.name, k.type]); break;
        case 'zone_grant': rows = await q('SELECT karidns_auth.zone_grant($1::text, $2::text) AS v', [k.schema, k.zone]); break;
        case 'is_global': rows = await q('SELECT karidns_auth.is_global() AS v'); break;
        case 'policy_subset': rows = await q('SELECT karidns_auth.policy_subset($1::bigint, $2::bigint) AS v', [pid[k.sub], pid[k.sup]]); break;
        case 'may_grant': rows = await q('SELECT karidns_auth.may_grant($1::text, $2::text, $3::text, $4::bigint) AS v', [k.role, k.schema, k.zone, pid[k.policy]]); break;
        default: throw new Error(`unknown check ${k.fn}`);
      }
      checks++;
      if (rows[0].v !== k.expect) {
        bad++;
        console.log(`  [FAIL] ${c.name}: ${JSON.stringify(k)} gave ${JSON.stringify(rows[0].v)}`);
      }
    }
  } finally {
    await client.query('ROLLBACK');
  }
  if (bad === 0) console.log(`  [ OK ] ${c.name} (${c.checks.length} checks)`);
  failures += bad;
}
await client.end();
console.log(`${checks} checks, ${failures} different`);
process.exit(failures ? 1 : 0);

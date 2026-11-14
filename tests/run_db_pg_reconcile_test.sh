#!/bin/sh
# run_db_pg_reconcile_test.sh - run_db_reconcile_test.sh on PostgreSQL (0.7 WP7b): the same first fill, restart, changes, mass-delete guard and release with the real karidns and
# karidns-dbloader.  SKIP when PostgreSQL is not reachable (tests/db/pg_lib.sh: KARIDNS_TEST_PG, KARIDNS_TEST_PG_USER).  Needs root, like the SQLite3 test.
exec env RECON_DRIVER=postgresql sh "$(dirname "$0")/run_db_reconcile_test.sh" "$@"

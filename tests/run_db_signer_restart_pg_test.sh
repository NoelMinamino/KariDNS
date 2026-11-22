#!/bin/sh
# run_db_signer_restart_pg_test.sh - run_db_signer_restart_test.sh with PostgreSQL (SIGNER_DB=pg; tests/db/pg_lib.sh, KARIDNS_TEST_PG): signer-wait across restarts of the
# server and of the loader and under memory-limit (0.7, P3 paths (c) and (d)), without the zone store and with it.  SKIP when PostgreSQL is not reachable.
exec env SIGNER_DB=pg sh "$(dirname "$0")/run_db_signer_restart_test.sh" "$@"

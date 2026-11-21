#!/bin/sh
# run_db_signer_wait_pg_store_test.sh - run_db_signer_wait_pg_test.sh with the zone store on (DB_STORE=on, the default of a production server).  Before the fix (0.7 development) the store path read the
# metadata X-KARIDNS-SIGNER outside a snapshot, which the PostgreSQL driver refuses (its scans are cursors), so every changed zone of the signer was served at once and none was
# listed as waiting; and a one-zone reload of a zone whose serial had not moved was "unchanged" (no version stamp).  Needs what run_db_signer_wait_pg_test.sh needs.
exec env DB_STORE=on sh "$(dirname "$0")/run_db_signer_wait_pg_test.sh" "$@"

#!/bin/sh
# run_db_signer_wait_store_test.sh - run_db_signer_wait_test.sh with the zone store on (DB_STORE=on, the default of a production server): the loader follows the change log with
# the store protocol (CHANGES), and a changed zone of the signer is sent with KDB_EF_HOLD, which the Backend's store keeps at the version it has (STORE_F_SIGNER_HELD).  Before the fix (0.7 development)
# the store path held a zone the Backend did not have yet as well (a new zone of the signer was never served) and named the waiting zones with a trailing dot.  Needs what
# run_db_signer_wait_test.sh needs.
exec env DB_STORE=on sh "$(dirname "$0")/run_db_signer_wait_test.sh" "$@"

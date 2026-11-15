#!/bin/sh
# run_karictl_rollback_db_store_test.sh - run_karictl_rollback_db_test.sh with the zone store on (0.7, review of S3 + S4, M4): the database server has `store "<dir>";`.  karictl rollback, zonestatus and notify find a
# zone of the store that is in memory (the entry is held for the command), and say something sensible for one that is not (the server is started again on its store: the zones are stored and not in memory): zonestatus shows
# the record, rollback says there is no previous version to go back to, notify attaches the zone first.  Needs what run_karictl_rollback_db_test.sh needs.
exec env DB_STORE=on sh "$(dirname "$0")/run_karictl_rollback_db_test.sh" "$@"

#!/bin/sh
# run_db_park_store_test.sh - run_db_park_test.sh with the zone store on (0.7 WP7b): the database server has `store "<dir>";` (the store protocol: the loader lists the zones, the bodies are fetched
# into the store), the default of a production server.  The checks whose premise is the old behaviour (a zone that is out of memory is read from the loader) are written for both modes
# in the test itself (the $STORE variable); the rest is the same.  Needs what run_db_park_test.sh needs.
exec env DB_STORE=on sh "$(dirname "$0")/run_db_park_test.sh" "$@"

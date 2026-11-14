#!/bin/sh
# run_db_file_diff_store_test.sh - run_db_file_diff_test.sh in the store-cold mode (0.7 store S3, WP6): the database server B has a zone store and has read every zone; it is stopped and started again
# on the same store with an idle program in the place of the loader, so every answer of B is made from the store alone (a zone is attached on its first query).  The answers (plain, EDNS, DO;
# owners x types, NXDOMAIN, NODATA, ANY; AXFR; a secondary of B) must still be the zone file's, byte for byte.  Needs root, like run_db_file_diff_test.sh.
exec env DB_DIFF_STORE=cold sh "$(dirname "$0")/run_db_file_diff_test.sh" "$@"

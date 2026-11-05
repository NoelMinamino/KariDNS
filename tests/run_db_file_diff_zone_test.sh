#!/bin/sh
# run_db_file_diff_zone_test.sh - run_db_file_diff_test.sh with the database filled by `karidns-zone import` instead of the SQL tests/db/zone2sql
# prints (0.6.0 milestone M3): a zone served from the file and the same zone imported with the product's importer and served from the database give the
# same answers (byte for byte: plain, EDNS, DO; owners x types, NXDOMAIN, NODATA, ANY; AXFR; a secondary of the database server).
# Needs root, like run_db_file_diff_test.sh (the loader runs as another user); karidns-zone itself does not.
exec env DB_IMPORTER=karidns-zone sh "$(dirname "$0")/run_db_file_diff_test.sh" "$@"

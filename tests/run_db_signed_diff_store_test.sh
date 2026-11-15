#!/bin/sh
# run_db_signed_diff_store_test.sh - run_db_signed_diff_test.sh in the store-cold mode (0.7 store S3, WP6): as run_db_file_diff_store_test.sh, for the signed zones (NSEC, NSEC3, opt-out; DO=1 answers
# with the RRSIGs and the proofs of the zone the database holds are the signed file's, byte for byte, from a server that answers from its store alone).  Needs root.
exec env DB_DIFF_STORE=cold sh "$(dirname "$0")/run_db_signed_diff_test.sh" "$@"

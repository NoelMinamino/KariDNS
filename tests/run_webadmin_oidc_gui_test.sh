#!/bin/sh
# run_webadmin_oidc_gui_test.sh - the browser part (part 3) of tests/run_webadmin_oidc_test.sh: Firefox headless (webadmin/test/e2e/gui_oidc.mjs) signs in at a fake
# OpenID Connect provider and comes back, the refusals, the link in the administration.  Category gui of tests/run_all_suite.sh (run with --with-gui or --only-gui).
# SKIP (exit 0, with the reason) without node 22.13, the sqlite3 tool, the binaries, Firefox or geckodriver.
OIDC_PARTS=3 exec sh "$(dirname "$0")/run_webadmin_oidc_test.sh" "$@"

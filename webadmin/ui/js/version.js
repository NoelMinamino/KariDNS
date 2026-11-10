// The version of these files.  GET /version names the service's; when they differ the page is old (the service was upgraded while it was open, or a cache kept
// it) and the GUI asks for a reload (planning 4.4).  Written by `make set-version` (tools/set_version.sh, docs/RELEASING.md): a static file of the
// browser cannot read the file VERSION.  A unit test keeps it equal to webadmin/package.json, tests/run_version_test.sh to VERSION.
export const GUI_VERSION = '0.6.0';

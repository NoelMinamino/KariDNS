// The version of these files.  GET /version names the service's; when they differ the page is old (the service was upgraded while it was open, or a cache kept
// it) and the GUI asks for a reload (planning 4.4).  Written by `make set-version` (tools/set_version.sh, docs/RELEASING.md): a static file of the
// browser cannot read the file VERSION.  A unit test keeps it equal to webadmin/package.json, tests/run_version_test.sh to VERSION.
export const GUI_VERSION = '0.6.2';

// What GET /version says about asking the servers to reload (T-1), for every screen that offers it (the update button, the "update the servers after saving"
// box): available = the service can ask (ui.reload_available; false on SQLite3 without karictl-config, where it refuses a reload with 400); checked = the box is
// ticked at first (ui.reload_after_change).  A service that does not say (older than the field, or /version not read) is taken to be able to: it still refuses.
export function reloadOffer(ctx) {
  const ui = ctx.session.state.version?.ui;
  const available = ui?.reload_available !== false;
  return { available, checked: available && ui?.reload_after_change === true };
}

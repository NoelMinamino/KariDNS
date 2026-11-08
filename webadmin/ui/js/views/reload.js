// The "update" button of a zone and what follows it (planning 3 S4 and S14, F-14).  A reload is explicit (D-RELOAD): the button asks the service to make the servers
// read the zone again.  The page then looks at the zone and at the servers every five seconds, for two minutes at most (the only polling the interface does: it
// would otherwise keep the session alive), and says how many servers have applied the request.  A zone the signer keeps signed has no button: the signer asks.

import { h } from '../dom.js';
import { message, problemNodes } from '../widgets.js';
import { zonePath } from '../zonelib.js';
import { plain } from '../format.js';

export const POLL_MS = 5000;
export const WATCH_MS = 120000;

// -> { node, watch(), dispose() }.  watch(): look at the progress of a reload that was asked for some other way (a change set with "reload now").
export function reloadControl(ctx, { ds, zone, signer }) {
  const { api, i18n, timers, now } = ctx;
  const t = i18n.t;
  const status = message('status');
  const err = message('error');
  let button = null;
  let timer = null;
  let until = 0;
  let alive = true;

  function stop() {
    if (timer !== null) timers.clearInterval(timer);
    timer = null;
  }

  async function poll() {
    try {
      const [z, s] = await Promise.all([api.get(zonePath(ds, zone)), api.get('/servers')]);
      if (!alive) return;
      const generation = z.zone.last_reload_request?.generation;
      const servers = (s.servers ?? []).filter((x) => x.dataset === ds);
      if (generation === undefined || servers.length === 0) { stop(); return; }
      const applied = servers.filter((x) => x.generation >= generation);
      if (applied.length === servers.length) {
        stop();
        status.set(t('reload.applied', { total: servers.length }));
      } else {
        status.set(t('reload.progress', { applied: applied.length, total: servers.length }));
      }
      if (timer !== null && now() >= until) { stop(); status.set(t('reload.gave-up', { applied: applied.length, total: servers.length })); }
    } catch {
      stop();
    }
  }

  function watch() {
    stop();
    until = now() + WATCH_MS;
    timer = timers.setInterval(poll, POLL_MS);
  }

  async function press() {
    err.set(null);
    status.set(null);
    button.disabled = true;
    try {
      const r = await api.post(`${zonePath(ds, zone)}/reload`, {});
      status.set(t('reload.requested'));
      ctx.announce(t('reload.requested'));
      if (r.reload === 'requested') watch();
    } catch (e) {
      err.setNodes(...problemNodes(i18n, e), e.status === 400 && e.detail ? [' ', plain(e.detail)] : null);
    } finally {
      button.disabled = false;
    }
  }

  if (!signer) button = h('button', { type: 'button', class: 'primary', on: { click: press } }, t('reload.button'));
  const node = h('div', { class: 'reload' },
    signer ? h('p', { class: 'hint' }, t('reload.signer')) : h('div', { class: 'actions' }, button, h('span', { class: 'hint' }, t('reload.hint'))),
    status.node, err.node);
  return { node, watch, dispose() { alive = false; stop(); } };
}

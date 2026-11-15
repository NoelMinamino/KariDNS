// session.js: who is signed in, and for how long (planning 5.3).
//
// - The CSRF token is held in memory only (api.js sends it); after a page reload it is fetched again by GET /auth/me.
// - F-14: NO background request extends the session.  The idle timeout of the service (every authenticated request moves `last_seen`) keeps its meaning: the GUI
//   counts down from its own last request, warns two minutes before the end, and offers "stay signed in" (one GET /auth/me, made when the user asks).  The service
//   writes last_seen at most once a minute, so the countdown ends a minute early.  With a short idle time (the person's own choice on the account screen, or a low
//   session-idle) both scale down: leadTimes() below.
// - Logout, and "log out everywhere", tell the other tabs through a BroadcastChannel; they go to the sign-in screen.
// - A 401 anywhere asks the app to sign in again over the current screen (reauth); the answer says whether it was the same principal.

export const CHANNEL = 'karidns-webadmin';
export const WARN_BEFORE_MS = 120000;
export const SAFETY_MS = 60000;
const MAX_TIMER = 2 ** 31 - 1;

// How early the GUI ends the countdown (margin) and warns before that end (warn), for an idle time in ms.  The service writes last_seen at most every
// min(60 s, idle / 4) (lib/session.js), so the margin is the same; the warning is two minutes, or a quarter of the idle time where that is shorter:
//   30 min: margin 60 s, warning 2 min    10 min: 60 s, 2 min    5 min: 60 s, 75 s    1 min: 15 s, 15 s
export const leadTimes = (idleMs) => ({ margin: Math.min(SAFETY_MS, idleMs / 4), warn: Math.min(WARN_BEFORE_MS, idleMs / 4) });

// opts: { api, timers: { setTimeout, clearTimeout }, now, BroadcastChannel (or null) }
export function createSession({ api, timers, now, BroadcastChannel: BC }) {
  const listeners = {};
  const emit = (ev, arg) => { for (const fn of listeners[ev] ?? []) fn(arg); };
  const st = {
    status: 'unknown',                // unknown | in | out | expired
    me: null,
    version: null,
    expiresAt: 0,
    idleMs: 0,
    lastActivity: 0,
    warned: false,
    timer: null,
    pending: null,                    // the sign-in dialog that is open (one at a time)
    previous: null,                   // the principal id of the session that ended
    leaving: false,
  };
  const guards = new Set();
  let reauthHandler = null;
  let channel = null;

  function stopTimer() {
    if (st.timer !== null) timers.clearTimeout(st.timer);
    st.timer = null;
  }

  // the end of this session as the GUI counts it: the idle time from the last request (less a minute), or the absolute end
  function deadlines() {
    const idle = st.lastActivity + st.idleMs - leadTimes(st.idleMs).margin;
    return st.expiresAt && st.expiresAt <= idle ? { at: st.expiresAt, kind: 'max' } : { at: idle, kind: 'idle' };
  }

  function schedule() {
    stopTimer();
    if (st.status !== 'in') return;
    const { at, kind } = deadlines();
    // (the absolute end may come sooner than the idle end: the warning is then at most half the time that is left)
    const warnAt = at - Math.min(leadTimes(st.idleMs).warn, (at - st.lastActivity) / 2);
    const t = now();
    if (t >= at) {
      st.status = 'expired';
      st.previous = st.me?.principal.id ?? null;
      emit('expired');
      return;
    }
    if (t >= warnAt && !st.warned) {
      st.warned = true;
      emit('warn', { at, kind });
    }
    const next = st.warned ? at : warnAt;
    st.timer = timers.setTimeout(schedule, Math.min(MAX_TIMER, Math.max(250, next - t)));
  }

  // every authenticated answer moves the service's last_seen, and so ours
  function touch(ms) {
    if (st.status !== 'in') return;
    st.lastActivity = ms;
    if (st.warned) {
      st.warned = false;
      emit('warn-clear');
    }
    schedule();
  }

  function setOut(status) {
    stopTimer();
    st.previous = st.me?.principal.id ?? st.previous;
    st.status = status;
    st.me = null;
    st.version = null;
    st.warned = false;
    api.setCsrf(null);
    emit('change');
  }

  function applyMe(me) {
    st.me = me;
    api.setCsrf(me.session?.csrf ?? null);
    st.expiresAt = me.session?.expires_at ? Date.parse(me.session.expires_at) : 0;
    st.idleMs = (me.session?.idle_timeout ?? 1800) * 1000;
    st.lastActivity = now();
    st.status = 'in';
    st.warned = false;
    schedule();
    emit('change');
  }

  async function loadMe() {
    applyMe(await api.get('/auth/me', { quiet: true }));
  }

  // the first request of a page: is there a session?  true / false; any other failure (no network) is thrown
  async function restore() {
    try {
      await loadMe();
      return true;
    } catch (e) {
      if (e.status !== 401) throw e;
      setOut('out');
      return false;
    }
  }

  // -> { enrollmentRequired }; wrong credentials throw the ApiProblem (invalid-credentials, totp-required, rate-limited)
  async function login({ user, password, totp }) {
    const r = await api.post('/auth/login', { user, password, ...(totp ? { totp } : {}) }, { quiet: true });
    api.setCsrf(r.csrf);
    await loadMe();
    channel?.postMessage({ type: 'login' });
    const samePrincipal = st.previous === null || st.previous === r.principal.id;
    st.previous = null;
    return { enrollmentRequired: Boolean(r.totp?.enrollment_required), samePrincipal };
  }

  async function loadVersion() {
    st.version = await api.get('/version');
    emit('change');
    return st.version;
  }

  async function logout(all) {
    st.leaving = true;                 // a 401 now means the session is over already: no sign-in dialog
    try {
      await api.post('/auth/logout', all ? { all: true } : {});
    } catch (e) {
      if (e.status !== 401) throw e;
    } finally {
      st.leaving = false;
    }
    st.previous = null;
    emit('logout');                    // the work that was not saved goes with the session (the drafts, F-13); a session that merely ended keeps it
    setOut('out');
    channel?.postMessage({ type: 'logout' });
  }

  // "stay signed in": one request, made because the user asked
  async function keepAlive() {
    await loadMe();
  }

  // the person chose another idle time (the answer of PUT /auth/idle-timeout): the countdown uses it at once, in this tab and (through the channel) in the others,
  // which apply it without sending it on.  -> whether it was taken (a tab that is signed out keeps nothing)
  function applyIdle(r) {
    if (st.status !== 'in' || !Number.isInteger(r?.idle_timeout) || r.idle_timeout <= 0) return false;
    if (st.warned) emit('warn-clear');
    st.idleMs = r.idle_timeout * 1000;
    st.me.session = { ...st.me.session, idle_timeout: r.idle_timeout, idle_timeout_choice: r.idle_timeout_choice ?? null, idle_timeout_max: r.idle_timeout_max };
    st.warned = false;
    schedule();
    emit('change');
    return true;
  }
  function setIdle(r) {
    if (applyIdle(r)) channel?.postMessage({ type: 'idle', idle_timeout: r.idle_timeout, idle_timeout_choice: r.idle_timeout_choice ?? null, idle_timeout_max: r.idle_timeout_max });
  }

  // TOTP was confirmed: the session was replaced, the answer has the new CSRF token
  async function replaced(r) {
    api.setCsrf(r.csrf);
    await loadMe();
  }

  // a 401 came: ask the app to sign in again; one dialog at a time
  function reauth() {
    if (!reauthHandler || st.leaving) return Promise.resolve('cancel');
    if (st.pending) return st.pending;
    st.previous = st.me?.principal.id ?? st.previous;
    st.pending = reauthHandler().then((outcome) => {
      st.pending = null;
      if (outcome === 'cancel') setOut('out');
      else emit('reauthenticated', outcome);
      return outcome;
    });
    return st.pending;
  }

  function open() {
    if (!BC) return;
    channel = new BC(CHANNEL);
    channel.onmessage = (ev) => {
      const type = ev?.data?.type;
      if (type === 'logout' && st.status !== 'out') {
        setOut('out');
        emit('other-tab-logout');
      } else if (type === 'login' && st.status !== 'in') {
        restore().then((ok) => ok && emit('other-tab-login')).catch(() => {});
      } else if (type === 'idle') {
        applyIdle(ev.data);
      }
    };
  }

  return {
    state: st,
    guards,
    open,
    restore,
    loadMe,
    login,
    logout,
    keepAlive,
    setIdle,
    replaced,
    loadVersion,
    touch,
    reauth,
    setReauthHandler(fn) { reauthHandler = fn; },
    // true when somebody has unsaved work (F-13: the change set drafts of M3 register a guard), for the warning before the page is left
    dirty: () => [...guards].some((g) => g()),
    on(ev, fn) { (listeners[ev] ??= []).push(fn); },
    close() { stopTimer(); channel?.close(); },
  };
}

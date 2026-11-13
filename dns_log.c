/* dns_log.c - the operational log of the server: BIND categories, channels and severities (BIND 9.20 `logging { }`).
 *
 * The messages come from syslog() calls turned into kdns_syslog() by dns_log.h; klog_route() below is the hook that receives them.  The
 * BIND behaviour followed here is lib/isc/log.c isc_log_doit():
 *   - a category with channels writes to those channels; a category without writes to the channels of the `default` category; with none
 *     there either, to the built-in default_syslog and default_debug (bin/named/log.c named_log_setdefaultcategory());
 *   - a channel passes a message when its severity is at least the message's (`dynamic`: when the debug level in force is; the built-in
 *     default_debug only while that level is above 0, ISC_LOG_DEBUGONLY);
 *   - a line is "<time> <category>: <severity>: <text>", each part when the channel asks for it;
 *   - syslog channels call syslog(facility | priority, ...), file channels append, stderr channels write to descriptor 2.
 *
 * Lifetime.  Everything a log call needs (the channels, their descriptors, the table that maps a category to its channels) is one
 * log_runtime_t, built from the parsed `logging` statement (log_runtime_build()) and published with log_runtime_install().  A reload builds
 * a new one; the old one is freed when the last thread that took it has put it back.  That is a two-slot scheme with a user count per slot
 * (a thread counts itself in, then checks that its slot is still the current one): no mutex, and the log calls need no RCU read section,
 * which most threads that log are not in.  The runtime does not live in server_config_t for this reason.
 *
 * The files are opened by log_open_channels() (dns_server_core.c) at start-up, before the sandbox, and again at a reload through the directory
 * descriptors the Backend already holds; nothing here opens a file for the first time inside capability mode.  Processes other than the
 * Backend (the supervisor, the routers, the broker) append to a file channel by opening the path for each line, so that they follow the
 * Backend's rotation; they never rotate. */
#include "dns_server_internal.h"
#include "dns_priv_sandbox.h"
#include "dns_log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#undef syslog   /* the real syslog() below; dns_log.h only matters to the callers */

/* ---- the category of a message: its "[Prefix]" ----
 * Every syslog() site of the server starts its text with "[Prefix] "; the table maps the prefixes to BIND's categories.  tests/run_logging_test.sh
 * checks that every prefix used in the sources is in the table.  Messages without a prefix, or with one that is not in the table, are
 * "general".  A site whose prefix gives the wrong category says so with kdns_logc(). */
static const struct { const char *prefix; int cat; } k_prefix_cat[] = {
  { "Config", LOGC_CONFIG },
  { "AXFR", LOGC_XFER_IN }, { "IXFR", LOGC_XFER_IN }, { "XFR", LOGC_XFER_IN },
  { "Notify", LOGC_NOTIFY },
  { "Update", LOGC_UPDATE },
  { "TSIG", LOGC_SECURITY }, { "Cookie", LOGC_SECURITY },
  { "Zone", LOGC_ZONELOAD }, { "ZoneLoader", LOGC_ZONELOAD }, { "Image", LOGC_ZONELOAD }, { "tinydns", LOGC_ZONELOAD },
  { "DB", LOGC_DATABASE },
  { "Network", LOGC_NETWORK },
  { "RRL", LOGC_RATE_LIMIT },
  { "dnstap", LOGC_DNSTAP },
  { "QueryLog", LOGC_GENERAL }, { "Control", LOGC_GENERAL }, { "Catalog", LOGC_GENERAL }, { "Manager", LOGC_GENERAL }, { "Backend", LOGC_GENERAL },
  { "Frontend", LOGC_GENERAL }, { "Core", LOGC_GENERAL }, { "Startup", LOGC_GENERAL }, { "Broker", LOGC_GENERAL },
  { "IPC", LOGC_GENERAL }, { "EpochRCU", LOGC_GENERAL }, { "GC", LOGC_GENERAL }, { "Logging", LOGC_GENERAL },
  { "Plugin", LOGC_GENERAL }, { "Alias", LOGC_GENERAL }, { "Forward", LOGC_GENERAL }, { "Worker", LOGC_GENERAL },
  { "Sandbox", LOGC_SECURITY },
};

int klog_category_for_message(const char *fmt) {
  if (!fmt || fmt[0] != '[') return LOGC_GENERAL;
  char word[16];
  size_t n = 0;
  for (const char *p = fmt + 1; *p && *p != ']' && *p != ' ' && n < sizeof(word) - 1; p++) word[n++] = *p;
  word[n] = '\0';
  for (size_t i = 0; i < sizeof(k_prefix_cat) / sizeof(k_prefix_cat[0]); i++)
    if (strcmp(word, k_prefix_cat[i].prefix) == 0) return k_prefix_cat[i].cat;
  return LOGC_GENERAL;
}

/* ---- priorities and severities ---- */

int klog_level_from_priority(int prio) {
  switch (prio & LOG_PRIMASK) {
    case LOG_EMERG: case LOG_ALERT: case LOG_CRIT: return LOG_LVL_CRITICAL;
    case LOG_ERR: return LOG_LVL_ERROR;
    case LOG_WARNING: return LOG_LVL_WARNING;
    case LOG_NOTICE: return LOG_LVL_NOTICE;
    case LOG_INFO: return LOG_LVL_INFO;
    default: return 1;   /* LOG_DEBUG: debug level 1 */
  }
}

/* BIND 9.20.4 lib/isc/log.c isc_log_doit(): `if (channel->level == ISC_LOG_DYNAMIC) { if (lctx->debug_level < level) continue; } else if
 * (channel->level < level) continue;`.  A `severity debug n` channel is a fixed level n: it passes up to debug n whatever the level in force
 * (bin/named/logconf.c channel_fromconf() gives a channel of the file no ISC_LOG_DEBUGONLY flag). */
bool klog_level_passes(int channel_level, int level, int debug_level) {
  return channel_level == LOG_LVL_DYNAMIC ? level <= debug_level : level <= channel_level;
}

/* The same for a channel with the level in force: and, before it, isc_log_doit()'s `if ((channel->flags & ISC_LOG_DEBUGONLY) != 0 &&
 * lctx->debug_level == 0) continue;` -- the built-in default_debug writes nothing at level 0, not even an error. */
static bool klog_channel_passes_at(const log_channel_t *ch, int level, int debug_level) {
  if (ch->debug_only && debug_level == 0) return false;
  return klog_level_passes(ch->level, level, debug_level);
}

bool klog_channel_passes(const log_channel_t *ch, int level) {
  return klog_channel_passes_at(ch, level, klog_debug_level());
}

/* A debug level as `named -d` and `rndc trace <level>` take it: decimal digits only, 0 .. 99 (BIND's range).  false: not a level. */
bool klog_parse_debug_level(const char *s, int *out) {
  if (!s || !*s) return false;
  int v = 0;
  for (const char *p = s; *p; p++) {
    if (*p < '0' || *p > '9') return false;
    v = v * 10 + (*p - '0');
    if (v > KLOG_DEBUG_LEVEL_MAX) return false;
  }
  *out = v;
  return true;
}

/* syslog_map[] */
static int klog_syslog_priority(int level) {
  if (level > 0) return LOG_DEBUG;
  switch (level) {
    case LOG_LVL_ERROR: return LOG_ERR;
    case LOG_LVL_WARNING: return LOG_WARNING;
    case LOG_LVL_NOTICE: return LOG_NOTICE;
    case LOG_LVL_INFO: return LOG_INFO;
    default: return LOG_CRIT;
  }
}

/* ---- the text of a line ---- */

/* The calendar fields of a UTC time without gmtime_r(): on FreeBSD that function loads the UTC zone file the first time it is called, which a
 * process in capability mode cannot open (the trap kills it).  Days since 1970-01-01 to a civil date: Howard Hinnant's days_from_civil, reversed. */
static void klog_utc_text(time_t t, char *out, size_t n) {
  int64_t days = (int64_t)(t / 86400), rem = (int64_t)(t % 86400);
  if (rem < 0) {
    rem += 86400;
    days--;
  }
  int64_t z = days + 719468;
  int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  int64_t doe = z - era * 146097;
  int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  int64_t mp = (5 * doy + 2) / 153;
  int64_t d = doy - (153 * mp + 2) / 5 + 1;
  int64_t m = mp < 10 ? mp + 3 : mp - 9;
  int64_t y = yoe + era * 400 + (m <= 2);
  snprintf(out, n, "%04lld-%02lld-%02lldT%02d:%02d:%02d", (long long)y, (long long)m, (long long)d, (int)(rem / 3600), (int)(rem % 3600 / 60),
           (int)(rem % 60));
}

/* "28-Oct-2026 12:34:56.789" (isc_time_formattimestamp()), "2026-10-28T12:34:56.789" (isc_time_formatISO8601Lms(): no zone), "2026-10-28T03:34:56.789Z"
 * (isc_time_formatISO8601ms()).  The seconds part is cached per thread. */
static size_t klog_time_prefix(log_time_t f, const struct timespec *ts, char *out, size_t n) {
  static _Thread_local struct { time_t sec[3]; char text[3][40]; } cache;
  if (f == LOGTIME_NONE || n < 2) {
    if (n) out[0] = '\0';
    return 0;
  }
  int k = (int)f - 1;
  if (cache.text[k][0] == '\0' || cache.sec[k] != ts->tv_sec) {
    struct tm tm;
    if (f == LOGTIME_LOCAL) {
      localtime_r(&ts->tv_sec, &tm);
      strftime(cache.text[k], sizeof(cache.text[k]), "%d-%b-%Y %H:%M:%S", &tm);
    } else if (f == LOGTIME_ISO8601) {
      localtime_r(&ts->tv_sec, &tm);
      strftime(cache.text[k], sizeof(cache.text[k]), "%Y-%m-%dT%H:%M:%S", &tm);
    } else {
      klog_utc_text(ts->tv_sec, cache.text[k], sizeof(cache.text[k]));
    }
    cache.sec[k] = ts->tv_sec;
  }
  int r = snprintf(out, n, "%s.%03ld%s", cache.text[k], (long)(ts->tv_nsec / 1000000), f == LOGTIME_ISO8601_UTC ? "Z" : "");
  return r < 0 ? 0 : (size_t)r < n ? (size_t)r : n - 1;
}

static size_t klog_level_text(int level, char *out, size_t n) {
  static const char *const names[] = { NULL, "info", "notice", "warning", "error", "critical" };
  int r;
  if (level > 0) r = snprintf(out, n, "debug %d: ", level);
  else if (level >= LOG_LVL_CRITICAL && level < 0) r = snprintf(out, n, "%s: ", names[-level]);
  else r = snprintf(out, n, "level %d: ", level);
  return r < 0 ? 0 : (size_t)r < n ? (size_t)r : n - 1;
}

/* "<time> <category>: <severity>: <message>" without the newline; returns the length */
size_t klog_build_line(const log_channel_t *ch, int cat, int level, const struct timespec *ts, const char *msg, char *out, size_t n) {
  size_t o = 0;
  if (n == 0) return 0;
  if (ch->time_fmt != LOGTIME_NONE) {
    o += klog_time_prefix(ch->time_fmt, ts, out + o, n - o);
    if (o + 1 < n) out[o++] = ' ';
  }
  if (ch->print_category && cat >= 0 && cat < LOGC_COUNT) {
    int r = snprintf(out + o, n - o, "%s: ", log_category_names[cat]);
    if (r > 0) o += (size_t)r < n - o ? (size_t)r : n - o - 1;
  }
  if (ch->print_severity) o += klog_level_text(level, out + o, n - o);
  int r = snprintf(out + o, n - o, "%s", msg);
  if (r > 0) o += (size_t)r < n - o ? (size_t)r : n - o - 1;
  out[o] = '\0';
  return o;
}

/* ---- where a line goes ---- */

static _Atomic int g_klog_role = KLOG_ROLE_BACKEND;

void klog_set_role(klog_role_t role) {
  atomic_store_explicit(&g_klog_role, (int)role, memory_order_relaxed);
}

/* A supervisor, router or broker process: the file may have been rolled by the Backend since the descriptor was inherited, so open it by name
 * for this line and never roll it here. */
static void klog_aux_append(const log_channel_t *ch, const char *line, size_t len) {
  if (!ch->file_path) return;
  /* default_debug: only appended to.  The Backend created karidns.run at the start and the start-up gave it to the run user; this process
   * (the manager is root) must not create one of its own when it has gone */
  int fd = open_via_dir_cache(ch->file_path, O_WRONLY | O_APPEND | (ch->debug_only ? 0 : O_CREAT), 0644, true);
  if (fd < 0) return;
  ssize_t w = write(fd, line, len);
  (void)w;
  close(fd);
}

static void klog_write_file(log_channel_t *ch, const char *buf, size_t len) {
  if (atomic_load_explicit(&g_klog_role, memory_order_relaxed) == KLOG_ROLE_AUX) {
    klog_aux_append(ch, buf, len);
    return;
  }
  struct timespec now;
  struct tm tm;
  clock_gettime(CLOCK_REALTIME, &now);
  localtime_r(&now.tv_sec, &tm);
  log_write_rotated(ch, buf, (int)len, &tm);
}

/* One record to one channel (its severity has been checked by the caller). */
void klog_channel_emit(log_channel_t *ch, int cat, int level, const struct timespec *ts, const char *msg) {
  switch (ch->dest) {
    case LOGDEST_NULL:
      return;
    case LOGDEST_SYSLOG: {
      char line[KLOG_MSG_MAX + 160];
      klog_build_line(ch, cat, level, ts, msg, line, sizeof(line));
      syslog(ch->syslog_facility | klog_syslog_priority(level), "%s", line);
      return;
    }
    case LOGDEST_STDERR:
    case LOGDEST_FILE: {
      char line[KLOG_MSG_MAX + 162];
      size_t len = klog_build_line(ch, cat, level, ts, msg, line, sizeof(line) - 1);
      line[len++] = '\n';
      if (ch->dest == LOGDEST_STDERR) {
        ssize_t w = write(STDERR_FILENO, line, len);
        (void)w;
      } else {
        klog_write_file(ch, line, len);
      }
      return;
    }
  }
}

/* The query log batches the lines of a drain of the rings into one write per channel. */
void klog_batch_flush(klog_batch_t *b, log_channel_t *ch) {
  if (b->len == 0) return;
  if (ch->dest == LOGDEST_STDERR) {
    ssize_t w = write(STDERR_FILENO, b->buf, b->len);
    (void)w;
  } else if (ch->dest == LOGDEST_FILE) {
    klog_write_file(ch, b->buf, b->len);
  }
  b->len = 0;
}

void klog_batch_add(klog_batch_t *b, log_channel_t *ch, int cat, int level, const struct timespec *ts, const char *msg) {
  if (ch->dest == LOGDEST_NULL) return;
  /* a syslog line is one call; a file with a size limit is written line by line, because the limit is tested for a write and a batch is
   * all or nothing (it would roll or stop a file for lines that would have fitted, and pass the limit when it does not) */
  if (ch->dest == LOGDEST_SYSLOG || (ch->dest == LOGDEST_FILE && ch->size_limit > 0)) {
    klog_channel_emit(ch, cat, level, ts, msg);
    return;
  }
  char line[KLOG_MSG_MAX + 162];
  size_t len = klog_build_line(ch, cat, level, ts, msg, line, sizeof(line) - 1);
  line[len++] = '\n';
  if (b->len + len > sizeof(b->buf)) klog_batch_flush(b, ch);
  memcpy(b->buf + b->len, line, len);
  b->len += len;
}

/* ---- the runtime: the channels and the table of categories ---- */

struct log_runtime {
  log_channel_t *channels;                          /* the channels of the file (newest first), then the built-in ones */
  log_channel_t *route[LOGC_COUNT][LOG_ROUTE_MAX];
  uint8_t nroute[LOGC_COUNT];
  int slot;
};

static log_channel_t *rt_new_channel(const char *name, log_dest_t dest, int level, log_time_t tf) {
  log_channel_t *ch = calloc(1, sizeof(*ch));
  if (!ch) return NULL;
  ch->name = strdup(name);
  if (!ch->name) {
    free(ch);
    return NULL;
  }
  ch->dest = dest;
  ch->level = level;
  ch->time_fmt = tf;
  ch->syslog_facility = LOG_DAEMON;
  ch->versions = LOG_VERSIONS_UNSET;
  ch->fd = -1;
  pthread_mutex_init(&ch->lock, NULL);
  return ch;
}

/* a channel of the file, copied (the copy owns a descriptor; the parsed one never does) */
static log_channel_t *rt_copy_channel(const log_channel_t *src) {
  log_channel_t *ch = rt_new_channel(src->name, src->dest, src->level, src->time_fmt);
  if (!ch) return NULL;
  if (src->file_path && !(ch->file_path = strdup(src->file_path))) {
    free(ch->name);
    free(ch);
    return NULL;
  }
  ch->syslog_facility = src->syslog_facility;
  ch->versions = src->versions;
  ch->size_limit = src->size_limit;
  ch->suffix_timestamp = src->suffix_timestamp;
  ch->print_category = src->print_category;
  ch->print_severity = src->print_severity;
  ch->buffered = src->buffered;
  ch->max_qps = src->max_qps;
  ch->max_qps_specified = src->max_qps_specified;
  return ch;
}

void log_channel_free(log_channel_t *ch) {
  if (ch->fd >= 0) close(ch->fd);
  free(ch->name);
  free(ch->file_path);
  pthread_mutex_destroy(&ch->lock);
  free(ch);
}

void log_runtime_free(log_runtime_t *rt) {
  if (!rt) return;
  log_channel_t *c = rt->channels;
  while (c) {
    log_channel_t *next = c->next;
    log_channel_free(c);
    c = next;
  }
  free(rt);
}

static log_channel_t *rt_find(log_runtime_t *rt, const char *name) {
  for (log_channel_t *c = rt->channels; c; c = c->next)
    if (strcmp(c->name, name) == 0) return c;
  return NULL;
}

/* lib/isc/log.c isc_logconfig_create() and bin/named/log.c named_log_setdefaultchannels(): default_syslog (daemon, info), default_stderr
 * (stderr, info, with the time), default_debug (`file "named.run"; severity dynamic;` with the time and ISC_LOG_DEBUGONLY: written only while
 * the debug level is above 0) and null.  KariDNS's default_debug is the file lc->debug_file (karidns.run in options { directory }), and a null
 * channel without a directory.  *dbg: the built-in default_debug. */
static bool rt_add_builtins(const logging_config_t *lc, log_channel_t **tail, log_channel_t **dbg) {
  const char *df = lc ? lc->debug_file : NULL;
  log_channel_t *b[4] = {
    rt_new_channel("default_syslog", LOGDEST_SYSLOG, LOG_LVL_INFO, LOGTIME_NONE),
    rt_new_channel("default_stderr", LOGDEST_STDERR, LOG_LVL_INFO, LOGTIME_LOCAL),
    rt_new_channel("default_debug", df ? LOGDEST_FILE : LOGDEST_NULL, LOG_LVL_DYNAMIC, LOGTIME_LOCAL),
    rt_new_channel("null", LOGDEST_NULL, LOG_LVL_DYNAMIC, LOGTIME_NONE),
  };
  bool ok = true;
  *dbg = b[2];
  if (b[2]) {
    b[2]->debug_only = true;
    if (df && !(b[2]->file_path = strdup(df))) ok = false;
  }
  for (int i = 0; i < 4; i++) {
    if (!b[i]) { ok = false; continue; }
    *tail = b[i];
    tail = &b[i]->next;
  }
  return ok;
}

log_runtime_t *log_runtime_build(const logging_config_t *lc, bool hand_off, logrt_status_t *status) {
  logrt_status_t dummy;
  if (!status) status = &dummy;
  *status = LOGRT_ERROR;
  log_runtime_t *rt = calloc(1, sizeof(*rt));
  if (!rt) return NULL;
  log_channel_t **tail = &rt->channels;
  for (const log_channel_t *src = lc ? lc->channels : NULL; src; src = src->next) {
    log_channel_t *c = rt_copy_channel(src);
    if (!c) goto fail;
    *tail = c;
    tail = &c->next;
  }
  log_channel_t *builtin_dbg = NULL;
  if (!rt_add_builtins(lc, tail, &builtin_dbg)) goto fail;
  /* the table: a category's own channels, else the `default` category's, else default_syslog and default_debug (ARM 8.2.10: "category default
   * { default_syslog; default_debug; };"; a channel of the file with one of these names stands in for the built-in one, as in BIND) */
  bool dbg_used = false;
  for (int cat = 0; cat < LOGC_COUNT; cat++) {
    const log_cat_cfg_t *src = lc && lc->cat[cat].n > 0 ? &lc->cat[cat] : lc && lc->cat[LOGC_DEFAULT].n > 0 ? &lc->cat[LOGC_DEFAULT] : NULL;
    if (!src) {
      rt->route[cat][rt->nroute[cat]++] = rt_find(rt, "default_syslog");
      rt->route[cat][rt->nroute[cat]++] = rt_find(rt, "default_debug");
    } else {
      for (int i = 0; i < src->n; i++) {
        log_channel_t *c = rt_find(rt, src->name[i]);
        if (c) rt->route[cat][rt->nroute[cat]++] = c;
      }
    }
    for (int i = 0; i < rt->nroute[cat]; i++) dbg_used |= rt->route[cat][i] == builtin_dbg;
  }
  /* karidns.run is created only when some category writes to the built-in default_debug (BIND opens named.run when it first writes to it;
   * the Backend cannot create a file after the start, so it is opened here, before the sandbox, and at a reload through the directory fd) */
  if (!dbg_used) builtin_dbg->dest = LOGDEST_NULL;
  int rc = log_open_channels(rt->channels, hand_off);
  if (rc != 0) {
    *status = rc > 0 ? LOGRT_RESTART : LOGRT_ERROR;
    log_runtime_free(rt);
    return NULL;
  }
  *status = LOGRT_OK;
  return rt;
fail:
  log_runtime_free(rt);
  return NULL;
}

/* ---- publishing: two slots, a user count for each ---- */

static _Atomic(log_runtime_t *) g_rt_slot[2];
static _Atomic uint32_t g_rt_users[2];
static _Atomic int g_rt_cur = -1;

log_runtime_t *log_runtime_acquire(void) {
  for (;;) {
    int s = atomic_load(&g_rt_cur);
    if (s < 0) return NULL;
    atomic_fetch_add(&g_rt_users[s], 1);
    if (atomic_load(&g_rt_cur) == s) return atomic_load(&g_rt_slot[s]);
    atomic_fetch_sub(&g_rt_users[s], 1);
  }
}

void log_runtime_release(log_runtime_t *rt) {
  if (rt) atomic_fetch_sub(&g_rt_users[rt->slot], 1);
}

/* a slot's users, waited for up to two seconds */
static bool rt_drain(int slot) {
  for (int i = 0; i < 2000; i++) {
    if (atomic_load(&g_rt_users[slot]) == 0) return true;
    usleep(1000);
  }
  return false;
}

static void klog_route(int cat, int prio, const char *fmt, va_list ap, int saved_errno);

/* set while this thread writes a record: log calls made meanwhile go to syslog() alone (see klog_route()) */
static _Thread_local bool t_inside;

bool klog_guard_enter(void) {
  bool prev = t_inside;
  t_inside = true;
  return prev;
}

void klog_guard_leave(bool prev) {
  t_inside = prev;
}

static uint32_t rt_level_mask(const log_runtime_t *rt, int cat, int debug_level);
static void klog_emit_level(int cat, int level, const char *msg);

/* bumped by every install, after the new runtime is current (klog_refresh_masks()) */
static _Atomic uint32_t g_rt_gen;

/* g_logev_mask[] from the installed runtime and the debug level in force: what log_runtime_install() and klog_set_debug_level() both need.  An
 * install (a reload, on the thread that runs it) and a level change (the control thread) can overlap; each stores its masks and then looks
 * again: when the runtime or the level changed meanwhile, its masks may be the stale ones and it computes them again.  The last writer has
 * therefore always seen the runtime and the level in force.  No lock, nothing allocated; a worker that reads a mask in between sees the old or
 * the new value of that category, either of which was right a moment ago. */
static void klog_refresh_masks(void) {
  for (;;) {
    uint32_t gen = atomic_load(&g_rt_gen);
    int dl = klog_debug_level();
    log_runtime_t *rt = log_runtime_acquire();
    if (!rt) return;
    for (int c = 0; c < LOGC_COUNT; c++) logev_set_mask(c, rt_level_mask(rt, c, dl));   /* (the event messages of dns_log.h look at it before they build anything) */
    log_runtime_release(rt);
    if (atomic_load(&g_rt_gen) == gen && klog_debug_level() == dl) return;
  }
}

/* `named -d`, `rndc trace` / `notrace` (BIND bin/named/server.c named_server_setdebuglevel(): isc_log_setdebuglevel()).  Opens nothing: a
 * channel that is to receive the output exists already (Rule 2). */
void klog_set_debug_level(int level) {
  if (level < 0) level = 0;
  if (level > KLOG_DEBUG_LEVEL_MAX) level = KLOG_DEBUG_LEVEL_MAX;
  atomic_store_explicit(&g_klog_debug_level, level, memory_order_relaxed);
  klog_refresh_masks();
}

bool log_runtime_install(log_runtime_t *nrt) {
  int old = atomic_load(&g_rt_cur);
  int ns = old < 0 ? 0 : 1 - old;
  log_runtime_t *stale = atomic_load(&g_rt_slot[ns]);   /* a runtime retired by the install before, whose last user was slow */
  if (stale) {
    if (!rt_drain(ns)) return false;
    atomic_store(&g_rt_slot[ns], NULL);
    log_runtime_free(stale);
  }
  nrt->slot = ns;
  atomic_store(&g_rt_slot[ns], nrt);
  atomic_store(&g_rt_cur, ns);
  atomic_fetch_add(&g_rt_gen, 1);
  klog_refresh_masks();
  klog_set_level_hook(klog_emit_level);
  klog_set_hook(klog_route);
  if (old >= 0) {
    log_runtime_t *o = atomic_load(&g_rt_slot[old]);
    if (rt_drain(old)) {
      atomic_store(&g_rt_slot[old], NULL);
      log_runtime_free(o);
    }   /* else the next install frees it */
  }
  return true;
}

/* the channels of the installed runtime (start-up only: the hand-off of the files and the fchown right) */
log_channel_t *log_runtime_current_channels(void) {
  int s = atomic_load(&g_rt_cur);
  log_runtime_t *rt = s < 0 ? NULL : atomic_load(&g_rt_slot[s]);
  return rt ? rt->channels : NULL;
}

log_channel_t *const *log_runtime_route(const log_runtime_t *rt, int cat, int *n) {
  *n = rt->nroute[cat];
  return rt->route[cat];
}

/* One record to the channels of its category. */
void klog_record(log_runtime_t *rt, int cat, int level, const struct timespec *ts, const char *msg) {
  const int dl = klog_debug_level();
  for (int i = 0; i < rt->nroute[cat]; i++) {
    log_channel_t *ch = rt->route[cat][i];
    if (klog_channel_passes_at(ch, level, dl)) klog_channel_emit(ch, cat, level, ts, msg);
  }
}

/* The levels a category passes at that debug level (the bits of g_logev_mask: dns_log.h), for the channels that write somewhere.  The mask
 * stops at debug 10 (LOGEV_LEVEL_MAX): a level above is never asked for (logev_wanted() says no). */
static uint32_t rt_level_mask(const log_runtime_t *rt, int cat, int debug_level) {
  uint32_t mask = 0;
  for (int i = 0; i < rt->nroute[cat]; i++) {
    const log_channel_t *ch = rt->route[cat][i];
    if (ch->dest == LOGDEST_NULL) continue;
    for (int l = LOGEV_LEVEL_MIN; l <= LOGEV_LEVEL_MAX; l++)
      if (klog_channel_passes_at(ch, l, debug_level)) mask |= LOGEV_BIT(l);
  }
  return mask;
}

static void klog_emit_level(int cat, int level, const char *msg);

/* The text of a record is cut at the end of the first control character that is not a tab: replace them.  A message can carry text that came
 * from the network (a key or zone name); in a file it must not be able to start a line of its own */
static void klog_sanitize(char *msg) {
  for (char *p = msg; *p; p++)
    if (((unsigned char)*p < 0x20 && *p != '\t') || *p == 0x7f) *p = '?';
}

/* The hook of kdns_syslog() / kdns_logc().  A message logged while a message is being written (a rotation that fails, say) goes to syslog()
 * directly, so that a log call cannot wait for the channel lock its own thread holds. */
static void klog_route(int cat, int prio, const char *fmt, va_list ap, int saved_errno) {
  const int level = klog_level_from_priority(prio);
  if (cat < 0 || cat >= LOGC_COUNT) cat = klog_category_for_message(fmt);
  /* a debug message that no channel wants is not formatted (the mask of the category says so: one atomic load).  Only debug: the masks of a
   * runtime that is being installed lag it by a moment, and an error must not be lost in that moment */
  if (level > 0 && !t_inside && !logev_wanted(cat, level)) return;
  char msg[KLOG_MSG_MAX];
  klog_vformat(msg, sizeof(msg), fmt, ap, saved_errno);
  klog_sanitize(msg);
  log_runtime_t *rt = t_inside ? NULL : log_runtime_acquire();
  if (!rt) {
    syslog(prio, "%s", msg);
    return;
  }
  /* A thread that is cancelled (the unit tests do that to the worker threads they start) must not be stopped while it holds the runtime or
   * a channel lock: the one would never be put back, the other would block every later writer.  Nothing in the server cancels threads. */
  int cancel_state;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
  bool guard = klog_guard_enter();
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  klog_record(rt, cat, level, &ts, msg);
  klog_guard_leave(guard);
  log_runtime_release(rt);
  pthread_setcancelstate(cancel_state, NULL);
}

/* One finished line of an event (dns_log.h logev_*) to the channels of its category, at the level the caller gives (up to debug 10, which a
 * syslog priority cannot say).  The same guards as klog_route(): no routing while this thread writes a record, no cancellation while the runtime
 * is held.  A thread that is inside a write has no way to report this one: it is dropped (events are never worth a deadlock). */
static void klog_emit_level(int cat, int level, const char *msg) {
  char text[KLOG_MSG_MAX];
  snprintf(text, sizeof(text), "%s", msg);
  klog_sanitize(text);
  if (cat < 0 || cat >= LOGC_COUNT) cat = LOGC_GENERAL;
  log_runtime_t *rt = t_inside ? NULL : log_runtime_acquire();
  if (!rt) return;
  int cancel_state;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
  bool guard = klog_guard_enter();
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  klog_record(rt, cat, level, &ts, text);
  klog_guard_leave(guard);
  log_runtime_release(rt);
  pthread_setcancelstate(cancel_state, NULL);
}

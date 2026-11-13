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
 * descriptors the Backend already holds; nothing here opens a file for the first time inside capability mode (the built-in default_debug,
 * karidns.run, is opened at the start only, with no directory descriptor kept, and a reload takes its descriptor over).  Processes other than
 * the Backend (the supervisor, the routers, the broker) append to a file channel by opening the path for each line, so that they follow the
 * Backend's rotation; they never rotate, and (0.7 M2) never create one.  They were forked with the start-up runtime and level; after a karictl
 * trace / notrace or a reload the Backend sends them the level and its runtime (dns_log_state.h, klog_state_encode() / klog_state_apply()),
 * which they take within the limits of klog_aux_init(). */
#include "dns_server_internal.h"
#include "dns_priv_sandbox.h"
#include "dns_log.h"
#include "dns_log_state.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/capsicum.h>
#include <sys/stat.h>

_Static_assert(KLS_ROUTE_MAX == LOG_ROUTE_MAX, "the KLS1 table has the runtime's width");
_Static_assert(LOGDEST_FILE == 0 && LOGDEST_SYSLOG == 1 && LOGDEST_STDERR == 2 && LOGDEST_NULL == 3, "KLS1 destination numbers");
_Static_assert(LOGTIME_NONE == 0 && LOGTIME_ISO8601_UTC == 3, "KLS1 print-time numbers");
_Static_assert(KLS_CHANNELS_MAX >= LOGC_COUNT * LOG_ROUTE_MAX, "every channel of a table fits a KLS1 record");

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

/* ---- the processes that only append (KLOG_ROLE_AUX): what they keep of the start (klog_aux_init(), before the forks) ----
 * The Backend sends them its channels (klog_state_apply()), and a Backend that has been taken over can send anything.  So what such a process
 * does with a record is held to what the start-up configuration (never the Backend) allowed:
 *   g_klog_aux_owner      the run user: the one owner of a file it appends to (klog_aux_append())
 *   g_klog_aux_dbg_*      the start's descriptor of the built-in default_debug (karidns.run) and its path: the one way to that file
 *   g_klog_floor          the start-up routing (no descriptor): the floor of the warnings and errors (klog_record())
 *   g_klog_aux_facilities the syslog facilities the start-up channels used (bit facility >> 3); ~0: no limit (klog_aux_init() not called) */
static uid_t g_klog_aux_owner = (uid_t)-1;
static int g_klog_aux_dbg_fd = -1;
static char *g_klog_aux_dbg_path;
static log_runtime_t *g_klog_floor;
static uint32_t g_klog_aux_facilities = ~0u;

/* A supervisor, router or broker process: the file may have been rolled by the Backend since the descriptor was inherited, so open it by name
 * for this line and never roll it here.  0.7 M2: only appended to, never created.  The Backend created every file of its runtime (at the
 * start, or at a reload as the run user) and owns the rotation; the manager is root and must not recreate a file that has gone (a root-owned
 * file the run-user Backend could neither append to nor roll).  Since the channels can come from a taken-over Backend (dns_log_state.h), a
 * line goes only where the Backend could write itself:
 *   - karidns.run (the start's path of the built-in default_debug, in options { directory }) through the descriptor the start opened: that
 *     directory is never opened here, it holds the configuration, the zone files and the loader's state;
 *   - any other file only in a directory that is in this process's cache as writable (open_via_dir_cache_existing()).  Those entries are the
 *     directories of the start-up's file channels (log_open_channels() before the forks; nothing in this role adds one), which the Backend
 *     holds writable as well; a reload that names a new directory is "restart needed" in the Backend, so no record can name one legitimately;
 *   - only a plain file, not a symbolic link (O_NOFOLLOW), with one link, owned by the run user.  The manager is root, so a file of its own
 *     user (a root-owned karidns.conf, a zone file, /var/log/auth.log) is never written; a FIFO (O_NONBLOCK: open() does not wait for a reader)
 *     or a hard link the Backend put there neither.  Without a run user the whole server runs as one user (a start as root needs `user`):
 *     there is no boundary to keep, the owner is this process's own user.
 * Nothing the record names is created. */
static void klog_aux_append(const log_channel_t *ch, const char *line, size_t len) {
  if (!ch->file_path) return;
  if (g_klog_aux_dbg_path && strcmp(ch->file_path, g_klog_aux_dbg_path) == 0) {
    if (g_klog_aux_dbg_fd >= 0) {
      ssize_t w = write(g_klog_aux_dbg_fd, line, len);
      (void)w;
    }
    return;
  }
  int fd = open_via_dir_cache_existing(ch->file_path, O_WRONLY | O_APPEND | O_NONBLOCK | O_NOFOLLOW);
  if (fd < 0) return;
  const uid_t owner = g_klog_aux_owner != (uid_t)-1 ? g_klog_aux_owner : geteuid();
  struct stat st;
  if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 && st.st_uid == owner) {
    ssize_t w = write(fd, line, len);
    (void)w;
  }
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
      klog_syslog_text(ch->syslog_facility | klog_syslog_priority(level), line);
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
   * the Backend cannot create a file after the start, so it is opened here, before the sandbox; a reload in the sandbox takes the descriptor
   * of the runtime in use: log_open_channels(), dns_server_core.c log_open_debug_file()) */
  if (!dbg_used) {
    builtin_dbg->dest = LOGDEST_NULL;
    /* in the sandbox the descriptor is still kept (nothing is written to it), so that a later reload that writes to default_debug again has it */
    if (builtin_dbg->file_path && atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire))
      builtin_dbg->fd = log_runtime_dup_debug_fd(builtin_dbg->file_path);
  }
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
static bool klog_aux_floor_active(const log_runtime_t *rt);

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
    /* (the event messages of dns_log.h look at it before they build anything; the warnings and worse of the floor are wanted as well) */
    const bool floor = klog_aux_floor_active(rt);
    for (int c = 0; c < LOGC_COUNT; c++)
      logev_set_mask(c, rt_level_mask(rt, c, dl) | (floor ? rt_level_mask(g_klog_floor, c, dl) & (LOGEV_BIT(LOG_LVL_WARNING + 1) - 1u) : 0u));
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

/* the built-in default_debug of rt when it has its file open (karidns.run; also a null one that keeps the descriptor: log_runtime_build()),
 * else NULL */
static log_channel_t *rt_open_builtin_debug(log_runtime_t *rt) {
  for (log_channel_t *c = rt ? rt->channels : NULL; c; c = c->next)
    if (c->debug_only && c->fd >= 0 && c->file_path) return c;
  return NULL;
}

int log_runtime_dup_debug_fd(const char *path) {
  int fd = -1;
  log_runtime_t *rt = log_runtime_acquire();
  log_channel_t *c = rt_open_builtin_debug(rt);
  if (c && path && strcmp(c->file_path, path) == 0) fd = fcntl(c->fd, F_DUPFD_CLOEXEC, 0);
  log_runtime_release(rt);
  return fd;
}

log_channel_t *const *log_runtime_route(const log_runtime_t *rt, int cat, int *n) {
  *n = rt->nroute[cat];
  return rt->route[cat];
}

/* ---- 0.7 M2: the level and the runtime in the other processes (dns_log_state.h) ---- */

/* The KLS1 record of the level in force and the installed runtime (the channels some category writes to, in the order the table first names
 * them).  A runtime whose record would not fit (or has a path the record cannot carry) goes as the level alone, and *spec_dropped says so: the
 * other processes then keep the channels they have.  Returns the length (0: nothing could be encoded). */
size_t klog_state_encode(uint8_t *buf, size_t cap, bool *spec_dropped) {
  kls_state_t s;
  memset(&s, 0, sizeof(s));
  s.debug_level = klog_debug_level();
  if (spec_dropped) *spec_dropped = false;
  log_runtime_t *rt = log_runtime_acquire();
  if (rt) {
    const log_channel_t *seen[KLS_CHANNELS_MAX];
    s.has_spec = true;
    for (int cat = 0; cat < LOGC_COUNT; cat++) {
      for (int i = 0; i < rt->nroute[cat]; i++) {
        const log_channel_t *ch = rt->route[cat][i];
        uint16_t k = 0;
        while (k < s.nch && seen[k] != ch) k++;
        if (k == s.nch) {
          kls_channel_t *c = &s.ch[s.nch];
          seen[s.nch++] = ch;
          c->dest = (uint8_t)ch->dest;
          c->time_fmt = (uint8_t)ch->time_fmt;
          c->flags = (ch->print_category ? KLS_CF_CATEGORY : 0) | (ch->print_severity ? KLS_CF_SEVERITY : 0) | (ch->debug_only ? KLS_CF_DEBUG_ONLY : 0);
          c->level = (int8_t)ch->level;
          c->facility = (uint16_t)ch->syslog_facility;
          if (ch->dest == LOGDEST_FILE) {
            size_t pl = ch->file_path ? strlen(ch->file_path) : 0;
            c->path = ch->file_path;
            c->path_len = (uint16_t)(pl > KLS_PATH_MAX ? KLS_PATH_MAX + 1 : pl);   /* (too long: kls_encode() refuses it) */
          }
        }
        s.route[cat][s.nroute[cat]++] = k;
      }
    }
  }
  size_t n = kls_encode(&s, buf, cap);
  if (n == 0 && s.has_spec) {
    s.has_spec = false;
    s.nch = 0;
    memset(s.nroute, 0, sizeof(s.nroute));
    n = kls_encode(&s, buf, cap);
    if (spec_dropped) *spec_dropped = true;
  }
  log_runtime_release(rt);
  return n;
}

/* The runtime of a record, for a process that only appends (KLOG_ROLE_AUX): no descriptor is opened, a file is opened by name for each line
 * (klog_aux_append()).  NULL: out of memory. */
static log_runtime_t *klog_runtime_from_state(const kls_state_t *s) {
  log_runtime_t *rt = calloc(1, sizeof(*rt));
  if (!rt) return NULL;
  log_channel_t *chs[KLS_CHANNELS_MAX];
  log_channel_t **tail = &rt->channels;
  for (uint16_t i = 0; i < s->nch; i++) {
    const kls_channel_t *c = &s->ch[i];
    log_channel_t *ch = rt_new_channel("(from the Backend)", (log_dest_t)c->dest, c->level, (log_time_t)c->time_fmt);
    if (!ch) goto fail;
    *tail = ch;
    tail = &ch->next;
    chs[i] = ch;
    /* a facility the start-up channels did not use is the default one: a record cannot put these lines into, say, the auth log */
    ch->syslog_facility = (g_klog_aux_facilities >> (c->facility >> 3)) & 1u ? c->facility : LOG_DAEMON;
    ch->print_category = (c->flags & KLS_CF_CATEGORY) != 0;
    ch->print_severity = (c->flags & KLS_CF_SEVERITY) != 0;
    ch->debug_only = (c->flags & KLS_CF_DEBUG_ONLY) != 0;
    if (c->path_len && !(ch->file_path = strndup(c->path, c->path_len))) goto fail;
  }
  for (int cat = 0; cat < LOGC_COUNT; cat++) {
    for (int k = 0; k < s->nroute[cat]; k++) rt->route[cat][k] = chs[s->route[cat][k]];
    rt->nroute[cat] = s->nroute[cat];
  }
  return rt;
fail:
  log_runtime_free(rt);
  return NULL;
}

/* 0.7: in the manager after the start-up runtime is installed, before the broker, the Backend and the routers are forked (they inherit what is
 * kept here): the run user (-1: none, the server runs as one user), the start-up routing as the floor, its syslog facilities, and a duplicate of
 * the start's karidns.run descriptor (write only).  The floor is what the start-up configuration routes, through a record of it (no descriptor;
 * a configuration that does not fit one: default_syslog for every category).  Called again, it replaces what it kept (the unit tests). */
void klog_aux_init(uid_t run_user) {
  static uint8_t rec[KLS_MAX];
  static kls_state_t s;
  g_klog_aux_owner = run_user;
  bool dropped = false;
  size_t n = klog_state_encode(rec, sizeof(rec), &dropped);
  if (n == 0 || dropped || kls_parse(rec, n, &s) != NULL || !s.has_spec) {
    memset(&s, 0, sizeof(s));
    s.has_spec = true;
    s.nch = 1;
    s.ch[0] = (kls_channel_t){ LOGDEST_SYSLOG, LOGTIME_NONE, 0, LOG_LVL_INFO, LOG_DAEMON, 0, NULL };
    for (int cat = 0; cat < LOGC_COUNT; cat++) {
      s.nroute[cat] = 1;
      s.route[cat][0] = 0;
    }
  }
  uint32_t fac = 0;
  for (uint16_t i = 0; i < s.nch; i++)
    if (s.ch[i].dest == LOGDEST_SYSLOG) fac |= 1u << (s.ch[i].facility >> 3);
  g_klog_aux_facilities = ~0u;   /* the floor keeps the facilities of the start */
  log_runtime_t *floor_rt = klog_runtime_from_state(&s);
  g_klog_aux_facilities = fac;
  if (floor_rt) {
    log_runtime_free(g_klog_floor);
    g_klog_floor = floor_rt;
  }
  if (g_klog_aux_dbg_fd >= 0) close(g_klog_aux_dbg_fd);
  free(g_klog_aux_dbg_path);
  g_klog_aux_dbg_fd = -1;
  g_klog_aux_dbg_path = NULL;
  log_runtime_t *rt = log_runtime_acquire();
  log_channel_t *dbg = rt_open_builtin_debug(rt);
  if (dbg && (g_klog_aux_dbg_path = strdup(dbg->file_path)) != NULL) {
    g_klog_aux_dbg_fd = fcntl(dbg->fd, F_DUPFD_CLOEXEC, 0);
    cap_rights_t rights;
    cap_rights_init(&rights, CAP_WRITE, CAP_SEEK, CAP_FSTAT);
    if (g_klog_aux_dbg_fd >= 0 && cap_rights_limit(g_klog_aux_dbg_fd, &rights) != 0 && errno != ENOSYS) {
      close(g_klog_aux_dbg_fd);
      g_klog_aux_dbg_fd = -1;
    }
  }
  log_runtime_release(rt);
}

/* syslog(3) itself (through klog_syslog_text(): KARIDNS_NOSYSLOG), not the routing: the messages of klog_state_apply() */
static void klog_syslogf(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void klog_syslogf(int prio, const char *fmt, ...) {
  char msg[KLOG_MSG_MAX];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  klog_syslog_text(prio, msg);
}

/* A record from the Backend in a process that only appends (the manager, a router, the broker): the level, and the channels when the record
 * has them.  `who` names this process in the messages ("Manager", "Frontend 0", "Broker").  The record is hostile input (kls_parse()), and
 * what it names is held to the start-up configuration (klog_aux_init()): a file only as klog_aux_append() takes one (a run-user file the Backend
 * could write itself), a syslog facility only one the start used, and the warnings and errors still reach the start's channels (klog_record()).
 * false: refused (logged, at most 16 times). */
bool klog_state_apply(const uint8_t *buf, size_t len, const char *who) {
  static unsigned long refused;
  kls_state_t s;
  const char *why = kls_parse(buf, len, &s);
  if (why) {
    if (refused++ < 16) klog_syslogf(LOG_ERR, "[Logging] %s: a logging state from the Backend was refused: %s", who, why);
    return false;
  }
  bool taken = false;
  if (s.has_spec) {
    log_runtime_t *rt = klog_runtime_from_state(&s);
    if (rt && log_runtime_install(rt)) {
      taken = true;
    } else {
      if (rt) log_runtime_free(rt);
      klog_syslogf(LOG_ERR, "[Logging] %s: cannot take the logging configuration of the Backend (out of memory, or the one before is still in use); "
                            "keeping the one in use", who);
    }
  }
  klog_set_debug_level(s.debug_level);
  if (taken)
    logev_post(LOGC_GENERAL, 1, NULL, 0, "[Logging] %s: debug level %d, logging configuration of the Backend taken (%u channel(s))", who,
               s.debug_level, (unsigned)s.nch);
  else
    logev_post(LOGC_GENERAL, 1, NULL, 0, "[Logging] %s: debug level %d", who, s.debug_level);
  return true;
}

/* two channels that write to the same place: the same syslog facility, the same file, standard error */
static bool klog_same_destination(const log_channel_t *a, const log_channel_t *b) {
  if (a->dest != b->dest) return false;
  if (a->dest == LOGDEST_SYSLOG) return a->syslog_facility == b->syslog_facility;
  if (a->dest == LOGDEST_FILE) return a->file_path && b->file_path && strcmp(a->file_path, b->file_path) == 0;
  return a->dest == LOGDEST_STDERR;
}

static bool klog_aux_floor_active(const log_runtime_t *rt) {
  return g_klog_floor && rt != g_klog_floor && atomic_load_explicit(&g_klog_role, memory_order_relaxed) == KLOG_ROLE_AUX;
}

/* One record to the channels of its category.  The floor (a process that only appends, after klog_aux_init()): a warning, an error or worse
 * also goes to each start-up channel of the category that takes it, unless a channel of the runtime in use has just written it to the same
 * place.  A record from the Backend can add channels and move the other lines, but cannot silence these: they are the ones that would show
 * a taken-over Backend (a refused plugin request, a loader that fails). */
void klog_record(log_runtime_t *rt, int cat, int level, const struct timespec *ts, const char *msg) {
  const int dl = klog_debug_level();
  const log_channel_t *done[LOG_ROUTE_MAX];
  int ndone = 0;
  for (int i = 0; i < rt->nroute[cat]; i++) {
    log_channel_t *ch = rt->route[cat][i];
    if (klog_channel_passes_at(ch, level, dl)) {
      klog_channel_emit(ch, cat, level, ts, msg);
      if (ndone < LOG_ROUTE_MAX) done[ndone++] = ch;
    }
  }
  if (level > LOG_LVL_WARNING || !klog_aux_floor_active(rt)) return;
  for (int i = 0; i < g_klog_floor->nroute[cat]; i++) {
    log_channel_t *f = g_klog_floor->route[cat][i];
    if (f->dest == LOGDEST_NULL || !klog_channel_passes_at(f, level, dl)) continue;
    bool written = false;
    for (int k = 0; k < ndone && !written; k++) written = klog_same_destination(done[k], f);
    if (!written) klog_channel_emit(f, cat, level, ts, msg);
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
    klog_syslog_text(prio, msg);
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

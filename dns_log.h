#ifndef DNS_LOG_H
#define DNS_LOG_H

/* Operational logging of the server (BIND 9.20 `logging { channel ...; category ...; }`).
 *
 * Every message of the server goes through syslog(LOG_xxx, "[Prefix] text ...").  Rather than touching the ~500 call sites, a .c file
 * includes this header (instead of <syslog.h>), which turns syslog() into kdns_syslog(): the message is formatted once and handed to
 * the routing hook the server installs at start-up (dns_log.c), which picks the BIND category from the "[Prefix]" of the message
 * (a table in dns_log.c; a site that needs another category uses kdns_logc()).  Without a hook (karicheck, dag, the unit tests) the
 * message goes to syslog() unchanged, so those programs behave as before.
 *
 * Only .c files include this header.  Headers keep <syslog.h>: a unit test that defines its own syslog() stub would otherwise have its
 * definition renamed; it still takes effect, because kdns_syslog() ends in a call to the (stubbed) syslog().
 *
 * No allocation: the message is formatted into a stack buffer of KLOG_MSG_MAX bytes (longer text is cut).  The syslog() macro is
 * not defined on Windows (the shared sources have their own no-op there). */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <syslog.h>
#include "dns_logcat.h"

#define KLOG_MSG_MAX 1024

/* dns_utils.c: the hook, the formatter and the two entry points */
typedef void (*klog_hook_t)(int cat, int prio, const char *fmt, va_list ap, int saved_errno);
void klog_set_hook(klog_hook_t hook);
/* Formats like vsnprintf(), plus syslog()'s %m (strerror(saved_errno)); always NUL-terminated.  Returns the length written. */
size_t klog_vformat(char *buf, size_t n, const char *fmt, va_list ap, int saved_errno);
void kdns_syslog(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void kdns_logc(int cat, int prio, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
/* The one place that hands a finished line to syslog(3) (dns_utils.c, dns_log.c).  After klog_nosyslog_from_env() found KARIDNS_NOSYSLOG=1 (a test
 * hook, docs/karidns.md ENVIRONMENT) the line goes to standard error only, as "<ident> <pid> - - <text>": the copy openlog()'s LOG_PERROR prints
 * on FreeBSD, so a foreground server's stderr is unchanged and the system log gets nothing. */
void klog_syslog_text(int prio, const char *msg);
bool klog_nosyslog_from_env(const char *ident);

/* ---- event messages (batch 14: update-security, update, xfer-out, query-errors) ----
 *
 * Messages that arise in a worker thread of the Backend, or that an attacker can make happen at will (a refused UPDATE or transfer, a malformed
 * query), must not cost a write() on the query path nor flood the log.  logev_post() is the one entry point for them:
 *   - logev_wanted(cat, level): one atomic load.  The mask of a category is computed when the logging runtime is installed (dns_log.c): it has
 *     a bit for every level that some non-null channel of the category passes.  Without a configured sink for the level nothing else is done,
 *     so a caller checks it before it builds anything for the message.
 *   - a rate limit per category and second (logev_admit_at()); the messages over it are counted and reported once, "N messages suppressed".
 *     The lines at critical .. info and the debug lines (level > 0) have a budget each, of the same limit, so a debug line never takes the
 *     place of a notice or an error (a `severity debug n` channel receives debug lines at debug level 0 too).
 *   - a worker thread (logev_set_thread_sink()) writes a fixed-size record into its ring (the query log ring of dns_server_core.c); the query
 *     logger thread formats it and routes it to the channels.  Any other thread formats the line itself and routes it at once.
 * The text is formatted into LOGEV_MSG_MAX bytes (cut); a name that came from the network must be escaped by the caller (escape_qname_for_log()).
 * The client is the address text and the port (0: unknown); the line is "client <ip>#<port>: <text>". */
#define LOGEV_MSG_MAX 256
#define LOGEV_LEVEL_MIN LOG_LVL_CRITICAL      /* -5 */
#define LOGEV_LEVEL_MAX 10                    /* debug 10 */

extern _Atomic uint32_t g_logev_mask[LOGC_COUNT];
static inline bool logev_wanted(int cat, int level) {
  if (cat < 0 || cat >= LOGC_COUNT || level < LOGEV_LEVEL_MIN || level > LOGEV_LEVEL_MAX) return false;
  return (atomic_load_explicit(&g_logev_mask[cat], memory_order_relaxed) >> (level - LOGEV_LEVEL_MIN)) & 1u;
}
void logev_set_mask(int cat, uint32_t mask);
/* the bit of level in a mask */
#define LOGEV_BIT(level) (1u << ((level) - LOGEV_LEVEL_MIN))

/* ---- the debug level in force (0.7: BIND's `named -d`, `rndc trace` / `notrace`) ----
 * One value for the process, 0 .. 99 (BIND's range).  It is a switch, not a data structure: read relaxed.  A `severity dynamic` channel passes
 * the messages up to it, and the built-in default_debug writes only while it is above 0 (dns_log.c klog_channel_passes()).  It is changed only
 * through klog_set_debug_level() (dns_log.c), which also recomputes g_logev_mask: the event path stays one atomic load. */
#define KLOG_DEBUG_LEVEL_MAX 99
extern _Atomic int g_klog_debug_level;
static inline int klog_debug_level(void) {
  return atomic_load_explicit(&g_klog_debug_level, memory_order_relaxed);
}

typedef void (*logev_sink_t)(void *ctx, int cat, int level, const char *client_ip, int client_port, const char *msg);
void logev_set_thread_sink(logev_sink_t fn, void *ctx);
/* 0.7 review M-3: a thread with a sink is on the query path (the workers, the async I/O pool): its general log lines (kdns_syslog()) go to the sink
 * too, never to a write() of its own.  logev_thread_sink_post() hands one finished line to it (false: this thread has none). */
bool logev_thread_has_sink(void);
bool logev_thread_sink_post(int cat, int level, const char *msg);

/* 0.7 review M-3: the rate limit of the general path (kdns_syslog() / kdns_logc(), dns_log.c klog_route()) on the query path (a thread with a sink:
 * a client can make those lines happen at will), per call site (the format string) and second: KLOG_SITE_RATE_QUERY lines, LOGEV_DEBUG_RATE while
 * the debug level is above 0.  The other threads are not limited (dns_log.c says why).  The lines over it are counted and said once, "[Logging] N
 * line(s) like "..." suppressed by the rate limit of R per second", when the second is over (at the next line of that site, the next line of any
 * site in a later second, or klog_sites_flush(), which the query logger thread calls with logev_flush_suppressed()). */
#define KLOG_SITE_RATE_QUERY 20u
void klog_sites_flush(int64_t now);
void klog_sites_reset(void);               /* tests */
/* the query logger thread drains the sinks' rings (true while it runs); without a drainer a line of the query path is written at once */
void klog_set_sink_drainer(bool on);
/* one finished line of a level (LOG_LVL_* or debug) to syslog(3) (klog_syslog_text()): the logger thread's way when there is no logging runtime */
void klog_syslog_level(int level, const char *msg);
/* The line of a record for the channels: "client <ip>#<port>: <msg>" (no client: msg).  Returns the length. */
size_t logev_format_line(char *out, size_t n, const char *client_ip, int client_port, const char *msg);
/* Routes a finished line to the channels of the category at once (dns_log.c: klog_emit_level()); null = no routing (tools, unit tests). */
typedef void (*klog_level_hook_t)(int cat, int level, const char *msg);
void klog_set_level_hook(klog_level_hook_t hook);
void logev_post(int cat, int level, const char *client_ip, int client_port, const char *fmt, ...) __attribute__((format(printf, 5, 6)));
void logev_vpost(int cat, int level, const char *client_ip, int client_port, const char *fmt, va_list ap) __attribute__((format(printf, 5, 0)));
/* A name for a log line.  `name` is the presentation text the engine keeps (already escaped: \. \\ \DDD); bytes outside 0x21..0x7e and the characters
 * " and ; are written \DDD, the trailing dot is dropped (BIND logs example.test, not example.test.; the root stays "."), the result is cut to n-1. */
void logev_name_text(const char *name, char *out, size_t n);
/* The rate limit (messages per second, per category) and its clock-driven part; `now` is time(NULL).  logev_admit_at() true = pass; *report is the
 * number of messages the second before dropped (to be said once); logev_flush_suppressed() is called by the query logger thread about every
 * 10 ms so that a report is not left waiting for the next message. */
bool logev_admit_at(int cat, int level, int64_t now, uint32_t *report, int *report_level);
/* 0.7 M3 (D-5): the limit of every category, of each of its two budgets, while the debug level in force is above 0 (BIND has none; a debug session at level 3 wants one line per
 * message, and the 10-50 lines a second of level 0 would hide most of them).  Why 1000: a worker's event ring has 1024 records at the least (4096 by
 * default: query-log-buffer-size / 8, 0.7) and the query logger thread empties it every 1 ms while there is work and every 10 ms when idle; a debug record
 * may only take the event ring up to half (qlog_event_sink(): the other half stays for info and above; the query log has a ring of its own), so 1000 lines a second in each of
 * the dozen categories a debug session can make busy is some 120 records per 10 ms, under the 512 a smallest ring leaves to debug records,
 * and some 12000 formatted lines a second for the logger thread, a small part of one core.  Records that still do not fit are dropped and
 * counted (ev_dropped, the "[QueryLog] Dropped N event log messages" warning): a worker never waits for the log. */
#define LOGEV_DEBUG_RATE 1000u
void logev_flush_suppressed(int64_t now);
uint32_t logev_rate_limit(int cat);
void logev_rate_reset(void);               /* tests */

#define syslog(...) kdns_syslog(__VA_ARGS__)

#endif

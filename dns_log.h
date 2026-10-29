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

#define syslog(...) kdns_syslog(__VA_ARGS__)

#endif

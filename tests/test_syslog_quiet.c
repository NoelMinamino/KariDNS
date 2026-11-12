/*
 * test_syslog_quiet.c - linked into every unit test binary (TEST_SYSLOG_QUIET in the TEST_*_SRCS of the Makefile; 0.6.2).
 *
 * The unit tests drive the error paths on purpose, and the code reports them with syslog(3): one `make unit-tests` wrote thousands of
 * lines to the system log of the build host.  This syslog() is weak, so that
 *   - a test that defines its own syslog() (to look at the messages) keeps it: a strong definition wins over this one;
 *   - every other test writes nothing to the system log, or, with KARIDNS_TEST_SYSLOG=1 in the environment, to standard error (to see
 *     the messages while debugging a test).  A test that sends its own standard error to /dev/null around a parse that must fail (as
 *     test_config_directives does) hides those messages too.
 * (glibc with _FORTIFY_SOURCE turns syslog() into __syslog_chk(), which this does not replace: on Linux the messages still go to the
 * system log, as before.  FreeBSD, where the suite runs, has no such wrapper.)
 */
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

__attribute__((weak)) void syslog(int priority, const char *format, ...) {
    static _Atomic int to_stderr = -1;     /* -1: not looked at yet (threads that race here all find the same value) */
    int t = atomic_load_explicit(&to_stderr, memory_order_relaxed);
    if (t < 0) {
        const char *e = getenv("KARIDNS_TEST_SYSLOG");
        t = e && e[0] == '1' && e[1] == '\0';
        atomic_store_explicit(&to_stderr, t, memory_order_relaxed);
    }
    if (!t) return;
    va_list ap;
    va_start(ap, format);
    fprintf(stderr, "syslog<%d>: ", priority);
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
    va_end(ap);
}

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_setuid)(uid_t) = NULL;
static int (*real_setgid)(gid_t) = NULL;
static int (*real_open)(const char *, int, ...) = NULL;
static time_t (*real_time)(time_t *) = NULL;
static int (*real_clock_gettime)(clockid_t, struct timespec *) = NULL;

static int g_bind_call_count = 0;
static int g_bind_fail_nth = -1;
static int g_bind_errno = EADDRINUSE;

static int g_setuid_noop = 0;
static int g_setgid_noop = 0;

static void init_preload_hooks(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    real_bind = dlsym(RTLD_NEXT, "bind");
    real_setuid = dlsym(RTLD_NEXT, "setuid");
    real_setgid = dlsym(RTLD_NEXT, "setgid");
    real_open = dlsym(RTLD_NEXT, "open");
    real_time = dlsym(RTLD_NEXT, "time");
    real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");

    const char *spec = getenv("KARI_FI_SPEC");
    if (spec) {
        if (strstr(spec, "setuid@1:noop")) g_setuid_noop = 1;
        if (strstr(spec, "setgid@1:noop")) g_setgid_noop = 1;
        if (strstr(spec, "bind@1:errno=EADDRINUSE")) {
            g_bind_fail_nth = 1;
            g_bind_errno = EADDRINUSE;
        }
        if (strstr(spec, "bind@2:errno=EADDRINUSE")) {
            g_bind_fail_nth = 2;
            g_bind_errno = EADDRINUSE;
        }
    }
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    init_preload_hooks();
    g_bind_call_count++;
    if (g_bind_fail_nth > 0 && g_bind_call_count == g_bind_fail_nth) {
        errno = g_bind_errno;
        return -1;
    }
    return real_bind ? real_bind(sockfd, addr, addrlen) : -1;
}

int setuid(uid_t uid) {
    init_preload_hooks();
    if (g_setuid_noop) {
        // Return success but DO NOT actually drop privileges
        return 0;
    }
    return real_setuid ? real_setuid(uid) : 0;
}

int setgid(gid_t gid) {
    init_preload_hooks();
    if (g_setgid_noop) {
        return 0;
    }
    return real_setgid ? real_setgid(gid) : 0;
}

time_t time(time_t *tloc) {
    init_preload_hooks();
    const char *time_file = getenv("KARI_FAKE_TIME_FILE");
    if (time_file) {
        FILE *fp = fopen(time_file, "r");
        if (fp) {
            long long val = 0;
            if (fscanf(fp, "%lld", &val) == 1 && val > 0) {
                fclose(fp);
                if (tloc) *tloc = (time_t)val;
                return (time_t)val;
            }
            fclose(fp);
        }
    }
    return real_time ? real_time(tloc) : 0;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    init_preload_hooks();
    const char *time_file = getenv("KARI_FAKE_TIME_FILE");
    if (time_file && tp) {
        FILE *fp = fopen(time_file, "r");
        if (fp) {
            long long val = 0;
            if (fscanf(fp, "%lld", &val) == 1 && val > 0) {
                fclose(fp);
                tp->tv_sec = (time_t)val;
                tp->tv_nsec = 0;
                return 0;
            }
            fclose(fp);
        }
    }
    return real_clock_gettime ? real_clock_gettime(clk_id, tp) : -1;
}

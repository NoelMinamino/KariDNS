#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "kari_fi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <pthread.h>

// Real function declarations (provided by -Wl,--wrap)
void*  __real_malloc(size_t size);
void*  __real_calloc(size_t nmemb, size_t size);
void*  __real_realloc(void *ptr, size_t size);
void   __real_free(void *ptr);
char*  __real_strdup(const char *s);
char*  __real_strndup(const char *s, size_t n);
int    __real_posix_memalign(void **memptr, size_t alignment, size_t size);

int    __real_open(const char *pathname, int flags, ...);
int    __real_openat(int dirfd, const char *pathname, int flags, ...);
FILE*  __real_fopen(const char *pathname, const char *mode);
ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __real_write(int fd, const void *buf, size_t count);
int    __real_socket(int domain, int type, int protocol);
int    __real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int    __real_listen(int sockfd, int backlog);
int    __real_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int    __real_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int    __real_fcntl(int fd, int cmd, ...);
int    __real_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int    __real_rename(const char *oldpath, const char *newpath);
int    __real_mkdir(const char *pathname, mode_t mode);
int    __real_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
int    __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);

time_t __real_time(time_t *tloc);
int    __real_clock_gettime(clockid_t clk_id, struct timespec *tp);
int    __real_gettimeofday(struct timeval *tv, struct timezone *tz);

// State tracking
static _Thread_local unsigned g_counts[FI_KIND_MAX] = {0};
static _Thread_local unsigned g_targets[FI_KIND_MAX] = {0};
static _Thread_local int      g_errnos[FI_KIND_MAX] = {0};
static _Thread_local int      g_fired[FI_KIND_MAX]  = {0};
static _Thread_local int      g_pause_depth = 0;
static _Thread_local time_t   g_fake_time = 0;

void fi_reset(void) {
    memset((void*)g_counts, 0, sizeof(g_counts));
    memset((void*)g_targets, 0, sizeof(g_targets));
    memset((void*)g_errnos, 0, sizeof(g_errnos));
    memset((void*)g_fired, 0, sizeof(g_fired));
    g_pause_depth = 0;
}

void fi_arm_nth(fi_kind_t k, unsigned n) {
    if (k < FI_KIND_MAX) {
        g_targets[k] = n;
        g_errnos[k] = (k == FI_ALLOC) ? ENOMEM : EIO;
    }
}

void fi_arm_nth_errno(fi_kind_t k, unsigned n, int err_code) {
    if (k < FI_KIND_MAX) {
        g_targets[k] = n;
        g_errnos[k] = err_code;
    }
}

unsigned fi_count(fi_kind_t k) {
    return (k < FI_KIND_MAX) ? g_counts[k] : 0;
}

int fi_fired(void) {
    for (int i = 0; i < FI_KIND_MAX; i++) {
        if (g_fired[i]) return 1;
    }
    return 0;
}

int fi_fired_kind(fi_kind_t k) {
    return (k < FI_KIND_MAX) ? g_fired[k] : 0;
}

void fi_pause(void) {
    g_pause_depth++;
}

void fi_resume(void) {
    if (g_pause_depth > 0) g_pause_depth--;
}

void fi_set_time(time_t fake_time) {
    g_fake_time = fake_time;
}

void fi_advance_time(time_t delta_sec) {
    if (g_fake_time == 0) g_fake_time = time(NULL);
    g_fake_time += delta_sec;
}

void fi_reset_time(void) {
    g_fake_time = 0;
}

static inline bool fi_should_fail(fi_kind_t k) {
    if (g_pause_depth > 0 || k >= FI_KIND_MAX) return false;
    g_counts[k]++;
    if (g_targets[k] > 0 && g_counts[k] == g_targets[k]) {
        g_fired[k] = 1;
        errno = g_errnos[k] ? g_errnos[k] : ((k == FI_ALLOC) ? ENOMEM : EIO);
        return true;
    }
    return false;
}

// -----------------------------------------------------------------------------
// Memory Allocator Wrappers
// -----------------------------------------------------------------------------
void* __wrap_malloc(size_t size) {
    if (fi_should_fail(FI_ALLOC)) return NULL;
    return __real_malloc(size);
}

void* __wrap_calloc(size_t nmemb, size_t size) {
    if (fi_should_fail(FI_ALLOC)) return NULL;
    return __real_calloc(nmemb, size);
}

void* __wrap_realloc(void *ptr, size_t size) {
    if (fi_should_fail(FI_ALLOC)) return NULL;
    return __real_realloc(ptr, size);
}

char* __wrap_strdup(const char *s) {
    if (!s) return NULL;
    if (fi_should_fail(FI_ALLOC)) return NULL;
    return __real_strdup(s);
}

char* __wrap_strndup(const char *s, size_t n) {
    if (!s) return NULL;
    if (fi_should_fail(FI_ALLOC)) return NULL;
    return __real_strndup(s, n);
}

int __wrap_posix_memalign(void **memptr, size_t alignment, size_t size) {
    if (fi_should_fail(FI_ALLOC)) return ENOMEM;
    return __real_posix_memalign(memptr, alignment, size);
}

// -----------------------------------------------------------------------------
// Syscall Wrappers
// -----------------------------------------------------------------------------
int __wrap_open(const char *pathname, int flags, mode_t mode) {
    if (fi_should_fail(FI_OPEN)) return -1;
    return __real_open(pathname, flags, mode);
}

int __wrap_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (fi_should_fail(FI_OPEN)) return -1;
    return __real_openat(dirfd, pathname, flags, mode);
}

FILE* __wrap_fopen(const char *pathname, const char *mode) {
    if (fi_should_fail(FI_OPEN)) return NULL;
    return __real_fopen(pathname, mode);
}

ssize_t __wrap_read(int fd, void *buf, size_t count) {
    if (fi_should_fail(FI_READ)) return -1;
    return __real_read(fd, buf, count);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count) {
    if (fi_should_fail(FI_WRITE)) return -1;
    return __real_write(fd, buf, count);
}

int __wrap_socket(int domain, int type, int protocol) {
    if (fi_should_fail(FI_SOCKET)) return -1;
    return __real_socket(domain, type, protocol);
}

int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (fi_should_fail(FI_BIND)) return -1;
    return __real_bind(sockfd, addr, addrlen);
}

int __wrap_listen(int sockfd, int backlog) {
    if (fi_should_fail(FI_LISTEN)) return -1;
    return __real_listen(sockfd, backlog);
}

int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (fi_should_fail(FI_ACCEPT)) return -1;
    return __real_accept(sockfd, addr, addrlen);
}

int __wrap_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (fi_should_fail(FI_CONNECT)) return -1;
    return __real_connect(sockfd, addr, addrlen);
}

int __wrap_rename(const char *oldpath, const char *newpath) {
    if (fi_should_fail(FI_RENAME)) return -1;
    return __real_rename(oldpath, newpath);
}

int __wrap_mkdir(const char *pathname, mode_t mode) {
    if (fi_should_fail(FI_MKDIR)) return -1;
    return __real_mkdir(pathname, mode);
}

int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    if (fi_should_fail(FI_GETADDRINFO)) return EAI_FAIL;
    return __real_getaddrinfo(node, service, hints, res);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    if (fi_should_fail(FI_PTHREAD_CREATE)) return EAGAIN;
    return __real_pthread_create(thread, attr, start_routine, arg);
}

// -----------------------------------------------------------------------------
// Time Wrappers
// -----------------------------------------------------------------------------
time_t __wrap_time(time_t *tloc) {
    if (g_fake_time > 0) {
        if (tloc) *tloc = g_fake_time;
        return g_fake_time;
    }
    return __real_time(tloc);
}

int __wrap_clock_gettime(clockid_t clk_id, struct timespec *tp) {
    if (g_fake_time > 0 && tp) {
        tp->tv_sec = g_fake_time;
        tp->tv_nsec = 0;
        return 0;
    }
    return __real_clock_gettime(clk_id, tp);
}

int __wrap_gettimeofday(struct timeval *tv, struct timezone *tz) {
    if (g_fake_time > 0 && tv) {
        tv->tv_sec = g_fake_time;
        tv->tv_usec = 0;
        return 0;
    }
    return __real_gettimeofday(tv, tz);
}

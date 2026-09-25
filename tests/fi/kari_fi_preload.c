#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#ifdef __FreeBSD__
#include <sys/event.h>
#include <sys/capsicum.h>
#endif

typedef struct {
    char func_name[32];
    int nth;
    int err_code;
    int is_noop;
    int child_only;   /* ":child": count only in forked children, not the first process */
    int call_count;
} fi_spec_item_t;

#define MAX_PRELOAD_SPECS 32
static fi_spec_item_t g_specs[MAX_PRELOAD_SPECS];
static int g_num_specs = 0;
static char g_fi_log_path[512];
static int g_fi_log_fd = -1;
static pid_t g_fi_root_pid = 0;

static int parse_errno_str(const char *s) {
    if (!s) return EIO;
    if (strncmp(s, "EADDRINUSE", 10) == 0) return EADDRINUSE;
    if (strncmp(s, "EPIPE", 5) == 0) return EPIPE;
    if (strncmp(s, "EMFILE", 6) == 0) return EMFILE;
    if (strncmp(s, "ENOMEM", 6) == 0) return ENOMEM;
    if (strncmp(s, "ECONNRESET", 10) == 0) return ECONNRESET;
    if (strncmp(s, "EINTR", 5) == 0) return EINTR;
    if (strncmp(s, "EAGAIN", 6) == 0) return EAGAIN;
    if (strncmp(s, "EWOULDBLOCK", 11) == 0) return EWOULDBLOCK;
    if (strncmp(s, "EACCES", 6) == 0) return EACCES;
    if (strncmp(s, "EPERM", 5) == 0) return EPERM;
    if (strncmp(s, "ENOENT", 6) == 0) return ENOENT;
    if (strncmp(s, "ENFILE", 6) == 0) return ENFILE;
    if (strncmp(s, "ENOBUFS", 7) == 0) return ENOBUFS;
    if (strncmp(s, "ECONNABORTED", 12) == 0) return ECONNABORTED;
    if (strncmp(s, "EXDEV", 5) == 0) return EXDEV;
    if (strncmp(s, "ELOOP", 5) == 0) return ELOOP;
    if (strncmp(s, "ECONNREFUSED", 12) == 0) return ECONNREFUSED;
    if (strncmp(s, "ENOSYS", 6) == 0) return ENOSYS;
    int val = atoi(s);
    return val > 0 ? val : EIO;
}

static void init_preload_hooks(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    g_fi_root_pid = getpid();
    const char *logp = getenv("KARI_FI_LOG");
    if (logp && *logp) {
        snprintf(g_fi_log_path, sizeof(g_fi_log_path), "%s", logp);
        /* Open the log now and keep it on a high descriptor: the fault usually
         * fires in a child that has already dropped privileges or entered a
         * Capsicum sandbox, where the path could no longer be opened. */
        int fd = open(logp, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
        if (fd >= 0) {
            int hi = fcntl(fd, F_DUPFD_CLOEXEC, 900);
            if (hi >= 0) { close(fd); fd = hi; }
            g_fi_log_fd = fd;
        }
    }

    const char *spec = getenv("KARI_FI_SPEC");
    if (!spec || !*spec) return;

    char buf[1024];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(buf, ",", &saveptr);
    while (token && g_num_specs < MAX_PRELOAD_SPECS) {
        fi_spec_item_t *it = &g_specs[g_num_specs];
        memset(it, 0, sizeof(*it));
        it->nth = 1;
        it->err_code = EIO;

        char item_str[128];
        strncpy(item_str, token, sizeof(item_str) - 1);
        item_str[sizeof(item_str) - 1] = '\0';

        char *at_pos = strchr(item_str, '@');
        char *colon_pos = strchr(item_str, ':');
        char *split_pos = at_pos ? at_pos : colon_pos;
        if (split_pos) {
            *split_pos = '\0';
            strncpy(it->func_name, item_str, sizeof(it->func_name) - 1);
            char *rest = split_pos + 1;
            if (at_pos) {
                it->nth = atoi(rest);
                char *rest_colon = strchr(rest, ':');
                if (rest_colon) rest = rest_colon + 1;
                else rest = "";
            }
            if (strstr(rest, "noop")) {
                it->is_noop = 1;
            }
            if (strstr(rest, "child")) {
                it->child_only = 1;
            }
            char *nth_sub = strstr(rest, "nth=");
            if (nth_sub) {
                it->nth = atoi(nth_sub + 4);
            }
            char *err_sub = strstr(rest, "errno=");
            if (err_sub) {
                it->err_code = parse_errno_str(err_sub + 6);
            }
        } else {
            strncpy(it->func_name, item_str, sizeof(it->func_name) - 1);
        }
        g_num_specs++;
        token = strtok_r(NULL, ",", &saveptr);
    }
}

/* When KARI_FI_LOG is set, every injected failure appends "name@nth" to that
 * file, so a sweep can tell whether the Nth call was ever reached. */

static void log_fired(const char *name, int nth) {
    if (g_fi_log_fd < 0) return;
    char line[64];
    int len = snprintf(line, sizeof(line), "%s@%d\n", name, nth);
    if (len > 0) (void)!write(g_fi_log_fd, line, (size_t)len);
}

static bool check_and_trigger_fi(const char *name, int *out_errno, int *out_noop) {
    init_preload_hooks();
    for (int i = 0; i < g_num_specs; i++) {
        if (strcmp(g_specs[i].func_name, name) == 0) {
            /* a child inherits the parent's counts at fork, so with ":child"
             * the Nth call of every child process fails */
            if (g_specs[i].child_only && getpid() == g_fi_root_pid) continue;
            /* hooks run on many threads: count atomically */
            int c = __atomic_add_fetch(&g_specs[i].call_count, 1, __ATOMIC_SEQ_CST);
            if (c == g_specs[i].nth) {
                if (out_errno) *out_errno = g_specs[i].err_code;
                if (out_noop) *out_noop = g_specs[i].is_noop;
                log_fired(name, c);
                return true;
            }
        }
    }
    return false;
}

// -----------------------------------------------------------------------------
// Intercepted Syscalls
// -----------------------------------------------------------------------------
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("bind", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "bind");
    return real_fn ? real_fn(sockfd, addr, addrlen) : -1;
}

int socket(int domain, int type, int protocol) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("socket", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(int, int, int) = dlsym(RTLD_NEXT, "socket");
    return real_fn ? real_fn(domain, type, protocol) : -1;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("setsockopt", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(int, int, int, const void *, socklen_t) = dlsym(RTLD_NEXT, "setsockopt");
    return real_fn ? real_fn(sockfd, level, optname, optval, optlen) : -1;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("getsockname", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(int, struct sockaddr *, socklen_t *) = dlsym(RTLD_NEXT, "getsockname");
    return real_fn ? real_fn(sockfd, addr, addrlen) : -1;
}

int listen(int sockfd, int backlog) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("listen", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(int, int) = dlsym(RTLD_NEXT, "listen");
    return real_fn ? real_fn(sockfd, backlog) : -1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("accept", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(int, struct sockaddr *, socklen_t *) = dlsym(RTLD_NEXT, "accept");
    return real_fn ? real_fn(sockfd, addr, addrlen) : -1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("connect", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    return real_fn ? real_fn(sockfd, addr, addrlen) : -1;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("send", &err, &noop)) {
        errno = err;
        return -1;
    }
    ssize_t (*real_fn)(int, const void *, size_t, int) = dlsym(RTLD_NEXT, "send");
    return real_fn ? real_fn(sockfd, buf, len, flags) : -1;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("sendto", &err, &noop)) {
        errno = err;
        return -1;
    }
    ssize_t (*real_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "sendto");
    return real_fn ? real_fn(sockfd, buf, len, flags, dest_addr, addrlen) : -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("recv", &err, &noop)) {
        errno = err;
        return -1;
    }
    ssize_t (*real_fn)(int, void *, size_t, int) = dlsym(RTLD_NEXT, "recv");
    return real_fn ? real_fn(sockfd, buf, len, flags) : -1;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("recvfrom", &err, &noop)) {
        errno = err;
        return -1;
    }
    ssize_t (*real_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = dlsym(RTLD_NEXT, "recvfrom");
    return real_fn ? real_fn(sockfd, buf, len, flags, src_addr, addrlen) : -1;
}

int pipe(int pipefd[2]) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("pipe", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(int[2]) = dlsym(RTLD_NEXT, "pipe");
    return real_fn ? real_fn(pipefd) : -1;
}

pid_t fork(void) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("fork", &err, &noop)) {
        errno = err;
        return -1;
    }
    pid_t (*real_fn)(void) = dlsym(RTLD_NEXT, "fork");
    return real_fn ? real_fn() : -1;
}

int execv(const char *path, char *const argv[]) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("execv", &err, &noop)) {
        errno = err;
        return -1;
    }
    int (*real_fn)(const char *, char *const[]) = dlsym(RTLD_NEXT, "execv");
    return real_fn ? real_fn(path, argv) : -1;
}

int setuid(uid_t uid) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("setuid", &err, &noop)) {
        if (noop) return 0;
        errno = err;
        return -1;
    }
    int (*real_fn)(uid_t) = dlsym(RTLD_NEXT, "setuid");
    return real_fn ? real_fn(uid) : 0;
}

int setgid(gid_t gid) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("setgid", &err, &noop)) {
        if (noop) return 0;
        errno = err;
        return -1;
    }
    int (*real_fn)(gid_t) = dlsym(RTLD_NEXT, "setgid");
    return real_fn ? real_fn(gid) : 0;
}

time_t time(time_t *tloc) {
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
    time_t (*real_fn)(time_t *) = dlsym(RTLD_NEXT, "time");
    return real_fn ? real_fn(tloc) : 0;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
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
    int (*real_fn)(clockid_t, struct timespec *) = dlsym(RTLD_NEXT, "clock_gettime");
    return real_fn ? real_fn(clk_id, tp) : -1;
}

/* -----------------------------------------------------------------------------
 * Further hooks for the server fault-injection sweep
 * (tests/run_server_core_fi_test.sh). Each returns the conventional failure
 * value with errno set when its turn comes.
 * -------------------------------------------------------------------------- */
#define FI_REAL(ret, name, params) \
    static ret (*real_fn) params = NULL; \
    if (!real_fn) real_fn = (ret (*) params)dlsym(RTLD_NEXT, #name)

int socketpair(int domain, int type, int protocol, int sv[2]) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("socketpair", &err, &noop)) { errno = err; return -1; }
    FI_REAL(int, socketpair, (int, int, int, int *));
    return real_fn ? real_fn(domain, type, protocol, sv) : -1;
}

int pthread_create(pthread_t *t, const pthread_attr_t *attr, void *(*fn)(void *), void *arg) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("pthread_create", &err, &noop)) return err ? err : EAGAIN;
    FI_REAL(int, pthread_create, (pthread_t *, const pthread_attr_t *, void *(*)(void *), void *));
    return real_fn ? real_fn(t, attr, fn, arg) : EAGAIN;
}

int rename(const char *from, const char *to) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("rename", &err, &noop)) { errno = err; return -1; }
    FI_REAL(int, rename, (const char *, const char *));
    return real_fn ? real_fn(from, to) : -1;
}

int mkdir(const char *path, mode_t mode) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("mkdir", &err, &noop)) { errno = err; return -1; }
    FI_REAL(int, mkdir, (const char *, mode_t));
    return real_fn ? real_fn(path, mode) : -1;
}

int dup2(int oldfd, int newfd) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("dup2", &err, &noop)) { errno = err; return -1; }
    FI_REAL(int, dup2, (int, int));
    return real_fn ? real_fn(oldfd, newfd) : -1;
}

pid_t setsid(void) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("setsid", &err, &noop)) { errno = err; return -1; }
    FI_REAL(pid_t, setsid, (void));
    return real_fn ? real_fn() : -1;
}

ssize_t sendmsg(int s, const struct msghdr *msg, int flags) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("sendmsg", &err, &noop)) { errno = err; return -1; }
    FI_REAL(ssize_t, sendmsg, (int, const struct msghdr *, int));
    return real_fn ? real_fn(s, msg, flags) : -1;
}

struct group *getgrnam(const char *name) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("getgrnam", &err, &noop)) { errno = 0; return NULL; }
    FI_REAL(struct group *, getgrnam, (const char *));
    return real_fn ? real_fn(name) : NULL;
}

struct passwd *getpwnam(const char *name) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("getpwnam", &err, &noop)) { errno = 0; return NULL; }
    FI_REAL(struct passwd *, getpwnam, (const char *));
    return real_fn ? real_fn(name) : NULL;
}

int renameat(int fromfd, const char *from, int tofd, const char *to) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("renameat", &err, &noop)) { errno = err; return -1; }
    FI_REAL(int, renameat, (int, const char *, int, const char *));
    return real_fn ? real_fn(fromfd, from, tofd, to) : -1;
}

int openat(int fd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int err = 0, noop = 0;
    if (check_and_trigger_fi("openat", &err, &noop)) { errno = err; return -1; }
    FI_REAL(int, openat, (int, const char *, int, ...));
    return real_fn ? real_fn(fd, path, flags, mode) : -1;
}

#ifdef __FreeBSD__
/* FreeBSD prototype; glibc declares setgroups(size_t, ...) */
int setgroups(int n, const gid_t *groups) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("setgroups", &err, &noop)) { if (noop) return 0; errno = err; return -1; }
    FI_REAL(int, setgroups, (int, const gid_t *));
    return real_fn ? real_fn(n, groups) : -1;
}

int kqueue(void) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("kqueue", &err, &noop)) { errno = err; return -1; }
    FI_REAL(int, kqueue, (void));
    return real_fn ? real_fn() : -1;
}

int cap_enter(void) {
    int err = 0, noop = 0;
    if (check_and_trigger_fi("cap_enter", &err, &noop)) { if (noop) return 0; errno = err; return -1; }
    FI_REAL(int, cap_enter, (void));
    return real_fn ? real_fn() : -1;
}
#endif

/*
 * test_db_supervisor.c - the supervisor side of karidns-dbloader (dns_db_supervisor.c; beta design 1.2).
 *
 * The loader is a small shell script, started the way karidns starts it (fd 3, cleared environment, working directory /).
 * Cases: db_sup_init refuses a loader path that is missing / not a regular file / writable by group or others / not
 * executable / owned by somebody else, and (as root) a database block without loader-user or with loader-group alone;
 * db_sup_open_pairs; the first spawn uses pair A (the script writes to fd 3, the Backend end reads it), a restart makes a
 * new pair and hands the Backend end over pair C with SCM_RIGHTS; db_sup_child_exited for an exit and for a signal, for a
 * child that is not the loader; the restart backoff 1, 2, 4 ... 60 s, back to 1 s after ten minutes of uptime; the timeout
 * the supervisor polls with; db_sup_tick; a loader that disappeared or lost its mode is not started (and a restart is
 * scheduled); the Backend cannot be reached over pair C.
 *
 * Usage: test_db_supervisor
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <grp.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <pwd.h>
#include "../dns_db_supervisor.h"
#include "../dns_priv_sandbox.h"
#include "../dns_utils.h"

/* what dns_priv_sandbox.c and dns_utils.c take from the server (dns_server_core.c, dns_dnstap.c, dns_wire.c, dns_snapshot_rcu.c): not used here */
char g_startup_cwd[PATH_MAX];
int g_cwd_fd = -1;
int g_dnstap_sock = -1;
void gc_snapshot_wait_idle(void) {}
long write_uncompressed_name_ext(uint8_t *buf, size_t offset, size_t max_len, const char *name, bool downcase) {
    (void)buf; (void)offset; (void)max_len; (void)name; (void)downcase;
    return -1;
}

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, ...) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define CHECK_HAS(actual, needle) do { g_checks++; const char *a_ = (actual); const char *n_ = (needle); \
    if (!a_ || !strstr(a_, n_)) { g_failed++; printf("  [FAIL] %s:%d: \"%s\" lacks \"%s\"\n", \
        __FILE__, __LINE__, a_ ? a_ : "(null)", n_); } } while (0)

static char g_dir[300];

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* a loader script: writes "hello" to fd 3 and exits with the status 3 */
static void write_loader(const char *path, mode_t mode) {
    FILE *f = fopen(path, "w");
    if (f) {
        fputs("#!/bin/sh\nprintf 'hello:%s' \"${KARIDNS_TEST_LEAK:-clean}\" >&3 2>/dev/null\nexit 3\n", f);
        fclose(f);
    }
    chmod(path, mode);
}

/* a server configuration with a database block; the identity is the one the test runs as (root needs a loader-user) */
static void make_cfg(server_config_t *cfg, const char *path) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->database.enabled = true;
    cfg->database.loader_path = (char *)path;
    cfg->database.loader_user = geteuid() == 0 ? (char *)"nobody" : NULL;   /* P4: root by name is refused */
}

/* reap the loader: the status of the child the supervisor started */
static int reap(pid_t pid) {
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return st;
}

static void test_init(void) {
    printf("db_sup_init\n");
    char err[300], path[400];
    db_sup_t s;
    server_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    CHECK(db_sup_init(&s, &cfg, err, sizeof(err)) && !s.enabled);          /* no database block: nothing to do */
    CHECK(s.ctrl_fd == -1 && s.first_fd == -1 && s.backoff_s == 1);
    CHECK(db_sup_timeout_ms(&s) == -1);
    CHECK(!db_sup_spawn(&s));
    CHECK(!db_sup_child_exited(&s, 1, 0));
    db_sup_tick(&s);
    db_sup_signal(&s, 0);
    db_sup_after_fork_supervisor(&s);
    db_sup_close_supervisor_ends(&s);

    snprintf(path, sizeof(path), "%s/missing", g_dir);
    make_cfg(&cfg, path);
    CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
    CHECK_HAS(err, "No such file or directory");

    snprintf(path, sizeof(path), "%s/dir", g_dir);
    mkdir(path, 0755);
    make_cfg(&cfg, path);
    CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
    CHECK_HAS(err, "is not a regular file");

    snprintf(path, sizeof(path), "%s/loader.sh", g_dir);
    write_loader(path, 0775);
    make_cfg(&cfg, path);
    CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
    CHECK_HAS(err, "is writable by group or others (mode 0775)");

    write_loader(path, 0644);
    CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
    CHECK_HAS(err, "is not executable by the user running karidns");

    write_loader(path, 0755);
    CHECK_MSG(db_sup_init(&s, &cfg, err, sizeof(err)), "%s", err);
    CHECK(s.enabled && strcmp(s.path, path) == 0 && s.backoff_s == 1 && s.starts == 0 && !s.restart_pending);

    if (geteuid() == 0) {
        chown(path, 12345, 12345);                                           /* a loader that somebody else owns */
        CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
        CHECK_HAS(err, "is owned by uid 12345; it must belong to root");
        chown(path, 0, 0);
        cfg.database.loader_user = NULL;
        CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
        CHECK_HAS(err, "loader-user");
        cfg.database.loader_group = (char *)getgrgid(0)->gr_name;                      /* P4: the root group is refused by name */
        CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
        CHECK_HAS(err, "is gid 0");
        cfg.database.loader_group = (char *)"nobody";                                  /* a group alone would leave the loader root */
        CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
        CHECK_HAS(err, "loader-group without loader-user");
    } else {
        cfg.database.loader_user = (char *)"no-such-user-karidns-test";      /* not the user running karidns */
        CHECK(!db_sup_init(&s, &cfg, err, sizeof(err)));
        CHECK_HAS(err, "database loader: ");
    }
    unlink(path);
    snprintf(path, sizeof(path), "%s/dir", g_dir);
    rmdir(path);
}

/* the fd that arrives over pair C: one byte "F" with an SCM_RIGHTS descriptor; -1 when nothing is there */
static int recv_fd(int ctrl) {
    char byte;
    struct iovec iov = { &byte, 1 };
    union { struct cmsghdr h; char buf[CMSG_SPACE(sizeof(int))]; } u;
    struct msghdr m;
    memset(&m, 0, sizeof(m));
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof(u.buf);
    ssize_t n;
    do { n = recvmsg(ctrl, &m, MSG_DONTWAIT); } while (n < 0 && errno == EINTR);
    if (n != 1 || byte != 'F') return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

/* read what the loader wrote to its fd 3 (until it closes the stream) */
static void read_all(int fd, char *out, size_t cap) {
    size_t n = 0;
    for (int tries = 0; tries < 200; tries++) {
        ssize_t r = read(fd, out + n, cap - 1 - n);
        if (r > 0) { n += (size_t)r; continue; }
        if (r == 0) break;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) { usleep(20000); continue; }
        break;
    }
    out[n] = '\0';
}

static void test_spawn_and_restart(void) {
    printf("spawn, restart, backoff\n");
    char err[300], path[400], got[100];
    snprintf(path, sizeof(path), "%s/loader.sh", g_dir);
    write_loader(path, 0755);
    server_config_t cfg;
    make_cfg(&cfg, path);
    db_sup_t s;
    CHECK(db_sup_init(&s, &cfg, err, sizeof(err)));
    CHECK_MSG(db_sup_open_pairs(&s, err, sizeof(err)), "%s", err);
    CHECK(s.ctrl_fd >= 0 && s.first_fd >= 0 && g_db_stream_fd >= 0 && g_db_ctrl_fd >= 0);

    setenv("KARIDNS_TEST_LEAK", "leaked", 1);                                /* the loader runs with a cleared environment */
    CHECK(db_sup_spawn(&s));
    CHECK(s.pid > 0 && s.starts == 1 && s.first_fd == -1 && !s.restart_pending);
    read_all(g_db_stream_fd, got, sizeof(got));
    CHECK_MSG(strcmp(got, "hello:clean") == 0, "the first loader writes to fd 3 (pair A) and sees no environment: \"%s\"", got);
    pid_t first = s.pid;
    CHECK(WIFEXITED(reap(first)));
    int st = 3 << 8;                                                         /* "exited with status 3" */
    CHECK(!db_sup_child_exited(&s, first + 100000, st));                     /* another child of the supervisor */
    CHECK(s.pid == first);
    CHECK(db_sup_child_exited(&s, first, st));
    CHECK(s.pid == 0 && s.restart_pending && s.backoff_s == 2);
    int t = db_sup_timeout_ms(&s);
    CHECK_MSG(t > 0 && t <= 1000, "first restart in 1 s: %d ms", t);
    db_sup_tick(&s);                                                         /* not yet */
    CHECK(s.pid == 0 && s.starts == 1);

    s.restart_at_ms = now_ms() - 1;                                          /* its time has come */
    CHECK(db_sup_timeout_ms(&s) == 0);
    db_sup_tick(&s);
    CHECK(s.pid > 0 && s.starts == 2 && !s.restart_pending);
    int fd = recv_fd(g_db_ctrl_fd);                   /* the restart's Backend end came over pair C */
    CHECK_MSG(fd >= 0, "SCM_RIGHTS descriptor");
    if (fd >= 0) {
        read_all(fd, got, sizeof(got));
        CHECK_MSG(strcmp(got, "hello:clean") == 0, "the restarted loader writes to the passed stream: \"%s\"", got);
        close(fd);
    }
    db_sup_signal(&s, 0);                                                    /* signal 0: the loader exists */
    CHECK(WIFEXITED(reap(s.pid)));

    /* the backoff doubles up to 60 s, and an exit after ten minutes of uptime starts again at 1 s */
    pid_t second = s.pid;
    unsigned want[] = { 4, 8, 16, 32, 60, 60 };           /* the wait doubles after each exit ... */
    unsigned waits[] = { 2, 4, 8, 16, 32, 60 };           /* ... and each exit waits the previous value */
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        s.pid = second;
        s.started_ms = now_ms();
        CHECK(db_sup_child_exited(&s, second, 9));                           /* killed by signal 9 */
        CHECK_MSG(s.backoff_s == want[i], "backoff after exit %zu: %u s", i + 3, s.backoff_s);
        int tm = db_sup_timeout_ms(&s);
        CHECK_MSG(tm > (int)(waits[i] - 1) * 1000 && tm <= (int)waits[i] * 1000, "wait before restart %zu: %d ms (want %u s)", i + 3, tm, waits[i]);
    }
    s.pid = second;
    s.started_ms = now_ms() - 11 * 60 * 1000;
    CHECK(db_sup_child_exited(&s, second, 0));
    CHECK_MSG(s.backoff_s == 2, "after ten minutes of uptime the wait is 1 s again (and the next one 2 s): %u", s.backoff_s);
    s.restart_at_ms = now_ms() + 5 * 3600 * 1000;
    CHECK(db_sup_timeout_ms(&s) == 3600 * 1000);                            /* never more than an hour */

    /* the loader lost its mode (or is gone): it is not started, and the next try is scheduled */
    write_loader(path, 0777);
    unsigned starts = s.starts;
    s.restart_pending = false;
    CHECK(!db_sup_spawn(&s));
    CHECK(s.restart_pending && s.starts == starts && s.pid == 0);
    unlink(path);
    s.restart_pending = false;
    CHECK(!db_sup_spawn(&s));
    CHECK(s.restart_pending);

    /* the Backend cannot take the stream (pair C is closed): the loader is started, the failure is logged */
    write_loader(path, 0755);
    close(g_db_ctrl_fd);
    g_db_ctrl_fd = -1;
    s.restart_pending = false;
    CHECK(db_sup_spawn(&s));
    CHECK(s.pid > 0);
    CHECK(WIFEXITED(reap(s.pid)));
    s.pid = 0;
    unsetenv("KARIDNS_TEST_LEAK");

    db_sup_after_fork_supervisor(&s);                                        /* the supervisor drops the Backend's ends ... */
    CHECK(g_db_stream_fd == -1 && g_db_ctrl_fd == -1);
    db_sup_close_supervisor_ends(&s);                                        /* ... and a child its own */
    CHECK(s.first_fd == -1 && s.ctrl_fd == -1);
    unlink(path);
}

/* P5 (a checked file is the file that runs), P1 (a file that fails the checks is not executed), P4 (root by another name) */
static bool copy_file(const char *from, const char *to, mode_t mode) {
    FILE *in = fopen(from, "rb"), *out = fopen(to, "wb");
    bool ok = in && out;
    char buf[8192];
    size_t n;
    while (ok && (n = fread(buf, 1, sizeof(buf), in)) > 0) ok = fwrite(buf, 1, n, out) == n;
    if (in) fclose(in);
    if (out && fclose(out) != 0) ok = false;
    if (ok) chmod(to, mode);
    return ok;
}

static int run_fd(int fd, const char *path) {   /* execute through exec_file_exec_fd() in a child; the exit status */
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { (char *)"prog", NULL };
        char *envp[] = { NULL };
        exec_file_exec_fd(fd, path, argv, envp);
        _exit(99);
    }
    int st = reap(pid);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void test_exec_file(void) {
    printf("exec_file_open_checked / exec_file_exec_fd (P1, P5)\n");
    char err[300], path[400], old[400];
    uid_t me = geteuid();
    snprintf(path, sizeof(path), "%s/prog", g_dir);
    snprintf(old, sizeof(old), "%s/prog.old", g_dir);

    CHECK(exec_file_open_checked(path, me, "database loader", "this user", err, sizeof(err)) < 0);
    CHECK_HAS(err, "No such file or directory");
    mkdir(old, 0755);
    CHECK(exec_file_open_checked(old, me, "database loader", "this user", err, sizeof(err)) < 0);
    CHECK_HAS(err, "is not a regular file");
    rmdir(old);

    if (!copy_file("/usr/bin/true", path, 0755)) {
        printf("  (no /usr/bin/true to copy: the execution checks are skipped)\n");
        return;
    }
    chmod(path, 0775);
    CHECK(exec_file_open_checked(path, me, "database loader", "this user", err, sizeof(err)) < 0);
    CHECK_HAS(err, "is writable by group or others (mode 0775)");
    chmod(path, 0757);
    CHECK(exec_file_open_checked(path, me, "database loader", "this user", err, sizeof(err)) < 0);
    CHECK_HAS(err, "is writable by group or others (mode 0757)");
    chmod(path, 0644);
    CHECK(exec_file_open_checked(path, me, "database loader", "this user", err, sizeof(err)) < 0);
    CHECK_HAS(err, "is not executable by this user");
    chmod(path, 0755);
    if (me == 0) {
        chown(path, 12345, 12345);                                           /* P1: not root's, not the caller's */
        CHECK(exec_file_open_checked(path, me, "database loader", "this user", err, sizeof(err)) < 0);
        CHECK_HAS(err, "is owned by uid 12345; it must belong to root");
        chown(path, 0, 0);
    }

    /* P5: the descriptor that was checked is what runs: the path is replaced between the check and the exec */
    int fd = exec_file_open_checked(path, me, "database loader", "this user", err, sizeof(err));
    CHECK_MSG(fd >= 0, "%s", err);
    CHECK(rename(path, old) == 0);
    CHECK(copy_file("/usr/bin/false", path, 0755));                         /* what execv(path) would have run: exit 1 */
#ifdef __FreeBSD__
    CHECK_MSG(run_fd(fd, path) == 0, "the replaced file was run");
#endif
    close(fd);
    unlink(path);
    unlink(old);

    /* a script: run after the same checks (by its descriptor when fdescfs is there, else by its path) */
    FILE *f = fopen(path, "w");
    if (f) { fputs("#!/bin/sh\nexit 7\n", f); fclose(f); }
    chmod(path, 0755);
    fd = exec_file_open_checked(path, me, "database loader", "this user", err, sizeof(err));
    CHECK_MSG(fd >= 0, "%s", err);
    CHECK(run_fd(fd, path) == 7);
    close(fd);
    unlink(path);
}

static void test_identity_names_root(void) {
    printf("identity_names_root / resolve_run_identity (P4)\n");
    char err[300];
    run_identity_t id;
    CHECK(identity_names_root("root", NULL, err, sizeof(err)));
    CHECK_HAS(err, "uid 0");
    CHECK(identity_names_root("root", "nobody", err, sizeof(err)));
    CHECK(!resolve_run_identity("root", NULL, &id, err, sizeof(err)));
    CHECK_HAS(err, "uid 0");
    if (getpwnam("toor")) {                                                  /* root by another name (FreeBSD: toor, uid 0) */
        CHECK(identity_names_root("toor", NULL, err, sizeof(err)));
        CHECK(!resolve_run_identity("toor", "nobody", &id, err, sizeof(err)));
        CHECK_HAS(err, "uid 0");
    }
    struct group *g0 = getgrgid(0);
    if (g0) {
        CHECK(identity_names_root(NULL, g0->gr_name, err, sizeof(err)));
        CHECK_HAS(err, "gid 0");
        CHECK(!resolve_run_identity(NULL, g0->gr_name, &id, err, sizeof(err)));
        if (getpwnam("nobody")) {
            CHECK(identity_names_root("nobody", g0->gr_name, err, sizeof(err)));   /* the group named is the one used */
            CHECK(!resolve_run_identity("nobody", g0->gr_name, &id, err, sizeof(err)));
        }
    }
    if (getpwnam("nobody")) {
        CHECK(!identity_names_root("nobody", NULL, err, sizeof(err)));
        CHECK(!identity_names_root("nobody", "nobody", err, sizeof(err)));
        if (geteuid() == 0) CHECK(resolve_run_identity("nobody", NULL, &id, err, sizeof(err)));
    }
    CHECK(!identity_names_root(NULL, NULL, err, sizeof(err)));
    CHECK(!identity_names_root("no-such-user-karidns-test", "no-such-group-karidns-test", err, sizeof(err)));
}

int main(void) {
    const char *tmp = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/karidns_dbsup_XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(g_dir)) {
        printf("  [FAIL] cannot create a temporary directory\n");
        return 1;
    }
    chmod(g_dir, 0755);
    signal(SIGPIPE, SIG_IGN);
    test_init();
    test_spawn_and_restart();
    test_exec_file();
    test_identity_names_root();
    rmdir(g_dir);
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

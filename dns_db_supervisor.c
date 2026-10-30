/*
 * dns_db_supervisor.c - starting, restarting and stopping karidns-dbloader (see dns_db_supervisor.h).
 *
 * Runs in the supervisor, a single-threaded process, so fork() followed by ordinary libc calls in the child is fine.
 */
#include "dns_db_supervisor.h"
#include "dns_snapshot_rcu.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_log.h"
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

int g_db_stream_fd = -1;
int g_db_ctrl_fd = -1;
int g_db_fetch_fd = -1;

#define DB_SUP_UPTIME_RESET_MS (10 * 60 * 1000)
#define DB_SUP_BACKOFF_MAX 60

static int64_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* The loader runs with the rights of loader-user, and karidns starts it as root: a binary others can replace would
 * be a way to root.  Checked at the start and again before every (re)start, and once more by the child on the open
 * file it then executes (P5: exec_file_open_checked() / exec_file_exec_fd(), shared with karicheck, dns_utils.c). */
static bool check_loader_path(const char *path, char *err, size_t errlen) {
  int fd = exec_file_open_checked(path, geteuid(), "database loader", "the user running karidns", err, errlen);
  if (fd < 0) return false;
  close(fd);
  return true;
}

bool db_sup_init(db_sup_t *s, const server_config_t *cfg, char *err, size_t errlen) {
  memset(s, 0, sizeof(*s));
  s->ctrl_fd = s->first_fd = s->first_fetch_fd = -1;
  s->backoff_s = 1;
  if (!cfg->database.enabled) return true;
  const database_config_t *db = &cfg->database;
  if (geteuid() == 0 && !db->loader_user && !db->loader_group) {
    snprintf(err, errlen, "options { database { loader-user \"...\"; } } is required when karidns is started as root "
                          "(the loader must not run as root)");
    return false;
  }
  if (!resolve_run_identity(db->loader_user, db->loader_group, &s->id, err, errlen)) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", err);
    snprintf(err, errlen, "database loader: %s", tmp);
    return false;
  }
  if (geteuid() == 0 && s->id.has_group && !s->id.has_user) {
    snprintf(err, errlen, "database loader: loader-group without loader-user would leave the loader running as root");
    return false;
  }
  snprintf(s->path, sizeof(s->path), "%s", db_loader_path(cfg));
  if (!check_loader_path(s->path, err, errlen)) return false;
  s->enabled = true;
  return true;
}

/* A fetch stream pair (D1a): f[0] for the loader, f[1] for the Backend (non-blocking: the Backend, in capability mode, never calls fcntl) */
static bool fetch_pair(int f[2]) {
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, f) != 0) return false;
  int fl = fcntl(f[1], F_GETFL, 0);
  if (fl < 0 || fcntl(f[1], F_SETFL, fl | O_NONBLOCK) != 0) {
    int e = errno;
    close(f[0]);
    close(f[1]);
    errno = e;
    return false;
  }
  return true;
}

bool db_sup_open_pairs(db_sup_t *s, char *err, size_t errlen) {
  if (!s->enabled) return true;
  int a[2], c[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, a) != 0) {
    snprintf(err, errlen, "cannot create the loader stream socketpair: %s", strerror(errno));
    return false;
  }
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, c) != 0) {
    snprintf(err, errlen, "cannot create the loader control socketpair: %s", strerror(errno));
    close(a[0]);
    close(a[1]);
    return false;
  }
  /* O_NONBLOCK is a property of the open file description, which travels with the descriptor: the Backend end is
   * made non-blocking here, so that the Backend (in capability mode, without CAP_FCNTL) never has to. */
  int fl = fcntl(a[1], F_GETFL, 0);
  int fl2 = fcntl(c[1], F_GETFL, 0);
  if (fl < 0 || fl2 < 0 || fcntl(a[1], F_SETFL, fl | O_NONBLOCK) != 0 || fcntl(c[1], F_SETFL, fl2 | O_NONBLOCK) != 0) {
    snprintf(err, errlen, "cannot set the Backend end of the loader sockets non-blocking: %s", strerror(errno));
    close(a[0]);
    close(a[1]);
    close(c[0]);
    close(c[1]);
    return false;
  }
  s->first_fd = a[0];
  s->ctrl_fd = c[0];
  g_db_stream_fd = a[1];
  g_db_ctrl_fd = c[1];
  /* D1a: the fetch stream.  A loader without it works as before (the Backend has no zone that needs a fetch yet), so a failure here is
   * not fatal: no pair, no `--fetch-fd`. */
  int f[2];
  if (fetch_pair(f)) {
    s->first_fetch_fd = f[0];
    g_db_fetch_fd = f[1];
  } else {
    syslog(LOG_WARNING, "[Manager] Cannot create the loader fetch stream: %m; the loader will run without it");
  }
  return true;
}

void db_sup_after_fork_supervisor(db_sup_t *s) {
  if (!s->enabled) return;
  if (g_db_stream_fd >= 0) close(g_db_stream_fd);
  if (g_db_ctrl_fd >= 0) close(g_db_ctrl_fd);
  if (g_db_fetch_fd >= 0) close(g_db_fetch_fd);
  g_db_stream_fd = g_db_ctrl_fd = g_db_fetch_fd = -1;
}

void db_sup_close_supervisor_ends(db_sup_t *s) {
  if (!s->enabled) return;
  if (s->first_fd >= 0) close(s->first_fd);
  if (s->first_fetch_fd >= 0) close(s->first_fetch_fd);
  if (s->ctrl_fd >= 0) close(s->ctrl_fd);
  s->first_fd = s->first_fetch_fd = s->ctrl_fd = -1;
}

/* Hand fds to the Backend over pair C (SCM_RIGHTS), one message: fds[0] is the stream, fds[1] (when nfd is 2) the fetch stream.  The
 * one-byte payload only gives the message a body. */
static bool send_fds(int ctrl, const int *fds, int nfd) {
  char byte = 'F';
  struct iovec iov = { &byte, 1 };
  union {
    struct cmsghdr h;
    char buf[CMSG_SPACE(sizeof(int) * 2)];
  } u;
  memset(&u, 0, sizeof(u));
  struct msghdr m;
  memset(&m, 0, sizeof(m));
  m.msg_iov = &iov;
  m.msg_iovlen = 1;
  m.msg_control = u.buf;
  m.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfd);
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfd);
  memcpy(CMSG_DATA(c), fds, sizeof(int) * (size_t)nfd);
  ssize_t n;
  do {
    n = sendmsg(ctrl, &m, MSG_DONTWAIT);
  } while (n < 0 && errno == EINTR);
  return n == 1;
}

/* The child between fork() and exec (design 1.2 step 4).  Never returns. */
static void child_exec(const db_sup_t *s, int stream_fd, int fetch_fd) {
  char msg[300];
  /* The parent blocked the signals across the fork: the dispositions are reset first, the mask is emptied last */
  /* An ignored disposition survives exec: a "pkill -HUP karidns" cannot kill a loader that has not installed its
   * handlers yet.  The loader handles SIGTERM / SIGINT itself. */
  signal(SIGHUP, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, SIG_DFL);
  signal(SIGINT, SIG_DFL);
  signal(SIGCHLD, SIG_DFL);
  sigset_t empty;
  sigemptyset(&empty);
  sigprocmask(SIG_SETMASK, &empty, NULL);

  const char *tz = getenv("TZ");
  char tzbuf[128] = "";
  if (tz) snprintf(tzbuf, sizeof(tzbuf), "%s", tz);

  /* stream on fd 3, the fetch stream (D1a) on fd 4, stdin / stdout on /dev/null, stderr kept, everything else closed */
  int hi = fcntl(stream_fd, F_DUPFD, 10);
  if (hi < 0) _exit(127);
  int hf = fetch_fd >= 0 ? fcntl(fetch_fd, F_DUPFD, 10) : -1;
  if (fetch_fd >= 0 && hf < 0) _exit(127);
  int dn = open("/dev/null", O_RDWR);
  if (dn >= 0) {
    dup2(dn, 0);
    dup2(dn, 1);
  }
  if (dup2(hi, 3) < 0) _exit(127);
  if (hf >= 0 && dup2(hf, 4) < 0) _exit(127);
  closefrom(hf >= 0 ? 5 : 4);

  /* P5: the file that is checked is the file that runs: opened and checked here (as the supervisor's user, before the
   * drop), executed by its descriptor after the drop */
  char err[256];
  int xfd = exec_file_open_checked(s->path, geteuid(), "database loader", "the user running karidns", err, sizeof(err));
  if (xfd < 0) {
    int n = snprintf(msg, sizeof(msg), "[Manager] %s\n", err);
    if (n > 0) (void)!write(2, msg, (size_t)n);
    _exit(127);
  }
  if (!apply_run_identity_id(&s->id, err, sizeof(err))) {
    int n = snprintf(msg, sizeof(msg), "[Manager] database loader: %s\n", err);
    if (n > 0) (void)!write(2, msg, (size_t)n);
    _exit(127);
  }
  /* Kept on purpose, although the server no longer leaves its own directory when it daemonizes: the loader runs as loader-user, which may
   * not be able to read the starting directory or options { directory }, and it must not hold that file system busy or drop a core file
   * there.  Everything it opens (database-file, conninfo-file) is an absolute path (config_set_base_cwd), so it does not need a cwd. */
  if (chdir("/") != 0) _exit(127);
  clearenv();
  if (tz) setenv("TZ", tzbuf, 1);
  char *argv[] = { (char *)"karidns-dbloader", (char *)"-s", (char *)"3", (char *)"--fetch-fd", (char *)"4", NULL };
  if (hf < 0) argv[3] = NULL;
  extern char **environ;
  exec_file_exec_fd(xfd, s->path, argv, environ);
  int n = snprintf(msg, sizeof(msg), "[Manager] cannot execute '%s': %s\n", s->path, strerror(errno));
  if (n > 0) (void)!write(2, msg, (size_t)n);
  _exit(127);
}

static void schedule_restart(db_sup_t *s, int64_t now) {
  s->restart_pending = true;
  s->restart_at_ms = now + (int64_t)s->backoff_s * 1000;
  syslog(LOG_NOTICE, "[Manager] Restarting the database loader in %u s", s->backoff_s);
  if (s->backoff_s < DB_SUP_BACKOFF_MAX) {
    s->backoff_s *= 2;
    if (s->backoff_s > DB_SUP_BACKOFF_MAX) s->backoff_s = DB_SUP_BACKOFF_MAX;
  }
}

bool db_sup_spawn(db_sup_t *s) {
  if (!s->enabled) return false;
  int64_t now = mono_ms();
  s->restart_pending = false;
  char err[300];
  int loader_fd = -1, backend_fd = -1, loader_fetch_fd = -1, backend_fetch_fd = -1;
  if (!check_loader_path(s->path, err, sizeof(err))) {
    syslog(LOG_ERR, "[Manager] %s", err);
    schedule_restart(s, now);
    return false;
  }
  if (s->first_fd >= 0) {
    loader_fd = s->first_fd;
    s->first_fd = -1;
    loader_fetch_fd = s->first_fetch_fd;      /* (the pair of db_sup_open_pairs(): the Backend already has its end) */
    s->first_fetch_fd = -1;
  } else {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) {
      syslog(LOG_ERR, "[Manager] Cannot create the loader stream socketpair: %m");
      schedule_restart(s, now);
      return false;
    }
    int fl = fcntl(sv[1], F_GETFL, 0);
    if (fl < 0 || fcntl(sv[1], F_SETFL, fl | O_NONBLOCK) != 0) {
      syslog(LOG_ERR, "[Manager] Cannot set the loader stream non-blocking: %m");
      close(sv[0]);
      close(sv[1]);
      schedule_restart(s, now);
      return false;
    }
    loader_fd = sv[0];
    backend_fd = sv[1];
    int fv[2];
    if (fetch_pair(fv)) {
      loader_fetch_fd = fv[0];
      backend_fetch_fd = fv[1];
    } else {
      syslog(LOG_WARNING, "[Manager] Cannot create the loader fetch stream: %m; the loader will run without it");
    }
  }
  gc_snapshot_wait_idle();   /* fork from a single thread (see dns_snapshot_rcu.c) */
  /* The child inherits the manager's flag-only handlers until child_exec() resets them: block the signals across the
   * fork so one that arrives meanwhile stays pending and is delivered with the default action after the reset */
  sigset_t fork_block, fork_orig;
  sigemptyset(&fork_block);
  sigaddset(&fork_block, SIGTERM);
  sigaddset(&fork_block, SIGINT);
  sigaddset(&fork_block, SIGHUP);
  sigaddset(&fork_block, SIGCHLD);
  sigprocmask(SIG_BLOCK, &fork_block, &fork_orig);
  pid_t pid = fork();
  if (pid == 0) {
    if (backend_fd >= 0) close(backend_fd);
    if (backend_fetch_fd >= 0) close(backend_fetch_fd);
    child_exec(s, loader_fd, loader_fetch_fd); /* resets the dispositions, then unblocks */
  }
  int fork_errno = errno;
  sigprocmask(SIG_SETMASK, &fork_orig, NULL);
  errno = fork_errno;
  if (pid < 0) {
    syslog(LOG_ERR, "[Manager] fork for the database loader failed: %m");
    close(loader_fd);
    if (loader_fetch_fd >= 0) close(loader_fetch_fd);
    if (backend_fd >= 0) close(backend_fd);
    if (backend_fetch_fd >= 0) close(backend_fetch_fd);
    schedule_restart(s, now);
    return false;
  }
  close(loader_fd);
  if (loader_fetch_fd >= 0) close(loader_fetch_fd);
  if (backend_fd >= 0) {
    /* The Backend turns the descriptors into its streams (and limits their rights).  If they cannot be sent, the Backend is
     * not listening any more; it is going down, and the loader will find its ends closed.  The fetch stream, when there is one,
     * is the second descriptor of the same message. */
    int fds[2] = { backend_fd, backend_fetch_fd };
    if (!send_fds(s->ctrl_fd, fds, backend_fetch_fd >= 0 ? 2 : 1))
      syslog(LOG_ERR, "[Manager] Cannot pass the loader stream to the Backend: %m");
    close(backend_fd);
    if (backend_fetch_fd >= 0) close(backend_fetch_fd);
  }
  s->pid = pid;
  s->started_ms = now;
  s->starts++;
  syslog(LOG_INFO, "[Manager] Database loader %s started (pid %d%s)", s->path, (int)pid,
         s->starts > 1 ? ", restart" : "");
  return true;
}

bool db_sup_child_exited(db_sup_t *s, pid_t pid, int status) {
  if (!s->enabled || s->pid == 0 || pid != s->pid) return false;
  int64_t now = mono_ms();
  if (WIFEXITED(status))
    syslog(WEXITSTATUS(status) == 0 ? LOG_NOTICE : LOG_ERR, "[Manager] Database loader (pid %d) exited (status=%d)",
           (int)pid, WEXITSTATUS(status));
  else if (WIFSIGNALED(status))
    syslog(LOG_ERR, "[Manager] Database loader (pid %d) killed by signal %d", (int)pid, WTERMSIG(status));
  s->pid = 0;
  if (now - s->started_ms >= DB_SUP_UPTIME_RESET_MS) s->backoff_s = 1;
  schedule_restart(s, now);
  return true;
}

int db_sup_timeout_ms(const db_sup_t *s) {
  if (!s->enabled || !s->restart_pending) return -1;
  int64_t left = s->restart_at_ms - mono_ms();
  if (left < 0) left = 0;
  if (left > 3600 * 1000) left = 3600 * 1000;
  return (int)left;
}

void db_sup_tick(db_sup_t *s) {
  if (s->enabled && s->restart_pending && mono_ms() >= s->restart_at_ms) db_sup_spawn(s);
}

void db_sup_signal(const db_sup_t *s, int sig) {
  if (s->enabled && s->pid > 0) kill(s->pid, sig);
}

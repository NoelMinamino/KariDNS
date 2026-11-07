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

/* ---- the messages of the loader: its stderr pipe, read line by line (see the header) ---- */

void db_logrd_init(db_logrd_t *rd) {
  memset(rd, 0, sizeof(*rd));
}

/* the report of the lines the rate limit dropped */
static void logrd_report(db_logrd_t *rd, db_logrd_sink_t sink, void *ud) {
  char msg[96];
  snprintf(msg, sizeof(msg), "[DB] %lu line(s) of the loader's output were not logged (more than %d per second)", rd->suppressed, DB_LOG_RATE_LINES);
  sink(LOG_WARNING, msg, ud);
  rd->suppressed = 0;
}

/* One complete line: "<N>text" (N = 0..7, the syslog priority; without it LOG_NOTICE), subject to the rate limit */
static void logrd_line(db_logrd_t *rd, int64_t now_ms, db_logrd_sink_t sink, void *ud) {
  if (rd->over) {
    memcpy(rd->buf + rd->len, "...", 3);
    rd->len += 3;
  }
  rd->buf[rd->len] = '\0';
  int prio = LOG_NOTICE;
  const char *text = rd->buf;
  if (rd->len >= 3 && text[0] == '<' && text[1] >= '0' && text[1] <= '7' && text[2] == '>') {
    prio = text[1] - '0';
    text += 3;
  }
  while (*text == ' ') text++;
  if (*text) {
    if (now_ms - rd->window_ms >= 1000 || now_ms < rd->window_ms) {     /* a new second (or the clock went back): report what the last one dropped */
      if (rd->suppressed) logrd_report(rd, sink, ud);
      rd->window_ms = now_ms;
      rd->window_lines = 0;
    }
    if (rd->window_lines < DB_LOG_RATE_LINES) {
      rd->window_lines++;
      sink(prio, text, ud);
    } else {
      rd->suppressed++;
    }
  }
  rd->len = 0;
  rd->over = false;
  rd->pending_cr = false;
}

/* text of the line: printable ASCII as it is, a tab as a space, everything else \xNN (the loader reads names out of a database; nothing it
 * writes may start a line of the log or hide in it) */
static void logrd_put(db_logrd_t *rd, unsigned char c) {
  char esc[4];
  const char *p = esc;
  size_t n = 1;
  if (c >= 0x20 && c < 0x7f) esc[0] = (char)c;
  else if (c == '\t') esc[0] = ' ';
  else {
    static const char hex[] = "0123456789abcdef";
    esc[0] = '\\';
    esc[1] = 'x';
    esc[2] = hex[c >> 4];
    esc[3] = hex[c & 15];
    n = 4;
  }
  if (rd->over) return;
  if (rd->len + n > DB_LOG_TEXT_MAX - 3) {      /* room for the "..." that marks a cut line */
    rd->over = true;
    return;
  }
  memcpy(rd->buf + rd->len, p, n);
  rd->len += n;
}

void db_logrd_feed(db_logrd_t *rd, const char *data, size_t n, int64_t now_ms, db_logrd_sink_t sink, void *ud) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)data[i];
    if (rd->pending_cr) {
      rd->pending_cr = false;
      if (c != '\n') logrd_put(rd, '\r');       /* (a CR that does not end a CRLF is text) */
    }
    if (c == '\n') logrd_line(rd, now_ms, sink, ud);
    else if (c == '\r') rd->pending_cr = true;
    else logrd_put(rd, c);
  }
}

void db_logrd_flush(db_logrd_t *rd, int64_t now_ms, db_logrd_sink_t sink, void *ud) {
  if (rd->pending_cr) logrd_put(rd, '\r');
  if (rd->len > 0 || rd->over) logrd_line(rd, now_ms, sink, ud);
  rd->pending_cr = false;
  if (rd->suppressed) logrd_report(rd, sink, ud);        /* nothing follows: say it now */
}

void db_logrd_tick(db_logrd_t *rd, int64_t now_ms, db_logrd_sink_t sink, void *ud) {
  if (rd->suppressed && (now_ms - rd->window_ms >= 1000 || now_ms < rd->window_ms)) logrd_report(rd, sink, ud);
}

void db_log_sink(int prio, const char *text, void *ud) {
  (void)ud;
  kdns_logc(LOGC_DATABASE, prio, text[0] == '[' ? "%s" : "[DB] %s", text);
}

static void log_close(db_sup_t *s) {
  if (s->log_fd >= 0) close(s->log_fd);
  s->log_fd = -1;
}

bool db_sup_log_read(db_sup_t *s) {
  if (s->log_fd < 0) return false;
  db_logrd_tick(&s->log_rd, mono_ms(), db_log_sink, NULL);        /* (a flood that stopped is reported when its second is over, not with the next line) */
  char buf[4096];
  size_t total = 0;
  while (total < DB_LOG_READ_BUDGET) {
    ssize_t r = read(s->log_fd, buf, sizeof(buf));
    if (r > 0) {
      total += (size_t)r;
      db_logrd_feed(&s->log_rd, buf, (size_t)r, mono_ms(), db_log_sink, NULL);
    } else if (r < 0 && errno == EINTR) {
      continue;
    } else if (r < 0 && errno == EAGAIN) {
      return false;
    } else {                                    /* the end of the stream (the loader, and everything it started, closed its stderr), or an error */
      db_logrd_flush(&s->log_rd, mono_ms(), db_log_sink, NULL);
      log_close(s);
      return false;
    }
  }
  return true;
}

/* The loader ended: what it left in the pipe is logged first, then the pipe goes (a restart makes a new one) */
void db_sup_log_finish(db_sup_t *s) {
  for (int i = 0; i < 4 && s->log_fd >= 0 && db_sup_log_read(s); i++) {
  }
  if (s->log_fd >= 0) {
    db_logrd_flush(&s->log_rd, mono_ms(), db_log_sink, NULL);
    log_close(s);
  }
}

int db_sup_wait_ms(const db_sup_t *s) {
  int t = db_sup_timeout_ms(s);
  if (s->log_fd >= 0 && (t < 0 || t > 1000)) t = 1000;
  return t;
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
  s->ctrl_fd = s->first_fd = s->first_fetch_fd = s->log_fd = -1;
  db_logrd_init(&s->log_rd);
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
  snprintf(s->path, sizeof(s->path), "%s", db_loader_path(cfg));
  snprintf(s->state_file, sizeof(s->state_file), "%s", cfg->database.loader_state_file ? cfg->database.loader_state_file : "");
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
static void child_exec(const db_sup_t *s, int stream_fd, int fetch_fd, int log_wfd) {
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

  /* stream on fd 3, the fetch stream (D1a) on fd 4, stdin / stdout on /dev/null, stderr the pipe to the supervisor (batch 14; no pipe: the
   * manager's own stderr, kept), everything else closed.  Each descriptor that is moved is first copied above 10, so that none of the
   * targets 0 .. 4 can be the source of a later copy. */
  int hi = fcntl(stream_fd, F_DUPFD, 10);
  if (hi < 0) _exit(127);
  int hw = log_wfd >= 0 ? fcntl(log_wfd, F_DUPFD, 10) : -1;
  if (log_wfd >= 0 && hw < 0) _exit(127);
  const char *pri = hw >= 0 ? "<3>" : "";      /* LOG_ERR for the pipe reader (what is written below before the exec) */
  int hf = fetch_fd >= 0 ? fcntl(fetch_fd, F_DUPFD, 10) : -1;
  if (fetch_fd >= 0 && hf < 0) _exit(127);
  int dn = open("/dev/null", O_RDWR);
  if (dn < 0 || dup2(dn, 0) < 0 || dup2(dn, 1) < 0) _exit(127);   /* (the loader must not keep the manager's stdin / stdout) */
  if (hw >= 0 && dup2(hw, 2) < 0) _exit(127);
  if (dup2(hi, 3) < 0) _exit(127);
  if (hf >= 0 && dup2(hf, 4) < 0) _exit(127);
  closefrom(hf >= 0 ? 5 : 4);

  /* P5: the file that is checked is the file that runs: opened and checked here (as the supervisor's user, before the
   * drop), executed by its descriptor after the drop */
  char err[256];
  int xfd = exec_file_open_checked(s->path, geteuid(), "database loader", "the user running karidns", err, sizeof(err));
  if (xfd < 0) {
    int n = snprintf(msg, sizeof(msg), "%s[Manager] %s\n", pri, err);
    if (n > 0) (void)!write(2, msg, (size_t)n);
    _exit(127);
  }
  if (!apply_run_identity_id(&s->id, err, sizeof(err))) {
    int n = snprintf(msg, sizeof(msg), "%s[Manager] database loader: %s\n", pri, err);
    if (n > 0) (void)!write(2, msg, (size_t)n);
    _exit(127);
  }
  /* Kept on purpose, although the server no longer leaves its own directory when it daemonizes: the loader runs as loader-user, which may
   * not be able to read the starting directory or options { directory }, and it must not hold that file system busy or drop a core file
   * there.  Everything it opens (database-file, conninfo-file) is an absolute path (config_set_base_cwd), so it does not need a cwd. */
  if (chdir("/") != 0) _exit(127);
  clearenv();
  if (tz) setenv("TZ", tzbuf, 1);
  char *argv[9] = { (char *)"karidns-dbloader", (char *)"-s", (char *)"3", NULL };
  int ac = 3;
  if (hf >= 0) {
    argv[ac++] = (char *)"--fetch-fd";
    argv[ac++] = (char *)"4";
  }
  if (s->state_file[0]) {                              /* D1a step 7: the loader keeps the hot list there (the Backend never names a path to it) */
    argv[ac++] = (char *)"--state-file";
    argv[ac++] = (char *)s->state_file;
  }
  if (hw >= 0) argv[ac++] = (char *)"--log-stderr";    /* its messages go down the pipe, not to syslog (the supervisor logs them) */
  argv[ac] = NULL;
  extern char **environ;
  exec_file_exec_fd(xfd, s->path, argv, environ);
  int n = snprintf(msg, sizeof(msg), "%s[Manager] cannot execute '%s': %s\n", pri, s->path, strerror(errno));
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
  /* batch 14: the loader's stderr, a pipe the supervisor reads (a new one for every start; the read end is close-on-exec and not shared with
   * the Backend or the routers, which were forked before the first start).  Without one the loader logs to syslog, as it did. */
  int log_rfd = -1, log_wfd = -1;
  {
    int lp[2];
    if (pipe2(lp, O_CLOEXEC) == 0) {
      int fl = fcntl(lp[0], F_GETFL, 0);
      if (fl >= 0 && fcntl(lp[0], F_SETFL, fl | O_NONBLOCK | (s->want_sigio ? O_ASYNC : 0)) == 0 &&
          (!s->want_sigio || fcntl(lp[0], F_SETOWN, getpid()) == 0)) {
        log_rfd = lp[0];
        log_wfd = lp[1];
      } else {
        close(lp[0]);
        close(lp[1]);
      }
    }
    if (log_rfd < 0) syslog(LOG_WARNING, "[Manager] Cannot create the pipe for the loader's messages: %m; the loader will log to syslog itself");
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
    if (log_rfd >= 0) close(log_rfd);
    child_exec(s, loader_fd, loader_fetch_fd, log_wfd); /* resets the dispositions, then unblocks */
  }
  int fork_errno = errno;
  sigprocmask(SIG_SETMASK, &fork_orig, NULL);
  errno = fork_errno;
  if (pid < 0) {
    syslog(LOG_ERR, "[Manager] fork for the database loader failed: %m");
    close(loader_fd);
    if (log_rfd >= 0) {
      close(log_rfd);
      close(log_wfd);
    }
    if (loader_fetch_fd >= 0) close(loader_fetch_fd);
    if (backend_fd >= 0) close(backend_fd);
    if (backend_fetch_fd >= 0) close(backend_fetch_fd);
    schedule_restart(s, now);
    return false;
  }
  close(loader_fd);
  if (loader_fetch_fd >= 0) close(loader_fetch_fd);
  if (log_rfd >= 0) {
    close(log_wfd);                  /* (the end of the pipe is seen when the loader, and everything it starts, has closed its stderr) */
    log_close(s);                    /* a pipe of an earlier start that was not drained: its loader is gone */
    db_logrd_init(&s->log_rd);
    s->log_fd = log_rfd;
  }
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
  db_sup_log_finish(s);                  /* the rest of its messages first */
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

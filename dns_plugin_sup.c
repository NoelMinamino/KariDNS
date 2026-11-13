/*
 * dns_plugin_sup.c - the plugins of type program zones: the supervisor in the manager process and the Backend's table (see dns_plugin_sup.h,
 * design 0.6.2 part B).
 *
 * The manager part runs in the manager, which has no thread of its own; the zone-version garbage collector (dns_snapshot_rcu.c) may have
 * started detached threads, so plug_spawn_process() waits for them (gc_snapshot_wait_idle()) before it forks, as db_sup_spawn() does: the
 * child is then a copy of a single-threaded process.
 *
 * The Backend part runs on the control thread (and, before the sandbox, on the main thread before the control thread is let go); the pool
 * threads only read the published table and call plug_backend_kill().
 */
#include "dns_plugin_sup.h"
#include "dns_utils.h"
#include "dns_server_internal.h"
#include "dns_epoch_rcu.h"
#include "dns_snapshot_rcu.h"
#include "dns_priv_sandbox.h"
#include "dns_query_engine.h"
#include "dns_log.h"
#include "dns_log_state.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#ifdef __FreeBSD__
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#endif

int g_plug_ctrl_fd = -1;

static int64_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* One record, with nfd descriptors (SCM_RIGHTS), on the non-blocking datagram socket of the pair.  A full socket buffer is waited for at most
 * wait_ms (0: not at all). */
static bool send_record(int fd, const plug_msg_t *m, const int *fds, int nfd, int wait_ms) {
  if (fd < 0) return false;
  struct iovec iov = { (void *)(uintptr_t)m, sizeof(*m) };
  union {
    struct cmsghdr h;
    char buf[CMSG_SPACE(sizeof(int) * PLUG_UP_NFDS)];
  } u;
  struct msghdr mh;
  memset(&mh, 0, sizeof(mh));
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  if (nfd > 0) {
    memset(&u, 0, sizeof(u));
    mh.msg_control = u.buf;
    mh.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfd);
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfd);
    memcpy(CMSG_DATA(c), fds, sizeof(int) * (size_t)nfd);
  }
  int64_t deadline = mono_ms() + wait_ms;
  for (;;) {
    ssize_t n = sendmsg(fd, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n == (ssize_t)sizeof(*m)) return true;
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == ENOBUFS)) {
      /* a datagram socket polls writable while the peer's queue is full (ENOBUFS): sleep a little instead of polling it */
      int64_t left = deadline - mono_ms();
      if (left <= 0) return false;
      (void)poll(NULL, 0, left > 10 ? 10 : (int)left);
      continue;
    }
    return false;
  }
}

/* ======================================================================================================================================
 * manager
 * ====================================================================================================================================== */

void plug_sup_init(plug_sup_t *s, const server_config_t *cfg, const char *config_path) {
  memset(s, 0, sizeof(*s));
  s->fd = -1;
  s->cfg = cfg;
  snprintf(s->config_path, sizeof(s->config_path), "%s", config_path ? config_path : "");
  for (int i = 0; i < PLUG_SLOTS; i++) s->s[i].pd = -1;
  s->tokens = PLUG_START_BURST;
  s->refill_ms = mono_ms();
}

bool plug_sup_open_pair(plug_sup_t *s, char *err, size_t errlen) {
  int p[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, p) != 0) {
    snprintf(err, errlen, "cannot create the plugin control socketpair: %s", strerror(errno));
    return false;
  }
  /* Room for a START of every slot: the Backend sends them at start-up, before the manager is in its loop */
  int sz = (int)(sizeof(plug_msg_t) * (PLUG_SLOTS + 16));
  for (int i = 0; i < 2; i++) {
    (void)setsockopt(p[i], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    (void)setsockopt(p[i], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    /* non-blocking: a property of the open file, so the Backend (in capability mode, without CAP_FCNTL) never sets it */
    int fl = fcntl(p[i], F_GETFL, 0);
    if (fl < 0 || fcntl(p[i], F_SETFL, fl | O_NONBLOCK) != 0) {
      snprintf(err, errlen, "cannot make the plugin control socket non-blocking: %s", strerror(errno));
      close(p[0]);
      close(p[1]);
      return false;
    }
  }
  s->fd = p[0];
  g_plug_ctrl_fd = p[1];
  return true;
}

void plug_sup_after_fork_manager(plug_sup_t *s) {
  if (g_plug_ctrl_fd >= 0) close(g_plug_ctrl_fd);
  g_plug_ctrl_fd = -1;
  if (s->fd < 0) return;
  /* SIGIO when the Backend writes: the manager's loop takes it with sigtimedwait() and calls plug_sup_tick() at once */
  int fl = fcntl(s->fd, F_GETFL, 0);
  if (fcntl(s->fd, F_SETOWN, getpid()) != 0 || fl < 0 || fcntl(s->fd, F_SETFL, fl | O_ASYNC) != 0)
    syslog(LOG_WARNING, "[Manager] Cannot arm SIGIO on the plugin control socket: %m; plugin requests wait for the next poll");
}

void plug_sup_close_manager_end(plug_sup_t *s) {
  if (s->fd >= 0) close(s->fd);
  s->fd = -1;
}

static bool m_send(plug_sup_t *s, const plug_msg_t *m, const int *fds, int nfd) {
  bool ok = send_record(s->fd, m, fds, nfd, 1000);
  if (!ok) syslog(LOG_ERR, "[Manager] Cannot send a plugin message to the Backend: %m");
  return ok;
}

static void m_kill(pid_t pid, int pd) {
#ifdef __FreeBSD__
  if (pd >= 0) {
    (void)pdkill(pd, SIGKILL);
    return;
  }
#else
  (void)pd;
#endif
  if (pid > 0) (void)kill(pid, SIGKILL);
}

/* A process that is no longer wanted: killed, and kept until it is collected */
static void m_stop_proc(plug_sup_t *s, pid_t pid, int pd) {
  if (pid <= 0) {
    if (pd >= 0) close(pd);
    return;
  }
  m_kill(pid, pd);
  if (s->nstopping < (int)(sizeof(s->stopping) / sizeof(s->stopping[0]))) {
    s->stopping[s->nstopping].pid = pid;
    s->stopping[s->nstopping].pd = pd;
    s->nstopping++;
  } else if (pd >= 0) {
    close(pd);   /* (no room: the last close of a process descriptor hands the process to init(8), which collects it) */
  }
}

static void m_free_exec(plug_mslot_t *sl) {
  if (sl->argv) {
    for (int i = 1; sl->argv[i]; i++) free(sl->argv[i]);
    free(sl->argv);
  }
  free(sl->path);
  free(sl->user);
  sl->argv = NULL;
  sl->path = sl->user = NULL;
}

/* The slot is given up: its process is stopped, everything it held is freed */
static void m_release(plug_sup_t *s, plug_mslot_t *sl) {
  if (sl->state == PLUG_MS_RUN) m_stop_proc(s, sl->pid, sl->pd);
  m_free_exec(sl);
  memset(sl, 0, sizeof(*sl));
  sl->pd = -1;
}

/* The program zone (view, zone) of cfg; *differs: there is one, but its settings have another fingerprint */
static const zone_config_t *m_find_zone(const server_config_t *cfg, const char *view, const char *zone, const char *fp, bool *differs) {
  *differs = false;
  if (!cfg) return NULL;
  for (const view_config_t *v = cfg->views; v; v = v->next) {
    if (strcasecmp(v->name ? v->name : "", view) != 0) continue;
    for (const zone_config_t *z = v->zones; z; z = z->next) {
      if (!z->type || strcasecmp(z->type, "program") != 0 || !z->domain || strcasecmp(z->domain, zone) != 0) continue;
      char zfp[PLUG_FP_MAX];
      compute_program_zone_fingerprint(z, zfp, sizeof(zfp));
      if (strcmp(zfp, fp) == 0) return z;
      *differs = true;
      return NULL;
    }
  }
  return NULL;
}

/* The configuration file again (the Backend asks for a zone, or settings, that the manager's copy does not have: a reload changed them) */
static void m_reread(plug_sup_t *s) {
  if (!s->config_path[0]) return;
  char *txt = read_entire_file(s->config_path, NULL, NULL);
  if (!txt) {
    syslog(LOG_ERR, "[Manager] Cannot read %s for the program zones: %m", s->config_path);
    return;
  }
  server_config_t *c = calloc(1, sizeof(*c));
  if (!c) {
    free(txt);
    return;
  }
  int rc = parse_named_conf_ext(txt, s->config_path, c);
  free(txt);
  if (rc != 0) {
    syslog(LOG_ERR, "[Manager] %s does not parse; the program zones it adds or changes are not started", s->config_path);
    free_server_config_fields(c);
    free(c);
    return;
  }
  if (s->own_cfg) {
    free_server_config_fields(s->own_cfg);
    free(s->own_cfg);
  }
  s->own_cfg = c;
  s->cfg = c;
}

static void m_refuse(plug_sup_t *s, uint32_t slot, const char *why) {
  plug_mslot_t *sl = &s->s[slot];
  syslog(LOG_ERR, "[Plugin] zone '%s' in view '%s': the plugin is not started: %s", sl->zone, sl->view, why);
  m_free_exec(sl);
  sl->state = PLUG_MS_REFUSED;
  plug_msg_t m;
  plug_msg_init(&m, PLUG_MSG_DOWN, slot, sl->gen, 0);
  m.flags = PLUG_DOWN_REFUSED;
  (void)m_send(s, &m, NULL, 0);
}

static char *dup_or_null(const char *p) {
  return p ? strdup(p) : NULL;
}

static void m_start_request(plug_sup_t *s, const plug_msg_t *m) {
  plug_mslot_t *sl = &s->s[m->slot];
  /* a repeat (the Backend got no answer) is ignored; a refused START is evaluated again when the Backend asks again (its backoff, a reload) */
  if (sl->gen == m->gen && sl->state != PLUG_MS_REFUSED) return;
  m_release(s, sl);                               /* an earlier use of the slot (its STOP was lost, or the Backend reuses it) */
  sl->gen = m->gen;
  snprintf(sl->zone, sizeof(sl->zone), "%s", m->zone);
  snprintf(sl->view, sizeof(sl->view), "%s", m->view);
  bool differs = false;
  const zone_config_t *z = m_find_zone(s->cfg, m->view, m->zone, m->fingerprint, &differs);
  /* the file again, at most once a second: a Backend cannot make the manager (root) parse it for every START.  The STARTs of a reload
   * come in one burst and are all answered from that one reading; one refused meanwhile is asked for again by the Backend's backoff. */
  int64_t now = mono_ms();
  if (!z && (s->rereads == 0 || now - s->reread_ms >= 1000)) {
    s->reread_ms = now;
    s->rereads++;
    m_reread(s);
    z = m_find_zone(s->cfg, m->view, m->zone, m->fingerprint, &differs);
  }
  if (!z) {
    m_refuse(s, m->slot, differs ? "its settings in the configuration file are not the ones the server loaded (changed again since the reload?)"
                                 : "it is not a program zone of the configuration file");
    return;
  }
  if (!s->cfg->allow_program_zones) {
    m_refuse(s, m->slot, "allow-program-zones is not yes");
    return;
  }
  const zone_ext_t *x = zext(z);
  if (!x->program_path) {
    m_refuse(s, m->slot, "the zone has no program");
    return;
  }
  /* the identity, resolved here (the child calls no getpwnam()); P4: never root, never the root group */
  uid_t uid = (uid_t)-1;
  gid_t gid = (gid_t)-1;
  if (!x->program_user) {
    if (geteuid() == 0) {
      m_refuse(s, m->slot, "program-user is not set and karidns runs as root; refusing to exec the plugin as root");
      return;
    }
  } else {
    if (!lookup_user_ids(x->program_user, &uid, &gid)) {
      m_refuse(s, m->slot, "program-user not found");
      return;
    }
    if (uid == 0 || gid == 0) {
      m_refuse(s, m->slot, "program-user is uid 0 or in group 0; refusing to run the plugin as root or in the root group");
      return;
    }
    if (geteuid() != 0 && uid != geteuid()) {
      m_refuse(s, m->slot, "program-user differs from the non-root user karidns runs as");
      return;
    }
  }
  int nargs = x->program_args_count > 62 ? 62 : x->program_args_count;
  sl->path = strdup(x->program_path);
  sl->user = dup_or_null(x->program_user);
  sl->argv = calloc((size_t)nargs + 2, sizeof(char *));
  bool ok = sl->path && sl->argv && (!x->program_user || sl->user);
  if (ok) {
    sl->argv[0] = sl->path;
    for (int i = 0; i < nargs && ok; i++) ok = (sl->argv[i + 1] = strdup(x->program_args[i])) != NULL;
  }
  if (!ok) {
    m_refuse(s, m->slot, "out of memory");
    return;
  }
  sl->uid = uid;
  sl->gid = gid;
  sl->state = PLUG_MS_WAIT;
  sl->start_at_ms = mono_ms();
  sl->backoff_s = 1;
}

/* The plugin of the slot has ended (or could not be started): try again after the backoff of the loader */
static void m_schedule(plug_mslot_t *sl, int64_t now) {
  if (sl->started_ms && now - sl->started_ms >= PLUG_UPTIME_RESET_MS) sl->backoff_s = 1;
  if (sl->backoff_s == 0) sl->backoff_s = 1;
  sl->state = PLUG_MS_WAIT;
  sl->start_at_ms = now + (int64_t)sl->backoff_s * 1000;
  syslog(LOG_NOTICE, "[Plugin] zone '%s' in view '%s': starting the plugin again in %u s", sl->zone, sl->view, sl->backoff_s);
  if (sl->backoff_s < PLUG_BACKOFF_MAX) {
    sl->backoff_s *= 2;
    if (sl->backoff_s > PLUG_BACKOFF_MAX) sl->backoff_s = PLUG_BACKOFF_MAX;
  }
}

/* stdin / stdout of the child: a descriptor that already has the number keeps it, without its close-on-exec flag */
static int child_fd_to(int fd, int target) {
  if (fd == target) return fcntl(fd, F_SETFD, 0);
  return dup2(fd, target) < 0 ? -1 : 0;
}

bool plug_spawn_process(const plug_mslot_t *m, plug_proc_t *out, char *err, size_t errlen) {
  out->pid = -1;
  out->pd = out->stdin_w = out->stdout_r = -1;
  if (!m->path || !m->argv) {
    snprintf(err, errlen, "no program path");
    return false;
  }
  /* S-1: an empty environment, but TZ (so that its time stamps match the server's).  Read before the fork (no getenv() in the child). */
  const char *tz = getenv("TZ");
  char tzenv[136] = "";
  char *envp[2] = { NULL, NULL };
  if (tz) {
    snprintf(tzenv, sizeof(tzenv), "TZ=%s", tz);
    envp[0] = tzenv;
  }
  /* The child writes its messages with write(2) from text made here */
  char msg_root[300], msg_user[300], msg_exec[300];
  int lr = snprintf(msg_root, sizeof(msg_root), "[FATAL] Zone '%s': 'program-user' is not set and karidns is running as root; "
                                                "refusing to exec plugin as root.\n", m->zone);
  int lu = snprintf(msg_user, sizeof(msg_user), "[FATAL] Zone '%s': program-user '%s' differs from the non-root user karidns runs as; "
                                                "refusing to exec plugin.\n", m->zone, m->user ? m->user : "");
  int le = snprintf(msg_exec, sizeof(msg_exec), "[ERROR] Zone '%s': cannot execute '%s'\n", m->zone, m->path);
  size_t root_len = lr < 0 ? 0 : (size_t)lr >= sizeof(msg_root) ? sizeof(msg_root) - 1 : (size_t)lr;
  size_t user_len = lu < 0 ? 0 : (size_t)lu >= sizeof(msg_user) ? sizeof(msg_user) - 1 : (size_t)lu;
  size_t exec_len = le < 0 ? 0 : (size_t)le >= sizeof(msg_exec) ? sizeof(msg_exec) - 1 : (size_t)le;

  int in_pipe[2], out_pipe[2];   /* in: karidns -> plugin stdin; out: plugin stdout -> karidns */
  if (pipe2(in_pipe, O_CLOEXEC) != 0) {
    snprintf(err, errlen, "pipe(): %s", strerror(errno));
    return false;
  }
  if (pipe2(out_pipe, O_CLOEXEC) != 0) {
    snprintf(err, errlen, "pipe(): %s", strerror(errno));
    close(in_pipe[0]);
    close(in_pipe[1]);
    return false;
  }
  gc_snapshot_wait_idle();
  int pd = -1;
#ifdef __FreeBSD__
  /* X-11: the Backend stops the plugin from inside the sandbox, so by its process descriptor (pdkill()), never by pid */
  pid_t pid = pdfork(&pd, PD_CLOEXEC);
#else
  pid_t pid = fork();
#endif
  if (pid < 0) {
    snprintf(err, errlen, "fork(): %s", strerror(errno));
    close(in_pipe[0]);
    close(in_pipe[1]);
    close(out_pipe[0]);
    close(out_pipe[1]);
    return false;
  }
  if (pid == 0) {
    /* The manager blocks its signals in its loop and has handlers for some: the plugin starts with the defaults and an empty mask (an
     * ignored disposition and the mask survive exec) */
    static const int sigs[] = { SIGPIPE, SIGHUP, SIGUSR1, SIGUSR2, SIGTERM, SIGINT, SIGCHLD, SIGIO, SIGALRM };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) signal(sigs[i], SIG_DFL);
    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);
    if (child_fd_to(in_pipe[0], STDIN_FILENO) != 0 || child_fd_to(out_pipe[1], STDOUT_FILENO) != 0) _exit(126);
    /* every other inherited descriptor (the manager's sockets, the loader's, the log files) is closed; stderr is inherited */
#ifdef __FreeBSD__
    closefrom(STDERR_FILENO + 1);
#else
    long maxfd = sysconf(_SC_OPEN_MAX);
    for (int fd = STDERR_FILENO + 1; fd < (maxfd > 0 ? maxfd : 1024); fd++) close(fd);
#endif
    /* never exec as root: no program-user while running as root is refused (the manager checked it before the fork; fail-closed here) */
    if (!m->user && geteuid() == 0) {
      (void)!write(STDERR_FILENO, msg_root, root_len);
      _exit(125);
    }
    if (m->user) {
      if (m->uid == 0 || m->gid == 0) _exit(126);
      if (geteuid() == 0) {
        if (setgroups(0, NULL) != 0 || setgid(m->gid) != 0 || setuid(m->uid) != 0) _exit(126);
      } else if (m->uid != geteuid() || m->uid != getuid()) {
        (void)!write(STDERR_FILENO, msg_user, user_len);
        _exit(126);
      }
    }
    /* the plugin runs in "/": it must not inherit the server's working directory (options { directory }, which program-user may not read) */
    if (chdir("/") != 0) _exit(126);
    execve(m->path, m->argv, envp);
    (void)!write(STDERR_FILENO, msg_exec, exec_len);
    _exit(127);
  }
  close(in_pipe[0]);
  close(out_pipe[1]);
  out->pid = pid;
  out->pd = pd;
  out->stdin_w = in_pipe[1];
  out->stdout_r = out_pipe[0];
  return true;
}

static void m_refill(plug_sup_t *s, int64_t now) {
  if (s->tokens >= PLUG_START_BURST || now < s->refill_ms) {   /* (full, or a refill time ahead of the clock: start counting now) */
    s->refill_ms = now;
    return;
  }
  int64_t add = (now - s->refill_ms) * PLUG_START_RATE / 1000;
  if (add <= 0) return;
  s->tokens = (unsigned)((int64_t)s->tokens + add > PLUG_START_BURST ? PLUG_START_BURST : (int64_t)s->tokens + add);
  s->refill_ms += add * 1000 / PLUG_START_RATE;
}

static void m_try_start(plug_sup_t *s, uint32_t slot, int64_t now) {
  plug_mslot_t *sl = &s->s[slot];
  plug_proc_t pr;
  char err[300];
  s->tokens--;
  if (!plug_spawn_process(sl, &pr, err, sizeof(err))) {
    syslog(LOG_ERR, "[Plugin] zone '%s' in view '%s': cannot start the plugin: %s", sl->zone, sl->view, err);
    sl->started_ms = 0;
    m_schedule(sl, now);
    return;
  }
  s->starts++;
  sl->seq++;
  sl->state = PLUG_MS_RUN;
  sl->pid = pr.pid;
  sl->pd = pr.pd;
  sl->started_ms = now;
  plug_msg_t m;
  plug_msg_init(&m, PLUG_MSG_UP, slot, sl->gen, sl->seq);
  m.pid = (int32_t)pr.pid;
  int fds[3] = { pr.stdin_w, pr.stdout_r, pr.pd };
  bool sent = m_send(s, &m, fds, PLUG_UP_NFDS);
  close(pr.stdin_w);                               /* the Backend has its copies */
  close(pr.stdout_r);
  syslog(LOG_INFO, "[Plugin] Spawned program zone '%s' (view '%s') -> pid=%d exec='%s' (start %u)", sl->zone, sl->view, (int)pr.pid,
         sl->path, sl->seq);
  logev_post(LOGC_GENERAL, 1, NULL, 0, "[Plugin] zone '%s' in view '%s': start %u (slot %u, generation %u) %s the Backend; %u start token(s) "
             "left, a restart would wait %u s", sl->zone, sl->view, sl->seq, (unsigned)slot, sl->gen, sent ? "handed to" : "could not be sent to",
             s->tokens, sl->backoff_s ? sl->backoff_s : 1);
  if (!sent) {
    m_stop_proc(s, sl->pid, sl->pd);
    sl->pid = 0;
    sl->pd = -1;
    m_schedule(sl, now);
  }
}

/* The plugin of a slot ended with status st */
static void m_ended(plug_sup_t *s, uint32_t slot, int st, int64_t now) {
  plug_mslot_t *sl = &s->s[slot];
  if (WIFSIGNALED(st))
    syslog(LOG_WARNING, "[Plugin] zone '%s' in view '%s': the plugin (pid %d) was killed by signal %d", sl->zone, sl->view, (int)sl->pid,
           WTERMSIG(st));
  else
    syslog(LOG_WARNING, "[Plugin] zone '%s' in view '%s': the plugin (pid %d) exited with status %d", sl->zone, sl->view, (int)sl->pid,
           WIFEXITED(st) ? WEXITSTATUS(st) : -1);
  if (sl->pd >= 0) close(sl->pd);
  sl->pd = -1;
  sl->pid = 0;
  plug_msg_t m;
  plug_msg_init(&m, PLUG_MSG_DOWN, slot, sl->gen, sl->seq);
  m.status = st;
  (void)m_send(s, &m, NULL, 0);
  m_schedule(sl, now);
}

void plug_sup_handle(plug_sup_t *s, const plug_msg_t *m) {
  plug_mslot_t *sl = &s->s[m->slot];
  switch (m->type) {
  case PLUG_MSG_START:
    m_start_request(s, m);
    break;
  case PLUG_MSG_STOP:
    if (sl->gen == m->gen) {
      if (sl->state == PLUG_MS_RUN)
        syslog(LOG_INFO, "[Plugin] zone '%s' in view '%s': stopping the plugin (pid %d)", sl->zone, sl->view, (int)sl->pid);
      m_release(s, sl);
    }
    break;
  case PLUG_MSG_KILL:
    if (sl->gen == m->gen && sl->seq == m->seq && sl->state == PLUG_MS_RUN) {
      syslog(LOG_WARNING, "[Plugin] zone '%s' in view '%s': program-max-failures reached; killing the plugin (pid %d)", sl->zone, sl->view,
             (int)sl->pid);
      m_kill(sl->pid, sl->pd);                    /* collected by plug_sup_tick(), then started again */
    }
    break;
  default:
    break;
  }
}

static void m_read(plug_sup_t *s) {
  static unsigned long refused;
  /* a plugin record, or (0.7 M2) a KLS1 record: the room for the larger one and a byte more, so that a longer datagram shows as MSG_TRUNC */
  static unsigned char buf[(sizeof(plug_msg_t) > KLS_MAX ? sizeof(plug_msg_t) : KLS_MAX) + 1];
  for (int k = 0; k < 4 * PLUG_SLOTS; k++) {
    union {
      struct cmsghdr h;
      char c[CMSG_SPACE(sizeof(int) * 4)];
    } u;
    struct iovec iov = { buf, sizeof(buf) };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = u.c;
    mh.msg_controllen = sizeof(u.c);
    ssize_t n = recvmsg(s->fd, &mh, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) return;                            /* nothing more (or the Backend is gone: the manager's loop sees its exit) */
    int nfds = recv_take_rights(&mh, NULL, 0);         /* the Backend sends no descriptor: whatever came is closed */
    if (n >= 4 && memcmp(buf, "KLS1", 4) == 0) {
      /* the Backend's debug level and logging runtime (dns_log_state.h): checked there as hostile input; cut or with descriptors: refused */
      if (!s->logstate || (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || nfds != 0 || !s->logstate(buf, (size_t)n, "Manager")) {
        if (refused++ < 16) syslog(LOG_ERR, "[Manager] A logging state from the Backend was refused");
      }
      continue;
    }
    plug_msg_t m;
    plug_err_t e = plug_check_from_backend(buf, (size_t)n, mh.msg_flags, nfds, &m);
    if (e != PLUG_OK) {
      if (refused++ < 16) syslog(LOG_ERR, "[Manager] A plugin message from the Backend was refused: %s", plug_err_text(e));
      continue;
    }
    plug_sup_handle(s, &m);
  }
}

void plug_sup_tick(plug_sup_t *s) {
  if (s->fd >= 0) m_read(s);
  int64_t now = mono_ms();
  for (uint32_t i = 0; i < PLUG_SLOTS; i++) {
    plug_mslot_t *sl = &s->s[i];
    if (sl->state != PLUG_MS_RUN || sl->pid <= 0) continue;
    int st = 0;
    pid_t w = waitpid(sl->pid, &st, WNOHANG);
    if (w == sl->pid || (w < 0 && errno == ECHILD)) m_ended(s, i, w == sl->pid ? st : 0, now);
  }
  for (int i = 0; i < s->nstopping;) {
    int st;
    pid_t w = waitpid(s->stopping[i].pid, &st, WNOHANG);
    if (w == s->stopping[i].pid || (w < 0 && errno == ECHILD)) {
      if (s->stopping[i].pd >= 0) close(s->stopping[i].pd);
      s->stopping[i] = s->stopping[--s->nstopping];
    } else {
      i++;
    }
  }
  m_refill(s, now);
  for (uint32_t i = 0; i < PLUG_SLOTS && s->tokens > 0; i++)
    if (s->s[i].state == PLUG_MS_WAIT && s->s[i].start_at_ms <= now) m_try_start(s, i, now);
}

int plug_sup_wait_ms(const plug_sup_t *s) {
  int64_t now = mono_ms();
  int64_t t = -1;
  bool running = s->nstopping > 0;
  for (int i = 0; i < PLUG_SLOTS; i++) {
    const plug_mslot_t *sl = &s->s[i];
    if (sl->state == PLUG_MS_RUN) running = true;
    if (sl->state != PLUG_MS_WAIT) continue;
    int64_t d = sl->start_at_ms - now;
    if (d < 0) d = 0;
    if (d == 0 && s->tokens == 0) d = 1000 / PLUG_START_RATE;   /* (the next token) */
    if (t < 0 || d < t) t = d;
  }
  if (running && (t < 0 || t > 250)) t = 250;
  return (int)t;
}

bool plug_sup_child_exited(plug_sup_t *s, pid_t pid, int status) {
  if (pid <= 0) return false;
  for (uint32_t i = 0; i < PLUG_SLOTS; i++)
    if (s->s[i].state == PLUG_MS_RUN && s->s[i].pid == pid) {
      m_ended(s, i, status, mono_ms());
      return true;
    }
  for (int i = 0; i < s->nstopping; i++)
    if (s->stopping[i].pid == pid) {
      if (s->stopping[i].pd >= 0) close(s->stopping[i].pd);
      s->stopping[i] = s->stopping[--s->nstopping];
      return true;
    }
  return false;
}

void plug_sup_stop_all(plug_sup_t *s) {
  for (int i = 0; i < PLUG_SLOTS; i++) {
    plug_mslot_t *sl = &s->s[i];
    if (sl->state == PLUG_MS_RUN) {
      m_kill(sl->pid, sl->pd);
      if (sl->pd >= 0) close(sl->pd);
    }
    m_free_exec(sl);
    memset(sl, 0, sizeof(*sl));
    sl->pd = -1;
  }
  for (int i = 0; i < s->nstopping; i++)
    if (s->stopping[i].pd >= 0) close(s->stopping[i].pd);
  s->nstopping = 0;
  if (s->own_cfg) {
    free_server_config_fields(s->own_cfg);
    free(s->own_cfg);
    s->own_cfg = NULL;
  }
}

/* ======================================================================================================================================
 * Backend
 * ====================================================================================================================================== */

_Atomic(program_plugin_table_t *) g_program_plugin_table;

#define PLUG_START_ANSWER_MS 10000   /* a START without an answer after this is sent again */

typedef struct {
  uint32_t gen;                 /* 0 = free */
  program_plugin_t *obj;        /* the slot's newest object: published, or (pending) a placeholder no reader has seen; NULL while retiring */
  bool pending;                 /* a replacement: its UP puts it in the place of `replaces` */
  int replaces;                 /* the slot of the plugin it replaces, -1 */
  bool answered;                /* the manager answered the START last sent (UP or DOWN) */
  bool first_answered;          /* it has answered one START of this slot (the start-up wait) */
  bool retiring;                /* the slot's plugin was replaced or its zone removed: its STOP goes after the readers (obj NULL) */
  int64_t start_sent_ms;        /* when the last START went, 0 = none outstanding */
  int64_t retry_at_ms;          /* a START to send again then (refused, or could not be sent), 0 = none */
  unsigned backoff_s;           /* the wait before the next retry */
} bslot_t;

typedef struct retire {
  struct retire *next;
  uint64_t epoch;
  program_plugin_t *obj;
  program_plugin_table_t *tab;
  int stop_slot;                /* the STOP to send once no reader can hold obj (the switch is made), -1 = none */
  uint32_t stop_gen;
} retire_t;

static bslot_t s_bs[PLUG_SLOTS];
static uint32_t s_next_gen = 1;
static retire_t *s_retire;
static bool s_ctrl_eof;

static void bk_send_simple(uint32_t type, uint32_t slot, uint32_t gen, uint32_t seq);

static void obj_free(program_plugin_t *p) {
  if (!p) return;
  if (p->stdin_fd >= 0) close(p->stdin_fd);
  if (p->stdout_fd >= 0) close(p->stdout_fd);
  if (p->proc_fd >= 0) close(p->proc_fd);
  pthread_mutex_destroy(&p->lock);
  free(p);
}

/* An object with the zone's settings and no process (dead) */
static program_plugin_t *obj_new(const zone_config_t *z, const char *view, uint32_t slot, uint32_t gen, const char *fp) {
  program_plugin_t *p = calloc(1, sizeof(*p));
  if (!p) return NULL;
  const zone_ext_t *x = zext(z);
  snprintf(p->domain, sizeof(p->domain), "%s", z->domain);
  snprintf(p->view_name, sizeof(p->view_name), "%s", view);
  p->slot = slot;
  p->gen = gen;
  p->pid = -1;
  p->proc_fd = p->stdin_fd = p->stdout_fd = -1;
  pthread_mutex_init(&p->lock, NULL);
  p->timeout_ms = x->program_timeout_ms > 0 ? x->program_timeout_ms : 2000;
  p->max_failures = x->program_max_failures > 0 ? x->program_max_failures : 5;
  p->disable_auto_tc_flag = x->disable_auto_tc_flag;
  p->reload_line = x->program_reload_line;
  snprintf(p->config_fingerprint, sizeof(p->config_fingerprint), "%s", fp);
  atomic_init(&p->reload_pending, false);
  atomic_init(&p->kill_owed, false);
  atomic_init(&p->consecutive_failures, 0);
  atomic_init(&p->dead, true);
  return p;
}

/* The object of start seq of the same slot: the settings of src, the descriptors fds */
static program_plugin_t *obj_up(const program_plugin_t *src, uint32_t seq, pid_t pid, const int *fds) {
  program_plugin_t *p = calloc(1, sizeof(*p));
  if (!p) return NULL;
  memcpy(p->domain, src->domain, sizeof(p->domain));
  memcpy(p->view_name, src->view_name, sizeof(p->view_name));
  memcpy(p->config_fingerprint, src->config_fingerprint, sizeof(p->config_fingerprint));
  p->slot = src->slot;
  p->gen = src->gen;
  p->seq = seq;
  p->pid = pid;
  p->stdin_fd = fds[0];
  p->stdout_fd = fds[1];
  p->proc_fd = PLUG_UP_NFDS > 2 ? fds[PLUG_UP_NFDS - 1] : -1;
  pthread_mutex_init(&p->lock, NULL);
  p->timeout_ms = src->timeout_ms;
  p->max_failures = src->max_failures;
  p->disable_auto_tc_flag = src->disable_auto_tc_flag;
  p->reload_line = src->reload_line;
  atomic_init(&p->reload_pending, false);
  atomic_init(&p->kill_owed, false);
  atomic_init(&p->consecutive_failures, 0);
  atomic_init(&p->dead, false);
  return p;
}

/* obj (and tab) are freed once no reader can hold them; then the STOP of (stop_slot, stop_gen) is sent, if any (stop_slot -1: none) */
static void retire_add_stop(program_plugin_t *obj, program_plugin_table_t *tab, uint64_t epoch, int stop_slot, uint32_t stop_gen) {
  if (!obj && !tab && stop_slot < 0) return;
  retire_t *r = malloc(sizeof(*r));
  if (!r) {
    /* no memory for the list: wait for the readers here (the control thread; a reader holds a plugin for at most program-timeout) */
    (void)rcu_writer_wait_until_safe(epoch, 0);
    obj_free(obj);
    free(tab);
    if (stop_slot >= 0) {
      bk_send_simple(PLUG_MSG_STOP, (uint32_t)stop_slot, stop_gen, 0);
      if (s_bs[stop_slot].retiring && s_bs[stop_slot].gen == stop_gen) memset(&s_bs[stop_slot], 0, sizeof(s_bs[stop_slot]));
    }
    return;
  }
  r->epoch = epoch;
  r->obj = obj;
  r->tab = tab;
  r->stop_slot = stop_slot;
  r->stop_gen = stop_gen;
  r->next = s_retire;
  s_retire = r;
}

static void retire_add(program_plugin_t *obj, program_plugin_table_t *tab, uint64_t epoch) {
  retire_add_stop(obj, tab, epoch, -1, 0);
}

/* The running plugin of slot i is replaced or its zone removed: the slot keeps its number (and the manager its process) until the STOP that
 * plug_backend_reap() sends after the readers are gone (design: "the old one is stopped after the switch") */
static void retire_slot(int i, uint64_t epoch) {
  program_plugin_t *o = s_bs[i].obj;
  uint32_t gen = s_bs[i].gen;
  memset(&s_bs[i], 0, sizeof(s_bs[i]));
  s_bs[i].gen = gen;
  s_bs[i].retiring = true;
  s_bs[i].replaces = -1;
  retire_add_stop(o, NULL, epoch, i, gen);
}

void plug_backend_reap(void) {
  for (retire_t **pp = &s_retire; *pp;) {
    retire_t *r = *pp;
    if (rcu_writer_is_safe(r->epoch)) {
      obj_free(r->obj);
      free(r->tab);
      if (r->stop_slot >= 0) {
        bk_send_simple(PLUG_MSG_STOP, (uint32_t)r->stop_slot, r->stop_gen, 0);
        bslot_t *b = &s_bs[r->stop_slot];
        if (b->retiring && b->gen == r->stop_gen) memset(b, 0, sizeof(*b));   /* (not when the slot was taken again meanwhile) */
      }
      *pp = r->next;
      free(r);
    } else {
      pp = &r->next;
    }
  }
}

static program_plugin_table_t *table_alloc(void) {
  program_plugin_table_t *t = malloc(sizeof(*t) + (size_t)PLUG_MAX_ZONES * sizeof(t->p[0]));
  if (t) t->count = 0;
  return t;
}

/* Publish t (NULL or empty: no plugin); the table it replaces is freed after the readers.  Never fails: the table was allocated before. */
static uint64_t publish_table(program_plugin_table_t *t) {
  if (t && t->count == 0) {
    free(t);
    t = NULL;
  }
  program_plugin_table_t *old = atomic_load_explicit(&g_program_plugin_table, memory_order_acquire);
  uint64_t epoch = rcu_writer_publish(&g_program_plugin_table, t);
  retire_add(NULL, old, epoch);
  return epoch ? epoch : 1;
}

/* The published objects, with from replaced by to (to == NULL: removed; from not there: to is added).  The retire epoch; 0 = nothing
 * changed (no memory, or the table would grow past PLUG_MAX_ZONES: logged) */
static uint64_t publish_replacing(program_plugin_t *from, program_plugin_t *to) {
  program_plugin_table_t *cur = atomic_load_explicit(&g_program_plugin_table, memory_order_acquire);
  bool found = false;
  for (int i = 0; cur && i < cur->count; i++)
    if (cur->p[i] == from) found = true;
  int n = (cur ? cur->count : 0) + (!found && to ? 1 : 0) - (found && !to ? 1 : 0);
  if (n > PLUG_MAX_ZONES) {
    syslog(LOG_ERR, "[Plugin] the table of the plugins would hold more than %d; zone '%s' is not added", PLUG_MAX_ZONES, to ? to->domain : "");
    return 0;
  }
  program_plugin_table_t *t = table_alloc();
  if (!t) return 0;
  for (int i = 0; cur && i < cur->count; i++) {
    if (cur->p[i] != from) t->p[t->count++] = cur->p[i];
    else if (to) t->p[t->count++] = to;
  }
  if (!found && to) t->p[t->count++] = to;
  return publish_table(t);
}

static bool bk_send(const plug_msg_t *m, int wait_ms) {
  return send_record(g_plug_ctrl_fd, m, NULL, 0, wait_ms);
}

static void bk_send_simple(uint32_t type, uint32_t slot, uint32_t gen, uint32_t seq) {
  plug_msg_t m;
  plug_msg_init(&m, type, slot, gen, seq);
  if (!bk_send(&m, type == PLUG_MSG_KILL ? 0 : 2000) && g_plug_ctrl_fd >= 0)
    syslog(LOG_ERR, "[Plugin] Cannot send a message to the manager (type %u, slot %u): %m", (unsigned)type, (unsigned)slot);
}

void plug_backend_expect(plug_expect_t *out, size_t n) {
  for (size_t i = 0; i < n && i < PLUG_SLOTS; i++) {
    bool live = s_bs[i].gen && s_bs[i].obj && !s_bs[i].retiring;   /* (a retiring slot takes no UP / DOWN) */
    out[i].gen = live ? s_bs[i].gen : 0;
    out[i].seq = live ? s_bs[i].obj->seq : 0;
  }
  for (size_t i = PLUG_SLOTS; i < n; i++) out[i].gen = out[i].seq = 0;
}

static int find_slot(const char *view, const char *domain, bool pending) {
  for (int i = 0; i < PLUG_SLOTS; i++) {
    const bslot_t *b = &s_bs[i];
    if (b->gen && b->obj && b->pending == pending && strcasecmp(b->obj->domain, domain) == 0 && strcasecmp(b->obj->view_name, view) == 0)
      return i;
  }
  return -1;
}

/* A free slot.  When every slot is in use, a retiring one is taken: its STOP goes now (the readers of its old plugin may still be there;
 * they get SERVFAIL).  With PLUG_SLOTS = 3 x PLUG_MAX_ZONES and at most one running and one pending plugin per zone, that needs a pile of
 * retirements from reloads within one grace period. */
static int alloc_slot(void) {
  for (int i = 0; i < PLUG_SLOTS; i++)
    if (s_bs[i].gen == 0) return i;
  for (int i = 0; i < PLUG_SLOTS; i++)
    if (s_bs[i].retiring) {
      bk_send_simple(PLUG_MSG_STOP, (uint32_t)i, s_bs[i].gen, 0);
      memset(&s_bs[i], 0, sizeof(s_bs[i]));   /* (its retire record still frees the object; its late STOP names the old generation) */
      return i;
    }
  return -1;
}

/* A replacement that is no longer wanted: STOP, and its placeholder freed (no reader has seen it) */
static void cancel_pending(int p) {
  bk_send_simple(PLUG_MSG_STOP, (uint32_t)p, s_bs[p].gen, 0);
  obj_free(s_bs[p].obj);
  memset(&s_bs[p], 0, sizeof(s_bs[p]));
}

static void bk_schedule_retry(int i, const char *why) {
  bslot_t *b = &s_bs[i];
  if (b->backoff_s == 0) b->backoff_s = 1;
  b->start_sent_ms = 0;
  b->retry_at_ms = mono_ms() + (int64_t)b->backoff_s * 1000;
  syslog(LOG_NOTICE, "[Plugin] zone '%s' in view '%s': %s; asking the manager again in %u s", b->obj->domain, b->obj->view_name, why,
         b->backoff_s);
  if (b->backoff_s < PLUG_BACKOFF_MAX) {
    b->backoff_s *= 2;
    if (b->backoff_s > PLUG_BACKOFF_MAX) b->backoff_s = PLUG_BACKOFF_MAX;
  }
}

/* Send (or send again: the manager takes the same generation again when it refused it) the START of slot i */
static void bk_start(int i) {
  bslot_t *b = &s_bs[i];
  const program_plugin_t *o = b->obj;
  plug_msg_t m;
  plug_msg_init(&m, PLUG_MSG_START, (uint32_t)i, b->gen, 0);
  snprintf(m.zone, sizeof(m.zone), "%s", o->domain);
  snprintf(m.view, sizeof(m.view), "%s", o->view_name);
  snprintf(m.fingerprint, sizeof(m.fingerprint), "%s", o->config_fingerprint);
  b->retry_at_ms = 0;
  b->answered = false;
  if (bk_send(&m, 2000)) {
    b->start_sent_ms = mono_ms();
  } else {
    syslog(LOG_ERR, "[Plugin] zone '%s' in view '%s': cannot ask the manager to start the plugin: %m (the zone answers SERVFAIL)", o->domain,
           o->view_name);
    bk_schedule_retry(i, "the START could not be sent");
  }
}

/* A slot whose plugin has never been up (refused, unanswered, not sent): a reload asks again at once (it is not "unchanged") */
static void bk_start_again_now(int i) {
  s_bs[i].backoff_s = 1;
  bk_start(i);
}

/* only_zone NULL: every program zone of cfg (a reload).  Else only the zone (only_view, only_zone), which is a program zone of cfg with a
 * plugin to run (the caller checked): every other plugin is left as it is, in the table and in the manager (karictl reload <zone>).
 * Returns what was done to that zone (PLUG_ZR_NOT_PROGRAM for a reload of all) */
static plug_zone_result_t plug_reconfigure(const server_config_t *cfg, const char *only_view, const char *only_zone) {
  plug_zone_result_t res = PLUG_ZR_NOT_PROGRAM;
  plug_backend_reap();
  /* 1. the table is allocated before anything is changed: a failure leaves everything as it was */
  program_plugin_table_t *t = table_alloc();
  if (!t) {
    syslog(LOG_ERR, "[Plugin] no memory for the table of the plugins; the program zones are left as they were");
    return PLUG_ZR_NOMEM;
  }
  static struct {
    const zone_config_t *z;
    const char *vn;
    char fp[PLUG_FP_MAX];
    int a;
    bool same;   /* the settings are those of the running plugin a (a restart asked for by name) */
  } want[PLUG_MAX_ZONES];
  int nwant = 0, skipped = 0, nzones = 0;
  int again[PLUG_MAX_ZONES], nagain = 0, reload[PLUG_MAX_ZONES], nreload = 0;
  bool keep[PLUG_SLOTS];
  memset(keep, 0, sizeof(keep));
  if (only_zone) {
    /* the plugins of every other zone, running or on their way, stay as they are */
    for (int i = 0; i < PLUG_SLOTS; i++) {
      const bslot_t *b = &s_bs[i];
      if (!b->gen || b->retiring || !b->obj) continue;
      if (strcasecmp(b->obj->domain, only_zone) == 0 && strcasecmp(b->obj->view_name, only_view) == 0) continue;
      keep[i] = true;
      if (!b->pending && t->count < PLUG_MAX_ZONES) t->p[t->count++] = b->obj;
    }
  }
  /* 2. what stays, and what needs a new plugin; no message yet */
  for (const view_config_t *v = cfg ? cfg->views : NULL; v; v = v->next) {
    const char *vn = v->name ? v->name : "";
    if (only_zone && strcasecmp(vn, only_view) != 0) continue;
    for (const zone_config_t *z = v->zones; z; z = z->next) {
      if (!z->type || strcasecmp(z->type, "program") != 0 || !z->domain) continue;
      if (only_zone && strcasecmp(z->domain, only_zone) != 0) continue;
      if (!cfg->allow_program_zones) {
        skipped++;
        continue;
      }
      if (!zext(z)->program_path) {
        syslog(LOG_ERR, "[Plugin] zone '%s' has type program but no 'program' path set; skipping (will SERVFAIL)", z->domain);
        continue;
      }
      if (nzones >= PLUG_MAX_ZONES) {   /* (the configuration parser refuses more; the table and want[] hold one per zone) */
        syslog(LOG_ERR, "[Plugin] more than %d program zones; zone '%s' answers SERVFAIL", PLUG_MAX_ZONES, z->domain);
        continue;
      }
      nzones++;
      char fp[PLUG_FP_MAX];
      compute_program_zone_fingerprint(z, fp, sizeof(fp));
      int a = find_slot(vn, z->domain, false), p = find_slot(vn, z->domain, true);
      if ((a >= 0 && keep[a]) || (p >= 0 && keep[p])) continue;   /* the same zone twice in one view (the parser refuses it) */
      const bool same_a = a >= 0 && strcmp(s_bs[a].obj->config_fingerprint, fp) == 0;
      /* A zone named by `karictl reload <zone>` whose plugin has the same settings and no RELOAD line can be made to read its data again
       * only by starting it again: a new plugin with these settings goes through the replacement path below */
      const bool restart = only_zone && same_a && s_bs[a].obj->seq != 0 && !s_bs[a].obj->reload_line;
      if (same_a && !restart) {
        /* Decision 4: unchanged settings leave the plugin alone; program-reload-line yes gets the RELOAD line.  One that has never been
         * up (refused, unanswered) is asked for again. */
        keep[a] = true;
        t->p[t->count++] = s_bs[a].obj;
        if (s_bs[a].obj->seq == 0) {
          again[nagain++] = a;
          res = PLUG_ZR_STARTING;
        } else {
          reload[nreload++] = a;
          res = PLUG_ZR_RELOAD_LINE;                /* (for a named zone: not `restart`, so it has program-reload-line yes) */
        }
        continue;                                 /* (a pending replacement is not kept: cancelled below) */
      }
      if (p >= 0 && strcmp(s_bs[p].obj->config_fingerprint, fp) == 0) {
        keep[p] = true;                           /* the replacement asked for by an earlier reload is still the right one */
        res = PLUG_ZR_PENDING;
        if (!s_bs[p].answered || s_bs[p].retry_at_ms) {
          again[nagain++] = p;
          res = PLUG_ZR_STARTING;
        }
        if (a >= 0) {
          keep[a] = true;
          t->p[t->count++] = s_bs[a].obj;
        }
        continue;
      }
      want[nwant].z = z;
      want[nwant].vn = vn;
      memcpy(want[nwant].fp, fp, sizeof(fp));
      want[nwant].a = a;
      want[nwant].same = same_a;
      nwant++;
      if (a >= 0) {
        keep[a] = true;                           /* the running plugin keeps answering until the new one is up */
        t->p[t->count++] = s_bs[a].obj;
      }
    }
  }
  if (skipped)
    syslog(LOG_ERR, "[Plugin] %d zone(s) with type \"program\" but allow-program-zones is not yes; they answer SERVFAIL", skipped);
  /* 3. replacements no longer wanted go at once (no reader has seen them); their slots are free before new ones are taken */
  for (int i = 0; i < PLUG_SLOTS; i++)
    if (s_bs[i].gen && !s_bs[i].retiring && !keep[i] && s_bs[i].pending) cancel_pending(i);
  bool gone[PLUG_SLOTS];
  for (int i = 0; i < PLUG_SLOTS; i++) gone[i] = s_bs[i].gen && !s_bs[i].retiring && !keep[i];
  /* 4. the new plugins (and the STARTs) */
  for (int w = 0; w < nwant; w++) {
    int ns = alloc_slot();
    program_plugin_t *o = NULL;
    uint32_t gen = s_next_gen++;
    if (s_next_gen == 0) s_next_gen = 1;
    if (ns >= 0) o = obj_new(want[w].z, want[w].vn, (uint32_t)ns, gen, want[w].fp);
    if (!o) {
      syslog(LOG_ERR, "[Plugin] zone '%s' in view '%s': no slot or no memory for its plugin; the next reload tries again", want[w].z->domain,
             want[w].vn);
      if (only_zone) res = PLUG_ZR_NOMEM;
      continue;
    }
    if (only_zone) res = want[w].same ? PLUG_ZR_RESTARTING : want[w].a >= 0 ? PLUG_ZR_REPLACING : PLUG_ZR_STARTING;
    memset(&s_bs[ns], 0, sizeof(s_bs[ns]));
    s_bs[ns].gen = gen;
    s_bs[ns].obj = o;
    s_bs[ns].pending = want[w].a >= 0;
    s_bs[ns].replaces = want[w].a;
    s_bs[ns].backoff_s = 1;
    if (want[w].a < 0) t->p[t->count++] = o;
    bk_start(ns);
  }
  /* 5. the switch; the plugins of removed zones are stopped once no reader can hold them */
  uint64_t epoch = publish_table(t);
  for (int i = 0; i < PLUG_SLOTS; i++) {
    if (!gone[i]) continue;
    syslog(LOG_INFO, "[Plugin] zone '%s' in view '%s' is gone: stopping its plugin", s_bs[i].obj->domain, s_bs[i].obj->view_name);
    retire_slot(i, epoch);
  }
  for (int k = 0; k < nagain; k++) bk_start_again_now(again[k]);
  for (int k = 0; k < nreload; k++) program_plugin_request_reload(s_bs[reload[k]].obj);
  return res;
}

void plug_backend_reconfigure(const server_config_t *cfg) {
  (void)plug_reconfigure(cfg, NULL, NULL);
}

plug_zone_result_t plug_backend_reconfigure_zone(const server_config_t *cfg, const char *view, const char *zone) {
  if (!cfg || !view || !zone) return PLUG_ZR_NOT_PROGRAM;
  const zone_config_t *found = NULL;
  for (const view_config_t *v = cfg->views; v && !found; v = v->next) {
    if (strcasecmp(v->name ? v->name : "", view) != 0) continue;
    for (const zone_config_t *z = v->zones; z; z = z->next)
      if (z->type && strcasecmp(z->type, "program") == 0 && z->domain && strcasecmp(z->domain, zone) == 0) {
        found = z;
        break;
      }
  }
  if (!found) return PLUG_ZR_NOT_PROGRAM;
  if (!cfg->allow_program_zones || !zext(found)->program_path) return PLUG_ZR_DISABLED;
  return plug_reconfigure(cfg, view, zone);
}

void plug_backend_start(const server_config_t *cfg) {
#ifdef __FreeBSD__
  if (g_plug_ctrl_fd >= 0) {
    cap_rights_t r;
    cap_rights_init(&r, CAP_SEND, CAP_RECV, CAP_EVENT);
    if (cap_rights_limit(g_plug_ctrl_fd, &r) != 0 && errno != ENOSYS) {
      syslog(LOG_CRIT, "[Plugin] cap_rights_limit on the plugin control socket failed: %m");
      backend_exit(EXIT_FAILURE);
    }
  }
#endif
  int count = 0;
  for (const view_config_t *v = cfg->views; v; v = v->next)
    for (const zone_config_t *z = v->zones; z; z = z->next)
      if (z->type && strcasecmp(z->type, "program") == 0) count++;
  if (count == 0) return;
  if (!cfg->allow_program_zones) {
    syslog(LOG_CRIT, "[Plugin] %d zone(s) with type \"program\" found but allow-program-zones is not set to yes in options{}. Refusing to start.",
           count);
    fprintf(stderr, "[FATAL] type \"program\" zones require 'allow-program-zones yes;' in options{}.\n");
    backend_exit(EXIT_FAILURE); /* O-15: the Backend's threads are running */
  }
  syslog(LOG_WARNING, "[Plugin] %d program zone(s) enabled. This is a TEST-ONLY feature; do not use in production.", count);
  if (g_plug_ctrl_fd < 0) syslog(LOG_ERR, "[Plugin] no channel to the manager: the program zones answer SERVFAIL");
  plug_backend_reconfigure(cfg);
}

/* A record from the manager that passed plug_check_from_manager(), with its descriptors (already limited) */
static void bk_up(const plug_msg_t *m, int *fds) {
  bslot_t *b = &s_bs[m->slot];
  program_plugin_t *o = obj_up(b->obj, m->seq, (pid_t)m->pid, fds);
  if (!o) {
    for (int i = 0; i < PLUG_UP_NFDS; i++) close(fds[i]);
    syslog(LOG_ERR, "[Plugin] zone '%s': no memory for the plugin that was started; asking the manager to start it again", b->obj->domain);
    bk_send_simple(PLUG_MSG_KILL, m->slot, m->gen, m->seq);
    return;
  }
  program_plugin_t *old = b->pending ? (b->replaces >= 0 && s_bs[b->replaces].gen ? s_bs[b->replaces].obj : NULL) : b->obj;
  uint64_t epoch = publish_replacing(old, o);
  if (epoch == 0) {
    obj_free(o);
    syslog(LOG_ERR, "[Plugin] zone '%s': no memory for the table of the plugins; asking the manager to start the plugin again", b->obj->domain);
    bk_send_simple(PLUG_MSG_KILL, m->slot, m->gen, m->seq);
    return;
  }
  if (b->pending) {
    if (old) retire_slot(b->replaces, epoch);     /* the switch is made: the old plugin is stopped after the readers */
    obj_free(b->obj);                             /* the placeholder, never published */
    b->pending = false;
    b->replaces = -1;
  } else {
    retire_add(old, NULL, epoch);
  }
  b->obj = o;
  b->answered = b->first_answered = true;
  b->start_sent_ms = b->retry_at_ms = 0;
  b->backoff_s = 1;
  syslog(LOG_INFO, "[Plugin] zone '%s' in view '%s': the plugin is up (pid %d, start %u)", o->domain, o->view_name, (int)o->pid,
         (unsigned)o->seq);
}

static void bk_down(const plug_msg_t *m) {
  bslot_t *b = &s_bs[m->slot];
  b->answered = b->first_answered = true;
  b->start_sent_ms = 0;
  if (m->flags & PLUG_DOWN_REFUSED) {
    /* the manager would not start it (the configuration file changed again, no memory, program-user unknown, ...): asked again with the
     * backoff, and at the next reload.  A replacement that is refused leaves the running plugin serving. */
    syslog(LOG_ERR, "[Plugin] zone '%s' in view '%s': the manager did not start the plugin (see its log); %s", b->obj->domain,
           b->obj->view_name, b->pending ? "the running plugin keeps serving" : "the zone answers SERVFAIL");
    bk_schedule_retry((int)m->slot, "refused");
    return;
  }
  if (!b->pending) {
    atomic_store_explicit(&b->obj->dead, true, memory_order_release);
    syslog(LOG_WARNING, "[Plugin] zone '%s' in view '%s': the plugin (pid %d) has ended; SERVFAIL until the manager has started it again",
           b->obj->domain, b->obj->view_name, (int)b->obj->pid);
  }
}

/* Rule 2: the descriptors of an UP are limited at once, before any other use: write + poll + fcntl for stdin, read + poll + fcntl for
 * stdout, pdkill for the process descriptor.  The pipes must be pipes.  false: not usable (the caller closes them). */
static bool plug_limit_up_fds(const int *fds) {
#ifdef __FreeBSD__
  struct stat st;
  cap_rights_t rw, rr, rp;
  cap_rights_init(&rw, CAP_WRITE, CAP_EVENT, CAP_FCNTL);
  cap_rights_init(&rr, CAP_READ, CAP_EVENT, CAP_FCNTL);
  cap_rights_init(&rp, CAP_PDKILL);
  return fstat(fds[0], &st) == 0 && S_ISFIFO(st.st_mode) && fstat(fds[1], &st) == 0 && S_ISFIFO(st.st_mode) &&
         cap_rights_limit(fds[0], &rw) == 0 && cap_rights_limit(fds[1], &rr) == 0 && cap_rights_limit(fds[2], &rp) == 0;
#else
  struct stat st;
  return fstat(fds[0], &st) == 0 && S_ISFIFO(st.st_mode) && fstat(fds[1], &st) == 0 && S_ISFIFO(st.st_mode);
#endif
}

void plug_backend_apply(const void *buf, size_t len, int msg_flags, int *fds, int nfds) {
  static unsigned long refused;
  plug_expect_t ex[PLUG_SLOTS];
  plug_backend_expect(ex, PLUG_SLOTS);
  plug_msg_t m;
  int nkeep = nfds < 8 ? nfds : 8;
  plug_err_t e = plug_check_from_manager(buf, len, msg_flags, nfds, ex, PLUG_SLOTS, &m);
  if (e != PLUG_OK) {
    for (int i = 0; i < nkeep; i++) close(fds[i]);
    if (refused++ < 16) syslog(LOG_ERR, "[Plugin] A message from the manager was refused: %s", plug_err_text(e));
    return;
  }
  if (m.type == PLUG_MSG_UP && !plug_limit_up_fds(fds)) {
    /* a valid record with descriptors that are not what they must be: a failed start.  The manager kills it and starts it again with the
     * backoff; the slot counts as answered (the start-up does not wait for it) */
    for (int i = 0; i < PLUG_UP_NFDS; i++) close(fds[i]);
    bslot_t *b = &s_bs[m.slot];
    b->answered = b->first_answered = true;
    b->start_sent_ms = 0;
    syslog(LOG_ERR, "[Plugin] zone '%s': the descriptors of the started plugin are refused (not pipes, or cannot be limited); asking the manager "
                    "to start it again", b->obj->domain);
    bk_send_simple(PLUG_MSG_KILL, m.slot, m.gen, m.seq);
    return;
  }
  if (m.type == PLUG_MSG_UP) bk_up(&m, fds);
  else bk_down(&m);
}

void plug_backend_handle_ctrl(void) {
  if (g_plug_ctrl_fd < 0 || s_ctrl_eof) return;
  for (int k = 0; k < 4 * PLUG_SLOTS; k++) {
    unsigned char buf[sizeof(plug_msg_t) + 1];
    union {
      struct cmsghdr h;
      char c[CMSG_SPACE(sizeof(int) * 8)];
    } u;
    struct iovec iov = { buf, sizeof(buf) };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = u.c;
    mh.msg_controllen = sizeof(u.c);
    ssize_t n = recvmsg(g_plug_ctrl_fd, &mh, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        s_ctrl_eof = true;
        syslog(LOG_ERR, "[Plugin] The plugin control socket failed (%m); the program zones are no longer restarted");
      }
      return;
    }
    /* (an empty datagram is no end of the stream on this socket: it is refused below, as any record of the wrong size) */
    int fds[8];
    int nfds = recv_take_rights(&mh, fds, 8);
    plug_backend_apply(buf, (size_t)n, mh.msg_flags, fds, nfds);
  }
}

void plug_backend_wait_startup(int ms) {
  if (g_plug_ctrl_fd < 0) return;
  int64_t deadline = mono_ms() + ms;
  for (;;) {
    int waiting = 0;
    for (int i = 0; i < PLUG_SLOTS; i++)
      if (s_bs[i].gen && s_bs[i].obj && !s_bs[i].first_answered) waiting++;
    if (waiting == 0) return;
    int64_t left = deadline - mono_ms();
    if (left <= 0 || s_ctrl_eof) {
      syslog(LOG_WARNING, "[Plugin] %d plugin(s) are not up after %d ms; their zones answer SERVFAIL until they are", waiting, ms);
      return;
    }
    struct pollfd p = { .fd = g_plug_ctrl_fd, .events = POLLIN, .revents = 0 };
    (void)poll(&p, 1, left > 100 ? 100 : (int)left);
    plug_backend_handle_ctrl();
    plug_backend_timer();                         /* (a START that could not be sent is tried again) */
  }
}

/* The KILL of p.  pdkill() stops the process at once where there is a process descriptor; the record tells the manager (and is the only
 * way without pdfork()).  A record that does not go (a full socket) stays owed and plug_backend_timer() sends it again. */
static void bk_send_kill(program_plugin_t *p) {
  plug_msg_t m;
  plug_msg_init(&m, PLUG_MSG_KILL, p->slot, p->gen, p->seq);
  if (bk_send(&m, 0)) atomic_store_explicit(&p->kill_owed, false, memory_order_release);
}

void plug_backend_kill(program_plugin_t *p) {
#ifdef __FreeBSD__
  /* X-11: inside the sandbox kill(pid) is ECAPMODE (and a SIGTRAP with PROC_TRAPCAP); the process descriptor it came with can */
  if (p->proc_fd >= 0 && p->pid > 0) (void)pdkill(p->proc_fd, SIGKILL);
#endif
  if (p->seq == 0) return;
  atomic_store_explicit(&p->kill_owed, true, memory_order_release);
  bk_send_kill(p);
}

void plug_backend_timer(void) {
  plug_backend_reap();
  int64_t now = mono_ms();
  for (int i = 0; i < PLUG_SLOTS; i++) {
    bslot_t *b = &s_bs[i];
    if (!b->gen || !b->obj || b->retiring) continue;
    if (b->retry_at_ms && b->retry_at_ms <= now) bk_start(i);                                      /* refused, or not sent */
    else if (!b->answered && b->start_sent_ms && now - b->start_sent_ms >= PLUG_START_ANSWER_MS) bk_start(i);   /* no answer */
  }
  program_plugin_table_t *t = atomic_load_explicit(&g_program_plugin_table, memory_order_acquire);
  for (int i = 0; t && i < t->count; i++)
    if (atomic_load_explicit(&t->p[i]->kill_owed, memory_order_acquire)) bk_send_kill(t->p[i]);
}

void program_plugins_set_for_test(program_plugin_t *arr, int n) {
  static program_plugin_table_t *t;
  if (!t) t = malloc(sizeof(*t) + 8 * sizeof(t->p[0]));
  if (!t || n <= 0) {
    atomic_store_explicit(&g_program_plugin_table, NULL, memory_order_release);
    return;
  }
  t->count = n > 8 ? 8 : n;
  for (int i = 0; i < t->count; i++) t->p[i] = &arr[i];
  atomic_store_explicit(&g_program_plugin_table, t, memory_order_release);
}

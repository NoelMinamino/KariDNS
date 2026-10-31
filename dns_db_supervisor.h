#ifndef DNS_DB_SUPERVISOR_H
#define DNS_DB_SUPERVISOR_H

/*
 * dns_db_supervisor.h - the supervisor (manager process) side of karidns-dbloader (beta design 1.2, milestone B4a).
 *
 * Only used when the configuration has an options { database { } } block.  The supervisor
 *   - resolves loader-user / loader-group once and checks loader-path (db_sup_init(), before daemonize()),
 *   - creates pair A (SOCK_STREAM, the KDB1 stream) and pair C (SOCK_SEQPACKET, supervisor -> Backend fd passing)
 *     before the Backend is forked (db_sup_open_pairs()); the Backend keeps its ends, the supervisor the other ones,
 *   - forks and execs the loader, and restarts it when it ends: a loader exit is not fatal.  The restarts wait
 *     1, 2, 4 ... 60 s (back to 1 s after 10 minutes of uptime); a restart makes a new pair A and hands the Backend
 *     end over pair C with SCM_RIGHTS.
 * The loader runs without Capsicum (design 1.3); everything it sends is untrusted for the Backend.
 */

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include "dns_config_parser.h"
#include "dns_priv_sandbox.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

typedef struct {
  bool enabled;
  pid_t pid;                /* 0: not running */
  int ctrl_fd;              /* the supervisor's end of pair C */
  int first_fd;             /* the loader's end of the first pair A, until the first spawn uses it */
  int first_fetch_fd;       /* the same for the fetch stream (D1a), -1 = the loader has none */
  run_identity_t id;        /* loader-user / loader-group, resolved once */
  char path[PATH_MAX];      /* loader-path */
  char state_file[PATH_MAX]; /* loader-state-file (D1a step 7): the loader keeps the hot list there; "" = none */
  int64_t started_ms;       /* CLOCK_MONOTONIC */
  int64_t restart_at_ms;
  unsigned backoff_s;       /* the wait after the next exit */
  bool restart_pending;
  unsigned starts;          /* how many times the loader was started */
} db_sup_t;

/* The Backend's ends of pair A and pair C: set by db_sup_open_pairs() before the fork, used by the Backend
 * (-1 without a database block). */
extern int g_db_stream_fd;
extern int g_db_ctrl_fd;
/* D1a: the Backend's end of the second stream, the fetch stream (design 6.1; -1 when it could not be made).  The loader gets its end as
 * file descriptor 4 (`--fetch-fd 4`); a restart makes a new pair, and the Backend end goes over pair C together with the first stream's. */
extern int g_db_fetch_fd;

/* Resolve loader-user / loader-group (root: loader-user or loader-group is required; non-root: they must be the
 * running user) and check loader-path (a regular executable file, owned by root or by the running user, not
 * writable by group or others).  false: err says why. */
bool db_sup_init(db_sup_t *s, const server_config_t *cfg, char *err, size_t errlen);
/* Create pair A and pair C.  Call before forking the Backend. */
bool db_sup_open_pairs(db_sup_t *s, char *err, size_t errlen);
/* In the supervisor after forking the Backend: close the Backend's ends. */
void db_sup_after_fork_supervisor(db_sup_t *s);
/* In a child of the supervisor that must not hold the loader link (Backend: closes the supervisor's ends; frontend
 * routers: closes both of the supervisor's ends). */
void db_sup_close_supervisor_ends(db_sup_t *s);
/* Start the loader (the first time with the pair made by db_sup_open_pairs, later with a new pair whose Backend end
 * goes over pair C).  false: could not be started; a restart has been scheduled. */
bool db_sup_spawn(db_sup_t *s);
/* A child of the supervisor ended.  true: it was the loader (logged, restart scheduled); false: another child. */
bool db_sup_child_exited(db_sup_t *s, pid_t pid, int status);
/* Milliseconds until the scheduled restart, or -1 when none is pending. */
int db_sup_timeout_ms(const db_sup_t *s);
/* Restart the loader when its time has come. */
void db_sup_tick(db_sup_t *s);
/* Send sig to the loader if it runs. */
void db_sup_signal(const db_sup_t *s, int sig);

#endif /* DNS_DB_SUPERVISOR_H */

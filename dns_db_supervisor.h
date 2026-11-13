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

/* The messages of the loader (batch 14).  The loader's stderr is a pipe made for every start (the loader gets --log-stderr and writes
 * "<N>[DB] text" lines, N = the syslog priority; 0.7 M2: "<7:L>[DB] text" is a message at debug level L, 1..99, which a reader that knows only
 * "<N>" logs as text at LOG_NOTICE).  The supervisor reads it without blocking, line by line, and logs every line in the
 * `database` category (kdns_logc(LOGC_DATABASE, ...)), so that `logging { category database { ...; }; }` decides where it goes.  The bytes are
 * untrusted: db_logrd_t cuts a line at DB_LOG_TEXT_MAX, escapes everything but printable ASCII, accepts any end of line / end of stream, and
 * forwards at most DB_LOG_RATE_LINES lines per second (the rest are counted and reported once).  A read takes at most DB_LOG_READ_BUDGET
 * bytes, so a loader that floods the pipe cannot keep the supervisor from its signals; the loader blocks on a full pipe meanwhile. */
#define DB_LOG_TEXT_MAX 512        /* the longest text of a line (after the "<N>" priority), escaped; a longer line ends in "..." */
#define DB_LOG_RATE_LINES 50       /* lines forwarded per second */
#define DB_LOG_READ_BUDGET 65536   /* bytes taken from the pipe by one db_sup_log_read() */

/* prio: the syslog priority; level: 0, or the debug level of a "<7:L>" line (0.7 M2) */
typedef void (*db_logrd_sink_t)(int prio, int level, const char *text, void *ud);
typedef struct {
  char buf[DB_LOG_TEXT_MAX + 1];
  size_t len;
  bool over;                /* the line is longer than DB_LOG_TEXT_MAX: the rest of it is dropped */
  bool pending_cr;          /* the last byte was a CR: dropped when a LF follows, else it is part of the text */
  int64_t window_ms;        /* start of the second being counted */
  unsigned window_lines;
  unsigned long suppressed; /* lines dropped by the rate limit since the last report */
} db_logrd_t;

void db_logrd_init(db_logrd_t *rd);
/* Take n bytes read from the loader; every complete line goes to sink(prio, text, ud).  now_ms: any monotonic clock (the rate limit). */
void db_logrd_feed(db_logrd_t *rd, const char *data, size_t n, int64_t now_ms, db_logrd_sink_t sink, void *ud);
/* Time passes without bytes: the report of the lines the rate limit dropped is made once their second is over. */
void db_logrd_tick(db_logrd_t *rd, int64_t now_ms, db_logrd_sink_t sink, void *ud);
/* The end of the stream: a line without its newline is forwarded, and a pending report of suppressed lines is made. */
void db_logrd_flush(db_logrd_t *rd, int64_t now_ms, db_logrd_sink_t sink, void *ud);
/* The sink of the supervisor: kdns_logc(LOGC_DATABASE, prio, ...) (a debug line: logev_post() at its level), with "[DB] " in front of a text that does not start with a "[Prefix]". */
void db_log_sink(int prio, int level, const char *text, void *ud);
/* The "<N>" or "<7:L>" in front of a line (see the top): its length, 0 = none (then *prio LOG_NOTICE, *level 0).  text is NUL-terminated. */
size_t db_logrd_prefix(const char *text, int *prio, int *level);

typedef struct {
  bool enabled;
  pid_t pid;                /* 0: not running */
  int log_fd;               /* the read end of the loader's stderr pipe, non-blocking; -1 = none */
  db_logrd_t log_rd;
  bool want_sigio;          /* the manager takes SIGIO (blocked, with a handler that does nothing) and calls db_sup_log_read() for it: the pipe is armed with O_ASYNC */
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
/* How long the manager may wait for a signal: db_sup_timeout_ms(), and at most one second while the loader's pipe is open (the backstop for
 * a SIGIO that did not come); -1 = no limit. */
int db_sup_wait_ms(const db_sup_t *s);
/* Read what the loader has written (at most DB_LOG_READ_BUDGET bytes) and log the lines.  true: the budget ran out, more may be waiting (call
 * again after the signals have been looked at).  The end of the stream closes the pipe. */
bool db_sup_log_read(db_sup_t *s);
/* The loader has ended: log what is left in its pipe and close it. */
void db_sup_log_finish(db_sup_t *s);
/* Restart the loader when its time has come. */
void db_sup_tick(db_sup_t *s);
/* Send sig to the loader if it runs. */
void db_sup_signal(const db_sup_t *s, int sig);

#endif /* DNS_DB_SUPERVISOR_H */

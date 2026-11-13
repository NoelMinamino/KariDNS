#ifndef DNS_PLUGIN_SUP_H
#define DNS_PLUGIN_SUP_H

/*
 * dns_plugin_sup.h - the plugins of type program zones (0.6.2, design part B): the supervisor in the manager process, and the Backend's
 * table of the running plugins.
 *
 * Manager (outside capability mode, as the karidns-dbloader supervisor, dns_db_supervisor.c):
 *   - creates the pair (AF_UNIX, SOCK_DGRAM: see dns_plugin_msg.h) before the Backend is forked (plug_sup_open_pair()); the Backend keeps g_plug_ctrl_fd;
 *   - on START it looks the zone up in its own copy of the configuration (and reads the configuration file again when the zone, or the
 *     fingerprint of its settings, is not in that copy), forks and execs the plugin with the steps of the earlier Backend code (program-user,
 *     closefrom, chdir /, an empty environment but TZ, the signals reset, no exec as root), and hands the Backend the write end of its stdin,
 *     the read end of its stdout and its process descriptor (UP, SCM_RIGHTS);
 *   - a plugin that ends (or that the Backend asks it to KILL: program-max-failures) is started again after 1, 2, 4 ... 60 s (back to 1 s
 *     after 10 minutes up), the loader's backoff; DOWN tells the Backend at once.  All starts take a token of a bucket of PLUG_START_BURST,
 *     refilled at PLUG_START_RATE per second, so a plugin that exits at once cannot make the manager fork without pause;
 *   - STOP ends a plugin for good.
 * The path, the arguments and the user always come from the manager's configuration, never from the Backend: the Backend names a zone and
 * the fingerprint it expects, and a mismatch is refused.
 *
 * Backend: the table of the plugins (program_plugin_table_t) is published through RCU (rcu_writer_publish(), read by the pool threads in
 * their read section); it is rebuilt on the control thread only (startup, reload, UP / DOWN), never on the query path (Rule 1).  An object
 * that is replaced (a restart, a changed zone, a removed zone) is freed, and its descriptors closed, once no reader can hold it.
 */

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include "dns_config_parser.h"
#include "dns_plugin_msg.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#define PLUG_START_BURST PLUG_MAX_ZONES /* a start of every zone at once */
#define PLUG_START_RATE 4               /* starts per second once the burst is used */
#define PLUG_BACKOFF_MAX 60
#define PLUG_UPTIME_RESET_MS (10 * 60 * 1000)

/* ---- manager ---- */

enum { PLUG_MS_FREE = 0, PLUG_MS_WAIT, PLUG_MS_RUN, PLUG_MS_REFUSED };

typedef struct {
  uint32_t gen;            /* the Backend's START number; 0 = free */
  uint32_t seq;            /* starts made for (slot, gen) */
  int state;
  pid_t pid;
  int pd;                  /* the process descriptor (FreeBSD), -1 = none */
  int64_t started_ms, start_at_ms;
  unsigned backoff_s;
  char zone[PLUG_ZONE_MAX], view[PLUG_VIEW_MAX];
  /* what is executed, copied from the configuration at START */
  char *path;
  char **argv;             /* argv[0] = path, NULL-terminated */
  char *user;              /* program-user, NULL = none */
  uid_t uid;
  gid_t gid;
} plug_mslot_t;

typedef struct {
  pid_t pid;
  int pd;
} plug_stopping_t;

typedef struct {
  int fd;                  /* the manager's end of the pair, -1 = none */
  char config_path[PATH_MAX];
  const server_config_t *cfg;  /* the configuration the manager looks zones up in (the start-up one, or own_cfg) */
  server_config_t *own_cfg;    /* a configuration read again by the manager (heap), NULL = none */
  plug_mslot_t s[PLUG_SLOTS];
  plug_stopping_t stopping[PLUG_SLOTS];
  int nstopping;
  unsigned tokens;
  int64_t refill_ms;
  unsigned long starts;    /* forks made (tests, the log) */
  int64_t reread_ms;       /* the last reading of the configuration file (at most one a second) */
  unsigned long rereads;
  /* 0.7 M2: what the manager does with a KLS1 record (the Backend's debug level and logging runtime, dns_log_state.h) that comes on the pair;
   * dns_log.c klog_state_apply() in the server, NULL (the record is refused) where dns_log.c is not linked */
  bool (*logstate)(const uint8_t *rec, size_t len, const char *who);
} plug_sup_t;

/* The Backend's end of the pair (-1 when it could not be made, or in the manager after the fork) */
extern int g_plug_ctrl_fd;

void plug_sup_init(plug_sup_t *s, const server_config_t *cfg, const char *config_path);
/* Create the pair; call before forking the Backend.  false: err says why */
bool plug_sup_open_pair(plug_sup_t *s, char *err, size_t errlen);
/* In the manager after the fork: close the Backend's end; arm SIGIO on the manager's end (the loop takes it) */
void plug_sup_after_fork_manager(plug_sup_t *s);
/* In a child of the manager that must not hold the pair (the Backend, the routers) */
void plug_sup_close_manager_end(plug_sup_t *s);
/* Read the Backend's messages, collect the plugins that ended, start those whose time has come */
void plug_sup_tick(plug_sup_t *s);
/* How long the manager may sleep: the next start, at most 250 ms while a plugin runs (its end is noticed by a poll), -1 = no limit */
int plug_sup_wait_ms(const plug_sup_t *s);
/* A child of the manager ended (waitpid(-1)): true when it was a plugin (without pdfork(), where the plugins are ordinary children) */
bool plug_sup_child_exited(plug_sup_t *s, pid_t pid, int status);
/* Shut down: kill every plugin */
void plug_sup_stop_all(plug_sup_t *s);
/* (tests) handle one record as if it came from the Backend */
void plug_sup_handle(plug_sup_t *s, const plug_msg_t *m);

/* The process of one plugin, made by the manager (exported for the unit tests).  false: nothing was started (err says why), nothing leaked */
typedef struct {
  pid_t pid;
  int pd;
  int stdin_w;
  int stdout_r;
} plug_proc_t;
bool plug_spawn_process(const plug_mslot_t *m, plug_proc_t *out, char *err, size_t errlen);

/* ---- Backend ---- */

/* At start-up, before capability mode: limit the pair, refuse (exit) program zones without allow-program-zones, publish the table and send
 * a START for every program zone */
void plug_backend_start(const server_config_t *cfg);
/* After the sandbox is entered, before the queries are let in: handle the answers of the manager for at most ms milliseconds, until every
 * zone of the start-up configuration has had one */
void plug_backend_wait_startup(int ms);
/* A reload published cfg: new zones get a plugin, a changed fingerprint a new one (the old one goes when the new one is up), removed zones'
 * plugins are stopped, the others are left as they are and get the RELOAD line when they have program-reload-line yes */
void plug_backend_reconfigure(const server_config_t *cfg);
/* What `karictl reload <zone>` did to the plugin of one program zone */
typedef enum {
  PLUG_ZR_NOT_PROGRAM = 0,  /* cfg has no program zone of that name in that view: nothing was done */
  PLUG_ZR_DISABLED,         /* it has one, but allow-program-zones is not yes or the zone has no program: no plugin is run */
  PLUG_ZR_NOMEM,            /* no memory or no slot: the plugin was left as it was */
  PLUG_ZR_RELOAD_LINE,      /* the settings are unchanged and the zone has program-reload-line yes: the RELOAD line was written (or is owed) */
  PLUG_ZR_REPLACING,        /* the settings changed: a new plugin was asked for; the running one answers until it is up */
  PLUG_ZR_RESTARTING,       /* the settings are the same, there is no program-reload-line: a new plugin with them was asked for, as for a replacement */
  PLUG_ZR_STARTING,         /* a plugin that never came up (or has no running one) was asked for again */
  PLUG_ZR_PENDING           /* a replacement with these settings is already on its way */
} plug_zone_result_t;
/* plug_backend_reconfigure() for the one program zone (view, zone) of cfg, with the same rules except that a plugin with the same settings
 * and no program-reload-line is replaced by a new one (the operator named the zone: it must read its data again); every other plugin is
 * left as it is.
 * The control thread only (as plug_backend_reconfigure()) */
plug_zone_result_t plug_backend_reconfigure_zone(const server_config_t *cfg, const char *view, const char *zone);
/* The pair is readable (the control thread's kqueue): handle what the manager sent */
void plug_backend_handle_ctrl(void);
/* Free the objects no reader can hold any more (the control thread's timer) */
void plug_backend_reap(void);
/* The control thread's timer (every second): plug_backend_reap(); a START that was refused or could not be sent is sent again when its
 * backoff (1, 2, 4 ... 60 s) is over, one without an answer after 10 s; an owed KILL is sent again */
void plug_backend_timer(void);
/* program-max-failures was reached (the thread of the exchange, under the plugin's lock): kill the process; the manager restarts it */
struct program_plugin;
void plug_backend_kill(struct program_plugin *p);
/* (tests) install n plugins as the table, without the manager; n == 0 empties it */
void program_plugins_set_for_test(struct program_plugin *arr, int n);
/* (tests) apply one record as if it came from the manager, with the descriptors fds[0 .. nfds-1] */
void plug_backend_apply(const void *buf, size_t len, int msg_flags, int *fds, int nfds);
/* (tests) the expectations the Backend checks the manager's records against */
void plug_backend_expect(plug_expect_t *out, size_t n);

#endif /* DNS_PLUGIN_SUP_H */

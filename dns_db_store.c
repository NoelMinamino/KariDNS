/*
 * dns_db_store.c - the zone store in the server: the directory, write-through of installed zones, attach of zones that are out of memory (see dns_db_store.h).
 */
#include "dns_db_store.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(__FreeBSD__)
#include <sys/capsicum.h>
#include <sys/event.h>
#endif
#include <openssl/sha.h>

#include "dns_db_ingest.h"
#include "dns_db_stream.h"
#include "dns_epoch_rcu.h"
#include "dns_log.h"
#include "dns_park.h"
#include "dns_server_internal.h"
#include "dns_snapshot_rcu.h"
#include "dns_store_status.h"
#include "dns_utils.h"
#include "dns_zone_image.h"

#define DBS_NAME_MAX 258          /* a store name (at most STORE_NAME_MAX) with its dot and NUL: the canonical name of a zref_t */
_Static_assert(DBS_NAME_MAX >= STORE_NAME_MAX + 3, "DBS_NAME_MAX");
_Static_assert(ZREF_NAME_SIZE >= STORE_NAME_MAX + 3, "ZREF_NAME_SIZE");
#define DBS_CFGID 8                        /* 0.7 WP7b: bytes of the cursor's identity that are the hash of the view's configuration; the loader's own identity follows (at most STORE_IDENT_MAX - 8 bytes) */
#define DBS_GUARD_PCT 20u                  /* decision D7: the sweep of a pass deletes nothing when it would delete more than this share of the view's zones ... */
#define DBS_GUARD_MIN 1000u                /* ... and more than this many */

static int64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000ll + ts.tv_nsec;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the directory                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

static struct {
  int dirfd, lockfd;
} g_dir = { -1, -1 };

const char *db_store_dir_of(const database_config_t *db, bool *is_default) {
  if (is_default) *is_default = false;
  if (!db || !db->enabled || db->store_none) return NULL;
  if (db->store_dir) return db->store_dir;
  if (is_default) *is_default = true;
  return KARIDNS_DB_DEFAULT_STORE_DIR;
}

int db_store_dir_fd(void) { return g_dir.dirfd; }

void db_store_frontend_close(void) {
  if (g_dir.dirfd >= 0) close(g_dir.dirfd);
  if (g_dir.lockfd >= 0) close(g_dir.lockfd);
  g_dir.dirfd = g_dir.lockfd = -1;
}

/* the part of `path` before its last '/' ("." when there is none, "/" for a file in the root) */
static void parent_of(const char *path, char *out, size_t cap) {
  const char *slash = strrchr(path, '/');
  if (!slash) snprintf(out, cap, ".");
  else if (slash == path) snprintf(out, cap, "/");
  else snprintf(out, cap, "%.*s", (int)(slash - path), path);
}

/* The lock file.  The directory belongs to the user the server runs as (or to root), so that user can put anything under the name "lock" before the start: a hard link to
 * a file of root's (the start, as root, would give it to the run user), a FIFO (opening it would wait for ever), a link, a file of another user.  Nothing that is there is
 * trusted: it is opened without following a link and without waiting (O_NOFOLLOW, O_NONBLOCK), and used only when it is a plain file with one name that belongs to root
 * or to the run user; anything else loses the name (unlinkat() of the name only: what a hard link points to is not touched) and the file is made again with O_EXCL, which
 * cannot open what exists.  Only a file that this call made, or one that passed the checks above, is given to the run user (fchown() on the descriptor that was checked).
 * Returns the descriptor, or -1 with `why` filled. */
static int lock_file_open(int dfd, bool privileged, uid_t uid, gid_t gid, char *why, size_t whylen, const char *path) {
  for (int attempt = 0; attempt < 4; attempt++) {
    const int fl = O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    bool made = true;
    int fd = openat(dfd, "lock", fl | O_CREAT | O_EXCL, 0600);
    if (fd < 0 && errno == EEXIST) {
      made = false;
      fd = openat(dfd, "lock", fl);
      if (fd < 0 && errno == ENOENT) continue;                          /* (it went away between the two calls) */
    }
    if (fd >= 0) {
      struct stat st;
      uid_t owner_ok = privileged ? 0 : geteuid();
      bool fine = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
                  (made || st.st_uid == owner_ok || (privileged && uid != (uid_t)-1 && st.st_uid == uid));
      if (fine) {
        if (privileged && (uid != (uid_t)-1 || gid != (gid_t)-1) && (st.st_uid != uid || st.st_gid != gid) && fchown(fd, uid, gid) != 0) {
          snprintf(why, whylen, "cannot give the lock file in %s to the user the server runs as: %s", path, strerror(errno));
          close(fd);
          return -1;
        }
        return fd;
      }
      close(fd);
    } else if (errno != ELOOP && errno != ENXIO && errno != EMLINK) {
      snprintf(why, whylen, "cannot open the lock file in %s: %s", path, strerror(errno));
      return -1;
    }
    /* something that is not ours is under the name: the name goes, a new file is made */
    syslog(LOG_WARNING, "[Store] the lock file in %s is not a plain file of root or of the user the server runs as (a link, a FIFO, another owner); it is replaced", path);
    if (unlinkat(dfd, "lock", 0) != 0 && errno != ENOENT) {
      snprintf(why, whylen, "cannot replace the lock file in %s: %s", path, strerror(errno));
      return -1;
    }
  }
  snprintf(why, whylen, "cannot make the lock file in %s (something keeps taking its name)", path);
  return -1;
}

bool db_store_frontend_open(const database_config_t *db, bool privileged, uid_t uid, gid_t gid, char *msg, size_t msglen) {
  if (msg && msglen) msg[0] = '\0';
  db_store_frontend_close();
  bool dflt = false;
  const char *path = db_store_dir_of(db, &dflt);
  if (!path) return true;                                       /* no database block, or `store none;` */
  int dfd = -1, lfd = -1;
  char why[320] = "";
  struct stat st;
  char parent[PATH_MAX];
  parent_of(path, parent, sizeof(parent));
  if (dflt && (stat(parent, &st) != 0 || !S_ISDIR(st.st_mode))) {
    snprintf(msg, msglen, "the zone store is off: its default directory %s needs %s, which does not exist (give `store \"<directory>\";` in the database block to keep one elsewhere, or `store none;`)",
             path, parent);
    return true;
  }
  if (mkdir(path, 0700) != 0 && errno != EEXIST) {
    snprintf(why, sizeof(why), "cannot make the directory %s: %s", path, strerror(errno));
    goto bad;
  }
  /* the directory itself, not what a symbolic link in the last place points to; every check below is on this descriptor */
  dfd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dfd < 0) {
    snprintf(why, sizeof(why), "cannot open the directory %s: %s", path, strerror(errno));
    goto bad;
  }
  if (fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode)) {
    snprintf(why, sizeof(why), "%s is not a directory", path);
    goto bad;
  }
  if (privileged) {
    /* a directory that root or the user the server runs as owns, that nobody else can write in; it is handed to that user (the same rule as karicheck's) */
    char own[200];
    if (!store_dir_owner_ok(&st, true, uid, geteuid(), own, sizeof(own))) {
      snprintf(why, sizeof(why), "the directory %s %s", path, own);
      goto bad;
    }
    if ((uid != (uid_t)-1 || gid != (gid_t)-1) && fchown(dfd, uid, gid) != 0) {
      snprintf(why, sizeof(why), "cannot give the directory %s to the user the server runs as: %s", path, strerror(errno));
      goto bad;
    }
    if ((st.st_mode & 0777) != 0700 && fchmod(dfd, 0700) != 0) {
      snprintf(why, sizeof(why), "cannot set the mode of the directory %s: %s", path, strerror(errno));
      goto bad;
    }
  } else {
    char own[200];
    if (!store_dir_owner_ok(&st, false, (uid_t)-1, geteuid(), own, sizeof(own))) {
      snprintf(why, sizeof(why), "the directory %s %s", path, own);
      goto bad;
    }
    if ((st.st_mode & 077) != 0 && fchmod(dfd, 0700) != 0) {
      snprintf(why, sizeof(why), "the directory %s can be used by group or others and its mode cannot be changed: %s", path, strerror(errno));
      goto bad;
    }
  }
  /* one server per store: a lock file inside it, held for as long as the descriptor is open (the Backend inherits it) */
  lfd = lock_file_open(dfd, privileged, uid, gid, why, sizeof(why), path);
  if (lfd < 0) goto bad;
  if (flock(lfd, LOCK_EX | LOCK_NB) != 0) {
    snprintf(why, sizeof(why), errno == EWOULDBLOCK ? "the directory %s is in use by another server" : "cannot lock the directory %s: %s", path, strerror(errno));
    goto bad;
  }
  g_dir.dirfd = dfd;
  g_dir.lockfd = lfd;
  return true;
bad:
  if (dfd >= 0) close(dfd);
  if (lfd >= 0) close(lfd);
  if (dflt) {
    snprintf(msg, msglen, "the zone store is off: %s (the default directory is not used; give `store \"<directory>\";` or `store none;`)", why);
    return true;
  }
  snprintf(msg, msglen, "database store: %s", why);
  return false;
}


/* ------------------------------------------------------------------------------------------------------------- */
/* state                                                                                                          */
/* ------------------------------------------------------------------------------------------------------------- */

#define DBS_MAX_ATTACH_THREADS 32
enum { DBS_HOT_NONE = 0, DBS_HOT_RUNNING, DBS_HOT_DONE, DBS_HOT_LIMIT, DBS_HOT_OFF };      /* the state of the background attach of hot.list */
#define HOT_THREADS_MAX 6                /* the threads of the hot list: 3/4 of the store threads, at most this many */
#define HOT_YIELD_US 400                 /* ... and a thread lets the attach requests of queries that wait go first for at most this long before each batch */
#define HOT_NAP_US 50
#define HOT_BATCH DBREG_ATT_BATCH        /* zones a thread takes from the list at a time, and registers in one section of the registry's lock */
#define DBS_SET_CHUNK 1024u              /* settings ids per chunk */
#define DBS_SET_CHUNKS 1024u             /* ... and chunks: up to a million distinct settings texts */

static struct {
  _Atomic(store_t *) st;
  _Atomic bool attach_on;
  /* the thread that keeps the store's time (group commit, checkpoint) */
  pthread_t wthr;
  bool wthr_started;
  pthread_mutex_t wlock;
  pthread_cond_t wcv;
  bool wstop;
  /* attach threads */
  pthread_t athr[DBS_MAX_ATTACH_THREADS];
  int nathr;
  int akq;
  _Atomic bool astop;
  /* the deepest label count of the stored zones of each view (an upper bound; the depth skip of the lookup) */
  _Atomic uint16_t dmax[STORE_MAX_VIEWS];
  _Atomic uint32_t view_gen;
  _Atomic int64_t room_next_ns;                  /* 0.7 WP7b: the next time an attach may make room under the hard line of memory-limit */
  _Atomic uint64_t cfgid[STORE_MAX_VIEWS];      /* 0.7 WP7b: the first 8 bytes of the hash of the view's configuration (view_identity()): the start of the identity kept with the cursor */
  /* counters */
  _Atomic uint64_t wt_queued, wt_inline, wt_put, wt_skipped, wt_deleted, wt_invalidated, wt_errors, wt_dropped;
  _Atomic uint64_t attach_ok, attach_stale, attach_missing, attach_damaged, attach_fallback, attach_resident, attach_busy;
  _Atomic uint64_t attached_bytes, versions_live;
  _Atomic uint64_t validated, validate_ns;       /* images checked by zone_image_validate() at an attach, and the time they took */
  _Atomic uint64_t pin_waits, pinned_peak;
  /* 0.7 fix 7 (the worker's attach): on only in MAP mode; what it did and why it did not */
  _Atomic uint32_t dir_pending;         /* 0.7 fix 8: the views whose list of zones (the name index) is not complete: no valid cursor at the start, and no complete pass since; bit = the view's id in the store */
  _Atomic bool wa_on;
  _Atomic uint64_t wa_ok, wa_cold, wa_over, wa_claim, wa_fail, wa_decline, wa_full, wa_adopted, wa_lost;
  _Atomic uint64_t wa_ns;               /* the time the worker attaches took */
  /* 0.7 fix 8 (hot.list) */
  pthread_t hthr[HOT_THREADS_MAX];
  int hot_nstarted;
  bool hthr_started;
  _Atomic bool hstop;
  _Atomic bool hot_limit;               /* a thread of the list met the high mark of memory-limit: they all stop */
  _Atomic size_t hot_next;              /* the next place of hot_ids that a thread takes (a batch of HOT_BATCH) */
  _Atomic uint32_t hot_live, hot_nthr;  /* the threads that have not ended, and the threads that were started */
  _Atomic int64_t hot_t0_ns, hot_end_ns; /* the start of the attach of the list, and its end (0: still running) */
  bool hot_on;                          /* store-hot-list */
  _Atomic uint32_t hot_state;           /* DBS_HOT_* */
  _Atomic uint64_t hot_listed, hot_attached, hot_skipped, hot_written;
  uint32_t *hot_ids;                    /* the list that was read at the start (freed when the thread ends) */
  size_t hot_n;
  _Atomic int64_t last_err_log_ns;
} G = { .wlock = PTHREAD_MUTEX_INITIALIZER, .wcv = PTHREAD_COND_INITIALIZER, .akq = -1 };

bool db_store_enabled(void) { return atomic_load_explicit(&G.st, memory_order_acquire) != NULL; }

/* The order of the writers of the records.  A record's version stamp and its existence are changed by the ingest thread (a CHANGES entry, a manifest entry, a delete, the sweep of a pass) while a builder
 * thread installs a body (dir_put() copies the record's stamp to the version it writes); the check "the body is for the stamp the record has" and the install must not have another writer between
 * them.  Every writer of a record's stamp or existence holds this mutex for its whole step, and the commit of a fetched body holds it from the check to the end of the install (db_store_commit_begin() /
 * _end()).  It is taken by the same thread again (a put that deletes the old name of a renamed domain goes through dbreg_delete() to dir_del()), so a thread keeps a depth; it is taken before the lock of
 * the registry, the lock of the reconcile (RC.mu) and the writer lock of the store, and none of the three holds it while waiting for it. */
static pthread_mutex_t g_rec_mu = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned t_rec_depth;
static _Thread_local bool t_put_refuse;        /* the commit of this thread was refused (db_store_commit_begin()): the store takes no version from it */
static void rec_lock(void) {
  if (t_rec_depth++ == 0) pthread_mutex_lock(&g_rec_mu);
}
static void rec_unlock(void) {
  if (--t_rec_depth == 0) pthread_mutex_unlock(&g_rec_mu);
}
#ifdef KARIDNS_UNIT_TEST
void (*db_store_test_commit_hook)(int where, const char *zone);
#endif
store_t *db_store_handle(void) { return atomic_load_explicit(&G.st, memory_order_acquire); }

/* the zones the list has attached in a second, from its start until now (until its end, when it has ended) */
static uint64_t hot_rate(uint64_t attached) {
  const int64_t t0 = atomic_load(&G.hot_t0_ns), te = atomic_load(&G.hot_end_ns);
  const int64_t el = t0 ? (te ? te : mono_ns()) - t0 : 0;
  return el > 0 ? (uint64_t)((double)attached * 1e9 / (double)el) : 0;
}

void db_store_counters(db_store_counters_t *o) {
  o->wt_queued = atomic_load(&G.wt_queued);
  o->wt_inline = atomic_load(&G.wt_inline);
  o->wt_put = atomic_load(&G.wt_put);
  o->wt_skipped = atomic_load(&G.wt_skipped);
  o->wt_deleted = atomic_load(&G.wt_deleted);
  o->wt_invalidated = atomic_load(&G.wt_invalidated);
  o->wt_errors = atomic_load(&G.wt_errors);
  o->wt_dropped = atomic_load(&G.wt_dropped);
  o->attach_ok = atomic_load(&G.attach_ok);
  o->attach_stale = atomic_load(&G.attach_stale);
  o->attach_missing = atomic_load(&G.attach_missing);
  o->attach_damaged = atomic_load(&G.attach_damaged);
  o->attach_fallback = atomic_load(&G.attach_fallback);
  o->attach_resident = atomic_load(&G.attach_resident);
  o->attach_busy = atomic_load(&G.attach_busy);
  o->attached_bytes = atomic_load(&G.attached_bytes);
  o->versions_live = atomic_load(&G.versions_live);
  o->validated = atomic_load(&G.validated);
  o->validate_ns = atomic_load(&G.validate_ns);
  o->pin_waits = atomic_load(&G.pin_waits);
  o->pinned_peak = atomic_load(&G.pinned_peak);
  o->wa_ok = atomic_load(&G.wa_ok);
  o->wa_cold = atomic_load(&G.wa_cold);
  o->wa_over = atomic_load(&G.wa_over);
  o->wa_claim = atomic_load(&G.wa_claim);
  o->wa_fail = atomic_load(&G.wa_fail);
  o->wa_decline = atomic_load(&G.wa_decline);
  o->wa_full = atomic_load(&G.wa_full);
  o->wa_adopted = atomic_load(&G.wa_adopted);
  o->wa_lost = atomic_load(&G.wa_lost);
  o->wa_ns = atomic_load(&G.wa_ns);
  o->hot_state = atomic_load(&G.hot_state);
  o->hot_listed = atomic_load(&G.hot_listed);
  o->hot_attached = atomic_load(&G.hot_attached);
  o->hot_skipped = atomic_load(&G.hot_skipped);
  o->hot_written = atomic_load(&G.hot_written);
  o->hot_threads = atomic_load(&G.hot_nthr);
  o->hot_per_s = hot_rate(o->hot_attached);
}

/* the store's name of a zone of the registry: no trailing dot (the registry's key keeps it); false: the root zone or too long */
static bool store_name(const char *zone, char *out, size_t cap, size_t *len) {
  size_t n = strlen(zone);
  if (n > 0 && zone[n - 1] == '.') n--;
  if (n == 0 || n >= cap || n > STORE_NAME_MAX) return false;
  memcpy(out, zone, n);
  out[n] = '\0';
  *len = n;
  return true;
}

static void store_log_cb(void *ctx, int level, const char *msg) {
  (void)ctx;
  syslog(level == 3 ? LOG_ERR : level == 4 ? LOG_WARNING : LOG_INFO, "[Store] %s", msg);
}

static void note_error(const char *what, const char *zone, int rc) {
  atomic_fetch_add(&G.wt_errors, 1);
  int64_t now = mono_ns();
  if (now - atomic_load_explicit(&G.last_err_log_ns, memory_order_relaxed) > 5000000000ll) {          /* (at most one line in five seconds: a full disk fails every zone) */
    atomic_store_explicit(&G.last_err_log_ns, now, memory_order_relaxed);
    syslog(LOG_ERR, "[Store] %s of zone '%s' failed: %s; the zone is served from memory and read from the database again when it is asked for", what, zone, strerror(rc < 0 ? -rc : rc));
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the settings of the zones: the interned texts by id, kept in settings.dat (a zone's record names its settings by id)   */
/* ------------------------------------------------------------------------------------------------------------- */

/* A record of the store holds the id of the settings of the zone, and a zone that is not in memory has to be answered (allow-query) and attached (its entry's settings) with
 * the loader stopped: the texts live in a file of their own in the store's directory, appended when a settings text is first used and made durable before a record names it,
 * and are read at the start.  Config-sized (one text per distinct settings of the zones, as the interned objects in the heap are today).  File: records of
 * u32 magic, u32 length, u32 crc32c, then the key of the interned object (profile name, NUL, profile text, NUL, zone text); a torn tail is cut at the next start. */
#define DBS_SET_MAGIC 0x4B534554u        /* "KSET" */
static struct {
  pthread_mutex_t lock;
  int fd;
  off_t end;
  uint32_t n;                                              /* the ids in use are 1..n */
  _Atomic(_Atomic(zone_ext_shared_t *) *) chunk[DBS_SET_CHUNKS];
} SET = { .lock = PTHREAD_MUTEX_INITIALIZER, .fd = -1 };

static uint32_t set_crc(const uint8_t *p, size_t n) {            /* CRC-32C, bitwise (the texts are short and few) */
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; i++) {
    c ^= p[i];
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0x82F63B78u & (uint32_t)-(int32_t)(c & 1u));
  }
  return ~c;
}

static zone_ext_shared_t *set_get(uint32_t id) {
  if (id == 0 || id > SET.n) return NULL;
  uint32_t c = (id - 1) / DBS_SET_CHUNK;
  _Atomic(zone_ext_shared_t *) *ch = atomic_load_explicit(&SET.chunk[c], memory_order_acquire);
  return ch ? atomic_load_explicit(&ch[(id - 1) % DBS_SET_CHUNK], memory_order_acquire) : NULL;
}

/* the object of a stored key: parsed again as the ingest parses what the loader sends, and interned */
static zone_ext_shared_t *set_rebuild(const uint8_t *key, size_t klen) {
  size_t pnlen = strnlen((const char *)key, klen);
  if (pnlen >= klen) return NULL;
  const char *ptext = (const char *)key + pnlen + 1;
  size_t ptlen = strnlen(ptext, klen - pnlen - 1);
  if (pnlen + 1 + ptlen + 1 > klen) return NULL;
  const char *ztext = ptext + ptlen + 1;
  size_t zlen = klen - (pnlen + 1 + ptlen + 1);
  char *merged = malloc(ptlen + 1 + zlen + 1);
  char *kc = malloc(klen + 1);
  if (!merged || !kc) {
    free(merged);
    free(kc);
    return NULL;
  }
  memcpy(merged, ptext, ptlen);
  merged[ptlen] = '\n';
  memcpy(merged + ptlen + 1, ztext, zlen);
  memcpy(kc, key, klen);
  kc[klen] = '\0';
  zone_ext_shared_t *sh = db_settings_find(kc, klen);
  if (sh) {
    free(merged);
    free(kc);
    return sh;
  }
  char err[200];
  sh = db_settings_parse(merged, ptlen + 1 + zlen, err, sizeof(err));
  free(merged);
  if (!sh) {
    free(kc);
    return NULL;
  }
  sh->key = kc;
  sh->key_len = klen;
  sh->hash = db_settings_hash(kc, klen);
  snprintf(sh->profile, sizeof(sh->profile), "%.*s", (int)(pnlen < sizeof(sh->profile) - 1 ? pnlen : sizeof(sh->profile) - 1), (const char *)key);
  return db_settings_intern(sh);
}

#ifdef KARIDNS_UNIT_TEST
int db_store_test_set_fail = 0;                              /* the n-th call of set_put_slot() fails (0: off): no room for the id */
#endif
static bool set_put_slot(uint32_t id, zone_ext_shared_t *sh) {
#ifdef KARIDNS_UNIT_TEST
  if (db_store_test_set_fail > 0 && --db_store_test_set_fail == 0) return false;
#endif
  uint32_t c = (id - 1) / DBS_SET_CHUNK;
  if (c >= DBS_SET_CHUNKS) return false;
  _Atomic(zone_ext_shared_t *) *ch = atomic_load_explicit(&SET.chunk[c], memory_order_relaxed);
  if (!ch) {
    ch = calloc(DBS_SET_CHUNK, sizeof(*ch));
    if (!ch) return false;
    atomic_store_explicit(&SET.chunk[c], ch, memory_order_release);
  }
  atomic_store_explicit(&ch[(id - 1) % DBS_SET_CHUNK], sh, memory_order_release);
  return true;
}

/* read the file at the start; a torn tail is cut.  The fd stays open for the appends.
 * Only a record that is really damaged (a torn end, a wrong checksum) is cut.  A record that cannot be loaded now (no memory, no room for its id) is not damaged: cutting it, and the records behind it, would give
 * its id (and the ids after it) to other texts at the next append, and the records of the zones that name the old ids would then carry the ACLs of another zone's settings.  So its id stays taken and unused
 * (a zone that names it is read from the database, which sends the settings again).  A read error leaves the file alone and ends its use (no new text is made durable). */
static void set_load(int dirfd) {
  SET.fd = openat(dirfd, "settings.dat", O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (SET.fd < 0) {
    syslog(LOG_WARNING, "[Store] cannot open settings.dat (%s): zones whose settings are not known are read from the database", strerror(errno));
    return;
  }
  struct stat st;
  if (fstat(SET.fd, &st) != 0) goto io_error;
  off_t off = 0;
  for (;;) {
    uint32_t h[3];
    ssize_t hr = pread(SET.fd, h, sizeof(h), off);
    if (hr < 0) goto io_error;
    if (hr != (ssize_t)sizeof(h) || h[0] != DBS_SET_MAGIC || h[1] == 0 || h[1] > (1u << 20) || off + 12 + (off_t)h[1] > st.st_size) break;
    uint8_t *buf = malloc(h[1]);
    if (!buf) {                                    /* no memory for this text: its id stays unused */
      SET.n++;
      off += 12 + (off_t)h[1];
      continue;
    }
    ssize_t br = pread(SET.fd, buf, h[1], off + 12);
    if (br < 0) {
      free(buf);
      goto io_error;
    }
    if (br != (ssize_t)h[1] || set_crc(buf, h[1]) != h[2]) {
      free(buf);
      break;
    }
    zone_ext_shared_t *sh = set_rebuild(buf, h[1]);
    free(buf);
    SET.n++;
    if (sh && !set_put_slot(SET.n, sh)) {          /* (no room for the id: unused as well) */
      zone_ext_shared_unref(sh);
    } else if (sh) {
      sh->store_id = SET.n;
    }                                              /* (a text that does not parse any more, the parser having changed: the id stays unused, a zone that names it is read from the database) */
    off += 12 + (off_t)h[1];
  }
  if (off < st.st_size && ftruncate(SET.fd, off) != 0) syslog(LOG_WARNING, "[Store] settings.dat: the torn end cannot be cut: %s", strerror(errno));
  SET.end = off;
  return;
io_error:
  syslog(LOG_WARNING, "[Store] cannot read settings.dat (%s): it is left as it is and not used for new texts; zones whose settings are not known are read from the database", strerror(errno));
  close(SET.fd);
  SET.fd = -1;
}

/* the id of the settings (assigned and made durable when it has none yet); 0: none, or the id could not be made (the zone is then not put in the store) */
static uint32_t dir_settings_id(zone_ext_shared_t *sh) {
  if (!sh) return 0;
  uint32_t id = atomic_load_explicit(&sh->store_id, memory_order_acquire);
  if (id) return id;
  pthread_mutex_lock(&SET.lock);
  id = atomic_load_explicit(&sh->store_id, memory_order_relaxed);
  if (!id && SET.fd >= 0 && sh->key && sh->key_len > 0 && sh->key_len <= (1u << 20) && SET.n + 1 < DBS_SET_CHUNKS * DBS_SET_CHUNK) {
    uint8_t *buf = malloc(12 + sh->key_len);
    if (buf) {
      uint32_t h[3] = { DBS_SET_MAGIC, (uint32_t)sh->key_len, set_crc((const uint8_t *)sh->key, sh->key_len) };
      memcpy(buf, h, 12);
      memcpy(buf + 12, sh->key, sh->key_len);
      if (pwrite(SET.fd, buf, 12 + sh->key_len, SET.end) == (ssize_t)(12 + sh->key_len) && fdatasync(SET.fd) == 0 && set_put_slot(SET.n + 1, sh)) {
        zone_ext_shared_ref(sh);                       /* (the table's reference: the object lives as long as the process) */
        SET.end += (off_t)(12 + sh->key_len);
        SET.n++;
        id = SET.n;
        atomic_store_explicit(&sh->store_id, id, memory_order_release);
      } else if (ftruncate(SET.fd, SET.end) != 0) {
        syslog(LOG_WARNING, "[Store] settings.dat: the failed record cannot be cut: %s", strerror(errno));
      }
      free(buf);
    }
  }
  pthread_mutex_unlock(&SET.lock);
  return id;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the attach table: zid -> the registry's element of a zone of the store that is in memory                      */
/* ------------------------------------------------------------------------------------------------------------- */

/* Open addressing, lock-free for readers (the query path, in its read section), one writer at a time (the registry lock is held by every caller; the table has a mutex of its own
 * as well).  An element is put in after it is complete and taken out before it is retired, so a reader that has it may use it until it leaves its read section.  A table that
 * grows is replaced as a whole and the old one is freed after the grace period of the epoch RCU: inserts and removals publish no zone-database snapshot (design 4.1). */
typedef struct att_tab {
  size_t cap, mask;
  _Atomic(zdir_elem_t *) slot[];
} att_tab_t;
typedef struct att_retired {
  struct att_retired *next;
  att_tab_t *t;
  uint64_t epoch;
} att_retired_t;
#define ATT_TOMB ((zdir_elem_t *)(uintptr_t)1)
#define ATT_MIN_CAP 1024u
#ifdef KARIDNS_UNIT_TEST
int db_store_test_attach_reserve_fail = 0;                   /* the n-th dir_attach_reserve() fails (0: off): the table cannot grow */
#endif
static struct {
  pthread_mutex_t lock;
  _Atomic(att_tab_t *) tab;
  size_t live, used;                 /* used = live + tombstones */
  size_t floor_cap;                  /* 0.7 M4: the smallest the table is made (att_presize()) */
  att_retired_t *retired;
  _Atomic uint64_t puts, removes, grows, shrinks;
} AT = { .lock = PTHREAD_MUTEX_INITIALIZER };

static inline size_t att_hash(uint32_t zid) {
  uint64_t x = (uint64_t)zid * 0x9E3779B97F4A7C15ull;
  return (size_t)(x >> 32);
}

static zdir_elem_t *dir_attach_get(uint32_t zid) {
  const att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_acquire);
  if (!t) return NULL;
  size_t i = att_hash(zid) & t->mask;
  for (;;) {
    zdir_elem_t *e = atomic_load_explicit(&t->slot[i], memory_order_acquire);
    if (!e) return NULL;
    if (e != ATT_TOMB && e->zid == zid) return e;
    i = (i + 1) & t->mask;
  }
}

static void att_retired_run_locked(bool force) {
  att_retired_t **pp = &AT.retired;
  while (*pp) {
    att_retired_t *r = *pp;
    if (force || rcu_writer_is_safe(r->epoch)) {
      *pp = r->next;
      free(r->t);
      free(r);
    } else {
      pp = &r->next;
    }
  }
}

static bool att_rehash_locked(size_t want_cap) {
  att_tab_t *nt = malloc(sizeof(*nt) + want_cap * sizeof(_Atomic(zdir_elem_t *)));
  if (!nt) return false;
  nt->cap = want_cap;
  nt->mask = want_cap - 1;
  for (size_t i = 0; i < want_cap; i++) atomic_init(&nt->slot[i], NULL);
  att_tab_t *old = atomic_load_explicit(&AT.tab, memory_order_relaxed);
  size_t n = 0;
  for (size_t i = 0; old && i < old->cap; i++) {
    zdir_elem_t *e = atomic_load_explicit(&old->slot[i], memory_order_relaxed);
    if (!e || e == ATT_TOMB) continue;
    size_t j = att_hash(e->zid) & nt->mask;
    while (atomic_load_explicit(&nt->slot[j], memory_order_relaxed)) j = (j + 1) & nt->mask;
    atomic_store_explicit(&nt->slot[j], e, memory_order_relaxed);
    n++;
  }
  atomic_store_explicit(&AT.tab, nt, memory_order_release);
  uint64_t ep = rcu_writer_advance_epoch();
  AT.live = AT.used = n;
  atomic_fetch_add_explicit(&AT.grows, 1, memory_order_relaxed);
  if (old) {
    att_retired_t *r = malloc(sizeof(*r));
    if (r) {
      r->t = old;
      r->epoch = ep;
      r->next = AT.retired;
      AT.retired = r;
    } else {
      (void)rcu_writer_wait_until_safe(ep, 60000);            /* (no memory for the node: the grace period is waited for here) */
      free(old);
    }
  }
  return true;
}

/* the size of a table for `live` elements: four slots each, at least the floor (the lock is held) */
static size_t att_cap_for(size_t live) {
  size_t cap = AT.floor_cap > ATT_MIN_CAP ? AT.floor_cap : ATT_MIN_CAP;
  while (cap < (live + 1) * 4) cap <<= 1;
  return cap;
}

/* the table has room for one more element (the lock is held); false: no memory for a bigger one */
static bool att_room_locked(void) {
  att_retired_run_locked(false);
  att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_relaxed);
  if (!t || (AT.used + 1) * 2 > t->cap) {                       /* load above 1/2 (tombstones count): a bigger table, or the same size without the tombstones */
    if (!att_rehash_locked(att_cap_for(AT.live))) return false;
  }
  return true;
}

/* 0.7 M4: the table is made for `n` zones before they come.  A table that grows with the zones is rehashed at every doubling inside the registry's lock, and the last doubling of 500,000 zones took 50 to
 * 100 ms in the middle of the rush of first queries after a restart (every attach waits for the lock: the queries that waited then waited as long: the 99th percentile of the wait of 100 ms in one run in
 * five).  The list of the last run says how many zones are coming; the floor keeps the table from being made smaller by the first detach. */
static void att_presize(size_t n) {
  pthread_mutex_lock(&AT.lock);
  const size_t want = att_cap_for(n > AT.live ? n : AT.live);
  AT.floor_cap = want;
  att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_relaxed);
  if (!t || t->cap < want) (void)att_rehash_locked(want);
  pthread_mutex_unlock(&AT.lock);
}

/* The registry makes the room before it changes anything (dbreg_commit_store()): an element that is registered with its entry and then cannot be put in the table is a zone that the caller frees the entry of,
 * under the registry's feet.  The registry lock is held by every caller of both, so the room is still there at the put. */
static bool dir_attach_reserve(void) {
#ifdef KARIDNS_UNIT_TEST
  if (db_store_test_attach_reserve_fail > 0 && --db_store_test_attach_reserve_fail == 0) return false;
#endif
  pthread_mutex_lock(&AT.lock);
  bool ok = att_room_locked();
  pthread_mutex_unlock(&AT.lock);
  return ok;
}

static bool dir_attach_put(zdir_elem_t *el) {
  pthread_mutex_lock(&AT.lock);
  if (!att_room_locked()) {
    pthread_mutex_unlock(&AT.lock);
    return false;
  }
  att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_relaxed);
  size_t i = att_hash(el->zid) & t->mask, tomb = (size_t)-1;
  for (;;) {
    zdir_elem_t *e = atomic_load_explicit(&t->slot[i], memory_order_relaxed);
    if (!e) break;
    if (e == ATT_TOMB) {
      if (tomb == (size_t)-1) tomb = i;
    } else if (e->zid == el->zid) {                              /* the same zone id: the element is replaced (or it is the same one) */
      atomic_store_explicit(&t->slot[i], el, memory_order_release);
      pthread_mutex_unlock(&AT.lock);
      return true;
    }
    i = (i + 1) & t->mask;
  }
  if (tomb != (size_t)-1) i = tomb;
  else AT.used++;
  atomic_store_explicit(&t->slot[i], el, memory_order_release);
  AT.live++;
  atomic_fetch_add_explicit(&AT.puts, 1, memory_order_relaxed);
  pthread_mutex_unlock(&AT.lock);
  return true;
}

static void dir_attach_remove(const zdir_elem_t *el) {
  pthread_mutex_lock(&AT.lock);
  att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_relaxed);
  if (t) {
    size_t i = att_hash(el->zid) & t->mask;
    for (;;) {
      zdir_elem_t *e = atomic_load_explicit(&t->slot[i], memory_order_relaxed);
      if (!e) break;
      if (e == el) {
        atomic_store_explicit(&t->slot[i], ATT_TOMB, memory_order_release);
        AT.live--;
        atomic_fetch_add_explicit(&AT.removes, 1, memory_order_relaxed);
        break;
      }
      i = (i + 1) & t->mask;
    }
    /* 0.7 store S5: after a mass detach the table is smaller again (1/8 full or less: a table of four times the live elements, the tombstones gone); the old one is freed after the grace period */
    if (t->cap > ATT_MIN_CAP && AT.live * 8 <= t->cap) {
      const size_t cap = att_cap_for(AT.live);
      if (cap < t->cap && att_rehash_locked(cap)) atomic_fetch_add_explicit(&AT.shrinks, 1, memory_order_relaxed);
    }
  }
  pthread_mutex_unlock(&AT.lock);
}

static zdir_elem_t *dir_attach_next(size_t *pos) {
  const att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_acquire);
  while (t && *pos < t->cap) {
    zdir_elem_t *e = atomic_load_explicit(&t->slot[(*pos)++], memory_order_acquire);
    if (e && e != ATT_TOMB) return e;
  }
  return NULL;
}
/* An element of the attach table at a random place (the random number r), for the cache manager's samples (design 4.4): the first live slot from a random one.  The registry lock is held by the caller, and by
 * every writer of the table, so the table does not change under it. */
static zdir_elem_t *dir_attach_sample(uint64_t r) {
  const att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_acquire);
  if (!t || AT.live == 0) return NULL;
  size_t i = (size_t)(r >> 11) & t->mask;
  for (size_t n = 0; n < t->cap; n++, i = (i + 1) & t->mask) {
    zdir_elem_t *e = atomic_load_explicit(&t->slot[i], memory_order_acquire);
    if (e && e != ATT_TOMB) return e;
  }
  return NULL;
}
static uint64_t dir_attach_tab_id(void) {
  const att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_acquire);
  return t ? ((uint64_t)(uintptr_t)t * 0x9e3779b97f4a7c15ull) ^ (uint64_t)t->cap : 0;
}

static size_t dir_attach_count(void) {
  pthread_mutex_lock(&AT.lock);
  size_t n = AT.live;
  pthread_mutex_unlock(&AT.lock);
  return n;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the staging table: zid -> the staged element of a zone that a worker attached (0.7 fix 7)                      */
/* ------------------------------------------------------------------------------------------------------------- */

/* The worker's attach (worker_attach(), below) takes no lock: it publishes the zone for the lookup in this table, and a store thread registers the zone (the registry, the attach table above) a moment
 * later.  A fixed number of slots, never grown and never rehashed, so that a put is one compare-and-swap and nothing moves under a reader: a zid has STG_PROBE slots (the hash, then the next ones), a
 * lookup looks at all of them (a slot that was emptied does not end the probe), a put that finds them all taken is refused (the worker leaves the zone to the store threads).  Only the store thread that
 * registers a staged element takes it out.  The claim of the zone (park_att_claim()) is what keeps two workers from staging the same zone; a put still looks for the zone first. */
/* (test hooks of the worker's attach and its registration: in every build, so that the functions that read them are the same in the test programs and in karidns, and the coverage of the two merges) */
int db_store_test_stg_fail = 0;                              /* the n-th put into the staging table is refused (0: off) */
_Atomic bool db_store_test_not_resident;                   /* the worker's attach finds no image in the page cache (tests: a page cannot be made to leave it) */
_Atomic bool db_store_test_resident;                       /* the worker's attach finds the image in the page cache whatever mincore() says (tests: on ZFS, and any file system that does not report the pages that were written, mincore() says no) */
void (*_Atomic db_store_test_adopt_hook)(void);           /* called by a store thread before it registers a staged zone (tests: hold it, and change the zone meanwhile) */
_Atomic bool db_store_test_adopt_noview;                  /* the registration of a staged zone finds no view for the store's id (tests: the store is closing) */
_Atomic bool db_store_test_hot_pending;                    /* the threads of hot.list see attach requests of queries that wait (tests: they are never starved by them) */
void (*_Atomic db_store_test_hot_hook)(uint32_t zid);     /* called by the threads of hot.list before each zone (tests: the order, and time) */
#define STG_CAP 16384u
#define STG_PROBE 8u
static _Atomic(zdir_elem_t *) g_stg[STG_CAP];

static zdir_elem_t *stg_get(uint32_t zid) {
  const size_t h = att_hash(zid);
  for (unsigned j = 0; j < STG_PROBE; j++) {
    zdir_elem_t *e = atomic_load_explicit(&g_stg[(h + j) & (STG_CAP - 1)], memory_order_acquire);
    if (e && e->zid == zid) return e;
  }
  return NULL;
}

static bool stg_put(zdir_elem_t *el) {
  if (db_store_test_stg_fail > 0 && --db_store_test_stg_fail == 0) return false;
  const size_t h = att_hash(el->zid);
  if (stg_get(el->zid)) return false;
  for (unsigned j = 0; j < STG_PROBE; j++) {
    _Atomic(zdir_elem_t *) *s = &g_stg[(h + j) & (STG_CAP - 1)];
    zdir_elem_t *none = NULL;
    if (atomic_load_explicit(s, memory_order_relaxed) == NULL && atomic_compare_exchange_strong_explicit(s, &none, el, memory_order_release, memory_order_relaxed)) return true;
  }
  return false;
}

static void stg_remove(const zdir_elem_t *el) {
  const size_t h = att_hash(el->zid);
  for (unsigned j = 0; j < STG_PROBE; j++) {
    _Atomic(zdir_elem_t *) *s = &g_stg[(h + j) & (STG_CAP - 1)];
    zdir_elem_t *e = (zdir_elem_t *)(uintptr_t)el;
    if (atomic_load_explicit(s, memory_order_relaxed) == e && atomic_compare_exchange_strong_explicit(s, &e, NULL, memory_order_release, memory_order_relaxed)) return;
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the lookup and what the registry asks of the store (the operations of g_dbdir)                                */
/* ------------------------------------------------------------------------------------------------------------- */

static int dir_view_sid(const char *view_name) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  return st ? store_view_id(st, view_name) : -1;
}
static uint32_t dir_view_gen(void) { return atomic_load_explicit(&G.view_gen, memory_order_relaxed); }
static unsigned dir_depth_max(int sid) {
  return sid >= 0 && sid < STORE_MAX_VIEWS ? atomic_load_explicit(&G.dmax[sid], memory_order_relaxed) : 0;
}
static zone_ext_shared_t *dir_settings(uint32_t id) { return set_get(id); }

/* G.dmax is the deepest label count of the stored zones of a view; 63 means "63 or more" (the store counts the deeper names in one bucket, and the depth skip of the lookup does not skip at 63).  A zone that is
 * put raises it, a delete may lower it (dmax_refresh() asks the store): both under one mutex, or a refresh that read the counters before a put would store a value below the one the put raised to (a zone
 * that the lookup then never asks the store for), and two ingest threads would lose each other's raise. */
static pthread_mutex_t g_dmax_mu = PTHREAD_MUTEX_INITIALIZER;
static void dmax_raise(int vid, unsigned labels) {
  if (vid < 0 || vid >= STORE_MAX_VIEWS) return;
  const uint16_t l = labels > 63 ? 63 : (uint16_t)labels;
  pthread_mutex_lock(&g_dmax_mu);
  if (l > atomic_load_explicit(&G.dmax[vid], memory_order_relaxed)) atomic_store_explicit(&G.dmax[vid], l, memory_order_relaxed);
  pthread_mutex_unlock(&g_dmax_mu);
}
static void dmax_refresh(store_t *st, int vid) {
  if (vid < 0 || vid >= STORE_MAX_VIEWS) return;
  pthread_mutex_lock(&g_dmax_mu);
  atomic_store_explicit(&G.dmax[vid], (uint16_t)store_view_depth_max(st, (uint16_t)vid), memory_order_relaxed);
  pthread_mutex_unlock(&g_dmax_mu);
}

/* One probe of the name index for (view sid, folded name).  A zone in memory is found through the attach table and verified by the name of its element; a zone that is not is verified in the
 * zone table.  A cell that was being written for longer than a worker may spin (store_reader_nosleep()) makes the answer "not known now" (out->busy). */
static bool dir_find(int sid, const char *fname, size_t len, zref_t *out) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st || sid < 0 || sid >= STORE_MAX_VIEWS || len > STORE_NAME_MAX) return false;
  (void)store_reader_busy_take();
  uint32_t cand[4];
  unsigned n = store_find_cand(st, (uint16_t)sid, fname, len, cand, 4);
  for (unsigned i = 0; i < n; i++) {
    zdir_elem_t *el = dir_attach_get(cand[i]);
    if (!el) el = stg_get(cand[i]);                            /* (a zone that a worker attached and a store thread has not registered yet) */
    if (el) {
      if (el->sview == (uint16_t)sid && el->klen == len && strncasecmp(el->name, fname, len) == 0) {
        /* an element of the attach table whose entry is not there (yet, or any more): the zone is known and its data is not in memory.  The answer is that, not "no such zone": the worker parks the
         * query for it (a lookup that skipped the element sent a query or a NOTIFY in that window to REFUSED / no zone, and nothing waited) */
        out->el = el;
        out->entry = zdir_entry(el);
        out->zid = cand[i];
        out->sview = (int16_t)sid;
        return true;
      }
      continue;
    }
    if (!store_zid_is(st, cand[i], (uint16_t)sid, fname, len)) continue;
    store_zone_t z;
    if (store_zone_get(st, cand[i], &z) != 0) continue;
    if (z.flags & STORE_F_NONSTORE) continue;                  /* (a secondary or catalog zone of the database: a heap zone; the record is the reconcile's) */
    out->zid = z.zid;
    out->sview = (int16_t)sid;
    out->serial = z.serial;
    out->settings = z.settings;
    out->flags = z.flags;
    out->zstate = z.state == STORE_STATE_STORED ? ZREF_ST_ABSENT : ZREF_ST_KNOWN;
    memcpy(out->name, fname, len);
    out->name[len] = '.';
    out->name[len + 1] = '\0';
    return true;
  }
  if (store_reader_busy_take()) {
    out->busy = true;
    memcpy(out->name, fname, len);
    out->name[len] = '.';
    out->name[len + 1] = '\0';
    return true;
  }
  return false;
}

static void rec_from_zone(const store_zone_t *z, dbdir_rec_t *o) {
  o->zid = z->zid;
  o->stamp_gen = z->stamp_gen;
  o->stamp_time = z->stamp_time;
  o->state = z->state;
  o->flags = z->flags;
  o->serial = z->serial;
  o->seq = z->seq;
  o->seq_set = true;
  o->settings = z->settings;
  o->source_id = z->source_id;
  memcpy(o->digest, z->digest, 32);
}

#ifdef KARIDNS_UNIT_TEST
_Atomic(const char *) db_store_test_rec_fault_zone;       /* dir_rec_get() cannot read the record of this zone (a damaged cell) */
#endif
static bool dir_rec_get(const char *view, const char *zone, dbdir_rec_t *o) {
#ifdef KARIDNS_UNIT_TEST
  {
    const char *fz = atomic_load_explicit(&db_store_test_rec_fault_zone, memory_order_acquire);
    if (fz && zone && strcmp(fz, zone) == 0) return false;
  }
#endif
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (!st || !store_name(zone, name, sizeof(name), &nlen)) return false;
  bool ok = false;
  store_read_lock();
  int vid = store_view_id(st, view);
  uint32_t zid = vid >= 0 ? store_find(st, (uint16_t)vid, name, nlen) : STORE_NONE;
  store_zone_t z;
  if (zid != STORE_NONE && store_zone_get(st, zid, &z) == 0 && !(z.flags & STORE_F_NONSTORE)) {
    rec_from_zone(&z, o);
    ok = true;
  }
  store_read_unlock();
  return ok;
}

/* 0.7 M4: has the record stayed as it was read?  The registry asks this inside its lock where it used to read the record again by name (the search in the name index and the two cells: page faults on the mapped tables, on ZFS a copy out of the ARC, while the lock is held and every other attach waits) */
static bool dir_rec_unchanged(const dbdir_rec_t *r) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  return st && r->seq_set && store_zone_unchanged(st, r->zid, r->seq);
}

/* The same for a caller that holds the registry lock: the readers of the store wait for a cell that is being written, up to half a second, and sleep while they do; here they spin a little and give up (-1). */
static int dir_rec_get_nb(const char *view, const char *zone, dbdir_rec_t *o) {
  const bool was = store_reader_nosleep(true);
  const bool ok = dir_rec_get(view, zone, o);
  const bool busy = store_reader_busy_take();
  store_reader_nosleep(was);
  return busy ? -1 : ok ? 1 : 0;
}

static void view_identity(const database_config_t *db, const view_config_t *v, uint8_t out[32]);

/* a view that the store did not know when it was opened (the configuration was reloaded with a new view): its identity is noted as at the start, so that the next start trusts what is stored */
static void note_view_identity(store_t *st, int vid, const char *view) {
  uint8_t want[32];
  bool ok = false;
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  if (cfg && cfg->database.enabled) {
    for (const view_config_t *v = cfg->views; v; v = v->next) {
      if (v->name && strcmp(v->name, view) == 0 && !v->database_none) {
        view_identity(&cfg->database, v, want);
        ok = true;
        break;
      }
    }
  }
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  if (ok) {
    uint64_t id8;
    memcpy(&id8, want, DBS_CFGID);
    atomic_store_explicit(&G.cfgid[vid], id8, memory_order_relaxed);
    (void)store_set_cursor(st, (uint16_t)vid, 0, want, DBS_CFGID);
  }
}

/* the id of the view in the store; the store gets the view when it has none (the configuration was reloaded with a new view).  < 0: no room */
static int view_ensure(store_t *st, const char *view) {
  int vid = store_view_id(st, view);
  if (vid >= 0) return vid;
  vid = store_view_add(st, view);
  if (vid < 0) {
    note_error("the view", view, vid);
    return vid;
  }
  atomic_fetch_add(&G.view_gen, 1);
  note_view_identity(st, vid, view);
  return vid;
}

/* The version of the entry goes to the store (the install of the loader's zone has made the entry and published its version; the registry commit follows).  *zid: the zone's id.
 * 0, or a negative errno; -ENOTSUP: not a zone the store can hold (the root zone, a name too long, no records, another serial by now). */
static int dir_put_locked(const char *view, const char *zone, zone_db_entry_t *entry, int64_t source_id, uint32_t serial, const uint8_t digest[32], uint32_t settings, uint32_t *zid_out) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (!st) return -ENODEV;
  if (t_put_refuse) return -ECANCELED;                     /* (the commit was refused: the body is not for the record's stamp any more, db_store_commit_begin()) */
  if (!store_name(zone, name, sizeof(name), &nlen)) return -ENOTSUP;
  int vid = view_ensure(st, view);
  if (vid < 0) return vid;
  /* the version is pinned while it is copied (a dynamic UPDATE or a newer install may replace it meanwhile) */
  zone_version_t *v = NULL;
  uint16_t flags = 0;
  int rc = -ENOTSUP;
  rcu_aux_read_lock();
  v = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  if (v && v->image && v->image->n_rrs > 0 && atomic_load_explicit(&entry->serial, memory_order_relaxed) == serial) {
    atomic_fetch_add_explicit(&v->xfr_refs, 1, memory_order_acq_rel);
    if (v->image->flags & ZONE_IMAGE_F_ALIAS) flags |= STORE_F_ALIAS;
    if (v->image->flags & ZONE_IMAGE_F_WILDCARD) flags |= STORE_F_WILDCARD;
    if (v->image->n_nsec > 0 || v->image->n_n3chains > 0) flags |= STORE_F_PRESIGNED;
    rc = 0;
  }
  rcu_aux_read_unlock();
  if (rc != 0) return rc;
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.source_id = source_id;
  m.source = (uint16_t)vid;
  m.flags = flags;
  m.serial = serial;
  m.settings = settings;
  memcpy(m.digest, digest, STORE_DIGEST_LEN);
  /* the store has this version already (a restart that reads every zone again): nothing to write */
  store_zone_t cur;
  bool same = false;
  uint16_t cflags = 0;
  uint32_t zid = STORE_NONE;
  store_read_lock();
  zid = store_find(st, (uint16_t)vid, name, nlen);
  if (zid != STORE_NONE && store_zone_get(st, zid, &cur) == 0) {
    if (cur.source_id == source_id || cur.source_id == 0) {          /* 0.7 WP7b: the stamp the reconcile asked this version with stays with the record (the body carries none) */
      m.stamp_gen = cur.stamp_gen;
      m.stamp_time = cur.stamp_time;
    }
    if (cur.state == STORE_STATE_STORED && cur.serial == serial && cur.source_id == source_id && cur.settings == settings && memcmp(cur.digest, digest, STORE_DIGEST_LEN) == 0 &&
        cur.stamp_gen == m.stamp_gen && cur.stamp_time == m.stamp_time)
      same = true;
    cflags = cur.flags;
  }
  store_read_unlock();
  if (same) {
    atomic_fetch_add(&G.wt_skipped, 1);
    if (cflags & (STORE_F_STALE | STORE_F_REJECTED_NEW)) (void)store_set_flags(st, zid, 0, STORE_F_STALE | STORE_F_REJECTED_NEW);       /* (the body that was asked for is this version) */
    *zid_out = zid;
    atomic_fetch_sub_explicit(&v->xfr_refs, 1, memory_order_acq_rel);
    return 0;
  }
  const unsigned labels = store_name_labels(name, nlen);
  dmax_raise(vid, labels);                                  /* (before the zone is in the index: the lookup must ask for it the moment it can be found; again below, after a delete's refresh) */
  const zone_image_t *img = v->image;
  int r = store_put(st, (uint16_t)vid, name, nlen, &m, img, img->total_size, &zid);
  if (r == -EEXIST && source_id != 0) {                    /* the domain id is another zone of the store (a renamed domain): that one goes, the new name is put */
    /* The old name goes through the registry (dbreg_delete()), not the store alone: the zone may be attached under the old name, and its element and entry would stay (counted resident, reachable by the
     * attach table) with no record behind them.  The registry's lock is not held here (dbreg_commit_store() calls the store before it takes it). */
    char oldname[STORE_NAME_MAX + 2];
    oldname[0] = '\0';
    store_zone_t oz;
    store_read_lock();
    uint32_t old = store_find_source(st, m.source, source_id, (uint16_t)vid);
    if (old != STORE_NONE && store_zone_get(st, old, &oz) == 0) snprintf(oldname, sizeof(oldname), "%s.", oz.name);
    store_read_unlock();
    if (oldname[0] && dbreg_delete(view, oldname, source_id) > 0) r = store_put(st, (uint16_t)vid, name, nlen, &m, img, img->total_size, &zid);
    else if (old != STORE_NONE && !oldname[0] && store_delete(st, old) == 0) r = store_put(st, (uint16_t)vid, name, nlen, &m, img, img->total_size, &zid);       /* (a record whose name cannot be read) */
  }
  atomic_fetch_sub_explicit(&v->xfr_refs, 1, memory_order_acq_rel);
  if (r == 0) {
    dmax_raise(vid, labels);
    atomic_fetch_add(&G.wt_put, 1);
    *zid_out = zid;
    return 0;
  }
  note_error("the write", zone, r);
  return r;
}

static int dir_put(const char *view, const char *zone, zone_db_entry_t *entry, int64_t source_id, uint32_t serial, const uint8_t digest[32], uint32_t settings, uint32_t *zid_out) {
  rec_lock();
  int r = dir_put_locked(view, zone, entry, source_id, serial, digest, settings, zid_out);
  rec_unlock();
  return r;
}

static int dir_del_locked(const char *view, const char *zone, int64_t source_id, bool *had) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  char name[DBS_NAME_MAX];
  size_t nlen;
  *had = false;
  if (!st || !store_name(zone, name, sizeof(name), &nlen)) return 0;
  store_zone_t cur;
  int vid;
  uint32_t zid = STORE_NONE;
  store_read_lock();
  vid = store_view_id(st, view);
  if (vid >= 0) zid = store_find(st, (uint16_t)vid, name, nlen);
  int gr = zid != STORE_NONE ? store_zone_get(st, zid, &cur) : -ENOENT;
  store_read_unlock();
  if (gr != 0 && gr != -EBADMSG) return 0;
  if (gr == 0 && source_id != 0 && cur.source_id != 0 && cur.source_id != source_id) return 0;      /* (another source id owns the name) */
  int r = store_delete(st, zid);
  if (r == 0) {
    *had = true;
    atomic_fetch_add(&G.wt_deleted, 1);
    dmax_refresh(st, vid);
  } else if (r != -ENOENT) {
    note_error("the delete", zone, r);
  }
  return r;
}

static int dir_del(const char *view, const char *zone, int64_t source_id, bool *had) {
  rec_lock();
  int r = dir_del_locked(view, zone, source_id, had);
  rec_unlock();
  return r;
}

/* the record loses its image (it is damaged, or the version is not trusted): the zone is read from the database again.  The name finds the record also when its cell cannot be read. */
static void set_known_by_name_locked(const char *view, const char *zone, int64_t source_id, uint32_t serial) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (!st || !store_name(zone, name, sizeof(name), &nlen)) return;
  int vid = store_view_id(st, view);
  uint32_t zid = STORE_NONE;
  store_read_lock();
  if (vid >= 0) zid = store_find(st, (uint16_t)vid, name, nlen);
  store_read_unlock();
  if (zid == STORE_NONE) return;
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.source_id = source_id;
  m.source = (uint16_t)vid;
  m.serial = serial;
  if (store_set_known(st, (uint16_t)vid, name, nlen, &m, NULL) == 0) atomic_fetch_add(&G.wt_invalidated, 1);
}

static void set_known_by_name(const char *view, const char *zone, int64_t source_id, uint32_t serial) {
  rec_lock();
  set_known_by_name_locked(view, zone, source_id, serial);
  rec_unlock();
}

static void dir_note_flags(uint32_t zid, uint16_t set, uint16_t clear) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (st) (void)store_set_flags(st, zid, set, clear);
}

static uint64_t dir_counters(int what) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) return 0;
  store_stats_t ss;
  store_stats(st, &ss);
  switch (what) {
  case 0: return ss.zones_known + ss.zones_stored > ss.zones_nonstore ? ss.zones_known + ss.zones_stored - ss.zones_nonstore : 0;      /* (the records of the database's secondary and catalog zones are the memory of a zone that the heap directory holds: counted there) */
  case 1: return ss.zones_stored;
  case 2: return ss.zones_known;
  case 3: return ss.zones_rejected;
  case 4: return AT.live;
  case 5: { const att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_acquire); return t ? t->cap : 0; }         /* slots of the attach table */
  case 6: return atomic_load_explicit(&AT.grows, memory_order_relaxed);
  case 7: return atomic_load_explicit(&AT.shrinks, memory_order_relaxed);
  default: return 0;
  }
}

/* design 6.7: the texts of rejected zones, by zone id, in err.ring of the store (dbreg_err_set_sink(), dns_server_internal.h) */
static void err_sink_put(uint32_t zid, uint32_t tag, uint64_t stamp, const char *text) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (st && zid != STORE_NONE) (void)store_err_put(st, zid, tag, stamp, text);
}
/* a zone id is reused after a delete (and a text can be left from before a crash): the text is the zone's only when the name tag and the version stamp are the ones it was put with */
static bool err_sink_get(uint32_t zid, uint32_t tag, uint64_t stamp, char *out, size_t cap) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  store_err_t e;
  if (!st || zid == STORE_NONE || !cap || store_err_get(st, zid, &e) != 0) return false;
  if (e.tag != (tag & 0xFFFFFFu) || e.stamp_gen != stamp) return false;
  snprintf(out, cap, "%s", e.text);
  return true;
}
static void err_sink_clear(uint32_t zid) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (st && zid != STORE_NONE) (void)store_err_clear(st, zid);
}
static const dbreg_err_sink_t g_err_sink = { err_sink_put, err_sink_get, err_sink_clear };

/* the figures `karictl store` has of the server's tables (dns_store_status.h) */
static bool extra_status_cb(store_extra_t *x) {
  zone_entry_pool_stats_t ep;
  zone_entry_pool_stats(&ep);
  dbreg_cache_stats_t cs;
  dbreg_cache_stats(&cs);
  x->pool_used = ep.used;
  x->pool_slabs = ep.slabs;
  x->pool_slab_bytes = ep.slab_bytes;
  x->pool_slot_bytes = ep.slot_bytes;
  x->pool_free_slots = ep.free_slots;
  x->attach_slots = dir_counters(5);
  x->attach_grows = dir_counters(6);
  x->attach_shrinks = dir_counters(7);
  dbreg_fold_stats(&x->folded, &x->fold_rows, &x->fold_replaced);
  size_t n = 0;
  dbreg_err_stats(&n, &x->err_noted, &x->err_dropped);
  x->err_texts = n;
  x->sampled_detaches = cs.sampled;
  x->wa_ok = atomic_load(&G.wa_ok);
  x->wa_cold = atomic_load(&G.wa_cold);
  x->wa_over = atomic_load(&G.wa_over);
  x->wa_claim = atomic_load(&G.wa_claim);
  x->wa_fail = atomic_load(&G.wa_fail);
  x->wa_decline = atomic_load(&G.wa_decline);
  x->wa_full = atomic_load(&G.wa_full);
  x->wa_adopted = atomic_load(&G.wa_adopted);
  x->wa_lost = atomic_load(&G.wa_lost);
  x->wa_ns = atomic_load(&G.wa_ns);
  x->hot_state = atomic_load(&G.hot_state);
  x->hot_listed = atomic_load(&G.hot_listed);
  x->hot_attached = atomic_load(&G.hot_attached);
  x->hot_skipped = atomic_load(&G.hot_skipped);
  x->hot_written = atomic_load(&G.hot_written);
  x->hot_threads = atomic_load(&G.hot_nthr);
  x->hot_per_s = hot_rate(x->hot_attached);
  return true;
}

static bool worker_attach(const view_snapshot_t *vs, const zref_t *pel, int widx);       /* (0.7 fix 7, below) */

static const dbdir_ops_t g_ops = {
  .view_sid = dir_view_sid,
  .view_gen = dir_view_gen,
  .depth_max = dir_depth_max,
  .find = dir_find,
  .settings = dir_settings,
  .settings_id = dir_settings_id,
  .rec_get = dir_rec_get,
  .rec_get_nb = dir_rec_get_nb,
  .rec_unchanged = dir_rec_unchanged,
  .put = dir_put,
  .del = dir_del,
  .note_flags = dir_note_flags,
  .attach_reserve = dir_attach_reserve,
  .attach_put = dir_attach_put,
  .attach_remove = dir_attach_remove,
  .attach_count = dir_attach_count,
  .attach_get = dir_attach_get,
  .attach_next = dir_attach_next,
  .attach_sample = dir_attach_sample,
  .attach_tab_id = dir_attach_tab_id,
  .counters = dir_counters,
  .worker_attach = worker_attach,
};

/* the time of the store: group commit and checkpoint, once a second */
static void *ticker_thread(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  pthread_mutex_lock(&G.wlock);
  while (!G.wstop) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    (void)pthread_cond_timedwait(&G.wcv, &G.wlock, &ts);
    if (G.wstop) break;
    store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
    if (st) {
      pthread_mutex_unlock(&G.wlock);
      (void)store_tick(st);
      pthread_mutex_lock(&G.wlock);
    }
  }
  pthread_mutex_unlock(&G.wlock);
  return NULL;
}

void db_store_batch_end(void) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (st) (void)store_commit(st);                        /* what the batch wrote to the store is made durable (group commit) */
}

/* ------------------------------------------------------------------------------------------------------------- */
/* attach                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

typedef struct {
  const store_t *st;
  store_img_t img;
  size_t bytes;
} imgref_t;

static void imgref_free(void *p) {
  imgref_t *r = p;
  atomic_fetch_sub(&G.attached_bytes, r->bytes);
  atomic_fetch_sub(&G.versions_live, 1);
  store_img_release(r->st, &r->img);
  free(r);
}

/* the attach did not work (the record or the image cannot be used, the zone is not the store's to attach): the queries that wait for it are given the park-timeout again and the zone
 * is read from the database.  Only here does a stored zone go to the database.  The workers told are the ones that asked (the claim of the zone: sview, zid; every worker without one). */
/* B1: the claim of a zone id is taken by the store thread that is done with the zone.  The zone id of a record can have been given to another zone since the first worker made the claim (the zone
 * was deleted, a new one took the id): the workers of the claim then include queries for a zone that is gone, which the wake by the new zone's name does not reach (their key is another one) and which
 * would wait for their park-timeout.  The claim keeps the name key of the zone its first worker waited for (park_att_claim_tag()); a key that is not the key of the zone the record holds now says it, and
 * att_gone_wake() sends the workers of the claim the zone id too (park_wake_queue_zid()): the queries that wait for the id and are still waiting after the wake by name ask for the fetch of their own
 * zone, which the database answers as for any zone that was deleted (a failure at once, not the park-timeout).  The wake by the id comes after the wake by name in each worker's ring, so the queries for
 * the new zone are not asked about again.  No claim, or a claim without a key (a worker that attaches by itself), is as before. */
static uint32_t att_take(const char *view, const char *zone, uint16_t sview, uint32_t zid, bool *gone) {
  uint64_t tag = 0;
  const uint32_t ws = park_att_take_tag(sview, zid, &tag);
  *gone = tag != 0 && tag != park_name_key(view, zone);
  return ws;
}

static void att_gone_wake(uint16_t sview, uint32_t zid, uint32_t ws, bool gone) {
  if (gone) park_wake_queue_zid(sview, zid, ws);
}

static void attach_fallback(const char *view, const char *zone, uint16_t sview, uint32_t zid) {
  atomic_fetch_add(&G.attach_fallback, 1);
  bool gone = false;
  const uint32_t ws = zid != STORE_NONE ? att_take(view, zone, sview, zid, &gone) : PARK_ATT_ALL;
  if (park_fetch_request_any(view, zone, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL)) park_wake_queue_retry(view, zone, ws, true);
  else park_wake_queue_ask(view, zone, ws);                  /* (every shared slot is taken: the workers that asked ask from their own rings, and the queries stay parked until their park-timeout; no SERVFAIL for a busy moment) */
  att_gone_wake(sview, zid, ws, gone);
}

/* the zone is in memory: the workers that asked (the claim of the zone) are woken.  A zone that nobody asked for through a claim (a background attach: a CNAME or glue target, a sibling) has none, and
 * nobody waits for it: no key is sent (it would go to every worker, tens of thousands a second in an attach burst). */
static void attach_wake(const char *view, const char *zone, uint16_t sview, uint32_t zid, bool nowait) {
  bool gone;
  const uint32_t ws = att_take(view, zone, sview, zid, &gone);
  if (nowait && ws == PARK_ATT_ALL) return;
  park_wake_queue_mask(view, zone, ws, false);
  att_gone_wake(sview, zid, ws, gone);
}

static uint32_t clamp_ttl(uint32_t v) { return v > 2147483647u ? 2147483647u : v; }

/* Design 6.4: the answers of a zone do not depend on which zones happen to be in memory.  The glue of a name server that lives in another zone of the view (the target of an NS, MX or SRV
 * record outside this zone) is taken from that zone when it is in memory (append_glue_records()); a zone that is only stored would leave the first answer without it.  So the attach of a
 * zone attaches, in the same job and before its queries are woken, the stored zones that its name server, mail and service targets are in (one level: those are attached without looking at
 * their own targets; at most SIB_MAX of them, the first ones in the order of the zone).  The targets are read from the image before the entry is committed (the image is the attach's own
 * until then: nothing is held, no lock is taken for it); the stored zones they are in are looked up after. */
#define SIB_MAX 8
#define SIB_TARGETS 48
typedef struct {
  int n;
  char t[SIB_TARGETS][DBS_NAME_MAX];
} sib_targets_t;
/* the flags of an attach */
enum {
  ATTF_SIB = 1u,                  /* the stored zones of the zone's name server targets are attached too, before its queries are woken */
  ATTF_BG = 2u,                   /* nobody waits (a CNAME or glue target): the zone is marked to go first when memory-limit needs room */
  ATTF_QUIET = 4u                 /* nobody waits, and the zone is not marked (the hot list): no wake-up, and no read from the database when the attach does not work */
};
static void attach_zone_x(const char *view, const char *zone, uint32_t zid, unsigned fl);

static void sib_collect(const zone_image_t *img, const char *zone, sib_targets_t *out) {
  out->n = 0;
  char tg[DNS_NAME_TEXT_SIZE];
  for (uint32_t i = 0; i < img->n_rrs && out->n < SIB_TARGETS; i++) {
    const uint16_t ty = zone_image_rr_type(img, i);
    if ((ty != 2 && ty != 15 && ty != 33) || zone_image_rr_target(img, i, tg, sizeof(tg)) != 0 || domain_name_is_at_or_below(tg, zone) || strlen(tg) >= DBS_NAME_MAX) continue;
    bool dup = false;
    for (int k = 0; k < out->n && !dup; k++) dup = domain_names_match_ci(out->t[k], tg);
    if (!dup) snprintf(out->t[out->n++], DBS_NAME_MAX, "%s", tg);
  }
}

static void sib_attach(const char *view, const sib_targets_t *tg) {
  if (tg->n == 0) return;
  static _Thread_local char names[SIB_MAX][DBS_NAME_MAX], holders[SIB_MAX][KARIDNS_VIEW_NAME_MAX];
  uint32_t zids[SIB_MAX];
  int n = 0;
  rcu_aux_read_lock();
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  view_snapshot_t *vs = snap ? snapshot_find_view(snap, view) : NULL;
  for (int i = 0; vs && i < tg->n && n < SIB_MAX; i++) {
    zref_t z;
    zref_clear(&z);
    if (!zref_find_suffix(vs, tg->t[i], &z) || z.entry || z.el || z.busy || z.zid == ZREF_NOZID || z.zstate != ZREF_ST_ABSENT) continue;
    bool same = false;
    for (int k = 0; k < n && !same; k++) same = domain_names_match_ci(names[k], zref_name(&z));
    if (same) continue;
    snprintf(names[n], sizeof(names[0]), "%s", zref_name(&z));
    snprintf(holders[n], sizeof(holders[0]), "%s", z.hview ? z.hview : view);
    zids[n] = z.zid;
    n++;
  }
  rcu_aux_read_unlock();
  for (int k = 0; k < n; k++) attach_zone_x(holders[k], names[k], zids[k], ATTF_BG);               /* (nobody waits for a sibling: it goes first when memory-limit needs room) */
}

void db_store_attach_zone(const char *view, const char *zone) { attach_zone_x(view, zone, STORE_NONE, ATTF_SIB); }

void db_store_ma_inputs(ma_in_t *in) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) return;
  store_stats_t ss;
  store_stats(st, &ss);
  in->store_mode = ss.mode == STORE_MODE_COPY ? MA_STORE_COPY : MA_STORE_MAP;
  in->stored_zones = ss.zones_stored;
  in->stored_image_bytes = 0;
  for (uint32_t i = 0; i < ss.nviews && i < STORE_MAX_VIEWS; i++) in->stored_image_bytes += ss.views[i].image_bytes;
}

/* 0.7 fix 8: is the list of the zones of a database view still being made (a first fill whose first pass has not ended)?  A query for a zone that the pass has not listed yet is refused as for any name
 * the server does not serve; warm-before-serve holds the queries meanwhile. */
bool db_store_directory_wait(void) { return atomic_load_explicit(&G.dir_pending, memory_order_acquire) != 0; }

/* the same for one view (its id in the store, zref_view_sid()): the list of its zones is not complete, so a name that no stored zone covers may still be a zone that the pass has not listed (0.7, the by-name lookup) */
bool db_store_view_pending(int sid) { return sid >= 0 && sid < 32 && (atomic_load_explicit(&G.dir_pending, memory_order_acquire) & (1u << sid)) != 0; }

bool db_store_filling(void) {
  db_recon_status_t r;
  db_recon_status(&r);
  return r.known_now > 0 && (r.active || r.in_flight > 0);
}

/* An attach brings a zone into memory, so it has to respect the hard line of memory-limit as a fetch does (a fetch waits for room, the wait queue of the ingest thread): the store thread takes the coldest zones
 * out of memory when the database zones are above the hard line, at most once in a millisecond for all of them (32 zones each time), and attaches in any case (an attach is not made to wait: a zone that is stored is answered, and the cache manager
 * brings the zones back under the limit).  Without this a burst of queries for cold zones (or transfers) attached every zone it asked for faster than the manager's rounds took them out (4.5 MB resident under a limit of 1 MB). */
static void attach_make_room(void) {
  if (!dbreg_cache_limit() || !dbreg_cache_over_limit()) return;
  const int64_t now = mono_ns();
  int64_t next = atomic_load_explicit(&G.room_next_ns, memory_order_relaxed);
  if (now < next || !atomic_compare_exchange_strong_explicit(&G.room_next_ns, &next, now + 1000000, memory_order_relaxed, memory_order_relaxed)) return;
  (void)dbreg_cache_make_room(32, NULL);
}

/* what the first half of an attach has made */
typedef struct {
  zone_db_entry_t *entry;         /* the entry, with the image installed as its version (not registered) */
  zone_ext_shared_t *sh;          /* a reference of the zone's settings that the caller gives back */
  sib_targets_t *sib;             /* the name server targets that are outside the zone (malloc; the caller frees it) */
  zone_image_soa_t nums;
  int cause;                      /* STORE_ATT_ERR_*, why not */
  const char *why;
  bool damaged;
} att_built_t;
enum { ATB_OK = 0, ATB_FAIL = -1, ATB_DECLINE = -2 };

/* Do any of the targets lie in a stored zone that is not in memory (the lookup of sib_attach())?  vs: the view of the lookup. */
static bool sib_pending(const view_snapshot_t *vs, const sib_targets_t *tg) {
  for (int i = 0; i < tg->n; i++) {
    zref_t z;
    zref_clear(&z);
    if (!zref_find_suffix(vs, tg->t[i], &z) || z.entry || z.el || z.busy || z.zid == ZREF_NOZID || z.zstate != ZREF_ST_ABSENT) continue;
    return true;
  }
  return false;
}

#define VAL_SAMPLE 8u                      /* the validations whose time is counted: one in this many */
/* The first half of an attach, for the store threads and the worker: the image of the record `sz` (zone id `zid`) is read and validated, the entry made.  Nothing of the registry is touched.
 * wview: the caller is a worker (in its read section; the store's read lock is not taken, nothing is logged for a failure): a zone that has stored zones of its name server targets that are not in
 * memory is declined (ATB_DECLINE: the store threads attach those first, so that the first answer has the glue), as a zone whose image cannot be used is (ATB_FAIL; the store threads look at it again
 * and say why).  On a failure everything that was made is given back, but the settings reference and the list of targets (the caller's). */
static int attach_build(const char *view, const char *zone, uint32_t zid, const store_zone_t *sz, unsigned fl, const view_snapshot_t *wview, att_built_t *b) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  memset(b, 0, sizeof(*b));
  b->cause = STORE_ATT_ERR_OTHER;
  b->why = "";
  store_img_t img;
  bool have_img = false;
  zone_version_t *ver = NULL;
  imgref_t *ref = NULL;
  zone_db_entry_t *entry = NULL;
  int rc = ATB_FAIL;
  if (sz->state != STORE_STATE_STORED) {                      /* known, no image */
    atomic_fetch_add(&G.attach_missing, 1);
    b->why = "missing";
    return rc;
  }
  if (!wview) store_read_lock();
  int r = store_image_read(st, zid, &img);
  if (!wview) store_read_unlock();
  have_img = r == 0;
  if (r != 0) {
    if (r == -ENOENT) {
      atomic_fetch_add(&G.attach_missing, 1);
      b->why = "missing";
    } else if (r == -EBADMSG) {
      b->damaged = true;
      b->cause = STORE_ATT_ERR_CHECKSUM;
      b->why = "damaged";
    } else {
      b->cause = r == -ENOMEM ? STORE_ATT_ERR_MEMORY : STORE_ATT_ERR_IO;
      b->why = "read";
    }
    return rc;
  }
  /* the image: the store's checksum detects damage, not a forgery (it is not keyed), and what the engine serves must be an image that zone_image_validate() accepts (the
   * offsets it follows are all checked there): every attach validates the image it read, the first read of a record and every later one (an image is about a kilobyte for the
   * zones this store is for; the time is counted, db_store_counters_t.validate_ns).  The apex name too (the validator does not know the zone). */
  const zone_image_t *zi = img.data;
  if (img.len < sizeof(zone_image_t) || ((uintptr_t)img.data & 7u) != 0 || zi->magic != ZONE_IMAGE_MAGIC || zi->version != ZONE_IMAGE_VERSION || zi->total_size != img.len) {
    b->damaged = true;
    b->cause = STORE_ATT_ERR_INVALID;
    b->why = "not an image";
    goto fail;
  }
  {
    char vw[96] = "";
    /* the time of the validations is counted for one in VAL_SAMPLE of them (scaled): where the clock is a system call (a virtual machine without a TSC clock) two readings were a tenth of all the CPU an attach took */
    static _Thread_local unsigned val_n;
    const bool timed = (val_n++ % VAL_SAMPLE) == 0;
    const int64_t tv0 = timed ? mono_ns() : 0;
    int vr = zone_image_validate(img.data, img.len, vw, sizeof(vw));
    if (timed) atomic_fetch_add(&G.validate_ns, (uint64_t)(mono_ns() - tv0) * VAL_SAMPLE);
    atomic_fetch_add(&G.validated, 1);
    if (vr != 0) {
      b->damaged = true;
      b->cause = STORE_ATT_ERR_INVALID;
      b->why = "the image is not valid";
      if (!wview) syslog(LOG_WARNING, "[Store] the image of zone '%s' (view '%s') is not valid: %s", zone, view, vw);
      goto fail;
    }
  }
  {
    uint32_t apex = zone_image_find_name(zi, zone);
    uint32_t soa = zone_image_apex_soa(zi);
    if (apex == ZONE_IMAGE_NONE || apex != zi->apex_name || soa == ZONE_IMAGE_NONE || zone_image_soa(zi, soa, NULL, 0, NULL, 0, &b->nums) != 0 || b->nums.serial != sz->serial) {
      b->damaged = true;
      b->cause = STORE_ATT_ERR_INVALID;
      b->why = "the image is not the zone's";
      goto fail;
    }
  }
  if (fl & ATTF_SIB) {                                        /* (the targets are read from the image before the entry is committed: after it the image may be taken out of memory) */
    b->sib = malloc(sizeof(*b->sib));
    if (b->sib) sib_collect(zi, zone, b->sib);
    if (wview && b->sib && sib_pending(wview, b->sib)) {
      rc = ATB_DECLINE;
      goto fail;
    }
  }
  if (sz->settings) {
    b->sh = dir_settings(sz->settings);
    if (!b->sh) {                                             /* (the settings text of the record is not known: the zone is read from the database, which sends it) */
      b->why = "settings";
      goto fail;
    }
    zone_ext_shared_ref(b->sh);
  }
  entry = db_ingest_new_entry(view, zone, b->sh);
  if (!entry) {
    b->cause = STORE_ATT_ERR_MEMORY;
    b->why = "memory";
    goto fail;
  }
  ref = malloc(sizeof(*ref));
  if (!ref) {
    b->cause = STORE_ATT_ERR_MEMORY;
    b->why = "memory";
    goto fail;
  }
  {
    /* what the version counts for the image: the mapped bytes, or the buffer the store read (the allocator's size) */
    size_t bytes = img.len;
    if (img.priv_) bytes = dns_alloc_size(img.priv_, (size_t)((64u + (((size_t)sz->klen + 15u) & ~(size_t)15u) + img.len + 63u) & ~63u));
    ref->st = st;
    ref->img = img;
    ref->bytes = bytes;
    ver = zone_version_new_ext((zone_image_t *)(uintptr_t)img.data, bytes, imgref_free, ref);
  }
  if (!ver) {
    free(ref);
    ref = NULL;
    b->cause = STORE_ATT_ERR_MEMORY;
    b->why = "memory";
    goto fail;
  }
  have_img = false;                                          /* the version owns the image from here (imgref_free() gives it back) */
  atomic_fetch_add(&G.attached_bytes, ref->bytes);
  atomic_fetch_add(&G.versions_live, 1);
  atomic_store_explicit(&entry->serial, b->nums.serial, memory_order_relaxed);
  atomic_store_explicit(&entry->refresh, clamp_ttl(b->nums.refresh), memory_order_relaxed);
  atomic_store_explicit(&entry->retry, clamp_ttl(b->nums.retry), memory_order_relaxed);
  atomic_store_explicit(&entry->expire, clamp_ttl(b->nums.expire), memory_order_relaxed);
  /* (the entry is new: nobody can reach it before it is registered or staged, so its writer lock is not taken, and a light entry never makes the lock's block (libthr makes it at the first lock; ~112 octets for every attached zone)) */
  zone_install_version(entry, ver, NULL, false);
  b->entry = entry;
  return ATB_OK;
fail:
  if (have_img) store_img_release(st, &img);
  if (entry) free_zone_db_entry(entry);
  return rc;
}

/* an attach that did not work: why is logged and counted, a damaged record is set back to "known" (the next look takes the fetch path at once), the zone is read from the database for the queries that
 * wait for it (a quiet attach has none: nothing is asked of the database) */
static void attach_fail(const char *view, const char *zone, uint16_t sview, uint32_t zid, const store_zone_t *sz, unsigned fl, att_built_t *b) {
  zone_ext_shared_unref(b->sh);
  free(b->sib);
  if (b->damaged) {
    atomic_fetch_add(&G.attach_damaged, 1);
    syslog(LOG_WARNING, "[Store] the record of zone '%s' (view '%s') cannot be used (%s); the zone is read from the database again", zone, view, b->why);
    set_known_by_name(view, zone, sz->source_id, sz->serial);   /* (the next look takes the fetch path at once, not an attach that fails again) */
  }
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[Store] zone '%s' (view '%s') not attached from the store: %s%s", zone, view, b->why, (fl & ATTF_QUIET) ? "" : "; fetched from the database");
  store_status_note_attach(0, b->cause);
  if (!(fl & ATTF_QUIET)) attach_fallback(view, zone, sview, zid);
}

static void attach_core(const char *view, const char *zone, uint16_t sview, uint32_t zid, const store_zone_t *sz, int64_t t0, unsigned fl, int tries);

/* What follows the registry's answer `c` (DBREG_ATT_*) for the attach of a zone whose entry b->entry was made (attach_build()) and offered to the registry (dbreg_attach_store(), or one item of
 * dbreg_attach_store_n()): the entry is the registry's when it started, and otherwise freed here; the zone is told (the queries that wait are woken).  The settings reference and the list of
 * targets of b are given back.  sz: the record the entry was made from. */
static void attach_finish(const char *view, const char *zone, uint16_t sview, uint32_t zid, const store_zone_t *sz, int64_t t0, unsigned fl, int tries, int c, att_built_t *b) {
  const bool nowait = (fl & (ATTF_BG | ATTF_QUIET)) != 0;
  if (c != DBREG_ATT_STARTED) {
    free_zone_db_entry(b->entry);                            /* never registered; its version (and the image) go with it */
    zone_ext_shared_unref(b->sh);
    free(b->sib);
    if (c == DBREG_ATT_RESIDENT) {                           /* (another attach or a fetch was first) */
      atomic_fetch_add(&G.attach_resident, 1);
      attach_wake(view, zone, sview, zid, nowait);
    } else if (c == DBREG_ATT_STALE && tries < 2) {           /* a newer version, a delete or a cell that was being written came after the record was read: read it again */
      store_zone_t again;
      store_read_lock();
      const int rr = store_zone_get(atomic_load_explicit(&G.st, memory_order_acquire), zid, &again);
      store_read_unlock();
      if (rr == 0 && again.view == sz->view && again.klen == sz->klen) attach_core(view, zone, sview, zid, &again, t0, fl, tries + 1);
      else if (!(fl & ATTF_QUIET)) attach_fallback(view, zone, sview, zid);
    } else if (c == DBREG_ATT_BUSY) {
      /* a fetch (or another attach) of the zone is on its way and wakes the queries that wait when it is done.  They were parked for the attach deadline, though: they are
       * given the park-timeout (a retry key), or they would be answered "not ready" at 200 ms behind a cold read that takes longer */
      atomic_fetch_add(&G.attach_busy, 1);
      bool gone;
      const uint32_t ws = att_take(view, zone, sview, zid, &gone);
      park_wake_queue_retry(view, zone, ws, false);
      att_gone_wake(sview, zid, ws, gone);
    } else {
      atomic_fetch_add(&G.attach_stale, 1);
      if (!(fl & ATTF_QUIET)) attach_fallback(view, zone, sview, zid);
      store_status_note_attach(0, STORE_ATT_ERR_OTHER);
    }
    return;
  }
  zone_ext_shared_unref(b->sh);
  atomic_fetch_add(&G.attach_ok, 1);
  const int64_t took = mono_ns() - t0;                       /* (one reading of the clock: where it is a system call, it is the dearest thing a small attach does)  */
  store_status_note_attach((uint64_t)took, STORE_ATT_OK);
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[Store] zone '%s' (view '%s'), serial %u attached from the store in %lld us", zone, view, sz->serial, (long long)(took / 1000));
  if (b->sib) {
    sib_attach(view, b->sib);                                /* (before the queries are woken: their first answer has the glue of the zones it depends on) */
    free(b->sib);
  }
  attach_wake(view, zone, sview, zid, nowait);
}

/* The attach of the zone `zone` of the view `view` whose record `sz` (zone id `zid`) the caller has read: the image is read and validated, the entry made (attach_build()), and the registry takes it in one
 * section of its lock (dbreg_attach_store()); then the stored zones of its name server targets, and the queries that wait for the zone (the workers that asked) are woken.
 * fl: ATTF_*. */
static void attach_core(const char *view, const char *zone, uint16_t sview, uint32_t zid, const store_zone_t *sz, int64_t t0, unsigned fl, int tries) {
  const bool bg = (fl & ATTF_BG) != 0, nowait = (fl & (ATTF_BG | ATTF_QUIET)) != 0;
  /* the zone may be in memory already (another attach, a fetch, a worker's attach that is not registered yet): nothing to read then */
  {
    rcu_aux_read_lock();
    const zdir_elem_t *el = dir_attach_get(zid);
    const bool res = (el && zdir_entry(el) != NULL) || stg_get(zid) != NULL;
    rcu_aux_read_unlock();
    if (res) {
      atomic_fetch_add(&G.attach_resident, 1);
      attach_wake(view, zone, sview, zid, nowait);
      return;
    }
  }
  att_built_t b;
  if (attach_build(view, zone, zid, sz, fl, NULL, &b) != ATB_OK) {
    attach_fail(view, zone, sview, zid, sz, fl, &b);
    return;
  }
  /* The commit checks, under the registry's lock and in the same section that makes the zone's element, that nothing has the zone: a fetch or another attach that is on its way, a zone that is in memory.  The record was read
   * before the lock; a newer version that was stored after that is committed by its own install (which replaces this entry), or finds the zone's element and waits for it. */
  dbdir_rec_t rec;
  rec_from_zone(sz, &rec);
  const int c = dbreg_attach_store(view, zone, &rec, b.entry, bg, NULL, NULL);
  attach_finish(view, zone, sview, zid, sz, t0, fl, tries, c, &b);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* 0.7 fix 7: the worker's attach                                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

/* A query for a zone of the store that is not in memory used to wait for a store thread: the worker parks it, asks through a ring, the thread reads the image, makes the entry, takes the registry's lock
 * and wakes the worker, which looks the query up again (8 to 16 ms at 200,000 first touches a second, the rings full).  Now a worker that finds the zone's image in the page cache does the whole of it
 * itself, in the read section it is in, and answers at once:
 *   - MAP mode and mincore() say the pages of the record are resident (store_image_resident()); COPY mode (ZFS: pread blocks) and an image that is not resident are the store threads', as before;
 *   - the zone's claim (park_att_claim(), the one that keeps the workers from asking twice) is taken: a worker that does not get it joins the claim of the other and parks, as before;
 *   - the image is read and validated and the entry made (attach_build(), what a store thread does: the checksum, zone_image_validate()); a zone whose name server targets are stored zones that are not in
 *     memory is left to the store threads (they attach those first, for the glue of the first answer), and so is anything above the hard line of memory-limit (they make room);
 *   - the entry is published for the lookup in the staging table (a compare-and-swap) as a staged element, and the zone is queued for registration: a store thread registers it (dbreg_attach_store(),
 *     the one section of the registry's lock) and takes the staged element out (adopt_job()).  The worker takes no lock of the registry, and no store thread is waited for.  A registry operation that
 *     comes before the registration (a new version, a delete) does not see the zone: the registration finds the record changed or the zone in memory, and drops the staged element; the queries that were
 *     answered meanwhile were answered by the version the record had (as a query in a read section that a writer passes).
 * What this does that "a worker never sleeps and never allocates" does not allow, and why it is kept: it allocates (the entry, the version, the staged element: a few hundred bytes from the allocator's thread
 * cache, no system call) and takes the entry pool's lock (a few instructions).  The residual risk is that a page can leave the page cache between mincore() and the first touch (the cache is under pressure):
 * the worker then reads that page from the disk, once, as it does when a lookup touches a page of the tables (the name index, the zone table) that was evicted.  That risk is the one MAP mode has on
 * every lookup, bounded by what is touched here (a record of about a kilobyte, one or two pages), and it is the reason COPY mode does not do this at all (docs/karidns.md, "The zone store"). */
static bool worker_attach(const view_snapshot_t *vs, const zref_t *pel, int widx) {
  if (!atomic_load_explicit(&G.wa_on, memory_order_relaxed)) return false;
  if (!vs->name || pel->el || pel->busy || (pel->hview && strcmp(pel->hview, vs->name) != 0) || pel->zstate != ZREF_ST_ABSENT || pel->zid == ZREF_NOZID || pel->sview < 0) return false;
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) return false;
  /* (the entry's settings are looked up in auxiliary read sections (db_ingest_new_entry()): the worker is in its own read section, which covers them without a slot of the table of auxiliary readers
   * (rcu_aux_read_lock()); no slot is pinned for the worker, 126 of them could not all have one) */
  const int64_t t0 = mono_ns();
  const uint16_t sview = (uint16_t)pel->sview;
  store_zone_t sz;
  if (store_zone_get(st, pel->zid, &sz) != 0 || sz.state != STORE_STATE_STORED || (sz.flags & STORE_F_NONSTORE) || sz.view != sview || (size_t)sz.klen + 1 != strlen(pel->name) ||
      strncasecmp(sz.name, pel->name, sz.klen) != 0)
    return false;
  bool resident = store_image_resident(st, &sz);
  if (atomic_load_explicit(&db_store_test_resident, memory_order_relaxed)) resident = true;
  if (atomic_load_explicit(&db_store_test_not_resident, memory_order_relaxed)) resident = false;
  if (!resident) {                                            /* (not in the page cache, or COPY mode) */
    atomic_fetch_add_explicit(&G.wa_cold, 1, memory_order_relaxed);
    return false;
  }
  if (dbreg_cache_over_limit()) {                             /* (the store threads make room first) */
    atomic_fetch_add_explicit(&G.wa_over, 1, memory_order_relaxed);
    return false;
  }
  if (!park_attach_room(widx)) {
    atomic_fetch_add_explicit(&G.wa_full, 1, memory_order_relaxed);
    return false;
  }
  if (park_att_claim(sview, pel->zid, widx) != 1) {           /* (another worker, or a store thread, is on the zone: this query joins it) */
    atomic_fetch_add_explicit(&G.wa_claim, 1, memory_order_relaxed);
    return false;
  }
  att_built_t b;
  const int r = attach_build(vs->name, pel->name, pel->zid, &sz, ATTF_SIB, vs, &b);
  zone_ext_shared_unref(b.sh);
  free(b.sib);
  if (r != ATB_OK) {                                          /* (the store threads look at it again, and say why) */
    atomic_fetch_add_explicit(r == ATB_DECLINE ? &G.wa_decline : &G.wa_fail, 1, memory_order_relaxed);
    (void)park_att_leave(sview, pel->zid, widx);
    return false;
  }
  dbdir_rec_t rec;
  rec_from_zone(&sz, &rec);
  zdir_elem_t *s = dbreg_staged_new(pel->name, sview, &rec, b.entry);
  if (!s || !stg_put(s)) {
    if (s) dbreg_staged_free(s);
    free_zone_db_entry(b.entry);
    atomic_fetch_add_explicit(&G.wa_full, 1, memory_order_relaxed);
    (void)park_att_leave(sview, pel->zid, widx);
    return false;
  }
  (void)park_attach_adopt(widx, sview, pel->zid);             /* (room was made sure of above: only this worker pushes to its ring) */
  const uint32_t ws = park_att_take(sview, pel->zid);        /* the workers that joined while this one worked: their queries are looked up again */
  const uint64_t ns = (uint64_t)(mono_ns() - t0);
  atomic_fetch_add_explicit(&G.wa_ok, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&G.wa_ns, ns, memory_order_relaxed);
  store_status_note_attach(ns, STORE_ATT_OK);
  const uint32_t others = ws == PARK_ATT_ALL ? 0 : (widx < 15 ? ws & ~(1u << widx) : ws);
  if (others) {
    park_wake_queue_mask(vs->name, pel->name, others, false);
    park_wake_flush();
  }
  return true;
}

/* A staged element that has been registered (taken out of the staging table) is freed after the grace period of the readers that may have found it.  It holds no reference of the entry (the
 * registry has the entry), so the entry can be taken out of memory at once; only the element waits here, in the order of its epochs, and is freed by the next registration or at the stop. */
typedef struct stg_ret {
  struct stg_ret *next;
  zdir_elem_t *s;
  uint64_t epoch;
} stg_ret_t;
static struct {
  pthread_mutex_t lock;
  stg_ret_t *head, *tail;
} STGR = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void stgr_run(bool force) {
  pthread_mutex_lock(&STGR.lock);
  while (STGR.head && (force || rcu_writer_is_safe(STGR.head->epoch))) {
    stg_ret_t *r = STGR.head;
    STGR.head = r->next;
    if (!STGR.head) STGR.tail = NULL;
    dbreg_staged_free(r->s);
    free(r);
  }
  pthread_mutex_unlock(&STGR.lock);
}

static void stgr_push(zdir_elem_t *s) {
  stg_ret_t *r = malloc(sizeof(*r));
  const uint64_t ep = rcu_writer_advance_epoch();
  if (!r) {                                                   /* (no memory for the node: the grace period is waited for here) */
    (void)rcu_writer_wait_until_safe(ep, 60000);
    dbreg_staged_free(s);
    return;
  }
  r->s = s;
  r->epoch = ep;
  r->next = NULL;
  pthread_mutex_lock(&STGR.lock);
  if (STGR.tail) STGR.tail->next = r;
  else STGR.head = r;
  STGR.tail = r;
  pthread_mutex_unlock(&STGR.lock);
}

static void stg_remove_cb(void *s) { stg_remove(s); }

/* The registration of a staged zone, by a store thread (the request of the worker's ring that has PARK_ATT_ADOPT): the same section of the registry's lock as an attach, with the record the staged
 * element holds.  Whatever the outcome the staged element goes out of the table (a reader that has it is done with it after the grace period).  Nobody is woken: the worker that staged the zone
 * answered, and the workers that joined its claim were woken by it. */
static void adopt_job(uint16_t sview, uint32_t zid) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  {
    void (*hook)(void) = atomic_load_explicit(&db_store_test_adopt_hook, memory_order_acquire);
    if (hook) hook();
  }
  stgr_run(false);
  rcu_aux_read_lock();
  zdir_elem_t *s = stg_get(zid);
  const char *view = st ? store_view_name(st, sview) : NULL;
  if (atomic_load_explicit(&db_store_test_adopt_noview, memory_order_relaxed)) view = NULL;
  if (!s || !view) {
    rcu_aux_read_unlock();
    if (s) {                                                  /* the store is closing, or the view id is not one (B2): the staged element would stay in the table for ever (and hold its entry) and the zone id could not be staged again.  Nobody is left to wake: the worker that staged it answered, took the claim of the zone and woke the workers that had joined it (worker_attach()) */
      stg_remove(s);
      atomic_fetch_add_explicit(&G.wa_lost, 1, memory_order_relaxed);
      dbreg_staged_retire(s, true);
    }
    return;
  }
  zone_db_entry_t *entry = zdir_entry(s);
  dbdir_rec_t rec;
  dbreg_staged_rec(s, &rec);
  /* the staged element leaves the staging table inside the registry's lock section (stg_remove_cb(), after the zone is in the attach table): a worker that looks the zone up between the registration
   * and a later removal could find an element whose entry the cache manager has evicted and retired meanwhile (an eviction takes the same lock) */
  const int c = dbreg_attach_store(view, s->name, &rec, entry, false, stg_remove_cb, s);
  rcu_aux_read_unlock();
  if (c == DBREG_ATT_STARTED) {
    atomic_fetch_add(&G.attach_ok, 1);
    atomic_fetch_add_explicit(&G.wa_adopted, 1, memory_order_relaxed);
    stgr_push(s);
  } else {                                                    /* in memory already, changed since, or gone: the entry that the worker answered from is not the registry's */
    atomic_fetch_add_explicit(&G.wa_lost, 1, memory_order_relaxed);
    dbreg_staged_retire(s, true);
  }
}

/* An attach by the zone's name (the engine's background attach of a CNAME or glue target, a transfer thread, the sibling of a zone): the record is looked up by name, or, with `zid`, read
 * by id */
static void attach_zone_x(const char *view, const char *zone, uint32_t zid, unsigned fl) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) {
    park_wake_queue_all(view, zone, true);
    return;
  }
  const int64_t t0 = mono_ns();
  attach_make_room();
  char name[DBS_NAME_MAX];
  size_t nlen = 0;
  store_zone_t sz;
  int r = -ENOENT;
  uint16_t sview = 0;
  if (store_name(zone, name, sizeof(name), &nlen)) {
    store_read_lock();
    int vid = store_view_id(st, view);
    if (vid >= 0) {
      sview = (uint16_t)vid;
      if (zid == STORE_NONE) zid = store_find(st, sview, name, nlen);
      r = zid == STORE_NONE ? -ENOENT : store_zone_get(st, zid, &sz);
    }
    store_read_unlock();
  }
  if (r == 0 && !(sz.view == sview && sz.klen == nlen)) r = -ENOENT;     /* (the zone id is another zone's now) */
  if (r != 0) {
    atomic_fetch_add(&G.attach_missing, 1);
    const bool dmg = r == -EBADMSG;
    if (dmg) atomic_fetch_add(&G.attach_damaged, 1);
    logev_post(LOGC_DATABASE, 2, NULL, 0, "[Store] zone '%s' (view '%s') not attached from the store: %s; fetched from the database", zone, view, dmg ? "damaged" : "missing");
    store_status_note_attach(0, dmg ? STORE_ATT_ERR_RECORD : STORE_ATT_ERR_OTHER);
    attach_fallback(view, zone, sview, zid);
    return;
  }
  attach_core(view, zone, sview, zid, &sz, t0, fl, 0);
}

/* 0.7 M4: the attach of several zones in one section of the registry's lock.  A burst of first queries on a ZFS store (COPY mode: no attach by a worker) sends tens of thousands of attach requests a
 * second to the store threads; each of them took the registry's lock for its own registration, 2 to 4 microseconds of work behind a contended mutex, and a thread that waits for it sleeps and is woken
 * (measured at 10 million zones: 96 microseconds waiting for every 4 of work, 8 threads: 37,000 attaches a second, the store threads idle but for that wait).  A thread now makes the entries of the
 * requests it finds waiting (up to ATT_BATCH), then registers them in one section of the lock (dbreg_attach_store_n()), then tells the queries.  The first request of a batch waits for the entries of the
 * others to be made (tens of microseconds each); a thread that finds one request registers it at once, as before. */
#define ATT_BATCH 16
typedef struct {
  store_zone_t sz;               /* the record the entry was made from */
  att_built_t b;                 /* the entry (attach_build()) */
  dbdir_rec_t rec;
  char view[KARIDNS_VIEW_NAME_MAX];
  char zone[STORE_NAME_MAX + 2];
  int64_t t0;
  unsigned fl;                   /* ATTF_* */
} att_job_t;

/* the entries of jobs[0..n) are registered together; each job's zone is then told as an attach of one zone tells it (attach_finish()) */
static void attach_batch_run(att_job_t *jobs, size_t n, dbreg_att_item_t *ri) {
  for (size_t i = 0; i < n; i++) {
    att_job_t *j = &jobs[i];
    rec_from_zone(&j->sz, &j->rec);
    ri[i].view = j->view;
    ri[i].name = j->zone;
    ri[i].rec = &j->rec;
    ri[i].entry = j->b.entry;
    ri[i].bg = (j->fl & ATTF_BG) != 0;
  }
  dbreg_attach_store_n(ri, n);
  for (size_t i = 0; i < n; i++) {
    att_job_t *j = &jobs[i];
    attach_finish(j->view, j->zone, j->sz.view, j->sz.zid, &j->sz, j->t0, j->fl, 0, ri[i].result, &j->b);
  }
}

/* A request of a worker for the zone with the id `zid` of the view `sview` (the worker's lookup named it, and nothing else: 8 bytes): the record gives the names.  The first half of the attach: the
 * record is read and the entry made.  true: the entry is in *j, to be registered (attach_batch_run()); false: there is nothing more to do (the zone is gone, in memory, or its image cannot be used: told). */
static bool attach_job_prep(const park_attach_req_t *q, att_job_t *j) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) return false;
  j->t0 = mono_ns();
  j->fl = ATTF_SIB;
  const char *vn;
  store_read_lock();
  const int r = store_zone_get(st, q->zid, &j->sz);
  vn = r == 0 && j->sz.view == q->sview ? store_view_name(st, q->sview) : NULL;
  if (vn) snprintf(j->view, sizeof(j->view), "%s", vn);
  store_read_unlock();
  if (!vn) {                                                 /* the zone is gone, its record cannot be read, or the id is another view's now: there is no name to wake by.  The workers of the claim are told the id: the queries that wait for it ask for the fetch of their own zones (a zone the database has no more ends at once: the fetch finds nothing, as for any zone that was deleted meanwhile) */
    park_wake_queue_zid(q->sview, q->zid, park_att_take(q->sview, q->zid));
    atomic_fetch_add(&G.attach_missing, 1);
    store_status_note_attach(0, r == -EBADMSG ? STORE_ATT_ERR_RECORD : STORE_ATT_ERR_OTHER);
    return false;
  }
  attach_make_room();
  snprintf(j->zone, sizeof(j->zone), "%s.", j->sz.name);
  /* the zone may be in memory already (another attach, a fetch, a worker's attach that is not registered yet): nothing to read then */
  {
    rcu_aux_read_lock();
    const zdir_elem_t *el = dir_attach_get(q->zid);
    const bool res = (el && zdir_entry(el) != NULL) || stg_get(q->zid) != NULL;
    rcu_aux_read_unlock();
    if (res) {
      atomic_fetch_add(&G.attach_resident, 1);
      attach_wake(j->view, j->zone, q->sview, q->zid, false);
      return false;
    }
  }
  if (attach_build(j->view, j->zone, q->zid, &j->sz, j->fl, NULL, &j->b) != ATB_OK) {
    attach_fail(j->view, j->zone, q->sview, q->zid, &j->sz, j->fl, &j->b);
    return false;
  }
  return true;
}

/* An attach request by the zone's name (the engine's background attach of a CNAME or glue target, a transfer thread, the sibling of a zone) */
static void attach_job(const park_attach_req_t *q, unsigned fl) {
  attach_zone_x(q->view, q->zone, STORE_NONE, ATTF_SIB | fl | (q->prio == 2 /* park_attach_request_bg() */ ? ATTF_BG : 0));
}

/* what a store thread does when it is awake: the requests that wait, in batches (ATT_BATCH) for the registration; true: there was one */
static bool attach_drain(att_job_t *jobs, dbreg_att_item_t *ri) {
  park_attach_req_t q;
  bool any = false;
  size_t n = 0;
  while (park_attach_next(&q)) {
    any = true;
    if (q.adopt) {
      adopt_job(q.sview, q.zid);
    } else if (q.by_name) {
      attach_job(&q, 0);
    } else if (attach_job_prep(&q, &jobs[n]) && ++n == ATT_BATCH) {
      attach_batch_run(jobs, n, ri);
      n = 0;
    }
  }
  if (n) attach_batch_run(jobs, n, ri);
  return any;
}

#if defined(__FreeBSD__)
static void *attach_thread(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  att_job_t jobs[ATT_BATCH];
  dbreg_att_item_t ri[ATT_BATCH];
  while (!atomic_load_explicit(&G.astop, memory_order_acquire)) {
    if (attach_drain(jobs, ri)) park_wake_flush();
    if (park_attach_sleep_prepare()) continue;
    struct kevent ev;
    struct timespec to = { 0, 200000000L };
    (void)kevent(G.akq, NULL, 0, &ev, 1, &to);
    park_attach_sleep_done();
  }
  return NULL;
}
#else
static void *attach_thread(void *arg) {
  (void)arg;
  att_job_t jobs[ATT_BATCH];
  dbreg_att_item_t ri[ATT_BATCH];
  while (!atomic_load_explicit(&G.astop, memory_order_acquire)) {
    if (attach_drain(jobs, ri)) park_wake_flush();
    struct timespec nap = { 0, 1000000L };
    nanosleep(&nap, NULL);
  }
  return NULL;
}
#endif

/* ------------------------------------------------------------------------------------------------------------- */
/* 0.7 fix 8: hot.list                                                                                            */
/* ------------------------------------------------------------------------------------------------------------- */

/* At a clean stop the zones that are in memory are written to hot.list of the store (the ids, the most used first, at most STORE_HOT_MAX); the next start reads it and threads of their own attach the
 * zones in that order, in the background, while the queries are served: a restart with the page cache of the old run kept answers from memory almost at once, and one with a cold page cache reads the
 * images the queries are going to want in the order they are going to want them.  0.7 M4: there are several threads (three quarters of the store threads, at most six) with no rate cap, and they give the
 * queries only a moment (hot_defer()): a restart on ZFS (COPY mode, where a worker cannot attach a zone itself) has its first second of queries for the hottest zones, and one thread that waited while any
 * query waited, at 20,000 zones a second, was starved by exactly that rush.  They stop at the high mark of memory-limit (the zones they attached are the hottest ones: nothing is taken out for the rest of
 * the list).  `store-hot-list no;` turns both off. */

static int hot_cmp(const void *a, const void *b) {         /* the highest score first, the zone id decides a tie */
  const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return x < y ? 1 : x > y ? -1 : 0;
}

/* the list of the zones in memory, written (a clean stop) */
static void hot_write(store_t *st) {
  size_t cap = dir_attach_count() + 4096;
  if (cap > STORE_HOT_MAX) cap = STORE_HOT_MAX;
  uint64_t *sc = malloc(cap * sizeof(*sc));
  uint32_t *ids = malloc(cap * sizeof(*ids));
  if (!sc || !ids) {
    free(sc);
    free(ids);
    return;
  }
  size_t n = dbreg_hot_collect(sc, cap);
  qsort(sc, n, sizeof(*sc), hot_cmp);
  for (size_t i = 0; i < n; i++) ids[i] = (uint32_t)sc[i];
  const int r = store_hot_write(st, ids, n);
  if (r == 0) {
    atomic_store(&G.hot_written, n);
    syslog(LOG_INFO, "[Store] hot.list: %zu zone(s) in memory written for the next start", n);
  } else {
    syslog(LOG_WARNING, "[Store] hot.list cannot be written (%s); the next start attaches zones when they are asked for", strerror(-r));
  }
  free(sc);
  free(ids);
}

/* The zones of the list are taken in batches of HOT_BATCH, in the order of the list, by the threads of the hot list (three quarters of the store threads, at most HOT_THREADS_MAX: the others are the
 * queries'); a thread reads the records and the images of its batch, makes the entries, and registers them in one section of the registry's lock (dbreg_attach_store_n()).  The zones it attaches are the
 * ones the queries are going to ask for first, and a query that asks for one of them before the thread has it is answered by the attach of its own request (the zone that is in memory when the thread
 * comes to it is skipped).  A zone attached for nobody has no queries to wake, and no read from the database when it does not work (ATTF_QUIET).
 * The zones ids[0..n) of the list: skipped (in memory already, deleted, not stored) or attached; an attach that did not work is counted and logged as any attach is. */
static void hot_attach_batch(store_t *st, const uint32_t *ids, size_t n, att_job_t *it, dbreg_att_item_t *ri) {
  size_t m = 0;
  const int64_t t0 = mono_ns();
  void (*hook)(uint32_t) = atomic_load_explicit(&db_store_test_hot_hook, memory_order_acquire);
  for (size_t i = 0; i < n; i++) {
    const uint32_t zid = ids[i];
    if (hook) hook(zid);
    att_job_t *h = &it[m];
    const char *vn = NULL;
    store_read_lock();
    const int r = store_zone_get(st, zid, &h->sz);
    if (r == 0) vn = store_view_name(st, h->sz.view);
    if (vn) snprintf(h->view, sizeof(h->view), "%s", vn);
    store_read_unlock();
    bool ok = vn && h->sz.state == STORE_STATE_STORED && !(h->sz.flags & STORE_F_NONSTORE);
    if (ok) {
      rcu_aux_read_lock();
      const zdir_elem_t *el = dir_attach_get(zid);
      ok = !((el && zdir_entry(el) != NULL) || stg_get(zid) != NULL);
      rcu_aux_read_unlock();
    }
    if (!ok) {
      atomic_fetch_add(&G.hot_skipped, 1);
      continue;
    }
    atomic_fetch_add(&G.hot_attached, 1);
    snprintf(h->zone, sizeof(h->zone), "%s.", h->sz.name);
    h->t0 = t0;
    h->fl = ATTF_SIB | ATTF_QUIET;
    if (attach_build(h->view, h->zone, zid, &h->sz, ATTF_SIB, NULL, &h->b) != ATB_OK) {
      attach_fail(h->view, h->zone, h->sz.view, zid, &h->sz, ATTF_QUIET, &h->b);
      continue;
    }
    m++;
  }
  if (m) attach_batch_run(it, m, ri);
  park_wake_flush();
}

/* the thread of the list that leaves last says how it ended */
static void hot_finish(void) {
  atomic_store(&G.hot_end_ns, mono_ns());
  const bool lim = atomic_load(&G.hot_limit);
  atomic_store(&G.hot_state, lim ? DBS_HOT_LIMIT : DBS_HOT_DONE);
  if (!atomic_load_explicit(&G.hstop, memory_order_acquire))
    syslog(LOG_NOTICE, "[Store] hot.list: %llu zone(s) attached in the background by %u thread(s), %llu skipped (in memory already, or not stored)%s", (unsigned long long)atomic_load(&G.hot_attached),
           (unsigned)atomic_load(&G.hot_nthr), (unsigned long long)atomic_load(&G.hot_skipped), lim ? "; stopped at the high mark of memory-limit" : "");
}

/* The queries come first, but the list is never starved by them (the starvation of 0.6.2: it waited for as long as any request waited, and in the rush of first queries after a restart one always did):
 * before a batch a thread gives the requests that wait up to HOT_YIELD_US, in naps, and then goes on whether they have been taken or not.  Measured at 10 million zones on ZFS, restart with the cache
 * warm, 400,000 queries a second from the start: six threads without the nap reach the steady rate in 4 s and 4.8 % of the queries that wait for a store thread wait more than 16 ms; with it 0.5 %. */
static bool hot_requests_wait(void) { return atomic_load_explicit(&db_store_test_hot_pending, memory_order_relaxed) || park_attach_pending(); }
static void hot_defer(void) {
  for (int w = 0; w < HOT_YIELD_US && hot_requests_wait(); w += HOT_NAP_US) {
    struct timespec nap = { 0, HOT_NAP_US * 1000L };
    nanosleep(&nap, NULL);
  }
}

static void *hot_thread(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  att_job_t *it = malloc(HOT_BATCH * sizeof(*it));
  dbreg_att_item_t *ri = malloc(HOT_BATCH * sizeof(*ri));
  while (st && it && ri && !atomic_load_explicit(&G.hstop, memory_order_acquire) && !atomic_load_explicit(&G.hot_limit, memory_order_relaxed)) {
    if (dbreg_cache_limit() && dbreg_cache_over_high(0)) {
      atomic_store(&G.hot_limit, true);
      break;
    }
    hot_defer();
    const size_t b = atomic_fetch_add(&G.hot_next, HOT_BATCH);
    if (b >= G.hot_n) break;
    const size_t e = b + HOT_BATCH < G.hot_n ? b + HOT_BATCH : G.hot_n;
    hot_attach_batch(st, G.hot_ids + b, e - b, it, ri);
  }
  free(it);
  free(ri);
  if (atomic_fetch_sub(&G.hot_live, 1) == 1) hot_finish();
  return NULL;
}

/* The background attach of hot.list (read at the start by db_store_start()); the server calls it when it is ready to serve (the privileges are dropped), a test when it wants it. */
void db_store_hot_start(void) {
  if (!G.hot_ids || G.hot_n == 0 || G.hthr_started || !atomic_load(&G.attach_on)) return;
  int n = G.nathr * 3 / 4;
  if (n > HOT_THREADS_MAX) n = HOT_THREADS_MAX;
  if (n < 1) n = 1;
  {
    size_t coming = G.hot_n;                                  /* the zones the list will bring: with memory-limit no more than the limit holds (a zone is a kilobyte or more) */
    if (dbreg_cache_limit() && coming > dbreg_cache_limit() / 1024) coming = (size_t)(dbreg_cache_limit() / 1024);
    att_presize(coming);
  }
  atomic_store(&G.hstop, false);
  atomic_store(&G.hot_limit, false);

  atomic_store(&G.hot_next, 0);
  atomic_store(&G.hot_end_ns, 0);
  atomic_store(&G.hot_t0_ns, mono_ns());
  atomic_store(&G.hot_state, DBS_HOT_RUNNING);
  atomic_store(&G.hot_live, 1);                               /* (this function's own count: the list cannot end before the last thread is started) */
  int started = 0;
  for (int i = 0; i < n; i++) {
    atomic_fetch_add(&G.hot_live, 1);
    if (pthread_create(&G.hthr[started], NULL, hot_thread, NULL) != 0) {
      atomic_fetch_sub(&G.hot_live, 1);
      break;
    }
    started++;
  }
  atomic_store(&G.hot_nthr, (uint32_t)started);
  G.hot_nstarted = started;
  G.hthr_started = started > 0;
  if (atomic_fetch_sub(&G.hot_live, 1) != 1) return;
  if (started > 0) hot_finish();                              /* (every thread has ended already) */
  else atomic_store(&G.hot_state, DBS_HOT_NONE);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* start and stop                                                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

static void evict_hook(int reason) {
  store_status_note_detach_why(reason == DBREG_EVICT_LIMIT ? STORE_DET_LIMIT : reason == DBREG_EVICT_ROOM ? STORE_DET_ROOM : STORE_DET_OTHER);
}

/* The scrub or the cleaner found the image of a zone damaged and made the zone KNOWN in the store (the tick calls this with no lock of the store held): a zone that is attached in MAP mode serves the damaged
 * pages.  It is taken out of memory (the record is KNOWN: the next query reads it from the database again).  A zone whose data is a copy or was built from a body (a fetch, an UPDATE) is not affected. */
static bool image_is_store_map(const zone_version_t *v) {
  return v && v->image_free == imgref_free && v->image_ref && ((const imgref_t *)v->image_ref)->img.priv_ == NULL;       /* (COPY: a private buffer, which the damage does not reach) */
}
static int bad_image_hook(uint32_t zid, void *ud) {
  (void)ud;
  return dbreg_store_image_lost(zid, image_is_store_map);
}

static bool attached_fn(uint32_t zid) { return dir_attach_get(zid) != NULL; }
static uint64_t attached_count_fn(void) { return (uint64_t)dir_attach_count(); }

/* what identifies the database a view reads, so that a store that was filled from another one is not trusted: a hash of the driver and the source */
static void view_identity(const database_config_t *db, const view_config_t *v, uint8_t out[32]) {
  bool sqlite = db->driver && strcmp(db->driver, "sqlite3") == 0;
  const char *src = sqlite ? (v->database_file ? v->database_file : db->database_file) : (v->database_schema ? v->database_schema : db->schema);
  SHA256_CTX c;
  SHA256_Init(&c);
  static const char sep = 0;
  const char *parts[4] = { db->driver ? db->driver : "", src ? src : "", sqlite ? "" : (db->conninfo_file ? db->conninfo_file : ""), v->name ? v->name : "" };
  for (int i = 0; i < 4; i++) {
    SHA256_Update(&c, parts[i], strlen(parts[i]));
    SHA256_Update(&c, &sep, 1);
  }
  SHA256_Final(out, &c);
}

/* the zones of the view that the store holds go (the store was filled from another database) */
static void purge_view(store_t *st, int vid) {
  uint32_t cursor = 0, n_del = 0;
  for (;;) {
    uint32_t zids[512];
    size_t nz = 0;
    int more = 0;
    store_read_lock();
    store_zone_t z;
    while (nz < 512 && (more = store_iter(st, &cursor, &z)) != 0) {
      if (more > 0 && z.view == (uint16_t)vid) zids[nz++] = z.zid;
    }
    store_read_unlock();
    for (size_t i = 0; i < nz; i++)
      if (store_delete(st, zids[i]) == 0) n_del++;
    if (more == 0) break;
  }
  if (n_del) syslog(LOG_WARNING, "[Store] the store held %u zone(s) of view %d that were read from another database: they are dropped", (unsigned)n_del, vid);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the reconcile: the loader's manifest and changes against the store (0.7 WP7b)                                  */
/* ------------------------------------------------------------------------------------------------------------- */

/* a bitmap over zone ids that grows as needed (1 bit per zone: 1.25 MB at 10,000,000) */
typedef struct { uint64_t *w; size_t nw; } bits_t;
static bool bits_grow(bits_t *b, uint32_t zid) {
  size_t need = (size_t)zid / 64 + 1;
  if (need <= b->nw) return true;
  size_t nn = b->nw ? b->nw : 1024;
  while (nn < need) nn *= 2;
  uint64_t *nw = realloc(b->w, nn * sizeof(*nw));
  if (!nw) return false;
  memset(nw + b->nw, 0, (nn - b->nw) * sizeof(*nw));
  b->w = nw;
  b->nw = nn;
  return true;
}
static bool bits_set(bits_t *b, uint32_t zid) {
  if (zid == STORE_NONE) return true;
  if (!bits_grow(b, zid)) return false;
  b->w[zid / 64] |= 1ull << (zid % 64);
  return true;
}
static void bits_clear(bits_t *b, uint32_t zid) {
  if (zid == STORE_NONE || (size_t)zid / 64 >= b->nw) return;
  b->w[zid / 64] &= ~(1ull << (zid % 64));
}
static bool bits_get(const bits_t *b, uint32_t zid) { return (size_t)zid / 64 < b->nw && (b->w[zid / 64] >> (zid % 64) & 1); }
static void bits_free(bits_t *b) {
  free(b->w);
  b->w = NULL;
  b->nw = 0;
}

/* A zone whose name the store cannot hold (the root zone: the store's names have no trailing dot, so it would be the empty name) has no record.  The
 * Backend remembers it here (config-sized: a handful of zones) so that it is fetched and served as a zone of the heap directory, as before the store.  The loader's stamp tells a new
 * version.  A pseudo zone id (UN_ZID_BASE + id) names it to the scan and its retry. */
#define UN_ZID_BASE 0xF0000000u
typedef struct un_zone {
  char view[STORE_VIEW_NAME_MAX + 1];
  char *name;                    /* canonical, with the trailing dot */
  int64_t sid;
  bool stamped, has_serial, done, seen;
  uint64_t gen, time;
  uint32_t serial, id;
} un_zone_t;

/* All of it is the ingest thread's, but the figures (RC.s, the guard) are read by the control thread (karictl store, dbstatus): under RC.mu */
static struct {
  pthread_mutex_t mu;
  /* the pass */
  bool active, force;
  int vid;
  char view[STORE_VIEW_NAME_MAX + 1];
  bits_t seen;
  bool failed;                      /* an entry of this pass could not be recorded (or its bit could not be set): the pass sweeps nothing and keeps no cursor */
  int64_t t0_ns;
  /* the secondary and catalog records that the scan has asked for since the start (the zone loads once a run unless it changes) */
  bits_t np_done;
  /* the mass-delete guard: the views whose sweep is held back */
  bool held[STORE_MAX_VIEWS];
  /* the zones the store cannot name (the root zone, a text name over 255 bytes): no record, a list of their own (under mu) */
  un_zone_t *un;
  size_t un_n, un_cap;
  uint32_t un_seq;
  db_recon_status_t s;
} RC = { .mu = PTHREAD_MUTEX_INITIALIZER };

#ifdef KARIDNS_UNIT_TEST
int db_store_test_bits_fail = 0;
#endif
static void rc_lock(void) { pthread_mutex_lock(&RC.mu); }
static void rc_unlock(void) { pthread_mutex_unlock(&RC.mu); }

/* ---- the zones the store cannot name (RC.un; every function takes RC.mu itself unless it says _locked) ---- */
static _Atomic uint32_t UN_CNT;

static int un_find_locked(const char *view, int64_t sid, const char *name) {
  for (size_t i = 0; i < RC.un_n; i++) {
    const un_zone_t *u = &RC.un[i];
    if (strcmp(u->view, view) != 0) continue;
    if ((sid != 0 && u->sid == sid) || (name && strcasecmp(u->name, name) == 0)) return (int)i;
  }
  return -1;
}

static void un_drop_locked(size_t i) {
  free(RC.un[i].name);
  RC.un[i] = RC.un[--RC.un_n];
  atomic_store_explicit(&UN_CNT, (uint32_t)RC.un_n, memory_order_relaxed);
}

/* forget the zone of the source id (or the name): true, and its name in old */
static bool un_remove(const char *view, int64_t sid, const char *name, char *old, size_t cap) {
  if (atomic_load_explicit(&UN_CNT, memory_order_relaxed) == 0) return false;
  bool r = false;
  rec_lock();
  rc_lock();
  int i = un_find_locked(view, sid, name);
  if (i >= 0) {
    snprintf(old, cap, "%s", RC.un[i].name);
    un_drop_locked((size_t)i);
    r = true;
  }
  rc_unlock();
  rec_unlock();
  return r;
}

static uint64_t un_count_view(const char *view) {
  if (atomic_load_explicit(&UN_CNT, memory_order_relaxed) == 0) return 0;
  uint64_t n = 0;
  rc_lock();
  for (size_t i = 0; i < RC.un_n; i++)
    if (strcmp(RC.un[i].view, view) == 0) n++;
  rc_unlock();
  return n;
}

static void un_mark(const char *view) {
  rc_lock();
  for (size_t i = 0; i < RC.un_n; i++)
    if (strcmp(RC.un[i].view, view) == 0) RC.un[i].seen = false;
  rc_unlock();
}

/* the end of a complete pass: the zones the pass did not list are gone from the database */
static uint64_t un_sweep(const char *view) {
  uint64_t n = 0;
  for (;;) {
    char old[1026];
    int64_t sid = 0;
    bool got = false;
    rec_lock();
    rc_lock();
    for (size_t i = 0; i < RC.un_n && !got; i++)
      if (!RC.un[i].seen && strcmp(RC.un[i].view, view) == 0) {
        snprintf(old, sizeof(old), "%s", RC.un[i].name);
        sid = RC.un[i].sid;
        un_drop_locked(i);
        got = true;
      }
    rc_unlock();
    rec_unlock();
    if (!got) break;
    if (dbreg_delete(view, old, sid) > 0) n++;
  }
  return n;
}

/* An entry of a zone the store cannot name: the Backend remembers it (a new version is asked for like a secondary zone's body) and the body is installed as a zone of the heap directory.
 * The result is the one of a record: NEW (a first sight), CHANGED (another version), RENAMED, PENDING (asked for, not here yet), SAME. */
static int un_apply(const char *view, const db_recon_entry_t *e) {
  /* the heap directory keys a name by at most 255 bytes of text too (its klen is a byte): a longer name (only escapes make one) cannot be served at all and is refused as before */
  if (strlen(e->name) > STORE_NAME_MAX + 1 || strlen(view) > STORE_VIEW_NAME_MAX) return DBR_UNSTORABLE;
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  char old[1026], oldrec[1026];
  old[0] = oldrec[0] = '\0';
  if (e->source_id != 0 && st) {                            /* a zone that had a name the store could hold: its record goes (the zone is made again under the new name) */
    int vid = view_ensure(st, view);
    if (vid >= 0) {
      store_zone_t rs;
      store_read_lock();
      uint32_t zs = store_find_source(st, (uint16_t)vid, e->source_id, (uint16_t)vid);
      bool has = zs != STORE_NONE && store_zone_get(st, zs, &rs) == 0;
      store_read_unlock();
      if (has) snprintf(oldrec, sizeof(oldrec), "%s.", rs.name);
    }
  }
  if (oldrec[0]) (void)dbreg_delete(view, oldrec, e->source_id);
  int res;
  bool is_new = false;
  char *nn = strdup(e->name);
  if (!nn) return DBR_ERROR;                                /* (no memory: not a refusal of the zone; the pass must not sweep what it could not look at) */
  rc_lock();
  int i = un_find_locked(view, e->source_id, e->name);
  if (i < 0) {
    if (RC.un_n == RC.un_cap) {
      size_t nc = RC.un_cap ? RC.un_cap * 2 : 8;
      un_zone_t *nu = realloc(RC.un, nc * sizeof(*nu));
      if (!nu) {
        rc_unlock();
        free(nn);
        return DBR_ERROR;
      }
      RC.un = nu;
      RC.un_cap = nc;
    }
    un_zone_t *u = &RC.un[RC.un_n++];
    memset(u, 0, sizeof(*u));
    snprintf(u->view, sizeof(u->view), "%s", view);
    u->name = nn;
    nn = NULL;
    u->sid = e->source_id;
    u->id = RC.un_seq++;
    u->stamped = e->stamped;
    u->gen = e->gen;
    u->time = e->time;
    u->has_serial = e->has_serial;
    u->serial = e->serial;
    u->seen = true;
    atomic_store_explicit(&UN_CNT, (uint32_t)RC.un_n, memory_order_relaxed);
    res = DBR_NEW;
    is_new = true;
  } else {
    un_zone_t *u = &RC.un[i];
    u->seen = true;
    if (strcmp(u->name, e->name) != 0) {                    /* the domain has another name now (or another domain has the name) */
      if (strcasecmp(u->name, e->name) != 0) snprintf(old, sizeof(old), "%s", u->name);
      free(u->name);
      u->name = nn;
      nn = NULL;
    }
    u->sid = e->source_id;
    const bool same = !e->force && !old[0] && ((e->stamped && u->stamped && u->gen == e->gen && u->time == e->time) ||
                                               (!e->stamped && e->has_serial && !u->stamped && u->has_serial && u->serial == e->serial));
    if (same) {
      res = u->done ? DBR_SAME : DBR_PENDING;
    } else {
      u->stamped = e->stamped;
      u->gen = e->gen;
      u->time = e->time;
      u->has_serial = e->has_serial;
      u->serial = e->serial;
      u->done = false;
      res = old[0] ? DBR_RENAMED : DBR_CHANGED;
    }
  }
  rc_unlock();
  free(nn);
  if (old[0]) (void)dbreg_delete(view, old, e->source_id);
  if (is_new)
    syslog(LOG_NOTICE, "[Store] zone '%s' (view '%s') cannot be kept in the zone store (the root zone): it is a zone of the heap directory, like a secondary zone, read from "
                       "the database at every start (the cursor of the view is not kept while the view has such a zone)", e->name, view);
  return res;
}

void db_recon_note_fetch(int what, uint64_t n) {
  rc_lock();
  if (what == DBR_FETCHED) RC.s.fetched += n;
  else if (what == DBR_FETCH_FAILED) RC.s.fetch_failed += n;
  else if (what == DBR_IN_FLIGHT) RC.s.in_flight = n;
  rc_unlock();
}

void db_recon_status(db_recon_status_t *out) {
  rc_lock();
  *out = RC.s;
  out->active = RC.active;
  if (RC.active) {
    snprintf(out->view, sizeof(out->view), "%s", RC.view);
    out->duration_ms = (uint64_t)((mono_ns() - RC.t0_ns) / 1000000);
  }
  unsigned gv = 0;
  for (int i = 0; i < STORE_MAX_VIEWS; i++) gv += RC.held[i] ? 1 : 0;
  out->guard_views = gv;
  out->nonstore = RC.un_n;
  rc_unlock();
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  out->known_now = 0;
  if (st) {
    store_stats_t *ss = malloc(sizeof(*ss));
    if (ss) {
      store_read_lock();
      store_stats(st, ss);
      store_read_unlock();
      out->known_now = ss->zones_known;
      free(ss);
    }
  }
}

/* the store's cursor of a view: the loader's own part of the identity follows the configuration's DBS_CFGID bytes */
bool db_recon_cursor_get(const char *view, uint64_t *cursor, uint8_t *ident, size_t *ident_len) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st || !view) return false;
  int vid = store_view_id(st, view);
  if (vid < 0 || vid >= STORE_MAX_VIEWS) return false;
  bool valid = false;
  uint8_t have[STORE_IDENT_MAX];
  size_t hl = 0;
  if (store_get_cursor(st, (uint16_t)vid, &valid, cursor, have, &hl) != 0 || !valid || hl <= DBS_CFGID || hl > STORE_IDENT_MAX) return false;
  uint64_t id8;
  memcpy(&id8, have, DBS_CFGID);
  if (id8 != atomic_load_explicit(&G.cfgid[vid], memory_order_relaxed)) return false;      /* (the store was not filled for this configuration) */
  memcpy(ident, have + DBS_CFGID, hl - DBS_CFGID);
  *ident_len = hl - DBS_CFGID;
  return true;
}

void db_recon_cursor_put(const char *view, uint64_t cursor, const uint8_t *ident, size_t ident_len) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st || !view) return;
  int vid = store_view_id(st, view);
  if (vid < 0 || vid >= STORE_MAX_VIEWS) return;
  rc_lock();
  bool held = RC.held[vid];
  rc_unlock();
  if (held) return;                                         /* (a restart then makes a pass again and finds the same) */
  if (un_count_view(view) > 0) return;                        /* (a zone the store cannot name has no record: only a pass or the changes since the old cursor bring it back at the next start) */
  uint8_t buf[STORE_IDENT_MAX];
  uint64_t id8 = atomic_load_explicit(&G.cfgid[vid], memory_order_relaxed);
  memcpy(buf, &id8, DBS_CFGID);
  size_t il = ident_len > STORE_IDENT_MAX - DBS_CFGID ? STORE_IDENT_MAX - DBS_CFGID : ident_len;      /* (a longer identity is cut: it never equals the loader's again, which makes a pass at every start) */
  if (il) memcpy(buf + DBS_CFGID, ident, il);
  int r = store_set_cursor(st, (uint16_t)vid, cursor, buf, DBS_CFGID + il);
  if (r < 0) {
    note_error("the cursor", view, r);
  } else {
    rc_lock();
    RC.s.cursors++;
    rc_unlock();
  }
}

/* One entry (design 5.3, 5.4).  See dns_db_store.h for the rules.  The step (what the record is, what it becomes) is one step for the writers of the records (g_rec_mu). */
static int recon_apply_locked(const char *view, const db_recon_entry_t *e, uint32_t *zid_out) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (zid_out) *zid_out = STORE_NONE;
  if (!st || !view || !e || !e->name) return DBR_ERROR;
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (!store_name(e->name, name, sizeof(name), &nlen)) return un_apply(view, e);        /* (a zone of the heap directory: see un_apply()) */
  if (e->source_id != 0) {                                  /* a zone that had a name the store could not hold: it is a zone of the store now (its heap element goes) */
    char uold[1026];
    if (un_remove(view, e->source_id, NULL, uold, sizeof(uold))) (void)dbreg_delete(view, uold, e->source_id);
  }
  int vid = view_ensure(st, view);
  if (vid < 0) return DBR_ERROR;
  const bool np = e->kind != KDB_ZK_PRIMARY;
  uint32_t zs = STORE_NONE, zn = STORE_NONE;
  store_zone_t rs, rn;
  bool has_s = false, has_n = false;
  store_read_lock();
  if (e->source_id != 0) zs = store_find_source(st, (uint16_t)vid, e->source_id, (uint16_t)vid);
  zn = store_find(st, (uint16_t)vid, name, nlen);
  if (zs != STORE_NONE) has_s = store_zone_get(st, zs, &rs) == 0;
  if (zn != STORE_NONE && zn != zs) has_n = store_zone_get(st, zn, &rn) == 0;
  store_read_unlock();
  (void)has_n;
  bool renamed = false;
  if (zs != STORE_NONE && zs != zn) {                       /* the domain has another name now: the old name goes (its element too), the zone is made under the new one */
    if (has_s) {
      char old[STORE_NAME_MAX + 2];
      snprintf(old, sizeof(old), "%s.", rs.name);
      (void)dbreg_delete(view, old, e->source_id);
    } else {
      int dr = store_delete(st, zs);
      if (dr < 0 && dr != -ENOENT) {
        if (zid_out) *zid_out = zs;                         /* (the record is still there: a pass counts it as listed, it is not for the sweep) */
        return DBR_ERROR;
      }
    }
    renamed = true;
    zs = STORE_NONE;
    has_s = false;
  }
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.source_id = e->source_id;
  m.source = (uint16_t)vid;
  m.flags = np ? STORE_F_NONSTORE : 0;
  m.stamp_gen = e->stamped ? e->gen : 0;
  m.stamp_time = e->stamped ? e->time : 0;
  uint32_t zid = STORE_NONE;
  int res = DBR_SAME;
  int r = 0;
  if (!has_s) {                                             /* a zone that is new, or whose name another domain held: a record without an image */
    r = store_set_known(st, (uint16_t)vid, name, nlen, &m, &zid);
    res = renamed ? DBR_RENAMED : DBR_NEW;
    if (r == 0) dmax_raise(vid, store_name_labels(name, nlen));
  } else {
    zid = rs.zid;
    const bool known = rs.state == STORE_STATE_KNOWN, stale = (rs.flags & STORE_F_STALE) != 0, rej = (rs.flags & STORE_F_REJECTED_NEW) != 0;
    const bool kind_eq = ((rs.flags & STORE_F_NONSTORE) != 0) == np;
    const bool stamp_eq = e->stamped && rs.stamp_gen == e->gen && rs.stamp_time == e->time;
    if (!kind_eq) {                                         /* a primary became a secondary or the other way: the zone is made again (its image is not the new kind's) */
      r = store_set_known(st, (uint16_t)vid, name, nlen, &m, &zid);
      res = DBR_CHANGED;
    } else if (np) {                                        /* a secondary or catalog zone: the record is only the memory of it */
      if (!e->force && stamp_eq) {
        res = DBR_SAME;
      } else {
        r = store_set_stamp(st, zid, m.stamp_gen, m.stamp_time, 0, STORE_F_REJECTED_NEW);
        res = DBR_CHANGED;
      }
    } else if (!e->force && e->stamped && stamp_eq) {
      res = rej ? DBR_KEPT : (known || stale) ? DBR_PENDING : DBR_SAME;
    } else if (!e->force && !e->stamped && e->has_serial && rs.state == STORE_STATE_STORED && rs.serial == e->serial) {
      res = (stale && !rej) ? DBR_PENDING : DBR_SAME;
    } else if (!e->force && !e->stamped && !e->has_serial && (known || stale) && !rej) {          /* (a zone without a version stamp is always asked for: it already is) */
      res = DBR_PENDING;
    } else {                                                /* another version: the stamp is recorded, the body is asked for; the image (if any) keeps serving until then */
      r = store_set_stamp(st, zid, m.stamp_gen, m.stamp_time, known ? 0 : STORE_F_STALE, STORE_F_REJECTED_NEW);
      res = DBR_CHANGED;
    }
  }
  if (r < 0) {
    note_error("the record of the reconcile", e->name, r);
    if (zid_out && zid != STORE_NONE) *zid_out = zid;       /* (a record that exists but could not be changed was listed by the database: the pass must not sweep it) */
    return DBR_ERROR;
  }
  if (np && (res == DBR_NEW || res == DBR_CHANGED || res == DBR_RENAMED)) bits_clear(&RC.np_done, zid);
  if (zid_out) *zid_out = zid;
  return res;
}

int db_recon_apply(const char *view, const db_recon_entry_t *e, uint32_t *zid_out) {
  rec_lock();
  int r = recon_apply_locked(view, e, zid_out);
  rec_unlock();
  return r;
}

static void rc_count(int res, bool in_pass) {
  rc_lock();
  if (in_pass) RC.s.entries++;
  switch (res) {
  case DBR_NEW: if (in_pass) RC.s.created++; break;
  case DBR_CHANGED: if (in_pass) RC.s.changed++; break;
  case DBR_RENAMED: if (in_pass) RC.s.renamed++; break;
  case DBR_PENDING: if (in_pass) RC.s.pending++; break;
  case DBR_KEPT: if (in_pass) RC.s.kept++; break;
  case DBR_SAME: if (in_pass) RC.s.same++; break;
  default: break;
  }
  if (res == DBR_NEW || res == DBR_CHANGED || res == DBR_RENAMED) RC.s.wanted++;
  if (!in_pass && res >= 0) RC.s.change_upserts++;
  rc_unlock();
}

int db_recon_change(const char *view, const db_recon_entry_t *e, uint32_t *zid) {
  int r = db_recon_apply(view, e, zid);
  rc_count(r, false);
  return r;
}

bool db_recon_begin(const char *view, uint64_t estimate, bool force, char *why, size_t whylen) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) {
    snprintf(why, whylen, "there is no zone store");
    return false;
  }
  int vid = view_ensure(st, view);
  if (vid < 0) {
    snprintf(why, whylen, "the zone store has no room for the view (%s)", strerror(-vid));
    return false;
  }
  if (RC.active) syslog(LOG_WARNING, "[Store] the pass of view '%s' did not end; it is dropped", RC.view);
  store_stats_t *ss = malloc(sizeof(*ss));
  uint64_t have = 0;
  if (ss) {
    store_read_lock();
    store_stats(st, ss);
    store_read_unlock();
    have = ss->zt_records;
    free(ss);
  }
  /* (a first fill: the tables are made big enough in one step; the estimate is the loader's claim, and a hostile loader must not make the Backend reserve sixteen million records on disk for a handful of zones: the
   * reserve is at most twice what the store holds plus a million, and the tables grow by themselves beyond that) */
  const uint64_t cap = 2 * have + 1000000ull, want = estimate < cap ? estimate : cap;
  if (want > have) (void)store_reserve(st, want);
  un_mark(view);
  rc_lock();
  bits_free(&RC.seen);
  RC.active = true;
  RC.force = force;
  RC.failed = false;
  RC.vid = vid;
  snprintf(RC.view, sizeof(RC.view), "%s", view);
  RC.t0_ns = mono_ns();
  struct timespec rt;
  clock_gettime(CLOCK_REALTIME, &rt);
  db_recon_status_t *s = &RC.s;
  s->started_unix = (uint64_t)rt.tv_sec;
  s->duration_ms = 0;
  s->estimate = estimate;
  s->entries = s->created = s->same = s->changed = s->renamed = s->pending = s->kept = s->skipped = 0;
  s->swept = s->unlisted = s->total = 0;
  s->passes++;
  snprintf(s->view, sizeof(s->view), "%s", view);
  rc_unlock();
  (void)bits_grow(&RC.seen, (uint32_t)(have + want + 4096));
  return true;
}

#ifdef KARIDNS_UNIT_TEST
void (*db_recon_test_entry_hook)(void);
#endif
int db_recon_entry(const db_recon_entry_t *e, uint32_t *zid_out) {
  if (!RC.active) return DBR_ERROR;
#ifdef KARIDNS_UNIT_TEST
  if (db_recon_test_entry_hook) db_recon_test_entry_hook();         /* (tests: an entry of a pass that takes time) */
#endif
  uint32_t zid = STORE_NONE;
  int r = db_recon_apply(RC.view, e, &zid);
  /* A zone the database lists is seen, whatever became of its record: one that could not be recorded (a full disk, an I/O error) and one whose bit could not be set (no memory) must not be swept as
   * unlisted at the end of the pass.  Either failure also ends the pass without a sweep and without a cursor (db_recon_end()): the next pass has to make it good. */
  bool seen_ok = bits_set(&RC.seen, zid);
#ifdef KARIDNS_UNIT_TEST
  if (db_store_test_bits_fail > 0 && --db_store_test_bits_fail == 0) seen_ok = false;      /* (tests: the bit of the n-th entry of a pass could not be set: no memory) */
#endif
  if (!seen_ok) RC.failed = true;
  if (r == DBR_ERROR) RC.failed = true;
  rc_count(r, true);
  if (zid_out) *zid_out = zid;
  return r;
}

void db_recon_abort(void) {
  rc_lock();
  if (RC.active) {
    syslog(LOG_WARNING, "[Store] the pass of view '%s' was cut off (the loader's stream ended); nothing is swept, the next pass starts again", RC.view);
    RC.active = false;
    bits_free(&RC.seen);
  }
  rc_unlock();
}

/* the zones of the view in the store, a few thousand at a time (the read section does not last for a pass over ten million zones) */
#define RC_CHUNK 4096u
#define RC_VICTIMS 128u
typedef struct { char zone[STORE_NAME_MAX + 2]; int64_t sid; } rc_victim_t;

void db_recon_end(bool complete, uint64_t n_skipped, bool cursor_valid, uint64_t cursor, const uint8_t *ident, size_t ident_len, db_recon_end_t *out) {
  memset(out, 0, sizeof(*out));
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!RC.active || !st) return;
  const int vid = RC.vid;
  char view[STORE_VIEW_NAME_MAX + 1];
  snprintf(view, sizeof(view), "%s", RC.view);
  const bool force = RC.force;
  out->duration_ms = (uint64_t)((mono_ns() - RC.t0_ns) / 1000000);
  if (complete && !RC.failed && vid >= 0 && vid < 32) atomic_fetch_and(&G.dir_pending, ~(1u << vid));         /* (every zone of the view is listed in the name index now, whatever the sweep does) */
  rc_lock();
  RC.s.skipped = n_skipped;
  rc_unlock();
  if (!complete) {
    syslog(LOG_WARNING, "[Store] view '%s': the pass was not complete (the loader had a database error): nothing is swept, no cursor is kept; the next pass starts again", view);
    goto done;
  }
  if (RC.failed) {
    syslog(LOG_ERR, "[Store] view '%s': an entry of the pass could not be recorded in the store (disk full, an I/O error, or no memory): NOTHING IS SWEPT and no cursor is kept; the zones keep being served and the next pass (at the next start, or `karictl reload`) starts again", view);
    out->failed = true;
    goto done;
  }
  /* the zones of the view that the pass did not list */
  uint64_t total = 0, unlisted = 0;
  uint32_t cur = 0;
  store_zone_t z;
  for (bool end = false; !end;) {
    store_read_lock();
    for (unsigned n = 0; n < RC_CHUNK; n++) {
      int more = store_iter(st, &cur, &z);
      if (more == 0) {
        end = true;
        break;
      }
      if (more < 0 || z.view != (uint16_t)vid) continue;
      total++;
      if (!bits_get(&RC.seen, z.zid)) unlisted++;
    }
    store_read_unlock();
  }
  out->total = total;
  out->unlisted = unlisted;
  const bool guard = unlisted > DBS_GUARD_MIN && unlisted * 100u > total * DBS_GUARD_PCT && !force;
  rc_lock();
  RC.s.total = total;
  RC.s.unlisted = unlisted;
  rc_unlock();
  if (guard) {
    out->held = true;
    struct timespec rt;
    clock_gettime(CLOCK_REALTIME, &rt);
    rc_lock();
    RC.held[vid] = true;
    snprintf(RC.s.guard_view, sizeof(RC.s.guard_view), "%s", view);
    RC.s.guard_unlisted = unlisted;
    RC.s.guard_total = total;
    RC.s.guard_unix = (uint64_t)rt.tv_sec;
    rc_unlock();
    {                                                       /* the hold survives a restart: the cursor of the view is made invalid (only the configuration's hash stays, as after a purge), so the next start does not trust */
      uint8_t cfg8[DBS_CFGID];                              /* the zones it has but makes a pass; that pass finds the same and holds again, until `karictl reload -force` deletes the zones or the source is repaired */
      const uint64_t id8 = atomic_load_explicit(&G.cfgid[vid], memory_order_relaxed);
      memcpy(cfg8, &id8, DBS_CFGID);
      int cr = store_set_cursor(st, (uint16_t)vid, 0, cfg8, DBS_CFGID);
      if (cr < 0) note_error("the cursor of the held view", view, cr);
    }
    syslog(LOG_ERR, "[Store] view '%s': the pass over the database lists %llu zone(s) fewer than the %llu the Backend holds for it (more than %u percent, and more than %u): NOTHING IS DELETED, the "
                    "zones keep being served and the cursor is not advanced. If the database is right, `karictl reload -force` deletes them; if not, repair the source",
           view, (unsigned long long)unlisted, (unsigned long long)total, DBS_GUARD_PCT, DBS_GUARD_MIN);
    goto done;
  }
  rc_lock();
  RC.held[vid] = false;                                     /* (a pass that finds nothing alarming, or that the operator asked for, lets go of an old hold) */
  rc_unlock();
  if (unlisted > 0) {
    uint64_t deleted = 0, nfail = 0;
    rc_victim_t *vic = malloc(RC_VICTIMS * sizeof(*vic));
    if (!vic) nfail = unlisted;
    if (vic) {
      cur = 0;
      for (bool end = false; !end;) {
        unsigned nv = 0;
        store_read_lock();
        while (nv < RC_VICTIMS) {
          int more = store_iter(st, &cur, &z);
          if (more == 0) {
            end = true;
            break;
          }
          if (more < 0 || z.view != (uint16_t)vid || bits_get(&RC.seen, z.zid)) continue;
          snprintf(vic[nv].zone, sizeof(vic[nv].zone), "%s.", z.name);
          vic[nv].sid = z.source_id;
          nv++;
        }
        store_read_unlock();
        for (unsigned i = 0; i < nv; i++) {
          int dr = dbreg_delete(view, vic[i].zone, vic[i].sid);
          if (dr > 0) deleted++;
          else if (dr < 0) nfail++;                       /* (the store could not delete it: it stays, and is listed by no database: the next pass tries again) */
        }
      }
      free(vic);
    }
    out->swept = true;
    out->deleted = deleted;
    if (nfail) {
      out->failed = true;
      syslog(LOG_ERR, "[Store] view '%s': %llu zone(s) the database no longer lists could not be deleted from the store (disk full, an I/O error, or no memory): they stay, and the cursor is not kept so that the next pass deletes them", view, (unsigned long long)nfail);
    }
    rc_lock();
    RC.s.swept = deleted;
    rc_unlock();
    syslog(LOG_NOTICE, "[Store] view '%s': %llu zone(s) the database no longer lists were deleted (%llu of %llu)%s", view, (unsigned long long)deleted, (unsigned long long)unlisted,
           (unsigned long long)total, force ? " (a pass the operator asked for)" : "");
    dmax_refresh(st, vid);
  }
  {                                                         /* the zones the store cannot name that the pass did not list */
    uint64_t ud = un_sweep(view);
    if (ud) {
      out->swept = true;
      out->deleted += ud;
      rc_lock();
      RC.s.swept += ud;
      rc_unlock();
      syslog(LOG_NOTICE, "[Store] view '%s': %llu zone(s) of the heap directory (names the store cannot hold) that the database no longer lists were deleted", view, (unsigned long long)ud);
    }
  }
  if (cursor_valid && !out->failed) db_recon_cursor_put(view, cursor, ident, ident_len);
done:
  rc_lock();
  RC.active = false;
  RC.s.duration_ms = out->duration_ms;
  bits_free(&RC.seen);
  rc_unlock();
}

static int recon_delete_locked(const char *view, int64_t source_id, const char *name) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st || !view) return 0;
  char zone[1026], uold[1026];
  zone[0] = '\0';
  bool un_gone = false;
  if (un_remove(view, source_id, name && *name ? name : NULL, uold, sizeof(uold))) {
    un_gone = true;          /* a zone of the heap directory (a name the store cannot hold) */
    snprintf(zone, sizeof(zone), "%s", uold);
  } else if (name && *name) {
    snprintf(zone, sizeof(zone), "%s", name);
  } else if (source_id != 0) {                              /* the loader does not have the name (the row is gone): the source index has it */
    int vid = store_view_id(st, view);
    store_zone_t z;
    store_read_lock();
    uint32_t zid = vid >= 0 ? store_find_source(st, (uint16_t)vid, source_id, (uint16_t)vid) : STORE_NONE;
    bool ok = zid != STORE_NONE && store_zone_get(st, zid, &z) == 0;
    store_read_unlock();
    if (ok) snprintf(zone, sizeof(zone), "%s.", z.name);
  }
  int r = zone[0] ? dbreg_delete(view, zone, source_id) : 0;
  if (r <= 0 && un_gone) r = 1;                                  /* (a zone of the heap directory that was never served is forgotten: it counts as deleted) */
  rc_lock();
  if (r > 0) RC.s.change_deletes++;
  rc_unlock();
  return r > 0 ? 1 : r < 0 ? -1 : 0;
}

int db_recon_scan(uint32_t *cursor, unsigned budget, db_scan_item_t *out) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) return 0;
  store_zone_t z;
  int rc = 2;
  store_read_lock();
  while (budget--) {
    int more = store_iter(st, cursor, &z);
    if (more == 0) {
      rc = 0;
      if (atomic_load_explicit(&UN_CNT, memory_order_relaxed) == 0) break;
      rc_lock();                                            /* (the zones the store cannot name come after the records: their body is wanted once a run, like a secondary zone's) */
      for (size_t i = 0; i < RC.un_n; i++) {
        un_zone_t *u = &RC.un[i];
        if (u->done || strlen(u->name) >= sizeof(out->zone)) continue;
        snprintf(out->view, sizeof(out->view), "%s", u->view);
        snprintf(out->zone, sizeof(out->zone), "%s", u->name);
        out->source_id = u->sid;
        out->zid = UN_ZID_BASE + u->id;
        out->nonstore = true;
        out->stamp_gen = u->gen;
        out->stamp_time = u->time;
        u->done = true;
        rc = 1;
        break;
      }
      rc_unlock();
      break;
    }
    if (more < 0) continue;
    const bool np = (z.flags & STORE_F_NONSTORE) != 0;
    bool want;
    if (np) want = !bits_get(&RC.np_done, z.zid);
    else if (z.flags & STORE_F_REJECTED_NEW) want = false;
    else want = z.state == STORE_STATE_KNOWN || (z.flags & STORE_F_STALE) != 0;
    if (!want) continue;
    const char *vn = store_view_name(st, z.view);
    if (!vn) continue;
    snprintf(out->view, sizeof(out->view), "%s", vn);
    snprintf(out->zone, sizeof(out->zone), "%s.", z.name);
    out->source_id = z.source_id;
    out->zid = z.zid;
    out->nonstore = np;
    out->stamp_gen = z.stamp_gen;
    out->stamp_time = z.stamp_time;
    if (np) bits_set(&RC.np_done, z.zid);
    rc = 1;
    break;
  }
  store_read_unlock();
  return rc;
}

int db_recon_delete(const char *view, int64_t source_id, const char *name) {
  rec_lock();
  int r = recon_delete_locked(view, source_id, name);
  rec_unlock();
  return r;
}

void db_recon_scan_retry(uint32_t zid) {
  if (zid >= UN_ZID_BASE && zid != STORE_NONE) {
    rc_lock();
    for (size_t i = 0; i < RC.un_n; i++)
      if (RC.un[i].id == zid - UN_ZID_BASE) RC.un[i].done = false;
    rc_unlock();
    return;
  }
  bits_clear(&RC.np_done, zid);
}

/* ---- a fetched body is installed only for the stamp it was asked for ---- */

/* The stamp of the Backend's entry for the zone: the store's record, or the entry of a zone the store cannot name (RC.un).  The record of a secondary or catalog zone is no entry here (it has no body to match). */
bool db_store_zone_stamp(const char *view, const char *zone, db_stamp_t *out, int64_t *sid) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st || !view || !zone) return false;
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (!store_name(zone, name, sizeof(name), &nlen)) {
    bool ok = false;
    if (atomic_load_explicit(&UN_CNT, memory_order_relaxed) == 0) return false;
    rc_lock();
    const int i = un_find_locked(view, 0, zone);
    if (i >= 0) {
      out->gen = RC.un[i].gen;
      out->time = RC.un[i].time;
      if (sid) *sid = RC.un[i].sid;
      ok = true;
    }
    rc_unlock();
    return ok;
  }
  dbdir_rec_t r;
  if (!dir_rec_get(view, zone, &r)) return false;
  out->gen = r.stamp_gen;
  out->time = r.stamp_time;
  if (sid) *sid = r.source_id;
  return true;
}

/* The commit of a body (the install into the entry has been made; what follows is dbreg_commit(): the version goes to the store with the record's stamp, the registry takes the zone) is one step with
 * the writers of the stamp.  expect: the stamp the body was asked for (NULL: no condition, the body is a batch's).  The record having another stamp (the database changed the zone again after the request: the
 * CHANGES entry marked the record wanted) or none (the zone was deleted) takes nothing from this body: DBC_STALE, DBC_GONE.  Always followed by db_store_commit_end(); until then the store takes no version
 * from this thread after a refusal (dbreg_commit() of a zone that is in memory still has to follow, for the registry of the entry that was updated), and the writers of the records wait. */
int db_store_commit_begin(const char *view, const char *zone, const db_stamp_t *expect) {
#ifdef KARIDNS_UNIT_TEST
  if (db_store_test_commit_hook) db_store_test_commit_hook(0, zone);      /* (before the step: another writer may come in) */
#endif
  rec_lock();
  int rc = DBC_OK;
  if (expect) {
    db_stamp_t cur;
    if (!db_store_zone_stamp(view, zone, &cur, NULL)) rc = DBC_GONE;
    else if (cur.gen != expect->gen || cur.time != expect->time) rc = DBC_STALE;
  }
  t_put_refuse = rc != DBC_OK;
#ifdef KARIDNS_UNIT_TEST
  if (db_store_test_commit_hook) db_store_test_commit_hook(1, zone);      /* (inside the step: another writer waits) */
#endif
  return rc;
}

void db_store_commit_end(void) {
  t_put_refuse = false;
  rec_unlock();
}

/* After a body was dropped (installed: `installed` is the stamp it was asked for): is the zone still wanted?  A record that is KNOWN or STALE and not refused is (the scan of the wanted bodies asks again); an
 * installed body leaves a wanted record only when the stamp moved after it (the install made the record current, so a record that still wants a body has another stamp: asking again for the same one would
 * not end).  A zone the store cannot name is made wanted again by the scan (the stamp of its entry is the one that changed). */
bool db_store_wanted_again(const char *view, const char *zone, const db_stamp_t *installed) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st || !view || !zone) return false;
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (!store_name(zone, name, sizeof(name), &nlen)) {
    bool ok = false;
    if (atomic_load_explicit(&UN_CNT, memory_order_relaxed) == 0) return false;
    rec_lock();
    rc_lock();
    const int i = un_find_locked(view, 0, zone);
    if (i >= 0 && (!installed || RC.un[i].gen != installed->gen || RC.un[i].time != installed->time)) {
      RC.un[i].done = false;
      ok = true;
    }
    rc_unlock();
    rec_unlock();
    return ok;
  }
  dbdir_rec_t r;
  if (!dir_rec_get(view, zone, &r)) return false;
  if (installed && r.stamp_gen == installed->gen && r.stamp_time == installed->time) return false;
  return (r.state == STORE_STATE_KNOWN || (r.flags & STORE_F_STALE)) && !(r.flags & STORE_F_REJECTED_NEW);
}

static bool recon_status_cb(store_recon_t *o) {
  db_recon_status(o);
  return true;
}

bool db_store_start(const server_config_t *cfg) {
  if (g_dir.dirfd < 0 || !cfg || !cfg->database.enabled) return true;
  const database_config_t *db = &cfg->database;
  store_opts_t o;
  store_opts_default(&o);
  o.mode = db->store_mode == 1 ? STORE_MODE_MAP : db->store_mode == 2 ? STORE_MODE_COPY : STORE_MODE_AUTO;
  o.scrub_interval_s = db->store_scrub_interval;             /* 0.7 S6 (WP9): the scrub of the store: its interval, and the structure check it makes of every image it reads */
  o.seg_size = db->store_segment_size;                       /* (0 = 256 MiB) */
  o.validate = zone_image_validate;
  o.bad_image = bad_image_hook;                             /* a zone whose image the scrub or the cleaner found damaged is taken out of memory */
  o.create = true;
  o.log = store_log_cb;
  store_t *st = NULL;
  int r = store_open(g_dir.dirfd, &o, &st);
  if (r == -EBADMSG) {                                       /* damaged or of another format: it is moved aside and made again from the database */
    syslog(LOG_WARNING, "[Store] the store in the directory cannot be opened (damaged or of another format); it is moved aside and made again from the database");
    if (store_quarantine(g_dir.dirfd) == 0) r = store_open(g_dir.dirfd, &o, &st);
  }
  if (r != 0 || !st) {
    syslog(LOG_ERR, "[Store] cannot open the store: %s; the zones are read from the database only", strerror(-r));
    return true;
  }
#if defined(__FreeBSD__)
  {
    /* design 2.1: lookup, create, read, write, seek (pread / pwrite), mmap, fsync, ftruncate, fstat, fstatfs, unlinkat; files opened beneath it get these rights */
    cap_rights_t rights;
    cap_rights_init(&rights, CAP_LOOKUP, CAP_CREATE, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_MMAP_RW, CAP_FSYNC, CAP_FTRUNCATE, CAP_FSTAT,
                    CAP_FSTATFS, CAP_UNLINKAT);
    if (cap_rights_limit(g_dir.dirfd, &rights) != 0 && errno != ENOSYS)
      syslog(LOG_ERR, "[Store] cannot limit the rights of the store directory: %s; it keeps its rights", strerror(errno));
  }
#endif
  store_open_segments(st);                                   /* (0.7 fix 7: the worker's attach looks at pages of segments that are open) */
  set_load(g_dir.dirfd);                                     /* the settings texts: a zone that is not in memory is answered and attached with them */
  for (const view_config_t *v = cfg->views; v; v = v->next) {
    if (v->database_none || !v->name) continue;
    int vid = store_view_add(st, v->name);
    if (vid < 0) {
      syslog(LOG_ERR, "[Store] no room for view '%s' in the store (%d at most); its zones are read from the database only", v->name, STORE_MAX_VIEWS);
      continue;
    }
    uint8_t want[32], have[STORE_IDENT_MAX];
    size_t hl = 0;
    bool valid = false;
    uint64_t cursor = 0;
    view_identity(db, v, want);
    {
      uint64_t id8;
      memcpy(&id8, want, DBS_CFGID);
      atomic_store_explicit(&G.cfgid[vid], id8, memory_order_relaxed);
    }
    /* the identity kept with the cursor: the first DBS_CFGID bytes are the hash of the view's configuration (an older store has the whole hash: its first bytes are the same), the rest
     * is the loader's identity of its database (db_recon_cursor_put()) */
    if (store_get_cursor(st, (uint16_t)vid, &valid, &cursor, have, &hl) != 0 || !valid || hl < DBS_CFGID || memcmp(have, want, DBS_CFGID) != 0) {
      purge_view(st, vid);
      (void)store_set_cursor(st, (uint16_t)vid, 0, want, DBS_CFGID);
      if (vid < 32) atomic_fetch_or(&G.dir_pending, 1u << vid);          /* (the store has no list of this view's zones: a first fill; a pass has to make it) */
    }
  }
  for (int vid = 0; vid < STORE_MAX_VIEWS; vid++) dmax_refresh(st, vid);
  atomic_fetch_add(&G.view_gen, 1);
  atomic_store(&G.st, st);
  store_status_bind(st);
  store_status_set_attached_fn(attached_fn);
  store_status_set_attached_count_fn(attached_count_fn);
  store_status_set_recon_fn(recon_status_cb);
  store_status_set_extra_fn(extra_status_cb);
  dbreg_err_set_sink(&g_err_sink);                           /* design 6.7: the rejection texts of zones that have a record go to err.ring */
  dbreg_set_evict_hook(evict_hook);
  G.wstop = false;
  if (pthread_create(&G.wthr, NULL, ticker_thread, NULL) != 0) return false;
  G.wthr_started = true;
#if defined(__FreeBSD__)
  G.akq = kqueue();
  if (G.akq >= 0) {
    struct kevent ev;
    EV_SET(&ev, PARK_ATTACH_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (kevent(G.akq, &ev, 1, NULL, 0, NULL) != 0) {
      close(G.akq);
      G.akq = -1;
    }
  }
  if (G.akq < 0) {
    syslog(LOG_ERR, "[Store] no kqueue for the attach threads; zones are read from the database only");
    return true;
  }
  park_attach_set_notify(G.akq);
#endif
  int n = db->store_threads ? (int)db->store_threads : KARIDNS_DB_STORE_THREADS_DEFAULT;
  if (n > DBS_MAX_ATTACH_THREADS) n = DBS_MAX_ATTACH_THREADS;
  atomic_store(&G.astop, false);
  for (int i = 0; i < n; i++) {
    if (pthread_create(&G.athr[G.nathr], NULL, attach_thread, NULL) != 0) break;
    G.nathr++;
  }
  if (G.nathr == 0) {
    syslog(LOG_ERR, "[Store] no attach thread could be started; zones are read from the database only");
    return true;
  }
  atomic_store(&G.attach_on, true);
  /* 0.7 fix 7: the worker attaches a zone whose image is in the page cache; only the MAP mode has a page cache to ask (COPY reads with pread) */
  {
    store_stats_t ms;
    store_stats(st, &ms);
    atomic_store(&G.wa_on, ms.mode == STORE_MODE_MAP);
  }
  /* 0.7 fix 8: the list of the zones that were in memory at the last clean stop (db_store_hot_start() attaches them) */
  G.hot_on = db->store_hot_list;
  atomic_store(&G.hot_state, db->store_hot_list ? DBS_HOT_NONE : DBS_HOT_OFF);
  if (db->store_hot_list) {
    size_t hn = 0;
    uint32_t *hids = NULL;
    const int hr = store_hot_read(st, &hids, &hn);
    if (hr == 0 && hn > 0) {
      G.hot_ids = hids;
      G.hot_n = hn;
      atomic_store(&G.hot_listed, hn);
      syslog(LOG_NOTICE, "[Store] hot.list: %zu zone(s) were in memory at the last clean stop; they are attached in the background, after the queries", hn);
    } else if (hr != 0 && hr != -ENOENT) {
      syslog(LOG_WARNING, "[Store] hot.list is not used (%s)", hr == -EBADMSG ? "damaged, or the list of another store" : strerror(-hr));
    }
  }
  atomic_store_explicit(&g_dbdir, &g_ops, memory_order_release);         /* from here the store is the directory of the database zones (zref_find_suffix()) */
  store_stats_t ss;
  store_stats(st, &ss);
  syslog(LOG_NOTICE, "[Store] the zone store is on: %s mode, %llu zone(s) stored, %llu known, %d attach thread(s)%s", ss.mode == STORE_MODE_MAP ? "map" : "copy",
         (unsigned long long)ss.zones_stored, (unsigned long long)ss.zones_known, G.nathr, ss.recovery.was_clean ? "" : ", the last stop was not clean");
  if (ss.recovery.created) {
    bool dflt = false;
    struct stat dst;
    const char *dpath = db_store_dir_of(&cfg->database, &dflt);
    const unsigned dmode = fstat(g_dir.dirfd, &dst) == 0 ? (unsigned)(dst.st_mode & 0777) : 0;
    syslog(LOG_NOTICE, "[Store] the zone store was created (first use) in %s%s: directory mode %04o (the user the server runs as), %s mode; it is the directory of the database zones: it keeps the zone images, and a zone that is not in memory costs no heap (about as much disk as the zones take in memory; it can be deleted while the server is stopped); `store none;` in the database block turns it off", dpath ? dpath : "?",
           dflt ? " (the default directory)" : "", dmode, ss.mode == STORE_MODE_MAP ? "map" : "copy");
  }
  return true;
}

void db_store_stop(void) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) return;
  atomic_store(&G.hstop, true);                               /* 0.7 fix 8: the background attach of hot.list ends first */
  for (int i = 0; G.hthr_started && i < G.hot_nstarted; i++) pthread_join(G.hthr[i], NULL);
  G.hthr_started = false;
  G.hot_nstarted = 0;
  free(G.hot_ids);
  G.hot_ids = NULL;
  G.hot_n = 0;
  atomic_store(&G.attach_on, false);
  atomic_store(&G.astop, true);
#if defined(__FreeBSD__)
  if (G.akq >= 0) {
    struct kevent t;
    EV_SET(&t, PARK_ATTACH_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    (void)kevent(G.akq, &t, 1, NULL, 0, NULL);
  }
#endif
  for (int i = 0; i < G.nathr; i++) pthread_join(G.athr[i], NULL);
  G.nathr = 0;
  (void)rcu_writer_wait_until_safe(rcu_writer_advance_epoch(), 5000);          /* (the staged elements that were registered are freed when the readers that may have found them have left) */
  stgr_run(false);
  pthread_mutex_lock(&G.wlock);
  G.wstop = true;
  pthread_cond_broadcast(&G.wcv);
  pthread_mutex_unlock(&G.wlock);
  if (G.wthr_started) pthread_join(G.wthr, NULL);
  G.wthr_started = false;
  if (G.hot_on) hot_write(st);                                /* 0.7 fix 8: what is in memory, the most used first, for the next start (the attach threads are gone: nothing registers a zone meanwhile) */
  /* a clean stop: the flag says so on disk, so the next start does not log an unclean stop and (after a reboot) does not rebuild the tables.  The store stays open, as
   * workers may still look; a write after this (a straggler) clears the flag again before it changes anything. */
  int r = store_checkpoint_clean(st);
  if (r < 0) syslog(LOG_WARNING, "[Store] the clean checkpoint at the stop failed: %s; the next start recovers from the journal", strerror(-r));
}

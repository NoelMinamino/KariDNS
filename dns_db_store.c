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

#define DBS_NAME_MAX 256
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

#define DBS_MAX_ATTACH_THREADS 8
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
  _Atomic int64_t last_err_log_ns;
} G = { .wlock = PTHREAD_MUTEX_INITIALIZER, .wcv = PTHREAD_COND_INITIALIZER, .akq = -1 };

bool db_store_enabled(void) { return atomic_load_explicit(&G.st, memory_order_acquire) != NULL; }
store_t *db_store_handle(void) { return atomic_load_explicit(&G.st, memory_order_acquire); }

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

static bool set_put_slot(uint32_t id, zone_ext_shared_t *sh) {
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

/* read the file at the start; a bad or torn tail is cut.  The fd stays open for the appends. */
static void set_load(int dirfd) {
  SET.fd = openat(dirfd, "settings.dat", O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (SET.fd < 0) {
    syslog(LOG_WARNING, "[Store] cannot open settings.dat (%s): zones whose settings are not known are read from the database", strerror(errno));
    return;
  }
  struct stat st;
  if (fstat(SET.fd, &st) != 0) return;
  off_t off = 0;
  for (;;) {
    uint32_t h[3];
    if (pread(SET.fd, h, sizeof(h), off) != (ssize_t)sizeof(h) || h[0] != DBS_SET_MAGIC || h[1] == 0 || h[1] > (1u << 20) || off + 12 + (off_t)h[1] > st.st_size) break;
    uint8_t *buf = malloc(h[1]);
    if (!buf) break;
    if (pread(SET.fd, buf, h[1], off + 12) != (ssize_t)h[1] || set_crc(buf, h[1]) != h[2]) {
      free(buf);
      break;
    }
    zone_ext_shared_t *sh = set_rebuild(buf, h[1]);
    free(buf);
    if (!sh) {                                     /* a text that does not parse any more (the parser changed): the id stays unused, a zone that names it is read from the database */
      SET.n++;
    } else {
      SET.n++;
      if (!set_put_slot(SET.n, sh)) {
        zone_ext_shared_unref(sh);
        break;
      }
      sh->store_id = SET.n;
    }
    off += 12 + (off_t)h[1];
  }
  if (off < st.st_size && ftruncate(SET.fd, off) != 0) syslog(LOG_WARNING, "[Store] settings.dat: the torn end cannot be cut: %s", strerror(errno));
  SET.end = off;
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
static struct {
  pthread_mutex_t lock;
  _Atomic(att_tab_t *) tab;
  size_t live, used;                 /* used = live + tombstones */
  att_retired_t *retired;
  _Atomic uint64_t puts, removes, grows;
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

static bool dir_attach_put(zdir_elem_t *el) {
  pthread_mutex_lock(&AT.lock);
  att_retired_run_locked(false);
  att_tab_t *t = atomic_load_explicit(&AT.tab, memory_order_relaxed);
  if (!t || (AT.used + 1) * 2 > t->cap) {                       /* load above 1/2 (tombstones count): a bigger table, or the same size without the tombstones */
    size_t cap = ATT_MIN_CAP;
    while (cap < (AT.live + 1) * 4) cap <<= 1;
    if (!att_rehash_locked(cap)) {
      pthread_mutex_unlock(&AT.lock);
      return false;
    }
    t = atomic_load_explicit(&AT.tab, memory_order_relaxed);
  }
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

static void dmax_refresh(store_t *st, int vid) {
  if (vid >= 0 && vid < STORE_MAX_VIEWS) atomic_store_explicit(&G.dmax[vid], (uint16_t)store_view_depth_max(st, (uint16_t)vid), memory_order_relaxed);
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
    if (el) {
      if (el->sview == (uint16_t)sid && el->klen == len && strncasecmp(el->name, fname, len) == 0) {
        zone_db_entry_t *e = zdir_entry(el);
        if (!e) continue;
        out->el = el;
        out->entry = e;
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

static bool dir_rec_get(const char *view, const char *zone, dbdir_rec_t *o) {
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
    o->zid = z.zid;
    o->stamp_gen = z.stamp_gen;
    o->stamp_time = z.stamp_time;
    o->state = z.state;
    o->flags = z.flags;
    o->serial = z.serial;
    o->settings = z.settings;
    o->source_id = z.source_id;
    memcpy(o->digest, z.digest, 32);
    ok = true;
  }
  store_read_unlock();
  return ok;
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
static int dir_put(const char *view, const char *zone, zone_db_entry_t *entry, int64_t source_id, uint32_t serial, const uint8_t digest[32], uint32_t settings, uint32_t *zid_out) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (!st) return -ENODEV;
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
  if (labels < 63 && labels > atomic_load_explicit(&G.dmax[vid], memory_order_relaxed)) atomic_store_explicit(&G.dmax[vid], (uint16_t)labels, memory_order_relaxed);
  const zone_image_t *img = v->image;
  int r = store_put(st, (uint16_t)vid, name, nlen, &m, img, img->total_size, &zid);
  if (r == -EEXIST && source_id != 0) {                    /* the domain id is another zone of the store (a renamed domain): that one goes, the new name is put */
    store_read_lock();
    uint32_t old = store_find_source(st, m.source, source_id, (uint16_t)vid);
    store_read_unlock();
    if (old != STORE_NONE && store_delete(st, old) == 0) r = store_put(st, (uint16_t)vid, name, nlen, &m, img, img->total_size, &zid);
  }
  atomic_fetch_sub_explicit(&v->xfr_refs, 1, memory_order_acq_rel);
  if (r == 0) {
    atomic_fetch_add(&G.wt_put, 1);
    *zid_out = zid;
    return 0;
  }
  note_error("the write", zone, r);
  return r;
}

static int dir_del(const char *view, const char *zone, int64_t source_id, bool *had) {
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

/* the record loses its image (it is damaged, or the version is not trusted): the zone is read from the database again.  The name finds the record also when its cell cannot be read. */
static void set_known_by_name(const char *view, const char *zone, int64_t source_id, uint32_t serial) {
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

static void dir_note_flags(uint32_t zid, uint16_t set, uint16_t clear) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (st) (void)store_set_flags(st, zid, set, clear);
}

static uint64_t dir_counters(int what) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) return 0;
  store_stats_t ss;
  store_read_lock();                                          /* (store_stats() reads the index generation, which a writer may retire: inside a read section) */
  store_stats(st, &ss);
  store_read_unlock();
  switch (what) {
  case 0: return ss.zones_known + ss.zones_stored;
  case 1: return ss.zones_stored;
  case 2: return ss.zones_known;
  case 3: return ss.zones_rejected;
  case 4: return AT.live;
  default: return 0;
  }
}

static const dbdir_ops_t g_ops = {
  .view_sid = dir_view_sid,
  .view_gen = dir_view_gen,
  .depth_max = dir_depth_max,
  .find = dir_find,
  .settings = dir_settings,
  .settings_id = dir_settings_id,
  .rec_get = dir_rec_get,
  .put = dir_put,
  .del = dir_del,
  .note_flags = dir_note_flags,
  .attach_put = dir_attach_put,
  .attach_remove = dir_attach_remove,
  .attach_count = dir_attach_count,
  .attach_get = dir_attach_get,
  .attach_next = dir_attach_next,
  .attach_tab_id = dir_attach_tab_id,
  .counters = dir_counters,
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

bool db_store_sync(int timeout_ms) {
  (void)timeout_ms;                                      /* (writes are made by the thread that installs the zone: nothing is queued) */
  return true;
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

/* the attach did not work, the zone is LOADING no more: the queries that wait for it are given the park-timeout again and the zone is fetched from the database */
static void attach_fallback(const char *view, const char *zone, bool undo_loading) {
  if (undo_loading) dbreg_fetch_end(view, zone);
  atomic_fetch_add(&G.attach_fallback, 1);
  if (park_fetch_request_any(view, zone, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL)) park_wake_queue_retry(view, zone);
  else park_wake_queue_all(view, zone, true);                /* (no place to ask from: the queries are answered "not ready" at once, the next one asks again) */
}

static uint32_t clamp_ttl(uint32_t v) { return v > 2147483647u ? 2147483647u : v; }

/* Design 6.4: the answers of a zone do not depend on which zones happen to be in memory.  The glue of a name server that lives in another zone of the view (the target of an NS, MX or SRV
 * record outside this zone) is taken from that zone when it is in memory (append_glue_records()); a zone that is only stored would leave the first answer without it.  So the attach of a
 * zone attaches, in the same job and before its queries are woken, the stored zones that its name server, mail and service targets are in (one level: those are attached without looking at
 * their own targets; at most SIB_MAX of them, the first ones in the order of the zone). */
#define SIB_MAX 8
#define SIB_TARGETS 48
static void attach_zone_x(const char *view, const char *zone, bool siblings, bool bg);
static void attach_siblings(const char *view, const char *zone) {
  zone_db_entry_t *e = dbreg_pin_entry(view, zone);
  if (!e) return;
  static _Thread_local char names[SIB_MAX][DBS_NAME_MAX], holders[SIB_MAX][KARIDNS_VIEW_NAME_MAX];
  char seen[SIB_TARGETS][DBS_NAME_MAX];
  int n = 0, ns = 0;
  rcu_aux_read_lock();
  zone_version_t *v = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
  const zone_image_t *img = v ? v->image : NULL;
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  view_snapshot_t *vs = snap ? snapshot_find_view(snap, view) : NULL;
  if (img && vs) {
    char tg[DNS_NAME_TEXT_SIZE];
    for (uint32_t i = 0; i < img->n_rrs && n < SIB_MAX && ns < SIB_TARGETS; i++) {
      const uint16_t ty = zone_image_rr_type(img, i);
      if ((ty != 2 && ty != 15 && ty != 33) || zone_image_rr_target(img, i, tg, sizeof(tg)) != 0 || domain_name_is_at_or_below(tg, zone)) continue;
      bool dup = false;
      for (int k = 0; k < ns && !dup; k++) dup = domain_names_match_ci(seen[k], tg);
      if (dup) continue;
      snprintf(seen[ns++], sizeof(seen[0]), "%s", tg);
      zref_t z;
      zref_clear(&z);
      if (!zref_find_suffix(vs, tg, &z) || z.entry || z.el || z.busy || z.zid == ZREF_NOZID || z.zstate != ZREF_ST_ABSENT) continue;
      bool same = false;
      for (int k = 0; k < n && !same; k++) same = domain_names_match_ci(names[k], zref_name(&z));
      if (same) continue;
      snprintf(names[n], sizeof(names[0]), "%s", zref_name(&z));
      snprintf(holders[n], sizeof(holders[0]), "%s", z.hview ? z.hview : view);
      n++;
    }
  }
  rcu_aux_read_unlock();
  xfr_entry_release(e);
  for (int k = 0; k < n; k++) attach_zone_x(holders[k], names[k], false, true);               /* (nobody waits for a sibling: it goes first when memory-limit needs room) */
}

void db_store_attach_zone(const char *view, const char *zone) { attach_zone_x(view, zone, true, false); }
void db_store_attach_zone_sync(const char *view, const char *zone) { attach_zone_x(view, zone, false, true); }

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

/* bg: nobody waits for the zone (the background attach of a CNAME or glue target): it is marked to go first when memory-limit needs room, like a zone a background fetch brought */
static void attach_zone_x(const char *view, const char *zone, bool siblings, bool bg) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) {
    park_wake_queue_all(view, zone, true);
    return;
  }
  const int64_t t0 = mono_ns();
  attach_make_room();
  dbreg_attach_info_t ai;
  int b = dbreg_attach_begin(view, zone, &ai);
  if (b == DBREG_ATT_RESIDENT) {                             /* (another attach or a fetch was first) */
    atomic_fetch_add(&G.attach_resident, 1);
    park_wake_queue_all(view, zone, false);
    return;
  }
  if (b == DBREG_ATT_BUSY) {
    /* a fetch (or another attach) of the zone is on its way and wakes the queries that wait when it is done.  They were parked for the attach deadline, though: they are
     * given the park-timeout (a retry key), or they would be answered "not ready" at 200 ms behind a cold read that takes longer */
    atomic_fetch_add(&G.attach_busy, 1);
    park_wake_queue_retry(view, zone);
    return;
  }
  if (b != DBREG_ATT_STARTED) {
    attach_fallback(view, zone, false);
    return;
  }
  /* the zone is LOADING: every way out of here makes the entry (dbreg_commit()) or ends it (dbreg_fetch_end()) */
  int cause = STORE_ATT_ERR_OTHER;
  const char *why = "";
  bool damaged = false;
  store_img_t img;
  bool have_img = false;
  zone_db_entry_t *entry = NULL;
  zone_version_t *ver = NULL;
  imgref_t *ref = NULL;
  store_zone_t sz;
  char name[DBS_NAME_MAX];
  size_t nlen = 0;
  uint32_t zid = STORE_NONE;
  zone_image_soa_t nums;
  memset(&nums, 0, sizeof(nums));
  if (!store_name(zone, name, sizeof(name), &nlen)) {
    why = "name";
    goto fail;
  }
  store_read_lock();
  int vid = store_view_id(st, view);
  if (vid >= 0) zid = store_find(st, (uint16_t)vid, name, nlen);
  int r = zid == STORE_NONE ? -ENOENT : store_zone_get(st, zid, &sz);
  if (r == 0 && sz.state == STORE_STATE_STORED) {
    if (sz.serial != ai.serial || (ai.source_id != 0 && sz.source_id != ai.source_id) || (ai.digest_set && memcmp(sz.digest, ai.digest, STORE_DIGEST_LEN) != 0)) {
      store_read_unlock();
      atomic_fetch_add(&G.attach_stale, 1);
      why = "stale";
      cause = STORE_ATT_ERR_OTHER;
      goto fail;                                             /* (a newer version was stored after the element was made: the install that did it commits its own entry) */
    }
    r = store_image_read(st, zid, &img);
    have_img = r == 0;
  } else if (r == 0) {
    r = -ENOENT;                                             /* known, no image */
  }
  store_read_unlock();
  if (r != 0) {
    if (r == -ENOENT) {
      atomic_fetch_add(&G.attach_missing, 1);
      why = "missing";
    } else if (r == -EBADMSG) {
      damaged = true;
      cause = zid != STORE_NONE && sz.state == STORE_STATE_STORED ? STORE_ATT_ERR_CHECKSUM : STORE_ATT_ERR_RECORD;
      why = "damaged";
    } else {
      cause = r == -ENOMEM ? STORE_ATT_ERR_MEMORY : STORE_ATT_ERR_IO;
      why = "read";
    }
    goto fail;
  }
  /* the image: the store's checksum detects damage, not a forgery (it is not keyed), and what the engine serves must be an image that zone_image_validate() accepts (the
   * offsets it follows are all checked there): every attach validates the image it read, the first read of a record and every later one (an image is about a kilobyte for the
   * zones this store is for; the time is counted, db_store_counters_t.validate_ns).  The apex name too (the validator does not know the zone). */
  const zone_image_t *zi = img.data;
  if (img.len < sizeof(zone_image_t) || ((uintptr_t)img.data & 7u) != 0 || zi->magic != ZONE_IMAGE_MAGIC || zi->version != ZONE_IMAGE_VERSION || zi->total_size != img.len) {
    damaged = true;
    cause = STORE_ATT_ERR_INVALID;
    why = "not an image";
    goto fail;
  }
  {
    char vw[96] = "";
    const int64_t tv0 = mono_ns();
    int vr = zone_image_validate(img.data, img.len, vw, sizeof(vw));
    atomic_fetch_add(&G.validate_ns, (uint64_t)(mono_ns() - tv0));
    atomic_fetch_add(&G.validated, 1);
    if (vr != 0) {
      damaged = true;
      cause = STORE_ATT_ERR_INVALID;
      why = "the image is not valid";
      syslog(LOG_WARNING, "[Store] the image of zone '%s' (view '%s') is not valid: %s", zone, view, vw);
      goto fail;
    }
  }
  {
    uint32_t apex = zone_image_find_name(zi, zone);
    uint32_t soa = zone_image_apex_soa(zi);
    if (apex == ZONE_IMAGE_NONE || apex != zi->apex_name || soa == ZONE_IMAGE_NONE || zone_image_soa(zi, soa, NULL, 0, NULL, 0, &nums) != 0 || nums.serial != ai.serial) {
      damaged = true;
      cause = STORE_ATT_ERR_INVALID;
      why = "the image is not the zone's";
      goto fail;
    }
  }
  entry = db_ingest_new_entry(view, zone, ai.sh);
  if (!entry) {
    cause = STORE_ATT_ERR_MEMORY;
    why = "memory";
    goto fail;
  }
  ref = malloc(sizeof(*ref));
  if (!ref) {
    cause = STORE_ATT_ERR_MEMORY;
    why = "memory";
    goto fail;
  }
  {
    /* what the version counts for the image: the mapped bytes, or the buffer the store read (the allocator's size) */
    size_t bytes = img.len;
    if (img.priv_) bytes = dns_alloc_size(img.priv_, (size_t)((64u + ((nlen + 15u) & ~15u) + img.len + 63u) & ~63u));
    ref->st = st;
    ref->img = img;
    ref->bytes = bytes;
    ver = zone_version_new_ext((zone_image_t *)(uintptr_t)img.data, bytes, imgref_free, ref);
  }
  if (!ver) {
    free(ref);
    ref = NULL;
    cause = STORE_ATT_ERR_MEMORY;
    why = "memory";
    goto fail;
  }
  have_img = false;                                          /* the version owns the image from here (imgref_free() gives it back) */
  atomic_fetch_add(&G.attached_bytes, ref->bytes);
  atomic_fetch_add(&G.versions_live, 1);
  atomic_store_explicit(&entry->serial, nums.serial, memory_order_relaxed);
  atomic_store_explicit(&entry->refresh, clamp_ttl(nums.refresh), memory_order_relaxed);
  atomic_store_explicit(&entry->retry, clamp_ttl(nums.retry), memory_order_relaxed);
  atomic_store_explicit(&entry->expire, clamp_ttl(nums.expire), memory_order_relaxed);
  pthread_mutex_lock(&entry->writer_lock);
  zone_install_version(entry, ver, NULL, false);
  pthread_mutex_unlock(&entry->writer_lock);
  ver = NULL;
  {
    /* the directory must still offer the version that was read (a delete or a newer install may have come meanwhile): checked in the commit, under the registry's lock, so
     * that nothing can come between the check and the store (the fetch path is safe by name_in_flight(): the jobs of one name do not overlap) */
    bool shadowed = false;
    if (dbreg_commit_attach(view, zone, entry, &ai, ai.digest_set ? ai.digest : sz.digest, &shadowed) != 0) {
      free_zone_db_entry(entry);                             /* never registered; its version (and the image) go with it */
      entry = NULL;
      atomic_fetch_add(&G.attach_stale, 1);
      zone_ext_shared_unref(ai.sh);
      attach_fallback(view, zone, true);
      store_status_note_attach(0, STORE_ATT_ERR_OTHER);
      return;
    }
  }
  dbreg_touch_loaded(view, zone);
  if (bg) dbreg_bg_loaded(view, zone);
  zone_ext_shared_unref(ai.sh);
  atomic_fetch_add(&G.attach_ok, 1);
  store_status_note_attach((uint64_t)(mono_ns() - t0), STORE_ATT_OK);
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[Store] zone '%s' (view '%s'), serial %u attached from the store in %lld us", zone, view, ai.serial, (long long)((mono_ns() - t0) / 1000));
  if (siblings) attach_siblings(view, zone);                  /* (before the queries are woken: their first answer has the glue of the zones it depends on) */
  park_wake_queue_all(view, zone, false);
  return;
fail:
  if (have_img) store_img_release(st, &img);
  if (ver) zone_version_free(ver);                           /* (no entry has it: its image goes through imgref_free() ... only when the version was made) */
  if (entry) free_zone_db_entry(entry);
  zone_ext_shared_unref(ai.sh);
  if (damaged) {
    atomic_fetch_add(&G.attach_damaged, 1);
    syslog(LOG_WARNING, "[Store] the record of zone '%s' (view '%s') cannot be used (%s); the zone is read from the database again", zone, view, why);
    set_known_by_name(view, zone, ai.source_id, ai.serial);   /* (the next look takes the fetch path at once, not an attach that fails again) */
  }
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[Store] zone '%s' (view '%s') not attached from the store: %s; fetched from the database", zone, view, why);
  store_status_note_attach(0, cause);
  attach_fallback(view, zone, true);
}

#if defined(__FreeBSD__)
static void *attach_thread(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  park_fetch_req_t q;
  while (!atomic_load_explicit(&G.astop, memory_order_acquire)) {
    bool any = false;
    while (park_attach_next(&q)) {
      any = true;
      attach_zone_x(q.view, q.zone, true, q.prio == 2 /* park_attach_request_bg() */);
    }
    if (any) park_wake_flush();
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
  park_fetch_req_t q;
  while (!atomic_load_explicit(&G.astop, memory_order_acquire)) {
    bool any = false;
    while (park_attach_next(&q)) {
      any = true;
      db_store_attach_zone(q.view, q.zone);
    }
    if (any) park_wake_flush();
    struct timespec nap = { 0, 1000000L };
    nanosleep(&nap, NULL);
  }
  return NULL;
}
#endif

/* ------------------------------------------------------------------------------------------------------------- */
/* start and stop                                                                                                 */
/* ------------------------------------------------------------------------------------------------------------- */

static void evict_hook(int reason) {
  store_status_note_detach_why(reason == DBREG_EVICT_LIMIT ? STORE_DET_LIMIT : reason == DBREG_EVICT_ROOM ? STORE_DET_ROOM : STORE_DET_OTHER);
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
static void bits_set(bits_t *b, uint32_t zid) {
  if (zid == STORE_NONE || !bits_grow(b, zid)) return;
  b->w[zid / 64] |= 1ull << (zid % 64);
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

/* All of it is the ingest thread's, but the figures (RC.s, the guard) are read by the control thread (karictl store, dbstatus): under RC.mu */
static struct {
  pthread_mutex_t mu;
  /* the pass */
  bool active, force;
  int vid;
  char view[STORE_VIEW_NAME_MAX + 1];
  bits_t seen;
  int64_t t0_ns;
  /* the secondary and catalog records that the scan has asked for since the start (the zone loads once a run unless it changes) */
  bits_t np_done;
  /* the mass-delete guard: the views whose sweep is held back */
  bool held[STORE_MAX_VIEWS];
  db_recon_status_t s;
} RC = { .mu = PTHREAD_MUTEX_INITIALIZER };

static void rc_lock(void) { pthread_mutex_lock(&RC.mu); }
static void rc_unlock(void) { pthread_mutex_unlock(&RC.mu); }

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

/* One entry (design 5.3, 5.4).  See dns_db_store.h for the rules. */
int db_recon_apply(const char *view, const db_recon_entry_t *e, uint32_t *zid_out) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (zid_out) *zid_out = STORE_NONE;
  if (!st || !view || !e || !e->name) return DBR_ERROR;
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (!store_name(e->name, name, sizeof(name), &nlen)) return DBR_UNSTORABLE;
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
      if (dr < 0 && dr != -ENOENT) return DBR_ERROR;
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
    if (r == 0) {
      const unsigned labels = store_name_labels(name, nlen);
      if (labels < 63 && labels > atomic_load_explicit(&G.dmax[vid], memory_order_relaxed)) atomic_store_explicit(&G.dmax[vid], (uint16_t)labels, memory_order_relaxed);
    }
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
    return DBR_ERROR;
  }
  if (np && (res == DBR_NEW || res == DBR_CHANGED || res == DBR_RENAMED)) bits_clear(&RC.np_done, zid);
  if (zid_out) *zid_out = zid;
  return res;
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
  if (estimate > have && estimate <= 16000000ull) (void)store_reserve(st, estimate);        /* (a first fill: the tables are made big enough once; the estimate is the loader's claim, bounded) */
  rc_lock();
  bits_free(&RC.seen);
  RC.active = true;
  RC.force = force;
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
  (void)bits_grow(&RC.seen, (uint32_t)(have + (estimate < 16000000ull ? estimate : 16000000ull) + 4096));
  return true;
}

int db_recon_entry(const db_recon_entry_t *e, uint32_t *zid_out) {
  if (!RC.active) return DBR_ERROR;
  uint32_t zid = STORE_NONE;
  int r = db_recon_apply(RC.view, e, &zid);
  if (zid != STORE_NONE) bits_set(&RC.seen, zid);
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
  rc_lock();
  RC.s.skipped = n_skipped;
  rc_unlock();
  if (!complete) {
    syslog(LOG_WARNING, "[Store] view '%s': the pass was not complete (the loader had a database error): nothing is swept, no cursor is kept; the next pass starts again", view);
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
    syslog(LOG_ERR, "[Store] view '%s': the pass over the database lists %llu zone(s) fewer than the %llu the Backend holds for it (more than %u percent, and more than %u): NOTHING IS DELETED, the "
                    "zones keep being served and the cursor is not advanced. If the database is right, `karictl reload -force` deletes them; if not, repair the source",
           view, (unsigned long long)unlisted, (unsigned long long)total, DBS_GUARD_PCT, DBS_GUARD_MIN);
    goto done;
  }
  rc_lock();
  RC.held[vid] = false;                                     /* (a pass that finds nothing alarming, or that the operator asked for, lets go of an old hold) */
  rc_unlock();
  if (unlisted > 0) {
    uint64_t deleted = 0;
    rc_victim_t *vic = malloc(RC_VICTIMS * sizeof(*vic));
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
        for (unsigned i = 0; i < nv; i++)
          if (dbreg_delete(view, vic[i].zone, vic[i].sid) > 0) deleted++;
      }
      free(vic);
    }
    out->swept = true;
    out->deleted = deleted;
    rc_lock();
    RC.s.swept = deleted;
    rc_unlock();
    syslog(LOG_NOTICE, "[Store] view '%s': %llu zone(s) the database no longer lists were deleted (%llu of %llu)%s", view, (unsigned long long)deleted, (unsigned long long)unlisted,
           (unsigned long long)total, force ? " (a pass the operator asked for)" : "");
    dmax_refresh(st, vid);
  }
  if (cursor_valid) db_recon_cursor_put(view, cursor, ident, ident_len);
done:
  rc_lock();
  RC.active = false;
  RC.s.duration_ms = out->duration_ms;
  bits_free(&RC.seen);
  rc_unlock();
}

int db_recon_delete(const char *view, int64_t source_id, const char *name) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st || !view) return 0;
  char zone[STORE_NAME_MAX + 2];
  zone[0] = '\0';
  if (name && *name) {
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
  rc_lock();
  if (r > 0) RC.s.change_deletes++;
  rc_unlock();
  return r > 0 ? 1 : 0;
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

void db_recon_scan_retry(uint32_t zid) { bits_clear(&RC.np_done, zid); }

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
    }
  }
  for (int vid = 0; vid < STORE_MAX_VIEWS; vid++) dmax_refresh(st, vid);
  atomic_fetch_add(&G.view_gen, 1);
  atomic_store(&G.st, st);
  store_status_bind(st);
  store_status_set_attached_fn(attached_fn);
  store_status_set_attached_count_fn(attached_count_fn);
  store_status_set_recon_fn(recon_status_cb);
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
  pthread_mutex_lock(&G.wlock);
  G.wstop = true;
  pthread_cond_broadcast(&G.wcv);
  pthread_mutex_unlock(&G.wlock);
  if (G.wthr_started) pthread_join(G.wthr, NULL);
  G.wthr_started = false;
  /* a clean stop: the flag says so on disk, so the next start does not log an unclean stop and (after a reboot) does not rebuild the tables.  The store stays open, as
   * workers may still look; a write after this (a straggler) clears the flag again before it changes anything. */
  int r = store_checkpoint_clean(st);
  if (r < 0) syslog(LOG_WARNING, "[Store] the clean checkpoint at the stop failed: %s; the next start recovers from the journal", strerror(-r));
}

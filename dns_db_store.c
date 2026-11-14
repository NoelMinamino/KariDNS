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

#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__) || __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define DBS_SANITIZER 1
#else
#define DBS_SANITIZER 0
#endif

#define DBS_NAME_MAX 256

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
    /* a directory that root or the user the server runs as owns, that nobody else can write in; it is handed to that user */
    if (st.st_uid != 0 && uid != (uid_t)-1 && st.st_uid != uid) {
      snprintf(why, sizeof(why), "the directory %s belongs to user %u, neither root nor the user the server runs as", path, (unsigned)st.st_uid);
      goto bad;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
      snprintf(why, sizeof(why), "the directory %s can be written by group or others (mode %o): it must not be", path, (unsigned)(st.st_mode & 07777));
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
    if (st.st_uid != geteuid()) {
      snprintf(why, sizeof(why), "the directory %s belongs to user %u, not to the user the server runs as", path, (unsigned)st.st_uid);
      goto bad;
    }
    if ((st.st_mode & 077) != 0 && fchmod(dfd, 0700) != 0) {
      snprintf(why, sizeof(why), "the directory %s can be used by group or others and its mode cannot be changed: %s", path, strerror(errno));
      goto bad;
    }
  }
  /* one server per store: a lock file inside it, held for as long as the descriptor is open (the Backend inherits it) */
  lfd = openat(dfd, "lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (lfd < 0) {
    snprintf(why, sizeof(why), "cannot open the lock file in %s: %s", path, strerror(errno));
    goto bad;
  }
  if (privileged && (uid != (uid_t)-1 || gid != (gid_t)-1)) (void)fchown(lfd, uid, gid);
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

enum { WJ_PUT = 1, WJ_DEL, WJ_KNOWN, WJ_COMMIT };

typedef struct {
  int kind;
  char view[PARK_VIEW_MAX + 1];
  char zone[DBS_NAME_MAX];            /* the store's name: lower case, no trailing dot */
  store_meta_t meta;
  zone_db_entry_t *entry;             /* PUT: held (xfr_entry_hold()) until the job is done */
  zone_version_t *ver;                /* PUT: pinned (xfr_refs) */
} wjob_t;

#define DBS_MAX_ATTACH_THREADS 8

static struct {
  _Atomic(store_t *) st;
  bool paranoid;
  _Atomic bool attach_on;
  /* writer */
  pthread_t wthr;
  bool wthr_started;
  pthread_mutex_t wlock;
  pthread_cond_t wcv;                 /* a job arrived, or stop */
  pthread_cond_t wdone;               /* the queue became empty and idle */
  wjob_t *wq;
  uint32_t wq_head, wq_n;
  bool wbusy, wstop;
  /* attach threads */
  pthread_t athr[DBS_MAX_ATTACH_THREADS];
  int nathr;
  int akq;
  _Atomic bool astop;
  /* counters */
  _Atomic uint64_t wt_queued, wt_inline, wt_put, wt_skipped, wt_deleted, wt_invalidated, wt_errors, wt_dropped;
  _Atomic uint64_t attach_ok, attach_stale, attach_missing, attach_damaged, attach_fallback, attach_resident, attach_busy;
  _Atomic uint64_t attached_bytes, versions_live;
  _Atomic int64_t last_err_log_ns;
} G = { .wlock = PTHREAD_MUTEX_INITIALIZER, .wcv = PTHREAD_COND_INITIALIZER, .wdone = PTHREAD_COND_INITIALIZER, .akq = -1 };

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

/* ------------------------------------------------------------------------------------------------------------- */
/* write-through                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------- */

static void job_release(wjob_t *j) {
  if (j->ver) atomic_fetch_sub_explicit(&j->ver->xfr_refs, 1, memory_order_acq_rel);
  if (j->entry) xfr_entry_release(j->entry);
  j->ver = NULL;
  j->entry = NULL;
}

static void note_error(const char *what, const char *zone, int rc) {
  atomic_fetch_add(&G.wt_errors, 1);
  int64_t now = mono_ns();
  if (now - atomic_load_explicit(&G.last_err_log_ns, memory_order_relaxed) > 5000000000ll) {          /* (at most one line in five seconds: a full disk fails every zone) */
    atomic_store_explicit(&G.last_err_log_ns, now, memory_order_relaxed);
    syslog(LOG_ERR, "[Store] %s of zone '%s' failed: %s; the zone is served from memory and read from the database again when it is asked for", what, zone, strerror(rc < 0 ? -rc : rc));
  }
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
  if (ok) (void)store_set_cursor(st, (uint16_t)vid, 0, want, sizeof(want));
}

/* one job, on the writer thread (or on a producer that found the queue full) */
static void job_run(store_t *st, wjob_t *j) {
  if (j->kind == WJ_COMMIT) {
    (void)store_commit(st);
    return;
  }
  size_t nlen = strlen(j->zone);
  int vid = store_view_id(st, j->view);
  if (vid < 0 && j->kind != WJ_DEL) {
    vid = store_view_add(st, j->view);
    if (vid >= 0) note_view_identity(st, vid, j->view);
  }
  if (vid < 0) {
    if (j->kind != WJ_DEL) note_error("the store has no room for another view", j->zone, vid);
    return;
  }
  if (j->kind == WJ_DEL) {
    int r = store_delete_name(st, (uint16_t)vid, j->zone, nlen);
    if (r == 0) atomic_fetch_add(&G.wt_deleted, 1);
    else if (r != -ENOENT) note_error("the delete", j->zone, r);
    return;
  }
  if (j->kind == WJ_KNOWN) {
    uint32_t zid = STORE_NONE;
    store_read_lock();
    zid = store_find(st, (uint16_t)vid, j->zone, nlen);
    store_read_unlock();
    if (zid == STORE_NONE) return;                          /* (nothing to set back) */
    j->meta.source = (uint16_t)vid;
    int r = store_set_known(st, (uint16_t)vid, j->zone, nlen, &j->meta, NULL);
    if (r == 0) atomic_fetch_add(&G.wt_invalidated, 1);
    else if (r != -ENOENT) note_error("the update", j->zone, r);
    return;
  }
  /* WJ_PUT */
  j->meta.source = (uint16_t)vid;
  if (!j->ver || !j->ver->image) return;
  /* the store has this version (a restart that reads every zone again): nothing to write */
  store_zone_t cur;
  bool same = false;
  store_read_lock();
  uint32_t zid = store_find(st, (uint16_t)vid, j->zone, nlen);
  if (zid != STORE_NONE && store_zone_get(st, zid, &cur) == 0 && cur.state == STORE_STATE_STORED && cur.serial == j->meta.serial &&
      cur.source_id == j->meta.source_id && memcmp(cur.digest, j->meta.digest, STORE_DIGEST_LEN) == 0) same = true;
  store_read_unlock();
  if (same) {
    atomic_fetch_add(&G.wt_skipped, 1);
    return;
  }
  const zone_image_t *img = j->ver->image;
  int r = store_put(st, (uint16_t)vid, j->zone, nlen, &j->meta, img, img->total_size, NULL);
  if (r == -EEXIST && j->meta.source_id != 0) {             /* the domain id is another zone of the store (a renamed domain): that one goes, the new name is put */
    store_read_lock();
    uint32_t old = store_find_source(st, j->meta.source, j->meta.source_id, (uint16_t)vid);
    store_read_unlock();
    if (old != STORE_NONE && store_delete(st, old) == 0) r = store_put(st, (uint16_t)vid, j->zone, nlen, &j->meta, img, img->total_size, NULL);
  }
  if (r == 0) atomic_fetch_add(&G.wt_put, 1);
  else note_error("the write", j->zone, r);
}

static void *writer_thread(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  pthread_mutex_lock(&G.wlock);
  for (;;) {
    while (G.wq_n == 0 && !G.wstop) {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      ts.tv_sec += 1;
      if (pthread_cond_timedwait(&G.wcv, &G.wlock, &ts) != 0 && G.wq_n == 0) {
        store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
        if (st) {
          pthread_mutex_unlock(&G.wlock);
          (void)store_tick(st);                           /* the time driven part: group commit, checkpoint */
          pthread_mutex_lock(&G.wlock);
        }
      }
    }
    if (G.wq_n == 0 && G.wstop) break;
    wjob_t j = G.wq[G.wq_head];
    G.wq_head = (G.wq_head + 1) % DB_STORE_WQ_MAX;
    G.wq_n--;
    G.wbusy = true;
    pthread_mutex_unlock(&G.wlock);
    store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
    if (st) job_run(st, &j);
    job_release(&j);
    pthread_mutex_lock(&G.wlock);
    G.wbusy = false;
    if (G.wq_n == 0) pthread_cond_broadcast(&G.wdone);
  }
  pthread_cond_broadcast(&G.wdone);
  pthread_mutex_unlock(&G.wlock);
  return NULL;
}

static void wq_push(wjob_t *j) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) {
    job_release(j);
    return;
  }
  pthread_mutex_lock(&G.wlock);
  if (G.wq_n < DB_STORE_WQ_MAX && G.wthr_started && !G.wstop) {
    G.wq[(G.wq_head + G.wq_n) % DB_STORE_WQ_MAX] = *j;
    G.wq_n++;
    pthread_cond_signal(&G.wcv);
    pthread_mutex_unlock(&G.wlock);
    atomic_fetch_add(&G.wt_queued, 1);
    return;
  }
  pthread_mutex_unlock(&G.wlock);
  /* the queue is full (the writer is slower than the loader): the producer does the job, so nothing is dropped and the loader is held back */
  atomic_fetch_add(&G.wt_inline, 1);
  job_run(st, j);
  job_release(j);
}

bool db_store_sync(int timeout_ms) {
  if (!db_store_enabled()) return true;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += timeout_ms / 1000;
  ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
  if (ts.tv_nsec >= 1000000000L) {
    ts.tv_sec++;
    ts.tv_nsec -= 1000000000L;
  }
  bool ok = true;
  pthread_mutex_lock(&G.wlock);
  while ((G.wq_n > 0 || G.wbusy) && G.wthr_started) {
    if (pthread_cond_timedwait(&G.wdone, &G.wlock, &ts) != 0) {
      ok = G.wq_n == 0 && !G.wbusy;
      break;
    }
  }
  pthread_mutex_unlock(&G.wlock);
  return ok;
}

void db_store_write_through(const char *view, const char *zone, int64_t source_id, uint32_t serial, const uint8_t digest[32]) {
  if (!db_store_enabled()) return;
  wjob_t j;
  memset(&j, 0, sizeof(j));
  size_t nlen;
  if (!store_name(zone, j.zone, sizeof(j.zone), &nlen) || strlen(view) > PARK_VIEW_MAX) return;
  zone_db_entry_t *e = dbreg_pin_entry(view, zone);
  if (!e) return;
  bool ok = false;
  zone_version_t *v = NULL;
  uint16_t flags = 0;
  rcu_aux_read_lock();
  v = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
  if (v && v->image && v->image->n_rrs > 0 && e->source == ZONE_SRC_DB && !e->is_secondary && !e->is_catalog_member &&
      !atomic_load_explicit(&e->updated, memory_order_relaxed) && atomic_load_explicit(&e->serial, memory_order_relaxed) == serial) {
    atomic_fetch_add_explicit(&v->xfr_refs, 1, memory_order_acq_rel);
    if (v->image->flags & ZONE_IMAGE_F_ALIAS) flags |= STORE_F_ALIAS;
    if (v->image->flags & ZONE_IMAGE_F_WILDCARD) flags |= STORE_F_WILDCARD;
    if (v->image->n_nsec > 0 || v->image->n_n3chains > 0) flags |= STORE_F_PRESIGNED;
    ok = true;
  }
  rcu_aux_read_unlock();
  if (!ok) {
    xfr_entry_release(e);
    return;
  }
  j.kind = WJ_PUT;
  snprintf(j.view, sizeof(j.view), "%s", view);
  j.meta.source_id = source_id;
  j.meta.flags = flags;
  j.meta.serial = serial;
  memcpy(j.meta.digest, digest, STORE_DIGEST_LEN);
  j.entry = e;
  j.ver = v;
  wq_push(&j);
}

void db_store_delete(const char *view, const char *zone) {
  if (!db_store_enabled()) return;
  wjob_t j;
  memset(&j, 0, sizeof(j));
  size_t nlen;
  if (!store_name(zone, j.zone, sizeof(j.zone), &nlen) || strlen(view) > PARK_VIEW_MAX) return;
  j.kind = WJ_DEL;
  snprintf(j.view, sizeof(j.view), "%s", view);
  wq_push(&j);
}

void db_store_invalidate(const char *view, const char *zone, int64_t source_id, uint32_t serial) {
  if (!db_store_enabled()) return;
  wjob_t j;
  memset(&j, 0, sizeof(j));
  size_t nlen;
  if (!store_name(zone, j.zone, sizeof(j.zone), &nlen) || strlen(view) > PARK_VIEW_MAX) return;
  j.kind = WJ_KNOWN;
  snprintf(j.view, sizeof(j.view), "%s", view);
  j.meta.source_id = source_id;
  j.meta.serial = serial;
  wq_push(&j);
}

void db_store_batch_end(void) {
  if (!db_store_enabled()) return;
  wjob_t j;
  memset(&j, 0, sizeof(j));
  j.kind = WJ_COMMIT;
  wq_push(&j);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* attach                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

bool db_store_attach_possible(const char *view, const char *zone, uint32_t dir_serial) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st || !atomic_load_explicit(&G.attach_on, memory_order_relaxed)) return false;
  int vid = store_view_id(st, view);
  char name[DBS_NAME_MAX];
  size_t nlen;
  if (vid < 0 || !store_name(zone, name, sizeof(name), &nlen)) return false;
  uint32_t zid = store_find(st, (uint16_t)vid, name, nlen);
  if (zid == STORE_NONE) return false;
  store_zone_t z;
  return store_zone_get(st, zid, &z) == 0 && z.state == STORE_STATE_STORED && z.serial == dir_serial;
}

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

void db_store_attach_zone(const char *view, const char *zone) {
  store_t *st = atomic_load_explicit(&G.st, memory_order_acquire);
  if (!st) {
    park_wake_queue_all(view, zone, true);
    return;
  }
  const int64_t t0 = mono_ns();
  dbreg_attach_info_t ai;
  int b = dbreg_attach_begin(view, zone, &ai);
  if (b == DBREG_ATT_RESIDENT) {                             /* (another attach or a fetch was first) */
    atomic_fetch_add(&G.attach_resident, 1);
    park_wake_queue_all(view, zone, false);
    return;
  }
  if (b == DBREG_ATT_BUSY) {
    atomic_fetch_add(&G.attach_busy, 1);                     /* (whoever is at it wakes every worker) */
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
      goto fail;
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
  /* the image: the store's checksum has held; the structure is checked when asked (store-paranoid, sanitizer builds), the apex name always (the validator does not know the zone) */
  const zone_image_t *zi = img.data;
  if (img.len < sizeof(zone_image_t) || ((uintptr_t)img.data & 7u) != 0 || zi->magic != ZONE_IMAGE_MAGIC || zi->version != ZONE_IMAGE_VERSION || zi->total_size != img.len) {
    damaged = true;
    cause = STORE_ATT_ERR_INVALID;
    why = "not an image";
    goto fail;
  }
  if (G.paranoid || DBS_SANITIZER) {
    char vw[96] = "";
    if (zone_image_validate(img.data, img.len, vw, sizeof(vw)) != 0) {
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
    /* the directory must still offer the version that was read (a summary or a delete may have come meanwhile: the fetch path checks the same) */
    int64_t sid;
    uint32_t sr;
    bool shadowed = false;
    if (!dbreg_zone_version(view, zone, &sid, &sr) || sid != ai.source_id || sr != ai.serial ||
        dbreg_commit(view, zone, entry, true, ai.source_id, ai.serial, ai.digest_set ? ai.digest : sz.digest, &shadowed) != 0) {
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
  zone_ext_shared_unref(ai.sh);
  atomic_fetch_add(&G.attach_ok, 1);
  store_status_note_attach((uint64_t)(mono_ns() - t0), STORE_ATT_OK);
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[Store] zone '%s' (view '%s'), serial %u attached from the store in %lld us", zone, view, ai.serial, (long long)((mono_ns() - t0) / 1000));
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
    db_store_invalidate(view, zone, ai.source_id, ai.serial);
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
      db_store_attach_zone(q.view, q.zone);
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
    if (store_get_cursor(st, (uint16_t)vid, &valid, &cursor, have, &hl) != 0 || !valid || hl != sizeof(want) || memcmp(have, want, sizeof(want)) != 0) {
      purge_view(st, vid);
      (void)store_set_cursor(st, (uint16_t)vid, 0, want, sizeof(want));
    }
  }
  G.wq = calloc(DB_STORE_WQ_MAX, sizeof(*G.wq));
  if (!G.wq) {
    (void)store_close(st);
    return false;
  }
  G.paranoid = db->store_paranoid;
  atomic_store(&G.st, st);
  store_status_bind(st);
  dbreg_set_evict_hook(evict_hook);
  G.wstop = false;
  if (pthread_create(&G.wthr, NULL, writer_thread, NULL) != 0) return false;
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
  store_stats_t ss;
  store_stats(st, &ss);
  syslog(LOG_NOTICE, "[Store] the zone store is on: %s mode, %llu zone(s) stored, %llu known, %d attach thread(s)%s%s", ss.mode == STORE_MODE_MAP ? "map" : "copy",
         (unsigned long long)ss.zones_stored, (unsigned long long)ss.zones_known, G.nathr, ss.recovery.was_clean ? "" : ", the last stop was not clean", G.paranoid ? ", paranoid" : "");
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
  (void)store_commit(st);
  (void)store_checkpoint(st);
}

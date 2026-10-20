/*
 * dns_db_ingest.c - the db ingest thread of the Backend (see dns_db_ingest.h).
 *
 * Single thread, no mutex: the stream state is owned by the thread; the only things other threads touch are the
 * "configuration changed" flag and the kqueue EVFILT_USER trigger.  The configuration is read inside an RCU read
 * section (rcu_aux_read_lock) and copied.  Everything from the stream is untrusted: dns_db_stream.c validates it,
 * a violation closes the stream (the loader then ends and the supervisor restarts it).
 *
 * The thread allocates outside the query path only (start, stream buffers, the output queue).
 */
#include "dns_db_ingest.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "dns_config_parser.h"
#include "dns_db_stream.h"
#include "dns_epoch_rcu.h"
#include "dns_server_internal.h"

#define ING_MAX_OUT (32u << 20)   /* queued answers the loader has not read: above this the loader is dropped */
#define ING_ZONES_LOGGED 16       /* zones logged one by one per connection */
#define ING_READ_ROUNDS 16
#define ING_EVT_CONFIG 1          /* EVFILT_USER ident */

typedef struct {
  uint64_t generation;
  char driver[40];
  uint32_t nviews;
  uint64_t max_zone_records, max_zone_bytes;
  bool enabled;
} ing_cfg_t;

typedef struct {
  int kq, ctrl_fd, stream_fd;
  bool write_armed;
  uint8_t *body;               /* KDB_MAX_BODY */
  uint8_t *rbuf;               /* ING_RBUF */
  kdb_framer_t fr;
  kdb_sm_t sm;
  kdb_enc_t enc;
  uint8_t *out;                /* answers queued for the loader */
  size_t out_len, out_off, out_cap;
  bool hello_done;
  /* the zone being received */
  uint16_t zone_view;
  char zone_name[DNS_NAME_TEXT_SIZE];
  uint64_t zone_rr;
  uint32_t zones_logged;
  uint32_t batch_rejected;
} ing_t;

#define ING_RBUF 65536

static ing_t g_ing;
static _Atomic bool g_cfg_dirty;
static _Atomic int g_ing_kq = -1;

/* ------------------------------------------------------------------------------------------------------------- */
/* rights                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

/* Design 1.3: the stream may be read, written and watched, nothing else (no fcntl, no shutdown, no sockopt). */
static void limit_stream_rights(int fd) {
  cap_rights_t r;
  cap_rights_init(&r, CAP_READ, CAP_WRITE, CAP_EVENT);
  if (cap_rights_limit(fd, &r) != 0 && errno != ENOSYS)
    syslog(LOG_ERR, "[DB] cannot limit the rights of the loader stream: %s", strerror(errno));
}

static void limit_ctrl_rights(int fd) {
  cap_rights_t r;
  cap_rights_init(&r, CAP_RECV, CAP_EVENT);
  if (cap_rights_limit(fd, &r) != 0 && errno != ENOSYS)
    syslog(LOG_ERR, "[DB] cannot limit the rights of the loader control socket: %s", strerror(errno));
}

/* ------------------------------------------------------------------------------------------------------------- */
/* configuration snapshot                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

static void fill_snap(const server_config_t *cfg, ing_cfg_t *c) {
  memset(c, 0, sizeof(*c));
  if (cfg && cfg->database.enabled) {
    c->enabled = true;
    c->generation = cfg->generation;
    snprintf(c->driver, sizeof(c->driver), "%s", cfg->database.driver ? cfg->database.driver : "");
    for (const view_config_t *v = cfg->views; v; v = v->next) c->nviews++;
    c->max_zone_records = cfg->database.max_zone_records;
    c->max_zone_bytes = cfg->database.max_zone_bytes;
  }
}

static void snapshot_cfg(ing_cfg_t *c) {
  rcu_aux_read_lock();
  fill_snap(acquire_config_snapshot(), c);
  rcu_aux_read_unlock();
}

/* Only printable ASCII goes into a TLV `str` (the loader refuses anything else): other bytes become '?'. */
static void enc_sane_str(kdb_enc_t *e, uint16_t tag, const char *s) {
  char buf[256];
  size_t n = 0;
  for (; s && *s && n < sizeof(buf) - 1; s++) buf[n++] = (*s >= 0x20 && *s <= 0x7E) ? *s : '?';
  buf[n] = '\0';
  kdb_enc_str(e, tag, buf);
}

/* CONFIG from the active configuration (design 1.4).  A view that takes no DB zones ("database none;") is left
 * out; the others carry their own source or, if they have none, the global one (the loader needs a path for every
 * view it reads; "absent = shared source" of the design is expressed by repeating the global path).  Views are
 * numbered by their position in the configuration.  false: no database block, or too many views. */
static bool build_config(ing_t *g, ing_cfg_t *snap) {
  bool ok = false;
  rcu_aux_read_lock();
  const server_config_t *cfg = acquire_config_snapshot();
  if (cfg && cfg->database.enabled) {
    const database_config_t *db = &cfg->database;
    bool sqlite = db->driver && strcmp(db->driver, "sqlite3") == 0;
    fill_snap(cfg, snap);
    kdb_enc_reset(&g->enc);
    kdb_enc_begin(&g->enc, KDB_T_CONFIG);
    kdb_enc_u64(&g->enc, 1, cfg->generation);
    kdb_enc_str(&g->enc, 2, db->driver);
    if (db->server_id) enc_sane_str(&g->enc, 3, db->server_id);
    uint32_t idx = 0, listed = 0;
    for (const view_config_t *v = cfg->views; v; v = v->next, idx++) {
      if (v->database_none) continue;
      const char *src = sqlite ? (v->database_file ? v->database_file : db->database_file)
                               : (v->database_schema ? v->database_schema : db->schema);
      if (listed >= KDB_MAX_CONFIG_VIEWS) break;
      listed++;
      kdb_enc_nest_begin(&g->enc, 4);
      kdb_enc_u16(&g->enc, 1, (uint16_t)idx);
      enc_sane_str(&g->enc, 2, v->name);
      if (src) kdb_enc_str(&g->enc, 3, src);
      if (!sqlite && db->conninfo_file) kdb_enc_str(&g->enc, 4, db->conninfo_file);
      kdb_enc_u8(&g->enc, 5, db->auto_reload ? 1 : 0);
      kdb_enc_u32(&g->enc, 6, db->poll_interval);
      kdb_enc_u32(&g->enc, 7, db->coalesce_ms);
      kdb_enc_u64(&g->enc, 8, db->max_zone_records);
      kdb_enc_u64(&g->enc, 9, db->max_zone_bytes);
      kdb_enc_nest_end(&g->enc);
    }
    kdb_enc_u32(&g->enc, 5, db->default_ttl);
    kdb_enc_u8(&g->enc, 6, (uint8_t)db->bulk_threshold);
    kdb_enc_u32(&g->enc, 7, db->loader_threads);
    ok = kdb_enc_end(&g->enc) == 0 && idx <= 0xFFFF;
  }
  rcu_aux_read_unlock();
  return ok;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* output queue                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------- */

static void drop_stream(ing_t *g);

static void arm_write(ing_t *g, bool on) {
  if (g->write_armed == on || g->stream_fd < 0) return;
  struct kevent ev;
  EV_SET(&ev, g->stream_fd, EVFILT_WRITE, on ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
  if (kevent(g->kq, &ev, 1, NULL, 0, NULL) == 0) g->write_armed = on;
}

static void out_flush(ing_t *g) {
  while (g->stream_fd >= 0 && g->out_off < g->out_len) {
    ssize_t n = write(g->stream_fd, g->out + g->out_off, g->out_len - g->out_off);
    if (n > 0) {
      g->out_off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      arm_write(g, true);
      return;
    }
    syslog(LOG_NOTICE, "[DB] loader disconnected (write: %s)", n < 0 ? strerror(errno) : "closed");
    drop_stream(g);
    return;
  }
  if (g->stream_fd >= 0) {
    g->out_len = g->out_off = 0;
    arm_write(g, false);
  }
}

/* queue the message built in g->enc and try to send it */
static void send_enc(ing_t *g) {
  if (g->enc.err) {
    syslog(LOG_ERR, "[DB] internal error: cannot encode a message for the loader; closing the stream");
    drop_stream(g);
    return;
  }
  if (g->stream_fd < 0) return;
  if (g->out_len - g->out_off + g->enc.len > ING_MAX_OUT) {
    syslog(LOG_ERR, "[DB] the loader does not read its answers (%zu bytes queued); closing the stream",
           g->out_len - g->out_off);
    drop_stream(g);
    return;
  }
  if (g->out_off > 0 && g->out_off == g->out_len) g->out_len = g->out_off = 0;
  if (g->out_len + g->enc.len > g->out_cap) {
    size_t nc = g->out_cap ? g->out_cap : 4096;
    while (nc < g->out_len + g->enc.len) nc *= 2;
    uint8_t *nb = realloc(g->out, nc);
    if (!nb) {
      syslog(LOG_ERR, "[DB] out of memory queueing an answer for the loader; closing the stream");
      drop_stream(g);
      return;
    }
    g->out = nb;
    g->out_cap = nc;
  }
  memcpy(g->out + g->out_len, g->enc.buf, g->enc.len);
  g->out_len += g->enc.len;
  kdb_enc_reset(&g->enc);
  out_flush(g);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* messages                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

static void drop_stream(ing_t *g) {
  if (g->stream_fd >= 0) close(g->stream_fd); /* the kqueue forgets the descriptor */
  g->stream_fd = -1;
  g->write_armed = false;
  g->out_len = g->out_off = 0;
  g->hello_done = false;
  kdb_enc_reset(&g->enc);
}

static void send_config(ing_t *g, const char *why) {
  ing_cfg_t snap;
  if (!build_config(g, &snap)) {
    syslog(LOG_ERR, "[DB] cannot build CONFIG for the loader (no database block, or more than %d views); "
                    "closing the stream", KDB_MAX_CONFIG_VIEWS);
    drop_stream(g);
    return;
  }
  /* the state machine checks view indexes and limits against the configuration it was sent */
  g->sm.lim.view_count = snap.nviews;
  g->sm.lim.max_zone_records = snap.max_zone_records;
  g->sm.lim.max_zone_bytes = snap.max_zone_bytes;
  syslog(LOG_INFO, "[DB] sent CONFIG generation %llu to the loader (%s): driver %s, %u view(s)",
         (unsigned long long)snap.generation, why, snap.driver, snap.nviews);
  send_enc(g);
}

/* does the comma separated list of the loader's drivers contain name? */
static bool driver_listed(const char *list, size_t len, const char *name) {
  size_t nl = strlen(name);
  size_t i = 0;
  while (i <= len) {
    size_t j = i;
    while (j < len && list[j] != ',') j++;
    if (j - i == nl && memcmp(list + i, name, nl) == 0) return true;
    i = j + 1;
  }
  return false;
}

static void on_hello(ing_t *g, const kdb_msg_t *m) {
  const kdb_hello_t *h = &m->u.hello;
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  syslog(LOG_INFO, "[DB] loader connected: pid %u, version %.*s, drivers %.*s", h->pid, (int)h->loader_version.len,
         h->loader_version.p, (int)h->driver.len, h->driver.p);
  if (!snap.enabled || !driver_listed(h->driver.p, h->driver.len, snap.driver)) {
    syslog(LOG_ERR, "[DB] driver %s is not available in the loader (it has: %.*s); closing the stream", snap.driver,
           (int)h->driver.len, h->driver.p);
    drop_stream(g);
    return;
  }
  g->hello_done = true;
  send_config(g, "handshake");
}

static void on_inventory_req(ing_t *g) {
  /* the registry of DB zones comes with B4b: nothing is installed yet, so the inventory is empty */
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_INVENTORY) != 0 || kdb_enc_end(&g->enc) != 0) {
    send_enc(g);
    return;
  }
  send_enc(g);
  if (g->stream_fd < 0) return;
  if (kdb_enc_begin(&g->enc, KDB_T_INVENTORY_END) != 0 || kdb_enc_u64(&g->enc, 1, 0) != 0 ||
      kdb_enc_u64(&g->enc, 2, 0) != 0 || kdb_enc_end(&g->enc) != 0) {
    send_enc(g);
    return;
  }
  send_enc(g);
  syslog(LOG_INFO, "[DB] loader asked for the inventory: sent 0 zones (the registry of DB zones comes with B4b)");
}

static void on_zone_end(ing_t *g) {
  static const char reason[] = "zone install not implemented yet (B4b)";
  if (g->zones_logged < ING_ZONES_LOGGED) {
    g->zones_logged++;
    syslog(LOG_INFO, "[DB] zone '%s' (view %u): %llu RRs received; %s, rejected", g->zone_name,
           (unsigned)g->zone_view, (unsigned long long)g->zone_rr, reason);
  }
  g->batch_rejected++;
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_ZONE_RESULT) != 0 || kdb_enc_u16(&g->enc, 1, g->zone_view) != 0 ||
      kdb_enc_name(&g->enc, 2, g->zone_name) != 0 || kdb_enc_u8(&g->enc, 3, KDB_ST_REJECTED) != 0 ||
      kdb_enc_str(&g->enc, 4, reason) != 0 || kdb_enc_end(&g->enc) != 0) {
    g->enc.err = true;
  }
  send_enc(g);
}

static void on_batch_end(ing_t *g, const kdb_msg_t *m) {
  const kdb_batch_end_t *b = &m->u.batch_end;
  syslog(LOG_INFO, "[DB] batch %llu complete: %u zone(s) received and rejected (install not implemented yet, B4b), "
                   "%u failed in the loader, %u deleted",
         (unsigned long long)b->batch_id, b->n_zones, b->n_failed, b->n_deleted);
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_BATCH_RESULT) != 0 || kdb_enc_u64(&g->enc, 1, b->batch_id) != 0 ||
      kdb_enc_u32(&g->enc, 3, 0) != 0 || kdb_enc_u32(&g->enc, 4, 0) != 0 ||
      kdb_enc_u32(&g->enc, 5, g->batch_rejected) != 0 || kdb_enc_u32(&g->enc, 6, 0) != 0 ||
      kdb_enc_end(&g->enc) != 0) {
    g->enc.err = true;
  }
  send_enc(g);
}

static void handle_msg(ing_t *g, const kdb_msg_t *m) {
  switch (m->type) {
  case KDB_T_HELLO:
    on_hello(g, m);
    break;
  case KDB_T_INVENTORY_REQ:
    on_inventory_req(g);
    break;
  case KDB_T_BATCH_BEGIN:
    g->batch_rejected = 0;
    break;
  case KDB_T_ZONE_BEGIN:
    g->zone_view = m->u.zone_begin.view;
    snprintf(g->zone_name, sizeof(g->zone_name), "%s", m->u.zone_begin.name);
    g->zone_rr = m->u.zone_begin.rr_count;
    break;
  case KDB_T_ZONE_END:
    on_zone_end(g);
    break;
  case KDB_T_ZONE_FAILED:
    syslog(LOG_WARNING, "[DB] the loader could not read zone '%s' (view %u, id %lld): %.*s", m->u.zone_failed.name,
           (unsigned)m->u.zone_failed.view, (long long)m->u.zone_failed.source_id, (int)m->u.zone_failed.reason.len,
           m->u.zone_failed.reason.p);
    break;
  case KDB_T_BATCH_END:
    on_batch_end(g, m);
    break;
  default: /* ZONE_DATA: counted and bounded by the state machine, nothing to do without an install */
    break;
  }
}

static void on_stream_readable(ing_t *g) {
  for (int round = 0; round < ING_READ_ROUNDS && g->stream_fd >= 0; round++) {
    ssize_t n = read(g->stream_fd, g->rbuf, ING_RBUF);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      syslog(LOG_NOTICE, "[DB] loader disconnected (read: %s)", strerror(errno));
      drop_stream(g);
      return;
    }
    if (n == 0) {
      syslog(LOG_NOTICE, "[DB] loader disconnected");
      drop_stream(g);
      return;
    }
    if (kdb_framer_feed(&g->fr, g->rbuf, (size_t)n) != KDB_OK) {
      syslog(LOG_ERR, "[DB] protocol error from the loader: %s; closing the stream", g->fr.reason);
      drop_stream(g);
      return;
    }
    kdb_frame_t fr;
    for (;;) {
      kdb_rc_t rc = kdb_framer_next(&g->fr, &fr);
      if (rc == KDB_MORE) break;
      if (rc != KDB_OK) {
        syslog(LOG_ERR, "[DB] protocol error from the loader: %s; closing the stream", g->fr.reason);
        drop_stream(g);
        return;
      }
      kdb_msg_t msg;
      rc = kdb_sm_accept(&g->sm, &fr, &msg);
      if (rc != KDB_OK) {
        /* the reason names the rule, never bytes of the stream */
        syslog(LOG_ERR, "[DB] protocol error from the loader: %s; closing the stream", g->sm.reason);
        drop_stream(g);
        return;
      }
      handle_msg(g, &msg);
      if (g->stream_fd < 0) return;
    }
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* connections                                                                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

static void adopt_stream(ing_t *g, int fd) {
  limit_stream_rights(fd); /* at once: a received descriptor has all the rights of the sender's end */
  if (g->stream_fd >= 0) {
    syslog(LOG_NOTICE, "[DB] a new loader stream replaces the old one");
    drop_stream(g);
  }
  g->stream_fd = fd;
  struct kevent ev[2];
  EV_SET(&ev[0], fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  EV_SET(&ev[1], fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, NULL);
  if (kevent(g->kq, ev, 2, NULL, 0, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot watch the loader stream: %s", strerror(errno));
    drop_stream(g);
    return;
  }
  g->write_armed = false;
  g->out_len = g->out_off = 0;
  g->hello_done = false;
  g->zones_logged = 0;
  g->batch_rejected = 0;
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  kdb_limits_t lim = { snap.max_zone_records ? snap.max_zone_records : KDB_DEFAULT_MAX_ZONE_RECORDS,
                       snap.max_zone_bytes ? snap.max_zone_bytes : KDB_DEFAULT_MAX_ZONE_BYTES,
                       snap.nviews ? snap.nviews : KDB_VIEWS_ANY };
  kdb_framer_init(&g->fr, KDB_FROM_LOADER, g->body, KDB_MAX_BODY);
  kdb_sm_init(&g->sm, &lim);
  kdb_enc_reset(&g->enc);
  syslog(LOG_INFO, "[DB] loader stream connected, waiting for HELLO");
}

static void on_ctrl_readable(ing_t *g) {
  for (;;) {
    char byte;
    struct iovec iov = { &byte, 1 };
    union {
      struct cmsghdr h;
      char buf[CMSG_SPACE(sizeof(int) * 4)];
    } u;
    struct msghdr m;
    memset(&m, 0, sizeof(m));
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof(u.buf);
    ssize_t n = recvmsg(g->ctrl_fd, &m, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      syslog(LOG_ERR, "[DB] recvmsg on the loader control socket: %s", strerror(errno));
      return;
    }
    if (n == 0) { /* the supervisor is gone: the server is going down; stop watching so the thread does not spin */
      syslog(LOG_NOTICE, "[DB] the loader control socket was closed by the supervisor");
      close(g->ctrl_fd);
      g->ctrl_fd = -1;
      return;
    }
    int got = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
      if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
      size_t cnt = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
      for (size_t i = 0; i < cnt; i++) {
        int fd;
        memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
        if (got < 0) got = fd;
        else close(fd); /* one stream per message */
      }
    }
    if (m.msg_flags & MSG_CTRUNC) syslog(LOG_ERR, "[DB] the loader control message was truncated");
    if (got >= 0) adopt_stream(g, got);
  }
}

static void on_config_event(ing_t *g) {
  if (!atomic_exchange_explicit(&g_cfg_dirty, false, memory_order_acq_rel)) return;
  if (g->stream_fd >= 0 && g->hello_done) send_config(g, "configuration reloaded");
  /* otherwise the CONFIG of the handshake reads the new configuration */
}

static void *ingest_thread(void *arg) {
  ing_t *g = arg;
  struct kevent evs[8];
  for (;;) {
    int n = kevent(g->kq, NULL, 0, evs, 8, NULL);
    if (n < 0) {
      if (errno == EINTR) continue;
      syslog(LOG_ERR, "[DB] the ingest thread stops: kevent: %s", strerror(errno));
      return NULL;
    }
    for (int i = 0; i < n; i++) {
      const struct kevent *e = &evs[i];
      if (e->filter == EVFILT_USER) {
        on_config_event(g);
      } else if (g->ctrl_fd >= 0 && e->ident == (uintptr_t)g->ctrl_fd) {
        on_ctrl_readable(g);
      } else if (g->stream_fd >= 0 && e->ident == (uintptr_t)g->stream_fd) {
        if (e->filter == EVFILT_WRITE) out_flush(g);
        else on_stream_readable(g);
      }
    }
  }
}

bool db_ingest_start(int stream_fd, int ctrl_fd) {
  ing_t *g = &g_ing;
  memset(g, 0, sizeof(*g));
  g->stream_fd = -1;
  g->ctrl_fd = ctrl_fd;
  g->body = malloc(KDB_MAX_BODY);
  g->rbuf = malloc(ING_RBUF);
  kdb_enc_init(&g->enc);
  g->kq = kqueue();
  if (!g->body || !g->rbuf || g->kq < 0 || ctrl_fd < 0) {
    syslog(LOG_ERR, "[DB] cannot start the ingest thread: %s", g->kq < 0 ? strerror(errno) : "no control socket or memory");
    return false;
  }
  limit_ctrl_rights(ctrl_fd);
  struct kevent ev[2];
  EV_SET(&ev[0], ctrl_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  EV_SET(&ev[1], ING_EVT_CONFIG, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  if (kevent(g->kq, ev, 2, NULL, 0, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot watch the loader control socket: %s", strerror(errno));
    return false;
  }
  if (stream_fd >= 0) adopt_stream(g, stream_fd);
  pthread_t t;
  if (pthread_create(&t, NULL, ingest_thread, g) != 0) {
    syslog(LOG_ERR, "[DB] cannot create the ingest thread");
    return false;
  }
  pthread_detach(t);
  atomic_store_explicit(&g_ing_kq, g->kq, memory_order_release);
  return true;
}

void db_ingest_config_changed(void) {
  int kq = atomic_load_explicit(&g_ing_kq, memory_order_acquire);
  if (kq < 0) return;
  atomic_store_explicit(&g_cfg_dirty, true, memory_order_release);
  struct kevent ev;
  EV_SET(&ev, ING_EVT_CONFIG, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &ev, 1, NULL, 0, NULL);
}

/*
 * dns_db_ingest.c - the db ingest thread of the Backend (see dns_db_ingest.h).
 *
 * The stream state is owned by one thread; the threads that touch it are the configuration trigger (an EVFILT_USER
 * event) and, with `ingest-threads` N > 1, N builder threads that parse and publish complete zones.  There is no
 * mutex of its own: builders get their job through an atomic slot and a per-builder kqueue, hand the result back on a
 * lock-free stack and an EVFILT_USER event, and share the DB zone registry under the existing
 * g_zone_db_rebuild_lock (dns_snapshot_rcu.c).  The configuration is read inside an RCU read section
 * (rcu_aux_read_lock) and copied.  Everything from the stream is untrusted: dns_db_stream.c validates it, a protocol
 * violation closes the stream (the loader then ends and the supervisor restarts it), a zone that fails its checks is
 * rejected alone and keeps its last good version.
 *
 * Allocation happens on the load path only (start, stream buffers, zones), never on the query path.
 */
#include "dns_db_ingest.h"
#include "dns_alias.h"
#include "dns_utils.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_log.h"
#include <time.h>
#include <unistd.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "dns_catalog_zone.h"
#include "dns_config_parser.h"
#include "dns_db_install.h"
#include "dns_db_recon.h"
#include "dns_db_store.h"
#include "dns_xfr_store.h"
#include "dns_db_stream.h"
#include "dns_epoch_rcu.h"
#include "dns_mem_advice.h"
#include "dns_park.h"
#include "dns_server_internal.h"
#include "dns_snapshot_rcu.h"
#include "dns_store_status.h"

_Static_assert(KARIDNS_DB_MAX_VIEWS == KDB_MAX_CONFIG_VIEWS, "the configuration check and the CONFIG message must agree");
_Static_assert(KARIDNS_DB_CONFIG_BODY_MAX == KDB_MAX_BODY, "the configuration check and the CONFIG message must agree on the body limit");
_Static_assert(ZDIR_APEX_NS_MAX == KDB_APEX_NS_MAX, "the apex block and the ZONE_BEGIN apex agree on the number of NS names");
_Static_assert(ZDIR_APEX_GLUE_PER_NS == KDB_APEX_GLUE_PER_NS && ZDIR_APEX_GLUE_MAX <= KDB_APEX_GLUE_BYTES, "... and on the glue");
_Static_assert(ZDIR_APEX_GLUE_PER_NS == KDB_NOTIFY_ADDR_PER_NS && ZDIR_APEX_NADDR_MAX == KDB_NOTIFY_ADDR_BYTES, "... and on the NOTIFY addresses");

#define ING_MAX_OUT (32u << 20)  /* queued answers the loader has not read: above this the loader is dropped */
#define ING_ZONES_LOGGED 16       /* zones logged one by one per connection */
#define ING_REJECTS_LOGGED 100    /* rejected zones logged one by one per batch */
#define ING_VIEW_HIST 8           /* view tables of earlier CONFIGs kept for a batch the loader began with one of them */
#define ING_READ_ROUNDS 16
#define ING_EVT_CONFIG 1          /* EVFILT_USER idents of the main kqueue */
#define ING_EVT_RESULT 2
#define ING_EVT_REQ 3             /* karictl reload requests from the control thread (SPSC ring g_rq) */
#define ING_EVT_DEBUG 7           /* 0.7 M2: the debug level changed (control thread): DEBUG to the loader */
#define ING_EVT_RECON 8           /* 0.7 M2: the reconcile thread (dns_db_recon.c) freed a slot of its ring, went idle, has counts or found a protocol error */
#define ING_REQ_MAX 32            /* reload requests waiting for the loader's answer (the control thread parks as many clients) */
#define RQ_RING 64                /* both rings: more than ING_REQ_MAX, so a ring never fills while the bound holds */
#define ING_RETIRE_EVERY 1024     /* design 4.3: a blocking grace period every this many published zones */
#define ING_DELTA_MS 1000         /* design 4.4: new zones become visible at least this often */
#define ING_DELTA_LIMITED_MS 100  /* with memory-limit: zones taken out of memory are given back once the snapshot that could show them is retired, so the delta is published sooner */
#define ING_INV_CHUNK 400         /* INVENTORY entries per message */
#define ING_INV_QUEUE_LOW (256u << 10)
#define ING_MAX_BUILDERS 16
#define ING_RBUF 65536
#define ING_FLUSH_AT 16384        /* queued bytes that are written at once; the rest goes out after the event round */
#ifndef ING_FETCH_MAX
#define ING_FETCH_MAX 1280         /* fetches in flight (D1a): more is refused, the queries then wait for their own deadline.  0.7 first-fill latency: the fill's ING_FILL_NFREQ_MAX (1024) and fetch-concurrency (at most 256) both fit */
#endif
#define ING_WQ_MAX 8192           /* 0.7 P-B: requests of queries that wait for a place, a token or room ("the wait queue"); the park tables bound the queries behind them, and a request is made once per zone */
#define ING_LQ_MAX 16384          /* 0.7: lookups that wait for a place ("the lookup queue"); a request that finds it full is dropped and counted (true overload: the queries behind it time out) */
#define ING_WQ_TICK_MS 10         /* ... and how often the thread looks again while some wait: the bucket, a new attempt to make room, their deadlines */
#define ING_WARM_NFREQ 8          /* fetches in flight below which the zones nobody asked for yet (pins) are read */
#define ING_SUMMARY_NFREQ 8       /* summary fetches (the apex of a zone out of memory, after a reload) in flight: they bring no zone data, so memory-limit does not hold them back, this does */
/* ING_FETCH_LIMITED (16 in flight, fixed) held the reads of the whole server to what one fetch thread of the loader did (about 500 a second) and shed the rest, whatever
 * fetch-rate said.  The limit is database { fetch-concurrency } now (default loader-threads x 16): the loader reads that many zones in parallel; a request over it waits. */
/* a fetch the loader has not answered by then is given up (the queries have timed out long before); a variable for the unit test */
#define STATIC_TEST
STATIC_TEST int64_t g_ing_fetch_timeout_ms = 30000;
/* review 2026-11-23 D-L4: a zone begun on a stream (ZONE_BEGIN) that gets no more data for this long is given up and the stream closed (zone_stalled()); a variable for the unit test */
STATIC_TEST _Atomic int64_t g_ing_zone_stall_ms = 120000;      /* (atomic: the test changes it while the thread runs) */
#define ING_FETCH_OUT_MAX (1u << 20)

typedef struct {
  uint64_t generation;
  char driver[40];
  uint32_t nviews;
  uint64_t max_zone_records, max_zone_bytes;
  uint64_t memory_limit;
  bool limit_default;          /* memory_limit is the default from the RAM (0.7.x: memory-limit not written) */
  uint32_t fetch_rate;
  uint32_t park_timeout_ms;    /* park-timeout: how long a request waits for room */
  uint32_t fetch_concurrency, loader_threads;
  uint32_t xfr_timeout_ms;
  uint32_t ingest_threads;
  bool auto_reload;
  uint32_t poll_interval, coalesce_ms;
  bool state_file;             /* D1a step 7: loader-state-file is set (the hot list is kept) */
  uint32_t hot_size, hot_interval, warm_wait;   /* hot-list-size, hot-list-interval (s), warm-before-serve (s) */
  bool enabled;
} ing_cfg_t;

/* one zone on its way from ZONE_BEGIN to ZONE_RESULT */
typedef struct ing_job {
  struct ing_job *next;                  /* result stack */
  uint16_t view;
  char view_name[KARIDNS_VIEW_NAME_MAX];
  char zone[DNS_NAME_TEXT_SIZE];
  int64_t source_id;
  uint32_t serial;
  uint64_t rr_count;
  uint8_t digest[KDB_DIGEST_LEN];
  uint8_t *img;                          /* 0.7 M3: the zone image, reassembled from the ZONE_IMAGE messages (malloc, grows with the octets that came: the announced size is only a cap) */
  size_t img_len, img_cap;
  uint64_t img_size;                     /* ZONE_BEGIN image_size */
  uint32_t zflags;                       /* ZONE_BEGIN flags (KDB_ZF_*) */
  uint64_t lim_bytes, lim_records;       /* max-zone-bytes and max-zone-records of the stream this zone came on (CONFIG) */
  bool skip;                             /* decided at ZONE_BEGIN: the data is discarded, the zone is rejected */
  bool failed;                           /* a ZONE_IMAGE message could not be kept (out of memory) */
  uint8_t zkind;                          /* B7b: KDB_ZK_*; secondary (SLAVE) and catalog (CONSUMER) zones have no data: the masters are in the settings */
  zone_ext_shared_t *shared;             /* B7a: the interned settings of the zone (this job holds a reference), NULL = none */
  uint8_t status;                        /* KDB_ST_* */
  int builder;                           /* index of the builder it was handed to */
  bool fill;                             /* 0.7 fix 8: the body of a background fetch of the reconcile (the first fill): the thread's time for it is counted apart (g_ing_fill_pct) */
  char reason[KDB_REASON_LEN];
  /* D1a, the fetch stream: the request the zone answers (0 = a zone of a batch), a summary (no data: what the directory keeps), a zone
   * nobody asked for (discarded; the loader may answer a request that was given up) */
  uint64_t fetch_id;
  bool summary, unsolicited, has_timers;
  bool dir_entry;                        /* D1a milestone 4: the zone came as a summary in a batch (cold, no data was sent); timers are applied after the commit */
  uint8_t batch_kind;                    /* 0.7 store S2: KDB_BATCH_* of the batch the zone came in (KDB_BATCH_STARTUP for a fetch) */
  bool cold;                             /* D1a step 5: a zone of a batch that is not kept in memory (the limit is reached): serial, digest and settings go into the directory, the data is discarded */
  uint32_t t_refresh, t_retry, t_expire;
  zdir_apex_t *apex;                     /* D1a step 6: the apex of a summary that is kept (see apex_from_begin()); the job owns it until dbreg_set_apex() takes it */
  bool no_apex;                          /* ... the summary came without apex tags: the loader cannot give one for this version */
  bool lk_skip;                          /* 0.7: the body of a lookup that is not wanted (LKS_SKIP): thrown away, and the request ends with it */
  bool iv_valid;                         /* a fetch of the whole zone: the version the directory had when the request was made (the zone is not installed if it has another by now) */
  int64_t iv_sid;
  uint32_t iv_serial;
  bool iv_st_valid;                      /* 0.7 WP7b: the stamp of the store's record when the request was made: a body for another stamp (the database changed again, or the zone is gone) is dropped */
  uint64_t iv_st_gen, iv_st_time;
} ing_job_t;

/* a fetch in flight: sent to the loader on the fetch stream, not answered yet */
/* the stage of a lookup (ing_freq_t.lkst): the answer is not here yet; the zone was found and its body is on its way (the request is a fetch of the zone now); the zone was found, its body is not wanted (the zone is
 * in memory or being fetched by another request already): it is read through and thrown away */
enum { LKS_ASK = 0, LKS_BODY, LKS_SKIP };

typedef struct {
  bool active;
  uint64_t id;
  uint16_t view;                         /* the index in the CONFIG of the loader */
  uint8_t prio, mode;
  bool v_valid;                          /* a request for the whole zone: the version the directory had when it was made (see ing_job_t.iv_valid) */
  int64_t v_sid;
  uint32_t v_serial;
  bool want_summary;                     /* a summary for the zone was not asked for because this request was on its way: if it fails or is dropped, the zone goes back to the list */
  bool dropped;                          /* the zone it brought was dropped (an older version than the directory's) */
  bool quiet;                            /* asked for by the list of zones to read (the apex after a reload), not by a query: nobody waits for it, so it wakes nobody */
  bool placed;                           /* B2 W5: it holds a place of the pool of fetch-concurrency (park_place_take()), given back when the fetch is over */
  bool hot;                              /* a zone of the hot list (D1a step 7): counted in the warm-up progress */
  uint32_t hrank;                        /* of the hot list: how many zones of the list were asked for before this one (the list is read in its order) */
  int64_t sid;                           /* 0.7 WP7b: the domain id the request names (FETCH_REQ tag 8; 0 = none) */
  bool st_valid;                         /* ... the stamp of the store's record when the request was made (see ing_job_t.iv_st_valid) */
  uint64_t st_gen, st_time;
  bool bulk;                             /* asked for by the background fetch of the wanted bodies (the scan of the store), not by a query */
  bool nonstore;                         /* ... a secondary or catalog zone (it has a record that only remembers it) */
  bool loader_failed;                    /* the loader answered ZONE_FAILED (not "busy"): the zone is marked refused until its stamp changes */
  bool busy;                             /* the loader answered "busy" (KDB_FETCH_BUSY_REASON): overload, not a failure of the zone: the queries that wait are dropped, not answered SERVFAIL (0.7) */
  bool reqfetch;                         /* the fetch of the zone a `karictl reload <zone>` asks for: the answer of the request waits for it */
  /* 0.7, a lookup of a name (FETCH_REQ mode KDB_FETCH_LOOKUP, or LOOKUP_FULL: the body of the zone that is found follows the answer, with the same request id).  `zone` is the name asked for until the answer; a request whose answer has a zone
   * that comes with its body (lkst LKS_BODY) is a fetch of that zone from then on (mode FULL, `zone` the zone), and lk_q is the name the queries wait for (they are woken by it too) */
  uint8_t lk;                            /* the request was made for a lookup: it counts in the lookups in flight (g->nlook) until it is over, and holds the claim mark of the name (ckey) */
  uint8_t lkst;                          /* LKS_*: where the lookup stands */
  bool body_seen;                        /* (lk only) the body of the zone has come: no second one is read for this request */
  uint64_t ckey;                         /* park_claim_key() of (view, lk_q) */
  int64_t lk_t0;                         /* CLOCK_MONOTONIC in ns when the lookup was sent (the time to the answer) */
  int64_t lk_sid;                        /* the source id the answer named: the body must be that zone */
  char lk_q[DNS_NAME_TEXT_SIZE];
  uint32_t bzid;
  int64_t sent_ms;
  uint32_t zh;                           /* dns_name_hash_ci(zone), kept with every write of `zone`: fetch_find_zone() compares it before the names (256 bodies of the fill in flight, looked through for every request) */
  char view_name[KARIDNS_VIEW_NAME_MAX];
  char zone[DNS_NAME_TEXT_SIZE];
} ing_freq_t;

typedef struct {
  pthread_t tid;
  int kq;
  _Atomic(ing_job_t *) slot;
} ing_builder_t;

/* B7a: the PROFILE messages of the batch (design 1.4): a zone names its profile in ZONE_BEGIN, the profile's text comes
 * before it.  A later PROFILE of the same name replaces the earlier one (two views may read different databases).  The
 * table is the stream thread's; a zone resolves its settings at ZONE_BEGIN, so builders never see it. */
#define ING_MAX_PROFILES 4096
#define ING_PROFILE_BYTES (16u << 20)  /* a hostile loader cannot make the Backend hold more than this */
typedef struct {
  char name[256];
  char *text;
  size_t len;
} ing_profile_t;

typedef struct {
  int kq, wait_kq, ctrl_fd, stream_fd;
  bool write_armed;
  uint8_t *body;               /* KDB_MAX_BODY */
  uint8_t *rbuf;               /* ING_RBUF */
  kdb_framer_t fr;
  kdb_sm_t sm;
  kdb_enc_t enc;
  uint8_t *out;                /* answers queued for the loader */
  size_t out_len, out_off, out_cap;
  bool hello_done, need_cleanup;
  int debug_sent;              /* 0.7 M2: the level the loader was last told (DEBUG), -1 = none on this stream */
  /* view index -> name, as of the CONFIG last sent */
  char (*view_names)[KARIDNS_VIEW_NAME_MAX];
  uint8_t *view_db;            /* [index]: the view takes zones from the database (not "database none;") */
  uint32_t nview_names;
  /* the zone being received */
  ing_job_t *cur;
  uint32_t zones_logged;
  uint32_t rejects_logged;
  uint32_t shadows_logged;     /* hidden zones logged one by one in this batch (ING_REJECTS_LOGGED, like the rejected ones) */
  ing_profile_t *profiles;     /* of the current batch */
  size_t nprof, cprof, prof_bytes;
  /* batch */
  bool in_batch;
  /* review db_ingest [1]: CONFIG renumbers the views, and the loader adopts a CONFIG only between two batches, so a batch
   * that started before it had read the newest one carries the numbers of an older one.  BATCH_BEGIN says which (tag 5);
   * the batch reads its view numbers in a copy of that CONFIG's table: the current one or one of the last ING_VIEW_HIST. */
  uint64_t view_gen;           /* the CONFIG generation view_names was built for */
  struct { uint64_t gen; uint32_t n; char (*names)[KARIDNS_VIEW_NAME_MAX]; } vhist[ING_VIEW_HIST];
  char (*b_names)[KARIDNS_VIEW_NAME_MAX];   /* the table of the batch in progress (a copy) */
  uint32_t b_n;
  uint64_t batch_id;
  uint8_t batch_kind;
  uint32_t b_applied, b_rejected, b_shadowed, b_deleted, b_failed;
  /* builders and work in flight */
  uint32_t nbuilders;          /* 0 = the stream thread builds */
  ing_builder_t builders[ING_MAX_BUILDERS];
  ing_job_t *flight[ING_MAX_BUILDERS];  /* the job each builder works on, until its result was taken (stream thread only) */
  _Atomic(ing_job_t *) res_head;
  uint32_t inflight;
  uint32_t since_retire;
  int64_t last_delta_ms;
  bool delta_wake;             /* 0.7 M3: a fetch completed that left a change for the index: it is published once, before the workers that wait for the zone are triggered (wake_flush()), not once per zone */
  /* INVENTORY in progress */
  bool inv_active;
  dbreg_cursor_t inv_cur;
  uint64_t inv_sent;
  uint32_t inv_zid;                    /* 0.7 S3: the zones of the store are listed by zone id after the registry (inv_store_pass()) */
  bool inv_store;                      /* ... and the registry's part is done */
  /* reload requests sent to the loader whose answer the control thread is waiting for (B6a, design 5.2) */
  struct {
    bool active;
    uint64_t id;
    uint16_t view;
    char view_name[KARIDNS_VIEW_NAME_MAX];
    char zone[DNS_NAME_TEXT_SIZE];
    int grp;                   /* >= 0: one view of a request that asks every view (grps[grp]) */
    bool force;                /* 0.7 WP7b: `reload -force`: its pass is not held back by the mass-delete guard */
  } reqs[ING_REQ_MAX];
  /* B6b: `reload <zone>` without a view while several views take database zones: one RELOAD_REQ per view (ids with the
   * top bit set, so they cannot clash with the control thread's), one combined answer for the control thread */
  struct {
    bool active;
    uint64_t ctl_id;
    int pending;
    bool any_ok, any_bad;
    char zone[DNS_NAME_TEXT_SIZE];
    char text[200];
  } grps[ING_REQ_MAX];
  uint64_t sub_seq;
  /* 0.7 WP7b, the store protocol: negotiated by HELLO features and CONFIG store_proto.  The loader lists the zones (MANIFEST) or the changes (CHANGES); the bodies are fetched
   * (the scan of the store below, or a query) */
  uint32_t loader_feat;        /* HELLO features of this loader */
  int b_store_err;             /* 0.7: the errno for which the store could not record the batch (BATCH_RESULT tag 7); 0 = recorded */
  bool store_proto;
  bool sig_carry;              /* 0.7 signer-wait (d): the holds of before this loader's HELLO are kept until a batch of it says which zones wait (BATCH_END KDB_BEF_SIGNER_SET) */
  /* 0.7 M2: the pages of a MANIFEST pass go to the reconcile thread (dns_db_recon.h).  A frame of the first stream that has to wait for it (a free slot of its ring, or everything before it applied) is kept here and the
   * stream is not read meanwhile (the read event of its descriptor is off): the pointers of the frame are into rbuf / body, which nothing touches while it waits */
  bool held_valid, hold_room, read_off;
  kdb_frame_t held_fr;
  bool bg_on, bg_again;        /* the background fetch of the wanted bodies is going / must go through the store once more when it ends */
  uint32_t bg_zid;             /* ... the zone id it has reached */
  uint32_t bg_fail;            /* ... the bodies of this round that could not be brought */
  int64_t bg_retry_ms;         /* ... no new round before this time (a round with failures is made again) */
  bool bg_idle_logged;
  bool batch_force;              /* the batch answers a `karictl reload -force`: its pass is not held back by the mass-delete guard */
  uint64_t all_force_id;       /* the request id of the last `reload -force` of everything */
  bool ch_failed;                /* an entry of this pass / drain could not be recorded: its cursor is not kept */
  uint32_t nbulk;                /* fetches of the wanted bodies in flight */
  bool qonly;                    /* 0.7 first-fill latency: fetch_issue() makes the requests of queries only (no fill, no warm-up): the ingest thread waits for the store's journal (ing_journal_wait()) */
  /* 0.7 first-fill latency (W3): the window of dd_tick(): the queries that were dropped because their data could not be read are counted, and said in one line a window, not one a query */
  int64_t dd_start;              /* when the window began (CLOCK_MONOTONIC ms; 0: not begun) */
  uint64_t dd_c0[3];             /* store.park.drop.failed, store.lookup.drop.failed, store.park.drop.timeout at its beginning */
  uint32_t dd_fail, dd_ok;       /* reads that failed / ended well in the window */
  bool dd_nolink;                /* the loader was not connected at some time in the window */
  bool dd_warned;                /* the WARNING of one failed fetch was written in the window */
  bool dd_reported;              /* the last line said the queries were dropped (the NOTICE of a window whose last read ended well says that is over) */
  bool dd_last_ok;               /* the last read (since the start) ended well */
  uint32_t fs_done;              /* 0.7 first-fill latency: bodies of the fill that came in the window of dd_tick() (a window without one while the fill has work: a stall) */
  bool fs_reported;              /* the last window said the fill stalled (the next one with progress says it goes on) */
  char dd_why[KDB_REASON_LEN];   /* the reason of the last failed read */
  bool rf_has;                   /* what the job of the request fetch became (fetch_job_finish() to fetch_complete()) */
  uint64_t rf_id;
  uint8_t rf_status;
  uint32_t rf_serial;
  char rf_reason[KDB_REASON_LEN];
  bool req_wait;               /* the zone of the request the batch answers is being fetched: the batch is not answered before it is here */
  uint64_t req_fetch_id;
  bool defer_end;              /* BATCH_END has come and the answer is held for it */
  uint64_t defer_batch;
  int64_t defer_ms;
  uint32_t b_unchanged;        /* manifest entries and changes that needed nothing */
  int cur_req;                 /* the request the current batch answers (BATCH_BEGIN request_id), -1 = none */
  int req_outcome;             /* what the batch did to the requested zone: ROUT_* */
  uint32_t req_serial;
  char req_reason[KDB_REASON_LEN];
  /* D1a: the fetch stream, the second KDB1 stream (design 6.1).  Its own framer, state machine and output queue; the zones that come on it go
   * through the same jobs as the batch zones (job_execute()), with their own profile table (prof_swap()) and no ZONE_RESULT. */
  int fetch_fd;
  bool fwrite_armed;
  uint8_t *fbody;              /* KDB_MAX_BODY */
  uint8_t *frbuf;              /* ING_RBUF: the fetch stream reads into its own buffer.  A framer keeps a pointer into the bytes it was fed (kdb_framer_feed() does not copy), and a pass that
                                * yields (fresume / sresume) leaves frames there: with one buffer for both streams the read of the other stream overwrote them ("bad magic") */
  kdb_framer_t ffr;
  kdb_sm_t fsm;
  kdb_enc_t fenc;
  uint8_t *fout;               /* FETCH_REQ messages not written yet */
  size_t fout_len, fout_off, fout_cap;
  ing_job_t *fcur;             /* the zone being received on the fetch stream */
  int64_t s_rx_ms, f_rx_ms;    /* review 2026-11-23 D-L4: when the batch / fetch stream last had data (zone_stalled()) */
  ing_profile_t *fprofiles;
  size_t fnprof, fcprof, fprof_bytes;
  uint64_t fseq;               /* request ids */
  uint32_t nfreq;
  uint32_t nsum;                         /* ... of which summary fetches (D1a step 6) */
  bool delta_failed;                     /* the last publication failed (out of memory): the delta interval paces the next try, whatever the garbage says */
  ing_freq_t freq[ING_FETCH_MAX];
  struct ing_warm { char view[PARK_VIEW_MAX + 1]; char zone[PARK_ZONE_MAX + 1]; bool hot; } *warm;     /* D1a milestone 4: zones to read before a query asks (pins) */
  size_t nwarm, cwarm;
  uint32_t hot_issued;                     /* the zones of the hot list asked for so far (their rank, see fetch_complete()) */
  uint32_t nhot, nhot_flight;           /* D1a step 7: of the list, the zones of the hot list; of the fetches in flight, the ones for the hot list */
  uint64_t warm_l0;                       /* g_wl_loaded when the hot list came (the counter is cumulative over loader sessions; the estimate divides by the zones read since) */
  uint64_t warm_r0;                       /* the bytes of the database zones in memory when the hot list came: what the zones of the list added is estimated from it (warm_hot_gate) */
  bool wl_open;                          /* the parts of a WARM_LIST are coming in: the list id and the next part */
  uint64_t wl_id, hot_seq;
  uint32_t wl_next, wl_count;
  bool hold;                             /* warm-before-serve: the workers wait; the thread logs how it ended */
  int64_t hold_start_ms;
  bool apex_walk;                        /* D1a step 6: after a reload, the zones out of memory that now keep an apex but have none are asked for (their summary) ... */
  dbreg_cursor_t apex_cur;               /* ... a few at a time, from here */
  uint32_t funsolicited;       /* zones nobody asked for, discarded (logged the first few) */
  int64_t fill_ns;             /* 0.7 fix 8: the time of the window that the bodies of the fill took (g_ing_fill_pct) */
  bool sresume, fresume;       /* 0.7 fix 8 (priorities): on_stream_readable() / on_fetch_readable() stopped in the middle of what the framer holds because requests of queries were waiting; they go on first when the loop comes back */
  bool fmore;                  /* B2 W5: the last fetch_issue() pass stopped at its bound (requests or time) with work left: the loop serves the streams and comes back */
  /* 0.7 P-B, the wait queue: the requests of queries (a worker's, or a transfer's) that cannot be made now because every place of fetch-concurrency is taken, the fetch-rate
   * bucket is empty, or the database zones are above the hard line of memory-limit and there is no room yet.  Oldest first (a ring: wq_head, nwq); a request that comes while
   * others wait goes behind them.  An entry holds the claim mark of its zone (no place, no token: those are taken when the request is made), and has a deadline, park-timeout from
   * when the thread took it: the queries that waited for it have timed out by then.  The queue is bounded by ING_WQ_MAX (a request that finds it full is refused: true overload). */
  struct ing_wq { park_fetch_req_t q; uint64_t key; int64_t deadline_ms; bool room; } *wq;     /* (ING_WQ_MAX entries, allocated at the start: pages nobody touched cost no memory) */
  uint32_t wq_head, nwq;
  uint32_t nwq_room;                     /* ... of them, the entries that have been held up by room (the zones in memory above the hard line) */
  int64_t room_next_ms;                  /* no attempt to make room before this time (the last one did not make it) */
  /* 0.7, the lookups of the first start: a request of a worker for the zone that encloses a name (a lookup) takes a place of fetch-concurrency like the fetch of a query and waits here until it has one (oldest first;
   * its deadline is park-timeout from when the thread took it).  A lookup that is out (in flight, or its body on its way) counts in nlook, which is bounded to a share of the places so that a flood of names that no zone has leaves
   * the rest to the fetches of zones.  lq_turn: the queue and the wait queue take turns when both could make a request. */
  struct ing_lq { park_fetch_req_t q; uint64_t key; int64_t deadline_ms; } *lq;     /* (ING_LQ_MAX entries, allocated at the start) */
  uint32_t lq_head, nlq, nlook;
  bool lq_turn;
} ing_t;

enum { ROUT_NONE = 0, ROUT_APPLIED, ROUT_SHADOWED, ROUT_REJECTED, ROUT_FAILED, ROUT_DELETED };
static void answer_request(ing_t *g);
static void fetch_adopt(ing_t *g, int fd);
static void fetch_drop(ing_t *g);
static void fetch_fail_all(ing_t *g, const char *why);

static ing_t g_ing;
static _Atomic bool g_cfg_dirty;
static _Atomic int g_ing_kq = -1;
static _Atomic uint64_t g_last_change_seq;   /* what the last BATCH_BEGIN said (design 1.4, INVENTORY_END) */

/* ------------------------------------------------------------------------------------------------------------- */
/* karictl reload: control thread <-> ingest thread, two single-producer single-consumer rings (no mutex)         */
/* ------------------------------------------------------------------------------------------------------------- */

enum { RQ_ALL = 1, RQ_ZONE, RQ_CANCEL };
typedef struct {
  uint8_t type;
  bool force;
  uint64_t id;
  char view[KARIDNS_VIEW_NAME_MAX];
  char zone[DNS_NAME_TEXT_SIZE];
} rq_item_t;

static rq_item_t g_rq[RQ_RING];              /* producer: the control thread; consumer: the ingest thread */
static _Atomic uint32_t g_rq_head, g_rq_tail;
static db_reload_result_t g_rs[RQ_RING];     /* producer: the ingest thread; consumer: the control thread */
static _Atomic uint32_t g_rs_head, g_rs_tail;
static uint64_t g_next_req_id;               /* control thread only */

/* ingest thread: queue an answer for the control thread and wake it */
static void post_result(uint64_t id, bool ok, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void post_result(uint64_t id, bool ok, const char *fmt, ...) {
  uint32_t t = atomic_load_explicit(&g_rs_tail, memory_order_relaxed);
  uint32_t h = atomic_load_explicit(&g_rs_head, memory_order_acquire);
  if (t - h >= RQ_RING) {
    syslog(LOG_ERR, "[DB] the answer queue for the control thread is full; the answer to request %llu is dropped",
           (unsigned long long)id);
    return;
  }
  db_reload_result_t *r = &g_rs[t % RQ_RING];
  r->id = id;
  r->ok = ok;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(r->text, sizeof(r->text), fmt, ap);
  va_end(ap);
  atomic_store_explicit(&g_rs_tail, t + 1, memory_order_release);
  int ckq = atomic_load_explicit(&g_control_kq, memory_order_acquire);
  if (ckq >= 0) {
    struct kevent ev;
    EV_SET(&ev, DB_INGEST_CTL_EVENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    (void)kevent(ckq, &ev, 1, NULL, 0, NULL);
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* status for `karictl dbstatus`: written by the stream thread, read by the control thread                        */
/* ------------------------------------------------------------------------------------------------------------- */

#define ST_STR 200
static struct {
  _Atomic bool connected, ever_connected, batch_done;
  _Atomic uint32_t pid, b_applied, b_rejected, b_shadowed, b_deleted;
  _Atomic int64_t since;                                    /* connected since / disconnected since */
  _Atomic uint64_t tot_applied, tot_rejected, tot_shadowed, tot_deleted, tot_failed;
  _Atomic uint64_t tot_auto_batches;                        /* B9: batches of kind auto since the start */
  _Atomic uint64_t batch_id;
  _Atomic int batch_kind;
  _Atomic int64_t batch_time;
  _Atomic uint32_t seq;                                     /* seqlock of the strings (one writer) */
  _Atomic char err[ST_STR], ver[ST_STR];
  _Atomic int64_t err_time;
} g_st;

static void st_str_set(_Atomic char *dst, const char *src, size_t n) {
  size_t i = 0;
  for (; src && i + 1 < n && src[i]; i++) atomic_store_explicit(&dst[i], src[i], memory_order_relaxed);
  atomic_store_explicit(&dst[i], '\0', memory_order_relaxed);
}

static void st_str_get(const _Atomic char *src, char *dst, size_t n) {
  size_t i = 0;
  for (; i + 1 < n; i++) {
    char c = atomic_load_explicit(&src[i], memory_order_relaxed);
    dst[i] = c;
    if (!c) return;
  }
  dst[i] = '\0';
}

static void st_set_strings(const char *err, const char *ver) {
  uint32_t s = atomic_load_explicit(&g_st.seq, memory_order_relaxed);
  atomic_store_explicit(&g_st.seq, s + 1, memory_order_release);
  atomic_thread_fence(memory_order_seq_cst);
  if (err) {
    st_str_set(g_st.err, err, ST_STR);
    atomic_store_explicit(&g_st.err_time, (int64_t)time(NULL), memory_order_relaxed);
  }
  if (ver) st_str_set(g_st.ver, ver, ST_STR);
  atomic_store_explicit(&g_st.seq, s + 2, memory_order_release);
}

static void st_get_strings(char *err, size_t en, char *ver, size_t vn, int64_t *err_time) {
  if (en) err[0] = '\0';      /* (all 1000 tries can see a write in progress: the caller gets empty strings, not stack bytes) */
  if (vn) ver[0] = '\0';
  *err_time = 0;
  for (int tries = 0; tries < 1000; tries++) {
    uint32_t s1 = atomic_load_explicit(&g_st.seq, memory_order_acquire);
    if (s1 & 1) continue;
    st_str_get(g_st.err, err, en);
    st_str_get(g_st.ver, ver, vn);
    *err_time = atomic_load_explicit(&g_st.err_time, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    if (atomic_load_explicit(&g_st.seq, memory_order_acquire) == s1) return;
  }
}

/* B9: what the loader reports about auto reload (AUTO_STATUS), per view index; written by the stream thread (one writer, a
 * seqlock per entry), read by the control thread for `karictl dbstatus`.  B11: the same entry carries the multi-server reload
 * request state of the view's source (the server id, the last request applied and whether it loaded every zone, the last error
 * of reading requests or writing the status row); as_data_t is the plain copy the two sides exchange. */
#define AS_ERR 120
#define AS_SID 68
typedef struct {
  int64_t last_poll;
  uint64_t applied_seq;
  uint32_t pending;
  char err[AS_ERR];
  unsigned flags;                    /* KDB_AS_AUTO: last_poll .. err are real; KDB_AS_REQ: the rest is real */
  char server_id[AS_SID];
  uint64_t req_generation;
  bool req_ok;
  char req_err[AS_ERR];
  int64_t req_time;
  uint32_t sig_wait;                 /* item C: zones that wait for the signer, and the first few names */
  char sig_names[AS_ERR];
} as_data_t;

static struct as_ent {
  _Atomic uint32_t seq;
  _Atomic bool valid;
  _Atomic int64_t last_poll;
  _Atomic uint64_t applied_seq;
  _Atomic uint32_t pending;
  _Atomic char err[AS_ERR];
  _Atomic unsigned flags;
  _Atomic char server_id[AS_SID];
  _Atomic uint64_t req_generation;
  _Atomic bool req_ok;
  _Atomic char req_err[AS_ERR];
  _Atomic int64_t req_time;
  _Atomic uint32_t sig_wait;
  _Atomic char sig_names[AS_ERR];
} g_as[KARIDNS_DB_MAX_VIEWS];

/* printable ASCII only, whatever the loader sent */
static void as_put_str(_Atomic char *dst, size_t cap, const char *src, size_t n) {
  size_t i = 0;
  for (; src && i < n && i + 1 < cap; i++)
    atomic_store_explicit(&dst[i], (src[i] >= 0x20 && src[i] <= 0x7E) ? src[i] : '?', memory_order_relaxed);
  atomic_store_explicit(&dst[i], '\0', memory_order_relaxed);
}

static void as_set(struct as_ent *a, const as_data_t *d, const char *err, size_t errn, const char *sid, size_t sidn, const char *rerr, size_t rerrn,
                   const char *snames, size_t snamesn) {
  uint32_t s = atomic_load_explicit(&a->seq, memory_order_relaxed);
  atomic_store_explicit(&a->seq, s + 1, memory_order_release);
  atomic_thread_fence(memory_order_seq_cst);
  atomic_store_explicit(&a->last_poll, d->last_poll, memory_order_relaxed);
  atomic_store_explicit(&a->applied_seq, d->applied_seq, memory_order_relaxed);
  atomic_store_explicit(&a->pending, d->pending, memory_order_relaxed);
  as_put_str(a->err, AS_ERR, err, errn);
  atomic_store_explicit(&a->flags, d->flags, memory_order_relaxed);
  as_put_str(a->server_id, AS_SID, sid, sidn);
  atomic_store_explicit(&a->req_generation, d->req_generation, memory_order_relaxed);
  atomic_store_explicit(&a->req_ok, d->req_ok, memory_order_relaxed);
  as_put_str(a->req_err, AS_ERR, rerr, rerrn);
  atomic_store_explicit(&a->req_time, d->req_time, memory_order_relaxed);
  atomic_store_explicit(&a->sig_wait, d->sig_wait, memory_order_relaxed);
  as_put_str(a->sig_names, AS_ERR, snames, snamesn);
  atomic_store_explicit(&a->valid, true, memory_order_relaxed);
  atomic_store_explicit(&a->seq, s + 2, memory_order_release);
}

static bool as_get(struct as_ent *a, as_data_t *d) {
  for (int tries = 0; tries < 1000; tries++) {
    uint32_t s1 = atomic_load_explicit(&a->seq, memory_order_acquire);
    if (s1 & 1) continue;
    bool valid = atomic_load_explicit(&a->valid, memory_order_relaxed);
    d->last_poll = atomic_load_explicit(&a->last_poll, memory_order_relaxed);
    d->applied_seq = atomic_load_explicit(&a->applied_seq, memory_order_relaxed);
    d->pending = atomic_load_explicit(&a->pending, memory_order_relaxed);
    st_str_get(a->err, d->err, sizeof(d->err));
    d->flags = atomic_load_explicit(&a->flags, memory_order_relaxed);
    st_str_get(a->server_id, d->server_id, sizeof(d->server_id));
    d->req_generation = atomic_load_explicit(&a->req_generation, memory_order_relaxed);
    d->req_ok = atomic_load_explicit(&a->req_ok, memory_order_relaxed);
    st_str_get(a->req_err, d->req_err, sizeof(d->req_err));
    d->req_time = atomic_load_explicit(&a->req_time, memory_order_relaxed);
    d->sig_wait = atomic_load_explicit(&a->sig_wait, memory_order_relaxed);
    st_str_get(a->sig_names, d->sig_names, sizeof(d->sig_names));
    atomic_thread_fence(memory_order_seq_cst);
    if (atomic_load_explicit(&a->seq, memory_order_acquire) == s1) return valid;
  }
  return false;
}

static void as_reset(void) {                                /* a new loader: what the old one said is stale */
  for (size_t i = 0; i < KARIDNS_DB_MAX_VIEWS; i++) atomic_store_explicit(&g_as[i].valid, false, memory_order_relaxed);
}

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* rights                                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

/* Design 1.3: the stream may be read, written and watched, nothing else (no fcntl, no shutdown, no sockopt). */
static bool limit_stream_rights(int fd) {
  cap_rights_t r;
  cap_rights_init(&r, CAP_READ, CAP_WRITE, CAP_EVENT);
  if (cap_rights_limit(fd, &r) != 0 && errno != ENOSYS) {
    syslog(LOG_ERR, "[DB] cannot limit the rights of the loader stream: %s; the stream is not used", strerror(errno));
    return false;                 /* (a descriptor with all the rights of the sender's end is not kept) */
  }
  return true;
}

static bool limit_ctrl_rights(int fd) {
  cap_rights_t r;
  cap_rights_init(&r, CAP_RECV, CAP_EVENT);
  if (cap_rights_limit(fd, &r) != 0 && errno != ENOSYS) {
    syslog(LOG_ERR, "[DB] cannot limit the rights of the loader control socket: %s", strerror(errno));
    return false;
  }
  return true;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* configuration snapshot                                                                                         */
/* ------------------------------------------------------------------------------------------------------------- */

/* 0.7.x: the RAM (hw.physmem) read before the sandbox, by db_ingest_start(); the default memory-limit is derived from it (dns_mem_advice.h) */
static uint64_t g_ram;
static _Atomic bool g_limit_default;   /* the limit in force is the default (the sizing lines and dbstatus say so) */

uint64_t db_ingest_memory_limit(const server_config_t *cfg, bool *is_default) {
  return ma_effective_limit(cfg->database.memory_limit, cfg->database.memory_limit_unlimited, db_store_enabled(), g_ram, is_default);   /* (the store that opened: the default directory is used only when its parent exists, db_store_start() runs first) */
}

static void fill_snap(const server_config_t *cfg, ing_cfg_t *c) {
  memset(c, 0, sizeof(*c));
  if (cfg && cfg->database.enabled) {
    c->enabled = true;
    c->generation = cfg->generation;
    snprintf(c->driver, sizeof(c->driver), "%s", cfg->database.driver ? cfg->database.driver : "");
    for (const view_config_t *v = cfg->views; v; v = v->next) c->nviews++;
    c->max_zone_records = cfg->database.max_zone_records;
    c->max_zone_bytes = cfg->database.max_zone_bytes;
    c->memory_limit = db_ingest_memory_limit(cfg, &c->limit_default);
    c->fetch_rate = cfg->database.fetch_rate;
    c->park_timeout_ms = cfg->database.park_timeout_ms ? cfg->database.park_timeout_ms : PARK_DEFAULT_TIMEOUT_MS;
    c->fetch_concurrency = cfg->database.fetch_concurrency;
    c->loader_threads = cfg->database.loader_threads;
    c->xfr_timeout_ms = cfg->database.transfer_fetch_timeout_ms;
    c->ingest_threads = cfg->database.ingest_threads;
    c->auto_reload = cfg->database.auto_reload;
    c->poll_interval = cfg->database.poll_interval;
    c->coalesce_ms = cfg->database.coalesce_ms;
    c->state_file = cfg->database.loader_state_file != NULL;
    c->hot_size = cfg->database.hot_list_size ? cfg->database.hot_list_size : KARIDNS_DB_HOT_LIST_DEFAULT;
    c->hot_interval = cfg->database.hot_list_interval ? cfg->database.hot_list_interval : KARIDNS_DB_HOT_INTERVAL_DEFAULT;
    c->warm_wait = cfg->database.warm_before_serve;
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

static void sane_copy(char *dst, size_t cap, const char *s, size_t n) {
  size_t i = 0;
  for (; i + 1 < cap && i < n && s[i]; i++) dst[i] = (s[i] >= 0x20 && s[i] <= 0x7E) ? s[i] : '?';
  dst[i] = '\0';
}

/* CONFIG from the active configuration (design 1.4).  A view that takes no DB zones ("database none;") is left
 * out; the others carry their own source or, if they have none, the global one (the loader needs a path for every
 * view it reads; "absent = shared source" of the design is expressed by repeating the global path).  Views are
 * numbered by their position in the configuration; the names are remembered so that ZONE_BEGIN's index can be
 * turned into a view name.  false: no database block, or too many views. */
static bool build_config(ing_t *g, ing_cfg_t *snap) {
  bool ok = false;
  rcu_aux_read_lock();
  const server_config_t *cfg = acquire_config_snapshot();
  if (cfg && cfg->database.enabled) {
    const database_config_t *db = &cfg->database;
    bool sqlite = db->driver && strcmp(db->driver, "sqlite3") == 0;
    /* 0.7 WP7b: the store protocol needs the store (it keeps the cursors and the records) and a loader that speaks it (HELLO features bit 0) */
    const bool store_proto = db_store_enabled() && (g->loader_feat & KDB_FEAT_STORE) != 0;
    g->store_proto = store_proto;
    fill_snap(cfg, snap);
    if (g->view_names) {   /* the table of the previous CONFIG goes to the history (the loader may still read with it) */
      free(g->vhist[ING_VIEW_HIST - 1].names);
      memmove(&g->vhist[1], &g->vhist[0], (ING_VIEW_HIST - 1) * sizeof(g->vhist[0]));
      g->vhist[0].gen = g->view_gen;
      g->vhist[0].n = g->nview_names;
      g->vhist[0].names = g->view_names;
    }
    g->view_gen = cfg->generation;
    free(g->view_db);
    g->view_names = snap->nviews ? calloc(snap->nviews, sizeof(*g->view_names)) : NULL;
    g->view_db = snap->nviews ? calloc(snap->nviews, 1) : NULL;
    g->nview_names = g->view_names && g->view_db ? snap->nviews : 0;
    kdb_enc_reset(&g->enc);
    kdb_enc_begin(&g->enc, KDB_T_CONFIG);
    kdb_enc_u64(&g->enc, 1, cfg->generation);
    kdb_enc_str(&g->enc, 2, db->driver);
    if (db->server_id) enc_sane_str(&g->enc, 3, db->server_id);
    uint32_t idx = 0, listed = 0;
    bool too_many = false;
    for (const view_config_t *v = cfg->views; v; v = v->next, idx++) {
      if (g->view_names && idx < g->nview_names) snprintf(g->view_names[idx], sizeof(g->view_names[idx]), "%s", v->name ? v->name : "");
      if (v->database_none) continue;
      if (listed >= KDB_MAX_CONFIG_VIEWS) {         /* (the configuration check refuses this; here a view without a source is not sent as if it had one) */
        too_many = true;
        break;
      }
      if (g->view_db && idx < g->nview_names) g->view_db[idx] = 1;
      const char *src = sqlite ? (v->database_file ? v->database_file : db->database_file)
                               : (v->database_schema ? v->database_schema : db->schema);
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
      /* B6b (design 7.1): a view on the global source gets the zones karidns_domain_views maps to it */
      if (sqlite ? !v->database_file : !v->database_schema) kdb_enc_u8(&g->enc, 10, 1);
      if (store_proto) {                                    /* 0.7 WP7b: the cursor of the change log and the identity of the database it belongs to, as the store has them */
        uint64_t cur = 0;
        uint8_t ident[KDB_IDENT_MAX];
        size_t il = 0;
        if (v->name && db_recon_cursor_get(v->name, &cur, ident, &il) && il <= KDB_IDENT_MAX) {
          kdb_enc_u64(&g->enc, 11, cur);
          kdb_enc_u8(&g->enc, 12, 1);
          if (il) kdb_enc_bytes(&g->enc, 13, ident, il);
        }
      }
      kdb_enc_nest_end(&g->enc);
    }
    kdb_enc_u32(&g->enc, 5, db->default_ttl);
    kdb_enc_u8(&g->enc, 6, (uint8_t)db->bulk_threshold);
    kdb_enc_u32(&g->enc, 7, db->loader_threads);
    if (snap->memory_limit && !dbdir()) kdb_enc_u8(&g->enc, 8, 1);       /* D1a milestone 4: the directory only for the zones that are not in memory (design 3.3); with the zone store (S3) the store is the directory and a zone is sent whole */
    kdb_enc_u8(&g->enc, 9, db->signer_wait ? 1 : 0);        /* 0.6.0 item C: a changed zone of the signer waits for the signer */
    if (store_proto) kdb_enc_u8(&g->enc, 10, 1);            /* 0.7 WP7b: the store protocol (no INVENTORY: the loader lists the zones or the changes, the Backend asks for the bodies) */
    ok = kdb_enc_end(&g->enc) == 0 && !too_many && idx <= 0xFFFF &&(snap->nviews == 0 || (g->view_names && g->view_db));
  }
  rcu_aux_read_unlock();
  return ok;
}

/* BATCH_BEGIN: the view numbers of the batch are those of the CONFIG the loader made it with (gen; 0 = not said: the
 * newest).  A copy, so that CONFIGs sent during the batch do not change it.  The state machine checks the view numbers
 * of the batch against that table. */
static void batch_table_begin(ing_t *g, uint64_t gen) {
  free(g->b_names);
  g->b_names = NULL;
  g->b_n = 0;
  char (*src)[KARIDNS_VIEW_NAME_MAX] = g->view_names;
  uint32_t n = g->nview_names;
  if (gen != 0 && gen != g->view_gen) {
    src = NULL;
    for (int i = 0; i < ING_VIEW_HIST && !src; i++)
      if (g->vhist[i].names && g->vhist[i].gen == gen) {
        src = g->vhist[i].names;
        n = g->vhist[i].n;
      }
    if (!src) {   /* older than every table kept: no view number of this batch can be trusted */
      syslog(LOG_ERR, "[DB] batch %llu was made with CONFIG generation %llu, which is no longer known; its zones are not "
                      "installed (the next reload sends them again)", (unsigned long long)g->batch_id, (unsigned long long)gen);
      n = 0;
    } else {
      syslog(LOG_INFO, "[DB] batch %llu numbers its views as CONFIG generation %llu did (the newest sent is %llu)",
             (unsigned long long)g->batch_id, (unsigned long long)gen, (unsigned long long)g->view_gen);
    }
  }
  if (src && n > 0) {
    g->b_names = malloc((size_t)n * sizeof(*g->b_names));
    if (g->b_names) {
      memcpy(g->b_names, src, (size_t)n * sizeof(*g->b_names));
      g->b_n = n;
    } else {
      syslog(LOG_ERR, "[DB] out of memory for the view table of batch %llu; its zones are not installed",
             (unsigned long long)g->batch_id);
    }
  }
  /* a batch whose table is not known: its zones are rejected one by one ("the view is not in the configuration"), the
   * stream stays */
  g->sm.lim.view_count = g->b_n ? g->b_n : g->nview_names;
}

static void batch_table_end(ing_t *g) {
  free(g->b_names);
  g->b_names = NULL;
  g->b_n = 0;
  g->sm.lim.view_count = g->nview_names;
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
  if (g->out_off > 0 && g->out_len + g->enc.len > g->out_cap) {
    /* the sent head of the buffer is dead: move the live bytes to the start before the buffer grows, so that its size follows the
     * queued bytes (bounded by ING_MAX_OUT above) and not out_len, which a slow reader's out_off never lets go back to 0 */
    memmove(g->out, g->out + g->out_off, g->out_len - g->out_off);
    g->out_len -= g->out_off;
    g->out_off = 0;
  }
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
  /* many small answers (one ZONE_RESULT per zone) go out in one write: here when a chunk has gathered, otherwise at
   * the end of the event round in ingest_thread() */
  if (g->out_len - g->out_off >= ING_FLUSH_AT) out_flush(g);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* jobs                                                                                                           */
/* ------------------------------------------------------------------------------------------------------------- */

static void job_free(ing_job_t *j) {
  if (!j) return;
  free(j->img);
  zone_ext_shared_unref(j->shared);
  free(j->apex);
  free(j);
}

static void job_drop_image(ing_job_t *j) {
  free(j->img);
  j->img = NULL;
  j->img_len = j->img_cap = 0;
}

static void job_reject(ing_job_t *j, const char *why) {
  j->status = KDB_ST_REJECTED;
  snprintf(j->reason, sizeof(j->reason), "%s", why);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* settings of DB zones (B7a, design 1.3, 3.5, 4.2)                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

/* do the ACL entries a..b overlap?  Two prefixes overlap when the shorter one contains the other's network. */
static bool cidr_overlap(const cidr_entry_t *a, const cidr_entry_t *b, bool *b_contains_a) {
  if (a->is_any || b->is_any) {
    *b_contains_a = b->is_any;
    return true;
  }
  if (!a->valid || !b->valid || a->family != b->family) return false;
  unsigned p = a->prefix < b->prefix ? a->prefix : b->prefix;
  for (unsigned i = 0; i < 16 && i * 8 < p; i++) {
    unsigned bits = p - i * 8;
    uint8_t m = bits >= 8 ? 0xFF : (uint8_t)(0xFF << (8 - bits));
    if ((a->addr[i] & m) != (b->addr[i] & m)) return false;
  }
  *b_contains_a = b->prefix <= a->prefix;
  return true;
}

/* How acl-ceiling cuts the ACLs of x: "<statement> <entry> <outside|narrowed by> the ceiling; ...".  Returns the length;
 * an empty text means nothing is cut.  Only address entries are judged here: whether a request is inside the ceiling also
 * depends on its key (dns_tsig_acl.c), but an address entry outside every ceiling address can only be used together with a
 * key the ceiling names. */
static size_t ceiling_notes(const server_config_t *cfg, const zone_ext_t *x, char *out, size_t cap) {
  size_t n = 0;
  if (cap) out[0] = '\0';
  bool have_acl = x->allow_transfer_count > 0 || x->tsig_keys_count > 0 || x->allow_update_count > 0;
  bool have_ecs = x->ecs_trusted_resolvers_count > 0;          /* B8: the trusted resolvers are bounded by the ceiling too */
  if (!have_acl && !have_ecs) return 0;
#define NOTE(...) do { if (n + 1 < cap) { int w_ = snprintf(out + n, cap - n, __VA_ARGS__); if (w_ > 0) n = (size_t)w_ < cap - n ? n + (size_t)w_ : cap - 1; } } while (0)
  if (!db_acl_ceiling_configured(cfg)) {
    if (have_acl) NOTE("no acl-ceiling is configured: these ACLs refuse everybody");
    if (have_ecs) NOTE("%sno acl-ceiling is configured: no resolver of ecs-trusted-resolvers is trusted", have_acl ? "; " : "");
    return n;
  }
  const database_config_t *d = &cfg->database;
  for (int pass = 0; pass < 3; pass++) {
    const char *what = pass == 0 ? "allow-transfer" : pass == 1 ? "allow-update" : "ecs-trusted-resolvers";
    char *const *list = pass == 0 ? x->allow_transfer : pass == 1 ? x->allow_update : x->ecs_trusted_resolvers;
    const acl_entry_t *parsed = pass == 0 ? x->allow_transfer_parsed : pass == 1 ? x->allow_update_parsed : x->ecs_trusted_resolvers_parsed;
    int count = pass == 0 ? x->allow_transfer_count : pass == 1 ? x->allow_update_count : x->ecs_trusted_resolvers_count;
    for (int i = 0; parsed && i < count; i++) {
      if (!parsed[i].cidr.valid || parsed[i].is_deny) continue;      /* a key name, none, or an exclusion */
      bool inside = false, overlaps = false;
      for (int k = 0; k < d->acl_ceiling_count && d->acl_ceiling_parsed; k++) {
        if (!d->acl_ceiling_parsed[k].cidr.valid || d->acl_ceiling_parsed[k].is_deny) continue;
        bool contains = false;
        if (cidr_overlap(&parsed[i].cidr, &d->acl_ceiling_parsed[k].cidr, &contains)) {
          overlaps = true;
          if (contains) inside = true;
        }
      }
      if (!inside)
        NOTE("%s %.64s %s; ", what, list[i], overlaps ? "is narrowed by acl-ceiling" : "lies outside acl-ceiling");
    }
  }
#undef NOTE
  return n;
}

/* Resolve the settings of a zone: the text of its profile followed by its own text, parsed in the restricted mode of the
 * configuration parser (statement by statement the zone overrides the profile: the loader sends both texts and the
 * Backend merges them, so a hostile loader cannot get a statement past the whitelist by the way it splits them).  The
 * result is interned: zones with the same texts share one parsed object.  Every TSIG key the settings name must exist in
 * karidns.conf now.  *out: a new reference (NULL = no settings at all).  false: the zone is rejected, why says why. */
static const ing_profile_t *find_profile(const ing_t *g, const char *name, size_t len) {
  for (size_t i = 0; i < g->nprof; i++)
    if (strlen(g->profiles[i].name) == len && memcmp(g->profiles[i].name, name, len) == 0) return &g->profiles[i];
  return NULL;
}

static _Atomic bool g_ceiling_warned;

static bool check_settings_against_config(const zone_ext_shared_t *sh, const char *zone, char *why, size_t whylen) {
  bool ok = true;
  rcu_aux_read_lock();
  const server_config_t *cfg = acquire_config_snapshot();
  const char *missing = db_settings_missing_key(&sh->ext, cfg);
  if (missing) {
    char shown[72];
    sane_copy(shown, sizeof(shown), missing, strlen(missing));
    snprintf(why, whylen, "the settings name the TSIG key '%s', which is not defined in karidns.conf", shown);
    ok = false;
  } else if ((sh->ext.allow_transfer_count > 0 || sh->ext.tsig_keys_count > 0 || sh->ext.allow_update_count > 0 ||
              sh->ext.ecs_trusted_resolvers_count > 0) &&
             !db_acl_ceiling_configured(cfg) && !atomic_exchange_explicit(&g_ceiling_warned, true, memory_order_relaxed)) {
    syslog(LOG_WARNING, "[DB] zone '%s' has ACLs in its database settings, but options { database { acl-ceiling } } is not "
                        "configured: database ACLs refuse every client until it is (this is logged once)", zone);
  }
  rcu_aux_read_unlock();
  return ok;
}

static bool resolve_zone_settings(ing_t *g, ing_job_t *j, const kdb_zone_begin_t *zb) {
  const char *ztext = zb->settings.p ? zb->settings.p : "";
  size_t zlen = zb->settings.p ? zb->settings.len : 0;
  size_t pnlen = zb->profile.p ? zb->profile.len : 0;
  if (pnlen == 0 && zlen == 0) return true;               /* no metadata: the defaults, no ACLs */
  const ing_profile_t *prof = NULL;
  if (pnlen) {
    prof = find_profile(g, zb->profile.p, pnlen);
    if (!prof) {
      char shown[72];
      sane_copy(shown, sizeof(shown), zb->profile.p, pnlen);
      char msg[KDB_REASON_LEN];
      snprintf(msg, sizeof(msg), "the profile '%s' is not defined (karidns_profiles) or was not sent", shown);
      job_reject(j, msg);
      return false;
    }
  }
  const char *ptext = prof ? prof->text : "";
  size_t ptlen = prof ? prof->len : 0;
  /* what makes two settings the same: profile name, profile text, zone text */
  size_t klen = pnlen + 1 + ptlen + 1 + zlen;
  char *key = malloc(klen + 1);
  if (!key) {
    job_reject(j, "out of memory");
    return false;
  }
  memcpy(key, zb->profile.p ? zb->profile.p : "", pnlen);
  key[pnlen] = '\0';
  memcpy(key + pnlen + 1, ptext, ptlen);
  key[pnlen + 1 + ptlen] = '\0';
  memcpy(key + pnlen + 2 + ptlen, ztext, zlen);
  key[klen] = '\0';
  zone_ext_shared_t *sh = db_settings_find(key, klen);
  char err[200];
  if (!sh) {
    char *merged = malloc(ptlen + 1 + zlen + 1);
    if (!merged) {
      free(key);
      job_reject(j, "out of memory");
      return false;
    }
    memcpy(merged, ptext, ptlen);
    merged[ptlen] = '\n';
    memcpy(merged + ptlen + 1, ztext, zlen);
    /* each text must be complete on its own (a profile that opens a block it never closes would swallow the zone's
     * statements); then the two together, the zone's statements after the profile's */
    zone_ext_shared_t *t;
    char msg[KDB_REASON_LEN];
    bool bad = false;
    if (ptlen > 0 && zlen > 0) {
      if (!(t = db_settings_parse(ptext, ptlen, err, sizeof(err)))) {
        snprintf(msg, sizeof(msg), "profile text: %.150s", err);
        bad = true;
      } else {
        zone_ext_shared_unref(t);
        if (!(t = db_settings_parse(ztext, zlen, err, sizeof(err)))) {
          snprintf(msg, sizeof(msg), "zone settings: %.150s", err);
          bad = true;
        } else {
          zone_ext_shared_unref(t);
        }
      }
    }
    if (!bad && !(sh = db_settings_parse(merged, ptlen + 1 + zlen, err, sizeof(err)))) {
      snprintf(msg, sizeof(msg), "%s: %.150s", ptlen > 0 && zlen == 0 ? "profile text" : "settings", err);
      bad = true;
    }
    free(merged);
    if (bad) {
      free(key);
      job_reject(j, msg);
      return false;
    }
    sh->key = key;
    sh->key_len = klen;
    sh->hash = db_settings_hash(key, klen);
    if (pnlen) sane_copy(sh->profile, sizeof(sh->profile), zb->profile.p, pnlen);
    sh = db_settings_intern(sh);
    rcu_aux_read_lock();
    const server_config_t *ccfg = acquire_config_snapshot();
    char notes[400];
    if (db_acl_ceiling_configured(ccfg) && ceiling_notes(ccfg, &sh->ext, notes, sizeof(notes)) > 0)
      syslog(LOG_WARNING, "[DB] zone '%s' (first zone with these settings): %s", j->zone, notes);
    rcu_aux_read_unlock();
  } else {
    free(key);
  }
  char why[KDB_REASON_LEN];
  if (!check_settings_against_config(sh, j->zone, why, sizeof(why))) {
    zone_ext_shared_unref(sh);
    job_reject(j, why);
    return false;
  }
  j->shared = sh;
  return true;
}

/* the ixfr-history depth of the entry follows its settings (and options { ixfr-history }) */
static void apply_ixfr_depth(zone_db_entry_t *e, const zone_config_t *dc) {
  rcu_aux_read_lock();
  ixfr_history_set_depth(e, ixfr_history_effective(acquire_config_snapshot(), dc));
  rcu_aux_read_unlock();
}

/* A new entry for a DB zone (design 4.2): source DB, its settings block (interned settings or none).  zkind: a primary (its data
 * comes in ZONE_IMAGE), or (B7b) a secondary / catalog consumer, which the existing secondary machinery of the control thread
 * transfers from the masters in its settings (refresh timer, SOA retry and expire, NOTIFY, IXFR), like a configured one. */
static zone_db_entry_t *new_db_entry(const char *view, const char *zone, zone_ext_shared_t *shared, uint8_t zkind) {
  zone_db_entry_t *e = (zkind == KDB_ZK_PRIMARY && dbdir()) ? create_light_zone_entry(zone, view) : create_new_zone_entry(zone, view);      /* 0.7 store S5: a primary zone of the store is a light entry (the core in a slot of the entry pool) */
  if (!e) return NULL;
  zone_config_t *dc = db_zone_config_new_kind(zone, shared, zkind == KDB_ZK_PRIMARY ? 0 : zkind == KDB_ZK_SECONDARY ? 1 : 2);
  if (!dc) {
    free_zone_db_entry(e);
    return NULL;
  }
  e->source = ZONE_SRC_DB;
  e->kind = zkind == KDB_ZK_PRIMARY ? ZONE_KIND_PRIMARY : ZONE_KIND_SECONDARY;
  e->is_secondary = zkind != KDB_ZK_PRIMARY;
  atomic_store_explicit(&e->dbcfg, dc, memory_order_release);
  rcu_aux_read_lock();                                  /* (0.7 B2: nobody else has the entry yet: the depth is set without its history lock) */
  ixfr_history_init_depth(e, ixfr_history_effective(acquire_config_snapshot(), dc));
  rcu_aux_read_unlock();
  return e;
}

/* 0.7 store S2: the entry of an attach (dns_db_store.c): a primary zone of the database, with the interned settings (NULL: none) */
zone_db_entry_t *db_ingest_new_entry(const char *view, const char *zone, zone_ext_shared_t *shared) {
  return new_db_entry(view, zone, shared, KDB_ZK_PRIMARY);
}

/* does the settings block of the entry already hold exactly these settings? */
static bool entry_has_settings(const zone_db_entry_t *e, const zone_ext_shared_t *sh) {
  const zone_config_t *c = atomic_load_explicit(&e->dbcfg, memory_order_acquire);
  if (!c) return false;
  return sh ? (c->ext_shared && c->ext == &sh->ext) : (c->ext == NULL);
}

/* B7b: ZONE_END of a secondary (SLAVE) or catalog consumer (CONSUMER) zone: there is no data.  The zone's entry is created, or its
 * settings are replaced (new masters or key: the zone is re-pointed and asked to refresh at once), and entered in the registry
 * with the serial and digest the loader sent (serial 0, the digest of the settings), which is what a restarted loader compares:
 * a zone that did not change is not sent again, so nothing is transferred again.  What the entry holds (the zone it transferred
 * from the masters) is not touched here.  0.7 P3: with the zone store its copy is kept there (dns_xfr_store.h): a new entry gets the stored
 * copy before it is registered, so that it answers and refreshes from it (IXFR) instead of starting empty. */
static void consumer_members(zone_db_entry_t *e, const char *view);
static void job_execute_secondary(ing_job_t *j) {
  zone_db_entry_t *entry = dbreg_lookup_entry(j->view_name, j->zone);
  bool created = false, restored = false;
  if (entry) {
    const zone_config_t *oc = atomic_load_explicit(&entry->dbcfg, memory_order_acquire);
    /* the zone was a primary, or a SLAVE became a CONSUMER (or back): a new entry replaces it */
    if (entry->source != ZONE_SRC_DB || !entry->is_secondary || !oc || oc->is_catalog != (j->zkind == KDB_ZK_CATALOG)) entry = NULL;
  }
  if (!entry) {
    entry = new_db_entry(j->view_name, j->zone, j->shared, j->zkind);
    if (!entry) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    created = true;
  } else if (!entry_has_settings(entry, j->shared)) {
    zone_config_t *nc = db_zone_config_new_kind(j->zone, j->shared, j->zkind == KDB_ZK_CATALOG ? 2 : 1);
    if (!nc) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    db_entry_set_config(entry, nc);
    apply_ixfr_depth(entry, nc);
    atomic_store_explicit(&entry->refresh_now, true, memory_order_release);      /* the masters or the key may have changed (the refresh writes the copy's state with the new settings id, 3.3) */
  }
  {
    /* 0.7 P3: the domains.id is part of the identity of the zone's copy in the store; a new entry gets its copy (the restore job of the start, which runs on this thread too, finds the entry
     * then and does nothing: M4 c) */
    zone_x_t *sx = zone_x_need(entry);
    if (sx) atomic_store_explicit(&sx->xfr_db_sid, j->source_id, memory_order_release);
    if (created && sx && xfr_store_active()) restored = xfr_store_db_restore(entry);
  }
  bool shadowed = false;
  if (dbreg_commit(j->view_name, j->zone, entry, created, j->source_id, j->serial, j->digest, &shadowed) != 0) {
    if (created) free_zone_db_entry(entry);
    job_reject(j, "out of memory registering the zone");
    goto rejected;
  }
  j->status = shadowed ? KDB_ST_SHADOWED : KDB_ST_APPLIED;
  if (restored && j->zkind == KDB_ZK_CATALOG) consumer_members(entry, j->view_name);
  return;
rejected:
  (void)dbreg_reject(j->view_name, j->zone, j->source_id, j->reason);
}

/* 0.7 M3: the zone images that came (store.fill.*, karictl store): validated, their octets and the time of the validation, the ones that were refused, and what became of the others: put in the
 * store alone (a bulk body of a zone without a version here) or installed as an entry (a query's fetch, a changed zone, heap mode).  Relaxed atomics: the stream thread or a builder writes. */
static _Atomic uint64_t g_fill_images, g_fill_image_bytes, g_fill_validate_ns, g_fill_invalid, g_fill_store_only, g_fill_resident;
static int64_t mono_ns(void);

/* ZONE_END work, on the stream thread (ingest-threads 1) or a builder: check the image, put it in the store alone or publish it
 * into the entry, enter the zone in the registry.  Sets j->status / j->reason; the reply is the caller's. */
static void job_execute(ing_job_t *j) {
  if (j->skip) {                                         /* status and reason were set at ZONE_BEGIN */
    /* (a zone nobody asked for, or a fetch that was refused, is not a rejection of the zone: its last good version, if any, keeps serving) */
    if (j->view_name[0] && !j->unsolicited && !j->fetch_id) (void)dbreg_reject(j->view_name, j->zone, j->source_id, j->reason);
    return;
  }
  if (j->summary) {                                      /* D1a: serial and SOA timers for the directory; nothing to install */
    bool ap = dbreg_apply_summary(j->view_name, j->zone, j->source_id, j->serial, j->has_timers, j->t_refresh, j->t_retry, j->t_expire);
    if (ap && dbreg_set_apex(j->view_name, j->zone, j->source_id, j->serial, j->apex)) j->apex = NULL;       /* (the old apex goes when this summary has none) */
    if (ap && j->no_apex) dbreg_note_no_apex(j->view_name, j->zone, j->source_id);
    j->status = ap ? KDB_ST_APPLIED : KDB_ST_UNCHANGED;
    return;
  }
  if (j->cold) {                                         /* D1a step 5: the directory learns the zone; the data is fetched when a query needs it */
    if (j->dir_entry) {
      /* The loader sent a summary because its inventory says the zone has no data here.  If it has (a fetch or an UPDATE brought it), the summary
       * is not applied: the same version is UNCHANGED, another one is answered SEND_BODY, and the loader sends the zone whole.  Answering
       * UNCHANGED for both made a changed zone serve its old data for ever. */
      int sc = dbreg_summary_check(j->view_name, j->zone, j->source_id, j->serial);
      if (sc != DBREG_SUM_NONE) {
        j->status = sc == DBREG_SUM_SAME ? KDB_ST_UNCHANGED : KDB_ST_SEND_BODY;
        return;
      }
    }
    int cc = dbreg_commit_cold(j->view_name, j->zone, j->source_id, j->serial, j->digest, j->shared);
    if (cc == DBREG_COLD_RESIDENT) {
      /* the zone came into memory (a fetch) after this was offered: what is here is not what the loader sent.  The loader sends the body again; the zone is
       * in memory, so that is installed (cache_wants_cold()).  APPLIED here would have the loader believe that its version is the one served. */
      j->status = KDB_ST_SEND_BODY;
    } else if (cc == 0) {
      if (j->dir_entry && j->has_timers) {
        (void)dbreg_apply_summary(j->view_name, j->zone, j->source_id, j->serial, true, j->t_refresh, j->t_retry, j->t_expire);
        if (dbreg_set_apex(j->view_name, j->zone, j->source_id, j->serial, j->apex)) j->apex = NULL;
        if (j->no_apex) dbreg_note_no_apex(j->view_name, j->zone, j->source_id);
      }
      /* a summary is the directory entry the loader asked for; a body that was left out (memory-limit) tells the loader that the Backend has no data of the
       * zone, so that its inventory stops saying so (the next change is a summary, with the apex that a body cannot give) */
      j->status = j->dir_entry ? KDB_ST_APPLIED : KDB_ST_NOT_RESIDENT;
      /* 0.7 store S2: a summary that comes after the first batch means the loader found the zone changed (a change log entry, a reload): what the store holds of it is not trusted any more */
    } else {
      job_reject(j, "out of memory registering the zone");
      (void)dbreg_reject(j->view_name, j->zone, j->source_id, j->reason);
    }
    return;
  }
  if (j->zkind != KDB_ZK_PRIMARY) {
    job_execute_secondary(j);
    return;
  }
  if (j->failed) {                                       /* j->reason says why */
    j->status = KDB_ST_REJECTED;
    goto rejected;
  }
  if (!j->img || j->img_len != j->img_size) {            /* (the state machine keeps this: ZONE_END comes when the image is complete) */
    job_reject(j, "the zone image is incomplete");
    goto rejected;
  }
  if (j->img_cap > j->img_len) {                         /* (the buffer grew by doubling: the image lives as long as the entry does, without the slack) */
    uint8_t *tr = realloc(j->img, j->img_len);
    if (tr) {
      j->img = tr;
      j->img_cap = j->img_len;
    }
  }
  /* A fetch brings the version the loader read when the request was made.  If the directory has another version by now (a summary or a body of a newer one came
   * meanwhile), what the fetch brings may be the older one and must not replace it: it is dropped (not a rejection: the zone is still asked for by the requests that
   * wait for it, and the loader reads the version it has now) - unless it is the version the directory has now (the body of that version came first and was left
   * out of memory, and this is the data of it).  A directory that did not change since the request takes what the fetch brings: it may be newer than the directory
   * (the loader has not announced it yet), and dropping it would repeat the request until the loader does.  The jobs of one zone do not run at the same time
   * (name_in_flight()), so the check and the install see the same registry. */
  if (j->fetch_id && j->iv_st_valid && dbdir()) {
    /* 0.7 WP7b: the body is the version the record asked for when the request was made.  A record that has another stamp now (the database changed again: that body is asked for
     * on its own) or none (the zone was deleted meanwhile: it must not come back) takes nothing from this one. */
    db_stamp_t now;
    if (!db_store_zone_stamp(j->view_name, j->zone, &now, NULL) || now.gen != j->iv_st_gen || now.time != j->iv_st_time) {
      j->status = KDB_ST_UNCHANGED;
      job_drop_image(j);
      return;
    }
  }
  if (j->fetch_id && j->iv_valid) {
    int64_t sid;
    uint32_t sr;
    if (!dbreg_zone_version(j->view_name, j->zone, &sid, &sr) || ((sid != j->iv_sid || sr != j->iv_serial) && (sid != j->source_id || sr != j->serial))) {
      j->status = KDB_ST_UNCHANGED;
      job_drop_image(j);
      return;
    }
  }
  /* 0.7 M3: the image is the loader's claim: what the building of the zone from RRs used to check (ZONE_DATA) is checked on the image now (the zone, the size, the counts, the limits of the stream,
   * what the extended encoding allows; dns_zone_image.h).  The time is counted (store.fill.validate_us). */
  {
    const zone_image_policy_t pol = { j->zone, j->serial, j->rr_count, j->img_size, j->lim_bytes, j->lim_records, (j->zflags & KDB_ZF_EXTENDED) != 0, (j->zflags & KDB_ZF_TINYDNS) != 0, false };
    char vw[160];
    const int64_t tv0 = mono_ns();
    const int vr = zone_image_validate_ex(j->img, j->img_len, &pol, vw, sizeof(vw));
    atomic_fetch_add_explicit(&g_fill_validate_ns, (uint64_t)(mono_ns() - tv0), memory_order_relaxed);
    atomic_fetch_add_explicit(&g_fill_images, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_fill_image_bytes, j->img_len, memory_order_relaxed);
    if (vr != 0) {
      atomic_fetch_add_explicit(&g_fill_invalid, 1, memory_order_relaxed);
      char msg[KDB_REASON_LEN];
      snprintf(msg, sizeof(msg), "the zone image is refused: %s", vw);
      job_reject(j, msg);
      goto rejected;
    }
  }
  /* A body that nobody waits for (the background fetch of the wanted bodies) of a zone that has no version here goes to the store as it is: no entry is made, nothing is attached; the first query
   * attaches the zone from its record (dbreg_commit_store_only()).  Every other body is installed as the entry's next version and committed as before. */
  if (j->fill && j->fetch_id && dbdir() && dbreg_store_only_candidate(j->view_name, j->zone, j->serial, j->shared)) {
    if (zone_limits_gate_settings(j->view_name, j->zone, j->shared, (const zone_image_t *)(const void *)j->img, "database load") != 0) {
      job_reject(j, "the zone is over a limit of the configuration (see the log)");
      goto rejected;
    }
    db_stamp_t swant = { j->iv_st_gen, j->iv_st_time };
    const int sgd = db_store_commit_begin(j->view_name, j->zone, j->iv_st_valid ? &swant : NULL);
    int so = DBREG_STORE_ENTRY;
    if (sgd == DBC_OK) db_store_signer_commit(j->view_name, j->zone);      /* (signer-wait: a held version that nothing signed here kept is served as it is, and said so) */
    if (sgd == DBC_OK) so = dbreg_commit_store_only(j->view_name, j->zone, (const zone_image_t *)(const void *)j->img, j->source_id, j->serial, j->digest, j->shared);
    db_store_commit_end();
    if (sgd != DBC_OK) {                                 /* the body is for another stamp than the record has now, or the zone is gone: nothing is taken from it */
      j->status = KDB_ST_UNCHANGED;
      job_drop_image(j);
      return;
    }
    if (so == DBREG_STORE_ONLY) {
      atomic_fetch_add_explicit(&g_fill_store_only, 1, memory_order_relaxed);
      j->status = KDB_ST_APPLIED;
      job_drop_image(j);
      return;
    }
  }
  zone_db_entry_t *entry = dbreg_lookup_entry_busy(j->view_name, j->zone);
  bool created = false;
  if (entry && entry->is_secondary) entry = NULL;          /* B7b: the zone was a SLAVE / CONSUMER; a new primary entry replaces it */
  if (entry && j->fetch_id && dbdir() && db_store_signer_keeps(j->view_name, j->zone)) {
    /* 0.7 signer-wait: the version in memory is the one a hold keeps serving (its record waits for the signer, dns_db_store.c recon_hold_keeps()): a body of the held version does not replace it.  The
     * loader's release (the zone sent again without KDB_EF_HOLD, or a reload) lets go of the hold first, and that body is installed. */
    dbreg_busy_clear(j->view_name, j->zone);
    j->status = KDB_ST_UNCHANGED;
    job_drop_image(j);
    return;
  }
  if (!entry) {
    entry = new_db_entry(j->view_name, j->zone, j->shared, KDB_ZK_PRIMARY);
    if (!entry) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    created = true;
  }
  /* B7a: the settings that came with the data are in force while the data is installed (also-notify, the response cache
   * and the NOTIFY after the install read them); when the data is refused the previous settings are put back, so a zone
   * that keeps serving its last good version also keeps its last good settings */
  const zone_config_t *old_cfg = NULL, *new_cfg = NULL;
  uint64_t cfg_epoch = 0;
  if (!created && !entry_has_settings(entry, j->shared)) {
    zone_config_t *nc = db_zone_config_new(j->zone, j->shared);
    if (!nc) {
      job_reject(j, "out of memory");
      goto rejected;
    }
    new_cfg = nc;
    old_cfg = db_entry_swap_config(entry, nc, &cfg_epoch);
    apply_ixfr_depth(entry, nc);
  }
  if (db_zone_install_image(entry, (zone_image_t *)(void *)j->img, NULL, j->reason, sizeof(j->reason)) != 0) {
    if (created) {
      free_zone_db_entry(entry);                         /* never registered or published into a snapshot */
    } else if (new_cfg) {
      uint64_t e2;
      (void)db_entry_swap_config(entry, old_cfg, &e2);   /* take the previous settings back ... */
      db_entry_retire_config(entry, new_cfg, e2);        /* ... and retire the ones that were refused */
      if (old_cfg) apply_ixfr_depth(entry, old_cfg);
    }
    j->status = KDB_ST_REJECTED;
    goto rejected;
  }
  if (new_cfg) db_entry_retire_config(entry, old_cfg, cfg_epoch);
  j->img = NULL;                                         /* (the entry's version owns the image now) */
  j->img_len = j->img_cap = 0;
  atomic_fetch_add_explicit(&g_fill_resident, 1, memory_order_relaxed);
  bool shadowed = false;
  const uint32_t serial_now = atomic_load(&entry->serial);      /* (before the commit: a zone of the store that is over the limit is not kept, the entry is gone) */
  /* 0.7 WP7b: the check above was made before the install, which takes a long time: the database may have changed the zone again (a CHANGES or manifest entry of the ingest thread, which does not wait for
   * this builder) or deleted it since.  The version that dbreg_commit() puts in the store gets the record's stamp, so the check is made again at the commit, as one step with the writers of the stamp
   * (db_store_commit_begin()): a body for another stamp is not put under the newer one (the record is wanted and the scan asks for it again, fetch_complete()), and a zone that is gone does not come
   * back.  A zone that is in memory was updated in place already: it is registered (it serves what it has until the body for the new stamp comes) but the store takes no version from it. */
  db_stamp_t want = { j->iv_st_gen, j->iv_st_time };
  const int gd = db_store_commit_begin(j->view_name, j->zone, j->fetch_id && j->iv_st_valid && dbdir() ? &want : NULL);
  if (gd == DBC_GONE || (gd == DBC_STALE && created)) {
    db_store_commit_end();
    if (created) free_zone_db_entry(entry);                    /* never registered or published into a snapshot */
    else dbreg_busy_clear(j->view_name, j->zone);              /* (the zone is in memory and was marked busy; no commit follows: its record is gone, or cannot be read now (a damaged cell), and the mark must not stay) */
    j->status = KDB_ST_UNCHANGED;
    job_drop_image(j);
    return;
  }
  if (gd == DBC_OK && j->fetch_id && dbdir()) db_store_signer_commit(j->view_name, j->zone);      /* (signer-wait: a held version that nothing signed here kept is served as it is, and said so) */
  if (j->fetch_id && !dbdir() && dbreg_signer_unsigned_take(j->view_name, j->zone)) db_signer_unsigned_note(j->view_name, j->zone);      /* (0.7, the same without the store: ZONE_HOLD) */
  const int cr = dbreg_commit(j->view_name, j->zone, entry, created, j->source_id, serial_now, j->digest, &shadowed);
  db_store_commit_end();
  if (cr != 0) {
    if (created) free_zone_db_entry(entry);
    job_reject(j, "out of memory registering the zone");
    goto rejected;
  }
  if (gd == DBC_STALE) {                                       /* (registered, but not stored: the version the record asks for is another one) */
    j->status = KDB_ST_UNCHANGED;
    job_drop_image(j);
    return;
  }
  j->serial = serial_now;
  j->status = shadowed ? KDB_ST_SHADOWED : KDB_ST_APPLIED;
  return;
rejected:
  {
    /* A fetched body that was refused marks the store's record (STORE_F_REJECTED_NEW: this version is not asked for again) only when the record still has the stamp the body was asked for: the database may have
     * changed the zone since, and then the newer version is not the one that was refused.  The check and the mark are one step with the writers of the stamp, as at a commit. */
    db_stamp_t want = { j->iv_st_gen, j->iv_st_time };
    const int gd = db_store_commit_begin(j->view_name, j->zone, j->fetch_id && j->iv_st_valid && dbdir() ? &want : NULL);
    (void)dbreg_reject_ex(j->view_name, j->zone, j->source_id, j->reason, gd == DBC_OK);
    db_store_commit_end();
  }
  job_drop_image(j);
}

static void *builder_thread(void *arg) {
  ing_builder_t *b = arg;
  ing_t *g = &g_ing;
  rcu_aux_thread_pin();
  struct kevent ev;
  burst_yield_t by = BURST_YIELD_INIT;
  bool poll_warned = false;
  for (;;) {
    if (kevent(b->kq, NULL, 0, &ev, 1, NULL) < 0) {
      if (errno == EINTR) continue;
      /* The wait is broken.  Returning would leave the job in the slot (and its flight entry) for ever, and the stream thread waiting
       * for it; so the thread looks at its slot every few ms instead. */
      if (!poll_warned) syslog(LOG_ERR, "[DB] a builder thread cannot wait for work (kevent: %s); it polls", strerror(errno));
      poll_warned = true;
      struct timespec nap = { 0, 5000000L };
      nanosleep(&nap, NULL);
    }
    ing_job_t *j = atomic_exchange_explicit(&b->slot, NULL, memory_order_acquire);
    if (!j) continue;
    burst_yield_check(&by);                /* a batch of a million zones: the pinned worker on this CPU gets its turns */
    job_execute(j);
    ing_job_t *h = atomic_load_explicit(&g->res_head, memory_order_relaxed);
    do {
      j->next = h;
    } while (!atomic_compare_exchange_weak_explicit(&g->res_head, &h, j, memory_order_release, memory_order_relaxed));
    struct kevent t;
    EV_SET(&t, ING_EVT_RESULT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    (void)kevent(g->kq, &t, 1, NULL, 0, NULL);
    EV_SET(&t, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    (void)kevent(g->wait_kq, &t, 1, NULL, 0, NULL);
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* replies and bookkeeping (stream thread)                                                                        */
/* ------------------------------------------------------------------------------------------------------------- */

static void send_zone_result(ing_t *g, uint16_t view, const char *zone, uint8_t status, const char *reason) {
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_ZONE_RESULT) != 0 || kdb_enc_u16(&g->enc, 1, view) != 0 ||
      kdb_enc_name(&g->enc, 2, zone) != 0 || kdb_enc_u8(&g->enc, 3, status) != 0 ||
      (reason && reason[0] && (enc_sane_str(&g->enc, 4, reason), g->enc.err)) || kdb_enc_end(&g->enc) != 0) {
    g->enc.err = true;
  }
  send_enc(g);
}

/* 0.7 signer-wait: the answer to a CHANGES upsert with KDB_EF_HOLD that the Backend did not hold (a zone it had no image of, a version it refused, the version it has): the loader stops
 * listing the zone as waiting for the signer (tag 5, the source id the loader keys its list by) */
static void send_hold_result(ing_t *g, uint16_t view, const char *zone, int64_t source_id, uint8_t status) {
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_ZONE_RESULT) != 0 || kdb_enc_u16(&g->enc, 1, view) != 0 || kdb_enc_name(&g->enc, 2, zone) != 0 || kdb_enc_u8(&g->enc, 3, status) != 0 ||
      kdb_enc_i64(&g->enc, 5, source_id) != 0 || kdb_enc_end(&g->enc) != 0) {
    g->enc.err = true;
  }
  send_enc(g);
}

static void apply_delta(ing_t *g);
static void wake_flush(ing_t *g) {
  if (g->delta_wake) {
    g->delta_wake = false;
    if (dbreg_pending_count() > 0) apply_delta(g);
  }
  park_wake_flush();
}

static void fetch_job_finish(ing_t *g, ing_job_t *j);
static void warm_add(ing_t *g, const char *view, const char *zone);
static void warm_add_ex(ing_t *g, const char *view, const char *zone, bool hot, bool fresh);
static void fetch_issue(ing_t *g);

/* the answer of a finished job; the job is freed */
static void job_finish(ing_t *g, ing_job_t *j) {
  if (j->fetch_id) {                                     /* D1a: a zone of the fetch stream has no ZONE_RESULT, it wakes the queries that wait for it */
    fetch_job_finish(g, j);
    return;
  }
  /* 0.7 M3, debug 1: what became of every zone of a batch (the INFO and WARNING lines below stop after the first few) */
  logev_post(LOGC_DATABASE, 1, NULL, 0, "[DB] zone '%s' (view '%s'), serial %u: %s%s%s", j->zone, j->view_name, j->serial,
             j->status == KDB_ST_APPLIED ? "installed" : j->status == KDB_ST_NOT_RESIDENT ? "version taken, the data stays out of memory"
             : j->status == KDB_ST_SHADOWED ? "loaded but hidden (a zone of karidns.conf or a catalog member has the name)"
             : j->status == KDB_ST_UNCHANGED ? "unchanged, nothing to install" : j->status == KDB_ST_SEND_BODY ? "another version: the whole zone is asked for"
             : "rejected", j->status == KDB_ST_REJECTED ? ": " : "", j->status == KDB_ST_REJECTED ? j->reason : "");
  switch (j->status) {
  case KDB_ST_NOT_RESIDENT:                              /* a body that was left out of memory: the directory has the version (counted as applied) */
  case KDB_ST_APPLIED:
    g->b_applied++;
    atomic_fetch_add_explicit(&g_st.tot_applied, 1, memory_order_relaxed);
    g->since_retire++;
    if (j->dir_entry && j->shared && j->shared->ext.cache_mode == 1) warm_add(g, j->view_name, j->zone);     /* a pinned zone is read after its summary */
    if (j->status == KDB_ST_APPLIED && g->zones_logged < ING_ZONES_LOGGED) {
      g->zones_logged++;
      syslog(LOG_INFO, "[DB] zone '%s' (view '%s'): installed, serial %u", j->zone, j->view_name, j->serial);
    }
    break;
  case KDB_ST_SHADOWED:
    g->b_shadowed++;
    atomic_fetch_add_explicit(&g_st.tot_shadowed, 1, memory_order_relaxed);
    g->since_retire++;
    if (g->shadows_logged < ING_REJECTS_LOGGED) {        /* the rest is in the count of the batch summary (on_batch_end) */
      dbreg_info_t si;
      bool cat = dbreg_find_info(j->view_name, j->zone, &si, 1) > 0 && si.shadow_by == DBREG_SH_CATALOG;
      g->shadows_logged++;
      syslog(LOG_WARNING, "[DB] zone '%s' (view '%s'): loaded, but hidden by %s", j->zone, j->view_name,
             cat ? "a catalog member of the same name" : "the zone in karidns.conf");
    }
    break;
  case KDB_ST_UNCHANGED:                                 /* a summary that was not applied (the zone has its data here in the same version) */
  case KDB_ST_SEND_BODY:                                 /* ... or in another one: the loader sends it whole; neither is a rejection */
    break;
  default:
    g->b_rejected++;
    atomic_fetch_add_explicit(&g_st.tot_rejected, 1, memory_order_relaxed);
    if (g->rejects_logged < ING_REJECTS_LOGGED) {
      g->rejects_logged++;
      syslog(LOG_WARNING, "[DB] zone '%s' (view '%s') rejected: %s; the last good version, if any, keeps serving",
             j->zone, j->view_name, j->reason);
    }
    break;
  }
  if (g->cur_req >= 0 && g->reqs[g->cur_req].view == j->view && domain_names_match_ci(g->reqs[g->cur_req].zone, j->zone)) {
    g->req_outcome = j->status == KDB_ST_SHADOWED ? ROUT_SHADOWED : j->status == KDB_ST_REJECTED ? ROUT_REJECTED : ROUT_APPLIED;
    g->req_serial = j->serial;
    snprintf(g->req_reason, sizeof(g->req_reason), "%s", j->status == KDB_ST_REJECTED ? j->reason : "");
  }
  send_zone_result(g, j->view, j->zone, j->status, j->status == KDB_ST_REJECTED ? j->reason : NULL);
  job_free(j);
}

static void retire_if_due(ing_t *g, bool force) {
  if (g->since_retire >= ING_RETIRE_EVERY || force) {
    zone_retire_process(true);                           /* outside any read section; a grace period for the batch */
    g->since_retire = 0;
  }
}

static void apply_delta(ing_t *g) {
  if (dbreg_pending_count() == 0) return;
  g->delta_failed = snapshot_apply_db_delta() < 0;
  g->last_delta_ms = now_ms();
}

/* publish new zones when a second has passed since the last time (design 4.4: the first DB zones appear early) */
/* wake the ingest thread: something it should look at without an event of its own (an eviction queued a change of the index) */
static _Atomic int g_ing_kick_kq = -1;
static void ing_kick(void) {
  int kq = atomic_load_explicit(&g_ing_kick_kq, memory_order_relaxed);
  if (kq < 0) return;
  struct kevent t;
  EV_SET(&t, ING_EVT_RESULT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &t, 1, NULL, 0, NULL);
}

static _Atomic uint64_t g_fetch_shed;   /* fetch requests not made because of memory-limit */
static _Atomic uint32_t g_fetch_rate = 0;   /* database { fetch-rate }: zones read for queries per second */
static _Atomic uint64_t g_fetch_limited;  /* fetch requests not made because the rate was used up */
static _Atomic uint32_t g_fetch_conc = KARIDNS_DB_FETCH_CONC_PER_THREAD;   /* fetches in flight while memory-limit is set (database { fetch-concurrency }) */
/* 0.7 B2 W8, room on demand (entries of the wait queue of ing_t that were held up by room): how many were, how many of them ran out of time (park-timeout) before there was room, how many wait now */
static _Atomic uint64_t g_room_waits, g_room_timeouts;
static _Atomic uint32_t g_room_waiting;
static _Atomic uint32_t g_park_timeout_ms = PARK_DEFAULT_TIMEOUT_MS;   /* database { park-timeout }: the deadline of a request that waits for room (the workers' own is read at their start) */

/* the limit of fetches in flight: fetch-concurrency, or loader-threads x KARIDNS_DB_FETCH_CONC_PER_THREAD (at least 16) when it is not set; never more than the table holds */
static uint32_t fetch_conc_eff(uint32_t conc, uint32_t loader_threads) {
  if (conc == 0) {
    conc = loader_threads * KARIDNS_DB_FETCH_CONC_PER_THREAD;
    if (conc < 16) conc = 16;
  }
  if (conc < KARIDNS_DB_FETCH_CONC_MIN) conc = KARIDNS_DB_FETCH_CONC_MIN;
  if (conc > ING_FETCH_MAX) conc = ING_FETCH_MAX;
  return conc;
}
static void fill_max_set(uint32_t loader_threads);
static void set_fetch_limits(const ing_cfg_t *c) {
  fill_max_set(c->loader_threads);           /* (0.7 first-fill latency: the fill's bodies in flight follow loader-threads) */
  uint32_t eff = fetch_conc_eff(c->fetch_concurrency, c->loader_threads);
  atomic_store_explicit(&g_fetch_conc, eff, memory_order_relaxed);
  park_places_set_limit(eff);                /* the pool of places the workers and this thread draw from: a lower limit takes effect as the places in use are given back, none is lost */
  uint32_t rate = c->fetch_rate;                /* (0.7 P-A: 0 = unlimited) */
  atomic_store_explicit(&g_fetch_rate, rate, memory_order_relaxed);
  atomic_store_explicit(&g_park_timeout_ms, c->park_timeout_ms ? c->park_timeout_ms : PARK_DEFAULT_TIMEOUT_MS, memory_order_relaxed);
  park_shed_set_ttl(c->park_timeout_ms ? c->park_timeout_ms : PARK_DEFAULT_TIMEOUT_MS);       /* (the names whose lookup was shed are remembered for as long as the queries wait: shed_remember()) */
  park_rate_set(rate);                      /* the bucket of this thread (dns_park.c; 0: no rate, no bucket) */
}
/* the zones nobody asked for yet (the warm-up, the walk for apexes) use at most this many places of the limit or `cap`, half the limit at the most, so that the queries have the rest */
static uint32_t fetch_sub_limit(uint32_t cap) {
  uint32_t half = atomic_load_explicit(&g_fetch_conc, memory_order_relaxed) / 2;
  return half < cap ? half : cap;
}
/* 0.7 fix 8, the first fill and the queries: the queries come first (the loader serves a request of a query before one of the fill, and a place goes to the oldest query that waits), but the fill is not
 * left to the places the queries do not use: a first fill that queries keep waiting for would read its zones one by one when a query asks for them (a read for one zone from the database is dearer
 * than one in the order of the scan), and the zones that the queries have not asked for yet would come when the queries stop.  So the fill keeps a share whatever waits: a quarter of
 * fetch-concurrency, at least one, at most ING_BULK_NFREQ, its bodies in flight while requests of queries wait (fill_limit(); since the first-fill latency work these take no place of
 * fetch-concurrency). */
#define ING_BULK_NFREQ 32
static uint32_t bulk_reserve_for(uint32_t conc) {
  uint32_t q = conc / 4;
  if (q < 1) q = 1;
  return q < ING_BULK_NFREQ ? q : ING_BULK_NFREQ;
}
static uint32_t bulk_reserve(void) { return bulk_reserve_for(atomic_load_explicit(&g_fetch_conc, memory_order_relaxed)); }
/* 0.7 first-fill latency (W1, W5): the bodies of the fill take no place of fetch-concurrency: every place is the queries' (their fetches and lookups), and the fill has a limit of its own, its
 * bodies in flight: fill_max_for(loader-threads) (256..1024) while no request of a query waits (the wait queue and the lookup queue are empty), so that the loader reads whole IN statements (DB_IN_MAX zones; with
 * 32 in flight spread over the workers it read about 2 zones a statement, PostgreSQL 10M zones 2556 s against SQLite3's 490 s), and back to the old share (bulk_reserve(), at most 32) while
 * one waits: the fill makes no new request then, and the queries come first.  What bounds the load of the database is loader-threads (the loader's workers read; the requests in flight only
 * wait in its queue), and the loader leaves one worker to the queries (fq_bg_cap(), karidns_dbloader.c). */

#define ING_FILL_NFREQ_MIN 256
#define ING_FILL_NFREQ_MAX 1024
#define ING_FILL_BATCH 128          /* the loader's batch of the fill (DB_IN_MAX of dns_db_driver.h, FETCH_BG_BATCH_MAX of karidns_dbloader.c) */
/* the fill's bodies in flight while no query waits: DB_IN_MAX for each worker of the loader that reads the fill (loader-threads - 1, at least one: fq_bg_limit() of the loader), between
 * ING_FILL_NFREQ_MIN and ING_FILL_NFREQ_MAX.  pc31, PostgreSQL 10M zones, loader-threads 8: 256 in flight gave 14 zones a read and 10.8k zones/s, 896 gave 112 zones a read and 13.8k zones/s
 * (PostgreSQL is CPU-bound: the statements and the parallel reads both count) */
static uint32_t fill_max_for(uint32_t loader_threads) {
  const uint32_t w = loader_threads > 1 ? loader_threads - 1 : 1;
  const uint32_t n = w * ING_FILL_BATCH;
  return n < ING_FILL_NFREQ_MIN ? ING_FILL_NFREQ_MIN : (n > ING_FILL_NFREQ_MAX ? ING_FILL_NFREQ_MAX : n);
}
static _Atomic uint32_t g_fill_max = ING_FILL_NFREQ_MIN;   /* fill_max_for(loader-threads), set_fetch_limits() */
static void fill_max_set(uint32_t loader_threads) { atomic_store_explicit(&g_fill_max, fill_max_for(loader_threads), memory_order_relaxed); }
static uint32_t fill_limit_calc(uint32_t nwq, uint32_t nlq, uint32_t conc, uint32_t fmax) { return nwq == 0 && nlq == 0 ? fmax : bulk_reserve_for(conc); }
/* 0.7 first-fill latency (W2): the attaches of stored zones for queries wait behind the fill's writes (the store threads read the segments while the fill writes them and its checkpoints sync
 * them: pc31, PostgreSQL 10M zones under load, store.cold.p99 1.4 s).  While the workers' attach rings hold ING_FILL_ATT_BACKLOG requests or more (the store threads are behind) the fill is
 * held to its old share as while queries wait (store.ingest.fill_throttled counts the times it began) */
#define ING_FILL_ATT_BACKLOG 32
static _Atomic uint64_t g_fill_throttled;
static uint32_t fill_limit(const ing_t *g) {
  uint32_t nwq = g->nwq;
  if (nwq == 0 && g->nlq == 0) {
    uint64_t shed, newest, queued;
    park_attach_counts(&shed, &newest, &queued);
    static bool s_held;                                      /* (this thread only: the last call held the fill back; a hold is counted once, when it begins) */
    const bool hold = queued >= ING_FILL_ATT_BACKLOG;
    if (hold && !s_held) atomic_fetch_add_explicit(&g_fill_throttled, 1, memory_order_relaxed);
    s_held = hold;
    if (hold) nwq = 1;                                       /* (the same limit as for a query that waits) */
  }
  return fill_limit_calc(nwq, g->nlq, atomic_load_explicit(&g_fetch_conc, memory_order_relaxed), atomic_load_explicit(&g_fill_max, memory_order_relaxed));
}
#ifdef KARIDNS_UNIT_TEST
/* tests: the fill's limit of bodies in flight with nwq requests of queries and nlq lookups waiting, at fetch-concurrency conc and loader-threads lt */
uint32_t db_ingest_test_fill_limit(uint32_t nwq, uint32_t nlq, uint32_t conc, uint32_t lt) { return fill_limit_calc(nwq, nlq, conc, fill_max_for(lt)); }
#endif
static _Atomic uint32_t g_ing_fill_pct;                    /* the share of the last window (~10 s) the ingest thread spent on the bodies of the fill (what a first fill takes of it) */
static _Atomic uint64_t g_fetch_issued;   /* fetches of a whole zone sent to the loader (queries, transfers, the warm-up) */
/* dbstatus "fetchq:" (B2 W3): where a fetch can be held up; the ingest thread writes them, the control thread reads them; all cumulative since the start */
static _Atomic uint32_t g_fq_inflight, g_fq_peak;          /* fetches in flight now (g->nfreq) and the most there have been */
static _Atomic uint64_t g_fq_table_full;                   /* requests of queries refused because every place of the fetch table was taken */
static _Atomic uint64_t g_fq_loader_busy;                  /* fetches the loader turned away ("busy": its queue was full) */
#define FQ_HIST_N 5
static _Atomic uint64_t g_fq_hist[FQ_HIST_N];              /* fetches installed, by the time from the request to the install: <=1 ms, <=10 ms, <=100 ms, <=1 s, more */
static _Atomic uint32_t g_ing_busy_pct;                    /* share of the last window (~10 s) the ingest thread was not waiting for events */
/* 0.7, the by-name lookups of the first start (FETCH_REQ mode KDB_FETCH_LOOKUP): the loader answers them (HELLO features, the store protocol on), and what became of them */
static _Atomic bool g_lookup_on;
static _Atomic bool g_lookup_hold;                         /* the last loader that said its HELLO looks names up, connected now or not (or, with the store on, no loader has said its HELLO since the start): while its pass is pending a query for a name no zone covers waits for the loader's return (it is dropped at its time-out), it is not refused (0.7) */
static _Atomic uint64_t g_lk_found, g_lk_none, g_lk_failed, g_lk_refused, g_lk_dup;
static _Atomic uint64_t g_lk_asked, g_lk_body, g_lk_covered, g_lk_shed, g_lk_expired, g_lk_bad, g_lk_max_ns;     /* requests of the workers taken; bodies that came with the answer and were taken; names whose zone was known by the time they were to go; requests dropped because the queue was full; queue entries whose time was up; bodies that were thrown away; the longest time to an answer */
static _Atomic uint32_t g_fp_max_n;                        /* the most requests one pass of fetch_issue() handled, since the start */
static _Atomic uint64_t g_fp_max_ns;                       /* the longest one pass of fetch_issue() ran (and handled something), since the start */
static _Atomic uint64_t g_fp_passes, g_fp_cut;             /* the passes that handled something, and those that ended at their bound (the time slice) with work left */
static _Atomic uint64_t g_ing_jw_slices;                   /* 0.7 first-fill latency: slices of the journal wait in which the requests of queries were served (ing_journal_wait(), store.ingest.journal_wait_slices) */
static _Atomic uint64_t g_fill_stalls;                     /* 0.7 first-fill latency: windows of dd_tick() in which the fill had work and no body of it came (store.ingest.fill_stalled_windows) */

/* ---- 0.7 first-fill latency (W3): a database that cannot be read ----
 * The queries whose data cannot be read are not answered (never SERVFAIL while the data is being loaded, DNS_NR_DROP) and are counted (store.park.drop.failed, store.lookup.drop.failed; a
 * query that waited for a loader that is not there runs into park-timeout, store.park.drop.timeout).  So that the operator hears of it once, not once a query: every DD_WINDOW_MS the ingest
 * thread writes one WARNING when queries were dropped in the window because reads failed (with the reason of the last one) or because the loader was not connected, and one NOTICE when a
 * window after that has reads that ended well and no such drop. */
#define DD_WINDOW_MS 60000
static int64_t g_dd_window_ms = DD_WINDOW_MS;              /* (the test builds: KARIDNS_TEST_DBDOWN_LOG_S, db_ingest_start()) */
static void dd_note(ing_t *g, bool ok, const char *why) {
  g->dd_last_ok = ok;
  if (ok) {
    g->dd_ok++;
    return;
  }
  g->dd_fail++;
  snprintf(g->dd_why, sizeof(g->dd_why), "%s", why && why[0] ? why : "no reason given");
}
static void dd_counts(uint64_t c[3]) {
  c[0] = park_cnt_get(PARK_CNT_ZONE_FAILED);
  c[1] = park_cnt_get(PARK_CNT_LK_FAILED);
  c[2] = park_cnt_get(PARK_CNT_ZONE_TIMEOUT) + park_cnt_get(PARK_CNT_LK_TIMEOUT);
}
static void dd_tick(ing_t *g, int64_t now) {
  if (g->fetch_fd < 0) g->dd_nolink = true;
  if (g->dd_start == 0) {
    g->dd_start = now;
    dd_counts(g->dd_c0);
    return;
  }
  if (now - g->dd_start < g_dd_window_ms) return;
  uint64_t c[3];
  dd_counts(c);
  const uint64_t failed = c[0] - g->dd_c0[0], lkfailed = c[1] - g->dd_c0[1], timeout = c[2] - g->dd_c0[2];
  const long long secs = (long long)((now - g->dd_start + 500) / 1000);
  if (failed + lkfailed > 0 || (g->dd_nolink && timeout > 0)) {
    if (g->dd_fail > 0)
      syslog(LOG_WARNING, "[DB] %llu queries were not answered in the last %lld s: %u reads of the database failed (the last: %s); store.park.drop.failed %llu, store.lookup.drop.failed %llu, store.park.drop.timeout %llu",
             (unsigned long long)(failed + lkfailed + timeout), secs, g->dd_fail, g->dd_why, (unsigned long long)failed, (unsigned long long)lkfailed, (unsigned long long)timeout);
    else
      syslog(LOG_WARNING, "[DB] %llu queries were not answered in the last %lld s: %s; store.park.drop.failed %llu, store.lookup.drop.failed %llu, store.park.drop.timeout %llu",
             (unsigned long long)(failed + lkfailed + timeout), secs, g->dd_nolink ? "the loader was not connected" : "the data of their zones could not be read",
             (unsigned long long)failed, (unsigned long long)lkfailed, (unsigned long long)timeout);
    g->dd_reported = true;
  }
  if (g->dd_reported && g->dd_ok > 0 && g->dd_last_ok && g->fetch_fd >= 0) {      /* (the last read of the window ended well: said once, also in the window of the WARNING) */
    syslog(LOG_NOTICE, "[DB] the database is read again (%u reads ended well in the last %lld s)", g->dd_ok, secs);
    g->dd_reported = false;
  }
  /* 0.7 first-fill latency: the fill waits while queries take the loader (queries first, fq_pick()); a window in which the fill has work and no body of it came is a stall: counted, and said
   * once a window; the fill goes on by itself when the queries leave the loader a worker, which a NOTICE says */
  if (g->bg_on && g->fetch_fd >= 0 && g->fs_done == 0) {
    atomic_fetch_add_explicit(&g_fill_stalls, 1, memory_order_relaxed);
    syslog(LOG_WARNING, "[DB] the fill of the store made no progress in the last %lld s: the queries take the loader first (%u fetches of queries and %u lookups waiting, %u in flight); it goes on when they leave it room (store.ingest.fill_stalled_windows)",
           secs, g->nwq, g->nlq, g->nfreq);
    g->fs_reported = true;
  } else if (g->fs_reported && g->fs_done > 0) {
    syslog(LOG_NOTICE, "[DB] the fill of the store goes on (%u bodies in the last %lld s)", g->fs_done, secs);
    g->fs_reported = false;
  }
  g->fs_done = 0;
  g->dd_start = now;
  memcpy(g->dd_c0, c, sizeof(c));
  g->dd_fail = g->dd_ok = 0;
  g->dd_nolink = g->fetch_fd < 0;
  g->dd_warned = false;
}
static _Atomic uint32_t g_lk_pending, g_lk_inflight, g_lk_peak;     /* waiting for a place now, out now (the lookups and the fetches that came of them), the most that waited */
static _Atomic uint64_t g_lk_hist[STORE_STATUS_HIST_BUCKETS];       /* the time from the request to the answer: <= 1 us, <= 2 us, ... (dns_store_status.h) */
/* tests (always compiled: the coverage of the test programs and of karidns merges): a smaller bound of the lookup queue and of the wait queue than ING_LQ_MAX / ING_WQ_MAX (0: the constants), so that a full queue can be made with a few requests */
_Atomic uint32_t db_ingest_test_lq_max, db_ingest_test_wq_max;
static uint32_t queue_cap(const _Atomic uint32_t *hook, uint32_t max) {
  const uint32_t v = atomic_load_explicit(hook, memory_order_relaxed);
  return v && v < max ? v : max;
}
/* 0.7: the scan of the wanted bodies (bg_on of the ingest thread, published) and the times it ended idle */
static _Atomic bool g_scan_on;
static _Atomic uint64_t g_scan_idle;
static void scan_set(ing_t *g, bool on) {
  g->bg_on = on;
  atomic_store_explicit(&g_scan_on, on, memory_order_release);
}
uint64_t db_ingest_fill_scan(bool *on) {
  const uint64_t n = atomic_load_explicit(&g_scan_idle, memory_order_acquire);
  if (on) *on = atomic_load_explicit(&g_scan_on, memory_order_acquire);
  return n;
}
/* 0.7 M3: the zone images (store.fill.*, dns_store_status.h) */
bool db_ingest_fill_stats(store_fill_t *out) {
  memset(out, 0, sizeof(*out));
  out->images = atomic_load_explicit(&g_fill_images, memory_order_relaxed);
  out->image_bytes = atomic_load_explicit(&g_fill_image_bytes, memory_order_relaxed);
  out->validate_ns = atomic_load_explicit(&g_fill_validate_ns, memory_order_relaxed);
  out->invalid = atomic_load_explicit(&g_fill_invalid, memory_order_relaxed);
  out->store_only = atomic_load_explicit(&g_fill_store_only, memory_order_relaxed);
  out->resident = atomic_load_explicit(&g_fill_resident, memory_order_relaxed);
  return true;
}
bool db_ingest_lookup_ready(void) { return atomic_load_explicit(&g_lookup_on, memory_order_acquire); }
bool db_ingest_lookup_wanted(void) { return atomic_load_explicit(&g_lookup_on, memory_order_acquire) || atomic_load_explicit(&g_lookup_hold, memory_order_acquire); }
/* the counters of the lookups for `karictl store` and dbstatus (dns_store_status.h): relaxed atomics that the ingest thread and the workers write, any thread reads */
bool db_ingest_lookup_stats(store_lookup_t *out) {
  memset(out, 0, sizeof(*out));
  out->ready = db_ingest_lookup_ready();
  out->asked = atomic_load_explicit(&g_lk_asked, memory_order_relaxed);
  out->found = atomic_load_explicit(&g_lk_found, memory_order_relaxed);
  out->none = atomic_load_explicit(&g_lk_none, memory_order_relaxed);
  out->failed = atomic_load_explicit(&g_lk_failed, memory_order_relaxed);
  out->refused = atomic_load_explicit(&g_lk_refused, memory_order_relaxed);
  out->same_name = atomic_load_explicit(&g_lk_dup, memory_order_relaxed);
  out->covered = atomic_load_explicit(&g_lk_covered, memory_order_relaxed);
  out->shed = atomic_load_explicit(&g_lk_shed, memory_order_relaxed);
  out->expired = atomic_load_explicit(&g_lk_expired, memory_order_relaxed);
  out->body_inline = atomic_load_explicit(&g_lk_body, memory_order_relaxed);
  out->bad_body = atomic_load_explicit(&g_lk_bad, memory_order_relaxed);
  out->pending = atomic_load_explicit(&g_lk_pending, memory_order_relaxed);
  out->in_flight = atomic_load_explicit(&g_lk_inflight, memory_order_relaxed);
  out->peak = atomic_load_explicit(&g_lk_peak, memory_order_relaxed);
  out->take_fail = park_lookup_take_fails();
  out->drop_lk_room = park_cnt_get(PARK_CNT_LK_ROOM);
  out->drop_lk_timeout = park_cnt_get(PARK_CNT_LK_TIMEOUT);
  out->drop_lk_queue = park_cnt_get(PARK_CNT_LK_QUEUE);
  out->drop_lk_failed = park_cnt_get(PARK_CNT_LK_FAILED);
  out->drop_zone_room = park_cnt_get(PARK_CNT_ZONE_ROOM);
  out->drop_zone_timeout = park_cnt_get(PARK_CNT_ZONE_TIMEOUT);
  out->drop_zone_queue = park_cnt_get(PARK_CNT_ZONE_QUEUE);
  out->drop_zone_failed = park_cnt_get(PARK_CNT_ZONE_FAILED);
  out->jw_slices = atomic_load_explicit(&g_ing_jw_slices, memory_order_relaxed);
  out->fill_throttled = atomic_load_explicit(&g_fill_throttled, memory_order_relaxed);
  out->fill_stalls = atomic_load_explicit(&g_fill_stalls, memory_order_relaxed);
  out->remembered = park_shed_remembered();
  out->reask_suppressed = park_cnt_get(PARK_CNT_LK_REMEMBERED);
  out->remember_releases = park_shed_releases();
  out->drain_passes = atomic_load_explicit(&g_fp_passes, memory_order_relaxed);
  out->drain_cut = atomic_load_explicit(&g_fp_cut, memory_order_relaxed);
  out->drain_pass_max = atomic_load_explicit(&g_fp_max_n, memory_order_relaxed);
  out->drain_pass_max_ns = atomic_load_explicit(&g_fp_max_ns, memory_order_relaxed);
  out->max_ns = atomic_load_explicit(&g_lk_max_ns, memory_order_relaxed);
  for (int i = 0; i < STORE_STATUS_HIST_BUCKETS; i++) out->hist[i] = atomic_load_explicit(&g_lk_hist[i], memory_order_relaxed);
  return true;
}
#define ING_BUSY_WINDOW_NS 10000000000LL
static _Atomic bool g_ma_event;                            /* 0.7 P-F: a start or a full load ended: the cache thread says what the database needs in memory (ma_tick()) */
static _Atomic bool g_ma_loaded;                           /* 0.7 P-F: the first full load has ended: before it the registry holds only part of the zones, and an estimate from them would name a wrong count */
static void fq_hist_add(int64_t ms) {
  int b = ms <= 1 ? 0 : ms <= 10 ? 1 : ms <= 100 ? 2 : ms <= 1000 ? 3 : 4;
  atomic_fetch_add_explicit(&g_fq_hist[b], 1, memory_order_relaxed);
}
static int64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
static _Atomic uint32_t g_xfr_timeout_ms = KARIDNS_DB_XFR_FETCH_TIMEOUT_DEFAULT;   /* database { transfer-fetch-timeout } */
static _Atomic uint64_t g_apex_asked, g_apex_answered, g_apex_walks;   /* D1a step 6: summaries asked for (for the apex of a zone out of memory, after a reload) / their fetches that ended */
static _Atomic uint32_t g_warm_n;                         /* the length of the list of zones to read (g->nwarm, for dbstatus) */
static _Atomic bool g_apex_walking;                       /* ... and the walk over the registry that finds the zones is still going */

/* D1a step 7 (design 8.4): the warm-up from the hot list and the state file, as dbstatus shows them */
#define ING_EVT_HOT 4                                   /* EVFILT_USER ident: the cache thread has a hot list for the ingest thread to send */
static _Atomic(kdb_hotl_t *) g_hot_out;                 /* the hot list the cache thread made, for the ingest thread (one slot; a newer list replaces it) */
static _Atomic uint64_t g_wl_queued, g_wl_loaded, g_wl_failed, g_wl_dropmem;     /* hot-list zones put in the warm list / read / not read (fetch failed) / dropped at the high water mark */
static _Atomic uint32_t g_wl_pending, g_wl_flight;      /* ... in the warm list now / being read now */
static _Atomic bool g_wl_received;                      /* this loader session's WARM_LIST is complete */
static _Atomic int g_sf_fstate = -1;                    /* what the loader found in its state file at its start (KDB_HF_*), -1 = it has not said */
static _Atomic uint32_t g_sf_fzones;
static _Atomic uint64_t g_hot_sent, g_hot_acks[KDB_HA_N];
static _Atomic uint32_t g_hot_last_n, g_hot_last_zones;
static _Atomic int g_hot_last_status = -1;
static _Atomic int64_t g_hot_last_sent;
/* warm-before-serve: the workers do not read their sockets before this time (CLOCK_MONOTONIC ms; 0 = no wait) unless the warm-up is done */
static _Atomic int64_t g_hold_deadline_ms;
static _Atomic bool g_warm_done;
static _Atomic int64_t g_warm_done_ms;                  /* how long the wait took (ms), for dbstatus */

static int64_t delta_interval_ms(void) { return dbreg_cache_limit() ? ING_DELTA_LIMITED_MS : ING_DELTA_MS; }

static void maybe_apply_delta(ing_t *g) {
  /* the garbage of summaries past its bound is published at once, not at the pace of the delta interval */
  if (dbreg_pending_count() > 0 && ((dbreg_garbage_due() && !g->delta_failed) || now_ms() - g->last_delta_ms >= delta_interval_ms())) apply_delta(g);
}

static void drain_results(ing_t *g) {
  ing_job_t *list = atomic_exchange_explicit(&g->res_head, NULL, memory_order_acquire);
  while (list) {
    ing_job_t *j = list;
    list = j->next;
    g->inflight--;
    g->flight[j->builder] = NULL;
    job_finish(g, j);
  }
  retire_if_due(g, false);
  maybe_apply_delta(g);
}

/* block until a builder reports a result (or a second has passed) */
static void wait_for_result(ing_t *g) {
  struct kevent ev;
  struct timespec ts = { 1, 0 };
  (void)kevent(g->wait_kq, NULL, 0, &ev, 1, &ts);
  drain_results(g);
}

static void drain_all(ing_t *g) {
  drain_results(g);
  while (g->inflight > 0) wait_for_result(g);
}

/* Everything in flight is done and published, the new zones are visible and the old versions are being reclaimed */
static void sync_all(ing_t *g) {
  drain_all(g);
  apply_delta(g);
  retire_if_due(g, true);
}

/* a zone of this name (in this view) is with a builder, or its result has not been taken yet */
static bool name_in_flight_by_name(const ing_t *g, const char *view_name, const char *zone) {
  for (uint32_t i = 0; i < g->nbuilders; i++) {
    const ing_job_t *j = g->flight[i];
    if (j && strcmp(j->view_name, view_name) == 0 && domain_names_match_ci(j->zone, zone)) return true;
  }
  return false;
}

/* the zones of this name that are in flight are finished (the others keep running): a ZONE_FAILED or ZONE_DELETE of it must not race on its record */
static void drain_name(ing_t *g, const char *view_name, const char *zone) {
  drain_results(g);
  while (name_in_flight_by_name(g, view_name, zone)) wait_for_result(g);
}

static bool name_in_flight(ing_t *g, const ing_job_t *me) {
  /* in-flight zones of the same name must finish first: two builders would race on one registry record */
  for (uint32_t i = 0; i < g->nbuilders; i++) {
    const ing_job_t *j = g->flight[i];
    if (j && j->view == me->view && domain_names_match_ci(j->zone, me->zone)) return true;
  }
  return false;
}

/* hand a complete zone over (or build it here) */
static void job_submit(ing_t *g, ing_job_t *j) {
  if (g->nbuilders == 0 || j->skip) {
    while (name_in_flight(g, j)) wait_for_result(g);      /* (a skip job runs here: a zone of the same name may still be in a builder) */
    job_execute(j);
    job_finish(g, j);
    retire_if_due(g, false);
    maybe_apply_delta(g);
    return;
  }
  for (;;) {
    int free_b = -1;
    for (uint32_t i = 0; i < g->nbuilders; i++) {
      if (!g->flight[i]) {
        free_b = (int)i;
        break;
      }
    }
    /* a finished job stays "same name in flight" until its result was taken */
    if (free_b >= 0 && !name_in_flight(g, j)) {
      ing_builder_t *b = &g->builders[free_b];
      j->builder = free_b;
      g->flight[free_b] = j;
      atomic_store_explicit(&b->slot, j, memory_order_release);
      g->inflight++;
      struct kevent t;
      EV_SET(&t, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
      (void)kevent(b->kq, &t, 1, NULL, 0, NULL);
      return;
    }
    wait_for_result(g);
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* messages                                                                                                       */
/* ------------------------------------------------------------------------------------------------------------- */

static void protocol_error(ing_t *g, const char *reason);

static void clear_profiles(ing_t *g) {
  for (size_t i = 0; i < g->nprof; i++) free(g->profiles[i].text);
  g->nprof = 0;
  g->prof_bytes = 0;
}

/* PROFILE (design 1.4): name and settings text, valid for the zones that follow in this batch.  The state machine has
 * checked the characters and the lengths; the Backend bounds what it holds (a hostile loader cannot make it keep more). */
enum { PROF_OK = 0, PROF_LIMIT, PROF_OOM };

static int profile_store(ing_t *g, const kdb_msg_t *m) {
  const kdb_profile_t *p = &m->u.profile;
  size_t i;
  for (i = 0; i < g->nprof; i++)
    if (strlen(g->profiles[i].name) == p->name.len && memcmp(g->profiles[i].name, p->name.p, p->name.len) == 0) break;
  size_t old = i < g->nprof ? g->profiles[i].len : 0;
  if (g->prof_bytes - old + p->settings.len > ING_PROFILE_BYTES || (i == g->nprof && g->nprof >= ING_MAX_PROFILES)) return PROF_LIMIT;
  char *copy = malloc(p->settings.len + 1);
  if (!copy) return PROF_OOM;
  memcpy(copy, p->settings.p, p->settings.len);
  copy[p->settings.len] = '\0';
  if (i == g->nprof) {
    if (g->nprof == g->cprof) {
      size_t nc = g->cprof ? g->cprof * 2 : 16;
      ing_profile_t *np = realloc(g->profiles, nc * sizeof(*np));
      if (!np) {
        free(copy);
        return PROF_OOM;
      }
      g->profiles = np;
      g->cprof = nc;
    }
    memcpy(g->profiles[i].name, p->name.p, p->name.len);
    g->profiles[i].name[p->name.len] = '\0';
    g->nprof++;
  } else {
    free(g->profiles[i].text);
    g->prof_bytes -= old;
  }
  g->profiles[i].text = copy;
  g->profiles[i].len = p->settings.len;
  g->prof_bytes += p->settings.len;
  return PROF_OK;
}

static void on_profile(ing_t *g, const kdb_msg_t *m) {
  int rc = profile_store(g, m);
  if (rc == PROF_LIMIT) {
    protocol_error(g, "PROFILE: more profile data in a batch than the Backend accepts");
  } else if (rc == PROF_OOM) {
    syslog(LOG_ERR, "[DB] out of memory; closing the stream");
    drop_stream(g);
  }
}

static void fail_requests(ing_t *g, const char *why) {
  for (int i = 0; i < ING_REQ_MAX; i++) {
    if (!g->reqs[i].active) continue;
    int grp = g->reqs[i].grp;
    if (grp < 0) {
      post_result(g->reqs[i].id, false, "zone %s (view %s): %s", g->reqs[i].zone, g->reqs[i].view_name, why);
    } else if (g->grps[grp].active) {          /* one answer for the group, under the id the control thread knows */
      post_result(g->grps[grp].ctl_id, false, "zone %s: %s", g->grps[grp].zone, why);
      g->grps[grp].active = false;
    }
    g->reqs[i].active = false;
  }
  g->cur_req = -1;
}

static void drop_stream(ing_t *g) {
  fail_requests(g, "the connection to the database loader was lost; the reload may or may not have been applied");
  if (g->stream_fd >= 0) close(g->stream_fd); /* the kqueue forgets the descriptor */
  g->stream_fd = -1;
  g->write_armed = false;
  g->out_len = g->out_off = 0;
  g->sresume = false;
  g->hello_done = false;
  atomic_store_explicit(&g_lookup_on, false, memory_order_release);      /* (a new loader says again whether it looks names up) */
  g->inv_active = false;
  db_recon_abort_stream();                    /* 0.7 WP7b: a pass that was cut off sweeps nothing (the reconcile thread forgets it; what it was given and has not applied is dropped) */
  g->held_valid = false;
  g->read_off = false;
  g->defer_end = false;                       /* (the loader that waited for BATCH_RESULT is gone) */
  g->req_wait = false;
  g->need_cleanup = true;                     /* zones in flight are finished by the main loop, not from here */
  kdb_enc_reset(&g->enc);
  if (atomic_exchange_explicit(&g_st.connected, false, memory_order_relaxed))
    atomic_store_explicit(&g_st.since, (int64_t)time(NULL), memory_order_relaxed);
}

/* the stream is gone (or replaced): throw away the partial zone, let the zones in flight finish, publish them */
static void cleanup_stream_state(ing_t *g) {
  g->need_cleanup = false;
  job_free(g->cur);
  g->cur = NULL;
  g->in_batch = false;
  batch_table_end(g);
  clear_profiles(g);
  drain_all(g);
  apply_delta(g);
  retire_if_due(g, true);
}

static void send_config(ing_t *g, const char *why) {
  ing_cfg_t snap;
  if (!build_config(g, &snap)) {
    syslog(LOG_ERR, "[DB] cannot build CONFIG for the loader (no database block, or more than %d views); "
                    "closing the stream", KDB_MAX_CONFIG_VIEWS);
    drop_stream(g);
    return;
  }
  /* the state machine checks view indexes and limits against the configuration it was sent; a batch in progress keeps
   * the view count of its own CONFIG (batch_table_begin) */
  if (!g->in_batch) g->sm.lim.view_count = snap.nviews;
  g->sm.lim.max_zone_records = snap.max_zone_records;
  g->sm.lim.max_zone_bytes = snap.max_zone_bytes;
  g->fsm.lim = g->sm.lim;                  /* the fetch stream's machine checks against the same configuration */
  g->fsm.lim.view_count = snap.nviews;     /* (the newest one, also during a batch of the first stream) */
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

/* 0.7 M2: DEBUG, the level in force, when the loader has not been told it yet (after the handshake's CONFIG, and at every karictl trace /
 * notrace: db_ingest_debug_changed()).  Only between messages of this thread, the one writer of the stream. */
static void send_debug(ing_t *g) {
  int lvl = klog_debug_level();
  if (g->stream_fd < 0 || !g->hello_done || g->debug_sent == lvl) return;
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_DEBUG) != 0 || kdb_enc_u8(&g->enc, 1, (uint8_t)lvl) != 0 || kdb_enc_end(&g->enc) != 0) g->enc.err = true;
  send_enc(g);
  g->debug_sent = lvl;
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
  char ver[ST_STR], drv[48];
  sane_copy(ver, sizeof(ver), h->loader_version.p, h->loader_version.len);
  sane_copy(drv, sizeof(drv), h->driver.p, h->driver.len);
  char line[ST_STR];
  snprintf(line, sizeof(line), "%s, drivers %s", ver, drv);
  st_set_strings(NULL, line);
  atomic_store_explicit(&g_st.pid, h->pid, memory_order_relaxed);
  atomic_store_explicit(&g_st.since, (int64_t)time(NULL), memory_order_relaxed);
  atomic_store_explicit(&g_st.ever_connected, true, memory_order_relaxed);
  atomic_store_explicit(&g_st.connected, true, memory_order_relaxed);
  as_reset();
  g->hello_done = true;
  g->loader_feat = h->features;
  if (!(h->features & KDB_FEAT_STORE)) db_store_bulk_early_cancel();      /* (0.7 first-fill latency: a loader without the store protocol makes no pass: the unlogged fill begun at the start is ended, on disk) */
  scan_set(g, false);
  send_config(g, "handshake");
  atomic_store_explicit(&g_lookup_on, g->stream_fd >= 0 && g->store_proto && (h->features & KDB_FEAT_LOOKUP) != 0, memory_order_release);      /* (send_config() may have dropped the stream) */
  atomic_store_explicit(&g_lookup_hold, g->store_proto && (h->features & KDB_FEAT_LOOKUP) != 0, memory_order_release);       /* (a loader that does not look up ends the hold: the queries are refused as before) */
  g->debug_sent = -1;                                  /* 0.7 M2: a new loader learns the level in force after its CONFIG */
  send_debug(g);
  /* 0.7 signer-wait (d): the versions held for the signer before this loader (or before the server started again: the store keeps the records) keep serving until its first batch has said which
   * zones still wait, from the signer's state in the database (BATCH_END KDB_BEF_SIGNER_SET); the others are let go then */
  g->sig_carry = true;
  if (g->store_proto) db_recon_held_carry();
  else (void)dbreg_signer_carry(false);
  if (g->store_proto) {                                /* 0.7 WP7b: the records the store holds that have no body (an interrupted fill, a changed zone, a secondary zone: they are heap zones) are fetched once now (not one held for the signer, above) */
    scan_set(g, true);
    g->bg_zid = 0;
    g->bg_again = false;
    g->bg_fail = 0;
    g->bg_retry_ms = 0;
    syslog(LOG_INFO, "[DB] the store protocol is on for this loader (it lists the zones, the Backend asks for the bodies)");
  }
}

/* ---- INVENTORY: the registry, a few hundred entries at a time so the output queue never holds all of it ---- */

typedef struct {
  ing_t *g;
  uint32_t n;
  bool bad;
  const char *last_view;          /* the view of the last zone, and what the lookup of its index said */
  uint16_t last_idx;
  bool last_found;
} inv_ctx_t;

static bool inv_cb(void *ud, const char *view, const dbreg_zone_t *z) {
  inv_ctx_t *c = ud;
  ing_t *g = c->g;
  if (z->kind & ZDIR_K_STORED) return true;              /* 0.7 S3: a zone of the store is listed from the store (inv_store_pass()), in memory or not */
  bool resident = zdir_entry(z) != NULL;
  if (!z->digest || (!resident && (z->shadowed || z->source_id == 0))) return true;     /* never applied: nothing the loader could skip */
  /* B6a: a zone whose last version was refused (or could not be read) is offered again by a loader that starts now: it
   * must not find the old version "up to date" and leave the error standing when the data are fixed */
  if (z->last_result == DBREG_REJECTED) return true;
  if (!c->last_view || (c->last_view != view && strcmp(c->last_view, view) != 0)) {      /* (the walk goes view by view: the lookup is cached) */
    c->last_found = false;
    for (uint32_t i = 0; i < g->nview_names; i++) {
      if (strcasecmp(g->view_names[i], view) == 0) {
        c->last_idx = (uint16_t)i;
        c->last_found = true;
        break;
      }
    }
    c->last_view = view;
  }
  if (!c->last_found) return true;                       /* a view that left the configuration */
  const uint16_t idx = c->last_idx;
  if (c->n >= ING_INV_CHUNK) return false;
  if (kdb_enc_nest_begin(&g->enc, 1) != 0 || kdb_enc_u16(&g->enc, 1, idx) != 0 || kdb_enc_name(&g->enc, 2, z->name) != 0 ||
      kdb_enc_i64(&g->enc, 3, z->source_id) != 0 || kdb_enc_u32(&g->enc, 4, zdir_serial(z)) != 0 ||
      (resident && kdb_enc_bytes(&g->enc, 5, z->digest, KDB_DIGEST_LEN) != 0) || kdb_enc_u8(&g->enc, 6, resident ? 1 : 0) != 0 ||
      kdb_enc_nest_end(&g->enc) != 0) {
    c->bad = true;
    return false;
  }
  c->n++;
  return true;
}

/* 0.7 S3: the zones of the store, a chunk at a time by zone id (no walk of anything that grows with the zones in the heap).  A zone with an image is listed as in memory,
 * with its digest: the loader leaves it alone when the database has the same version.  A zone whose last version was refused (STORE_F_REJECTED_NEW) is not listed, as the
 * registry's elements of such zones are not: a loader that starts now offers it again.  true: the end of the store. */
static bool inv_store_pass(ing_t *g, inv_ctx_t *c) {
  store_t *st = db_store_handle();
  if (!st) return true;
  bool end = true;
  store_read_lock();
  store_zone_t z;
  for (;;) {
    if (c->n >= ING_INV_CHUNK) {
      end = false;
      break;
    }
    int more = store_iter(st, &g->inv_zid, &z);
    if (more == 0) break;
    if (more < 0 || (z.flags & STORE_F_REJECTED_NEW) || (z.state != STORE_STATE_STORED && z.state != STORE_STATE_KNOWN)) continue;
    if ((z.flags & STORE_F_XFR) || (int)z.view == xfr_store_vid()) continue;     /* (0.7, W6: the secondaries' copies are not the loader's zones; explicit, not only because the view is not configured) */
    const char *vn = store_view_name(st, z.view);
    int idx = -1;
    for (uint32_t i = 0; vn && i < g->nview_names; i++) {
      if (strcasecmp(g->view_names[i], vn) == 0) {
        idx = (int)i;
        break;
      }
    }
    if (idx < 0) continue;                               /* a view that left the configuration */
    char zn[STORE_NAME_MAX + 2];
    snprintf(zn, sizeof(zn), "%s.", z.name);
    const bool resident = z.state == STORE_STATE_STORED;
    if (kdb_enc_nest_begin(&g->enc, 1) != 0 || kdb_enc_u16(&g->enc, 1, (uint16_t)idx) != 0 || kdb_enc_name(&g->enc, 2, zn) != 0 ||
        kdb_enc_i64(&g->enc, 3, z.source_id) != 0 || kdb_enc_u32(&g->enc, 4, z.serial) != 0 ||
        (resident && kdb_enc_bytes(&g->enc, 5, z.digest, KDB_DIGEST_LEN) != 0) || kdb_enc_u8(&g->enc, 6, resident ? 1 : 0) != 0 || kdb_enc_nest_end(&g->enc) != 0) {
      c->bad = true;
      break;
    }
    c->n++;
  }
  store_read_unlock();
  return end;
}

static void pump_inventory(ing_t *g) {
  burst_yield_t by = BURST_YIELD_INIT;
  while (g->inv_active && g->stream_fd >= 0 && g->out_len - g->out_off < ING_INV_QUEUE_LOW) {
    burst_yield_check(&by);                /* a million zones are read in chunks; the pinned worker on this CPU gets its turns */
    inv_ctx_t c = { .g = g };
    kdb_enc_reset(&g->enc);
    if (kdb_enc_begin(&g->enc, KDB_T_INVENTORY) != 0) {
      send_enc(g);
      return;
    }
    bool done = true;
    if (!g->inv_store) {
      done = dbreg_walk(&g->inv_cur, inv_cb, &c);
      if (done) g->inv_store = true;
    }
    if (done && dbdir()) done = inv_store_pass(g, &c);
    if (c.bad || kdb_enc_end(&g->enc) != 0) {
      g->enc.err = true;
      send_enc(g);
      return;
    }
    if (c.n > 0) {
      g->inv_sent += c.n;
      send_enc(g);
    } else {
      kdb_enc_reset(&g->enc);
    }
    if (done) {
      g->inv_active = false;
      if (g->stream_fd < 0) return;
      kdb_enc_reset(&g->enc);
      if (kdb_enc_begin(&g->enc, KDB_T_INVENTORY_END) != 0 ||
          kdb_enc_u64(&g->enc, 1, atomic_load_explicit(&g_last_change_seq, memory_order_relaxed)) != 0 ||
          kdb_enc_u64(&g->enc, 2, g->inv_sent) != 0 || kdb_enc_end(&g->enc) != 0)
        g->enc.err = true;
      send_enc(g);
      syslog(LOG_INFO, "[DB] loader asked for the inventory: sent %llu zone(s)", (unsigned long long)g->inv_sent);
    }
  }
}

static void protocol_error(ing_t *g, const char *reason);
static void on_inventory_req(ing_t *g) {
  if (g->store_proto) {                                /* 0.7 WP7b: the store protocol has no inventory (the loader keeps no table of the zones) */
    protocol_error(g, "INVENTORY_REQ with the store protocol on");
    return;
  }
  g->inv_active = true;
  memset(&g->inv_cur, 0, sizeof(g->inv_cur));
  g->inv_sent = 0;
  g->inv_zid = 0;
  g->inv_store = false;
  pump_inventory(g);
}

static const char *kind_name(int k) {
  static const char *const n[] = { "startup", "full", "diff", "zone", "auto" };
  return k >= 0 && k < 5 ? n[k] : "?";
}

static void on_batch_begin(ing_t *g, const kdb_msg_t *m) {
  drain_all(g);
  g->in_batch = true;
  g->batch_id = m->u.batch_begin.batch_id;
  batch_table_begin(g, m->u.batch_begin.cfg_generation);
  g->batch_kind = m->u.batch_begin.kind;
  g->b_applied = g->b_rejected = g->b_shadowed = g->b_deleted = g->b_failed = g->b_unchanged = 0;
  g->b_store_err = 0;
  g->ch_failed = false;
  clear_profiles(g);                                     /* B7a: the profiles of the previous batch */
  g->rejects_logged = 0;
  g->shadows_logged = 0;
  if (m->u.batch_begin.change_seq != 0)                  /* a one-zone batch does not read the log */
    atomic_store_explicit(&g_last_change_seq, m->u.batch_begin.change_seq, memory_order_relaxed);
  g->cur_req = -1;
  g->req_outcome = ROUT_NONE;
  g->req_reason[0] = '\0';
  if (m->u.batch_begin.request_id != 0) {
    for (int i = 0; i < ING_REQ_MAX; i++)
      if (g->reqs[i].active && g->reqs[i].id == m->u.batch_begin.request_id) g->cur_req = i;
  }
  g->batch_force = m->u.batch_begin.request_id != 0 && (m->u.batch_begin.request_id == g->all_force_id || (g->cur_req >= 0 && g->reqs[g->cur_req].force));
  atomic_store_explicit(&g_st.batch_id, g->batch_id, memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_kind, g->batch_kind, memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_done, false, memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_time, (int64_t)time(NULL), memory_order_relaxed);
  g->last_delta_ms = now_ms();
}

/* D1a step 5 (design 3.3, 8.3): is this zone of a batch left out of memory?  Only with memory-limit, only when the database zones are above the
 * high mark of the limit with this zone counted (about 160 bytes a record, what the declared record count says), and not for a zone that was asked
 * for (a fetch), one that is in memory (its update is installed), one that is pinned, or one in a view that does not take database zones. */
static bool cache_wants_cold(const ing_job_t *j) {
  if (dbdir()) return false;                          /* 0.7 S3: the zone store is the directory: a zone is sent whole and goes to the store, whether it is kept in memory is decided when it is registered */
  if (!dbreg_cache_limit() || j->fetch_id || (j->shared && j->shared->ext.cache_mode == 1)) return false;
  if (dbreg_lookup_entry(j->view_name, j->zone)) return false;
  return dbreg_cache_over_high((uint64_t)j->rr_count * 160u);
}

/* D1a step 6 (design 12-12): does the summary of a fetch keep its apex?  The same predicate as for the summary of a batch (dbreg_apex_wanted()), with the
 * settings the registry kept for the zone: the summary of a fetch carries none. */
static bool apex_wanted_registry(const char *view, const char *zone, bool *naddr) {
  zone_ext_shared_t *sh = dbreg_settings_ref(view, zone);
  bool wanted = dbreg_apex_wanted(view, zone, sh);
  *naddr = wanted && dbreg_apex_notify_ns_wanted(view, zone, sh);
  zone_ext_shared_unref(sh);
  return wanted;
}

/* The apex block of a summary: the names as wire names (RFC 1035 3.1), the TTLs as they are.  The loader is not trusted: the stream layer has checked the
 * names and the TTLs (dns_db_stream.c), the conversion checks them again (a label over 63 octets or a name over 255 fails).  NULL: none, or out of memory
 * (then the SOA question reads the zone). */
static zdir_apex_t *apex_from_begin(const kdb_zone_begin_t *zb, bool want_naddr) {
  if (!zb->has_apex || zb->ns_count == 0 || zb->ns_count > KDB_APEX_NS_MAX) return NULL;
  uint8_t tmp[2 * 256 + KDB_APEX_NS_MAX * 256 + KDB_APEX_GLUE_BYTES + KDB_NOTIFY_ADDR_BYTES];
  uint16_t off = 0;
  uint16_t ml, rl;
  if (write_dns_name_str(tmp, &off, zb->soa_mname, NULL, sizeof(tmp)) != 0) return NULL;
  ml = off;
  if (write_dns_name_str(tmp, &off, zb->soa_rname, NULL, sizeof(tmp)) != 0) return NULL;
  rl = (uint16_t)(off - ml);
  uint16_t ns_start = off;
  unsigned n = 0;
  char nm[DNS_NAME_TEXT_SIZE];
  for (const char *p = zb->ns_names, *end = zb->ns_names + zb->ns_names_len; p <= end && n < zb->ns_count;) {
    const char *e = memchr(p, '\n', (size_t)(end - p));
    size_t l = e ? (size_t)(e - p) : (size_t)(end - p);
    if (l == 0 || l >= sizeof(nm)) return NULL;
    memcpy(nm, p, l);
    nm[l] = '\0';
    if (write_dns_name_str(tmp, &off, nm, NULL, sizeof(tmp)) != 0) return NULL;
    n++;
    p += l + 1;
  }
  if (n != zb->ns_count) return NULL;
  /* the glue: the decoder has checked it (kdb_apex_glue_valid()); the copy is bounded again, and a list longer than the block takes is no apex */
  if (zb->glue_len > KDB_APEX_GLUE_BYTES || (zb->glue_len > 0 && !kdb_apex_glue_valid(zb->glue, zb->glue_len, n))) return NULL;
  uint16_t ns_end = off;
  if (zb->glue_len) {
    /* the addresses belong to NS names that are inside the zone: the zone in memory adds nothing else to Additional from its own data.  Which names have records */
    unsigned used = 0;
    for (size_t i = 0; i < zb->glue_len; i += 6 + (zb->glue[i + 1] == 1 ? 4u : 16u)) used |= 1u << zb->glue[i];
    unsigned k = 0;
    for (const char *p = zb->ns_names, *end = zb->ns_names + zb->ns_names_len; p <= end && k < n; k++) {
      const char *e = memchr(p, '\n', (size_t)(end - p));
      size_t l = e ? (size_t)(e - p) : (size_t)(end - p);
      if (l >= sizeof(nm)) return NULL;
      memcpy(nm, p, l);
      nm[l] = '\0';
      if ((used & (1u << k)) && !domain_name_is_at_or_below(nm, zb->name)) return NULL;
      p += l + 1;
    }
    memcpy(tmp + off, zb->glue, zb->glue_len);
    off = (uint16_t)(off + zb->glue_len);
  }
  /* D1a step 7: the addresses of the NS targets outside the zone, found by the loader (tag 22), for the NOTIFY of the zone while its data is out of memory: kept
   * only for a zone that sends NOTIFY to its NS hosts.  The decoder has checked the format; the loader is not trusted, so every index must also name a target that
   * is NOT inside the zone (an address of an in-zone name is the glue's), else the list is left out (the zone still has its apex). */
  uint16_t naddr = 0;
  if (want_naddr && zb->naddrs_len > 0 && zb->naddrs_len <= KDB_NOTIFY_ADDR_BYTES && kdb_notify_addrs_valid(zb->naddrs, zb->naddrs_len, n)) {
    unsigned used = 0;
    for (size_t i = 0; i < zb->naddrs_len; i += 2 + (zb->naddrs[i + 1] == 1 ? 4u : 16u)) used |= 1u << zb->naddrs[i];
    bool ok = true;
    unsigned k = 0;
    for (const char *p = zb->ns_names, *end = zb->ns_names + zb->ns_names_len; ok && p <= end && k < n; k++) {
      const char *e = memchr(p, '\n', (size_t)(end - p));
      size_t l = e ? (size_t)(e - p) : (size_t)(end - p);
      if (l >= sizeof(nm)) return NULL;
      memcpy(nm, p, l);
      nm[l] = '\0';
      if ((used & (1u << k)) && domain_name_is_at_or_below(nm, zb->name)) ok = false;
      p += l + 1;
    }
    if (ok) {
      memcpy(tmp + off, zb->naddrs, zb->naddrs_len);
      off = (uint16_t)(off + zb->naddrs_len);
      naddr = zb->naddrs_len;
    }
  }
  zdir_apex_t *a = malloc(sizeof(*a) + off);
  if (!a) return NULL;
  a->serial = zb->serial;
  a->soa_ttl = zb->soa_ttl;
  a->refresh = zb->soa_refresh > 2147483647u ? 2147483647u : zb->soa_refresh;      /* (as dbreg_apply_summary() keeps them: the zone parser rounds a value with the top bit set down) */
  a->retry = zb->soa_retry > 2147483647u ? 2147483647u : zb->soa_retry;
  a->expire = zb->soa_expire > 2147483647u ? 2147483647u : zb->soa_expire;
  a->minimum = zb->soa_minimum;
  a->ns_ttl = zb->ns_ttl;
  a->mname_len = ml;
  a->rname_len = rl;
  a->ns_len = (uint16_t)(ns_end - ns_start);
  a->glue_len = zb->glue_len;
  a->naddr_len = naddr;
  a->n_ns = (uint8_t)n;
  memcpy(a->data, tmp, off);
  return a;
}

/* The name of view number v as the loader meant it ("" = none): a zone message of a batch reads the table of the batch's
 * CONFIG (batch_table_begin), the fetch stream the newest one (its requests name the views of the newest CONFIG). */
static const char *view_name_at(const ing_t *g, uint32_t v, bool of_batch) {
  if (of_batch && g->in_batch) return v < g->b_n ? g->b_names[v] : "";
  return v < g->nview_names ? g->view_names[v] : "";
}

/* the job of a ZONE_BEGIN (either stream), with its settings resolved; NULL: out of memory */
static ing_job_t *job_from_begin(ing_t *g, const kdb_zone_begin_t *zb, bool of_batch) {
  ing_job_t *j = calloc(1, sizeof(*j));
  if (!j) return NULL;
  j->view = zb->view;
  snprintf(j->zone, sizeof(j->zone), "%s", zb->name);
  j->source_id = zb->source_id;
  j->batch_kind = of_batch && g->in_batch ? g->batch_kind : KDB_BATCH_STARTUP;
  j->serial = zb->serial;
  j->rr_count = zb->rr_count;
  j->fetch_id = zb->request_id;
  memcpy(j->digest, zb->digest, KDB_DIGEST_LEN);
  snprintf(j->view_name, sizeof(j->view_name), "%s", view_name_at(g, zb->view, of_batch));
  if (j->view_name[0] == '\0') {
    j->skip = true;
    job_reject(j, "the view is not in the configuration");
  } else if ((zb->flags & KDB_ZF_SUMMARY) && j->fetch_id) {
    j->summary = true;                                   /* D1a: a primary's summary: no settings, no data (the state machine checked) */
    j->has_timers = zb->has_soa_timers;
    j->t_refresh = zb->soa_refresh;
    j->t_retry = zb->soa_retry;
    j->t_expire = zb->soa_expire;
    bool want_naddr = false;
    if (zb->has_apex && apex_wanted_registry(j->view_name, j->zone, &want_naddr)) j->apex = apex_from_begin(zb, want_naddr);
    j->no_apex = !zb->has_apex;                          /* (an apex that was not wanted is no inability: a reload can make it wanted) */
  } else if (zb->flags & KDB_ZF_SUMMARY) {
    /* D1a milestone 4 (design 3.3, 6.3): the directory entry of a zone in a batch: the loader sends the summary instead of the data for a zone that is
     * not in memory (CONFIG dir_only, which is memory-limit).  The loader is not trusted: a summary without memory-limit, or for a zone that has
     * its data here, installs nothing (job_execute()). */
    j->has_timers = zb->has_soa_timers;
    j->t_refresh = zb->soa_refresh;
    j->t_retry = zb->soa_retry;
    j->t_expire = zb->soa_expire;
    if (!dbreg_cache_limit()) {
      j->skip = true;
      job_reject(j, "a summary was sent, but memory-limit is not set");
    } else if (!resolve_zone_settings(g, j, zb)) {
      j->skip = true;
    } else if (j->shared && j->shared->ext.masters_count > 0) {
      j->skip = true;
      job_reject(j, "the settings of a primary zone name masters (masters / primaries belong to SLAVE and CONSUMER zones)");
    } else {
      j->cold = true;
      j->dir_entry = true;
      if (zb->has_apex && dbreg_apex_wanted(j->view_name, j->zone, j->shared)) j->apex = apex_from_begin(zb, dbreg_apex_notify_ns_wanted(j->view_name, j->zone, j->shared));
      j->no_apex = !zb->has_apex;
    }
  } else if (zb->zone_kind != KDB_ZK_PRIMARY && zb->flags != 0) {
    j->skip = true;                                      /* a SLAVE / CONSUMER has no data to describe */
    job_reject(j, "a secondary zone from the database carries no zone flags");
  } else if (!resolve_zone_settings(g, j, zb)) {
    j->skip = true;                                      /* job_reject() was called: the zone is rejected, its data skipped */
  } else if (zb->zone_kind != KDB_ZK_PRIMARY && (!j->shared || j->shared->ext.masters_count <= 0)) {
    j->skip = true;
    job_reject(j, "a secondary zone from the database needs masters in its settings");
  } else if (zb->zone_kind == KDB_ZK_PRIMARY && j->shared && j->shared->ext.masters_count > 0) {
    /* a profile shared with secondary zones may carry masters; a primary has nothing to transfer, and the NOTIFY check
     * (masters = who may notify) would otherwise treat it as a secondary */
    j->skip = true;
    job_reject(j, "the settings of a primary zone name masters (masters / primaries belong to SLAVE and CONSUMER zones)");
  } else if (zb->zone_kind != KDB_ZK_PRIMARY) {
    j->zkind = zb->zone_kind;                            /* no image follows (the stream rules, dns_db_stream.c): ZONE_END runs it */
  } else if (cache_wants_cold(j)) {
    j->cold = true;                                      /* nothing is built; the data that follows is discarded (job_feed()) */
  } else {
    /* 0.7 M3: the data is a zone image (the state machine requires it): job_image() collects it, job_execute() checks it */
    j->zflags = zb->flags;
    j->img_size = zb->image_size;
    const kdb_limits_t *lim = of_batch ? &g->sm.lim : &g->fsm.lim;
    j->lim_bytes = lim->max_zone_bytes;
    j->lim_records = lim->max_zone_records;
  }
  return j;
}

static void on_zone_begin(ing_t *g, const kdb_msg_t *m) {
  ing_job_t *j = job_from_begin(g, &m->u.zone_begin, true);
  if (!j) {
    syslog(LOG_ERR, "[DB] out of memory; closing the stream");
    drop_stream(g);
    return;
  }
  g->cur = j;
}

/* ZONE_IMAGE of the zone j (either stream): the octets are appended to the image.  The announced size (ZONE_BEGIN image_size) is what the image must be (zone_image_validate_ex() refuses any other length) and is at most
 * max-zone-bytes (the state machine: dns_db_stream.c), so the buffer is allocated once with that size, with the first piece: no doubling that copies the image again and holds up to three times its size meanwhile.  A
 * loader that announces the most and sends a kilobyte holds the address space of one zone for as long as the stream's zone lasts (an allocation that nothing has touched is not memory), and a job is a zone of
 * one stream at a time. */
static void job_image(ing_job_t *j, const kdb_msg_t *m) {
  if (!j || j->skip || j->failed || j->cold) return;
  const int rc = zone_image_asm_add(&j->img, &j->img_len, &j->img_cap, j->img_size, m->u.zone_image.body, m->u.zone_image.len);      /* (the harness of tests/fuzz/fuzz_db_image_frames.c runs the same function) */
  if (rc == -1) {                                        /* (the state machine refuses it: a job that is not an image zone, or more octets than announced) */
    j->failed = true;
    snprintf(j->reason, sizeof(j->reason), "zone image data that was not announced");
  } else if (rc != 0) {
    j->failed = true;
    snprintf(j->reason, sizeof(j->reason), "out of memory");
  }
}

static void on_zone_image(ing_t *g, const kdb_msg_t *m) { job_image(g->cur, m); }

static void on_zone_end(ing_t *g) {
  ing_job_t *j = g->cur;
  g->cur = NULL;
  if (j) job_submit(g, j);
}

static void on_zone_failed(ing_t *g, const kdb_msg_t *m) {
  const kdb_zone_failed_t *zf = &m->u.zone_failed;
  char reason[KDB_REASON_LEN];
  sane_copy(reason, sizeof(reason), zf->reason.p, zf->reason.len);
  g->b_failed++;
  atomic_fetch_add_explicit(&g_st.tot_failed, 1, memory_order_relaxed);
  syslog(LOG_WARNING, "[DB] the loader could not read zone '%s' (view %u, id %lld): %s", zf->name,
         (unsigned)zf->view, (long long)zf->source_id, reason);
  const char *vname = view_name_at(g, zf->view, true);
  if (vname[0]) {
    /* a zone of the same name in flight must be finished first (it would race on the record) */
    drain_name(g, vname, zf->name);
    (void)dbreg_reject(vname, zf->name, zf->source_id, reason);
  }
  if (g->cur_req >= 0 && g->reqs[g->cur_req].view == zf->view && domain_names_match_ci(g->reqs[g->cur_req].zone, zf->name)) {
    g->req_outcome = ROUT_FAILED;
    snprintf(g->req_reason, sizeof(g->req_reason), "%s", reason);
  }
}

static void on_zone_delete(ing_t *g, const kdb_msg_t *m) {
  const kdb_zone_delete_t *zd = &m->u.zone_delete;
  uint8_t st = KDB_ST_UNCHANGED;
  const char *vname = view_name_at(g, zd->view, true);
  if (vname[0]) {
    drain_name(g, vname, zd->name);                      /* a zone of the same name may be in flight */
    int r = dbreg_delete(vname, zd->name, zd->source_id);
    if (r > 0) {
      st = KDB_ST_DELETED;
      if (g->cur_req >= 0 && g->reqs[g->cur_req].view == zd->view && domain_names_match_ci(g->reqs[g->cur_req].zone, zd->name))
        g->req_outcome = ROUT_DELETED;
      g->b_deleted++;
      atomic_fetch_add_explicit(&g_st.tot_deleted, 1, memory_order_relaxed);
      syslog(LOG_INFO, "[DB] zone '%s' (view '%s') deleted", zd->name, vname);
    } else if (r == 0) {
      syslog(LOG_NOTICE, "[DB] delete of zone '%s' (view %u, id %lld) ignored: not registered with that id",
             zd->name, (unsigned)zd->view, (long long)zd->source_id);
    } else {
      syslog(LOG_ERR, "[DB] zone '%s' (view '%s') could not be deleted from the store; it stays", zd->name, vname);
    }
  }
  send_zone_result(g, zd->view, zd->name, st, NULL);
}

/* the answer to the loader: BATCH_RESULT (the entries are recorded in the store; the bodies are not waited for, except that of a one-zone reload) */
static void batch_finish(ing_t *g, uint64_t batch_id) {
  g->defer_end = false;
  answer_request(g);
  g->in_batch = false;
  batch_table_end(g);
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_BATCH_RESULT) != 0 || kdb_enc_u64(&g->enc, 1, batch_id) != 0 ||
      kdb_enc_u32(&g->enc, 3, g->b_applied + g->b_shadowed) != 0 || kdb_enc_u32(&g->enc, 4, g->b_unchanged) != 0 ||
      kdb_enc_u32(&g->enc, 5, g->b_rejected) != 0 || kdb_enc_u32(&g->enc, 6, g->b_deleted) != 0 ||
      (g->b_store_err && (g->loader_feat & KDB_FEAT_BATCH_STATUS) && kdb_enc_u32(&g->enc, 7, (uint32_t)g->b_store_err) != 0) ||    /* (0.7: the store could not record it: the loader does not go past it) */
      kdb_enc_end(&g->enc) != 0) {
    g->enc.err = true;
  }
  send_enc(g);
}

static void bulk_kick(ing_t *g);

/* 0.7 signer-wait (d): the loader's batch said which zones still wait for the signer (BATCH_END KDB_BEF_SIGNER_SET, its first after a start): the holds of before its HELLO that it said again
 * keep their signed version serving, the others are let go (the store's scan asks for their bodies; without the store the version in memory may leave it, and the next fetch reads the zone) */
static void signer_carry_end(ing_t *g) {
  g->sig_carry = false;
  if (g->store_proto) {
    const size_t kept = db_recon_held_carry_end();
    bulk_kick(g);
    if (kept)
      syslog(LOG_WARNING, "[DB] signer-wait: %zu zone(s) still wait for karidns-signer after the start (the database has a version the signer has not signed); their signed version keeps "
                          "serving until the signer has signed them (`karictl dbstatus` lists them)", kept);
  } else {
    const size_t gone = dbreg_signer_carry(true);
    if (gone) syslog(LOG_INFO, "[DB] signer-wait: %zu zone(s) held for the signer before the loader started again do not wait any more", gone);
  }
}

/* 0.7 signer-wait without the store protocol (ZONE_HOLD): the loader holds a zone back for the signer, lets it go, or sends it as it is although it waits.  The loader is not trusted: the zone must
 * be the one of that id in the registry (dbreg_signer_mark()), and what it can do is keep a version that is served now (as a pinned zone) or make the Backend say something, rate-limited. */
static void on_zone_hold(ing_t *g, const kdb_msg_t *m) {
  const kdb_zone_hold_t *h = &m->u.zone_hold;
  if (g->store_proto) {
    protocol_error(g, "ZONE_HOLD with the store protocol on");
    return;
  }
  const char *vname = view_name_at(g, h->view, true);
  if (!vname[0]) return;
  if (h->state == KDB_HOLD_UNSIGNED) {                     /* (a zone the Backend has no version of: it is read as it is) */
    db_signer_unsigned_note(vname, h->name);
    return;
  }
  const int r = dbreg_signer_mark(vname, h->name, h->source_id, h->state == KDB_HOLD_KEEP);
  if (r & (ZDIR_SIG_MEM | ZDIR_SIG_UNSIGNED)) db_signer_count((r & ZDIR_SIG_MEM) != 0, (r & ZDIR_SIG_OLD) != 0);
}

static void on_batch_end(ing_t *g, const kdb_msg_t *m) {
  const kdb_batch_end_t *b = &m->u.batch_end;
  sync_all(g);
  const int sr = db_store_batch_end();                   /* 0.7 store S2: what the batch wrote to the store is made durable (after sync_all(): the reconcile thread's records are in it) */
  g->b_store_err = sr < 0 ? -sr : 0;
  if (sr < 0 && !(g->loader_feat & KDB_FEAT_BATCH_STATUS))
    syslog(LOG_ERR, "[DB] batch %llu: the store could not record it (%s) and the loader cannot be told (it does not read BATCH_RESULT tag 7): it is read again only after a restart",
           (unsigned long long)b->batch_id, strerror(-sr));
  atomic_store_explicit(&g_st.b_applied, g->b_applied, memory_order_relaxed);
  atomic_store_explicit(&g_st.b_rejected, g->b_rejected, memory_order_relaxed);
  atomic_store_explicit(&g_st.b_shadowed, g->b_shadowed, memory_order_relaxed);
  atomic_store_explicit(&g_st.b_deleted, g->b_deleted, memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_time, (int64_t)time(NULL), memory_order_relaxed);
  atomic_store_explicit(&g_st.batch_done, true, memory_order_relaxed);
  if (g->batch_kind == KDB_BATCH_AUTO) atomic_fetch_add_explicit(&g_st.tot_auto_batches, 1, memory_order_relaxed);
  syslog(LOG_INFO, "[DB] batch %llu complete: %u zone(s) received (%u installed, %u hidden by karidns.conf, %u rejected), "
                   "%u failed in the loader, %u deleted",
         (unsigned long long)b->batch_id, b->n_zones, g->b_applied, g->b_shadowed, g->b_rejected, b->n_failed,
         g->b_deleted);
  if (g->b_shadowed > g->shadows_logged)
    syslog(LOG_WARNING, "[DB] batch %llu: %u more zone(s) are loaded but hidden by a zone in karidns.conf or a catalog member (not logged one by one; "
                        "see `karictl dbstatus`)", (unsigned long long)b->batch_id, g->b_shadowed - g->shadows_logged);
  if (g->batch_kind == KDB_BATCH_STARTUP) {
    /* the loader may have sent nothing (a restarted loader finds the Backend up to date): count the registry */
    size_t total, rej, shc, shk;
    dbreg_counts2(&total, &rej, &shc, &shk);                 /* (with the store: the zones of the heap directory and the store's records that are not secondary or catalog zones) */
    if (g->store_proto) {
      db_recon_status_t rs;
      db_recon_status(&rs);
      syslog(LOG_INFO, "[DB] initial load complete: %zu zone(s) served from the database (%llu of them still without a body: fetched in the background, or when a query asks for it)", total, (unsigned long long)rs.known_now);
    } else {
      syslog(LOG_INFO, "[DB] initial load complete: %zu zone(s) served from the database", total);
    }
  }
  if ((b->flags & KDB_BEF_SIGNER_SET) && g->sig_carry) signer_carry_end(g);
  if (g->batch_kind == KDB_BATCH_STARTUP || g->batch_kind == KDB_BATCH_FULL) {
    atomic_store_explicit(&g_ma_loaded, true, memory_order_relaxed);
    atomic_store_explicit(&g_ma_event, true, memory_order_relaxed);        /* 0.7 P-F: the cache thread says what the database needs */
  }
  if (g->req_wait) {                                     /* 0.7 WP7b: a reload of one zone: the body is being fetched, and the answer says what became of it: the loader (it waits for BATCH_RESULT) and the request wait for it */
    g->defer_end = true;
    g->defer_batch = b->batch_id;
    g->defer_ms = now_ms();
    return;
  }
  batch_finish(g, b->batch_id);
}

/* B9: the loader's report on auto reload, one entry per view that has it on */
static void on_auto_status(const kdb_msg_t *m) {
  kdb_iter_t it;
  kdb_auto_status_entry_t e;
  kdb_auto_status_entries(m, &it);
  while (kdb_auto_status_entries_next(&it, &e)) {
    if (e.view >= KARIDNS_DB_MAX_VIEWS) continue;
    as_data_t d;
    memset(&d, 0, sizeof(d));
    d.last_poll = (int64_t)e.last_poll;
    d.applied_seq = e.applied_seq;
    d.pending = e.pending;
    d.flags = e.flags;
    d.req_generation = e.req_generation;
    d.req_ok = e.req_ok;
    d.req_time = (int64_t)e.req_time;
    d.sig_wait = e.sig_wait;
    as_set(&g_as[e.view], &d, e.error.p, e.error.len, e.server_id.p, e.server_id.len, e.req_error.p, e.req_error.len, e.sig_names.p, e.sig_names.len);
  }
}

/* D1a step 7: the zones of the loader's state file, hottest first (WARM_LIST, design 8.4).  The loader is not trusted: the parts must follow one another, at most
 * KDB_HOT_MAX entries in all, and a zone that is not in the directory of its view is ignored by warm_add_ex().  The zones are put in the warm list in the order
 * they come; fetch_issue() reads them with the priority "warm". */
static void on_warm_list(ing_t *g, const kdb_msg_t *m) {
  const kdb_hot_list_t *h = &m->u.hot_list;
  if (h->part == 0) {
    g->wl_open = true;
    g->wl_id = h->list_id;
    g->wl_count = 0;
    g->hot_issued = 0;
    zone_bytes_t zb;
    zone_bytes_get(ZBYTES_DB, &zb);
    g->warm_r0 = zb.resident;
    g->warm_l0 = atomic_load_explicit(&g_wl_loaded, memory_order_relaxed);
  } else if (!g->wl_open || h->list_id != g->wl_id || h->part != g->wl_next) {
    g->wl_open = false;
    syslog(LOG_WARNING, "[DB] a WARM_LIST part does not follow the one before; the list is ignored");
    return;
  }
  g->wl_next = h->part + 1;
  if (h->file_state >= 0) {
    atomic_store_explicit(&g_sf_fstate, h->file_state, memory_order_relaxed);
    atomic_store_explicit(&g_sf_fzones, h->file_zones, memory_order_relaxed);
  }
  kdb_iter_t it;
  char view[256], zone[DNS_NAME_TEXT_SIZE];
  kdb_hot_entries(m, &it);
  while (kdb_hot_entries_next(&it, view, zone) && g->wl_count < KDB_HOT_MAX) {
    g->wl_count++;
    warm_add_ex(g, view, zone, true, true);
  }
  if (h->last) {
    g->wl_open = false;
    atomic_store_explicit(&g_wl_received, true, memory_order_release);
    syslog(LOG_INFO, "[DB] warm-up: %u zone(s) of the hot list received from the loader, %u queued to read", g->wl_count, g->nhot);
  }
}

static void on_hot_ack(const kdb_msg_t *m) {
  const kdb_hot_ack_t *a = &m->u.hot_ack;
  atomic_fetch_add_explicit(&g_hot_acks[a->status < KDB_HA_N ? a->status : KDB_HA_FAILED], 1, memory_order_relaxed);
  atomic_store_explicit(&g_hot_last_status, a->status, memory_order_relaxed);
  atomic_store_explicit(&g_hot_last_zones, a->zones, memory_order_relaxed);
  if (a->status == KDB_HA_FAILED) syslog(LOG_WARNING, "[DB] the loader could not write its state file: %.*s", (int)a->error.len, a->error.p ? a->error.p : "");
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the store protocol (0.7 WP7b, store design 5.3, 5.4): the loader lists the zones, the Backend decides what it wants */
/* ------------------------------------------------------------------------------------------------------------- */

/* the background fetch of the wanted bodies has work: the scan of the store starts (or goes through the store once more when it ends) */
static void bulk_kick(ing_t *g) {
  if (!g->store_proto) return;
  if (!g->bg_on) {
    scan_set(g, true);
    g->bg_zid = 0;
    g->bg_fail = 0;
    g->bg_again = false;
    g->bg_retry_ms = 0;
    g->bg_idle_logged = false;
  } else {
    g->bg_again = true;
  }
}

/* what an entry became, in the numbers of the batch (BATCH_RESULT, dbstatus); true: a body is wanted.  The same rules for the entries of the pages of a pass, which the reconcile thread counts (db_recon_note()) */
static bool entry_note(ing_t *g, int r, const char *zone, bool *unstorable_logged) {
  dbrt_counts_t c;
  memset(&c, 0, sizeof(c));
  const bool w = db_recon_note(&c, r, zone, unstorable_logged);
  g->b_applied += c.applied;
  g->b_unchanged += c.unchanged;
  g->b_rejected += c.rejected;
  atomic_fetch_add_explicit(&g_st.tot_applied, c.tot_applied, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_st.tot_rejected, c.tot_rejected, memory_order_relaxed);
  if (c.failed) g->ch_failed = true;
  return w;
}

/* MANIFEST_BEGIN: the stream thread decoded it (it is small); the pass is applied by the reconcile thread (the pages come after it in the ring) */
static void on_manifest_begin(ing_t *g, const kdb_msg_t *m) {
  const kdb_manifest_begin_t *mb = &m->u.manifest_begin;
  if (!g->store_proto) {
    protocol_error(g, "MANIFEST_BEGIN with the store protocol off");
    return;
  }
  const char *vname = view_name_at(g, mb->view, true);
  if (!vname[0]) syslog(LOG_WARNING, "[DB] a manifest pass for view %u, which the configuration does not have; it is ignored", (unsigned)mb->view);
  db_recon_post_begin(mb->batch_id, mb->view, g->sm.lim.view_count, vname, mb->count, g->batch_force);
}

static void on_manifest_end(ing_t *g, const kdb_msg_t *m) {
  (void)g;
  db_recon_post_end(&m->u.manifest_end);
}

/* the counts of what the reconcile thread has applied (the batch's numbers, the zones the state machine counts for BATCH_END): only when it is idle, so that nothing of a stream that ended is in them */
static void recon_collect(ing_t *g) {
  dbrt_counts_t c;
  db_recon_take(&c);
  g->b_applied += c.applied;
  g->b_unchanged += c.unchanged;
  g->b_rejected += c.rejected;
  g->b_deleted += c.deleted;
  g->sm.n_zones += c.zones;
}

/* the zone a `karictl reload <zone>` asks for is being fetched now: the answer of the request waits for it (BATCH_RESULT is held, on_batch_end()) */
static void req_fetch_start(ing_t *g, uint16_t view, const char *view_name, const char *zone, int64_t sid, bool nonstore);

/* the entries of a CHANGES message that are upserts, applied in groups (db_recon_change_n(): one journal record for a group) */
#define ING_CHG_GROUP DBRT_CHUNK
static void changes_flush(ing_t *g, const kdb_changes_t *c, const char *vname, const kdb_changes_entry_t *ents, const db_recon_entry_t *re, const bool *is_req, unsigned nq, bool *wanted, bool *unst) {
  int res[ING_CHG_GROUP];
  uint32_t zid[ING_CHG_GROUP];
  if (nq == 0) return;
  db_recon_change_n(vname, re, nq, res, zid);
  for (unsigned i = 0; i < nq; i++) {
    const bool w = entry_note(g, res[i], ents[i].name, unst);
    *wanted |= w;
    if (w && is_req[i]) req_fetch_start(g, c->view, vname, ents[i].name, ents[i].source_id, ents[i].kind != KDB_ZK_PRIMARY);
    if (re[i].hold && res[i] != DBR_HELD) send_hold_result(g, c->view, ents[i].name, ents[i].source_id, w ? KDB_ST_APPLIED : KDB_ST_UNCHANGED);
  }
}

static void on_changes(ing_t *g, const kdb_msg_t *m) {
  const kdb_changes_t *c = &m->u.changes;
  if (!g->store_proto) {
    protocol_error(g, "CHANGES with the store protocol off");
    return;
  }
  const char *vname = view_name_at(g, c->view, true);
  if (!vname[0]) {
    syslog(LOG_WARNING, "[DB] changes for view %u, which the configuration does not have; they are ignored", (unsigned)c->view);
    return;
  }
  static kdb_changes_entry_t ents[ING_CHG_GROUP];          /* (the ingest thread's: the group of upserts that waits for its record) */
  static db_recon_entry_t re[ING_CHG_GROUP];
  bool is_req[ING_CHG_GROUP];
  unsigned nq = 0;
  kdb_iter_t it;
  burst_yield_t by = BURST_YIELD_INIT;
  bool wanted = false, unst = false;
  uint32_t n = 0;
  kdb_changes_entries(m, &it);
  for (;;) {
    kdb_changes_entry_t *e = &ents[nq];
    if (!kdb_changes_entries_next(&it, e)) break;
    if (e->op == KDB_CH_DELETE) {
      changes_flush(g, c, vname, ents, re, is_req, nq, &wanted, &unst);          /* (the upserts before it are recorded first: the order of the entries is the order of the effects) */
      nq = 0;
      if (e->has_name) drain_name(g, vname, e->name);        /* (a zone of the same name may be in flight) */
      const int dd = db_recon_delete(vname, e->source_id, e->has_name ? e->name : NULL);
      if (dd > 0) {
        g->b_deleted++;
        atomic_fetch_add_explicit(&g_st.tot_deleted, 1, memory_order_relaxed);
        if (g->cur_req >= 0 && g->reqs[g->cur_req].view == c->view && e->has_name && domain_names_match_ci(g->reqs[g->cur_req].zone, e->name)) g->req_outcome = ROUT_DELETED;
        logev_post(LOGC_DATABASE, 1, NULL, 0, "[DB] zone '%s' (view '%s', id %lld) deleted", e->has_name ? e->name : "?", vname, (long long)e->source_id);
      } else if (dd < 0) {                                 /* the store could not delete it: the zone stays, and the cursor is not kept, so that the delete is made again */
        g->b_rejected++;
        atomic_fetch_add_explicit(&g_st.tot_rejected, 1, memory_order_relaxed);
        g->ch_failed = true;
        syslog(LOG_ERR, "[DB] zone '%s' (view '%s', id %lld) could not be deleted from the store; it stays", e->has_name ? e->name : "?", vname, (long long)e->source_id);
      } else {
        g->b_unchanged++;
      }
      if ((++n & 1023) == 0) burst_yield_check(&by);
      continue;
    }
    db_recon_entry_t *r = &re[nq];
    memset(r, 0, sizeof(*r));
    r->source_id = e->source_id;
    r->name = e->name;
    r->kind = e->kind;
    r->stamped = e->stamped;
    r->gen = e->stamp_gen;
    r->time = e->stamp_time;
    r->has_serial = e->has_serial;
    r->serial = e->serial;
    /* the loader marks the entry of a one-zone reload FORCE; the body is read whatever the stamp says only when the operator said `force` (karictl reload <zone> force): without it the stamp decides, and
     * a zone that did not change is "unchanged" and is not read, whether or not its data is in memory */
    is_req[nq] = g->cur_req >= 0 && g->reqs[g->cur_req].view == c->view && domain_names_match_ci(g->reqs[g->cur_req].zone, e->name);
    r->force = e->force && (!is_req[nq] || g->reqs[g->cur_req].force);
    r->hold = e->hold && !r->force;                      /* (signer-wait: a zone the Backend has keeps its version, db_recon_change_n()) */
    if (++nq == ING_CHG_GROUP) {
      changes_flush(g, c, vname, ents, re, is_req, nq, &wanted, &unst);
      nq = 0;
    }
    if ((++n & 1023) == 0) burst_yield_check(&by);
  }
  changes_flush(g, c, vname, ents, re, is_req, nq, &wanted, &unst);
  if (c->last) {                                           /* the drain is complete up to this cursor, and every entry is in the store: it may be made durable */
    if (g->ch_failed) syslog(LOG_ERR, "[DB] view '%s': an entry of the changes could not be recorded; the cursor is not kept, the next start reads the changes again", vname);
    else db_recon_cursor_put(vname, c->cursor, c->ident_len ? c->ident : NULL, c->ident_len);
    g->ch_failed = false;
  }
  if (wanted) bulk_kick(g);
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
    on_batch_begin(g, m);
    break;
  case KDB_T_ZONE_BEGIN:
    on_zone_begin(g, m);
    break;
  case KDB_T_ZONE_IMAGE:
    on_zone_image(g, m);
    break;
  case KDB_T_ZONE_END:
    on_zone_end(g);
    break;
  case KDB_T_ZONE_ABORT:
    job_free(g->cur);                                    /* the loader gave the zone up: no result */
    g->cur = NULL;
    break;
  case KDB_T_ZONE_FAILED:
    on_zone_failed(g, m);
    break;
  case KDB_T_ZONE_DELETE:
    on_zone_delete(g, m);
    break;
  case KDB_T_BATCH_END:
    on_batch_end(g, m);
    break;
  case KDB_T_CHANGES:
    on_changes(g, m);
    break;
  case KDB_T_ZONE_HOLD:
    on_zone_hold(g, m);
    break;
  case KDB_T_PROFILE:
    on_profile(g, m);
    break;
  case KDB_T_AUTO_STATUS:
    on_auto_status(m);
    break;
  case KDB_T_WARM_LIST:
    on_warm_list(g, m);
    break;
  case KDB_T_HOT_ACK:
    on_hot_ack(m);
    break;
  default:
    break;
  }
}

static void protocol_error(ing_t *g, const char *reason) {
  syslog(LOG_ERR, "[DB] protocol error from the loader: %s; closing the stream", reason);
  char line[ST_STR];
  snprintf(line, sizeof(line), "%s", reason);
  st_set_strings(line, NULL);
  drop_stream(g);
}

/* 0.7 fix 8: the queries come before the fill.  A request of a worker that is waiting for the ingest thread (a zone to read from the database) is looked at once per pass of the main loop, and
 * a pass used to read and process up to 16 rounds of 64 KB of what the loader sends (a manifest pass or a flood of bodies: a few thousand entries, tens of milliseconds, with the install of a
 * body in each).  Now a pass that has run for g_ing_yield_ns and sees a request waiting leaves the rest of the frames it has for the next pass (g->sresume / fresume) and goes to the requests first. */
STATIC_TEST _Atomic int64_t g_ing_yield_ns = 1000000;      /* (a variable so that a test can make every pass yield: test_db_fetch.c) */
#define ING_YIELD_EVERY 1
static inline bool ing_yield(int64_t t0, unsigned handled) {
  if ((handled % ING_YIELD_EVERY) != 0 || mono_ns() - t0 < atomic_load_explicit(&g_ing_yield_ns, memory_order_relaxed)) return false;
  return park_fetch_pending();
}

/* the frame waits (room: for a free slot of the reconcile ring; else for the thread to have applied everything it was given); the stream is not read meanwhile, and its read event is off so that the loop does not spin on it */
static void stream_hold(ing_t *g, const kdb_frame_t *fr, bool room) {
  g->held_fr = *fr;
  g->held_valid = true;
  g->hold_room = room;
  if (room) db_recon_note_full();
  if (!g->read_off && g->stream_fd >= 0) {
    struct kevent ev;
    EV_SET(&ev, g->stream_fd, EVFILT_READ, EV_DISABLE, 0, 0, NULL);
    if (kevent(g->kq, &ev, 1, NULL, 0, NULL) == 0) g->read_off = true;
  }
}

static void recon_poll(ing_t *g);

/* A frame of the first stream.  The pages of a manifest pass are not decoded here: they are legal or not (the state of the stream), and the reconcile thread gets them, with the pass's begin and end, in a ring (0.7 M2,
 * dns_db_recon.h).  Every other frame waits until that thread has applied what it was given, then its counts are collected: the frame sees the pass whole.  A frame that has to wait is held (the stream is not
 * read); false: stop reading now (a protocol error closed the stream, or the frame is held). */
static bool stream_frame(ing_t *g, const kdb_frame_t *fr) {
  kdb_msg_t msg;
  kdb_rc_t rc;
  const uint16_t t = fr->type;
  {                                                      /* a protocol error that the reconcile thread found in a page: before any frame is handled (the thread may be idle again by now, and BATCH_END or CHANGES would commit what the stream said after the bad page) */
    char why[KDB_REASON_LEN];
    if (db_recon_error_take(why, sizeof(why))) {
      protocol_error(g, why);
      return false;
    }
  }
  if (t == KDB_T_MANIFEST || t == KDB_T_MANIFEST_BEGIN || t == KDB_T_MANIFEST_END) {
    if (!db_recon_room()) {
      stream_hold(g, fr, true);
      return false;
    }
    if (t == KDB_T_MANIFEST) {
      rc = kdb_sm_legal_frame(&g->sm, t);
      if (rc != KDB_OK) {
        protocol_error(g, g->sm.reason);
        return false;
      }
      db_recon_post_page(fr->body, fr->len, g->sm.lim.view_count);
      return true;
    }
    rc = kdb_sm_accept(&g->sm, fr, &msg);
    if (rc != KDB_OK) {
      protocol_error(g, g->sm.reason);
      return false;
    }
    if (t == KDB_T_MANIFEST_BEGIN) on_manifest_begin(g, &msg);
    else on_manifest_end(g, &msg);
    return g->stream_fd >= 0;
  }
  if (!db_recon_idle()) {
    stream_hold(g, fr, false);
    return false;
  }
  recon_collect(g);
  rc = kdb_sm_accept(&g->sm, fr, &msg);
  if (rc != KDB_OK) {
    /* the reason names the rule, never bytes of the stream */
    protocol_error(g, g->sm.reason);
    return false;
  }
  handle_msg(g, &msg);
  return g->stream_fd >= 0;
}

static void stream_pass(ing_t *g) {
  const int64_t t0 = mono_ns();
  unsigned handled = 0;
  for (int round = 0; round < ING_READ_ROUNDS && g->stream_fd >= 0; round++) {
    if (g->sresume || g->held_valid) {
      g->sresume = false;                                /* (the frames the last pass left, or the one that waits, are handled first) */
    } else {
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
      g->s_rx_ms = now_ms();
      if (kdb_framer_feed(&g->fr, g->rbuf, (size_t)n) != KDB_OK) {
        protocol_error(g, g->fr.reason);
        return;
      }
    }
    kdb_frame_t fr;
    for (;;) {
      if (g->held_valid) {
        if (!(g->hold_room ? db_recon_room() : db_recon_idle())) return;      /* (it still waits) */
        fr = g->held_fr;
        g->held_valid = false;
      } else {
        kdb_rc_t rc = kdb_framer_next(&g->fr, &fr);
        if (rc == KDB_MORE) break;
        if (rc != KDB_OK) {
          protocol_error(g, g->fr.reason);
          return;
        }
      }
      if (!stream_frame(g, &fr)) return;
      if (g->stream_fd < 0) return;
      /* (0.7 M2: a pass of the stream thread is not longer than the time slice whether or not a request waits: the pages of a manifest pass are copies, a megabyte of them is a few hundred microseconds, and
       * the fetch stream, the answers of the lookups and the bodies that wake the queries are served between the passes) */
      if (ing_yield(t0, ++handled) || mono_ns() - t0 >= atomic_load_explicit(&g_ing_yield_ns, memory_order_relaxed)) {
        g->sresume = true;
        return;
      }
    }
  }
}

static void on_stream_readable(ing_t *g) {
  const int64_t t0 = mono_ns();
  stream_pass(g);
  db_recon_note_stream(mono_ns() - t0);                 /* 0.7 M2: store.ingest.stream_max_us */
}

/* the reconcile thread has said something (EVFILT_USER ING_EVT_RECON): a protocol error it found in what the loader sent, bodies that are wanted, a free slot or an idle thread for the frame that waits */
_Atomic bool db_ingest_test_recon_poll_off;              /* tests (always compiled, as db_ingest_test_lq_max): the event of the reconcile thread does not take its error, so that the stream thread's own look at it (stream_frame()) is the only one */
static void recon_poll(ing_t *g) {
  char why[KDB_REASON_LEN];
  if (!atomic_load_explicit(&db_ingest_test_recon_poll_off, memory_order_relaxed) && db_recon_error_take(why, sizeof(why))) {
    protocol_error(g, why);
    return;
  }
  if (db_recon_wanted_take()) bulk_kick(g);
  if (g->held_valid && g->stream_fd >= 0 && (g->hold_room ? db_recon_room() : db_recon_idle())) {
    if (g->read_off) {
      struct kevent ev;
      EV_SET(&ev, g->stream_fd, EVFILT_READ, EV_ENABLE, 0, 0, NULL);
      if (kevent(g->kq, &ev, 1, NULL, 0, NULL) == 0) g->read_off = false;
    }
    on_stream_readable(g);
  }
}

/* ------------------------------------------------------------------------------------------------------------- */
/* connections                                                                                                    */
/* ------------------------------------------------------------------------------------------------------------- */

static void adopt_stream(ing_t *g, int fd) {
  if (!limit_stream_rights(fd)) {   /* at once: a received descriptor has all the rights of the sender's end */
    close(fd);
    return;
  }
  if (g->stream_fd >= 0) {
    syslog(LOG_NOTICE, "[DB] a new loader stream replaces the old one");
    drop_stream(g);
  }
  if (g->need_cleanup) cleanup_stream_state(g);
  g->stream_fd = fd;
  g->loader_feat = 0;                                  /* a new loader: its HELLO says what it can do (the lookups that wait for an answer are asked again in mode 2 until then, fetch_adopt()) */
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
  g->rejects_logged = 0;
  g->shadows_logged = 0;
  g->wl_open = false;                                    /* a new loader: its WARM_LIST is still to come */
  atomic_store_explicit(&g_wl_received, false, memory_order_release);
  g->inv_active = false;
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  kdb_limits_t lim = { snap.max_zone_records ? snap.max_zone_records : KDB_DEFAULT_MAX_ZONE_RECORDS,
                       snap.max_zone_bytes ? snap.max_zone_bytes : KDB_DEFAULT_MAX_ZONE_BYTES,
                       snap.nviews ? snap.nviews : KDB_VIEWS_ANY };
  kdb_framer_init(&g->fr, KDB_FROM_LOADER, g->body, KDB_MAX_BODY);
  g->sresume = false;
  kdb_sm_init(&g->sm, &lim);
  kdb_sm_defer_manifest(&g->sm);                       /* 0.7 M2: the pages of a pass are checked by the reconcile thread */
  g->held_valid = false;
  g->read_off = false;
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
      if (errno == EMFILE || errno == ENFILE || errno == ENOMEM || errno == ENOBUFS) return;      /* (it may pass: the message is tried again) */
      close(g->ctrl_fd);              /* a permanent error would be reported again at every wake-up: stop watching, as for the end of the stream */
      g->ctrl_fd = -1;
      return;
    }
    if (n == 0) { /* the supervisor is gone: the server is going down; stop watching so the thread does not spin */
      syslog(LOG_NOTICE, "[DB] the loader control socket was closed by the supervisor");
      close(g->ctrl_fd);
      g->ctrl_fd = -1;
      return;
    }
    int fds[2] = { -1, -1 };
    recv_take_rights(&m, fds, 2);              /* the first descriptor is the stream, the second (D1a) the fetch stream; any other is closed */
    int got = fds[0], got_fetch = fds[1];
    if (m.msg_flags & MSG_CTRUNC) syslog(LOG_ERR, "[DB] the loader control message was truncated");
    if (got >= 0) {
      adopt_stream(g, got);
      if (got_fetch >= 0) {
        fetch_adopt(g, got_fetch);
      } else {                                  /* a loader without the fetch stream: the old one is gone with the old loader */
        fetch_drop(g);
        fetch_fail_all(g, "the loader has no fetch stream");
      }
    }
  }
}

/* B7a: karidns.conf was reloaded.  The ceiling is evaluated for every request against the active configuration, and so is
 * the existence of a TSIG key (dns_tsig_acl.c: a database ACL that names a key the configuration no longer defines refuses
 * everybody), so nothing has to be republished and no data has to be read again; what is left to do is to say it: a line
 * per zone (the first few) and the counts in `karictl dbstatus`. */
typedef struct {
  const server_config_t *cfg;
  uint32_t zones, with_acl, missing, logged;
  uint32_t chunk;     /* zones seen in the current hold of the lock */
} reeval_ctx_t;

static _Atomic uint32_t g_settings_missing_keys;     /* zones with a missing key, as of the last reload (dbstatus) */

#define REEVAL_CHUNK 4096     /* zones per hold of the rebuild lock (about 1 ms); the walk sleeps between chunks */

static bool reeval_cb(void *ud, const char *view, const dbreg_zone_t *z) {
  reeval_ctx_t *c = ud;
  if (++c->chunk > REEVAL_CHUNK) {     /* stop before this zone: the next chunk starts at it */
    c->chunk = 0;
    return false;
  }
  /* a zone out of memory has its settings in the element (zdir_elem_t.sh), one in memory in its entry */
  const zone_ext_t *x = NULL;
  if (zdir_entry(z)) {
    const zone_config_t *dc = atomic_load_explicit(&zdir_entry(z)->dbcfg, memory_order_acquire);
    if (dc && dc->ext_shared) x = dc->ext;
  } else {
    zone_ext_shared_t *sh = atomic_load_explicit(&((dbreg_zone_t *)z)->sh, memory_order_acquire);
    if (sh) x = &sh->ext;
  }
  if (!x) return true;
  c->zones++;
  if (x->allow_transfer_count > 0 || x->tsig_keys_count > 0 || x->allow_update_count > 0) c->with_acl++;
  const char *missing = db_settings_missing_key(x, c->cfg);
  if (missing) {
    c->missing++;
    if (c->logged < 20) {
      c->logged++;
      char shown[72];
      sane_copy(shown, sizeof(shown), missing, strlen(missing));
      syslog(LOG_WARNING, "[DB] zone '%s' (view '%s'): its settings name the TSIG key '%s', which karidns.conf no longer defines; "
                          "the ACL that names it refuses everybody until the key is back", z->name, view, shown);
    }
  }
  return true;
}

/* D1a step 6 (design 12-12): a reload can make a zone that is out of memory keep an apex (notify, allow-transfer).  The zones that have none are asked for
 * their summary (the fetch stream, the list of zones to read before a query asks), a few at a time, from the ingest loop: no list of a million zones. */
#define APEXW_BATCH 16
typedef struct {
  const server_config_t *cfg;
  uint32_t chunk, n;
  struct { char view[PARK_VIEW_MAX + 1]; char zone[PARK_ZONE_MAX + 1]; } item[APEXW_BATCH];
} apexw_t;

static bool apexw_cb(void *ud, const char *view, const dbreg_zone_t *z) {
  apexw_t *c = ud;
  if (++c->chunk > REEVAL_CHUNK || c->n >= APEXW_BATCH) return false;      /* stop before this zone: the next step starts at it */
  if ((z->kind & ZDIR_K_STORED) || zdir_entry(z) || atomic_load_explicit((_Atomic(zdir_apex_t *) *)&z->apex, memory_order_relaxed) || (z->flags & (ZDIR_F_DELETED | ZDIR_F_WARM | ZDIR_F_NOAPEX)) || !z->digest || z->shadowed ||
      atomic_load_explicit((_Atomic uint8_t *)&z->state, memory_order_relaxed) == ZDIR_ST_ERROR || strlen(z->name) > PARK_ZONE_MAX || strlen(view) > PARK_VIEW_MAX)
    return true;
  if (!dbreg_apex_wanted_cfg(c->cfg, view, z->name, atomic_load_explicit((_Atomic(zone_ext_shared_t *) *)&z->sh, memory_order_acquire))) return true;
  snprintf(c->item[c->n].view, sizeof(c->item[0].view), "%s", view);
  snprintf(c->item[c->n].zone, sizeof(c->item[0].zone), "%s", z->name);
  c->n++;
  return true;
}

static void apex_walk_step(ing_t *g) {
  if (!g->apex_walk || g->nwarm > g->nhot || g->fetch_fd < 0) return;      /* (the zones of the hot list wait for room and do not hold the walk back) */
  apexw_t *c = calloc(1, sizeof(*c));
  if (!c) return;
  rcu_aux_read_lock();
  c->cfg = acquire_config_snapshot();
  bool done = dbreg_walk(&g->apex_cur, apexw_cb, c);
  rcu_aux_read_unlock();
  if (done) {
    g->apex_walk = false;
    atomic_store_explicit(&g_apex_walking, false, memory_order_relaxed);
  }
  for (uint32_t i = 0; i < c->n; i++) warm_add(g, c->item[i].view, c->item[i].zone);
  free(c);
  if (g->nwarm > 0) fetch_issue(g);
}

static void reeval_settings(ing_t *g) {
  (void)g;
  reeval_ctx_t c = { NULL, 0, 0, 0, 0, 0 };
  dbreg_cursor_t cur;
  memset(&cur, 0, sizeof(cur));
  /* in chunks: a hold of the rebuild lock over a million zones (50 ms) would stall a reload or a delta that needs it, and
   * the ingest thread shares its CPU with a pinned worker (burst_yield()).  The read section of the RCU is held for one chunk
   * only (not across the sleeps: a writer's grace period would wait for it); every chunk takes the configuration anew. */
  for (;;) {
    rcu_aux_read_lock();
    c.cfg = acquire_config_snapshot();
    bool done = dbreg_walk(&cur, reeval_cb, &c);
    if (done && c.with_acl > 0 && !db_acl_ceiling_configured(c.cfg))
      syslog(LOG_WARNING, "[DB] %u zone(s) have ACLs in their database settings, but options { database { acl-ceiling } } is not "
                          "configured: they refuse every client", c.with_acl);
    rcu_aux_read_unlock();
    if (done) break;
    struct timespec ts = { 0, BURST_YIELD_NS };
    nanosleep(&ts, NULL);
  }
  atomic_store_explicit(&g_settings_missing_keys, c.missing, memory_order_relaxed);
  if (c.zones > 0)
    syslog(LOG_INFO, "[DB] configuration reloaded: settings of %u database zone(s) checked against it (%u with ACLs, %u naming a "
                     "TSIG key that is not defined)", c.zones, c.with_acl, c.missing);
}

static void on_config_event(ing_t *g) {
  if (!atomic_exchange_explicit(&g_cfg_dirty, false, memory_order_acq_rel)) return;
  reeval_settings(g);
  g->apex_walk = true;                                 /* the zones out of memory that keep an apex now are asked for it */
  atomic_store_explicit(&g_apex_walking, true, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_apex_walks, 1, memory_order_relaxed);
  memset(&g->apex_cur, 0, sizeof(g->apex_cur));
  /* a batch in progress keeps the view numbers of its own CONFIG (b_names, review db_ingest [1]) */
  if (g->stream_fd >= 0 && g->hello_done) send_config(g, "configuration reloaded");
  /* otherwise the CONFIG of the handshake reads the new configuration */
}

/* ---- karictl reload requests (control thread -> loader) and their answers ---- */

/* the zone name as the stream wants it: canonical, absolute */
static bool canon_zone(const char *in, char out[DNS_NAME_TEXT_SIZE]) {
  char norm[DNS_NAME_TEXT_SIZE];
  size_t nl = dns_name_normalize(in, norm, sizeof(norm) - 1);
  if (nl == (size_t)-1 || nl == 0) return false;
  if (dns_name_len_no_root(norm, nl) == nl) {
    norm[nl++] = '.';
    norm[nl] = '\0';
  }
  if (nl > 255) return false;
  snprintf(out, DNS_NAME_TEXT_SIZE, "%s", norm);
  return true;
}

static void send_reload_req(ing_t *g, uint64_t id, bool all, uint16_t view, const char *zone, bool force) {
  kdb_enc_reset(&g->enc);
  if (kdb_enc_begin(&g->enc, KDB_T_RELOAD_REQ) != 0 || kdb_enc_u64(&g->enc, 1, id) != 0 ||
      kdb_enc_u8(&g->enc, 2, all ? 0 : 1) != 0 ||
      (!all && (kdb_enc_u16(&g->enc, 3, view) != 0 || kdb_enc_name(&g->enc, 4, zone) != 0)) ||
      kdb_enc_u8(&g->enc, 5, force ? 1 : 0) != 0 || kdb_enc_end(&g->enc) != 0)
    g->enc.err = true;
  send_enc(g);
}

static void on_config_event(ing_t *g);

/* B6b: one RELOAD_REQ per view that takes database zones; answer_request() combines the answers */
static void request_all_views(ing_t *g, const rq_item_t *it, const char *canon) {
  int need = 0, gi = -1, slots[ING_REQ_MAX], ns = 0;
  for (uint32_t v = 0; v < g->nview_names; v++)
    if (g->view_db && g->view_db[v]) need++;
  for (int i = 0; i < ING_REQ_MAX; i++) {
    if (gi < 0 && !g->grps[i].active) gi = i;
    if (!g->reqs[i].active && ns < need) slots[ns++] = i;
  }
  if (need == 0) {
    post_result(it->id, false, "no view takes zones from the database");
    return;
  }
  if (gi < 0 || ns < need) {
    post_result(it->id, false, "too many reload requests are waiting for the database loader");
    return;
  }
  g->grps[gi].active = true;
  g->grps[gi].ctl_id = it->id;
  g->grps[gi].pending = need;
  g->grps[gi].any_ok = g->grps[gi].any_bad = false;
  g->grps[gi].text[0] = '\0';
  snprintf(g->grps[gi].zone, sizeof(g->grps[gi].zone), "%s", canon);
  syslog(LOG_NOTICE, "[DB] reload of zone '%s' (all %d views that take database zones) requested (request %llu)%s", canon, need,
         (unsigned long long)it->id, it->force ? ", force" : "");
  int k = 0;
  for (uint32_t v = 0; v < g->nview_names; v++) {
    if (!g->view_db || !g->view_db[v]) continue;
    int slot = slots[k++];
    g->reqs[slot].active = true;
    g->reqs[slot].id = (1ULL << 63) | ++g->sub_seq;
    g->reqs[slot].force = it->force;
    g->reqs[slot].grp = gi;
    g->reqs[slot].view = (uint16_t)v;
    snprintf(g->reqs[slot].view_name, sizeof(g->reqs[slot].view_name), "%s", g->view_names[v]);
    snprintf(g->reqs[slot].zone, sizeof(g->reqs[slot].zone), "%s", canon);
    send_reload_req(g, g->reqs[slot].id, false, (uint16_t)v, canon, it->force);
  }
}

static void process_requests(ing_t *g) {
  on_config_event(g);          /* a reload that changed the configuration sends CONFIG before the request */
  for (;;) {
    uint32_t h = atomic_load_explicit(&g_rq_head, memory_order_relaxed);
    uint32_t t = atomic_load_explicit(&g_rq_tail, memory_order_acquire);
    if (h == t) break;
    rq_item_t it = g_rq[h % RQ_RING];
    atomic_store_explicit(&g_rq_head, h + 1, memory_order_release);
    bool ready = g->stream_fd >= 0 && g->hello_done;
    switch (it.type) {
    case RQ_ALL:
      if (ready) {
        send_reload_req(g, it.id, true, 0, NULL, it.force);
        if (it.force) g->all_force_id = it.id;
        syslog(LOG_NOTICE, "[DB] reload requested (request %llu): the loader compares every source with the zones served",
               (unsigned long long)it.id);
      } else {
        syslog(LOG_WARNING, "[DB] reload requested (request %llu), but the database loader is not connected",
               (unsigned long long)it.id);
      }
      break;
    case RQ_ZONE: {
      char canon[DNS_NAME_TEXT_SIZE];
      if (!canon_zone(it.zone, canon)) {
        post_result(it.id, false, "'%.100s' is not a valid zone name", it.zone);
        break;
      }
      if (!it.view[0]) { /* no view named, several take database zones: ask every one of them */
        if (!ready) {
          post_result(it.id, false, "the database loader is not connected (see 'karictl dbstatus')");
          break;
        }
        request_all_views(g, &it, canon);
        break;
      }
      int vi = -1;
      for (uint32_t i = 0; i < g->nview_names; i++)
        if (strcasecmp(g->view_names[i], it.view) == 0) vi = (int)i;
      if (vi < 0) {
        post_result(it.id, false, "view '%.60s' is not in the configuration", it.view);
        break;
      }
      if (!ready) {
        post_result(it.id, false, "the database loader is not connected (see 'karictl dbstatus')");
        break;
      }
      int slot = -1;
      for (int i = 0; i < ING_REQ_MAX && slot < 0; i++)
        if (!g->reqs[i].active) slot = i;
      if (slot < 0) {
        post_result(it.id, false, "too many reload requests are waiting for the database loader");
        break;
      }
      g->reqs[slot].active = true;
      g->reqs[slot].id = it.id;
      g->reqs[slot].force = it.force;
      g->reqs[slot].grp = -1;
      g->reqs[slot].view = (uint16_t)vi;
      snprintf(g->reqs[slot].view_name, sizeof(g->reqs[slot].view_name), "%s", g->view_names[vi]);
      snprintf(g->reqs[slot].zone, sizeof(g->reqs[slot].zone), "%s", canon);
      syslog(LOG_NOTICE, "[DB] reload of zone '%s' (view '%s') requested (request %llu)%s", canon, g->view_names[vi],
             (unsigned long long)it.id, it.force ? ", force" : "");
      send_reload_req(g, it.id, false, (uint16_t)vi, canon, it.force);
      break;
    }
    case RQ_CANCEL:
      for (int i = 0; i < ING_REQ_MAX; i++)
        if (g->grps[i].active && g->grps[i].ctl_id == it.id) g->grps[i].active = false;
      for (int i = 0; i < ING_REQ_MAX; i++)
        if (g->reqs[i].active && (g->reqs[i].id == it.id || (g->reqs[i].grp >= 0 && !g->grps[g->reqs[i].grp].active))) {
          g->reqs[i].active = false;
          if (g->cur_req == i) g->cur_req = -1;
        }
      break;
    default:
      break;
    }
  }
}

/* What a finished request says about its zone in one view: the text after "zone Z (view V): " and whether it is good news.
 * *notfound: the loader sent nothing and the zone is not served (the zone is not in the database of this view). */
static void request_clause(ing_t *g, int i, char *out, size_t cap, bool *ok, bool *notfound) {
  const char *zone = g->reqs[i].zone, *view = g->reqs[i].view_name;
  dbreg_info_t info;
  int n = dbreg_find_info(view, zone, &info, 1);
  *ok = true;
  *notfound = false;
  switch (g->req_outcome) {
  case ROUT_APPLIED:
    snprintf(out, cap, "applied, serial %u", g->req_serial);
    break;
  case ROUT_SHADOWED:
    snprintf(out, cap, "loaded, serial %u, but hidden by %s", g->req_serial,
             n > 0 && info.shadow_by == DBREG_SH_CATALOG ? "a catalog member of the same name" : "the zone in karidns.conf");
    break;
  case ROUT_REJECTED:
    *ok = false;
    snprintf(out, cap, "rejected: %.100s; the last good version, if any, keeps serving", g->req_reason);
    break;
  case ROUT_FAILED:
    *ok = false;
    snprintf(out, cap, "failed: %.100s", g->req_reason);
    break;
  case ROUT_DELETED:
    snprintf(out, cap, "deleted (it is no longer in the database)");
    break;
  default: /* nothing was sent for the zone: the loader found it unchanged, or the database does not have it */
    /* (a zone out of memory is a zone of the database too: the directory knows its version, a summary; only a zone the registry has no usable version of, or that is deleted, is not) */
    if (n > 0 && !(info.flags & ZDIR_F_DELETED) && (info.has_entry || info.last_result == DBREG_APPLIED)) {
      snprintf(out, cap, "unchanged, serial %u%s%s", info.serial, info.has_entry ? "" : " (not in memory)", info.shadowed ? " (hidden by another zone of the same name)" : "");
    } else {
      *ok = false;
      *notfound = true;
      snprintf(out, cap, "not in the database");
    }
    break;
  }
}

/* BATCH_END of a batch that answers a request: tell the control thread what became of the zone (design 5.2).  A request
 * that is one view of a group (B6b) only adds its part; the last part posts the combined answer. */
static void answer_request(ing_t *g) {
  if (g->cur_req < 0) return;
  int i = g->cur_req;
  g->cur_req = -1;
  if (!g->reqs[i].active) return;
  uint64_t id = g->reqs[i].id;
  const char *zone = g->reqs[i].zone, *view = g->reqs[i].view_name;
  int grp = g->reqs[i].grp;
  g->reqs[i].active = false;
  char clause[160];
  bool ok, notfound;
  request_clause(g, i, clause, sizeof(clause), &ok, &notfound);
  if (grp < 0) {
    if (notfound)
      post_result(id, false, "zone not found (it is not in the database of view %s)", view);
    else
      post_result(id, ok, "zone %s (view %s): %s", zone, view, clause);
    return;
  }
  size_t l = strlen(g->grps[grp].text);
  snprintf(g->grps[grp].text + l, sizeof(g->grps[grp].text) - l, "%sview %s: %s", l ? "; " : "", view, clause);
  if (ok) g->grps[grp].any_ok = true;
  if (!ok && !notfound) g->grps[grp].any_bad = true;
  if (--g->grps[grp].pending > 0) return;
  g->grps[grp].active = false;
  if (!g->grps[grp].any_ok && !g->grps[grp].any_bad)
    post_result(g->grps[grp].ctl_id, false, "zone not found (it is not in the database of any view that takes database zones)");
  else
    post_result(g->grps[grp].ctl_id, g->grps[grp].any_ok, "zone %s: %s", g->grps[grp].zone, g->grps[grp].text);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* the fetch stream (D1a, design 6.1)                                                                             */
/* ------------------------------------------------------------------------------------------------------------- */
/* A worker that has parked a query for a zone whose data is not in memory pushes the request on its ring (dns_park.h) and triggers EVFILT_USER
 * PARK_FETCH_IDENT.  This thread turns the requests into FETCH_REQ messages on the second stream (one per zone in flight, the table below keeps
 * them), reads the loader's answers there (the state machine of the fetch stream, dns_db_stream.c), installs each zone through the same jobs as a
 * batch zone, and then tells every worker (park_wake_broadcast()): woken when the zone is in memory, answered at once when the fetch failed.
 * A zone nobody asked for is discarded as it is read: it takes no memory and counts against nothing.  The loader's answers are not ZONE_RESULTs:
 * the first stream's inventory is the batch's business. */

static void prof_swap(ing_t *g) {
  ing_profile_t *p = g->profiles;
  g->profiles = g->fprofiles;
  g->fprofiles = p;
  size_t t = g->nprof;
  g->nprof = g->fnprof;
  g->fnprof = t;
  t = g->cprof;
  g->cprof = g->fcprof;
  g->fcprof = t;
  t = g->prof_bytes;
  g->prof_bytes = g->fprof_bytes;
  g->fprof_bytes = t;
}

static void farm_write(ing_t *g, bool on) {
  if (g->fwrite_armed == on || g->fetch_fd < 0) return;
  struct kevent ev;
  EV_SET(&ev, g->fetch_fd, EVFILT_WRITE, on ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
  if (kevent(g->kq, &ev, 1, NULL, 0, NULL) == 0) g->fwrite_armed = on;
}

static void fetch_drop(ing_t *g) {
  if (g->fetch_fd >= 0) close(g->fetch_fd);              /* the kqueue forgets the descriptor */
  g->fetch_fd = -1;
  g->fwrite_armed = false;
  g->fout_len = g->fout_off = 0;
  g->fresume = false;
  job_free(g->fcur);
  g->fcur = NULL;
  prof_swap(g);
  clear_profiles(g);
  prof_swap(g);
  kdb_enc_reset(&g->fenc);
}

static void fetch_flush(ing_t *g) {
  while (g->fetch_fd >= 0 && g->fout_off < g->fout_len) {
    ssize_t n = write(g->fetch_fd, g->fout + g->fout_off, g->fout_len - g->fout_off);
    if (n > 0) {
      g->fout_off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      farm_write(g, true);
      return;
    }
    syslog(LOG_NOTICE, "[DB] loader fetch stream disconnected (write: %s)", n < 0 ? strerror(errno) : "closed");
    fetch_drop(g);
    return;
  }
  if (g->fetch_fd >= 0) {
    g->fout_len = g->fout_off = 0;
    farm_write(g, false);
  }
}

/* queue the message built in g->fenc.  false: nothing was queued (no stream, or the stream was dropped) */
static bool fetch_queue(ing_t *g) {
  if (g->fenc.err) {
    kdb_enc_reset(&g->fenc);
    return false;
  }
  if (g->fetch_fd < 0) {
    kdb_enc_reset(&g->fenc);
    return false;
  }
  if (g->fout_len - g->fout_off + g->fenc.len > ING_FETCH_OUT_MAX) {
    syslog(LOG_ERR, "[DB] the loader does not read its fetch requests; closing the fetch stream");
    fetch_drop(g);
    return false;
  }
  if (g->fout_off > 0 && g->fout_off == g->fout_len) g->fout_len = g->fout_off = 0;
  if (g->fout_len + g->fenc.len > g->fout_cap) {
    size_t nc = g->fout_cap ? g->fout_cap : 4096;
    while (nc < g->fout_len + g->fenc.len) nc *= 2;
    uint8_t *nb = realloc(g->fout, nc);
    if (!nb) {
      syslog(LOG_ERR, "[DB] out of memory queueing a fetch request; closing the fetch stream");
      fetch_drop(g);
      return false;
    }
    g->fout = nb;
    g->fout_cap = nc;
  }
  memcpy(g->fout + g->fout_len, g->fenc.buf, g->fenc.len);
  g->fout_len += g->fenc.len;
  kdb_enc_reset(&g->fenc);
  return true;
}

#ifdef KARIDNS_UNIT_TEST
void (*db_ingest_test_fetch_req_hook)(const char *zone);
#endif
static bool fetch_send_req(ing_t *g, const ing_freq_t *r) {
#ifdef KARIDNS_UNIT_TEST
  if (db_ingest_test_fetch_req_hook) db_ingest_test_fetch_req_hook(r->zone);       /* (tests: where the thread was when it made the request) */
#endif
  kdb_enc_reset(&g->fenc);
  if (kdb_enc_begin(&g->fenc, KDB_T_FETCH_REQ) != 0 || kdb_enc_u64(&g->fenc, 1, r->id) != 0 || kdb_enc_u16(&g->fenc, 2, r->view) != 0 ||
      kdb_enc_name(&g->fenc, 3, r->zone) != 0 || kdb_enc_u8(&g->fenc, 4, r->prio) != 0 || kdb_enc_u8(&g->fenc, 5, r->mode) != 0 ||
      (g->store_proto && r->sid != 0 && r->mode == KDB_FETCH_FULL && kdb_enc_i64(&g->fenc, 8, r->sid) != 0) ||        /* 0.7 WP7b: the domain id the record holds (the loader answers ZONE_FAILED for another one) */
      kdb_enc_end(&g->fenc) != 0)
    g->fenc.err = true;
  return fetch_queue(g);
}

static ing_freq_t *fetch_find(ing_t *g, uint64_t id) {
  if (g->nfreq == 0 || id == 0) return NULL;
  for (uint32_t i = 0; i < ING_FETCH_MAX; i++)
    if (g->freq[i].active && g->freq[i].id == id) return &g->freq[i];
  return NULL;
}

/* the request in flight for the zone in this mode (the whole zone, or its summary: the two do not stand in for each other, see fetch_issue()) */
static ing_freq_t *fetch_find_zone(ing_t *g, uint16_t view, const char *zone, uint8_t mode) {
  if (g->nfreq == 0) return NULL;
  const uint32_t zh = dns_name_hash_ci(zone);
  for (uint32_t i = 0; i < ING_FETCH_MAX; i++)
    if (g->freq[i].active && g->freq[i].zh == zh && g->freq[i].view == view && g->freq[i].mode == mode && domain_names_match_ci(g->freq[i].zone, zone)) return &g->freq[i];
  return NULL;
}

/* 0.7 WP7b: the stamp of the store's record of the zone (and its domain id, when the request has none) at the time of the request: the body that comes is installed only while the record has it */
static void freq_stamp(ing_freq_t *r, const char *view, const char *zone) {
  db_stamp_t s;
  int64_t sid = 0;
  if (dbdir() && db_store_zone_stamp(view, zone, &s, &sid)) {
    r->st_valid = true;
    r->st_gen = s.gen;
    r->st_time = s.time;
    if (r->sid == 0) r->sid = sid;
  }
}

/* The next body the reconcile wants (the scan of the store, db_recon_scan(): the records without an image, the ones whose version the database changed, the secondary and catalog
 * zones once a run), as a fetch request of the lowest priority.  Only while its bodies in flight are under its limit (fill_limit(): no place of fetch-concurrency, which is the queries'), and in
 * slices, so that a store of ten million records is not looked at in one go.  A round with failures is made again after a pause; a round that finds nothing ends the work (bg_on).
 * *back: where the scan stood before the zone, for a request that cannot be made now. */
#define ING_BULK_LOOK 4096        /* records the scan looks at in one call */
static bool bulk_take(ing_t *g, park_fetch_req_t *q, uint32_t *zid, uint32_t *back, bool *np, int64_t *sid) {
  if (!g->bg_on || g->fetch_fd < 0 || !dbdir()) return false;
  if (g->bg_retry_ms && now_ms() < g->bg_retry_ms) return false;
  if (g->nbulk >= fill_limit(g) || g->nfreq >= ING_FETCH_MAX) return false;      /* (0.7 first-fill latency: its own limit, not places of fetch-concurrency) */
  for (int round = 0; round < 4; round++) {
    db_scan_item_t it;
    *back = g->bg_zid;
    int rc = db_recon_scan(&g->bg_zid, ING_BULK_LOOK, &it);
    if (rc == 2) continue;
    if (rc == 0) {                                       /* the end of the store */
      if (g->bg_again) {
        g->bg_again = false;
        g->bg_zid = 0;
      } else if (g->bg_fail > 0) {
        g->bg_retry_ms = now_ms() + 5000;
        g->bg_zid = 0;
        g->bg_fail = 0;
      } else {
        scan_set(g, false);
        atomic_fetch_add_explicit(&g_scan_idle, 1, memory_order_release);     /* (the end of an unlogged first fill waits for this, db_ingest_fill_scan()) */
        if (!g->bg_idle_logged) {
          g->bg_idle_logged = true;
          logev_post(LOGC_DATABASE, 1, NULL, 0, "[DB] the bodies the reconcile wanted are all asked for");
        }
      }
      return false;
    }
    int vi = -1;
    for (uint32_t i = 0; i < g->nview_names; i++)
      if (g->view_db && g->view_db[i] && strcasecmp(g->view_names[i], it.view) == 0) {
        vi = (int)i;
        break;
      }
    if (vi < 0 || fetch_find_zone(g, (uint16_t)vi, it.zone, KDB_FETCH_FULL)) continue;      /* a view that left the configuration, or the body is on its way already */
    memset(q, 0, sizeof(*q));
    q->worker = -1;
    snprintf(q->view, sizeof(q->view), "%s", it.view);
    snprintf(q->zone, sizeof(q->zone), "%s", it.zone);
    q->prio = KDB_FETCH_PRIO_BACKGROUND;
    q->mode = KDB_FETCH_FULL;
    *zid = it.zid;
    *np = it.nonstore;
    *sid = it.source_id;
    return true;
  }
  g->fmore = true;                                       /* (the scan has not finished: look again after the streams were served) */
  return false;
}

static void req_fetch_done(ing_t *g, const ing_freq_t *done, bool ok, const char *why);
static void fetch_complete(ing_t *g, ing_freq_t *r, bool ok, const char *why);

/* ---- 0.7: the by-name lookups of the first start ----
 * A query for a name that no stored zone of a view covers, while the first pass of the view has not listed every zone, would be refused as for any name the server does not serve; instead the worker
 * parks it and asks for a lookup (FETCH_REQ mode KDB_FETCH_LOOKUP on the fetch stream, which a pass on the first stream does not hold up).  The loader finds the zone of the view that encloses the name
 * (the longest one) and answers LOOKUP_RESULT; a zone it found is recorded as a MANIFEST entry would (a KNOWN record), and the queries that wait for the name are woken (as for the fetch of a zone:
 * park_wake_queue_all()) and look the name up again: with a record they park for the zone and are answered from it, without they are refused as before.  Whatever becomes of the lookup the queries are
 * woken, not failed.
 * Mode KDB_FETCH_LOOKUP_FULL (a loader whose HELLO has KDB_FEAT_LOOKUP_BODY; not with a fetch-rate, which counts the zones read for queries, and not above the hard line of memory-limit, which holds the fetches back
 * for room): the loader sends the body of the zone it found after the answer, with the same request id, and the request becomes the fetch of that zone (mode FULL, the same id, the same place): the zone is
 * answerable after one round trip, not two.  The body is a claim of an untrusted loader like the answer: it must be the zone the answer named (the name and the source id), once, after the answer
 * (on_fetch_begin()); the stamp check at the commit is the fetch's (the record the answer made is the stamp the body is asked for).  A zone that another request has in flight or that is in memory already
 * (dbreg_fetch_begin() does not start it) has its body read through and thrown away (LKS_SKIP): the loader cannot be told not to send it.
 * A lookup is a fetch of the class of the queries': it takes a place of fetch-concurrency (park_place_take()) like a fetch, and a request that finds none, or whose share is used up, waits in a queue of its own
 * (lq) until park-timeout; the workers' requests are never refused for the lack of a place.  The lookups out (in flight, and their bodies) are at most three quarters of the places (lk_share()), so that a
 * flood of names that no zone has leaves the rest to the fetches of zones, and a place is given back the moment the answer is "none".  The queue and the wait queue of the fetches take turns when both could make a
 * request.  A name that is asked for twice at once is one request (the claim mark of the name, and lookup_find()); one whose zone has become known meanwhile is not asked for (lookup_covered()). */
static ing_freq_t *lookup_find(ing_t *g, uint16_t view, const char *name) {
  if (g->nfreq == 0 || g->nlook == 0) return NULL;
  for (uint32_t i = 0; i < ING_FETCH_MAX; i++)
    if (g->freq[i].active && g->freq[i].lk && g->freq[i].lkst == LKS_ASK && g->freq[i].view == view && domain_names_match_ci(g->freq[i].lk_q, name)) return &g->freq[i];
  return NULL;
}

/* the name of a query as the stream wants it: canonical text, which the loader's decoder checks (a name it refuses would close the stream) */
static bool lookup_name_ok(const char *name) {
  char out[DNS_NAME_TEXT_SIZE];
  const size_t n = strlen(name);
  if (n == 0 || n >= sizeof(out) || (n == 1 && name[0] == '.')) return false;      /* (the root is not looked for) */
  for (size_t i = 0; i < n; i++)
    if ((unsigned char)name[i] < 0x21 || (unsigned char)name[i] > 0x7E) return false;
  return dns_name_normalize(name, out, sizeof(out)) == n && memcmp(name, out, n) == 0 && dns_name_len_no_root(name, n) != n;
}

/* the places that the lookups out (and the bodies that came with them) may take: three quarters of fetch-concurrency, but always at least one place is left to the fetches of zones (with two to four places, one), so that a flood
 * of names that no zone has cannot hold every place.  A single place cannot be shared: the lookup takes it for one round trip (it is given back at once when the answer is none), and the places go to the lookups and the fetches by turns. */
static uint32_t lk_share_for(uint32_t conc) {
  if (conc <= 1) return 1;
  return conc - (conc / 4 ? conc / 4 : 1);
}
static uint32_t lk_share(void) { return lk_share_for(atomic_load_explicit(&g_fetch_conc, memory_order_relaxed)); }
#ifdef KARIDNS_UNIT_TEST
uint32_t db_ingest_test_lk_share(uint32_t conc) { return lk_share_for(conc); }    /* tests: the places the lookups may take at a fetch-concurrency */
#endif

/* can a lookup be made now?  A stream, a free slot of the table, its share, and a place (every place is the queries': the fill takes none) */
static bool lookup_ready(const ing_t *g) {
  return g->fetch_fd >= 0 && atomic_load_explicit(&g_lookup_on, memory_order_acquire) && g->nfreq < ING_FETCH_MAX && g->nlook < lk_share() && park_place_avail();
}

/* the mode of the request: with the body of the zone when the loader sends it, there is no fetch-rate to keep (it counts the zones read for queries) and the zones in memory are below the hard line */
static uint8_t lookup_mode(const ing_t *g) {
  if ((g->loader_feat & KDB_FEAT_LOOKUP_BODY) && atomic_load_explicit(&g_fetch_rate, memory_order_relaxed) == 0 && !dbreg_cache_over_limit()) return KDB_FETCH_LOOKUP_FULL;
  return KDB_FETCH_LOOKUP;
}

/* does the store have a zone that encloses the name already (an earlier lookup found it, or the pass listed it)?  Then there is nothing to look for: the queries look the name up again */
static bool lookup_covered(const char *view, const char *name) {
  const dbdir_ops_t *ops = dbdir();
  dbdir_rec_t rec;
  if (!ops) return false;
  for (const char *p = name; *p && !(p[0] == '.' && p[1] == '\0');) {
    if (ops->rec_get(view, p, &rec)) return true;
    const char *dot = strchr_unescaped(p, '.');
    if (!dot) break;
    p = dot + 1;
  }
  return false;
}

static void lookup_hist(int64_t ns) {
  const uint64_t us = ns <= 0 ? 0 : ((uint64_t)ns + 999) / 1000;
  int b = 0;
  while (b < STORE_STATUS_HIST_BUCKETS - 1 && ((uint64_t)1 << b) < us) b++;
  atomic_fetch_add_explicit(&g_lk_hist[b], 1, memory_order_relaxed);
  if (ns > 0 && (uint64_t)ns > atomic_load_explicit(&g_lk_max_ns, memory_order_relaxed)) atomic_store_explicit(&g_lk_max_ns, (uint64_t)ns, memory_order_relaxed);
}

/* The names whose lookup was shed are remembered (park_shed_remember(), dns_park.h): a query for such a name is dropped by its worker with no request, for park-timeout or until this thread has caught up
 * (shed_release_check()).  Only this thread calls these (the statics need no atomics); the counters are the park table's. */
static int64_t s_shed_last_ms;                           /* when a name was remembered last (the loop looks for the catch-up while the entries could still be live) */
static int64_t s_shed_rel_ms;                            /* ... and when the names were released last */
static bool s_shed_since;                                /* a name was remembered after the last release (not s_shed_last_ms > s_shed_rel_ms: both can fall in one millisecond) */
static void shed_remember(uint64_t ckey) {
  if (!ckey) return;
  s_shed_last_ms = now_ms();
  s_shed_since = true;
  park_shed_remember(ckey, s_shed_last_ms);
}

/* The queue is empty and a lookup could be made: this thread has caught up, so the names that were remembered are asked again by the next query (at most once in an eighth of park-timeout: a thread that is
 * on and off the edge of its queue would otherwise forget the names at every pass).  park_shed_release(now) forgets the names stamped before the millisecond `now` and keeps the ones of `now`, so that a name shed
 * right after the release in the same millisecond is held; the names shed in the current millisecond before it are released at the next look (the loop looks every ING_WQ_TICK_MS while names are remembered). */
static void shed_release_check(const ing_t *g) {
  if (!s_shed_since || g->nlq != 0 || !lookup_ready(g)) return;      /* (nothing was remembered since the last release, or not caught up) */
  const int64_t now = now_ms();
  const int64_t gap = (int64_t)atomic_load_explicit(&g_park_timeout_ms, memory_order_relaxed) / 8;
  if (now - s_shed_rel_ms < (gap > 10 ? gap : 10) || now <= s_shed_last_ms) return;      /* (a name was remembered in this millisecond: it would be kept, the next look releases it) */
  s_shed_rel_ms = now;
  s_shed_since = false;
  park_shed_release(now);
}

/* the lookup's own end (the answer is none, it failed, it was read through): the queries that wait for the name look it up again.  The place and the claim mark went back in fetch_complete(). */
static void lookup_complete(const ing_freq_t *done, bool ok, const char *why) {
  const bool shed = !ok && done->busy;                   /* (the loader said it is busy: overload, the queries are dropped, not failed) */
  if (shed) {
    atomic_fetch_add_explicit(&g_lk_shed, 1, memory_order_relaxed);
    shed_remember(done->ckey);                           /* (before the workers are told: a query that comes after their drop finds the name remembered) */
    logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] lookup of the name '%s' (view '%s') shed: the loader is busy; its queries are dropped", done->lk_q, done->view_name);
  } else if (!ok) {
    atomic_fetch_add_explicit(&g_lk_failed, 1, memory_order_relaxed);
    logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] lookup of the name '%s' (view '%s') failed: %s", done->lk_q, done->view_name, why && why[0] ? why : "no reason given");
  }
  /* (a failure is "not ready" for the queries, SERVFAIL + EDE 14 as for a zone whose fetch failed; "none" is the normal answer for a name that no zone has; the workers that asked are told, the claim is cleared by the caller after this) */
  park_wake_queue_claim(done->view_name, done->lk_q, done->ckey, !ok && !shed, shed ? PARK_ASK_DROP : 0);
}

/* a request that ends before it was made (a loader that does not look up, a view that takes no database zones, a zone that is known already): its queries look the name up again (the normal answer).  The workers that asked are woken,
 * then the claim mark goes. */
static void lookup_drop(const park_fetch_req_t *q, uint64_t ckey) {
  park_wake_queue_claim(q->view, q->zone, ckey, false, 0);
  if (ckey) park_claim_clear(ckey);
}

/* a lookup that is dropped because the ingest thread is overloaded (its queue is full, or it waited until its time was up), or because the loader that would answer it is away: the queries that wait for the name are
 * dropped (counted at their workers), not answered REFUSED or SERVFAIL for a name whose zone the database may have.  Only the workers that asked are told (park_wake_queue_claim()): a flood of shed lookups
 * must not fill the wake ring of every worker.  The name is remembered first (shed_remember()): the next query for it is dropped by its worker, it does not ask again for a request that would be shed again. */
static void lookup_shed(const park_fetch_req_t *q, uint64_t ckey) {
  shed_remember(ckey);
  park_wake_queue_claim(q->view, q->zone, ckey, false, PARK_ASK_DROP);
  if (ckey) park_claim_clear(ckey);
}

static void lookup_note(const ing_t *g) {
  atomic_store_explicit(&g_lk_pending, g->nlq, memory_order_relaxed);
  atomic_store_explicit(&g_lk_inflight, g->nlook, memory_order_relaxed);
}

/* the request of a lookup, made: a place, a slot, FETCH_REQ.  The caller has seen lookup_ready().  vi: the loader's index of the view; ckey: the claim mark of the name */
static void lookup_start(ing_t *g, const park_fetch_req_t *q, int vi, uint64_t ckey) {
  if (lookup_covered(q->view, q->zone)) {
    atomic_fetch_add_explicit(&g_lk_covered, 1, memory_order_relaxed);
    lookup_drop(q, ckey);
    return;
  }
  ing_freq_t *r = NULL;
  for (uint32_t i = 0; i < ING_FETCH_MAX && !r; i++)
    if (!g->freq[i].active) r = &g->freq[i];
  if (!r || !park_place_take()) {                        /* (lookup_ready() said there was room, and no other thread takes places: not here) */
    atomic_fetch_add_explicit(&g_lk_refused, 1, memory_order_relaxed);
    lookup_drop(q, ckey);
    return;
  }
  memset(r, 0, sizeof(*r));
  r->active = true;
  r->id = ++g->fseq;
  r->view = (uint16_t)vi;
  r->prio = KDB_FETCH_PRIO_QUERY;
  r->mode = lookup_mode(g);
  r->lk = 1;
  r->lkst = LKS_ASK;
  r->placed = true;                                      /* (the place stays with the request: the lookup, and the fetch of the zone that comes of it) */
  r->ckey = ckey;
  r->sent_ms = now_ms();
  r->lk_t0 = mono_ns();
  snprintf(r->view_name, sizeof(r->view_name), "%s", g->view_names[vi]);
  snprintf(r->zone, sizeof(r->zone), "%s", q->zone);
  r->zh = dns_name_hash_ci(r->zone);
  snprintf(r->lk_q, sizeof(r->lk_q), "%s", q->zone);
  g->nfreq++;
  g->nlook++;
  atomic_store_explicit(&g_fq_inflight, g->nfreq, memory_order_relaxed);
  lookup_note(g);
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] lookup %llu: the zone of the name '%s' (view '%s')%s", (unsigned long long)r->id, r->zone, r->view_name, r->mode == KDB_FETCH_LOOKUP_FULL ? ", with its body" : "");
  if (!fetch_send_req(g, r)) fetch_complete(g, r, false, "the loader's fetch stream is not connected");
}

/* the index of a view that takes zones from the database (the loader's numbering), -1 none */
static int view_db_index(const ing_t *g, const char *name) {
  for (uint32_t i = 0; i < g->nview_names; i++)
    if (g->view_db && g->view_db[i] && strcasecmp(g->view_names[i], name) == 0) return (int)i;
  return -1;
}

/* the head of the queue goes, if it can: false when nothing waits or nothing can be made now.  The ones whose time is up are dropped before (lq_expire(): their queries have timed out). */
static bool lq_pump_one(ing_t *g) {
  while (g->nlq > 0) {
    const bool hold = atomic_load_explicit(&g_lookup_hold, memory_order_acquire);
    if (hold && !lookup_ready(g)) return false;           /* (a loader that looks names up is away or has no place: the entry waits for it until its time is up, lq_expire(): dropped, not refused) */
    struct ing_lq e = g->lq[g->lq_head];
    g->lq_head = (g->lq_head + 1) % ING_LQ_MAX;
    g->nlq--;
    lookup_note(g);
    const int vi = view_db_index(g, e.q.view);
    if (vi < 0 || !hold) {                                /* a view that takes no database zones, or a loader that does not look names up (a new one came): the normal answer */
      atomic_fetch_add_explicit(&g_lk_refused, 1, memory_order_relaxed);
      lookup_drop(&e.q, e.key);
      continue;
    }
    lookup_start(g, &e.q, vi, e.key);
    return true;
  }
  return false;
}

static void lq_expire(ing_t *g, int64_t now) {
  while (g->nlq > 0 && g->lq[g->lq_head].deadline_ms <= now) {
    struct ing_lq e = g->lq[g->lq_head];
    g->lq_head = (g->lq_head + 1) % ING_LQ_MAX;
    g->nlq--;
    atomic_fetch_add_explicit(&g_lk_expired, 1, memory_order_relaxed);
    lookup_shed(&e.q, e.key);
  }
  lookup_note(g);
}

/* a request of a worker (mode KDB_FETCH_LOOKUP) taken from a ring: vi is the loader's index of its view (-1: none).  It is made now, or it waits for a place in the queue. */
static void lookup_offer(ing_t *g, const park_fetch_req_t *q, int vi) {
  atomic_fetch_add_explicit(&g_lk_asked, 1, memory_order_relaxed);
  if ((vi < 0 && g->hello_done) || !atomic_load_explicit(&g_lookup_hold, memory_order_acquire) || !lookup_name_ok(q->zone)) {      /* (the worker did not know: it asked, and is woken as for the end of a lookup; a loader that is away for a while is not this case: the request waits for it.  Before the first HELLO the views of the database are not known yet: the request waits, lq_pump_one() looks at its view again) */
    atomic_fetch_add_explicit(&g_lk_refused, 1, memory_order_relaxed);
    if (q->worker >= 0) park_wake_queue_one(q->worker, q->view, q->zone, false);
    else park_wake_queue_all(q->view, q->zone, false);
    return;
  }
  const uint64_t key = park_lookup_claim_key(q->view, q->zone);       /* (a key of its own: not the zone's, whose fetch must not be taken for this request's duplicate) */
  if (lookup_find(g, (uint16_t)vi, q->zone)) {           /* the same name is on its way: its answer wakes the workers that asked */
    park_claim_note_worker(key, q->worker);
    atomic_fetch_add_explicit(&g_lk_dup, 1, memory_order_relaxed);
    return;
  }
  const bool marked = park_claim_mark(key);
  park_claim_note_worker(key, q->worker);
  if (!marked) {                                         /* the same name waits in the queue (the mark is the name's) */
    atomic_fetch_add_explicit(&g_lk_dup, 1, memory_order_relaxed);
    return;
  }
  if (g->nlq == 0 && lookup_ready(g)) {
    lookup_start(g, q, vi, key);
    return;
  }
  if (!g->lq || g->nlq >= queue_cap(&db_ingest_test_lq_max, ING_LQ_MAX)) {                  /* true overload: the queries behind it time out (park-timeout) */
    atomic_fetch_add_explicit(&g_lk_shed, 1, memory_order_relaxed);
    lookup_shed(q, key);
    return;
  }
  struct ing_lq *e = &g->lq[(g->lq_head + g->nlq) % ING_LQ_MAX];
  e->q = *q;
  e->key = key;
  e->deadline_ms = now_ms() + (int64_t)atomic_load_explicit(&g_park_timeout_ms, memory_order_relaxed);
  g->nlq++;
  if (g->nlq > atomic_load_explicit(&g_lk_peak, memory_order_relaxed)) atomic_store_explicit(&g_lk_peak, g->nlq, memory_order_relaxed);
  lookup_note(g);
}

/* the request is over.  ok: the zone (or its summary) was received and installed; else the queries that wait for it are answered at once. */
static void fetch_complete(ing_t *g, ing_freq_t *r, bool ok, const char *why) {
  ing_freq_t done = *r;
  r->active = false;
  if (!done.busy && !done.quiet) dd_note(g, ok, why);    /* (0.7 first-fill latency: the reads that failed, for the line of dd_tick(); "busy" is overload, not a database that cannot be read) */
  if (done.placed) park_place_give();                    /* (B2 W5: the one place of the fetch goes back, whichever way it ended: installed, failed, dropped, the loader gone) */
  g->nfreq--;
  atomic_store_explicit(&g_fq_inflight, g->nfreq, memory_order_relaxed);
  if (done.lk) {                                         /* 0.7: a lookup (and the fetch that came of it) is over: the share of the places it took is free; its claim mark goes after the workers that asked are told (below) */
    g->nlook--;
    lookup_note(g);
  }
  if (done.mode == KDB_FETCH_LOOKUP || done.mode == KDB_FETCH_LOOKUP_FULL) {      /* 0.7: a lookup that has not become a fetch of a zone (no LOADING state, no stamp): the queries that wait for the name look it up again */
    lookup_complete(&done, ok, why);
    if (done.ckey) park_claim_clear(done.ckey);
    return;
  }
  if (ok) fq_hist_add(now_ms() - done.sent_ms);
  if (done.mode != KDB_FETCH_SUMMARY) {
    dbreg_fetch_end(done.view_name, done.zone);
  } else {                                               /* (a summary is not a fetch of the data: it took no LOADING state) */
    g->nsum--;
    atomic_fetch_add_explicit(&g_apex_answered, 1, memory_order_relaxed);
  }
  if (done.hot) {
    g->nhot_flight--;
    atomic_store_explicit(&g_wl_flight, g->nhot_flight, memory_order_relaxed);
    atomic_fetch_add_explicit(ok ? &g_wl_loaded : &g_wl_failed, 1, memory_order_relaxed);
  }
  if (!ok && !g->dd_warned) {                            /* (one WARNING in a window of dd_tick(): a database that cannot be read fails every fetch, and the line of the window counts them) */
    g->dd_warned = true;
    syslog(LOG_WARNING, "[DB] fetch of zone '%s' (view '%s') failed: %s", done.zone, done.view_name, why && why[0] ? why : "no reason given");
  } else if (!ok)
    logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] fetch of zone '%s' (view '%s') failed: %s", done.zone, done.view_name, why && why[0] ? why : "no reason given");
  else
    logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] fetch %llu of zone '%s' (view '%s') done in %lld ms%s", (unsigned long long)done.id, done.zone, done.view_name,
               (long long)(now_ms() - done.sent_ms), done.dropped ? ": unchanged, the version in memory stays" : "");
  if (done.bulk) {                                       /* 0.7 WP7b: the background fetch of the wanted bodies */
    if (g->nbulk) g->nbulk--;
    db_recon_note_fetch(DBR_IN_FLIGHT, g->nbulk);
    if (ok) {
      db_recon_note_fetch(DBR_FETCHED, 1);
      g->fs_done++;                                      /* (0.7 first-fill latency: the fill moved in this window, dd_tick()) */
    } else {
      db_recon_note_fetch(DBR_FETCH_FAILED, 1);
      if (!done.loader_failed) g->bg_fail++;             /* (a busy or lost loader: the round is made again; a zone the loader cannot read is marked refused below) */
      if (done.nonstore && !done.loader_failed) db_recon_scan_retry(done.bzid);
    }
  }
  if ((done.dropped || (ok && done.st_valid)) && done.mode == KDB_FETCH_FULL && g->store_proto && dbdir()) {
    /* 0.7 M6: the body was dropped (job_execute(): it was for another stamp than the record has now, or the zone was changed since).  The scan of the wanted bodies skipped the zone while this fetch was in
     * flight, and nothing else would ask for it again: the record would stay STALE (or KNOWN) and the old image would be served for ever.  A record that is still wanted starts the scan again.  The same for a body that was installed while the database changed the zone again (the ingest thread recorded the new stamp after the install, db_store_commit_begin()):
     * the record has another stamp than the body was asked for, and the scan skipped the zone for the same reason. */
    const db_stamp_t inst = { done.st_gen, done.st_time };
    if (db_store_wanted_again(done.view_name, done.zone, done.dropped ? NULL : &inst)) bulk_kick(g);
  }
  if (!ok && done.loader_failed && dbdir()) {            /* the loader cannot read the zone: the record is marked refused (not asked for again before the database says another version) */
    dbdir_rec_t rec;
    if (dbdir()->rec_get(done.view_name, done.zone, &rec)) dbdir()->note_flags(rec.zid, STORE_F_REJECTED_NEW, 0);
  }
  req_fetch_done(g, &done, ok, why);
  g->delta_wake = true;                                  /* a zone that was new to the index becomes visible before its queries are woken: the delta is published once, by wake_flush(), before the triggers go out (0.7 M3: at 10k zones a second a publish per zone was most of the work) */
  if (ok && !done.quiet && done.mode == KDB_FETCH_FULL) dbreg_touch_loaded(done.view_name, done.zone);
  /* a zone that only a background fetch (a CNAME or glue that leads into it, step 8) brought is the first to go when memory-limit needs room (BGLOAD): N cold name
   * servers behind the glue of one zone must not push the zones the queries use out of memory.  Unlike a zone a transfer brought (design 7) it stays while there
   * is room: the next query that follows the chain or wants the glue is why it was asked for.  The mark is dropped by the cache manager when a query is answered
   * from the zone. */
  /* a zone of the hot list starts with a frequency of its rank (the list is read hottest first: the first has the number of zones in the list, the last 1), not 0: a zone
   * with no queries yet is the cache manager's first victim, and the warm-up must not read the zones that matter most only to lose them first.  The queries that follow
   * add to it. */
  if (ok && done.hot && !done.dropped && done.mode == KDB_FETCH_FULL) dbreg_warm_freq(done.view_name, done.zone, g->wl_count > done.hrank ? g->wl_count - done.hrank : 1);
  if (ok && !done.dropped && !done.quiet && !done.bulk && done.mode == KDB_FETCH_FULL && done.prio == KDB_FETCH_PRIO_BACKGROUND) dbreg_bg_loaded(done.view_name, done.zone);
  if ((!ok || done.dropped) && done.want_summary) warm_add(g, done.view_name, done.zone);     /* (the summary that was not asked for because this request was on its way) */
  /* a loader that said it is busy is overload, not a failure of the zone: the queries that wait are dropped and counted (store.park.drop.queue), not answered SERVFAIL (0.7) */
  const bool shed = !ok && done.busy;
  if (done.lk) {                                         /* 0.7: the fetch came of a lookup (its body, mode 3): the queries that wait for the zone, and those that wait for the name it was asked for, are woken; both are failed when the body failed
                                                          * (SERVFAIL + EDE 14: the lookup found the zone and the database could not give it), dropped when the loader was busy.  The workers that asked for the name are told by the claim. */
    const bool same = domain_names_match_ci(done.lk_q, done.zone);
    if (shed) park_wake_queue_drop_all(done.view_name, done.zone);
    else park_wake_queue_all(done.view_name, done.zone, !ok);
    if (!same) park_wake_queue_claim(done.view_name, done.lk_q, done.ckey, !ok && !shed, shed ? PARK_ASK_DROP : 0);
    if (done.ckey) park_claim_clear(done.ckey);
  } else if (!done.quiet) {
    if (shed) park_wake_queue_drop_all(done.view_name, done.zone);
    else park_wake_queue_all(done.view_name, done.zone, !ok);      /* (the triggers go out together, park_wake_flush())  */
  }
  /* (the summary for the apex wakes nobody: no query waits for it, and the queries that wait for the data are not woken for nothing) */
}

/* 0.7 WP7b: `karictl reload <zone>` with the store protocol.  The loader's CHANGES entry (FORCE) made the record want its body; the zone is read now, not when the scan comes to it, and the
 * answer of the request (and BATCH_RESULT, which the loader waits for) comes when it is here, so that the operator is told what became of the zone, as with the inventory. */
static void req_fetch_start(ing_t *g, uint16_t view, const char *view_name, const char *zone, int64_t sid, bool nonstore) {
  if (g->fetch_fd < 0 || g->req_wait) return;
  ing_freq_t *e = fetch_find_zone(g, view, zone, KDB_FETCH_FULL);
  if (e) {                                               /* already on its way (the scan or a query asked): the answer waits for that one */
    e->reqfetch = true;
    g->req_wait = true;
    g->req_fetch_id = e->id;
    g->rf_has = false;
    return;
  }
  ing_freq_t *r = NULL;
  for (uint32_t i = 0; i < ING_FETCH_MAX && !r; i++)
    if (!g->freq[i].active) r = &g->freq[i];
  if (!r) return;                                        /* (no free place: the zone is read by the scan, the request is answered as "unchanged") */
  memset(r, 0, sizeof(*r));
  r->active = true;
  r->id = ++g->fseq;
  r->view = view;
  r->prio = KDB_FETCH_PRIO_QUERY;
  r->mode = KDB_FETCH_FULL;
  r->sid = sid;
  r->nonstore = nonstore;
  r->reqfetch = true;
  r->sent_ms = now_ms();
  snprintf(r->view_name, sizeof(r->view_name), "%s", view_name);
  snprintf(r->zone, sizeof(r->zone), "%s", zone);
  r->zh = dns_name_hash_ci(r->zone);
  if (!nonstore) {
    r->v_valid = dbreg_zone_version(view_name, zone, &r->v_sid, &r->v_serial);
    freq_stamp(r, view_name, zone);
  }
  g->nfreq++;
  atomic_store_explicit(&g_fq_inflight, g->nfreq, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_fetch_issued, 1, memory_order_relaxed);
  g->req_wait = true;
  g->req_fetch_id = r->id;
  g->rf_has = false;
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] fetch %llu: zone '%s' (view '%s'), whole zone, for a reload request", (unsigned long long)r->id, r->zone, r->view_name);
  if (!fetch_send_req(g, r)) fetch_complete(g, r, false, "the loader's fetch stream is not connected");
}

/* the fetch of the zone of the reload request is over: what became of it is the outcome of the request, and the held BATCH_RESULT goes out */
static void req_fetch_done(ing_t *g, const ing_freq_t *done, bool ok, const char *why) {
  if (!g->req_wait || done->id != g->req_fetch_id) return;
  g->req_wait = false;
  if (g->rf_has && g->rf_id == done->id) {
    g->rf_has = false;
    switch (g->rf_status) {
    case KDB_ST_APPLIED:
    case KDB_ST_NOT_RESIDENT:
      g->req_outcome = ROUT_APPLIED;
      break;
    case KDB_ST_SHADOWED:
      g->req_outcome = ROUT_SHADOWED;
      break;
    case KDB_ST_REJECTED:
      g->req_outcome = ROUT_REJECTED;
      snprintf(g->req_reason, sizeof(g->req_reason), "%s", g->rf_reason);
      break;
    default:                                             /* the body was not needed after all (the version here is the database's): "unchanged" */
      g->req_outcome = ROUT_NONE;
      break;
    }
    g->req_serial = g->rf_serial;
  } else if (!ok) {
    g->req_outcome = ROUT_FAILED;
    snprintf(g->req_reason, sizeof(g->req_reason), "%s", why && why[0] ? why : "no reason given");
  }
  if (g->defer_end) batch_finish(g, g->defer_batch);
}

static void fetch_job_finish(ing_t *g, ing_job_t *j) {
  if (!j->unsolicited) {
    ing_freq_t *r = fetch_find(g, j->fetch_id);
    bool ok = j->status != KDB_ST_REJECTED;
    if (ok && !j->summary) g->since_retire++;
    if (r) {
      r->dropped = ok && !j->summary && j->status == KDB_ST_UNCHANGED;
      if (r->reqfetch) {                                 /* 0.7 WP7b: what became of the zone a reload asked for */
        g->rf_has = true;
        g->rf_id = r->id;
        g->rf_status = j->status;
        g->rf_serial = j->serial;
        snprintf(g->rf_reason, sizeof(g->rf_reason), "%s", j->reason);
      }
      fetch_complete(g, r, ok, j->reason);
    }
  }
  job_free(j);
}

static void fetch_fail_all(ing_t *g, const char *why) {
  if (g->nfreq == 0) return;
  for (uint32_t i = 0; i < ING_FETCH_MAX && g->nfreq > 0; i++)
    if (g->freq[i].active) fetch_complete(g, &g->freq[i], false, why);
}

static void fetch_expire(ing_t *g) {
  if (g->nfreq == 0) return;
  int64_t now = now_ms();
  for (uint32_t i = 0; i < ING_FETCH_MAX; i++)
    if (g->freq[i].active && now - g->freq[i].sent_ms >= g_ing_fetch_timeout_ms)
      fetch_complete(g, &g->freq[i], false, "the loader did not answer in time");
}

/* the requests the workers have pushed since the last time */
/* D1a milestone 4: the zones to read although no query asked for them yet (a pinned zone that came as a summary; the warm-up of step 7 will use the
 * same list).  They go after the requests of the queries, at most ING_WARM_NFREQ in flight, and a zone that cannot be asked for now (the rate, the
 * limit) waits at the end of the list. */
/* hot: a zone of the hot list (read whole, in the order of the list); fresh: it comes from the list now (counted), not a zone that goes back for a free place */
static void warm_add_ex(ing_t *g, const char *view, const char *zone, bool hot, bool fresh) {
  if (!dbreg_warm_mark(view, zone)) return;              /* in the list already (a summary for the same pinned zone again), or not a zone of the registry */
  if (g->nwarm == g->cwarm) {
    size_t nc = g->cwarm ? g->cwarm * 2 : 64;
    struct ing_warm *n = realloc(g->warm, nc * sizeof(*n));
    if (!n) {
      (void)dbreg_warm_take(view, zone, NULL);
      return;                                            /* out of memory: the zone is read when a query asks for it */
    }
    g->warm = n;
    g->cwarm = nc;
  }
  snprintf(g->warm[g->nwarm].view, sizeof(g->warm[0].view), "%s", view);
  snprintf(g->warm[g->nwarm].zone, sizeof(g->warm[0].zone), "%s", zone);
  g->warm[g->nwarm].hot = hot;
  g->nwarm++;
  if (hot) {
    g->nhot++;
    atomic_store_explicit(&g_wl_pending, g->nhot, memory_order_relaxed);
    if (fresh) atomic_fetch_add_explicit(&g_wl_queued, 1, memory_order_relaxed);
  }
  atomic_store_explicit(&g_warm_n, (uint32_t)g->nwarm, memory_order_relaxed);
}

static void warm_add(ing_t *g, const char *view, const char *zone) { warm_add_ex(g, view, zone, false, false); }

/* The hot items of the warm list are taken from its head only when there is room for them (so that the order of the list holds): the queries come first (fewer than
 * ING_WARM_NFREQ fetches in flight, the rate bucket at least half full), the limit is respected, and at the high water mark of memory-limit the rest of the hot
 * list is dropped (design 8.4: warming never takes memory from the zones that are in use).  1: read the head now; 0: not now (it stays); -1: the hot items were
 * dropped, look at the list again. */
static void warm_drop_hot(ing_t *g) {
  size_t k = 0;
  for (size_t i = 0; i < g->nwarm; i++) {
    bool whole = false;
    if (g->warm[i].hot) {
      /* a pinned zone is never dropped: it is read whole whatever the memory says (dbreg_warm_take() says it is pinned), so it stays as a zone of the list that is
       * not hot (the flag is set again: it was the hot item that had put it in the list, and a pin summary for it was refused as a duplicate) */
      if (dbreg_warm_take(g->warm[i].view, g->warm[i].zone, &whole) && whole && dbreg_warm_mark(g->warm[i].view, g->warm[i].zone)) {
        g->warm[k] = g->warm[i];
        g->warm[k++].hot = false;
      } else {
        atomic_fetch_add_explicit(&g_wl_dropmem, 1, memory_order_relaxed);
      }
    } else {
      g->warm[k++] = g->warm[i];
    }
  }
  g->nwarm = k;
  g->nhot = 0;
  atomic_store_explicit(&g_wl_pending, 0, memory_order_relaxed);
  atomic_store_explicit(&g_warm_n, (uint32_t)g->nwarm, memory_order_relaxed);
}
static int warm_hot_gate(ing_t *g) {
  if (g->nfreq - g->nbulk >= fetch_sub_limit(ING_WARM_NFREQ)) return 0;      /* (the fill's bodies do not count: they have their own limit, fill_limit()) */
  if (dbreg_cache_limit()) {
    /* the zones in flight are not in the resident bytes yet: estimate them from what the zones of the list added so far (a zone of the list is about that big);
     * until one is in, one at a time.  The mark is the cache manager's high water mark: no zone is taken out of memory to make room for the warm-up. */
    uint64_t loaded = atomic_load_explicit(&g_wl_loaded, memory_order_relaxed), est = 0;
    zone_bytes_t zb;
    zone_bytes_get(ZBYTES_DB, &zb);
    if (loaded > g->warm_l0 && zb.resident > g->warm_r0) est = (zb.resident - g->warm_r0) / (loaded - g->warm_l0);
    if (est == 0 && g->nhot_flight > 0) return 0;
    /* (the zones in flight differ from the average: with one or more in flight the room for them is counted twice, so that the overshoot past the mark stays about one zone) */
    if (g->nhot_flight > 0 && dbreg_cache_over_high(est * 2 * ((uint64_t)g->nhot_flight + 1))) return 0;
    if (dbreg_cache_over_high(est * ((uint64_t)g->nhot_flight + 1))) {
      syslog(LOG_INFO, "[DB] warm-up: the database zones reached the high water mark of memory-limit; %u zone(s) of the hot list are not read", g->nhot);
      warm_drop_hot(g);
      return -1;
    }
    if (g->nfreq - g->nbulk >= atomic_load_explicit(&g_fetch_conc, memory_order_relaxed) || dbreg_cache_over_limit()) return 0;
  }
  return park_rate_check(now_ms(), true) ? 1 : 0;        /* the bucket is at least half full (and has a token): the queries come first */
}

/* B2 W5: one pass of fetch_issue() runs about ING_FETCH_SLICE_NS (a time slice, checked every eighth request) and then the main loop serves the streams (the loader's answers, the
 * installs, the delta) before it comes back: a flood of requests cannot keep the thread in here.  (At 200k queries a second for zones out of memory one pass ran 4 to
 * 130 ms, 97% of the thread, and the FETCH_REQs of the whole pass were written at its end: a fetch took 10 to 100 ms to start and the loader's answers waited for the
 * next pass.)  The FETCH_REQs made in a pass are written when it ends, so a request leaves at most about ING_FETCH_SLICE_NS after it was made.
 * 0.7: the pass was also cut at 64 requests, and a lookup of a name costs a few microseconds: a loop that passes 200 times a second (it waits for the store between two passes) drained 13000 requests a second from
 * rings that fill at 400000 a second (the workers' rings of PARK_FETCH_RING requests were full: take_fail, drop.room).  The count is a limit only against a clock that does not advance. */
#define ING_FETCH_SLICE_N 4096
#define ING_FETCH_SLICE_NS 1000000LL

/* A request that is being handled may hold a place of the pool of fetch-concurrency (park_place_take(): this thread takes it below, nobody else does) and a
 * token of the fetch-rate bucket.  They are given back here on every path that does not end in a fetch; a fetch keeps the place (ing_freq_t.placed) until it is over
 * (fetch_complete()) and the token is spent.  The claim mark of the zone (park_claim_mark(), B2 M1) is cleared on every path as well, a fetch that starts included (from then on the
 * state is LOADING, which is what tells the workers); `key` is the mark's key, 0 when the request holds none. */
static void fetch_release(bool *place, bool *tok, uint64_t *key) {
  if (*place) park_place_give();
  if (*tok) park_rate_give();
  if (*key) park_claim_clear(*key);
  *place = *tok = false;
  *key = 0;
}

/* The request cannot be made (the wait queue is full, a view is gone, no free slot of the table): its queries get "not ready" now.  A request that holds a claim speaks for every
 * worker that parked for the zone without one (their requests are dropped while the mark is up, see below), so all of them are told; any other request concerns its worker only. */
static void fetch_refuse(const park_fetch_req_t *q) {
  if (q->claimed) park_wake_queue_claim(q->view, q->zone, park_claim_key(q->view, q->zone), true, 0);
  else park_wake_queue_one(q->worker, q->view, q->zone, true);
}

/* ---- 0.7 P-B: the wait queue ----
 * A request of a query (a worker's, or a zone transfer's) that cannot be made now is not refused: it waits here, oldest first, and goes out when the thread has what it needs:
 *   - a place of fetch-concurrency (park_place_take(): fetches in flight, and nothing else, hold places: the reads that protect the database),
 *   - a token of fetch-rate (park_rate_take(); with no rate, the default, there is no bucket and nothing to wait for),
 *   - room, when the database zones are above the hard line of memory-limit (110%): the thread takes the coldest zones out of memory now (dbreg_cache_make_room(): the coldest first,
 *     the minimum residency only relaxed as far as needed; the rules are there), not more often than every ING_WQ_TICK_MS while that does not help, and the request goes
 *     when the zones in memory are back under the line (0.7 B2 W8).
 * The head goes first; a request that comes while others wait goes behind them (so the order holds whichever of the three held the head up).  An entry holds the claim mark
 * of its zone (a request for a marked zone is a duplicate and is dropped, so there is one entry per zone), and nothing else: the place and the token are taken at the moment
 * the request is made, so waiting requests cannot use up the pool or the bucket.  Its deadline is park-timeout from when the thread took it; past that the queries that waited
 * for it have timed out at their workers (SERVFAIL + EDE 14, `park_timeout` in dbstatus), so the entry is dropped, the mark cleared, and the workers are woken (not failed): a query
 * that came later, with time left, asks again (a new entry), and one with none left answers "not ready".  Only a full queue refuses (ING_WQ_MAX: the park tables of the workers
 * bound the queries, so it is full only when thousands of zones are asked for at once and nothing is read), counted in `shed` and `queue_full`.
 * The warm-up and the background requests are not queries: they do not wait, and none is made while a query waits (they would take its place). */
static _Atomic uint64_t g_wq_waited, g_wq_dropped, g_wq_full;      /* requests that had to wait / were dropped at their deadline / found the queue full */
static _Atomic uint32_t g_wq_len, g_wq_peak;                       /* waiting now, the most there have been */

static void wq_note(ing_t *g) {
  atomic_store_explicit(&g_wq_len, g->nwq, memory_order_relaxed);
  atomic_store_explicit(&g_room_waiting, g->nwq_room, memory_order_relaxed);
  if (g->nwq > atomic_load_explicit(&g_wq_peak, memory_order_relaxed)) atomic_store_explicit(&g_wq_peak, g->nwq, memory_order_relaxed);
}

/* the entry has been held up by room (counted once per entry: room_waits, and room_timeouts if it ran out of time) */
static void wq_mark_room(ing_t *g, struct ing_wq *e) {
  if (e->room) return;
  e->room = true;
  g->nwq_room++;
  atomic_fetch_add_explicit(&g_room_waits, 1, memory_order_relaxed);
  wq_note(g);
}

static void wq_take_head(ing_t *g, struct ing_wq *out) {
  *out = g->wq[g->wq_head];
  g->wq_head = (g->wq_head + 1) % ING_WQ_MAX;
  g->nwq--;
  if (out->room) g->nwq_room--;
  wq_note(g);
}

/* Entries whose time is up are dropped: the claim mark goes, and the workers are woken, not failed (see above) */
static void wq_expire(ing_t *g, int64_t now) {
  while (g->nwq > 0 && g->wq[g->wq_head].deadline_ms <= now) {
    struct ing_wq e;
    wq_take_head(g, &e);
    atomic_fetch_add_explicit(&g_wq_dropped, 1, memory_order_relaxed);
    if (e.room) atomic_fetch_add_explicit(&g_room_timeouts, 1, memory_order_relaxed);
    park_wake_queue_claim(e.q.view, e.q.zone, e.key, false, 0);        /* (a transfer's request too: workers may have parked for its mark; the workers that asked are told, every worker when the mark knows none) */
    if (e.key) park_claim_clear(e.key);
  }
}

/* Can the oldest waiting request be made now?  Room first (make it, not more often than every ING_WQ_TICK_MS when that did not help: the scan holds the registry lock), then
 * a place, then a token.  Nothing is taken: the loop takes them when it makes the request (only this thread takes places and tokens). */
static bool wq_head_ready(ing_t *g, int64_t now) {
  struct ing_wq *h = &g->wq[g->wq_head];
  if (dbreg_cache_over_limit()) {
    if (now < g->room_next_ms) {
      wq_mark_room(g, h);
      return false;
    }
    uint32_t conc = atomic_load_explicit(&g_fetch_conc, memory_order_relaxed);
    (void)dbreg_cache_make_room(g->nwq < conc ? g->nwq : conc, NULL);
    if (dbreg_cache_over_limit()) {
      g->room_next_ms = now + ING_WQ_TICK_MS;
      wq_mark_room(g, h);
      return false;
    }
  }
  if (!park_place_avail() || g->nfreq >= ING_FETCH_MAX) return false;      /* (a place of fetch-concurrency, and a slot of the table: summaries and the warm-up use some) */
  return park_rate_check(now, false);
}

/* The request in hand waits.  Place and token go back; the claim mark moves to the entry (a request that holds none marks its zone now: when the zone is marked already the
 * request is a duplicate and is dropped).  `deadline` is 0 for a request that is new (park-timeout from now) and the entry's own for one that was taken from the head and
 * goes back to it (front).  false: the queue is full, nothing was kept (the caller refuses the request, wq_overflow()). */
static bool wq_wait(ing_t *g, const park_fetch_req_t *q, bool *place, bool *tok, uint64_t *key, int64_t deadline, bool room, bool front, int64_t now) {
  if (*place) park_place_give();
  if (*tok) park_rate_give();
  *place = *tok = false;
  uint64_t k = *key;
  bool marked_here = false;
  if (k == 0) {
    k = park_claim_key(q->view, q->zone);
    const bool marked = park_claim_mark(k);
    park_claim_note_worker(k, q->worker);
    if (!marked) return true;                            /* a request for this zone is on its way or waits already */
    marked_here = true;
  }
  if (!g->wq || g->nwq >= queue_cap(&db_ingest_test_wq_max, ING_WQ_MAX)) {
    if (marked_here) park_claim_clear(k);
    return false;
  }
  uint32_t slot;
  if (front) {
    g->wq_head = (g->wq_head + ING_WQ_MAX - 1) % ING_WQ_MAX;
    slot = g->wq_head;
  } else {
    slot = (g->wq_head + g->nwq) % ING_WQ_MAX;
  }
  struct ing_wq *e = &g->wq[slot];
  e->q = *q;
  e->key = k;
  e->deadline_ms = deadline ? deadline : now + (int64_t)atomic_load_explicit(&g_park_timeout_ms, memory_order_relaxed);
  e->room = false;
  g->nwq++;
  if (room) wq_mark_room(g, e);
  if (!front) atomic_fetch_add_explicit(&g_wq_waited, 1, memory_order_relaxed);
  *key = 0;
  wq_note(g);
  return true;
}

/* The queue is full: the request is shed, the only loss of a query that is left (true overload).  0.7: its queries are dropped and counted (store.park.drop.queue), like the queries that RRL drops: not answered "not ready" for a
 * zone that the database has */
static void wq_overflow(const park_fetch_req_t *q) {
  atomic_fetch_add_explicit(&g_wq_full, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_fetch_shed, 1, memory_order_relaxed);
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] fetch of zone '%s' (view '%s') shed: the wait queue is full; its queries are dropped", q->zone, q->view);
  if (q->claimed) park_wake_queue_claim(q->view, q->zone, park_claim_key(q->view, q->zone), false, PARK_ASK_DROP);
  else park_wake_queue_drop_one(q->worker, q->view, q->zone);
}

static void fetch_issue(ing_t *g) {
  park_fetch_req_t q;
  bool warm = false;
  size_t warm_left = g->nwarm;                           /* the zones that were in the list when the pass started (those put back wait for the next pass) */
  bool hot = false;
  bool bulk = false, bulk_np = false;                    /* 0.7 WP7b: the request in hand is of the background fetch of the wanted bodies (the scan of the store) */
  uint32_t bulk_zid = 0, bulk_back = 0;                  /* ... the zone's id in the store, and where the scan stood before it */
  int64_t bulk_sid = 0;
  bool hold_place = false, hold_tok = false;             /* what the request in hand holds (fetch_release()) */
  uint64_t hold_key = 0;                                 /* the claim mark of the request in hand */
  bool from_wq = false, wq_room = false;                 /* the request in hand was the head of the wait queue (0.7 P-B), and had been held up by room */
  int64_t wq_deadline = 0;                               /* ... and its deadline */
  int handled = 0;
  int64_t t0 = mono_ns();
  g->fmore = false;
  if (g->nwq > 0) wq_expire(g, now_ms());                /* (the requests that waited until park-timeout) */
  if (g->nlq > 0) lq_expire(g, now_ms());                /* (and the lookups) */
  for (;;) {
    fetch_release(&hold_place, &hold_tok, &hold_key);    /* (the request of the last round did not become a fetch: it was refused, a duplicate, or in memory) */
    from_wq = wq_room = false;
    bulk = false;
    wq_deadline = 0;
    if (++handled > ING_FETCH_SLICE_N || ((handled & 7) == 0 && mono_ns() - t0 >= ING_FETCH_SLICE_NS)) {
      g->fmore = true;
      break;
    }
    if (handled == 1 && !g->qonly && g->nbulk < bulk_reserve() && bulk_take(g, &q, &bulk_zid, &bulk_back, &bulk_np, &bulk_sid)) {      /* 0.7 fix 8: the fill's own share, once in a pass, whatever waits */
      warm = hot = false;
      bulk = true;
    } else if (g->nlq > 0 && g->lq_turn && lq_pump_one(g)) {      /* 0.7: a lookup, in its turn (the lookups and the fetches that wait take places by turns) */
      g->lq_turn = false;
      continue;
    } else if (g->nwq > 0 && wq_head_ready(g, now_ms())) {      /* the oldest request that waited goes first (it holds its claim mark and nothing else) */
      struct ing_wq e;
      g->lq_turn = true;
      wq_take_head(g, &e);
      warm = hot = false;
      q = e.q;
      q.claimed = e.key != 0;
      hold_key = e.key;
      from_wq = true;
      wq_room = e.room;
      wq_deadline = e.deadline_ms;
    } else if (g->nlq > 0 && lq_pump_one(g)) {           /* 0.7: a lookup waits and the fetches that wait could not go */
      continue;
    } else if (park_fetch_next(&q)) {
      warm = hot = false;                                /* (a query's request is not of the hot list, whatever the item before it in this pass was) */
      if (q.claimed) {                                   /* (a worker marked the zone at its gate) */
        hold_key = park_claim_key(q.view, q.zone);
        park_claim_note_worker(hold_key, q.worker);
      }
    } else if (g->nwarm > 0 && warm_left > 0 && g->nwq == 0 && g->nlq == 0 && !g->qonly) {      /* (the warm-up does not take what queries wait for) */
      size_t wi = 0;                                     /* the item to take: the head, or (hot items that cannot be read now) the first that is not hot */
      if (g->warm[0].hot) {                              /* (a hot item is not taken out of the list until it can be read, so that the order of the list holds) */
        int gate = warm_hot_gate(g);
        if (gate < 0) {
          warm_left = g->nwarm < warm_left ? g->nwarm : warm_left;
          continue;
        }
        if (gate == 0) {                                 /* a pinned zone or an apex behind the hot items does not wait for them */
          while (wi < g->nwarm && g->warm[wi].hot) wi++;
          if (wi == g->nwarm) break;
        }
      }
      warm = true;
      warm_left--;
      memset(&q, 0, sizeof(q));
      q.worker = -1;
      snprintf(q.view, sizeof(q.view), "%s", g->warm[wi].view);
      snprintf(q.zone, sizeof(q.zone), "%s", g->warm[wi].zone);
      q.prio = KDB_FETCH_PRIO_WARM;
      hot = g->warm[wi].hot;
      memmove(g->warm + wi, g->warm + wi + 1, (g->nwarm - wi - 1) * sizeof(*g->warm));
      g->nwarm--;
      if (hot) {
        g->nhot--;
        atomic_store_explicit(&g_wl_pending, g->nhot, memory_order_relaxed);
      }
      atomic_store_explicit(&g_warm_n, (uint32_t)g->nwarm, memory_order_relaxed);
      bool whole = false;
      if (hot) {
        if (!dbreg_warm_take_hot(q.view, q.zone)) continue;        /* in memory by now (a query read it), or gone: nothing to read */
        whole = true;
      } else if (!dbreg_warm_take(q.view, q.zone, &whole)) continue;
      /* it came into memory meanwhile, was deleted, or has nothing to read for (not pinned, has an apex) */
      q.mode = whole ? KDB_FETCH_FULL : KDB_FETCH_SUMMARY;         /* a pinned zone whole; any other zone in the list is there for its apex */
      if ((whole && g->nfreq - g->nbulk >= fetch_sub_limit(ING_WARM_NFREQ)) || (!whole && g->nsum >= fetch_sub_limit(ING_SUMMARY_NFREQ))) {      /* the zones nobody asked for yet wait for a free place */
        warm_add_ex(g, q.view, q.zone, hot, false);
        break;
      }
    } else if (!g->qonly && (g->nwq == 0 || g->nbulk < bulk_reserve()) && bulk_take(g, &q, &bulk_zid, &bulk_back, &bulk_np, &bulk_sid)) {      /* 0.7 WP7b: the bodies the reconcile wants, after the queries and the warm-up */
      warm = hot = false;
      bulk = true;
    } else {
      break;
    }
    int vi = -1;
    for (uint32_t i = 0; i < g->nview_names; i++) {
      if (g->view_db && g->view_db[i] && strcasecmp(g->view_names[i], q.view) == 0) {
        vi = (int)i;
        break;
      }
    }
    if (q.mode == KDB_FETCH_LOOKUP) {                    /* 0.7: a name, not a zone: it takes a place when there is one and waits in its own queue when there is none (lookup_offer()) */
      lookup_offer(g, &q, vi);
      continue;
    }
    if (vi < 0) {                                        /* a view that takes no zones from the database (or left): nothing to fetch */
      park_wake_queue_all(q.view, q.zone, true);
      continue;
    }
    /* in flight for the same thing: its answer wakes this worker too.  A summary does not stand in for the zone (it wakes nobody, and the query would have to ask
     * again: the request for the zone is made); the zone in flight stands in for the summary (the apex of a zone that leaves memory is made from its image) */
    ing_freq_t *r = fetch_find_zone(g, (uint16_t)vi, q.zone, q.mode);
    /* 0.7 first-fill latency: a request of a query (or a transfer) does not join a body of the fill on its way: the loader reads the fill after every query (fq_pick(), karidns_dbloader.c),
     * so the query would wait behind the fill.  It makes its own request, of its priority; the body that comes second is dropped as unchanged (the version is the one the first installed) */
    if (r && !(r->bulk && q.mode == KDB_FETCH_FULL && q.prio == KDB_FETCH_PRIO_QUERY && !bulk && !warm)) continue;
    r = NULL;
    /* a worker that found the zone claimed asked without a claim (B2 M1): the claimed request is queued, and it takes the place and the token, starts the fetch and wakes every
     * worker (the completion), or fails them all (fetch_refuse()).  This request would be a second one for the same zone, so it is dropped. */
    if (!q.claimed && !warm && q.mode == KDB_FETCH_FULL && q.worker >= 0 && park_claim_held(park_claim_key(q.view, q.zone))) {
      park_claim_note_worker(park_claim_key(q.view, q.zone), q.worker);       /* (this worker waits for the claimed request too: it is told when that one ends) */
      continue;
    }
    if (q.mode == KDB_FETCH_SUMMARY) {
      ing_freq_t *full = fetch_find_zone(g, (uint16_t)vi, q.zone, KDB_FETCH_FULL);
      if (full) {
        full->want_summary |= warm;                       /* (a query's summary does not take back what the walk asked for) */
        continue;
      }
    }
    /* A query's request (a worker's, or a transfer's) that cannot be made now waits in the queue (0.7 P-B, "the wait queue"); the warm-up, the summaries and the background
     * requests do not (they are not queries): they are put back, or refused as they always were. */
    const bool can_wait = !warm && q.mode == KDB_FETCH_FULL && q.prio == KDB_FETCH_PRIO_QUERY;
    if (can_wait && !from_wq && g->nwq > 0) {            /* others wait: this one goes behind them */
      if (!wq_wait(g, &q, &hold_place, &hold_tok, &hold_key, 0, false, false, now_ms())) wq_overflow(&q);
      continue;
    }
    if (q.mode != KDB_FETCH_SUMMARY) {
      /* memory-limit (design 8.5): the zones that are fetched add to what the cache manager has to take out again.  With the database zones above the hard line, or every place
       * of fetch-concurrency taken, the request of a query waits (it is not refused); the others are not made.  Without memory-limit the zones are never above the line, but the
       * places of fetch-concurrency hold the queries back all the same: a zone that the store knows without an image, or one of a database without a store, is fetched for a
       * query with no limit set too (0.7), and a burst of them waits for a place, not for a refusal when the 256 places of the table are taken.
       * (A summary brings no zone data: the limit does not hold it back, ING_SUMMARY_NFREQ bounds it.) */
      {
        /* the places of fetch-concurrency are one pool (park_place_take()): only this thread takes them (a fetch keeps its place until it is over), so that fetches in flight
         * stay within the limit */
        bool over = dbreg_cache_over_limit();
        if (over && can_wait) {
          /* (0.7 B2 W8) room on demand: with none waiting before it, room is made now (the zones that the cache manager would take at its next round, the coldest first); if that
           * does not bring the zones in memory under the hard line the request waits for it (wq_head_ready() makes room again) */
          int64_t tn = now_ms();
          if (g->nwq == 0 && tn >= g->room_next_ms) {
            (void)dbreg_cache_make_room(1, NULL);
            over = dbreg_cache_over_limit();
            if (over) g->room_next_ms = tn + ING_WQ_TICK_MS;
          }
          if (over) {
            if (!wq_wait(g, &q, &hold_place, &hold_tok, &hold_key, wq_deadline, true, from_wq, tn)) wq_overflow(&q);
            continue;
          }
        }
        if (!over && !hold_place && !bulk && (can_wait || g->nwq == 0)) hold_place = park_place_take();
        if (over || (!hold_place && !bulk)) {      /* (0.7 first-fill latency: a body of the fill takes no place, bulk_take() kept it to fill_limit()) */
          if (can_wait) {                                /* every place is taken */
            if (!wq_wait(g, &q, &hold_place, &hold_tok, &hold_key, wq_deadline, wq_room, from_wq, now_ms())) wq_overflow(&q);
            continue;
          }
          if (bulk) {                                       /* (0.7 WP7b: the scan stands before the zone again; it is asked for at the next pass) */
            g->bg_zid = bulk_back;
            if (bulk_np) db_recon_scan_retry(bulk_zid);
            break;
          }
          if (warm) {
            warm_add_ex(g, q.view, q.zone, hot, false);
            break;
          }
          atomic_fetch_add_explicit(&g_fetch_shed, 1, memory_order_relaxed);
          logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] fetch of zone '%s' (view '%s') not made (a background request): %s", q.zone, q.view,
                     over ? "the database zones in memory are over the limit" : "as many fetches in flight as fetch-concurrency allows, or queries wait");
          fetch_refuse(&q);
          continue;
        }
      }
    }
    /* fetch-rate (design 8.5): scattered queries for many zones that are out of memory must not make the loader read zones faster than this; a token bucket (burst = one second
     * of the rate) of zones read for queries.  Only a read that is really made takes a token (below).  With no rate (the default, 0.7 P-A) the bucket is not there: park_rate_take()
     * returns at once.  A query's request that finds the bucket empty waits (0.7 P-B); a background request is refused (`refused_by_rate`). */
    if (!hold_tok) {
      /* the queries come first: a summary for the apex (the walk after a reload) takes a token only from a bucket that is more than half full, so that the walk
       * cannot leave the queries without one; ... and so does a whole zone that the query path asks for in the background (a CNAME or glue leads into it, D1a step 8) */
      bool half = (warm && q.mode == KDB_FETCH_SUMMARY) || (q.prio == KDB_FETCH_PRIO_BACKGROUND && q.mode == KDB_FETCH_FULL);
      hold_tok = park_rate_take(now_ms(), half);
      if (!hold_tok) {
        if (can_wait) {
          if (!wq_wait(g, &q, &hold_place, &hold_tok, &hold_key, wq_deadline, wq_room, from_wq, now_ms())) wq_overflow(&q);
          continue;
        }
        if (bulk) {                                       /* (0.7 WP7b: the scan stands before the zone again; it is asked for at the next pass) */
          g->bg_zid = bulk_back;
            if (bulk_np) db_recon_scan_retry(bulk_zid);
          break;
        }
        if (warm) {
          warm_add_ex(g, q.view, q.zone, hot, false);
          break;
        }
        atomic_fetch_add_explicit(&g_fetch_limited, 1, memory_order_relaxed);
        logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] fetch of zone '%s' (view '%s') held back by fetch-rate %u/s: no token left", q.zone,
                   q.view, (unsigned)atomic_load_explicit(&g_fetch_rate, memory_order_relaxed));
        fetch_refuse(&q);
        continue;
      }
    }
    /* a slot of the table first, before the registry is asked: a request that finds the table full is refused (or waits) without a lock of the registry (it used to make an element of the zone
     * for the request and take it away again, two sections of the lock that every attach and every install wait for) */
    for (uint32_t i = 0; i < ING_FETCH_MAX && !r; i++)
      if (!g->freq[i].active) r = &g->freq[i];
    if (!r) {                                            /* every slot is taken */
      if (can_wait) {                                    /* a query's request waits for a slot, as for a place */
        if (!wq_wait(g, &q, &hold_place, &hold_tok, &hold_key, wq_deadline, wq_room, from_wq, now_ms())) wq_overflow(&q);
        continue;
      }
      if (bulk) {                                       /* (0.7 WP7b: the scan stands before the zone again; it is asked for at the next pass) */
        g->bg_zid = bulk_back;
            if (bulk_np) db_recon_scan_retry(bulk_zid);
        break;
      }
      if (warm) {
        warm_add_ex(g, q.view, q.zone, hot, false);
        break;
      }
      atomic_fetch_add_explicit(&g_fq_table_full, 1, memory_order_relaxed);
      fetch_refuse(&q);
      continue;
    }
    /* 0.7 first-fill latency: a request of a query that waited (a place, the wait queue) while the fill, 256 bodies in flight, brought its zone into the store: the zone is attached
     * from there, not read from the database a second time; the queries are woken and look again (as for a zone that came into memory meanwhile, below).  Only a worker's request: a
     * transfer (worker -1) waits for the zone in memory, which a wake-up does not bring */
    if (!bulk && !warm && q.worker >= 0 && q.mode == KDB_FETCH_FULL && dbdir()) {
      dbdir_rec_t rec;
      if (dbdir()->rec_get(q.view, q.zone, &rec) && rec.state == STORE_STATE_STORED && !(rec.flags & STORE_F_STALE)) {
        park_wake_queue_all(q.view, q.zone, false);
        continue;
      }
    }
    int st = (q.mode == KDB_FETCH_SUMMARY || bulk) ? DBREG_FETCH_STARTED : dbreg_fetch_begin(g->view_names[vi], q.zone);       /* (a summary leaves the zone's state alone: queries are not held for it) */
    if (st == DBREG_FETCH_BUSY) continue;
    if (st != DBREG_FETCH_STARTED) {                     /* in memory already (woken), or not a zone of the registry (answered at once) */
      park_wake_queue_all(q.view, q.zone, st == DBREG_FETCH_NONE);
      continue;
    }
    if (q.mode == KDB_FETCH_SUMMARY) {
      g->nsum++;
      atomic_fetch_add_explicit(&g_apex_asked, 1, memory_order_relaxed);
    } else {
      atomic_fetch_add_explicit(&g_fetch_issued, 1, memory_order_relaxed);
    }
    memset(r, 0, sizeof(*r));
    r->placed = hold_place;                              /* (the place stays with the fetch; the token is spent) */
    hold_place = hold_tok = false;
    if (hold_key) {                                      /* (the zone is LOADING: that is what the workers look at now) */
      park_claim_clear(hold_key);
      hold_key = 0;
    }
    if (q.mode != KDB_FETCH_SUMMARY) r->v_valid = dbreg_zone_version(g->view_names[vi], q.zone, &r->v_sid, &r->v_serial);
    if (bulk) {                                           /* 0.7 WP7b */
      r->bulk = true;
      r->nonstore = bulk_np;
      r->bzid = bulk_zid;
      r->sid = bulk_sid;
      g->nbulk++;
      db_recon_note_fetch(DBR_IN_FLIGHT, g->nbulk);
    } else if (r->v_valid) {
      r->sid = r->v_sid;
    }
    if (q.mode != KDB_FETCH_SUMMARY) freq_stamp(r, g->view_names[vi], q.zone);
    r->active = true;
    r->id = ++g->fseq;
    r->view = (uint16_t)vi;
    r->prio = q.prio < KDB_FETCH_PRIO_N ? q.prio : KDB_FETCH_PRIO_QUERY;
    r->mode = q.mode <= KDB_FETCH_SUMMARY ? q.mode : KDB_FETCH_FULL;
    r->quiet = warm && r->mode == KDB_FETCH_SUMMARY;
    if (hot) {
      r->hot = true;
      r->hrank = g->hot_issued++;
      g->nhot_flight++;
      atomic_store_explicit(&g_wl_flight, g->nhot_flight, memory_order_relaxed);
    }
    r->sent_ms = now_ms();
    snprintf(r->view_name, sizeof(r->view_name), "%s", g->view_names[vi]);
    snprintf(r->zone, sizeof(r->zone), "%s", q.zone);
    r->zh = dns_name_hash_ci(r->zone);
    g->nfreq++;
    atomic_store_explicit(&g_fq_inflight, g->nfreq, memory_order_relaxed);
    if (g->nfreq > atomic_load_explicit(&g_fq_peak, memory_order_relaxed)) atomic_store_explicit(&g_fq_peak, g->nfreq, memory_order_relaxed);
    logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] fetch %llu: zone '%s' (view '%s'), %s, %s%s; %u in flight", (unsigned long long)r->id, r->zone, r->view_name,
               r->mode == KDB_FETCH_SUMMARY ? "summary (the apex)" : "whole zone", r->prio == KDB_FETCH_PRIO_WARM ? "warm-up" :
               r->prio == KDB_FETCH_PRIO_BACKGROUND ? "background (CNAME or glue)" : "for a query", hot ? ", hot list" : "", (unsigned)g->nfreq);
    if (!fetch_send_req(g, r)) fetch_complete(g, r, false, "the loader's fetch stream is not connected");
  }
  fetch_release(&hold_place, &hold_tok, &hold_key);
  {                                                      /* the pass, for store.lookup.drain_* (a pass that handled nothing is not counted) */
    const uint32_t n = handled > 1 ? (uint32_t)(handled - 1) : 0;      /* (the count is one ahead at the end: it was raised to look at the next request) */
    if (n > 0) {
      const uint64_t ns = (uint64_t)(mono_ns() - t0);
      atomic_fetch_add_explicit(&g_fp_passes, 1, memory_order_relaxed);
      if (g->fmore) atomic_fetch_add_explicit(&g_fp_cut, 1, memory_order_relaxed);
      if (n > atomic_load_explicit(&g_fp_max_n, memory_order_relaxed)) atomic_store_explicit(&g_fp_max_n, n, memory_order_relaxed);
      if (ns > atomic_load_explicit(&g_fp_max_ns, memory_order_relaxed)) atomic_store_explicit(&g_fp_max_ns, ns, memory_order_relaxed);
    }
  }
  if (g->fetch_fd >= 0 && g->fout_off < g->fout_len) fetch_flush(g);      /* (the requests of the pass go out now) */
  wake_flush(g);
}

static void fetch_protocol_error(ing_t *g, const char *reason) {
  syslog(LOG_ERR, "[DB] protocol error from the loader on the fetch stream: %s; closing it", reason);
  fetch_drop(g);
}

static void fetch_discard(ing_t *g, const kdb_zone_begin_t *zb, const char *why) {
  g->funsolicited++;
  if (g->funsolicited <= 8)
    syslog(LOG_WARNING, "[DB] the loader sent a zone on the fetch stream that was not asked for (%s); discarded", why);
  (void)zb;
}

static void on_fetch_begin(ing_t *g, const kdb_zone_begin_t *zb) {
  ing_freq_t *r = fetch_find(g, zb->request_id);
  bool wanted = r && r->view == zb->view && domain_names_match_ci(r->zone, zb->name);
  if (wanted) {
    bool summary = (zb->flags & KDB_ZF_SUMMARY) != 0;
    /* a summary request is answered with a summary (a secondary zone has no data to leave out); a full request with the zone */
    wanted = r->mode == KDB_FETCH_SUMMARY ? (summary || zb->zone_kind != KDB_ZK_PRIMARY) : !summary;
  }
  if (r && r->lk) {                                      /* 0.7: the body of a lookup (mode KDB_FETCH_LOOKUP_FULL) is the zone the answer named, once, after the answer: nothing else is read for the request */
    wanted = wanted && r->lkst != LKS_ASK && !r->body_seen && zb->source_id == r->lk_sid;
    if (!wanted) atomic_fetch_add_explicit(&g_lk_bad, 1, memory_order_relaxed);
    else r->body_seen = true;
  }
  if (!wanted || (r && r->lk && r->lkst == LKS_SKIP)) {  /* nobody asked (or the zone is not wanted: LKS_SKIP): read it through the state machine and throw it away */
    ing_job_t *j = calloc(1, sizeof(*j));
    if (!j) {
      syslog(LOG_ERR, "[DB] out of memory; closing the fetch stream");
      fetch_drop(g);
      return;
    }
    j->skip = j->unsolicited = true;
    j->fetch_id = zb->request_id;
    if (wanted) j->lk_skip = true;                       /* (the end of the body is the end of the request) */
    else fetch_discard(g, zb, r ? (r->lk ? "it is not the body the lookup's answer announced" : "it is not what the request wants") : "no such request");
    job_free(g->fcur);
    g->fcur = j;
    return;
  }
  prof_swap(g);
  ing_job_t *j = job_from_begin(g, zb, false);
  prof_swap(g);
  if (!j) {
    syslog(LOG_ERR, "[DB] out of memory; closing the fetch stream");
    fetch_drop(g);
    return;
  }
  j->fill = r && r->bulk;
  if (r && r->v_valid) {
    j->iv_valid = true;
    j->iv_sid = r->v_sid;
    j->iv_serial = r->v_serial;
  }
  if (r && r->st_valid) {                                /* 0.7 WP7b */
    j->iv_st_valid = true;
    j->iv_st_gen = r->st_gen;
    j->iv_st_time = r->st_time;
  }
  job_free(g->fcur);
  g->fcur = j;
}

static void on_fetch_end(ing_t *g) {
  ing_job_t *j = g->fcur;
  g->fcur = NULL;
  if (!j) return;
  if (j->unsolicited) {
    if (j->lk_skip) {                                    /* 0.7: the body that was not wanted has been read through: the lookup is over */
      ing_freq_t *r = fetch_find(g, j->fetch_id);
      if (r) fetch_complete(g, r, true, NULL);
    }
    job_free(j);
    return;
  }
  job_submit(g, j);                                      /* (job_finish() -> fetch_job_finish()) */
}

static void on_fetch_failed(ing_t *g, const kdb_zone_failed_t *zf) {
  ing_freq_t *r = fetch_find(g, zf->request_id);
  if (!r || r->view != zf->view || !domain_names_match_ci(r->zone, zf->name)) {
    fetch_discard(g, NULL, "a failure of no request");
    return;
  }
  char reason[KDB_REASON_LEN];
  sane_copy(reason, sizeof(reason), zf->reason.p, zf->reason.len);
  if (strcmp(reason, KDB_FETCH_BUSY_REASON) == 0) {
    atomic_fetch_add_explicit(&g_fq_loader_busy, 1, memory_order_relaxed);
    r->busy = true;
  } else {
    r->loader_failed = true;
  }
  fetch_complete(g, r, false, reason);
}

/* LOOKUP_RESULT: the zone of the view that encloses the name of a lookup, or none.  The entry is a claim of an untrusted loader: the request must be one that is in flight, and the zone must enclose
 * the name that was asked for (a loader that names another zone would put a zone that has nothing to do with the query into the store).  A zone that is recorded is a MANIFEST entry's record (KNOWN, or
 * the stamp noted when the store has it already): its body is read when a query asks for it, or by the scan of the wanted bodies; the pass of the view that is still going lists it too, and finds the record. */
static void on_lookup_result(ing_t *g, const kdb_lookup_result_t *l) {
  ing_freq_t *r = fetch_find(g, l->request_id);
  if (!r || !r->lk || r->lkst != LKS_ASK || r->view != l->view) {      /* (not a lookup, or answered already: a second answer, and a body that follows it, are no part of the request) */
    fetch_discard(g, NULL, "an answer of no lookup");
    return;
  }
  lookup_hist(mono_ns() - r->lk_t0);
  if (!l->found) {
    atomic_fetch_add_explicit(&g_lk_none, 1, memory_order_relaxed);
    fetch_complete(g, r, true, NULL);                    /* (the place is free at once) */
    return;
  }
  if (!domain_name_is_at_or_below(r->lk_q, l->name) || strcmp(l->name, ".") == 0 || l->source_id <= 0) {
    syslog(LOG_WARNING, "[DB] the loader answered the lookup of the name '%s' (view '%s') with a zone that does not enclose it; the answer is ignored", r->lk_q, r->view_name);
    fetch_complete(g, r, false, "the loader named a zone that does not enclose the name");
    return;
  }
  db_recon_entry_t re;
  memset(&re, 0, sizeof(re));
  re.source_id = l->source_id;
  re.name = l->name;
  re.kind = l->kind;
  re.stamped = l->stamped;
  re.gen = l->stamp_gen;
  re.time = l->stamp_time;
  re.has_serial = l->has_serial;
  re.serial = l->serial;
  uint32_t zid;
  const int rc = db_recon_lookup(r->view_name, &re, &zid);
  if (rc < 0) {
    fetch_complete(g, r, false, "the zone could not be recorded");
    return;
  }
  atomic_fetch_add_explicit(&g_lk_found, 1, memory_order_relaxed);
  logev_post(LOGC_DATABASE, 2, NULL, 0, "[DB] lookup %llu: the name '%s' is in zone '%s' (view '%s', id %lld)", (unsigned long long)r->id, r->lk_q, l->name, r->view_name, (long long)l->source_id);
  if (r->mode != KDB_FETCH_LOOKUP_FULL) {
    fetch_complete(g, r, true, NULL);
    return;
  }
  /* mode 3: the body of the zone follows, with this request id.  The request is the fetch of the zone from here on (the same place, the same id): LOADING for the queries that look at the zone, the record's
   * stamp (the one the answer made) for the check at the install.  When the zone is not started by this request (another fetch has it, it is in memory) the body is read through and thrown away. */
  snprintf(r->zone, sizeof(r->zone), "%s", l->name);
  r->zh = dns_name_hash_ci(r->zone);
  r->lk_sid = l->source_id;
  if (dbreg_fetch_begin(r->view_name, r->zone) == DBREG_FETCH_STARTED) {
    r->lkst = LKS_BODY;
    r->mode = KDB_FETCH_FULL;
    r->v_valid = dbreg_zone_version(r->view_name, r->zone, &r->v_sid, &r->v_serial);
    r->sid = l->source_id;
    freq_stamp(r, r->view_name, r->zone);
    atomic_fetch_add_explicit(&g_fetch_issued, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_lk_body, 1, memory_order_relaxed);
  } else {
    r->lkst = LKS_SKIP;
    park_wake_queue_claim(r->view_name, r->lk_q, r->ckey, false, 0);   /* (the zone is known: the queries need not wait for a body that is not read) */
  }
}

static void handle_fetch_msg(ing_t *g, const kdb_msg_t *m) {
  switch (m->type) {
  case KDB_T_PROFILE: {
    prof_swap(g);
    int rc = profile_store(g, m);
    prof_swap(g);
    if (rc == PROF_LIMIT) fetch_protocol_error(g, "PROFILE: more profile data than the Backend accepts");
    else if (rc == PROF_OOM) {
      syslog(LOG_ERR, "[DB] out of memory; closing the fetch stream");
      fetch_drop(g);
    }
    break;
  }
  case KDB_T_ZONE_BEGIN:
    on_fetch_begin(g, &m->u.zone_begin);
    break;
  case KDB_T_ZONE_IMAGE:
    job_image(g->fcur, m);
    break;
  case KDB_T_ZONE_END:
    on_fetch_end(g);
    break;
  case KDB_T_ZONE_ABORT: {
    ing_job_t *j = g->fcur;
    g->fcur = NULL;
    if (j && (!j->unsolicited || j->lk_skip)) {
      ing_freq_t *r = fetch_find(g, j->fetch_id);
      if (r) fetch_complete(g, r, j->lk_skip, "the loader gave the zone up");
    }
    job_free(j);
    break;
  }
  case KDB_T_ZONE_FAILED:
    on_fetch_failed(g, &m->u.zone_failed);
    break;
  case KDB_T_LOOKUP_RESULT:
    on_lookup_result(g, &m->u.lookup_result);
    break;
  default:
    break;
  }
}

static void on_fetch_readable(ing_t *g) {
  const int64_t t0 = mono_ns();
  unsigned handled = 0;
  for (int round = 0; round < ING_READ_ROUNDS && g->fetch_fd >= 0; round++) {
    if (g->fresume) {
      g->fresume = false;                                /* (the frames the last pass left are handled first) */
    } else {
      ssize_t n = read(g->fetch_fd, g->frbuf, ING_RBUF);
      if (n < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        syslog(LOG_NOTICE, "[DB] loader fetch stream disconnected (read: %s)", strerror(errno));
        fetch_drop(g);
        return;
      }
      if (n == 0) {
        syslog(LOG_NOTICE, "[DB] loader fetch stream disconnected");
        fetch_drop(g);
        return;
      }
      g->f_rx_ms = now_ms();
      if (kdb_framer_feed(&g->ffr, g->frbuf, (size_t)n) != KDB_OK) {
        fetch_protocol_error(g, g->ffr.reason);
        return;
      }
    }
    kdb_frame_t fr;
    for (;;) {
      kdb_rc_t rc = kdb_framer_next(&g->ffr, &fr);
      if (rc == KDB_MORE) break;
      if (rc != KDB_OK) {
        fetch_protocol_error(g, g->ffr.reason);
        return;
      }
      kdb_msg_t msg;
      rc = kdb_sm_accept(&g->fsm, &fr, &msg);
      if (rc != KDB_OK) {
        fetch_protocol_error(g, g->fsm.reason);            /* (the reason names the rule, never bytes of the stream) */
        return;
      }
      const bool fillmsg = g->fcur && g->fcur->fill && (msg.type == KDB_T_ZONE_IMAGE || msg.type == KDB_T_ZONE_END);
      const int64_t tm0 = fillmsg ? mono_ns() : 0;
      handle_fetch_msg(g, &msg);
      if (fillmsg) g->fill_ns += mono_ns() - tm0;
      if (g->fetch_fd < 0) return;
      if (ing_yield(t0, ++handled)) {
        g->fresume = true;
        return;
      }
    }
  }
}

static int hot_emit(void *ud) {
  ing_t *g = ud;
  if (g->enc.err) return -1;
  send_enc(g);
  return g->stream_fd < 0 ? -1 : 0;
}

/* The hot list the cache thread made goes to the loader (HOT_LIST, in parts); the loader merges it into its state file and answers with HOT_ACK.  A loader that
 * is not connected, or does not read, gets nothing: the next list is made after hot-list-interval. */
static void hot_send(ing_t *g) {
  kdb_hotl_t *l = atomic_exchange_explicit(&g_hot_out, NULL, memory_order_acquire);
  if (!l) return;
  if (g->stream_fd >= 0 && g->hello_done && g->out_len - g->out_off < ING_MAX_OUT / 2) {
    ing_cfg_t snap;
    snapshot_cfg(&snap);
    if (kdb_hot_encode(l, &g->enc, KDB_T_HOT_LIST, ++g->hot_seq, snap.hot_size, -1, 0, hot_emit, g) == 0) {
      atomic_fetch_add_explicit(&g_hot_sent, 1, memory_order_relaxed);
      atomic_store_explicit(&g_hot_last_n, l->n, memory_order_relaxed);
      atomic_store_explicit(&g_hot_last_sent, (int64_t)time(NULL), memory_order_relaxed);
    } else {
      kdb_enc_reset(&g->enc);
    }
  }
  kdb_hotl_free(l);
  free(l);
}

/* warm-before-serve: the workers wait (db_ingest_hold_queries) until the loader's hot list is received and read, or the time is up; this says how it ended */
static void hold_check(ing_t *g) {
  if (!g->hold) return;
  int64_t now = now_ms();
  bool done = atomic_load_explicit(&g_wl_received, memory_order_acquire) && g->nhot == 0 && g->nhot_flight == 0 && !db_store_directory_wait();      /* (0.7: with a first fill of the store the list of the zones is complete when the first pass has ended) */     /* (zones of the list only: a pinned zone that waits for room must not hold the queries back) */
  if (!done && now < atomic_load_explicit(&g_hold_deadline_ms, memory_order_relaxed)) return;
  g->hold = false;
  atomic_store_explicit(&g_warm_done_ms, now - g->hold_start_ms, memory_order_relaxed);
  atomic_store_explicit(&g_warm_done, true, memory_order_release);
  if (done)
    syslog(LOG_INFO, "[DB] warm-before-serve: the hot list is read (%llu zone(s) loaded, %llu failed); accepting queries after %lld ms",
           (unsigned long long)atomic_load_explicit(&g_wl_loaded, memory_order_relaxed), (unsigned long long)atomic_load_explicit(&g_wl_failed, memory_order_relaxed),
           (long long)(now - g->hold_start_ms));
  else
    syslog(LOG_WARNING, "[DB] warm-before-serve: the time is up after %lld ms with the hot list not read (%u queued, %u in flight, list received: %s); accepting queries",
           (long long)(now - g->hold_start_ms), g->nhot, g->nhot_flight, atomic_load_explicit(&g_wl_received, memory_order_relaxed) ? "yes" : "no");
}

bool db_ingest_hold_queries(void) {
  int64_t dl = atomic_load_explicit(&g_hold_deadline_ms, memory_order_relaxed);
  if (dl == 0 || atomic_load_explicit(&g_warm_done, memory_order_acquire)) return false;
  return now_ms() < dl;
}

static void fetch_adopt(ing_t *g, int fd) {
  if (!limit_stream_rights(fd)) {
    close(fd);
    return;
  }
  if (g->fetch_fd >= 0) fetch_drop(g);
  g->fetch_fd = fd;
  struct kevent ev[2];
  EV_SET(&ev[0], fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  EV_SET(&ev[1], fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, NULL);
  if (kevent(g->kq, ev, 2, NULL, 0, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot watch the loader fetch stream: %s", strerror(errno));
    fetch_drop(g);
    return;
  }
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  kdb_limits_t lim = { snap.max_zone_records ? snap.max_zone_records : KDB_DEFAULT_MAX_ZONE_RECORDS,
                       snap.max_zone_bytes ? snap.max_zone_bytes : KDB_DEFAULT_MAX_ZONE_BYTES, snap.nviews ? snap.nviews : KDB_VIEWS_ANY };
  kdb_framer_init(&g->ffr, KDB_FROM_LOADER, g->fbody, KDB_MAX_BODY);
  g->fresume = false;
  kdb_sm_init_fetch(&g->fsm, &lim);
  kdb_enc_reset(&g->fenc);
  g->fout_len = g->fout_off = 0;
  syslog(LOG_INFO, "[DB] loader fetch stream connected");
  for (uint32_t i = 0; i < ING_FETCH_MAX && g->fetch_fd >= 0; i++)      /* what a restarted loader has not answered is asked again */
    if (g->freq[i].active) {
      ing_freq_t *r = &g->freq[i];
      if (r->lk) {                                       /* 0.7: a lookup whose body was not wanted has nothing left to wait for; the others are asked again, with the mode the loader answers */
        r->body_seen = false;
        if (r->lkst == LKS_SKIP) {
          fetch_complete(g, r, true, NULL);
          continue;
        }
        if (r->lkst == LKS_ASK && r->mode == KDB_FETCH_LOOKUP_FULL && !(g->loader_feat & KDB_FEAT_LOOKUP_BODY)) r->mode = KDB_FETCH_LOOKUP;      /* (the new loader has not said it has the body: it is asked what every loader that looks up answers) */
      }
      r->sent_ms = now_ms();
      (void)fetch_send_req(g, r);
    }
  if (g->fetch_fd >= 0 && g->fout_off < g->fout_len) fetch_flush(g);
}

/* D1a step 7: the cache thread makes the hot list (design 8.4), a slice at a time, every hot-list-interval; only with memory-limit (the frequencies are kept then)
 * and loader-state-file.  The list is handed to the ingest thread (one slot); an empty one is not sent: the state file keeps what it has. */
typedef struct { kdb_hotl_t *l; uint32_t left_out; } hot_add_t;
static void hot_add_cb(void *ud, const char *view, const char *zone) {
  hot_add_t *a = ud;
  if (!kdb_hotl_add(a->l, view, zone)) a->left_out++;
}

static void hot_tick(const ing_cfg_t *c) {
  static dbreg_hot_t *s_hot;
  static int64_t s_due;
  int64_t now = now_ms();
  if (dbdir()) return;                       /* 0.7 S3: no hot list: a zone is attached from the store when it is asked for (50 us), and the page cache / ARC survived the restart (design 6.2) */
  if (!s_hot) {
    if (s_due == 0) s_due = now + (int64_t)c->hot_interval * 1000;
    if (now < s_due) return;
    s_hot = dbreg_hot_begin(c->hot_size);
    if (!s_hot) {
      s_due = now + 1000;
      return;
    }
  }
  if (!dbreg_hot_step(s_hot)) return;
  dbreg_hot_t *h = s_hot;
  s_hot = NULL;
  s_due = now + (int64_t)c->hot_interval * 1000;
  kdb_hotl_t *l = malloc(sizeof(*l));
  if (!l) {
    dbreg_hot_free(h);
    return;
  }
  kdb_hotl_init(l);
  hot_add_t ha = { l, 0 };
  (void)dbreg_hot_emit(h, hot_add_cb, &ha);
  if (ha.left_out) {                                     /* a name the list cannot carry (a view name with a byte that is not printable, a name that is not a valid name), or out of memory */
    static bool s_logged;
    if (!s_logged) {
      s_logged = true;
      syslog(LOG_WARNING, "[DB] hot list: %u zone(s) left out of the list: a view or zone name that the hot list cannot carry (a byte that is not printable) (said once)", (unsigned)ha.left_out);
    }
  }
  if (l->n == 0) {
    free(l);
    return;
  }
  kdb_hotl_t *old = atomic_exchange_explicit(&g_hot_out, l, memory_order_acq_rel);
  if (old) {
    kdb_hotl_free(old);
    free(old);
  }
  int kq = atomic_load_explicit(&g_ing_kick_kq, memory_order_relaxed);
  if (kq >= 0) {
    struct kevent t;
    EV_SET(&t, ING_EVT_HOT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    (void)kevent(kq, &t, 1, NULL, 0, NULL);
  }
}

/* 0.7 P-F: what the database needs in memory, said in syslog (dns_mem_advice.c has the figures and the rules).  The cache thread says it: after the
 * start and every full load (g_ma_event, set by on_batch_end()), when memory-limit changes, when the zone count, the level or what the size of a zone is
 * based on moves (looked at every 10 s and 50 us a zone: the count walks the registry), and, at run time, when the fetches use up the fetch capacity or queries are refused for overload. */
static ma_rt_t g_ma_rt;
static ma_est_t g_ma_est;                                    /* the cache thread's last estimate (the run-time warning names its numbers) */
static void ma_inputs(ma_in_t *in, const dbreg_residency_t *rs, uint64_t limit) {
  zone_bytes_t zdb;
  zone_bytes_get(ZBYTES_DB, &zdb);
  memset(in, 0, sizeof(*in));
  in->zones = rs->total;                                /* (0.7 D6: every zone of the database; with the store the zones that are not in memory cost no heap, and the estimate says so: its tables are file pages) */
  in->resident_zones = rs->resident;
  in->resident_bytes = zdb.resident;
  in->limit = limit;
  in->limit_default = limit && atomic_load_explicit(&g_limit_default, memory_order_relaxed);
  in->ram = g_ram;
  in->fetch_conc = atomic_load_explicit(&g_fetch_conc, memory_order_relaxed);
  if (dbdir()) db_store_ma_inputs(in);                  /* the mode, and the size of the images the store holds */
}
static void ma_say(const ma_est_t *e) {
  char t[900];
  ma_text_estimate(t, sizeof(t), e);
  syslog(LOG_INFO, "[DB] %s", t);
  if (ma_text_advice(t, sizeof(t), e) > 0)
    syslog(e->level == MA_LEVEL_ERROR ? LOG_ERR : e->level == MA_LEVEL_WARNING ? LOG_WARNING : LOG_NOTICE, "[DB] %s", t);
}
static void ma_check(uint64_t limit, bool event) {
  dbreg_residency_t rs;
  dbreg_residency(&rs);
  ma_in_t in;
  ma_inputs(&in, &rs, limit);
  ma_estimate(&in, &g_ma_est);
  if (in.zones > 0 && ma_rt_report_due(&g_ma_rt, &g_ma_est, event)) ma_say(&g_ma_est);
}
static void ma_tick(uint64_t limit, int64_t now) {
  static int64_t next_check, next_rt;
  bool ev = atomic_exchange_explicit(&g_ma_event, false, memory_order_relaxed);
  if (ev || (atomic_load_explicit(&g_ma_loaded, memory_order_relaxed) && (limit != g_ma_est.limit || now >= next_check))) {
    ma_check(limit, ev);
    next_check = now + 10000 + (int64_t)g_ma_est.zones / 20;       /* (10 s and 50 us a zone: the count walks the registry, 60 s at a million zones) */
  }
  if (!limit || now < next_rt) return;
  next_rt = now + MA_WINDOW_MS;
  if (db_store_filling()) {                             /* 0.7 D9: a first fill is the load: the zones are read for the store, not for the traffic, and the queries it makes wait for the zones all the same; the window starts again when it is over */
    g_ma_rt.have_prev = false;
    return;
  }
  park_stats_t ps;
  park_stats_get(&ps);
  dbreg_cache_stats_t cs;
  dbreg_cache_stats(&cs);
  ma_rt_in_t in;
  memset(&in, 0, sizeof(in));
  in.now_ms = now;
  for (int i = 0; i < FQ_HIST_N; i++) in.hist[i] = atomic_load_explicit(&g_fq_hist[i], memory_order_relaxed);
  in.issued = atomic_load_explicit(&g_fetch_issued, memory_order_relaxed);
  in.misses = cs.misses;
  in.refused = atomic_load_explicit(&g_fetch_shed, memory_order_relaxed) + atomic_load_explicit(&g_fetch_limited, memory_order_relaxed);
  in.park_full = ps.full;
  in.park_timeout = ps.timeout;
  in.concurrency = atomic_load_explicit(&g_fetch_conc, memory_order_relaxed);
  uint32_t rate = atomic_load_explicit(&g_fetch_rate, memory_order_relaxed);
  in.fetch_rate = rate >= 1000000000u ? 0 : rate;                  /* (0 and "unlimited" are no rate limit) */
  in.busy_pct = atomic_load_explicit(&g_ing_busy_pct, memory_order_relaxed);
  char t[900];
  int prio = ma_rt_tick(&g_ma_rt, &in, &g_ma_est, t, sizeof(t));
  if (prio) syslog(prio, "[DB] %s", t);
}

/* The cache manager (D1a step 5, design 8.2): with a limit, every 50 ms it reads memory-limit (a reload changes it at once) and runs a round: the
 * zones with the lowest frequency per byte are taken out of memory when the database zones are above the high mark.  Without a limit it only
 * looks at the configuration once a second. */
static void *cache_thread(void *arg) {
  (void)arg;
  rcu_aux_thread_pin();
  for (;;) {
    ing_cfg_t c;
    snapshot_cfg(&c);
    uint64_t lim = c.enabled ? c.memory_limit : 0;
    dbreg_cache_apply_limit(lim);
    atomic_store_explicit(&g_limit_default, c.enabled && c.limit_default, memory_order_relaxed);
    set_fetch_limits(&c);
    atomic_store_explicit(&g_xfr_timeout_ms, c.xfr_timeout_ms ? c.xfr_timeout_ms : KARIDNS_DB_XFR_FETCH_TIMEOUT_DEFAULT, memory_order_relaxed);
    if (c.enabled) ma_tick(lim, now_ms());                  /* 0.7 P-F: the sizing lines and the run-time warning */
    struct timespec ts = { 0, lim ? 50 * 1000000L : 0 };
    if (!lim) {
      ts.tv_sec = 1;
    } else {
      int64_t t0 = now_ms();
      uint32_t n = dbreg_cache_manager_paused() ? 0 : dbreg_cache_round();   /* (a unit test that paused the manager makes the rounds itself: two of them at once would take out more and fight for the lock, CI flakes row 79) */
      int64_t dt = now_ms() - t0;
      if (n || dt > 50) syslog(LOG_DEBUG, "[DB] cache round: %u zone(s) taken out in %lld ms", n, (long long)dt);
      if (c.state_file) hot_tick(&c);
    }
    nanosleep(&ts, NULL);
  }
  return NULL;
}

/* ------------------------------------------------------------------------------------------------------------- */
/* 0.7 P3: the restore of the database secondaries' copies (planing_0.7.x_secondary_store.md 4.4)                  */
/* ------------------------------------------------------------------------------------------------------------- */

/* The restore thread of the store (dns_xfr_store.c) posts one job per stored copy of a database secondary at its start, maybe before this thread runs.  The jobs run on this thread (the stream
 * thread: with the store there are no builders), each after the loader's jobs of the same zone that are in flight, so the loader's job and the restore never make two entries of one zone (M4 c). */
typedef struct xr_job {
  struct xr_job *next;
  char view[KARIDNS_VIEW_NAME_MAX];
  char zone[DNS_NAME_TEXT_SIZE];
} xr_job_t;
static pthread_mutex_t g_xr_mu = PTHREAD_MUTEX_INITIALIZER;
static xr_job_t *g_xr_head, **g_xr_tail = &g_xr_head;
static _Atomic uint32_t g_xr_n;
#ifdef KARIDNS_UNIT_TEST
void (*_Atomic db_ingest_test_xfr_job_hook)(const char *zone);
#endif

bool db_ingest_xfr_restore_post(const char *view, const char *zone) {
  xr_job_t *j = calloc(1, sizeof(*j));
  if (!j) return false;
  snprintf(j->view, sizeof(j->view), "%s", view);
  snprintf(j->zone, sizeof(j->zone), "%s", zone);
  pthread_mutex_lock(&g_xr_mu);
  *g_xr_tail = j;
  g_xr_tail = &j->next;
  atomic_fetch_add_explicit(&g_xr_n, 1, memory_order_release);
  pthread_mutex_unlock(&g_xr_mu);
  ing_kick();                                            /* (the thread looks at the jobs at the top of every round; before it runs it looks at its start) */
  return true;
}

/* the members of a catalog consumer whose copy was restored (RFC 9432 §5): its catalog is read from the restored version as a transfer of it would, so that the members (with their own copies)
 * are there before the primary answers.  After the registration: the delta is published first, so that the consumer is in the snapshot the membership is made against. */
static void consumer_members(zone_db_entry_t *e, const char *view) {
  if (g_ing.nbuilders) return;                           /* (a builder thread: the snapshot is the stream thread's to publish; the members come with the next transfer of the consumer) */
  apply_delta(&g_ing);
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  const zone_config_t *zc = zone_entry_config(cfg, e);
  if (zc && zc->is_catalog) catalog_process_membership(e, zc, view);
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
}

/* one job: the zone gets its entry from the copy when it has none (the loader's job may have made it already, with the copy restored), the reconcile's record of the zone (STORE_F_NONSTORE)
 * still names a row of the same identity (its domains.id; the row may have been deleted, renamed or purged while the server was stopped: then the copy goes), and the settings the copy names
 * are in settings.dat (else the zone waits for the loader, as before). */
static uint64_t g_xr_restored, g_xr_dropped, g_xr_waiting;
static void xr_one(ing_t *g, const xr_job_t *q) {
  drain_name(g, q->view, q->zone);
  if (!xfr_store_active() || dbreg_lookup_entry(q->view, q->zone)) return;
  int kind = 0;
  uint32_t settings = 0;
  uint64_t identity = 0;
  if (!xfr_store_db_copy(q->view, q->zone, &kind, &settings, &identity)) return;    /* (gone or made KNOWN meanwhile) */
  int64_t sid = 0;
  if (!db_store_nonstore_sid(q->view, q->zone, &sid) || xfr_identity(kind, q->zone, q->view, NULL, sid) != identity) {
    xfr_store_db_copy_drop(q->view, q->zone, identity);
    g_xr_dropped++;
    return;
  }
  zone_ext_shared_t *sh = db_store_settings_by_id(settings);
  if (!sh) {
    g_xr_waiting++;
    syslog(LOG_INFO, "[DB] zone '%s' (view '%s'): the settings its stored copy names are not in settings.dat; it waits for the loader", q->zone, q->view);
    return;
  }
  zone_db_entry_t *e = new_db_entry(q->view, q->zone, sh, kind == XFR_K_DB_CONSUMER ? KDB_ZK_CATALOG : KDB_ZK_SECONDARY);
  zone_x_t *x = e ? zone_x_need(e) : NULL;
  if (!x) {
    if (e) free_zone_db_entry(e);
    return;
  }
  atomic_store_explicit(&x->xfr_db_sid, sid, memory_order_release);
  if (!xfr_store_db_restore(e)) {                        /* (a damaged image, another serial, a copy of another zone: logged and handled there; the loader's job makes the entry) */
    free_zone_db_entry(e);
    return;
  }
  /* the registry learns the zone as from the loader's job (serial 0, no digest: the loader's own job compares nothing of it and finds the entry) */
  static const uint8_t zero[32];
  bool shadowed = false;
  if (dbreg_commit(q->view, q->zone, e, true, sid, 0, zero, &shadowed) != 0) {
    free_zone_db_entry(e);
    return;
  }
  g_xr_restored++;
  if (kind == XFR_K_DB_CONSUMER) consumer_members(e, q->view);
}

static void xr_run(ing_t *g) {
  if (atomic_load_explicit(&g_xr_n, memory_order_acquire) == 0) return;
  for (;;) {
    pthread_mutex_lock(&g_xr_mu);
    xr_job_t *q = g_xr_head;
    if (q) {
      g_xr_head = q->next;
      if (!g_xr_head) g_xr_tail = &g_xr_head;
      atomic_fetch_sub_explicit(&g_xr_n, 1, memory_order_release);
    }
    pthread_mutex_unlock(&g_xr_mu);
    if (!q) break;
#ifdef KARIDNS_UNIT_TEST
    void (*h)(const char *) = atomic_load_explicit(&db_ingest_test_xfr_job_hook, memory_order_acquire);
    if (h) h(q->zone);
#endif
    xr_one(g, q);
    free(q);
    xfr_store_db_job_done();
  }
  static uint64_t said;
  const uint64_t all = g_xr_restored + g_xr_dropped + g_xr_waiting;
  if (all != said) {
    said = all;
    apply_delta(g);                                      /* (the restored zones answer now, not at the next delta of the batch) */
    syslog(LOG_NOTICE, "[DB] secondaries: %" PRIu64 " database secondary zone(s) restored from their stored copies, %" PRIu64 " copy(ies) of zones no longer in the database deleted, %" PRIu64 " wait for the loader",
           g_xr_restored, g_xr_dropped, g_xr_waiting);
  }
}

/* review 2026-11-23 D-L4: a zone begun on a stream and never finished.  The loader builds the messages of a zone in memory before it writes the first
 * one (karidns_dbloader.c, B6b), so after ZONE_BEGIN the rest of the zone only waits for the socket: a stream that brings no data for g_ing_zone_stall_ms
 * while a zone is open is a loader that hangs (or one that holds the image buffer, D-L1, on purpose).  The zone is given up and the stream closed
 * (protocol_error() / fetch_protocol_error(): the partial image is freed; the supervisor starts the loader again).  The clock does not run while this
 * thread itself does not read the stream (paused: a frame held for the reconcile thread, the read event off, frames left in the framer).  An open
 * batch between two zones has no such limit: the loader reads the database then. */
static bool zone_stalled(const ing_job_t *j, int64_t *rx, bool paused, int64_t now) {
  if (!j || paused) {
    *rx = now;
    return false;
  }
  return now - *rx >= atomic_load_explicit(&g_ing_zone_stall_ms, memory_order_relaxed);
}

static void zone_stall_check(ing_t *g) {
  const int64_t now = now_ms();
  char why[KDB_REASON_LEN + DNS_NAME_TEXT_SIZE];
  if (g->stream_fd >= 0 && zone_stalled(g->cur, &g->s_rx_ms, g->read_off || g->held_valid || g->sresume, now)) {
    snprintf(why, sizeof(why), "zone '%s' was begun and nothing more came for %lld ms", g->cur->zone, (long long)(now - g->s_rx_ms));
    protocol_error(g, why);
  }
  if (g->fetch_fd >= 0 && zone_stalled(g->fcur, &g->f_rx_ms, g->fresume, now)) {
    snprintf(why, sizeof(why), "zone '%s' was begun and nothing more came for %lld ms", g->fcur->zone, (long long)(now - g->f_rx_ms));
    fetch_protocol_error(g, why);
  }
}

/* 0.7 first-fill latency (W1): the bound of the store's journal (4 x its limit) at the end of a pass of the loop.  It used to be one wait for the checkpoint (seconds on ZFS during a first fill),
 * with no request of a query made meanwhile: the lookups and the fetches of the queries waited behind the fill's writes.  Now the wait is cut into ING_JW_SLICE_MS slices, and between them the
 * thread makes the requests of queries (fetch_issue() with qonly: the workers' rings, the wait queue, the lookup queue; no body of the fill, no warm-up), sends them and wakes the workers.
 * What it may touch there: the fetch table, the queues, the fetch stream's output and the park rings, all of this thread; the store is only read (the stamps, lookup_covered()); nothing is
 * installed (the streams are not read: that is the back-pressure).  No reentry: this runs at the end of the loop, where no pass, job or stream message is half done, and qonly keeps
 * fetch_issue() off the paths that write. */
#define ING_JW_SLICE_MS 5
static void ing_journal_wait(ing_t *g) {
  store_jwait_t w;
  memset(&w, 0, sizeof(w));
  while (db_store_journal_wait_slice(4, &w, ING_JW_SLICE_MS)) {
    atomic_fetch_add_explicit(&g_ing_jw_slices, 1, memory_order_relaxed);
    if (g->nwq > 0 || g->nlq > 0 || park_fetch_pending()) {
      g->qonly = true;
      fetch_issue(g);
      g->qonly = false;
    }
    if (g->fetch_fd >= 0 && g->fout_off < g->fout_len) fetch_flush(g);
    wake_flush(g);
  }
}

static void *ingest_thread(void *arg) {
  ing_t *g = arg;
  rcu_aux_thread_pin();
  db_store_defer_thread(true);                          /* 0.7: its store calls do not wait for the journal; the commit at the end of a batch does (db_store_batch_end()) */
  struct kevent evs[8];
  int64_t win_start = mono_ns(), busy_ns = 0, t_wake = win_start;
  for (;;) {
    xr_run(g);                                           /* 0.7 P3: the restore jobs of the database secondaries' copies (also those posted before this thread ran) */
    struct timespec ts, *tp = NULL;
    int64_t wait_ms = -1;
    if (dbreg_pending_count() > 0) {                     /* new zones are waiting to become visible */
      wait_ms = (dbreg_garbage_due() && !g->delta_failed) ? 0 : g->last_delta_ms + delta_interval_ms() - now_ms();
      if (wait_ms < 0) wait_ms = 0;
    }
    if (g->nfreq > 0) {                                  /* fetches in flight: look at their deadlines */
      int64_t tick = g_ing_fetch_timeout_ms / 10;
      if (tick > 1000) tick = 1000;
      if (tick < 10) tick = 10;
      if (wait_ms < 0 || wait_ms > tick) wait_ms = tick;
    }
    if ((g->nwarm > 0 || (g->apex_walk && g->fetch_fd >= 0)) && (wait_ms < 0 || wait_ms > 50)) wait_ms = 50;      /* zones to read before a query asks, or the walk for apexes (while there is a fetch stream): try again soon */
    if (g->bg_on && g->fetch_fd >= 0 && (wait_ms < 0 || wait_ms > 50)) wait_ms = 50;           /* 0.7 WP7b: the bodies the reconcile wants are being asked for: look again soon (a pause after a failed round, a free place) */
    if ((g->nwq > 0 || g->nlq > 0) && (wait_ms < 0 || wait_ms > ING_WQ_TICK_MS)) wait_ms = ING_WQ_TICK_MS;     /* 0.7 P-B: requests wait (for the bucket, room, a place): look again, and at their deadlines */
    if (s_shed_since && now_ms() < s_shed_last_ms + (int64_t)atomic_load_explicit(&g_park_timeout_ms, memory_order_relaxed) && (wait_ms < 0 || wait_ms > ING_WQ_TICK_MS))
      wait_ms = ING_WQ_TICK_MS;                          /* 0.7: names are remembered as shed: look again soon, to forget them when this thread has caught up (shed_release_check()) */
    if (g->hold && (wait_ms < 0 || wait_ms > 50)) wait_ms = 50;           /* warm-before-serve: look at the warm-up and the time often */
    if (g->cur || g->fcur) {                                               /* D-L4: a zone is open on a stream: look at its stall clock (zone_stall_check()) */
      int64_t tick = atomic_load_explicit(&g_ing_zone_stall_ms, memory_order_relaxed) / 10;
      if (tick > 1000) tick = 1000;
      if (tick < 10) tick = 10;
      if (wait_ms < 0 || wait_ms > tick) wait_ms = tick;
    }
    if (wait_ms < 0 || wait_ms > 10000) wait_ms = 10000;                  /* (the busy share of dbstatus is closed at the end of a window, so the thread wakes at least that often) */
    if (g->sresume || g->fresume) wait_ms = 0;                            /* 0.7 fix 8: frames are left in a framer, the requests of the queries were served first */
    if (g->fmore) wait_ms = 0;                                            /* B2 W5: the last pass of fetch_issue() stopped at its bound: serve what is ready on the streams, then go on */
    /* B2 W5, the sleep protocol (dns_park.c): say "asleep", and look once more for requests, so that a worker that pushed one and saw no flag has not left it unseen */
    if (park_fetch_sleep_prepare()) wait_ms = 0;
    if (wait_ms >= 0) {
      ts.tv_sec = wait_ms / 1000;
      ts.tv_nsec = (wait_ms % 1000) * 1000000;
      tp = &ts;
    }
    int n = kevent(g->kq, NULL, 0, evs, 8, tp);
    park_fetch_sleep_done();
    if (n < 0) {
      if (errno == EINTR) continue;
      syslog(LOG_ERR, "[DB] the ingest thread stops: kevent: %s", strerror(errno));
      db_store_defer_thread(false);                     /* (its slot is freed before the thread ends: thread ids are reused) */
      return NULL;
    }
    t_wake = mono_ns();
    bool ran_s = false, ran_f = false;
    for (int i = 0; i < n; i++) {
      const struct kevent *e = &evs[i];
      if (e->filter == EVFILT_USER && e->ident == ING_EVT_RESULT) {
        drain_results(g);
      } else if (e->filter == EVFILT_USER && e->ident == ING_EVT_REQ) {
        process_requests(g);
      } else if (e->filter == EVFILT_USER && e->ident == ING_EVT_DEBUG) {
        send_debug(g);
      } else if (e->filter == EVFILT_USER && e->ident == ING_EVT_RECON) {
        recon_poll(g);                                   /* 0.7 M2: the reconcile thread: a protocol error, bodies wanted, a frame that waited for it */
      } else if (e->filter == EVFILT_USER && e->ident == ING_EVT_HOT) {
        hot_send(g);                                     /* D1a step 7: the cache thread made a hot list */
      } else if (e->filter == EVFILT_USER && e->ident == PARK_FETCH_IDENT) {
        /* D1a: a worker parked a query for a zone that is not in memory: fetch_issue() below looks at every request that is there, whether this trigger came or not
         * (a worker does not trigger while the thread is awake) */
      } else if (e->filter == EVFILT_USER) {
        on_config_event(g);
      } else if (g->ctrl_fd >= 0 && e->ident == (uintptr_t)g->ctrl_fd) {
        on_ctrl_readable(g);
      } else if (g->fetch_fd >= 0 && e->ident == (uintptr_t)g->fetch_fd) {
        if (e->filter == EVFILT_WRITE) fetch_flush(g);
        else {
          on_fetch_readable(g);
          ran_f = true;
        }
      } else if (g->stream_fd >= 0 && e->ident == (uintptr_t)g->stream_fd) {
        if (e->filter == EVFILT_WRITE) out_flush(g);
        else {
          on_stream_readable(g);
          ran_s = true;
        }
      }
      if (g->need_cleanup) cleanup_stream_state(g);
      wake_flush(g);                                     /* B2 W5: the workers that a completion woke are triggered once per event, not once per zone (and the index delta is published once, M3) */
    }
    if (g->sresume && !ran_s && g->stream_fd >= 0) on_stream_readable(g);        /* (what the last pass left, when no event of the stream came) */
    if (g->fresume && !ran_f && g->fetch_fd >= 0) on_fetch_readable(g);
    if (g->inv_active) pump_inventory(g);
    zone_stall_check(g);
    if (g->need_cleanup) cleanup_stream_state(g);
    maybe_apply_delta(g);
    if (g->nwarm > 0 || g->fmore || g->nwq > 0 || g->nlq > 0 || g->bg_on || park_fetch_pending()) fetch_issue(g);
    shed_release_check(g);
    apex_walk_step(g);
    fetch_expire(g);
    dd_tick(g, now_ms());                               /* (0.7 first-fill latency: the line of the queries a database that cannot be read left unanswered) */
    wake_flush(g);
    hold_check(g);
    if (g->stream_fd >= 0 && g->out_off < g->out_len) out_flush(g);
    if (g->fetch_fd >= 0 && g->fout_off < g->fout_len) fetch_flush(g);
    ing_journal_wait(g);                                 /* 0.7: the hard bound of the store's journal (4 x its limit; the reconcile thread waits at 2 x), with no lock held */
    {
      int64_t t1 = mono_ns();
      busy_ns += t1 - t_wake;
      db_recon_note_loop(t1 - t_wake);                   /* 0.7 M2: the longest pass of this loop (store.ingest.loop_max_us) */
      if (t1 - win_start >= ING_BUSY_WINDOW_NS) {
        atomic_store_explicit(&g_ing_busy_pct, (uint32_t)(busy_ns * 100 / (t1 - win_start)), memory_order_relaxed);
        atomic_store_explicit(&g_ing_fill_pct, (uint32_t)(g->fill_ns * 100 / (t1 - win_start)), memory_order_relaxed);
        g->fill_ns = 0;
        win_start = t1;
        busy_ns = 0;
      }
    }
  }
}

bool db_ingest_start(int stream_fd, int ctrl_fd, int fetch_fd) {
  ing_t *g = &g_ing;
  g_ram = ma_host_ram();                                   /* (before the sandbox: the Backend cannot read hw.physmem in capability mode) */
  const char *tram = getenv("KARIDNS_TEST_PHYSMEM");       /* test switch (tests/run_db_memdefault_test.sh): the RAM the default memory-limit is derived from, in bytes */
  if (tram && *tram) g_ram = strtoull(tram, NULL, 10);
#ifdef KARIDNS_TEST_EVICT
  {
    const char *dd = getenv("KARIDNS_TEST_DBDOWN_LOG_S");  /* (the test builds only: the window of dd_tick() in seconds, tests/run_db_firstfill_latency_test.sh) */
    const unsigned long v = dd && *dd ? strtoul(dd, NULL, 10) : 0;
    if (v >= 1 && v <= 3600) g_dd_window_ms = (int64_t)v * 1000;
  }
#endif
  static struct ing_wq *s_wq;
  static struct ing_lq *s_lq;
  memset(g, 0, sizeof(*g));
  if (!s_wq) s_wq = calloc(ING_WQ_MAX, sizeof(*s_wq));       /* (NULL: nothing can wait, a request that cannot be made is refused) */
  g->wq = s_wq;
  if (!s_lq) s_lq = calloc(ING_LQ_MAX, sizeof(*s_lq));       /* (NULL: a lookup that finds no place is dropped) */
  g->lq = s_lq;
  /* 0.7: until the first loader's HELLO says whether it looks names up, one that does is expected when the store is on (it is the loader of this package): a query for a name that no
   * listed zone covers, while a view's list of zones is not complete (a first fill), waits for that loader as it waits for one that is away (its lookup is queued and made after the
   * HELLO, or dropped at its time-out, counted), not REFUSED in the second before the loader is up.  The HELLO sets the hold for what the loader is (on_hello()). */
  atomic_store_explicit(&g_lookup_hold, db_store_enabled(), memory_order_release);
  g->stream_fd = -1;
  g->fetch_fd = -1;
  g->cur_req = -1;
  g->ctrl_fd = ctrl_fd;
  g->body = malloc(KDB_MAX_BODY);
  g->fbody = malloc(KDB_MAX_BODY);
  g->rbuf = malloc(ING_RBUF);
  g->frbuf = malloc(ING_RBUF);
  kdb_enc_init(&g->enc);
  kdb_enc_init(&g->fenc);
  g->kq = kqueue();
  g->wait_kq = kqueue();
  if (!g->body || !g->fbody || !g->rbuf || !g->frbuf || g->kq < 0 || g->wait_kq < 0 || ctrl_fd < 0) {
    syslog(LOG_ERR, "[DB] cannot start the ingest thread: %s", g->kq < 0 ? strerror(errno) : "no control socket or memory");
    return false;
  }
  if (!limit_ctrl_rights(ctrl_fd)) return false;
  struct kevent ev[8];
  EV_SET(&ev[0], ctrl_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  EV_SET(&ev[1], ING_EVT_CONFIG, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev[2], ING_EVT_RESULT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev[3], ING_EVT_REQ, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev[4], PARK_FETCH_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);      /* D1a: a worker asks for a zone */
  EV_SET(&ev[5], ING_EVT_HOT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);      /* D1a step 7: a hot list to send */
  EV_SET(&ev[6], ING_EVT_DEBUG, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);    /* 0.7 M2: karictl trace / notrace */
  EV_SET(&ev[7], ING_EVT_RECON, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);    /* 0.7 M2: the reconcile thread */
  if (kevent(g->kq, ev, 8, NULL, 0, NULL) != 0) {
    syslog(LOG_ERR, "[DB] cannot watch the loader control socket: %s", strerror(errno));
    return false;
  }
  EV_SET(&ev[0], 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  if (kevent(g->wait_kq, ev, 1, NULL, 0, NULL) != 0) return false;
  atomic_store_explicit(&g_ing_kick_kq, g->kq, memory_order_relaxed);
  store_status_set_lookup_fn(db_ingest_lookup_stats);
  store_status_set_fill_fn(db_ingest_fill_stats);          /* 0.7 M3: `karictl store` shows the zone images (store.fill.*) */        /* 0.7: `karictl store` shows the lookups of the first start (store.lookup.*) */
  dbreg_set_pending_notify(ing_kick);                /* D1a step 5: an eviction leaves a delta to publish; the thread may be asleep without a timeout */
  /* builder threads (design 1.5, D10): ingest-threads 1 = the stream thread builds */
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  uint32_t nthr = snap.ingest_threads;
  if (nthr > ING_MAX_BUILDERS) nthr = ING_MAX_BUILDERS;
  if (nthr > 1 && db_store_enabled()) {
    /* 0.7 M3: with the store a zone costs a check of its image and one write that the store serializes (the loader builds the image): builders gain nothing, so ingest-threads has no effect here */
    syslog(LOG_INFO, "[DB] ingest-threads %u has no effect with the zone store (the loader builds the zone images); it applies to `store none` only", nthr);
    nthr = 1;
  }
  if (nthr > 1) {
    for (uint32_t i = 0; i < nthr; i++) {
      ing_builder_t *b = &g->builders[i];
      atomic_init(&b->slot, NULL);
      b->kq = kqueue();
      EV_SET(&ev[0], 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
      if (b->kq < 0 || kevent(b->kq, ev, 1, NULL, 0, NULL) != 0) {
        syslog(LOG_ERR, "[DB] cannot create a builder thread kqueue: %s", strerror(errno));
        return false;
      }
    }
    for (uint32_t i = 0; i < nthr; i++) {
      if (pthread_create(&g->builders[i].tid, NULL, builder_thread, &g->builders[i]) != 0) {
        syslog(LOG_ERR, "[DB] cannot create a builder thread");
        return false;
      }
      pthread_detach(g->builders[i].tid);
      g->nbuilders = i + 1;
    }
    syslog(LOG_INFO, "[DB] %u builder thread(s) for the zones of the database", g->nbuilders);
  }
  if (!db_recon_thread_start(g->kq, ING_EVT_RECON)) return false;      /* 0.7 M2: the pages of a manifest pass are applied by a thread of their own (dns_db_recon.h) */
  if (stream_fd >= 0) adopt_stream(g, stream_fd);
  if (fetch_fd >= 0) fetch_adopt(g, fetch_fd);
  park_fetch_set_notify(g->kq);
  dbreg_cache_apply_limit(snap.memory_limit);              /* before the first batch: the startup load already keeps within it */
  atomic_store_explicit(&g_limit_default, snap.limit_default, memory_order_relaxed);
  if (snap.limit_default) {                          /* 0.7.x: a database block without memory-limit gets one from the RAM (docs/karidns.md, "Memory limit") */
    char t[400];
    ma_text_default(t, sizeof(t), snap.memory_limit, g_ram);
    syslog(LOG_NOTICE, "[DB] %s", t);
  }
  if (snap.warm_wait) {                              /* warm-before-serve: the workers wait for the hot list to be read, at most this long (db_ingest_hold_queries) */
    g->hold = true;
    g->hold_start_ms = now_ms();
    atomic_store_explicit(&g_hold_deadline_ms, g->hold_start_ms + (int64_t)snap.warm_wait * 1000, memory_order_relaxed);
  }
  set_fetch_limits(&snap);
  atomic_store_explicit(&g_xfr_timeout_ms, snap.xfr_timeout_ms ? snap.xfr_timeout_ms : KARIDNS_DB_XFR_FETCH_TIMEOUT_DEFAULT, memory_order_relaxed);
  pthread_t t;
  if (pthread_create(&t, NULL, ingest_thread, g) != 0) {
    syslog(LOG_ERR, "[DB] cannot create the ingest thread");
    return false;
  }
  pthread_detach(t);
  pthread_t ct;
  if (pthread_create(&ct, NULL, cache_thread, g) != 0) syslog(LOG_ERR, "[DB] cannot create the cache manager thread; memory-limit is not enforced");
  else pthread_detach(ct);
  atomic_store_explicit(&g_ing_kq, g->kq, memory_order_release);
  return true;
}

#define XFR_POLL_NS 5000000L        /* a transfer thread looks at the zone every 5 ms while it waits for it */
#define XFR_REREQUEST_MS 100        /* ... and asks again this often while nothing is on its way (a request that was shed, or lost with a restarted loader) */

zone_db_entry_t *db_ingest_xfr_await(zdir_elem_t *el, const char *view) {
  const int64_t end = now_ms() + (int64_t)atomic_load_explicit(&g_xfr_timeout_ms, memory_order_relaxed);
  int64_t next_ask = 0;
  bool waited = false;
  for (;;) {
    zone_db_entry_t *e = dbreg_xfr_acquire(el);
    if (e) {
      if (waited) {
        dbreg_xfr_note(DBREG_XFR_LOADED);
        dbreg_xfr_loaded(view, el->name);      /* the zone is here for this transfer: the first to go when memory is needed (design 7) */
      }
      return e;
    }
    if (!waited) {
      waited = true;
      dbreg_xfr_note(DBREG_XFR_WAITED);
    }
    const uint8_t st = atomic_load_explicit(&el->state, memory_order_acquire);
    const int64_t now = now_ms();
    if (st == ZDIR_ST_ERROR || now >= end) break;       /* no usable version in the registry (a rejected zone), or the time is up */
    if (st == ZDIR_ST_ABSENT && now >= next_ask) {
      /* (the ingest thread keeps the request in its wait queue for a place, a token or room, as it does for a query, and drops it after park-timeout;
       * the transfer asks again until its time is up) */
      next_ask = now + (park_fetch_request_any(view, el->name, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL) ? XFR_REREQUEST_MS : XFR_REREQUEST_MS / 5);
    }
    struct timespec ts = { 0, XFR_POLL_NS };
    nanosleep(&ts, NULL);
  }
  dbreg_xfr_note(DBREG_XFR_FAILED);
  return NULL;
}

/* 0.7 store S3: the same for a zone of the store that is not in memory (it has no element): the thread has a store thread's job done on its own thread (the attach of a stored zone), or
 * asks the ingest thread for the zone (a zone the store knows without an image), until the zone is in memory or the time is up.  The entry is held as db_ingest_xfr_await() holds it. */
zone_db_entry_t *db_ingest_xfr_await_zone(const char *zone, const char *view) {
  const int64_t end = now_ms() + (int64_t)atomic_load_explicit(&g_xfr_timeout_ms, memory_order_relaxed);
  int64_t next_ask = 0;
  bool waited = false;
  for (;;) {
    zone_db_entry_t *e = dbreg_pin_entry(view, zone);
    if (e) {
      if (waited) {
        dbreg_xfr_note(DBREG_XFR_LOADED);
        dbreg_xfr_loaded(view, zone);                  /* the zone is here for this transfer: the first to go when memory is needed (design 7) */
      }
      return e;
    }
    if (!waited) {
      waited = true;
      dbreg_xfr_note(DBREG_XFR_WAITED);
    }
    const int64_t now = now_ms();
    if (now >= end) break;
    if (now >= next_ask) {
      dbdir_rec_t rec;
      if (dbdir() && dbdir()->rec_get(view, zone, &rec) && rec.state == STORE_STATE_STORED) {
        db_store_attach_zone(view, zone);                /* (the zone is attached on this thread; a failure falls back to a fetch, which the next round waits for) */
        next_ask = now + XFR_REREQUEST_MS;
      } else {
        next_ask = now + (park_fetch_request_any(view, zone, KDB_FETCH_PRIO_QUERY, KDB_FETCH_FULL) ? XFR_REREQUEST_MS : XFR_REREQUEST_MS / 5);
      }
      continue;                                          /* (look again at once: an attach that worked has made the entry) */
    }
    struct timespec ts = { 0, XFR_POLL_NS };
    nanosleep(&ts, NULL);
  }
  dbreg_xfr_note(DBREG_XFR_FAILED);
  return NULL;
}

bool db_ingest_enabled(void) {
  return atomic_load_explicit(&g_ing_kq, memory_order_acquire) >= 0;
}

uint64_t db_ingest_reload(bool all, const char *view, const char *zone, bool force) {
  int kq = atomic_load_explicit(&g_ing_kq, memory_order_acquire);
  if (kq < 0) return 0;
  uint32_t t = atomic_load_explicit(&g_rq_tail, memory_order_relaxed);
  uint32_t h = atomic_load_explicit(&g_rq_head, memory_order_acquire);
  if (t - h >= RQ_RING) return 0;
  rq_item_t *it = &g_rq[t % RQ_RING];
  memset(it, 0, sizeof(*it));
  it->type = all ? RQ_ALL : RQ_ZONE;
  it->force = force;
  it->id = ++g_next_req_id;
  if (view) snprintf(it->view, sizeof(it->view), "%s", view);
  if (zone) snprintf(it->zone, sizeof(it->zone), "%s", zone);
  uint64_t id = it->id;
  atomic_store_explicit(&g_rq_tail, t + 1, memory_order_release);
  struct kevent ev;
  EV_SET(&ev, ING_EVT_REQ, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &ev, 1, NULL, 0, NULL);
  return id;
}

void db_ingest_reload_cancel(uint64_t id) {
  int kq = atomic_load_explicit(&g_ing_kq, memory_order_acquire);
  if (kq < 0) return;
  uint32_t t = atomic_load_explicit(&g_rq_tail, memory_order_relaxed);
  uint32_t h = atomic_load_explicit(&g_rq_head, memory_order_acquire);
  if (t - h >= RQ_RING) return;                          /* the table entry then lives until its batch ends */
  rq_item_t *it = &g_rq[t % RQ_RING];
  memset(it, 0, sizeof(*it));
  it->type = RQ_CANCEL;
  it->id = id;
  atomic_store_explicit(&g_rq_tail, t + 1, memory_order_release);
  struct kevent ev;
  EV_SET(&ev, ING_EVT_REQ, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &ev, 1, NULL, 0, NULL);
}

bool db_ingest_reload_result(db_reload_result_t *out) {
  uint32_t h = atomic_load_explicit(&g_rs_head, memory_order_relaxed);
  uint32_t t = atomic_load_explicit(&g_rs_tail, memory_order_acquire);
  if (h == t) return false;
  *out = g_rs[h % RQ_RING];
  atomic_store_explicit(&g_rs_head, h + 1, memory_order_release);
  return true;
}

bool db_ingest_pick_view(const char *view_arg, char *out, size_t cap, char *err, size_t errlen) {
  bool ok = false;
  if (cap) out[0] = '\0';
  rcu_aux_read_lock();
  const server_config_t *cfg = acquire_config_snapshot();
  if (!cfg || !cfg->database.enabled) {
    snprintf(err, errlen, "no database block is configured");
  } else {
    int n = 0;
    const view_config_t *only = NULL, *named = NULL;
    for (const view_config_t *v = cfg->views; v; v = v->next) {
      if (view_arg && v->name && strcasecmp(v->name, view_arg) == 0) named = v;
      if (v->database_none) continue;
      n++;
      only = v;
    }
    if (view_arg) {
      if (!named) snprintf(err, errlen, "view '%.60s' does not exist", view_arg);
      else if (named->database_none) snprintf(err, errlen, "view '%.60s' takes no zones from the database", view_arg);
      else ok = true, snprintf(out, cap, "%s", named->name);
    } else if (n == 1) {
      ok = true;
      snprintf(out, cap, "%s", only->name ? only->name : "");
    } else if (n == 0) {
      snprintf(err, errlen, "no view takes zones from the database");
    } else {
      ok = true;                 /* several views and none named: the caller asks every one of them (B6b) */
      out[0] = '\0';
    }
  }
  rcu_aux_read_unlock();
  return ok;
}

void db_ingest_debug_changed(void) {
  int kq = atomic_load_explicit(&g_ing_kq, memory_order_acquire);
  if (kq < 0) return;
  struct kevent ev;
  EV_SET(&ev, ING_EVT_DEBUG, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &ev, 1, NULL, 0, NULL);
}

void db_ingest_config_changed(void) {
  int kq = atomic_load_explicit(&g_ing_kq, memory_order_acquire);
  if (kq < 0) return;
  atomic_store_explicit(&g_cfg_dirty, true, memory_order_release);
  struct kevent ev;
  EV_SET(&ev, ING_EVT_CONFIG, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  (void)kevent(kq, &ev, 1, NULL, 0, NULL);
}

/* ------------------------------------------------------------------------------------------------------------- */
/* karictl dbstatus                                                                                               */
/* ------------------------------------------------------------------------------------------------------------- */

/* "YYYY-MM-DD HH:MM:SS UTC" without the C library's time functions: gmtime_r() and localtime_r() load a time zone file
 * on first use, which the Backend must not do in capability mode (CLAUDE.md Rule 2; it is a SIGTRAP).  The days are
 * converted with the civil-from-days algorithm (proleptic Gregorian calendar). */
static void fmt_time(int64_t t, char *buf, size_t n) {
  if (t <= 0) {
    snprintf(buf, n, "never");
    return;
  }
  int64_t days = t / 86400, rem = t % 86400;
  int64_t z = days + 719468;
  int64_t era = z / 146097;
  int64_t doe = z - era * 146097;
  int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t y = yoe + era * 400;
  int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  int64_t mp = (5 * doy + 2) / 153;
  int64_t d = doy - (153 * mp + 2) / 5 + 1;
  int64_t m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2) y++;
  snprintf(buf, n, "%04lld-%02lld-%02lld %02lld:%02lld:%02lld UTC", (long long)y, (long long)m, (long long)d,
           (long long)(rem / 3600), (long long)(rem % 3600 / 60), (long long)(rem % 60));
}

typedef struct {
  const char *zone, *view;
  char *out;
  size_t cap, len;
  int matches;
  const server_config_t *cfg;   /* B7a: for the ceiling lines of one zone; valid inside the read section of db_ingest_status() */
} status_ctx_t;

static void st_append(status_ctx_t *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void st_append(status_ctx_t *c, const char *fmt, ...) {
  if (c->len + 1 >= c->cap) return;
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(c->out + c->len, c->cap - c->len, fmt, ap);
  va_end(ap);
  if (n > 0) c->len = (size_t)n < c->cap - c->len ? c->len + (size_t)n : c->cap - 1;
}

static void st_list(status_ctx_t *c, const char *label, char *const *list, int n) {
  if (n <= 0) return;
  st_append(c, " %s", label);
  for (int i = 0; i < n && i < 8; i++) st_append(c, "%s%.64s", i ? ", " : " ", list[i] ? list[i] : "?");
  if (n > 8) st_append(c, ", ... (%d entries)", n);
}

/* B7b: a SLAVE / CONSUMER zone: where it transfers from and how far it got (its data is in memory only) */
static void secondary_status(status_ctx_t *c, const zone_db_entry_t *e, const zone_config_t *dc) {
  const zone_ext_t *x = dc->ext;
  st_append(c, "  type: %s, masters", dc->is_catalog ? "catalog consumer (CONSUMER)" : "secondary (SLAVE)");
  for (int i = 0; x && i < x->masters_count && i < 8; i++)
    st_append(c, "%s%.64s port %d", i ? ", " : " ", x->masters[i].ip ? x->masters[i].ip : "?", config_target_port(c->cfg, x->masters[i].port));
  if (x && x->masters_count > 8) st_append(c, ", ... (%d entries; only the first is used for transfers)", x->masters_count);
  if (x && x->tsig_key) st_append(c, ", TSIG key '%.64s'", x->tsig_key);
  st_append(c, "\n");
  time_t last = atomic_load_explicit(&e->last_successful_transfer, memory_order_acquire);
  char t[40];
  fmt_time((int64_t)last, t, sizeof(t));
  if (last > 0)
    st_append(c, "  transfer: last successful %s, serial %u (%s)\n", t, (unsigned)atomic_load_explicit(&e->serial, memory_order_relaxed),
              xfr_store_active() ? "a copy is kept in the zone store; a restart restores it" : "kept in memory only; a restart transfers it again");     /* (0.7 P3) */
  else
    st_append(c, "  transfer: no transfer has succeeded yet (%s)\n", xfr_store_active() ? "the first one is kept in the zone store" : "kept in memory only");
  /* B8t-2: the settings the primary sent with the zone (Extended AXFR version 3); the statements of the zone's own metadata win */
  if (atomic_load_explicit(&zone_xr(e)->rxcfg, memory_order_acquire))
    st_append(c, "  settings from the primary: in force (what the zone's own metadata sets wins over them)\n");
  /* 0.7 P4 (secondary store 11): the lines of `karictl zonestatus` about the copy in the store (Store:, Last-refresh:, Expired:), indented.  Under the registry's lock and in a read
   * section: they read the store's index and the configuration only (no lock, no write) */
  char sl[480];
  if (xfr_store_zonestatus((zone_db_entry_t *)e, c->cfg, sl, sizeof(sl)) > 0)
    for (char *p = sl, *nl; *p; p = nl + 1) {
      nl = strchr(p, '\n');
      if (!nl) {
        st_append(c, "  %s\n", p);
        break;
      }
      st_append(c, "  %.*s\n", (int)(nl - p), p);
    }
}

/* B7a: where the settings of a DB zone come from and what acl-ceiling makes of its ACLs */
static void settings_status(status_ctx_t *c, const zone_db_entry_t *e) {
  const zone_config_t *dc = atomic_load_explicit(&e->dbcfg, memory_order_acquire);
  if (dc && e->is_secondary) secondary_status(c, e, dc);
  if (!dc || !dc->ext_shared) {
    st_append(c, "  settings: none (the defaults; no ACLs, so transfers and updates are refused)\n");
    return;
  }
  const zone_ext_shared_t *sh = (const zone_ext_shared_t *)dc->ext;
  const zone_ext_t *x = dc->ext;
  if (sh->profile[0])
    st_append(c, "  settings: profile '%.64s' (statements in the zone's own metadata override the profile's)\n", sh->profile);
  else
    st_append(c, "  settings: the zone's own metadata\n");
  if (x->allow_transfer_count > 0 || x->tsig_keys_count > 0) {
    st_append(c, "  allow-transfer:");
    st_list(c, "addresses", x->allow_transfer, x->allow_transfer_count);
    st_list(c, "keys", x->tsig_keys, x->tsig_keys_count);
    st_append(c, " (match %s)\n", x->transfer_acl_match == ACL_MATCH_ANY ? "any" : "all");
  }
  if (x->allow_update_count > 0) {
    st_append(c, "  allow-update:");
    st_list(c, "entries", x->allow_update, x->allow_update_count);
    st_append(c, " (match %s)\n", x->update_acl_match == ACL_MATCH_ALL ? "all" : "any");
  }
  if (c->cfg) {
    char notes[400];
    if (ceiling_notes(c->cfg, x, notes, sizeof(notes)) > 0) st_append(c, "  acl-ceiling: %s\n", notes);
    const char *missing = db_settings_missing_key(x, c->cfg);
    if (missing)
      st_append(c, "  settings error: the TSIG key '%.64s' is not defined in karidns.conf; the ACL that names it refuses everybody\n",
                missing);
  }
}

/* 0.7 signer-wait: what the store's record of the zone says about karidns-signer (flags: STORE_F_*); in_memory: the version in memory is held (dbreg_signer_hold()) */
static void signer_status(status_ctx_t *c, uint16_t flags, bool in_memory) {
  if (flags & STORE_F_SIGNER_HELD)
    st_append(c, "  signer-wait: the database has another version, which waits for the signer; %s keeps serving until the signer has signed it\n",
              in_memory ? "the version in memory (held there)" : "the version here");
  if (flags & STORE_F_SIGNER_UNSIGNED)
    st_append(c, "  signer-wait: serving a version the signer has not signed yet (no signed version was here to keep; it is served as it is until the signer signs it)\n");
}

static bool status_cb(void *ud, const char *view, const dbreg_zone_t *z) {
  status_ctx_t *c = ud;
  if (c->view && strcasecmp(c->view, view) != 0) return true;
  if (!domain_names_match_ci(z->name, c->zone)) return true;
  c->matches++;
  const char *st = z->shadowed ? "shadowed" : (z->last_result == DBREG_REJECTED ? "rejected" : "applied");
  st_append(c, "zone %s view %s: source id %lld, serial %u, status %s", z->name, view, (long long)z->source_id,
            zdir_entry(z) ? (zdir_entry(z)->is_secondary ? atomic_load_explicit(&zdir_entry(z)->serial, memory_order_relaxed) : zdir_serial(z)) : zdir_serial(z), st);
  if (z->shadowed) st_append(c, z->shadow_by == DBREG_SH_CATALOG ? " (hidden by a catalog member)" : " (hidden by a zone in karidns.conf)");
  if (z->last_result == DBREG_REJECTED && zdir_entry(z)) st_append(c, " (serving the last good version, serial %u)", zdir_serial(z));
  if (!zdir_entry(z)) st_append(c, z->digest && atomic_load_explicit(&z->state, memory_order_relaxed) != ZDIR_ST_ERROR
                                       ? " (the data is out of memory: it is read when a query needs it)" : " (no version loaded)");
  {
    char errtxt[192];
    if (dbreg_err_get_locked(view, z->name, (z->kind & ZDIR_K_STORED) ? z->zid : 0xFFFFFFFFu, errtxt, sizeof(errtxt))) st_append(c, ", last error: %s", errtxt);
  }
  if (zdir_entry(z) && atomic_load_explicit(&zdir_entry(z)->rolled_back, memory_order_acquire))
    st_append(c, " (rolled back: serial %u, from %u; pinned in memory until the next load from the database)", atomic_load_explicit(&zone_xr(zdir_entry(z))->rb_serial, memory_order_relaxed),
              atomic_load_explicit(&zone_xr(zdir_entry(z))->rb_from, memory_order_relaxed));
  else if (zdir_entry(z) && atomic_load_explicit(&zdir_entry(z)->updated, memory_order_relaxed)) st_append(c, " (changed by a dynamic UPDATE: pinned in memory until the next load from the database)");
  st_append(c, "\n");
  {
    dbdir_rec_t rr;                                      /* 0.7 signer-wait: what the store's record says (the registry lock is held: a read that never sleeps) */
    if (dbdir() && dbdir()->rec_get_nb(view, z->name, &rr) == 1) signer_status(c, rr.flags, (z->sig_hold & ZDIR_SIG_MEM) != 0);
    else if (!dbdir() && (z->sig_hold & ZDIR_SIG_MEM)) signer_status(c, STORE_F_SIGNER_HELD, true);      /* (0.7, without the store: ZONE_HOLD) */
    else if (!dbdir() && (z->sig_hold & ZDIR_SIG_UNSIGNED))
      st_append(c, "  signer-wait: the database has another version, which waits for the signer; nothing of the zone is in memory, so the next query reads that version as it is (and the log says so)\n");
  }
  /* a line of its own: the zone line above keeps its form (it ends with the status) */
  if (zdir_entry(z) && atomic_load_explicit(&zone_xr(zdir_entry(z))->prev_bytes, memory_order_relaxed))
    st_append(c, "  previous version kept for rollback: serial %u, %llu bytes\n", atomic_load_explicit(&zone_xr(zdir_entry(z))->prev_serial, memory_order_relaxed),
              (unsigned long long)atomic_load_explicit(&zone_xr(zdir_entry(z))->prev_bytes, memory_order_relaxed));
  if (zdir_entry(z)) settings_status(c, zdir_entry(z));
  return true;
}

/* karictl dbstatus is polled by scripts and operators; the count of the zones in memory walks the whole registry under its lock (O(N)), so it is done at most once
 * a second and the lines of the second between show that figure.  A caller that finds the cache in use by another thread counts for itself.
 * *rbytes: the bytes of the zones in memory (zone_bytes_get) taken at the same moment as the count.  The memory: line divides the one by the other: a count
 * of up to a second ago with the bytes of now gave a wrong average right after an eviction (300 zones in the count, the bytes of the few still in memory:
 * fit=100% and status=ok under a limit that keeps less than half of them). */
static void residency_cached(dbreg_residency_t *rs, uint64_t *rbytes) {
  static atomic_flag busy = ATOMIC_FLAG_INIT;
  static dbreg_residency_t cache;
  static uint64_t cache_bytes;
  static int64_t at;
  zone_bytes_t zdb;
  if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire)) {
    dbreg_residency(rs);
    zone_bytes_get(ZBYTES_DB, &zdb);
    *rbytes = zdb.resident;
    return;
  }
  int64_t now = now_ms();
  if (at == 0 || now - at >= 1000) {
    dbreg_residency(&cache);
    zone_bytes_get(ZBYTES_DB, &zdb);
    cache_bytes = zdb.resident;
    at = now;
  }
  *rs = cache;
  *rbytes = cache_bytes;
  atomic_flag_clear_explicit(&busy, memory_order_release);
}

size_t db_ingest_status(const char *zone, const char *view, char *out, size_t cap) {
  if (cap == 0) return 0;
  out[0] = '\0';
  ing_cfg_t snap;
  snapshot_cfg(&snap);
  if (!snap.enabled) return 0;
  status_ctx_t c = { zone, view, out, cap, 0, 0, NULL };
  if (zone) {
    dbreg_cursor_t cur;
    memset(&cur, 0, sizeof(cur));
    rcu_aux_read_lock();                                 /* the entries' settings blocks are read */
    c.cfg = acquire_config_snapshot();
    (void)dbreg_walk(&cur, status_cb, &c);
    rcu_aux_read_unlock();
    if (c.matches == 0 && dbdir()) {                     /* 0.7 S3: a zone of the store that is not in memory has no registry element: one index lookup per view, no attach */
      char canon[260];
      snprintf(canon, sizeof(canon), "%s", zone);
      size_t cl = strlen(canon);
      if (cl > 0 && canon[cl - 1] != '.' && cl + 1 < sizeof(canon)) {
        canon[cl] = '.';
        canon[cl + 1] = '\0';
      }
      dbreg_info_t info[8];
      int ni = dbreg_find_info(view, canon, info, 8);
      for (int i = 0; i < ni && i < 8; i++) {
        c.matches++;
        dbdir_rec_t rr;
        const bool has_rr = dbdir()->rec_get(info[i].view, canon, &rr);
        if (has_rr && rr.state == STORE_STATE_KNOWN)         /* 0.7 WP7b: the reconcile has the zone, its body is not here yet */
          st_append(&c, "zone %s view %s: source id %lld, in the zone store without a body yet (not in memory; %s): the body is fetched in the background, or when a query asks for it\n", canon, info[i].view,
                    (long long)info[i].source_id, (rr.flags & STORE_F_REJECTED_NEW) ? "refused: the loader cannot read it or the Backend rejected it; asked for again when the database says another version" : "asked for");
        else
          st_append(&c, "zone %s view %s: source id %lld, serial %u, status %s (in the zone store, not in memory: it is attached when a query needs it)%s%s%s\n", canon, info[i].view,
                    (long long)info[i].source_id, (unsigned)info[i].serial, info[i].last_result == DBREG_REJECTED ? "rejected" : "applied", has_rr && (rr.flags & STORE_F_STALE) ? "; the database has another version, its body is fetched in the background" : has_rr && (rr.flags & STORE_F_SIGNER_HELD) ? "; the database has another version, which waits for the signer (signer-wait)" : "",
                    info[i].error[0] ? ", last error: " : "", info[i].error);
        if (has_rr) signer_status(&c, rr.state == STORE_STATE_KNOWN ? rr.flags : (uint16_t)(rr.flags & STORE_F_SIGNER_UNSIGNED), false);      /* (the stored line says the hold already) */
      }
    }
    if (c.matches == 0) st_append(&c, "zone %s: not in the database registry\n", zone);
    return c.len;
  }
  char err[ST_STR], ver[ST_STR], t1[40], t2[40], t3[40];
  int64_t err_time = 0;
  st_get_strings(err, sizeof(err), ver, sizeof(ver), &err_time);
  fmt_time(atomic_load(&g_st.since), t1, sizeof(t1));
  if (atomic_load(&g_st.connected))
    st_append(&c, "loader: connected since %s (pid %u, %s)\n", t1, atomic_load(&g_st.pid), ver);
  else if (atomic_load(&g_st.ever_connected))
    st_append(&c, "loader: not connected since %s (last pid %u)\n", t1, atomic_load(&g_st.pid));
  else
    st_append(&c, "loader: not connected yet\n");
  size_t total, rejected, sh_cfg, sh_cat;
  dbreg_counts2(&total, &rejected, &sh_cfg, &sh_cat);
  if (sh_cat == 0)
    st_append(&c, "zones: %zu in the registry (%zu served, %zu shadowed by karidns.conf), %zu with a rejected version\n",
              total, total - sh_cfg, sh_cfg, rejected);
  else
    st_append(&c, "zones: %zu in the registry (%zu served, %zu shadowed by karidns.conf, %zu hidden by catalog members), "
                  "%zu with a rejected version\n", total, total - sh_cfg - sh_cat, sh_cfg, sh_cat, rejected);
  if (dbdir()) {                                   /* 0.7 store S5: what the zones of the store cost and what is kept of the zones that left memory (design 4.2, 6.1, 6.7) */
    zone_entry_pool_stats_t ep;
    zone_entry_pool_stats(&ep);
    uint64_t folded = 0, frows = 0, freplaced = 0, enoted = 0, edropped = 0;
    size_t etexts = 0;
    dbreg_fold_stats(&folded, &frows, &freplaced);
    dbreg_err_stats(&etexts, &enoted, &edropped);
    st_append(&c, "zone entries: %llu in the pool (%llu slab(s) of %llu KiB, %llu octets a slot); %llu zone(s) left memory with their counters folded into the totals (%llu in the table of the top zones); %zu rejection text(s) in the ring (%llu pushed out)\n",
              (unsigned long long)ep.used, (unsigned long long)ep.slabs, (unsigned long long)(ep.slab_bytes >> 10), (unsigned long long)ep.slot_bytes, (unsigned long long)folded,
              (unsigned long long)frows, etexts, (unsigned long long)edropped);
  }
  {
    /* D1a (design 8.1): what the zone versions hold; "retired" = replaced, not freed yet (a reader or a transfer may still hold it) */
    zone_bytes_t zdb, zot;
    zone_bytes_get(ZBYTES_DB, &zdb);
    zone_bytes_get(ZBYTES_OTHER, &zot);
    st_append(&c, "zone versions and IXFR deltas: database zones %llu bytes resident + %llu retired; other zones %llu resident + %llu retired\n",
              (unsigned long long)zdb.resident, (unsigned long long)zdb.retired, (unsigned long long)zot.resident,
              (unsigned long long)zot.retired);
    st_append(&c, "zone versions kept for karictl rollback (rollback-window): database zones %llu bytes; other zones %llu bytes\n", (unsigned long long)zdb.previous,
              (unsigned long long)zot.previous);
    park_stats_t ps;
    park_stats_get(&ps);                                
    uint32_t frate = atomic_load_explicit(&g_fetch_rate, memory_order_relaxed);
    char frs[24];
    if (frate) snprintf(frs, sizeof(frs), "%u/s", (unsigned)frate);
    else snprintf(frs, sizeof(frs), "unlimited");
    st_append(&c, "fetch: rate=%s refused_by_rate=%llu issued=%llu concurrency=%u\n", frs,
              (unsigned long long)atomic_load_explicit(&g_fetch_limited, memory_order_relaxed), (unsigned long long)atomic_load_explicit(&g_fetch_issued, memory_order_relaxed),
              (unsigned)atomic_load_explicit(&g_fetch_conc, memory_order_relaxed));
    {
      st_append(&c, "fetchq: in_flight=%u places=%u peak=%u table_full=%llu ring_dropped=%llu park_full=%llu park_timeout=%llu loader_busy=%llu ingest_busy=%u%% fill_busy=%u%% hist=%llu,%llu,%llu,%llu,%llu queued=%u queue_peak=%u waited=%llu queue_dropped=%llu queue_full=%llu\n",
                (unsigned)atomic_load_explicit(&g_fq_inflight, memory_order_relaxed), (unsigned)park_places_used(), (unsigned)atomic_load_explicit(&g_fq_peak, memory_order_relaxed),
                (unsigned long long)atomic_load_explicit(&g_fq_table_full, memory_order_relaxed), (unsigned long long)ps.ring_dropped, (unsigned long long)ps.full,
                (unsigned long long)ps.timeout, (unsigned long long)atomic_load_explicit(&g_fq_loader_busy, memory_order_relaxed),
                (unsigned)atomic_load_explicit(&g_ing_busy_pct, memory_order_relaxed), (unsigned)atomic_load_explicit(&g_ing_fill_pct, memory_order_relaxed), (unsigned long long)atomic_load_explicit(&g_fq_hist[0], memory_order_relaxed),
                (unsigned long long)atomic_load_explicit(&g_fq_hist[1], memory_order_relaxed), (unsigned long long)atomic_load_explicit(&g_fq_hist[2], memory_order_relaxed),
                (unsigned long long)atomic_load_explicit(&g_fq_hist[3], memory_order_relaxed), (unsigned long long)atomic_load_explicit(&g_fq_hist[4], memory_order_relaxed),
                (unsigned)atomic_load_explicit(&g_wq_len, memory_order_relaxed), (unsigned)atomic_load_explicit(&g_wq_peak, memory_order_relaxed),
                (unsigned long long)atomic_load_explicit(&g_wq_waited, memory_order_relaxed), (unsigned long long)atomic_load_explicit(&g_wq_dropped, memory_order_relaxed),
                (unsigned long long)atomic_load_explicit(&g_wq_full, memory_order_relaxed));
    }
    {
      store_lookup_t lk;
      db_ingest_lookup_stats(&lk);
      st_append(&c, "lookup of names while the first pass has not listed every zone: ready=%s in_flight=%u pending=%u asked=%llu found=%llu none=%llu failed=%llu refused=%llu same_name=%llu body_inline=%llu take_fail=%llu covered=%llu shed=%llu expired=%llu drop_room=%llu drop_timeout=%llu drop_queue=%llu drop_failed=%llu zone_drop_room=%llu zone_drop_timeout=%llu zone_drop_queue=%llu zone_drop_failed=%llu bad_body=%llu rtt_p50_us=%llu rtt_p99_us=%llu remembered=%llu reask_suppressed=%llu remember_releases=%llu drain_passes=%llu drain_cut=%llu drain_pass_max=%u drain_pass_max_us=%llu\n",
                lk.ready ? "yes" : "no", (unsigned)lk.in_flight, (unsigned)lk.pending, (unsigned long long)lk.asked, (unsigned long long)lk.found, (unsigned long long)lk.none, (unsigned long long)lk.failed,
                (unsigned long long)lk.refused, (unsigned long long)lk.same_name, (unsigned long long)lk.body_inline, (unsigned long long)lk.take_fail, (unsigned long long)lk.covered, (unsigned long long)lk.shed,
                (unsigned long long)lk.expired, (unsigned long long)lk.drop_lk_room, (unsigned long long)lk.drop_lk_timeout, (unsigned long long)lk.drop_lk_queue, (unsigned long long)lk.drop_lk_failed,
                (unsigned long long)lk.drop_zone_room, (unsigned long long)lk.drop_zone_timeout, (unsigned long long)lk.drop_zone_queue, (unsigned long long)lk.drop_zone_failed, (unsigned long long)lk.bad_body, (unsigned long long)store_status_hist_pct(lk.hist, 50, lk.max_ns), (unsigned long long)store_status_hist_pct(lk.hist, 99, lk.max_ns),
                (unsigned long long)lk.remembered, (unsigned long long)lk.reask_suppressed, (unsigned long long)lk.remember_releases, (unsigned long long)lk.drain_passes, (unsigned long long)lk.drain_cut,
                (unsigned)lk.drain_pass_max, (unsigned long long)((lk.drain_pass_max_ns + 999) / 1000));
    }
    dbreg_cache_stats_t cs;
    dbreg_cache_stats(&cs);
    {                                                    /* 0.7: the state of the store's journal (written after its lock): a failed journal takes no more changes */
      store_t *sth = db_store_handle();
      store_stats_t *ss = sth ? calloc(1, sizeof(*ss)) : NULL;
      if (ss) {
        store_read_lock();
        store_stats(sth, ss);
        store_read_unlock();
        static const char *const jst[] = { "ok", "nospace", "failed" };
        db_recon_status_t rs;
        db_recon_status(&rs);
        st_append(&c, "store: journal=%s error=%d failed_at=%llu unwritten=%llu batch_commit_errors=%llu%s\n", jst[ss->journal_state < 0 || ss->journal_state > 2 ? 2 : ss->journal_state],
                  ss->journal_error, (unsigned long long)ss->journal_failed_unix, (unsigned long long)ss->ring_unwritten_bytes, (unsigned long long)rs.batch_store_errors,
                  ss->journal_state == STORE_JOURNAL_FAILED ? " (the store takes no more changes; restart the server: the open replays what was written)" :
                  ss->journal_state == STORE_JOURNAL_NOSPACE ? " (no room for the journal: changes are refused until there is room)" : "");
        free(ss);
      }
    }
    {
      uint64_t nq, nd;
      dbreg_notify_stats(&nq, &nd);
      st_append(&c, "notify of zones out of memory: queued=%llu deferred=%llu (a serial that changed while the data was out of memory; the NS addresses come with the summary; deferred: the ring was full, the zone is queued later)\n", (unsigned long long)nq, (unsigned long long)nd);
    }
    st_append(&c, "transfers of zones out of memory: waited=%llu loaded=%llu failed=%llu summary_answers=%llu marked=%llu timeout=%ums\n",
              (unsigned long long)cs.xfr[DBREG_XFR_WAITED], (unsigned long long)cs.xfr[DBREG_XFR_LOADED], (unsigned long long)cs.xfr[DBREG_XFR_FAILED],
              (unsigned long long)cs.xfr[DBREG_XFR_SUMMARY], (unsigned long long)cs.xfr_marked, (unsigned)atomic_load_explicit(&g_xfr_timeout_ms, memory_order_relaxed));
    if (cs.limit)
      st_append(&c, "cache: limit=%llu resident=%llu retired=%llu previous=%llu inflight=%llu held=%llu long_reader=%d evictions=%llu rounds=%llu cold=%llu marked=%llu misses=%llu "
                    "shed=%llu pinned=%llu peak=%llu victim_freq=%u room_evictions=%llu room_relaxed=%llu room_waits=%llu room_timeouts=%llu room_waiting=%u limit_default=%d\n",
                (unsigned long long)cs.limit, (unsigned long long)cs.resident, (unsigned long long)cs.retired, (unsigned long long)cs.previous, (unsigned long long)cs.inflight, (unsigned long long)cs.held, cs.long_reader ? 1 : 0,
                (unsigned long long)cs.evictions, (unsigned long long)cs.rounds, (unsigned long long)cs.cold, (unsigned long long)cs.marked,
                (unsigned long long)cs.misses, (unsigned long long)atomic_load_explicit(&g_fetch_shed, memory_order_relaxed),
                (unsigned long long)cs.pinned_bytes, (unsigned long long)cs.peak, (unsigned)cs.victim_freq,
                (unsigned long long)cs.room_evictions, (unsigned long long)cs.room_relaxed, (unsigned long long)atomic_load_explicit(&g_room_waits, memory_order_relaxed),
                (unsigned long long)atomic_load_explicit(&g_room_timeouts, memory_order_relaxed), (unsigned)atomic_load_explicit(&g_room_waiting, memory_order_relaxed),
                atomic_load_explicit(&g_limit_default, memory_order_relaxed) ? 1 : 0);
    else
      st_append(&c, "cache: no memory-limit (every database zone stays in memory)\n");
    st_append(&c, "apex: asked=%llu answered=%llu walking=%d walks=%llu queued=%u (summaries asked for after a reload, for the apex of zones out of memory; queued: zones in the list that wait for a free place or a token)\n",
              (unsigned long long)atomic_load_explicit(&g_apex_asked, memory_order_relaxed), (unsigned long long)atomic_load_explicit(&g_apex_answered, memory_order_relaxed),
              atomic_load_explicit(&g_apex_walking, memory_order_relaxed) ? 1 : 0, (unsigned long long)atomic_load_explicit(&g_apex_walks, memory_order_relaxed), (unsigned)atomic_load_explicit(&g_warm_n, memory_order_relaxed));
    st_append(&c, "updated: %zu zone(s) changed by a dynamic UPDATE are pinned in memory until the next load from the database replaces them\n",
              dbreg_count_updated());
    size_t nel, rbytes, ibytes;
    dbreg_dir_bytes(&nel, &rbytes, &ibytes);
    if (dbdir()) {                                        /* 0.7 S3: the zone store is the directory; the heap holds the zones that are in memory */
      store_stats_t sst;
      store_t *sth = db_store_handle();
      if (sth) {
        store_stats(sth, &sst);
        st_append(&c, "zone directory: the zone store (%llu zones: %llu stored, %llu known; its index and tables are files, %llu bytes on disk per zone for the tables), the heap holds %zu elements for the zones in memory: %zu bytes in the registry + %zu bytes in the indexes of the views, %llu zones in the attach table\n",
                  (unsigned long long)(sst.zones_stored + sst.zones_known), (unsigned long long)sst.zones_stored, (unsigned long long)sst.zones_known, 160ull, nel, rbytes, ibytes,
                  (unsigned long long)dbdir()->counters(4));
      }
    } else {
      st_append(&c, "zone directory: %zu elements, %zu bytes in the registry + %zu bytes in the indexes of the views (%zu bytes per zone)\n",
                nel, rbytes, ibytes, nel ? (rbytes + ibytes) / nel : (size_t)0);
    }
    if (dbdir()) {                                        /* 0.7 WP7b: the reconcile with the loader (store design 5.3, 5.4): the pass, the bodies still to come, the mass-delete guard */
      db_recon_status_t rs;
      db_recon_status(&rs);
      st_append(&c, "store pass: %s view=%s entries=%llu of about %llu (new %llu, changed %llu, renamed %llu, unchanged %llu, already asked for %llu, refused with this version %llu), not offered by the loader %llu; "
                    "sweep: %llu of %llu zone(s) not listed, %llu deleted; bodies: %llu without one now, %llu fetched, %llu failed, %llu in flight (since the start: %llu wanted); changes: %llu upserts, %llu deletes; "
                    "cursors kept %llu; passes %llu\n",
                rs.active ? "running" : "idle", rs.view[0] ? rs.view : "-", (unsigned long long)rs.entries, (unsigned long long)rs.estimate, (unsigned long long)rs.created,
                (unsigned long long)rs.changed, (unsigned long long)rs.renamed, (unsigned long long)rs.same, (unsigned long long)rs.pending, (unsigned long long)rs.kept,
                (unsigned long long)rs.skipped, (unsigned long long)rs.unlisted, (unsigned long long)rs.total, (unsigned long long)rs.swept, (unsigned long long)rs.known_now,
                (unsigned long long)rs.fetched, (unsigned long long)rs.fetch_failed, (unsigned long long)rs.in_flight, (unsigned long long)rs.wanted,
                (unsigned long long)rs.change_upserts, (unsigned long long)rs.change_deletes, (unsigned long long)rs.cursors, (unsigned long long)rs.passes);
      if (rs.nonstore)
        st_append(&c, "store: %llu zone(s) have a name the store cannot hold (the root zone): zones of the heap directory, read from the database at every start\n", (unsigned long long)rs.nonstore);
      if (rs.guard_views) {
        char tg[40];
        fmt_time((int64_t)rs.guard_unix, tg, sizeof(tg));
        st_append(&c, "MASS-DELETE GUARD HELD: view %s: the pass of %s did not list %llu of the %llu zone(s) the Backend holds (more than 20 percent and more than 1000), so none was deleted and the cursor was not advanced; "
                      "if the database is right, `karictl reload -force` deletes them\n", rs.guard_view, tg, (unsigned long long)rs.guard_unlisted, (unsigned long long)rs.guard_total);
      }
    }
    {
      db_recon_status_t rs;                              /* 0.7 signer-wait (with the store and without it) */
      db_recon_status(&rs);
      uint64_t pz = 0, pb = 0;
      dbreg_signer_pinned(&pz, &pb);
      if (rs.signer_held || rs.signer_unsigned || rs.signer_carried || pz)
        st_append(&c, "signer-wait: since the start %llu version(s) waited for the signer while a signed one kept serving (%llu kept by the version in memory alone; %llu held across a start of the "
                      "loader or the server), %llu version(s) served that the signer has not signed yet (nothing signed was here to keep; `karictl dbstatus <zone>` and the log name them); held in memory "
                      "now: %llu zone(s), %llu bytes (counted against memory-limit)\n",
                  (unsigned long long)rs.signer_held, (unsigned long long)rs.signer_held_mem, (unsigned long long)rs.signer_carried, (unsigned long long)rs.signer_unsigned,
                  (unsigned long long)pz, (unsigned long long)pb);
    }
    st_append(&c, "alias: scans=%llu (the alias thread's scans of the zones for ALIAS records: they follow ALIAS zones coming, changing and going and the configuration, not every zone a fetch brings)\n",
              (unsigned long long)alias_scan_count());
    {
      /* D1a step 7: what is in memory, how the queries fare, the warm-up and the state file.  The lines above keep their form. */
      dbreg_residency_t rs;
      uint64_t rs_bytes;
      residency_cached(&rs, &rs_bytes);
      uint64_t parked = cs.misses;
      st_append(&c, "residency: directory=%zu resident=%zu out_of_memory=%zu evictions=%llu\n", rs.total, rs.resident, rs.absent,
                (unsigned long long)cs.evictions);
      {                                                  /* 0.7 P-F: what the database needs in memory, and what memory-limit does about it (dns_mem_advice.c) */
        ma_in_t mi;
        ma_est_t me;
        char mt[700];
        ma_inputs(&mi, &rs, dbreg_cache_limit());
        mi.resident_bytes = rs_bytes;                    /* the bytes of the moment of the count (residency_cached) */
        ma_estimate(&mi, &me);
        ma_text_status(mt, sizeof(mt), &me);
        st_append(&c, "memory: %s\n", mt);
      }
      if (rs.queries > 0)
        st_append(&c, "queries: answered=%llu parked=%llu hit_rate=%.1f%% (answered from a zone already in memory / all; answered: the zones' own counts, including those of versions that were replaced or taken out; parked: the queries that had to wait for a zone, since the start)\n",
                  (unsigned long long)rs.queries, (unsigned long long)parked,
                  100.0 * (double)(rs.queries > parked ? rs.queries - parked : 0) / (double)rs.queries);
      else
        st_append(&c, "queries: answered=0 parked=%llu hit_rate=n/a\n", (unsigned long long)parked);
      uint64_t wq = atomic_load_explicit(&g_wl_queued, memory_order_relaxed), wl = atomic_load_explicit(&g_wl_loaded, memory_order_relaxed);
      uint64_t wf = atomic_load_explicit(&g_wl_failed, memory_order_relaxed), wm = atomic_load_explicit(&g_wl_dropmem, memory_order_relaxed);
      uint32_t wp = atomic_load_explicit(&g_wl_pending, memory_order_relaxed), wi = atomic_load_explicit(&g_wl_flight, memory_order_relaxed);
      uint64_t gone = wl + wf + wm + wp + wi;
      uint64_t wskip = wq > gone ? wq - gone : 0;            /* in memory by the time its turn came, or no longer a zone */
      st_append(&c, "warm: received=%d queued=%llu loaded=%llu skipped=%llu (memory limit %llu, already in memory or gone %llu) failed=%llu pending=%u in_flight=%u\n",
                atomic_load_explicit(&g_wl_received, memory_order_relaxed) ? 1 : 0, (unsigned long long)wq, (unsigned long long)wl,
                (unsigned long long)(wskip + wm), (unsigned long long)wm, (unsigned long long)wskip, (unsigned long long)wf, wp, wi);
      int64_t hold_dl = atomic_load_explicit(&g_hold_deadline_ms, memory_order_relaxed);
      if (!hold_dl)
        st_append(&c, "warm-before-serve: off\n");
      else if (atomic_load_explicit(&g_warm_done, memory_order_acquire))
        st_append(&c, "warm-before-serve: queries accepted after %lld ms\n", (long long)atomic_load_explicit(&g_warm_done_ms, memory_order_relaxed));
      else
        st_append(&c, "warm-before-serve: holding the queries (%lld ms left)\n", (long long)(hold_dl - now_ms() > 0 ? hold_dl - now_ms() : 0));
      char sfp[1100] = "";
      rcu_aux_read_lock();
      const server_config_t *scfg = acquire_config_snapshot();
      if (scfg && scfg->database.loader_state_file) snprintf(sfp, sizeof(sfp), "%s", scfg->database.loader_state_file);
      rcu_aux_read_unlock();
      if (!sfp[0]) {
        st_append(&c, "state-file: none (loader-state-file is not set)\n");
      } else {
        static const char *const fs[KDB_HF_N] = { "none", "loaded", "missing (first start)", "corrupt, ignored", "unreadable, ignored" };
        int fst = atomic_load_explicit(&g_sf_fstate, memory_order_relaxed);
        int ls = atomic_load_explicit(&g_hot_last_status, memory_order_relaxed);
        static const char *const as[KDB_HA_N] = { "written", "unchanged", "failed", "no state file", "list not valid" };
        char t4[40];
        fmt_time(atomic_load_explicit(&g_hot_last_sent, memory_order_relaxed), t4, sizeof(t4));
        st_append(&c, "state-file: %s at_start=%s (%u zones) hot_lists_sent=%llu last_sent=%s (%u zones) acks: written=%llu unchanged=%llu failed=%llu last_ack=%s (%u zones in the file)%s\n",
                  sfp, fst >= 0 && fst < KDB_HF_N ? fs[fst] : "not reported yet", atomic_load_explicit(&g_sf_fzones, memory_order_relaxed),
                  (unsigned long long)atomic_load_explicit(&g_hot_sent, memory_order_relaxed), atomic_load_explicit(&g_hot_last_sent, memory_order_relaxed) ? t4 : "never",
                  atomic_load_explicit(&g_hot_last_n, memory_order_relaxed), (unsigned long long)atomic_load_explicit(&g_hot_acks[KDB_HA_WRITTEN], memory_order_relaxed),
                  (unsigned long long)atomic_load_explicit(&g_hot_acks[KDB_HA_UNCHANGED], memory_order_relaxed),
                  (unsigned long long)atomic_load_explicit(&g_hot_acks[KDB_HA_FAILED], memory_order_relaxed), ls >= 0 && ls < KDB_HA_N ? as[ls] : "none yet",
                  atomic_load_explicit(&g_hot_last_zones, memory_order_relaxed), dbreg_cache_limit() ? "" : " [no memory-limit: no hot list is made]");
      }
    }
  }
  fmt_time(atomic_load(&g_st.batch_time), t2, sizeof(t2));
  if (atomic_load(&g_st.batch_id) == 0)
    st_append(&c, "last batch: none yet\n");
  else
    st_append(&c, "last batch: id %llu, kind %s, %s %s: %u applied, %u rejected, %u shadowed, %u deleted\n",
              (unsigned long long)atomic_load(&g_st.batch_id), kind_name(atomic_load(&g_st.batch_kind)),
              atomic_load(&g_st.batch_done) ? "finished" : "started", t2, atomic_load(&g_st.b_applied),
              atomic_load(&g_st.b_rejected), atomic_load(&g_st.b_shadowed), atomic_load(&g_st.b_deleted));
  if (!snap.auto_reload) {
    st_append(&c, "auto reload: off\n");
  } else {
    st_append(&c, "auto reload: on (poll-interval %u s, coalesce %u ms), %llu auto batch(es) since start\n", snap.poll_interval,
              snap.coalesce_ms, (unsigned long long)atomic_load(&g_st.tot_auto_batches));
    rcu_aux_read_lock();
    const server_config_t *vcfg = acquire_config_snapshot();
    uint32_t vidx = 0;
    for (const view_config_t *v = vcfg ? vcfg->views : NULL; v; v = v->next, vidx++) {
      if (v->database_none) continue;
      as_data_t ad;
      char tp[40];
      if (vidx >= KARIDNS_DB_MAX_VIEWS || !as_get(&g_as[vidx], &ad) || !(ad.flags & KDB_AS_AUTO)) {
        st_append(&c, "  view %.64s: no report from the loader yet\n", v->name ? v->name : "?");
        continue;
      }
      fmt_time(ad.last_poll, tp, sizeof(tp));
      st_append(&c, "  view %.64s: last poll %s, applied change seq %llu, pending changes %u, last error: %s\n",
                v->name ? v->name : "?", tp, (unsigned long long)ad.applied_seq, ad.pending, ad.err[0] ? ad.err : "none");
      if (ad.sig_wait)                                  /* item C: zones changed in the database that wait for karidns-signer (X-KARIDNS-SIGNER=1) */
        st_append(&c, "    waiting for the signer: %u zone(s)%s%s\n", ad.sig_wait, ad.sig_names[0] ? ": " : "", ad.sig_names);
    }
    rcu_aux_read_unlock();
  }
  /* B11: multi-server reload requests, one line per view whose source has the tables (the loader reports them whether or not
   * auto reload is on) */
  {
    rcu_aux_read_lock();
    const server_config_t *vcfg = acquire_config_snapshot();
    uint32_t vidx = 0;
    for (const view_config_t *v = vcfg ? vcfg->views : NULL; v; v = v->next, vidx++) {
      if (v->database_none || vidx >= KARIDNS_DB_MAX_VIEWS) continue;
      as_data_t rd;
      if (!as_get(&g_as[vidx], &rd) || !(rd.flags & KDB_AS_REQ)) continue;
      char tw[40];
      fmt_time(rd.req_time, tw, sizeof(tw));
      st_append(&c, "reload requests (view %.64s): server-id %s, last applied generation %llu, ok %s, status written %s, last error: %s\n",
                v->name ? v->name : "?", rd.server_id[0] ? rd.server_id : "(none)", (unsigned long long)rd.req_generation,
                rd.req_ok ? "yes" : "no", tw, rd.req_err[0] ? rd.req_err : "none");
    }
    rcu_aux_read_unlock();
  }
  uint64_t rt_applied, rt_rejected, rt_deleted;
  db_recon_totals(&rt_applied, &rt_rejected, &rt_deleted);               /* (the entries of the manifest pages: counted by the reconcile thread) */
  st_append(&c, "since start: %llu applied, %llu rejected, %llu shadowed, %llu deleted, %llu failed in the loader\n",
            (unsigned long long)(atomic_load(&g_st.tot_applied) + rt_applied), (unsigned long long)(atomic_load(&g_st.tot_rejected) + rt_rejected),
            (unsigned long long)atomic_load(&g_st.tot_shadowed), (unsigned long long)(atomic_load(&g_st.tot_deleted) + rt_deleted),
            (unsigned long long)atomic_load(&g_st.tot_failed));
  st_append(&c, "settings: %zu distinct (shared between zones), %u zone(s) name a TSIG key that karidns.conf does not define\n",
            db_settings_count(), atomic_load_explicit(&g_settings_missing_keys, memory_order_relaxed));
  fmt_time(err_time, t3, sizeof(t3));
  if (err[0]) st_append(&c, "last protocol error: %s (%s)\n", err, t3);
  else st_append(&c, "last protocol error: none\n");
  return c.len;
}

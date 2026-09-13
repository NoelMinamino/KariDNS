#define _GNU_SOURCE
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include "dns_wire.h"
#include "dns_zone_parser.h"

typedef struct {
  _Atomic(zone_arena_t *) active;
  zone_arena_t arena_a;
  zone_arena_t arena_b;
} zone_rcu_t;

#define MAX_IXFR_HISTORY 32

typedef struct {
  uint32_t old_serial;
  uint32_t new_serial;
  dns_record_t *deleted;
  int deleted_count;
  dns_record_t *added;
  int added_count;
  _Atomic int ref_count;
  zone_arena_t arena;
} ixfr_txn_t;

typedef struct {
  ixfr_txn_t *entries[MAX_IXFR_HISTORY];
  int head;
  int count;
  pthread_mutex_t lock;
} ixfr_history_t;

typedef struct {
  char unique_id[256];
  char domain[256];
  char **groups;
  int group_count;
  char coo_target[256];
} catalog_member_id_t;

typedef struct {
    _Atomic uint64_t queries_total;
    _Atomic uint64_t responses_noerror;
    _Atomic uint64_t responses_nxdomain;
    _Atomic uint64_t responses_nodata;
    _Atomic uint64_t responses_servfail;
    _Atomic uint64_t responses_refused;
    _Atomic uint64_t tcp_queries;
    _Atomic uint64_t ecs_queries;
    _Atomic uint64_t edns_queries;
    _Atomic uint64_t dnssec_do_queries;
    _Atomic uint64_t rrl_dropped;
    _Atomic uint64_t rrl_slipped;
    _Atomic uint64_t notify_sent;
    _Atomic uint64_t notify_ack;
    _Atomic uint64_t axfr_success;
    _Atomic uint64_t ixfr_success;
    _Atomic time_t   last_transfer_time;
    _Atomic time_t   last_notify_time;
} zone_observatory_t;

typedef struct {
  char domain[256];
  char view_name[64];
  zone_rcu_t rcu;
  pthread_mutex_t writer_lock;
  _Atomic(uint32_t) serial;
  _Atomic(uint32_t) refresh;
  _Atomic(uint32_t) retry;
  _Atomic(uint32_t) expire;
  _Atomic(time_t) next_check;
  _Atomic bool refresh_now;
  _Atomic bool notify_now;
  _Atomic bool is_transferring;
  _Atomic(int) active_axfr;
  _Atomic int snapshot_refs;
  ixfr_history_t ixfr_history;
  zone_observatory_t observatory;
  catalog_member_id_t *catalog_members;
  int catalog_member_count;
  bool is_catalog_member;
  bool is_secondary;
  char catalog_member_unique_id[256];
  char **groups;
  int group_count;
  char cached_master_ip[64];
  int cached_master_port;
  char cached_tsig_key_name[64];
  char owning_catalog_domain[256];
  _Atomic(time_t) last_successful_transfer;
  _Atomic(time_t) last_stale_log_time;
  time_t last_loaded_mtime;
} zone_db_entry_t;

void *calloc(size_t nmemb, size_t size) {
    static void *(*real_calloc)(size_t, size_t) = NULL;
    if (!real_calloc) {
        real_calloc = dlsym(RTLD_NEXT, "calloc");
    }

    size_t total = nmemb * size;
    if (total == sizeof(zone_db_entry_t)) {
        static int zone_calloc_count = 0;
        char *env_n = getenv("OOM_FAIL_NTH_ZONE_CALLOC");
        if (env_n) {
            int target_n = atoi(env_n);
            if (zone_calloc_count == target_n) {
                fprintf(stderr, "[LD_PRELOAD] Intercepted calloc for zone_db_entry_t (call #%d, size=%zu)! Simulating OOM.\n",
                        zone_calloc_count, total);
                zone_calloc_count++;
                return NULL;
            }
        }
        zone_calloc_count++;
    }

    return real_calloc(nmemb, size);
}

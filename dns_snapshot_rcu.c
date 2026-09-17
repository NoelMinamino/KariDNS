#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_snapshot_rcu.h"
#include "dns_server_internal.h"
#include "dns_catalog_zone.h"
#include "dns_edns_ecs.h"
#include "dns_axfr_ixfr.h"
#include "dns_zone_parser.h"
#include "dns_wire.h"
#include "dns_utils.h"
#include "dns_tsig_acl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

pthread_mutex_t g_zone_db_rebuild_lock = PTHREAD_MUTEX_INITIALIZER;

// Protected by g_zone_db_rebuild_lock
pending_coo_t *g_pending_coo = NULL;
int g_pending_coo_count = 0;
int g_pending_coo_capacity = 0;

static _Atomic(zone_db_snapshot_t *) g_zone_db_active = ATOMIC_VAR_INIT(NULL);

zone_db_snapshot_t *acquire_zone_snapshot(void) {
  return atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
}

void release_zone_snapshot(zone_db_snapshot_t *snap) {
  (void)snap;
}

zone_config_t *find_zone_config_in_view(server_config_t *cfg,
                                        const char *view_name,
                                        const char *domain) {
  if (!cfg || !domain) return NULL;
  if (cfg->views) {
    for (view_config_t *v = cfg->views; v; v = v->next) {
      if (view_name && view_name[0] != '\0' && strcasecmp(v->name, view_name) != 0) continue;
      for (zone_config_t *z = v->zones; z; z = z->next) {
        if (domain_names_match_ci(z->domain, domain)) return z;
      }
      if (view_name && view_name[0] != '\0') return NULL;
    }
  } else {
    for (zone_config_t *z = cfg->zones; z; z = z->next) {
      if (domain_names_match_ci(z->domain, domain)) return z;
    }
  }
  return NULL;
}

// domainに一致するゾーンを、view_nameが指定されていればそのview内だけを、
// NULLなら全view横断で検索する。戻り値は一致したview数(0/1/2以上)。
// 1件のみ一致した場合にresultへ結果を格納する。
int lookup_zone_across_views(zone_db_snapshot_t *snap, server_config_t *cfg,
                             const char *domain, const char *view_name,
                             zone_lookup_result_t *result) {
  int matches = 0;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    if (view_name && strcasecmp(v->name, view_name) != 0) continue;
    zone_config_t *zcfg = NULL;
    for (zone_config_t *z = v->zones; z; z = z->next) {
      if (domain_names_match_ci(z->domain, domain)) { zcfg = z; break; }
    }
    if (!zcfg) continue;

    zone_db_entry_t *entry = NULL;
    if (snap) {
      for (size_t sv = 0; sv < snap->view_count; sv++) {
        if (strcasecmp(snap->views[sv].name, v->name) != 0) continue;
        if (snap->views[sv].hash_size > 0 && snap->views[sv].hash_table) {
          uint32_t hash = calc_fnv1a_str(domain);
          size_t idx = hash & (snap->views[sv].hash_size - 1);
          for (int i = snap->views[sv].hash_table[idx]; i != -1; i = snap->views[sv].chain_next[i]) {
            if (domain_names_match_ci(snap->views[sv].entries[i]->domain, domain)) {
              entry = snap->views[sv].entries[i];
              break;
            }
          }
        }
        break;
      }
    }
    matches++;
    if (matches == 1) {
      result->entry = entry;
      result->zcfg = zcfg;
      result->view_name = v->name;
    }
  }
  return matches;
}

zone_db_entry_t *snapshot_get_zone(zone_db_snapshot_t *snap, const char *domain) {
  if (!snap) return NULL;
  for (size_t v = 0; v < snap->view_count; v++) {
    if (snap->views[v].hash_size > 0 && snap->views[v].hash_table) {
      uint32_t hash = calc_fnv1a_str(domain);
      size_t idx = hash & (snap->views[v].hash_size - 1);
      for (int i = snap->views[v].hash_table[idx]; i != -1; i = snap->views[v].chain_next[i]) {
        if (domain_names_match_ci(snap->views[v].entries[i]->domain, domain)) {
          return snap->views[v].entries[i];
        }
      }
    }
  }
  return NULL;
}

static inline uint32_t calc_fnv1a_strn(const char *str, size_t len) {
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = (uint8_t)str[i];
    if (c >= 'A' && c <= 'Z')
      c |= 0x20;
    hash ^= c;
    hash *= 16777619u;
  }
  return hash;
}

static zone_db_entry_t *view_suffix_hash_lookup(view_snapshot_t *view, const char *key, size_t key_len) {
  if (!view || !view->suffix_hash_table || !view->suffix_chain_next || view->suffix_hash_size == 0) {
    return NULL;
  }
  uint32_t hash = calc_fnv1a_strn(key, key_len);
  size_t idx = hash & (view->suffix_hash_size - 1);
  for (int i = view->suffix_hash_table[idx]; i != -1; i = view->suffix_chain_next[i]) {
    zone_db_entry_t *entry = view->entries[i];
    if (!entry) continue;
    size_t z_len = strlen(entry->domain);
    while (z_len > 0 && entry->domain[z_len - 1] == '.') z_len--;
    if (z_len == key_len && strncasecmp(entry->domain, key, key_len) == 0) {
      return entry;
    }
  }
  return NULL;
}

zone_db_entry_t *find_zone_in_view(view_snapshot_t *view, const char *qname) {
  if (!view || !qname) return NULL;
  if (!view->suffix_hash_table || !view->suffix_chain_next || view->suffix_hash_size == 0) {
    // Suffix hash table not built (e.g. manually constructed mock view in fuzzers/tests)
    // Fall back to linear scan
    size_t q_len = strlen(qname);
    while (q_len > 0 && qname[q_len - 1] == '.') q_len--;

    zone_db_entry_t *best_entry = NULL;
    size_t longest_match_len = 0;
    for (size_t i = 0; i < view->zone_count; i++) {
      zone_db_entry_t *entry = view->entries[i];
      if (!entry) continue;
      size_t z_len = strlen(entry->domain);
      while (z_len > 0 && entry->domain[z_len - 1] == '.') z_len--;

      bool match = false;
      if (z_len == 0 && (strcmp(entry->domain, ".") == 0 || entry->domain[0] == '\0')) {
        match = true;
      } else if (q_len == z_len && strncasecmp(qname, entry->domain, z_len) == 0) {
        match = true;
      } else if (q_len > z_len && qname[q_len - z_len - 1] == '.' &&
                 strncasecmp(qname + (q_len - z_len), entry->domain, z_len) == 0) {
        match = true;
      }
      if (match && (!best_entry || z_len > longest_match_len)) {
        longest_match_len = z_len;
        best_entry = entry;
      }
    }
    return best_entry;
  }

  size_t q_len = strlen(qname);
  while (q_len > 0 && qname[q_len - 1] == '.') q_len--;

  const char *cursor = qname;
  size_t remaining = q_len;
  while (remaining > 0) {
    zone_db_entry_t *hit = view_suffix_hash_lookup(view, cursor, remaining);
    if (hit) return hit;
    // 次のラベル境界まで進める（cursor内、remaining文字の範囲でドットを探す）
    const char *dot = memchr(cursor, '.', remaining);
    if (!dot) break;
    remaining -= (size_t)(dot - cursor) + 1;
    cursor = dot + 1;
  }
  // ルートゾーン（"." または空文字列）へのフォールバック
  return view_suffix_hash_lookup(view, "", 0);
}

zone_db_entry_t *create_new_zone_entry(const char *domain, const char *view_name) {
  zone_db_entry_t *z = calloc(1, sizeof(zone_db_entry_t));
  if (!z) return NULL;
  atomic_init(&z->active_axfr, 0);
  atomic_init(&z->snapshot_refs, 1);
  strncpy(z->domain, domain, sizeof(z->domain) - 1);
  z->domain[sizeof(z->domain) - 1] = 0;
  strncpy(z->view_name, view_name, sizeof(z->view_name) - 1);
  z->view_name[sizeof(z->view_name) - 1] = 0;
  pthread_mutex_init(&z->writer_lock, NULL);
  pthread_mutex_init(&z->ixfr_history.lock, NULL);
  z->ixfr_history.count = 0;
  z->ixfr_history.head = 0;
  zone_arena_init(&z->rcu.arena_a);
  zone_arena_init(&z->rcu.arena_b);
  atomic_init(&z->rcu.active, &z->rcu.arena_a);
  return z;
}

void wait_for_readers(zone_arena_t *arena) {
  (void)arena;
}

void free_zone_db_entry(zone_db_entry_t *entry) {
  if (!entry) return;
  if (entry->groups) {
    for (int i = 0; i < entry->group_count; i++) {
      free(entry->groups[i]);
    }
    free(entry->groups);
  }
  int axfr_retries = 0;
  useconds_t axfr_sleep = 1;
  while (atomic_load(&entry->active_axfr) > 0) {
    rcu_exponential_backoff(&axfr_retries, &axfr_sleep);
  }
  pthread_mutex_destroy(&entry->writer_lock);
  pthread_mutex_destroy(&entry->ixfr_history.lock);
  for (int idx = 0; idx < MAX_IXFR_HISTORY; idx++) {
    ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
    if (txn) {
      free_ixfr_txn(txn);
    }
  }
  zone_arena_destroy(&entry->rcu.arena_a);
  zone_arena_destroy(&entry->rcu.arena_b);
  free(entry);
}

void *gc_snapshot_thread(void *arg) {
  zone_db_snapshot_t *snap = (zone_db_snapshot_t *)arg;
  if (!snap) return NULL;
  rcu_writer_wait_until_safe(snap->retire_epoch, 60000);
  if (snap->views) {
    for (size_t v = 0; v < snap->view_count; v++) {
      if (snap->views[v].entries) {
        for (size_t i = 0; i < snap->views[v].zone_count; i++) {
          zone_db_entry_t *entry = snap->views[v].entries[i];
          if (entry) {
            if (atomic_fetch_sub_explicit(&entry->snapshot_refs, 1, memory_order_acq_rel) == 1) {
              syslog(LOG_INFO, "[GC] Freeing deleted zone '%s'", entry->domain);
              free_zone_db_entry(entry);
            }
          }
        }
        free(snap->views[v].entries);
      }
      if (snap->views[v].name) free(snap->views[v].name);
      if (snap->views[v].match_clients) {
        for (int i = 0; i < snap->views[v].match_clients_count; i++) {
          if (snap->views[v].match_clients[i]) free(snap->views[v].match_clients[i]);
        }
        free(snap->views[v].match_clients);
      }
      if (snap->views[v].match_clients_parsed) {
        free(snap->views[v].match_clients_parsed);
        snap->views[v].match_clients_parsed = NULL;
      }
      if (snap->views[v].hash_table) free(snap->views[v].hash_table);
      if (snap->views[v].chain_next) free(snap->views[v].chain_next);
      if (snap->views[v].suffix_hash_table) free(snap->views[v].suffix_hash_table);
      if (snap->views[v].suffix_chain_next) free(snap->views[v].suffix_chain_next);
    }
    free(snap->views);
  }
  free(snap);
  return NULL;
}

static char *server_load_file_cb(parse_context_t *ctx, const char *rel_path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
    int fd = open_via_dir_cache(rel_path, O_RDONLY | O_NOFOLLOW, 0, false);
    if (fd < 0) {
        return NULL;
    }
    
    if (out_dev || out_ino) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (out_dev) *out_dev = st.st_dev;
            if (out_ino) *out_ino = st.st_ino;
        } else {
            close(fd);
            return NULL; // fstat failed, fail-closed
        }
    }

    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0 || len > KARIDNS_MAX_CONFIG_FILE_SIZE) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read_len = fread(buf, 1, len, f);
    buf[read_len] = '\0';
    fclose(f);
    return buf;
}

#define MAX_PRELINK_TARGETS 256
#define MAX_MATCH_RECS 32

void prelink_zone_additional_glue(zone_arena_t *current_zone,
                                  const char *zone_domain,
                                  zone_db_snapshot_t *snap,
                                  view_snapshot_t *view,
                                  additional_from_auth_t policy) {
  if (!current_zone || current_zone->count == 0 || !zone_domain || policy == ADDITIONAL_AUTH_NO) {
    if (current_zone) {
      current_zone->prelinked_glue = NULL;
      current_zone->prelinked_glue_count = 0;
    }
    return;
  }

  if (snap && !view) {
    for (size_t v = 0; v < snap->view_count; v++) {
      for (size_t i = 0; i < snap->views[v].zone_count; i++) {
        if (snap->views[v].entries[i] &&
            domain_names_match_ci(snap->views[v].entries[i]->domain, zone_domain)) {
          view = &snap->views[v];
          break;
        }
      }
      if (view) break;
    }
    if (!view && snap->view_count > 0) {
      view = &snap->views[0];
    }
  }

  const char *raw_targets[MAX_PRELINK_TARGETS];
  int raw_target_count = 0;

  for (size_t i = 0; i < current_zone->count; i++) {
    dns_record_t *rec = &current_zone->records[i];
    const char *tgt = NULL;
    if (rec->type_code == 2 && rec->rdata_count >= 1) {
      tgt = rec->rdata[0];
    } else if (rec->type_code == 15 && rec->rdata_count >= 2) {
      tgt = rec->rdata[1];
    } else if (rec->type_code == 33 && rec->rdata_count >= 4) {
      tgt = rec->rdata[3];
    }
    if (!tgt || *tgt == '\0') continue;

    bool dup = false;
    for (int k = 0; k < raw_target_count; k++) {
      if (domain_names_match_ci(raw_targets[k], tgt)) {
        dup = true;
        break;
      }
    }
    if (!dup && raw_target_count < MAX_PRELINK_TARGETS) {
      raw_targets[raw_target_count++] = tgt;
    }
  }

  if (raw_target_count == 0) {
    current_zone->prelinked_glue = NULL;
    current_zone->prelinked_glue_count = 0;
    return;
  }

  prelinked_glue_entry_t entries[MAX_PRELINK_TARGETS];
  int entry_count = 0;

  size_t z_len = strlen(zone_domain);
  while (z_len > 0 && zone_domain[z_len - 1] == '.') z_len--;

  for (int t = 0; t < raw_target_count; t++) {
    const char *tgt = raw_targets[t];
    size_t t_len = strlen(tgt);
    while (t_len > 0 && tgt[t_len - 1] == '.') t_len--;

    bool in_domain = false;
    if (t_len >= z_len) {
      if (strncasecmp(tgt + (t_len - z_len), zone_domain, z_len) == 0) {
        if (t_len == z_len || tgt[t_len - z_len - 1] == '.') {
          in_domain = true;
        }
      }
    }

    if (policy == ADDITIONAL_AUTH_IN_DOMAIN && !in_domain) {
      continue;
    }

    dns_record_t *found_recs[MAX_MATCH_RECS];
    int found_count = 0;

    // 1. Search current_zone first
    if (current_zone->hash_size > 0 && current_zone->hash_table) {
      uint32_t hashes[2];
      int h_count = 1;
      hashes[0] = calc_fnv1a_str(tgt);
      char alt_tgt[256];
      size_t raw_len = strlen(tgt);
      if (raw_len > 0 && tgt[raw_len - 1] == '.') {
        snprintf(alt_tgt, sizeof(alt_tgt), "%.*s", (int)(raw_len - 1), tgt);
        hashes[1] = calc_fnv1a_str(alt_tgt);
        h_count = 2;
      } else if (raw_len > 0 && raw_len + 1 < sizeof(alt_tgt)) {
        snprintf(alt_tgt, sizeof(alt_tgt), "%s.", tgt);
        hashes[1] = calc_fnv1a_str(alt_tgt);
        h_count = 2;
      }

      for (int h = 0; h < h_count; h++) {
        size_t idx = hashes[h] & (current_zone->hash_size - 1);
        for (int j = current_zone->hash_table[idx]; j != -1;
             j = current_zone->records[j].next_record) {
          dns_record_t *r = &current_zone->records[j];
          if ((r->type_code == 1 || r->type_code == 28) &&
              domain_names_match_ci(r->name, tgt)) {
            bool rdup = false;
            for (int f = 0; f < found_count; f++) {
              if (found_recs[f] == r) { rdup = true; break; }
            }
            if (!rdup && found_count < MAX_MATCH_RECS) {
              found_recs[found_count++] = r;
            }
          }
        }
      }
    }

    // 2. Search sibling authoritative zones in view if policy == ADDITIONAL_AUTH_YES
    if (policy == ADDITIONAL_AUTH_YES && view) {
      zone_db_entry_t *sib_entry = find_zone_in_view(view, tgt);
      if (sib_entry) {
        zone_arena_t *sib_arena = atomic_load_explicit(&sib_entry->rcu.active, memory_order_acquire);
        if (sib_arena && sib_arena != current_zone && sib_arena->hash_size > 0 && sib_arena->hash_table) {
          uint32_t hashes[2];
          int h_count = 1;
          hashes[0] = calc_fnv1a_str(tgt);
          char alt_tgt[256];
          size_t raw_len = strlen(tgt);
          if (raw_len > 0 && tgt[raw_len - 1] == '.') {
            snprintf(alt_tgt, sizeof(alt_tgt), "%.*s", (int)(raw_len - 1), tgt);
            hashes[1] = calc_fnv1a_str(alt_tgt);
            h_count = 2;
          } else if (raw_len > 0 && raw_len + 1 < sizeof(alt_tgt)) {
            snprintf(alt_tgt, sizeof(alt_tgt), "%s.", tgt);
            hashes[1] = calc_fnv1a_str(alt_tgt);
            h_count = 2;
          }
          for (int h = 0; h < h_count; h++) {
            size_t idx = hashes[h] & (sib_arena->hash_size - 1);
            for (int j = sib_arena->hash_table[idx]; j != -1;
                 j = sib_arena->records[j].next_record) {
              dns_record_t *r = &sib_arena->records[j];
              if ((r->type_code == 1 || r->type_code == 28) &&
                  domain_names_match_ci(r->name, tgt)) {
                bool rdup = false;
                for (int f = 0; f < found_count; f++) {
                  if (found_recs[f]->type_code == r->type_code &&
                      found_recs[f]->rdata_count == r->rdata_count) {
                    bool match_all = true;
                    for (int rc = 0; rc < r->rdata_count; rc++) {
                      if (strcasecmp(found_recs[f]->rdata[rc], r->rdata[rc]) != 0) {
                        match_all = false; break;
                      }
                    }
                    if (match_all) { rdup = true; break; }
                  }
                }
                if (!rdup && found_count < MAX_MATCH_RECS) {
                  found_recs[found_count++] = r;
                }
              }
            }
          }
        }
      }
    }

    if (found_count > 0) {
      dns_record_t **copied_recs = (dns_record_t **)arena_alloc(current_zone, found_count * sizeof(dns_record_t *));
      if (!copied_recs) continue;

      int copied_count = 0;
      for (int f = 0; f < found_count; f++) {
        dns_record_t *src_rec = found_recs[f];
        dns_record_t *d_rec = (dns_record_t *)arena_alloc(current_zone, sizeof(dns_record_t));
        if (!d_rec) break;
        *d_rec = *src_rec;
        d_rec->name = arena_strdup(current_zone, src_rec->name);
        d_rec->ttl = src_rec->ttl ? arena_strdup(current_zone, src_rec->ttl) : NULL;
        d_rec->class_str = src_rec->class_str ? arena_strdup(current_zone, src_rec->class_str) : NULL;
        d_rec->type = src_rec->type ? arena_strdup(current_zone, src_rec->type) : NULL;
        d_rec->ecs_subnet_tag = src_rec->ecs_subnet_tag ? arena_strdup(current_zone, src_rec->ecs_subnet_tag) : NULL;
        d_rec->bind_location_tag = src_rec->bind_location_tag ? arena_strdup(current_zone, src_rec->bind_location_tag) : NULL;
        for (int r = 0; r < src_rec->rdata_count && r < MAX_RDATA; r++) {
          d_rec->rdata[r] = src_rec->rdata[r] ? arena_strdup(current_zone, src_rec->rdata[r]) : NULL;
        }
        if (src_rec->generic_len > 0 && src_rec->generic_data) {
          d_rec->generic_data = (uint8_t *)arena_alloc(current_zone, src_rec->generic_len);
          if (d_rec->generic_data)
            memcpy(d_rec->generic_data, src_rec->generic_data, src_rec->generic_len);
        } else if (src_rec->generic_data) {
          d_rec->generic_data = (uint8_t *)"";
        } else {
          d_rec->generic_data = NULL;
        }
        d_rec->next_record = -1;
        d_rec->is_cached = false;
        dns_record_preparse_cache(current_zone, d_rec);
        copied_recs[copied_count++] = d_rec;
      }

      if (copied_count > 0) {
        entries[entry_count].target_name = arena_strdup(current_zone, tgt);
        entries[entry_count].records = copied_recs;
        entries[entry_count].record_count = copied_count;
        entry_count++;
      }
    }
  }

  if (entry_count > 0) {
    current_zone->prelinked_glue = (prelinked_glue_entry_t *)arena_alloc(current_zone, entry_count * sizeof(prelinked_glue_entry_t));
    if (current_zone->prelinked_glue) {
      memcpy(current_zone->prelinked_glue, entries, entry_count * sizeof(prelinked_glue_entry_t));
      current_zone->prelinked_glue_count = entry_count;
    } else {
      current_zone->prelinked_glue_count = 0;
    }
  } else {
    current_zone->prelinked_glue = NULL;
    current_zone->prelinked_glue_count = 0;
  }
}

reload_result_t reload_master_zone(zone_db_entry_t *entry, zone_config_t *zcfg) {
  if (!entry || !zcfg || !zcfg->file) return RELOAD_ERR_FILE_READ;
  const char *file = zcfg->file;
  dev_t root_dev = 0;
  ino_t root_ino = 0;
  char *buf = read_entire_file(file, &root_dev, &root_ino);
  if (!buf) {
    syslog(LOG_ERR, "[Zone] Failed to read file '%s' for zone '%s'.", file, entry->domain);
    return RELOAD_ERR_FILE_READ;
  }
  pthread_mutex_lock(&entry->writer_lock);
  int axfr_wait_ms = 0;
  int backoff = 1;
  while (atomic_load_explicit(&entry->active_axfr, memory_order_acquire) > 0) {
    if (axfr_wait_ms >= 5000) {
      syslog(LOG_WARNING, "[Zone] Reload of zone '%s' postponed: active AXFR in progress (timeout 5s).", entry->domain);
      free(buf);
      pthread_mutex_unlock(&entry->writer_lock);
      return RELOAD_ERR_BUSY;
    }
    usleep(backoff * 1000);
    axfr_wait_ms += backoff;
    if (backoff < 50) backoff *= 2;
  }
  zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
  rcu_writer_wait_until_safe(entry->rcu.retire_epoch, 60000);

  zone_arena_free_include_buffers(z_standby);
  free(z_standby->locations);
  z_standby->locations = NULL;
  z_standby->location_count = 0;
  free_ecs_tags_array(z_standby->bind_location_tags, z_standby->bind_location_tag_count);
  z_standby->bind_location_tags = NULL;
  z_standby->bind_location_tag_count = 0;
  free_ecs_tags_array(z_standby->bind_ecs_tags, z_standby->bind_ecs_tag_count);
  z_standby->bind_ecs_tags = NULL;
  z_standby->bind_ecs_tag_count = 0;
  if (z_standby->bind_ecs_trusted_resolvers) {
    for (int i = 0; i < z_standby->bind_ecs_trusted_resolver_count; i++) {
      free(z_standby->bind_ecs_trusted_resolvers[i]);
    }
    free(z_standby->bind_ecs_trusted_resolvers);
    z_standby->bind_ecs_trusted_resolvers = NULL;
    z_standby->bind_ecs_trusted_resolver_count = 0;
  }
  if (z_standby->bind_ecs_trusted_resolvers_parsed) {
    free(z_standby->bind_ecs_trusted_resolvers_parsed);
    z_standby->bind_ecs_trusted_resolvers_parsed = NULL;
  }
  z_standby->count = 0;
  z_standby->data_pool_count = 0;
  z_standby->current_pool_cap = 0;
  z_standby->current_pool_idx = 0;
  z_standby->file_buf_count = 0;
  z_standby->file_bufs[z_standby->file_buf_count] = buf;
  z_standby->file_paths[z_standby->file_buf_count] = strdup(file);
  z_standby->file_buf_count++;

  char *root_ttl = NULL;
  char *root_ecs_tag = NULL;
  char *root_loc_tag = NULL;
  char *visited_paths[16];
  dev_t visited_devs[16];
  ino_t visited_inos[16];
  
  char abs_file[PATH_MAX];
  if (file[0] != '/' && g_startup_cwd[0] != '\0') {
      snprintf(abs_file, sizeof(abs_file), "%s/%s", g_startup_cwd, file);
  } else {
      snprintf(abs_file, sizeof(abs_file), "%s", file);
  }
  
  char *root_path = strdup(abs_file);

  parse_error_t parse_err = {0};
  parse_context_t ctx = {0};
  ctx.default_origin = entry->domain;
  ctx.base_dir = get_base_dir(root_path);
  if (!ctx.base_dir) {
      syslog(LOG_ERR, "[ZoneLoader] Out of memory allocating base_dir for zone '%s'", entry->domain);
      free(root_path);
      pthread_mutex_unlock(&entry->writer_lock);
      return RELOAD_ERR_PARSE;
  }
  ctx.is_standalone_mode = false;
  ctx.load_file_cb = server_load_file_cb;
  ctx.shared_ttl_io = &root_ttl;
  ctx.shared_ecs_tag_io = &root_ecs_tag;
  ctx.shared_loc_tag_io = &root_loc_tag;
  ctx.visited_paths = visited_paths;
  ctx.visited_devs = visited_devs;
  ctx.visited_inos = visited_inos;
  ctx.visited_cap = 16;
  ctx.visited_count = 1;
  ctx.visited_paths[0] = root_path;
  ctx.visited_devs[0] = root_dev;
  ctx.visited_inos[0] = root_ino;
  ctx.err_out = &parse_err;

  server_config_t *active_cfg = acquire_config_snapshot();
  const char *all_zone_ptrs[256];
  int all_zone_cnt = 0;
  if (active_cfg) {
      for (zone_config_t *zc = active_cfg->zones; zc; zc = zc->next) {
          if (zc->domain) {
              if (all_zone_cnt < 256) {
                  all_zone_ptrs[all_zone_cnt++] = zc->domain;
              } else {
                  syslog(LOG_WARNING, "[ZoneLoader] Configured zones exceed 256; parent-child delegation filtering may be degraded for '%s'", entry->domain);
                  break;
              }
          }
      }
  }
  ctx.all_zone_names = (all_zone_cnt > 0) ? all_zone_ptrs : NULL;
  ctx.all_zone_count = all_zone_cnt;

  int count;
  if (zcfg->file_format && strcasecmp(zcfg->file_format, "tinydns") == 0) {
      count = parse_tinydns_data(buf, strlen(buf), z_standby, &ctx);
  } else {
      count = parse_zone_fast(buf, strlen(buf), z_standby, &ctx);
  }
  release_config_snapshot(active_cfg);
  free((void*)ctx.base_dir);
  free(root_path);

  if (count < 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      if (parse_err.error_message) {
          syslog(LOG_ERR, "[Zone] Parse error reloading zone '%s' from '%s': %s (offset=%zu, file=%s)",
                 entry->domain, file, parse_err.error_message,
                 parse_err.error_offset,
                 parse_err.file_path ? parse_err.file_path : file);
      } else {
          syslog(LOG_ERR, "[Zone] Parse error reloading zone '%s' from '%s'", entry->domain, file);
      }
      return RELOAD_ERR_PARSE;
  }

  if (build_zone_index(z_standby, true) != 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after reload for '%s'", entry->domain);
      return RELOAD_ERR_PARSE;
  }
  if (validate_zone_dname(z_standby, &parse_err) < 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] DNAME validation error reloading zone '%s' from '%s': %s",
             entry->domain, file, parse_err.error_message);
      return RELOAD_ERR_PARSE;
  }
  if (validate_zone_name_lengths(z_standby, &parse_err) < 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Name length validation error reloading zone '%s' from '%s': %s",
             entry->domain, file, parse_err.error_message);
      return RELOAD_ERR_PARSE;
  }
  bool has_soa = false;
  uint32_t hash = calc_fnv1a_str(entry->domain);
  size_t idx = hash & (z_standby->hash_size - 1);
  for (int i = z_standby->hash_table[idx]; i != -1; i = z_standby->records[i].next_record) {
      if (z_standby->records[i].type_code == 6 && domain_names_match_ci(z_standby->records[i].name, entry->domain)) {
          has_soa = true;
          if (z_standby->records[i].rdata_count >= 7) {
              entry->serial = strtoul(z_standby->records[i].rdata[2], NULL, 10);
              entry->refresh = parse_ttl_value(z_standby->records[i].rdata[3]);
              entry->retry = parse_ttl_value(z_standby->records[i].rdata[4]);
              entry->expire = parse_ttl_value(z_standby->records[i].rdata[5]);
          }
          break;
      }
  }
  if (!has_soa) {
      size_t elen = strlen(entry->domain);
      if (elen > 0 && entry->domain[elen - 1] != '.' && elen + 2 < 256) {
          char dot_domain[256];
          memcpy(dot_domain, entry->domain, elen);
          dot_domain[elen] = '.';
          dot_domain[elen + 1] = '\0';
          uint32_t dot_hash = calc_fnv1a_str(dot_domain);
          size_t dot_idx = dot_hash & (z_standby->hash_size - 1);
          for (int i = z_standby->hash_table[dot_idx]; i != -1; i = z_standby->records[i].next_record) {
              if (z_standby->records[i].type_code == 6 && domain_names_match_ci(z_standby->records[i].name, entry->domain)) {
                  has_soa = true;
                  if (z_standby->records[i].rdata_count >= 7) {
                      entry->serial = strtoul(z_standby->records[i].rdata[2], NULL, 10);
                      entry->refresh = parse_ttl_value(z_standby->records[i].rdata[3]);
                      entry->retry = parse_ttl_value(z_standby->records[i].rdata[4]);
                      entry->expire = parse_ttl_value(z_standby->records[i].rdata[5]);
                  }
                  break;
              }
          }
      }
  }
  if (!has_soa) {
      for (size_t i = 0; i < z_standby->count; i++) {
          if (z_standby->records[i].type_code == 6 && domain_names_match_ci(z_standby->records[i].name, entry->domain)) {
              has_soa = true;
              if (z_standby->records[i].rdata_count >= 7) {
                  entry->serial = strtoul(z_standby->records[i].rdata[2], NULL, 10);
                  entry->refresh = parse_ttl_value(z_standby->records[i].rdata[3]);
                  entry->retry = parse_ttl_value(z_standby->records[i].rdata[4]);
                  entry->expire = parse_ttl_value(z_standby->records[i].rdata[5]);
              }
              break;
          }
      }
  }
  if (!has_soa) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Missing SOA reloading zone '%s' from '%s'", entry->domain, file);
      return RELOAD_ERR_MISSING_SOA;
  }

  zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
  server_config_t *active_cfg_prelink = acquire_config_snapshot();
  additional_from_auth_t policy = (zcfg && zcfg->additional_from_auth_specified)
                                      ? zcfg->additional_from_auth
                                      : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
  prelink_zone_additional_glue(z_standby, entry->domain, cur_snap, NULL, policy);
  build_zone_response_cache(z_standby, active_cfg_prelink, entry->domain);
  release_config_snapshot(active_cfg_prelink);
  if (cur_snap) release_zone_snapshot(cur_snap);

  compute_ixfr_diff(entry, z_active, z_standby);
  entry->rcu.retire_epoch = rcu_writer_advance_epoch();
  atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
  struct stat st_loaded;
  if (stat_via_dir_cache(file, &st_loaded) == 0) {
    entry->last_loaded_mtime = st_loaded.st_mtime;
    if (entry->is_secondary) {
      atomic_store_explicit(&entry->last_successful_transfer, (time_t)st_loaded.st_mtime, memory_order_release);
    }
  }
  pthread_mutex_unlock(&entry->writer_lock);
  syslog(LOG_NOTICE, "[Zone] Reload successful for '%s'", entry->domain);
  return RELOAD_OK;
}

static void abort_rebuild_snapshot(zone_db_snapshot_t *new_snap, const char *reason) {
    syslog(LOG_ERR, "[Core] Memory allocation failed during snapshot rebuild (%s), aborting", reason);
    if (new_snap) {
        gc_snapshot_thread(new_snap);
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
}

zone_db_snapshot_t *rebuild_zone_db_snapshot(
    server_config_t *active_config, 
    const char *catalog_view_name,
    zone_db_entry_t *catalog_entry_to_update,
    zone_config_t *catalog_cfg,
    catalog_member_id_t *new_desired_members, int new_desired_count) 
{
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    zone_db_snapshot_t *old_snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    zone_db_snapshot_t *new_snap = calloc(1, sizeof(zone_db_snapshot_t));
    if (!new_snap) {
        abort_rebuild_snapshot(NULL, "new_snap");
        return NULL;
    }
    
    if (active_config) {
        // MODE: Full Config Reload
        
        int max_valid_members = 0;
        if (old_snap) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = old_snap->views[v].entries[i];
                    if (!entry) continue;
                    if (entry->catalog_member_count > 0) {
                        max_valid_members += entry->catalog_member_count;
                    }
                }
            }
        }
        catalog_member_id_t *valid_members = max_valid_members > 0 ? calloc(max_valid_members, sizeof(catalog_member_id_t)) : NULL;
        if (max_valid_members > 0 && !valid_members) {
            abort_rebuild_snapshot(new_snap, "valid_members");
            return NULL;
        }
        int valid_member_count = 0;
        
        if (old_snap) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = old_snap->views[v].entries[i];
                    if (!entry) continue;
                    if (entry->catalog_member_count > 0) {
                        zone_config_t *zcfg = find_zone_config_in_view(active_config, entry->view_name, entry->domain);
                        if (zcfg && zcfg->is_catalog) {
                            for (int k = 0; k < entry->catalog_member_count; k++) {
                                valid_members[valid_member_count++] = entry->catalog_members[k];
                            }
                        } else {
                            free_catalog_member_ids(entry->catalog_members, entry->catalog_member_count);
                            entry->catalog_members = NULL;
                            entry->catalog_member_count = 0;
                            
                            int p = 0;
                            while (p < g_pending_coo_count) {
                                if (strcasecmp(g_pending_coo[p].old_catalog, entry->domain) == 0) {
                                    if (p < g_pending_coo_count - 1) {
                                        g_pending_coo[p] = g_pending_coo[g_pending_coo_count - 1];
                                    }
                                    g_pending_coo_count--;
                                } else {
                                    p++;
                                }
                            }
                        }
                    }
                }
            }
        }

        int view_count = 0;
        for (view_config_t *v = active_config->views; v; v = v->next) view_count++;
        
        new_snap->view_count = view_count;
        if (view_count > 0) {
            new_snap->views = calloc(view_count, sizeof(view_snapshot_t));
            if (!new_snap->views) {
                if (valid_members) free(valid_members);
                abort_rebuild_snapshot(new_snap, "new_snap->views");
                return NULL;
            }
        }
        atomic_init(&new_snap->reader_count, 0);

        int vidx = 0;
        for (view_config_t *v = active_config->views; v; v = v->next, vidx++) {
            view_snapshot_t *vs = &new_snap->views[vidx];
            vs->name = strdup(v->name);
            vs->match_clients_count = v->match_clients_count;
            if (v->match_clients_count > 0) {
                vs->match_clients = calloc(v->match_clients_count, sizeof(char *));
                if (!vs->match_clients) {
                    if (valid_members) free(valid_members);
                    abort_rebuild_snapshot(new_snap, "vs->match_clients");
                    return NULL;
                }
                for (int i = 0; i < v->match_clients_count; i++) {
                    vs->match_clients[i] = strdup(v->match_clients[i]);
                }
                vs->match_clients_parsed = acl_list_parse(vs->match_clients, vs->match_clients_count);
            } else {
                vs->match_clients = NULL;
                vs->match_clients_parsed = NULL;
            }

            int static_count = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) static_count++;
            
            int dynamic_count = 0;
            if (old_snap) {
                for (size_t ov = 0; ov < old_snap->view_count; ov++) {
                    if (strcasecmp(old_snap->views[ov].name, v->name) == 0) {
                        for (size_t oi = 0; oi < old_snap->views[ov].zone_count; oi++) {
                            zone_db_entry_t *entry = old_snap->views[ov].entries[oi];
                            if (!entry) continue;
                            if (entry->is_catalog_member) {
                                bool is_valid = false;
                                for (int k = 0; k < valid_member_count; k++) {
                                    if (strcasecmp(valid_members[k].domain, entry->domain) == 0 &&
                                        strcmp(valid_members[k].unique_id, entry->catalog_member_unique_id) == 0) {
                                        is_valid = true; break;
                                    }
                                }
                                if (is_valid) {
                                    bool overridden = false;
                                    for (zone_config_t *z = v->zones; z; z = z->next) {
                                        if (strcasecmp(z->domain, entry->domain) == 0) {
                                             overridden = true; break;
                                        }
                                    }
                                    if (!overridden) dynamic_count++;
                                }
                            }
                        }
                        break;
                    }
                }
            }

            vs->zone_count = static_count + dynamic_count;
            if (vs->zone_count > 0) {
                vs->entries = calloc(vs->zone_count, sizeof(zone_db_entry_t *));
                if (!vs->entries) {
                    if (valid_members) free(valid_members);
                    abort_rebuild_snapshot(new_snap, "vs->entries");
                    return NULL;
                }
            }
            
            int zidx = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) {
                zone_db_entry_t *entry = NULL;
                if (old_snap) {
                    for (size_t ov = 0; ov < old_snap->view_count; ov++) {
                        if (strcasecmp(old_snap->views[ov].name, v->name) == 0) {
                            for (size_t oi = 0; oi < old_snap->views[ov].zone_count; oi++) {
                                if (!old_snap->views[ov].entries[oi]) continue;
                                if (strcasecmp(old_snap->views[ov].entries[oi]->domain, z->domain) == 0) {
                                    entry = old_snap->views[ov].entries[oi];
                                    atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
                if (!entry) {
                    entry = create_new_zone_entry(z->domain, v->name);
                    if (entry && z->type && (strcasecmp(z->type, "slave") == 0 || strcasecmp(z->type, "secondary") == 0)) {
                        entry->is_secondary = true;
                    }
                    if (entry && z->file) {
                        reload_master_zone(entry, z);
                    }
                }
                if (!entry) {
                    syslog(LOG_ERR, "[Core] Failed to allocate memory for zone '%s' in view '%s', skipping this zone this reload cycle",
                           z->domain, v->name);
                    continue;
                }
                vs->entries[zidx++] = entry;
            }

            if (old_snap) {
                for (size_t ov = 0; ov < old_snap->view_count; ov++) {
                    if (strcasecmp(old_snap->views[ov].name, v->name) == 0) {
                        for (size_t oi = 0; oi < old_snap->views[ov].zone_count; oi++) {
                            zone_db_entry_t *entry = old_snap->views[ov].entries[oi];
                            if (!entry) continue;
                            if (entry->is_catalog_member) {
                                bool is_valid = false;
                                for (int k = 0; k < valid_member_count; k++) {
                                    if (strcasecmp(valid_members[k].domain, entry->domain) == 0 &&
                                        strcmp(valid_members[k].unique_id, entry->catalog_member_unique_id) == 0) {
                                        is_valid = true; break;
                                    }
                                }
                                if (is_valid) {
                                    bool overridden = false;
                                    for (zone_config_t *z = v->zones; z; z = z->next) {
                                        if (strcasecmp(z->domain, entry->domain) == 0) {
                                            overridden = true; break;
                                        }
                                    }
                                    if (!overridden) {
                                        atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                                        vs->entries[zidx++] = entry;
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
            vs->zone_count = zidx;
        }
        if (valid_members) free(valid_members);

    } else {
        // MODE: Catalog Delta Update
        
        // Step A: Update Pending CoO Intentions (acting as $OLDCATZ)
        if (catalog_entry_to_update) {
            int p = 0;
            while (p < g_pending_coo_count) {
                if (strcasecmp(g_pending_coo[p].old_catalog, catalog_entry_to_update->domain) == 0) {
                    if (p < g_pending_coo_count - 1) {
                        g_pending_coo[p] = g_pending_coo[g_pending_coo_count - 1];
                    }
                    g_pending_coo_count--;
                } else {
                    p++;
                }
            }
            for (int i = 0; i < new_desired_count; i++) {
                if (strlen(new_desired_members[i].coo_target) > 0) {
                    if (g_pending_coo_count >= g_pending_coo_capacity) {
                        size_t old_cap = g_pending_coo_capacity;
                        size_t new_cap = old_cap == 0 ? 16 : old_cap * 2;
                        pending_coo_t *tmp = realloc(g_pending_coo, new_cap * sizeof(pending_coo_t));
                        if (!tmp) {
                            syslog(LOG_ERR, "[Catalog] Failed to allocate memory for g_pending_coo (domain=%s); skipping CoO tracking for this member", new_desired_members[i].domain);
                            continue;
                        }
                        g_pending_coo = tmp;
                        g_pending_coo_capacity = new_cap;
                        memset(&g_pending_coo[old_cap], 0, (new_cap - old_cap) * sizeof(pending_coo_t));
                    }
                    snprintf(g_pending_coo[g_pending_coo_count].domain, sizeof(g_pending_coo[0].domain), "%s", new_desired_members[i].domain);
                    snprintf(g_pending_coo[g_pending_coo_count].old_catalog, sizeof(g_pending_coo[0].old_catalog), "%s", catalog_entry_to_update->domain);
                    snprintf(g_pending_coo[g_pending_coo_count].new_catalog, sizeof(g_pending_coo[0].new_catalog), "%s", new_desired_members[i].coo_target);
                    g_pending_coo_count++;
                }
            }
        }

        int added_count = 0;
        int removed_count = 0;
        catalog_member_id_t *added_members = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(catalog_member_id_t));
        catalog_member_id_t *removed_members = calloc(catalog_entry_to_update->catalog_member_count > 0 ? catalog_entry_to_update->catalog_member_count : 1, sizeof(catalog_member_id_t));
        catalog_member_id_t *coo_evicted_members = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(catalog_member_id_t));
        int coo_evicted_count = 0;

        int filtered_count = 0;
        view_snapshot_t *target_view = NULL;
        if (old_snap) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                if (strcasecmp(old_snap->views[v].name, catalog_view_name) == 0) {
                    target_view = &old_snap->views[v];
                    break;
                }
            }
        }

        // Ephemeral hash table for catalog_entry_to_update->catalog_members
        int *cur_hash_table = NULL;
        int *cur_chain_next = NULL;
        size_t cur_hash_size = 0;
        int cur_count = catalog_entry_to_update->catalog_member_count;
        if (cur_count > 0 && catalog_entry_to_update->catalog_members) {
            size_t p = 256;
            while (p < (size_t)cur_count * 2) p <<= 1;
            cur_hash_size = p;
            cur_hash_table = malloc(cur_hash_size * sizeof(int));
            cur_chain_next = malloc(cur_count * sizeof(int));
            if (cur_hash_table && cur_chain_next) {
                for (size_t k = 0; k < cur_hash_size; k++) cur_hash_table[k] = -1;
                for (int j = 0; j < cur_count; j++) {
                    uint32_t h = calc_catalog_member_hash(catalog_entry_to_update->catalog_members[j].domain,
                                                          catalog_entry_to_update->catalog_members[j].unique_id);
                    size_t idx = h & (cur_hash_size - 1);
                    cur_chain_next[j] = cur_hash_table[idx];
                    cur_hash_table[idx] = j;
                }
            } else {
                if (cur_hash_table) { free(cur_hash_table); cur_hash_table = NULL; }
                if (cur_chain_next) { free(cur_chain_next); cur_chain_next = NULL; }
                cur_hash_size = 0;
            }
        }

        for (int i = 0; i < new_desired_count; i++) {
            bool found = false;
            if (cur_hash_table && cur_chain_next) {
                uint32_t h = calc_catalog_member_hash(new_desired_members[i].domain, new_desired_members[i].unique_id);
                size_t idx = h & (cur_hash_size - 1);
                for (int j = cur_hash_table[idx]; j != -1; j = cur_chain_next[j]) {
                    if (strcasecmp(new_desired_members[i].domain, catalog_entry_to_update->catalog_members[j].domain) == 0 &&
                        strcmp(new_desired_members[i].unique_id, catalog_entry_to_update->catalog_members[j].unique_id) == 0) {
                        bool groups_match = (new_desired_members[i].group_count == catalog_entry_to_update->catalog_members[j].group_count);
                        if (groups_match) {
                            for (int k = 0; k < new_desired_members[i].group_count; k++) {
                                if (strcmp(new_desired_members[i].groups[k], catalog_entry_to_update->catalog_members[j].groups[k]) != 0) {
                                    groups_match = false; break;
                                }
                            }
                        }
                        if (groups_match) {
                            found = true; break;
                        }
                    }
                }
            } else {
                for (int j = 0; j < catalog_entry_to_update->catalog_member_count; j++) {
                    if (strcasecmp(new_desired_members[i].domain, catalog_entry_to_update->catalog_members[j].domain) == 0 &&
                        strcmp(new_desired_members[i].unique_id, catalog_entry_to_update->catalog_members[j].unique_id) == 0) {
                        bool groups_match = (new_desired_members[i].group_count == catalog_entry_to_update->catalog_members[j].group_count);
                        if (groups_match) {
                            for (int k = 0; k < new_desired_members[i].group_count; k++) {
                                if (strcmp(new_desired_members[i].groups[k], catalog_entry_to_update->catalog_members[j].groups[k]) != 0) {
                                    groups_match = false; break;
                                }
                            }
                        }
                        if (groups_match) {
                            found = true; break;
                        }
                    }
                }
            }
            
            bool member_accepted = true;
            bool needs_creation = true;

            if (!found) {
                if (target_view) {
                    zone_db_entry_t *existing = find_catalog_parent_in_snapshot(target_view, new_desired_members[i].domain);
                    if (existing && existing->is_catalog_member) {
                        if (strcasecmp(existing->owning_catalog_domain, catalog_entry_to_update->domain) != 0) {
                            bool valid_coo = false;
                            for (int p = 0; p < g_pending_coo_count; p++) {
                                if (strcasecmp(g_pending_coo[p].domain, new_desired_members[i].domain) == 0 &&
                                    strcasecmp(g_pending_coo[p].old_catalog, existing->owning_catalog_domain) == 0 &&
                                    strcasecmp(g_pending_coo[p].new_catalog, catalog_entry_to_update->domain) == 0) {
                                    valid_coo = true; break;
                                }
                            }
                            if (valid_coo) {
                                zone_db_entry_t *old_catalog_entry = find_catalog_parent_in_snapshot(target_view, existing->owning_catalog_domain);
                                if (old_catalog_entry) {
                                    remove_member_from_catalog_bookkeeping(old_catalog_entry, existing->catalog_member_unique_id, new_desired_members[i].domain);
                                }
                                if (strcmp(existing->catalog_member_unique_id, new_desired_members[i].unique_id) == 0) {
                                    // Retain state
                                    syslog(LOG_INFO, "[Catalog] CoO transfer: retained state for '%s' (unique-id: %s), owner %s -> %s",
                                           existing->domain, existing->catalog_member_unique_id, existing->owning_catalog_domain, catalog_entry_to_update->domain);
                                    strncpy(existing->owning_catalog_domain, catalog_entry_to_update->domain, sizeof(existing->owning_catalog_domain) - 1);
                                    
                                    // Deep copy new groups in-place
                                    if (existing->groups) {
                                        for (int g = 0; g < existing->group_count; g++) {
                                            free(existing->groups[g]);
                                        }
                                        free(existing->groups);
                                        existing->groups = NULL;
                                    }
                                    existing->group_count = new_desired_members[i].group_count;
                                    if (existing->group_count > 0) {
                                        existing->groups = calloc(existing->group_count, sizeof(char*));
                                        for (int g = 0; g < existing->group_count; g++) {
                                            existing->groups[g] = strdup(new_desired_members[i].groups[g]);
                                        }
                                    }
                                    needs_creation = false;
                                } else {
                                    // State reset
                                    syslog(LOG_INFO, "[Catalog] CoO transfer: evicted old state for '%s' (old unique-id: %s, new unique-id: %s)",
                                           existing->domain, existing->catalog_member_unique_id, new_desired_members[i].unique_id);
                                    strncpy(coo_evicted_members[coo_evicted_count].unique_id, existing->catalog_member_unique_id, sizeof(coo_evicted_members[coo_evicted_count].unique_id) - 1);
                                    strncpy(coo_evicted_members[coo_evicted_count].domain, existing->domain, sizeof(coo_evicted_members[coo_evicted_count].domain) - 1);
                                    coo_evicted_count++;
                                }
                            } else {
                                syslog(LOG_WARNING, "[Catalog] Name collision for '%s' between '%s' and '%s'. Ignoring.", 
                                       new_desired_members[i].domain, existing->owning_catalog_domain, catalog_entry_to_update->domain);
                                member_accepted = false;
                            }
                        }
                    }
                }
            } else {
                needs_creation = false; // Already existed exactly in our catalog
            }

            if (member_accepted) {
                if (filtered_count != i) {
                    new_desired_members[filtered_count] = new_desired_members[i];
                }
                filtered_count++;
                if (needs_creation) {
                    added_members[added_count++] = new_desired_members[i];
                }
            } else {
                if (new_desired_members[i].groups) {
                    for (int g = 0; g < new_desired_members[i].group_count; g++) {
                        free(new_desired_members[i].groups[g]);
                    }
                    free(new_desired_members[i].groups);
                }
            }
        }
        if (cur_hash_table) free(cur_hash_table);
        if (cur_chain_next) free(cur_chain_next);
        new_desired_count = filtered_count;

        // Ephemeral hash table for new_desired_members
        int *des_hash_table = NULL;
        int *des_chain_next = NULL;
        size_t des_hash_size = 0;
        if (new_desired_count > 0) {
            size_t p = 256;
            while (p < (size_t)new_desired_count * 2) p <<= 1;
            des_hash_size = p;
            des_hash_table = malloc(des_hash_size * sizeof(int));
            des_chain_next = malloc(new_desired_count * sizeof(int));
            if (des_hash_table && des_chain_next) {
                for (size_t k = 0; k < des_hash_size; k++) des_hash_table[k] = -1;
                for (int j = 0; j < new_desired_count; j++) {
                    uint32_t h = calc_catalog_member_hash(new_desired_members[j].domain, new_desired_members[j].unique_id);
                    size_t idx = h & (des_hash_size - 1);
                    des_chain_next[j] = des_hash_table[idx];
                    des_hash_table[idx] = j;
                }
            } else {
                if (des_hash_table) { free(des_hash_table); des_hash_table = NULL; }
                if (des_chain_next) { free(des_chain_next); des_chain_next = NULL; }
                des_hash_size = 0;
            }
        }

        for (int i = 0; i < catalog_entry_to_update->catalog_member_count; i++) {
            bool found = false;
            if (des_hash_table && des_chain_next) {
                uint32_t h = calc_catalog_member_hash(catalog_entry_to_update->catalog_members[i].domain,
                                                      catalog_entry_to_update->catalog_members[i].unique_id);
                size_t idx = h & (des_hash_size - 1);
                for (int j = des_hash_table[idx]; j != -1; j = des_chain_next[j]) {
                    if (strcasecmp(catalog_entry_to_update->catalog_members[i].domain, new_desired_members[j].domain) == 0 &&
                        strcmp(catalog_entry_to_update->catalog_members[i].unique_id, new_desired_members[j].unique_id) == 0) {
                        bool groups_match = (catalog_entry_to_update->catalog_members[i].group_count == new_desired_members[j].group_count);
                        if (groups_match) {
                            for (int k = 0; k < new_desired_members[i].group_count; k++) {
                                if (strcmp(new_desired_members[i].groups[k], catalog_entry_to_update->catalog_members[j].groups[k]) != 0) {
                                    groups_match = false; break;
                                }
                            }
                        }
                        if (groups_match) {
                            found = true; break;
                        }
                    }
                }
            } else {
                for (int j = 0; j < new_desired_count; j++) {
                    if (strcasecmp(catalog_entry_to_update->catalog_members[i].domain, new_desired_members[j].domain) == 0 &&
                        strcmp(catalog_entry_to_update->catalog_members[i].unique_id, new_desired_members[j].unique_id) == 0) {
                        bool groups_match = (catalog_entry_to_update->catalog_members[i].group_count == new_desired_members[j].group_count);
                        if (groups_match) {
                            for (int k = 0; k < new_desired_members[i].group_count; k++) {
                                if (strcmp(catalog_entry_to_update->catalog_members[i].groups[k], new_desired_members[j].groups[k]) != 0) {
                                    groups_match = false; break;
                                }
                            }
                        }
                        if (groups_match) {
                            found = true; break;
                        }
                    }
                }
            }
            if (!found) {
                removed_members[removed_count++] = catalog_entry_to_update->catalog_members[i];
            }
        }
        if (des_hash_table) free(des_hash_table);
        if (des_chain_next) free(des_chain_next);

        zone_db_entry_t **new_entries = calloc(added_count > 0 ? added_count : 1, sizeof(zone_db_entry_t*));
        if (!new_entries) {
            free(added_members); free(removed_members); free(coo_evicted_members);
            abort_rebuild_snapshot(new_snap, "catalog new_entries");
            return NULL;
        }
        int actual_added_count = 0;
        for (int i = 0; i < added_count; i++) {
            zone_db_entry_t *entry = create_new_zone_entry(added_members[i].domain, catalog_view_name);
            if (!entry) {
                syslog(LOG_ERR, "[Catalog] Failed to allocate memory for member '%s' owned by %s, skipping",
                       added_members[i].domain, catalog_entry_to_update->domain);
                continue;
            }
            strncpy(entry->owning_catalog_domain, catalog_entry_to_update->domain, sizeof(entry->owning_catalog_domain) - 1);
            syslog(LOG_INFO, "[Catalog] Added new member '%s' (unique-id: %s) owned by %s", added_members[i].domain, added_members[i].unique_id, catalog_entry_to_update->domain);
            entry->is_catalog_member = true;
            entry->is_secondary = true;
            strncpy(entry->catalog_member_unique_id, added_members[i].unique_id, sizeof(entry->catalog_member_unique_id) - 1);
            if (added_members[i].group_count > 0) {
                entry->groups = calloc(added_members[i].group_count, sizeof(char*));
                entry->group_count = added_members[i].group_count;
                for (int g = 0; g < added_members[i].group_count; g++) {
                    entry->groups[g] = strdup(added_members[i].groups[g]);
                }
            }
            if (catalog_cfg->masters_count > 0 && catalog_cfg->masters[0].ip != NULL) {
                strncpy(entry->cached_master_ip, catalog_cfg->masters[0].ip, sizeof(entry->cached_master_ip) - 1);
                entry->cached_master_port = catalog_cfg->masters[0].port;
            }
            if (catalog_cfg->tsig_key) {
                strncpy(entry->cached_tsig_key_name, catalog_cfg->tsig_key, sizeof(entry->cached_tsig_key_name) - 1);
            }
            atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
            new_entries[actual_added_count++] = entry;
        }
        added_count = actual_added_count;

        new_snap->view_count = old_snap ? old_snap->view_count : 0;
        if (new_snap->view_count > 0) {
            new_snap->views = calloc(new_snap->view_count, sizeof(view_snapshot_t));
            if (!new_snap->views) {
                free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                abort_rebuild_snapshot(new_snap, "catalog new_snap->views");
                return NULL;
            }
            atomic_init(&new_snap->reader_count, 0);

            // Build ephemeral hash table for deleted members (removed + coo_evicted)
            int total_deleted = removed_count + coo_evicted_count;
            int *del_hash_table = NULL;
            int *del_chain_next = NULL;
            size_t del_hash_size = 0;
            if (total_deleted > 0) {
                size_t p = 256;
                while (p < (size_t)total_deleted * 2) p <<= 1;
                del_hash_size = p;
                del_hash_table = malloc(del_hash_size * sizeof(int));
                del_chain_next = malloc(total_deleted * sizeof(int));
                if (del_hash_table && del_chain_next) {
                    for (size_t k = 0; k < del_hash_size; k++) del_hash_table[k] = -1;
                    for (int j = 0; j < total_deleted; j++) {
                        const catalog_member_id_t *del = (j < removed_count) ? 
                            &removed_members[j] : &coo_evicted_members[j - removed_count];
                        uint32_t h = calc_catalog_member_hash(del->domain, del->unique_id);
                        size_t idx = h & (del_hash_size - 1);
                        del_chain_next[j] = del_hash_table[idx];
                        del_hash_table[idx] = j;
                    }
                } else {
                    if (del_hash_table) { free(del_hash_table); del_hash_table = NULL; }
                    if (del_chain_next) { free(del_chain_next); del_chain_next = NULL; }
                    del_hash_size = 0;
                }
            }

            for (size_t v = 0; v < old_snap->view_count; v++) {
                view_snapshot_t *vs = &new_snap->views[v];
                vs->name = strdup(old_snap->views[v].name);
                vs->match_clients_count = old_snap->views[v].match_clients_count;
                if (vs->match_clients_count > 0) {
                    vs->match_clients = calloc(vs->match_clients_count, sizeof(char *));
                    if (!vs->match_clients) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog vs->match_clients");
                        return NULL;
                    }
                    for (int i = 0; i < vs->match_clients_count; i++) {
                        vs->match_clients[i] = strdup(old_snap->views[v].match_clients[i]);
                    }
                    vs->match_clients_parsed = acl_list_parse(vs->match_clients, vs->match_clients_count);
                } else {
                    vs->match_clients = NULL;
                    vs->match_clients_parsed = NULL;
                }

                if (strcasecmp(vs->name, catalog_view_name) == 0) {
                    size_t max_zones = old_snap->views[v].zone_count + added_count;
                    vs->entries = calloc(max_zones > 0 ? max_zones : 1, sizeof(zone_db_entry_t *));
                    if (!vs->entries) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog vs->entries");
                        return NULL;
                    }
                    
                    int zidx = 0;
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        zone_db_entry_t *entry = old_snap->views[v].entries[i];
                        bool is_removed = false;
                        if (entry->is_catalog_member && del_hash_table && del_chain_next) {
                            uint32_t h = calc_catalog_member_hash(entry->domain, entry->catalog_member_unique_id);
                            size_t idx = h & (del_hash_size - 1);
                            for (int j = del_hash_table[idx]; j != -1; j = del_chain_next[j]) {
                                const catalog_member_id_t *del = (j < removed_count) ? 
                                    &removed_members[j] : &coo_evicted_members[j - removed_count];
                                if (strcasecmp(entry->domain, del->domain) == 0 &&
                                    strcmp(entry->catalog_member_unique_id, del->unique_id) == 0) {
                                    is_removed = true;
                                    break;
                                }
                            }
                        } else if (entry->is_catalog_member && total_deleted > 0) {
                            for (int j = 0; j < removed_count; j++) {
                                if (strcasecmp(entry->domain, removed_members[j].domain) == 0 &&
                                    strcmp(entry->catalog_member_unique_id, removed_members[j].unique_id) == 0) {
                                    is_removed = true; break;
                                }
                            }
                            if (!is_removed) {
                                for (int j = 0; j < coo_evicted_count; j++) {
                                    if (strcasecmp(entry->domain, coo_evicted_members[j].domain) == 0 &&
                                        strcmp(entry->catalog_member_unique_id, coo_evicted_members[j].unique_id) == 0) {
                                        is_removed = true; break;
                                    }
                                }
                            }
                        }
                        if (!is_removed) {
                            atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                            vs->entries[zidx++] = entry;
                        }
                    }
                    
                    for (int i = 0; i < added_count; i++) {
                        vs->entries[zidx++] = new_entries[i];
                    }
                    vs->zone_count = zidx;
                } else {
                    vs->zone_count = old_snap->views[v].zone_count;
                    vs->entries = calloc(vs->zone_count > 0 ? vs->zone_count : 1, sizeof(zone_db_entry_t *));
                    if (!vs->entries) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog other vs->entries");
                        return NULL;
                    }
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        zone_db_entry_t *entry = old_snap->views[v].entries[i];
                        atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                        vs->entries[i] = entry;
                    }
                }
            }
            if (del_hash_table) free(del_hash_table);
            if (del_chain_next) free(del_chain_next);
        }

        free(added_members);
        free(removed_members);
        free(coo_evicted_members);
        free(new_entries);

        if (catalog_entry_to_update) {
            // handled above
            if (catalog_entry_to_update->catalog_members) free_catalog_member_ids(catalog_entry_to_update->catalog_members, catalog_entry_to_update->catalog_member_count);
            catalog_entry_to_update->catalog_members = new_desired_members;
            catalog_entry_to_update->catalog_member_count = new_desired_count;
        }
    }

    for (size_t v = 0; v < new_snap->view_count; v++) {
        view_snapshot_t *vs = &new_snap->views[v];
        size_t p = 256;
        while (p < vs->zone_count * 2) p <<= 1;
        vs->hash_size = p;
        if (vs->hash_size > 0) {
            vs->hash_table = malloc(vs->hash_size * sizeof(int));
            if (vs->hash_table) {
                for (size_t i = 0; i < vs->hash_size; i++) vs->hash_table[i] = -1;
            }
        }
        if (vs->zone_count > 0) {
            vs->chain_next = malloc(vs->zone_count * sizeof(int));
            if (vs->chain_next) {
                for (size_t i = 0; i < vs->zone_count; i++) vs->chain_next[i] = -1;
            }
        }

        vs->suffix_hash_size = p;
        if (vs->suffix_hash_size > 0) {
            vs->suffix_hash_table = malloc(vs->suffix_hash_size * sizeof(int));
            if (vs->suffix_hash_table) {
                for (size_t i = 0; i < vs->suffix_hash_size; i++) vs->suffix_hash_table[i] = -1;
            }
        }
        if (vs->zone_count > 0) {
            vs->suffix_chain_next = malloc(vs->zone_count * sizeof(int));
            if (vs->suffix_chain_next) {
                for (size_t i = 0; i < vs->zone_count; i++) vs->suffix_chain_next[i] = -1;
            }
        }
        
        if ((vs->hash_size > 0 && !vs->hash_table) || (vs->zone_count > 0 && !vs->chain_next) ||
            (vs->suffix_hash_size > 0 && !vs->suffix_hash_table) || (vs->zone_count > 0 && !vs->suffix_chain_next)) {
            syslog(LOG_ERR, "[Core] Hash table allocation failed for view '%s', aborting snapshot rebuild", vs->name);
            gc_snapshot_thread(new_snap); // Clean up the new snapshot cleanly
            pthread_mutex_unlock(&g_zone_db_rebuild_lock);
            return NULL;
        }

        if (vs->hash_table && vs->chain_next) {
            for (size_t i = 0; i < vs->zone_count; i++) {
                if (!vs->entries[i]) continue;
                uint32_t hash = calc_fnv1a_str(vs->entries[i]->domain);
                size_t idx = hash & (vs->hash_size - 1);
                vs->chain_next[i] = vs->hash_table[idx];
                vs->hash_table[idx] = i;
            }
        }

        if (vs->suffix_hash_table && vs->suffix_chain_next) {
            for (size_t i = 0; i < vs->zone_count; i++) {
                if (!vs->entries[i]) continue;
                size_t z_len = strlen(vs->entries[i]->domain);
                while (z_len > 0 && vs->entries[i]->domain[z_len - 1] == '.') z_len--;
                uint32_t hash = calc_fnv1a_strn(vs->entries[i]->domain, z_len);
                size_t idx = hash & (vs->suffix_hash_size - 1);
                vs->suffix_chain_next[i] = vs->suffix_hash_table[idx];
                vs->suffix_hash_table[idx] = i;
            }
        }
    }

    uint64_t retire_epoch = 0;
    if (old_snap) {
        retire_epoch = rcu_writer_advance_epoch();
        old_snap->retire_epoch = retire_epoch;
    }
    atomic_store_explicit(&g_zone_db_active, new_snap, memory_order_release);
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);

    if (old_snap) {
        pthread_t gc_tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&gc_tid, &attr, gc_snapshot_thread, old_snap);
        pthread_attr_destroy(&attr);
    }

    return new_snap;
}

void rebuild_zone_db_from_config(server_config_t *config, bool skip_unchanged) {
    zone_db_snapshot_t *new_snap = rebuild_zone_db_snapshot(config, NULL, NULL, NULL, NULL, 0);
    if (!new_snap) {
        syslog(LOG_ERR, "[Core] Failed to rebuild zone DB snapshot from config due to allocation failure. Reload aborted.");
        return;
    }

    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            zone_db_snapshot_t *snap = acquire_zone_snapshot();
            if (snap) {
                zone_db_entry_t *entry = snapshot_get_zone(snap, z->domain);
                if (entry && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                    struct stat st;
                    if (skip_unchanged && stat_via_dir_cache(z->file, &st) == 0 && entry->last_loaded_mtime != 0 && st.st_mtime == entry->last_loaded_mtime) {
                        syslog(LOG_DEBUG, "[Config] zone '%s' file unchanged (mtime match), skipping reload", z->domain);
                    } else {
                        reload_master_zone(entry, z);
                    }
                }
                release_zone_snapshot(snap);
            }
        }
    }

    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            if (z->is_catalog && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                zone_db_snapshot_t *snap = acquire_zone_snapshot();
                if (snap) {
                    zone_db_entry_t *entry = snapshot_get_zone(snap, z->domain);
                    if (entry) {
                        catalog_process_membership(entry, z, v->name);
                    }
                    release_zone_snapshot(snap);
                }
            }
        }
    }

    // Pass 2: Pre-link additional glue across authoritative zones in each view
    zone_db_snapshot_t *relink_snap = acquire_zone_snapshot();
    if (relink_snap) {
        for (size_t v = 0; v < relink_snap->view_count; v++) {
            view_snapshot_t *view = &relink_snap->views[v];
            for (size_t i = 0; i < view->zone_count; i++) {
                zone_db_entry_t *entry = view->entries[i];
                if (!entry) continue;
                pthread_mutex_lock(&entry->writer_lock);
                zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
                if (z_active && z_active->count > 0) {
                    zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
                    rcu_writer_wait_until_safe(entry->rcu.retire_epoch, 60000);
                    clone_zone_arena(z_active, z_standby);
                    build_zone_index(z_standby, true);
                    zone_config_t *zcfg = find_zone_config_in_view(config, view->name, entry->domain);
                    additional_from_auth_t policy = (zcfg && zcfg->additional_from_auth_specified)
                                                        ? zcfg->additional_from_auth
                                                        : (config ? config->additional_from_auth : ADDITIONAL_AUTH_YES);
                    prelink_zone_additional_glue(z_standby, entry->domain, relink_snap, view, policy);
                    build_zone_response_cache(z_standby, config, entry->domain);
                    entry->rcu.retire_epoch = rcu_writer_advance_epoch();
                    atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
                }
                pthread_mutex_unlock(&entry->writer_lock);
            }
        }
        release_zone_snapshot(relink_snap);
    }
}

void zone_arena_clear_data_pools(zone_arena_t *arena) {
  if (!arena) return;
  for (int i = 0; i < arena->data_pool_count; i++) {
    if (arena->data_pools[i]) {
      free(arena->data_pools[i]);
      arena->data_pools[i] = NULL;
    }
  }
  if (arena->nsec_records) {
    free(arena->nsec_records);
    arena->nsec_records = NULL;
    arena->nsec_count = 0;
  }
  if (arena->sorted_unique_names) {
    free(arena->sorted_unique_names);
    arena->sorted_unique_names = NULL;
    arena->sorted_unique_count = 0;
  }
  if (arena->locations) {
    free(arena->locations);
    arena->locations = NULL;
    arena->location_count = 0;
  }
  if (arena->bind_location_tags) {
    free_ecs_tags_array(arena->bind_location_tags, arena->bind_location_tag_count);
    arena->bind_location_tags = NULL;
    arena->bind_location_tag_count = 0;
  }
  if (arena->bind_ecs_tags) {
    free_ecs_tags_array(arena->bind_ecs_tags, arena->bind_ecs_tag_count);
    arena->bind_ecs_tags = NULL;
    arena->bind_ecs_tag_count = 0;
  }
  if (arena->bind_ecs_trusted_resolvers) {
    for (int i = 0; i < arena->bind_ecs_trusted_resolver_count; i++) {
      free(arena->bind_ecs_trusted_resolvers[i]);
    }
    free(arena->bind_ecs_trusted_resolvers);
    arena->bind_ecs_trusted_resolvers = NULL;
    arena->bind_ecs_trusted_resolver_count = 0;
  }
  if (arena->bind_ecs_trusted_resolvers_parsed) {
    free(arena->bind_ecs_trusted_resolvers_parsed);
    arena->bind_ecs_trusted_resolvers_parsed = NULL;
  }
  arena->prelinked_glue = NULL;
  arena->prelinked_glue_count = 0;
  free_zone_response_cache(arena);
  arena->count = 0;
  arena->data_pool_count = 0;
  arena->current_pool_cap = 0;
  arena->current_pool_idx = 0;
}

void clone_zone_arena(zone_arena_t *src, zone_arena_t *dst) {
  zone_arena_clear_data_pools(dst);
  dst->is_tinydns_format = src->is_tinydns_format;
  if (src->location_count > 0 && src->locations) {
    dst->locations = malloc(src->location_count * sizeof(tinydns_location_entry_t));
    if (dst->locations) {
      memcpy(dst->locations, src->locations, src->location_count * sizeof(tinydns_location_entry_t));
      dst->location_count = src->location_count;
    }
  }
  if (src->bind_location_tag_count > 0 && src->bind_location_tags) {
    dst->bind_location_tags = clone_ecs_tags_array(src->bind_location_tags, src->bind_location_tag_count);
    if (dst->bind_location_tags) {
      dst->bind_location_tag_count = src->bind_location_tag_count;
    }
  }
  if (src->bind_ecs_tag_count > 0 && src->bind_ecs_tags) {
    dst->bind_ecs_tags = clone_ecs_tags_array(src->bind_ecs_tags, src->bind_ecs_tag_count);
    if (dst->bind_ecs_tags) {
      dst->bind_ecs_tag_count = src->bind_ecs_tag_count;
    }
  }
  if (src->bind_ecs_trusted_resolver_count > 0 && src->bind_ecs_trusted_resolvers) {
    dst->bind_ecs_trusted_resolvers = malloc(src->bind_ecs_trusted_resolver_count * sizeof(char *));
    if (dst->bind_ecs_trusted_resolvers) {
      dst->bind_ecs_trusted_resolver_count = 0;
      for (int i = 0; i < src->bind_ecs_trusted_resolver_count; i++) {
        if (src->bind_ecs_trusted_resolvers[i]) {
          dst->bind_ecs_trusted_resolvers[dst->bind_ecs_trusted_resolver_count] = strdup(src->bind_ecs_trusted_resolvers[i]);
          if (dst->bind_ecs_trusted_resolvers[dst->bind_ecs_trusted_resolver_count]) {
            dst->bind_ecs_trusted_resolver_count++;
          }
        }
      }
      if (dst->bind_ecs_trusted_resolver_count > 0) {
        dst->bind_ecs_trusted_resolvers_parsed = acl_list_parse(dst->bind_ecs_trusted_resolvers, dst->bind_ecs_trusted_resolver_count);
      }
    }
  }
  for (size_t i = 0; i < src->count; i++) {
    if (dst->count >= dst->records_cap) {
      size_t new_cap = dst->records_cap == 0 ? 16 : dst->records_cap * 2;
      if (new_cap > SIZE_MAX / sizeof(dns_record_t)) break;
      dns_record_t *new_records =
          realloc(dst->records, new_cap * sizeof(dns_record_t));
      if (!new_records)
        break;
      memset(new_records + dst->records_cap, 0,
             (new_cap - dst->records_cap) * sizeof(dns_record_t));
      dst->records = new_records;
      dst->records_cap = new_cap;
    }
    dns_record_t *s_rec = &src->records[i];
    dns_record_t *d_rec = &dst->records[dst->count++];
    memset(d_rec, 0, sizeof(*d_rec));
    d_rec->name = arena_strdup(dst, s_rec->name);
    d_rec->ttl = s_rec->ttl ? arena_strdup(dst, s_rec->ttl) : NULL;
    d_rec->ttl_value = s_rec->ttl_value;
    d_rec->class_str =
        s_rec->class_str ? arena_strdup(dst, s_rec->class_str) : NULL;
    d_rec->class_val = s_rec->class_val;
    d_rec->type = s_rec->type ? arena_strdup(dst, s_rec->type) : NULL;
    d_rec->type_code = s_rec->type_code;
    d_rec->tinydns_ttd = s_rec->tinydns_ttd;
    d_rec->tinydns_ttl_countdown = s_rec->tinydns_ttl_countdown;
    d_rec->tinydns_loc[0] = s_rec->tinydns_loc[0];
    d_rec->tinydns_loc[1] = s_rec->tinydns_loc[1];
    d_rec->ecs_subnet_tag = s_rec->ecs_subnet_tag ? arena_strdup(dst, s_rec->ecs_subnet_tag) : NULL;
    d_rec->bind_location_tag = s_rec->bind_location_tag ? arena_strdup(dst, s_rec->bind_location_tag) : NULL;
    d_rec->rdata_count = s_rec->rdata_count;
    for (int j = 0; j < s_rec->rdata_count; j++)
      d_rec->rdata[j] = s_rec->rdata[j] ? arena_strdup(dst, s_rec->rdata[j]) : NULL;
    d_rec->generic_len = s_rec->generic_len;
    if (s_rec->generic_len > 0 && s_rec->generic_data) {
      d_rec->generic_data = (uint8_t *)arena_alloc(dst, s_rec->generic_len);
      if (d_rec->generic_data)
        memcpy(d_rec->generic_data, s_rec->generic_data, s_rec->generic_len);
    } else if (s_rec->generic_data) {
      d_rec->generic_data = (uint8_t *)"";
    } else {
      d_rec->generic_data = NULL;
    }
    d_rec->next_record = -1;
    d_rec->is_cached = false;
    dns_record_preparse_cache(dst, d_rec);
  }
}

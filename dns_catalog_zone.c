#define OPENSSL_SUPPRESS_DEPRECATED 1
#define STATIC_TEST
#include "dns_catalog_zone.h"

uint32_t calc_catalog_member_hash(const char *domain, const char *unique_id) {
  uint32_t hash = calc_fnv1a_str(domain);
  if (unique_id) {
    for (const char *p = unique_id; *p; p++) {
      hash ^= (uint8_t)*p;
      hash *= 16777619u;
    }
  }
  return hash;
}

void free_catalog_member_ids(catalog_member_id_t *arr, int count) {
  if (!arr) return;
  for (int i = 0; i < count; i++) {
    if (arr[i].groups) {
      for (int j = 0; j < arr[i].group_count; j++) {
        free(arr[i].groups[j]);
      }
      free(arr[i].groups);
    }
  }
  free(arr);
}

zone_db_entry_t *find_catalog_parent_in_snapshot(view_snapshot_t *view, const char *catalog_domain) {
    if (!view || !catalog_domain) return NULL;
    if (view->hash_size > 0 && view->hash_table && view->chain_next) {
        uint32_t hash = calc_fnv1a_str(catalog_domain);
        size_t idx = hash & (view->hash_size - 1);
        for (int i = view->hash_table[idx]; i != -1; i = view->chain_next[i]) {
            if (strcasecmp(view->entries[i]->domain, catalog_domain) == 0) {
                return view->entries[i];
            }
        }
        return NULL;
    }
    for (size_t i = 0; i < view->zone_count; i++) {
        if (strcasecmp(view->entries[i]->domain, catalog_domain) == 0) {
            return view->entries[i];
        }
    }
    return NULL;
}

void remove_member_from_catalog_bookkeeping(zone_db_entry_t *catalog_entry, const char *unique_id, const char *domain) {
    if (!catalog_entry || !catalog_entry->catalog_members) return;
    for (int i = 0; i < catalog_entry->catalog_member_count; i++) {
        if (strcasecmp(catalog_entry->catalog_members[i].domain, domain) == 0 && 
            strcmp(catalog_entry->catalog_members[i].unique_id, unique_id) == 0) {
            
            // Explicitly free the dynamically allocated `groups` strings of the targeted element
            if (catalog_entry->catalog_members[i].groups) {
                for (int g = 0; g < catalog_entry->catalog_members[i].group_count; g++) {
                    free(catalog_entry->catalog_members[i].groups[g]);
                }
                free(catalog_entry->catalog_members[i].groups);
            }
            
            // Shift the remaining elements forward
            int elements_after = catalog_entry->catalog_member_count - i - 1;
            if (elements_after > 0) {
                memmove(&catalog_entry->catalog_members[i], 
                        &catalog_entry->catalog_members[i + 1], 
                        elements_after * sizeof(catalog_member_id_t));
            }
            catalog_entry->catalog_member_count--;
            break;
        }
    }
}

static void normalize_domain_fqdn_local(const char *in, char *out, size_t out_cap) {
    size_t len = strlen(in);
    if (len > 0 && in[len - 1] != '.' && len + 1 < out_cap) {
        memcpy(out, in, len);
        out[len] = '.';
        out[len + 1] = '\0';
    } else {
        snprintf(out, out_cap, "%s", in);
    }
}

STATIC_TEST void free_catalog_desired_list(catalog_member_id_t *list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) {
        if (list[i].groups) {
            for (int j = 0; j < list[i].group_count; j++) {
                if (list[i].groups[j]) free(list[i].groups[j]);
            }
            free(list[i].groups);
        }
    }
    free(list);
}

void catalog_process_membership(zone_db_entry_t *catalog_entry, zone_config_t *catalog_cfg, const char *view_name) {
    if (!catalog_entry || !catalog_cfg) return;

    zone_arena_t *arena = atomic_load_explicit(&catalog_entry->rcu.active, memory_order_acquire);
    if (!arena) return;

    atomic_fetch_add_explicit(&arena->reader_count, 1, memory_order_acquire);

    // Verify version.<catalog_zone>. TXT "2"
    char version_txt[256];
    snprintf(version_txt, sizeof(version_txt), "version.%s", catalog_entry->domain);
    bool found_version = false;
    for (size_t i = 0; i < arena->count; i++) {
        if (arena->records[i].type_code == 16 && strcasecmp(arena->records[i].name, version_txt) == 0) {
            if (arena->records[i].rdata_count > 0 && strcmp(arena->records[i].rdata[0], "2") == 0) {
                found_version = true;
                break;
            }
        }
    }

    if (!found_version) {
        syslog(LOG_ERR, "[Catalog] Zone '%s' is missing '%s TXT \"2\"', aborting catalog update", catalog_entry->domain, version_txt);
        atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
        return;
    }

    // Build desired members list
    int max_possible = arena->count;
    catalog_member_id_t *new_desired = calloc(max_possible, sizeof(catalog_member_id_t));
    if (!new_desired) {
        syslog(LOG_ERR, "[Catalog] Zone '%s': out of memory building member list", catalog_entry->domain);
        atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
        return;
    }
    int new_desired_count = 0;

    char suffix[256];
    snprintf(suffix, sizeof(suffix), ".zones.%s", catalog_entry->domain);
    size_t suffix_len = strlen(suffix);

    server_config_t *cfg = acquire_config_snapshot();
    for (size_t i = 0; i < arena->count; i++) {
        if (arena->records[i].type_code == 12) { // PTR
            size_t name_len = strlen(arena->records[i].name);
            if (name_len > suffix_len && strcasecmp(arena->records[i].name + name_len - suffix_len, suffix) == 0) {
                if (arena->records[i].rdata_count > 0) {
                    char *target = arena->records[i].rdata[0];
                    char norm_target[256];
                    normalize_domain_fqdn_local(target, norm_target, sizeof(norm_target));
                    
                    // Collision check with static config
                    zone_config_t *zcfg = find_zone_config_in_view(cfg, view_name, norm_target);
                    if (zcfg) {
                        syslog(LOG_WARNING, "[Catalog] Zone '%s' generated member '%s' which collides with static config. Skipping.", catalog_entry->domain, norm_target);
                        continue;
                    }
                    
                    // Extract unique_id
                    size_t prefix_len = name_len - suffix_len;
                    if (prefix_len < sizeof(new_desired[new_desired_count].unique_id)) {
                        strncpy(new_desired[new_desired_count].unique_id, arena->records[i].name, prefix_len);
                        new_desired[new_desired_count].unique_id[prefix_len] = '\0';
                        strncpy(new_desired[new_desired_count].domain, norm_target, sizeof(new_desired[new_desired_count].domain) - 1);
                        new_desired[new_desired_count].domain[sizeof(new_desired[new_desired_count].domain) - 1] = '\0';
                        new_desired_count++;
                    }
                }
            }
        }
    }
    release_config_snapshot(cfg);

    // RFC 9432 §5.1: 壊れたカタログゾーンの検出
    // (1) 同一 <unique-N> に複数のPTRレコードが存在しないか
    bool catalog_broken = false;
    for (size_t i = 0; i < arena->count && !catalog_broken; i++) {
        if (arena->records[i].type_code != 12) continue;
        size_t name_len = strlen(arena->records[i].name);
        if (name_len <= suffix_len ||
            strcasecmp(arena->records[i].name + name_len - suffix_len, suffix) != 0)
            continue;
        int count_for_this_name = 0;
        for (size_t j = 0; j < arena->count; j++) {
            if (arena->records[j].type_code == 12 &&
                strcasecmp(arena->records[j].name, arena->records[i].name) == 0) {
                count_for_this_name++;
            }
        }
        if (count_for_this_name > 1) {
            syslog(LOG_ERR, "[Catalog] Zone '%s': member node '%s' has %d PTR records (RFC 9432 requires exactly 1); catalog zone is broken and will NOT be processed",
                   catalog_entry->domain, arena->records[i].name, count_for_this_name);
            catalog_broken = true;
        }
    }

    // (2) 異なる<unique-N>が同一ターゲットを指していないか
    for (int a = 0; a < new_desired_count && !catalog_broken; a++) {
        for (int b = a + 1; b < new_desired_count; b++) {
            if (strcasecmp(new_desired[a].domain, new_desired[b].domain) == 0) {
                syslog(LOG_ERR, "[Catalog] Zone '%s': member zone '%s' is referenced by both '%s' and '%s' labels; catalog zone is broken and will NOT be processed",
                       catalog_entry->domain, new_desired[a].domain, new_desired[a].unique_id, new_desired[b].unique_id);
                catalog_broken = true;
                break;
            }
        }
    }

    if (catalog_broken) {
        free_catalog_desired_list(new_desired, new_desired_count);
        atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
        return; // カタログゾーン全体の更新を中止(既存の状態を維持)
    }

    for (int d = 0; d < new_desired_count; d++) {
        char group_name[512];
        snprintf(group_name, sizeof(group_name), "group.%s.zones.%s", new_desired[d].unique_id, catalog_entry->domain);
        
        int grp_count = 0;
        for (size_t i = 0; i < arena->count; i++) {
            if (arena->records[i].type_code == 16 && strcasecmp(arena->records[i].name, group_name) == 0) {
                grp_count++;
            }
        }
        
        if (grp_count > 0) {
            new_desired[d].groups = calloc(grp_count, sizeof(char *));
            if (!new_desired[d].groups) {
                syslog(LOG_ERR, "[Catalog] Zone '%s': out of memory building group list for member '%s'", catalog_entry->domain, new_desired[d].domain);
                free_catalog_desired_list(new_desired, new_desired_count);
                atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
                return;
            }
            new_desired[d].group_count = 0;
            for (size_t i = 0; i < arena->count; i++) {
                if (arena->records[i].type_code == 16 && strcasecmp(arena->records[i].name, group_name) == 0) {
                    if (arena->records[i].rdata_count > 0) {
                        char *g = strdup(arena->records[i].rdata[0]);
                        if (!g) {
                            syslog(LOG_ERR, "[Catalog] Zone '%s': out of memory duplicating group string", catalog_entry->domain);
                            free_catalog_desired_list(new_desired, new_desired_count);
                            atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
                            return;
                        }
                        new_desired[d].groups[new_desired[d].group_count++] = g;
                    }
                }
            }
            for (int i = 0; i < new_desired[d].group_count - 1; i++) {
                for (int j = i + 1; j < new_desired[d].group_count; j++) {
                    if (strcmp(new_desired[d].groups[i], new_desired[d].groups[j]) > 0) {
                        char *tmp = new_desired[d].groups[i];
                        new_desired[d].groups[i] = new_desired[d].groups[j];
                        new_desired[d].groups[j] = tmp;
                    }
                }
            }
        }
        char coo_name[512];
        snprintf(coo_name, sizeof(coo_name), "coo.%s.zones.%s", new_desired[d].unique_id, catalog_entry->domain);
        
        int coo_count = 0;
        char coo_rdata[256] = {0};
        for (size_t i = 0; i < arena->count; i++) {
            if (arena->records[i].type_code == 12 && strcasecmp(arena->records[i].name, coo_name) == 0) {
                if (arena->records[i].rdata_count > 0) {
                    strncpy(coo_rdata, arena->records[i].rdata[0], sizeof(coo_rdata) - 1);
                }
                coo_count++;
            }
        }
        
        if (coo_count == 1) {
            normalize_domain_fqdn_local(coo_rdata, new_desired[d].coo_target, sizeof(new_desired[d].coo_target));
        } else if (coo_count > 1) {
            syslog(LOG_ERR, "[Catalog] Multiple coo PTR records found for member '%s' in catalog '%s'; catalog zone is broken and will NOT be processed", new_desired[d].domain, catalog_entry->domain);
            free_catalog_desired_list(new_desired, new_desired_count);
            atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
            return;
        } else {
            new_desired[d].coo_target[0] = '\0';
        }
    }

    if (new_desired_count > 0) {
        catalog_member_id_t *shrunk = calloc(new_desired_count, sizeof(catalog_member_id_t));
        if (!shrunk) {
            syslog(LOG_ERR, "[Catalog] Zone '%s': out of memory finalizing member list", catalog_entry->domain);
            free_catalog_desired_list(new_desired, new_desired_count);
            atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
            return;
        }
        for (int i = 0; i < new_desired_count; i++) shrunk[i] = new_desired[i];
        free(new_desired);
        new_desired = shrunk;
    } else {
        free(new_desired);
        new_desired = NULL;
    }

    atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
    zone_db_snapshot_t *new_snap = rebuild_zone_db_snapshot(NULL, view_name, catalog_entry, catalog_cfg, new_desired, new_desired_count);
    if (!new_snap) {
        syslog(LOG_ERR, "[Catalog] Failed to rebuild zone DB snapshot; catalog membership update skipped for '%s'", catalog_entry->domain);
        return;
    }
    syslog(LOG_INFO, "[Catalog] Processed membership for '%s', desired members: %d", catalog_entry->domain, new_desired_count);
}

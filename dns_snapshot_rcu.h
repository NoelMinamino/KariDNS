#ifndef DNS_SNAPSHOT_RCU_H
#define DNS_SNAPSHOT_RCU_H

#include "dns_server_internal.h"

typedef struct {
  zone_db_entry_t *entry;
  zone_config_t *zcfg;
  const char *view_name;
} zone_lookup_result_t;

typedef enum {
    RELOAD_OK = 0,
    RELOAD_ERR_FILE_READ = -1,
    RELOAD_ERR_PARSE = -2,
    RELOAD_ERR_MISSING_SOA = -3,
    RELOAD_ERR_BUSY = -4,
} reload_result_t;

extern _Atomic(zone_db_snapshot_t *) g_zone_db_active;
zone_db_snapshot_t *acquire_zone_snapshot(void);
void retain_zone_snapshot(zone_db_snapshot_t *snap);
void release_zone_snapshot(zone_db_snapshot_t *snap);
zone_config_t *find_zone_config_in_view(server_config_t *cfg,
                                        const char *view_name,
                                        const char *domain);
int lookup_zone_across_views(zone_db_snapshot_t *snap, server_config_t *cfg,
                             const char *domain, const char *view_name,
                             zone_lookup_result_t *result);
zone_db_entry_t *snapshot_get_zone(zone_db_snapshot_t *snap, const char *domain);
zone_db_entry_t *find_zone_in_view(view_snapshot_t *view, const char *qname);
void wait_for_readers(zone_arena_t *arena);
void free_zone_db_entry(zone_db_entry_t *entry);
void *gc_snapshot_thread(void *arg);
zone_db_entry_t *create_new_zone_entry(const char *domain, const char *view_name);
void prelink_zone_additional_glue(zone_arena_t *current_zone,
                                  const char *zone_domain,
                                  zone_db_snapshot_t *snap,
                                  view_snapshot_t *view,
                                  additional_from_auth_t policy);
reload_result_t reload_master_zone(zone_db_entry_t *entry, zone_config_t *zcfg);
zone_db_snapshot_t *rebuild_zone_db_snapshot(
    server_config_t *active_config, 
    const char *catalog_view_name,
    zone_db_entry_t *catalog_entry_to_update,
    zone_config_t *catalog_cfg,
    catalog_member_id_t *new_desired_members, int new_desired_count);
void rebuild_zone_db_from_config(server_config_t *config, bool skip_unchanged);
void zone_arena_clear_data_pools(zone_arena_t *arena);
void clone_zone_arena(zone_arena_t *src, zone_arena_t *dst);

void free_zone_db_snapshot(zone_db_snapshot_t *snap);

#ifdef KARIDNS_UNIT_TEST
void abort_rebuild_snapshot(zone_db_snapshot_t *new_snap, const char *reason);
#endif

#endif /* DNS_SNAPSHOT_RCU_H */

#ifndef DNS_CATALOG_ZONE_H
#define DNS_CATALOG_ZONE_H

#include "dns_server_internal.h"

uint32_t calc_catalog_member_hash(const char *domain, const char *unique_id);
void free_catalog_member_ids(catalog_member_id_t *arr, int count);
zone_db_entry_t *find_catalog_parent_in_snapshot(view_snapshot_t *view, const char *catalog_domain);
void remove_member_from_catalog_bookkeeping(zone_db_entry_t *catalog_entry, const char *unique_id, const char *domain);
void catalog_process_membership(zone_db_entry_t *catalog_entry, zone_config_t *catalog_cfg, const char *view_name);

#endif /* DNS_CATALOG_ZONE_H */

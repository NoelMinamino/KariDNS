#ifndef DNS_EDNS_ECS_H
#define DNS_EDNS_ECS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"

// EDE stats counters
extern _Atomic uint64_t g_ede_prohibited_total;
extern _Atomic uint64_t g_ede_not_authoritative_total;
extern _Atomic uint64_t g_ede_not_supported_total;
extern _Atomic uint64_t g_ede_other_total;

void init_server_cookie_secret(void);
bool generate_server_cookie(const char *client_ip, const uint8_t client_cookie[8], uint8_t server_cookie[16], uint32_t timestamp);
void add_ede(edns_info_t *edns, bool enabled, uint16_t code, const char *text);

const char *resolve_ecs_subnet_tag(const zone_arena_t *zone, const server_config_t *cfg, const zone_config_t *zcfg,
                                   const uint8_t *addr, uint16_t family, uint8_t *out_scope_prefix);

const char *resolve_bind_location_tag(const zone_arena_t *zone, const server_config_t *cfg, const zone_config_t *zcfg,
                                      const char *client_ip);

bool is_ecs_trusted_resolver(const zone_arena_t *zone, const server_config_t *cfg,
                             const zone_config_t *zcfg, const char *client_ip);

void tinydns_resolve_client_location(const zone_arena_t *zone, const char *client_ip,
                                     char out_loc[2]);

size_t pack_tag_def_rdata(uint8_t *buf, size_t buf_cap, const ecs_tag_def_t *def);
bool unpack_tag_def_rdata(const uint8_t *data, size_t len, ecs_tag_def_t **defs_out, int *count_out);
bool unpack_trusted_resolvers_rdata(const uint8_t *data, size_t len, char ***resolvers_out, int *count_out);
bool unpack_tinydns_loc_rdata(const uint8_t *data, size_t len, tinydns_location_entry_t **locs_out, int *count_out);
bool wrap_tinydns_record(const dns_record_t *rec, dns_record_t *out_wrap, uint8_t *wrap_buf, size_t wrap_buf_cap);

#endif /* DNS_EDNS_ECS_H */

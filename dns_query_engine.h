#ifndef DNS_QUERY_ENGINE_H
#define DNS_QUERY_ENGINE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_server_internal.h"

int process_dns_query(const uint8_t *req, size_t req_len, uint8_t *res,
                      size_t max_res_len, const char *qname, uint16_t qtype,
                      const char *client_ip, compress_ctx_t *comp_ctx,
                      bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                      zone_db_snapshot_t *snap);

view_snapshot_t *select_view(zone_db_snapshot_t *snap, const char *client_ip);
bool spawn_one_program_plugin(zone_config_t *zcfg, program_plugin_t *out);
void spawn_program_zone_plugins(server_config_t *cfg);
void compute_program_zone_fingerprint(const zone_config_t *z, char *out, size_t out_cap);
size_t get_question_end_offset(const uint8_t *pkt, size_t len, uint16_t qdcount);

void resolve_name(const char *qname, uint16_t qclass, const uint16_t *qtypes, int num_qtypes,
                  zone_db_entry_t **db_entry_ptr,
                  zone_arena_t **current_zone_ptr, uint8_t *res,
                  size_t max_res_len, uint16_t *offset,
                  compress_ctx_t *comp_ctx, uint16_t *ancount,
                  uint16_t *nscount, uint16_t *arcount,
                  bool minimal_responses,
                  bool minimal_any, uint32_t minimal_any_ttl, bool dnssec_ok,
                  view_snapshot_t *view, uint32_t *qtx_included_out,
                  const char *client_ip, server_config_t *cfg,
                  bool ecs_trusted, const uint8_t *ecs_addr, uint16_t ecs_family,
                  uint8_t ecs_source_prefix,
                  uint8_t *out_ecs_scope_prefix);

void build_zone_response_cache(zone_arena_t *arena, server_config_t *cfg, const char *domain);

#endif /* DNS_QUERY_ENGINE_H */

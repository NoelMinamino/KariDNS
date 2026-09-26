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

int process_dns_query_impl(const uint8_t *req, size_t req_len, uint8_t *res,
                          size_t max_res_len, const char *qname, uint16_t qtype,
                          const char *client_ip, compress_ctx_t *comp_ctx,
                          bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                          zone_db_snapshot_t *snap, server_config_t *cfg,
                          zone_db_entry_t **out_matched_entry);

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

typedef struct resolve_checkpoint {
    uint16_t offset;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} resolve_checkpoint_t;

void build_zone_response_cache(zone_arena_t *arena, server_config_t *cfg, const char *domain);

#ifdef KARIDNS_UNIT_TEST
void restore_checkpoint(const resolve_checkpoint_t *cp, uint16_t *offset,
                        uint16_t *ancount, uint16_t *nscount, uint16_t *arcount);
size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max_out);
bool tinydns_record_currently_valid(const dns_record_t *rec, time_t now,
                                    const char client_loc[2],
                                    const char *client_ecs_tag,
                                    const char *client_loc_tag,
                                    uint32_t *effective_ttl_out);
bool append_glue_records(zone_arena_t *current_zone, const char *target,
                         const char *zone_apex, uint8_t *res,
                         size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *arcount,
                         const char client_loc[2],
                         const char *client_ecs_tag,
                         const char *client_loc_tag,
                         additional_from_auth_t policy,
                         view_snapshot_t *view);
void collect_additional_rr_glue(dns_record_t *rec,
                                const char *glue_targets[16],
                                int *glue_target_count,
                                bool minimal_responses);
bool name_exists_in_zone(zone_arena_t *zone, const char *name,
                         const char client_loc[2], const char *client_ecs_tag,
                         const char *client_loc_tag);
const char *find_closest_encloser(zone_arena_t *zone, const char *qname,
                                  const char *zone_apex, const char client_loc[2],
                                  const char *client_ecs_tag,
                                  const char *client_loc_tag);
size_t name_to_canonical_wire(const char *name, uint8_t *wire, size_t max_wire);
bool compute_nsec3_hash(const char *name, uint8_t algo, uint16_t iterations,
                        const uint8_t *salt, size_t salt_len,
                        char *out_b32, size_t out_b32_sz);
bool nsec3_covers_hash(const char *owner_hash, const char *next_hash, const char *target_hash);
dns_record_t *find_matching_nsec3(zone_arena_t *zone, const char *hash_b32, const char *apex);
dns_record_t *find_covering_nsec3(zone_arena_t *zone, const char *target_hash);
bool find_next_closer_name(const char *qname, const char *encloser, char *out, size_t out_sz);
bool attach_nsec3_record(zone_arena_t *zone, dns_record_t *rec,
                         uint8_t *res, size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *nscount,
                         dns_record_t **attached, int *attached_count);
bool find_delegation(zone_arena_t *current_zone, const char *qname,
                     uint32_t qname_hash,
                     const char *zone_apex, uint8_t *res,
                     size_t max_res_len, uint16_t *offset,
                     compress_ctx_t *comp_ctx, uint16_t *nscount,
                     uint16_t *arcount, bool is_ds_query,
                     const char client_loc[2],
                     const char *client_ecs_tag,
                     const char *client_loc_tag,
                     additional_from_auth_t policy,
                     view_snapshot_t *view,
                     bool dnssec_ok);
int build_synthetic_servfail(const uint8_t *req, size_t req_len,
                             uint8_t *res, size_t max_res_len);
bool question_section_matches(const uint8_t *resp, size_t resp_len,
                              const uint8_t *req, size_t req_len);
ssize_t write_all_timeout(int fd, const uint8_t *buf, size_t len, uint32_t timeout_ms);
ssize_t read_all_timeout(int fd, uint8_t *buf, size_t len, uint32_t timeout_ms);
int64_t monotonic_ms(void);
uint32_t remaining_ms(int64_t deadline);
program_plugin_t *find_program_plugin(const char *domain);
int dispatch_to_program_zone(const char *domain, const uint8_t *req, size_t req_len,
                             uint8_t *res, size_t max_res_len,
                             const char *client_ip, bool is_tcp);
ssize_t forward_via_tcp(const struct sockaddr_storage *ss, size_t ss_len,
                        const uint8_t *query, size_t query_len,
                        uint8_t *resp_out, size_t resp_out_cap,
                        uint32_t timeout_ms);
int dispatch_forward_zone(zone_config_t *zcfg, const uint8_t *req, size_t req_len,
                          uint8_t *res, size_t max_res_len);
bool nsec_covers_name(const dns_record_t *rec, const char *name);
dns_record_t *find_covering_nsec(zone_arena_t *zone, const char *name);
bool spawn_one_program_plugin(zone_config_t *zcfg, program_plugin_t *out);
void record_observatory_response(zone_db_entry_t *entry, uint8_t rcode, uint16_t ancount);
#endif

#endif /* DNS_QUERY_ENGINE_H */


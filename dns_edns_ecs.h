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

/* --- RFC 9018 interoperable DNS Server Cookies (Version 1) -------------------------------
 *   Server Cookie = Version(1) | Reserved(3) | Timestamp(4, big-endian) | Hash(8)
 *   Hash = SipHash-2-4(Client Cookie | Version | Reserved | Timestamp | Client-IP, Server Secret)
 * The 8-byte Hash is the little-endian serialization of the SipHash output (RFC 9018 App. A).
 * Secrets come from `cookie-secret` in named.conf (cfg->cookie_secrets); with none configured a
 * random per-process secret is used, which is NOT interoperable across servers. */
#define SERVER_COOKIE_LEN 16
#define SERVER_COOKIE_SECRET_LEN 16
#define SERVER_COOKIE_VERSION 1
#define SERVER_COOKIE_VALID_PAST_SECS 3600    /* RFC 9018 §4.3: accept up to 1 hour old   */
#define SERVER_COOKIE_VALID_FUTURE_SECS 300   /* ...and up to 5 minutes in the future     */
#define SERVER_COOKIE_REFRESH_SECS 1800       /* RFC 9018 §4.3: renew if older than 30 min */

typedef enum {
    SERVER_COOKIE_INVALID = 0,      /* wrong length/version, stale/too-far-future, or bad hash  */
    SERVER_COOKIE_VALID,            /* valid and fresh                                          */
    SERVER_COOKIE_VALID_REFRESH     /* valid but older than 30 min: caller should send a new one */
} server_cookie_status_t;

void init_server_cookie_secret(void);

/* Computes the 8-byte Hash sub-field. `ver_rsvd_ts` is the 8 bytes Version|Reserved|Timestamp exactly
 * as they appear in the cookie (Reserved is hashed as received). Returns false if client_ip is not a
 * parsable IPv4/IPv6 literal. */
bool compute_server_cookie_hash(const uint8_t secret[SERVER_COOKIE_SECRET_LEN], const char *client_ip,
                                const uint8_t client_cookie[8], const uint8_t ver_rsvd_ts[8],
                                uint8_t hash_out[8]);

/* `cfg` may be NULL (uses the random per-process secret). Reserved is always generated as zero. */
bool generate_server_cookie(const server_config_t *cfg, const char *client_ip,
                            const uint8_t client_cookie[8], uint8_t server_cookie[SERVER_COOKIE_LEN],
                            uint32_t timestamp);

/* Verifies a received Server Cookie against every configured secret (rollover). Reserved is NOT
 * required to be zero (RFC 9018 §4.2); the timestamp window uses RFC 1982 serial arithmetic. */
server_cookie_status_t verify_server_cookie(const server_config_t *cfg, const char *client_ip,
                                            const uint8_t client_cookie[8],
                                            const uint8_t *server_cookie, size_t server_cookie_len,
                                            uint32_t now);
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

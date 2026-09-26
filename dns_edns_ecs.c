#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_edns_ecs.h"
#include "dns_server_internal.h"
#include "dns_utils.h"
#include "dns_tsig_acl.h"
#include "dns_siphash.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

_Atomic uint64_t g_ede_prohibited_total = 0;
_Atomic uint64_t g_ede_not_authoritative_total = 0;
_Atomic uint64_t g_ede_not_supported_total = 0;
_Atomic uint64_t g_ede_other_total = 0;

static uint8_t g_server_cookie_secret[SERVER_COOKIE_SECRET_LEN];

void init_server_cookie_secret(void) {
  arc4random_buf(g_server_cookie_secret, sizeof(g_server_cookie_secret));
}

bool compute_server_cookie_hash(const uint8_t secret[SERVER_COOKIE_SECRET_LEN], const char *client_ip,
                                const uint8_t client_cookie[8], const uint8_t ver_rsvd_ts[8],
                                uint8_t hash_out[8]) {
    /* RFC 9018 §4.4 input order: Client Cookie | Version | Reserved | Timestamp | Client-IP */
    uint8_t data[8 + 8 + 16];
    size_t data_len = 0;
    memcpy(data, client_cookie, 8);
    memcpy(data + 8, ver_rsvd_ts, 8);
    data_len = 16;

    struct in_addr a4;
    struct in6_addr a6;
    if (client_ip && inet_pton(AF_INET, client_ip, &a4) == 1) {
        memcpy(data + data_len, &a4, 4);
        data_len += 4;
    } else if (client_ip && inet_pton(AF_INET6, client_ip, &a6) == 1) {
        memcpy(data + data_len, &a6, 16);
        data_len += 16;
    } else {
        syslog(LOG_WARNING, "[Cookie] client_ip could not be parsed as IPv4/IPv6; refusing to bind cookie to address");
        return false;
    }

    uint64_t key[2];
    dns_siphash_key_from_bytes(secret, key);
    uint64_t h = dns_siphash24(data, data_len, key);
    for (int i = 0; i < 8; i++) hash_out[i] = (uint8_t)(h >> (8 * i));   /* little-endian */
    return true;
}

static const uint8_t *cookie_active_secret(const server_config_t *cfg) {
    return (cfg && cfg->cookie_secret_count > 0) ? cfg->cookie_secrets[0] : g_server_cookie_secret;
}

bool generate_server_cookie(const server_config_t *cfg, const char *client_ip,
                            const uint8_t client_cookie[8], uint8_t server_cookie[SERVER_COOKIE_LEN],
                            uint32_t timestamp) {
    server_cookie[0] = SERVER_COOKIE_VERSION;
    server_cookie[1] = 0;   /* Reserved: MUST be zero on construction */
    server_cookie[2] = 0;
    server_cookie[3] = 0;
    server_cookie[4] = (uint8_t)((timestamp >> 24) & 0xFF);
    server_cookie[5] = (uint8_t)((timestamp >> 16) & 0xFF);
    server_cookie[6] = (uint8_t)((timestamp >> 8) & 0xFF);
    server_cookie[7] = (uint8_t)(timestamp & 0xFF);
    return compute_server_cookie_hash(cookie_active_secret(cfg), client_ip, client_cookie,
                                      server_cookie, server_cookie + 8);
}

server_cookie_status_t verify_server_cookie(const server_config_t *cfg, const char *client_ip,
                                            const uint8_t client_cookie[8],
                                            const uint8_t *server_cookie, size_t server_cookie_len,
                                            uint32_t now) {
    if (!server_cookie || server_cookie_len != SERVER_COOKIE_LEN ||
        server_cookie[0] != SERVER_COOKIE_VERSION)
        return SERVER_COOKIE_INVALID;

    /* RFC 9018 §4.3: all timestamp comparisons use RFC 1982 serial arithmetic (wrap-safe). */
    uint32_t ts = ((uint32_t)server_cookie[4] << 24) | ((uint32_t)server_cookie[5] << 16) |
                  ((uint32_t)server_cookie[6] << 8)  |  (uint32_t)server_cookie[7];
    int32_t age = (int32_t)(now - ts);          /* >0: cookie is `age` seconds old; <0: from the future */
    if (age > SERVER_COOKIE_VALID_PAST_SECS || age < -SERVER_COOKIE_VALID_FUTURE_SECS)
        return SERVER_COOKIE_INVALID;

    /* Reserved (bytes 1..3) is deliberately NOT required to be zero; it is hashed as received. */
    bool match = false;
    if (cfg && cfg->cookie_secret_count > 0) {
        for (int i = 0; i < cfg->cookie_secret_count && !match; i++) {
            uint8_t expected[8];
            if (!compute_server_cookie_hash(cfg->cookie_secrets[i], client_ip, client_cookie,
                                            server_cookie, expected))
                return SERVER_COOKIE_INVALID;
            match = (const_time_memcmp(server_cookie + 8, expected, 8) == 0);
        }
    } else {
        uint8_t expected[8];
        if (!compute_server_cookie_hash(g_server_cookie_secret, client_ip, client_cookie,
                                        server_cookie, expected))
            return SERVER_COOKIE_INVALID;
        match = (const_time_memcmp(server_cookie + 8, expected, 8) == 0);
    }
    if (!match) return SERVER_COOKIE_INVALID;
    return (age > SERVER_COOKIE_REFRESH_SECS) ? SERVER_COOKIE_VALID_REFRESH : SERVER_COOKIE_VALID;
}

void add_ede(edns_info_t *edns, bool enabled, uint16_t code, const char *text) {
    if (!enabled || !edns->present) return;
    if (edns->ede_count >= MAX_EDE_COUNT) return;

    edns->ede_list[edns->ede_count].code = code;
    if (text) {
        strncpy(edns->ede_list[edns->ede_count].text, text, sizeof(edns->ede_list[0].text) - 1);
        edns->ede_list[edns->ede_count].text[sizeof(edns->ede_list[0].text) - 1] = '\0';
    } else {
        edns->ede_list[edns->ede_count].text[0] = '\0';
    }
    edns->ede_count++;

    switch (code) {
        case 18: atomic_fetch_add_explicit(&g_ede_prohibited_total, 1, memory_order_relaxed); break;
        case 20: atomic_fetch_add_explicit(&g_ede_not_authoritative_total, 1, memory_order_relaxed); break;
        case 21: atomic_fetch_add_explicit(&g_ede_not_supported_total, 1, memory_order_relaxed); break;
        case 0:  atomic_fetch_add_explicit(&g_ede_other_total, 1, memory_order_relaxed); break;
    }
}

size_t pack_tag_def_rdata(uint8_t *buf, size_t buf_cap, const ecs_tag_def_t *def) {
  if (!def || !buf) return 0;
  size_t tag_len = strlen(def->tag) + 1;
  if (tag_len + 2 > buf_cap) return 0;
  memcpy(buf, def->tag, tag_len);
  size_t off = tag_len;
  buf[off++] = (def->cidr_count >> 8) & 0xFF;
  buf[off++] = def->cidr_count & 0xFF;
  for (int j = 0; j < def->cidr_count; j++) {
    size_t c_len = strlen(def->cidrs[j].cidr) + 1;
    if (off + c_len > buf_cap) return 0;
    memcpy(buf + off, def->cidrs[j].cidr, c_len);
    off += c_len;
  }
  return off;
}

bool unpack_tag_def_rdata(const uint8_t *data, size_t len, ecs_tag_def_t **defs_out, int *count_out) {
  if (!data || len < 3 || !defs_out || !count_out) return false;
  size_t off = 0;
  const char *tag = (const char *)&data[off];
  size_t tag_len = strnlen(tag, len - off);
  if (off + tag_len + 1 + 2 > len) return false;
  off += tag_len + 1;
  uint16_t cidr_count = (data[off] << 8) | data[off + 1];
  off += 2;

  ecs_tag_def_t def;
  memset(&def, 0, sizeof(def));
  def.tag = strdup(tag);
  if (!def.tag) return false;
  def.cidrs = (cidr_count > 0) ? calloc(cidr_count, sizeof(ecs_cidr_entry_t)) : NULL;
  if (cidr_count > 0 && !def.cidrs) {
    free(def.tag);
    return false;
  }
  def.cidr_count = cidr_count;

  for (int j = 0; j < cidr_count; j++) {
    if (off >= len) {
      for (int k = 0; k < j; k++) free(def.cidrs[k].cidr);
      free(def.cidrs);
      free(def.tag);
      return false;
    }
    const char *cidr_str = (const char *)&data[off];
    size_t clen = strnlen(cidr_str, len - off);
    if (off + clen + 1 > len) {
      for (int k = 0; k < j; k++) free(def.cidrs[k].cidr);
      free(def.cidrs);
      free(def.tag);
      return false;
    }
    def.cidrs[j].cidr = strdup(cidr_str);
    if (!def.cidrs[j].cidr) {
      for (int k = 0; k < j; k++) free(def.cidrs[k].cidr);
      free(def.cidrs);
      free(def.tag);
      return false;
    }
    cidr_entry_parse(&def.cidrs[j].parsed, def.cidrs[j].cidr);
    off += clen + 1;
  }

  int cur_count = *count_out;
  ecs_tag_def_t *new_defs = realloc(*defs_out, (cur_count + 1) * sizeof(ecs_tag_def_t));
  if (!new_defs) {
    for (int k = 0; k < cidr_count; k++) free(def.cidrs[k].cidr);
    free(def.cidrs);
    free(def.tag);
    return false;
  }
  new_defs[cur_count] = def;
  *defs_out = new_defs;
  *count_out = cur_count + 1;
  return true;
}

bool unpack_trusted_resolvers_rdata(const uint8_t *data, size_t len, char ***resolvers_out, int *count_out) {
  if (!data || len < 1 || !resolvers_out || !count_out) return false;
  size_t off = 0;
  int count = data[off++];
  if (count <= 0) return true;

  int cur_count = *count_out;
  char **new_res = realloc(*resolvers_out, (cur_count + count) * sizeof(char *));
  if (!new_res) return false;
  *resolvers_out = new_res;

  for (int i = 0; i < count && off < len; i++) {
    size_t slen = data[off++];
    if (off + slen > len) return false;
    char *s = malloc(slen + 1);
    if (!s) return false;
    memcpy(s, &data[off], slen);
    s[slen] = '\0';
    (*resolvers_out)[cur_count++] = s;
    *count_out = cur_count;
    off += slen;
  }
  return true;
}

bool unpack_tinydns_loc_rdata(const uint8_t *data, size_t len, tinydns_location_entry_t **locs_out, int *count_out) {
  if (!data || len < 3 || !locs_out || !count_out) return false;
  char code[2] = { (char)data[0], (char)data[1] };
  uint8_t prefix_len = data[2];
  if (prefix_len > 4 || (size_t)(3 + prefix_len) > len) return false;

  tinydns_location_entry_t loc;
  memset(&loc, 0, sizeof(loc));
  loc.code[0] = code[0];
  loc.code[1] = code[1];
  loc.prefix_len = prefix_len;
  if (prefix_len > 0) {
    memcpy(loc.prefix, &data[3], prefix_len);
  }

  int cur_count = *count_out;
  tinydns_location_entry_t *new_locs = realloc(*locs_out, (cur_count + 1) * sizeof(tinydns_location_entry_t));
  if (!new_locs) return false;
  new_locs[cur_count] = loc;
  *locs_out = new_locs;
  *count_out = cur_count + 1;
  return true;
}

bool wrap_tinydns_record(const dns_record_t *rec, dns_record_t *out_wrap, uint8_t *wrap_buf, size_t wrap_buf_cap) {
  if (!rec || !out_wrap || !wrap_buf) return false;
  uint8_t tmp_wire[4096];
  uint16_t tmp_off = 0;
  compress_ctx_t dummy_comp;
  memset(&dummy_comp, 0, sizeof(dummy_comp));
  compress_ctx_init_packet(&dummy_comp);
  if (serialize_dns_record(tmp_wire, sizeof(tmp_wire), &tmp_off, (dns_record_t *)rec, &dummy_comp, NULL, 0xFFFFFFFF) < 0) {
    return false;
  }
  size_t p = 0;
  if (skip_wire_name(tmp_wire, tmp_off, 0, &p) != 0) return false;
  if (p + 10 > tmp_off) return false;
  uint16_t orig_type = (tmp_wire[p] << 8) | tmp_wire[p+1];
  uint16_t orig_class = (tmp_wire[p+2] << 8) | tmp_wire[p+3];
  uint32_t orig_ttl = ((uint32_t)tmp_wire[p+4] << 24) | ((uint32_t)tmp_wire[p+5] << 16) | ((uint32_t)tmp_wire[p+6] << 8) | tmp_wire[p+7];
  uint16_t orig_rdlen = (tmp_wire[p+8] << 8) | tmp_wire[p+9];
  if (p + 10 + orig_rdlen > tmp_off) return false;
  const uint8_t *orig_rdata = &tmp_wire[p+10];

  size_t total_wrap_len = 21 + orig_rdlen;
  if (total_wrap_len > wrap_buf_cap) return false;

  wrap_buf[0] = (orig_type >> 8) & 0xFF;
  wrap_buf[1] = orig_type & 0xFF;
  wrap_buf[2] = (orig_class >> 8) & 0xFF;
  wrap_buf[3] = orig_class & 0xFF;
  wrap_buf[4] = (orig_ttl >> 24) & 0xFF;
  wrap_buf[5] = (orig_ttl >> 16) & 0xFF;
  wrap_buf[6] = (orig_ttl >> 8) & 0xFF;
  wrap_buf[7] = orig_ttl & 0xFF;
  wrap_buf[8] = (uint8_t)rec->tinydns_loc[0];
  wrap_buf[9] = (uint8_t)rec->tinydns_loc[1];
  uint64_t ttd = (uint64_t)rec->tinydns_ttd;
  for (int b = 0; b < 8; b++) {
    wrap_buf[10 + b] = (ttd >> ((7 - b) * 8)) & 0xFF;
  }
  wrap_buf[18] = rec->tinydns_ttl_countdown ? 1 : 0;
  wrap_buf[19] = (orig_rdlen >> 8) & 0xFF;
  wrap_buf[20] = orig_rdlen & 0xFF;
  if (orig_rdlen > 0) {
    memcpy(&wrap_buf[21], orig_rdata, orig_rdlen);
  }

  memset(out_wrap, 0, sizeof(*out_wrap));
  out_wrap->name = rec->name;
  out_wrap->type_code = DNS_TYPE_KARIDNS_TINYDNS_WRAP;
  out_wrap->class_val = DNS_CLASS_KARIDNS_EXT;
  out_wrap->class_str = "KARIDNS";
  out_wrap->ttl_value = rec->ttl_value;
  out_wrap->generic_data = wrap_buf;
  out_wrap->generic_len = total_wrap_len;
  return true;
}

const char *resolve_ecs_subnet_tag(const zone_arena_t *zone, const server_config_t *cfg, const zone_config_t *zcfg,
                                   const uint8_t *addr, uint16_t family, uint8_t *out_scope_prefix) {
    if (out_scope_prefix) *out_scope_prefix = 0;
    const ecs_tag_def_t *tags = (zone && zone->bind_ecs_tags && zone->bind_ecs_tag_count > 0)
                                 ? zone->bind_ecs_tags : NULL;
    int tag_count = tags ? zone->bind_ecs_tag_count : 0;
    if (!tags) {
        tags = (zcfg && zcfg->ecs_tags) ? zcfg->ecs_tags : (cfg ? cfg->ecs_tags : NULL);
        tag_count = (zcfg && zcfg->ecs_tags) ? zcfg->ecs_tag_count : (cfg ? cfg->ecs_tag_count : 0);
    }
    if (!tags || tag_count == 0 || !addr) return NULL;

    int af = (family == 1) ? AF_INET : ((family == 2) ? AF_INET6 : -1);
    if (af == -1) return NULL;

    for (int i = 0; i < tag_count; i++) {
        for (int j = 0; j < tags[i].cidr_count; j++) {
            const ecs_cidr_entry_t *ce = &tags[i].cidrs[j];
            bool match = false;
            if (ce->parsed.valid) {
                match = cidr_entry_match(&ce->parsed, af, addr);
            } else if (ce->cidr) {
                char ip_buf[INET6_ADDRSTRLEN];
                if (inet_ntop(af, addr, ip_buf, sizeof(ip_buf))) {
                    match = match_cidr(ip_buf, ce->cidr);
                }
            }
            if (match) {
                if (out_scope_prefix) {
                    if (ce->parsed.valid && !ce->parsed.is_any) {
                        *out_scope_prefix = ce->parsed.prefix;
                    } else if (ce->cidr) {
                        const char *slash = strchr(ce->cidr, '/');
                        if (slash) {
                            int pfx = atoi(slash + 1);
                            *out_scope_prefix = (pfx >= 0 && pfx <= 128) ? (uint8_t)pfx : 0;
                        } else {
                            *out_scope_prefix = (family == 1) ? 32 : 128;
                        }
                    } else {
                        *out_scope_prefix = (family == 1) ? 32 : 128;
                    }
                }
                return tags[i].tag;
            }
        }
    }
    return NULL;
}

const char *resolve_bind_location_tag(const zone_arena_t *zone, const server_config_t *cfg, const zone_config_t *zcfg,
                                      const char *client_ip) {
    if (!client_ip) return NULL;

    const ecs_tag_def_t *tags = (zone && zone->bind_location_tags && zone->bind_location_tag_count > 0)
                                 ? zone->bind_location_tags : NULL;
    int tag_count = tags ? zone->bind_location_tag_count : 0;
    if (!tags) {
        tags = (zcfg && zcfg->location_tags) ? zcfg->location_tags : (cfg ? cfg->location_tags : NULL);
        tag_count = (zcfg && zcfg->location_tags) ? zcfg->location_tag_count : (cfg ? cfg->location_tag_count : 0);
    }
    if (!tags || tag_count == 0) return NULL;

    struct in_addr addr4;
    struct in6_addr addr6;
    int af = 0;
    const uint8_t *addr_bytes = NULL;
    if (inet_pton(AF_INET, client_ip, &addr4) == 1) {
        af = AF_INET;
        addr_bytes = (const uint8_t *)&addr4.s_addr;
    } else if (inet_pton(AF_INET6, client_ip, &addr6) == 1) {
        af = AF_INET6;
        addr_bytes = (const uint8_t *)&addr6.s6_addr;
    } else {
        return NULL;
    }

    for (int i = 0; i < tag_count; i++) {
        for (int j = 0; j < tags[i].cidr_count; j++) {
            const ecs_cidr_entry_t *ce = &tags[i].cidrs[j];
            if (ce->parsed.valid) {
                if (cidr_entry_match(&ce->parsed, af, addr_bytes)) {
                    return tags[i].tag;
                }
            } else if (ce->cidr && match_cidr(client_ip, ce->cidr)) {
                return tags[i].tag;
            }
        }
    }
    return NULL;
}

bool is_ecs_trusted_resolver(const zone_arena_t *zone, const server_config_t *cfg,
                             const zone_config_t *zcfg, const char *client_ip) {
    if (!client_ip) return false;

    const acl_entry_t *parsed = (zone && zone->bind_ecs_trusted_resolvers_parsed && zone->bind_ecs_trusted_resolver_count > 0)
                                 ? zone->bind_ecs_trusted_resolvers_parsed : NULL;
    int count = parsed ? zone->bind_ecs_trusted_resolver_count : 0;
    if (!parsed) {
        parsed = (zcfg && zcfg->ecs_trusted_resolvers_parsed) ? zcfg->ecs_trusted_resolvers_parsed
                                                              : (cfg ? cfg->ecs_trusted_resolvers_parsed : NULL);
        count = (zcfg && zcfg->ecs_trusted_resolvers_parsed) ? zcfg->ecs_trusted_resolvers_count
                                                             : (cfg ? cfg->ecs_trusted_resolvers_count : 0);
    }
    if (parsed && count > 0) {
        return check_acl_bin(client_ip, parsed, count);
    }

    char **resolvers = (zone && zone->bind_ecs_trusted_resolvers && zone->bind_ecs_trusted_resolver_count > 0)
                        ? zone->bind_ecs_trusted_resolvers : NULL;
    count = resolvers ? zone->bind_ecs_trusted_resolver_count : 0;
    if (!resolvers) {
        resolvers = (zcfg && zcfg->ecs_trusted_resolvers) ? zcfg->ecs_trusted_resolvers
                                                           : (cfg ? cfg->ecs_trusted_resolvers : NULL);
        count = (zcfg && zcfg->ecs_trusted_resolvers) ? zcfg->ecs_trusted_resolvers_count
                                                       : (cfg ? cfg->ecs_trusted_resolvers_count : 0);
    }
    if (!resolvers || count == 0) return false;
    return check_acl(client_ip, resolvers, count);
}

void tinydns_resolve_client_location(const zone_arena_t *zone, const char *client_ip,
                                     char out_loc[2]) {
    out_loc[0] = 0;
    out_loc[1] = 0;
    if (!zone || zone->location_count == 0 || !client_ip) return;

    struct in_addr addr;
    if (inet_pton(AF_INET, client_ip, &addr) != 1) return; /* IPv6は非対応(仕様通り) */
    const uint8_t *ipb = (const uint8_t *)&addr.s_addr;

    for (int plen = 4; plen >= 0; plen--) {
        for (int li = 0; li < zone->location_count; li++) {
            const tinydns_location_entry_t *loc = &zone->locations[li];
            if (loc->prefix_len != plen) continue;
            if (plen == 0 || memcmp(loc->prefix, ipb, plen) == 0) {
                out_loc[0] = loc->code[0];
                out_loc[1] = loc->code[1];
                return;
            }
        }
    }
}

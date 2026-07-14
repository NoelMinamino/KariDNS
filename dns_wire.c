#include "dns_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <math.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "dns_utils.h"

// ============================================================================
// 5. 名前圧縮アルゴリズム (FNV-1a, Branchless, 無限ループ防御)
// ============================================================================
void compress_ctx_init_packet(compress_ctx_t *ctx) {
    ctx->current_generation++;
    if (ctx->current_generation == 0) { memset(ctx->table, 0, sizeof(ctx->table)); ctx->current_generation = 1; }
}

static inline uint32_t calc_fnv1a_suffix(const uint8_t *name) {
    uint32_t hash = 2166136261u; const uint8_t *p = name;
    while (*p != 0) {
        uint8_t len = *p++; hash ^= len; hash *= 16777619u;
        for (uint8_t i = 0; i < len; i++) {
            uint8_t c = *p++; if (c >= 'A' && c <= 'Z') c |= 0x20;
            hash ^= c; hash *= 16777619u;
        }
    }
    return hash;
}

static inline bool suffix_equals(const uint8_t *packet_buf, uint16_t offset, const uint8_t *name) {
    const uint8_t *p = packet_buf + offset, *n = name; int jump_count = 0;
    while (*n != 0) {
        if ((*p & 0xC0) == 0xC0) {
            if (++jump_count > MAX_JUMPS) return false;
            uint16_t next_offset = ((*p & 0x3F) << 8) | *(p + 1);
            if (next_offset >= offset) return false;
            offset = next_offset; p = packet_buf + offset; continue;
        }
        if (*p != *n) return false;
        uint8_t len = *p; p++; n++;
        for (uint8_t i = 0; i < len; i++) {
            uint8_t c1 = *p++, c2 = *n++;
            if (c1 >= 'A' && c1 <= 'Z') c1 |= 0x20;
            if (c2 >= 'A' && c2 <= 'Z') c2 |= 0x20;
            if (c1 != c2) return false;
        }
    }
    jump_count = 0;
    while ((*p & 0xC0) == 0xC0) {
        if (++jump_count > MAX_JUMPS) return false;
        uint16_t next_offset = ((*p & 0x3F) << 8) | *(p + 1);
        if (next_offset >= offset) return false;
        offset = next_offset; p = packet_buf + offset;
    }
    return *p == 0;
}

int compress_name(uint8_t *packet_buf, uint16_t *offset, const uint8_t *name, compress_ctx_t *ctx, size_t max_len) {
    const uint8_t *s = name;
    while (*s != 0) {
        if (*offset >= 0x3FFF) return -1;
        uint32_t hash = calc_fnv1a_suffix(s), idx = hash & COMPRESS_HASH_MASK;
        for (int i = 0; i < MAX_PROBE_DEPTH; i++) {
            compress_entry_t *entry = &ctx->table[(idx + i) & COMPRESS_HASH_MASK];
            if (entry->generation != ctx->current_generation) break;
            if (entry->hash == hash && suffix_equals(packet_buf, entry->offset, s)) {
                if (*offset + 2 > max_len) return -1;
                uint16_t ptr = 0xC000 | entry->offset;
                packet_buf[(*offset)++] = ptr >> 8; packet_buf[(*offset)++] = ptr & 0xFF;
                return 0;
            }
        }
        for (int i = 0; i < MAX_PROBE_DEPTH; i++) {
            compress_entry_t *entry = &ctx->table[(idx + i) & COMPRESS_HASH_MASK];
            if (entry->generation != ctx->current_generation) {
                entry->generation = ctx->current_generation; entry->hash = hash; entry->offset = *offset; break;
            }
        }
        uint8_t len = *s; 
        if (*offset + 1 + len > max_len) return -1;
        packet_buf[(*offset)++] = *s++;
        for (uint8_t i = 0; i < len; i++) packet_buf[(*offset)++] = *s++;
    }
    if (*offset + 1 > max_len) return -1;
    packet_buf[(*offset)++] = 0; return 0;
}

// ============================================================================
// 6. AXFR クライアント & ワイヤーデシリアライザ (スタック安全・バグ修正済)
// ============================================================================

int skip_wire_name(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset) {
    size_t p = current_offset; int jump_count = 0; bool jumped = false; size_t jumped_offset = 0;
    while (1) {
        if (p >= packet_len) return -1;
        uint8_t len = packet[p];
        if ((len & 0xC0) == 0xC0) {
            if (p + 1 >= packet_len) return -1;
            if (++jump_count > MAX_JUMPS) return -1;
            uint16_t ptr = ((len & 0x3F) << 8) | packet[p+1];
            if (!jumped) { jumped_offset = p + 2; jumped = true; }
            if (ptr >= p && jumped) return -1;
            p = ptr; continue;
        }
        if (len == 0) { p++; break; }
        p += 1 + len;
    }
    *next_offset = jumped ? jumped_offset : p; return 0;
}

int expand_wire_name(const uint8_t *packet, size_t packet_len, size_t current_offset, size_t *next_offset, zone_arena_t *arena, char **name_out) {
    size_t p = current_offset, jumped_offset = 0; bool jumped = false; int jump_count = 0;
    char buf[257]; size_t written = 0;
    while (1) {
        if (p >= packet_len) return -1;
        uint8_t len = packet[p];
        if ((len & 0xC0) == 0xC0) {
            if (p + 1 >= packet_len || ++jump_count > MAX_JUMPS) return -1;
            uint16_t ptr = ((len & 0x3F) << 8) | packet[p+1];
            if (!jumped) { jumped_offset = p + 2; jumped = true; }
            if (ptr >= p && jumped) return -1;
            p = ptr; continue;
        }
        p++;
        if (len == 0) {
            if (written == 0 || buf[written - 1] != '.') { 
                if (written >= 256) return -1; 
                buf[written++] = '.'; 
            } 
            buf[written++] = '\0'; 
            break; 
        }
        if (written > 0 && buf[written - 1] != '.') { 
            if (written >= 256) return -1; 
            buf[written++] = '.'; 
        }
        if (written + len >= 256 || p + len > packet_len) return -1;
        memcpy(&buf[written], &packet[p], len); written += len; p += len;
    }
    *next_offset = jumped ? jumped_offset : p; 
    char *dst = arena_alloc(arena, written);
    if (!dst) return -1;
    memcpy(dst, buf, written);
    *name_out = dst; return 0;
}

const char *get_type_str(uint16_t type, zone_arena_t *arena) {
    switch (type) {
        case 1: return "A"; case 2: return "NS"; case 3: return "MD"; case 4: return "MF";
        case 5: return "CNAME"; case 6: return "SOA"; case 7: return "MB"; case 8: return "MG";
        case 9: return "MR"; case 10: return "NULL"; case 11: return "WKS"; case 12: return "PTR";
        case 13: return "HINFO"; case 14: return "MINFO"; case 15: return "MX"; case 16: return "TXT";
        case 17: return "RP"; case 18: return "AFSDB"; case 19: return "X25"; case 20: return "ISDN";
        case 21: return "RT"; case 22: return "NSAP"; case 23: return "NSAP-PTR"; case 24: return "SIG";
        case 25: return "KEY"; case 26: return "PX"; case 27: return "GPOS"; case 28: return "AAAA";
        case 29: return "LOC"; case 30: return "NXT"; case 31: return "EID"; case 32: return "NIMLOC";
        case 33: return "SRV"; case 34: return "ATMA"; case 35: return "NAPTR"; case 36: return "KX";
        case 37: return "CERT"; case 38: return "A6"; case 39: return "DNAME"; case 40: return "SINK";
        case 41: return "OPT"; case 42: return "APL"; case 43: return "DS"; case 44: return "SSHFP";
        case 45: return "IPSECKEY"; case 46: return "RRSIG"; case 47: return "NSEC"; case 48: return "DNSKEY";
        case 49: return "DHCID"; case 50: return "NSEC3"; case 51: return "NSEC3PARAM"; case 52: return "TLSA";
        case 53: return "SMIMEA"; case 55: return "HIP"; case 59: return "CDS"; case 60: return "CDNSKEY";
        case 61: return "OPENPGPKEY"; case 62: return "CSYNC"; case 63: return "ZONEMD"; case 64: return "SVCB";
        case 65: return "HTTPS"; case 99: return "SPF"; case 104: return "NID"; case 105: return "L32";
        case 106: return "L64"; case 107: return "LP"; case 108: return "EUI48"; case 109: return "EUI64";
        case 249: return "TKEY"; case 250: return "TSIG"; case 251: return "IXFR"; case 252: return "AXFR";
        case 253: return "MAILB"; case 254: return "MAILA"; case 255: return "ANY"; case 256: return "URI";
        case 257: return "CAA"; case 258: return "AVC"; case 259: return "DOA"; case 260: return "AMTRELAY";
        case 32768: return "TA"; case 32769: return "DLV";
        default: {
            char *buf = arena ? arena_alloc(arena, 16) : malloc(16);
            if (buf) snprintf(buf, 16, "TYPE%d", type);
            return buf;
        }
    }
}

int parse_resource_record(const uint8_t *packet, size_t packet_len, size_t *offset, zone_arena_t *arena, dns_record_t *rec, uint16_t *type_out) {
    char *name; if (expand_wire_name(packet, packet_len, *offset, offset, arena, &name) != 0) { syslog(LOG_ERR, "[AXFR] parse_resource_record: expand_wire_name failed for owner name"); return -1; }
    rec->name = name; if (*offset + 10 > packet_len) { syslog(LOG_ERR, "[AXFR] parse_resource_record: packet too short for header"); return -1; }
    uint16_t type = (packet[*offset] << 8) | packet[*offset + 1];
    uint16_t class_val = (packet[*offset + 2] << 8) | packet[*offset + 3];
    uint32_t ttl = ((uint32_t)packet[*offset + 4] << 24) | ((uint32_t)packet[*offset + 5] << 16) | ((uint32_t)packet[*offset + 6] << 8) | packet[*offset + 7];
    uint16_t rdlen = (packet[*offset + 8] << 8) | packet[*offset + 9]; *offset += 10;
    if (*offset + rdlen > packet_len) { syslog(LOG_ERR, "[AXFR] parse_resource_record: rdlen %u goes out of bounds (len=%zu)", rdlen, packet_len); return -1; }

    *type_out = type; rec->type_code = type; rec->class_str = (class_val == 1) ? "IN" : "CH"; rec->type = (char *)get_type_str(type, arena);
    char *ttl_buf = arena_alloc(arena, 16); if (!ttl_buf) return -1; snprintf(ttl_buf, 16, "%u", ttl); rec->ttl = ttl_buf;
    rec->rdata_count = 0;

    if (type == 6) {
        size_t rdata_p = *offset; char *mname, *rname;
        if (expand_wire_name(packet, packet_len, rdata_p, &rdata_p, arena, &mname) != 0) { syslog(LOG_ERR, "[AXFR] parse_resource_record: SOA mname expand failed"); return -1; }
        if (expand_wire_name(packet, packet_len, rdata_p, &rdata_p, arena, &rname) != 0) { syslog(LOG_ERR, "[AXFR] parse_resource_record: SOA rname expand failed"); return -1; }
        rec->rdata[0] = mname; rec->rdata[1] = rname; rec->rdata_count = 2;
        for (int j = 0; j < 5; j++) {
            if (rdata_p + 4 > *offset + rdlen) { syslog(LOG_ERR, "[AXFR] parse_resource_record: SOA numbers out of bounds"); return -1; }
            uint32_t val = ((uint32_t)packet[rdata_p] << 24) | ((uint32_t)packet[rdata_p+1] << 16) | ((uint32_t)packet[rdata_p+2] << 8) | packet[rdata_p+3];
            char *val_buf = arena_alloc(arena, 16); if (!val_buf) return -1; snprintf(val_buf, 16, "%u", val); rec->rdata[rec->rdata_count++] = val_buf; rdata_p += 4;
        }
    } else if (type == 1) {
        if (rdlen != 4) { syslog(LOG_ERR, "[AXFR] parse_resource_record: A record rdlen != 4"); return -1; }
        char *ip_buf = arena_alloc(arena, 16); if (!ip_buf) return -1;
        snprintf(ip_buf, 16, "%d.%d.%d.%d", packet[*offset], packet[*offset+1], packet[*offset+2], packet[*offset+3]);
        rec->rdata[0] = ip_buf; rec->rdata_count = 1;
    } else if (type == 2 || type == 5 || type == 12) {
        size_t rdata_p = *offset; char *target;
        if (expand_wire_name(packet, packet_len, rdata_p, &rdata_p, arena, &target) != 0) { syslog(LOG_ERR, "[AXFR] parse_resource_record: NAME expand failed"); return -1; }
        rec->rdata[0] = target; rec->rdata_count = 1;
    } else if (type == 15) {
        if (rdlen < 3) return -1;
        size_t rdata_p = *offset; char *target;
        uint16_t pref = (packet[rdata_p] << 8) | packet[rdata_p+1];
        rdata_p += 2;
        if (expand_wire_name(packet, packet_len, rdata_p, &rdata_p, arena, &target) != 0) return -1;
        char *pref_buf = arena_alloc(arena, 16); if (!pref_buf) return -1;
        snprintf(pref_buf, 16, "%u", pref);
        rec->rdata[0] = pref_buf; rec->rdata[1] = target; rec->rdata_count = 2;
    } else if (type == 16) {
        size_t rdata_p = *offset;
        while (rdata_p < *offset + rdlen) {
            if (rec->rdata_count >= MAX_RDATA) return -1;
            uint8_t len = packet[rdata_p++];
            if (rdata_p + len > *offset + rdlen) break;
            char *txt = arena_alloc(arena, len + 1); if (!txt) return -1;
            memcpy(txt, &packet[rdata_p], len); txt[len] = '\0';
            rec->rdata[rec->rdata_count++] = txt;
            rdata_p += len;
        }
    } else if (type == 28) {
        if (rdlen != 16) return -1;
        char *ip6_buf = arena_alloc(arena, INET6_ADDRSTRLEN); if (!ip6_buf) return -1;
        inet_ntop(AF_INET6, &packet[*offset], ip6_buf, INET6_ADDRSTRLEN);
        rec->rdata[0] = ip6_buf; rec->rdata_count = 1;
    } else {
        uint8_t *blob = (uint8_t *)arena_alloc(arena, rdlen);
        if (!blob) return -1;
        memcpy(blob, &packet[*offset], rdlen);
        rec->generic_data = blob;
        rec->generic_len = rdlen;
        rec->rdata_count = 0;
    }
    *offset += rdlen; return 0;
}

// ============================================================================
// TSIG ヘルパー
// ============================================================================

int const_time_memcmp(const void *a, const void *b, size_t len) {
    const unsigned char *p1 = a; const unsigned char *p2 = b;
    unsigned char res = 0;
    for (size_t i = 0; i < len; i++) res |= p1[i] ^ p2[i];
    return res == 0 ? 0 : 1;
}

long write_uncompressed_name(uint8_t *buf, size_t offset, size_t max_len, const char *name) {
    size_t w_len = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len > 63) return -1;
        if (len > 0) {
            if (offset + w_len + len + 1 > max_len) return -1;
            buf[offset + w_len++] = len;
            for (size_t i = 0; i < len; i++)
                buf[offset + w_len++] = (p[i] >= 'A' && p[i] <= 'Z') ? (p[i] | 0x20) : p[i];
        }
        if (!dot) break;
        p = dot + 1;
    }
    if (offset + w_len + 1 > max_len) return -1;
    buf[offset + w_len++] = 0;
    return (long)w_len;
}

static int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap) {
    size_t out_len = 0;
    int high = -1;
    for (const char *h = hex; *h; h++) {
        int v = hex_char_to_val(*h);
        if (v < 0) continue; // 空白/コロン等の区切り文字は無視
        if (high < 0) { high = v; continue; }
        if (out_len >= out_cap) return (size_t)-1; // 出力先超過
        out[out_len++] = (uint8_t)((high << 4) | v);
        high = -1;
    }
    return out_len;
}

static int cert_type_to_num(const char *s) {
    if (strcasecmp(s, "PKIX") == 0) return 1;
    if (strcasecmp(s, "SPKI") == 0) return 2;
    if (strcasecmp(s, "PGP") == 0) return 3;
    if (strcasecmp(s, "IPKIX") == 0) return 4;
    if (strcasecmp(s, "ISPKI") == 0) return 5;
    if (strcasecmp(s, "IPGP") == 0) return 6;
    if (strcasecmp(s, "ACPKIX") == 0) return 7;
    if (strcasecmp(s, "IACPKIX") == 0) return 8;
    if (strcasecmp(s, "URI") == 0) return 253;
    if (strcasecmp(s, "OID") == 0) return 254;
    return atoi(s);
}

int tsig_sign_packet(uint8_t *packet, size_t *packet_len, size_t max_len, tsig_key_t *key, uint16_t tsig_error, uint8_t *prior_mac, size_t *prior_mac_len, bool is_subsequent) {
    if (!key || *packet_len + 512 > max_len) return -1;
    size_t pre_mac_len = *packet_len;
    size_t pre_mac_cap = pre_mac_len + 512 + (key->algorithm ? strlen(key->algorithm) : 11) + strlen(key->name) + (prior_mac_len && *prior_mac_len > 0 ? *prior_mac_len + 2 : 0);
    uint8_t *pre_mac = malloc(pre_mac_cap);
    if (!pre_mac) return -1;
    size_t offset = 0;
    if (prior_mac_len && *prior_mac_len > 0) {
        pre_mac[offset++] = *prior_mac_len >> 8;
        pre_mac[offset++] = *prior_mac_len & 0xFF;
        memcpy(&pre_mac[offset], prior_mac, *prior_mac_len);
        offset += *prior_mac_len;
    }
    memcpy(&pre_mac[offset], packet, pre_mac_len);
    offset += pre_mac_len;
    const char *alg = key->algorithm ? key->algorithm : "hmac-sha256";
    if (!is_subsequent) {
        long w = write_uncompressed_name(pre_mac, offset, pre_mac_cap, key->name);
        if (w < 0) { free(pre_mac); return -1; }
        offset += (size_t)w;
        pre_mac[offset++] = 0; pre_mac[offset++] = 255;
        pre_mac[offset++] = 0; pre_mac[offset++] = 0; pre_mac[offset++] = 0; pre_mac[offset++] = 0;
        w = write_uncompressed_name(pre_mac, offset, pre_mac_cap, alg);
        if (w < 0) { free(pre_mac); return -1; }
        offset += (size_t)w;
    }
    uint64_t now = time(NULL);
    pre_mac[offset++] = (now >> 40) & 0xFF; pre_mac[offset++] = (now >> 32) & 0xFF;
    pre_mac[offset++] = (now >> 24) & 0xFF; pre_mac[offset++] = (now >> 16) & 0xFF;
    pre_mac[offset++] = (now >> 8) & 0xFF; pre_mac[offset++] = now & 0xFF;
    uint16_t fudge = 300;
    pre_mac[offset++] = fudge >> 8; pre_mac[offset++] = fudge & 0xFF;
    if (!is_subsequent) {
        pre_mac[offset++] = tsig_error >> 8; pre_mac[offset++] = tsig_error & 0xFF; // Error
        if (tsig_error == 18) {
            pre_mac[offset++] = 0; pre_mac[offset++] = 6; // Other Len
            uint64_t now_48 = time(NULL);
            pre_mac[offset++] = (now_48 >> 40) & 0xFF; pre_mac[offset++] = (now_48 >> 32) & 0xFF;
            pre_mac[offset++] = (now_48 >> 24) & 0xFF; pre_mac[offset++] = (now_48 >> 16) & 0xFF;
            pre_mac[offset++] = (now_48 >> 8) & 0xFF; pre_mac[offset++] = now_48 & 0xFF;
        } else {
            pre_mac[offset++] = 0; pre_mac[offset++] = 0; // Other Len
        }
    }
    unsigned int mac_len = 0; unsigned char mac[EVP_MAX_MD_SIZE];
    if (key->secret_decoded_len > 0) {
        const EVP_MD *evp_md = EVP_sha256();
        if (strstr(alg, "sha1")) evp_md = EVP_sha1();
        else if (strstr(alg, "sha512")) evp_md = EVP_sha512();
        else if (strstr(alg, "md5")) evp_md = EVP_md5();
        HMAC(evp_md, key->secret_decoded, key->secret_decoded_len, pre_mac, offset, mac, &mac_len);
    }
    free(pre_mac);
    
    if (prior_mac_len && prior_mac) {
        *prior_mac_len = mac_len;
        if (mac_len > 0) memcpy(prior_mac, mac, mac_len);
    }
    
    size_t p_offset = *packet_len;
    long w2 = write_uncompressed_name(packet, p_offset, max_len, key->name);
    if (w2 < 0) return -1;
    p_offset += (size_t)w2;
    packet[p_offset++] = 0; packet[p_offset++] = 250; // TSIG
    packet[p_offset++] = 0; packet[p_offset++] = 255; // ANY
    packet[p_offset++] = 0; packet[p_offset++] = 0; packet[p_offset++] = 0; packet[p_offset++] = 0; // TTL
    size_t rdata_len_idx = p_offset; p_offset += 2;
    w2 = write_uncompressed_name(packet, p_offset, max_len, alg);
    if (w2 < 0) return -1;
    p_offset += (size_t)w2;
    packet[p_offset++] = (now >> 40) & 0xFF; packet[p_offset++] = (now >> 32) & 0xFF;
    packet[p_offset++] = (now >> 24) & 0xFF; packet[p_offset++] = (now >> 16) & 0xFF;
    packet[p_offset++] = (now >> 8) & 0xFF; packet[p_offset++] = now & 0xFF;
    packet[p_offset++] = fudge >> 8; packet[p_offset++] = fudge & 0xFF;
    packet[p_offset++] = mac_len >> 8; packet[p_offset++] = mac_len & 0xFF;
    memcpy(&packet[p_offset], mac, mac_len); p_offset += mac_len;
    packet[p_offset++] = packet[0]; packet[p_offset++] = packet[1]; // Orig ID
    packet[p_offset++] = tsig_error >> 8; packet[p_offset++] = tsig_error & 0xFF; // Error
    if (tsig_error == 18) {
        packet[p_offset++] = 0; packet[p_offset++] = 6; // Other Len
        uint64_t now_48 = time(NULL);
        packet[p_offset++] = (now_48 >> 40) & 0xFF; packet[p_offset++] = (now_48 >> 32) & 0xFF;
        packet[p_offset++] = (now_48 >> 24) & 0xFF; packet[p_offset++] = (now_48 >> 16) & 0xFF;
        packet[p_offset++] = (now_48 >> 8) & 0xFF; packet[p_offset++] = now_48 & 0xFF;
    } else {
        packet[p_offset++] = 0; packet[p_offset++] = 0; // Other Len
    }
    uint16_t rdlen = p_offset - rdata_len_idx - 2;
    packet[rdata_len_idx] = rdlen >> 8; packet[rdata_len_idx+1] = rdlen & 0xFF;
    uint16_t arcount = (packet[10] << 8) | packet[11]; arcount++;
    packet[10] = arcount >> 8; packet[11] = arcount & 0xFF;
    *packet_len = p_offset;
    return 0;
}

int tsig_verify_packet(const uint8_t *packet, size_t packet_len, tsig_key_t *key, uint8_t *mac_out, size_t *mac_len_out) {
    if (!key || packet_len < 12) return -1;
    uint16_t arcount = (packet[10] << 8) | packet[11];
    if (arcount == 0) return -1;
    size_t offset = 12;
    uint16_t qdcount = (packet[4] << 8) | packet[5], ancount = (packet[6] << 8) | packet[7], nscount = (packet[8] << 8) | packet[9];
    for (int i = 0; i < qdcount; i++) {
        int jump_count = 0;
        while (offset < packet_len && packet[offset] != 0 && (packet[offset] & 0xC0) != 0xC0) {
            offset += packet[offset] + 1;
            if (++jump_count > 128) return -1;
        }
        if (offset < packet_len && (packet[offset] & 0xC0) == 0xC0) offset += 2; else offset++;
        offset += 4;
    }
    size_t last_rr_offset = 0;
    for (int i = 0; i < ancount + nscount + arcount; i++) {
        if (i == ancount + nscount + arcount - 1) last_rr_offset = offset;
        if (offset >= packet_len) return -1;
        int jump_count = 0;
        while (offset < packet_len && packet[offset] != 0 && (packet[offset] & 0xC0) != 0xC0) {
            offset += packet[offset] + 1;
            if (++jump_count > 128) return -1;
        }
        if (offset < packet_len && (packet[offset] & 0xC0) == 0xC0) offset += 2; else offset++;
        if (offset + 10 > packet_len) return -1;
        uint16_t rdlen = (packet[offset+8] << 8) | packet[offset+9];
        offset += 10 + rdlen;
    }
    if (last_rr_offset == 0 || offset > packet_len) return -1;
    size_t tsig_p = last_rr_offset;
    int jump_count = 0;
    while (tsig_p < packet_len && packet[tsig_p] != 0 && (packet[tsig_p] & 0xC0) != 0xC0) {
        tsig_p += packet[tsig_p] + 1;
        if (++jump_count > 128) return -1;
    }
    if (tsig_p < packet_len && (packet[tsig_p] & 0xC0) == 0xC0) tsig_p += 2; else tsig_p++;
    if (tsig_p + 10 > packet_len) return -1;
    uint16_t type = (packet[tsig_p] << 8) | packet[tsig_p+1];
    if (type != 250) return -1;
    tsig_p += 10;
    size_t alg_start = tsig_p; (void)alg_start;
    jump_count = 0;
    while (tsig_p < packet_len && packet[tsig_p] != 0) {
        tsig_p += packet[tsig_p] + 1;
        if (++jump_count > 128) return -1;
    }
    tsig_p++;
    if (tsig_p + 16 > packet_len) return -1;
    size_t time_fudge_start = tsig_p;
    uint64_t time_signed = 
        ((uint64_t)packet[time_fudge_start] << 40) | ((uint64_t)packet[time_fudge_start+1] << 32) |
        ((uint64_t)packet[time_fudge_start+2] << 24) | ((uint64_t)packet[time_fudge_start+3] << 16) |
        ((uint64_t)packet[time_fudge_start+4] << 8)  |  (uint64_t)packet[time_fudge_start+5];
    uint16_t fudge = (packet[time_fudge_start+6] << 8) | packet[time_fudge_start+7];
    uint64_t now = time(NULL);
    if (now > time_signed + fudge || now + fudge < time_signed) return 18; // BADTIME
    tsig_p += 8;
    uint16_t mac_size = (packet[tsig_p] << 8) | packet[tsig_p+1]; tsig_p += 2;
    if (tsig_p + mac_size + 6 > packet_len) return -1;
    const uint8_t *mac = &packet[tsig_p]; tsig_p += mac_size;
    uint16_t orig_id = (packet[tsig_p] << 8) | packet[tsig_p+1]; tsig_p += 2;
    uint16_t err = (packet[tsig_p] << 8) | packet[tsig_p+1]; tsig_p += 2;
    uint16_t other_len = (packet[tsig_p] << 8) | packet[tsig_p+1]; tsig_p += 2;
    if (tsig_p + other_len > packet_len) return -1;
    size_t pre_mac_cap = last_rr_offset + 512 + other_len;
    uint8_t *pre_mac = malloc(pre_mac_cap);
    if (!pre_mac) return -1;
    memcpy(pre_mac, packet, last_rr_offset);
    pre_mac[0] = orig_id >> 8; pre_mac[1] = orig_id & 0xFF;
    uint16_t new_arcount = arcount - 1;
    pre_mac[10] = new_arcount >> 8; pre_mac[11] = new_arcount & 0xFF;
    size_t p_offset = last_rr_offset;
    long w3 = write_uncompressed_name(pre_mac, p_offset, pre_mac_cap, key->name);
    if (w3 < 0) { free(pre_mac); return -1; }
    p_offset += (size_t)w3;
    pre_mac[p_offset++] = 0; pre_mac[p_offset++] = 255;
    pre_mac[p_offset++] = 0; pre_mac[p_offset++] = 0; pre_mac[p_offset++] = 0; pre_mac[p_offset++] = 0;
    const char *alg = key->algorithm ? key->algorithm : "hmac-sha256";
    w3 = write_uncompressed_name(pre_mac, p_offset, pre_mac_cap, alg);
    if (w3 < 0) { free(pre_mac); return -1; }
    p_offset += (size_t)w3;
    memcpy(&pre_mac[p_offset], &packet[time_fudge_start], 8); p_offset += 8;
    pre_mac[p_offset++] = err >> 8; pre_mac[p_offset++] = err & 0xFF;
    pre_mac[p_offset++] = other_len >> 8; pre_mac[p_offset++] = other_len & 0xFF;
    if (other_len > 0) { memcpy(&pre_mac[p_offset], &packet[tsig_p], other_len); p_offset += other_len; }
    unsigned int calc_mac_len = 0; unsigned char calc_mac[EVP_MAX_MD_SIZE];
    const EVP_MD *evp_md = EVP_sha256();
    if (strstr(alg, "sha1")) evp_md = EVP_sha1();
    else if (strstr(alg, "sha512")) evp_md = EVP_sha512();
    else if (strstr(alg, "md5")) evp_md = EVP_md5();
    HMAC(evp_md, key->secret_decoded, key->secret_decoded_len, pre_mac, p_offset, calc_mac, &calc_mac_len);
    free(pre_mac);
    if (calc_mac_len != mac_size) return 16; // BADSIG
    if (const_time_memcmp(calc_mac, mac, mac_size) != 0) return 16; // BADSIG
    if (mac_out && mac_len_out) {
        *mac_len_out = mac_size;
        memcpy(mac_out, mac, mac_size);
    }
    return 0;
}

// ============================================================================
// 7. インメモリDNSパケット高速処理・統合スタブ
// ============================================================================

int write_dns_name_str(uint8_t *packet_buf, uint16_t *offset, const char *name, compress_ctx_t *ctx, size_t max_len) {
    uint8_t wire[256];
    size_t w_len = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        if (!dot) {
            size_t len = strlen(p);
            if (len > 63) return -1;
            if (w_len + len + 1 > 255) return -1;
            wire[w_len++] = len;
            memcpy(&wire[w_len], p, len);
            w_len += len;
            break;
        } else {
            size_t len = dot - p;
            if (len > 63) return -1;
            if (len > 0) {
                if (w_len + len + 1 > 255) return -1;
                wire[w_len++] = len;
                memcpy(&wire[w_len], p, len);
                w_len += len;
            }
            p = dot + 1;
        }
    }
    if (w_len + 1 > 255) return -1;
    wire[w_len++] = 0;
    return compress_name(packet_buf, offset, wire, ctx, max_len);
}


// Type Bitmap (NSEC/NSEC3/CSYNC用) を構築するヘルパー
static int encode_type_bitmap(uint8_t *res, size_t max_res_len, uint16_t *offset, char **types, int type_count) {
    if (type_count == 0) return 0;
    
    uint16_t *codes = malloc(sizeof(uint16_t) * type_count);
    if (!codes) return -1;
    for (int i = 0; i < type_count; i++) {
        codes[i] = get_type_code(types[i]);
    }
    
    for (int i = 0; i < type_count - 1; i++) {
        for (int j = i + 1; j < type_count; j++) {
            if (codes[i] > codes[j]) {
                uint16_t tmp = codes[i];
                codes[i] = codes[j];
                codes[j] = tmp;
            }
        }
    }
    
    int current_window = -1;
    uint8_t bitmap[32] = {0};
    int max_bit_in_window = -1;
    
    for (int i = 0; i < type_count; i++) {
        uint16_t code = codes[i];
        if (code == 0) continue;
        int window = code / 256;
        int bit = code % 256;
        
        if (window != current_window) {
            if (current_window != -1) {
                size_t map_len = (max_bit_in_window / 8) + 1;
                if (*offset + 2 + map_len > max_res_len) { free(codes); return -1; }
                res[(*offset)++] = current_window;
                res[(*offset)++] = (uint8_t)map_len;
                memcpy(&res[*offset], bitmap, map_len);
                *offset += map_len;
            }
            current_window = window;
            memset(bitmap, 0, sizeof(bitmap));
            max_bit_in_window = bit;
        } else {
            if (bit > max_bit_in_window) max_bit_in_window = bit;
        }
        bitmap[bit / 8] |= (1 << (7 - (bit % 8)));
    }
    
    if (current_window != -1) {
        size_t map_len = (max_bit_in_window / 8) + 1;
        if (*offset + 2 + map_len > max_res_len) { free(codes); return -1; }
        res[(*offset)++] = current_window;
        res[(*offset)++] = (uint8_t)map_len;
        memcpy(&res[*offset], bitmap, map_len);
        *offset += map_len;
    }
    
    free(codes);
    return 0;
}

// 追加するヘルパー関数
static int write_char_string(uint8_t *res, size_t max_res_len, uint16_t *offset, const char *str) {
    size_t len = strlen(str);
    if (len > 255) len = 255;
    if (*offset + 1 + len > max_res_len) return -1;
    res[(*offset)++] = (uint8_t)len;
    memcpy(&res[*offset], str, len);
    *offset += len;
    return 0;
}

static int loc_parse_coord(char **rdata, int rdata_count, int *idx, double *out_seconds, char *dir_out) {
    double parts[3] = {0, 0, 0};
    int n = 0;
    while (n < 3 && *idx < rdata_count) {
        char *endptr;
        double v = strtod(rdata[*idx], &endptr);
        if (endptr == rdata[*idx] || *endptr != '\0') break; // 数値でなければ方角トークンとみなす
        parts[n++] = v;
        (*idx)++;
    }
    if (n == 0) return -1; // 度は必須
    if (*idx >= rdata_count) return -1; // 方角が無い
    char d = (char)toupper((unsigned char)rdata[*idx][0]);
    if (d != 'N' && d != 'S' && d != 'E' && d != 'W') return -1;
    (*idx)++;
    *dir_out = d;
    *out_seconds = parts[0] * 3600.0 + parts[1] * 60.0 + parts[2];
    return 0;
}

static const uint32_t loc_poweroften[10] = {
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000
};

static uint8_t loc_encode_precsize(double meters) {
    if (meters < 0) meters = 0;
    uint32_t cm = (uint32_t)llround(meters * 100.0);
    int exponent;
    for (exponent = 0; exponent < 9; exponent++) {
        if (cm < loc_poweroften[exponent + 1]) break;
    }
    uint32_t mantissa = cm / loc_poweroften[exponent];
    if (mantissa > 9) mantissa = 9;
    return (uint8_t)((mantissa << 4) | exponent);
}

int serialize_dns_record(uint8_t *res, size_t max_res_len, uint16_t *offset_ptr, dns_record_t *rec, compress_ctx_t *comp_ctx, const char *owner_name, uint32_t override_ttl) {
    uint16_t offset = *offset_ptr;
    uint16_t rec_type = rec->type_code;

    if (offset + 12 > max_res_len) return -1; // TC bit needed

    if (write_dns_name_str(res, &offset, owner_name ? owner_name : rec->name, comp_ctx, max_res_len) != 0) {
        return -1;
    }

    if (offset + 10 > max_res_len) return -1;

    res[offset++] = rec_type >> 8; res[offset++] = rec_type & 0xFF;
    res[offset++] = 0; res[offset++] = 1; // IN
    
    uint32_t ttl = rec->ttl ? (uint32_t)strtoul(rec->ttl, NULL, 10) : 3600;
    if (override_ttl != 0xFFFFFFFF && override_ttl < ttl) ttl = override_ttl;
    
    res[offset++] = ttl >> 24; res[offset++] = (ttl >> 16) & 0xFF; res[offset++] = (ttl >> 8) & 0xFF; res[offset++] = ttl & 0xFF;

    uint16_t rdlength_idx = offset;
    offset += 2; // reserve for rdlength

    if (rec->generic_data && rec->generic_len > 0) {
        if (offset + rec->generic_len > max_res_len) return -1;
        memcpy(&res[offset], rec->generic_data, rec->generic_len);
        offset += rec->generic_len;
    } else {
        switch (rec_type) {
            case 1: { // A
                if (rec->rdata_count == 0) return -1;
                if (offset + 4 > max_res_len) return -1;
                struct in_addr addr; inet_pton(AF_INET, rec->rdata[0], &addr);
                memcpy(&res[offset], &addr.s_addr, 4); offset += 4;
                break;
            }
            case 28: { // AAAA
                if (rec->rdata_count == 0) return -1;
                if (offset + 16 > max_res_len) return -1;
                struct in6_addr addr; inet_pton(AF_INET6, rec->rdata[0], &addr);
                memcpy(&res[offset], &addr.s6_addr, 16); offset += 16;
                break;
            }
            case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: { // NS, MD, MF, CNAME, MB, MG, MR, PTR
                if (rec->rdata_count == 0) return -1;
                if (write_dns_name_str(res, &offset, rec->rdata[0], comp_ctx, max_res_len) != 0 || offset > max_res_len) return -1;
                break;
            }
            case 39: { // DNAME (RFC 6672: 圧縮禁止)
                if (rec->rdata_count == 0) return -1;
                long w = write_uncompressed_name(res, offset, max_res_len, rec->rdata[0]);
                if (w < 0) return -1;
                offset += w;
                break;
            }
            case 15: { // MX
                if (rec->rdata_count < 2) return -1;
                if (offset + 2 > max_res_len) return -1;
                uint16_t pref = atoi(rec->rdata[0]);
                res[offset++] = pref >> 8; res[offset++] = pref & 0xFF;
                if (write_dns_name_str(res, &offset, rec->rdata[1], comp_ctx, max_res_len) != 0 || offset > max_res_len) return -1;
                break;
            }
            case 33: { // SRV (RFC 2782: 圧縮禁止)
                if (rec->rdata_count < 4) return -1;
                if (offset + 6 > max_res_len) return -1;
                uint16_t prio = atoi(rec->rdata[0]);
                uint16_t weight = atoi(rec->rdata[1]);
                uint16_t port = atoi(rec->rdata[2]);
                res[offset++] = prio >> 8; res[offset++] = prio & 0xFF;
                res[offset++] = weight >> 8; res[offset++] = weight & 0xFF;
                res[offset++] = port >> 8; res[offset++] = port & 0xFF;
                long w = write_uncompressed_name(res, offset, max_res_len, rec->rdata[3]);
                if (w < 0) return -1;
                offset += w;
                break;
            }
            case 29: { // LOC
                if (offset + 16 > max_res_len) return -1;

                int idx = 0;
                double lat_sec, lon_sec;
                char lat_dir, lon_dir;
                if (loc_parse_coord(rec->rdata, rec->rdata_count, &idx, &lat_sec, &lat_dir) != 0) return -1;
                if (lat_dir != 'N' && lat_dir != 'S') return -1; // 1つ目は南北のみ許可
                if (loc_parse_coord(rec->rdata, rec->rdata_count, &idx, &lon_sec, &lon_dir) != 0) return -1;
                if (lon_dir != 'E' && lon_dir != 'W') return -1; // 2つ目は東西のみ許可

                // 度分秒の合計が範囲内か(緯度0-90度=0-324000秒、経度0-180度=0-648000秒)
                if (lat_sec < 0 || lat_sec > 324000.0) return -1;
                if (lon_sec < 0 || lon_sec > 648000.0) return -1;

                double alt_m = 0, size_m = 1, hp_m = 10000, vp_m = 10;
                if (idx < rec->rdata_count) alt_m  = strtod(rec->rdata[idx++], NULL);
                if (idx < rec->rdata_count) size_m = strtod(rec->rdata[idx++], NULL);
                if (idx < rec->rdata_count) hp_m   = strtod(rec->rdata[idx++], NULL);
                if (idx < rec->rdata_count) vp_m   = strtod(rec->rdata[idx++], NULL);

                uint8_t size_b = loc_encode_precsize(size_m);
                uint8_t hp_b   = loc_encode_precsize(hp_m);
                uint8_t vp_b   = loc_encode_precsize(vp_m);

                int64_t lat_signed = (int64_t)llround(lat_sec * 1000.0) * (lat_dir == 'S' ? -1 : 1);
                int64_t lon_signed = (int64_t)llround(lon_sec * 1000.0) * (lon_dir == 'W' ? -1 : 1);
                uint32_t lat_wire = (uint32_t)(0x80000000LL + lat_signed);
                uint32_t lon_wire = (uint32_t)(0x80000000LL + lon_signed);
                uint32_t alt_wire = (uint32_t)(llround(alt_m * 100.0) + 10000000LL);

                res[offset++] = 0; // VERSION
                res[offset++] = size_b;
                res[offset++] = hp_b;
                res[offset++] = vp_b;
                res[offset++] = lat_wire >> 24; res[offset++] = lat_wire >> 16;
                res[offset++] = lat_wire >> 8;  res[offset++] = lat_wire;
                res[offset++] = lon_wire >> 24; res[offset++] = lon_wire >> 16;
                res[offset++] = lon_wire >> 8;  res[offset++] = lon_wire;
                res[offset++] = alt_wire >> 24; res[offset++] = alt_wire >> 16;
                res[offset++] = alt_wire >> 8;  res[offset++] = alt_wire;
                break;
            }
            case 42: { // APL
                for (int i = 0; i < rec->rdata_count; i++) {
                    char item_buf[300];
                    strncpy(item_buf, rec->rdata[i], sizeof(item_buf) - 1);
                    item_buf[sizeof(item_buf) - 1] = '\0';

                    char *p = item_buf;
                    bool negate = false;
                    if (*p == '!') { negate = true; p++; }

                    char *colon = strchr(p, ':');
                    if (!colon) return -1;
                    int afi = atoi(p);
                    char *addr_prefix = colon + 1;
                    char *slash = strchr(addr_prefix, '/');
                    if (!slash) return -1;
                    *slash = '\0';
                    int prefix = atoi(slash + 1);

                    uint8_t addr_bytes[16];
                    int addr_len;
                    if (afi == 1) {
                        struct in_addr a;
                        if (inet_pton(AF_INET, addr_prefix, &a) != 1) return -1;
                        if (prefix < 0 || prefix > 32) return -1;
                        memcpy(addr_bytes, &a.s_addr, 4);
                        addr_len = 4;
                    } else if (afi == 2) {
                        struct in6_addr a;
                        if (inet_pton(AF_INET6, addr_prefix, &a) != 1) return -1;
                        if (prefix < 0 || prefix > 128) return -1;
                        memcpy(addr_bytes, &a.s6_addr, 16);
                        addr_len = 16;
                    } else {
                        return -1; // 未対応のAddress Family
                    }

                    // 末尾ゼロバイトを省略
                    int afdlength = addr_len;
                    while (afdlength > 0 && addr_bytes[afdlength - 1] == 0) afdlength--;

                    if (offset + 4 + (size_t)afdlength > max_res_len) return -1;
                    res[offset++] = (afi >> 8) & 0xFF; res[offset++] = afi & 0xFF;
                    res[offset++] = (uint8_t)prefix;
                    res[offset++] = (uint8_t)((negate ? 0x80 : 0) | (afdlength & 0x7F));
                    memcpy(&res[offset], addr_bytes, (size_t)afdlength);
                    offset += afdlength;
                }
                break;
            }
            case 257: { // CAA
                if (rec->rdata_count < 3) return -1;
                uint8_t flags = atoi(rec->rdata[0]);
                size_t tag_len = strlen(rec->rdata[1]);
                if (tag_len > 255) tag_len = 255;
                size_t val_len = strlen(rec->rdata[2]);
                if (offset + 2 + tag_len + val_len > max_res_len) return -1;
                
                res[offset++] = flags;
                res[offset++] = tag_len;
                memcpy(&res[offset], rec->rdata[1], tag_len); offset += tag_len;
                memcpy(&res[offset], rec->rdata[2], val_len); offset += val_len;
                break;
            }
            case 6: { // SOA
                if (rec->rdata_count < 7) return -1;
                if (write_dns_name_str(res, &offset, rec->rdata[0], comp_ctx, max_res_len) != 0 ||
                    write_dns_name_str(res, &offset, rec->rdata[1], comp_ctx, max_res_len) != 0) return -1;
                if (offset + 20 > max_res_len) return -1;
                for (int j = 2; j < 7; j++) {
                    uint32_t val = strtoul(rec->rdata[j], NULL, 10);
                    res[offset++] = val >> 24; res[offset++] = (val >> 16) & 0xFF; res[offset++] = (val >> 8) & 0xFF; res[offset++] = val & 0xFF;
                }
                break;
            }
            case 16: case 99: case 258: { // TXT, SPF, AVC
                if (rec->rdata_count == 0) return -1;
                size_t required = 0;
                for (int j = 0; j < rec->rdata_count; j++) {
                    size_t len = strlen(rec->rdata[j]);
                    size_t chunks = (len + 254) / 255;
                    if (chunks == 0) chunks = 1;
                    required += chunks + len;
                }
                if (offset + required > max_res_len) return -1;
                
                for (int j = 0; j < rec->rdata_count; j++) {
                    size_t len = strlen(rec->rdata[j]);
                    const char *str = rec->rdata[j];
                    if (len == 0) {
                        res[offset++] = 0;
                    } else {
                        while (len > 0) {
                            size_t chunk_len = (len > 255) ? 255 : len;
                            res[offset++] = chunk_len;
                            memcpy(&res[offset], str, chunk_len);
                            offset += chunk_len;
                            str += chunk_len;
                            len -= chunk_len;
                        }
                    }
                }
                break;
            }
            case 45: { // IPSECKEY
                if (rec->rdata_count < 3) return -1;
                uint8_t prec = atoi(rec->rdata[0]);
                uint8_t gw_type = atoi(rec->rdata[1]);
                uint8_t alg = atoi(rec->rdata[2]);
                if (offset + 3 > max_res_len) return -1;
                res[offset++] = prec; res[offset++] = gw_type; res[offset++] = alg;
                
                int pk_idx = 3;
                if (gw_type == 1) { // IPv4
                    if (rec->rdata_count < 5) return -1;
                    if (offset + 4 > max_res_len) return -1;
                    struct in_addr addr;
                    if (inet_pton(AF_INET, rec->rdata[3], &addr) != 1) return -1;
                    memcpy(&res[offset], &addr.s_addr, 4); offset += 4;
                    pk_idx = 4;
                } else if (gw_type == 2) { // IPv6
                    if (rec->rdata_count < 5) return -1;
                    if (offset + 16 > max_res_len) return -1;
                    struct in6_addr addr;
                    if (inet_pton(AF_INET6, rec->rdata[3], &addr) != 1) return -1;
                    memcpy(&res[offset], &addr.s6_addr, 16); offset += 16;
                    pk_idx = 4;
                } else if (gw_type == 3) { // Domain name
                    if (rec->rdata_count < 5) return -1;
                    long w = write_uncompressed_name(res, offset, max_res_len, rec->rdata[3]);
                    if (w < 0) return -1;
                    offset += (size_t)w;
                    pk_idx = 4;
                } else if (gw_type != 0) {
                    return -1;
                }
                
                if (pk_idx < rec->rdata_count) {
                    const char *b64 = rec->rdata[pk_idx];
                    size_t b64_len = strlen(b64);
                    size_t decoded_upper_bound = (b64_len / 4) * 3;
                    if (offset + decoded_upper_bound > max_res_len) return -1;
                    int declen = EVP_DecodeBlock(&res[offset], (const unsigned char *)b64, b64_len);
                    if (declen < 0) return -1;
                    int padding = 0;
                    if (b64_len > 0 && b64[b64_len - 1] == '=') padding++;
                    if (b64_len > 1 && b64[b64_len - 2] == '=') padding++;
                    offset += (declen - padding);
                }
                break;
            }
            case 260: { // AMTRELAY
                if (rec->rdata_count < 3) return -1;
                uint8_t prec = atoi(rec->rdata[0]);
                uint8_t dbit = atoi(rec->rdata[1]);
                if (dbit > 1) return -1;
                uint8_t type = atoi(rec->rdata[2]);
                if (offset + 2 > max_res_len) return -1;
                res[offset++] = prec;
                res[offset++] = (dbit << 7) | (type & 0x7F);
                
                if (type == 1) { // IPv4
                    if (rec->rdata_count < 4) return -1;
                    if (offset + 4 > max_res_len) return -1;
                    struct in_addr addr;
                    if (inet_pton(AF_INET, rec->rdata[3], &addr) != 1) return -1;
                    memcpy(&res[offset], &addr.s_addr, 4); offset += 4;
                } else if (type == 2) { // IPv6
                    if (rec->rdata_count < 4) return -1;
                    if (offset + 16 > max_res_len) return -1;
                    struct in6_addr addr;
                    if (inet_pton(AF_INET6, rec->rdata[3], &addr) != 1) return -1;
                    memcpy(&res[offset], &addr.s6_addr, 16); offset += 16;
                } else if (type == 3) { // Domain name
                    if (rec->rdata_count < 4) return -1;
                    long w = write_uncompressed_name(res, offset, max_res_len, rec->rdata[3]);
                    if (w < 0) return -1;
                    offset += (size_t)w;
                } else if (type != 0) {
                    return -1;
                }
                break;
            }
            case 104: { // NID
                if (rec->rdata_count < 2) return -1;
                if (offset + 10 > max_res_len) return -1;
                uint16_t pref = atoi(rec->rdata[0]);
                res[offset++] = pref >> 8; res[offset++] = pref & 0xFF;
                uint8_t nodeid[8];
                if (hex_decode(rec->rdata[1], nodeid, 8) != 8) return -1;
                memcpy(&res[offset], nodeid, 8); offset += 8;
                break;
            }
            case 105: { // L32
                if (rec->rdata_count < 2) return -1;
                if (offset + 6 > max_res_len) return -1;
                uint16_t pref = atoi(rec->rdata[0]);
                res[offset++] = pref >> 8; res[offset++] = pref & 0xFF;
                struct in_addr addr;
                if (inet_pton(AF_INET, rec->rdata[1], &addr) != 1) return -1;
                memcpy(&res[offset], &addr.s_addr, 4); offset += 4;
                break;
            }
            case 106: { // L64
                if (rec->rdata_count < 2) return -1;
                if (offset + 10 > max_res_len) return -1;
                uint16_t pref = atoi(rec->rdata[0]);
                res[offset++] = pref >> 8; res[offset++] = pref & 0xFF;
                uint8_t loc64[8];
                if (hex_decode(rec->rdata[1], loc64, 8) != 8) return -1;
                memcpy(&res[offset], loc64, 8); offset += 8;
                break;
            }
            case 44: { // SSHFP
                if (rec->rdata_count < 3) return -1;
                uint8_t alg = atoi(rec->rdata[0]);
                uint8_t fptype = atoi(rec->rdata[1]);
                uint8_t fp[64]; 
                size_t fp_len = hex_decode(rec->rdata[2], fp, sizeof(fp));
                if (fp_len == (size_t)-1) return -1;
                if (offset + 2 + fp_len > max_res_len) return -1;
                res[offset++] = alg;
                res[offset++] = fptype;
                memcpy(&res[offset], fp, fp_len);
                offset += fp_len;
                break;
            }
            case 52: case 53: { // TLSA / SMIMEA
                if (rec->rdata_count < 4) return -1;
                uint8_t usage = atoi(rec->rdata[0]);
                uint8_t selector = atoi(rec->rdata[1]);
                uint8_t matching = atoi(rec->rdata[2]);
                uint8_t cad[512]; 
                size_t cad_len = hex_decode(rec->rdata[3], cad, sizeof(cad));
                if (cad_len == (size_t)-1) return -1;
                if (offset + 3 + cad_len > max_res_len) return -1;
                res[offset++] = usage;
                res[offset++] = selector;
                res[offset++] = matching;
                memcpy(&res[offset], cad, cad_len);
                offset += cad_len;
                break;
            }
            case 37: { // CERT
                if (rec->rdata_count < 4) return -1;
                uint16_t cert_type = cert_type_to_num(rec->rdata[0]);
                uint16_t key_tag = atoi(rec->rdata[1]);
                uint8_t algorithm = atoi(rec->rdata[2]);
                const char *b64 = rec->rdata[3];
                size_t b64_len = strlen(b64);
                size_t decoded_upper_bound = (b64_len / 4) * 3;
                if (offset + 5 + decoded_upper_bound > max_res_len) return -1;
                res[offset++] = cert_type >> 8; res[offset++] = cert_type & 0xFF;
                res[offset++] = key_tag >> 8; res[offset++] = key_tag & 0xFF;
                res[offset++] = algorithm;
                int declen = EVP_DecodeBlock(&res[offset], (const unsigned char *)b64, b64_len);
                if (declen < 0) return -1;
                int padding = 0;
                if (b64_len > 0 && b64[b64_len - 1] == '=') padding++;
                if (b64_len > 1 && b64[b64_len - 2] == '=') padding++;
                offset += (declen - padding);
                break;
            }
            case 35: { // NAPTR
                if (rec->rdata_count < 6) return -1;
                if (offset + 4 > max_res_len) return -1;
                uint16_t order = atoi(rec->rdata[0]);
                uint16_t pref  = atoi(rec->rdata[1]);
                res[offset++] = order >> 8; res[offset++] = order & 0xFF;
                res[offset++] = pref >> 8;  res[offset++] = pref & 0xFF;
                const char *cstrs[3] = { rec->rdata[2], rec->rdata[3], rec->rdata[4] };
                for (int k = 0; k < 3; k++) {
                    if (write_char_string(res, max_res_len, &offset, cstrs[k]) != 0) return -1;
                }
                long w = write_uncompressed_name(res, offset, max_res_len, rec->rdata[5]);
                if (w < 0) return -1;
                offset += (size_t)w;
                break;
            }
            case 51: { // NSEC3PARAM
                if (rec->rdata_count < 4) return -1;
                uint8_t halg = atoi(rec->rdata[0]);
                uint8_t flags = atoi(rec->rdata[1]);
                uint16_t iterations = atoi(rec->rdata[2]);
                uint8_t salt[255];
                size_t salt_len = 0;
                if (strcmp(rec->rdata[3], "-") != 0) {
                    salt_len = hex_decode(rec->rdata[3], salt, sizeof(salt));
                    if (salt_len == (size_t)-1) return -1;
                }
                if (offset + 5 + salt_len > max_res_len) return -1;
                res[offset++] = halg;
                res[offset++] = flags;
                res[offset++] = iterations >> 8; res[offset++] = iterations & 0xFF;
                res[offset++] = (uint8_t)salt_len;
                memcpy(&res[offset], salt, salt_len); offset += salt_len;
                break;
            }
            case 64: case 65: { // HTTPS / SVCB (RFC 9460: 圧縮禁止)
                if (rec->rdata_count < 2) return -1;
                if (offset + 2 > max_res_len) return -1;
                uint16_t svc_prio = atoi(rec->rdata[0]);
                res[offset++] = svc_prio >> 8; res[offset++] = svc_prio & 0xFF;
                long w = write_uncompressed_name(res, offset, max_res_len, rec->rdata[1]);
                if (w < 0) return -1;
                offset += w;
                break;
            }
            case 13: { // HINFO
                if (rec->rdata_count < 2) return -1;
                if (write_char_string(res, max_res_len, &offset, rec->rdata[0]) != 0) return -1;
                if (write_char_string(res, max_res_len, &offset, rec->rdata[1]) != 0) return -1;
                break;
            }
            case 256: { // URI
                if (rec->rdata_count < 3) return -1;
                uint16_t prio = atoi(rec->rdata[0]);
                uint16_t weight = atoi(rec->rdata[1]);
                const char *target = rec->rdata[2];
                size_t tlen = strlen(target);
                if (offset + 4 + tlen > max_res_len) return -1;
                res[offset++] = prio >> 8; res[offset++] = prio & 0xFF;
                res[offset++] = weight >> 8; res[offset++] = weight & 0xFF;
                memcpy(&res[offset], target, tlen);
                offset += tlen;
                break;
            }
            case 61: case 49: { // OPENPGPKEY, DHCID
                if (rec->rdata_count < 1) return -1;
                const char *b64 = rec->rdata[0];
                size_t b64_len = strlen(b64);
                size_t decoded_upper_bound = (b64_len / 4) * 3;
                if (offset + decoded_upper_bound > max_res_len) return -1;
                int declen = EVP_DecodeBlock(&res[offset], (const unsigned char *)b64, b64_len);
                if (declen < 0) return -1;
                int padding = 0;
                if (b64_len > 0 && b64[b64_len - 1] == '=') padding++;
                if (b64_len > 1 && b64[b64_len - 2] == '=') padding++;
                offset += (declen - padding);
                break;
            }
            case 108: case 109: { // EUI48, EUI64
                if (rec->rdata_count < 1) return -1;
                size_t expected = (rec_type == 108) ? 6 : 8;
                if (offset + expected > max_res_len) return -1;
                uint8_t eui[16];
                size_t dec_len = hex_decode(rec->rdata[0], eui, sizeof(eui));
                if (dec_len != expected) return -1;
                memcpy(&res[offset], eui, expected);
                offset += expected;
                break;
            }
            case 63: { // ZONEMD
                if (rec->rdata_count < 4) return -1;
                uint32_t serial = strtoul(rec->rdata[0], NULL, 10);
                uint8_t scheme = atoi(rec->rdata[1]);
                uint8_t halg = atoi(rec->rdata[2]);
                uint8_t digest[512];
                size_t digest_len = hex_decode(rec->rdata[3], digest, sizeof(digest));
                if (digest_len == (size_t)-1) return -1;
                if (offset + 6 + digest_len > max_res_len) return -1;
                res[offset++] = serial >> 24; res[offset++] = (serial >> 16) & 0xFF;
                res[offset++] = (serial >> 8) & 0xFF; res[offset++] = serial & 0xFF;
                res[offset++] = scheme;
                res[offset++] = halg;
                memcpy(&res[offset], digest, digest_len);
                offset += digest_len;
                break;
            }

            case 14: { // MINFO
                if (rec->rdata_count < 2) return -1;
                if (write_dns_name_str(res, &offset, rec->rdata[0], comp_ctx, max_res_len) != 0 || offset > max_res_len) return -1;
                if (write_dns_name_str(res, &offset, rec->rdata[1], comp_ctx, max_res_len) != 0 || offset > max_res_len) return -1;
                break;
            }
            case 17: { // RP
                if (rec->rdata_count < 2) return -1;
                long w1 = write_uncompressed_name(res, offset, max_res_len, rec->rdata[0]);
                if (w1 < 0) return -1;
                offset += w1;
                long w2 = write_uncompressed_name(res, offset, max_res_len, rec->rdata[1]);
                if (w2 < 0) return -1;
                offset += w2;
                break;
            }
            case 18: case 21: case 36: case 107: { // AFSDB, RT, KX, LP
                if (rec->rdata_count < 2) return -1;
                if (offset + 2 > max_res_len) return -1;
                uint16_t pref = atoi(rec->rdata[0]);
                res[offset++] = pref >> 8; res[offset++] = pref & 0xFF;
                long w = write_uncompressed_name(res, offset, max_res_len, rec->rdata[1]);
                if (w < 0) return -1;
                offset += w;
                break;
            }
            case 26: { // PX
                if (rec->rdata_count < 3) return -1;
                if (offset + 2 > max_res_len) return -1;
                uint16_t pref = atoi(rec->rdata[0]);
                res[offset++] = pref >> 8; res[offset++] = pref & 0xFF;
                long w1 = write_uncompressed_name(res, offset, max_res_len, rec->rdata[1]);
                if (w1 < 0) return -1;
                offset += w1;
                long w2 = write_uncompressed_name(res, offset, max_res_len, rec->rdata[2]);
                if (w2 < 0) return -1;
                offset += w2;
                break;
            }
            case 62: { // CSYNC
                if (rec->rdata_count < 3) return -1; // Serial, Flags, at least one type
                uint32_t serial = strtoul(rec->rdata[0], NULL, 10);
                uint16_t flags = atoi(rec->rdata[1]);
                if (offset + 6 > max_res_len) return -1;
                res[offset++] = serial >> 24; res[offset++] = (serial >> 16) & 0xFF;
                res[offset++] = (serial >> 8) & 0xFF; res[offset++] = serial & 0xFF;
                res[offset++] = flags >> 8; res[offset++] = flags & 0xFF;
                if (encode_type_bitmap(res, max_res_len, &offset, &rec->rdata[2], rec->rdata_count - 2) != 0) return -1;
                break;
            }
            case 43: case 59: { // DS, CDS
                if (rec->rdata_count < 4) return -1;
                uint16_t keytag = atoi(rec->rdata[0]);
                uint8_t alg = atoi(rec->rdata[1]);
                uint8_t dtype = atoi(rec->rdata[2]);
                if (offset + 4 > max_res_len) return -1;
                res[offset++] = keytag >> 8; res[offset++] = keytag & 0xFF;
                res[offset++] = alg;
                res[offset++] = dtype;
                
                char hex[1024] = "";
                for (int i = 3; i < rec->rdata_count; i++) {
                    if (strlen(hex) + strlen(rec->rdata[i]) < sizeof(hex)) strcat(hex, rec->rdata[i]);
                }
                size_t dec_len = hex_decode(hex, &res[offset], max_res_len - offset);
                if (dec_len == (size_t)-1) return -1;
                offset += dec_len;
                break;
            }
            case 48: case 60: { // DNSKEY, CDNSKEY
                if (rec->rdata_count < 4) return -1;
                uint16_t flags = atoi(rec->rdata[0]);
                uint8_t proto = atoi(rec->rdata[1]);
                uint8_t alg = atoi(rec->rdata[2]);
                if (offset + 4 > max_res_len) return -1;
                res[offset++] = flags >> 8; res[offset++] = flags & 0xFF;
                res[offset++] = proto;
                res[offset++] = alg;
                
                char b64[2048] = "";
                for (int i = 3; i < rec->rdata_count; i++) {
                    if (strlen(b64) + strlen(rec->rdata[i]) < sizeof(b64)) strcat(b64, rec->rdata[i]);
                }
                size_t b64_len = strlen(b64);
                size_t decoded_upper_bound = (b64_len / 4) * 3;
                if (offset + decoded_upper_bound > max_res_len) return -1;
                int declen = EVP_DecodeBlock(&res[offset], (const unsigned char *)b64, b64_len);
                if (declen < 0) return -1;
                int padding = 0;
                if (b64_len > 0 && b64[b64_len - 1] == '=') padding++;
                if (b64_len > 1 && b64[b64_len - 2] == '=') padding++;
                offset += (declen - padding);
                break;
            }
            default: {
                // [安全装置] 汎用フォーマット(generic_data)を持たず、ネイティブのシリアライズ方法も未定義のレコード
                // 低レイヤー関数であるためログ出力は行わず、上位層にエラー状態のみを伝播させる
                return -1;
            }
        }
    }
    
    uint16_t rdlength = offset - rdlength_idx - 2;
    res[rdlength_idx] = rdlength >> 8; res[rdlength_idx+1] = rdlength & 0xFF;
    
    *offset_ptr = offset;
    return 0;
}

// ============================================================================
// EDNS 処理 (process_dns_query から切り出し)
// ============================================================================

int parse_edns_opt(const uint8_t *req, size_t req_len,
                    uint16_t qdcount, uint16_t ancount_req,
                    uint16_t nscount_req, uint16_t arcount_req,
                    edns_info_t *edns) {
    memset(edns, 0, sizeof(edns_info_t));
    edns->udp_payload_size = 512;

    size_t scan_offset = 12;
    for (int i = 0; i < qdcount + ancount_req + nscount_req + arcount_req; i++) {
        if (scan_offset >= req_len) break;
        bool is_opt = (i >= qdcount + ancount_req + nscount_req);
        
        while (scan_offset < req_len) {
            uint8_t len = req[scan_offset];
            if (len == 0) { scan_offset++; break; }
            if ((len & 0xC0) == 0xC0) { scan_offset += 2; break; }
            if (scan_offset + len + 1 > req_len) return -1;
            scan_offset += len + 1;
        }
        
        if (i < qdcount) {
            scan_offset += 4;
        } else {
            if (scan_offset + 10 <= req_len) {
                uint16_t rtype = (req[scan_offset] << 8) | req[scan_offset+1];
                uint16_t rclass = (req[scan_offset+2] << 8) | req[scan_offset+3];
                uint32_t ttl = ((uint32_t)req[scan_offset+4] << 24) |
                               ((uint32_t)req[scan_offset+5] << 16) |
                               ((uint32_t)req[scan_offset+6] << 8) |
                               req[scan_offset+7];
                uint16_t rdlen = (req[scan_offset+8] << 8) | req[scan_offset+9];
                
                if (is_opt && rtype == 41) {
                    edns->present = true;
                    edns->udp_payload_size = rclass;
                    edns->ext_rcode = (ttl >> 24) & 0xFF;
                    edns->version = (ttl >> 16) & 0xFF;
                    edns->dnssec_ok = (ttl & 0x00008000) != 0;
                    
                    size_t rdata_offset = scan_offset + 10;
                    size_t rdata_end = rdata_offset + rdlen;
                    if (rdata_end > req_len) return -1; // Truncated OPT record
                    
                    while (rdata_offset + 4 <= rdata_end) {
                        uint16_t opt_code = (req[rdata_offset] << 8) | req[rdata_offset+1];
                        uint16_t opt_len = (req[rdata_offset+2] << 8) | req[rdata_offset+3];
                        rdata_offset += 4;
                        if (rdata_offset + opt_len > rdata_end) break;
                        
                        if (opt_code == 10) { // DNS Cookie
                            if (opt_len >= 8) {
                                edns->has_cookie = true;
                                memcpy(edns->client_cookie, req + rdata_offset, 8);
                                if (opt_len > 8) {
                                    edns->server_cookie_len = opt_len - 8;
                                    if (edns->server_cookie_len > sizeof(edns->server_cookie))
                                        edns->server_cookie_len = sizeof(edns->server_cookie);
                                    memcpy(edns->server_cookie, req + rdata_offset + 8, edns->server_cookie_len);
                                }
                            }
                        } else if (opt_code == 15) { // Extended DNS Error
                            if (opt_len >= 2) {
                                if (edns->ede_count < MAX_EDE_COUNT) {
                                    parsed_ede_t *ede = &edns->ede_list[edns->ede_count++];
                                    ede->code = (req[rdata_offset] << 8) | req[rdata_offset+1];
                                    ede->text[0] = '\0';
                                    if (opt_len > 2) {
                                        size_t text_len = opt_len - 2;
                                        if (text_len >= sizeof(ede->text)) {
                                            text_len = sizeof(ede->text) - 1;
                                        }
                                        memcpy(ede->text, req + rdata_offset + 2, text_len);
                                        ede->text[text_len] = '\0';
                                    }
                                }
                            }
                        }
                        rdata_offset += opt_len;
                    }
                    break;
                }
                scan_offset += 10 + rdlen;
            }
        }
    }
    return 0;
}

void assemble_edns_opt(uint8_t *res, size_t max_res_len,
                       uint16_t *offset_inout, uint16_t *arcount_inout,
                       edns_info_t *edns, uint8_t rcode_ext) {
    uint16_t offset = *offset_inout;
    uint16_t rdlen = 0;
    if (edns && edns->has_cookie) {
        rdlen += 4 + 8 + edns->server_cookie_len;
    }
    if (edns && edns->ede_count > 0) {
        for (uint16_t i = 0; i < edns->ede_count; i++) {
            rdlen += 4 + 2;
            if (edns->ede_list[i].text[0] != '\0') {
                rdlen += strlen(edns->ede_list[i].text);
            }
        }
    }

    if (offset + 11 + rdlen <= max_res_len) {
        res[offset++] = 0; // Root name
        res[offset++] = 0; res[offset++] = 41; // TYPE OPT
        res[offset++] = 1232 >> 8; res[offset++] = 1232 & 0xFF; // UDP Payload size
        
        res[offset++] = rcode_ext; 
        res[offset++] = 0; // Version (0)
        
        uint16_t flags = 0;
        if (edns && edns->dnssec_ok) flags |= 0x8000;
        res[offset++] = flags >> 8; res[offset++] = flags & 0xFF;
        
        res[offset++] = rdlen >> 8; res[offset++] = rdlen & 0xFF; // RDLENGTH
        
        if (edns && edns->has_cookie) {
            uint16_t opt_len = 8 + edns->server_cookie_len;
            res[offset++] = 0; res[offset++] = 10; // Option Code: 10
            res[offset++] = opt_len >> 8; res[offset++] = opt_len & 0xFF; // Option Length
            memcpy(res + offset, edns->client_cookie, 8);
            offset += 8;
            if (edns->server_cookie_len > 0) {
                memcpy(res + offset, edns->server_cookie, edns->server_cookie_len);
                offset += edns->server_cookie_len;
            }
        }
        
        if (edns && edns->ede_count > 0) {
            for (uint16_t i = 0; i < edns->ede_count; i++) {
                uint16_t text_len = strlen(edns->ede_list[i].text);
                res[offset++] = 0; res[offset++] = 15; // Option Code: 15 (Extended DNS Error)
                res[offset++] = (2 + text_len) >> 8; res[offset++] = (2 + text_len) & 0xFF;  // Option Length
                res[offset++] = edns->ede_list[i].code >> 8; res[offset++] = edns->ede_list[i].code & 0xFF; // EDE Code
                if (text_len > 0) {
                    memcpy(res + offset, edns->ede_list[i].text, text_len);
                    offset += text_len;
                }
            }
        }
        
        (*arcount_inout)++;
    }
    *offset_inout = offset;
}

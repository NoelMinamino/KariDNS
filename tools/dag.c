/*
 * dag - DNS Anomaly Generator (test client / protocol fuzzer)
 *
 * Usage:
 *   dag <name> <type> @<server> [-p <port>] [+tcp] [+ldnsz]
 *       [+edns] [+dnssec] [+nsid] [+cookie[=hex]] [+nocookie] [+subnet=addr[/prefix]]
 *       [--break <kind>[=<param>] ...]
 *
 * Builds a DNS query, sends it over UDP/TCP, and pretty-prints the response
 * with a hexdump. Supports intentional packet malformation via --break.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zlib.h>

#include "../dns_wire.h"

/* ========================================================================
 * 1. Arena (dag only ever bump-allocates scratch strings; never freed)
 * ==================================================================== */
#define DAG_ARENA_SIZE (256 * 1024)
static char g_arena_buf[DAG_ARENA_SIZE];
static size_t g_arena_pos = 0;

struct zone_arena_s {
    char pad[1]; /* dag doesn't need real zone_arena_t internals */
};

void *arena_alloc(zone_arena_t *arena, size_t size) {
    (void)arena;
    size_t aligned = (size + 7) & ~((size_t)7);
    if (g_arena_pos + aligned > DAG_ARENA_SIZE) return NULL;
    void *p = &g_arena_buf[g_arena_pos];
    g_arena_pos += aligned;
    return p;
}

/* ========================================================================
 * 2. EDE strings / basic helpers
 * ==================================================================== */
static const char *get_ede_error_string(uint16_t code) {
    switch (code) {
        case 0: return "Other Error";
        case 1: return "Unsupported DNSKEY Algorithm";
        case 2: return "Unsupported DS Digest Type";
        case 3: return "Stale Answer";
        case 4: return "Forged Answer";
        case 5: return "DNSSEC Indeterminate";
        case 6: return "DNSSEC Bogus";
        case 7: return "Signature Expired";
        case 8: return "Signature Not Yet Valid";
        case 9: return "DNSKEY Missing";
        case 10: return "RRSIGs Missing";
        case 11: return "No Zone Key Bit Set";
        case 12: return "NSEC Missing";
        case 13: return "Cached Error";
        case 14: return "Not Ready";
        case 15: return "Blocked";
        case 16: return "Censored";
        case 17: return "Filtered";
        case 18: return "Prohibited";
        case 19: return "Stale NXDomain Answer";
        case 20: return "Not Authoritative";
        case 21: return "Not Supported";
        case 22: return "No Reachable Authority";
        case 23: return "Network Error";
        case 24: return "Invalid Data";
        default: return "Unassigned";
    }
}

static uint16_t parse_qtype(const char *s) {
    if (strncasecmp(s, "TYPE", 4) == 0) {
        return (uint16_t)atoi(s + 4);
    }
    static const struct { const char *name; uint16_t type; } types[] = {
        {"A", 1}, {"NS", 2}, {"MD", 3}, {"MF", 4}, {"CNAME", 5}, {"SOA", 6},
        {"MB", 7}, {"MG", 8}, {"MR", 9}, {"NULL", 10}, {"WKS", 11}, {"PTR", 12},
        {"HINFO", 13}, {"MINFO", 14}, {"MX", 15}, {"TXT", 16}, {"RP", 17},
        {"AFSDB", 18}, {"X25", 19}, {"ISDN", 20}, {"RT", 21}, {"NSAP", 22},
        {"NSAP-PTR", 23}, {"SIG", 24}, {"KEY", 25}, {"PX", 26}, {"GPOS", 27},
        {"AAAA", 28}, {"LOC", 29}, {"NXT", 30}, {"EID", 31}, {"NIMLOC", 32},
        {"SRV", 33}, {"ATMA", 34}, {"NAPTR", 35}, {"KX", 36}, {"CERT", 37},
        {"A6", 38}, {"DNAME", 39}, {"SINK", 40}, {"OPT", 41}, {"APL", 42},
        {"DS", 43}, {"SSHFP", 44}, {"IPSECKEY", 45}, {"RRSIG", 46}, {"NSEC", 47},
        {"DNSKEY", 48}, {"DHCID", 49}, {"NSEC3", 50}, {"NSEC3PARAM", 51},
        {"TLSA", 52}, {"SMIMEA", 53}, {"HIP", 55}, {"CDS", 59}, {"CDNSKEY", 60},
        {"OPENPGPKEY", 61}, {"CSYNC", 62}, {"ZONEMD", 63}, {"SVCB", 64},
        {"HTTPS", 65}, {"SPF", 99}, {"NID", 104}, {"L32", 105}, {"L64", 106},
        {"LP", 107}, {"EUI48", 108}, {"EUI64", 109}, {"TKEY", 249}, {"TSIG", 250},
        {"IXFR", 251}, {"AXFR", 252}, {"MAILB", 253}, {"MAILA", 254}, {"ANY", 255},
        {"URI", 256}, {"CAA", 257}, {"AVC", 258}, {"DOA", 259}, {"AMTRELAY", 260},
        {"TA", 32768}, {"DLV", 32769}
    };
    for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
        if (strcasecmp(s, types[i].name) == 0) return types[i].type;
    }
    return (uint16_t)atoi(s);
}

static void print_ldnsz_url(const uint8_t *buf, size_t len) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        printf(";; deflateInit2 failed\n");
        return;
    }
    strm.next_in = (uint8_t *)buf;
    strm.avail_in = len;
    size_t out_cap = deflateBound(&strm, len);
    uint8_t *out_buf = malloc(out_cap);
    if (!out_buf) { deflateEnd(&strm); return; }
    strm.next_out = out_buf;
    strm.avail_out = out_cap;
    deflate(&strm, Z_FINISH);
    size_t comp_len = out_cap - strm.avail_out;
    deflateEnd(&strm);

    static const char b64url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    printf(";; View in browser: https://ldns.jp/?dnsz=");
    for (size_t i = 0; i < comp_len; i += 3) {
        uint32_t val = out_buf[i] << 16;
        if (i + 1 < comp_len) val |= out_buf[i + 1] << 8;
        if (i + 2 < comp_len) val |= out_buf[i + 2];

        printf("%c", b64url_table[(val >> 18) & 0x3F]);
        printf("%c", b64url_table[(val >> 12) & 0x3F]);
        if (i + 1 < comp_len) printf("%c", b64url_table[(val >> 6) & 0x3F]);
        if (i + 2 < comp_len) printf("%c", b64url_table[val & 0x3F]);
    }
    printf("\n");
    free(out_buf);
}

static void hexdump(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%04zx  ", i);
        printf("%02x ", buf[i]);
        if (i % 16 == 7) printf(" ");
        if (i % 16 == 15 || i + 1 == len) {
            size_t pad = 15 - (i % 16);
            for (size_t j = 0; j < pad; j++) printf("   ");
            if ((i % 16) < 7) printf(" ");
            printf(" |");
            size_t row_start = i - (i % 16);
            for (size_t j = row_start; j <= i; j++) {
                unsigned char c = buf[j];
                printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
            }
            printf("|\n");
        }
    }
}

/* ========================================================================
 * 3. --break (fuzz) option handling
 * ==================================================================== */
typedef enum {
    BRK_NONE = 0,
    BRK_COMPRESSION_LOOP,
    BRK_COMPRESSION_FORWARD,
    BRK_LABEL_TOO_LONG,
    BRK_RESERVED_LENGTH_BITS,
    BRK_OVERSIZED_QNAME,
    BRK_QDCOUNT,
    BRK_TRUNCATED_QUESTION,
    BRK_OPT_RDLEN,
    BRK_ARCOUNT,
    BRK_OPCODE,
    BRK_QR_BIT,
    BRK_NOTIFY_NO_QUESTION,
    BRK_TOO_SHORT,
    BRK_TCP_LENGTH_OVERCLAIM,
    BRK_TCP_ZERO_LENGTH,
    BRK_TCP_IDLE_HOLD
} break_kind_t;

typedef struct {
    break_kind_t kind;
    long param;
    bool has_param;
} break_opt_t;

#define MAX_BREAKS 8
static break_opt_t g_breaks[MAX_BREAKS];
static int g_break_count = 0;

static bool is_structural_break(break_kind_t k) {
    switch (k) {
        case BRK_COMPRESSION_LOOP:
        case BRK_COMPRESSION_FORWARD:
        case BRK_LABEL_TOO_LONG:
        case BRK_RESERVED_LENGTH_BITS:
        case BRK_OVERSIZED_QNAME:
        case BRK_TRUNCATED_QUESTION:
        case BRK_NOTIFY_NO_QUESTION:
            return true;
        default:
            return false;
    }
}

static bool is_tcp_only_break(break_kind_t k) {
    return k == BRK_TCP_LENGTH_OVERCLAIM || k == BRK_TCP_ZERO_LENGTH || k == BRK_TCP_IDLE_HOLD;
}

static bool has_break(break_kind_t kind, long *param_out, bool *has_param_out) {
    for (int i = 0; i < g_break_count; i++) {
        if (g_breaks[i].kind == kind) {
            if (param_out) *param_out = g_breaks[i].param;
            if (has_param_out) *has_param_out = g_breaks[i].has_param;
            return true;
        }
    }
    return false;
}

static bool any_structural_break(break_kind_t *which_out) {
    for (int i = 0; i < g_break_count; i++) {
        if (is_structural_break(g_breaks[i].kind)) {
            if (which_out) *which_out = g_breaks[i].kind;
            return true;
        }
    }
    return false;
}

static void parse_break_arg(const char *arg) {
    if (g_break_count >= MAX_BREAKS) {
        fprintf(stderr, "warning: too many --break options, ignoring '%s'\n", arg);
        return;
    }
    char name[64]; long param = 0; bool has_param = false;
    const char *eq = strchr(arg, '=');
    if (eq) {
        size_t nlen = (size_t)(eq - arg);
        if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
        memcpy(name, arg, nlen); name[nlen] = '\0';
        param = strtol(eq + 1, NULL, 0);
        has_param = true;
    } else {
        strncpy(name, arg, sizeof(name) - 1); name[sizeof(name) - 1] = '\0';
    }

    break_kind_t kind = BRK_NONE;
    if      (strcmp(name, "compression-loop") == 0)     kind = BRK_COMPRESSION_LOOP;
    else if (strcmp(name, "compression-forward") == 0)  kind = BRK_COMPRESSION_FORWARD;
    else if (strcmp(name, "label-too-long") == 0)        { kind = BRK_LABEL_TOO_LONG; if (!has_param) { param = 100; has_param = true; } }
    else if (strcmp(name, "reserved-length-bits") == 0)  kind = BRK_RESERVED_LENGTH_BITS;
    else if (strcmp(name, "oversized-qname") == 0)       kind = BRK_OVERSIZED_QNAME;
    else if (strcmp(name, "qdcount") == 0)               kind = BRK_QDCOUNT;
    else if (strcmp(name, "truncated-question") == 0)    kind = BRK_TRUNCATED_QUESTION;
    else if (strcmp(name, "opt-rdlen") == 0)              kind = BRK_OPT_RDLEN;
    else if (strcmp(name, "arcount") == 0)                kind = BRK_ARCOUNT;
    else if (strcmp(name, "opcode") == 0)                 kind = BRK_OPCODE;
    else if (strcmp(name, "qr-bit") == 0)                 kind = BRK_QR_BIT;
    else if (strcmp(name, "notify-no-question") == 0)     kind = BRK_NOTIFY_NO_QUESTION;
    else if (strcmp(name, "too-short") == 0)              kind = BRK_TOO_SHORT;
    else if (strcmp(name, "tcp-length-overclaim") == 0)   { kind = BRK_TCP_LENGTH_OVERCLAIM; if (!has_param) { param = 10; has_param = true; } }
    else if (strcmp(name, "tcp-zero-length") == 0)        kind = BRK_TCP_ZERO_LENGTH;
    else if (strcmp(name, "tcp-idle-hold") == 0)          { kind = BRK_TCP_IDLE_HOLD; if (!has_param) { param = 20; has_param = true; } }
    else {
        fprintf(stderr, "warning: unknown --break kind '%s', ignoring\n", name);
        return;
    }

    g_breaks[g_break_count].kind = kind;
    g_breaks[g_break_count].param = param;
    g_breaks[g_break_count].has_param = has_param;
    g_break_count++;
}

static void print_break_help(void) {
    printf(
        "--break kinds:\n"
        "  compression-loop           question name = self-referencing compression pointer\n"
        "  compression-forward        question name = pointer to an unseen forward offset\n"
        "  label-too-long[=N]         label length byte N (63<N<192), default 100\n"
        "  reserved-length-bits       label length byte 0x40 (reserved bit pattern)\n"
        "  oversized-qname            QNAME > 255 bytes via many short labels\n"
        "  qdcount=N                  override header QDCOUNT\n"
        "  truncated-question         cut the packet mid-label\n"
        "  opt-rdlen=N                lie about the OPT record's RDLENGTH (forces OPT)\n"
        "  arcount=N                  override header ARCOUNT\n"
        "  opcode=N                   override header OPCODE\n"
        "  qr-bit                     set QR=1 on an outgoing query\n"
        "  notify-no-question         OPCODE=4 (NOTIFY) with QDCOUNT=0, no question\n"
        "  too-short                  send only the first 3 bytes of the message\n"
        "  tcp-length-overclaim[=N]   (--tcp only) length prefix N bytes bigger than body sent\n"
        "  tcp-zero-length            (--tcp only) send a 0 length prefix\n"
        "  tcp-idle-hold[=SEC]        (--tcp only) send only the length prefix, hold the\n"
        "                             connection, report when/if the server disconnects\n"
    );
}

/* ========================================================================
 * 4. Query options (EDNS request side) -- built entirely in this file
 * ==================================================================== */
typedef struct {
    bool want_opt;
    uint16_t udp_payload_size;
    bool dnssec_ok;

    bool want_nsid;

    bool want_cookie;
    uint8_t client_cookie[8];
    uint8_t server_cookie[32];
    size_t server_cookie_len;

    bool want_subnet;
    int subnet_family;      /* 1 = IPv4, 2 = IPv6 */
    uint8_t subnet_addr[16];
    int subnet_prefix;

    bool is_ixfr;
    uint32_t ixfr_serial;
} query_opts_t;

static bool parse_subnet_arg(const char *arg, query_opts_t *qo) {
    char buf[128];
    strncpy(buf, arg, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, buf, &a4) == 1) {
        qo->subnet_family = 1;
        memcpy(qo->subnet_addr, &a4, 4);
        qo->subnet_prefix = (prefix >= 0) ? prefix : 24;
        if (qo->subnet_prefix > 32) qo->subnet_prefix = 32;
        return true;
    }
    if (inet_pton(AF_INET6, buf, &a6) == 1) {
        qo->subnet_family = 2;
        memcpy(qo->subnet_addr, &a6, 16);
        qo->subnet_prefix = (prefix >= 0) ? prefix : 56;
        if (qo->subnet_prefix > 128) qo->subnet_prefix = 128;
        return true;
    }
    fprintf(stderr, "invalid +subnet address: %s\n", arg);
    return false;
}

static uint16_t build_opt_record(uint8_t *pkt, size_t max_len, uint16_t offset,
                                  const query_opts_t *qo, uint16_t *opt_rdlen_field_out) {
    if ((size_t)offset + 1 > max_len) return offset;
    pkt[offset++] = 0x00; /* Root name */

    if ((size_t)offset + 10 > max_len) return offset;
    pkt[offset++] = 0x00; pkt[offset++] = 41; /* TYPE = OPT */
    pkt[offset++] = qo->udp_payload_size >> 8; pkt[offset++] = qo->udp_payload_size & 0xFF;
    pkt[offset++] = 0x00; /* extended RCODE */
    pkt[offset++] = 0x00; /* version */
    uint16_t flags = qo->dnssec_ok ? 0x8000 : 0x0000;
    pkt[offset++] = flags >> 8; pkt[offset++] = flags & 0xFF;

    uint16_t rdlen_field_offset = offset;
    pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* RDLENGTH placeholder */
    uint16_t rdata_start = offset;

    if (qo->want_nsid) {
        if ((size_t)offset + 4 > max_len) goto done;
        pkt[offset++] = 0x00; pkt[offset++] = 0x03; /* OPTION-CODE = NSID */
        pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* OPTION-LENGTH = 0 (empty request) */
    }

    if (qo->want_cookie) {
        uint16_t opt_len = 8 + (uint16_t)qo->server_cookie_len;
        if ((size_t)offset + 4 + opt_len > max_len) goto done;
        pkt[offset++] = 0x00; pkt[offset++] = 0x0A; /* OPTION-CODE = COOKIE */
        pkt[offset++] = opt_len >> 8; pkt[offset++] = opt_len & 0xFF;
        memcpy(&pkt[offset], qo->client_cookie, 8); offset += 8;
        if (qo->server_cookie_len > 0) {
            memcpy(&pkt[offset], qo->server_cookie, qo->server_cookie_len);
            offset += qo->server_cookie_len;
        }
    }

    if (qo->want_subnet) {
        int addr_bytes = (qo->subnet_prefix + 7) / 8;
        uint16_t opt_len = 4 + (uint16_t)addr_bytes;
        if ((size_t)offset + 4 + opt_len > max_len) goto done;
        pkt[offset++] = 0x00; pkt[offset++] = 0x08; /* OPTION-CODE = ECS */
        pkt[offset++] = opt_len >> 8; pkt[offset++] = opt_len & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = (qo->subnet_family == 2) ? 0x02 : 0x01; /* FAMILY */
        pkt[offset++] = (uint8_t)qo->subnet_prefix; /* SOURCE PREFIX-LENGTH */
        pkt[offset++] = 0x00;                        /* SCOPE PREFIX-LENGTH */
        uint8_t addr_copy[16];
        memcpy(addr_copy, qo->subnet_addr, 16);
        int total_bits = qo->subnet_prefix;
        for (int b = 0; b < addr_bytes; b++) {
            int bits_in_byte = total_bits - b * 8;
            if (bits_in_byte < 8) {
                uint8_t mask = (bits_in_byte <= 0) ? 0x00 : (uint8_t)(0xFF << (8 - bits_in_byte));
                addr_copy[b] &= mask;
            }
        }
        memcpy(&pkt[offset], addr_copy, addr_bytes);
        offset += addr_bytes;
    }

done:
    {
        uint16_t rdlen = offset - rdata_start;
        pkt[rdlen_field_offset] = rdlen >> 8;
        pkt[rdlen_field_offset + 1] = rdlen & 0xFF;
    }
    if (opt_rdlen_field_out) *opt_rdlen_field_out = rdlen_field_offset;
    return offset;
}

/* ========================================================================
 * 5. Packet construction (normal path + structural --break variants)
 * ==================================================================== */
static size_t build_query_packet(uint8_t *pkt, size_t max_len,
                                  const char *qname, uint16_t qtype,
                                  const query_opts_t *qo) {
    memset(pkt, 0, 12);
    uint16_t id = (uint16_t)(time(NULL) ^ getpid());
    pkt[0] = id >> 8; pkt[1] = id & 0xFF;
    pkt[2] = 0x01; /* RD=1 */
    pkt[4] = 0x00; pkt[5] = 0x01; /* QDCOUNT=1 (may be overridden below) */

    break_kind_t structural = BRK_NONE;
    bool has_structural = any_structural_break(&structural);

    uint16_t offset = 12;

    if (has_structural && structural == BRK_NOTIFY_NO_QUESTION) {
        pkt[4] = 0x00; pkt[5] = 0x00; /* QDCOUNT=0, no question bytes at all */
        pkt[2] = (pkt[2] & 0x87) | (4 << 3); /* OPCODE=4 (NOTIFY) */
    } else if (has_structural && structural == BRK_COMPRESSION_LOOP) {
        pkt[offset++] = 0xC0; pkt[offset++] = 0x0C;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_COMPRESSION_FORWARD) {
        pkt[offset++] = 0xC0; pkt[offset++] = 0xFF;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_LABEL_TOO_LONG) {
        long n = 100; has_break(BRK_LABEL_TOO_LONG, &n, NULL);
        pkt[offset++] = (uint8_t)n;
        int filler = (n < 20) ? (int)n : 20;
        for (int i = 0; i < filler; i++) pkt[offset++] = 'A';
        pkt[offset++] = 0x00;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_RESERVED_LENGTH_BITS) {
        pkt[offset++] = 0x40;
        for (int i = 0; i < 20; i++) pkt[offset++] = 'B';
        pkt[offset++] = 0x00;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_OVERSIZED_QNAME) {
        for (int i = 0; i < 60; i++) { pkt[offset++] = 4; memcpy(&pkt[offset], "aaaa", 4); offset += 4; }
        pkt[offset++] = 0x00;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_TRUNCATED_QUESTION) {
        pkt[offset++] = 0x05;
        memcpy(&pkt[offset], "www", 3); offset += 3;
        return offset;
    } else {
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        if (write_dns_name_str(pkt, &offset, qname, &comp_ctx) != 0) {
            fprintf(stderr, "write_dns_name_str failed (name too long?)\n");
            return 0;
        }
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    }

    if (qo->is_ixfr) {
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        if (write_dns_name_str(pkt, &offset, qname, &comp_ctx) == 0) {
            pkt[offset++] = 0x00; pkt[offset++] = 0x06; /* Type SOA */
            pkt[offset++] = 0x00; pkt[offset++] = 0x01; /* Class IN */
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* TTL 0 */
            pkt[offset++] = 0x00; pkt[offset++] = 0x16; /* RDLEN 22 */
            pkt[offset++] = 0x00; /* MNAME (.) */
            pkt[offset++] = 0x00; /* RNAME (.) */
            pkt[offset++] = (qo->ixfr_serial >> 24) & 0xFF;
            pkt[offset++] = (qo->ixfr_serial >> 16) & 0xFF;
            pkt[offset++] = (qo->ixfr_serial >> 8) & 0xFF;
            pkt[offset++] = qo->ixfr_serial & 0xFF; /* SERIAL */
            for (int i = 0; i < 16; i++) pkt[offset++] = 0; /* REFRESH, RETRY, EXPIRE, MINIMUM */
            
            uint16_t nscount = (pkt[8] << 8) | pkt[9];
            nscount++;
            pkt[8] = nscount >> 8; pkt[9] = nscount & 0xFF;
        }
    }

    long opt_rdlen_override = 0; bool want_opt_rdlen_break = has_break(BRK_OPT_RDLEN, &opt_rdlen_override, NULL);
    if (qo->want_opt || want_opt_rdlen_break) {
        uint16_t rdlen_field = 0;
        uint16_t before = offset;
        offset = build_opt_record(pkt, max_len, offset, qo, &rdlen_field);
        if (offset > before) {
            uint16_t arcount = (pkt[10] << 8) | pkt[11];
            arcount++;
            pkt[10] = arcount >> 8; pkt[11] = arcount & 0xFF;
            if (want_opt_rdlen_break) {
                pkt[rdlen_field] = (opt_rdlen_override >> 8) & 0xFF;
                pkt[rdlen_field + 1] = opt_rdlen_override & 0xFF;
            }
        }
    }

    long p;
    if (has_break(BRK_QDCOUNT, &p, NULL)) { pkt[4] = (p >> 8) & 0xFF; pkt[5] = p & 0xFF; }
    if (has_break(BRK_ARCOUNT, &p, NULL)) { pkt[10] = (p >> 8) & 0xFF; pkt[11] = p & 0xFF; }
    if (has_break(BRK_OPCODE, &p, NULL))  { pkt[2] = (pkt[2] & 0x87) | ((p & 0x0F) << 3); }
    if (has_break(BRK_QR_BIT, NULL, NULL)) { pkt[2] |= 0x80; }

    return offset;
}

/* ========================================================================
 * 6. Networking
 * ==================================================================== */
static int connect_udp(const char *server, int port, struct sockaddr_storage *dest, socklen_t *dest_len) {
    memset(dest, 0, sizeof(*dest));
    struct sockaddr_in *d4 = (struct sockaddr_in *)dest;
    struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)dest;
    int family = AF_INET;
    if (inet_pton(AF_INET, server, &d4->sin_addr) == 1) {
        d4->sin_family = AF_INET; d4->sin_port = htons((uint16_t)port);
        *dest_len = sizeof(*d4); family = AF_INET;
    } else if (inet_pton(AF_INET6, server, &d6->sin6_addr) == 1) {
        d6->sin6_family = AF_INET6; d6->sin6_port = htons((uint16_t)port);
        *dest_len = sizeof(*d6); family = AF_INET6;
    } else {
        fprintf(stderr, "Invalid server address: %s\n", server);
        return -1;
    }
    int sock = socket(family, SOCK_DGRAM, 0);
    if (sock < 0) perror("socket");
    return sock;
}

static int connect_tcp(const char *server, int port) {
    struct sockaddr_storage dest; socklen_t dest_len;
    memset(&dest, 0, sizeof(dest));
    struct sockaddr_in *d4 = (struct sockaddr_in *)&dest;
    struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)&dest;
    int family = AF_INET;
    if (inet_pton(AF_INET, server, &d4->sin_addr) == 1) {
        d4->sin_family = AF_INET; d4->sin_port = htons((uint16_t)port);
        dest_len = sizeof(*d4); family = AF_INET;
    } else if (inet_pton(AF_INET6, server, &d6->sin6_addr) == 1) {
        d6->sin6_family = AF_INET6; d6->sin6_port = htons((uint16_t)port);
        dest_len = sizeof(*d6); family = AF_INET6;
    } else {
        fprintf(stderr, "Invalid server address: %s\n", server);
        return -1;
    }
    int sock = socket(family, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }
    if (connect(sock, (struct sockaddr *)&dest, dest_len) != 0) {
        perror("connect"); close(sock); return -1;
    }
    return sock;
}

static ssize_t do_udp_exchange(const char *server, int port,
                                const uint8_t *pkt, size_t pkt_len,
                                uint8_t *resp, size_t resp_cap) {
    struct sockaddr_storage dest; socklen_t dest_len;
    int sock = connect_udp(server, port, &dest, &dest_len);
    if (sock < 0) return -1;

    size_t send_len = pkt_len;
    if (has_break(BRK_TOO_SHORT, NULL, NULL) && send_len > 3) send_len = 3;

    if (sendto(sock, pkt, send_len, 0, (struct sockaddr *)&dest, dest_len) < 0) {
        perror("sendto"); close(sock); return -1;
    }

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t n = recv(sock, resp, resp_cap, 0);
    close(sock);
    return n;
}

static ssize_t do_tcp_exchange(const char *server, int port,
                                const uint8_t *pkt, size_t pkt_len,
                                uint8_t *resp, size_t resp_cap) {
    int sock = connect_tcp(server, port);
    if (sock < 0) return -1;

    long idle_secs = 20; bool idle_hold = has_break(BRK_TCP_IDLE_HOLD, &idle_secs, NULL);
    long overclaim = 0; bool overclaim_break = has_break(BRK_TCP_LENGTH_OVERCLAIM, &overclaim, NULL);
    bool zero_len_break = has_break(BRK_TCP_ZERO_LENGTH, NULL, NULL);
    bool too_short = has_break(BRK_TOO_SHORT, NULL, NULL);

    size_t body_len = pkt_len;
    if (too_short && body_len > 3) body_len = 3;

    uint16_t prefix_value;
    if (zero_len_break) prefix_value = 0;
    else if (overclaim_break) prefix_value = (uint16_t)(body_len + overclaim);
    else prefix_value = (uint16_t)body_len;

    uint8_t len_prefix[2] = { prefix_value >> 8, prefix_value & 0xFF };
    if (send(sock, len_prefix, 2, 0) < 0) { perror("send(len prefix)"); close(sock); return -1; }

    if (idle_hold) {
        printf(";; --break tcp-idle-hold: sent only the length prefix, holding connection open for up to %lds...\n", idle_secs);
        time_t start = time(NULL);
        while (time(NULL) - start < idle_secs) {
            fd_set rfds; FD_ZERO(&rfds); FD_SET(sock, &rfds);
            struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
            int r = select(sock + 1, &rfds, NULL, NULL, &tv);
            if (r > 0) {
                uint8_t tmp[1];
                ssize_t n = recv(sock, tmp, sizeof(tmp), MSG_PEEK);
                if (n == 0) {
                    printf(";; server closed the connection after ~%lds (idle timeout appears to work)\n",
                           (long)(time(NULL) - start));
                    close(sock);
                    return -1;
                }
            }
        }
        printf(";; connection still OPEN after %lds -- no idle timeout observed\n", idle_secs);
        close(sock);
        return -1;
    }

    if (zero_len_break) {
        /* prefix already claims 0 bytes; send no body at all */
    } else if (!(too_short && body_len == 0)) {
        if (send(sock, pkt, body_len, 0) < 0) { perror("send(body)"); close(sock); return -1; }
    }

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t rlen_buf[2];
    ssize_t n = recv(sock, rlen_buf, 2, 0);
    if (n < 2) { close(sock); return -1; }
    uint16_t rlen = (rlen_buf[0] << 8) | rlen_buf[1];
    if (rlen > resp_cap) rlen = (uint16_t)resp_cap;

    size_t got = 0;
    while (got < rlen) {
        ssize_t r = recv(sock, resp + got, rlen - got, 0);
        if (r <= 0) break;
        got += r;
    }
    close(sock);
    return (ssize_t)got;
}

/* ========================================================================
 * 7. Response pretty-printing (dig-style)
 * ==================================================================== */
static const char *rcode_name(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN"; case 4: return "NOTIMP"; case 5: return "REFUSED";
        case 9: return "NOTAUTH"; case 16: return "BADVERS/BADSIG"; case 17: return "BADKEY";
        case 18: return "BADTIME";
        default: return "UNKNOWN";
    }
}

static const char *opcode_name(uint8_t opcode) {
    switch (opcode) {
        case 0: return "QUERY"; case 1: return "IQUERY"; case 2: return "STATUS";
        case 4: return "NOTIFY"; case 5: return "UPDATE";
        default: return "UNKNOWN";
    }
}

static void print_rdata(const uint8_t *pkt, size_t pkt_len, uint16_t type,
                         size_t abs_offset, uint16_t rdlen) {
    switch (type) {
        case 1:
            if (rdlen == 4) {
                printf("%d.%d.%d.%d", pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], pkt[abs_offset+3]);
            } else printf("(malformed A, rdlen=%u)", rdlen);
            break;
        case 28:
            if (rdlen == 16) {
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &pkt[abs_offset], buf, sizeof(buf));
                printf("%s", buf);
            } else printf("(malformed AAAA, rdlen=%u)", rdlen);
            break;
        case 2: case 5: case 12: {
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, NULL, &name) == 0) printf("%s", name);
            else printf("(unparsable name)");
            break;
        }
        case 15: {
            if (rdlen < 3) { printf("(malformed MX)"); break; }
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, NULL, &name) == 0)
                printf("%u %s", pref, name);
            else printf("%u (unparsable name)", pref);
            break;
        }
        case 6: {
            char *mname = NULL, *rname = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, NULL, &mname) != 0) { printf("(unparsable SOA)"); break; }
            size_t after_mname = next;
            if (expand_wire_name(pkt, pkt_len, after_mname, &next, NULL, &rname) != 0) { printf("(unparsable SOA)"); break; }
            size_t nums_off = next;
            if (nums_off + 20 > pkt_len) { printf("(truncated SOA)"); break; }
            uint32_t serial  = ((uint32_t)pkt[nums_off]<<24)|((uint32_t)pkt[nums_off+1]<<16)|((uint32_t)pkt[nums_off+2]<<8)|pkt[nums_off+3];
            uint32_t refresh = ((uint32_t)pkt[nums_off+4]<<24)|((uint32_t)pkt[nums_off+5]<<16)|((uint32_t)pkt[nums_off+6]<<8)|pkt[nums_off+7];
            uint32_t retry   = ((uint32_t)pkt[nums_off+8]<<24)|((uint32_t)pkt[nums_off+9]<<16)|((uint32_t)pkt[nums_off+10]<<8)|pkt[nums_off+11];
            uint32_t expire  = ((uint32_t)pkt[nums_off+12]<<24)|((uint32_t)pkt[nums_off+13]<<16)|((uint32_t)pkt[nums_off+14]<<8)|pkt[nums_off+15];
            uint32_t minimum = ((uint32_t)pkt[nums_off+16]<<24)|((uint32_t)pkt[nums_off+17]<<16)|((uint32_t)pkt[nums_off+18]<<8)|pkt[nums_off+19];
            printf("%s %s %u %u %u %u %u", mname, rname, serial, refresh, retry, expire, minimum);
            break;
        }
        case 33: {
            if (rdlen < 7) { printf("(malformed SRV)"); break; }
            uint16_t prio = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            uint16_t weight = (pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
            uint16_t port = (pkt[abs_offset+4]<<8)|pkt[abs_offset+5];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 6, &next, NULL, &name) == 0)
                printf("%u %u %u %s", prio, weight, port, name);
            else printf("%u %u %u (unparsable name)", prio, weight, port);
            break;
        }
        case 16: {
            size_t p = abs_offset, end = abs_offset + rdlen;
            bool first = true;
            while (p < end) {
                uint8_t slen = pkt[p++];
                if (p + slen > end) break;
                if (!first) printf(" ");
                first = false;
                printf("\"");
                for (uint8_t i = 0; i < slen; i++) {
                    unsigned char c = pkt[p + i];
                    if (c == '"' || c == '\\') printf("\\%c", c);
                    else if (c >= 0x20 && c < 0x7f) printf("%c", c);
                    else printf("\\%03o", c);
                }
                printf("\"");
                p += slen;
            }
            break;
        }
        default:
            printf("\\# %u ", rdlen);
            for (uint16_t i = 0; i < rdlen && abs_offset + i < pkt_len; i++) printf("%02x", pkt[abs_offset + i]);
            break;
    }
}

static bool print_one_rr(const uint8_t *pkt, size_t pkt_len, size_t *offset) {
    char *name = NULL; size_t next;
    if (expand_wire_name(pkt, pkt_len, *offset, &next, NULL, &name) != 0) return false;
    size_t hdr = next;
    if (hdr + 10 > pkt_len) return false;

    uint16_t type = (pkt[hdr] << 8) | pkt[hdr+1];
    uint16_t klass = (pkt[hdr+2] << 8) | pkt[hdr+3];
    uint32_t ttl = ((uint32_t)pkt[hdr+4]<<24)|((uint32_t)pkt[hdr+5]<<16)|((uint32_t)pkt[hdr+6]<<8)|pkt[hdr+7];
    uint16_t rdlen = (pkt[hdr+8] << 8) | pkt[hdr+9];
    size_t rdata_start = hdr + 10;
    if (rdata_start + rdlen > pkt_len) return false;

    if (type == 41) {
        *offset = rdata_start + rdlen;
        return true;
    }

    const char *tname = get_type_str(type, NULL);
    const char *cname = (klass == 1) ? "IN" : (klass == 255) ? "ANY" : "CH";
    printf("%-24s %-6u %-4s %-8s ", name, ttl, cname, tname);
    print_rdata(pkt, pkt_len, type, rdata_start, rdlen);
    printf("\n");

    *offset = rdata_start + rdlen;
    return true;
}

static void print_opt_extra_options(const uint8_t *pkt, size_t pkt_len,
                                     uint16_t qdcount, uint16_t ancount,
                                     uint16_t nscount, uint16_t arcount) {
    size_t scan_offset = 12;
    int total = qdcount + ancount + nscount + arcount;
    for (int i = 0; i < total; i++) {
        if (scan_offset >= pkt_len) return;
        bool is_opt = (i >= qdcount + ancount + nscount);
        size_t next;
        if (skip_wire_name(pkt, pkt_len, scan_offset, &next) != 0) return;
        scan_offset = next;
        if (i < qdcount) { scan_offset += 4; continue; }
        if (scan_offset + 10 > pkt_len) return;
        uint16_t rtype = (pkt[scan_offset] << 8) | pkt[scan_offset+1];
        uint16_t rdlen = (pkt[scan_offset+8] << 8) | pkt[scan_offset+9];
        size_t rdata_off = scan_offset + 10;
        if (is_opt && rtype == 41) {
            size_t p = rdata_off, end = rdata_off + rdlen;
            if (end > pkt_len) end = pkt_len;
            while (p + 4 <= end) {
                uint16_t code = (pkt[p] << 8) | pkt[p+1];
                uint16_t olen = (pkt[p+2] << 8) | pkt[p+3];
                p += 4;
                if (p + olen > end) break;
                if (code == 3) {
                    printf("; NSID: ");
                    for (uint16_t j = 0; j < olen; j++) printf("%02x", pkt[p + j]);
                    printf(" (\"");
                    for (uint16_t j = 0; j < olen; j++) {
                        unsigned char c = pkt[p + j];
                        printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
                    }
                    printf("\")\n");
                } else if (code == 8 && olen >= 4) {
                    uint16_t family = (pkt[p] << 8) | pkt[p+1];
                    uint8_t src_prefix = pkt[p+2];
                    uint8_t scope_prefix = pkt[p+3];
                    char abuf[64] = "?";
                    uint8_t addr[16] = {0};
                    int addr_bytes = olen - 4;
                    if (addr_bytes > 16) addr_bytes = 16;
                    memcpy(addr, &pkt[p + 4], addr_bytes);
                    if (family == 1) inet_ntop(AF_INET, addr, abuf, sizeof(abuf));
                    else if (family == 2) inet_ntop(AF_INET6, addr, abuf, sizeof(abuf));
                    printf("; CLIENT-SUBNET: %s/%u/%u\n", abuf, src_prefix, scope_prefix);
                }
                p += olen;
            }
            return;
        }
        scan_offset = rdata_off + rdlen;
    }
}

static void print_response(const uint8_t *pkt, size_t pkt_len) {
    if (pkt_len < 12) {
        printf(";; response too short to contain a header (%zu bytes)\n", pkt_len);
        return;
    }
    uint16_t qid = (pkt[0] << 8) | pkt[1];
    uint8_t flags1 = pkt[2], flags2 = pkt[3];
    uint8_t opcode = (flags1 >> 3) & 0x0F;
    bool qr = flags1 & 0x80, aa = flags1 & 0x04, tc = flags1 & 0x02, rd = flags1 & 0x01;
    bool ra = flags2 & 0x80, ad = flags2 & 0x20, cd = flags2 & 0x10;
    uint8_t rcode = flags2 & 0x0F;
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    uint16_t nscount = (pkt[8] << 8) | pkt[9];
    uint16_t arcount = (pkt[10] << 8) | pkt[11];

    printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n", opcode_name(opcode), rcode_name(rcode), qid);
    printf(";; flags:%s%s%s%s%s%s; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
           qr ? " qr" : "", aa ? " aa" : "", tc ? " tc" : "", rd ? " rd" : "",
           ra ? " ra" : "", ad ? " ad" : "",
           qdcount, ancount, nscount, arcount);
    if (cd) printf(";; (checking disabled)\n");

    size_t offset = 12;
    if (qdcount > 0) {
        printf("\n;; QUESTION SECTION:\n");
        for (int i = 0; i < qdcount; i++) {
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, offset, &next, NULL, &name) != 0) {
                printf(";; (unparsable question, stopping here)\n");
                goto fallback;
            }
            if (next + 4 > pkt_len) { printf(";; (truncated question)\n"); goto fallback; }
            uint16_t qtype = (pkt[next] << 8) | pkt[next+1];
            uint16_t qclass = (pkt[next+2] << 8) | pkt[next+3];
            printf(";%-24s %-4s %s\n", name, (qclass == 1) ? "IN" : (qclass == 255) ? "ANY" : "CH", get_type_str(qtype, NULL));
            offset = next + 4;
        }
    }

    if (ancount > 0) {
        printf("\n;; ANSWER SECTION:\n");
        for (int i = 0; i < ancount; i++) if (!print_one_rr(pkt, pkt_len, &offset)) { printf(";; (failed to parse answer record %d, stopping here)\n", i); goto fallback; }
    }
    if (nscount > 0) {
        printf("\n;; AUTHORITY SECTION:\n");
        for (int i = 0; i < nscount; i++) if (!print_one_rr(pkt, pkt_len, &offset)) { printf(";; (failed to parse authority record %d, stopping here)\n", i); goto fallback; }
    }
    if (arcount > 0) {
        printf("\n;; ADDITIONAL SECTION:\n");
        for (int i = 0; i < arcount; i++) if (!print_one_rr(pkt, pkt_len, &offset)) { printf(";; (failed to parse additional record %d, stopping here)\n", i); goto fallback; }
    }

    {
        edns_info_t edns;
        parse_edns_opt(pkt, pkt_len, qdcount, ancount, nscount, arcount, &edns);
        if (edns.present) {
            printf("\n;; OPT PSEUDOSECTION:\n");
            printf("; EDNS: version: %d, flags:%s; udp: %d\n", edns.version, edns.dnssec_ok ? " do" : "", edns.udp_payload_size);
            if (edns.ext_rcode != 0) printf("; EXT RCODE: %d\n", edns.ext_rcode);
            if (edns.has_cookie) {
                printf("; COOKIE: ");
                for (int i = 0; i < 8; i++) printf("%02x", edns.client_cookie[i]);
                if (edns.server_cookie_len > 0) {
                    printf(" (client) ");
                    for (uint16_t i = 0; i < edns.server_cookie_len; i++) printf("%02x", edns.server_cookie[i]);
                    printf(" (server)");
                }
                printf("\n");
            }
            print_opt_extra_options(pkt, pkt_len, qdcount, ancount, nscount, arcount);
            for (uint16_t i = 0; i < edns.ede_count; i++) {
                const char *msg = get_ede_error_string(edns.ede_list[i].code);
                if (edns.ede_list[i].text[0]) printf("; EDE: %d (%s): (%s)\n", edns.ede_list[i].code, msg, edns.ede_list[i].text);
                else printf("; EDE: %d (%s)\n", edns.ede_list[i].code, msg);
            }
        }
    }
    return;

fallback:
    printf(";; parsing stopped early; remaining bytes are only visible in the hexdump above.\n");
}

/* ========================================================================
 * 8. main
 * ==================================================================== */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <name> <type|IXFR=serial> @<server> [-p <port>] [+tcp]\n"
        "          [+edns] [+dnssec] [+nsid] [+cookie[=hex]] [+nocookie]\n"
        "          [+subnet=addr[/prefix]] [+ldnsz] [--break <kind>[=<param>] ...]\n"
        "\n"
        "       %s --break-help    (list all --break kinds)\n",
        prog, prog);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--break-help") == 0) { print_break_help(); return 0; }
    if (argc < 4) { usage(argv[0]); return 1; }

    const char *qname = argv[1];
    const char *qtype_s = argv[2];
    const char *server_arg = argv[3];
    int port = 53;
    bool use_tcp = false;
    bool use_ldnsz = false;

    if (server_arg[0] != '@') { fprintf(stderr, "Server must start with '@', e.g. @192.0.2.1\n"); return 1; }
    const char *server = server_arg + 1;

    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.udp_payload_size = 1232;

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--tcp") == 0 || strcmp(argv[i], "+tcp") == 0) {
            use_tcp = true;
        } else if (strcmp(argv[i], "+ldnsz") == 0) {
            use_ldnsz = true;
        } else if (strcmp(argv[i], "--break") == 0 && i + 1 < argc) {
            parse_break_arg(argv[++i]);
        } else if (strcmp(argv[i], "+edns") == 0) {
            qo.want_opt = true;
        } else if (strcmp(argv[i], "+dnssec") == 0) {
            qo.want_opt = true; qo.dnssec_ok = true;
        } else if (strcmp(argv[i], "+nsid") == 0) {
            qo.want_opt = true; qo.want_nsid = true;
        } else if (strncmp(argv[i], "+subnet=", 8) == 0) {
            if (parse_subnet_arg(argv[i] + 8, &qo)) { qo.want_opt = true; qo.want_subnet = true; }
        } else if (strncmp(argv[i], "+cookie", 7) == 0) {
            qo.want_opt = true; qo.want_cookie = true;
            if (argv[i][7] == '=') {
                const char *hex = argv[i] + 8;
                size_t hex_len = strlen(hex);
                if (hex_len > 64) hex_len = 64;
                uint8_t full[32]; size_t full_len = hex_len / 2;
                for (size_t j = 0; j < full_len; j++) {
                    unsigned int byte; sscanf(hex + j * 2, "%02x", &byte); full[j] = (uint8_t)byte;
                }
                if (full_len >= 8) {
                    memcpy(qo.client_cookie, full, 8);
                    if (full_len > 8) { qo.server_cookie_len = full_len - 8; memcpy(qo.server_cookie, full + 8, qo.server_cookie_len); }
                } else {
                    for (int k = 0; k < 8; k++) qo.client_cookie[k] = (uint8_t)(k + 1);
                }
            } else {
                for (int k = 0; k < 8; k++) qo.client_cookie[k] = (uint8_t)(rand() & 0xFF);
            }
        } else if (strcmp(argv[i], "+nocookie") == 0) {
            qo.want_cookie = false;
        } else {
            fprintf(stderr, "warning: unrecognized argument '%s', ignoring\n", argv[i]);
        }
    }

    for (int i = 0; i < g_break_count; i++) {
        if (is_tcp_only_break(g_breaks[i].kind) && !use_tcp) {
            fprintf(stderr, "error: this --break kind requires --tcp\n");
            return 1;
        }
    }

    uint16_t qtype = 0;
    if (strncasecmp(qtype_s, "IXFR=", 5) == 0) {
        qtype = 251;
        qo.is_ixfr = true;
        qo.ixfr_serial = strtoul(qtype_s + 5, NULL, 10);
        use_tcp = true;
    } else {
        qtype = parse_qtype(qtype_s);
    }

    static uint8_t pkt[65535];
    size_t pkt_len = build_query_packet(pkt, sizeof(pkt), qname, qtype, &qo);
    if (pkt_len == 0) return 1;

    bool retry_tcp = false;
    do {
        retry_tcp = false;

        printf("; <<>> dag <<>> %s %s @%s%s\n", qname, qtype_s, server, use_tcp ? " (tcp)" : "");
        printf("Query (%zu bytes):\n", pkt_len);
        hexdump(pkt, pkt_len);
        printf("\n");

        static uint8_t resp[65535];
        ssize_t n = use_tcp
            ? do_tcp_exchange(server, port, pkt, pkt_len, resp, sizeof(resp))
            : do_udp_exchange(server, port, pkt, pkt_len, resp, sizeof(resp));

        if (n < 0) {
            printf(";; no usable response received\n");
            return 1;
        }

        printf("Response (%zd bytes%s):\n", n, use_tcp ? ", TCP" : "");
        hexdump(resp, (size_t)n);
        if (use_ldnsz) {
            print_ldnsz_url(resp, (size_t)n);
        }
        printf("\n");
        print_response(resp, (size_t)n);

        if (!use_tcp && n >= 12 && (resp[2] & 0x02) != 0) {
            printf("\n;; Truncated, retrying in TCP mode...\n\n");
            use_tcp = true;
            retry_tcp = true;
        }
    } while (retry_tcp);

    return 0;
}
/*
 * dag - DNS Anomaly Generator (test client / protocol fuzzer)
 *
 * Usage:
 *   dag <name> <type> @<server>[,<server>...] [-p <port>] [+tcp] [+ldnsz]
 *       [+edns] [+dnssec] [+nsid] [+cookie[=hex]] [+nocookie] [+subnet=addr[/prefix]]
 *       [--break <kind>[=<param>] ...]
 *
 * <server> accepts IPv4/IPv6 literals or FQDNs (resolved via getaddrinfo()),
 * and a comma-separated list to query multiple servers in a single run, e.g.
 * @8.8.8.8,9.9.9.9,1.1.1.1
 *
 * Builds a DNS query, sends it over UDP/TCP, and pretty-prints the response
 * with a hexdump. Supports intentional packet malformation via --break.
 */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <zlib.h>
#include <strings.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <openssl/evp.h>
#include "../dns_wire.h"
#include "../dns_utils.h"

/* ========================================================================
 * 1. Arena (dag only ever bump-allocates scratch strings; never freed)
 * ==================================================================== */
#define DAG_ARENA_SIZE (256 * 1024)
#define MAX_DAG_SERVERS 16
static char g_arena_buf[DAG_ARENA_SIZE];
static size_t g_arena_pos = 0;

struct zone_arena_s {
    char pad[1]; /* dag doesn't need real zone_arena_t internals */
};

void *arena_alloc(zone_arena_t *arena, size_t size) {
    (void)arena;
    if (size > DAG_ARENA_SIZE) return NULL;
    size_t aligned = (size + 7) & ~((size_t)7);
    if (aligned < size) return NULL; // Overflow
    if (g_arena_pos + aligned > DAG_ARENA_SIZE || g_arena_pos + aligned < g_arena_pos) return NULL;
    void *p = &g_arena_buf[g_arena_pos];
    g_arena_pos += aligned;
    return p;
}

void reset_dag_arena(void) {
    g_arena_pos = 0;
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
    if (strncasecmp(s, "TYPE", 4) == 0 && s[4] != '\0') {
        char *end;
        long v = strtol(s + 4, &end, 10);
        if (*end == '\0' && v >= 0 && v <= 65535) return (uint16_t)v;
    }
    fprintf(stderr, "dag: unknown query type '%s'\n", s);
    exit(1);
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
    if (deflate(&strm, Z_FINISH) != Z_STREAM_END) {
        printf(";; compression did not complete\n");
        free(out_buf);
        deflateEnd(&strm);
        return;
    }
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

    struct {
        uint16_t code;
        uint16_t len;
        uint8_t data[512];
    } custom_edns_opts[8];
    int custom_edns_opt_count;

    bool want_padding;
    int padding_size;

    int timeout_sec;
    int tries;

    bool is_ixfr;
    uint32_t ixfr_serial;

    bool want_tsig;
    tsig_key_t tsig_key;
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

    for (int i = 0; i < qo->custom_edns_opt_count; i++) {
        if ((size_t)offset + 4 + qo->custom_edns_opts[i].len > max_len) break;
        pkt[offset++] = qo->custom_edns_opts[i].code >> 8;
        pkt[offset++] = qo->custom_edns_opts[i].code & 0xFF;
        pkt[offset++] = qo->custom_edns_opts[i].len >> 8;
        pkt[offset++] = qo->custom_edns_opts[i].len & 0xFF;
        if (qo->custom_edns_opts[i].len > 0) {
            memcpy(&pkt[offset], qo->custom_edns_opts[i].data, qo->custom_edns_opts[i].len);
            offset += qo->custom_edns_opts[i].len;
        }
    }

    if (qo->want_padding && qo->padding_size >= 0) {
        if ((size_t)offset + 4 + qo->padding_size <= max_len) {
            pkt[offset++] = 0x00; pkt[offset++] = 0x0C; // Padding (12)
            pkt[offset++] = qo->padding_size >> 8; pkt[offset++] = qo->padding_size & 0xFF;
            memset(&pkt[offset], 0, qo->padding_size);
            offset += qo->padding_size;
        }
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
        if (write_dns_name_str(pkt, &offset, qname, &comp_ctx, max_len) != 0) {
            fprintf(stderr, "write_dns_name_str failed (name too long?)\n");
            return 0;
        }
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    }

    if (qo->is_ixfr) {
        compress_ctx_t comp_ctx;
        compress_ctx_init_packet(&comp_ctx);
        if (write_dns_name_str(pkt, &offset, qname, &comp_ctx, max_len) == 0) {
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
/*
 * server引数(IPv4リテラル / IPv6リテラル / FQDN)をsockaddr_storageへ解決する。
 * まずinet_pton()でIPリテラルとしての解釈を試み(DNS解決を伴わない高速パス)、
 * どちらにも一致しなければFQDNとみなしgetaddrinfo()でシステムリゾルバに問い合わせる。
 */
static bool resolve_server_addr(const char *server, int port,
                                 struct sockaddr_storage *dest, socklen_t *dest_len,
                                 int *family_out) {
    memset(dest, 0, sizeof(*dest));
    struct sockaddr_in *d4 = (struct sockaddr_in *)dest;
    struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)dest;

    if (inet_pton(AF_INET, server, &d4->sin_addr) == 1) {
        d4->sin_family = AF_INET; d4->sin_port = htons((uint16_t)port);
        *dest_len = sizeof(*d4);
        if (family_out) *family_out = AF_INET;
        return true;
    }
    if (inet_pton(AF_INET6, server, &d6->sin6_addr) == 1) {
        d6->sin6_family = AF_INET6; d6->sin6_port = htons((uint16_t)port);
        *dest_len = sizeof(*d6);
        if (family_out) *family_out = AF_INET6;
        return true;
    }

    /* IPリテラルとして解釈できなかった場合はFQDNとみなし、システムリゾルバへ問い合わせる */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM; /* UDP/TCPどちらでも使うアドレスなので0でも良いが、重複エントリ抑制のため指定 */
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    int rc = getaddrinfo(server, portbuf, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "Cannot resolve server '%s': %s\n", server,
                rc != 0 ? gai_strerror(rc) : "no addresses returned");
        if (res) freeaddrinfo(res);
        return false;
    }
    if (res->ai_addrlen > sizeof(*dest)) {
        fprintf(stderr, "Resolved address for '%s' is unexpectedly large\n", server);
        freeaddrinfo(res);
        return false;
    }
    /* 複数レコードが返る場合もあるが、digやBIND互換ツールと同様に先頭(リゾルバの優先順位)を採用する */
    memcpy(dest, res->ai_addr, res->ai_addrlen);
    *dest_len = (socklen_t)res->ai_addrlen;
    if (family_out) *family_out = res->ai_family;
    freeaddrinfo(res);
    return true;
}

static int connect_udp(const char *server, int port, struct sockaddr_storage *dest, socklen_t *dest_len) {
    int family = AF_INET;
    if (!resolve_server_addr(server, port, dest, dest_len, &family)) return -1;
    int sock = socket(family, SOCK_DGRAM, 0);
    if (sock < 0) perror("socket");
    return sock;
}

static int connect_tcp(const char *server, int port) {
    struct sockaddr_storage dest; socklen_t dest_len; int family = AF_INET;
    if (!resolve_server_addr(server, port, &dest, &dest_len, &family)) return -1;
    int sock = socket(family, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }
    if (connect(sock, (struct sockaddr *)&dest, dest_len) != 0) {
        perror("connect"); close(sock); return -1;
    }
    return sock;
}

static ssize_t do_udp_exchange(const char *server, int port,
                                const uint8_t *pkt, size_t pkt_len,
                                uint8_t *resp, size_t resp_cap, int timeout_sec) {
    struct sockaddr_storage dest; socklen_t dest_len;
    int sock = connect_udp(server, port, &dest, &dest_len);
    if (sock < 0) return -1;

    size_t send_len = pkt_len;
    if (has_break(BRK_TOO_SHORT, NULL, NULL) && send_len > 3) send_len = 3;

    if (sendto(sock, pkt, send_len, 0, (struct sockaddr *)&dest, dest_len) < 0) {
        perror("sendto"); close(sock); return -1;
    }

    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t n = recv(sock, resp, resp_cap, 0);
    close(sock);
    return n;
}

static int do_tcp_send_request(const char *server, int port,
                                const uint8_t *pkt, size_t pkt_len, int timeout_sec) {
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

    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return sock;
}

static ssize_t do_tcp_recv_response(int sock, uint8_t *resp, size_t resp_cap) {
    uint8_t rlen_buf[2];
    ssize_t n = recv(sock, rlen_buf, 2, MSG_WAITALL);
    if (n < 2) return -1;
    uint16_t rlen = (rlen_buf[0] << 8) | rlen_buf[1];
    if (rlen > resp_cap) rlen = (uint16_t)resp_cap;

    size_t got = 0;
    while (got < rlen) {
        ssize_t r = recv(sock, resp + got, rlen - got, 0);
        if (r <= 0) break;
        got += r;
    }
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

// dag.c: get_type_str(dns_wire.c, arena依存)を使わず、dag内で完結させる。
// format_type_name is now in dns_utils.h

static const uint8_t *read_char_string(const uint8_t *p, const uint8_t *end, char *out, size_t out_cap) {
    if (p >= end) return NULL;
    uint8_t len = *p++;
    if (p + len > end) return NULL;
    size_t copy_len = (len < out_cap - 1) ? len : out_cap - 1;
    memcpy(out, p, copy_len);
    out[copy_len] = '\0';
    return p + len;
}

static double loc_decode_precsize(uint8_t b) {
    uint8_t mantissa = b >> 4;
    uint8_t exponent = b & 0x0F;
    double cm = mantissa * pow(10, exponent);
    return cm / 100.0;
}

static void loc_format_coord(uint32_t wire_val, bool is_lat, char *out, size_t out_cap) {
    int64_t signed_val = (int64_t)wire_val - 0x80000000LL;
    char dir = is_lat ? (signed_val < 0 ? 'S' : 'N') : (signed_val < 0 ? 'W' : 'E');
    double total_sec = fabs((double)signed_val) / 1000.0;
    int deg = (int)(total_sec / 3600.0);
    int min = (int)(fmod(total_sec, 3600.0) / 60.0);
    double sec = fmod(total_sec, 60.0);
    snprintf(out, out_cap, "%d %d %.3f %c", deg, min, sec, dir);
}

static const char *cert_type_name(uint16_t type, char *buf, size_t buf_size) {
    switch (type) {
        case 1: return "PKIX"; case 2: return "SPKI"; case 3: return "PGP";
        case 4: return "IPKIX"; case 5: return "ISPKI"; case 6: return "IPGP";
        case 7: return "ACPKIX"; case 8: return "IACPKIX";
        case 253: return "URI"; case 254: return "OID";
        default: snprintf(buf, buf_size, "%u", type); return buf;
    }
}

static void decode_type_bitmap(const uint8_t *bitmap, size_t bitmap_len, char *out, size_t out_cap) {
    size_t pos = 0, out_len = 0;
    out[0] = '\0';
    while (pos + 2 <= bitmap_len) {
        uint8_t window = bitmap[pos];
        uint8_t block_len = bitmap[pos + 1];
        pos += 2;
        if (pos + block_len > bitmap_len) break;
        for (int byte_idx = 0; byte_idx < block_len; byte_idx++) {
            uint8_t b = bitmap[pos + byte_idx];
            for (int bit = 0; bit < 8; bit++) {
                if (b & (0x80 >> bit)) {
                    uint16_t type_code = (window << 8) | (byte_idx * 8 + bit);
                    char tbuf[32];
                    const char *tname = format_type_name(type_code, tbuf, sizeof(tbuf));
                    int n = snprintf(out + out_len, out_cap - out_len, "%s%s",
                                      (out_len > 0) ? " " : "", tname);
                    if (n < 0 || (size_t)n >= out_cap - out_len) return;
                    out_len += (size_t)n;
                }
            }
        }
        pos += block_len;
    }
}

static void print_dnskey_like(const uint8_t *rdata, size_t rdlen) {
    if (rdlen < 4) { printf("(malformed)"); return; }
    uint16_t flags = (rdata[0]<<8)|rdata[1];
    uint8_t protocol = rdata[2];
    uint8_t algorithm = rdata[3];
    size_t b64_cap = ((rdlen - 4) * 4 / 3) + 8;
    char *b64 = malloc(b64_cap);
    if (!b64) { printf("(oom)"); return; }
    int n = EVP_EncodeBlock((unsigned char*)b64, &rdata[4], (int)(rdlen - 4));
    printf("%u %u %u %.*s", flags, protocol, algorithm, n, b64);
    free(b64);
}

static void print_ds_like(const uint8_t *rdata, size_t rdlen) {
    if (rdlen < 4) { printf("(malformed)"); return; }
    uint16_t keytag = (rdata[0]<<8)|rdata[1];
    uint8_t algorithm = rdata[2];
    uint8_t digest_type = rdata[3];
    printf("%u %u %u ", keytag, algorithm, digest_type);
    for (size_t i = 4; i < rdlen; i++) printf("%02X", rdata[i]);
}

static void base32hex_encode(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    size_t out_len = 0;
    int buffer = 0, bits_left = 0;
    for (size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | data[i];
        bits_left += 8;
        while (bits_left >= 5) {
            if (out_len + 1 >= out_cap) { out[out_len] = '\0'; return; }
            out[out_len++] = alphabet[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }
    if (bits_left > 0 && out_len + 1 < out_cap) {
        out[out_len++] = alphabet[(buffer << (5 - bits_left)) & 0x1F];
    }
    out[out_len] = '\0';
}

static void format_rrsig_time(uint32_t t, char *out, size_t out_cap) {
    time_t tt = (time_t)t;
    struct tm tm_buf;
    gmtime_r(&tt, &tm_buf);
    strftime(out, out_cap, "%Y%m%d%H%M%S", &tm_buf);
}

static void print_nsec3_params(const uint8_t *rdata, size_t rdlen, bool with_hash) {
    if (rdlen < 5) { printf("(malformed)"); return; }
    uint8_t hash_alg = rdata[0];
    uint8_t flags = rdata[1];
    uint16_t iterations = (rdata[2]<<8)|rdata[3];
    uint8_t salt_len = rdata[4];
    if (5 + salt_len > rdlen) { printf("(malformed)"); return; }
    char salt_hex[512] = "-";
    if (salt_len > 0) {
        size_t p2 = 0;
        for (int i = 0; i < salt_len; i++) p2 += snprintf(salt_hex + p2, sizeof(salt_hex) - p2, "%02X", rdata[5 + i]);
    }
    printf("%u %u %u %s", hash_alg, flags, iterations, salt_hex);

    if (with_hash) { // NSEC3 specific
        if (5 + salt_len + 1 > rdlen) { printf(" (malformed)"); return; }
        size_t pos = 5 + salt_len;
        uint8_t hash_len = rdata[pos++];
        if (pos + hash_len > rdlen) { printf(" (malformed)"); return; }
        char hash_b32[128];
        base32hex_encode(&rdata[pos], hash_len, hash_b32, sizeof(hash_b32));
        pos += hash_len;
        char types_buf[512];
        decode_type_bitmap(&rdata[pos], rdlen - pos, types_buf, sizeof(types_buf));
        printf(" %s %s", hash_b32, types_buf);
    }
}

static void print_svcparam_alpn(const uint8_t *value, uint16_t value_len) {
    printf("alpn=\"");
    size_t pos = 0;
    bool first = true;
    while (pos < value_len) {
        uint8_t len = value[pos++];
        if (pos + len > value_len) break;
        if (!first) printf(",");
        printf("%.*s", len, &value[pos]);
        pos += len;
        first = false;
    }
    printf("\"");
}

static void print_svcparam_ipvXhint(const uint8_t *value, uint16_t value_len, bool is_v6) {
    printf("%s=", is_v6 ? "ipv6hint" : "ipv4hint");
    size_t addr_size = is_v6 ? 16 : 4;
    size_t pos = 0;
    bool first = true;
    while (pos + addr_size <= value_len) {
        char buf[64];
        inet_ntop(is_v6 ? AF_INET6 : AF_INET, &value[pos], buf, sizeof(buf));
        if (!first) printf(",");
        printf("%s", buf);
        pos += addr_size;
        first = false;
    }
}

static void print_svcparams(const uint8_t *rdata, size_t offset, size_t rdlen) {
    while (offset + 4 <= rdlen) {
        uint16_t key = (rdata[offset]<<8)|rdata[offset+1];
        uint16_t vlen = (rdata[offset+2]<<8)|rdata[offset+3];
        offset += 4;
        if (offset + vlen > rdlen) break;
        printf(" ");
        const uint8_t *value = &rdata[offset];
        switch (key) {
            case 0: { // mandatory
                printf("mandatory=");
                for (size_t i = 0; i + 2 <= vlen; i += 2) {
                    uint16_t mkey = (value[i]<<8)|value[i+1];
                    printf("%s%u", (i>0)?",":"", mkey);
                }
                break;
            }
            case 1: print_svcparam_alpn(value, vlen); break;
            case 2: printf("no-default-alpn"); break;
            case 3: { // port
                uint16_t port = (vlen>=2) ? ((value[0]<<8)|value[1]) : 0;
                printf("port=%u", port);
                break;
            }
            case 4: print_svcparam_ipvXhint(value, vlen, false); break;
            case 5: { // ech
                size_t b64_cap = (vlen * 4 / 3) + 8;
                char *b64 = malloc(b64_cap);
                if (b64) {
                    int n = EVP_EncodeBlock((unsigned char*)b64, value, (int)vlen);
                    printf("ech=\"%.*s\"", n, b64);
                    free(b64);
                }
                break;
            }
            case 6: print_svcparam_ipvXhint(value, vlen, true); break;
            default: { // unknown
                printf("key%u=\"", key);
                for (uint16_t i = 0; i < vlen; i++) printf("%02x", value[i]);
                printf("\"");
                break;
            }
        }
        offset += vlen;
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
        case 2: case 5: case 12: case 39: { // NS / CNAME / PTR / DNAME
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
        case 17: { // RP
            char *mbox = NULL, *txt = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, NULL, &mbox) != 0 ||
                expand_wire_name(pkt, pkt_len, next, &next, NULL, &txt) != 0) {
                goto fallback;
            }
            printf("%s %s", mbox, txt);
            break;
        }
        case 18: { // AFSDB
            if (rdlen < 3) goto fallback;
            uint16_t subtype = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *hostname = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, NULL, &hostname) != 0) goto fallback;
            printf("%u %s", subtype, hostname);
            break;
        }

        case 13: { // HINFO
            char cpu[256], os[256];
            const uint8_t *p = &pkt[abs_offset];
            const uint8_t *end = p + rdlen;
            p = read_char_string(p, end, cpu, sizeof(cpu));
            if (!p) goto fallback;
            p = read_char_string(p, end, os, sizeof(os));
            if (!p) goto fallback;
            printf("\"%s\" \"%s\"", cpu, os);
            break;
        }
        case 26: { // PX
            if (rdlen < 2) goto fallback;
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *map822 = NULL, *mapx400 = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, NULL, &map822) != 0 ||
                expand_wire_name(pkt, pkt_len, next, &next, NULL, &mapx400) != 0) {
                goto fallback;
            }
            printf("%u %s %s", pref, map822, mapx400);
            break;
        }
        case 29: { // LOC
            if (rdlen != 16) goto fallback;
            uint8_t size_b = pkt[abs_offset + 1], hp_b = pkt[abs_offset + 2], vp_b = pkt[abs_offset + 3];
            uint32_t lat_wire = ((uint32_t)pkt[abs_offset + 4]<<24)|((uint32_t)pkt[abs_offset + 5]<<16)|((uint32_t)pkt[abs_offset + 6]<<8)|pkt[abs_offset + 7];
            uint32_t lon_wire = ((uint32_t)pkt[abs_offset + 8]<<24)|((uint32_t)pkt[abs_offset + 9]<<16)|((uint32_t)pkt[abs_offset + 10]<<8)|pkt[abs_offset + 11];
            uint32_t alt_wire = ((uint32_t)pkt[abs_offset + 12]<<24)|((uint32_t)pkt[abs_offset + 13]<<16)|((uint32_t)pkt[abs_offset + 14]<<8)|pkt[abs_offset + 15];
            double alt_m = ((int64_t)alt_wire - 10000000LL) / 100.0;
            char lat_buf[64], lon_buf[64];
            loc_format_coord(lat_wire, true, lat_buf, sizeof(lat_buf));
            loc_format_coord(lon_wire, false, lon_buf, sizeof(lon_buf));
            printf("%s %s %.2fm %.2fm %.2fm %.2fm", lat_buf, lon_buf, alt_m,
                   loc_decode_precsize(size_b), loc_decode_precsize(hp_b), loc_decode_precsize(vp_b));
            break;
        }
        case 35: { // NAPTR
            if (rdlen < 4) goto fallback;
            uint16_t order = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            uint16_t pref = (pkt[abs_offset + 2] << 8) | pkt[abs_offset + 3];
            char flags[256], svcs[256], regexp[256];
            const uint8_t *p = &pkt[abs_offset + 4];
            const uint8_t *end = &pkt[abs_offset + rdlen];
            p = read_char_string(p, end, flags, sizeof(flags)); if (!p) goto fallback;
            p = read_char_string(p, end, svcs, sizeof(svcs)); if (!p) goto fallback;
            p = read_char_string(p, end, regexp, sizeof(regexp)); if (!p) goto fallback;
            char *repl = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, p - pkt, &next, NULL, &repl) != 0) goto fallback;
            printf("%u %u \"%s\" \"%s\" \"%s\" %s", order, pref, flags, svcs, regexp, repl);
            break;
        }
        case 21: case 36: case 107: { // RT / KX / LP
            if (rdlen < 2) goto fallback;
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, NULL, &name) != 0) goto fallback;
            printf("%u %s", pref, name);
            break;
        }
        case 37: { // CERT
            if (rdlen < 5) goto fallback;
            uint16_t ctype = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            uint16_t keytag = (pkt[abs_offset + 2] << 8) | pkt[abs_offset + 3];
            uint8_t alg = pkt[abs_offset + 4];
            char cbuf[32];
            printf("%s %u %u ", cert_type_name(ctype, cbuf, sizeof(cbuf)), keytag, alg);
            if (rdlen > 5) {
                size_t b64_len = 4 * ((rdlen - 5 + 2) / 3) + 1;
                char *b64 = malloc(b64_len);
                if (!b64) goto fallback;
                EVP_EncodeBlock((unsigned char *)b64, &pkt[abs_offset + 5], rdlen - 5);
                printf("%s", b64);
                free(b64);
            }
            break;
        }
        case 42: { // APL
            size_t pos = 0;
            bool first = true;
            while (pos + 4 <= rdlen) {
                uint16_t afi = (pkt[abs_offset + pos]<<8)|pkt[abs_offset + pos+1];
                uint8_t prefix = pkt[abs_offset + pos+2];
                uint8_t neg_len = pkt[abs_offset + pos+3];
                bool negate = (neg_len & 0x80) != 0;
                uint8_t afdlength = neg_len & 0x7F;
                pos += 4;
                if (pos + afdlength > rdlen) break;

                // RFC 3123: afdlength for AFI=1 must be <=4, AFI=2 must be <=16
                uint8_t max_len = (afi == 1) ? 4 : (afi == 2) ? 16 : 0;
                bool afd_invalid = (max_len == 0 || afdlength > max_len);
                uint8_t addr[16] = {0};
                size_t copy_len = (afdlength > sizeof(addr)) ? sizeof(addr) : afdlength;
                memcpy(addr, &pkt[abs_offset + pos], copy_len);
                pos += afdlength; // rdlen上の位置は仕様通りに進める

                if (afd_invalid) {
                    if (!first) printf(" ");
                    printf("[APL afdlength=%u invalid for AFI=%u]", afdlength, afi);
                    first = false;
                    continue;
                }
                char addr_str[64] = "?";
                if (afi == 1) inet_ntop(AF_INET, addr, addr_str, sizeof(addr_str));
                else if (afi == 2) inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));

                if (!first) printf(" ");
                printf("%s%u:%s/%u", negate ? "!" : "", afi, addr_str, prefix);
                first = false;
            }
            if (first && rdlen != 0 && pos != rdlen) goto fallback;
            break;
        }
        case 44: { // SSHFP
            if (rdlen < 2) goto fallback;
            printf("%u %u ", pkt[abs_offset], pkt[abs_offset + 1]);
            for (size_t i = 2; i < rdlen; i++) printf("%02X", pkt[abs_offset + i]);
            break;
        }
        case 45: { // IPSECKEY
            if (rdlen < 3) goto fallback;
            uint8_t prec = pkt[abs_offset];
            uint8_t gw_type = pkt[abs_offset + 1];
            uint8_t alg = pkt[abs_offset + 2];
            printf("%u %u %u ", prec, gw_type, alg);
            const uint8_t *p = &pkt[abs_offset + 3];
            const uint8_t *end = &pkt[abs_offset + rdlen];
            if (gw_type == 0) {
                printf(". ");
            } else if (gw_type == 1) {
                if (p + 4 > end) goto fallback;
                printf("%d.%d.%d.%d ", p[0], p[1], p[2], p[3]);
                p += 4;
            } else if (gw_type == 2) {
                if (p + 16 > end) goto fallback;
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, p, buf, sizeof(buf));
                printf("%s ", buf);
                p += 16;
            } else if (gw_type == 3) {
                char *gw = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, p - pkt, &next, NULL, &gw) != 0) goto fallback;
                printf("%s ", gw);
                p = &pkt[next];
            } else goto fallback;
            if (p < end) {
                size_t key_len = end - p;
                size_t b64_len = 4 * ((key_len + 2) / 3) + 1;
                char *b64 = malloc(b64_len);
                if (!b64) goto fallback;
                EVP_EncodeBlock((unsigned char *)b64, p, key_len);
                printf("%s", b64);
                free(b64);
            }
            break;
        }
        case 49: case 61: { // DHCID / OPENPGPKEY
            if (rdlen == 0) break;
            size_t b64_len = 4 * ((rdlen + 2) / 3) + 1;
            char *b64 = malloc(b64_len);
            if (!b64) goto fallback;
            EVP_EncodeBlock((unsigned char *)b64, &pkt[abs_offset], rdlen);
            printf("%s", b64);
            free(b64);
            break;
        }
        case 51: { // NSEC3PARAM
            print_nsec3_params(&pkt[abs_offset], rdlen, false);
            break;
        }
        case 52: case 53: { // TLSA / SMIMEA
            if (rdlen < 3) goto fallback;
            printf("%u %u %u ", pkt[abs_offset], pkt[abs_offset + 1], pkt[abs_offset + 2]);
            for (size_t i = 3; i < rdlen; i++) printf("%02X", pkt[abs_offset + i]);
            break;
        }
        case 64: case 65: { // SVCB / HTTPS
            if (rdlen < 2) goto fallback;
            uint16_t priority = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            char *target = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, NULL, &target) != 0) goto fallback;
            size_t target_len = next - abs_offset - 2;
            printf("%u %s", priority, (target[0] == '\0') ? "." : target);
            print_svcparams(&pkt[abs_offset], 2 + target_len, rdlen);
            break;
        }
        case 108: { // EUI48
            if (rdlen != 6) goto fallback;
            printf("%02x-%02x-%02x-%02x-%02x-%02x", 
                pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], 
                pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5]);
            break;
        }
        case 109: { // EUI64
            if (rdlen != 8) goto fallback;
            printf("%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x", 
                pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], pkt[abs_offset+3], 
                pkt[abs_offset+4], pkt[abs_offset+5], pkt[abs_offset+6], pkt[abs_offset+7]);
            break;
        }
        case 256: { // URI
            if (rdlen < 4) goto fallback;
            uint16_t prio = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            uint16_t weight = (pkt[abs_offset + 2] << 8) | pkt[abs_offset + 3];
            printf("%u %u \"%.*s\"", prio, weight, (int)(rdlen - 4), &pkt[abs_offset + 4]);
            break;
        }
        case 257: { // CAA
            if (rdlen < 2) goto fallback;
            uint8_t flags = pkt[abs_offset];
            uint8_t tag_len = pkt[abs_offset + 1];
            if (2 + tag_len > rdlen) goto fallback;
            printf("%u %.*s \"%.*s\"", flags, tag_len, &pkt[abs_offset + 2], (int)(rdlen - 2 - tag_len), &pkt[abs_offset + 2 + tag_len]);
            break;
        }
        case 260: { // AMTRELAY
            if (rdlen < 1) goto fallback;
            uint8_t prec = pkt[abs_offset];
            uint8_t d_opt = (prec & 0x80) != 0;
            prec &= 0x7F;
            if (rdlen < 2) {
                printf("%u %u 0 .", prec, d_opt);
                break;
            }
            uint8_t relay_type = pkt[abs_offset + 1];
            const uint8_t *p = &pkt[abs_offset + 2];
            const uint8_t *end = &pkt[abs_offset + rdlen];
            printf("%u %u %u ", prec, d_opt, relay_type);
            if (relay_type == 0) {
                printf(".");
            } else if (relay_type == 1) {
                if (p + 4 > end) goto fallback;
                printf("%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
            } else if (relay_type == 2) {
                if (p + 16 > end) goto fallback;
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, p, buf, sizeof(buf));
                printf("%s", buf);
            } else if (relay_type == 3) {
                char *gw = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, p - pkt, &next, NULL, &gw) != 0) goto fallback;
                printf("%s", gw);
            } else goto fallback;
            break;
        }

        case 46: { // RRSIG
            if (rdlen < 18) goto fallback;
            uint16_t type_covered = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            uint8_t algorithm = pkt[abs_offset+2];
            uint8_t labels = pkt[abs_offset+3];
            uint32_t original_ttl = ((uint32_t)pkt[abs_offset+4]<<24)|((uint32_t)pkt[abs_offset+5]<<16)|((uint32_t)pkt[abs_offset+6]<<8)|pkt[abs_offset+7];
            uint32_t sig_exp = ((uint32_t)pkt[abs_offset+8]<<24)|((uint32_t)pkt[abs_offset+9]<<16)|((uint32_t)pkt[abs_offset+10]<<8)|pkt[abs_offset+11];
            uint32_t sig_inc = ((uint32_t)pkt[abs_offset+12]<<24)|((uint32_t)pkt[abs_offset+13]<<16)|((uint32_t)pkt[abs_offset+14]<<8)|pkt[abs_offset+15];
            uint16_t key_tag = (pkt[abs_offset+16]<<8)|pkt[abs_offset+17];

            char *signer_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 18, &next, NULL, &signer_name) != 0) goto fallback;
            size_t sig_offset_in_rdata = (next - abs_offset);
            if (sig_offset_in_rdata >= rdlen) goto fallback;

            char covered_buf[32];
            const char *covered_name = format_type_name(type_covered, covered_buf, sizeof(covered_buf));
            char exp_str[32], inc_str[32];
            format_rrsig_time(sig_exp, exp_str, sizeof(exp_str));
            format_rrsig_time(sig_inc, inc_str, sizeof(inc_str));

            size_t sig_len = rdlen - sig_offset_in_rdata;
            size_t b64_cap = (sig_len * 4 / 3) + 8;
            char *b64 = malloc(b64_cap);
            if (!b64) goto fallback;
            int n = EVP_EncodeBlock((unsigned char*)b64, &pkt[abs_offset + sig_offset_in_rdata], (int)sig_len);

            printf("%s %u %u %u %s %s %u %s %.*s", covered_name, algorithm, labels,
                   original_ttl, exp_str, inc_str, key_tag, signer_name, n, b64);
            free(b64);
            break;
        }
        case 47: { // NSEC
            char *next_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, NULL, &next_name) != 0) goto fallback;
            size_t name_consumed = next - abs_offset;
            if (name_consumed >= rdlen) goto fallback;
            char types_buf[512];
            decode_type_bitmap(&pkt[abs_offset + name_consumed], rdlen - name_consumed, types_buf, sizeof(types_buf));
            printf("%s %s", next_name, types_buf);
            break;
        }
        case 48: case 60: { // DNSKEY / CDNSKEY
            print_dnskey_like(&pkt[abs_offset], rdlen);
            break;
        }
        case 50: { // NSEC3
            print_nsec3_params(&pkt[abs_offset], rdlen, true);
            break;
        }
        case 43: case 59: { // DS / CDS
            print_ds_like(&pkt[abs_offset], rdlen);
            break;
        }
        case 62: { // CSYNC
            if (rdlen < 6) goto fallback;
            uint32_t serial = ((uint32_t)pkt[abs_offset]<<24)|((uint32_t)pkt[abs_offset+1]<<16)|((uint32_t)pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
            uint16_t flags = (pkt[abs_offset+4]<<8)|pkt[abs_offset+5];
            char types_buf[512];
            decode_type_bitmap(&pkt[abs_offset+6], rdlen - 6, types_buf, sizeof(types_buf));
            printf("%u %u %s", serial, flags, types_buf);
            break;
        }
        case 250: { // TSIG
            char *alg_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, NULL, &alg_name) != 0) goto fallback;
            size_t pos = next - abs_offset;
            if (pos + 10 > rdlen) goto fallback;

            uint64_t time_signed = ((uint64_t)pkt[abs_offset+pos] << 40) | ((uint64_t)pkt[abs_offset+pos+1] << 32) |
                                    ((uint64_t)pkt[abs_offset+pos+2] << 24) | ((uint64_t)pkt[abs_offset+pos+3] << 16) |
                                    ((uint64_t)pkt[abs_offset+pos+4] << 8) | pkt[abs_offset+pos+5];
            uint16_t fudge = (pkt[abs_offset+pos+6]<<8)|pkt[abs_offset+pos+7];
            uint16_t mac_size = (pkt[abs_offset+pos+8]<<8)|pkt[abs_offset+pos+9];
            pos += 10;
            if (pos + mac_size + 6 > rdlen) goto fallback;

            size_t b64_cap = (mac_size * 4 / 3) + 8;
            char *mac_b64 = malloc(b64_cap);
            int n = mac_b64 ? EVP_EncodeBlock((unsigned char*)mac_b64, &pkt[abs_offset+pos], (int)mac_size) : 0;
            pos += mac_size;

            uint16_t original_id = (pkt[abs_offset+pos]<<8)|pkt[abs_offset+pos+1];
            uint16_t tsig_error = (pkt[abs_offset+pos+2]<<8)|pkt[abs_offset+pos+3];
            uint16_t other_len = (pkt[abs_offset+pos+4]<<8)|pkt[abs_offset+pos+5];
            
            const char *err_str = rcode_name(tsig_error);

            printf("%s %llu %u %u %.*s %u %s %u", alg_name, (unsigned long long)time_signed,
                   fudge, mac_size, n, mac_b64 ? mac_b64 : "", original_id,
                   err_str, other_len);
            if (mac_b64) free(mac_b64);
            break;
        }
        case 55: { // HIP
            if (rdlen < 4) goto fallback;
            uint8_t hit_len = pkt[abs_offset];
            uint8_t pk_algorithm = pkt[abs_offset+1];
            uint16_t pk_len = (pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
            size_t pos = 4;
            if (pos + hit_len + pk_len > rdlen) goto fallback;

            printf("%u ", pk_algorithm);
            for (int i = 0; i < hit_len; i++) printf("%02X", pkt[abs_offset + pos + i]);
            pos += hit_len;

            size_t b64_cap = (pk_len * 4 / 3) + 8;
            char *b64 = malloc(b64_cap);
            if (!b64) goto fallback;
            int n = EVP_EncodeBlock((unsigned char*)b64, &pkt[abs_offset + pos], (int)pk_len);
            printf(" %.*s", n, b64);
            free(b64);
            pos += pk_len;

            while (pos < rdlen) {
                char *rvs_name = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset + pos, &next, NULL, &rvs_name) != 0) break;
                printf(" %s", rvs_name);
                pos = next - abs_offset;
            }
            break;
        }
        default:
        fallback:
            printf("\\# %u ", rdlen);
            for (uint16_t i = 0; i < rdlen && abs_offset + i < pkt_len; i++) printf("%02x", pkt[abs_offset + i]);
            break;
    }
}

typedef struct {
    bool is_axfr;
    char first_soa_name[256];
    uint8_t first_soa_norm[512];
    size_t first_soa_norm_len;
    int soa_seen_count;
    bool axfr_complete;
} axfr_state_t;

static void check_axfr_soa(axfr_state_t *state, const uint8_t *pkt, size_t pkt_len, const char *name, const uint8_t *hdr, uint16_t rdlen) {
    if (!state || !state->is_axfr) return;
    const uint8_t *rdata = hdr + 10;
    
    char *mname = NULL, *rname = NULL;
    size_t next1, next2;
    if (expand_wire_name(pkt, pkt_len, rdata - pkt, &next1, NULL, &mname) != 0) return;
    if (expand_wire_name(pkt, pkt_len, next1, &next2, NULL, &rname) != 0) return;
    if (next2 + 20 > (size_t)(rdata - pkt) + rdlen) return;

    size_t mlen = strlen(mname);
    size_t rlen = strlen(rname);
    size_t norm_len = mlen + 1 + rlen + 1 + 20;
    if (norm_len > sizeof(state->first_soa_norm)) return;

    uint8_t norm[512];
    memcpy(norm, mname, mlen + 1);
    memcpy(norm + mlen + 1, rname, rlen + 1);
    memcpy(norm + mlen + 1 + rlen + 1, pkt + next2, 20);

    if (state->soa_seen_count == 0) {
        snprintf(state->first_soa_name, sizeof(state->first_soa_name), "%s", name);
        memcpy(state->first_soa_norm, norm, norm_len);
        state->first_soa_norm_len = norm_len;
        state->soa_seen_count = 1;
    } else {
        if (strcmp(state->first_soa_name, name) == 0 &&
            norm_len == state->first_soa_norm_len &&
            memcmp(norm, state->first_soa_norm, norm_len) == 0) {
            state->axfr_complete = true;
        }
        state->soa_seen_count++;
    }
}

static bool print_one_rr(const uint8_t *pkt, size_t pkt_len, size_t *offset, axfr_state_t *axfr_state) {
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

    char tname_buf[32];
    if (type == 6) {
        check_axfr_soa(axfr_state, pkt, pkt_len, name, &pkt[hdr], rdlen);
    }

    const char *tname = format_type_name(type, tname_buf, sizeof(tname_buf));
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

static void print_response(const uint8_t *pkt, size_t pkt_len, axfr_state_t *axfr_state) {
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
            char qtname_buf[32];
            const char *qtname = format_type_name(qtype, qtname_buf, sizeof(qtname_buf));
            printf(";%-24s %-4s %s\n", name, (qclass == 1) ? "IN" : (qclass == 255) ? "ANY" : "CH", qtname);
            offset = next + 4;
        }
    }

    if (ancount > 0) {
        printf("\n;; ANSWER SECTION:\n");
        for (int i = 0; i < ancount; i++) if (!print_one_rr(pkt, pkt_len, &offset, axfr_state)) { printf(";; (failed to parse answer record %d, stopping here)\n", i); goto fallback; }
    }
    if (nscount > 0) {
        printf("\n;; AUTHORITY SECTION:\n");
        for (int i = 0; i < nscount; i++) if (!print_one_rr(pkt, pkt_len, &offset, axfr_state)) { printf(";; (failed to parse authority record %d, stopping here)\n", i); goto fallback; }
    }
    if (arcount > 0) {
        printf("\n;; ADDITIONAL SECTION:\n");
        for (int i = 0; i < arcount; i++) if (!print_one_rr(pkt, pkt_len, &offset, axfr_state)) { printf(";; (failed to parse additional record %d, stopping here)\n", i); goto fallback; }
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

static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t parse_hex_string(const char *hex, uint8_t *out, size_t out_cap) {
    size_t out_len = 0;
    while (*hex) {
        int h1 = hex_char_to_int(*hex++);
        if (h1 < 0) continue;
        int h2 = -1;
        while (*hex) {
            h2 = hex_char_to_int(*hex++);
            if (h2 >= 0) break;
        }
        if (h2 < 0) break;
        if (out_len < out_cap) out[out_len++] = (uint8_t)((h1 << 4) | h2);
    }
    return out_len;
}
static int run_test(const char *test_name, const char *qname, const char *qtype_s, const char *server, int port,
                    bool use_tcp, bool use_ldnsz, bool short_mode, bool norecurse,
                    bool adflag, bool cdflag, bool aaflag, bool tcflag, bool zflag,
                    bool no_hexdump_query, bool no_hexdump_response,
                    query_opts_t *qo, const char *hex_payload) {
    if (test_name) {
        printf("=========================================================\n");
        printf(">>> TEST: %s\n", test_name);
        printf("=========================================================\n");
    }

    uint16_t qtype = 0;
    if (strncasecmp(qtype_s, "IXFR=", 5) == 0) {
        qtype = 251;
        qo->is_ixfr = true;
        qo->ixfr_serial = strtoul(qtype_s + 5, NULL, 10);
        use_tcp = true;
    } else {
        qtype = parse_qtype(qtype_s);
    }

    uint8_t pkt[65535];
    size_t pkt_len = 0;

    if (hex_payload) {
        pkt_len = parse_hex_string(hex_payload, pkt, sizeof(pkt));
        if (pkt_len == 0) {
            fprintf(stderr, "Error: Invalid or empty hex payload\n");
            return 1;
        }
    } else {
        pkt_len = build_query_packet(pkt, sizeof(pkt), qname, qtype, qo);
        if (pkt_len == 0) return 1;
    }

    if (qo->want_tsig) {
        if (tsig_sign_packet(pkt, &pkt_len, sizeof(pkt), &qo->tsig_key, 0, NULL, 0, false) != 0) {
            fprintf(stderr, "Error: tsig_sign_packet failed\n");
            return 1;
        }
    }

    if (norecurse) {
        pkt[2] &= ~0x01; // Clear RD bit
    }
    if (adflag) {
        pkt[3] |= 0x20;  // Set AD bit
    }
    if (cdflag) {
        pkt[3] |= 0x10;  // Set CD bit
    }
    if (aaflag) {
        pkt[2] |= 0x04;  // Set AA bit
    }
    if (tcflag) {
        pkt[2] |= 0x02;  // Set TC bit
    }
    if (zflag) {
        pkt[3] |= 0x40;  // Set Z bit
    }

    bool retry_tcp = false;
    do {
        retry_tcp = false;
        struct timeval start_tv;
        
        axfr_state_t axfr_state = {0};
        axfr_state.is_axfr = (qtype == 252 || qtype == 251);
        gettimeofday(&start_tv, NULL);

        if (!short_mode) {
            printf("; <<>> dag <<>> %s %s @%s%s\n", qname, qtype_s, server, use_tcp ? " (tcp)" : "");
            printf("Query (%zu bytes):\n", pkt_len);
            if (!no_hexdump_query) {
                hexdump(pkt, pkt_len);
            } else {
                printf("(hexdump suppressed)\n");
            }
            printf("\n");
        }

        static uint8_t resp[65535];
        ssize_t n = -1;
        int attempts = 0;
        int max_tries = (qo->tries < 1) ? 1 : qo->tries;
        
        int tcp_sock = -1;
        while (attempts < max_tries) {
            attempts++;
            if (use_tcp) {
                tcp_sock = do_tcp_send_request(server, port, pkt, pkt_len, qo->timeout_sec);
                if (tcp_sock >= 0) {
                    n = do_tcp_recv_response(tcp_sock, resp, sizeof(resp));
                    if (n > 0) {
                        break; // connected and got first message
                    }
                    close(tcp_sock);
                    tcp_sock = -1;
                    n = -1;
                }
            } else {
                n = do_udp_exchange(server, port, pkt, pkt_len, resp, sizeof(resp), qo->timeout_sec);
                if (n >= 0) break;
            }
            if (attempts < max_tries) {
                if (!short_mode) printf(";; connection timed out; retrying...\n");
            }
        }

        if (n <= 0) {
            printf(";; no usable response received\n");
            return 1;
        }

        if (!use_tcp && n >= 4 && (resp[2] & 0x02) != 0) {
            if (!short_mode) {
                reset_dag_arena();
                printf("Response (%zd bytes, UDP):\n", n);
                if (!no_hexdump_response) {
                    hexdump(resp, (size_t)n);
                } else {
                    printf("(hexdump suppressed)\n");
                }
                if (use_ldnsz) {
                    print_ldnsz_url(resp, (size_t)n);
                }
                printf("\n");
                print_response(resp, (size_t)n, &axfr_state);
            }
            fprintf(stderr, ";; Truncated, retrying in TCP mode.\n");
            use_tcp = true;
            tcp_sock = do_tcp_send_request(server, port, pkt, pkt_len, qo->timeout_sec);
            if (tcp_sock < 0) {
                fprintf(stderr, "dag: TCP retry failed\n");
                return 1;
            }
            n = do_tcp_recv_response(tcp_sock, resp, sizeof(resp));
            if (n <= 0) {
                printf(";; no usable response received on TCP retry\n");
                return 1;
            }
            memset(&axfr_state, 0, sizeof(axfr_state));
            axfr_state.is_axfr = (qtype == 252 || qtype == 251);
        }


        int msg_index = 1;
        int total_records = 0;
        size_t total_bytes = 0;
        do {
            total_bytes += (size_t)n;
            if (n >= 12) {
                total_records += (resp[6] << 8) | resp[7];
            }
            reset_dag_arena();
            if (!short_mode) {
                if (use_tcp) {
                    printf("Response message %d (%zd bytes, TCP):\n", msg_index, n);
                } else {
                    printf("Response (%zd bytes, UDP):\n", n);
                }
                if (!no_hexdump_response) {
                    hexdump(resp, (size_t)n);
                } else {
                    printf("(hexdump suppressed)\n");
                }
                if (use_ldnsz) {
                    print_ldnsz_url(resp, (size_t)n);
                }
                printf("\n");
                print_response(resp, (size_t)n, &axfr_state);
            } else {
                uint16_t ancount = (resp[6] << 8) | resp[7];
                size_t off = 12;
                uint16_t qdcount = (resp[4] << 8) | resp[5];
                for (int k=0; k<qdcount; k++) {
                    size_t nxt; if(skip_wire_name(resp, n, off, &nxt)==0) off = nxt + 4;
                }
                for (int k=0; k<ancount; k++) {
                    char *name = NULL;
                    size_t nxt; if(expand_wire_name(resp, n, off, &nxt, NULL, &name)==0) {
                        uint16_t type = (resp[nxt]<<8)|resp[nxt+1];
                        uint16_t rdlen = (resp[nxt+8]<<8)|resp[nxt+9];
                        if (type == 6) {
                            check_axfr_soa(&axfr_state, resp, n, name, &resp[nxt], rdlen);
                        }
                        print_rdata(resp, n, type, nxt+10, rdlen);
                        printf("\n");
                        off = nxt+10+rdlen;
                    } else break;
                }
            }

            if (axfr_state.is_axfr && axfr_state.axfr_complete) break;
            
            // AXFR/IXFR 以外の通常クエリは応答が1メッセージで終わるため、次を待たずに抜ける
            if (!axfr_state.is_axfr) break;

            if (use_tcp && tcp_sock >= 0) {
                n = do_tcp_recv_response(tcp_sock, resp, sizeof(resp));
                if (n > 0) msg_index++;
            } else {
                n = 0; // stop loop for UDP
            }
        } while (n > 0);

        struct timeval end_tv;
        gettimeofday(&end_tv, NULL);
        long elapsed_ms = (end_tv.tv_sec - start_tv.tv_sec) * 1000 +
                          (end_tv.tv_usec - start_tv.tv_usec) / 1000;

        time_t now = time(NULL);
        char time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%a %b %e %H:%M:%S %Z %Y", localtime(&now));

        printf("\n;; Query time: %ld msec\n", elapsed_ms);
        printf(";; SERVER: %s#%d(%s) (%s)\n", server, port, server, use_tcp ? "TCP" : "UDP");
        printf(";; WHEN: %s\n", time_buf);
        if (qtype == 252 || qtype == 251) {
            printf(";; XFR size: %d records (messages %d, bytes %zu)\n", total_records, msg_index, total_bytes);
        }

        if (tcp_sock >= 0) close(tcp_sock);
        n = 1; // set to valid value to avoid retry logic thinking it failed

        if (!use_tcp && n >= 12 && (resp[2] & 0x02) != 0) {
            printf("\n;; Truncated, retrying in TCP mode...\n\n");
            use_tcp = true;
            retry_tcp = true;
        }
    } while (retry_tcp);

    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <name> <type|IXFR=serial> @<server>[,<server>...] [-p <port>] [+tcp]\n"
        "          [+edns] [+dnssec] [+nsid] [+cookie[=hex]] [+nocookie]\n"
        "          [+subnet=addr[/prefix]] [+bufsize=N] [+adflag] [+cdflag]\n"
        "          [+aaflag] [+tcflag] [+zflag] [+ednsopt=CODE[:HEX]]\n"
        "          [+padding=N] [+timeout=N] [+tries=N] [+ldnsz]\n"
        "          [-y [alg:]name:secret] [+tsig=alg:name:secret]\n"
        "          [--test-all] [--break <kind>[=<param>] ...]\n"
        "          [+nohexdump] [+nohexdump-query] [+nohexdump-response]\n"
        "\n"
        "  <server> may be an IPv4/IPv6 literal or an FQDN (resolved via the\n"
        "  system resolver), e.g. @8.8.8.8, @2001:4860:4860::8888, @dns.google\n"
        "  Multiple servers can be queried in one run with a comma-separated list:\n"
        "    %s example.com A @8.8.8.8,9.9.9.9,1.1.1.1\n"
        "\n"
        "       %s --break-help    (list all --break kinds)\n",
        prog, prog, prog);
}

static bool make_reverse_name(const char *ip_str, char *out_name, size_t out_len) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ip_str, &a4) == 1) {
        uint8_t *p = (uint8_t *)&a4.s_addr;
        snprintf(out_name, out_len, "%u.%u.%u.%u.in-addr.arpa", p[3], p[2], p[1], p[0]);
        return true;
    } else if (inet_pton(AF_INET6, ip_str, &a6) == 1) {
        uint8_t *p = a6.s6_addr;
        char *ptr = out_name;
        for (int i = 15; i >= 0; i--) {
            int n = snprintf(ptr, out_len - (ptr - out_name), "%x.%x.", p[i] & 0x0F, p[i] >> 4);
            if (n < 0 || (size_t)n >= out_len - (ptr - out_name)) return false;
            ptr += n;
        }
        int n = snprintf(ptr, out_len - (ptr - out_name), "ip6.arpa");
        if (n < 0 || (size_t)n >= out_len - (ptr - out_name)) return false;
        return true;
    }
    return false;
}

static void parse_tsig_str(char *tsig_str, query_opts_t *qo) {
    qo->want_tsig = true;
    char *colon1 = strchr(tsig_str, ':');
    if (colon1) {
        char *colon2 = strchr(colon1 + 1, ':');
        char *alg, *name, *secret_b64;
        if (colon2) {
            *colon1 = '\0'; *colon2 = '\0';
            alg = tsig_str; name = colon1 + 1; secret_b64 = colon2 + 1;
        } else {
            *colon1 = '\0';
            alg = "hmac-sha256"; name = tsig_str; secret_b64 = colon1 + 1;
        }
        qo->tsig_key.algorithm = alg;
        qo->tsig_key.name = name;
        int b64_len = strlen(secret_b64);
        int pad = 0;
        if (b64_len > 0 && secret_b64[b64_len - 1] == '=') pad++;
        if (b64_len > 1 && secret_b64[b64_len - 2] == '=') pad++;
        int dec_len = EVP_DecodeBlock(qo->tsig_key.secret_decoded, (const unsigned char *)secret_b64, b64_len);
        if (dec_len > 0) {
            qo->tsig_key.secret_decoded_len = dec_len - pad;
        } else {
            fprintf(stderr, "warning: invalid tsig secret base64\n");
            qo->want_tsig = false;
        }
    } else {
        fprintf(stderr, "warning: invalid tsig format (expected [alg:]name:key)\n");
        qo->want_tsig = false;
    }
}


int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--break-help") == 0) { print_break_help(); return 0; }
    if (argc < 3) { usage(argv[0]); return 1; }

    int arg_idx = 1;
    char rev_name[128];
    const char *qname = NULL;
    const char *qtype_s = NULL;
    const char *server_arg = NULL;
    const char *hex_payload = NULL;

    if (strcmp(argv[arg_idx], "--hex") == 0) {
        if (arg_idx + 1 >= argc) { usage(argv[0]); return 1; }
        hex_payload = argv[arg_idx + 1];
        arg_idx += 2;
        qname = "(hex)";
        qtype_s = "ANY";
    } else if (strncmp(argv[arg_idx], "--hex=", 6) == 0) {
        hex_payload = argv[arg_idx] + 6;
        arg_idx++;
        qname = "(hex)";
        qtype_s = "ANY";
    } else if (strcmp(argv[arg_idx], "-x") == 0) {
        arg_idx++;
        if (arg_idx >= argc) { usage(argv[0]); return 1; }
        if (!make_reverse_name(argv[arg_idx], rev_name, sizeof(rev_name))) {
            fprintf(stderr, "Invalid IP address for -x\n");
            return 1;
        }
        qname = rev_name;
        qtype_s = "PTR";
        arg_idx++;
    } else {
        qname = argv[arg_idx++];
        if (arg_idx < argc && argv[arg_idx][0] != '@' && argv[arg_idx][0] != '+' && argv[arg_idx][0] != '-') {
            qtype_s = argv[arg_idx++];
        } else {
            qtype_s = "A";
        }
    }

    if (arg_idx < argc && argv[arg_idx][0] == '@') {
        server_arg = argv[arg_idx++];
    } else {
        fprintf(stderr, "Server must start with '@', e.g. @192.0.2.1\n");
        return 1;
    }

    /*
     * @8.8.8.8,9.9.9.9 のようにカンマ区切りで複数サーバーを指定できるようにする。
     * 各要素はIPv4/IPv6リテラルの他、@dns.google のようなFQDNも許可する
     * (resolve_server_addr()がgetaddrinfo()で解決する)。
     */
    char *server_list_buf = strdup(server_arg + 1);
    if (!server_list_buf) { perror("strdup"); return 1; }
    const char *servers[MAX_DAG_SERVERS];
    int server_count = 0;
    {
        char *save = NULL;
        char *tok = strtok_r(server_list_buf, ",", &save);
        while (tok) {
            if (*tok == '\0') {
                fprintf(stderr, "warning: skipping empty server entry\n");
            } else if (server_count >= MAX_DAG_SERVERS) {
                fprintf(stderr, "warning: too many servers specified, only the first %d will be used\n", MAX_DAG_SERVERS);
                break;
            } else {
                servers[server_count++] = tok;
            }
            tok = strtok_r(NULL, ",", &save);
        }
    }
    if (server_count == 0) {
        fprintf(stderr, "Server must start with '@', e.g. @192.0.2.1 or @192.0.2.1,192.0.2.2,1.1.1.1\n");
        free(server_list_buf);
        return 1;
    }

    int port = 53;
    bool use_tcp = false;
    bool force_udp = false;
    bool use_ldnsz = false;
    bool short_mode = false;
    bool norecurse = false;
    bool adflag = false;
    bool cdflag = false;
    bool aaflag = false;
    bool tcflag = false;
    bool zflag = false;
    bool test_all = false;
    bool no_hexdump_query = false;
    bool no_hexdump_response = false;

    query_opts_t qo;
    memset(&qo, 0, sizeof(qo));
    qo.udp_payload_size = 1232;
    qo.timeout_sec = 5;
    qo.tries = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test-all") == 0) test_all = true;
        if (strcmp(argv[i], "--break") == 0 && i + 1 < argc && strcmp(argv[i+1], "all") == 0) test_all = true;
    }

    for (int i = arg_idx; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--tcp") == 0 || strcmp(argv[i], "+tcp") == 0) {
            use_tcp = true;
        } else if (strcmp(argv[i], "+udp") == 0) {
            force_udp = true;
        } else if (strcmp(argv[i], "+ldnsz") == 0) {
            use_ldnsz = true;
        } else if (strcmp(argv[i], "+short") == 0) {
            short_mode = true;
        } else if (strcmp(argv[i], "+norec") == 0 || strcmp(argv[i], "+norecurse") == 0) {
            norecurse = true;
        } else if (strcmp(argv[i], "+nohexdump") == 0) {
            no_hexdump_query = true;
            no_hexdump_response = true;
        } else if (strcmp(argv[i], "+nohexdump-query") == 0) {
            no_hexdump_query = true;
        } else if (strcmp(argv[i], "+nohexdump-response") == 0) {
            no_hexdump_response = true;
        } else if (strcmp(argv[i], "--break") == 0 && i + 1 < argc) {
            char *brk = argv[++i];
            if (strcmp(brk, "all") == 0) {
                // Already handled in the first loop
            } else {
                parse_break_arg(brk);
            }
        } else if (strcmp(argv[i], "+edns") == 0) {
            qo.want_opt = true;
        } else if (strcmp(argv[i], "+dnssec") == 0) {
            qo.want_opt = true; qo.dnssec_ok = true;
        } else if (strcmp(argv[i], "+nsid") == 0) {
            qo.want_opt = true; qo.want_nsid = true;
        } else if (strncmp(argv[i], "+bufsize=", 9) == 0) {
            qo.want_opt = true; qo.udp_payload_size = (uint16_t)atoi(argv[i] + 9);
        } else if (strcmp(argv[i], "+adflag") == 0) {
            adflag = true;
        } else if (strcmp(argv[i], "+cdflag") == 0) {
            cdflag = true;
        } else if (strcmp(argv[i], "+aaflag") == 0) {
            aaflag = true;
        } else if (strcmp(argv[i], "+tcflag") == 0) {
            tcflag = true;
        } else if (strcmp(argv[i], "+zflag") == 0) {
            zflag = true;
        } else if (strncmp(argv[i], "+timeout=", 9) == 0) {
            qo.timeout_sec = atoi(argv[i] + 9);
        } else if (strncmp(argv[i], "+tries=", 7) == 0) {
            qo.tries = atoi(argv[i] + 7);
        } else if (strncmp(argv[i], "+padding=", 9) == 0) {
            qo.want_opt = true; qo.want_padding = true;
            qo.padding_size = atoi(argv[i] + 9);
        } else if (strncmp(argv[i], "+ednsopt=", 9) == 0) {
            qo.want_opt = true;
            if (qo.custom_edns_opt_count < 8) {
                const char *val = argv[i] + 9;
                char *colon = strchr(val, ':');
                if (colon) {
                    qo.custom_edns_opts[qo.custom_edns_opt_count].code = (uint16_t)strtoul(val, NULL, 10);
                    const char *hex = colon + 1;
                    size_t hex_len = strlen(hex);
                    size_t bytes = hex_len / 2;
                    if (bytes > sizeof(qo.custom_edns_opts[0].data)) bytes = sizeof(qo.custom_edns_opts[0].data);
                    qo.custom_edns_opts[qo.custom_edns_opt_count].len = (uint16_t)bytes;
                    for (size_t j = 0; j < bytes; j++) {
                        unsigned int b; sscanf(hex + j * 2, "%02x", &b);
                        qo.custom_edns_opts[qo.custom_edns_opt_count].data[j] = (uint8_t)b;
                    }
                } else {
                    qo.custom_edns_opts[qo.custom_edns_opt_count].code = (uint16_t)strtoul(val, NULL, 10);
                    qo.custom_edns_opts[qo.custom_edns_opt_count].len = 0;
                }
                qo.custom_edns_opt_count++;
            }
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
        } else if (strcmp(argv[i], "-y") == 0) {
            if (i + 1 < argc) {
                i++;
                char *tsig_str = strdup(argv[i]);
                parse_tsig_str(tsig_str, &qo);
            } else {
                fprintf(stderr, "warning: -y requires an argument\n");
            }
        } else if (strncmp(argv[i], "+tsig=", 6) == 0) {
            char *tsig_str = strdup(argv[i] + 6);
            parse_tsig_str(tsig_str, &qo);
        } else if (strcmp(argv[i], "--test-all") == 0) {
            // Already handled earlier
        } else {
            fprintf(stderr, "warning: unrecognized argument '%s', ignoring\n", argv[i]);
        }
    }

    // AXFRの場合は自動的にTCPモードに昇格（+udpが明示されていない場合）
    if (strcasecmp(qtype_s, "AXFR") == 0 && !force_udp) {
        use_tcp = true;
    }

    for (int i = 0; i < g_break_count; i++) {
        if (is_tcp_only_break(g_breaks[i].kind) && !use_tcp) {
            fprintf(stderr, "error: this --break kind requires --tcp\n");
            return 1;
        }
    }

    for (int si = 0; si < server_count; si++) {
        const char *server = servers[si];
        if (server_count > 1) {
            printf("\n;; ===============================================\n");
            printf(";; Server: %s\n", server);
            printf(";; ===============================================\n");
        }

        if (test_all) {
        struct {
            const char *name; break_kind_t kind; long param; bool tcp;
            bool cdflag; bool zflag; bool aaflag; bool tcflag;
            int padding; int edns_code;
        } all_tests[] = {
            {"Compression Loop", BRK_COMPRESSION_LOOP, 0, false, false,false,false,false, -1, -1},
            {"Compression Forward", BRK_COMPRESSION_FORWARD, 0, false, false,false,false,false, -1, -1},
            {"Label Too Long", BRK_LABEL_TOO_LONG, 100, false, false,false,false,false, -1, -1},
            {"Reserved Length Bits", BRK_RESERVED_LENGTH_BITS, 0, false, false,false,false,false, -1, -1},
            {"Oversized QNAME", BRK_OVERSIZED_QNAME, 0, false, false,false,false,false, -1, -1},
            {"Override QDCOUNT", BRK_QDCOUNT, 2, false, false,false,false,false, -1, -1},
            {"Truncated Question", BRK_TRUNCATED_QUESTION, 0, false, false,false,false,false, -1, -1},
            {"Fake OPT RDLEN", BRK_OPT_RDLEN, 500, false, false,false,false,false, -1, -1},
            {"Override ARCOUNT", BRK_ARCOUNT, 10, false, false,false,false,false, -1, -1},
            {"Override OPCODE", BRK_OPCODE, 15, false, false,false,false,false, -1, -1},
            {"Set QR Bit", BRK_QR_BIT, 0, false, false,false,false,false, -1, -1},
            {"Notify No Question", BRK_NOTIFY_NO_QUESTION, 0, false, false,false,false,false, -1, -1},
            {"Too Short Packet", BRK_TOO_SHORT, 0, false, false,false,false,false, -1, -1},
            {"TCP Length Overclaim", BRK_TCP_LENGTH_OVERCLAIM, 50, true, false,false,false,false, -1, -1},
            {"TCP Zero Length", BRK_TCP_ZERO_LENGTH, 0, true, false,false,false,false, -1, -1},
            {"TCP Idle Hold", BRK_TCP_IDLE_HOLD, 2, true, false,false,false,false, -1, -1},
            {"Bogus EDNS Option", BRK_NONE, 0, false, false,false,false,false, -1, 65535},
            {"Z-Flag Set", BRK_NONE, 0, false, false,true,false,false, -1, -1},
            {"AA-Flag Set", BRK_NONE, 0, false, false,false,true,false, -1, -1},
            {"CD-Flag Set", BRK_NONE, 0, false, true,false,false,false, -1, -1},
            {"TC-Flag Set", BRK_NONE, 0, false, false,false,false,true, -1, -1},
            {"Massive Padding", BRK_NONE, 0, false, false,false,false,false, 2000, -1},
        };

        qo.timeout_sec = 1; // Faster fail for tests
        qo.tries = 1;

        for (size_t t = 0; t < sizeof(all_tests)/sizeof(all_tests[0]); t++) {
            g_break_count = 0;
            if (all_tests[t].kind != BRK_NONE) {
                g_breaks[0].kind = all_tests[t].kind;
                g_breaks[0].param = all_tests[t].param;
                g_breaks[0].has_param = true;
                g_break_count = 1;
            }
            
            query_opts_t t_qo = qo;
            if (all_tests[t].edns_code >= 0) {
                t_qo.want_opt = true;
                t_qo.custom_edns_opts[0].code = all_tests[t].edns_code;
                t_qo.custom_edns_opts[0].len = 4;
                t_qo.custom_edns_opts[0].data[0] = 0xDE;
                t_qo.custom_edns_opts[0].data[1] = 0xAD;
                t_qo.custom_edns_opts[0].data[2] = 0xBE;
                t_qo.custom_edns_opts[0].data[3] = 0xEF;
                t_qo.custom_edns_opt_count = 1;
            }
            if (all_tests[t].padding >= 0) {
                t_qo.want_opt = true;
                t_qo.want_padding = true;
                t_qo.padding_size = all_tests[t].padding;
            }

            run_test(all_tests[t].name, qname, qtype_s, server, port,
                     use_tcp || all_tests[t].tcp, use_ldnsz, short_mode, norecurse,
                     adflag, all_tests[t].cdflag, all_tests[t].aaflag, all_tests[t].tcflag, all_tests[t].zflag,
                     no_hexdump_query, no_hexdump_response,
                     &t_qo, hex_payload);
        }

        } else {
            run_test(NULL, qname, qtype_s, server, port, use_tcp, use_ldnsz, short_mode, norecurse,
                     adflag, cdflag, aaflag, tcflag, zflag,
                     no_hexdump_query, no_hexdump_response, &qo, hex_payload);
        }
    }

    free(server_list_buf);
    return 0;
}
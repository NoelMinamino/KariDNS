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
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <locale.h>
#include <limits.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <io.h>
#define close(s) closesocket(s)
#ifndef MSG_WAITALL
#define MSG_WAITALL 0
#endif

/* Winsock API casting wrappers for uint8_t* buffers to avoid signedness warnings */
#define send(s, b, l, f) send((s), (const char *)(b), (int)(l), (f))
#define recv(s, b, l, f) recv((s), (char *)(b), (int)(l), (f))
#define sendto(s, b, l, f, to, tolen) sendto((s), (const char *)(b), (int)(l), (f), (to), (tolen))

/* Portable gmtime_r for Windows */
static inline struct tm *dag_gmtime_r(const time_t *timep, struct tm *result) {
    if (gmtime_s(result, timep) == 0) return result;
    return NULL;
}
#undef gmtime_r
#define gmtime_r dag_gmtime_r

/* Portable memmem for Windows */
static inline void *dag_memmem(const void *haystack, size_t haystacklen,
                               const void *needle, size_t needlelen) {
    if (!haystack || !needle || needlelen == 0 || haystacklen < needlelen) return NULL;
    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(&h[i], n, needlelen) == 0) {
            return (void *)&h[i];
        }
    }
    return NULL;
}
#undef memmem
#define memmem dag_memmem

#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <signal.h>
#endif

#include <zlib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#ifdef HAVE_LIBIDN2
#include <idn2.h>
#endif
#include "../dns_wire.h"
#include "../dns_utils.h"
#include "../dns_zone_parser.h"

static inline void set_socket_timeouts(int sock, int timeout_sec) {
    int tsec = timeout_sec > 0 ? timeout_sec : 5;
#ifdef _WIN32
    DWORD tv = (DWORD)(tsec * 1000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv = { .tv_sec = tsec, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) && !defined(__APPLE__)
#if defined(__linux__)
#include <sys/random.h>
#include <fcntl.h>
#endif

/* Portable strlcpy for Linux / non-BSD platforms */
static inline size_t dag_strlcpy(char *dst, const char *src, size_t siz) {
    char *d = dst;
    const char *s = src;
    size_t n = siz;

    if (n != 0) {
        while (--n != 0) {
            if ((*d++ = *s++) == '\0')
                break;
        }
    }
    if (n == 0) {
        if (siz != 0)
            *d = '\0';
        while (*s++)
            ;
    }
    return (s - src - 1);
}
#undef strlcpy
#define strlcpy dag_strlcpy

/* Portable arc4random for Linux / non-BSD platforms */
static inline uint32_t dag_arc4random(void) {
    uint32_t val = 0;
    if (RAND_bytes((unsigned char *)&val, sizeof(val)) == 1) {
        return val;
    }
#if defined(__linux__)
    if (getrandom(&val, sizeof(val), 0) == (ssize_t)sizeof(val)) {
        return val;
    }
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, &val, sizeof(val));
        close(fd);
        if (n == (ssize_t)sizeof(val)) return val;
    }
#endif
    static bool warned = false;
    if (!warned) {
        fprintf(stderr, ";; WARNING: all CSPRNG sources failed; falling back to a "
                        "non-cryptographic PRNG. Query IDs/cookies may be predictable.\n");
        warned = true;
    }
    return (uint32_t)rand();
}
#undef arc4random
#define arc4random dag_arc4random
#endif

static bool g_dag_suppress_stdout = false;
#define printf(...) do { if (!g_dag_suppress_stdout) { fprintf(stdout, __VA_ARGS__); } } while(0)
/* ========================================================================
 * 1. Arena (dag only ever bump-allocates scratch strings; never freed)
 * ==================================================================== */
#define DAG_ARENA_SIZE (256 * 1024)
#define MAX_DAG_SERVERS 32

typedef enum {
    MATCH_BASE = 0,
    MATCH_EXACT,       // バイナリ完全一致 (クエリID除く)
    MATCH_SEMANTIC,    // ハッシュ一致 (順序やTTL違い)
    MATCH_DIFF         // 差異あり
} match_status_t;

typedef struct {
    char server_ip[64];
    char proto[8];
    uint8_t rcode;
    uint16_t qdcount, ancount, nscount, arcount;
    bool qr, aa, tc, rd, ra, ad, cd;
    ssize_t resp_len;
    uint8_t resp_buf[65535];
    uint32_t semantic_hash; // 順不同ハッシュの合計値 (Wire format)
    uint32_t record_hash;   // 順不同レコードハッシュの合計値 (Canonical Text)
    long elapsed_ms;
    match_status_t match_status;
    int msg_index;
    int msg_total;
} server_result_t;

#define MAX_DAG_RESULT_ROWS 4096

static server_result_t *g_results = NULL;
static int g_result_cap = 0;
static int g_server_count = 0; // Number of registered rows

static server_result_t *alloc_result_row(void) {
    if (g_server_count >= MAX_DAG_RESULT_ROWS) {
        static bool warned = false;
        if (!warned) {
            fprintf(stderr, ";; warning: result row limit (%d) reached; further messages will not be recorded\n", MAX_DAG_RESULT_ROWS);
            warned = true;
        }
        return NULL;
    }
    if (g_server_count >= g_result_cap) {
        int new_cap = g_result_cap == 0 ? 64 : g_result_cap * 2;
        if (new_cap > MAX_DAG_RESULT_ROWS) new_cap = MAX_DAG_RESULT_ROWS;
        server_result_t *tmp = realloc(g_results, sizeof(server_result_t) * new_cap);
        if (!tmp) {
            fprintf(stderr, ";; warning: out of memory allocating result rows\n");
            return NULL;
        }
        g_results = tmp;
        g_result_cap = new_cap;
    }
    server_result_t *row = &g_results[g_server_count];
    memset(row, 0, sizeof(*row));
    return row;
}
static bool g_want_allcompare = false;
static zone_arena_t g_dag_arena;

static void reset_dag_arena(void) {
    zone_arena_destroy(&g_dag_arena);
    zone_arena_init(&g_dag_arena);
}

static inline int timespec_diff_ms(const struct timespec *start, const struct timespec *end) {
    return (int)((end->tv_sec - start->tv_sec) * 1000 + (end->tv_nsec - start->tv_nsec) / 1000000);
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
        case 25: return "Signature Expired before Valid";
        case 26: return "Too Early";
        case 27: return "Unsupported NSEC3 Iterations Value";
        case 28: return "Unable to conform to policy";
        case 29: return "Synthesized";
        default: return "Unassigned";
    }
}

static bool resolve_qtype(const char *s, uint16_t *out_type) {
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
        {"HTTPS", 65}, {"DSYNC", 66}, {"NXNAME", 128}, {"SPF", 99}, {"NID", 104}, {"L32", 105}, {"L64", 106},
        {"LP", 107}, {"EUI48", 108}, {"EUI64", 109}, {"TKEY", 249}, {"TSIG", 250},
        {"IXFR", 251}, {"AXFR", 252}, {"MAILB", 253}, {"MAILA", 254}, {"ANY", 255},
        {"URI", 256}, {"CAA", 257}, {"AVC", 258}, {"DOA", 259}, {"AMTRELAY", 260},
        {"TA", 32768}, {"DLV", 32769}
    };
    for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
        if (strcasecmp(s, types[i].name) == 0) {
            if (out_type) *out_type = types[i].type;
            return true;
        }
    }
    if (strncasecmp(s, "TYPE", 4) == 0 && s[4] != '\0') {
        char *end;
        long v = strtol(s + 4, &end, 10);
        if (*end == '\0' && v >= 0 && v <= 65535) {
            if (out_type) *out_type = (uint16_t)v;
            return true;
        }
    }
    if (strncasecmp(s, "IXFR=", 5) == 0) {
        if (out_type) *out_type = 251; // IXFR
        return true;
    }
    return false;
}

static bool is_known_qtype(const char *s) {
    return resolve_qtype(s, NULL);
}

static uint16_t parse_qtype(const char *s) {
    uint16_t t;
    if (resolve_qtype(s, &t)) return t;
    fprintf(stderr, "dag: unknown query type '%s'\n", s);
    exit(1);
}

static void print_ldnsz_payload(const uint8_t *buf, size_t len) {
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
    for (size_t i = 0; i < comp_len; i += 3) {
        uint32_t val = out_buf[i] << 16;
        if (i + 1 < comp_len) val |= out_buf[i + 1] << 8;
        if (i + 2 < comp_len) val |= out_buf[i + 2];

        printf("%c", b64url_table[(val >> 18) & 0x3F]);
        printf("%c", b64url_table[(val >> 12) & 0x3F]);
        if (i + 1 < comp_len) printf("%c", b64url_table[(val >> 6) & 0x3F]);
        if (i + 2 < comp_len) printf("%c", b64url_table[val & 0x3F]);
    }
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
    BRK_TCP_IDLE_HOLD,
    BRK_UPDATE_META_TYPE
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
    else if (strcmp(name, "too-short") == 0 || strcmp(name, "short-header") == 0) {
        kind = BRK_TOO_SHORT;
        if (!has_param) { param = 3; has_param = true; }
    }
    else if (strcmp(name, "tcp-length-overclaim") == 0)   { kind = BRK_TCP_LENGTH_OVERCLAIM; if (!has_param) { param = 10; has_param = true; } }
    else if (strcmp(name, "tcp-zero-length") == 0)        kind = BRK_TCP_ZERO_LENGTH;
    else if (strcmp(name, "tcp-idle-hold") == 0)          { kind = BRK_TCP_IDLE_HOLD; if (!has_param) { param = 20; has_param = true; } }
    else if (strcmp(name, "update-meta-type") == 0)       { kind = BRK_UPDATE_META_TYPE; if (!has_param) { param = 41; has_param = true; } }
    else {
        fprintf(stderr, "warning: unknown --break kind '%s', ignoring\n", name);
        return;
    }

    // Check if the same break kind is already registered; if so, override parameter
    for (int i = 0; i < g_break_count; i++) {
        if (g_breaks[i].kind == kind) {
            fprintf(stderr, ";; note: --break '%s' overrides previous value for this kind (was param=%ld, now param=%ld)\n",
                    name, g_breaks[i].param, param);
            g_breaks[i].param = param;
            g_breaks[i].has_param = has_param;
            return;
        }
    }

    if (is_structural_break(kind)) {
        break_kind_t existing;
        if (any_structural_break(&existing) && existing != kind) {
            fprintf(stderr,
                "warning: --break '%s' ignored; structural break kind is already set "
                "and only one structural break can be active per query (see --break-help)\n",
                name);
            return;
        }
    }

    if (g_break_count >= MAX_BREAKS) {
        fprintf(stderr, "warning: too many --break options, ignoring '%s'\n", arg);
        return;
    }

    g_breaks[g_break_count].kind = kind;
    g_breaks[g_break_count].param = param;
    g_breaks[g_break_count].has_param = has_param;
    g_break_count++;
}

static void print_break_help(void) {
    printf(
        "NOTE: Only one *structural* --break kind (compression-loop, compression-forward,\n"
        "      label-too-long, reserved-length-bits, oversized-qname, truncated-question,\n"
        "      notify-no-question) can be active per query. If multiple are specified, only\n"
        "      the first one takes effect; TCP-only and header-flag breaks can still be\n"
        "      combined freely with a structural break.\n\n"
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
        "  too-short[=N]              send only the first N bytes of the message (default 3)\n"
        "  short-header[=N]           alias for too-short[=N]\n"
        "  tcp-length-overclaim[=N]   (--tcp only) length prefix N bytes bigger than body sent\n"
        "  tcp-zero-length            (--tcp only) send a 0 length prefix\n"
        "  tcp-idle-hold[=SEC]        (--tcp only) send only the length prefix, hold the\n"
        "                             connection, report when/if the server disconnects\n"
        "  update-meta-type[=N]       (UPDATE only) inject a meta-type RR (default 41) into Update Section\n"
    );
}

/* ========================================================================
 * 4. Query options (EDNS request side) -- built entirely in this file
 * ==================================================================== */
typedef enum { PREREQ_NXDOMAIN, PREREQ_YXDOMAIN, PREREQ_NXRRSET, PREREQ_YXRRSET } prereq_kind_t;
typedef enum { UPDATE_OP_ADD, UPDATE_OP_DEL, UPDATE_OP_DEL_EXACT } update_op_kind_t;

#define MAX_PREREQS 16
#define MAX_UPDATE_OPS 16

typedef struct {
    uint16_t qclass;
    bool want_opt;
    uint8_t edns_version;
    uint16_t udp_payload_size;
    bool dnssec_ok;
    bool compact_answers_ok;
    uint16_t ednsflags_z;

    bool want_nsid;
    bool want_expire_opt;

    bool want_cookie;
    uint8_t client_cookie[8];
    uint8_t server_cookie[32];
    size_t server_cookie_len;
    bool retry_on_badcookie;

    int pref_family;
    char bind_addr[64];
    int bind_port;

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

    struct {
        update_op_kind_t kind;
        char raw[512];
    } update_ops[MAX_UPDATE_OPS];
    int update_op_count;
    struct {
        prereq_kind_t kind;
        char name[256];
        char type_str[32];
        char rdata[512];
    } prereqs[MAX_PREREQS];
    int prereq_count;
    uint16_t query_id;
    int qid_override;
    int opcode_override;
    bool header_only;
    bool ra_flag;
    bool rd_flag;
    bool aa_flag;
    bool ad_flag;
    bool cd_flag;
    bool tc_flag;
    bool z_flag;
    bool send_keepalive;
    bool keep_tcp_open;
    bool use_tcp;
    bool edns_negotiation;
    int64_t fuzztime;
    const char *explicit_qname;
    const char *orig_qname;
    const char *orig_qtype_s;
    bool mem_debug;
    bool check_dns64prefix;
    bool server_explicit;

    bool use_search_list;
    char *search_domain;
    int ndots;

    bool idnin;
    bool ignore_tc;
    bool nofail;

    // PROXYv2
    bool use_proxy;
    bool proxy_use_local_cmd;
    int proxy_family;
    char proxy_src_addr[64];
    int proxy_src_port;
    char proxy_dst_addr[64];
    int proxy_dst_port;

    int tcp_mss;
    int tcp_window;

    // TLS (DoT)
    bool use_tls;
    char *tls_ca_file;
    bool tls_verify_default_store;
    char *tls_certfile;
    char *tls_keyfile;
    char *tls_hostname;

    // DoH
    bool use_doh;
    enum { DOH_POST, DOH_GET } doh_method;
    bool doh_tls;
    char *doh_path;
} query_opts_t;

typedef struct {
    bool show_question;   // default true
    bool show_answer;     // default true
    bool show_authority;  // default true
    bool show_additional; // default true
    bool show_comments;   // default true (";; ->>HEADER<<-" 等)
    bool show_stats;      // default true
    bool show_cmd;        // default true (";; global options:" ヘッダ相当)
    bool short_mode;
    bool identify;
    bool multiline;
    bool yaml;
    bool ttlid;
    bool expire;
    bool showsearch;
    bool idnout;

    bool time_unit_usec;
    bool besteffort;
    bool show_class;
    bool show_crypto;
    bool show_query_message;
    bool rrcomments;
    bool onesoa;
    bool show_badcookie_msg;
    bool show_badvers_msg;
    bool expandaaaa;
    int split_width;
    bool force_unknown_format;
    bool ttlunits;
    bool has_expected_client_cookie;
    uint8_t expected_client_cookie[8];
    bool check_dns64prefix;
} display_opts_t;

static const char *format_ttl_units(uint32_t ttl, char *buf, size_t buf_size) {
    if (ttl == 0) {
        snprintf(buf, buf_size, "0s");
        return buf;
    }
    uint32_t w = ttl / 604800; ttl %= 604800;
    uint32_t d = ttl / 86400;  ttl %= 86400;
    uint32_t h = ttl / 3600;   ttl %= 3600;
    uint32_t m = ttl / 60;     ttl %= 60;
    uint32_t s = ttl;
    size_t off = 0;
    if (w) off += snprintf(buf + off, buf_size - off, "%uw", w);
    if (d) off += snprintf(buf + off, buf_size - off, "%ud", d);
    if (h) off += snprintf(buf + off, buf_size - off, "%uh", h);
    if (m) off += snprintf(buf + off, buf_size - off, "%um", m);
    if (s) off += snprintf(buf + off, buf_size - off, "%us", s);
    return buf;
}

static uint16_t compute_dnskey_tag(const uint8_t *rdata, size_t rdlen) {
    if (rdlen < 4) return 0;
    if (rdata[3] == 1) { // Algorithm 1 (RSAMD5)
        return (rdata[rdlen - 3] << 8) | rdata[rdlen - 2];
    }
    uint32_t ac = 0;
    for (size_t i = 0; i < rdlen; i++) {
        ac += (i & 1) ? rdata[i] : (rdata[i] << 8);
    }
    ac += (ac >> 16) & 0xFFFF;
    return (uint16_t)(ac & 0xFFFF);
}

static const char *dnssec_algo_name(uint8_t alg) {
    switch (alg) {
        case 1: return "RSAMD5";
        case 2: return "DH";
        case 3: return "DSA";
        case 5: return "RSASHA1";
        case 6: return "DSA-NSEC3-SHA1";
        case 7: return "RSASHA1-NSEC3-SHA1";
        case 8: return "RSASHA256";
        case 10: return "RSASHA512";
        case 12: return "ECC-GOST";
        case 13: return "ECDSAP256SHA256";
        case 14: return "ECDSAP384SHA384";
        case 15: return "ED25519";
        case 16: return "ED448";
        default: return "UNKNOWN";
    }
}

static bool parse_proxy_arg(const char *arg, query_opts_t *qo) {
    if (!arg || !*arg) {
        qo->proxy_use_local_cmd = true;
        return true;
    }
    char buf[256];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *dash = strchr(buf, '-');
    if (!dash) {
        qo->proxy_use_local_cmd = true;
        return true;
    }
    *dash = '\0';
    char *src_part = buf;
    char *dst_part = dash + 1;

    qo->proxy_src_port = 0;
    qo->proxy_dst_port = 53;

    char *src_hash = strchr(src_part, '#');
    if (src_hash) {
        *src_hash = '\0';
        qo->proxy_src_port = atoi(src_hash + 1);
    }
    char *dst_hash = strchr(dst_part, '#');
    if (dst_hash) {
        *dst_hash = '\0';
        qo->proxy_dst_port = atoi(dst_hash + 1);
    }

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, src_part, &a4) == 1 && inet_pton(AF_INET, dst_part, &a4) == 1) {
        qo->proxy_family = AF_INET;
        snprintf(qo->proxy_src_addr, sizeof(qo->proxy_src_addr), "%.63s", src_part);
        snprintf(qo->proxy_dst_addr, sizeof(qo->proxy_dst_addr), "%.63s", dst_part);
        return true;
    }
    if (inet_pton(AF_INET6, src_part, &a6) == 1 && inet_pton(AF_INET6, dst_part, &a6) == 1) {
        qo->proxy_family = AF_INET6;
        snprintf(qo->proxy_src_addr, sizeof(qo->proxy_src_addr), "%.63s", src_part);
        snprintf(qo->proxy_dst_addr, sizeof(qo->proxy_dst_addr), "%.63s", dst_part);
        return true;
    }
    qo->proxy_use_local_cmd = true;
    return true;
}

static size_t build_proxyv2_header(uint8_t *buf, size_t buf_cap, const query_opts_t *qo, bool is_tcp) {
    if (!qo->use_proxy || buf_cap < 52) return 0;
    static const uint8_t v2sig[12] = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };
    memcpy(buf, v2sig, 12);
    size_t off = 12;

    if (qo->proxy_use_local_cmd) {
        buf[off++] = 0x20; // v2 + LOCAL command
        buf[off++] = 0x00; // AF_UNSPEC
        buf[off++] = 0x00; // len msb
        buf[off++] = 0x00; // len lsb
        return off;
    }

    buf[off++] = 0x21; // v2 + PROXY command
    if (qo->proxy_family == AF_INET6) {
        buf[off++] = is_tcp ? 0x21 : 0x22; // AF_INET6, STREAM or DGRAM
        uint16_t addr_len = 36;
        buf[off++] = addr_len >> 8;
        buf[off++] = addr_len & 0xFF;
        struct in6_addr s6, d6;
        inet_pton(AF_INET6, qo->proxy_src_addr[0] ? qo->proxy_src_addr : "::1", &s6);
        inet_pton(AF_INET6, qo->proxy_dst_addr[0] ? qo->proxy_dst_addr : "::1", &d6);
        memcpy(buf + off, &s6, 16); off += 16;
        memcpy(buf + off, &d6, 16); off += 16;
        uint16_t sp = (uint16_t)qo->proxy_src_port;
        uint16_t dp = (uint16_t)qo->proxy_dst_port;
        buf[off++] = sp >> 8; buf[off++] = sp & 0xFF;
        buf[off++] = dp >> 8; buf[off++] = dp & 0xFF;
    } else {
        buf[off++] = is_tcp ? 0x11 : 0x12; // AF_INET, STREAM or DGRAM
        uint16_t addr_len = 12;
        buf[off++] = addr_len >> 8;
        buf[off++] = addr_len & 0xFF;
        struct in_addr s4, d4;
        inet_pton(AF_INET, qo->proxy_src_addr[0] ? qo->proxy_src_addr : "127.0.0.1", &s4);
        inet_pton(AF_INET, qo->proxy_dst_addr[0] ? qo->proxy_dst_addr : "127.0.0.1", &d4);
        memcpy(buf + off, &s4, 4); off += 4;
        memcpy(buf + off, &d4, 4); off += 4;
        uint16_t sp = (uint16_t)qo->proxy_src_port;
        uint16_t dp = (uint16_t)qo->proxy_dst_port;
        buf[off++] = sp >> 8; buf[off++] = sp & 0xFF;
        buf[off++] = dp >> 8; buf[off++] = dp & 0xFF;
    }
    return off;
}

static void send_proxyv2_if_enabled(int sock, const query_opts_t *qo, bool is_tcp) {
    if (qo && qo->use_proxy) {
        uint8_t pbuf[64];
        size_t plen = build_proxyv2_header(pbuf, sizeof(pbuf), qo, is_tcp);
        if (plen > 0) send(sock, pbuf, plen, 0);
    }
}

static bool parse_subnet_arg(const char *arg, query_opts_t *qo) {
    char buf[128];
    strncpy(buf, arg, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';

    // プライバシー保護目的の +subnet=0 の処理
    if (strcmp(buf, "0") == 0) {
        qo->subnet_family = 1;
        memset(qo->subnet_addr, 0, sizeof(qo->subnet_addr));
        qo->subnet_prefix = 0;
        return true;
    }

    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        char *endptr;
        long pfx_val = strtol(slash + 1, &endptr, 10);
        if (*endptr == '\0' && pfx_val >= 0) prefix = (int)pfx_val;
    }

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
    pkt[offset++] = qo->edns_version; /* version */
    uint16_t flags = 0;
    if (qo->dnssec_ok) flags |= 0x8000;
    if (qo->compact_answers_ok) flags |= 0x4000;
    if (qo->ednsflags_z) flags |= (qo->ednsflags_z & ~(uint16_t)0xC000);
    pkt[offset++] = flags >> 8; pkt[offset++] = flags & 0xFF;

    uint16_t rdlen_field_offset = offset;
    pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* RDLENGTH placeholder */
    uint16_t rdata_start = offset;

    if (qo->want_nsid) {
        if ((size_t)offset + 4 > max_len) goto done;
        pkt[offset++] = 0x00; pkt[offset++] = 0x03; /* OPTION-CODE = NSID */
        pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* OPTION-LENGTH = 0 (empty request) */
    }

    if (qo->want_expire_opt) {
        if ((size_t)offset + 4 <= max_len) {
            pkt[offset++] = 0x00; pkt[offset++] = 0x09; /* OPTION-CODE = EDNS EXPIRE (RFC 7314) */
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* OPTION-LENGTH = 0 */
        }
    }

    if (qo->send_keepalive) {
        if ((size_t)offset + 4 <= max_len) {
            pkt[offset++] = 0x00; pkt[offset++] = 11; /* OPTION-CODE = edns-tcp-keepalive */
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* OPTION-LENGTH = 0 */
        }
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
    if (qo->update_op_count > 0 || qo->prereq_count > 0 || has_break(BRK_UPDATE_META_TYPE, NULL, NULL)) {
        qtype = 6; /* SOA for Zone section */
    }

    memset(pkt, 0, 12);
    uint16_t id = (qo->qid_override >= 0) ? (uint16_t)(qo->qid_override & 0xFFFF) : qo->query_id;
    pkt[0] = id >> 8; pkt[1] = id & 0xFF;
    pkt[2] = qo->rd_flag ? 0x01 : 0x00;
    if (qo->aa_flag) pkt[2] |= 0x04;
    if (qo->tc_flag) pkt[2] |= 0x02;
    if (qo->ra_flag) pkt[3] |= 0x80;
    if (qo->ad_flag) pkt[3] |= 0x20;
    if (qo->cd_flag) pkt[3] |= 0x10;
    if (qo->z_flag)  pkt[3] |= 0x40;

    if (qo->opcode_override >= 0) {
        pkt[2] = (pkt[2] & 0x87) | ((qo->opcode_override & 0x0F) << 3);
    }

    if (qo->header_only) {
        pkt[4] = 0x00; pkt[5] = 0x00; /* QDCOUNT=0 */
    } else {
        pkt[4] = 0x00; pkt[5] = 0x01; /* QDCOUNT=1 (may be overridden below) */
    }

    if (qo->update_op_count > 0 || qo->prereq_count > 0 || has_break(BRK_UPDATE_META_TYPE, NULL, NULL)) {
        pkt[2] = (pkt[2] & 0x87) | (5 << 3); /* OPCODE=5 (UPDATE) */
    }

    break_kind_t structural = BRK_NONE;
    bool has_structural = any_structural_break(&structural);

    uint16_t offset = 12;

    if (qo->header_only || (has_structural && structural == BRK_NOTIFY_NO_QUESTION)) {
        pkt[4] = 0x00; pkt[5] = 0x00; /* QDCOUNT=0, no question bytes at all */
        if (!qo->header_only) {
            pkt[2] = (pkt[2] & 0x87) | (4 << 3); /* OPCODE=4 (NOTIFY) */
        }
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
        memset(&comp_ctx, 0, sizeof(comp_ctx));
        compress_ctx_init_packet(&comp_ctx);
        if (write_dns_name_str(pkt, &offset, qname, &comp_ctx, max_len) != 0) {
            fprintf(stderr, "write_dns_name_str failed (name too long?)\n");
            return 0;
        }
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = qo->qclass >> 8; pkt[offset++] = qo->qclass & 0xFF;
    }

    if (qo->is_ixfr) {
        compress_ctx_t comp_ctx;
        memset(&comp_ctx, 0, sizeof(comp_ctx));
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

    if (qo->prereq_count > 0) {
        compress_ctx_t comp_ctx;
        memset(&comp_ctx, 0, sizeof(comp_ctx));
        compress_ctx_init_packet(&comp_ctx);

        for (int pi = 0; pi < qo->prereq_count; pi++) {
            const char *name = qo->prereqs[pi].name;
            uint16_t type, class_val;

            if (qo->prereqs[pi].kind == PREREQ_YXRRSET && qo->prereqs[pi].rdata[0] != '\0') {
                // RFC 2136 Section 2.4.2: RRset Exists (Value Dependent)
                char *buf = strdup(qo->prereqs[pi].rdata);
                char *tokens[32];
                int token_count = 0;
                bool in_quote = false;
                char *p = buf;
                char *tok_start = NULL;
                char *out = buf;

                while (*p && token_count < 32) {
                    if (*p == '"') {
                        in_quote = !in_quote;
                        if (!tok_start) tok_start = out;
                        p++;
                    } else if (*p == ' ' && !in_quote) {
                        if (tok_start) {
                            *out++ = '\0';
                            tokens[token_count++] = tok_start;
                            tok_start = NULL;
                        }
                        p++;
                    } else {
                        if (!tok_start) tok_start = out;
                        if (*p == '\\' && *(p+1) == '"') {
                            p++;
                            *out++ = *p++;
                        } else {
                            *out++ = *p++;
                        }
                    }
                }
                if (tok_start && token_count < 32) {
                    *out = '\0';
                    tokens[token_count++] = tok_start;
                }

                if (!resolve_qtype(qo->prereqs[pi].type_str, &type)) {
                    fprintf(stderr, "warning: unknown record type '%s' in prereq yxrrset, skipping\n", qo->prereqs[pi].type_str);
                    free(buf);
                    continue;
                }
                dns_record_t rec;
                memset(&rec, 0, sizeof(rec));
                rec.name = (char *)name;
                rec.ttl = (char *)"0";
                rec.type_code = type;
                rec.type = (char *)qo->prereqs[pi].type_str;
                rec.class_str = (char *)(qo->qclass == 3 ? "CH" : (qo->qclass == 4 ? "HS" : "IN"));
                rec.rdata_count = token_count;
                for (int t = 0; t < token_count; t++) rec.rdata[t] = tokens[t];

                uint16_t out_offset = offset;
                if (serialize_dns_record(pkt, max_len, &out_offset, &rec, &comp_ctx, NULL, 0) == 0) {
                    offset = out_offset;
                    uint16_t prcount = (pkt[6] << 8) | pkt[7];
                    prcount++;
                    pkt[6] = prcount >> 8; pkt[7] = prcount & 0xFF;
                } else {
                    fprintf(stderr, "warning: failed to serialize yxrrset prereq rdata: %s\n", qo->prereqs[pi].rdata);
                }
                free(buf);
                continue;
            }

            switch (qo->prereqs[pi].kind) {
                case PREREQ_NXDOMAIN: type = 255; class_val = 254; break; // ANY, NONE
                case PREREQ_YXDOMAIN: type = 255; class_val = 255; break; // ANY, ANY
                case PREREQ_NXRRSET:
                    if (!resolve_qtype(qo->prereqs[pi].type_str, &type)) {
                        fprintf(stderr, "warning: unknown record type '%s' in prereq nxrrset, skipping\n", qo->prereqs[pi].type_str);
                        continue;
                    }
                    class_val = 254; break;
                case PREREQ_YXRRSET:
                    if (!resolve_qtype(qo->prereqs[pi].type_str, &type)) {
                        fprintf(stderr, "warning: unknown record type '%s' in prereq yxrrset, skipping\n", qo->prereqs[pi].type_str);
                        continue;
                    }
                    class_val = 255; break;
                default: continue;
            }

            if (write_dns_name_str(pkt, &offset, name, &comp_ctx, max_len) != 0) {
                fprintf(stderr, "warning: failed to encode prereq name '%s', skipping\n", name);
                continue;
            }
            if ((size_t)offset + 10 > max_len) {
                fprintf(stderr, "warning: packet buffer full, dropping remaining prereqs\n");
                break;
            }
            pkt[offset++] = type >> 8; pkt[offset++] = type & 0xFF;
            pkt[offset++] = class_val >> 8; pkt[offset++] = class_val & 0xFF;
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* TTL 0 */
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* RDLEN 0 */

            uint16_t prcount = (pkt[6] << 8) | pkt[7];
            prcount++;
            pkt[6] = prcount >> 8; pkt[7] = prcount & 0xFF;
        }
    }

    if (qo->update_op_count > 0 || has_break(BRK_UPDATE_META_TYPE, NULL, NULL)) {
        compress_ctx_t comp_ctx;
        memset(&comp_ctx, 0, sizeof(comp_ctx));
        compress_ctx_init_packet(&comp_ctx);

        for (int oi = 0; oi < qo->update_op_count; oi++) {
            const char *raw = qo->update_ops[oi].raw;

            if (qo->update_ops[oi].kind == UPDATE_OP_ADD) {
                char *buf = strdup(raw);
                char *tokens[32];
                int token_count = 0;
                bool in_quote = false;
                char *p = buf;
                char *tok_start = NULL;
                char *out = buf;

                while (*p && token_count < 32) {
                    if (*p == '"') {
                        in_quote = !in_quote;
                        if (!tok_start) tok_start = out;
                        p++;
                    } else if (*p == ' ' && !in_quote) {
                        if (tok_start) {
                            *out++ = '\0';
                            tokens[token_count++] = tok_start;
                            tok_start = NULL;
                        }
                        p++;
                    } else {
                        if (!tok_start) tok_start = out;
                        if (*p == '\\' && *(p+1) == '"') {
                            p++;
                            *out++ = *p++;
                        } else {
                            *out++ = *p++;
                        }
                    }
                }
                if (tok_start && token_count < 32) {
                    *out = '\0';
                    tokens[token_count++] = tok_start;
                }

                if (token_count >= 3) {
                    int type_idx = 2;
                    char *class_str = (char *)"IN";
                    if (token_count >= 4 && (strcasecmp(tokens[2], "IN") == 0 || strcasecmp(tokens[2], "CH") == 0 ||
                                             strcasecmp(tokens[2], "ANY") == 0 || strcasecmp(tokens[2], "NONE") == 0 ||
                                             strcasecmp(tokens[2], "HS") == 0)) {
                        class_str = tokens[2];
                        type_idx = 3;
                    }
                    if (token_count > type_idx) {
                        uint16_t type_code;
                        if (!resolve_qtype(tokens[type_idx], &type_code)) {
                            fprintf(stderr, "warning: unknown record type '%s' in update-add operation, skipping: %s\n", tokens[type_idx], raw);
                            free(buf);
                            continue;
                        }
                        dns_record_t rec;
                        memset(&rec, 0, sizeof(rec));
                        rec.name = tokens[0];
                        rec.ttl = tokens[1];
                        rec.ttl_value = parse_ttl_value(tokens[1]);
                        rec.type_code = type_code;
                        rec.type = tokens[type_idx];
                        rec.class_str = class_str;
                        rec.rdata_count = token_count - (type_idx + 1);
                        for (int i = 0; i < rec.rdata_count; i++) rec.rdata[i] = tokens[type_idx + 1 + i];

                        uint16_t out_offset = offset;
                        if (serialize_dns_record(pkt, max_len, &out_offset, &rec, &comp_ctx, NULL, 0xFFFFFFFF) == 0) {
                            offset = out_offset;
                            uint16_t upcount = (pkt[8] << 8) | pkt[9];
                            upcount++;
                            pkt[8] = upcount >> 8; pkt[9] = upcount & 0xFF;
                        } else {
                            fprintf(stderr, "Failed to serialize update-add record: %s\n", raw);
                        }
                    } else {
                        fprintf(stderr, "Invalid update-add string format: %s\n", raw);
                    }
                } else {
                    fprintf(stderr, "Invalid update-add string format: %s\n", raw);
                }
                free(buf);

            } else if (qo->update_ops[oi].kind == UPDATE_OP_DEL) { // UPDATE_OP_DEL
                char *buf = strdup(raw);
                char *name = strtok(buf, " ");
                char *type_str = strtok(NULL, " ");
                if (name) {
                    if ((size_t)offset + 10 > max_len) {
                        fprintf(stderr, "warning: packet buffer full, dropping remaining update ops\n");
                        free(buf);
                        break;
                    }
                    uint16_t type = 255; // Default: ANY (255) for all RRsets delete (RFC 2136 §2.5.2)
                    if (type_str) {
                        if (!resolve_qtype(type_str, &type)) {
                            fprintf(stderr, "warning: unknown record type '%s' in update-del operation, skipping: %s\n", type_str, raw);
                            free(buf);
                            continue;
                        }
                    }
                    if (write_dns_name_str(pkt, &offset, name, &comp_ctx, max_len) == 0) {
                        pkt[offset++] = type >> 8; pkt[offset++] = type & 0xFF;
                        pkt[offset++] = 0x00; pkt[offset++] = 255; /* Class ANY */
                        pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* TTL 0 */
                        pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* RDLEN 0 */
                        uint16_t upcount = (pkt[8] << 8) | pkt[9];
                        upcount++;
                        pkt[8] = upcount >> 8; pkt[9] = upcount & 0xFF;
                    } else {
                        fprintf(stderr, "Failed to serialize update-del name: %s\n", raw);
                    }
                } else {
                    fprintf(stderr, "Invalid update-del string format: %s\n", raw);
                }
                free(buf);
            } else if (qo->update_ops[oi].kind == UPDATE_OP_DEL_EXACT) {
                char *buf = strdup(raw);
                char *tokens[32];
                int token_count = 0;
                bool in_quote = false;
                char *p = buf;
                char *tok_start = NULL;
                char *out = buf;

                while (*p && token_count < 32) {
                    if (*p == '"') {
                        in_quote = !in_quote;
                        if (!tok_start) tok_start = out;
                        p++;
                    } else if (*p == ' ' && !in_quote) {
                        if (tok_start) {
                            *out++ = '\0';
                            tokens[token_count++] = tok_start;
                            tok_start = NULL;
                        }
                        p++;
                    } else {
                        if (!tok_start) tok_start = out;
                        if (*p == '\\' && *(p+1) == '"') {
                            p++;
                            *out++ = *p++;
                        } else {
                            *out++ = *p++;
                        }
                    }
                }
                if (tok_start && token_count < 32) {
                    *out = '\0';
                    tokens[token_count++] = tok_start;
                }

                if (token_count >= 3) {
                    int type_idx = 1;
                    if (token_count >= 3 && (strcasecmp(tokens[1], "NONE") == 0 || strcasecmp(tokens[1], "IN") == 0 ||
                                             strcasecmp(tokens[1], "ANY") == 0 || strcasecmp(tokens[1], "CH") == 0 ||
                                             strcasecmp(tokens[1], "HS") == 0)) {
                        type_idx = 2; // name class type rdata...
                    } else if (token_count >= 3 && isdigit((unsigned char)tokens[1][0])) {
                        if (token_count >= 4 && (strcasecmp(tokens[2], "NONE") == 0 || strcasecmp(tokens[2], "IN") == 0 ||
                                                 strcasecmp(tokens[2], "ANY") == 0 || strcasecmp(tokens[2], "CH") == 0 ||
                                                 strcasecmp(tokens[2], "HS") == 0)) {
                            type_idx = 3; // name ttl class type rdata...
                        } else {
                            type_idx = 2; // name ttl type rdata... (class omitted)
                        }
                    }
                    if (token_count > type_idx) {
                        uint16_t type_code;
                        if (!resolve_qtype(tokens[type_idx], &type_code)) {
                            fprintf(stderr, "warning: unknown record type '%s' in update-del-exact operation, skipping: %s\n", tokens[type_idx], raw);
                            free(buf);
                            continue;
                        }
                        dns_record_t rec;
                        memset(&rec, 0, sizeof(rec));
                        rec.name = tokens[0];
                        rec.ttl = (char *)"0"; // TTL must be 0 for exact match delete
                        rec.type_code = type_code;
                        rec.type = tokens[type_idx];
                        rec.class_str = (char *)"NONE"; // Class NONE for exact match delete
                        rec.rdata_count = token_count - (type_idx + 1);
                        for (int i = 0; i < rec.rdata_count; i++) rec.rdata[i] = tokens[type_idx + 1 + i];

                        uint16_t out_offset = offset;
                        if (serialize_dns_record(pkt, max_len, &out_offset, &rec, &comp_ctx, NULL, 0) == 0) {
                            offset = out_offset;
                            uint16_t upcount = (pkt[8] << 8) | pkt[9];
                            upcount++;
                            pkt[8] = upcount >> 8; pkt[9] = upcount & 0xFF;
                        } else {
                            fprintf(stderr, "Failed to serialize update-del-exact record: %s\n", raw);
                        }
                    } else {
                        fprintf(stderr, "Invalid update-del-exact string format: %s\n", raw);
                    }
                } else {
                    fprintf(stderr, "Invalid update-del-exact string format: %s\n", raw);
                }
                free(buf);
            }
        }

        long meta_type = 0; bool has_meta = false;
        if (has_break(BRK_UPDATE_META_TYPE, &meta_type, &has_meta)) {
            uint16_t fallback_offset = offset;
            if (write_dns_name_str(pkt, &fallback_offset, qname, &comp_ctx, max_len) == 0 && (size_t)fallback_offset + 10 <= max_len) {
                pkt[fallback_offset++] = (uint16_t)meta_type >> 8; pkt[fallback_offset++] = (uint16_t)meta_type & 0xFF;
                pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x01; /* Class IN */
                pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x00; /* TTL 0 */
                pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x00; /* RDLEN 0 */
                offset = fallback_offset;
                uint16_t upcount = (pkt[8] << 8) | pkt[9];
                upcount++;
                pkt[8] = upcount >> 8; pkt[9] = upcount & 0xFF;
            }
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
static int g_last_socket_family = AF_INET;

/*
 * server引数(IPv4リテラル / IPv6リテラル / FQDN)をsockaddr_storageへ解決する。
 * まずinet_pton()でIPリテラルとしての解釈を試み(DNS解決を伴わない高速パス)、
 * どちらにも一致しなければFQDNとみなしgetaddrinfo()でシステムリゾルバに問い合わせる。
 */
static bool resolve_server_addr(const char *server, int port, int pref_family,
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
    hints.ai_family = pref_family;
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

static int get_server_addr_count(const char *server, int port, int pref_family) {
    struct sockaddr_in d4;
    struct sockaddr_in6 d6;
    if (inet_pton(AF_INET, server, &d4.sin_addr) == 1) return 1;
    if (inet_pton(AF_INET6, server, &d6.sin6_addr) == 1) return 1;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = pref_family;
    hints.ai_socktype = SOCK_DGRAM;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    if (getaddrinfo(server, portbuf, &hints, &res) == 0 && res != NULL) {
        int cnt = 0;
        for (struct addrinfo *p = res; p != NULL; p = p->ai_next) cnt++;
        freeaddrinfo(res);
        return cnt > 0 ? cnt : 1;
    }
    return 1;
}

static int connect_udp(const char *server, int port, int pref_family, const char *bind_addr, int bind_port, struct sockaddr_storage *dest, socklen_t *dest_len) {
    int family = AF_INET;
    if (!resolve_server_addr(server, port, pref_family, dest, dest_len, &family)) return -1;
    g_last_socket_family = family;
    int sock = socket(family, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }
    if (bind_addr && bind_addr[0] != '\0') {
        struct sockaddr_storage baddr; socklen_t blen; int bfam = family;
        if (!resolve_server_addr(bind_addr, bind_port, AF_UNSPEC, &baddr, &blen, &bfam)) {
            fprintf(stderr, "Error: -b address '%s' could not be resolved\n", bind_addr);
            close(sock);
            return -1;
        }
        if (bfam != family) {
            fprintf(stderr, "Error: -b address '%s' is %s, but destination server '%s' resolved to %s; "
                            "the source address family must match the destination\n",
                    bind_addr, bfam == AF_INET6 ? "IPv6" : "IPv4",
                    server, family == AF_INET6 ? "IPv6" : "IPv4");
            close(sock);
            return -1;
        }
        if (bind(sock, (struct sockaddr *)&baddr, blen) != 0) {
            fprintf(stderr, ";; UDP setup with %s#%d(%s) failed: %s.\n", server, port, server, strerror(errno));
            close(sock);
            return -1;
        }
    }
    /*
     * RFC 5452 §9.1: Connect UDP socket to the destination address/port.
     * This instructs the OS kernel to automatically filter and discard any
     * incoming UDP datagrams originating from unauthorized sources/ports.
     */
    if (connect(sock, (struct sockaddr *)dest, *dest_len) != 0) {
        perror("connect (udp)");
        close(sock);
        return -1;
    }
    return sock;
}

static int connect_tcp(const char *server, int port, const query_opts_t *qo, int timeout_sec) {
    const char *bind_addr = qo->bind_addr;
    int bind_port = qo->bind_port;
    struct sockaddr_storage dest; socklen_t dest_len; int family = AF_INET;
    if (!resolve_server_addr(server, port, qo->pref_family, (struct sockaddr_storage *)&dest, &dest_len, &family)) return -1;
    g_last_socket_family = family;
    int sock = socket(family, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    if (qo->tcp_mss > 0) {
        int mss = qo->tcp_mss;
#ifdef TCP_MAXSEG
        setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, (const char *)&mss, sizeof(mss));
#endif
    }
    if (qo->tcp_window > 0) {
        int wsize = qo->tcp_window;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&wsize, sizeof(wsize));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *)&wsize, sizeof(wsize));
    }

    if (bind_addr && bind_addr[0] != '\0') {
        struct sockaddr_storage baddr; socklen_t blen; int bfam = family;
        if (!resolve_server_addr(bind_addr, bind_port, AF_UNSPEC, &baddr, &blen, &bfam)) {
            fprintf(stderr, "Error: -b address '%s' could not be resolved\n", bind_addr);
            close(sock);
            return -1;
        }
        if (bfam != family) {
            fprintf(stderr, "Error: -b address '%s' is %s, but destination server '%s' resolved to %s; "
                            "the source address family must match the destination\n",
                    bind_addr, bfam == AF_INET6 ? "IPv6" : "IPv4",
                    server, family == AF_INET6 ? "IPv6" : "IPv4");
            close(sock);
            return -1;
        }
        if (bind(sock, (struct sockaddr *)&baddr, blen) != 0) {
            perror("bind (tcp)");
            close(sock);
            return -1;
        }
    }

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    int res = connect(sock, (struct sockaddr *)&dest, dest_len);
    if (res != 0) {
        bool in_progress = false;
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) in_progress = true;
#else
        if (errno == EINPROGRESS) in_progress = true;
#endif
        if (in_progress) {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
            struct timeval tv = { .tv_sec = (timeout_sec > 0) ? timeout_sec : 5, .tv_usec = 0 };
            int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
            if (sel <= 0) {
                fprintf(stderr, ";; connection to %s#%d timed out after %ds\n", server, port, (timeout_sec > 0) ? timeout_sec : 5);
                close(sock); return -1;
            }
            int sock_err = 0; socklen_t err_len = sizeof(sock_err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&sock_err, &err_len) < 0 || sock_err != 0) {
                fprintf(stderr, ";; connect to %s#%d failed: %s\n", server, port, strerror(sock_err ? sock_err : errno));
                close(sock); return -1;
            }
        } else {
            fprintf(stderr, ";; connect to %s#%d failed: %s\n", server, port, strerror(errno));
            close(sock); return -1;
        }
    }

#ifdef _WIN32
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    if (flags >= 0) fcntl(sock, F_SETFL, flags);
#endif

    set_socket_timeouts(sock, timeout_sec);
    return sock;
}

static ssize_t do_udp_exchange(const char *server, int port, const query_opts_t *qo,
                                const uint8_t *pkt, size_t pkt_len,
                                uint8_t *resp, size_t resp_cap, int timeout_sec) {
    struct sockaddr_storage dest; socklen_t dest_len;
    int sock = connect_udp(server, port, qo->pref_family, qo->bind_addr, qo->bind_port, &dest, &dest_len);
    if (sock < 0) return -1;

    uint8_t wire_buf[65535 + 64];
    size_t wire_len = 0;
    if (qo && qo->use_proxy) {
        wire_len = build_proxyv2_header(wire_buf, sizeof(wire_buf), qo, false);
    }
    size_t send_len = pkt_len;
    long short_len = 3;
    if (has_break(BRK_TOO_SHORT, &short_len, NULL)) {
        if (short_len < 0) short_len = 3;
        if (send_len > (size_t)short_len) send_len = (size_t)short_len;
    }
    memcpy(wire_buf + wire_len, pkt, send_len);
    wire_len += send_len;

    if (send(sock, wire_buf, wire_len, 0) < 0) {
        fprintf(stderr, ";; UDP setup with %s#%d(%s) failed: %s\n", server, port, server, strerror(errno));
        close(sock); return -1;
    }

    int eff_timeout = (timeout_sec > 0) ? timeout_sec : 5;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += eff_timeout;

    uint16_t sent_id = (pkt_len >= 2) ? ((pkt[0] << 8) | pkt[1]) : 0;
    bool skip_id_check = has_break(BRK_QR_BIT, NULL, NULL) || has_break(BRK_TOO_SHORT, NULL, NULL);

    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long remain_sec = deadline.tv_sec - now.tv_sec;
        long remain_usec = (deadline.tv_nsec - now.tv_nsec) / 1000;
        if (remain_usec < 0) {
            remain_sec -= 1;
            remain_usec += 1000000;
        }
        if (remain_sec < 0 || (remain_sec == 0 && remain_usec <= 0)) {
            close(sock);
            return -1; // Timeout
        }

#ifdef _WIN32
        DWORD dw_timeout = (DWORD)(remain_sec * 1000 + (remain_usec / 1000));
        if (dw_timeout == 0) dw_timeout = 1;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&dw_timeout, sizeof(dw_timeout));
#else
        struct timeval tv;
        tv.tv_sec = (time_t)remain_sec;
        tv.tv_usec = (long)remain_usec;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#endif

        ssize_t n = recv(sock, resp, resp_cap, 0);
        if (n < 0) {
            if (errno == ECONNREFUSED) {
                printf(";; communications error to %s#%d: connection refused\n", server, port);
            }
            close(sock);
            return -1; // Timeout or network error
        }
        if (n < 2) {
            // Malformed/too short response, discard and keep waiting
            continue;
        }

        if (!skip_id_check) {
            uint16_t resp_id = (resp[0] << 8) | resp[1];
            if (resp_id != sent_id) {
                fprintf(stderr, ";; Warning: ID mismatch: expected %u, got %u\n", sent_id, resp_id);
                continue; // Discard spoofed / stray packet and wait for matching response (RFC 5452)
            }
        }

        // RFC 7873 §5.2: Client Cookie Echo Verification
        if (qo && qo->want_cookie && n >= 12 && !skip_id_check) {
            uint16_t r_qd = (resp[4] << 8) | resp[5];
            uint16_t r_an = (resp[6] << 8) | resp[7];
            uint16_t r_ns = (resp[8] << 8) | resp[9];
            uint16_t r_ar = (resp[10] << 8) | resp[11];
            edns_info_t chk_edns;
            if (parse_edns_opt(resp, (size_t)n, r_qd, r_an, r_ns, r_ar, &chk_edns) == 0 &&
                chk_edns.present && chk_edns.has_cookie) {
                if (memcmp(qo->client_cookie, chk_edns.client_cookie, 8) != 0) {
                    fprintf(stderr, ";; Warning: Client COOKIE mismatch\n");
                    continue; // Discard spoofed or stale response and wait for matching cookie (RFC 7873 §5.2)
                }
            }
        }

        close(sock);
        return n;
    }
}

typedef struct {
    int sock;
    SSL *ssl;
    char server[256];
    int port;
    int pref_family;
    int family;
    char bind_addr[64];
    int bind_port;
    bool is_tls;
} tcp_conn_cache_t;

static tcp_conn_cache_t g_cached_conn = {
    .sock = -1,
    .ssl = NULL,
    .server = {0},
    .port = 0,
    .pref_family = AF_UNSPEC,
    .family = AF_INET,
    .bind_addr = {0},
    .bind_port = 0,
    .is_tls = false
};

static void close_cached_tcp(void) {
    if (g_cached_conn.ssl) {
        SSL_shutdown(g_cached_conn.ssl);
        SSL_free(g_cached_conn.ssl);
        g_cached_conn.ssl = NULL;
    }
    if (g_cached_conn.sock >= 0) {
        close(g_cached_conn.sock);
        g_cached_conn.sock = -1;
    }
    g_cached_conn.server[0] = '\0';
    g_cached_conn.port = 0;
    g_cached_conn.is_tls = false;
}

static int do_tcp_send_request(const char *server, int port, const query_opts_t *qo, const uint8_t *pkt, size_t pkt_len, int timeout_sec) {
    int sock = connect_tcp(server, port, qo, timeout_sec);
    if (sock < 0) return -1;

    send_proxyv2_if_enabled(sock, qo, true);

    long idle_secs = 20; bool idle_hold = has_break(BRK_TCP_IDLE_HOLD, &idle_secs, NULL);
    long overclaim = 0; bool overclaim_break = has_break(BRK_TCP_LENGTH_OVERCLAIM, &overclaim, NULL);
    bool zero_len_break = has_break(BRK_TCP_ZERO_LENGTH, NULL, NULL);
    long short_len = 3;
    bool too_short = has_break(BRK_TOO_SHORT, &short_len, NULL);

    size_t body_len = pkt_len;
    if (too_short) {
        if (short_len < 0) short_len = 3;
        if (body_len > (size_t)short_len) body_len = (size_t)short_len;
    }

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

    set_socket_timeouts(sock, timeout_sec);

    return sock;
}

static ssize_t do_tcp_recv_response(int sock, uint8_t *resp, size_t resp_cap) {
    uint8_t rlen_buf[2];
    size_t got_len = 0;
    while (got_len < 2) {
        ssize_t n = recv(sock, rlen_buf + got_len, 2 - got_len, 0);
        if (n <= 0) return -1;
        got_len += (size_t)n;
    }
    uint16_t rlen = (rlen_buf[0] << 8) | rlen_buf[1];
    if (rlen > resp_cap) {
        // バッファ超過時はTCPストリームの同期崩れを防ぐため直ちに切断する
        return -1;
    }

    size_t got = 0;
    while (got < rlen) {
        ssize_t r = recv(sock, resp + got, rlen - got, 0);
        if (r <= 0) {
            // 宣言された長さに満たないまま受信が終了した。
            // ストリームの同期が崩れている可能性が高いため、
            // 呼び出し元が必ず接続を破棄できるよう -1 を返す。
            return -1;
        }
        got += r;
    }
    return (ssize_t)got;
}

static SSL_CTX *g_ssl_ctx = NULL;

static SSL *establish_tls(int tcp_sock, const query_opts_t *qo, const char *server, int port) {
    if (!g_ssl_ctx) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_ssl_ctx) return NULL;
    }
    if (qo->tls_ca_file) {
        SSL_CTX_load_verify_locations(g_ssl_ctx, qo->tls_ca_file, NULL);
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else if (qo->tls_verify_default_store) {
        SSL_CTX_set_default_verify_paths(g_ssl_ctx);
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    if (qo->tls_certfile && qo->tls_keyfile) {
        SSL_CTX_use_certificate_file(g_ssl_ctx, qo->tls_certfile, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(g_ssl_ctx, qo->tls_keyfile, SSL_FILETYPE_PEM);
    }
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, tcp_sock);

    const char *sni_host = qo->tls_hostname ? qo->tls_hostname : server;
    struct in_addr a4; struct in6_addr a6;
    bool sni_is_ip = (inet_pton(AF_INET, sni_host, &a4) == 1 || inet_pton(AF_INET6, sni_host, &a6) == 1);
    if (!sni_is_ip) {
        SSL_set_tlsext_host_name(ssl, sni_host);
    }

    /* 証明書検証を行うモード(tls_ca_fileまたはtls_verify_default_store指定時)
       のみ、ホスト名検証パラメータを明示的に設定する */
    if (qo->tls_ca_file || qo->tls_verify_default_store) {
        X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
        if (sni_is_ip) {
            X509_VERIFY_PARAM_set1_ip_asc(vpm, sni_host);
        } else {
            X509_VERIFY_PARAM_set1_host(vpm, sni_host, 0);
        }
    }

    if (SSL_connect(ssl) <= 0) {
        if (qo->tls_ca_file || qo->tls_verify_default_store) {
            long vres = SSL_get_verify_result(ssl);
            if (vres != X509_V_OK) {
                fprintf(stderr, ";; TLS peer certificate verification for %s#%d failed: %s\n",
                        server, port, X509_verify_cert_error_string(vres));
            }
        }
        SSL_free(ssl);
        return NULL;
    }

    /* ハンドシェイク成功後も、検証結果を明示的に再確認する */
    if ((qo->tls_ca_file || qo->tls_verify_default_store) &&
        SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, ";; TLS peer certificate verification for %s#%d failed: %s\n",
                server, port, X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

static ssize_t do_tls_exchange(const char *server, int port, const query_opts_t *qo,
                               const uint8_t *pkt, size_t pkt_len,
                               uint8_t *resp, size_t resp_cap, int timeout_sec) {
    SSL *ssl = NULL;
    int sock = -1;
    bool reused = false;

    if (qo && qo->keep_tcp_open) {
        if (g_cached_conn.sock >= 0 && g_cached_conn.is_tls && g_cached_conn.ssl &&
            strcmp(g_cached_conn.server, server) == 0 && g_cached_conn.port == port &&
            g_cached_conn.pref_family == qo->pref_family &&
            strcmp(g_cached_conn.bind_addr, qo->bind_addr) == 0 &&
            g_cached_conn.bind_port == qo->bind_port) {
            sock = g_cached_conn.sock;
            ssl = g_cached_conn.ssl;
            g_last_socket_family = g_cached_conn.family;
            reused = true;
        } else {
            close_cached_tcp();
        }
    } else {
        close_cached_tcp();
    }

    if (!ssl) {
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        set_socket_timeouts(sock, timeout_sec);
        send_proxyv2_if_enabled(sock, qo, true);
        ssl = establish_tls(sock, qo, server, port);
        if (!ssl) {
            close(sock);
            return -1;
        }
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = ssl;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = true;
        }
    }

    uint8_t len_prefix[2] = { (uint8_t)(pkt_len >> 8), (uint8_t)(pkt_len & 0xFF) };
    bool write_ok = (SSL_write(ssl, len_prefix, 2) > 0 && SSL_write(ssl, pkt, (int)pkt_len) > 0);
    if (!write_ok && reused) {
        close_cached_tcp();
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        set_socket_timeouts(sock, timeout_sec);
        send_proxyv2_if_enabled(sock, qo, true);
        ssl = establish_tls(sock, qo, server, port);
        if (!ssl) { close(sock); return -1; }
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = ssl;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = true;
        }
        if (SSL_write(ssl, len_prefix, 2) <= 0 || SSL_write(ssl, pkt, (int)pkt_len) <= 0) {
            close_cached_tcp();
            return -1;
        }
    } else if (!write_ok) {
        close_cached_tcp();
        if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
        return -1;
    }

    uint8_t rlen_buf[2];
    int got = 0;
    while (got < 2) {
        int r = SSL_read(ssl, rlen_buf + got, 2 - got);
        if (r <= 0) break;
        got += r;
    }
    if (got < 2) {
        if (reused) {
            close_cached_tcp();
            printf(";; communications error to %s#%d: end of file\n", server, port);
            sock = connect_tcp(server, port, qo, timeout_sec);
            if (sock < 0) return -1;
            set_socket_timeouts(sock, timeout_sec);
            send_proxyv2_if_enabled(sock, qo, true);
            ssl = establish_tls(sock, qo, server, port);
            if (!ssl) { close(sock); return -1; }
            if (qo && qo->keep_tcp_open) {
                g_cached_conn.sock = sock;
                g_cached_conn.ssl = ssl;
                snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
                g_cached_conn.port = port;
                g_cached_conn.pref_family = qo->pref_family;
                snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
                g_cached_conn.bind_port = qo->bind_port;
                g_cached_conn.is_tls = true;
            }
            if (SSL_write(ssl, len_prefix, 2) <= 0 || SSL_write(ssl, pkt, (int)pkt_len) <= 0) {
                close_cached_tcp();
                return -1;
            }
            got = 0;
            while (got < 2) {
                int r = SSL_read(ssl, rlen_buf + got, 2 - got);
                if (r <= 0) { close_cached_tcp(); return -1; }
                got += r;
            }
        } else {
            close_cached_tcp();
            if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
            return -1;
        }
    }
    uint16_t rlen = (rlen_buf[0] << 8) | rlen_buf[1];
    if (rlen > resp_cap) {
        // TLSストリームの同期崩れを防ぐため直ちに切断する
        close_cached_tcp();
        if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
        return -1;
    }
    size_t total_read = 0;
    while (total_read < rlen) {
        int r = SSL_read(ssl, resp + total_read, (int)(rlen - total_read));
        if (r <= 0) break;
        total_read += r;
    }

    if (total_read < (size_t)rlen) {
        if (reused) {
            close_cached_tcp();
            printf(";; communications error to %s#%d: end of file\n", server, port);
            sock = connect_tcp(server, port, qo, timeout_sec);
            if (sock < 0) return -1;
            set_socket_timeouts(sock, timeout_sec);
            send_proxyv2_if_enabled(sock, qo, true);
            ssl = establish_tls(sock, qo, server, port);
            if (!ssl) { close(sock); return -1; }
            if (qo && qo->keep_tcp_open) {
                g_cached_conn.sock = sock;
                g_cached_conn.ssl = ssl;
                snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
                g_cached_conn.port = port;
                g_cached_conn.pref_family = qo->pref_family;
                snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
                g_cached_conn.bind_port = qo->bind_port;
                g_cached_conn.is_tls = true;
            }
            if (SSL_write(ssl, len_prefix, 2) <= 0 || SSL_write(ssl, pkt, (int)pkt_len) <= 0) {
                close_cached_tcp();
                return -1;
            }
            uint8_t rlen_buf2[2];
            int got2 = 0;
            while (got2 < 2) {
                int r = SSL_read(ssl, rlen_buf2 + got2, 2 - got2);
                if (r <= 0) { close_cached_tcp(); return -1; }
                got2 += r;
            }
            uint16_t rlen2 = (rlen_buf2[0] << 8) | rlen_buf2[1];
            if (rlen2 > resp_cap) {
                // TLSストリームの同期崩れを防ぐため直ちに切断する
                close_cached_tcp();
                if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
                return -1;
            }
            total_read = 0;
            while (total_read < rlen2) {
                int r = SSL_read(ssl, resp + total_read, (int)(rlen2 - total_read));
                if (r <= 0) break;
                total_read += r;
            }
            if (total_read < (size_t)rlen2) {
                close_cached_tcp();
                return -1;
            }
        } else {
            close_cached_tcp();
            if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
            return -1;
        }
    }

    if (!(qo && qo->keep_tcp_open)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
    }
    return (ssize_t)total_read;
}

static void base64url_encode(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    static const char b64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t out_len = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = (uint32_t)data[i] << 16;
        if (i + 1 < len) val |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) val |= data[i + 2];

        if (out_len + 1 < out_cap) out[out_len++] = b64url[(val >> 18) & 0x3F];
        if (out_len + 1 < out_cap) out[out_len++] = b64url[(val >> 12) & 0x3F];
        if (i + 1 < len && out_len + 1 < out_cap) out[out_len++] = b64url[(val >> 6) & 0x3F];
        if (i + 2 < len && out_len + 1 < out_cap) out[out_len++] = b64url[val & 0x3F];
    }
    out[out_len] = '\0';
}

static ssize_t do_doh_exchange(const char *server, int port, const query_opts_t *qo,
                               const uint8_t *pkt, size_t pkt_len,
                               uint8_t *resp, size_t resp_cap, int timeout_sec) {
    int sock = connect_tcp(server, port, qo, timeout_sec);
    if (sock < 0) return -1;
    set_socket_timeouts(sock, timeout_sec);
    send_proxyv2_if_enabled(sock, qo, true);
    SSL *ssl = NULL;
    if (qo->doh_tls) {
        ssl = establish_tls(sock, qo, server, port);
        if (!ssl) { close(sock); return -1; }
    }

    const char *path = (qo->doh_path && qo->doh_path[0]) ? qo->doh_path : "/dns-query";
    char req_hdr[4096];
    int req_hdr_len = 0;

    if (qo->doh_method == DOH_GET) {
        char b64_dns[8192];
        size_t b64_needed = ((pkt_len + 2) / 3) * 4 + 1;
        if (b64_needed > sizeof(b64_dns)) {
            fprintf(stderr, ";; Query too large for +https-get (use +https-post or +https instead)\n");
            if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
            close(sock);
            return -1;
        }
        base64url_encode(pkt, pkt_len, b64_dns, sizeof(b64_dns));
        const char *separator = strchr(path, '?') ? "&" : "?";
        req_hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "GET %s%sdns=%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Accept: application/dns-message\r\n"
            "User-Agent: KariDNS-dag/1.0\r\n"
            "Connection: close\r\n\r\n",
            path, separator, b64_dns, server);
    } else {
        req_hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/dns-message\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Length: %zu\r\n"
            "User-Agent: KariDNS-dag/1.0\r\n"
            "Connection: close\r\n\r\n",
            path, server, pkt_len);
    }

    if (ssl) {
        if (SSL_write(ssl, req_hdr, req_hdr_len) <= 0) goto err;
        if (qo->doh_method == DOH_POST) {
            if (SSL_write(ssl, pkt, (int)pkt_len) <= 0) goto err;
        }
    } else {
        if (send(sock, req_hdr, req_hdr_len, 0) < 0) goto err;
        if (qo->doh_method == DOH_POST) {
            if (send(sock, pkt, pkt_len, 0) < 0) goto err;
        }
    }

    uint8_t http_buf[65535 + 4096];
    size_t http_len = 0;
    while (http_len < sizeof(http_buf)) {
        int r = 0;
        if (ssl) r = SSL_read(ssl, http_buf + http_len, (int)(sizeof(http_buf) - http_len));
        else r = (int)recv(sock, http_buf + http_len, sizeof(http_buf) - http_len, 0);
        if (r <= 0) break;
        http_len += r;

        // Content-Lengthを動的にチェックしてループを抜ける
        uint8_t *hdr_end = memmem(http_buf, http_len, "\r\n\r\n", 4);
        if (hdr_end) {
            size_t header_len = hdr_end - http_buf;
            size_t body_offset = header_len + 4;
            size_t current_body_len = http_len - body_offset;
            
            size_t cl_val = 0;
            for (size_t i = 0; i + 15 <= header_len; i++) {
                if (strncasecmp((char *)http_buf + i, "Content-Length:", 15) == 0) {
                    cl_val = (size_t)strtoul((char *)http_buf + i + 15, NULL, 10);
                    break;
                }
            }
            if (cl_val > 0 && current_body_len >= cl_val) break;
        }
    }

    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(sock);

    if (http_len < 16) return -1;
    uint8_t *hdr_end_u8 = memmem(http_buf, http_len, "\r\n\r\n", 4);
    if (!hdr_end_u8) return -1;
    size_t header_len = hdr_end_u8 - http_buf;
    size_t body_offset = header_len + 4;
    size_t body_len = http_len - body_offset;

    size_t cl_val = 0;
    bool found_cl = false;
    for (size_t i = 0; i + 15 <= header_len; i++) {
        if (strncasecmp((char *)http_buf + i, "Content-Length:", 15) == 0) {
            cl_val = (size_t)strtoul((char *)http_buf + i + 15, NULL, 10);
            found_cl = true;
            break;
        }
    }
    if (found_cl && cl_val < body_len) body_len = cl_val;

    if (body_len > resp_cap) body_len = resp_cap;
    memcpy(resp, http_buf + body_offset, body_len);
    return (ssize_t)body_len;

err:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(sock);
    return -1;
}

static ssize_t do_tcp_exchange(const char *server, int port, const query_opts_t *qo,
                               const uint8_t *pkt, size_t pkt_len,
                               uint8_t *resp, size_t resp_cap, int timeout_sec) {
    int sock = -1;
    bool reused = false;

    if (qo && qo->keep_tcp_open) {
        if (g_cached_conn.sock >= 0 && !g_cached_conn.is_tls &&
            strcmp(g_cached_conn.server, server) == 0 && g_cached_conn.port == port &&
            g_cached_conn.pref_family == qo->pref_family &&
            strcmp(g_cached_conn.bind_addr, qo->bind_addr) == 0 &&
            g_cached_conn.bind_port == qo->bind_port) {
            sock = g_cached_conn.sock;
            g_last_socket_family = g_cached_conn.family;
            reused = true;
        } else {
            close_cached_tcp();
        }
    } else {
        close_cached_tcp();
    }

    if (sock < 0) {
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        send_proxyv2_if_enabled(sock, qo, true);
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = NULL;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = false;
        }
    }

    set_socket_timeouts(sock, timeout_sec);

    uint16_t prefix_value = (uint16_t)pkt_len;
    uint8_t len_prefix[2] = { (uint8_t)(prefix_value >> 8), (uint8_t)(prefix_value & 0xFF) };

    bool send_ok = (send(sock, len_prefix, 2, 0) == 2 && send(sock, pkt, pkt_len, 0) == (ssize_t)pkt_len);
    if (!send_ok && reused) {
        close_cached_tcp();
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        send_proxyv2_if_enabled(sock, qo, true);
        set_socket_timeouts(sock, timeout_sec);
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = NULL;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = false;
        }
        if (send(sock, len_prefix, 2, 0) != 2 || send(sock, pkt, pkt_len, 0) != (ssize_t)pkt_len) {
            close_cached_tcp();
            return -1;
        }
    } else if (!send_ok) {
        close_cached_tcp();
        return -1;
    }

    ssize_t n = do_tcp_recv_response(sock, resp, resp_cap);
    if (n < 0 && reused) {
        printf(";; communications error to %s#%d: end of file\n", server, port);
        close_cached_tcp();
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        send_proxyv2_if_enabled(sock, qo, true);
        set_socket_timeouts(sock, timeout_sec);
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = NULL;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = false;
        }
        if (send(sock, len_prefix, 2, 0) == 2 && send(sock, pkt, pkt_len, 0) == (ssize_t)pkt_len) {
            n = do_tcp_recv_response(sock, resp, resp_cap);
        }
    }
    if (n < 0 || !(qo && qo->keep_tcp_open)) {
        close_cached_tcp();
        if (!(qo && qo->keep_tcp_open)) close(sock);
    }
    return n;
}

static ssize_t do_dns_exchange_by_transport(const char *server, int port, const query_opts_t *qo,
                                            bool use_tcp, const uint8_t *pkt, size_t pkt_len,
                                            uint8_t *resp, size_t resp_cap, int timeout_sec) {
    if (qo && qo->use_doh) {
        return do_doh_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    } else if (qo && qo->use_tls) {
        return do_tls_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    } else if (use_tcp) {
        return do_tcp_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    } else {
        return do_udp_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    }
}

static ssize_t do_dns_exchange_auto(const char *server, int port, const query_opts_t *qo,
                                     const uint8_t *pkt, size_t pkt_len,
                                     uint8_t *resp, size_t resp_cap, int timeout_sec,
                                     bool force_tcp) {
    if (force_tcp || (qo && (qo->use_doh || qo->use_tls))) {
        return do_dns_exchange_by_transport(server, port, qo, force_tcp, pkt, pkt_len, resp, resp_cap, timeout_sec);
    }
    ssize_t n = do_udp_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    if (n >= 4 && (resp[2] & 0x02) != 0) { // TC bit detected (truncation)
        ssize_t tn = do_tcp_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
        if (tn > 0) return tn;
    }
    return n;
}

static const char *format_class_name(uint16_t klass, char *buf, size_t buf_size);

/* ========================================================================
 * 7. Response pretty-printing (dig-style)
 * ==================================================================== */
static const char *rcode_name(uint16_t rcode) {
    // Note: RCODEs 6 (YXDOMAIN), 7 (YXRRSET), 8 (NXRRSET) are only meaningful in
    // RFC 2136 DNS UPDATE responses (opcode_name(opcode) == "UPDATE"). In normal 
    // QUERY responses, they are undefined. We unconditionally return their UPDATE
    // names here since they rarely appear otherwise.
    switch (rcode) {
        case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN"; case 4: return "NOTIMP"; case 5: return "REFUSED";
        case 6: return "YXDOMAIN"; case 7: return "YXRRSET"; case 8: return "NXRRSET";
        case 9: return "NOTAUTH"; case 16: return "BADVERS/BADSIG"; case 17: return "BADKEY";
        case 18: return "BADTIME"; case 23: return "BADCOOKIE";
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

static int parse_opcode_value(const char *s) {
    if (!s || !*s) return -1;
    if (strcasecmp(s, "QUERY") == 0) return 0;
    if (strcasecmp(s, "IQUERY") == 0) return 1;
    if (strcasecmp(s, "STATUS") == 0) return 2;
    if (strcasecmp(s, "NOTIFY") == 0) return 4;
    if (strcasecmp(s, "UPDATE") == 0) return 5;
    char *endp;
    long val = strtol(s, &endp, 10);
    if (*endp == '\0' && val >= 0 && val <= 15) return (int)val;
    return -1;
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

static void format_loc_prec(double val, char *buf, size_t len) {
    if (val == (long)val) {
        snprintf(buf, len, "%.0fm", val);
    } else {
        snprintf(buf, len, "%.2fm", val);
    }
}

static void format_time_comment(uint32_t sec, char *buf, size_t len) {
    if (sec == 0) { snprintf(buf, len, " (0 seconds)"); return; }
    if (sec % 604800 == 0) {
        uint32_t w = sec / 604800;
        snprintf(buf, len, " (%u %s)", w, w == 1 ? "week" : "weeks");
    } else if (sec % 86400 == 0) {
        uint32_t d = sec / 86400;
        snprintf(buf, len, " (%u %s)", d, d == 1 ? "day" : "days");
    } else if (sec % 3600 == 0) {
        uint32_t h = sec / 3600;
        snprintf(buf, len, " (%u %s)", h, h == 1 ? "hour" : "hours");
    } else if (sec % 60 == 0) {
        uint32_t m = sec / 60;
        snprintf(buf, len, " (%u %s)", m, m == 1 ? "minute" : "minutes");
    } else {
        snprintf(buf, len, " (%u %s)", sec, sec == 1 ? "second" : "seconds");
    }
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

static char *base64_encode_alloc(const uint8_t *data, size_t len, int *out_len) {
    size_t cap = 4 * ((len + 2) / 3) + 1;
    char *buf = malloc(cap);
    if (!buf) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    int n = EVP_EncodeBlock((unsigned char *)buf, data, (int)len);
    if (out_len) *out_len = n;
    return buf;
}

static void print_split_b64(const char *b64, int len, int split_width) {
    if (split_width > 0 && len > split_width) {
        for (int i = 0; i < len; i += split_width) {
            if (i > 0) printf(" ");
            printf("%.*s", (len - i) < split_width ? (len - i) : split_width, b64 + i);
        }
    } else {
        printf("%.*s", len, b64);
    }
}

static void print_split_hex(const uint8_t *data, size_t len, int split_width) {
    int sw = (split_width > 0) ? (split_width / 2) : 0;
    for (size_t i = 0; i < len; i++) {
        if (sw > 0 && i > 0 && (i % sw) == 0) printf(" ");
        printf("%02X", data[i]);
    }
}

static void print_multiline_hex(const uint8_t *data, size_t len, int split_width) {
    if (len == 0) {
        printf("\t\t\t\t\t )\n");
        return;
    }
    int sw = (split_width > 0) ? (split_width / 2) : 22;
    if (sw <= 0) sw = 22;
    for (size_t i = 0; i < len; ) {
        printf("\t\t\t\t\t");
        size_t chunk = (len - i) < (size_t)sw ? (len - i) : (size_t)sw;
        for (size_t j = 0; j < chunk; j++) printf("%02X", data[i + j]);
        i += chunk;
        if (i < len) printf("\n");
        else printf(" )");
    }
}

static void print_multiline_b64(const char *b64, int len, int split_width) {
    if (len == 0) {
        printf("\t\t\t\t\t )\n");
        return;
    }
    int sw = (split_width > 0) ? split_width : 44;
    if (sw <= 0) sw = 44;
    for (int i = 0; i < len; ) {
        printf("\t\t\t\t\t");
        int chunk = (len - i) < sw ? (len - i) : sw;
        printf("%.*s", chunk, b64 + i);
        i += chunk;
        if (i < len) printf("\n");
        else printf(" )");
    }
}

static void print_dnskey_like(const uint8_t *rdata, size_t rdlen, const display_opts_t *dopt) {
    if (rdlen < 4) { printf("(malformed)"); return; }
    uint16_t flags = (rdata[0]<<8)|rdata[1];
    uint8_t protocol = rdata[2];
    uint8_t algorithm = rdata[3];
    uint16_t keytag = compute_dnskey_tag(rdata, rdlen);
    const char *alg_name = dnssec_algo_name(algorithm);
    bool is_ksk = (flags & 0x01) != 0;

    if (dopt && !dopt->show_crypto) {
        printf("%u %u %u [key id = %u]", flags, protocol, algorithm, keytag);
        return;
    }

    int n = 0;
    char *b64 = base64_encode_alloc(&rdata[4], rdlen - 4, &n);
    if (!b64) { printf("(oom)"); return; }

    if (dopt && dopt->multiline) {
        printf("%u %u %u (\n", flags, protocol, algorithm);
        int split_w = (dopt->split_width > 0) ? dopt->split_width : 44;
        for (int i = 0; i < n; i += split_w) {
            printf("\t\t\t\t\t%.*s\n", (n - i) < split_w ? (n - i) : split_w, b64 + i);
        }
        if (dopt->rrcomments || dopt->multiline) {
            printf("\t\t\t\t\t) ; %s; alg = %s ; key id = %u", is_ksk ? "KSK" : "ZSK", alg_name, keytag);
        } else {
            printf("\t\t\t\t\t)");
        }
    } else {
        printf("%u %u %u ", flags, protocol, algorithm);
        print_split_b64(b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
        if (dopt && dopt->rrcomments) {
            printf("  ; %s; alg = %s ; key id = %u", is_ksk ? "KSK" : "ZSK", alg_name, keytag);
        }
    }
    free(b64);
}

static void print_ds_like(const uint8_t *rdata, size_t rdlen, const display_opts_t *dopt) {
    if (rdlen < 4) { printf("(malformed)"); return; }
    uint16_t keytag = (rdata[0]<<8)|rdata[1];
    uint8_t algorithm = rdata[2];
    uint8_t digest_type = rdata[3];

    if (dopt && !dopt->show_crypto) {
        printf("%u %u %u [omitted]", keytag, algorithm, digest_type);
        return;
    }

    if (dopt && dopt->multiline) {
        printf("%u %u %u (\n", keytag, algorithm, digest_type);
        print_multiline_hex(&rdata[4], rdlen - 4, dopt->split_width);
    } else {
        printf("%u %u %u ", keytag, algorithm, digest_type);
        print_split_hex(&rdata[4], rdlen - 4, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
    }
}

static void base32hex_encode(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    size_t out_len = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
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

static void print_nsec3_params(const uint8_t *rdata, size_t rdlen, bool with_hash, const display_opts_t *dopt) {
    if (rdlen < 5) { printf("(malformed)"); return; }
    uint8_t hash_alg = rdata[0];
    uint8_t flags = rdata[1];
    uint16_t iterations = (rdata[2]<<8)|rdata[3];
    uint8_t salt_len = rdata[4];
    if ((size_t)(5 + salt_len) > rdlen) { printf("(malformed)"); return; }
    char salt_hex[512] = "-";
    if (salt_len > 0) {
        size_t p2 = 0;
        for (int i = 0; i < salt_len; i++) p2 += snprintf(salt_hex + p2, sizeof(salt_hex) - p2, "%02X", rdata[5 + i]);
    }

    if (with_hash) { // NSEC3 specific
        if ((size_t)(5 + salt_len + 1) > rdlen) { printf(" (malformed)"); return; }
        size_t pos = 5 + salt_len;
        uint8_t hash_len = rdata[pos++];
        if (pos + hash_len > rdlen) { printf(" (malformed)"); return; }
        char hash_b32[128];
        base32hex_encode(&rdata[pos], hash_len, hash_b32, sizeof(hash_b32));
        pos += hash_len;
        char types_buf[512];
        decode_type_bitmap(&rdata[pos], rdlen - pos, types_buf, sizeof(types_buf));
        if (dopt && dopt->multiline) {
            printf("%u %u %u %s (\n\t\t\t\t\t%s\n\t\t\t\t\t%s )", hash_alg, flags, iterations, salt_hex, hash_b32, types_buf);
        } else {
            printf("%u %u %u %s %s %s", hash_alg, flags, iterations, salt_hex, hash_b32, types_buf);
        }
    } else {
        printf("%u %u %u %s", hash_alg, flags, iterations, salt_hex);
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
                int n = 0;
                char *b64 = base64_encode_alloc(value, vlen, &n);
                if (b64) {
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

static void rdata_buf_append(char *out, size_t out_cap, size_t *pos, const char *fmt, ...) {
    if (*pos >= out_cap) return;
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(out + *pos, out_cap - *pos, fmt, args);
    va_end(args);
    if (n > 0) {
        *pos += (size_t)n;
        if (*pos >= out_cap) *pos = out_cap - 1;
    }
}

static void rdata_buf_append_split_b64(char *out, size_t out_cap, size_t *pos, const char *b64, int len, int split_width) {
    if (split_width <= 0) split_width = 56;
    for (int i = 0; i < len; i += split_width) {
        if (i > 0) rdata_buf_append(out, out_cap, pos, " ");
        int chunk = (len - i) < split_width ? (len - i) : split_width;
        rdata_buf_append(out, out_cap, pos, "%.*s", chunk, b64 + i);
    }
}

static void rdata_buf_append_split_hex(char *out, size_t out_cap, size_t *pos, const uint8_t *data, size_t len, int split_width) {
    int sw = (split_width > 0) ? (split_width / 2) : 0;
    for (size_t i = 0; i < len; i++) {
        if (sw > 0 && i > 0 && (i % sw) == 0) rdata_buf_append(out, out_cap, pos, " ");
        rdata_buf_append(out, out_cap, pos, "%02X", data[i]);
    }
}

static void format_rdata_for_display(const uint8_t *pkt, size_t pkt_len, uint16_t type,
                                     size_t abs_offset, uint16_t rdlen,
                                     char *out, size_t out_cap, const display_opts_t *dopt) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    size_t pos = 0;

    if (abs_offset + rdlen > pkt_len) {
        rdata_buf_append(out, out_cap, &pos, "(truncated RDATA)");
        return;
    }

    if (dopt && dopt->force_unknown_format) {
        rdata_buf_append(out, out_cap, &pos, "\\# %u", rdlen);
        if (rdlen > 0) {
            rdata_buf_append(out, out_cap, &pos, " ");
            for (size_t i = 0; i < rdlen; i++) {
                rdata_buf_append(out, out_cap, &pos, "%02X", pkt[abs_offset + i]);
            }
        }
        return;
    }

    switch (type) {
        case 1: { // A
            if (rdlen == 4) {
                rdata_buf_append(out, out_cap, &pos, "%d.%d.%d.%d",
                                 pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], pkt[abs_offset+3]);
            } else {
                rdata_buf_append(out, out_cap, &pos, "(malformed A, rdlen=%u)", rdlen);
            }
            return;
        }
        case 28: { // AAAA
            if (rdlen == 16) {
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &pkt[abs_offset], buf, sizeof(buf));
                rdata_buf_append(out, out_cap, &pos, "%s", buf);
            } else {
                rdata_buf_append(out, out_cap, &pos, "(malformed AAAA, rdlen=%u)", rdlen);
            }
            return;
        }
        case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 23: case 39: { // NS, MD, MF, CNAME, MB, MG, MR, PTR, NSAP-PTR, DNAME
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &name) == 0 && next <= abs_offset + rdlen) {
                rdata_buf_append(out, out_cap, &pos, "%s", name);
            } else {
                rdata_buf_append(out, out_cap, &pos, "(unparsable name)");
            }
            return;
        }
        case 15: { // MX
            if (rdlen < 3) { rdata_buf_append(out, out_cap, &pos, "(malformed MX)"); return; }
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &name) == 0 && next <= abs_offset + rdlen) {
                rdata_buf_append(out, out_cap, &pos, "%u %s", pref, name);
            } else {
                rdata_buf_append(out, out_cap, &pos, "%u (unparsable name)", pref);
            }
            return;
        }
        case 6: { // SOA
            char *mname = NULL, *rname = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &mname) != 0 ||
                expand_wire_name(pkt, pkt_len, next, &next, &g_dag_arena, &rname) != 0 ||
                next > abs_offset + rdlen) { // RDATA境界外読み取り防止
                rdata_buf_append(out, out_cap, &pos, "(unparsable SOA)");
                return;
            }
            size_t nums_off = next;
            if (nums_off + 20 > pkt_len || nums_off + 20 > abs_offset + rdlen) {
                rdata_buf_append(out, out_cap, &pos, "(truncated SOA)");
                return;
            }
            uint32_t serial  = ((uint32_t)pkt[nums_off]<<24)|((uint32_t)pkt[nums_off+1]<<16)|((uint32_t)pkt[nums_off+2]<<8)|pkt[nums_off+3];
            uint32_t refresh = ((uint32_t)pkt[nums_off+4]<<24)|((uint32_t)pkt[nums_off+5]<<16)|((uint32_t)pkt[nums_off+6]<<8)|pkt[nums_off+7];
            uint32_t retry   = ((uint32_t)pkt[nums_off+8]<<24)|((uint32_t)pkt[nums_off+9]<<16)|((uint32_t)pkt[nums_off+10]<<8)|pkt[nums_off+11];
            uint32_t expire  = ((uint32_t)pkt[nums_off+12]<<24)|((uint32_t)pkt[nums_off+13]<<16)|((uint32_t)pkt[nums_off+14]<<8)|pkt[nums_off+15];
            uint32_t minimum = ((uint32_t)pkt[nums_off+16]<<24)|((uint32_t)pkt[nums_off+17]<<16)|((uint32_t)pkt[nums_off+18]<<8)|pkt[nums_off+19];
            rdata_buf_append(out, out_cap, &pos, "%s %s %u %u %u %u %u", mname, rname, serial, refresh, retry, expire, minimum);
            return;
        }
        case 16: case 99: case 258: { // TXT, SPF, AVC
            size_t p = abs_offset, end = abs_offset + rdlen;
            bool first = true;
            while (p < end) {
                uint8_t slen = pkt[p++];
                if (p + slen > end) break;
                if (!first) rdata_buf_append(out, out_cap, &pos, " ");
                first = false;
                rdata_buf_append(out, out_cap, &pos, "\"");
                for (uint8_t i = 0; i < slen; i++) {
                    unsigned char c = pkt[p + i];
                    if (c == '"' || c == '\\') rdata_buf_append(out, out_cap, &pos, "\\%c", c);
                    else if (c >= 0x20 && c < 0x7f) rdata_buf_append(out, out_cap, &pos, "%c", c);
                    else rdata_buf_append(out, out_cap, &pos, "\\%03o", c);
                }
                rdata_buf_append(out, out_cap, &pos, "\"");
                p += slen;
            }
            return;
        }
        case 17: case 18: case 19: case 20: case 22: case 26: case 40: { // RP, AFSDB, X25, ISDN, NSAP, PX, SINK
            if (type == 17) { // RP
                char *mbox = NULL, *txt = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &mbox) == 0 &&
                    expand_wire_name(pkt, pkt_len, next, &next, &g_dag_arena, &txt) == 0 &&
                    next <= abs_offset + rdlen) {
                    rdata_buf_append(out, out_cap, &pos, "%s %s", mbox, txt);
                    return;
                }
            } else if (type == 18) { // AFSDB
                if (rdlen >= 2) {
                    uint16_t sub = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                    char *name = NULL; size_t next;
                    if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &name) == 0 &&
                        next <= abs_offset + rdlen) {
                        rdata_buf_append(out, out_cap, &pos, "%u %s", sub, name);
                        return;
                    }
                }
            } else if (type == 19) { // X25
                if (rdlen >= 1) {
                    uint8_t slen = pkt[abs_offset];
                    if (1 + slen <= rdlen) {
                        rdata_buf_append(out, out_cap, &pos, "\"%.*s\"", slen, &pkt[abs_offset + 1]);
                        return;
                    }
                }
            } else if (type == 20) { // ISDN
                if (rdlen >= 1) {
                    uint8_t slen = pkt[abs_offset];
                    if (1 + slen <= rdlen) {
                        rdata_buf_append(out, out_cap, &pos, "\"%.*s\"", slen, &pkt[abs_offset + 1]);
                        size_t p2 = 1 + slen;
                        if (p2 < rdlen) {
                            uint8_t slen2 = pkt[abs_offset + p2];
                            if (p2 + 1 + slen2 <= rdlen) {
                                rdata_buf_append(out, out_cap, &pos, " \"%.*s\"", slen2, &pkt[abs_offset + p2 + 1]);
                            }
                        }
                        return;
                    }
                }
            } else if (type == 22) { // NSAP
                rdata_buf_append(out, out_cap, &pos, "0x");
                for (size_t i = 0; i < rdlen; i++) rdata_buf_append(out, out_cap, &pos, "%02x", pkt[abs_offset + i]);
                return;
            }
            break;
        }
        case 21: case 36: case 107: { // RT / KX / LP
            if (rdlen >= 2) {
                uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
                char *name = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &name) == 0 &&
                    next <= abs_offset + rdlen) {
                    rdata_buf_append(out, out_cap, &pos, "%u %s", pref, name);
                    return;
                }
            }
            break;
        }
        case 27: { // GPOS
            const uint8_t *p = &pkt[abs_offset], *end = p + rdlen;
            char lat[64], lon[64], alt[64];
            p = read_char_string(p, end, lat, sizeof(lat));
            if (p) p = read_char_string(p, end, lon, sizeof(lon));
            if (p) p = read_char_string(p, end, alt, sizeof(alt));
            if (p) {
                rdata_buf_append(out, out_cap, &pos, "\"%s\" \"%s\" \"%s\"", lat, lon, alt);
                return;
            }
            break;
        }
        case 37: { // CERT
            if (rdlen >= 5) {
                uint16_t ctype = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
                uint16_t keytag = (pkt[abs_offset + 2] << 8) | pkt[abs_offset + 3];
                uint8_t alg = pkt[abs_offset + 4];
                char cbuf[32];
                rdata_buf_append(out, out_cap, &pos, "%s %u %u", cert_type_name(ctype, cbuf, sizeof(cbuf)), keytag, alg);
                if (rdlen > 5) {
                    int n = 0;
                    char *b64 = base64_encode_alloc(&pkt[abs_offset + 5], rdlen - 5, &n);
                    if (b64) {
                        rdata_buf_append(out, out_cap, &pos, " ");
                        rdata_buf_append_split_b64(out, out_cap, &pos, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                        free(b64);
                    }
                }
                return;
            }
            break;
        }
        case 42: { // APL
            size_t p = 0;
            bool first = true;
            while (p + 4 <= rdlen) {
                uint16_t afi = (pkt[abs_offset + p]<<8)|pkt[abs_offset + p + 1];
                uint8_t prefix = pkt[abs_offset + p + 2];
                uint8_t n_len = pkt[abs_offset + p + 3];
                bool negate = (n_len & 0x80) != 0;
                uint8_t afdlength = n_len & 0x7F;
                p += 4;
                if (p + afdlength > rdlen) break;
                uint8_t addr[16] = {0};
                memcpy(addr, &pkt[abs_offset + p], afdlength);
                p += afdlength;
                char addr_str[64] = "?";
                if (afi == 1) inet_ntop(AF_INET, addr, addr_str, sizeof(addr_str));
                else if (afi == 2) inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));
                if (!first) rdata_buf_append(out, out_cap, &pos, " ");
                first = false;
                rdata_buf_append(out, out_cap, &pos, "%s%u:%s/%u", negate ? "!" : "", afi, addr_str, prefix);
            }
            return;
        }
        case 44: { // SSHFP
            if (rdlen >= 2) {
                rdata_buf_append(out, out_cap, &pos, "%u %u ", pkt[abs_offset], pkt[abs_offset + 1]);
                rdata_buf_append_split_hex(out, out_cap, &pos, &pkt[abs_offset + 2], rdlen - 2, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                return;
            }
            break;
        }
        case 45: { // IPSECKEY
            if (rdlen >= 3) {
                uint8_t prec = pkt[abs_offset];
                uint8_t gw_type = pkt[abs_offset + 1];
                uint8_t alg = pkt[abs_offset + 2];
                char gw_buf[256] = ".";
                const uint8_t *p = &pkt[abs_offset + 3];
                const uint8_t *end = &pkt[abs_offset + rdlen];
                if (gw_type == 0) {
                    snprintf(gw_buf, sizeof(gw_buf), ".");
                } else if (gw_type == 1) {
                    if (p + 4 <= end) {
                        snprintf(gw_buf, sizeof(gw_buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
                        p += 4;
                    }
                } else if (gw_type == 2) {
                    if (p + 16 <= end) {
                        inet_ntop(AF_INET6, p, gw_buf, sizeof(gw_buf));
                        p += 16;
                    }
                } else if (gw_type == 3) {
                    char *gw = NULL; size_t next;
                    if (expand_wire_name(pkt, pkt_len, p - pkt, &next, &g_dag_arena, &gw) == 0 &&
                        next <= abs_offset + rdlen) {
                        snprintf(gw_buf, sizeof(gw_buf), "%s", gw);
                        p = &pkt[next];
                    }
                }
                rdata_buf_append(out, out_cap, &pos, "%u %u %u %s", prec, gw_type, alg, gw_buf);
                if (p < end) {
                    int n = 0;
                    char *b64 = base64_encode_alloc(p, end - p, &n);
                    if (b64) {
                        rdata_buf_append(out, out_cap, &pos, " ");
                        rdata_buf_append_split_b64(out, out_cap, &pos, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                        free(b64);
                    }
                }
                return;
            }
            break;
        }
        case 49: case 61: { // DHCID / OPENPGPKEY
            if (rdlen > 0) {
                int n = 0;
                char *b64 = base64_encode_alloc(&pkt[abs_offset], rdlen, &n);
                if (b64) {
                    rdata_buf_append_split_b64(out, out_cap, &pos, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                    free(b64);
                }
                return;
            }
            break;
        }
        case 51: { // NSEC3PARAM
            if (rdlen >= 4) {
                uint8_t hash_alg = pkt[abs_offset];
                uint8_t flags = pkt[abs_offset + 1];
                uint16_t iter = (pkt[abs_offset + 2]<<8)|pkt[abs_offset + 3];
                uint8_t slen = pkt[abs_offset + 4];
                char salt_hex[512] = "-";
                if (slen > 0 && 5 + slen <= rdlen) {
                    size_t p2 = 0;
                    for (int i = 0; i < slen; i++) p2 += snprintf(salt_hex + p2, sizeof(salt_hex) - p2, "%02X", pkt[abs_offset + 5 + i]);
                }
                rdata_buf_append(out, out_cap, &pos, "%u %u %u %s", hash_alg, flags, iter, salt_hex);
                return;
            }
            break;
        }
        case 52: case 53: { // TLSA / SMIMEA
            if (rdlen >= 3) {
                rdata_buf_append(out, out_cap, &pos, "%u %u %u ", pkt[abs_offset], pkt[abs_offset + 1], pkt[abs_offset + 2]);
                rdata_buf_append_split_hex(out, out_cap, &pos, &pkt[abs_offset + 3], rdlen - 3, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                return;
            }
            break;
        }
        case 64: case 65: { // SVCB / HTTPS
            if (rdlen >= 2) {
                uint16_t priority = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                char *target = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &target) == 0 &&
                    next >= abs_offset + 2 && next <= abs_offset + rdlen) {
                    rdata_buf_append(out, out_cap, &pos, "%u %s", priority, (target[0] == '\0') ? "." : target);
                    size_t sp_pos = next;
                    while (sp_pos + 4 <= abs_offset + rdlen) {
                        uint16_t key = (pkt[sp_pos]<<8)|pkt[sp_pos+1];
                        uint16_t vlen = (pkt[sp_pos+2]<<8)|pkt[sp_pos+3];
                        sp_pos += 4;
                        if (sp_pos + vlen > abs_offset + rdlen) break;
                        const uint8_t *val = &pkt[sp_pos];
                        if (key == 1) { // alpn
                            rdata_buf_append(out, out_cap, &pos, " alpn=\"");
                            size_t ap = 0; bool afirst = true;
                            while (ap < vlen) {
                                uint8_t alen = val[ap++];
                                if (ap + alen > vlen) break;
                                if (!afirst) rdata_buf_append(out, out_cap, &pos, ",");
                                afirst = false;
                                rdata_buf_append(out, out_cap, &pos, "%.*s", alen, &val[ap]);
                                ap += alen;
                            }
                            rdata_buf_append(out, out_cap, &pos, "\"");
                        } else if (key == 2) {
                            rdata_buf_append(out, out_cap, &pos, " no-default-alpn");
                        } else if (key == 3) {
                            uint16_t pnum = (vlen >= 2) ? ((val[0]<<8)|val[1]) : 0;
                            rdata_buf_append(out, out_cap, &pos, " port=%u", pnum);
                        } else if (key == 4 || key == 6) {
                            rdata_buf_append(out, out_cap, &pos, " %s=\"", (key == 4) ? "ipv4hint" : "ipv6hint");
                            size_t sz = (key == 4) ? 4 : 16;
                            bool hfirst = true;
                            for (size_t hp = 0; hp + sz <= vlen; hp += sz) {
                                char abuf[INET6_ADDRSTRLEN];
                                if (key == 4) inet_ntop(AF_INET, val + hp, abuf, sizeof(abuf));
                                else inet_ntop(AF_INET6, val + hp, abuf, sizeof(abuf));
                                if (!hfirst) rdata_buf_append(out, out_cap, &pos, ",");
                                hfirst = false;
                                rdata_buf_append(out, out_cap, &pos, "%s", abuf);
                            }
                            rdata_buf_append(out, out_cap, &pos, "\"");
                        }
                        sp_pos += vlen;
                    }
                    return;
                }
            }
            break;
        }
        case 33: { // SRV
            if (rdlen < 7) { rdata_buf_append(out, out_cap, &pos, "(malformed SRV)"); return; }
            uint16_t prio = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            uint16_t weight = (pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
            uint16_t port = (pkt[abs_offset+4]<<8)|pkt[abs_offset+5];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 6, &next, &g_dag_arena, &name) == 0 &&
                next <= abs_offset + rdlen) {
                rdata_buf_append(out, out_cap, &pos, "%u %u %u %s", prio, weight, port, name);
            } else {
                rdata_buf_append(out, out_cap, &pos, "%u %u %u (unparsable name)", prio, weight, port);
            }
            return;
        }
        case 35: { // NAPTR
            if (rdlen >= 4) {
                uint16_t order = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
                uint16_t pref = (pkt[abs_offset + 2] << 8) | pkt[abs_offset + 3];
                char flags[256], svcs[256], regexp[256];
                const uint8_t *p = &pkt[abs_offset + 4];
                const uint8_t *end = &pkt[abs_offset + rdlen];
                p = read_char_string(p, end, flags, sizeof(flags));
                if (p) p = read_char_string(p, end, svcs, sizeof(svcs));
                if (p) p = read_char_string(p, end, regexp, sizeof(regexp));
                if (p) {
                    char *repl = NULL; size_t next;
                    if (expand_wire_name(pkt, pkt_len, p - pkt, &next, &g_dag_arena, &repl) == 0 &&
                        next <= abs_offset + rdlen) {
                        rdata_buf_append(out, out_cap, &pos, "%u %u \"%s\" \"%s\" \"%s\" %s", order, pref, flags, svcs, regexp, repl);
                        return;
                    }
                }
            }
            break;
        }
        case 256: { // URI
            if (rdlen >= 4) {
                uint16_t prio = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
                uint16_t weight = (pkt[abs_offset + 2] << 8) | pkt[abs_offset + 3];
                rdata_buf_append(out, out_cap, &pos, "%u %u \"%.*s\"", prio, weight, (int)(rdlen - 4), &pkt[abs_offset + 4]);
                return;
            }
            break;
        }
        case 24: case 46: { // SIG, RRSIG
            if (rdlen < 18) { rdata_buf_append(out, out_cap, &pos, "(malformed)"); return; }
            uint16_t type_covered = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            uint8_t algorithm = pkt[abs_offset+2];
            uint8_t labels = pkt[abs_offset+3];
            uint32_t original_ttl = ((uint32_t)pkt[abs_offset+4]<<24)|((uint32_t)pkt[abs_offset+5]<<16)|((uint32_t)pkt[abs_offset+6]<<8)|pkt[abs_offset+7];
            uint32_t sig_expiration = ((uint32_t)pkt[abs_offset+8]<<24)|((uint32_t)pkt[abs_offset+9]<<16)|((uint32_t)pkt[abs_offset+10]<<8)|pkt[abs_offset+11];
            uint32_t sig_inception = ((uint32_t)pkt[abs_offset+12]<<24)|((uint32_t)pkt[abs_offset+13]<<16)|((uint32_t)pkt[abs_offset+14]<<8)|pkt[abs_offset+15];
            uint16_t key_tag = (pkt[abs_offset+16]<<8)|pkt[abs_offset+17];
            char *signer_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 18, &next, &g_dag_arena, &signer_name) == 0 &&
                next <= abs_offset + rdlen) {
                char exp_str[32], inc_str[32], tname_buf[32];
                format_rrsig_time(sig_expiration, exp_str, sizeof(exp_str));
                format_rrsig_time(sig_inception, inc_str, sizeof(inc_str));
                const char *cov_name = format_type_name(type_covered, tname_buf, sizeof(tname_buf));
                rdata_buf_append(out, out_cap, &pos, "%s %u %u %u %s %s %u %s ",
                                 cov_name, algorithm, labels, original_ttl, exp_str, inc_str, key_tag, signer_name);
                size_t sig_offset = next - abs_offset;
                if (sig_offset <= rdlen) {
                    int n = 0;
                    char *b64 = base64_encode_alloc(&pkt[abs_offset + sig_offset], rdlen - sig_offset, &n);
                    if (b64) {
                        rdata_buf_append_split_b64(out, out_cap, &pos, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 56);
                        free(b64);
                        return;
                    }
                }
            }
            break;
        }
        case 43: case 59: case 32768: case 32769: { // DS, CDS, TA, DLV
            if (rdlen < 4) { rdata_buf_append(out, out_cap, &pos, "(malformed)"); return; }
            uint16_t keytag = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            uint8_t algorithm = pkt[abs_offset+2];
            uint8_t digest_type = pkt[abs_offset+3];
            rdata_buf_append(out, out_cap, &pos, "%u %u %u ", keytag, algorithm, digest_type);
            rdata_buf_append_split_hex(out, out_cap, &pos, &pkt[abs_offset + 4], rdlen - 4, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
            return;
        }
        case 25: case 48: case 60: { // KEY, DNSKEY, CDNSKEY
            if (rdlen < 4) { rdata_buf_append(out, out_cap, &pos, "(malformed)"); return; }
            uint16_t flags = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            uint8_t protocol = pkt[abs_offset+2];
            uint8_t algorithm = pkt[abs_offset+3];
            rdata_buf_append(out, out_cap, &pos, "%u %u %u ", flags, protocol, algorithm);
            int n = 0;
            char *b64 = base64_encode_alloc(&pkt[abs_offset + 4], rdlen - 4, &n);
            if (b64) {
                rdata_buf_append_split_b64(out, out_cap, &pos, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 56);
                free(b64);
            }
            return;
        }
        case 47: { // NSEC
            char *next_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &next_name) == 0 &&
                next <= abs_offset + rdlen) {
                size_t name_consumed = next - abs_offset;
                if (name_consumed < rdlen) {
                    char types_buf[512];
                    decode_type_bitmap(&pkt[abs_offset + name_consumed], rdlen - name_consumed, types_buf, sizeof(types_buf));
                    rdata_buf_append(out, out_cap, &pos, "%s %s", next_name, types_buf);
                    return;
                }
            }
            break;
        }
        case 50: { // NSEC3
            if (rdlen < 5) { rdata_buf_append(out, out_cap, &pos, "(malformed)"); return; }
            uint8_t hash_alg = pkt[abs_offset];
            uint8_t flags = pkt[abs_offset + 1];
            uint16_t iterations = (pkt[abs_offset + 2]<<8)|pkt[abs_offset + 3];
            uint8_t salt_len = pkt[abs_offset + 4];
            if ((size_t)(5 + salt_len) <= rdlen) {
                char salt_hex[512] = "-";
                if (salt_len > 0) {
                    size_t p2 = 0;
                    for (int i = 0; i < salt_len; i++) p2 += snprintf(salt_hex + p2, sizeof(salt_hex) - p2, "%02X", pkt[abs_offset + 5 + i]);
                }
                rdata_buf_append(out, out_cap, &pos, "%u %u %u %s", hash_alg, flags, iterations, salt_hex);
                size_t p3 = 5 + salt_len;
                if (p3 < rdlen) {
                    uint8_t hash_len = pkt[abs_offset + p3++];
                    if (p3 + hash_len <= rdlen) {
                        char hash_b32[128];
                        base32hex_encode(&pkt[abs_offset + p3], hash_len, hash_b32, sizeof(hash_b32));
                        p3 += hash_len;
                        char types_buf[512];
                        decode_type_bitmap(&pkt[abs_offset + p3], rdlen - p3, types_buf, sizeof(types_buf));
                        rdata_buf_append(out, out_cap, &pos, " %s %s", hash_b32, types_buf);
                        return;
                    }
                }
            }
            break;
        }
        case 62: { // CSYNC
            if (rdlen >= 6) {
                uint32_t serial = ((uint32_t)pkt[abs_offset]<<24)|((uint32_t)pkt[abs_offset+1]<<16)|((uint32_t)pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
                uint16_t flags = (pkt[abs_offset+4]<<8)|pkt[abs_offset+5];
                char types_buf[512];
                decode_type_bitmap(&pkt[abs_offset+6], rdlen - 6, types_buf, sizeof(types_buf));
                rdata_buf_append(out, out_cap, &pos, "%u %u %s", serial, flags, types_buf);
                return;
            }
            break;
        }
        case 63: { // ZONEMD
            if (rdlen >= 6) {
                uint32_t serial = ((uint32_t)pkt[abs_offset]<<24)|((uint32_t)pkt[abs_offset+1]<<16)|((uint32_t)pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
                uint8_t scheme = pkt[abs_offset+4];
                uint8_t halg = pkt[abs_offset+5];
                rdata_buf_append(out, out_cap, &pos, "%u %u %u ", serial, scheme, halg);
                for (size_t i = 6; i < rdlen; i++) rdata_buf_append(out, out_cap, &pos, "%02X", pkt[abs_offset + i]);
                return;
            }
            break;
        }
        case 250: { // TSIG
            char *alg_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &alg_name) == 0 &&
                next <= abs_offset + rdlen) {
                size_t tpos = next - abs_offset;
                if (tpos + 10 <= rdlen) {
                    uint64_t time_signed = ((uint64_t)pkt[abs_offset+tpos] << 40) | ((uint64_t)pkt[abs_offset+tpos+1] << 32) |
                                            ((uint64_t)pkt[abs_offset+tpos+2] << 24) | ((uint64_t)pkt[abs_offset+tpos+3] << 16) |
                                            ((uint64_t)pkt[abs_offset+tpos+4] << 8) | pkt[abs_offset+tpos+5];
                    uint16_t fudge = (pkt[abs_offset+tpos+6]<<8)|pkt[abs_offset+tpos+7];
                    uint16_t mac_size = (pkt[abs_offset+tpos+8]<<8)|pkt[abs_offset+tpos+9];
                    tpos += 10;
                    if (tpos + mac_size + 6 <= rdlen) {
                        char *mac_b64 = base64_encode_alloc(&pkt[abs_offset+tpos], mac_size, NULL);
                        tpos += mac_size;
                        uint16_t orig_id = (pkt[abs_offset+tpos]<<8)|pkt[abs_offset+tpos+1];
                        uint16_t tsig_err = (pkt[abs_offset+tpos+2]<<8)|pkt[abs_offset+tpos+3];
                        uint16_t other_len = (pkt[abs_offset+tpos+4]<<8)|pkt[abs_offset+tpos+5];
                        rdata_buf_append(out, out_cap, &pos, "%s %llu %u %u %s %u %s %u",
                                         alg_name, (unsigned long long)time_signed, fudge, mac_size,
                                         mac_b64 ? mac_b64 : "", orig_id, rcode_name(tsig_err), other_len);
                        if (mac_b64) free(mac_b64);
                        return;
                    }
                }
            }
            break;
        }
        case 257: { // CAA
            if (rdlen >= 2) {
                uint8_t flags = pkt[abs_offset];
                uint8_t tag_len = pkt[abs_offset + 1];
                if (2 + tag_len <= rdlen) {
                    rdata_buf_append(out, out_cap, &pos, "%u %.*s \"%.*s\"",
                                     flags, tag_len, &pkt[abs_offset + 2],
                                     (int)(rdlen - 2 - tag_len), &pkt[abs_offset + 2 + tag_len]);
                    return;
                }
            }
            break;
        }
        case 108: { // EUI48
            if (rdlen == 6) {
                rdata_buf_append(out, out_cap, &pos, "%02x-%02x-%02x-%02x-%02x-%02x",
                                 pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2],
                                 pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5]);
                return;
            }
            break;
        }
        case 109: { // EUI64
            if (rdlen == 8) {
                rdata_buf_append(out, out_cap, &pos, "%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
                                 pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], pkt[abs_offset+3],
                                 pkt[abs_offset+4], pkt[abs_offset+5], pkt[abs_offset+6], pkt[abs_offset+7]);
                return;
            }
            break;
        }
        case 104: { // NID
            if (rdlen == 10) {
                uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
                rdata_buf_append(out, out_cap, &pos, "%u %02x%02x:%02x%02x:%02x%02x:%02x%02x", pref,
                                 pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5],
                                 pkt[abs_offset+6], pkt[abs_offset+7], pkt[abs_offset+8], pkt[abs_offset+9]);
                return;
            }
            break;
        }
        case 105: { // L32
            if (rdlen == 6) {
                uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
                rdata_buf_append(out, out_cap, &pos, "%u %d.%d.%d.%d", pref,
                                 pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5]);
                return;
            }
            break;
        }
        case 106: { // L64
            if (rdlen == 10) {
                uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
                rdata_buf_append(out, out_cap, &pos, "%u %02x%02x:%02x%02x:%02x%02x:%02x%02x", pref,
                                 pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5],
                                 pkt[abs_offset+6], pkt[abs_offset+7], pkt[abs_offset+8], pkt[abs_offset+9]);
                return;
            }
            break;
        }
        default:
            break;
    }

    // Fallback: RFC 3597 Generic Format "\# <rdlen> <hex>"
    rdata_buf_append(out, out_cap, &pos, "\\# %u", rdlen);
    if (rdlen > 0) {
        rdata_buf_append(out, out_cap, &pos, " ");
        for (size_t i = 0; i < rdlen; i++) {
            rdata_buf_append(out, out_cap, &pos, "%02X", pkt[abs_offset + i]);
        }
    }
}

static void print_rdata(const uint8_t *pkt, size_t pkt_len, uint16_t type,
                         size_t abs_offset, uint16_t rdlen, const display_opts_t *dopt) {
    if (dopt && dopt->force_unknown_format) {
        printf("\\# %u", rdlen);
        if (rdlen > 0) {
            printf(" ");
            size_t valid_len = (abs_offset + rdlen <= pkt_len) ? rdlen : (pkt_len - abs_offset);
            print_split_hex(&pkt[abs_offset], valid_len, dopt->split_width);
        }
        return;
    }
    switch (type) {
        case 1:
            if (rdlen == 4) {
                printf("%d.%d.%d.%d", pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], pkt[abs_offset+3]);
            } else printf("(malformed A, rdlen=%u)", rdlen);
            break;
        case 28:
            if (rdlen == 16) {
                if (dopt && dopt->expandaaaa) {
                    for (int g = 0; g < 8; g++) {
                        uint16_t val = (pkt[abs_offset + g * 2] << 8) | pkt[abs_offset + g * 2 + 1];
                        printf("%s%04x", (g > 0) ? ":" : "", val);
                    }
                } else {
                    char buf[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &pkt[abs_offset], buf, sizeof(buf));
                    printf("%s", buf);
                }
            } else printf("(malformed AAAA, rdlen=%u)", rdlen);
            break;
        case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 23: case 39: { // NS / CNAME / PTR / DNAME
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &name) == 0 && next <= abs_offset + rdlen) printf("%s", name);
            else printf("(unparsable name)");
            break;
        }
        case 15: {
            if (rdlen < 3) { printf("(malformed MX)"); break; }
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &name) == 0 && next <= abs_offset + rdlen)
                printf("%u %s", pref, name);
            else printf("%u (unparsable name)", pref);
            break;
        }
        case 6: {
            char *mname = NULL, *rname = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &mname) != 0) { printf("(unparsable SOA)"); break; }
            size_t after_mname = next;
            if (expand_wire_name(pkt, pkt_len, after_mname, &next, &g_dag_arena, &rname) != 0 || next > abs_offset + rdlen) { printf("(unparsable SOA)"); break; }
            size_t nums_off = next;
            if (nums_off + 20 > pkt_len || nums_off + 20 > abs_offset + rdlen) { printf("(truncated SOA)"); break; }
            uint32_t serial  = ((uint32_t)pkt[nums_off]<<24)|((uint32_t)pkt[nums_off+1]<<16)|((uint32_t)pkt[nums_off+2]<<8)|pkt[nums_off+3];
            uint32_t refresh = ((uint32_t)pkt[nums_off+4]<<24)|((uint32_t)pkt[nums_off+5]<<16)|((uint32_t)pkt[nums_off+6]<<8)|pkt[nums_off+7];
            uint32_t retry   = ((uint32_t)pkt[nums_off+8]<<24)|((uint32_t)pkt[nums_off+9]<<16)|((uint32_t)pkt[nums_off+10]<<8)|pkt[nums_off+11];
            uint32_t expire  = ((uint32_t)pkt[nums_off+12]<<24)|((uint32_t)pkt[nums_off+13]<<16)|((uint32_t)pkt[nums_off+14]<<8)|pkt[nums_off+15];
            uint32_t minimum = ((uint32_t)pkt[nums_off+16]<<24)|((uint32_t)pkt[nums_off+17]<<16)|((uint32_t)pkt[nums_off+18]<<8)|pkt[nums_off+19];
            if (dopt && dopt->multiline) {
                char t_ref[32], t_ret[32], t_exp[32], t_min[32];
                format_time_comment(refresh, t_ref, sizeof(t_ref));
                format_time_comment(retry, t_ret, sizeof(t_ret));
                format_time_comment(expire, t_exp, sizeof(t_exp));
                format_time_comment(minimum, t_min, sizeof(t_min));
                printf("%s %s (\n", mname, rname);
                printf("\t\t\t\t\t%u\t; serial\n", serial);
                printf("\t\t\t\t\t%u\t; refresh%s\n", refresh, t_ref);
                printf("\t\t\t\t\t%u\t; retry%s\n", retry, t_ret);
                printf("\t\t\t\t\t%u\t; expire%s\n", expire, t_exp);
                printf("\t\t\t\t\t%u\t; minimum%s\n", minimum, t_min);
                printf("\t\t\t\t\t)");
            } else {
                printf("%s %s %u %u %u %u %u", mname, rname, serial, refresh, retry, expire, minimum);
            }
            break;
        }
        case 33: {
            if (rdlen < 7) { printf("(malformed SRV)"); break; }
            uint16_t prio = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            uint16_t weight = (pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
            uint16_t port = (pkt[abs_offset+4]<<8)|pkt[abs_offset+5];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 6, &next, &g_dag_arena, &name) == 0 && next <= abs_offset + rdlen)
                printf("%u %u %u %s", prio, weight, port, name);
            else printf("%u %u %u (unparsable name)", prio, weight, port);
            break;
        }
        case 16: case 99: case 258: { // TXT, SPF, AVC
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
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &mbox) != 0 ||
                expand_wire_name(pkt, pkt_len, next, &next, &g_dag_arena, &txt) != 0 ||
                next > abs_offset + rdlen) {
                goto fallback;
            }
            printf("%s %s", mbox, txt);
            break;
        }
        case 18: { // AFSDB
            if (rdlen < 3) goto fallback;
            uint16_t subtype = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *hostname = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &hostname) != 0 ||
                next > abs_offset + rdlen) goto fallback;
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
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &map822) != 0 ||
                expand_wire_name(pkt, pkt_len, next, &next, &g_dag_arena, &mapx400) != 0 ||
                next > abs_offset + rdlen) {
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
            char s_buf[32], hp_buf[32], vp_buf[32];
            format_loc_prec(loc_decode_precsize(size_b), s_buf, sizeof(s_buf));
            format_loc_prec(loc_decode_precsize(hp_b), hp_buf, sizeof(hp_buf));
            format_loc_prec(loc_decode_precsize(vp_b), vp_buf, sizeof(vp_buf));
            printf("%s %s %.2fm %s %s %s", lat_buf, lon_buf, alt_m, s_buf, hp_buf, vp_buf);
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
            if (expand_wire_name(pkt, pkt_len, p - pkt, &next, &g_dag_arena, &repl) != 0 ||
                next > abs_offset + rdlen) goto fallback;
            printf("%u %u \"%s\" \"%s\" \"%s\" %s", order, pref, flags, svcs, regexp, repl);
            break;
        }
        case 21: case 36: case 107: { // RT / KX / LP
            if (rdlen < 2) goto fallback;
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &name) != 0 ||
                next > abs_offset + rdlen) goto fallback;
            printf("%u %s", pref, name);
            break;
        }
        case 37: { // CERT
            if (rdlen < 5) goto fallback;
            uint16_t ctype = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            uint16_t keytag = (pkt[abs_offset + 2] << 8) | pkt[abs_offset + 3];
            uint8_t alg = pkt[abs_offset + 4];
            char cbuf[32];
            if (dopt && dopt->multiline) {
                printf("%s %u %u (\n", cert_type_name(ctype, cbuf, sizeof(cbuf)), keytag, alg);
                if (rdlen > 5) {
                    int n = 0;
                    char *b64 = base64_encode_alloc(&pkt[abs_offset + 5], rdlen - 5, &n);
                    if (!b64) goto fallback;
                    print_multiline_b64(b64, n, dopt->split_width);
                    free(b64);
                } else {
                    printf("\t\t\t\t\t)");
                }
            } else {
                printf("%s %u %u ", cert_type_name(ctype, cbuf, sizeof(cbuf)), keytag, alg);
                if (rdlen > 5) {
                    char *b64 = base64_encode_alloc(&pkt[abs_offset + 5], rdlen - 5, NULL);
                    if (!b64) goto fallback;
                    printf("%s", b64);
                    free(b64);
                }
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
            if (dopt && dopt->multiline) {
                printf("%u %u (\n", pkt[abs_offset], pkt[abs_offset + 1]);
                print_multiline_hex(&pkt[abs_offset + 2], rdlen - 2, dopt->split_width);
            } else {
                printf("%u %u ", pkt[abs_offset], pkt[abs_offset + 1]);
                print_split_hex(&pkt[abs_offset + 2], rdlen - 2, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
            }
            break;
        }
        case 45: { // IPSECKEY
            if (rdlen < 3) goto fallback;
            uint8_t prec = pkt[abs_offset];
            uint8_t gw_type = pkt[abs_offset + 1];
            uint8_t alg = pkt[abs_offset + 2];
            char gw_buf[256] = ".";
            const uint8_t *p = &pkt[abs_offset + 3];
            const uint8_t *end = &pkt[abs_offset + rdlen];
            if (gw_type == 0) {
                snprintf(gw_buf, sizeof(gw_buf), ".");
            } else if (gw_type == 1) {
                if (p + 4 > end) goto fallback;
                snprintf(gw_buf, sizeof(gw_buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
                p += 4;
            } else if (gw_type == 2) {
                if (p + 16 > end) goto fallback;
                inet_ntop(AF_INET6, p, gw_buf, sizeof(gw_buf));
                p += 16;
            } else if (gw_type == 3) {
                char *gw = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, p - pkt, &next, &g_dag_arena, &gw) != 0 ||
                    next > abs_offset + rdlen) goto fallback;
                snprintf(gw_buf, sizeof(gw_buf), "%s", gw);
                p = &pkt[next];
            } else goto fallback;

            if (dopt && dopt->multiline) {
                printf("( %u %u %u %s\n", prec, gw_type, alg, gw_buf);
                if (p < end) {
                    size_t key_len = end - p;
                    int n = 0;
                    char *b64 = base64_encode_alloc(p, key_len, &n);
                    if (!b64) goto fallback;
                    print_multiline_b64(b64, n, dopt->split_width);
                    free(b64);
                } else {
                    printf("\t\t\t\t\t)");
                }
            } else {
                printf("%u %u %u %s ", prec, gw_type, alg, gw_buf);
                if (p < end) {
                    size_t key_len = end - p;
                    int n = 0;
                    char *b64 = base64_encode_alloc(p, key_len, &n);
                    if (!b64) goto fallback;
                    print_split_b64(b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                    free(b64);
                }
            }
            break;
        }
        case 49: { // DHCID
            if (rdlen == 0) break;
            int n = 0;
            char *b64 = base64_encode_alloc(&pkt[abs_offset], rdlen, &n);
            if (!b64) goto fallback;
            if (dopt && dopt->multiline) {
                printf("( ");
                print_multiline_b64(b64, n, dopt->split_width);
                if (rdlen >= 3) {
                    uint16_t id_type = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                    uint8_t d_type = pkt[abs_offset+2];
                    printf(" ; %u %u %u", id_type, d_type, (unsigned int)(rdlen - 3));
                }
            } else {
                print_split_b64(b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
            }
            free(b64);
            break;
        }
        case 61: { // OPENPGPKEY
            if (rdlen == 0) break;
            int n = 0;
            char *b64 = base64_encode_alloc(&pkt[abs_offset], rdlen, &n);
            if (!b64) goto fallback;
            if (dopt && dopt->multiline) {
                printf("( ");
                print_multiline_b64(b64, n, dopt->split_width);
            } else {
                print_split_b64(b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
            }
            free(b64);
            break;
        }
        case 51: { // NSEC3PARAM
            print_nsec3_params(&pkt[abs_offset], rdlen, false, dopt);
            break;
        }
        case 52: case 53: { // TLSA / SMIMEA
            if (rdlen < 3) goto fallback;
            if (dopt && dopt->multiline) {
                printf("%u %u %u (\n", pkt[abs_offset], pkt[abs_offset + 1], pkt[abs_offset + 2]);
                print_multiline_hex(&pkt[abs_offset + 3], rdlen - 3, dopt->split_width);
            } else {
                printf("%u %u %u ", pkt[abs_offset], pkt[abs_offset + 1], pkt[abs_offset + 2]);
                print_split_hex(&pkt[abs_offset + 3], rdlen - 3, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
            }
            break;
        }
        case 64: case 65: { // SVCB / HTTPS
            if (rdlen < 2) goto fallback;
            uint16_t priority = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            char *target = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &target) != 0) goto fallback;
            if (next < abs_offset + 2 || next > abs_offset + rdlen) {
                // RFC 9460 §2.2 違反: TargetNameがこのRRのRDATA境界をはみ出している
                printf("(malformed SVCB/HTTPS: TargetName exceeds RDLENGTH)");
                break;
            }
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
                if (expand_wire_name(pkt, pkt_len, p - pkt, &next, &g_dag_arena, &gw) != 0 ||
                    next > abs_offset + rdlen) goto fallback;
                printf("%s", gw);
            } else goto fallback;
            break;
        }

        case 24: case 46: { // SIG, RRSIG
            if (rdlen < 18) goto fallback;
            uint16_t type_covered = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
            uint8_t algorithm = pkt[abs_offset+2];
            uint8_t labels = pkt[abs_offset+3];
            uint32_t original_ttl = ((uint32_t)pkt[abs_offset+4]<<24)|((uint32_t)pkt[abs_offset+5]<<16)|((uint32_t)pkt[abs_offset+6]<<8)|pkt[abs_offset+7];
            uint32_t sig_exp = ((uint32_t)pkt[abs_offset+8]<<24)|((uint32_t)pkt[abs_offset+9]<<16)|((uint32_t)pkt[abs_offset+10]<<8)|pkt[abs_offset+11];
            uint32_t sig_inc = ((uint32_t)pkt[abs_offset+12]<<24)|((uint32_t)pkt[abs_offset+13]<<16)|((uint32_t)pkt[abs_offset+14]<<8)|pkt[abs_offset+15];
            uint16_t key_tag = (pkt[abs_offset+16]<<8)|pkt[abs_offset+17];

            char *signer_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 18, &next, &g_dag_arena, &signer_name) != 0 ||
                next > abs_offset + rdlen) goto fallback;
            size_t sig_offset_in_rdata = (next - abs_offset);
            if (sig_offset_in_rdata >= rdlen) goto fallback;

            char covered_buf[32];
            const char *covered_name = format_type_name(type_covered, covered_buf, sizeof(covered_buf));
            char exp_str[32], inc_str[32];
            format_rrsig_time(sig_exp, exp_str, sizeof(exp_str));
            format_rrsig_time(sig_inc, inc_str, sizeof(inc_str));

            if (dopt && !dopt->show_crypto) {
                printf("%s %u %u %u %s %s %u %s [omitted]", covered_name, algorithm, labels,
                       original_ttl, exp_str, inc_str, key_tag, signer_name);
                break;
            }

            size_t sig_len = rdlen - sig_offset_in_rdata;
            int n = 0;
            char *b64 = base64_encode_alloc(&pkt[abs_offset + sig_offset_in_rdata], sig_len, &n);
            if (!b64) goto fallback;

            if (dopt && dopt->multiline) {
                printf("%s %u %u %u (\n", covered_name, algorithm, labels, original_ttl);
                printf("\t\t\t\t\t%s %s %u %s\n", exp_str, inc_str, key_tag, signer_name);
                print_multiline_b64(b64, n, dopt->split_width);
            } else {
                printf("%s %u %u %u %s %s %u %s ", covered_name, algorithm, labels,
                       original_ttl, exp_str, inc_str, key_tag, signer_name);
                print_split_b64(b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
            }
            free(b64);
            break;
        }
        case 47: { // NSEC
            char *next_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &next_name) != 0 ||
                next > abs_offset + rdlen) goto fallback;
            size_t name_consumed = next - abs_offset;
            if (name_consumed >= rdlen) goto fallback;
            char types_buf[512];
            decode_type_bitmap(&pkt[abs_offset + name_consumed], rdlen - name_consumed, types_buf, sizeof(types_buf));
            printf("%s %s", next_name, types_buf);
            break;
        }
        case 25: case 48: case 60: { // KEY, DNSKEY, CDNSKEY
            print_dnskey_like(&pkt[abs_offset], rdlen, dopt);
            break;
        }
        case 50: { // NSEC3
            print_nsec3_params(&pkt[abs_offset], rdlen, true, dopt);
            break;
        }
        case 43: case 59: case 32768: case 32769: { // DS, CDS, TA, DLV
            print_ds_like(&pkt[abs_offset], rdlen, dopt);
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
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &alg_name) != 0 ||
                next > abs_offset + rdlen) goto fallback;
            size_t pos = next - abs_offset;
            if (pos + 10 > rdlen) goto fallback;

            uint64_t time_signed = ((uint64_t)pkt[abs_offset+pos] << 40) | ((uint64_t)pkt[abs_offset+pos+1] << 32) |
                                    ((uint64_t)pkt[abs_offset+pos+2] << 24) | ((uint64_t)pkt[abs_offset+pos+3] << 16) |
                                    ((uint64_t)pkt[abs_offset+pos+4] << 8) | pkt[abs_offset+pos+5];
            uint16_t fudge = (pkt[abs_offset+pos+6]<<8)|pkt[abs_offset+pos+7];
            uint16_t mac_size = (pkt[abs_offset+pos+8]<<8)|pkt[abs_offset+pos+9];
            pos += 10;
            if (pos + mac_size + 6 > rdlen) goto fallback;

            int n = 0;
            char *mac_b64 = base64_encode_alloc(&pkt[abs_offset+pos], mac_size, &n);
            pos += mac_size;

            uint16_t original_id = (pkt[abs_offset+pos]<<8)|pkt[abs_offset+pos+1];
            uint16_t tsig_error = (pkt[abs_offset+pos+2]<<8)|pkt[abs_offset+pos+3];
            uint16_t other_len = (pkt[abs_offset+pos+4]<<8)|pkt[abs_offset+pos+5];
            
            const char *err_str = rcode_name(tsig_error);

            if (dopt && dopt->multiline) {
                printf("%s %llu %u %u (\n\t\t\t\t\t%.*s ) %u %s %u",
                       alg_name, (unsigned long long)time_signed, fudge, mac_size,
                       n, mac_b64 ? mac_b64 : "", original_id, err_str, other_len);
            } else {
                printf("%s %llu %u %u %.*s %u %s %u", alg_name, (unsigned long long)time_signed,
                       fudge, mac_size, n, mac_b64 ? mac_b64 : "", original_id,
                       err_str, other_len);
            }
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

            char hit_hex[512] = "";
            size_t hp = 0;
            for (int i = 0; i < hit_len; i++) hp += snprintf(hit_hex + hp, sizeof(hit_hex) - hp, "%02X", pkt[abs_offset + pos + i]);
            pos += hit_len;

            int n = 0;
            char *b64 = base64_encode_alloc(&pkt[abs_offset + pos], pk_len, &n);
            if (!b64) goto fallback;
            pos += pk_len;

            char rvs_names[512] = "";
            size_t rp = 0;
            while (pos < rdlen) {
                char *rvs_name = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset + pos, &next, &g_dag_arena, &rvs_name) != 0 ||
                    next > abs_offset + rdlen) break;
                rp += snprintf(rvs_names + rp, sizeof(rvs_names) - rp, "\n\t\t\t\t\t%s", rvs_name);
                pos = next - abs_offset;
            }

            if (dopt && dopt->multiline) {
                printf("( %u %s\n\t\t\t\t\t%.*s%s )", pk_algorithm, hit_hex, n, b64, rvs_names);
            } else {
                printf("%u %s %.*s", pk_algorithm, hit_hex, n, b64);
                if (rvs_names[0] != '\0') {
                    // in single line, replace newline with space
                    for (char *c = rvs_names; *c; c++) {
                        if (*c == '\n' || *c == '\t') *c = ' ';
                    }
                    printf("%s", rvs_names);
                }
            }
            free(b64);
            break;
        }
        case 11: { // WKS
            if (rdlen < 5) goto fallback;
            printf("%d.%d.%d.%d %u", pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4]);
            for (uint16_t i = 5; i < rdlen; i++) {
                uint8_t b = pkt[abs_offset+i];
                for (int bit = 0; bit < 8; bit++) {
                    if (b & (0x80 >> bit)) printf(" %d", (i - 5) * 8 + bit);
                }
            }
            break;
        }
        case 14: { // MINFO
            char *rmailbx = NULL, *emailbx = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &rmailbx) != 0 ||
                expand_wire_name(pkt, pkt_len, next, &next, &g_dag_arena, &emailbx) != 0 ||
                next > abs_offset + rdlen) {
                goto fallback;
            }
            printf("%s %s", rmailbx, emailbx);
            break;
        }
        case 63: { // ZONEMD
            if (rdlen < 6) goto fallback;
            uint32_t serial = ((uint32_t)pkt[abs_offset]<<24) | ((uint32_t)pkt[abs_offset+1]<<16) |
                              ((uint32_t)pkt[abs_offset+2]<<8)  | pkt[abs_offset+3];
            uint8_t scheme = pkt[abs_offset+4];
            uint8_t halg = pkt[abs_offset+5];
            if (dopt && dopt->multiline) {
                printf("%u %u %u (\n", serial, scheme, halg);
                print_multiline_hex(&pkt[abs_offset + 6], rdlen - 6, dopt->split_width);
            } else {
                printf("%u %u %u ", serial, scheme, halg);
                print_split_hex(&pkt[abs_offset + 6], rdlen - 6, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
            }
            break;
        }
        case 104: { // NID
            if (rdlen != 10) goto fallback;
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
            printf("%u %02x%02x:%02x%02x:%02x%02x:%02x%02x", pref,
                pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5],
                pkt[abs_offset+6], pkt[abs_offset+7], pkt[abs_offset+8], pkt[abs_offset+9]);
            break;
        }
        case 105: { // L32
            if (rdlen != 6) goto fallback;
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
            printf("%u %d.%d.%d.%d", pref,
                pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5]);
            break;
        }
        case 106: { // L64
            if (rdlen != 10) goto fallback;
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
            printf("%u %02x%02x:%02x%02x:%02x%02x:%02x%02x", pref,
                pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5],
                pkt[abs_offset+6], pkt[abs_offset+7], pkt[abs_offset+8], pkt[abs_offset+9]);
            break;
        }
        case 19: { // X25
            char psdn[256];
            const uint8_t *p = &pkt[abs_offset];
            const uint8_t *end = p + rdlen;
            p = read_char_string(p, end, psdn, sizeof(psdn));
            if (!p) goto fallback;
            printf("\"%s\"", psdn);
            break;
        }
        case 20: { // ISDN
            char isdn_addr[256], sub_addr[256];
            const uint8_t *p = &pkt[abs_offset];
            const uint8_t *end = p + rdlen;
            p = read_char_string(p, end, isdn_addr, sizeof(isdn_addr));
            if (!p) goto fallback;
            if (p < end) {
                p = read_char_string(p, end, sub_addr, sizeof(sub_addr));
                if (!p) goto fallback;
                printf("\"%s\" \"%s\"", isdn_addr, sub_addr);
            } else {
                printf("\"%s\"", isdn_addr);
            }
            break;
        }
        case 22: { // NSAP
            printf("0x");
            for (uint16_t i = 0; i < rdlen; i++) {
                printf("%02x", pkt[abs_offset + i]);
            }
            break;
        }
        case 27: { // GPOS
            char lon[256], lat[256], alt[256];
            const uint8_t *p = &pkt[abs_offset];
            const uint8_t *end = p + rdlen;
            p = read_char_string(p, end, lon, sizeof(lon));
            if (!p) goto fallback;
            p = read_char_string(p, end, lat, sizeof(lat));
            if (!p) goto fallback;
            p = read_char_string(p, end, alt, sizeof(alt));
            if (!p) goto fallback;
            printf("\"%s\" \"%s\" \"%s\"", lon, lat, alt);
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
    if (expand_wire_name(pkt, pkt_len, rdata - pkt, &next1, &g_dag_arena, &mname) != 0) return;
    if (expand_wire_name(pkt, pkt_len, next1, &next2, &g_dag_arena, &rname) != 0) return;
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
        if (strcasecmp(state->first_soa_name, name) == 0 &&
            norm_len == state->first_soa_norm_len &&
            memcmp(norm, state->first_soa_norm, norm_len) == 0) {
            state->axfr_complete = true;
        }
        state->soa_seen_count++;
    }
}

static uint32_t calc_wire_rr_hash(const char *name, uint16_t type, uint16_t klass, uint32_t ttl, const uint8_t *rdata, uint16_t rdlen) {
    uint32_t h = 2166136261u;
    for (int i = 0; name && name[i]; i++) {
        h ^= tolower((unsigned char)name[i]);
        h *= 16777619u;
    }
    h ^= (type >> 8); h *= 16777619u;
    h ^= (type & 0xFF); h *= 16777619u;
    h ^= (klass >> 8); h *= 16777619u;
    h ^= (klass & 0xFF); h *= 16777619u;

    if (g_want_allcompare) {
        h ^= (ttl >> 24) & 0xFF; h *= 16777619u;
        h ^= (ttl >> 16) & 0xFF; h *= 16777619u;
        h ^= (ttl >> 8)  & 0xFF; h *= 16777619u;
        h ^= (ttl & 0xFF);       h *= 16777619u;
    }

    for (uint16_t i = 0; i < rdlen; i++) {
        h ^= rdata[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t calc_record_rr_hash(const char *name, uint16_t type, uint16_t klass, uint32_t ttl, const char *rdata_text) {
    uint32_t h = 2166136261u;
    for (int i = 0; name && name[i]; i++) {
        h ^= tolower((unsigned char)name[i]);
        h *= 16777619u;
    }
    h ^= (type >> 8); h *= 16777619u;
    h ^= (type & 0xFF); h *= 16777619u;
    h ^= (klass >> 8); h *= 16777619u;
    h ^= (klass & 0xFF); h *= 16777619u;

    if (g_want_allcompare) {
        h ^= (ttl >> 24) & 0xFF; h *= 16777619u;
        h ^= (ttl >> 16) & 0xFF; h *= 16777619u;
        h ^= (ttl >> 8)  & 0xFF; h *= 16777619u;
        h ^= (ttl & 0xFF);       h *= 16777619u;
    }

    for (int i = 0; rdata_text && rdata_text[i]; i++) {
        h ^= tolower((unsigned char)rdata_text[i]);
        h *= 16777619u;
    }
    return h;
}

static void calculate_packet_hashes(const uint8_t *pkt, size_t pkt_len, uint32_t *wire_hash_out, uint32_t *record_hash_out) {
    uint32_t wire_hash = 0;
    uint32_t record_hash = 0;
    if (pkt_len >= 12) {
        uint16_t qdcount = (pkt[4] << 8) | pkt[5];
        uint16_t ancount = (pkt[6] << 8) | pkt[7];
        uint16_t nscount = (pkt[8] << 8) | pkt[9];
        uint16_t arcount = (pkt[10] << 8) | pkt[11];
        
        size_t offset = 12;
        for (int i = 0; i < qdcount; i++) {
            size_t next;
            if (skip_wire_name(pkt, pkt_len, offset, &next) != 0) break;
            offset = next + 4;
            if (offset > pkt_len) break;
        }
        
        int total_rr = ancount + nscount + arcount;
        for (int i = 0; i < total_rr; i++) {
            char *name = NULL;
            size_t next;
            if (expand_wire_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) break;
            if (next + 10 > pkt_len) break;
            uint16_t type = (pkt[next] << 8) | pkt[next+1];
            uint16_t klass = (pkt[next+2] << 8) | pkt[next+3];
            uint32_t ttl = ((uint32_t)pkt[next+4] << 24) | ((uint32_t)pkt[next+5] << 16) | ((uint32_t)pkt[next+6] << 8) | pkt[next+7];
            uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
            size_t rdata_start = next + 10;
            if (rdata_start + rdlen > pkt_len) break;
            
            if (type != 41) { // Skip OPT
                // 1. 生のワイヤフォーマット RDATA をハッシュ（圧縮の有無が反映される）
                wire_hash += calc_wire_rr_hash(name, type, klass, ttl, &pkt[rdata_start], rdlen);
                
                // 2. 展開された Canonical テキスト表現をハッシュ（出力レコード内容が反映される）
                char rdata_raw[2048];
                format_rdata_for_display(pkt, pkt_len, type, rdata_start, rdlen, rdata_raw, sizeof(rdata_raw), NULL);
                record_hash += calc_record_rr_hash(name, type, klass, ttl, rdata_raw);
            }
            offset = rdata_start + rdlen;
        }
    }
    if (wire_hash_out) *wire_hash_out = wire_hash;
    if (record_hash_out) *record_hash_out = record_hash;
}

static const char *format_class_name(uint16_t klass, char *buf, size_t buf_size) {
    switch (klass) {
        case 1: return "IN";
        case 3: return "CH";
        case 4: return "HS";
        case 254: return "NONE";
        case 255: return "ANY";
        default:
            snprintf(buf, buf_size, "CLASS%u", klass);
            return buf;
    }
}

static const char *idn_to_ascii(const char *name, bool *allocated) {
    if (allocated) *allocated = false;
#ifdef HAVE_LIBIDN2
    char *p = NULL;
    int rc = idn2_lookup_u8((const uint8_t *)name, (uint8_t **)&p, 0);
    if (rc != IDN2_OK) {
        rc = idn2_lookup_ul(name, &p, 0);
    }
    if (rc == IDN2_OK) {
        if (allocated) *allocated = true;
        return p;
    }
    fprintf(stderr, ";; IDN conversion failed: %s\n", idn2_strerror(rc));
#else
    static bool warned = false;
    bool looks_non_ascii = false;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p >= 0x80) { looks_non_ascii = true; break; }
    }
    if (looks_non_ascii && !warned) {
        fprintf(stderr, ";; WARNING: this build of dag was compiled without libidn2; "
                        "IDN conversion for '%s' was skipped and the name will be sent as-is\n", name);
        warned = true;
    }
#endif
    return name;
}

static const char *idn_to_unicode(const char *name, char *buf, size_t buf_size) {
#ifdef HAVE_LIBIDN2
    char *p;
    if (idn2_to_unicode_8z8z(name, &p, 0) == IDN2_OK) {
        snprintf(buf, buf_size, "%s", p);
        idn2_free(p);
        return buf;
    }
#endif
    snprintf(buf, buf_size, "%s", name);
    return buf;
}

static bool print_one_rr(const uint8_t *pkt, size_t pkt_len, size_t *offset, axfr_state_t *axfr_state, const display_opts_t *dopt) {
    char *name = NULL; size_t next;
    if (expand_wire_name(pkt, pkt_len, *offset, &next, &g_dag_arena, &name) != 0) return false;
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

    if (type == 6) {
        check_axfr_soa(axfr_state, pkt, pkt_len, name, &pkt[hdr], rdlen);
        if (axfr_state && axfr_state->is_axfr && axfr_state->soa_seen_count > 1 && dopt && dopt->onesoa) {
            *offset = rdata_start + rdlen;
            return true;
        }
    }

    char tname_buf[32];
    char cname_buf[16];
    char idn_buf[512];
    const char *display_name = (dopt && dopt->idnout) ? idn_to_unicode(name, idn_buf, sizeof(idn_buf)) : name;

    const char *tname;
    const char *cname;
    if (dopt && dopt->force_unknown_format) {
        snprintf(tname_buf, sizeof(tname_buf), "TYPE%u", type);
        tname = tname_buf;
        snprintf(cname_buf, sizeof(cname_buf), "CLASS%u", klass);
        cname = cname_buf;
    } else {
        tname = format_type_name(type, tname_buf, sizeof(tname_buf));
        cname = format_class_name(klass, cname_buf, sizeof(cname_buf));
    }

    char ttl_str[32];
    if (dopt && dopt->ttlunits) {
        format_ttl_units(ttl, ttl_str, sizeof(ttl_str));
    } else {
        snprintf(ttl_str, sizeof(ttl_str), "%u", ttl);
    }

    bool show_c = (dopt == NULL || dopt->show_class);
    bool show_t = (dopt == NULL || dopt->ttlid);

    if (show_t && show_c) {
        printf("%-24s %-6s %-4s %-8s ", display_name, ttl_str, cname, tname);
    } else if (show_t && !show_c) {
        printf("%-24s %-6s %-8s ", display_name, ttl_str, tname);
    } else if (!show_t && show_c) {
        printf("%-24s %-4s %-8s ", display_name, cname, tname);
    } else {
        printf("%-24s %-8s ", display_name, tname);
    }

    print_rdata(pkt, pkt_len, type, rdata_start, rdlen, dopt);
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
                } else if (code == 9) {
                    if (olen >= 4) {
                        uint32_t exp_sec = ((uint32_t)pkt[p]<<24)|((uint32_t)pkt[p+1]<<16)|((uint32_t)pkt[p+2]<<8)|pkt[p+3];
                        printf("; EXPIRE: %u (seconds)\n", exp_sec);
                    } else {
                        printf("; EXPIRE\n");
                    }
                } else if (code == 11) {
                    if (olen >= 2) {
                        uint16_t to = (pkt[p] << 8) | pkt[p+1];
                        printf("; KEEPALIVE: %u\n", to);
                    } else {
                        printf("; KEEPALIVE\n");
                    }
                } else if (code == 12) {
                    printf("; PADDING: %u octets\n", olen);
                } else if (code == 20 || code == 21) {
                    printf("; MQTYPE: ");
                    if (olen % 2 != 0) {
                        printf("(malformed, length %u is not even)\n", olen);
                    } else if (olen == 0) {
                        printf("(empty)\n");
                    } else {
                        for (uint16_t j = 0; j < olen; j += 2) {
                            uint16_t mq = (pkt[p + j] << 8) | pkt[p + j + 1];
                            char tbuf[16];
                            const char *mq_name = format_type_name(mq, tbuf, sizeof(tbuf));
                            if (j > 0) printf(", ");
                            printf("%s", mq_name);
                        }
                        printf("\n");
                    }
                } else if (code != 10 && code != 15) {
                    printf("; OPTION: %u", code);
                    if (olen > 0) {
                        printf(": ");
                        for (uint16_t j = 0; j < olen; j++) printf("%02x ", pkt[p + j]);
                    }
                    printf("\n");
                }
                p += olen;
            }
            return;
        }
        scan_offset = rdata_off + rdlen;
    }
}

// YAML single-quoted scalar内で安全な形にエスケープする（'を''に置換するのみ）
static void yaml_single_quote_escape(const char *src, char *dst, size_t dst_cap) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d + 1 < dst_cap; s++) {
        if (src[s] == '\'') {
            if (d + 2 >= dst_cap) break;
            dst[d++] = '\'';
            dst[d++] = '\'';
        } else {
            dst[d++] = src[s];
        }
    }
    dst[d] = '\0';
}

// YAML double-quoted scalar内で安全な形にエスケープする（" \ および制御文字を処理）
static void yaml_double_quote_escape(const char *src, char *dst, size_t dst_cap) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d + 1 < dst_cap; s++) {
        unsigned char c = (unsigned char)src[s];
        if (c == '"' || c == '\\') {
            if (d + 2 >= dst_cap) break;
            dst[d++] = '\\';
            dst[d++] = (char)c;
        } else if (c < 0x20) {
            if (d + 4 >= dst_cap) break;
            d += (size_t)snprintf(dst + d, dst_cap - d, "\\x%02x", c);
        } else {
            dst[d++] = (char)c;
        }
    }
    dst[d] = '\0';
}

static void print_response_yaml(const uint8_t *pkt, size_t pkt_len, const char *server, uint16_t port, bool is_tcp, const display_opts_t *dopt) {
    if (pkt_len < 12) return;
    uint16_t id = (pkt[0] << 8) | pkt[1];
    uint16_t flags = (pkt[2] << 8) | pkt[3];
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    uint16_t nscount = (pkt[8] << 8) | pkt[9];
    uint16_t arcount = (pkt[10] << 8) | pkt[11];

    bool qr = (flags >> 15) & 1;
    bool aa = (flags >> 10) & 1;
    bool tc = (flags >> 9) & 1;
    bool rd = (flags >> 8) & 1;
    bool ra = (flags >> 7) & 1;
    bool z  = (flags >> 6) & 1;
    bool ad = (flags >> 5) & 1;
    bool cd = (flags >> 4) & 1;
    uint8_t opcode = (flags >> 11) & 0xF;
    uint8_t rcode = flags & 0xF;

    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S.000Z", &tm_utc);

    const char *resp_type = "RESPONSE";
    if (qr) {
        if (aa) resp_type = "AUTH_RESPONSE";
        else resp_type = "RECURSIVE_RESPONSE";
    } else {
        resp_type = "QUERY";
    }

    const char *family_str = (g_last_socket_family == AF_INET6) ? "INET6" : "INET";
    const char *proto_str = is_tcp ? "TCP" : "UDP";

    printf("- type: MESSAGE\n");
    printf("  message:\n");
    printf("    type: %s\n", resp_type);
    printf("    query_time: !!timestamp %s\n", time_str);
    printf("    response_time: !!timestamp %s\n", time_str);
    printf("    message_size: %zub\n", pkt_len);
    printf("    socket_family: %s\n", family_str);
    printf("    socket_protocol: %s\n", proto_str);
    printf("    response_address: \"%s\"\n", server ? server : "127.0.0.1");
    printf("    response_port: %u\n", port ? port : 53);
    printf("    query_address: \"0.0.0.0\"\n");
    printf("    query_port: 0\n");
    printf("    response_message_data:\n");
    printf("      opcode: %s\n", opcode_name(opcode));
    printf("      status: %s\n", rcode_name(rcode));
    printf("      id: %u\n", id);

    printf("      flags:");
    if (qr) printf(" qr");
    if (aa) printf(" aa");
    if (tc) printf(" tc");
    if (rd) printf(" rd");
    if (ra) printf(" ra");
    if (z)  printf(" z");
    if (ad) printf(" ad");
    if (cd) printf(" cd");
    printf("\n");

    printf("      QUESTION: %u\n", qdcount);
    printf("      ANSWER: %u\n", ancount);
    printf("      AUTHORITY: %u\n", nscount);
    printf("      ADDITIONAL: %u\n", arcount);

    // Scan for OPT record in additional section
    size_t scan_off = 12;
    for (int i = 0; i < qdcount; i++) {
        size_t nxt;
        if (skip_wire_name(pkt, pkt_len, scan_off, &nxt) != 0) break;
        scan_off = nxt + 4;
        if (scan_off > pkt_len) break;
    }
    int non_qd_total = ancount + nscount + arcount;
    bool has_opt = false;
    uint8_t opt_ver = 0;
    uint16_t opt_udp = 0;
    uint16_t opt_ext_flags = 0;
    char client_cookie[64] = "";
    char server_cookie[128] = "";
    bool has_cookie = false;
    bool cookie_matches = true;

    for (int i = 0; i < non_qd_total; i++) {
        if (scan_off >= pkt_len) break;
        char *rname = NULL;
        size_t nxt;
        if (expand_wire_name(pkt, pkt_len, scan_off, &nxt, &g_dag_arena, &rname) != 0) break;
        if (nxt + 10 > pkt_len) break;
        uint16_t type = (pkt[nxt] << 8) | pkt[nxt+1];
        uint16_t klass = (pkt[nxt+2] << 8) | pkt[nxt+3];
        uint32_t ttl = ((uint32_t)pkt[nxt+4]<<24)|((uint32_t)pkt[nxt+5]<<16)|((uint32_t)pkt[nxt+6]<<8)|pkt[nxt+7];
        uint16_t rdlen = (pkt[nxt+8] << 8) | pkt[nxt+9];
        size_t rdata_start = nxt + 10;
        if (rdata_start + rdlen > pkt_len) break;

        if (i >= ancount + nscount && type == 41) { // OPT in additional
            has_opt = true;
            opt_udp = klass;
            opt_ver = (ttl >> 16) & 0xFF;
            opt_ext_flags = (ttl & 0xFFFF);
            size_t p = rdata_start, end = rdata_start + rdlen;
            while (p + 4 <= end) {
                uint16_t code = (pkt[p] << 8) | pkt[p+1];
                uint16_t olen = (pkt[p+2] << 8) | pkt[p+3];
                p += 4;
                if (p + olen > end) break;
                if (code == 10) { // COOKIE
                    has_cookie = true;
                    if (olen >= 8) {
                        for (int j = 0; j < 8; j++) snprintf(client_cookie + j * 2, 3, "%02x", pkt[p + j]);
                        if (dopt->has_expected_client_cookie) {
                            cookie_matches = (memcmp(dopt->expected_client_cookie, &pkt[p], 8) == 0);
                        }
                        if (olen > 8) {
                            for (int j = 8; j < olen && (j - 8) * 2 < (int)sizeof(server_cookie) - 3; j++) {
                                snprintf(server_cookie + (j - 8) * 2, 3, "%02x", pkt[p + j]);
                            }
                        }
                    }
                }
                p += olen;
            }
        }
        scan_off = rdata_start + rdlen;
    }

    if (has_opt) {
        printf("      OPT_PSEUDOSECTION:\n");
        printf("        EDNS:\n");
        printf("          version: %u\n", opt_ver);
        printf("          flags:");
        if (opt_ext_flags & 0x8000) printf(" do");
        if (opt_ext_flags & 0x0040) printf(" co");
        printf("\n");
        printf("          udp: %u\n", opt_udp);
        if (has_cookie) {
            printf("          COOKIE:\n");
            printf("            CLIENT: %s\n", client_cookie);
            if (server_cookie[0] != '\0') {
                printf("            SERVER: %s\n", server_cookie);
            }
            if (dopt->has_expected_client_cookie) {
                printf("            STATUS: %s\n", cookie_matches ? "good" : "bad");
            }
        }
        edns_info_t yaml_edns;
        if (parse_edns_opt(pkt, pkt_len, qdcount, ancount, nscount, arcount, &yaml_edns) == 0) {
            for (uint16_t i = 0; i < yaml_edns.ede_count; i++) {
                const char *msg = get_ede_error_string(yaml_edns.ede_list[i].code);
                printf("          EDE:\n");
                printf("            INFO-CODE: %u (%s)\n", yaml_edns.ede_list[i].code, msg);
                if (yaml_edns.ede_list[i].text[0]) {
                    char text_esc[512];
                    yaml_double_quote_escape(yaml_edns.ede_list[i].text, text_esc, sizeof(text_esc));
                    printf("            EXTRA-TEXT: \"%s\"\n", text_esc);
                }
            }
        }
    }

    size_t offset = 12;
    if (qdcount > 0) {
        printf("      QUESTION_SECTION:\n");
        for (int i = 0; i < qdcount; i++) {
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) break;
            if (next + 4 > pkt_len) break;
            uint16_t qtype = (pkt[next] << 8) | pkt[next+1];
            uint16_t qclass = (pkt[next+2] << 8) | pkt[next+3];
            char tname_buf[32];
            char cname_buf[16];
            char name_esc[512];
            yaml_single_quote_escape(name ? name : ".", name_esc, sizeof(name_esc));
            const char *tname = format_type_name(qtype, tname_buf, sizeof(tname_buf));
            const char *cname = format_class_name(qclass, cname_buf, sizeof(cname_buf));
            printf("        - '%s %s %s'\n", name_esc, cname, tname);
            offset = next + 4;
        }
    }

    struct { const char *section_yaml_name; int count; } sec_defs[] = {
        { "ANSWER_SECTION", ancount },
        { "AUTHORITY_SECTION", nscount },
        { "ADDITIONAL_SECTION", arcount }
    };

    for (int s = 0; s < 3; s++) {
        if (sec_defs[s].count <= 0) continue;
        size_t sec_offset = offset;
        int non_opt_count = 0;
        for (int i = 0; i < sec_defs[s].count; i++) {
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, sec_offset, &next, &g_dag_arena, &name) != 0) break;
            if (next + 10 > pkt_len) break;
            uint16_t type = (pkt[next] << 8) | pkt[next+1];
            uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
            if (s != 2 || type != 41) non_opt_count++;
            sec_offset = next + 10 + rdlen;
        }

        if (non_opt_count > 0) {
            printf("      %s:\n", sec_defs[s].section_yaml_name);
            for (int i = 0; i < sec_defs[s].count; i++) {
                char *name = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) break;
                if (next + 10 > pkt_len) break;
                uint16_t type = (pkt[next] << 8) | pkt[next+1];
                uint16_t klass = (pkt[next+2] << 8) | pkt[next+3];
                uint32_t ttl = ((uint32_t)pkt[next+4]<<24)|((uint32_t)pkt[next+5]<<16)|((uint32_t)pkt[next+6]<<8)|pkt[next+7];
                uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
                size_t rdata_start = next + 10;
                if (rdata_start + rdlen > pkt_len) break;

                if (type == 41 && s == 2) {
                    offset = rdata_start + rdlen;
                    continue;
                }

                char tname_buf[32];
                char cname_buf[16];
                char ttl_str[32];
                if (dopt && dopt->ttlunits) {
                    format_ttl_units(ttl, ttl_str, sizeof(ttl_str));
                } else {
                    snprintf(ttl_str, sizeof(ttl_str), "%u", ttl);
                }

                const char *tname = format_type_name(type, tname_buf, sizeof(tname_buf));
                const char *cname = format_class_name(klass, cname_buf, sizeof(cname_buf));

                char rdata_raw[2048];
                format_rdata_for_display(pkt, pkt_len, type, rdata_start, rdlen, rdata_raw, sizeof(rdata_raw), dopt);

                char name_esc[512];
                char rdata_esc[4096];
                yaml_single_quote_escape(name ? name : ".", name_esc, sizeof(name_esc));
                yaml_single_quote_escape(rdata_raw, rdata_esc, sizeof(rdata_esc));

                printf("        - '%s %s %s %s %s'\n", name_esc, ttl_str, cname, tname, rdata_esc);
                offset = rdata_start + rdlen;
            }
        } else {
            offset = sec_offset;
        }
    }
}

static void format_edns_flags(bool dnssec_ok, bool compact_answers_ok, char *buf, size_t buf_size) {
    buf[0] = '\0';
    if (dnssec_ok) strncat(buf, " do", buf_size - strlen(buf) - 1);
    if (compact_answers_ok) strncat(buf, " co", buf_size - strlen(buf) - 1);
}

static void print_sent_query(const uint8_t *pkt, size_t pkt_len, const query_opts_t *qo, const display_opts_t *dopt) {
    if (pkt_len < 12) return;
    if (dopt->yaml) {
        printf(";; Sending query in YAML format\n");
        print_response_yaml(pkt, pkt_len, "0.0.0.0", 0, qo ? qo->use_tcp : false, dopt);
        return;
    }
    uint16_t qid = (pkt[0] << 8) | pkt[1];
    uint8_t flags1 = pkt[2], flags2 = pkt[3];
    uint8_t opcode = (flags1 >> 3) & 0x0F;
    bool aa = flags1 & 0x04, tc = flags1 & 0x02, rd = flags1 & 0x01;
    bool ra = flags2 & 0x80, ad = flags2 & 0x20, cd = flags2 & 0x10;
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    uint16_t nscount = (pkt[8] << 8) | pkt[9];
    uint16_t arcount = (pkt[10] << 8) | pkt[11];

    printf(";; Sending:\n");
    printf(";; ->>HEADER<<- opcode: %s, status: NOERROR, id: %u\n", opcode_name(opcode), qid);
    printf(";; flags:%s%s%s%s%s%s; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n\n",
           aa ? " aa" : "", tc ? " tc" : "", rd ? " rd" : "",
           ra ? " ra" : "", ad ? " ad" : "", cd ? " cd" : "",
           qdcount, ancount, nscount, arcount);

    if (qo->want_opt) {
        char flags_buf[32];
        format_edns_flags(qo->dnssec_ok, qo->compact_answers_ok, flags_buf, sizeof(flags_buf));
        printf(";; OPT PSEUDOSECTION:\n");
        printf("; EDNS: version: %d, flags:%s; udp: %u\n", qo->edns_version, flags_buf, qo->udp_payload_size);
        if (qo->want_cookie) {
            printf("; COOKIE: ");
            for (int i = 0; i < 8; i++) printf("%02x", qo->client_cookie[i]);
            if (qo->server_cookie_len > 0) {
                for (size_t i = 0; i < qo->server_cookie_len; i++) printf("%02x", qo->server_cookie[i]);
            }
            printf("\n");
        }
        print_opt_extra_options(pkt, pkt_len, qdcount, ancount, nscount, arcount);
    }

    if (qdcount > 0) {
        size_t offset = 12;
        printf(";; QUESTION SECTION:\n");
        for (int i = 0; i < qdcount; i++) {
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) break;
            if (next + 4 > pkt_len) break;
            uint16_t qtype = (pkt[next] << 8) | pkt[next+1];
            uint16_t qclass = (pkt[next+2] << 8) | pkt[next+3];
            char qtname_buf[32];
            const char *qtname;
            char qcname_buf[16];
            const char *qcname;
            if (dopt->force_unknown_format) {
                snprintf(qtname_buf, sizeof(qtname_buf), "TYPE%u", qtype);
                qtname = qtname_buf;
                snprintf(qcname_buf, sizeof(qcname_buf), "CLASS%u", qclass);
                qcname = qcname_buf;
            } else {
                qtname = format_type_name(qtype, qtname_buf, sizeof(qtname_buf));
                qcname = format_class_name(qclass, qcname_buf, sizeof(qcname_buf));
            }
            char idn_buf[512];
            const char *display_name = dopt->idnout ? idn_to_unicode(name, idn_buf, sizeof(idn_buf)) : name;
            printf(";%-24s\t%-4s\t%s\n", display_name, qcname, qtname);
            offset = next + 4;
        }
        printf("\n");
    }

    printf(";; QUERY SIZE: %zu\n\n", pkt_len);
}

static bool check_packet_malformed(const uint8_t *pkt, size_t pkt_len, size_t *extra_bytes) {
    if (pkt_len < 12) return true;
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    uint16_t nscount = (pkt[8] << 8) | pkt[9];
    uint16_t arcount = (pkt[10] << 8) | pkt[11];

    size_t offset = 12;
    for (int i = 0; i < qdcount; i++) {
        size_t next;
        if (skip_wire_name(pkt, pkt_len, offset, &next) != 0 || next + 4 > pkt_len) {
            if (extra_bytes) *extra_bytes = (pkt_len > offset) ? (pkt_len - offset) : 0;
            return true;
        }
        offset = next + 4;
    }

    int total_rr = ancount + nscount + arcount;
    for (int i = 0; i < total_rr; i++) {
        size_t next;
        if (skip_wire_name(pkt, pkt_len, offset, &next) != 0 || next + 10 > pkt_len) {
            if (extra_bytes) *extra_bytes = (pkt_len > offset) ? (pkt_len - offset) : 0;
            return true;
        }
        uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
        if (next + 10 + rdlen > pkt_len) {
            if (extra_bytes) *extra_bytes = (pkt_len > (next + 10)) ? (pkt_len - (next + 10)) : 0;
            return true;
        }
        offset = next + 10 + rdlen;
    }

    if (offset < pkt_len) {
        if (extra_bytes) *extra_bytes = pkt_len - offset;
        return true;
    }
    return false;
}

static int count_non_opt_rrs(const uint8_t *pkt, size_t pkt_len, size_t offset, uint16_t arcount) {
    int count = 0;
    size_t cur = offset;
    for (uint16_t i = 0; i < arcount; i++) {
        size_t next;
        if (skip_wire_name(pkt, pkt_len, cur, &next) != 0) break;
        if (next + 10 > pkt_len) break;
        uint16_t rtype = (pkt[next] << 8) | pkt[next + 1];
        uint16_t rdlen = (pkt[next + 8] << 8) | pkt[next + 9];
        if (rtype != 41) { // Type 41 is OPT
            count++;
        }
        cur = next + 10 + rdlen;
        if (cur > pkt_len) break;
    }
    return count;
}

static void print_response(const uint8_t *pkt, size_t pkt_len, axfr_state_t *axfr_state, const display_opts_t *dopt) {
    size_t extra_bytes = 0;
    bool is_malformed = check_packet_malformed(pkt, pkt_len, &extra_bytes);
    if (is_malformed && dopt && dopt->show_comments) {
        printf(";; Warning: Message parser reports malformed message packet.\n\n");
    }

    if (pkt_len < 12) {
        if (!dopt || !dopt->besteffort) {
            printf(";; Got bad packet: unexpected end of input\n%zu bytes\n", pkt_len);
            hexdump(pkt, pkt_len);
        }
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

    edns_info_t edns;
    parse_edns_opt(pkt, pkt_len, qdcount, ancount, nscount, arcount, &edns);

    uint16_t full_rcode = edns.present ? (((uint16_t)edns.ext_rcode << 4) | rcode) : rcode;

    if (axfr_state && axfr_state->is_axfr && full_rcode == 0) {
        size_t offset = 12;
        for (int i = 0; i < qdcount; i++) {
            size_t next;
            if (skip_wire_name(pkt, pkt_len, offset, &next) != 0 || next + 4 > pkt_len) return;
            offset = next + 4;
        }
        for (int i = 0; i < ancount; i++) {
            if (!print_one_rr(pkt, pkt_len, &offset, axfr_state, dopt)) return;
        }
        for (int i = 0; i < nscount; i++) {
            if (!print_one_rr(pkt, pkt_len, &offset, axfr_state, dopt)) return;
        }
        for (int i = 0; i < arcount; i++) {
            if (!print_one_rr(pkt, pkt_len, &offset, axfr_state, dopt)) return;
        }
        return;
    }

    if (dopt->show_comments) {
        if (edns.present && edns.has_cookie && dopt->has_expected_client_cookie) {
            if (memcmp(dopt->expected_client_cookie, edns.client_cookie, 8) != 0) {
                printf(";; Warning: Client COOKIE mismatch\n\n");
            }
        }
        printf(";; Got answer:\n");
        printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n", opcode_name(opcode), rcode_name(full_rcode), qid);
        printf(";; flags:%s%s%s%s%s%s%s;%s QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
               qr ? " qr" : "", aa ? " aa" : "", tc ? " tc" : "", rd ? " rd" : "",
               ra ? " ra" : "", ad ? " ad" : "", cd ? " cd" : "",
               (flags2 & 0x40) ? " MBZ: 0x4;" : "",
               qdcount, ancount, nscount, arcount);
        if (!ra && rd) {
            printf(";; WARNING: recursion requested but not available\n");
        }
        if (is_malformed && extra_bytes > 0) {
            printf(";; WARNING: Message has %zu extra bytes at end\n", extra_bytes);
        }
    }

    if (edns.present && dopt->show_comments) {
        printf("\n;; OPT PSEUDOSECTION:\n");
        char flags_buf[32];
        format_edns_flags(edns.dnssec_ok, edns.compact_answers_ok, flags_buf, sizeof(flags_buf));
        printf("; EDNS: version: %d, flags:%s; udp: %d\n", edns.version, flags_buf, edns.udp_payload_size);
        if (edns.ext_rcode != 0) printf("; EXT RCODE: %d\n", edns.ext_rcode);
        if (edns.has_cookie) {
            printf("; COOKIE: ");
            for (int i = 0; i < 8; i++) printf("%02x", edns.client_cookie[i]);
            if (edns.server_cookie_len > 0) {
                for (uint16_t i = 0; i < edns.server_cookie_len; i++) printf("%02x", edns.server_cookie[i]);
            }
            if (dopt->has_expected_client_cookie) {
                if (memcmp(dopt->expected_client_cookie, edns.client_cookie, 8) == 0) {
                    printf(" (good)");
                } else {
                    printf(" (bad)");
                }
            } else if (edns.server_cookie_len > 0) {
                printf(" (good)");
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

    size_t offset = 12;
    if (qdcount > 0) {
        if (dopt->show_comments && dopt->show_question) printf("\n;; QUESTION SECTION:\n");
        if (!dopt->show_question) g_dag_suppress_stdout = true;
        for (int i = 0; i < qdcount; i++) {
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) {
                if (dopt->besteffort) { g_dag_suppress_stdout = false; return; }
                else { printf(";; Got bad packet: unexpected end of input\n%zu bytes\n", pkt_len); hexdump(pkt, pkt_len); return; }
            }
            if (next + 4 > pkt_len) {
                if (dopt->besteffort) { g_dag_suppress_stdout = false; return; }
                else { printf(";; Got bad packet: unexpected end of input\n%zu bytes\n", pkt_len); hexdump(pkt, pkt_len); return; }
            }
            uint16_t qtype = (pkt[next] << 8) | pkt[next+1];
            uint16_t qclass = (pkt[next+2] << 8) | pkt[next+3];
            char qtname_buf[32];
            const char *qtname;
            char qcname_buf[16];
            const char *qcname;
            if (dopt->force_unknown_format) {
                snprintf(qtname_buf, sizeof(qtname_buf), "TYPE%u", qtype);
                qtname = qtname_buf;
                snprintf(qcname_buf, sizeof(qcname_buf), "CLASS%u", qclass);
                qcname = qcname_buf;
            } else {
                qtname = format_type_name(qtype, qtname_buf, sizeof(qtname_buf));
                qcname = format_class_name(qclass, qcname_buf, sizeof(qcname_buf));
            }
            char idn_buf[512];
            const char *display_name = dopt->idnout ? idn_to_unicode(name, idn_buf, sizeof(idn_buf)) : name;
            printf(";%-24s %-4s %s\n", display_name, qcname, qtname);
            offset = next + 4;
        }
        g_dag_suppress_stdout = false;
    }

    if (ancount > 0) {
        if (dopt->show_comments && dopt->show_answer) printf("\n;; ANSWER SECTION:\n");
        if (!dopt->show_answer) g_dag_suppress_stdout = true;
        for (int i = 0; i < ancount; i++) {
            if (!print_one_rr(pkt, pkt_len, &offset, axfr_state, dopt)) {
                if (dopt->besteffort) {
                    g_dag_suppress_stdout = false;
                    return;
                } else {
                    printf(";; Got bad packet: unexpected end of input\n%zu bytes\n", pkt_len);
                    hexdump(pkt, pkt_len);
                    return;
                }
            }
        }
        g_dag_suppress_stdout = false;
    }
    if (nscount > 0) {
        if (dopt->show_comments && dopt->show_authority) printf("\n;; AUTHORITY SECTION:\n");
        if (!dopt->show_authority) g_dag_suppress_stdout = true;
        for (int i = 0; i < nscount; i++) {
            if (!print_one_rr(pkt, pkt_len, &offset, axfr_state, dopt)) {
                if (dopt->besteffort) {
                    g_dag_suppress_stdout = false;
                    return;
                } else {
                    printf(";; Got bad packet: unexpected end of input\n%zu bytes\n", pkt_len);
                    hexdump(pkt, pkt_len);
                    return;
                }
            }
        }
        g_dag_suppress_stdout = false;
    }
    if (arcount > 0) {
        int non_opt_cnt = count_non_opt_rrs(pkt, pkt_len, offset, arcount);
        if (non_opt_cnt > 0) {
            if (dopt->show_comments && dopt->show_additional) printf("\n;; ADDITIONAL SECTION:\n");
            if (!dopt->show_additional) g_dag_suppress_stdout = true;
            for (int i = 0; i < arcount; i++) {
                if (!print_one_rr(pkt, pkt_len, &offset, axfr_state, dopt)) {
                    if (dopt->besteffort) {
                        g_dag_suppress_stdout = false;
                        return;
                    } else {
                        printf(";; Got bad packet: unexpected end of input\n%zu bytes\n", pkt_len);
                        hexdump(pkt, pkt_len);
                        return;
                    }
                }
            }
            g_dag_suppress_stdout = false;
        }
    }
}

/* ========================================================================
 * 8. main
 * ==================================================================== */


static size_t parse_hex_string(const char *hex, uint8_t *out, size_t out_cap) {
    size_t r = hex_decode(hex, out, out_cap);
    if (r == (size_t)-1) return 0;
    return r;
}

// AAAAレコードのアドレスからRFC 6052 Well-Known PrefixまたはNSPを検出し、
// 見つかった場合はプレフィックス文字列とプレフィックス長を返す。見つからなければ false。
static bool detect_dns64_prefix_from_aaaa(const uint8_t *addr16, char *out_pstr, size_t out_cap, int *out_plen) {
    const uint8_t *b = addr16;
    int plen = 0;
    if (b[12] == 0xC0 && b[13] == 0x00 && b[14] == 0x00 && (b[15] == 0xAA || b[15] == 0xAB)) plen = 96;
    else if (b[8] == 0x00 && b[9] == 0xC0 && b[10] == 0x00 && b[11] == 0x00 && (b[12] == 0xAA || b[12] == 0xAB)) plen = 64;
    else if (b[8] == 0x00 && b[7] == 0xC0 && b[9] == 0x00 && b[10] == 0x00 && (b[11] == 0xAA || b[11] == 0xAB)) plen = 56;
    else if (b[8] == 0x00 && b[6] == 0xC0 && b[7] == 0x00 && b[9] == 0x00 && (b[10] == 0xAA || b[10] == 0xAB)) plen = 48;
    else if (b[8] == 0x00 && b[5] == 0xC0 && b[6] == 0x00 && b[7] == 0x00 && (b[9] == 0xAA || b[9] == 0xAB)) plen = 40;
    else if (b[4] == 0xC0 && b[5] == 0x00 && b[6] == 0x00 && (b[7] == 0xAA || b[7] == 0xAB)) plen = 32;
    if (plen == 0) return false;

    struct in6_addr pref_addr;
    memcpy(&pref_addr, addr16, 16);
    for (int bit = plen; bit < 128; bit++) {
        pref_addr.s6_addr[bit / 8] &= ~(1 << (7 - (bit % 8)));
    }
    inet_ntop(AF_INET6, &pref_addr, out_pstr, out_cap);
    *out_plen = plen;
    return true;
}

static void print_response_yaml_dns64(const uint8_t *pkt, size_t pkt_len, const char *server, uint16_t port, bool is_tcp) {
    if (pkt_len < 12) return;
    uint16_t id = (pkt[0] << 8) | pkt[1];
    uint16_t flags = (pkt[2] << 8) | pkt[3];
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    uint16_t nscount = (pkt[8] << 8) | pkt[9];
    uint16_t arcount = (pkt[10] << 8) | pkt[11];

    bool qr = (flags >> 15) & 1;
    bool aa = (flags >> 10) & 1;
    bool tc = (flags >> 9) & 1;
    bool rd = (flags >> 8) & 1;
    bool ra = (flags >> 7) & 1;
    bool z  = (flags >> 6) & 1;
    bool ad = (flags >> 5) & 1;
    bool cd = (flags >> 4) & 1;
    uint8_t opcode = (flags >> 11) & 0xF;
    uint8_t rcode = flags & 0xF;

    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S.000Z", &tm_utc);

    const char *resp_type = "RESPONSE";
    if (qr) {
        if (aa) resp_type = "AUTH_RESPONSE";
        else resp_type = "RECURSIVE_RESPONSE";
    } else {
        resp_type = "QUERY";
    }

    const char *family_str = (g_last_socket_family == AF_INET6) ? "INET6" : "INET";
    const char *proto_str = is_tcp ? "TCP" : "UDP";

    printf("- type: MESSAGE\n");
    printf("  message:\n");
    printf("    type: %s\n", resp_type);
    printf("    query_time: !!timestamp %s\n", time_str);
    printf("    response_time: !!timestamp %s\n", time_str);
    printf("    message_size: %zub\n", pkt_len);
    printf("    socket_family: %s\n", family_str);
    printf("    socket_protocol: %s\n", proto_str);
    printf("    response_address: \"%s\"\n", server ? server : "127.0.0.1");
    printf("    response_port: %u\n", port ? port : 53);
    printf("    query_address: \"0.0.0.0\"\n");
    printf("    query_port: 0\n");
    printf("    response_message_data:\n");
    printf("      opcode: %s\n", opcode_name(opcode));
    printf("      status: %s\n", rcode_name(rcode));
    printf("      id: %u\n", id);

    printf("      flags:");
    if (qr) printf(" qr");
    if (aa) printf(" aa");
    if (tc) printf(" tc");
    if (rd) printf(" rd");
    if (ra) printf(" ra");
    if (z)  printf(" z");
    if (ad) printf(" ad");
    if (cd) printf(" cd");
    printf("\n");

    printf("      QUESTION: %u\n", qdcount);
    printf("      ANSWER: %u\n", ancount);
    printf("      AUTHORITY: %u\n", nscount);
    printf("      ADDITIONAL: %u\n", arcount);
}

static void run_dns64prefix_check(const char *server, int port, const query_opts_t *qo, bool use_tcp,
                                   bool no_hexdump_query, bool no_hexdump_response,
                                   const display_opts_t *dopt) {
    (void)no_hexdump_query; (void)no_hexdump_response;
    uint8_t qbuf[512];
    query_opts_t q = *qo;
    q.check_dns64prefix = false;
    size_t qlen = build_query_packet(qbuf, sizeof(qbuf), "ipv4only.arpa", 28 /* AAAA */, &q);
    uint8_t resp[65535];
    ssize_t n = do_dns_exchange_auto(server, port, &q, qbuf, qlen, resp, sizeof(resp), q.timeout_sec, use_tcp);
    if (n < 12) {
        return;
    }

    int qdcount = (resp[4] << 8) | resp[5];
    int ancount = (resp[6] << 8) | resp[7];
    size_t offset = 12;
    for (int i = 0; i < qdcount; i++) {
        char *dummy;
        if (expand_wire_name(resp, (size_t)n, offset, &offset, &g_dag_arena, &dummy) != 0) return;
        offset += 4;
    }

    if (dopt->yaml) {
        print_response_yaml_dns64(resp, (size_t)n, server, port, use_tcp);
    }

    for (int i = 0; i < ancount; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, (size_t)n, &offset, &g_dag_arena, &rec, &type) != 0) break;
        if (type == 28 && rec.rdata_count > 0) {
            struct in6_addr in6;
            if (inet_pton(AF_INET6, rec.rdata[0], &in6) == 1) {
                char pstr[INET6_ADDRSTRLEN];
                int plen = 0;
                if (detect_dns64_prefix_from_aaaa(in6.s6_addr, pstr, sizeof(pstr), &plen)) {
                    if (dopt->yaml) {
                        printf("    %s/%d\n", pstr, plen);
                    } else if (dopt->short_mode) {
                        printf("%s/%d\n", pstr, plen);
                    } else {
                        printf("\n%s/%d\n", pstr, plen);
                    }
                    break;
                }
            }
        }
    }
}

static int run_test(const char *test_name, const char *qname, const char *qtype_s, const char *server, int port,
                    bool use_tcp, bool norecurse,
                    bool adflag, bool cdflag, bool aaflag, bool tcflag, bool zflag,
                    bool no_hexdump_query, bool no_hexdump_response,
                    query_opts_t *qo, const char *hex_payload, const display_opts_t *dopt) {
    zone_arena_destroy(&g_dag_arena);
    zone_arena_init(&g_dag_arena);

    if (test_name) {
        printf("=========================================================\n");
        printf(">>> TEST: %s\n", test_name);
        printf("=========================================================\n");
    }

    uint16_t qtype = 0;
    display_opts_t effective_dopt = *dopt;
    if (qo->want_cookie) {
        effective_dopt.has_expected_client_cookie = true;
        memcpy(effective_dopt.expected_client_cookie, qo->client_cookie, 8);
    }
    if (qo->check_dns64prefix) {
        effective_dopt.check_dns64prefix = true;
    }
    dopt = &effective_dopt;
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
        if (pkt_len == 0 || pkt_len > sizeof(pkt)) {
            fprintf(stderr, "Error: Invalid, empty, or oversized hex payload (max %zu bytes)\n", sizeof(pkt));
            return 1;
        }
    } else {
        pkt_len = build_query_packet(pkt, sizeof(pkt), qname, qtype, qo);
        if (pkt_len == 0) return 1;
    }

    uint8_t request_mac[64];
    size_t request_mac_len = 0;

    if (qo->want_tsig) {
        qo->tsig_key.fuzztime = qo->fuzztime;
        if (tsig_sign_packet(pkt, &pkt_len, sizeof(pkt), &qo->tsig_key, 0, request_mac, &request_mac_len, NULL, 0, false) != 0) {
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

    long short_len = 3;
    if (has_break(BRK_TOO_SHORT, &short_len, NULL)) {
        if (short_len < 0) short_len = 3;
        if (pkt_len > (size_t)short_len) pkt_len = (size_t)short_len;
    }

    server_result_t *sres = NULL;

    bool retry_tcp = false;
    do {
        retry_tcp = false;
        struct timespec start_ts;
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        
        axfr_state_t axfr_state = {0};
        axfr_state.is_axfr = (qtype == 252 || qtype == 251);


        if (!dopt->short_mode && !dopt->yaml) {
            if (dopt->show_cmd) {
                const char *disp_qname = (qo && qo->orig_qname) ? qo->orig_qname : qname;
                const char *disp_qtype = (qo && qo->orig_qtype_s) ? qo->orig_qtype_s : (qtype_s ? qtype_s : "");
                if (qo && qo->server_explicit) {
                    int found_cnt = get_server_addr_count(server, port, qo ? qo->pref_family : AF_UNSPEC);
                    if (disp_qtype && disp_qtype[0]) {
                        printf("; <<>> dag <<>> %s %s @%s%s\n", disp_qname, disp_qtype, server, use_tcp ? " (tcp)" : "");
                    } else {
                        printf("; <<>> dag <<>> %s @%s%s\n", disp_qname, server, use_tcp ? " (tcp)" : "");
                    }
                    printf("; (%d server%s found)\n", found_cnt, found_cnt == 1 ? "" : "s");
                } else {
                    if (disp_qtype && disp_qtype[0]) {
                        printf("; <<>> dag <<>> %s %s%s\n", disp_qname, disp_qtype, use_tcp ? " (tcp)" : "");
                    } else {
                        printf("; <<>> dag <<>> %s%s\n", disp_qname, use_tcp ? " (tcp)" : "");
                    }
                }
                printf(";; global options: +cmd\n");
            }
            if (!no_hexdump_query) {
                printf("Query (%zu bytes):\n", pkt_len);
                hexdump(pkt, pkt_len);
                printf("\n");
            }
        }

        if (dopt->show_query_message) {
            print_sent_query(pkt, pkt_len, qo, dopt);
        }

        static uint8_t resp[65535];
        ssize_t n = -1;
        int attempts = 0;
        int max_tries = (qo->tries < 1) ? 1 : qo->tries;
        
        int tcp_sock = -1;
        while (attempts < max_tries) {
            attempts++;
            if (qo->use_doh) {
                n = do_doh_exchange(server, port, qo, pkt, pkt_len, resp, sizeof(resp), qo->timeout_sec);
                if (n > 0) break;
            } else if (qo->use_tls) {
                n = do_tls_exchange(server, port, qo, pkt, pkt_len, resp, sizeof(resp), qo->timeout_sec);
                if (n > 0) break;
            } else if (use_tcp) {
                if (qo->keep_tcp_open && !axfr_state.is_axfr) {
                    n = do_tcp_exchange(server, port, qo, pkt, pkt_len, resp, sizeof(resp), qo->timeout_sec);
                    if (n > 0) break;
                } else {
                    tcp_sock = do_tcp_send_request(server, port, qo, pkt, pkt_len, qo->timeout_sec);
                    if (tcp_sock >= 0) {
                        n = do_tcp_recv_response(tcp_sock, resp, sizeof(resp));
                        if (n > 0) {
                            break; // connected and got first message
                        }
                        close(tcp_sock);
                        tcp_sock = -1;
                        n = -1;
                    }
                }
            } else {
                n = do_udp_exchange(server, port, qo, pkt, pkt_len, resp, sizeof(resp), qo->timeout_sec);
                if (n >= 0) break;
            }
            if (attempts < max_tries) {
                if (!dopt->short_mode) printf(";; connection timed out; retrying...\n");
            }
        }

        if (n <= 0) {
            printf(";; no servers could be reached\n");
            return 9;
        }

        if (n >= 12 && qo->retry_on_badcookie) {
            edns_info_t bc_edns;
            uint16_t b_qd = (resp[4] << 8) | resp[5];
            uint16_t b_an = (resp[6] << 8) | resp[7];
            uint16_t b_ns = (resp[8] << 8) | resp[9];
            uint16_t b_ar = (resp[10] << 8) | resp[11];
            parse_edns_opt(resp, n, b_qd, b_an, b_ns, b_ar, &bc_edns);
            uint16_t b_rcode = bc_edns.present ? (((uint16_t)bc_edns.ext_rcode << 4) | (resp[3] & 0x0F)) : (resp[3] & 0x0F);
            if (b_rcode == 23 && bc_edns.has_cookie && bc_edns.server_cookie_len > 0) {
                if (dopt->show_badcookie_msg) {
                    if (!dopt->short_mode) {
                        print_response(resp, (size_t)n, &axfr_state, dopt);
                        printf("\n");
                    }
                }
                printf(";; BADCOOKIE, retrying.\n");
                qo->want_cookie = true;
                qo->server_cookie_len = bc_edns.server_cookie_len;
                memcpy(qo->server_cookie, bc_edns.server_cookie, bc_edns.server_cookie_len);
                pkt_len = build_query_packet(pkt, sizeof(pkt), qname, qtype, qo);
                if (qo->want_tsig) {
                    qo->tsig_key.fuzztime = qo->fuzztime;
                    if (tsig_sign_packet(pkt, &pkt_len, sizeof(pkt), &qo->tsig_key, 0, request_mac, &request_mac_len, NULL, 0, false) != 0) {
                        fprintf(stderr, "Error: tsig_sign_packet failed on badcookie retry\n");
                        return 1;
                    }
                }
                n = do_dns_exchange_by_transport(server, port, qo, use_tcp, pkt, pkt_len, resp, sizeof(resp), qo->timeout_sec);
            }
        }

        if (n >= 12 && qo->edns_negotiation && qo->want_opt) {
            uint16_t bv_qd = (resp[4] << 8) | resp[5];
            uint16_t bv_an = (resp[6] << 8) | resp[7];
            uint16_t bv_ns = (resp[8] << 8) | resp[9];
            uint16_t bv_ar = (resp[10] << 8) | resp[11];
            edns_info_t bv_edns;
            parse_edns_opt(resp, n, bv_qd, bv_an, bv_ns, bv_ar, &bv_edns);
            uint16_t bv_rcode = bv_edns.present
                ? (((uint16_t)bv_edns.ext_rcode << 4) | (resp[3] & 0x0F))
                : (resp[3] & 0x0F);
            if (bv_rcode == 16 && qo->edns_version > 0) {
                if (dopt->show_badvers_msg && !dopt->short_mode) {
                    print_response(resp, (size_t)n, &axfr_state, dopt);
                    printf("\n");
                }
                printf(";; BADVERS, retrying with EDNS version %d.\n", qo->edns_version - 1);
                qo->edns_version -= 1;
                pkt_len = build_query_packet(pkt, sizeof(pkt), qname, qtype, qo);
                if (qo->want_tsig) {
                    qo->tsig_key.fuzztime = qo->fuzztime;
                    if (tsig_sign_packet(pkt, &pkt_len, sizeof(pkt), &qo->tsig_key, 0, request_mac, &request_mac_len, NULL, 0, false) != 0) {
                        fprintf(stderr, "Error: tsig_sign_packet failed on badvers retry\n");
                        return 1;
                    }
                }
                n = do_dns_exchange_by_transport(server, port, qo, use_tcp, pkt, pkt_len, resp, sizeof(resp), qo->timeout_sec);
            }
        }

        struct timespec end_ts;
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        long long elapsed_usec = (end_ts.tv_sec - start_ts.tv_sec) * 1000000LL + (end_ts.tv_nsec - start_ts.tv_nsec) / 1000LL;
        long elapsed_ms = (long)(elapsed_usec / 1000LL);

        bool is_truncated = (!use_tcp && n >= 4 && (resp[2] & 0x02) != 0);

        int msg_index = 1;
        int total_records = 0;
        size_t total_bytes = 0;
        bool had_tsig_fail = false;
        bool last_msg_had_tsig = false;
        int unsigned_msg_count = 0;
        uint8_t unsigned_accum[262144];
        size_t unsigned_accum_len = 0;
        
        int start_index = g_server_count;
        sres = alloc_result_row();

        do {
            if (n >= 2) {
                uint16_t resp_id = (resp[0] << 8) | resp[1];
                uint16_t expected_id = (qo->qid_override >= 0) ? (uint16_t)(qo->qid_override & 0xFFFF) : qo->query_id;
                if (resp_id != expected_id) {
                    fprintf(stderr, ";; Warning: ID mismatch: expected %u, got %u\n", expected_id, resp_id);
                }
            }
            reset_dag_arena();
            total_bytes += (size_t)n;
            if (n >= 12) {
                total_records += (resp[6] << 8) | resp[7];
            }
            if (sres && n >= 12) {
                sres->rcode = resp[3] & 0x0F;
                sres->qdcount = (resp[4] << 8) | resp[5];
                sres->ancount = (resp[6] << 8) | resp[7];
                sres->nscount = (resp[8] << 8) | resp[9];
                sres->arcount = (resp[10] << 8) | resp[11];
                sres->qr = resp[2] & 0x80; sres->aa = resp[2] & 0x04; sres->tc = resp[2] & 0x02; sres->rd = resp[2] & 0x01;
                sres->ra = resp[3] & 0x80; sres->ad = resp[3] & 0x20; sres->cd = resp[3] & 0x10;
                sres->msg_index = msg_index;
                sres->msg_total = 0;

                size_t to_copy = (size_t)n < sizeof(sres->resp_buf) ? (size_t)n : sizeof(sres->resp_buf);
                memcpy(sres->resp_buf, resp, to_copy);
                sres->resp_len = (ssize_t)to_copy;
                calculate_packet_hashes(resp, n, &sres->semantic_hash, &sres->record_hash);
                snprintf(sres->server_ip, sizeof(sres->server_ip), "%s", server);
                snprintf(sres->proto, sizeof(sres->proto), "%s", use_tcp ? "TCP" : "UDP");
            }
            
            if (qo->want_tsig) {
                uint8_t resp_mac[64];
                size_t resp_mac_len = 0;
                int err = tsig_verify_packet(resp, (size_t)n, &qo->tsig_key, request_mac, request_mac_len,
                                             unsigned_accum, unsigned_accum_len, (msg_index > 1),
                                             resp_mac, &resp_mac_len);
                if (err == 0) {
                    // Update prior_mac for subsequent AXFR messages
                    if (resp_mac_len > 0 && resp_mac_len <= sizeof(request_mac)) {
                        memcpy(request_mac, resp_mac, resp_mac_len);
                        request_mac_len = resp_mac_len;
                    }
                    unsigned_accum_len = 0;
                    unsigned_msg_count = 0;
                    last_msg_had_tsig = true;
                } else if (err == -1 && axfr_state.is_axfr && msg_index > 1) {
                    // RFC 2845 §4.4 / RFC 8945 §5.4: Intermediate AXFR messages MAY omit TSIG
                    last_msg_had_tsig = false;
                    unsigned_msg_count++;
                    if (unsigned_msg_count > 99) {
                        had_tsig_fail = true;
                        fprintf(stderr, ";; WARNING: too many consecutive unsigned intermediate messages (%d > 99, RFC 8945 violation)\n", unsigned_msg_count);
                    }
                    if (unsigned_accum_len + (size_t)n <= sizeof(unsigned_accum)) {
                        memcpy(unsigned_accum + unsigned_accum_len, resp, (size_t)n);
                        unsigned_accum_len += (size_t)n;
                    } else {
                        had_tsig_fail = true;
                        fprintf(stderr, ";; WARNING: unsigned intermediate message buffer overflow, cannot verify final TSIG\n");
                    }
                } else {
                    had_tsig_fail = true;
                    last_msg_had_tsig = false;
                    if (err == -1) {
                        fprintf(stderr, ";; Couldn't verify signature: expected a TSIG or SIG(0)\n");
                    } else if (err == 16) {
                        fprintf(stderr, ";; Couldn't verify signature: tsig verify failure (BADSIG)\n");
                    } else if (err == 17) {
                        fprintf(stderr, ";; Couldn't verify signature: tsig verify failure (BADKEY)\n");
                    } else if (err == 18) {
                        fprintf(stderr, ";; Couldn't verify signature: tsig verify failure (BADTIME)\n");
                    } else if (err == 21) {
                        fprintf(stderr, ";; Couldn't verify signature: tsig verify failure (BADALG)\n");
                    } else {
                        fprintf(stderr, ";; Couldn't verify signature: tsig verify failure (%d)\n", err);
                    }
                }
            }

            if (!dopt->short_mode) {
                if (!dopt->yaml && !no_hexdump_response && dopt->show_comments) {
                    if (use_tcp) {
                        printf("Response message %d (%zd bytes, TCP):\n", msg_index, n);
                    } else {
                        printf("Response (%zd bytes, UDP):\n", n);
                    }
                    hexdump(resp, (size_t)n);
                    printf("\n");
                }
                if (dopt->yaml) {
                    print_response_yaml(resp, (size_t)n, server, port, use_tcp, dopt);
                } else {
                    print_response(resp, (size_t)n, &axfr_state, dopt);
                }
            } else {
                uint16_t ancount = (resp[6] << 8) | resp[7];
                size_t off = 12;
                uint16_t qdcount = (resp[4] << 8) | resp[5];
                for (int k=0; k<qdcount; k++) {
                    size_t nxt; if(skip_wire_name(resp, n, off, &nxt)==0) off = nxt + 4;
                }
                for (int k=0; k<ancount; k++) {
                    char *name = NULL;
                    size_t nxt; if(expand_wire_name(resp, n, off, &nxt, &g_dag_arena, &name)==0) {
                        uint16_t type = (resp[nxt]<<8)|resp[nxt+1];
                        uint16_t rdlen = (resp[nxt+8]<<8)|resp[nxt+9];
                        if (type == 6) {
                            check_axfr_soa(&axfr_state, resp, n, name, &resp[nxt], rdlen);
                        }
                        print_rdata(resp, n, type, nxt+10, rdlen, dopt);
                        if (dopt->identify) {
                            printf(" from server %s in %ld ms.", server, elapsed_ms);
                        }
                        printf("\n");
                        off = nxt+10+rdlen;
                    } else break;
                }
            }


            bool has_more = axfr_state.is_axfr && !axfr_state.axfr_complete && use_tcp && tcp_sock >= 0;

            if (has_more) {
                if (sres) g_server_count++;
                n = do_tcp_recv_response(tcp_sock, resp, sizeof(resp));
                if (n <= 0) {
                    sres = NULL;
                    break;
                }
                msg_index++;
                sres = alloc_result_row();
            } else {
                break;
            }
        } while (true);

        if (qo->want_tsig && axfr_state.is_axfr && axfr_state.axfr_complete) {
            if (!last_msg_had_tsig) {
                had_tsig_fail = true;
                fprintf(stderr, ";; WARNING: final AXFR message MUST contain TSIG but none was found (RFC 8945 §5.4 violation)\n");
            }
        }

        if (sres) g_server_count++;

        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        elapsed_usec = (end_ts.tv_sec - start_ts.tv_sec) * 1000000LL + (end_ts.tv_nsec - start_ts.tv_nsec) / 1000LL;
        elapsed_ms = (long)(elapsed_usec / 1000LL);

        int end_index = g_server_count;
        for (int idx = start_index; idx < end_index; idx++) {
            g_results[idx].msg_total = end_index - start_index;
            g_results[idx].elapsed_ms = elapsed_ms;
        }

        time_t now = time(NULL);
        char time_buf[64];
#ifdef _WIN32
        strftime(time_buf, sizeof(time_buf), "%a %b %d %H:%M:%S %Z %Y", localtime(&now));
#else
        strftime(time_buf, sizeof(time_buf), "%a %b %e %H:%M:%S %Z %Y", localtime(&now));
#endif

        const char *proto_name = "UDP";
        if (qo->use_doh) {
            proto_name = (qo->doh_method == DOH_GET) ? (qo->doh_tls ? "HTTPS-GET" : "HTTP-GET") : (qo->doh_tls ? "HTTPS" : "HTTP");
        } else if (qo->use_tls) {
            proto_name = "TLS";
        } else if (use_tcp) {
            proto_name = "TCP";
        }

        if (!dopt->short_mode && !dopt->yaml && dopt->show_stats) {
            if (dopt->time_unit_usec) {
                printf("\n;; Query time: %lld usec\n", elapsed_usec);
            } else {
                printf("\n;; Query time: %ld msec\n", elapsed_ms);
            }
            printf(";; SERVER: %s#%d(%s) (%s)\n", server, port, server, proto_name);
            printf(";; WHEN: %s\n", time_buf);
            if (qtype == 252 || qtype == 251) {
                printf(";; XFR size: %d records (messages %d, bytes %zu)\n", total_records, msg_index, total_bytes);
            } else {
                printf(";; MSG SIZE  rcvd: %zu\n", total_bytes);
            }
            if (qo->want_tsig && had_tsig_fail) {
                printf(";; WARNING -- Some TSIG could not be validated\n");
            }
        }
        if (tcp_sock >= 0) close(tcp_sock);

        if (is_truncated) {
            if (qo->ignore_tc) {
                fprintf(stderr, "\n;; Truncated response received, but +ignore specified; not retrying in TCP mode.\n");
            } else {
                fprintf(stderr, ";; Truncated, retrying in TCP mode.\n");
                use_tcp = true;
                retry_tcp = true;
            }
        }
    } while (retry_tcp);

    if (qo->check_dns64prefix) {
        run_dns64prefix_check(server, port, qo, use_tcp, no_hexdump_query, no_hexdump_response, dopt);
    }

    return 0;
}

static void print_multi_server_summary(bool use_ldnsz) {
    if (g_server_count == 0) return;
    
    if (g_server_count > 1) {

    int max_server_len = 18;
    for (int i = 0; i < g_server_count; i++) {
        int len = strlen(g_results[i].server_ip);
        if (g_results[i].msg_total > 1) {
            char tmp[128];
            snprintf(tmp, sizeof(tmp), "%s (msg %d/%d)", g_results[i].server_ip, g_results[i].msg_index, g_results[i].msg_total);
            len = strlen(tmp);
        }
        if (len > max_server_len) {
            max_server_len = len;
        }
    }

    printf("\n;; === MULTI-SERVER COMPARISON SUMMARY ===\n");
    
    // 2. ヘッダの出力 ( %-*s を使って動的幅を指定 )
    printf("%-*s | %-5s | %-7s | %3s | %3s | %3s | %-13s | %-6s | %s\n", 
           max_server_len, "SERVER", "PROTO", "RCODE", "ANS", "AUT", "ADD", 
           g_want_allcompare ? "SEM_HASH(+TTL)" : "SEM_HASH", "TIME", "MATCH STATUS");
    
    // 3. 区切り線の出力 ( max_server_len の分だけ '-' を出力 )
    for (int i = 0; i < max_server_len; i++) printf("-");
    printf("-+-------+---------+-----+-----+-----+---------------+--------+------------------------\n");

    server_result_t *base = &g_results[0];
    for (int i = 0; i < g_server_count; i++) {
        if (!g_results[i].tc) {
            base = &g_results[i];
            break;
        }
    }

    for (int i = 0; i < g_server_count; i++) {
        server_result_t *r = &g_results[i];
        
        const char *status_str = "";
        if (r == base) {
            status_str = "MATCH_BASE";
        } else {
            // クエリID (2バイト) を除外してバイナリ比較
            if (r->resp_len == base->resp_len && r->resp_len >= 2 && 
                memcmp(r->resp_buf + 2, base->resp_buf + 2, r->resp_len - 2) == 0) {
                status_str = "MATCH_EXACT";
            } else if (r->rcode == base->rcode && (r->semantic_hash == base->semantic_hash || r->record_hash == base->record_hash)) {
                status_str = "MATCH_SEMANTIC";
            } else {
                status_str = "MATCH_DIFF";
            }
        }

        // 4. データ行の出力 ( %-*s を使って動的幅を指定 )
        char label[128];
        if (r->msg_total > 1) {
            snprintf(label, sizeof(label), "%s (msg %d/%d)", r->server_ip, r->msg_index, r->msg_total);
        } else {
            snprintf(label, sizeof(label), "%s", r->server_ip);
        }
        printf("%-*s | %-5s | %-7s | %3d | %3d | %3d | 0x%08X | %4ldms | %s\n",
               max_server_len, label, r->proto, rcode_name(r->rcode),
               r->ancount, r->nscount, r->arcount,
               r->semantic_hash, r->elapsed_ms, status_str);
    }
    
    // 5. フッター区切り線の出力
    for (int i = 0; i < max_server_len; i++) printf("-");
    printf("-+-------+---------+-----+-----+-----+------------+--------+------------------------\n");
    }
    
    // URL出力 (+ldnsz が指定された場合のみ)
    if (use_ldnsz) {
        if (g_server_count > 1) {
            printf(";; Compare details in browser:\n;; https://ldns.jp/diff/#c=");
            for (int i = 0; i < g_server_count; i++) {
                server_result_t *r = &g_results[i];
                printf("%s%s", (i > 0) ? "," : "", r->server_ip);
                if (r->msg_total > 1) printf("/%d-%d", r->msg_index, r->msg_total);
                printf("|%s|%ld:", r->proto, r->elapsed_ms);
                print_ldnsz_payload(r->resp_buf, r->resp_len);
            }
        } else {
            printf(";; View details in browser:\n;; https://ldns.jp/?dnsz=");
            print_ldnsz_payload(g_results[0].resp_buf, g_results[0].resp_len);
        }
        printf("\n");
    }
}


static void usage(const char *prog) {
    (void)prog;
    printf(
        "Usage:  dag [@server] [-p port] [domain] [type] [options]\n"
        "\n"
        "Query & Target Arguments:\n"
        "  domain                       Domain name to query (default: '.')\n"
        "  type                         Record type (default: 'NS' for root '.', 'A' otherwise)\n"
        "                               (Use IXFR=serial for incremental zone transfer)\n"
        "  @server[:port]               Target server IPv4/IPv6 address or FQDN (default: system resolver)\n"
        "                               Supports direct port specification (e.g. @127.0.0.1:10053 or @[::1]:5353)\n"
        "                               Accepts comma-separated list to query multiple servers (e.g. @8.8.8.8,9.9.9.9:5353,1.1.1.1)\n"
        "  -p <port>                    Port number (default: 53)\n"
        "  -x <addr>                    Shortcut for reverse DNS lookups (IPv4/IPv6)\n"
        "  -c <class>                   Specify query class (IN, CH, HS, etc.) [default: IN]\n"
        "  -q <name>                    Explicitly specify query name\n"
        "  -t <type>                    Explicitly specify query type\n"
        "  -y [alg:]name:secret         Specify TSIG key in base64 format (e.g. -y hmac-sha256:keyname:secret==)\n"
        "  +tsig=[alg:]name:secret      Specify TSIG key (+tsig alternative for -y)\n"
        "  -k <keyfile>                 Load TSIG key from BIND-format keyfile\n"
        "  -4 / -6                      Force IPv4 or IPv6 query transport\n"
        "  -b <addr>[#port]             Bind source IP address and optional port\n"
        "  -f <file>                    Batch mode (read queries from file)\n"
        "  -r                           Do not read ~/.digrc\n"
        "  -m                           Enable memory allocation debugging\n"
        "  -u                           Display query times in microseconds (usec)\n"
        "  -h, --help                   Display this help message and exit\n"
        "  -v, --version                Display version information and exit\n"
        "\n"
        "Transport & Protocol Options:\n"
        "  +[no]tcp                     Use TCP transport (+[no]vc)\n"
        "  +[no]tls                     Use DNS-over-TLS (DoT) [default port: 853]\n"
        "  +[no]tls-ca[=file]           Enable TLS certificate verification using system store or CA file\n"
        "  +tls-certfile=file           Load client TLS certificate chain from file\n"
        "  +tls-keyfile=file            Load client TLS private key from file\n"
        "  +tls-hostname=host           Explicitly specify expected TLS Server Name Indication (SNI)\n"
        "  +[no]https[=endpoint]        Use DNS-over-HTTPS (DoH) mode [default endpoint: /dns-query, port: 443]\n"
        "  +[no]https-get[=endpoint]    Use GET method instead of POST for DoH\n"
        "  +[no]https-post[=endpoint]   Use POST method for DoH\n"
        "  +[no]http-plain[=endpoint]   Use plain HTTP DNS mode [default endpoint: /dns-query, port: 80]\n"
        "  +[no]http-plain-get[=ep]     Use GET method for plain HTTP\n"
        "  +[no]http-plain-post[=ep]    Use POST method for plain HTTP\n"
        "  +[no]proxy[=spec]            Inject PROXYv2 transport header ahead of any TLS handshake (e.g. +proxy=192.0.2.1#1234-192.0.2.2#53)\n"
        "  +[no]proxy-plain[=spec]      Alias for +proxy (retained for dig/kdig compatibility); behaves identically\n"
        "  +[no]keepalive               Send EDNS TCP keepalive option (RFC 7828)\n"
        "  +[no]keepopen                Keep TCP socket open between consecutive queries (RFC 7766)\n"
        "  +[no]dns64prefix             Query IPv4-only prefix from ipv4only.arpa (RFC 7050)\n"
        "  +timeout=N                   Query timeout in seconds [5]\n"
        "  +tries=N / +retry=N          Number of query attempts [1]\n"
        "  +[no]recurse                 Set / clear RD (Recursion Desired) bit (+[no]rdflag)\n"
        "  +[no]adflag                  Set / clear AD (Authenticated Data) bit in query\n"
        "  +[no]cdflag                  Set / clear CD (Checking Disabled) bit in query\n"
        "  +[no]aaflag                  Set / clear AA (Authoritative Answer) bit in query (+[no]aaonly)\n"
        "  +[no]tcflag                  Set / clear TC (Truncated) bit in query\n"
        "  +[no]raflag                  Set / clear RA (Recursion Available) bit in query\n"
        "  +[no]zflag                   Set / clear Z (Reserved) bit in query\n"
        "  +opcode=N                    Override DNS Opcode in query header (0=QUERY, 2=STATUS, 5=UPDATE, etc.)\n"
        "  +qid=N                       Explicitly specify DNS query ID (0-65535)\n"
        "  +[no]ignore                  Ignore TC flag and do not retry via TCP\n"
        "  +tcp-mss=N                   Force TCP Maximum Segment Size (MSS) to N bytes\n"
        "  +tcp-window=N                Force TCP Receive/Send Window Size to N bytes\n"
        "  +[no]fail                    Do not try next server if SERVFAIL is received\n"
        "  +[no]trace                   Trace delegation hierarchy down from root servers (honors +tcp; falls back to TCP on truncated responses)\n"
        "  +[no]nssearch                Search all authoritative nameservers for zone (honors +tcp; falls back to TCP on truncated responses)\n"
        "  +[no]search / +[no]defname   Use search list defined in /etc/resolv.conf\n"
        "  +domain=domain               Set default search domain\n"
        "  +ndots=N                     Set search NDOTS threshold\n"
        "\n"
        "EDNS0 Extension Options:\n"
        "  +[no]edns[=N]                Set EDNS version (0 to disable: +noedns) [0]\n"
        "  +bufsize=N                   Set EDNS0 advertised UDP buffer size [1232]\n"
        "  +[no]dnssec                  Request DNSSEC records by setting DO (DNSSEC OK) bit (+[no]do)\n"
        "  +[no]cookie[=hex]            Send EDNS COOKIE option with optional client/server cookie hex\n"
        "  +[no]badcookie               Automatically retry with returned server cookie on BADCOOKIE\n"
        "  +[no]showbadcookie           Display diagnostic message when BADCOOKIE retry occurs\n"
        "  +subnet=addr[/prefix]        Send EDNS Client Subnet (ECS) option (e.g. +subnet=192.0.2.0/24)\n"
        "  +[no]nsid                    Request Name Server Identifier (NSID) option (RFC 5001)\n"
        "  +padding[=N]                 Add EDNS padding option with block size N (RFC 7830/8467)\n"
        "  +ednsopt=code[:hex]          Send custom EDNS option by code and hex payload (e.g. +ednsopt=65001:0102)\n"
        "  +noednsopt                   Clear all configured custom EDNS options\n"
        "  +ednsflags=N                 Set raw EDNS Z flag bits in OPT record\n"
        "  +[no]coflag                  Set Compact Answers OK (CO) flag bit in OPT record (+[no]co)\n"
        "  +[no]ednsnegotiation         Enable/disable EDNS version negotiation fallback on BADVERS\n"
        "  +[no]showbadvers             Display diagnostic message when BADVERS fallback occurs\n"
        "\n"
        "Display & Formatting Options:\n"
        "  +[no]short                   Display concise short-form answer data only\n"
        "  +[no]multiline               Display multiline format for SOA, DNSKEY, and RRSIG records\n"
        "  +[no]yaml                    Output parsed response in structured YAML format\n"
        "  +[no]ttlunits                Display TTL values in human-readable time units (w/d/h/m/s)\n"
        "  +[no]class                   Display / suppress CLASS field in resource records\n"
        "  +[no]ttlid                   Display / suppress TTL field in resource records\n"
        "  +[no]unknownformat           Format record RDATA using RFC 3597 unknown type syntax (\\#)\n"
        "  +[no]crypto                  Display / suppress cryptographic key fields in DNSKEY/DS\n"
        "  +[no]rrcomments              Display explanatory keytag comments on DNSKEY records\n"
        "  +[no]comments                Toggle comment banners and section header comments\n"
        "  +[no]cmd                     Toggle command line header banner (; <<>> dag <<>> ...)\n"
        "  +[no]stats                   Toggle query timing and server statistics section\n"
        "  +[no]question                Toggle QUESTION section display\n"
        "  +[no]answer                  Toggle ANSWER section display\n"
        "  +[no]authority               Toggle AUTHORITY section display\n"
        "  +[no]additional              Toggle ADDITIONAL section display\n"
        "  +[no]all                     Set or clear all display section flags at once\n"
        "  +[no]qr                      Display outgoing query packet representation before sending\n"
        "  +[no]identify                Display responding server IP in short-mode responses\n"
        "  +[no]idn                     Convert Internationalized Domain Names (IDN) (+[no]idnin / +[no]idnout)\n"
        "  +[no]onesoa                  Display only the first SOA record during AXFR transfers\n"
        "  +[no]expandaaaa              Display IPv6 AAAA addresses in fully expanded 8-field format\n"
        "  +[no]split=N                 Split long hex and base64 fields into N-character chunks [56]\n"
        "  +[no]besteffort              Attempt to parse and display malformed/illegal DNS packets\n"
        "  +[no]expire                  Request and highlight zone expiration TTL in SOA output\n"
        "  +[no]showsearch              Display intermediate results during search list resolution\n"
        "\n"
        "Dynamic DNS Update Options (RFC 2136):\n"
        "  --update-add <RR>            Add resource record (e.g. --update-add 'host.example.com 300 IN A 192.0.2.1')\n"
        "  --update-del <name> [type]   Delete RRset or all records on name (e.g. --update-del 'host.example.com A')\n"
        "  --update-del-exact <RR>      Delete specific RR matching full RDATA (e.g. --update-del-exact 'host.example.com 300 IN A 192.0.2.1')\n"
        "  --prereq-yxdomain <name>     Prerequisite: Domain name must exist (in use)\n"
        "  --prereq-nxdomain <name>     Prerequisite: Domain name must NOT exist (not in use)\n"
        "  --prereq-yxrrset <name> <type> [rdata]\n"
        "                               Prerequisite: RRset must exist (optionally matching specified RDATA value)\n"
        "  --prereq-nxrrset <name> <type>\n"
        "                               Prerequisite: RRset must NOT exist\n"
        "  --prereq=<expr>              Specify prerequisite expression (e.g. --prereq='yxdomain:host.example.com')\n"
        "  Example:\n"
        "    dag example.com SOA @127.0.0.1 -k /etc/rndc.key --update-add 'web.example.com 3600 IN A 192.0.2.80'\n"
        "\n"
        "KariDNS / dag Unique Features & Protocol Fuzzing:\n"
        "  +[no]ldnsz                   Enable LDNSZ extended query compression / format (RFC draft)\n"
        "                               Example: dag example.com A @127.0.0.1 +ldnsz\n"
        "  +[no]allcompare              Compare responses across all queried nameservers for consistency\n"
        "                               Example: dag example.com A @8.8.8.8,1.1.1.1,9.9.9.9 +allcompare\n"
        "  +mqtype=TYPE[,TYPE...]       Send Multiple QTYPE EDNS option (RFC 10029)\n"
        "                               Example: dag example.com A @127.0.0.1 +mqtype=A,AAAA,HTTPS\n"
        "  +[no]header-only             Send DNS query packet without a QUESTION section\n"
        "  +[no]nohexdump               Suppress raw packet hex dumps for query and response\n"
        "  +[no]nohexdump-query         Suppress raw query packet hex dump\n"
        "  +[no]nohexdump-response      Suppress raw response packet hex dump\n"
        "  --hex=<hex> | --hex <hex>    Send raw hex payload directly as DNS query packet\n"
        "                               Example: dag @127.0.0.1 --hex '000101000001000000000000076578616d706c6503636f6d0000010001'\n"
        "  --break <kind>[=<param>]     Inject deliberate protocol anomalies / mutations into query packet\n"
        "                               Examples:\n"
        "                                 dag example.com A @127.0.0.1 --break oversized-qname\n"
        "                                 dag example.com A @127.0.0.1 --break compression-loop\n"
        "                                 dag example.com A @127.0.0.1 --break too-short=2\n"
        "                                 dag example.com A @127.0.0.1 --break all\n"
        "  --break-help                 Display list of all supported --break anomaly mutation kinds\n"
    );
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
            alg = strdup(tsig_str); name = strdup(colon1 + 1); secret_b64 = colon2 + 1;
        } else {
            *colon1 = '\0';
            alg = strdup("hmac-sha256"); name = strdup(tsig_str); secret_b64 = colon1 + 1;
        }
        qo->tsig_key.algorithm = alg;
        qo->tsig_key.name = name;
        int b64_len = strlen(secret_b64);
        int pad = 0;
        if (b64_len > 0 && secret_b64[b64_len - 1] == '=') pad++;
        if (b64_len > 1 && secret_b64[b64_len - 2] == '=') pad++;
        size_t decoded_upper_bound = ((b64_len + 3) / 4) * 3;
        if (b64_len == 0 || decoded_upper_bound > sizeof(qo->tsig_key.secret_decoded)) {
            fprintf(stderr, "warning: tsig secret base64 too long or empty\n");
            qo->want_tsig = false;
            return;
        }
        int dec_len = EVP_DecodeBlock(qo->tsig_key.secret_decoded, (const unsigned char *)secret_b64, b64_len);
        if (dec_len > 0 && dec_len >= pad) {
            qo->tsig_key.secret_decoded_len = (size_t)(dec_len - pad);
        } else {
            fprintf(stderr, "warning: invalid tsig secret base64\n");
            qo->want_tsig = false;
        }
    } else {
        fprintf(stderr, "warning: invalid tsig format (expected [alg:]name:key)\n");
        qo->want_tsig = false;
    }
}

static void parse_tsig_keyfile(const char *path, query_opts_t *qo) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "warning: could not open TSIG key file '%s': %s\n", path, strerror(errno));
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    #define KARIDNS_MAX_TSIG_KEYFILE_SIZE (64 * 1024)
    if (size < 0 || size > KARIDNS_MAX_TSIG_KEYFILE_SIZE) {
        fprintf(stderr, "warning: TSIG key file '%s' is not a regular seekable file or exceeds size limit\n", path);
        fclose(f);
        return;
    }
    
    char *buf = malloc((size_t)size + 1);
    if (!buf) { fclose(f); return; }
    size_t n = fread(buf, 1, (size_t)size, f);
    buf[n] = '\0';
    fclose(f);
    
    char name[128] = {0}, algo[128] = {0}, secret[256] = {0};
    
    char *p = strstr(buf, "key ");
    if (p) {
        p += 4;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') {
            p++;
            char *end = strchr(p, '"');
            if (end && (long)(end - p) < (long)sizeof(name)) {
                memcpy(name, p, end - p);
                name[end - p] = '\0';
            }
        } else {
            sscanf(p, "%127s", name);
        }
    }
    
    p = strstr(buf, "algorithm ");
    if (p) {
        p += 10;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') p++;
        char *end = p;
        while (*end && *end != ';' && *end != '"' && *end != ' ' && *end != '\n') end++;
        if ((long)(end - p) < (long)sizeof(algo)) {
            memcpy(algo, p, end - p);
            algo[end - p] = '\0';
        }
    }
    
    p = strstr(buf, "secret ");
    if (p) {
        p += 7;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') {
            p++;
            char *end = strchr(p, '"');
            if (end && (long)(end - p) < (long)sizeof(secret)) {
                memcpy(secret, p, end - p);
                secret[end - p] = '\0';
            }
        } else {
            char *end = p;
            while (*end && *end != ';' && *end != ' ' && *end != '\t' && *end != '\n') end++;
            if ((long)(end - p) < (long)sizeof(secret)) {
                memcpy(secret, p, end - p);
                secret[end - p] = '\0';
            }
        }
    }
    
    free(buf);
    
    if (name[0] && secret[0]) {
        if (!algo[0]) {
            if (strlcpy(algo, "hmac-sha256", sizeof(algo)) >= sizeof(algo)) {
                fprintf(stderr, "warning: algorithm name truncated\n");
            }
        }
        size_t combined_len = strlen(name) + strlen(secret) + strlen(algo) + 3;
        char *combined_copy = malloc(combined_len);
        if (!combined_copy) {
            fprintf(stderr, "error: out of memory for TSIG key string\n");
            return;
        }
        int ret = snprintf(combined_copy, combined_len, "%s:%s:%s", algo, name, secret);
        if (ret < 0 || (size_t)ret >= combined_len) {
            fprintf(stderr, "warning: TSIG key string truncated\n");
        }
        parse_tsig_str(combined_copy, qo);
    } else {
        fprintf(stderr, "warning: failed to parse TSIG key from '%s'\n", path);
    }
}

/*
 * /etc/resolv.conf (Windows: GetNetworkParams) から最初の nameserver を読み取って返す。
 * 見つからなければパブリックDNS (1.1.1.1) または 127.0.0.1 をフォールバックとして使用。
 */

static const char *get_system_resolver(void) {
    static char resolver[256];
#ifdef _WIN32
    FIXED_INFO *pFixedInfo = NULL;
    ULONG ulOutBufLen = sizeof(FIXED_INFO);
    pFixedInfo = (FIXED_INFO *)malloc(ulOutBufLen);
    if (pFixedInfo) {
        if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pFixedInfo);
            pFixedInfo = (FIXED_INFO *)malloc(ulOutBufLen);
        }
        if (pFixedInfo && GetNetworkParams(pFixedInfo, &ulOutBufLen) == NO_ERROR) {
            IP_ADDR_STRING *pIPAddr = &pFixedInfo->DnsServerList;
            while (pIPAddr) {
                if (pIPAddr->IpAddress.String[0] != '\0' &&
                    strcmp(pIPAddr->IpAddress.String, "0.0.0.0") != 0) {
                    snprintf(resolver, sizeof(resolver), "%s", pIPAddr->IpAddress.String);
                    free(pFixedInfo);
                    return resolver;
                }
                pIPAddr = pIPAddr->Next;
            }
        }
        if (pFixedInfo) free(pFixedInfo);
    }
    snprintf(resolver, sizeof(resolver), "1.1.1.1");
    return resolver;
#else
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (!fp) {
        snprintf(resolver, sizeof(resolver), "127.0.0.1");
        return resolver;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n') continue;
        if (strncmp(p, "nameserver", 10) == 0 && (p[10] == ' ' || p[10] == '\t')) {
            p += 10;
            while (*p == ' ' || *p == '\t') p++;
            char *end = p + strlen(p) - 1;
            while (end > p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) *end-- = '\0';
            snprintf(resolver, sizeof(resolver), "%s", p);
            fclose(fp);
            return resolver;
        }
    }
    fclose(fp);
    snprintf(resolver, sizeof(resolver), "127.0.0.1");
    return resolver;
#endif
}

static int get_system_search_domains(char domains[][256], int max_domains) {
#ifdef _WIN32
    (void)domains; (void)max_domains;
    return 0;
#else
    int count = 0;
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (!fp) return 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n') continue;
        if ((strncmp(p, "search", 6) == 0 && (p[6] == ' ' || p[6] == '\t')) ||
            (strncmp(p, "domain", 6) == 0 && (p[6] == ' ' || p[6] == '\t'))) {
            p += 6;
            char *tok = strtok(p, " \t\r\n");
            while (tok && count < max_domains) {
                snprintf(domains[count++], 256, "%s", tok);
                tok = strtok(NULL, " \t\r\n");
            }
        }
    }
    fclose(fp);
    return count;
#endif
}

static int run_single_job(const char *qname, const char *qtype_s, const char *server_arg, int port,
                          bool use_tcp, bool force_udp, bool test_all, bool norecurse,
                          bool adflag, bool cdflag, bool aaflag, bool tcflag, bool zflag,
                          bool no_hexdump_query, bool no_hexdump_response,
                          query_opts_t qo, const char *hex_payload, const display_opts_t *dopt);

static void record_ldnsz_result(const char *server, ssize_t n, const uint8_t *resp, long elapsed_ms, const char *proto) {
    if (n < 12) return;
    server_result_t *sres = alloc_result_row();
    if (!sres) return;
    sres->rcode = resp[3] & 0x0F;
    sres->qdcount = (resp[4] << 8) | resp[5];
    sres->ancount = (resp[6] << 8) | resp[7];
    sres->nscount = (resp[8] << 8) | resp[9];
    sres->arcount = (resp[10] << 8) | resp[11];
    sres->qr = resp[2] & 0x80; sres->aa = resp[2] & 0x04; sres->tc = resp[2] & 0x02; sres->rd = resp[2] & 0x01;
    sres->ra = resp[3] & 0x80; sres->ad = resp[3] & 0x20; sres->cd = resp[3] & 0x10;
    sres->msg_index = 1;
    sres->msg_total = 1;
    size_t to_copy = (size_t)n < sizeof(sres->resp_buf) ? (size_t)n : sizeof(sres->resp_buf);
    memcpy(sres->resp_buf, resp, to_copy);
    sres->resp_len = (ssize_t)to_copy;
    calculate_packet_hashes(resp, n, &sres->semantic_hash, &sres->record_hash);
    snprintf(sres->server_ip, sizeof(sres->server_ip), "%s", server);
    snprintf(sres->proto, sizeof(sres->proto), "%s", proto ? proto : "UDP");
    sres->elapsed_ms = elapsed_ms;
    g_server_count++;
}

static int run_trace_query(const char *qname, const char *server, const char *qtype_s, int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response, query_opts_t qo, const char *hex_payload, const display_opts_t *dopt) {
    (void)force_udp; (void)hex_payload;
    qo.rd_flag = false;
    printf(";; TRACE: tracing %s from root servers...\n", qname);
    char target_ips[32][64];
    int target_count = 0;
    
    const char *eff_server = server ? server : get_system_resolver();
    display_opts_t trace_dopt = *dopt;
    trace_dopt.show_comments = false;
    trace_dopt.show_question = false;
    trace_dopt.show_stats = false;

    uint8_t root_qbuf[512];
    size_t root_qlen = build_query_packet(root_qbuf, sizeof(root_qbuf), ".", 2 /* NS */, &qo);
    uint8_t root_resp[65535];
    if (!no_hexdump_query) {
        printf("Query (%zd bytes):\n", root_qlen);
        hexdump(root_qbuf, root_qlen);
        printf("\n");
    }

    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    ssize_t root_n = do_dns_exchange_auto(eff_server, port, &qo, root_qbuf, root_qlen, root_resp, sizeof(root_resp), qo.timeout_sec, use_tcp);
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    
    if (root_n > 0) {
        int dt_ms = timespec_diff_ms(&start_ts, &end_ts);
        record_ldnsz_result(eff_server, root_n, root_resp, dt_ms, use_tcp ? "TCP" : "UDP");
        if (!no_hexdump_response) {
            printf("Response (%zd bytes):\n", root_n);
            hexdump(root_resp, (size_t)root_n);
            printf("\n");
        }
    }

    if (root_n > 12) {
        axfr_state_t dummy_axfr = {0};
        print_response(root_resp, root_n, &dummy_axfr, &trace_dopt);
        int dt_ms = timespec_diff_ms(&start_ts, &end_ts);
        printf(";; Received %zd bytes from %s#%d in %d ms\n\n", root_n, eff_server, port, dt_ms);
        
        int r_qd = (root_resp[4] << 8) | root_resp[5];
        int r_an = (root_resp[6] << 8) | root_resp[7];
        int r_ns = (root_resp[8] << 8) | root_resp[9];
        int r_ar = (root_resp[10] << 8) | root_resp[11];
        size_t roff = 12;
        for (int i = 0; i < r_qd; i++) {
            char *d;
            if (expand_wire_name(root_resp, root_n, roff, &roff, &g_dag_arena, &d) != 0) break;
            roff += 4;
        }
        
        char rns_names[32][256];
        int rns_count = 0;
        for (int i=0; i<r_an; i++) {
            dns_record_t rec; uint16_t type;
            if (parse_resource_record(root_resp, root_n, &roff, &g_dag_arena, &rec, &type) != 0) break;
            if (type == 2 && rns_count < 32 && rec.rdata_count > 0) {
                snprintf(rns_names[rns_count++], sizeof(rns_names[0]), "%s", rec.rdata[0]);
            }
        }
        for (int i=0; i<r_ns; i++) {
            dns_record_t rec; uint16_t type;
            if (parse_resource_record(root_resp, root_n, &roff, &g_dag_arena, &rec, &type) != 0) break;
            if (type == 2 && rns_count < 32 && rec.rdata_count > 0) {
                snprintf(rns_names[rns_count++], sizeof(rns_names[0]), "%s", rec.rdata[0]);
            }
        }
        for (int i=0; i<r_ar; i++) {
            dns_record_t rec; uint16_t type;
            if (parse_resource_record(root_resp, root_n, &roff, &g_dag_arena, &rec, &type) != 0) break;
            bool want = false;
            if (type == 1 && (qo.pref_family == AF_UNSPEC || qo.pref_family == AF_INET)) want = true;
            if (type == 28 && (qo.pref_family == AF_UNSPEC || qo.pref_family == AF_INET6)) want = true;
            if (want && rec.rdata_count > 0) {
                for (int j=0; j<rns_count; j++) {
                    if (strcasecmp(rec.name, rns_names[j]) == 0 && target_count < 32) {
                        snprintf(target_ips[target_count++], sizeof(target_ips[0]), "%s", rec.rdata[0]);
                    }
                }
            }
        }
    }
    
    if (target_count == 0) {
        printf(";; could not fetch root servers, falling back to 198.41.0.4\n");
        if (strlcpy(target_ips[0], "198.41.0.4", sizeof(target_ips[0])) >= sizeof(target_ips[0])) {
            fprintf(stderr, "warning: target IP truncated\n");
        }
        target_count = 1;
    }
    
    int hop = 0;
    while (hop < 15 && target_count > 0) {
        hop++;
        uint8_t qbuf[512];
        int qtype_val = parse_qtype(qtype_s);
        size_t qlen = build_query_packet(qbuf, sizeof(qbuf), qname, qtype_val, &qo);
        if (qlen == 0) break;
        
        uint8_t resp[65535];
        if (!no_hexdump_query) {
            printf("Query (%zd bytes):\n", qlen);
            hexdump(qbuf, qlen);
            printf("\n");
        }
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        ssize_t n = do_dns_exchange_auto(target_ips[0], port, &qo, qbuf, qlen, resp, sizeof(resp), qo.timeout_sec, use_tcp);
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        if (n <= 0) {
            printf(";; connection timed out; no servers could be reached\n");
            return 9;
        }
        
        int dt_ms = timespec_diff_ms(&start_ts, &end_ts);
        record_ldnsz_result(target_ips[0], n, resp, dt_ms, use_tcp ? "TCP" : "UDP");

        if (!no_hexdump_response) {
            printf("Response (%zd bytes):\n", n);
            hexdump(resp, (size_t)n);
            printf("\n");
        }

        axfr_state_t dummy_axfr = {0};
        print_response(resp, n, &dummy_axfr, &trace_dopt);
        printf(";; Received %zd bytes from %s#%d in %d ms\n\n", n, target_ips[0], port, dt_ms);
        
        if (n < 12) break;
        uint16_t flags = (resp[2] << 8) | resp[3];
        int qdcount = (resp[4] << 8) | resp[5];
        int ancount = (resp[6] << 8) | resp[7];
        int nscount = (resp[8] << 8) | resp[9];
        int arcount = (resp[10] << 8) | resp[11];
        
        if ((flags & 0x000F) != 0 || ancount > 0 || (flags & 0x0400)) {
            break;
        }
        
        size_t offset = 12;
        for (int i = 0; i < qdcount; i++) {
            char *dummy;
            if (expand_wire_name(resp, n, offset, &offset, &g_dag_arena, &dummy) != 0) break;
            offset += 4;
        }
        
        char ns_names[16][256];
        int ns_count = 0;
        for (int i = 0; i < nscount; i++) {
            dns_record_t rec; uint16_t type;
            if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
            if (type == 2 && ns_count < 16 && rec.rdata_count > 0) {
                snprintf(ns_names[ns_count++], sizeof(ns_names[0]), "%s", rec.rdata[0]);
            }
        }
        
        int new_target_count = 0;
        char new_target_ips[16][64];
        for (int i = 0; i < arcount; i++) {
            dns_record_t rec; uint16_t type;
            if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
            bool want = false;
            if (type == 1 && (qo.pref_family == AF_UNSPEC || qo.pref_family == AF_INET)) want = true;
            if (type == 28 && (qo.pref_family == AF_UNSPEC || qo.pref_family == AF_INET6)) want = true;
            if (want && rec.rdata_count > 0) {
                bool match = false;
                for (int j=0; j<ns_count; j++) {
                    if (strcasecmp(rec.name, ns_names[j]) == 0) { match = true; break; }
                }
                if (match && new_target_count < 16) {
                    snprintf(new_target_ips[new_target_count++], sizeof(new_target_ips[0]), "%s", rec.rdata[0]);
                }
            }
        }
        
        if (new_target_count == 0) {
            printf(";; No glue found for next hop, stopping trace.\n");
            break;
        }
        
        target_count = new_target_count;
        _Static_assert(sizeof(target_ips[0]) == sizeof(new_target_ips[0]), "buffer size mismatch");
        for(int i=0; i<target_count; i++) {
            if (strlcpy(target_ips[i], new_target_ips[i], sizeof(target_ips[i])) >= sizeof(target_ips[i])) {
                fprintf(stderr, "warning: target IP truncated\n");
            }
        }
    }
    return 0;
}

static int run_nssearch(const char *qname, const char *server, int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response, query_opts_t qo, const char *hex_payload, const display_opts_t *dopt) {
    (void)force_udp; (void)hex_payload; (void)dopt;
    qo.rd_flag = false;
    const char *eff_server = server ? server : get_system_resolver();
    uint8_t qbuf[512];
    size_t qlen = build_query_packet(qbuf, sizeof(qbuf), qname, 2 /* NS */, &qo);
    if (!no_hexdump_query) {
        printf("Query (%zd bytes):\n", qlen);
        hexdump(qbuf, qlen);
        printf("\n");
    }
    uint8_t resp[65535];
    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    ssize_t n = do_dns_exchange_auto(eff_server, port, &qo, qbuf, qlen, resp, sizeof(resp), qo.timeout_sec, use_tcp);
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    if (n > 0) {
        int dt_ms = timespec_diff_ms(&start_ts, &end_ts);
        record_ldnsz_result(eff_server, n, resp, dt_ms, use_tcp ? "TCP" : "UDP");
        if (!no_hexdump_response) {
            printf("Response (%zd bytes):\n", n);
            hexdump(resp, (size_t)n);
            printf("\n");
        }
    }
    if (n <= 0) {
        printf(";; connection timed out; no servers could be reached\n");
        return 9;
    }
    
    if (n < 12) return 1;
    int qdcount = (resp[4] << 8) | resp[5];
    int ancount = (resp[6] << 8) | resp[7];
    int nscount = (resp[8] << 8) | resp[9];
    
    size_t offset = 12;
    for (int i = 0; i < qdcount; i++) {
        char *dummy;
        if (expand_wire_name(resp, n, offset, &offset, &g_dag_arena, &dummy) != 0) return 1;
        offset += 4;
    }
    
    char ns_names[32][256];
    int ns_count = 0;
    for (int i = 0; i < ancount; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
        if (type == 2 && ns_count < 32 && rec.rdata_count > 0) {
            snprintf(ns_names[ns_count++], sizeof(ns_names[0]), "%s", rec.rdata[0]);
        }
    }
    if (ns_count == 0) {
        for (int i = 0; i < nscount; i++) {
            dns_record_t rec; uint16_t type;
            if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
            if (type == 2 && ns_count < 32 && rec.rdata_count > 0) {
                snprintf(ns_names[ns_count++], sizeof(ns_names[0]), "%s", rec.rdata[0]);
            }
        }
    }

    if (ns_count == 0) {
        printf(";; no NS records found for %s\n", qname);
        return 1;
    }

    struct { char ns_name[256]; char ip[64]; } all_ns_ips[128];
    int all_ns_count = 0;

    for (int j = 0; j < ns_count; j++) {
        char clean_name[256];
        snprintf(clean_name, sizeof(clean_name), "%s", ns_names[j]);
        size_t c_len = strlen(clean_name);
        if (c_len > 0 && clean_name[c_len - 1] == '.') clean_name[c_len - 1] = '\0';

        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = qo.pref_family;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(clean_name, NULL, &hints, &res) == 0 && res != NULL) {
            for (struct addrinfo *p = res; p != NULL && all_ns_count < 128; p = p->ai_next) {
                char ip_str[64];
                if (p->ai_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
                    inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
                } else if (p->ai_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)p->ai_addr;
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
                } else {
                    continue;
                }
                bool duplicate = false;
                for (int d = 0; d < all_ns_count; d++) {
                    if (strcmp(all_ns_ips[d].ip, ip_str) == 0) { duplicate = true; break; }
                }
                if (!duplicate) {
                    snprintf(all_ns_ips[all_ns_count].ns_name, sizeof(all_ns_ips[all_ns_count].ns_name), "%s", ns_names[j]);
                    snprintf(all_ns_ips[all_ns_count].ip, sizeof(all_ns_ips[all_ns_count].ip), "%s", ip_str);
                    all_ns_count++;
                }
            }
            freeaddrinfo(res);
        } else {
            fprintf(stderr, "couldn't get address for '%s': failure\n", clean_name);
        }
    }

    if (all_ns_count == 0) {
        char clean_first[256];
        snprintf(clean_first, sizeof(clean_first), "%s", ns_names[0]);
        size_t c_len = strlen(clean_first);
        if (c_len > 0 && clean_first[c_len - 1] == '.') clean_first[c_len - 1] = '\0';
        fprintf(stderr, "dig: couldn't get address for '%s': no more\n", clean_first);
        return 9;
    }

    for (int k = 0; k < all_ns_count; k++) {
        size_t slen = build_query_packet(qbuf, sizeof(qbuf), qname, 6 /* SOA */, &qo);
        if (!no_hexdump_query) {
            printf("Query (%zd bytes):\n", slen);
            hexdump(qbuf, slen);
            printf("\n");
        }
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        ssize_t sn = do_dns_exchange_auto(all_ns_ips[k].ip, port, &qo, qbuf, slen, resp, sizeof(resp), qo.timeout_sec, use_tcp);
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        int dt_ms = 0;
        if (sn > 0) {
            dt_ms = timespec_diff_ms(&start_ts, &end_ts);
            record_ldnsz_result(all_ns_ips[k].ip, sn, resp, dt_ms, use_tcp ? "TCP" : "UDP");
            if (!no_hexdump_response) {
                printf("Response (%zd bytes):\n", sn);
                hexdump(resp, (size_t)sn);
                printf("\n");
            }
        }
        if (sn > 12) {
            int sancount = (resp[6] << 8) | resp[7];
            size_t soff = 12;
            int sqdcount = (resp[4] << 8) | resp[5];
            for (int i = 0; i < sqdcount; i++) {
                char *d;
                if (expand_wire_name(resp, sn, soff, &soff, &g_dag_arena, &d) != 0) break;
                soff += 4;
            }
            for (int i=0; i<sancount; i++) {
                dns_record_t rec; uint16_t type;
                if (parse_resource_record(resp, sn, &soff, &g_dag_arena, &rec, &type) != 0) break;
                if (type == 6 && rec.rdata_count >= 7) {
                    printf("SOA %s %s %s %s %s %s %s from server %s in %d ms\n",
                           rec.rdata[0], rec.rdata[1], rec.rdata[2], rec.rdata[3], rec.rdata[4], rec.rdata[5], rec.rdata[6],
                           all_ns_ips[k].ip, dt_ms);
                    break;
                }
            }
        } else {
            printf(";; connection timed out; no servers could be reached\n");
        }
    }
    return 0;
}

static int run_single_job(const char *qname, const char *qtype_s, const char *server_arg, int port,
                          bool use_tcp, bool force_udp, bool test_all, bool norecurse,
                          bool adflag, bool cdflag, bool aaflag, bool tcflag, bool zflag,
                          bool no_hexdump_query, bool no_hexdump_response,
                          query_opts_t qo, const char *hex_payload, const display_opts_t *dopt) {
    char expanded_qname[512];
    int num_dots = 0;
    for (const char *p = qname; *p; p++) {
        if (*p == '.') num_dots++;
    }
    int req_ndots = (qo.ndots > 0) ? qo.ndots : 1;
    if (qo.use_search_list && num_dots < req_ndots) {
        if (qo.search_domain && *qo.search_domain) {
            snprintf(expanded_qname, sizeof(expanded_qname), "%s.%s", qname, qo.search_domain);
            qname = expanded_qname;
        } else {
            char domains[4][256];
            int count = get_system_search_domains(domains, 4);
            if (count > 0) {
                snprintf(expanded_qname, sizeof(expanded_qname), "%s.%s", qname, domains[0]);
                qname = expanded_qname;
            }
        }
    }

    /*
     * @8.8.8.8,9.9.9.9 のようにカンマ区切りで複数サーバーを指定できるようにする。
     * 各要素はIPv4/IPv6リテラルの他、@dns.google のようなFQDNも許可する
     * (resolve_server_addr()がgetaddrinfo()で解決する)。
     */
    if (!server_arg) return 1;
    char *server_list_buf = strdup(server_arg);
    if (!server_list_buf) { perror("strdup"); return 1; }
    const char *servers[MAX_DAG_SERVERS];
    int server_ports[MAX_DAG_SERVERS];
    int server_count = 0;
    {
        char *save = NULL;
        char *tok = strtok_r(server_list_buf, ",", &save);
        while (tok) {
            while (*tok == ' ' || *tok == '\t') tok++;
            char *end = tok + strlen(tok);
            while (end > tok && isspace((unsigned char)end[-1])) {
                *--end = '\0';
            }

            if (*tok == '\0') {
                fprintf(stderr, "warning: skipping empty server entry\n");
            } else if (server_count >= MAX_DAG_SERVERS) {
                fprintf(stderr, "warning: too many servers specified, only the first %d will be used\n", MAX_DAG_SERVERS);
                break;
            } else {
                int srv_port = port; // -p のデフォルト値
                char *hash = strchr(tok, '#');
                if (hash) {
                    *hash = '\0';
                    char *endptr;
                    long p = strtol(hash + 1, &endptr, 10);
                    if (*endptr == '\0' && p > 0 && p <= 65535) {
                        srv_port = (int)p;
                    } else {
                        fprintf(stderr, "warning: invalid port '%s' for server '%s'; using default %d\n", hash + 1, tok, port);
                    }
                } else if (tok[0] == '[') {
                    // [IPv6]:port 記法
                    char *close = strchr(tok, ']');
                    if (close) {
                        *close = '\0';
                        tok++; // '[' をスキップ
                        if (close[1] == ':' && close[2] != '\0') {
                            char *endptr;
                            long p = strtol(close + 2, &endptr, 10);
                            if (*endptr == '\0' && p > 0 && p <= 65535) {
                                srv_port = (int)p;
                            } else {
                                fprintf(stderr, "warning: invalid port '%s' for server '%s'; using default %d\n", close + 2, tok, port);
                            }
                        }
                    } else {
                        fprintf(stderr, "warning: unclosed IPv6 bracket in server entry '%s'\n", tok);
                    }
                } else {
                    // IPv4/FQDN: 最後の ':' をポート区切りとして扱う
                    char *first_colon = strchr(tok, ':');
                    if (first_colon && !strchr(first_colon + 1, ':')) {
                        // ':' が1つだけ → IPv4:port
                        *first_colon = '\0';
                        char *endptr;
                        long p = strtol(first_colon + 1, &endptr, 10);
                        if (*endptr == '\0' && p > 0 && p <= 65535) {
                            srv_port = (int)p;
                        } else {
                            fprintf(stderr, "warning: invalid port '%s' for server '%s'; using default %d\n", first_colon + 1, tok, port);
                        }
                    }
                }
                servers[server_count] = tok;
                server_ports[server_count] = srv_port;
                server_count++;
            }
            tok = strtok_r(NULL, ",", &save);
        }
    }
    if (server_count == 0) {
        fprintf(stderr, "Server must start with '@', e.g. @192.0.2.1 or @192.0.2.1:10053,192.0.2.2\n");
        free(server_list_buf);
        return 1;
    }


    // AXFRまたはANYの場合は自動的にTCPモードに昇格（+udpが明示されていない場合、BIND 9 dig / RFC 8482準拠）
    if ((strcasecmp(qtype_s, "AXFR") == 0 || strcasecmp(qtype_s, "ANY") == 0) && !force_udp) {
        use_tcp = true;
    }

    for (int i = 0; i < g_break_count; i++) {
        if (is_tcp_only_break(g_breaks[i].kind) && !use_tcp) {
            fprintf(stderr, "error: this --break kind requires --tcp\n");
            free(server_list_buf);
            return 1;
        }
    }
    qo.query_id = (uint16_t)(arc4random() & 0xFFFF);

    if (qo.nofail && server_count > 1 && !test_all) {
        for (int si = 0; si < server_count; si++) {
            const char *server = servers[si];
            int srv_port = server_ports[si];
            bool is_last = (si == server_count - 1);

            int rc = run_test(NULL, qname, qtype_s, server, srv_port, use_tcp, norecurse,
                              adflag, cdflag, aaflag, tcflag, zflag,
                              no_hexdump_query, no_hexdump_response, &qo, hex_payload, dopt);

            uint8_t last_rcode = 2; // Default to SERVFAIL if no response
            if (g_server_count > 0) {
                last_rcode = g_results[g_server_count - 1].rcode;
            }

            if (rc == 0 && last_rcode != 2) {
                break;
            }
            if (!is_last) {
                fprintf(stderr, ";; Server %s failed (SERVFAIL or no response), trying next server...\n", server);
            }
        }
    } else {
        for (int si = 0; si < server_count; si++) {
            const char *server = servers[si];
            int srv_port = server_ports[si];
            
            if (server_count > 1) {
                printf("\n;; ===============================================\n");
                printf(";; Server: %s\n", server);
                printf(";; ===============================================\n");
            }

            if (test_all) {
            if (strcmp(qname, ".") == 0) qname = "example.com";
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

            qo.timeout_sec = 1;
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

                run_test(all_tests[t].name, qname, qtype_s, server, srv_port,
                         use_tcp || all_tests[t].tcp, norecurse,
                         adflag, all_tests[t].cdflag, all_tests[t].aaflag, all_tests[t].tcflag, all_tests[t].zflag,
                         no_hexdump_query, no_hexdump_response,
                         &t_qo, hex_payload, dopt);
            }

            } else {
                int rc = run_test(NULL, qname, qtype_s, server, srv_port, use_tcp, norecurse,
                                  adflag, cdflag, aaflag, tcflag, zflag,
                                  no_hexdump_query, no_hexdump_response, &qo, hex_payload, dopt);
                if (rc != 0) { free(server_list_buf); return rc; }
            }
        }
    }
    
    free(server_list_buf);
    return 0;
}

#define MAX_DAG_QUERIES 64

typedef struct {
    int start;
    int end;
} arg_slice_t;

typedef struct query_spec_s {
    const char *server_arg;
    int port;
    const char *batch_file;
    bool use_tcp;
    bool force_udp;
    bool use_ldnsz;
    bool do_trace;
    bool do_nssearch;
    bool norecurse;
    bool adflag;
    bool cdflag;
    bool aaflag;
    bool tcflag;
    bool zflag;
    bool test_all;
    bool no_hexdump_query;
    bool no_hexdump_response;
    const char *hex_payload;
    const char *qname;
    const char *qtype_s;
    char rev_name[128];
    query_opts_t qo;
    display_opts_t dopt;
} query_spec_t;

static void init_query_spec(query_spec_t *spec) {
    memset(spec, 0, sizeof(*spec));
    spec->port = 53;
    spec->dopt.show_question = true;
    spec->dopt.show_answer = true;
    spec->dopt.show_authority = true;
    spec->dopt.show_additional = true;
    spec->dopt.show_comments = true;
    spec->dopt.show_stats = true;
    spec->dopt.show_cmd = true;
    spec->dopt.short_mode = false;
    spec->dopt.multiline = false;
    spec->dopt.yaml = false;
    spec->dopt.ttlid = true;
    spec->dopt.expire = false;
    spec->dopt.showsearch = false;
    spec->dopt.idnout = false;
    spec->dopt.time_unit_usec = false;
    spec->dopt.besteffort = false;
    spec->dopt.show_class = true;
    spec->dopt.show_crypto = true;
    spec->dopt.show_query_message = false;
    spec->dopt.rrcomments = false;
    spec->dopt.onesoa = false;
    spec->dopt.show_badcookie_msg = false;
    spec->dopt.show_badvers_msg = false;
    spec->dopt.split_width = 56;
    spec->dopt.force_unknown_format = false;
    spec->dopt.ttlunits = false;

    spec->qo.qclass = 1;
    spec->qo.udp_payload_size = 1232;
    spec->qo.timeout_sec = 5;
    spec->qo.tries = 1;
    spec->qo.pref_family = AF_UNSPEC;
    spec->qo.bind_addr[0] = '\0';
    spec->qo.bind_port = 0;
    spec->qo.retry_on_badcookie = true;
    spec->qo.edns_negotiation = true;
    spec->qo.rd_flag = true;
    spec->adflag = true;
    spec->qo.ad_flag = true;
    spec->qo.opcode_override = -1;
    spec->qo.qid_override = -1;
    spec->qo.ndots = -1;
    spec->qo.tcp_mss = 0;
    spec->qo.tcp_window = 0;
}

static bool is_known_qclass_str(const char *s, uint16_t *out_class) {
    if (!s) return false;
    if (strcasecmp(s, "IN") == 0) {
        if (out_class) *out_class = 1;
        return true;
    }
    if (strcasecmp(s, "CH") == 0 || strcasecmp(s, "CHAOS") == 0) {
        if (out_class) *out_class = 3;
        return true;
    }
    if (strcasecmp(s, "HS") == 0 || strcasecmp(s, "HESIOD") == 0) {
        if (out_class) *out_class = 4;
        return true;
    }
    if (strncasecmp(s, "CLASS", 5) == 0 && isdigit((unsigned char)s[5])) {
        if (out_class) *out_class = (uint16_t)atoi(s + 5);
        return true;
    }
    return false;
}

// 2引数（オプション名 + 値1個）を消費するオプションの一覧（Single Source of Truth）
static const char *TWO_ARG_OPTIONS[] = {
    "-p", "-c", "-t", "-b", "-k", "-y", "-q", "-x", "-f",
    "--hex", "--break",
    "--update-add", "--update-del", "--update-del-exact",
    "--prereq-nxdomain", "--prereq-yxdomain",
    NULL
};

static int get_arg_consume_count(int argc, char **argv, int i) {
    if (i >= argc) return 0;
    if (i + 1 >= argc) return 1;
    const char *arg = argv[i];

    if (strcmp(arg, "--prereq-nxrrset") == 0) {
        if (strchr(argv[i + 1], ' ') != NULL) {
            return 2; // "name type" quoted in single token
        }
        if (i + 2 < argc && argv[i + 2][0] != '-' && argv[i + 2][0] != '+' && argv[i + 2][0] != '@') {
            return 3; // name type
        }
        return 2;
    }
    if (strcmp(arg, "--prereq-yxrrset") == 0) {
        if (strchr(argv[i + 1], ' ') != NULL) {
            return 2; // "name type [rdata]" quoted in single token
        }
        if (i + 2 < argc && argv[i + 2][0] != '-' && argv[i + 2][0] != '+' && argv[i + 2][0] != '@') {
            if (i + 3 < argc && argv[i + 3][0] != '-' && argv[i + 3][0] != '+' && argv[i + 3][0] != '@') {
                return 4; // name type rdata
            }
            return 3; // name type
        }
        return 2;
    }

    for (int k = 0; TWO_ARG_OPTIONS[k]; k++) {
        if (strcmp(arg, TWO_ARG_OPTIONS[k]) == 0) return 2;
    }
    return 1;
}

static void prescan_always_global_options(int argc, char **argv, query_spec_t *global_spec) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "+cmd") == 0) global_spec->dopt.show_cmd = true;
        else if (strcmp(argv[i], "+nocmd") == 0) global_spec->dopt.show_cmd = false;
        else if (strcmp(argv[i], "+short") == 0) global_spec->dopt.short_mode = true;
        else if (strcmp(argv[i], "+noshort") == 0) global_spec->dopt.short_mode = false;
        else if (strcmp(argv[i], "+yaml") == 0) global_spec->dopt.yaml = true;
        else if (strcmp(argv[i], "+noyaml") == 0) global_spec->dopt.yaml = false;
        else if (strcmp(argv[i], "+ldnsz") == 0) global_spec->use_ldnsz = true;
        else if (strcmp(argv[i], "+noldnsz") == 0) global_spec->use_ldnsz = false;
        else if (strcmp(argv[i], "-m") == 0) global_spec->qo.mem_debug = true;
        else if (strcmp(argv[i], "+allcompare") == 0) g_want_allcompare = true;
    }
}

static int parse_query_arg_token(int argc, char **argv, int i, query_spec_t *spec) {
    const char *arg = argv[i];

    // プレスキャンで確定済みの全域グローバルオプションは最優先でスキップ (no-op)
    if (strcmp(arg, "+cmd") == 0 || strcmp(arg, "+nocmd") == 0 ||
        strcmp(arg, "+short") == 0 || strcmp(arg, "+noshort") == 0 ||
        strcmp(arg, "+yaml") == 0 || strcmp(arg, "+noyaml") == 0) {
        return 1;
    }

    if (arg[0] == '@') {
        spec->server_arg = arg + 1;
        spec->qo.server_explicit = true;
        return 1;
    }

    if (strcmp(arg, "--hex") == 0 && i + 1 < argc) {
        spec->hex_payload = argv[i + 1];
        spec->qname = "(hex)";
        spec->qtype_s = "ANY";
        return 2;
    }
    if (strncmp(arg, "--hex=", 6) == 0) {
        spec->hex_payload = arg + 6;
        spec->qname = "(hex)";
        spec->qtype_s = "ANY";
        return 1;
    }
    if (strcmp(arg, "-x") == 0 && i + 1 < argc) {
        if (!make_reverse_name(argv[i + 1], spec->rev_name, sizeof(spec->rev_name))) {
            fprintf(stderr, "Invalid IP address for -x\n");
            return -1;
        }
        spec->qname = spec->rev_name;
        spec->qtype_s = "PTR";
        spec->qo.qclass = 1;
        return 2;
    }
    if (strcmp(arg, "-c") == 0 && i + 1 < argc) {
        const char *c = argv[i + 1];
        uint16_t cls = 0;
        if (is_known_qclass_str(c, &cls)) {
            spec->qo.qclass = cls;
        } else {
            printf(";; Warning, ignoring invalid class %s\n", c);
            spec->qo.qclass = 1;
        }
        return 2;
    }
    if (strcmp(arg, "-t") == 0 && i + 1 < argc) {
        spec->qtype_s = argv[i + 1];
        return 2;
    }
    if (strcmp(arg, "-q") == 0 && i + 1 < argc) {
        spec->qo.explicit_qname = argv[i + 1];
        return 2;
    }
    if (strcmp(arg, "-u") == 0) {
        spec->dopt.time_unit_usec = true;
        return 1;
    }
    if (strcmp(arg, "-m") == 0) {
        spec->qo.mem_debug = true;
        return 1;
    }
    if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
        usage(argv[0]);
        exit(0);
    }
    if (strcmp(arg, "-r") == 0) {
        /* Handled in pre-scan */
        return 1;
    }
    if (strcmp(arg, "-p") == 0 && i + 1 < argc) {
        char *endptr;
        long pval = strtol(argv[i + 1], &endptr, 10);
        if (*endptr == '\0' && pval > 0 && pval <= 65535) spec->port = (int)pval;
        return 2;
    }
    if (strcmp(arg, "-4") == 0) {
        spec->qo.pref_family = AF_INET;
        return 1;
    }
    if (strcmp(arg, "-6") == 0) {
        spec->qo.pref_family = AF_INET6;
        return 1;
    }
    if (strcmp(arg, "-b") == 0 && i + 1 < argc) {
        const char *b_arg = argv[i + 1];
        char *hash = strchr(b_arg, '#');
        if (hash) {
            int len = hash - b_arg;
            if (len >= (int)sizeof(spec->qo.bind_addr)) len = sizeof(spec->qo.bind_addr) - 1;
            memcpy(spec->qo.bind_addr, b_arg, len);
            spec->qo.bind_addr[len] = '\0';
            char *endptr;
            long bp = strtol(hash + 1, &endptr, 10);
            if (*endptr == '\0' && bp > 0 && bp <= 65535) spec->qo.bind_port = (int)bp;
        } else {
            snprintf(spec->qo.bind_addr, sizeof(spec->qo.bind_addr), "%s", b_arg);
            spec->qo.bind_port = 0;
        }
        return 2;
    }
    if (strcmp(arg, "-f") == 0 && i + 1 < argc) {
        spec->batch_file = argv[i + 1];
        return 2;
    }
    if (strcmp(arg, "-y") == 0 && i + 1 < argc) {
        char *tsig_str = strdup(argv[i + 1]);
        parse_tsig_str(tsig_str, &spec->qo);
        free(tsig_str);
        return 2;
    }
    if (strcmp(arg, "-k") == 0 && i + 1 < argc) {
        parse_tsig_keyfile(argv[i + 1], &spec->qo);
        return 2;
    }
    if (strcmp(arg, "--update-add") == 0 && i + 1 < argc) {
        if (spec->qo.update_op_count < MAX_UPDATE_OPS) {
            spec->qo.update_ops[spec->qo.update_op_count].kind = UPDATE_OP_ADD;
            snprintf(spec->qo.update_ops[spec->qo.update_op_count].raw, sizeof(spec->qo.update_ops[0].raw), "%s", argv[i + 1]);
            spec->qo.update_op_count++;
        } else {
            fprintf(stderr, "warning: too many --update-add/--update-del options, ignoring '%s' (max %d)\n", argv[i + 1], MAX_UPDATE_OPS);
        }
        return 2;
    }
    if (strcmp(arg, "--update-del") == 0 && i + 1 < argc) {
        if (spec->qo.update_op_count < MAX_UPDATE_OPS) {
            spec->qo.update_ops[spec->qo.update_op_count].kind = UPDATE_OP_DEL;
            snprintf(spec->qo.update_ops[spec->qo.update_op_count].raw, sizeof(spec->qo.update_ops[0].raw), "%s", argv[i + 1]);
            spec->qo.update_op_count++;
        } else {
            fprintf(stderr, "warning: too many --update-add/--update-del options, ignoring '%s' (max %d)\n", argv[i + 1], MAX_UPDATE_OPS);
        }
        return 2;
    }
    if (strcmp(arg, "--update-del-exact") == 0 && i + 1 < argc) {
        if (spec->qo.update_op_count < MAX_UPDATE_OPS) {
            spec->qo.update_ops[spec->qo.update_op_count].kind = UPDATE_OP_DEL_EXACT;
            snprintf(spec->qo.update_ops[spec->qo.update_op_count].raw, sizeof(spec->qo.update_ops[0].raw), "%s", argv[i + 1]);
            spec->qo.update_op_count++;
        } else {
            fprintf(stderr, "warning: too many update options, ignoring '%s' (max %d)\n", argv[i + 1], MAX_UPDATE_OPS);
        }
        return 2;
    }
    if (strncmp(arg, "--prereq=", 9) == 0) {
        if (spec->qo.prereq_count >= MAX_PREREQS) {
            fprintf(stderr, "warning: too many --prereq options, ignoring '%s' (max %d)\n", arg, MAX_PREREQS);
        } else {
            char *spec_str = strdup(arg + 9);
            char *kind_str = strtok(spec_str, ":");
            char *name = strtok(NULL, ":");
            char *type_str = strtok(NULL, ":");
            char *rdata = strtok(NULL, "");
            prereq_kind_t kind = PREREQ_NXDOMAIN;
            bool needs_type = false;
            if (kind_str && strcasecmp(kind_str, "nxdomain") == 0) kind = PREREQ_NXDOMAIN;
            else if (kind_str && strcasecmp(kind_str, "yxdomain") == 0) kind = PREREQ_YXDOMAIN;
            else if (kind_str && strcasecmp(kind_str, "nxrrset") == 0) { kind = PREREQ_NXRRSET; needs_type = true; }
            else if (kind_str && strcasecmp(kind_str, "yxrrset") == 0) { kind = PREREQ_YXRRSET; needs_type = true; }
            else { fprintf(stderr, "error: unknown prereq kind '%s'\n", kind_str ? kind_str : "(null)"); free(spec_str); return -1; }

            if (!name || (needs_type && !type_str)) {
                fprintf(stderr, "error: --prereq=%s requires a name%s\n", kind_str, needs_type ? " and a type" : "");
                free(spec_str);
                return -1;
            }

            int p = spec->qo.prereq_count++;
            spec->qo.prereqs[p].kind = kind;
            snprintf(spec->qo.prereqs[p].name, sizeof(spec->qo.prereqs[p].name), "%s", name);
            snprintf(spec->qo.prereqs[p].type_str, sizeof(spec->qo.prereqs[p].type_str), "%s", needs_type ? type_str : "");
            snprintf(spec->qo.prereqs[p].rdata, sizeof(spec->qo.prereqs[p].rdata), "%s", rdata ? rdata : "");
            free(spec_str);
        }
        return 1;
    }
    if (strcmp(arg, "--prereq-nxdomain") == 0 && i + 1 < argc) {
        if (spec->qo.prereq_count < MAX_PREREQS) {
            spec->qo.prereqs[spec->qo.prereq_count].kind = PREREQ_NXDOMAIN;
            snprintf(spec->qo.prereqs[spec->qo.prereq_count].name, sizeof(spec->qo.prereqs[0].name), "%s", argv[i + 1]);
            spec->qo.prereqs[spec->qo.prereq_count].type_str[0] = '\0';
            spec->qo.prereqs[spec->qo.prereq_count].rdata[0] = '\0';
            spec->qo.prereq_count++;
        }
        return 2;
    }
    if (strcmp(arg, "--prereq-yxdomain") == 0 && i + 1 < argc) {
        if (spec->qo.prereq_count < MAX_PREREQS) {
            spec->qo.prereqs[spec->qo.prereq_count].kind = PREREQ_YXDOMAIN;
            snprintf(spec->qo.prereqs[spec->qo.prereq_count].name, sizeof(spec->qo.prereqs[0].name), "%s", argv[i + 1]);
            spec->qo.prereqs[spec->qo.prereq_count].type_str[0] = '\0';
            spec->qo.prereqs[spec->qo.prereq_count].rdata[0] = '\0';
            spec->qo.prereq_count++;
        }
        return 2;
    }
    if (strcmp(arg, "--prereq-nxrrset") == 0 && i + 1 < argc) {
        if (spec->qo.prereq_count < MAX_PREREQS) {
            int p = spec->qo.prereq_count;
            spec->qo.prereqs[p].kind = PREREQ_NXRRSET;
            spec->qo.prereqs[p].rdata[0] = '\0';
            if (strchr(argv[i + 1], ' ') != NULL) {
                char *buf = strdup(argv[i + 1]);
                char *name = strtok(buf, " ");
                char *type_str = strtok(NULL, " ");
                if (name && type_str) {
                    snprintf(spec->qo.prereqs[p].name, sizeof(spec->qo.prereqs[p].name), "%s", name);
                    snprintf(spec->qo.prereqs[p].type_str, sizeof(spec->qo.prereqs[p].type_str), "%s", type_str);
                    spec->qo.prereq_count++;
                }
                free(buf);
                return 2;
            } else if (i + 2 < argc && argv[i + 2][0] != '-' && argv[i + 2][0] != '+' && argv[i + 2][0] != '@') {
                snprintf(spec->qo.prereqs[p].name, sizeof(spec->qo.prereqs[p].name), "%s", argv[i + 1]);
                snprintf(spec->qo.prereqs[p].type_str, sizeof(spec->qo.prereqs[p].type_str), "%s", argv[i + 2]);
                spec->qo.prereq_count++;
                return 3;
            } else {
                fprintf(stderr, "error: --prereq-nxrrset requires <name> <type>\n");
                return -1;
            }
        }
        return get_arg_consume_count(argc, argv, i);
    }
    if (strcmp(arg, "--prereq-yxrrset") == 0 && i + 1 < argc) {
        if (spec->qo.prereq_count < MAX_PREREQS) {
            int p = spec->qo.prereq_count;
            spec->qo.prereqs[p].kind = PREREQ_YXRRSET;
            spec->qo.prereqs[p].rdata[0] = '\0';
            if (strchr(argv[i + 1], ' ') != NULL) {
                char *buf = strdup(argv[i + 1]);
                char *name = strtok(buf, " ");
                char *type_str = strtok(NULL, " ");
                char *rdata = strtok(NULL, "");
                if (name && type_str) {
                    snprintf(spec->qo.prereqs[p].name, sizeof(spec->qo.prereqs[p].name), "%s", name);
                    snprintf(spec->qo.prereqs[p].type_str, sizeof(spec->qo.prereqs[p].type_str), "%s", type_str);
                    if (rdata) {
                        while (*rdata == ' ') rdata++;
                        snprintf(spec->qo.prereqs[p].rdata, sizeof(spec->qo.prereqs[p].rdata), "%s", rdata);
                    }
                    spec->qo.prereq_count++;
                }
                free(buf);
                return 2;
            } else if (i + 2 < argc && argv[i + 2][0] != '-' && argv[i + 2][0] != '+' && argv[i + 2][0] != '@') {
                snprintf(spec->qo.prereqs[p].name, sizeof(spec->qo.prereqs[p].name), "%s", argv[i + 1]);
                snprintf(spec->qo.prereqs[p].type_str, sizeof(spec->qo.prereqs[p].type_str), "%s", argv[i + 2]);
                int consumed = 3;
                if (i + 3 < argc && argv[i + 3][0] != '-' && argv[i + 3][0] != '+' && argv[i + 3][0] != '@') {
                    snprintf(spec->qo.prereqs[p].rdata, sizeof(spec->qo.prereqs[p].rdata), "%s", argv[i + 3]);
                    consumed = 4;
                }
                spec->qo.prereq_count++;
                return consumed;
            } else {
                fprintf(stderr, "error: --prereq-yxrrset requires <name> <type> [rdata]\n");
                return -1;
            }
        }
        return get_arg_consume_count(argc, argv, i);
    }
    if (strcmp(arg, "--break") == 0 && i + 1 < argc) {
        char *brk = argv[i + 1];
        if (strcmp(brk, "all") == 0) {
            spec->test_all = true;
        } else {
            parse_break_arg(brk);
        }
        return 2;
    }

    if (arg[0] == '-' || arg[0] == '+') {
        if (strcmp(arg, "+tcp") == 0 || strcmp(arg, "--tcp") == 0 || strcmp(arg, "+vc") == 0) {
            spec->use_tcp = true; spec->qo.use_tcp = true;
        } else if (strcmp(arg, "+novc") == 0) {
            spec->use_tcp = false; spec->qo.use_tcp = false;
        } else if (strcmp(arg, "+udp") == 0) {
            spec->force_udp = true;
        } else if (strcmp(arg, "+ignore") == 0) {
            spec->qo.ignore_tc = true;
        } else if (strcmp(arg, "+noignore") == 0) {
            spec->qo.ignore_tc = false;
        } else if (strcmp(arg, "+fail") == 0) {
            spec->qo.nofail = false;
        } else if (strcmp(arg, "+nofail") == 0) {
            spec->qo.nofail = true;
        } else if (strcmp(arg, "+ldnsz") == 0) {
            spec->use_ldnsz = true;
        } else if (strcmp(arg, "+noldnsz") == 0) {
            spec->use_ldnsz = false;
        } else if (strcmp(arg, "+allcompare") == 0) {
            g_want_allcompare = true;
        } else if (strcmp(arg, "+noall") == 0) {
            spec->dopt.show_question = spec->dopt.show_answer = spec->dopt.show_authority =
                spec->dopt.show_additional = spec->dopt.show_comments = spec->dopt.show_stats =
                spec->dopt.show_cmd = false;
        } else if (strcmp(arg, "+all") == 0) {
            spec->dopt.show_question = spec->dopt.show_answer = spec->dopt.show_authority =
                spec->dopt.show_additional = spec->dopt.show_comments = spec->dopt.show_stats =
                spec->dopt.show_cmd = true;
        } else if (strcmp(arg, "+answer") == 0) {
            spec->dopt.show_answer = true;
        } else if (strcmp(arg, "+noanswer") == 0) {
            spec->dopt.show_answer = false;
        } else if (strcmp(arg, "+authority") == 0) {
            spec->dopt.show_authority = true;
        } else if (strcmp(arg, "+noauthority") == 0) {
            spec->dopt.show_authority = false;
        } else if (strcmp(arg, "+additional") == 0) {
            spec->dopt.show_additional = true;
        } else if (strcmp(arg, "+noadditional") == 0) {
            spec->dopt.show_additional = false;
        } else if (strcmp(arg, "+question") == 0) {
            spec->dopt.show_question = true;
        } else if (strcmp(arg, "+noquestion") == 0) {
            spec->dopt.show_question = false;
        } else if (strcmp(arg, "+comments") == 0) {
            spec->dopt.show_comments = true;
        } else if (strcmp(arg, "+nocomments") == 0) {
            spec->dopt.show_comments = false;
        } else if (strcmp(arg, "+stats") == 0) {
            spec->dopt.show_stats = true;
        } else if (strcmp(arg, "+nostats") == 0) {
            spec->dopt.show_stats = false;
        } else if (strcmp(arg, "+identify") == 0) {
            spec->dopt.identify = true;
        } else if (strcmp(arg, "+noidentify") == 0) {
            spec->dopt.identify = false;
        } else if (strcmp(arg, "+multiline") == 0 || strcmp(arg, "+multi") == 0) {
            spec->dopt.multiline = true;
            if (spec->dopt.split_width == 56) spec->dopt.split_width = 44;
        } else if (strcmp(arg, "+nomultiline") == 0 || strcmp(arg, "+nomulti") == 0) {
            spec->dopt.multiline = false;
            if (spec->dopt.split_width == 44) spec->dopt.split_width = 56;
        } else if (strcmp(arg, "+expandaaaa") == 0) {
            spec->dopt.expandaaaa = true;
        } else if (strcmp(arg, "+noexpandaaaa") == 0) {
            spec->dopt.expandaaaa = false;
        } else if (strcmp(arg, "+yaml") == 0) {
            spec->dopt.yaml = true;
        } else if (strcmp(arg, "+noyaml") == 0) {
            spec->dopt.yaml = false;
        } else if (strcmp(arg, "+trace") == 0) {
            spec->do_trace = true;
        } else if (strcmp(arg, "+notrace") == 0) {
            spec->do_trace = false;
        } else if (strcmp(arg, "+nssearch") == 0) {
            spec->do_nssearch = true;
        } else if (strcmp(arg, "+nonssearch") == 0) {
            spec->do_nssearch = false;
        } else if (strcmp(arg, "+search") == 0 || strcmp(arg, "+defname") == 0) {
            spec->qo.use_search_list = true;
        } else if (strcmp(arg, "+nosearch") == 0 || strcmp(arg, "+nodefname") == 0) {
            spec->qo.use_search_list = false;
        } else if (strncmp(arg, "+domain=", 8) == 0) {
            spec->qo.search_domain = strdup(arg + 8);
            spec->qo.use_search_list = true;
        } else if (strncmp(arg, "+ndots=", 7) == 0) {
            spec->qo.ndots = atoi(arg + 7);
        } else if (strcmp(arg, "+class") == 0) {
            spec->dopt.show_class = true;
        } else if (strcmp(arg, "+noclass") == 0) {
            spec->dopt.show_class = false;
        } else if (strcmp(arg, "+crypto") == 0) {
            spec->dopt.show_crypto = true;
        } else if (strcmp(arg, "+nocrypto") == 0) {
            spec->dopt.show_crypto = false;
        } else if (strcmp(arg, "+besteffort") == 0) {
            spec->dopt.besteffort = true;
        } else if (strcmp(arg, "+nobesteffort") == 0) {
            spec->dopt.besteffort = false;
        } else if (strcmp(arg, "+badcookie") == 0) {
            spec->qo.want_opt = true;
            spec->qo.want_cookie = true;
            spec->qo.retry_on_badcookie = true;
            bool all_zero = true;
            for (int k = 0; k < 8; k++) { if (spec->qo.client_cookie[k] != 0) { all_zero = false; break; } }
            if (all_zero) {
                for (int k = 0; k < 8; k++) spec->qo.client_cookie[k] = (uint8_t)(arc4random() & 0xFF);
            }
        } else if (strcmp(arg, "+nobadcookie") == 0) {
            spec->qo.retry_on_badcookie = false;
        } else if (strcmp(arg, "+showbadcookie") == 0) {
            spec->dopt.show_badcookie_msg = true;
        } else if (strcmp(arg, "+noshowbadcookie") == 0) {
            spec->dopt.show_badcookie_msg = false;
        } else if (strcmp(arg, "+ednsnegotiation") == 0) {
            spec->qo.edns_negotiation = true;
        } else if (strcmp(arg, "+noednsnegotiation") == 0) {
            spec->qo.edns_negotiation = false;
        } else if (strcmp(arg, "+showbadvers") == 0) {
            spec->dopt.show_badvers_msg = true;
        } else if (strcmp(arg, "+noshowbadvers") == 0) {
            spec->dopt.show_badvers_msg = false;
        } else if (strcmp(arg, "+qr") == 0) {
            spec->dopt.show_query_message = true;
        } else if (strcmp(arg, "+noqr") == 0) {
            spec->dopt.show_query_message = false;
        } else if (strcmp(arg, "+rrcomments") == 0) {
            spec->dopt.rrcomments = true;
        } else if (strcmp(arg, "+norrcomments") == 0) {
            spec->dopt.rrcomments = false;
        } else if (strcmp(arg, "+onesoa") == 0) {
            spec->dopt.onesoa = true;
        } else if (strcmp(arg, "+noonesoa") == 0) {
            spec->dopt.onesoa = false;
        } else if (strncmp(arg, "+split=", 7) == 0) {
            int w = atoi(arg + 7);
            if (w < 0) w = 0;
            spec->dopt.split_width = (w == 0) ? 0 : ((w + 3) / 4) * 4;
        } else if (strcmp(arg, "+nosplit") == 0) {
            spec->dopt.split_width = 0;
        } else if (strcmp(arg, "+unknownformat") == 0) {
            spec->dopt.force_unknown_format = true;
        } else if (strcmp(arg, "+nounknownformat") == 0) {
            spec->dopt.force_unknown_format = false;
        } else if (strcmp(arg, "+ttlunits") == 0) {
            spec->dopt.ttlunits = true; spec->dopt.ttlid = true;
        } else if (strcmp(arg, "+nottlunits") == 0) {
            spec->dopt.ttlunits = false;
        } else if (strcmp(arg, "+ttlid") == 0) {
            spec->dopt.ttlid = true;
        } else if (strcmp(arg, "+nottlid") == 0) {
            spec->dopt.ttlid = false;
        } else if (strcmp(arg, "+expire") == 0) {
            spec->dopt.expire = true;
            spec->qo.want_opt = true;
            spec->qo.want_expire_opt = true;
        } else if (strcmp(arg, "+noexpire") == 0) {
            spec->dopt.expire = false;
            spec->qo.want_expire_opt = false;
        } else if (strcmp(arg, "+showsearch") == 0) {
            spec->dopt.showsearch = true;
        } else if (strcmp(arg, "+noshowsearch") == 0) {
            spec->dopt.showsearch = false;
        } else if (strcmp(arg, "+idn") == 0) {
            spec->qo.idnin = true;
            spec->dopt.idnout = true;
        } else if (strcmp(arg, "+noidn") == 0) {
            spec->qo.idnin = false;
            spec->dopt.idnout = false;
        } else if (strcmp(arg, "+idnin") == 0) {
            spec->qo.idnin = true;
        } else if (strcmp(arg, "+noidnin") == 0) {
            spec->qo.idnin = false;
        } else if (strcmp(arg, "+idnout") == 0) {
            spec->dopt.idnout = true;
        } else if (strcmp(arg, "+noidnout") == 0) {
            spec->dopt.idnout = false;
        } else if (strcmp(arg, "--version") == 0 || strcmp(arg, "-v") == 0) {
            printf("KariDNS dag v%s\n", KARIDNS_VERSION);
            exit(0);
        } else if (strcmp(arg, "+norec") == 0 || strcmp(arg, "+norecurse") == 0 || strcmp(arg, "+nordflag") == 0) {
            spec->norecurse = true; spec->qo.rd_flag = false;
        } else if (strcmp(arg, "+rec") == 0 || strcmp(arg, "+recurse") == 0 || strcmp(arg, "+rdflag") == 0) {
            spec->norecurse = false; spec->qo.rd_flag = true;
        } else if (strcmp(arg, "+raflag") == 0) {
            spec->qo.ra_flag = true;
        } else if (strcmp(arg, "+noraflag") == 0) {
            spec->qo.ra_flag = false;
        } else if (strcmp(arg, "+aaonly") == 0 || strcmp(arg, "+aaflag") == 0) {
            spec->aaflag = true; spec->qo.aa_flag = true;
        } else if (strcmp(arg, "+noaaonly") == 0 || strcmp(arg, "+noaaflag") == 0) {
            spec->aaflag = false; spec->qo.aa_flag = false;
        } else if (strcmp(arg, "+coflag") == 0 || strcmp(arg, "+co") == 0) {
            spec->qo.want_opt = true; spec->qo.compact_answers_ok = true;
        } else if (strcmp(arg, "+nocoflag") == 0 || strcmp(arg, "+noco") == 0) {
            spec->qo.compact_answers_ok = false;
        } else if (strncmp(arg, "+ednsflags=", 11) == 0) {
            spec->qo.want_opt = true; spec->qo.ednsflags_z = (uint16_t)strtol(arg + 11, NULL, 0);
        } else if (strcmp(arg, "+ednsflags") == 0 || strcmp(arg, "+noednsflags") == 0) {
            spec->qo.ednsflags_z = 0;
        } else if (strncmp(arg, "+opcode=", 8) == 0) {
            spec->qo.opcode_override = parse_opcode_value(arg + 8);
        } else if (strcmp(arg, "+noopcode") == 0) {
            spec->qo.opcode_override = -1;
        } else if (strncmp(arg, "+qid=", 5) == 0) {
            spec->qo.qid_override = atoi(arg + 5);
        } else if (strcmp(arg, "+header-only") == 0) {
            spec->qo.header_only = true;
        } else if (strcmp(arg, "+noheader-only") == 0) {
            spec->qo.header_only = false;
        } else if (strcmp(arg, "+keepalive") == 0) {
            spec->qo.want_opt = true; spec->qo.send_keepalive = true;
        } else if (strcmp(arg, "+nokeepalive") == 0) {
            spec->qo.send_keepalive = false;
        } else if (strcmp(arg, "+keepopen") == 0) {
            spec->qo.keep_tcp_open = true;
        } else if (strcmp(arg, "+nokeepopen") == 0) {
            spec->qo.keep_tcp_open = false;
        } else if (strncmp(arg, "+fuzztime=", 10) == 0) {
            spec->qo.fuzztime = strtoll(arg + 10, NULL, 10);
        } else if (strcmp(arg, "+fuzztime") == 0) {
            spec->qo.fuzztime = 1646972129;
        } else if (strcmp(arg, "+nofuzztime") == 0) {
            spec->qo.fuzztime = 0;
        } else if (strcmp(arg, "+dns64prefix") == 0) {
            spec->qo.want_opt = true; spec->qo.check_dns64prefix = true;
        } else if (strcmp(arg, "+nodns64prefix") == 0) {
            spec->qo.check_dns64prefix = false;
        } else if (strncmp(arg, "+proxy=", 7) == 0) {
            spec->qo.use_proxy = true; spec->qo.proxy_use_local_cmd = false; parse_proxy_arg(arg + 7, &spec->qo);
        } else if (strcmp(arg, "+proxy") == 0) {
            spec->qo.use_proxy = true; spec->qo.proxy_use_local_cmd = true;
        } else if (strcmp(arg, "+noproxy") == 0) {
            spec->qo.use_proxy = false;
        } else if (strncmp(arg, "+proxy-plain=", 13) == 0) {
            spec->qo.use_proxy = true; spec->qo.proxy_use_local_cmd = false; parse_proxy_arg(arg + 13, &spec->qo);
        } else if (strcmp(arg, "+proxy-plain") == 0) {
            spec->qo.use_proxy = true; spec->qo.proxy_use_local_cmd = true;
        } else if (strcmp(arg, "+noproxy-plain") == 0) {
            spec->qo.use_proxy = false;
        } else if (strcmp(arg, "+tls") == 0) {
            spec->qo.use_tls = true; if (spec->port == 53) spec->port = 853;
        } else if (strcmp(arg, "+notls") == 0) {
            spec->qo.use_tls = false; if (spec->port == 853) spec->port = 53;
        } else if (strncmp(arg, "+tls-ca=", 8) == 0) {
            spec->qo.tls_ca_file = strdup(arg + 8);
        } else if (strcmp(arg, "+tls-ca") == 0) {
            spec->qo.tls_verify_default_store = true;
        } else if (strcmp(arg, "+notls-ca") == 0) {
            spec->qo.tls_verify_default_store = false;
        } else if (strncmp(arg, "+tls-certfile=", 14) == 0) {
            spec->qo.tls_certfile = strdup(arg + 14);
        } else if (strncmp(arg, "+tls-keyfile=", 13) == 0) {
            spec->qo.tls_keyfile = strdup(arg + 13);
        } else if (strncmp(arg, "+tls-hostname=", 14) == 0) {
            spec->qo.tls_hostname = strdup(arg + 14);
        } else if (strncmp(arg, "+https=", 7) == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = true; spec->qo.doh_path = strdup(arg + 7); if (spec->port == 53) spec->port = 443;
        } else if (strcmp(arg, "+https") == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = true; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 443;
        } else if (strncmp(arg, "+https-get=", 11) == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_GET; spec->qo.doh_tls = true; spec->qo.doh_path = strdup(arg + 11); if (spec->port == 53) spec->port = 443;
        } else if (strcmp(arg, "+https-get") == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_GET; spec->qo.doh_tls = true; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 443;
        } else if (strncmp(arg, "+https-post=", 12) == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = true; spec->qo.doh_path = strdup(arg + 12); if (spec->port == 53) spec->port = 443;
        } else if (strcmp(arg, "+https-post") == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = true; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 443;
        } else if (strncmp(arg, "+http-plain=", 12) == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = false; spec->qo.doh_path = strdup(arg + 12); if (spec->port == 53) spec->port = 80;
        } else if (strcmp(arg, "+http-plain") == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = false; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 80;
        } else if (strncmp(arg, "+http-plain-get=", 16) == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_GET; spec->qo.doh_tls = false; spec->qo.doh_path = strdup(arg + 16); if (spec->port == 53) spec->port = 80;
        } else if (strcmp(arg, "+http-plain-get") == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_GET; spec->qo.doh_tls = false; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 80;
        } else if (strncmp(arg, "+http-plain-post=", 17) == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = false; spec->qo.doh_path = strdup(arg + 17); if (spec->port == 53) spec->port = 80;
        } else if (strcmp(arg, "+http-plain-post") == 0) {
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = false; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 80;
        } else if (strcmp(arg, "+nohttps") == 0 || strcmp(arg, "+nohttp-plain") == 0) {
            spec->qo.use_doh = false;
            if (spec->port == 443 || spec->port == 80) spec->port = 53;
        } else if (strcmp(arg, "+nohexdump") == 0) {
            spec->no_hexdump_query = true;
            spec->no_hexdump_response = true;
        } else if (strcmp(arg, "+hexdump") == 0) {
            spec->no_hexdump_query = false;
            spec->no_hexdump_response = false;
        } else if (strcmp(arg, "+nohexdump-query") == 0) {
            spec->no_hexdump_query = true;
        } else if (strcmp(arg, "+hexdump-query") == 0) {
            spec->no_hexdump_query = false;
        } else if (strcmp(arg, "+nohexdump-response") == 0) {
            spec->no_hexdump_response = true;
        } else if (strcmp(arg, "+hexdump-response") == 0) {
            spec->no_hexdump_response = false;
        } else if (strcmp(arg, "+edns") == 0) {
            spec->qo.want_opt = true;
        } else if (strncmp(arg, "+edns=", 6) == 0) {
            spec->qo.want_opt = true;
            spec->qo.edns_version = (uint8_t)strtoul(arg + 6, NULL, 10);
        } else if (strcmp(arg, "+noedns") == 0) {
            spec->qo.want_opt = false;
        } else if (strcmp(arg, "+dnssec") == 0 || strcmp(arg, "+do") == 0) {
            spec->qo.want_opt = true; spec->qo.dnssec_ok = true;
        } else if (strcmp(arg, "+nodo") == 0 || strcmp(arg, "+nodnssec") == 0) {
            spec->qo.dnssec_ok = false;
        } else if (strcmp(arg, "+nsid") == 0) {
            spec->qo.want_opt = true; spec->qo.want_nsid = true;
        } else if (strcmp(arg, "+nonsid") == 0) {
            spec->qo.want_nsid = false;
        } else if (strncmp(arg, "+bufsize=", 9) == 0) {
            char *endptr;
            long bsz = strtol(arg + 9, &endptr, 10);
            if (*endptr == '\0' && bsz >= 0 && bsz <= 65535) {
                spec->qo.want_opt = true; spec->qo.udp_payload_size = (uint16_t)bsz;
            }
        } else if (strcmp(arg, "+adflag") == 0) {
            spec->adflag = true; spec->qo.ad_flag = true;
        } else if (strcmp(arg, "+noadflag") == 0) {
            spec->adflag = false; spec->qo.ad_flag = false;
        } else if (strcmp(arg, "+cdflag") == 0) {
            spec->cdflag = true; spec->qo.cd_flag = true;
        } else if (strcmp(arg, "+nocdflag") == 0) {
            spec->cdflag = false; spec->qo.cd_flag = false;
        } else if (strcmp(arg, "+tcflag") == 0) {
            spec->tcflag = true; spec->qo.tc_flag = true;
        } else if (strcmp(arg, "+notcflag") == 0) {
            spec->tcflag = false; spec->qo.tc_flag = false;
        } else if (strcmp(arg, "+zflag") == 0) {
            spec->zflag = true; spec->qo.z_flag = true;
        } else if (strcmp(arg, "+nozflag") == 0) {
            spec->zflag = false; spec->qo.z_flag = false;
        } else if (strncmp(arg, "+tcp-mss=", 9) == 0) {
            spec->use_tcp = true; spec->qo.use_tcp = true;
            spec->qo.tcp_mss = atoi(arg + 9);
        } else if (strncmp(arg, "+tcp-window=", 12) == 0) {
            spec->use_tcp = true; spec->qo.use_tcp = true;
            spec->qo.tcp_window = atoi(arg + 12);
        } else if (strncmp(arg, "+timeout=", 9) == 0 || strncmp(arg, "+time=", 6) == 0) {
            const char *val = (arg[5] == '=') ? arg + 6 : arg + 9;
            char *endptr;
            long to = strtol(val, &endptr, 10);
            if (*endptr == '\0' && to >= 0) spec->qo.timeout_sec = (int)to;
        } else if (strncmp(arg, "+tries=", 7) == 0) {
            char *endptr;
            long tr = strtol(arg + 7, &endptr, 10);
            if (*endptr == '\0' && tr >= 0) spec->qo.tries = (int)tr;
        } else if (strncmp(arg, "+retry=", 7) == 0) {
            char *endptr;
            long tr = strtol(arg + 7, &endptr, 10);
            if (*endptr == '\0' && tr >= 0) spec->qo.tries = (int)tr + 1;
        } else if (strncmp(arg, "+padding=", 9) == 0) {
            char *endptr;
            long pd = strtol(arg + 9, &endptr, 10);
            if (*endptr == '\0' && pd >= 0) {
                spec->qo.want_opt = true; spec->qo.want_padding = true;
                spec->qo.padding_size = (int)pd;
            }
        } else if (strcmp(arg, "+nopadding") == 0) {
            spec->qo.want_padding = false;
            spec->qo.padding_size = -1;
        } else if (strncmp(arg, "+mqtype=", 8) == 0) {
            spec->qo.want_opt = true;
            if (spec->qo.custom_edns_opt_count < 8) {
                char *mqstr = strdup(arg + 8);
                char *token = strtok(mqstr, ",");
                uint16_t mqtypes[16];
                int mq_count = 0;
                while (token && mq_count < 16) {
                    mqtypes[mq_count++] = parse_qtype(token);
                    token = strtok(NULL, ",");
                }
                spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].code = 20;
                spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].len = mq_count * 2;
                for (int m = 0; m < mq_count; m++) {
                    spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].data[m*2] = mqtypes[m] >> 8;
                    spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].data[m*2+1] = mqtypes[m] & 0xFF;
                }
                spec->qo.custom_edns_opt_count++;
                free(mqstr);
            }
        } else if (strcmp(arg, "+noednsopt") == 0) {
            spec->qo.custom_edns_opt_count = 0;
        } else if (strncmp(arg, "+ednsopt=", 9) == 0) {
            spec->qo.want_opt = true;
            if (spec->qo.custom_edns_opt_count < 8) {
                const char *val = arg + 9;
                char *colon = strchr(val, ':');
                if (colon) {
                    spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].code = (uint16_t)strtoul(val, NULL, 10);
                    const char *hex = colon + 1;
                    size_t hex_len = strlen(hex);
                    size_t bytes = hex_len / 2;
                    if (bytes > sizeof(spec->qo.custom_edns_opts[0].data)) bytes = sizeof(spec->qo.custom_edns_opts[0].data);
                    spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].len = (uint16_t)bytes;
                    for (size_t j = 0; j < bytes; j++) {
                        unsigned int b; sscanf(hex + j * 2, "%02x", &b);
                        spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].data[j] = (uint8_t)b;
                    }
                } else {
                    spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].code = (uint16_t)strtoul(val, NULL, 10);
                    spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].len = 0;
                }
                spec->qo.custom_edns_opt_count++;
            }
        } else if (strncmp(arg, "+subnet=", 8) == 0) {
            if (parse_subnet_arg(arg + 8, &spec->qo)) { spec->qo.want_opt = true; spec->qo.want_subnet = true; }
        } else if (strcmp(arg, "+nosubnet") == 0) {
            spec->qo.want_subnet = false;
        } else if (strcmp(arg, "+cookie") == 0 || strncmp(arg, "+cookie=", 8) == 0) {
            spec->qo.want_opt = true; spec->qo.want_cookie = true;
            if (arg[7] == '=') {
                const char *hex = arg + 8;
                size_t hex_len = strlen(hex);
                if (hex_len > 64) hex_len = 64;
                uint8_t full[32]; size_t full_len = hex_len / 2;
                for (size_t j = 0; j < full_len; j++) {
                    unsigned int byte; sscanf(hex + j * 2, "%02x", &byte); full[j] = (uint8_t)byte;
                }
                if (full_len >= 8) {
                    memcpy(spec->qo.client_cookie, full, 8);
                    if (full_len > 8) { spec->qo.server_cookie_len = full_len - 8; memcpy(spec->qo.server_cookie, full + 8, spec->qo.server_cookie_len); }
                } else {
                    for (int k = 0; k < 8; k++) spec->qo.client_cookie[k] = (uint8_t)(k + 1);
                }
            } else {
                for (int k = 0; k < 8; k++) spec->qo.client_cookie[k] = (uint8_t)(arc4random() & 0xFF);
            }
        } else if (strcmp(arg, "+nocookie") == 0) {
            spec->qo.want_cookie = false;
        } else if (strncmp(arg, "+tsig=", 6) == 0) {
            char *tsig_str = strdup(arg + 6);
            parse_tsig_str(tsig_str, &spec->qo);
            free(tsig_str);
        } else if (strcmp(arg, "--test-all") == 0) {
            spec->test_all = true;
        } else {
            fprintf(stderr, "Invalid option: %s\n", arg);
            fprintf(stderr, "Usage:  dag [@server] [-p port] [name] [type] [options]\n");
            return -1;
        }
        return 1;
    }

    // 位置引数: CLASS / TYPE / NAME (任意順序対応)
    uint16_t cls_val = 0;
    if (is_known_qclass_str(arg, &cls_val)) {
        spec->qo.qclass = cls_val;
    } else if (is_known_qtype(arg)) {
        if (!spec->qtype_s) {
            spec->qtype_s = arg;
        } else if (!spec->qname) {
            spec->qname = arg;
        }
    } else {
        if (!spec->qname) {
            spec->qname = arg;
        } else if (!spec->qtype_s) {
            spec->qtype_s = arg;
        }
    }
    return 1;
}

static int parse_arg_slice(int start, int end, int argc, char **argv, query_spec_t *spec) {
    for (int i = start; i < end; ) {
        int rc = parse_query_arg_token(argc, argv, i, spec);
        if (rc < 0) return -1;
        i += rc;
    }
    return 0;
}


static int execute_batch_spec(const query_spec_t *spec) {
    if (!spec->batch_file) return 0;
    FILE *bf = fopen(spec->batch_file, "r");
    if (!bf) {
        fprintf(stderr, "error: could not open batch file '%s': %s\n", spec->batch_file, strerror(errno));
        exit(8);
    }
    char line[512];
    while (fgets(line, sizeof(line), bf)) {
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        
        char *b_qname = NULL;
        char *b_qtype = NULL;
        char *b_server = NULL;
        int extra_tokens = 0;
        char orig_line[512];
        snprintf(orig_line, sizeof(orig_line), "%s", p);
        char *nl = strchr(orig_line, '\n');
        if (nl) *nl = '\0';
        char *cr = strchr(orig_line, '\r');
        if (cr) *cr = '\0';

        char *tok = strtok(p, " \t\r\n");
        while (tok) {
            if (tok[0] == '@') {
                if (!b_server) b_server = tok + 1;
                else extra_tokens++;
            } else if (strcasecmp(tok, "IN") == 0 || strcasecmp(tok, "CH") == 0 || strcasecmp(tok, "HS") == 0) {
                // ignore class
            } else if (is_known_qtype(tok)) {
                if (!b_qtype) b_qtype = tok;
                else if (!b_qname) b_qname = tok;
                else extra_tokens++;
            } else {
                if (!b_qname) b_qname = tok;
                else if (!b_qtype) b_qtype = tok;
                else extra_tokens++;
            }
            tok = strtok(NULL, " \t\r\n");
        }
        if (extra_tokens > 0) {
            fprintf(stderr, "warning: batch file line has %d unexpected extra token(s), ignoring: %s\n", extra_tokens, orig_line);
        }
        if (!b_qname) continue;
        if (!b_qtype) b_qtype = "A";
        
        query_opts_t qo = spec->qo;
        bool b_allocated = false;
        qo.orig_qname = b_qname;
        qo.orig_qtype_s = b_qtype;
        if (qo.idnin) b_qname = (char *)idn_to_ascii(b_qname, &b_allocated);
        const char *eff_server = b_server ? b_server : spec->server_arg;
        if (spec->do_trace) {
            run_trace_query(b_qname, eff_server, b_qtype, spec->port, spec->use_tcp, spec->force_udp,
                            spec->no_hexdump_query, spec->no_hexdump_response, qo, spec->hex_payload, &spec->dopt);
        } else if (spec->do_nssearch) {
            run_nssearch(b_qname, eff_server, spec->port, spec->use_tcp, spec->force_udp,
                         spec->no_hexdump_query, spec->no_hexdump_response, qo, spec->hex_payload, &spec->dopt);
        } else {
            run_single_job(b_qname, b_qtype, eff_server, spec->port, spec->use_tcp, spec->force_udp,
                           spec->test_all, spec->norecurse,
                           spec->adflag, spec->cdflag, spec->aaflag, spec->tcflag, spec->zflag,
                           spec->no_hexdump_query, spec->no_hexdump_response, qo, spec->hex_payload, &spec->dopt);
        }
#ifdef HAVE_LIBIDN2
        if (b_allocated) idn2_free((void *)b_qname);
#endif
    }
    fclose(bf);
    return 0;
}

static int execute_query_spec(query_spec_t *spec) {
    spec->qo.orig_qname = spec->qname;
    spec->qo.orig_qtype_s = spec->qtype_s;

    if (spec->qo.explicit_qname) spec->qname = spec->qo.explicit_qname;
    if (!spec->qname) {
        spec->qname = ".";
        if (!spec->qtype_s) spec->qtype_s = "NS";
    } else {
        if (!spec->qtype_s) {
            if (strcmp(spec->qname, ".") == 0) spec->qtype_s = "NS";
            else spec->qtype_s = "A";
        }
    }

    static char resolv_server_buf[260];
    if (!spec->server_arg) {
        const char *sys_resolver = get_system_resolver();
        snprintf(resolv_server_buf, sizeof(resolv_server_buf), "%s", sys_resolver);
        spec->server_arg = resolv_server_buf;
    }

    bool q_allocated = false;
    if (spec->qo.idnin) spec->qname = (char *)idn_to_ascii(spec->qname, &q_allocated);

    int exit_code = 0;
    if (spec->do_trace) {
        exit_code = run_trace_query(spec->qname, spec->server_arg, spec->qtype_s, spec->port, spec->use_tcp, spec->force_udp,
                                    spec->no_hexdump_query, spec->no_hexdump_response, spec->qo, spec->hex_payload, &spec->dopt);
    } else if (spec->do_nssearch) {
        exit_code = run_nssearch(spec->qname, spec->server_arg, spec->port, spec->use_tcp, spec->force_udp,
                                 spec->no_hexdump_query, spec->no_hexdump_response, spec->qo, spec->hex_payload, &spec->dopt);
    } else {
        exit_code = run_single_job(spec->qname, spec->qtype_s, spec->server_arg, spec->port, spec->use_tcp, spec->force_udp,
                                   spec->test_all, spec->norecurse,
                                   spec->adflag, spec->cdflag, spec->aaflag, spec->tcflag, spec->zflag,
                                   spec->no_hexdump_query, spec->no_hexdump_response, spec->qo, spec->hex_payload, &spec->dopt);
    }

#ifdef HAVE_LIBIDN2
    if (q_allocated) idn2_free((void *)spec->qname);
#endif

    return exit_code;
}

int main(int argc, char **argv) {
#ifndef _WIN32
    // サーバーからのTCP切断時におけるSIGPIPEによるプロセス強制終了を防止
    signal(SIGPIPE, SIG_IGN);
#endif
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
    srand((unsigned int)time(NULL) ^ (unsigned int)GetCurrentProcessId());
#else
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
#endif
    setlocale(LC_ALL, "");
    zone_arena_init(&g_dag_arena);
    if (argc >= 2 && strcmp(argv[1], "--break-help") == 0) { print_break_help(); return 0; }
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) { usage(argv[0]); return 0; }

    bool skip_digrc = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) { skip_digrc = true; break; }
    }
    if (!skip_digrc) {
        const char *home = getenv("HOME");
        if (home) {
            char digrc_path[PATH_MAX];
            snprintf(digrc_path, sizeof(digrc_path), "%s/.digrc", home);
            FILE *f = fopen(digrc_path, "r");
            if (f) {
                char line[1024];
                char **prepend_argv = NULL;
                int prepend_count = 0;
                while (fgets(line, sizeof(line), f)) {
                    char *p = line;
                    while (isspace((unsigned char)*p)) p++;
                    if (*p == '#' || *p == ';' || *p == '\0') continue;
                    char *saveptr = NULL;
                    char *tok = strtok_r(p, " \t\r\n", &saveptr);
                    while (tok) {
                        char **tmp = realloc(prepend_argv, sizeof(char*) * (prepend_count + 1));
                        if (!tmp) { fclose(f); exit(10); }
                        prepend_argv = tmp;
                        char *dup = strdup(tok);
                        if (!dup) { fclose(f); exit(10); }
                        prepend_argv[prepend_count++] = dup;
                        tok = strtok_r(NULL, " \t\r\n", &saveptr);
                    }
                }
                fclose(f);
                if (prepend_count > 0) {
                    int new_argc = 1 + prepend_count + (argc - 1);
                    char **new_argv = malloc(sizeof(char*) * (new_argc + 1));
                    if (!new_argv) exit(10);
                    new_argv[0] = argv[0];
                    for (int k = 0; k < prepend_count; k++) new_argv[1 + k] = prepend_argv[k];
                    for (int k = 1; k < argc; k++) new_argv[1 + prepend_count + (k - 1)] = argv[k];
                    new_argv[new_argc] = NULL;
                    argc = new_argc;
                    argv = new_argv;
                    free(prepend_argv);
                }
            }
        }
    }

    query_spec_t global_spec;
    init_query_spec(&global_spec);

    // 全域グローバルオプションのプレスキャン
    prescan_always_global_options(argc, argv, &global_spec);

    // クエリタプルの境界検出 (Token Slicing)
    int global_end = 1;
    arg_slice_t queries[MAX_DAG_QUERIES];
    int query_count = 0;

    bool in_queries = false;
    bool cur_has_name = false;
    bool cur_has_type = false;
    bool cur_has_class = false;
    int cur_start = 1;

    for (int i = 1; i < argc; ) {
        int count = get_arg_consume_count(argc, argv, i);
        const char *arg = argv[i];

        bool is_name_arg = false;
        bool is_type_arg = false;
        bool is_class_arg = false;
        bool is_reverse = false;

        if (arg[0] == '@' || arg[0] == '-' || arg[0] == '+') {
            if (strcmp(arg, "-x") == 0) {
                is_reverse = true;
                is_name_arg = true;
                is_type_arg = true;
                is_class_arg = true;
            } else if (strcmp(arg, "-q") == 0) {
                is_name_arg = true;
            } else if (strcmp(arg, "-t") == 0) {
                is_type_arg = true;
            } else if (strcmp(arg, "-c") == 0) {
                is_class_arg = true;
            } else if (strcmp(arg, "--hex") == 0 || strncmp(arg, "--hex=", 6) == 0) {
                is_name_arg = true;
                is_type_arg = true;
            }
        } else {
            // 位置引数
            if (is_known_qclass_str(arg, NULL)) {
                is_class_arg = true;
            } else if (is_known_qtype(arg)) {
                is_type_arg = true;
            } else {
                is_name_arg = true;
            }
        }

        if (!in_queries) {
            if (is_name_arg || is_type_arg || is_class_arg) {
                in_queries = true;
                cur_start = i;
                cur_has_name = is_name_arg;
                cur_has_type = is_type_arg;
                cur_has_class = is_class_arg;
                global_end = i;
            }
        } else {
            bool start_new_query = false;
            if (is_reverse) {
                if (cur_has_name || cur_has_type || cur_has_class) {
                    start_new_query = true;
                }
            } else if (is_name_arg && cur_has_name) {
                start_new_query = true;
            } else if (is_type_arg && cur_has_name && cur_has_type) {
                start_new_query = true;
            } else if (is_class_arg && cur_has_name && cur_has_class) {
                start_new_query = true;
            }

            if (start_new_query) {
                if (query_count >= MAX_DAG_QUERIES) {
                    fprintf(stderr, "error: too many queries specified (max %d)\n", MAX_DAG_QUERIES);
                    return 1;
                }
                queries[query_count].start = cur_start;
                queries[query_count].end = i;
                query_count++;

                cur_start = i;
                cur_has_name = is_name_arg;
                cur_has_type = is_type_arg;
                cur_has_class = is_class_arg;
            } else {
                if (is_name_arg) cur_has_name = true;
                if (is_type_arg) cur_has_type = true;
                if (is_class_arg) cur_has_class = true;
            }
        }

        i += count;
    }

    if (in_queries) {
        if (query_count >= MAX_DAG_QUERIES) {
            fprintf(stderr, "error: too many queries specified (max %d)\n", MAX_DAG_QUERIES);
            return 1;
        }
        queries[query_count].start = cur_start;
        queries[query_count].end = argc;
        query_count++;
    } else {
        global_end = argc;
    }

    // グローバル引数区間のパース
    if (parse_arg_slice(1, global_end, argc, argv, &global_spec) < 0) {
        return 1;
    }

    // -f バッチファイルモードの処理
    if (global_spec.batch_file) {
        execute_batch_spec(&global_spec);
        print_multi_server_summary(global_spec.use_ldnsz);
#ifndef _WIN32
        if (global_spec.qo.mem_debug) {
            struct rusage ru;
            getrusage(RUSAGE_SELF, &ru);
            fprintf(stderr, ";; Memory usage: maxrss=%ld KB\n", (long)ru.ru_maxrss);
        }
#endif
        zone_arena_destroy(&g_dag_arena);
        if (g_results) free(g_results);
        return 0;
    }

    // クエリタプルが0個の場合はデフォルトクエリを1個作成
    if (query_count == 0) {
        queries[0].start = 0;
        queries[0].end = 0;
        query_count = 1;
    }

    int last_exit_code = 0;
    for (int q = 0; q < query_count; q++) {
        query_spec_t local_spec = global_spec;
        if (queries[q].start < queries[q].end) {
            if (parse_arg_slice(queries[q].start, queries[q].end, argc, argv, &local_spec) < 0) {
                last_exit_code = 1;
                continue;
            }
        }

        // タプル内で -f が指定された場合
        if (local_spec.batch_file) {
            execute_batch_spec(&local_spec);
            continue;
        }

        if (local_spec.qo.mem_debug) global_spec.qo.mem_debug = true;
        if (local_spec.use_ldnsz) global_spec.use_ldnsz = true;
        int rc = execute_query_spec(&local_spec);
        if (rc != 0) last_exit_code = rc;

        if (query_count > 1) {
            bool used_nofail = local_spec.qo.nofail && (!local_spec.test_all) && (!local_spec.do_trace) && (!local_spec.do_nssearch) && (!local_spec.batch_file) && (local_spec.server_arg && strchr(local_spec.server_arg, ',') != NULL);
            if (!used_nofail) {
                print_multi_server_summary(local_spec.use_ldnsz);
            }
            g_server_count = 0;
        }
    }

    if (query_count <= 1) {
        bool used_nofail_failover = global_spec.qo.nofail && (!global_spec.test_all) && (!global_spec.do_trace) && (!global_spec.do_nssearch) && (!global_spec.batch_file) && (global_spec.server_arg && strchr(global_spec.server_arg, ',') != NULL);
        if (!used_nofail_failover) {
            print_multi_server_summary(global_spec.use_ldnsz);
        }
    }

#ifndef _WIN32
    if (global_spec.qo.mem_debug) {
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        fprintf(stderr, ";; Memory usage: maxrss=%ld KB\n", (long)ru.ru_maxrss);
    }
#endif

    close_cached_tcp();
    zone_arena_destroy(&g_dag_arena);
    if (g_results) free(g_results);
#ifdef _WIN32
    WSACleanup();
#endif
    return last_exit_code;
}

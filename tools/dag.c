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
#include "dag_internal.h"
#include "dag_output_yaml.h"
#include "dag_batch.h"
#include "dag_axfr_client.h"
#include "dag_trace.h"
#include "dag_tsig_client.h"
#include "dag_edns_client.h"
#include "dag_transport.h"



bool g_dag_suppress_stdout = false;
/* ========================================================================
 * 1. Arena (dag only ever bump-allocates scratch strings; never freed)
 * ==================================================================== */
#define DAG_ARENA_SIZE (256 * 1024)
#define MAX_DAG_SERVERS 32

#define MAX_DAG_RESULT_ROWS 4096

static server_result_t *g_results = NULL;
static int g_result_cap = 0;
int g_server_count = 0; // Number of registered rows

server_result_t *alloc_result_row(void) {
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
char g_last_server_ip[INET6_ADDRSTRLEN + 1] = {0};
zone_arena_t g_dag_arena;

void reset_dag_arena(void) {
    zone_arena_destroy(&g_dag_arena);
    zone_arena_init(&g_dag_arena);
}

/* ========================================================================
 * 2. EDE strings / basic helpers
 * ==================================================================== */
const char *get_ede_error_string(uint16_t code) {
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

bool resolve_qtype(const char *s, uint16_t *out_type) {
    if (!s) return false;
    char upper_s[32];
    size_t len = strlen(s);
    if (len < sizeof(upper_s)) {
        for (size_t i = 0; i < len; i++) {
            upper_s[i] = (char)toupper((unsigned char)s[i]);
        }
        upper_s[len] = '\0';
        // dig互換: TYPE<n> (0-65535) をサポート
        if (strncmp(upper_s, "TYPE", 4) == 0 && isdigit((unsigned char)upper_s[4])) {
            char *endptr = NULL;
            long val = strtol(upper_s + 4, &endptr, 10);
            if (*endptr == '\0' && val >= 0 && val <= 65535) {
                if (out_type) *out_type = (uint16_t)val;
                return true;
            }
        }
        uint16_t t = get_type_code(upper_s);
        if (t != 0) {
            if (out_type) *out_type = t;
            return true;
        }
    } else {
        if (strncasecmp(s, "TYPE", 4) == 0 && isdigit((unsigned char)s[4])) {
            char *endptr = NULL;
            long val = strtol(s + 4, &endptr, 10);
            if (*endptr == '\0' && val >= 0 && val <= 65535) {
                if (out_type) *out_type = (uint16_t)val;
                return true;
            }
        }
        uint16_t t = get_type_code(s);
        if (t != 0) {
            if (out_type) *out_type = t;
            return true;
        }
    }
    // IXFR等の特殊構文処理は残す
    if (strncasecmp(s, "IXFR=", 5) == 0) {
        if (out_type) *out_type = 251; // IXFR
        return true;
    }
    return false;
}

static bool is_known_qtype(const char *s) {
    return resolve_qtype(s, NULL);
}

static bool is_qtype_syntax_or_known(const char *s) {
    if (!s) return false;
    if (is_known_qtype(s)) return true;
    if (strncasecmp(s, "TYPE", 4) == 0 && isdigit((unsigned char)s[4])) {
        const char *p = s + 4;
        while (*p && isdigit((unsigned char)*p)) p++;
        if (*p == '\0') return true;
    }
    return false;
}

int parse_qtype(const char *s) {
    uint16_t t = 0;
    if (resolve_qtype(s, &t)) return (int)t;
    fprintf(stderr, "dag: unknown query type '%s'\n", s);
    return -1;
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

void hexdump(const uint8_t *buf, size_t len) {
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
 * 3. Response formatting helpers
 * ==================================================================== */

const char *format_ttl_units(uint32_t ttl, char *buf, size_t buf_size) {
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




/* ========================================================================
 * 7. Response pretty-printing (dig-style)
 * ==================================================================== */
const char *rcode_name(uint16_t rcode) {
    // Note: RCODEs 6 (YXDOMAIN), 7 (YXRRSET), 8 (NXRRSET) are only meaningful in
    // RFC 2136 DNS UPDATE responses (opcode_name(opcode) == "UPDATE"). In normal 
    // QUERY responses, they are undefined. We unconditionally return their UPDATE
    // names here since they rarely appear otherwise.
    switch (rcode) {
        case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN"; case 4: return "NOTIMP"; case 5: return "REFUSED";
        case 6: return "YXDOMAIN"; case 7: return "YXRRSET"; case 8: return "NXRRSET";
        case 9: return "NOTAUTH"; case 10: return "NOTZONE"; case 11: return "DSOTYPENI";
        case 16: return "BADVERS/BADSIG"; case 17: return "BADKEY";
        case 18: return "BADTIME"; case 19: return "BADMODE"; case 20: return "BADNAME";
        case 21: return "BADALG"; case 22: return "BADTRUNC"; case 23: return "BADCOOKIE";
        default: {
            static _Thread_local char buf[32];
            snprintf(buf, sizeof(buf), "%u", (unsigned int)rcode);
            return buf;
        }
    }
}

const char *opcode_name(uint8_t opcode) {
    switch (opcode) {
        case 0: return "QUERY"; case 1: return "IQUERY"; case 2: return "STATUS";
        case 4: return "NOTIFY"; case 5: return "UPDATE";
        default: {
            static _Thread_local char buf[32];
            snprintf(buf, sizeof(buf), "%u", (unsigned int)opcode);
            return buf;
        }
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
    if (!out || out_cap == 0) return NULL;
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
    if (!out || out_cap == 0) return;
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
    if (!out || out_cap == 0) return;
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
                    if (out_len >= out_cap) return;
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

typedef struct {
    char *buf;        /* Destination buffer, or NULL for stdout */
    size_t buf_cap;   /* Buffer capacity (when buf != NULL) */
    size_t *pos;      /* Current write position (when buf != NULL) */
} rdata_sink_t;

static void sink_printf(rdata_sink_t *sink, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (sink->buf) {
        if (sink->buf_cap > 0 && sink->pos && *sink->pos < sink->buf_cap - 1) {
            int n = vsnprintf(sink->buf + *sink->pos, sink->buf_cap - *sink->pos, fmt, args);
            if (n > 0) {
                if ((size_t)n >= sink->buf_cap - *sink->pos) {
                    *sink->pos = sink->buf_cap - 1;
                } else {
                    *sink->pos += (size_t)n;
                }
            }
        }
    } else {
        if (!g_dag_suppress_stdout) {
            vprintf(fmt, args);
        }
    }
    va_end(args);
}

static void sink_split_b64(rdata_sink_t *sink, const char *b64, int len, int split_width) {
    if (split_width > 0 && len > split_width) {
        for (int i = 0; i < len; i += split_width) {
            if (i > 0) sink_printf(sink, " ");
            sink_printf(sink, "%.*s", (len - i) < split_width ? (len - i) : split_width, b64 + i);
        }
    } else {
        sink_printf(sink, "%.*s", len, b64);
    }
}

static void sink_split_hex(rdata_sink_t *sink, const uint8_t *data, size_t len, int split_width) {
    int sw = (split_width > 0) ? (split_width / 2) : 0;
    for (size_t i = 0; i < len; i++) {
        if (sw > 0 && i > 0 && (i % sw) == 0) sink_printf(sink, " ");
        sink_printf(sink, "%02X", data[i]);
    }
}

static void sink_multiline_hex(rdata_sink_t *sink, const uint8_t *data, size_t len, int split_width) {
    if (len == 0) {
        sink_printf(sink, "\t\t\t\t\t )\n");
        return;
    }
    int sw = (split_width > 0) ? (split_width / 2) : 22;
    if (sw <= 0) sw = 22;
    for (size_t i = 0; i < len; ) {
        sink_printf(sink, "\t\t\t\t\t");
        size_t chunk = (len - i) < (size_t)sw ? (len - i) : (size_t)sw;
        for (size_t j = 0; j < chunk; j++) sink_printf(sink, "%02X", data[i + j]);
        i += chunk;
        if (i < len) sink_printf(sink, "\n");
        else sink_printf(sink, " )");
    }
}

static void sink_multiline_b64(rdata_sink_t *sink, const char *b64, int len, int split_width) {
    if (len == 0) {
        sink_printf(sink, "\t\t\t\t\t )\n");
        return;
    }
    int sw = (split_width > 0) ? split_width : 44;
    if (sw <= 0) sw = 44;
    for (int i = 0; i < len; ) {
        sink_printf(sink, "\t\t\t\t\t");
        int chunk = (len - i) < sw ? (len - i) : sw;
        sink_printf(sink, "%.*s", chunk, b64 + i);
        i += chunk;
        if (i < len) sink_printf(sink, "\n");
        else sink_printf(sink, " )");
    }
}

static void sink_dnskey_like(rdata_sink_t *sink, const uint8_t *rdata, size_t rdlen, const display_opts_t *dopt) {
    if (rdlen < 4) { sink_printf(sink, "(malformed)"); return; }
    uint16_t flags = (rdata[0]<<8)|rdata[1];
    uint8_t protocol = rdata[2];
    uint8_t algorithm = rdata[3];
    uint16_t keytag = compute_dnskey_tag(rdata, rdlen);
    const char *alg_name = dnssec_algo_name(algorithm);
    bool is_ksk = (flags & 0x01) != 0;

    if (dopt && !dopt->yaml && !dopt->show_crypto) {
        sink_printf(sink, "%u %u %u [key id = %u]", flags, protocol, algorithm, keytag);
        return;
    }

    int n = 0;
    char *b64 = base64_encode_alloc(&rdata[4], rdlen - 4, &n);
    if (!b64) { sink_printf(sink, "(oom)"); return; }

    if (dopt && !dopt->yaml && dopt->multiline) {
        sink_printf(sink, "%u %u %u (\n", flags, protocol, algorithm);
        int split_w = (dopt->split_width > 0) ? dopt->split_width : 44;
        for (int i = 0; i < n; i += split_w) {
            sink_printf(sink, "\t\t\t\t\t%.*s\n", (n - i) < split_w ? (n - i) : split_w, b64 + i);
        }
        if (dopt->rrcomments || dopt->multiline) {
            sink_printf(sink, "\t\t\t\t\t) ; %s; alg = %s ; key id = %u", is_ksk ? "KSK" : "ZSK", alg_name, keytag);
        } else {
            sink_printf(sink, "\t\t\t\t\t)");
        }
    } else {
        sink_printf(sink, "%u %u %u ", flags, protocol, algorithm);
        sink_split_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
        if (dopt && !dopt->yaml && dopt->rrcomments) {
            sink_printf(sink, "  ; %s; alg = %s ; key id = %u", is_ksk ? "KSK" : "ZSK", alg_name, keytag);
        }
    }
    free(b64);
}

static void sink_ds_like(rdata_sink_t *sink, const uint8_t *rdata, size_t rdlen, const display_opts_t *dopt) {
    if (rdlen < 4) { sink_printf(sink, "(malformed)"); return; }
    uint16_t keytag = (rdata[0]<<8)|rdata[1];
    uint8_t algorithm = rdata[2];
    uint8_t digest_type = rdata[3];

    if (dopt && !dopt->yaml && !dopt->show_crypto) {
        sink_printf(sink, "%u %u %u [omitted]", keytag, algorithm, digest_type);
        return;
    }

    if (dopt && !dopt->yaml && dopt->multiline) {
        sink_printf(sink, "%u %u %u (\n", keytag, algorithm, digest_type);
        sink_multiline_hex(sink, &rdata[4], rdlen - 4, dopt->split_width);
    } else {
        sink_printf(sink, "%u %u %u ", keytag, algorithm, digest_type);
        sink_split_hex(sink, &rdata[4], rdlen - 4, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
    }
}

static void base32hex_encode(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
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
    if (!out || out_cap == 0) return;
    time_t tt = (time_t)t;
    struct tm tm_buf;
    gmtime_r(&tt, &tm_buf);
    strftime(out, out_cap, "%Y%m%d%H%M%S", &tm_buf);
}

static void sink_nsec3_params(rdata_sink_t *sink, const uint8_t *rdata, size_t rdlen, bool with_hash, const display_opts_t *dopt) {
    if (rdlen < 5) { sink_printf(sink, "(malformed)"); return; }
    uint8_t hash_alg = rdata[0];
    uint8_t flags = rdata[1];
    uint16_t iterations = (rdata[2]<<8)|rdata[3];
    uint8_t salt_len = rdata[4];
    if ((size_t)(5 + salt_len) > rdlen) { sink_printf(sink, "(malformed)"); return; }
    char salt_hex[512] = "-";
    if (salt_len > 0) {
        size_t p2 = 0;
        for (int i = 0; i < salt_len; i++) p2 += snprintf(salt_hex + p2, sizeof(salt_hex) - p2, "%02X", rdata[5 + i]);
    }

    if (with_hash) { // NSEC3 specific
        if ((size_t)(5 + salt_len + 1) > rdlen) { sink_printf(sink, " (malformed)"); return; }
        size_t pos = 5 + salt_len;
        uint8_t hash_len = rdata[pos++];
        if (pos + hash_len > rdlen) { sink_printf(sink, " (malformed)"); return; }
        char hash_b32[128];
        base32hex_encode(&rdata[pos], hash_len, hash_b32, sizeof(hash_b32));
        pos += hash_len;
        char types_buf[512];
        decode_type_bitmap(&rdata[pos], rdlen - pos, types_buf, sizeof(types_buf));
        if (dopt && !dopt->yaml && dopt->multiline) {
            sink_printf(sink, "%u %u %u %s (\n\t\t\t\t\t%s\n\t\t\t\t\t%s )", hash_alg, flags, iterations, salt_hex, hash_b32, types_buf);
        } else {
            sink_printf(sink, "%u %u %u %s %s %s", hash_alg, flags, iterations, salt_hex, hash_b32, types_buf);
        }
    } else {
        sink_printf(sink, "%u %u %u %s", hash_alg, flags, iterations, salt_hex);
    }
}

static void sink_svcparam_alpn(rdata_sink_t *sink, const uint8_t *value, uint16_t value_len) {
    sink_printf(sink, "alpn=\"");
    size_t pos = 0;
    bool first = true;
    while (pos < value_len) {
        uint8_t len = value[pos++];
        if (pos + len > value_len) break;
        if (!first) sink_printf(sink, ",");
        sink_printf(sink, "%.*s", len, &value[pos]);
        pos += len;
        first = false;
    }
    sink_printf(sink, "\"");
}

static void sink_svcparam_ipvXhint(rdata_sink_t *sink, const uint8_t *value, uint16_t value_len, bool is_v6) {
    sink_printf(sink, "%s=\"", is_v6 ? "ipv6hint" : "ipv4hint");
    size_t addr_size = is_v6 ? 16 : 4;
    size_t pos = 0;
    bool first = true;
    while (pos + addr_size <= value_len) {
        char buf[64];
        inet_ntop(is_v6 ? AF_INET6 : AF_INET, &value[pos], buf, sizeof(buf));
        if (!first) sink_printf(sink, ",");
        sink_printf(sink, "%s", buf);
        pos += addr_size;
        first = false;
    }
    sink_printf(sink, "\"");
}

static void sink_svcparams(rdata_sink_t *sink, const uint8_t *rdata, size_t offset, size_t rdlen) {
    while (offset + 4 <= rdlen) {
        uint16_t key = (rdata[offset]<<8)|rdata[offset+1];
        uint16_t vlen = (rdata[offset+2]<<8)|rdata[offset+3];
        offset += 4;
        if (offset + vlen > rdlen) break;
        sink_printf(sink, " ");
        const uint8_t *value = &rdata[offset];
        switch (key) {
            case 0: { // mandatory (RFC 9460 §8)
                sink_printf(sink, "mandatory=");
                for (size_t i = 0; i + 2 <= vlen; i += 2) {
                    uint16_t mkey = (value[i]<<8)|value[i+1];
                    const char *mk_name = (mkey == 1) ? "alpn" : (mkey == 2) ? "no-default-alpn" :
                                          (mkey == 3) ? "port" : (mkey == 4) ? "ipv4hint" :
                                          (mkey == 5) ? "ech" : (mkey == 6) ? "ipv6hint" : NULL;
                    if (mk_name) {
                        sink_printf(sink, "%s%s", (i > 0) ? "," : "", mk_name);
                    } else {
                        sink_printf(sink, "%skey%u", (i > 0) ? "," : "", mkey);
                    }
                }
                break;
            }
            case 1: sink_svcparam_alpn(sink, value, vlen); break;
            case 2: sink_printf(sink, "no-default-alpn"); break;
            case 3: { // port
                uint16_t port = (vlen>=2) ? ((value[0]<<8)|value[1]) : 0;
                sink_printf(sink, "port=%u", port);
                break;
            }
            case 4: sink_svcparam_ipvXhint(sink, value, vlen, false); break;
            case 5: { // ech
                int n = 0;
                char *b64 = base64_encode_alloc(value, vlen, &n);
                if (b64) {
                    sink_printf(sink, "ech=\"%.*s\"", n, b64);
                    free(b64);
                }
                break;
            }
            case 6: sink_svcparam_ipvXhint(sink, value, vlen, true); break;
            case 7: // dohpath / key7 (RFC 9460 / RFC 9461 / RFC 9462)
            default: { // unknown / generic keyNNN (RFC 9460 §2.1 character-string value)
                if (key == 7) {
                    sink_printf(sink, "key7=\"");
                } else {
                    sink_printf(sink, "key%u=\"", key);
                }
                for (uint16_t i = 0; i < vlen; i++) {
                    if (value[i] == '"' || value[i] == '\\') {
                        sink_printf(sink, "\\%c", value[i]);
                    } else if (value[i] >= 32 && value[i] <= 126) {
                        sink_printf(sink, "%c", value[i]);
                    } else {
                        sink_printf(sink, "\\%03u", value[i]);
                    }
                }
                sink_printf(sink, "\"");
                break;
            }
        }
        offset += vlen;
    }
}

static void format_rdata_common(const uint8_t *pkt, size_t pkt_len, uint16_t type,
                                size_t abs_offset, uint16_t rdlen,
                                rdata_sink_t *sink, const display_opts_t *dopt) {
    if (abs_offset + rdlen > pkt_len) {
        sink_printf(sink, "(truncated RDATA)");
        return;
    }
    if (dopt && dopt->force_unknown_format) {
        sink_printf(sink, "\\# %u", rdlen);
        if (rdlen > 0) {
            sink_printf(sink, " ");
            int sw = (dopt && dopt->split_width > 0) ? dopt->split_width : 0;
            sink_split_hex(sink, &pkt[abs_offset], rdlen, sw);
        }
        return;
    }

    switch (type) {
        case 1: { // A
            if (rdlen == 4) {
                sink_printf(sink, "%d.%d.%d.%d",
                            pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], pkt[abs_offset+3]);
            } else {
                sink_printf(sink, "(malformed A, rdlen=%u)", rdlen);
            }
            return;
        }
        case 28: { // AAAA
            if (rdlen == 16) {
                if (dopt && !dopt->yaml && dopt->expandaaaa) {
                    for (int g = 0; g < 8; g++) {
                        uint16_t val = (pkt[abs_offset + g * 2] << 8) | pkt[abs_offset + g * 2 + 1];
                        sink_printf(sink, "%s%04x", (g > 0) ? ":" : "", val);
                    }
                } else {
                    char buf[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &pkt[abs_offset], buf, sizeof(buf));
                    sink_printf(sink, "%s", buf);
                }
            } else {
                sink_printf(sink, "(malformed AAAA, rdlen=%u)", rdlen);
            }
            return;
        }
        case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 23: case 39: { // NS, MD, MF, CNAME, MB, MG, MR, PTR, NSAP-PTR, DNAME
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &name) == 0 &&
                next <= abs_offset + rdlen) {
                sink_printf(sink, "%s", name);
            } else {
                sink_printf(sink, "(unparsable name)");
            }
            return;
        }
        case 15: { // MX
            if (rdlen < 3) { sink_printf(sink, "(malformed MX)"); return; }
            uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &name) == 0 &&
                next <= abs_offset + rdlen) {
                sink_printf(sink, "%u %s", pref, name);
            } else {
                sink_printf(sink, "%u (unparsable name)", pref);
            }
            return;
        }
        case 6: { // SOA
            char *mname = NULL, *rname = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &mname) != 0) {
                sink_printf(sink, "(unparsable SOA)");
                return;
            }
            size_t after_mname = next;
            if (expand_wire_name(pkt, pkt_len, after_mname, &next, &g_dag_arena, &rname) != 0 ||
                next > abs_offset + rdlen) {
                sink_printf(sink, "(unparsable SOA)");
                return;
            }
            size_t nums_off = next;
            if (nums_off + 20 > pkt_len || nums_off + 20 > abs_offset + rdlen) {
                sink_printf(sink, "(truncated SOA)");
                return;
            }
            uint32_t serial  = ((uint32_t)pkt[nums_off]<<24)|((uint32_t)pkt[nums_off+1]<<16)|((uint32_t)pkt[nums_off+2]<<8)|pkt[nums_off+3];
            uint32_t refresh = ((uint32_t)pkt[nums_off+4]<<24)|((uint32_t)pkt[nums_off+5]<<16)|((uint32_t)pkt[nums_off+6]<<8)|pkt[nums_off+7];
            uint32_t retry   = ((uint32_t)pkt[nums_off+8]<<24)|((uint32_t)pkt[nums_off+9]<<16)|((uint32_t)pkt[nums_off+10]<<8)|pkt[nums_off+11];
            uint32_t expire  = ((uint32_t)pkt[nums_off+12]<<24)|((uint32_t)pkt[nums_off+13]<<16)|((uint32_t)pkt[nums_off+14]<<8)|pkt[nums_off+15];
            uint32_t minimum = ((uint32_t)pkt[nums_off+16]<<24)|((uint32_t)pkt[nums_off+17]<<16)|((uint32_t)pkt[nums_off+18]<<8)|pkt[nums_off+19];
            if (dopt && !dopt->yaml && dopt->multiline) {
                char t_ref[32], t_ret[32], t_exp[32], t_min[32];
                format_time_comment(refresh, t_ref, sizeof(t_ref));
                format_time_comment(retry, t_ret, sizeof(t_ret));
                format_time_comment(expire, t_exp, sizeof(t_exp));
                format_time_comment(minimum, t_min, sizeof(t_min));
                sink_printf(sink, "%s %s (\n", mname, rname);
                sink_printf(sink, "\t\t\t\t\t%u\t; serial\n", serial);
                sink_printf(sink, "\t\t\t\t\t%u\t; refresh%s\n", refresh, t_ref);
                sink_printf(sink, "\t\t\t\t\t%u\t; retry%s\n", retry, t_ret);
                sink_printf(sink, "\t\t\t\t\t%u\t; expire%s\n", expire, t_exp);
                sink_printf(sink, "\t\t\t\t\t%u\t; minimum%s\n", minimum, t_min);
                sink_printf(sink, "\t\t\t\t\t)");
            } else {
                sink_printf(sink, "%s %s %u %u %u %u %u", mname, rname, serial, refresh, retry, expire, minimum);
            }
            return;
        }
        case 56: // NINFO — display identical to TXT
        case 16: case 99: case 258: { // TXT, SPF, AVC
            size_t p = abs_offset, end = abs_offset + rdlen;
            bool first = true;
            while (p < end) {
                uint8_t slen = pkt[p++];
                if (p + slen > end) break;
                if (!first) sink_printf(sink, " ");
                first = false;
                sink_printf(sink, "\"");
                for (uint8_t i = 0; i < slen; i++) {
                    unsigned char c = pkt[p + i];
                    if (c == '"' || c == '\\') sink_printf(sink, "\\%c", c);
                    else if (c >= 0x20 && c < 0x7f) sink_printf(sink, "%c", c);
                    else sink_printf(sink, "\\%03o", c);
                }
                sink_printf(sink, "\"");
                p += slen;
            }
            return;
        }
        case 11: { // WKS
            if (rdlen >= 5) {
                sink_printf(sink, "%d.%d.%d.%d %u",
                            pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4]);
                for (uint16_t i = 5; i < rdlen; i++) {
                    uint8_t b = pkt[abs_offset+i];
                    for (int bit = 0; bit < 8; bit++) {
                        if (b & (0x80 >> bit)) {
                            sink_printf(sink, " %d", (i - 5) * 8 + bit);
                        }
                    }
                }
                return;
            }
            break;
        }
        case 13: { // HINFO
            char cpu[256], os[256];
            const uint8_t *p = &pkt[abs_offset];
            const uint8_t *end = p + rdlen;
            p = read_char_string(p, end, cpu, sizeof(cpu));
            if (p) p = read_char_string(p, end, os, sizeof(os));
            if (p) {
                sink_printf(sink, "\"%s\" \"%s\"", cpu, os);
                return;
            }
            break;
        }
        case 14: { // MINFO
            char *rmailbx = NULL, *emailbx = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &rmailbx) == 0 &&
                expand_wire_name(pkt, pkt_len, next, &next, &g_dag_arena, &emailbx) == 0 &&
                next <= abs_offset + rdlen) {
                sink_printf(sink, "%s %s", rmailbx, emailbx);
                return;
            }
            break;
        }
        case 17: case 18: case 19: case 20: case 22: case 26: case 40: { // RP, AFSDB, X25, ISDN, NSAP, PX, SINK
            if (type == 17) { // RP
                char *mbox = NULL, *txt = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &mbox) == 0 &&
                    expand_wire_name(pkt, pkt_len, next, &next, &g_dag_arena, &txt) == 0 &&
                    next <= abs_offset + rdlen) {
                    sink_printf(sink, "%s %s", mbox, txt);
                    return;
                }
            } else if (type == 18) { // AFSDB
                if (rdlen >= 2) {
                    uint16_t sub = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                    char *name = NULL; size_t next;
                    if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &name) == 0 &&
                        next <= abs_offset + rdlen) {
                        sink_printf(sink, "%u %s", sub, name);
                        return;
                    }
                }
            } else if (type == 19) { // X25
                char psdn[256];
                const uint8_t *p = &pkt[abs_offset];
                const uint8_t *end = p + rdlen;
                p = read_char_string(p, end, psdn, sizeof(psdn));
                if (p) {
                    sink_printf(sink, "\"%s\"", psdn);
                    return;
                }
            } else if (type == 20) { // ISDN
                char isdn_addr[256], sub_addr[256];
                const uint8_t *p = &pkt[abs_offset];
                const uint8_t *end = p + rdlen;
                p = read_char_string(p, end, isdn_addr, sizeof(isdn_addr));
                if (p) {
                    if (p < end) {
                        p = read_char_string(p, end, sub_addr, sizeof(sub_addr));
                        if (p) {
                            sink_printf(sink, "\"%s\" \"%s\"", isdn_addr, sub_addr);
                            return;
                        }
                    } else {
                        sink_printf(sink, "\"%s\"", isdn_addr);
                        return;
                    }
                }
            } else if (type == 22) { // NSAP
                sink_printf(sink, "0x");
                for (size_t i = 0; i < rdlen; i++) sink_printf(sink, "%02x", pkt[abs_offset + i]);
                return;
            } else if (type == 26) { // PX
                if (rdlen >= 2) {
                    uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
                    char *map822 = NULL, *mapx400 = NULL; size_t next;
                    if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &map822) == 0 &&
                        expand_wire_name(pkt, pkt_len, next, &next, &g_dag_arena, &mapx400) == 0 &&
                        next <= abs_offset + rdlen) {
                        sink_printf(sink, "%u %s %s", pref, map822, mapx400);
                        return;
                    }
                }
            }
            break;
        }
        case 21: case 36: case 107: { // RT / KX / LP
            if (rdlen >= 2) {
                uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
                char *name = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset + 2, &next, &g_dag_arena, &name) == 0 &&
                    next <= abs_offset + rdlen) {
                    sink_printf(sink, "%u %s", pref, name);
                    return;
                }
            }
            break;
        }
        case 27: { // GPOS
            const uint8_t *p = &pkt[abs_offset], *end = p + rdlen;
            char lat[256], lon[256], alt[256];
            p = read_char_string(p, end, lat, sizeof(lat));
            if (p) p = read_char_string(p, end, lon, sizeof(lon));
            if (p) p = read_char_string(p, end, alt, sizeof(alt));
            if (p) {
                sink_printf(sink, "\"%s\" \"%s\" \"%s\"", lat, lon, alt);
                return;
            }
            break;
        }
        case 29: { // LOC
            if (rdlen == 16 && pkt[abs_offset] == 0) {
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
                sink_printf(sink, "%s %s %.2fm %s %s %s", lat_buf, lon_buf, alt_m, s_buf, hp_buf, vp_buf);
                return;
            }
            break;
        }
        case 33: { // SRV
            if (rdlen >= 6) {
                uint16_t prio = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                uint16_t weight = (pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
                uint16_t port = (pkt[abs_offset+4]<<8)|pkt[abs_offset+5];
                char *name = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset + 6, &next, &g_dag_arena, &name) == 0 &&
                    next <= abs_offset + rdlen) {
                    sink_printf(sink, "%u %u %u %s", prio, weight, port, name);
                    return;
                }
            }
            break;
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
                        sink_printf(sink, "%u %u \"%s\" \"%s\" \"%s\" %s", order, pref, flags, svcs, regexp, repl);
                        return;
                    }
                }
            }
            break;
        }
        case 37: { // CERT
            if (rdlen >= 5) {
                uint16_t ctype = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
                uint16_t keytag = (pkt[abs_offset + 2] << 8) | pkt[abs_offset + 3];
                uint8_t alg = pkt[abs_offset + 4];
                char cbuf[32];
                const char *cname = cert_type_name(ctype, cbuf, sizeof(cbuf));
                if (dopt && !dopt->yaml && dopt->multiline) {
                    sink_printf(sink, "%s %u %u (\n", cname, keytag, alg);
                    if (rdlen > 5) {
                        int n = 0;
                        char *b64 = base64_encode_alloc(&pkt[abs_offset + 5], rdlen - 5, &n);
                        if (b64) {
                            sink_multiline_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 44);
                            free(b64);
                        } else {
                            sink_printf(sink, "\t\t\t\t\t)");
                        }
                    } else {
                        sink_printf(sink, "\t\t\t\t\t)");
                    }
                } else {
                    sink_printf(sink, "%s %u %u", cname, keytag, alg);
                    if (rdlen > 5) {
                        int n = 0;
                        char *b64 = base64_encode_alloc(&pkt[abs_offset + 5], rdlen - 5, &n);
                        if (b64) {
                            sink_printf(sink, " ");
                            sink_split_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                            free(b64);
                        }
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

                uint8_t max_len = (afi == 1) ? 4 : (afi == 2) ? 16 : 0;
                bool afd_invalid = (max_len == 0 || afdlength > max_len);
                uint8_t addr[16] = {0};
                size_t copy_len = (afdlength > sizeof(addr)) ? sizeof(addr) : afdlength;
                memcpy(addr, &pkt[abs_offset + p], copy_len);
                p += afdlength;

                if (afd_invalid) {
                    if (!first) sink_printf(sink, " ");
                    sink_printf(sink, "[APL afdlength=%u invalid for AFI=%u]", afdlength, afi);
                    first = false;
                    continue;
                }

                char addr_str[64] = "?";
                if (afi == 1) inet_ntop(AF_INET, addr, addr_str, sizeof(addr_str));
                else if (afi == 2) inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));
                if (!first) sink_printf(sink, " ");
                first = false;
                sink_printf(sink, "%s%u:%s/%u", negate ? "!" : "", afi, addr_str, prefix);
            }
            return;
        }
        case 44: { // SSHFP
            if (rdlen >= 2) {
                if (dopt && !dopt->yaml && dopt->multiline) {
                    sink_printf(sink, "%u %u (\n", pkt[abs_offset], pkt[abs_offset + 1]);
                    sink_multiline_hex(sink, &pkt[abs_offset + 2], rdlen - 2, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                } else {
                    sink_printf(sink, "%u %u ", pkt[abs_offset], pkt[abs_offset + 1]);
                    sink_split_hex(sink, &pkt[abs_offset + 2], rdlen - 2, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                }
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
                if (dopt && !dopt->yaml && dopt->multiline) {
                    sink_printf(sink, "( %u %u %u %s\n", prec, gw_type, alg, gw_buf);
                    if (p < end) {
                        int n = 0;
                        char *b64 = base64_encode_alloc(p, end - p, &n);
                        if (b64) {
                            sink_multiline_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 44);
                            free(b64);
                        } else {
                            sink_printf(sink, "\t\t\t\t\t)");
                        }
                    } else {
                        sink_printf(sink, "\t\t\t\t\t)");
                    }
                } else {
                    sink_printf(sink, "%u %u %u %s", prec, gw_type, alg, gw_buf);
                    if (p < end) {
                        int n = 0;
                        char *b64 = base64_encode_alloc(p, end - p, &n);
                        if (b64) {
                            sink_printf(sink, " ");
                            sink_split_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                            free(b64);
                        }
                    }
                }
                return;
            }
            break;
        }
        case 49: { // DHCID
            if (rdlen > 0) {
                int n = 0;
                char *b64 = base64_encode_alloc(&pkt[abs_offset], rdlen, &n);
                if (b64) {
                    if (dopt && !dopt->yaml && dopt->multiline) {
                        sink_printf(sink, "( ");
                        sink_multiline_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 44);
                        if (rdlen >= 3) {
                            uint16_t id_type = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                            uint8_t d_type = pkt[abs_offset+2];
                            sink_printf(sink, " ; %u %u %u", id_type, d_type, (unsigned int)(rdlen - 3));
                        }
                    } else {
                        sink_split_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                    }
                    free(b64);
                }
                return;
            }
            break;
        }
        case 61: { // OPENPGPKEY
            if (rdlen > 0) {
                int n = 0;
                char *b64 = base64_encode_alloc(&pkt[abs_offset], rdlen, &n);
                if (b64) {
                    if (dopt && !dopt->yaml && dopt->multiline) {
                        sink_printf(sink, "( ");
                        sink_multiline_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 44);
                    } else {
                        sink_split_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                    }
                    free(b64);
                }
                return;
            }
            break;
        }
        case 51: { // NSEC3PARAM
            sink_nsec3_params(sink, &pkt[abs_offset], rdlen, false, dopt);
            return;
        }
        case 50: { // NSEC3
            sink_nsec3_params(sink, &pkt[abs_offset], rdlen, true, dopt);
            return;
        }
        case 52: case 53: { // TLSA / SMIMEA
            if (rdlen >= 3) {
                if (dopt && !dopt->yaml && dopt->multiline) {
                    sink_printf(sink, "%u %u %u (\n", pkt[abs_offset], pkt[abs_offset + 1], pkt[abs_offset + 2]);
                    sink_multiline_hex(sink, &pkt[abs_offset + 3], rdlen - 3, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                } else {
                    sink_printf(sink, "%u %u %u ", pkt[abs_offset], pkt[abs_offset + 1], pkt[abs_offset + 2]);
                    sink_split_hex(sink, &pkt[abs_offset + 3], rdlen - 3, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                }
                return;
            }
            break;
        }
        case 55: { // HIP
            if (rdlen >= 4) {
                uint8_t hit_len = pkt[abs_offset];
                uint8_t pk_algorithm = pkt[abs_offset+1];
                uint16_t pk_len = (pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
                size_t p_off = 4;
                if (p_off + hit_len + pk_len <= rdlen) {
                    char hit_hex[512] = "";
                    size_t hp = 0;
                    for (int i = 0; i < hit_len && hp + 2 < sizeof(hit_hex); i++) {
                        hp += snprintf(hit_hex + hp, sizeof(hit_hex) - hp, "%02X", pkt[abs_offset + p_off + i]);
                    }
                    p_off += hit_len;

                    int n = 0;
                    char *b64 = base64_encode_alloc(&pkt[abs_offset + p_off], pk_len, &n);
                    if (b64) {
                        p_off += pk_len;
                        if (dopt && !dopt->yaml && dopt->multiline) {
                            sink_printf(sink, "( %u %s\n\t\t\t\t\t%.*s", pk_algorithm, hit_hex, n, b64);
                            while (p_off < rdlen) {
                                char *rvs_name = NULL; size_t next;
                                if (expand_wire_name(pkt, pkt_len, abs_offset + p_off, &next, &g_dag_arena, &rvs_name) != 0 ||
                                    next > abs_offset + rdlen) break;
                                sink_printf(sink, "\n\t\t\t\t\t%s", rvs_name ? rvs_name : ".");
                                p_off = next - abs_offset;
                            }
                            sink_printf(sink, " )");
                        } else {
                            sink_printf(sink, "%u %s %.*s", pk_algorithm, hit_hex, n, b64);
                            while (p_off < rdlen) {
                                char *rvs_name = NULL; size_t next;
                                if (expand_wire_name(pkt, pkt_len, abs_offset + p_off, &next, &g_dag_arena, &rvs_name) != 0 ||
                                    next > abs_offset + rdlen) break;
                                sink_printf(sink, " %s", rvs_name ? rvs_name : ".");
                                p_off = next - abs_offset;
                            }
                        }
                        free(b64);
                        return;
                    }
                }
            }
            break;
        }
        case 64: case 65: { // SVCB / HTTPS
            if (rdlen >= 2) {
                uint16_t priority = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                char target[256]; size_t next;
                if (extract_wire_name_to_buffer(pkt, pkt_len, abs_offset + 2, &next, target, sizeof(target)) == 0 &&
                    next >= abs_offset + 2 && next <= abs_offset + rdlen) {
                    sink_printf(sink, "%u %s", priority, (target[0] == '\0' || strcmp(target, ".") == 0) ? "." : target);
                    sink_svcparams(sink, &pkt[abs_offset], next - abs_offset, rdlen);
                    return;
                }
            }
            break;
        }
        case 66: { // DSYNC (RFC 9859)
            if (rdlen >= 5) {
                uint16_t target_type = (pkt[abs_offset] << 8) | pkt[abs_offset + 1];
                uint8_t scheme = pkt[abs_offset + 2];
                uint16_t port = (pkt[abs_offset + 3] << 8) | pkt[abs_offset + 4];
                char *target = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset + 5, &next, &g_dag_arena, &target) == 0 &&
                    next <= abs_offset + rdlen) {
                    char tbuf[32];
                    const char *tname = format_type_name(target_type, tbuf, sizeof(tbuf));
                    if (scheme == 1) {
                        sink_printf(sink, "%s NOTIFY %u %s", tname, port, target);
                    } else {
                        sink_printf(sink, "%s %u %u %s", tname, scheme, port, target);
                    }
                    return;
                }
            }
            break;
        }
        case 256: { // URI
            if (rdlen >= 4) {
                uint16_t prio = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                uint16_t weight = (pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
                sink_printf(sink, "%u %u \"%.*s\"", prio, weight, (int)(rdlen - 4), &pkt[abs_offset + 4]);
                return;
            }
            break;
        }
        case 24: case 46: { // SIG, RRSIG
            if (rdlen >= 18) {
                uint16_t cov = (pkt[abs_offset]<<8)|pkt[abs_offset+1];
                uint8_t alg = pkt[abs_offset+2];
                uint8_t labels = pkt[abs_offset+3];
                uint32_t orig_ttl = ((uint32_t)pkt[abs_offset+4]<<24)|((uint32_t)pkt[abs_offset+5]<<16)|((uint32_t)pkt[abs_offset+6]<<8)|pkt[abs_offset+7];
                uint32_t exp = ((uint32_t)pkt[abs_offset+8]<<24)|((uint32_t)pkt[abs_offset+9]<<16)|((uint32_t)pkt[abs_offset+10]<<8)|pkt[abs_offset+11];
                uint32_t incep = ((uint32_t)pkt[abs_offset+12]<<24)|((uint32_t)pkt[abs_offset+13]<<16)|((uint32_t)pkt[abs_offset+14]<<8)|pkt[abs_offset+15];
                uint16_t keytag = (pkt[abs_offset+16]<<8)|pkt[abs_offset+17];
                char *signer = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, abs_offset + 18, &next, &g_dag_arena, &signer) == 0 &&
                    next <= abs_offset + rdlen) {
                    char cov_buf[32];
                    const char *cov_str = (cov == 0) ? "0" : format_type_name(cov, cov_buf, sizeof(cov_buf));
                    char exp_buf[32], incep_buf[32];
                    format_rrsig_time(exp, exp_buf, sizeof(exp_buf));
                    format_rrsig_time(incep, incep_buf, sizeof(incep_buf));
                    if (dopt && !dopt->yaml && !dopt->show_crypto) {
                        sink_printf(sink, "%s %u %u %u %s %s %u %s [ ... ]",
                                    cov_str,
                                    alg, labels, orig_ttl, exp_buf, incep_buf, keytag, signer);
                        return;
                    }
                    int n = 0;
                    char *b64 = (next < abs_offset + rdlen) ? base64_encode_alloc(&pkt[next], abs_offset + rdlen - next, &n) : NULL;
                    if (dopt && !dopt->yaml && dopt->multiline) {
                        sink_printf(sink, "%s %u %u %u (\n\t\t\t\t\t%s %s %u %s\n",
                                    cov_str,
                                    alg, labels, orig_ttl, exp_buf, incep_buf, keytag, signer);
                        if (b64) {
                            sink_multiline_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 44);
                            free(b64);
                        } else {
                            sink_printf(sink, "\t\t\t\t\t)");
                        }
                    } else {
                        sink_printf(sink, "%s %u %u %u %s %s %u %s",
                                    cov_str,
                                    alg, labels, orig_ttl, exp_buf, incep_buf, keytag, signer);
                        if (b64) {
                            sink_printf(sink, " ");
                            sink_split_b64(sink, b64, n, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                            free(b64);
                        }
                    }
                    return;
                }
            }
            break;
        }
        case 57: // RKEY — display identical to DNSKEY/KEY
        case 25: case 48: case 60: { // KEY, DNSKEY, CDNSKEY
            sink_dnskey_like(sink, &pkt[abs_offset], rdlen, dopt);
            return;
        }
        case 43: case 59: case 32768: case 32769: { // DS, CDS, TA, DLV
            sink_ds_like(sink, &pkt[abs_offset], rdlen, dopt);
            return;
        }
        case 47: { // NSEC
            char *next_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &next_name) == 0 &&
                next <= abs_offset + rdlen) {
                char types_buf[512];
                decode_type_bitmap(&pkt[next], abs_offset + rdlen - next, types_buf, sizeof(types_buf));
                sink_printf(sink, "%s %s", next_name, types_buf);
                return;
            }
            break;
        }
        case 62: { // CSYNC (RFC 7477)
            if (rdlen >= 6) {
                uint32_t serial = ((uint32_t)pkt[abs_offset]<<24)|((uint32_t)pkt[abs_offset+1]<<16)|((uint32_t)pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
                uint16_t flags = (pkt[abs_offset+4]<<8)|pkt[abs_offset+5];
                char types_buf[512];
                decode_type_bitmap(&pkt[abs_offset+6], rdlen - 6, types_buf, sizeof(types_buf));
                sink_printf(sink, "%u %u %s", serial, flags, types_buf);
                return;
            }
            break;
        }
        case 63: { // ZONEMD (RFC 8976)
            if (rdlen >= 6) {
                uint32_t serial = ((uint32_t)pkt[abs_offset]<<24)|((uint32_t)pkt[abs_offset+1]<<16)|((uint32_t)pkt[abs_offset+2]<<8)|pkt[abs_offset+3];
                uint8_t scheme = pkt[abs_offset+4];
                uint8_t hash_alg = pkt[abs_offset+5];
                if (dopt && !dopt->yaml && dopt->multiline) {
                    sink_printf(sink, "%u %u %u (\n", serial, scheme, hash_alg);
                    sink_multiline_hex(sink, &pkt[abs_offset+6], rdlen - 6, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                } else {
                    sink_printf(sink, "%u %u %u ", serial, scheme, hash_alg);
                    sink_split_hex(sink, &pkt[abs_offset+6], rdlen - 6, (dopt && dopt->split_width > 0) ? dopt->split_width : 0);
                }
                return;
            }
            break;
        }
        case 250: { // TSIG
            char *alg_name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &next, &g_dag_arena, &alg_name) == 0 &&
                next + 6 <= abs_offset + rdlen) {
                uint64_t time_signed = ((uint64_t)pkt[next]<<40)|((uint64_t)pkt[next+1]<<32)|((uint64_t)pkt[next+2]<<24)|
                                       ((uint64_t)pkt[next+3]<<16)|((uint64_t)pkt[next+4]<<8)|pkt[next+5];
                next += 6;
                if (next + 2 <= abs_offset + rdlen) {
                    uint16_t fudge = (pkt[next]<<8)|pkt[next+1];
                    next += 2;
                    if (next + 2 <= abs_offset + rdlen) {
                        uint16_t mac_size = (pkt[next]<<8)|pkt[next+1];
                        next += 2;
                        if (next + mac_size + 6 <= abs_offset + rdlen) {
                            const uint8_t *mac_bytes = &pkt[next];
                            next += mac_size;
                            uint16_t orig_id = (pkt[next]<<8)|pkt[next+1];
                            uint16_t err = (pkt[next+2]<<8)|pkt[next+3];
                            uint16_t other_len = (pkt[next+4]<<8)|pkt[next+5];
                            next += 6;
                            if (next + other_len <= abs_offset + rdlen) {
                                int n = 0;
                                char *b64 = (mac_size > 0) ? base64_encode_alloc(mac_bytes, mac_size, &n) : NULL;
                                if (dopt && !dopt->yaml && dopt->multiline) {
                                    sink_printf(sink, "%s %llu %u %u (\n\t\t\t\t\t%.*s ) %u %s %u",
                                                alg_name, (unsigned long long)time_signed, fudge, mac_size,
                                                n, b64 ? b64 : "",
                                                orig_id, rcode_name(err), other_len);
                                    if (other_len > 0) {
                                        sink_printf(sink, " ");
                                        sink_split_hex(sink, &pkt[next], other_len, 0);
                                    }
                                } else {
                                    sink_printf(sink, "%s %llu %u %u %.*s %u %s %u",
                                                alg_name, (unsigned long long)time_signed, fudge, mac_size,
                                                n, b64 ? b64 : "",
                                                orig_id, rcode_name(err), other_len);
                                    if (other_len > 0) {
                                        sink_printf(sink, " ");
                                        sink_split_hex(sink, &pkt[next], other_len, 0);
                                    }
                                }
                                if (b64) free(b64);
                                return;
                            }
                        }
                    }
                }
            }
            break;
        }
        case 257: { // CAA (RFC 8659)
            if (rdlen >= 2) {
                uint8_t flags = pkt[abs_offset];
                uint8_t tag_len = pkt[abs_offset + 1];
                if (2 + tag_len <= rdlen) {
                    sink_printf(sink, "%u %.*s \"", flags, tag_len, &pkt[abs_offset + 2]);
                    const uint8_t *val = &pkt[abs_offset + 2 + tag_len];
                    size_t vlen = rdlen - 2 - tag_len;
                    for (size_t vi = 0; vi < vlen; vi++) {
                        unsigned char c = val[vi];
                        if (c == '"' || c == '\\') sink_printf(sink, "\\%c", c);
                        else if (c >= 0x20 && c < 0x7f) sink_printf(sink, "%c", c);
                        else sink_printf(sink, "\\%03o", c);
                    }
                    sink_printf(sink, "\"");
                    return;
                }
            }
            break;
        }
        case 108: { // EUI48
            if (rdlen == 6) {
                sink_printf(sink, "%02x-%02x-%02x-%02x-%02x-%02x",
                            pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2],
                            pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5]);
                return;
            }
            break;
        }
        case 109: { // EUI64
            if (rdlen == 8) {
                sink_printf(sink, "%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
                            pkt[abs_offset], pkt[abs_offset+1], pkt[abs_offset+2],
                            pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5],
                            pkt[abs_offset+6], pkt[abs_offset+7]);
                return;
            }
            break;
        }
        case 104: { // NID
            if (rdlen == 10) {
                uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
                sink_printf(sink, "%u %02x%02x:%02x%02x:%02x%02x:%02x%02x", pref,
                            pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5],
                            pkt[abs_offset+6], pkt[abs_offset+7], pkt[abs_offset+8], pkt[abs_offset+9]);
                return;
            }
            break;
        }
        case 105: { // L32
            if (rdlen == 6) {
                uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
                sink_printf(sink, "%u %d.%d.%d.%d", pref,
                            pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5]);
                return;
            }
            break;
        }
        case 106: { // L64
            if (rdlen == 10) {
                uint16_t pref = (pkt[abs_offset] << 8) | pkt[abs_offset+1];
                sink_printf(sink, "%u %02x%02x:%02x%02x:%02x%02x:%02x%02x", pref,
                            pkt[abs_offset+2], pkt[abs_offset+3], pkt[abs_offset+4], pkt[abs_offset+5],
                            pkt[abs_offset+6], pkt[abs_offset+7], pkt[abs_offset+8], pkt[abs_offset+9]);
                return;
            }
            break;
        }
        case 260: { // AMTRELAY
            if (rdlen >= 1) {
                uint8_t prec = pkt[abs_offset];
                uint8_t d_opt = (prec & 0x80) != 0;
                prec &= 0x7F;
                if (rdlen < 2) {
                    sink_printf(sink, "%u %u 0 .", prec, d_opt);
                    return;
                }
                uint8_t relay_type = pkt[abs_offset + 1];
                const uint8_t *p = &pkt[abs_offset + 2];
                const uint8_t *end = &pkt[abs_offset + rdlen];
                sink_printf(sink, "%u %u %u ", prec, d_opt, relay_type);
                if (relay_type == 0) {
                    sink_printf(sink, ".");
                    return;
                } else if (relay_type == 1) {
                    if (p + 4 <= end) {
                        sink_printf(sink, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
                        return;
                    }
                } else if (relay_type == 2) {
                    if (p + 16 <= end) {
                        char buf[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, p, buf, sizeof(buf));
                        sink_printf(sink, "%s", buf);
                        return;
                    }
                } else if (relay_type == 3) {
                    char *gw = NULL; size_t next;
                    if (expand_wire_name(pkt, pkt_len, p - pkt, &next, &g_dag_arena, &gw) == 0 &&
                        next <= abs_offset + rdlen) {
                        sink_printf(sink, "%s", gw);
                        return;
                    }
                }
            }
            break;
        }
        case 30: { // NXT (RFC 2535 §5.1): Next Domain Name + simple type bitmap
            // 名前部分 (非圧縮ドメイン名)
            char *nxt_name = NULL;
            size_t name_end;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &name_end, &g_dag_arena, &nxt_name) != 0 ||
                name_end > abs_offset + rdlen) {
                sink_printf(sink, "(malformed NXT)");
                return;
            }
            sink_printf(sink, "%s", nxt_name ? nxt_name : ".");
            // タイプビットマップ: ビット n = タイプ n (RFC 2535 §5.2 シンプル形式)
            size_t boff = name_end;
            size_t bend = abs_offset + rdlen;
            for (size_t i = boff; i < bend; i++) {
                uint8_t byte = pkt[i];
                for (int bit = 7; bit >= 0; bit--) {
                    if (byte & (1u << bit)) {
                        uint16_t tc = (uint16_t)((i - boff) * 8 + (7 - bit));
                        if (tc == 0) continue;
                        char tbuf[32];
                        sink_printf(sink, " %s", format_type_name(tc, tbuf, sizeof(tbuf)));
                    }
                }
            }
            return;
        }
        case 34: { // ATMA (RFC 2163 §2): format byte + address
            // dig と同じ表示: フォーマットバイトを除いた残りのバイト列を hex 表示
            if (rdlen < 2) { sink_printf(sink, "(malformed ATMA)"); return; }
            sink_split_hex(sink, &pkt[abs_offset + 1], rdlen - 1, 0);
            return;
        }
        case 38: { // A6 (RFC 2874 §3): prefix-length + suffix + optional prefix name
            if (rdlen < 1) { sink_printf(sink, "(malformed A6)"); return; }
            uint8_t a6_plen = pkt[abs_offset];
            if (a6_plen > 128) { sink_printf(sink, "(malformed A6 prefix-length=%u)", a6_plen); return; }
            sink_printf(sink, "%u", a6_plen);
            size_t a6_suffix = (size_t)((128 - a6_plen + 7) / 8);
            if (a6_suffix > 0) {
                if (abs_offset + 1 + a6_suffix > abs_offset + rdlen) {
                    sink_printf(sink, " (truncated suffix)");
                    return;
                }
                // 下位バイトとして IPv6 アドレスを復元し inet_ntop で表示
                uint8_t a6_addr[16] = {0};
                memcpy(&a6_addr[16 - a6_suffix], &pkt[abs_offset + 1], a6_suffix);
                char a6_ipbuf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, a6_addr, a6_ipbuf, sizeof(a6_ipbuf));
                sink_printf(sink, " %s", a6_ipbuf);
            }
            // プレフィックス名 (prefix_len > 0 のとき)
            if (a6_plen > 0) {
                size_t pfx_off = abs_offset + 1 + a6_suffix;
                if (pfx_off < abs_offset + rdlen) {
                    char *pfx_name = NULL;
                    size_t pfx_end;
                    if (expand_wire_name(pkt, pkt_len, pfx_off, &pfx_end, &g_dag_arena, &pfx_name) == 0 &&
                        pfx_end <= abs_offset + rdlen) {
                        sink_printf(sink, " %s", pfx_name ? pfx_name : ".");
                    }
                }
            }
            return;
        }
        case 259: { // DOA (RFC 7169 §4.4.2): Enterprise+Type+Location+MediaType+Data
            if (rdlen < 10) { sink_printf(sink, "(malformed DOA)"); return; }
            uint32_t doa_ent  = ((uint32_t)pkt[abs_offset]   << 24) | ((uint32_t)pkt[abs_offset+1] << 16) |
                                ((uint32_t)pkt[abs_offset+2]  <<  8) |  (uint32_t)pkt[abs_offset+3];
            uint32_t doa_type = ((uint32_t)pkt[abs_offset+4] << 24) | ((uint32_t)pkt[abs_offset+5] << 16) |
                                ((uint32_t)pkt[abs_offset+6]  <<  8) |  (uint32_t)pkt[abs_offset+7];
            uint8_t  doa_loc  = pkt[abs_offset + 8];
            uint8_t  mlen     = pkt[abs_offset + 9];
            if (abs_offset + 10 + mlen > abs_offset + rdlen) {
                sink_printf(sink, "(malformed DOA media-type)");
                return;
            }
            sink_printf(sink, "%u %u %u \"", doa_ent, doa_type, doa_loc);
            for (uint8_t i = 0; i < mlen; i++) {
                uint8_t c = pkt[abs_offset + 10 + i];
                sink_printf(sink, "%c", (c >= 0x20 && c < 0x7F) ? c : '?');
            }
            sink_printf(sink, "\"");
            // DOA-DATA: base64 (データがある場合)
            size_t doa_data_off = abs_offset + 10 + mlen;
            size_t doa_data_len = (abs_offset + rdlen) - doa_data_off;
            if (doa_data_len > 0) {
                int b64_n = 0;
                char *b64 = base64_encode_alloc(&pkt[doa_data_off], doa_data_len, &b64_n);
                if (b64) {
                    sink_printf(sink, " ");
                    int sw = (dopt && dopt->split_width > 0) ? dopt->split_width : 0;
                    sink_split_b64(sink, b64, b64_n, sw);
                    free(b64);
                }
            }
            return;
        }
        case 58: { // TALINK: prev-name next-name
            if (rdlen < 2) { sink_printf(sink, "(malformed TALINK)"); return; }
            char *prev = NULL, *next = NULL;
            size_t n1, n2;
            if (expand_wire_name(pkt, pkt_len, abs_offset, &n1, &g_dag_arena, &prev) != 0 ||
                n1 > abs_offset + rdlen) {
                sink_printf(sink, "(malformed TALINK prev)"); return;
            }
            if (expand_wire_name(pkt, pkt_len, n1, &n2, &g_dag_arena, &next) != 0 ||
                n2 > abs_offset + rdlen) {
                sink_printf(sink, "(malformed TALINK next)"); return;
            }
            sink_printf(sink, "%s %s", prev ? prev : ".", next ? next : ".");
            return;
        }
        case 67: case 68: { // HHIT, BRID (RFC 9886) — opaque base64
            if (rdlen == 0) { sink_printf(sink, "(empty)"); return; }
            int b64_n = 0;
            char *b64 = base64_encode_alloc(&pkt[abs_offset], rdlen, &b64_n);
            if (b64) {
                int sw = (dopt && dopt->split_width > 0) ? dopt->split_width : 0;
                sink_split_b64(sink, b64, b64_n, sw);
                free(b64);
            }
            return;
        }
        default:
            break;
    }

    // Fallback: RFC 3597 Generic Format "\# <rdlen> <hex>"
    sink_printf(sink, "\\# %u", rdlen);
    if (rdlen > 0) {
        sink_printf(sink, " ");
        int sw = (dopt && dopt->split_width > 0) ? dopt->split_width : 0;
        sink_split_hex(sink, &pkt[abs_offset], rdlen, sw);
    }
}

void format_rdata_for_display(const uint8_t *pkt, size_t pkt_len, uint16_t type,
                                     size_t abs_offset, uint16_t rdlen,
                                     char *out, size_t out_cap, const display_opts_t *dopt) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    size_t pos = 0;
    rdata_sink_t sink = { .buf = out, .buf_cap = out_cap, .pos = &pos };
    format_rdata_common(pkt, pkt_len, type, abs_offset, rdlen, &sink, dopt);
}

static void print_rdata(const uint8_t *pkt, size_t pkt_len, uint16_t type,
                        size_t abs_offset, uint16_t rdlen, const display_opts_t *dopt) {
    rdata_sink_t sink = { .buf = NULL, .buf_cap = 0, .pos = NULL };
    format_rdata_common(pkt, pkt_len, type, abs_offset, rdlen, &sink, dopt);
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

void calculate_packet_hashes(const uint8_t *pkt, size_t pkt_len, uint32_t *wire_hash_out, uint32_t *record_hash_out) {
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
                static char rdata_raw[65536];
                format_rdata_for_display(pkt, pkt_len, type, rdata_start, rdlen, rdata_raw, sizeof(rdata_raw), NULL);
                record_hash += calc_record_rr_hash(name, type, klass, ttl, rdata_raw);
            }
            offset = rdata_start + rdlen;
        }
    }
    if (wire_hash_out) *wire_hash_out = wire_hash;
    if (record_hash_out) *record_hash_out = record_hash;
}

const char *format_class_name(uint16_t klass, char *buf, size_t buf_size) {
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
                                     uint16_t nscount, uint16_t arcount,
                                     const display_opts_t *dopt) {
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
                decode_and_print_edns_option(pkt, p, code, olen, "; ", dopt);
                p += olen;
            }
            return;
        }
        scan_offset = rdata_off + rdlen;
    }
}


static void format_edns_flags(bool dnssec_ok, bool compact_answers_ok, char *buf, size_t buf_size) {
    buf[0] = '\0';
    if (dnssec_ok) strncat(buf, " do", buf_size - strlen(buf) - 1);
    if (compact_answers_ok) strncat(buf, " co", buf_size - strlen(buf) - 1);
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
        print_opt_extra_options(pkt, pkt_len, qdcount, ancount, nscount, arcount, dopt);
    }

    size_t offset = 12;
    if (qdcount > 0) {
        if (opcode == 5) {
            printf(";; ZONE SECTION:\n");
        } else {
            printf(";; QUESTION SECTION:\n");
        }
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

    if (ancount > 0) {
        if (opcode == 5) {
            printf(";; PREREQUISITE SECTION:\n");
        } else {
            printf(";; ANSWER SECTION:\n");
        }
        for (int i = 0; i < ancount; i++) {
            if (!print_one_rr(pkt, pkt_len, &offset, NULL, dopt)) break;
        }
        printf("\n");
    }

    if (nscount > 0) {
        if (opcode == 5) {
            printf(";; UPDATE SECTION:\n");
        } else {
            printf(";; AUTHORITY SECTION:\n");
        }
        for (int i = 0; i < nscount; i++) {
            if (!print_one_rr(pkt, pkt_len, &offset, NULL, dopt)) break;
        }
        printf("\n");
    }

    if (arcount > 0) {
        int non_opt_cnt = count_non_opt_rrs(pkt, pkt_len, offset, arcount);
        if (non_opt_cnt > 0) {
            printf(";; ADDITIONAL SECTION:\n");
            for (int i = 0; i < arcount; i++) {
                if (!print_one_rr(pkt, pkt_len, &offset, NULL, dopt)) break;
            }
            printf("\n");
        }
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

void print_response(const uint8_t *pkt, size_t pkt_len, axfr_state_t *axfr_state, const display_opts_t *dopt) {
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
        if (axfr_state->is_ixfr && ancount == 1 && axfr_state->soa_seen_count == 1) {
            axfr_state->axfr_complete = true;
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
        print_opt_extra_options(pkt, pkt_len, qdcount, ancount, nscount, arcount, dopt);
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


size_t parse_hex_string(const char *hex, uint8_t *out, size_t out_cap) {
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


static void run_dns64prefix_check(const char *server, int port, const query_opts_t *qo, bool use_tcp,
                                   bool no_hexdump_query, bool no_hexdump_response,
                                   const display_opts_t *dopt) {
    (void)no_hexdump_query; (void)no_hexdump_response;
    uint8_t qbuf[512];
    query_opts_t q = *qo;
    q.check_dns64prefix = false;
    uint8_t req_mac[64];
    size_t req_mac_len = 0;
    size_t qlen = build_and_sign_query(qbuf, sizeof(qbuf), "ipv4only.arpa", 28 /* AAAA */, &q, req_mac, &req_mac_len);
    uint8_t resp[65535];
    ssize_t n = do_dns_exchange_auto(server, port, &q, qbuf, qlen, resp, sizeof(resp), q.timeout_sec, use_tcp);
    if (n < 12) {
        return;
    }

    if (q.want_tsig) {
        uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
        int terr = tsig_verify_packet(resp, (size_t)n, &q.tsig_key, req_mac, req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
        if (terr == -1) {
            printf(";; Couldn't verify signature: expected a TSIG or SIG(0)\n");
        } else if (terr != 0) {
            printf(";; Couldn't verify signature: tsig verify failure (%d)\n", terr);
        }
        fflush(stdout);
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
    } else {
        int parsed_t = parse_qtype(qtype_s);
        if (parsed_t < 0) return -1;
        qtype = (uint16_t)parsed_t;
        if (qtype == 251) {
            qo->is_ixfr = true;
            qo->ixfr_serial = 0; // シリアル指定なし時は 0 (全転送/差分開始シリアル)
        }
    }

    uint8_t pkt[65535];
    size_t pkt_len = 0;

    uint8_t request_mac[64];
    size_t request_mac_len = 0;

    if (hex_payload) {
        pkt_len = parse_hex_string(hex_payload, pkt, sizeof(pkt));
        if (pkt_len == 0 || pkt_len > sizeof(pkt)) {
            fprintf(stderr, "Error: Invalid, empty, or oversized hex payload (max %zu bytes)\n", sizeof(pkt));
            return 1;
        }
        if (qo->want_tsig) {
            qo->tsig_key.fuzztime = qo->fuzztime;
            if (tsig_sign_packet(pkt, &pkt_len, sizeof(pkt), &qo->tsig_key, 0, request_mac, &request_mac_len, NULL, 0, false) != 0) {
                fprintf(stderr, "Error: tsig_sign_packet failed\n");
                return 1;
            }
        }
    } else {
        pkt_len = build_and_sign_query(pkt, sizeof(pkt), qname, qtype, qo, request_mac, &request_mac_len);
        if (pkt_len == 0 && !has_break(BRK_TOO_SHORT, NULL, NULL) && !qo->header_only) {
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
    bool tc_retried = false;

    do {
        retry_tcp = false;
        struct timespec start_ts;
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        
        axfr_state_t axfr_state = {0};
        axfr_state.is_axfr = (qtype == 252 || qtype == 251);
        axfr_state.is_ixfr = (qtype == 251);


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

        query_opts_t eff_qo = *qo;
        if (axfr_state.is_axfr) {
            eff_qo.keep_tcp_open = true;
        }

        static uint8_t resp[65535];
        ssize_t n = -1;
        int attempts = 0;
        int max_tries = (qo->tries < 1) ? 1 : qo->tries;
        
        int tcp_sock = -1;
        while (attempts < max_tries) {
            attempts++;
            if (eff_qo.use_doh) {
                n = do_doh_exchange(server, port, &eff_qo, pkt, pkt_len, resp, sizeof(resp), eff_qo.timeout_sec);
                if (n > 0) break;
            } else if (eff_qo.use_tls) {
                n = do_tls_exchange(server, port, &eff_qo, pkt, pkt_len, resp, sizeof(resp), eff_qo.timeout_sec);
                if (n > 0) break;
            } else if (use_tcp) {
                if (eff_qo.keep_tcp_open) {
                    n = do_tcp_exchange(server, port, &eff_qo, pkt, pkt_len, resp, sizeof(resp), eff_qo.timeout_sec);
                    if (n > 0) break;
                } else {
                    tcp_sock = do_tcp_send_request(server, port, &eff_qo, pkt, pkt_len, eff_qo.timeout_sec);
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
                n = do_udp_exchange(server, port, &eff_qo, pkt, pkt_len, resp, sizeof(resp), eff_qo.timeout_sec);
                if (n >= 0) break;
            }
            if (attempts < max_tries) {
                if (!dopt->short_mode) printf(";; connection timed out; retrying...\n");
            }
        }

        if (n >= 12 && eff_qo.retry_on_badcookie) {
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
                eff_qo.retry_on_badcookie = false; // RFC 7873 §5.4: 再送は 1 回限り
                eff_qo.want_cookie = true;
                eff_qo.server_cookie_len = bc_edns.server_cookie_len;
                memcpy(eff_qo.server_cookie, bc_edns.server_cookie, bc_edns.server_cookie_len);
                pkt_len = build_and_sign_query(pkt, sizeof(pkt), qname, qtype, &eff_qo, request_mac, &request_mac_len);
                n = do_dns_exchange_by_transport(server, port, &eff_qo, use_tcp, pkt, pkt_len, resp, sizeof(resp), eff_qo.timeout_sec);
            }
        }

        if (n >= 12 && eff_qo.edns_negotiation && eff_qo.want_opt) {
            uint16_t bv_qd = (resp[4] << 8) | resp[5];
            uint16_t bv_an = (resp[6] << 8) | resp[7];
            uint16_t bv_ns = (resp[8] << 8) | resp[9];
            uint16_t bv_ar = (resp[10] << 8) | resp[11];
            edns_info_t bv_edns;
            parse_edns_opt(resp, n, bv_qd, bv_an, bv_ns, bv_ar, &bv_edns);
            uint16_t bv_rcode = bv_edns.present
                ? (((uint16_t)bv_edns.ext_rcode << 4) | (resp[3] & 0x0F))
                : (resp[3] & 0x0F);
            if (bv_rcode == 16 && eff_qo.edns_version > 0) {
                if (dopt->show_badvers_msg && !dopt->short_mode) {
                    print_response(resp, (size_t)n, &axfr_state, dopt);
                    printf("\n");
                }
                printf(";; BADVERS, retrying with EDNS version %d.\n", eff_qo.edns_version - 1);
                eff_qo.edns_version -= 1;
                pkt_len = build_and_sign_query(pkt, sizeof(pkt), qname, qtype, &eff_qo, request_mac, &request_mac_len);
                n = do_dns_exchange_by_transport(server, port, &eff_qo, use_tcp, pkt, pkt_len, resp, sizeof(resp), eff_qo.timeout_sec);
            }
        }

        if (n <= 0) {
            printf(";; no servers could be reached\n");
            sres = alloc_result_row();
            if (sres) {
                sres->rcode = 2; // SERVFAIL
                sres->resp_len = 0;
                if (port != 53) {
                    snprintf(sres->server_ip, sizeof(sres->server_ip), "%s#%d", (g_last_server_ip[0] ? g_last_server_ip : server), port);
                } else {
                    snprintf(sres->server_ip, sizeof(sres->server_ip), "%s", (g_last_server_ip[0] ? g_last_server_ip : server));
                }
                snprintf(sres->proto, sizeof(sres->proto), "%s", use_tcp ? "TCP" : "UDP");
                g_server_count++;
            }
            if (tcp_sock >= 0) close(tcp_sock);
            return 9;
        }

        struct timespec end_ts;
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        long long elapsed_usec = (end_ts.tv_sec - start_ts.tv_sec) * 1000000LL + (end_ts.tv_nsec - start_ts.tv_nsec) / 1000LL;
        long elapsed_ms = (long)(elapsed_usec / 1000LL);

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
                if (port != 53) {
                    snprintf(sres->server_ip, sizeof(sres->server_ip), "%s#%d", (g_last_server_ip[0] ? g_last_server_ip : server), port);
                } else {
                    snprintf(sres->server_ip, sizeof(sres->server_ip), "%s", (g_last_server_ip[0] ? g_last_server_ip : server));
                }
                snprintf(sres->proto, sizeof(sres->proto), "%s", use_tcp ? "TCP" : "UDP");
            }
            
            if (qo->want_tsig) {
                uint8_t resp_mac[64];
                size_t resp_mac_len = 0;
                int err = tsig_verify_packet(resp, (size_t)n, &qo->tsig_key, request_mac, request_mac_len,
                                             unsigned_accum, unsigned_accum_len, (msg_index > 1),
                                             resp_mac, &resp_mac_len);
                if (err == 0) {
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
                        printf(";; Couldn't verify signature: expected a TSIG or SIG(0)\n");
                    } else if (err == 16) {
                        printf(";; Couldn't verify signature: tsig verify failure (BADSIG)\n");
                    } else if (err == 17) {
                        printf(";; Couldn't verify signature: tsig verify failure (BADKEY)\n");
                    } else if (err == 18) {
                        printf(";; Couldn't verify signature: tsig verify failure (BADTIME)\n");
                    } else if (err == 21) {
                        printf(";; Couldn't verify signature: tsig verify failure (BADALG)\n");
                    } else {
                        printf(";; Couldn't verify signature: tsig verify failure (%d)\n", err);
                    }
                    fflush(stdout);
                }
            }

            if (!dopt->short_mode) {
                if (!dopt->yaml && !no_hexdump_response && dopt->show_comments) {
                    const char *resp_proto = "UDP";
                    if (qo->use_doh) {
                        resp_proto = (qo->doh_method == DOH_GET) ? (qo->doh_tls ? "HTTPS-GET" : "HTTP-GET") : (qo->doh_tls ? "HTTPS" : "HTTP");
                    } else if (qo->use_tls) {
                        resp_proto = "TLS";
                    } else if (use_tcp) {
                        resp_proto = "TCP";
                    }
                    if (use_tcp && (qtype == 252 || qtype == 251)) {
                        printf("Response message %d (%zd bytes, %s):\n", msg_index, n, resp_proto);
                    } else {
                        printf("Response (%zd bytes, %s):\n", n, resp_proto);
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
                        uint32_t ttl = ((uint32_t)resp[nxt+4]<<24)|((uint32_t)resp[nxt+5]<<16)|((uint32_t)resp[nxt+6]<<8)|resp[nxt+7];
                        uint16_t rdlen = (resp[nxt+8]<<8)|resp[nxt+9];
                        if (type == 6) {
                            check_axfr_soa(&axfr_state, resp, n, name, &resp[nxt], rdlen);
                            if (axfr_state.is_axfr && axfr_state.soa_seen_count > 1 && dopt && dopt->onesoa) {
                                off = nxt + 10 + rdlen;
                                continue;
                            }
                        }
                        if (dopt->explicit_ttlid) {
                            if (dopt->ttlunits) {
                                char ttl_str[32];
                                format_ttl_units(ttl, ttl_str, sizeof(ttl_str));
                                printf("%s ", ttl_str);
                            } else {
                                printf("%u ", ttl);
                            }
                        }
                        print_rdata(resp, n, type, nxt+10, rdlen, dopt);
                        if (dopt->identify) {
                            printf(" from server %s in %ld ms.", (g_last_server_ip[0] ? g_last_server_ip : server), elapsed_ms);
                        }
                        printf("\n");
                        off = nxt+10+rdlen;
                    } else break;
                }
                if (axfr_state.is_ixfr && ancount == 1 && axfr_state.soa_seen_count == 1) {
                    axfr_state.axfr_complete = true;
                }
            }


            bool has_more = axfr_state.is_axfr && !axfr_state.axfr_complete &&
                            (use_tcp || eff_qo.use_tls || eff_qo.use_doh);

            if (has_more) {
                if (msg_index >= 100000) {
                    fprintf(stderr, ";; AXFR aborted: exceeded 100000 messages without a closing SOA\n");
                    break;
                }
                if (sres) g_server_count++;
                n = do_axfr_recv_next(tcp_sock, &eff_qo, resp, sizeof(resp));
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

        if (tcp_sock >= 0) {
            close(tcp_sock);
            tcp_sock = -1;
        }
        if (!qo->keep_tcp_open && axfr_state.is_axfr) {
            close_cached_tcp();
        }

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

        if (g_results && g_server_count > 0 && start_index < g_server_count) {
            for (int i = start_index; i < g_server_count; i++) {
                g_results[i].elapsed_ms = elapsed_ms;
                g_results[i].msg_total = (msg_index > 1) ? msg_index : 0;
            }
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
            printf(";; SERVER: %s#%d(%s) (%s)\n", (g_last_server_ip[0] ? g_last_server_ip : server), port, server, proto_name);
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

        bool is_truncated = (!use_tcp && n >= 4 && (resp[2] & 0x02) != 0);
        if (is_truncated && !tc_retried) {
            if (eff_qo.ignore_tc) {
                if (!dopt->short_mode && !dopt->yaml) {
                    fprintf(stderr, "\n;; Truncated response received, but +ignore specified; not retrying in TCP mode.\n");
                }
            } else {
                if (!dopt->short_mode && !dopt->yaml) {
                    printf("\n;; Truncated, retrying in TCP mode.\n");
                }
                use_tcp = true;
                retry_tcp = true;
                tc_retried = true;
            }
        }
    } while (retry_tcp);

    if (qo->check_dns64prefix) {
        run_dns64prefix_check(server, port, qo, use_tcp, no_hexdump_query, no_hexdump_response, dopt);
    }

    return 0;
}

static void print_multi_server_summary(bool use_ldnsz, bool is_yaml) {
    if (is_yaml || g_server_count == 0) return;
    
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
    printf("%-*s | %-5s | %-7s | %3s | %3s | %3s | %-*s | %-6s | %s\n", 
           max_server_len, "SERVER", "PROTO", "RCODE", "ANS", "AUT", "ADD", 
           g_want_allcompare ? 13 : 10,
           g_want_allcompare ? "SEM_HASH(+TTL)" : "SEM_HASH", "TIME", "MATCH STATUS");
    
    // 3. 区切り線の出力 ( max_server_len の分だけ '-' を出力 )
    for (int i = 0; i < max_server_len; i++) printf("-");
    if (g_want_allcompare) {
        printf("-+-------+---------+-----+-----+-----+---------------+--------+------------------------\n");
    } else {
        printf("-+-------+---------+-----+-----+-----+------------+--------+------------------------\n");
    }

    server_result_t *base = &g_results[0];
    for (int i = 0; i < g_server_count; i++) {
        if (g_results[i].resp_len > 0 && !g_results[i].tc) {
            base = &g_results[i];
            break;
        }
    }

    for (int i = 0; i < g_server_count; i++) {
        server_result_t *r = &g_results[i];
        
        const char *status_str = "";
        if (r == base) {
            status_str = "[BASE]";
        } else {
            // クエリID (2バイト) を除外してバイナリ比較
            if (r->resp_len == base->resp_len && r->resp_len >= 2 && 
                memcmp(r->resp_buf + 2, base->resp_buf + 2, r->resp_len - 2) == 0) {
                status_str = "MATCH_EXACT";
            } else if (r->rcode == base->rcode && (r->semantic_hash == base->semantic_hash || r->record_hash == base->record_hash)) {
                status_str = "MATCH_SEMANTIC";
            } else {
                status_str = "[DIFF]";
            }
        }

        // 4. データ行の出力 ( %-*s を使って動的幅を指定 )
        char label[128];
        if (r->msg_total > 1) {
            snprintf(label, sizeof(label), "%s (msg %d/%d)", r->server_ip, r->msg_index, r->msg_total);
        } else {
            snprintf(label, sizeof(label), "%s", r->server_ip);
        }
        char hash_str[32];
        snprintf(hash_str, sizeof(hash_str), "0x%08X", r->semantic_hash);
        printf("%-*s | %-5s | %-7s | %3d | %3d | %3d | %-*s | %4ldms | %s\n",
               max_server_len, label, r->proto, rcode_name(r->rcode),
               r->ancount, r->nscount, r->arcount,
               g_want_allcompare ? 13 : 10, hash_str,
               r->elapsed_ms, status_str);
    }
    
    // 5. フッター区切り線の出力
    for (int i = 0; i < max_server_len; i++) printf("-");
    if (g_want_allcompare) {
        printf("-+-------+---------+-----+-----+-----+---------------+--------+------------------------\n");
    } else {
        printf("-+-------+---------+-----+-----+-----+------------+--------+------------------------\n");
    }
    }
    
    // URL出力 (+ldnsz が指定された場合のみ)
    if (use_ldnsz) {
        if (g_server_count > 1) {
            printf(";; Compare details in browser:\n;; https://ldns.jp/diff/#c=");
            for (int i = 0; i < g_server_count; i++) {
                server_result_t *r = &g_results[i];
                printf("%s", (i > 0) ? "," : "");
                bool is_ipv6 = (strchr(r->server_ip, ':') != NULL && r->server_ip[0] != '[');
                if (is_ipv6) {
                    printf("[%s]", r->server_ip);
                } else {
                    printf("%s", r->server_ip);
                }
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
        "  -k <keyfile>                 Load TSIG key or BIND SIG(0) (.private) keyfile\n"
        "  +sig0-pkey=<file>            Specify SIG(0) private key file (PEM or BIND .private format)\n"
        "  +sig0-name=<name>            Specify Signer's Name for SIG(0) record\n"
        "  +sig0-alg=<N>                Override DNSSEC algorithm number for SIG(0) (default: auto)\n"
        "  +sig0-keytag=<N>             Override Key Tag for SIG(0) record (default: auto)\n"
        "  +[no]sig0                    Enable/disable SIG(0) transaction signing\n"
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
        "  +udp                         Force UDP transport (opposite of +tcp)\n"
        "  +[no]tls                     Use DNS-over-TLS (DoT) [default port: 853]\n"
        "  +[no]tls-ca[=file]           Enable TLS certificate verification using system store or CA file\n"
        "  +tls-certfile=file           Load client TLS certificate chain from file\n"
        "  +tls-keyfile=file            Load client TLS private key from file\n"
        "  +tls-hostname=host           Explicitly specify expected TLS Server Name Indication (SNI)\n"
        "  +[no]https[=endpoint]        Use DNS-over-HTTPS (DoH) mode [default endpoint: /dns-query, port: 443]\n"
        "  +[no]https-get[=endpoint]    Use GET method instead of POST for DoH\n"
        "  +[no]https-post[=endpoint]   Use POST method for DoH\n"
        "  +[no]http-plain[=endpoint]   Use plain HTTP DNS mode (+http) [default endpoint: /dns-query, port: 80]\n"
        "  +[no]http-plain-get[=ep]     Use GET method for plain HTTP (+http-get)\n"
        "  +[no]http-plain-post[=ep]    Use POST method for plain HTTP (+http-post)\n"
        "  +[no]http[=endpoint]         Alias for +http-plain\n"
        "  +[no]http-get[=endpoint]     Alias for +http-plain-get\n"
        "  +[no]http-post[=endpoint]    Alias for +http-plain-post\n"
        "  +[no]proxy[=spec]            Inject PROXYv2 transport header ahead of any TLS handshake (e.g. +proxy=192.0.2.1#1234-192.0.2.2#53)\n"
        "  +[no]proxy-plain[=spec]      Alias for +proxy (retained for dig/kdig compatibility); behaves identically\n"
        "  +[no]keepalive               Send EDNS TCP keepalive option (RFC 7828)\n"
        "  +[no]keepopen                Keep TCP socket open between consecutive queries (RFC 7766)\n"
        "  +[no]dns64prefix             Query IPv4-only prefix from ipv4only.arpa (RFC 7050)\n"
        "  +timeout=N, +time=N          Query timeout in seconds [5]\n"
        "  +tries=N / +retry=N          Number of query attempts [1]\n"
        "  +[no]rec, +[no]recurse      Set / clear RD (Recursion Desired) bit (+[no]rdflag)\n"
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
        "  +[no]nssearch                Search all authoritative nameservers for zone (honors +tcp; falls back to TCP; uses +noglue by default)\n"
        "  +[no]glue                    Prefer in-bailiwick Glue records from ADDITIONAL section for +nssearch [default: +noglue]\n"
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
        "  +[no]multiline, +[no]multi   Display multiline format for SOA, DNSKEY, and RRSIG records\n"
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
        "  +[no]hexdump                 Show/suppress raw packet hex dumps for query and response\n"
        "  +[no]hexdump-query           Show/suppress raw query packet hex dump\n"
        "  +[no]hexdump-response        Show/suppress raw response packet hex dump\n"
        "  +fuzztime[=N]                [TEST-ONLY] Override TSIG time_signed with a fixed\n"
        "                               timestamp (default 1646972129) instead of current time,\n"
        "                               for reproducible TSIG MAC testing. Do not use against\n"
        "                               production TSIG keys.\n"
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


/*
 * /etc/resolv.conf (Windows: GetNetworkParams) から最初の nameserver を読み取って返す。
 * 見つからなければパブリックDNS (1.1.1.1) または 127.0.0.1 をフォールバックとして使用。
 */

const char *get_system_resolver(void) {
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
            count = 0; // search と domain は相互排他で最後のインスタンスが有効
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


static inline void add_search_candidate(char candidates[8][512], int *count, const char *prefix, const char *suffix) {
    if (!count || *count >= 8) return;
    int written;
    if (suffix && *suffix) {
        written = snprintf(candidates[*count], sizeof(candidates[0]), "%s.%s", prefix, suffix);
    } else {
        written = snprintf(candidates[*count], sizeof(candidates[0]), "%s", prefix);
    }
    if (written < 0 || (size_t)written >= sizeof(candidates[0])) {
        fprintf(stderr, ";; warning: search-list candidate exceeds maximum buffer size, skipping\n");
        return;
    }
    (*count)++;
}

static int run_single_job(const char *qname, const char *qtype_s, const char *server_arg, int port,
                          bool use_tcp, bool force_udp, bool test_all, bool norecurse,
                          bool adflag, bool cdflag, bool aaflag, bool tcflag, bool zflag,
                          bool no_hexdump_query, bool no_hexdump_response,
                          query_opts_t qo, const char *hex_payload, const display_opts_t *dopt) {
    char search_candidates[8][512];
    int candidate_count = 0;

    size_t qname_len = strlen(qname);
    bool is_absolute = (qname_len > 0 && qname[qname_len - 1] == '.');
    int num_dots = 0;
    for (const char *p = qname; *p; p++) {
        if (*p == '.') num_dots++;
    }
    int req_ndots = (qo.ndots >= 0) ? qo.ndots : 1;
    if (qo.use_search_list && !is_absolute) {
        if (num_dots < req_ndots) {
            /* 1. サーチドメインを先に追加 */
            if (qo.search_domain && *qo.search_domain) {
                add_search_candidate(search_candidates, &candidate_count, qname, qo.search_domain);
            } else {
                char domains[4][256];
                int count = get_system_search_domains(domains, 4);
                for (int i = 0; i < count && candidate_count < 6; i++) {
                    add_search_candidate(search_candidates, &candidate_count, qname, domains[i]);
                }
            }
            /* 2. 生のドメイン (qname) を最後に追加 */
            add_search_candidate(search_candidates, &candidate_count, qname, NULL);
        } else {
            /* 1. 生のドメイン (qname) を先に追加 */
            add_search_candidate(search_candidates, &candidate_count, qname, NULL);
            /* 2. サーチドメインを最後に追加 */
            if (qo.search_domain && *qo.search_domain) {
                add_search_candidate(search_candidates, &candidate_count, qname, qo.search_domain);
            } else {
                char domains[4][256];
                int count = get_system_search_domains(domains, 4);
                for (int i = 0; i < count && candidate_count < 6; i++) {
                    add_search_candidate(search_candidates, &candidate_count, qname, domains[i]);
                }
            }
        }
    } else {
        add_search_candidate(search_candidates, &candidate_count, qname, NULL);
    }

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

    // AXFR, IXFRまたはANYの場合は自動的にTCPモードに昇格（+udpが明示されていない場合、BIND 9 dig / RFC 8482 / RFC 1995準拠）
    if ((strcasecmp(qtype_s, "AXFR") == 0 || strncasecmp(qtype_s, "IXFR", 4) == 0 || strcasecmp(qtype_s, "ANY") == 0) && !force_udp) {
        use_tcp = true;
    }

    for (int i = 0; i < g_break_count; i++) {
        if (is_tcp_only_break(g_breaks[i].kind) && !use_tcp) {
            fprintf(stderr, "error: this --break kind requires --tcp\n");
            free(server_list_buf);
            return 1;
        }
    }
    if (candidate_count == 0) {
        fprintf(stderr, ";; No valid search candidates remaining\n");
        free(server_list_buf);
        return 1;
    }
    qo.query_id = (uint16_t)(arc4random() & 0xFFFF);

    int last_overall_rc = 0;
    bool has_any_success = false;
    for (int ci = 0; ci < candidate_count; ci++) {
        const char *cur_qname = search_candidates[ci];

        if (qo.nofail && server_count > 1 && !test_all) {
            for (int si = 0; si < server_count; si++) {
                const char *server = servers[si];
                int srv_port = server_ports[si];
                bool is_last = (si == server_count - 1);

                int rc = run_test(NULL, cur_qname, qtype_s, server, srv_port, use_tcp, norecurse,
                                  adflag, cdflag, aaflag, tcflag, zflag,
                                  no_hexdump_query, no_hexdump_response, &qo, hex_payload, dopt);
                last_overall_rc = rc;
                if (rc == 0) has_any_success = true;

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
                    if (strcmp(cur_qname, ".") == 0) cur_qname = "example.com";
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

                        run_test(all_tests[t].name, cur_qname, qtype_s, server, srv_port,
                                 use_tcp || all_tests[t].tcp, norecurse,
                                 adflag, all_tests[t].cdflag, all_tests[t].aaflag, all_tests[t].tcflag, all_tests[t].zflag,
                                 no_hexdump_query, no_hexdump_response,
                                 &t_qo, hex_payload, dopt);
                    }

                } else {
                    int rc = run_test(NULL, cur_qname, qtype_s, server, srv_port, use_tcp, norecurse,
                                      adflag, cdflag, aaflag, tcflag, zflag,
                                      no_hexdump_query, no_hexdump_response, &qo, hex_payload, dopt);
                    last_overall_rc = rc;
                    if (rc == 0) has_any_success = true;
                    if (rc != 0 && server_count == 1 && candidate_count == 1) { free(server_list_buf); return rc; }
                }
            }
        }

        // RFC 1536: NXDOMAIN (rcode 3) が返った場合のみ次のサーチドメイン候補へフォールバック
        uint8_t last_rcode = 0;
        if (g_server_count > 0) {
            last_rcode = g_results[g_server_count - 1].rcode;
        }
        if (last_rcode != 3 /* NXDOMAIN */ || ci == candidate_count - 1) {
            break;
        }
    }
    
    if (server_count > 1 && has_any_success) {
        last_overall_rc = 0;
    }

    free(server_list_buf);
    return last_overall_rc;
}

#define MAX_DAG_QUERIES 64

typedef struct {
    int start;
    int end;
} arg_slice_t;



void init_query_spec(query_spec_t *spec) {
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
    spec->dopt.explicit_ttlid = false;
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
    spec->qo.use_glue = false;
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

void prescan_always_global_options(int argc, char **argv, query_spec_t *global_spec) {
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
        else if (strcmp(argv[i], "+glue") == 0) global_spec->qo.use_glue = true;
        else if (strcmp(argv[i], "+noglue") == 0) global_spec->qo.use_glue = false;
        else if (strcmp(argv[i], "+search") == 0 || strcmp(argv[i], "+defname") == 0) {
            global_spec->qo.use_search_list = true;
            global_spec->qo.use_glue = false;
        }
        else if (strncmp(argv[i], "+domain=", 8) == 0) {
            global_spec->qo.use_search_list = true;
            global_spec->qo.use_glue = false;
        }
    }
}

static int parse_query_arg_token(int argc, char **argv, int i, query_spec_t *spec) {
    const char *arg = argv[i];

    if (strcmp(arg, "+cmd") == 0) {
        spec->dopt.show_cmd = true;
        return 1;
    } else if (strcmp(arg, "+nocmd") == 0) {
        spec->dopt.show_cmd = false;
        return 1;
    } else if (strcmp(arg, "+short") == 0) {
        spec->dopt.short_mode = true;
        return 1;
    } else if (strcmp(arg, "+noshort") == 0) {
        spec->dopt.short_mode = false;
        return 1;
    } else if (strcmp(arg, "+yaml") == 0) {
        spec->dopt.yaml = true;
        return 1;
    } else if (strcmp(arg, "+noyaml") == 0) {
        spec->dopt.yaml = false;
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
        if (spec->qo.want_sig0 || spec->qo.sig0_specified) {
            fprintf(stderr, "error: TSIG (-k/-y) and SIG(0) (+sig0-pkey) cannot be combined in this version of dag\n");
            return -1;
        }
        spec->qo.tsig_specified = true;
        char *tsig_str = strdup(argv[i + 1]);
        parse_tsig_str(tsig_str, &spec->qo);
        free(tsig_str);
        return 2;
    }
    if (strcmp(arg, "-k") == 0 && i + 1 < argc) {
        const char *keyfile = argv[i + 1];
        if (load_bind_sig0_private_key(keyfile, &spec->qo.sig0_key)) {
            if (spec->qo.want_tsig || spec->qo.tsig_specified) {
                fprintf(stderr, "error: TSIG (-k/-y) and SIG(0) (+sig0-pkey) cannot be combined in this version of dag\n");
                return -1;
            }
            spec->qo.sig0_specified = true;
            spec->qo.want_sig0 = true;
            return 2;
        }
        if (spec->qo.want_sig0 || spec->qo.sig0_specified) {
            fprintf(stderr, "error: TSIG (-k/-y) and SIG(0) (+sig0-pkey) cannot be combined in this version of dag\n");
            return -1;
        }
        spec->qo.tsig_specified = true;
        parse_tsig_keyfile(keyfile, &spec->qo);
        return 2;
    }
    if (strcmp(arg, "--update-add") == 0 && i + 1 < argc) {
        if (spec->qo.update_op_count < MAX_UPDATE_OPS) {
            spec->qo.update_ops[spec->qo.update_op_count].kind = UPDATE_OP_ADD;
            spec->qo.update_ops[spec->qo.update_op_count].raw = strdup(argv[i + 1]);
            spec->qo.update_op_count++;
        } else {
            fprintf(stderr, "warning: too many --update-add/--update-del options, ignoring '%s' (max %d)\n", argv[i + 1], MAX_UPDATE_OPS);
        }
        return 2;
    }
    if (strcmp(arg, "--update-del") == 0 && i + 1 < argc) {
        if (spec->qo.update_op_count < MAX_UPDATE_OPS) {
            spec->qo.update_ops[spec->qo.update_op_count].kind = UPDATE_OP_DEL;
            spec->qo.update_ops[spec->qo.update_op_count].raw = strdup(argv[i + 1]);
            spec->qo.update_op_count++;
        } else {
            fprintf(stderr, "warning: too many --update-add/--update-del options, ignoring '%s' (max %d)\n", argv[i + 1], MAX_UPDATE_OPS);
        }
        return 2;
    }
    if (strcmp(arg, "--update-del-exact") == 0 && i + 1 < argc) {
        if (spec->qo.update_op_count < MAX_UPDATE_OPS) {
            spec->qo.update_ops[spec->qo.update_op_count].kind = UPDATE_OP_DEL_EXACT;
            spec->qo.update_ops[spec->qo.update_op_count].raw = strdup(argv[i + 1]);
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
            spec->force_udp = false;
        } else if (strcmp(arg, "+novc") == 0 || strcmp(arg, "+notcp") == 0) {
            spec->use_tcp = false; spec->qo.use_tcp = false;
            spec->force_udp = true;
        } else if (strcmp(arg, "+udp") == 0) {
            spec->force_udp = true;
            spec->use_tcp = false; spec->qo.use_tcp = false;
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
        } else if (strcmp(arg, "+glue") == 0) {
            spec->qo.use_glue = true;
        } else if (strcmp(arg, "+noglue") == 0) {
            spec->qo.use_glue = false;
        } else if (strcmp(arg, "+search") == 0 || strcmp(arg, "+defname") == 0) {
            spec->qo.use_search_list = true;
            spec->qo.use_glue = false;
        } else if (strcmp(arg, "+nosearch") == 0 || strcmp(arg, "+nodefname") == 0) {
            spec->qo.use_search_list = false;
        } else if (strncmp(arg, "+domain=", 8) == 0) {
            if (spec->qo.search_domain) free(spec->qo.search_domain);
            spec->qo.search_domain = strdup(arg + 8);
            spec->qo.use_search_list = true;
            spec->qo.use_glue = false;
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
            spec->dopt.ttlunits = true; spec->dopt.ttlid = true; spec->dopt.explicit_ttlid = true;
        } else if (strcmp(arg, "+nottlunits") == 0) {
            spec->dopt.ttlunits = false;
        } else if (strcmp(arg, "+ttlid") == 0) {
            spec->dopt.ttlid = true; spec->dopt.explicit_ttlid = true;
        } else if (strcmp(arg, "+nottlid") == 0) {
            spec->dopt.ttlid = false; spec->dopt.explicit_ttlid = false;
        } else if (strcmp(arg, "+expire") == 0) {
            spec->dopt.expire = true;
            spec->qo.want_opt = true;
            spec->qo.want_expire_opt = true;
        } else if (strcmp(arg, "+noexpire") == 0) {
            spec->dopt.expire = false;
            spec->qo.want_expire_opt = false;
        } else if (strcmp(arg, "+showsearch") == 0) {
            spec->dopt.showsearch = true;
            spec->qo.use_search_list = true;
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
            spec->qo.use_proxy = true; spec->qo.proxy_use_local_cmd = false;
            if (!parse_proxy_arg(arg + 7, &spec->qo)) {
                fprintf(stderr, "dag: invalid proxy specification '%s'\n", arg + 7);
                return -1;
            }
        } else if (strcmp(arg, "+proxy") == 0) {
            spec->qo.use_proxy = true; spec->qo.proxy_use_local_cmd = true;
        } else if (strcmp(arg, "+noproxy") == 0) {
            spec->qo.use_proxy = false;
        } else if (strncmp(arg, "+proxy-plain=", 13) == 0) {
            spec->qo.use_proxy = true; spec->qo.proxy_use_local_cmd = false;
            if (!parse_proxy_arg(arg + 13, &spec->qo)) {
                fprintf(stderr, "dag: invalid proxy specification '%s'\n", arg + 13);
                return -1;
            }
        } else if (strcmp(arg, "+proxy-plain") == 0) {
            spec->qo.use_proxy = true; spec->qo.proxy_use_local_cmd = true;
        } else if (strcmp(arg, "+noproxy-plain") == 0) {
            spec->qo.use_proxy = false;
        } else if (strcmp(arg, "+tls") == 0) {
            spec->qo.use_tls = true; if (spec->port == 53) spec->port = 853;
        } else if (strcmp(arg, "+notls") == 0) {
            spec->qo.use_tls = false; if (spec->port == 853) spec->port = 53;
        } else if (strncmp(arg, "+tls-ca=", 8) == 0) {
            if (spec->qo.tls_ca_file) free(spec->qo.tls_ca_file);
            spec->qo.tls_ca_file = strdup(arg + 8);
        } else if (strcmp(arg, "+tls-ca") == 0) {
            spec->qo.tls_verify_default_store = true;
        } else if (strcmp(arg, "+notls-ca") == 0) {
            spec->qo.tls_verify_default_store = false;
        } else if (strncmp(arg, "+tls-certfile=", 14) == 0) {
            if (spec->qo.tls_certfile) free(spec->qo.tls_certfile);
            spec->qo.tls_certfile = strdup(arg + 14);
        } else if (strncmp(arg, "+tls-keyfile=", 13) == 0) {
            if (spec->qo.tls_keyfile) free(spec->qo.tls_keyfile);
            spec->qo.tls_keyfile = strdup(arg + 13);
        } else if (strncmp(arg, "+tls-hostname=", 14) == 0) {
            if (spec->qo.tls_hostname) free(spec->qo.tls_hostname);
            spec->qo.tls_hostname = strdup(arg + 14);
        } else if (strncmp(arg, "+https=", 7) == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = true; spec->qo.doh_path = strdup(arg + 7); if (spec->port == 53) spec->port = 443;
        } else if (strcmp(arg, "+https") == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = true; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 443;
        } else if (strncmp(arg, "+https-get=", 11) == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_GET; spec->qo.doh_tls = true; spec->qo.doh_path = strdup(arg + 11); if (spec->port == 53) spec->port = 443;
        } else if (strcmp(arg, "+https-get") == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_GET; spec->qo.doh_tls = true; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 443;
        } else if (strncmp(arg, "+https-post=", 12) == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = true; spec->qo.doh_path = strdup(arg + 12); if (spec->port == 53) spec->port = 443;
        } else if (strcmp(arg, "+https-post") == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = true; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 443;
        } else if (strncmp(arg, "+http-plain=", 12) == 0 || strncmp(arg, "+http=", 6) == 0) {
            const char *val = (strncmp(arg, "+http-plain=", 12) == 0) ? (arg + 12) : (arg + 6);
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = false; spec->qo.doh_path = strdup(val); if (spec->port == 53) spec->port = 80;
        } else if (strcmp(arg, "+http-plain") == 0 || strcmp(arg, "+http") == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = false; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 80;
        } else if (strncmp(arg, "+http-plain-get=", 16) == 0 || strncmp(arg, "+http-get=", 10) == 0) {
            const char *val = (strncmp(arg, "+http-plain-get=", 16) == 0) ? (arg + 16) : (arg + 10);
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_GET; spec->qo.doh_tls = false; spec->qo.doh_path = strdup(val); if (spec->port == 53) spec->port = 80;
        } else if (strcmp(arg, "+http-plain-get") == 0 || strcmp(arg, "+http-get") == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_GET; spec->qo.doh_tls = false; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 80;
        } else if (strncmp(arg, "+http-plain-post=", 17) == 0 || strncmp(arg, "+http-post=", 11) == 0) {
            const char *val = (strncmp(arg, "+http-plain-post=", 17) == 0) ? (arg + 17) : (arg + 11);
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = false; spec->qo.doh_path = strdup(val); if (spec->port == 53) spec->port = 80;
        } else if (strcmp(arg, "+http-plain-post") == 0 || strcmp(arg, "+http-post") == 0) {
            if (spec->qo.doh_path) free(spec->qo.doh_path);
            spec->qo.use_doh = true; spec->qo.doh_method = DOH_POST; spec->qo.doh_tls = false; spec->qo.doh_path = strdup("/dns-query"); if (spec->port == 53) spec->port = 80;
        } else if (strcmp(arg, "+nohttps") == 0 || strcmp(arg, "+nohttp-plain") == 0 || strcmp(arg, "+nohttp") == 0) {
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
        } else if (strcmp(arg, "+padding") == 0) {
            spec->qo.want_opt = true;
            spec->qo.want_padding = true;
            spec->qo.padding_size = 0;
        } else if (strcmp(arg, "+nopadding") == 0) {
            spec->qo.want_padding = false;
            spec->qo.padding_size = -1;
        } else if (strncmp(arg, "+mqtype=", 8) == 0) {
            spec->qo.want_opt = true;
            char *mqstr = strdup(arg + 8);
            if (mqstr) {
                char *token = strtok(mqstr, ",");
                uint16_t mqtypes[16];
                int mq_count = 0;
                while (token && mq_count < 16) {
                    int mq = parse_qtype(token);
                    if (mq >= 0) mqtypes[mq_count++] = (uint16_t)mq;
                    token = strtok(NULL, ",");
                }
                free(mqstr);

                int idx = -1;
                for (int i = 0; i < spec->qo.custom_edns_opt_count; i++) {
                    if (spec->qo.custom_edns_opts[i].code == 20) {
                        idx = i;
                        break;
                    }
                }
                if (idx == -1 && spec->qo.custom_edns_opt_count < 8) {
                    idx = spec->qo.custom_edns_opt_count++;
                    spec->qo.custom_edns_opts[idx].code = 20;
                    spec->qo.custom_edns_opts[idx].len = 0;
                }
                if (idx != -1) {
                    for (int m = 0; m < mq_count; m++) {
                        if ((size_t)spec->qo.custom_edns_opts[idx].len + 2 <= sizeof(spec->qo.custom_edns_opts[idx].data)) {
                            size_t cur_len = spec->qo.custom_edns_opts[idx].len;
                            spec->qo.custom_edns_opts[idx].data[cur_len] = (uint8_t)(mqtypes[m] >> 8);
                            spec->qo.custom_edns_opts[idx].data[cur_len + 1] = (uint8_t)(mqtypes[m] & 0xFF);
                            spec->qo.custom_edns_opts[idx].len += 2;
                        }
                    }
                }
            }
        } else if (strcmp(arg, "+nomqtype") == 0) {
            for (int i = 0; i < spec->qo.custom_edns_opt_count; i++) {
                if (spec->qo.custom_edns_opts[i].code == 20) {
                    for (int j = i; j < spec->qo.custom_edns_opt_count - 1; j++) {
                        spec->qo.custom_edns_opts[j] = spec->qo.custom_edns_opts[j + 1];
                    }
                    spec->qo.custom_edns_opt_count--;
                    break;
                }
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
                    size_t dec_len = hex_decode(hex, spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].data,
                                                sizeof(spec->qo.custom_edns_opts[0].data));
                    if (dec_len == (size_t)-1) {
                        fprintf(stderr, "error: +ednsopt hex payload exceeds buffer size or is invalid\n");
                        return -1;
                    }
                    spec->qo.custom_edns_opts[spec->qo.custom_edns_opt_count].len = (uint16_t)dec_len;
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
                    unsigned int byte = 0;
                    if (sscanf(hex + j * 2, "%02x", &byte) == 1) {
                        full[j] = (uint8_t)byte;
                    } else {
                        full[j] = 0;
                    }
                }
                if (full_len >= 8) {
                    memcpy(spec->qo.client_cookie, full, 8);
                    if (full_len > 8) { spec->qo.server_cookie_len = full_len - 8; memcpy(spec->qo.server_cookie, full + 8, spec->qo.server_cookie_len); }
                } else {
                    memset(spec->qo.client_cookie, 0, 8);
                    memcpy(spec->qo.client_cookie, full, full_len);
                }
            } else {
                for (int k = 0; k < 8; k++) spec->qo.client_cookie[k] = (uint8_t)(arc4random() & 0xFF);
            }
        } else if (strcmp(arg, "+nocookie") == 0) {
            spec->qo.want_cookie = false;
        } else if (strncmp(arg, "+tsig=", 6) == 0) {
            if (spec->qo.want_sig0 || spec->qo.sig0_specified) {
                fprintf(stderr, "error: TSIG (-k/-y) and SIG(0) (+sig0-pkey) cannot be combined in this version of dag\n");
                return -1;
            }
            spec->qo.tsig_specified = true;
            char *tsig_str = strdup(arg + 6);
            parse_tsig_str(tsig_str, &spec->qo);
            free(tsig_str);
        } else if (strncmp(arg, "+sig0-pkey=", 11) == 0) {
            if (spec->qo.want_tsig || spec->qo.tsig_specified) {
                fprintf(stderr, "error: TSIG (-k/-y) and SIG(0) (+sig0-pkey) cannot be combined in this version of dag\n");
                return -1;
            }
            spec->qo.sig0_specified = true;
            const char *path = arg + 11;
            if (!load_sig0_pkey(path, &spec->qo.sig0_key)) {
                return -1;
            }
            spec->qo.want_sig0 = true;
        } else if (strncmp(arg, "+sig0-name=", 11) == 0) {
            if (spec->qo.sig0_key.signer_name) {
                free(spec->qo.sig0_key.signer_name);
                spec->qo.sig0_key.signer_name = NULL;
            }
            spec->qo.sig0_key.signer_name = strdup(arg + 11);
        } else if (strncmp(arg, "+sig0-alg=", 10) == 0) {
            uint8_t alg = 0;
            if (!parse_u8(arg + 10, &alg)) {
                fprintf(stderr, "error: invalid algorithm number '%s' for +sig0-alg (must be 0-255)\n", arg + 10);
                return -1;
            }
            spec->qo.sig0_key.algorithm = alg;
        } else if (strncmp(arg, "+sig0-keytag=", 13) == 0) {
            uint16_t keytag = 0;
            if (!parse_u16(arg + 13, &keytag)) {
                fprintf(stderr, "error: invalid key tag '%s' for +sig0-keytag (must be 0-65535)\n", arg + 13);
                return -1;
            }
            spec->qo.sig0_key.key_tag = keytag;
        } else if (strcmp(arg, "+sig0") == 0) {
            if (spec->qo.want_tsig || spec->qo.tsig_specified) {
                fprintf(stderr, "error: TSIG (-k/-y) and SIG(0) (+sig0-pkey) cannot be combined in this version of dag\n");
                return -1;
            }
            spec->qo.sig0_specified = true;
            spec->qo.want_sig0 = true;
        } else if (strcmp(arg, "+nosig0") == 0) {
            spec->qo.want_sig0 = false;
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
    } else if (is_qtype_syntax_or_known(arg)) {
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

int parse_arg_slice(int start, int end, int argc, char **argv, query_spec_t *spec) {
    for (int i = start; i < end; ) {
        int rc = parse_query_arg_token(argc, argv, i, spec);
        if (rc < 0) return -1;
        i += rc;
    }
    return 0;
}


void deep_copy_query_opts(query_opts_t *dst, const query_opts_t *src) {
    if (!dst || !src) return;
    *dst = *src;
    if (src->tls_ca_file) dst->tls_ca_file = strdup(src->tls_ca_file);
    if (src->tls_certfile) dst->tls_certfile = strdup(src->tls_certfile);
    if (src->tls_keyfile) dst->tls_keyfile = strdup(src->tls_keyfile);
    if (src->tls_hostname) dst->tls_hostname = strdup(src->tls_hostname);
    if (src->doh_path) dst->doh_path = strdup(src->doh_path);
    if (src->search_domain) dst->search_domain = strdup(src->search_domain);
    if (src->tsig_key.algorithm) dst->tsig_key.algorithm = strdup(src->tsig_key.algorithm);
    if (src->tsig_key.name) dst->tsig_key.name = strdup(src->tsig_key.name);
    if (src->sig0_key.signer_name) dst->sig0_key.signer_name = strdup(src->sig0_key.signer_name);
    if (src->sig0_key.pkey) {
        EVP_PKEY_up_ref(src->sig0_key.pkey);
        dst->sig0_key.pkey = src->sig0_key.pkey;
    }
    for (int i = 0; i < src->update_op_count; i++) {
        if (src->update_ops[i].raw) {
            dst->update_ops[i].raw = strdup(src->update_ops[i].raw);
        }
    }
}

void free_query_opts(query_opts_t *qo) {
    if (!qo) return;
    if (qo->tls_ca_file) { free(qo->tls_ca_file); qo->tls_ca_file = NULL; }
    if (qo->tls_certfile) { free(qo->tls_certfile); qo->tls_certfile = NULL; }
    if (qo->tls_keyfile) { free(qo->tls_keyfile); qo->tls_keyfile = NULL; }
    if (qo->tls_hostname) { free(qo->tls_hostname); qo->tls_hostname = NULL; }
    if (qo->doh_path) { free(qo->doh_path); qo->doh_path = NULL; }
    if (qo->search_domain) { free(qo->search_domain); qo->search_domain = NULL; }
    if (qo->tsig_key.algorithm) { free((void *)qo->tsig_key.algorithm); qo->tsig_key.algorithm = NULL; }
    if (qo->tsig_key.name) { free((void *)qo->tsig_key.name); qo->tsig_key.name = NULL; }
    if (qo->sig0_key.pkey) { EVP_PKEY_free(qo->sig0_key.pkey); qo->sig0_key.pkey = NULL; }
    if (qo->sig0_key.signer_name) { free(qo->sig0_key.signer_name); qo->sig0_key.signer_name = NULL; }
    for (int i = 0; i < qo->update_op_count; i++) {
        if (qo->update_ops[i].raw) {
            free(qo->update_ops[i].raw);
            qo->update_ops[i].raw = NULL;
        }
    }
    qo->update_op_count = 0;
}



int execute_query_spec(query_spec_t *spec) {
    if ((spec->qo.want_tsig || spec->qo.tsig_specified) && (spec->qo.want_sig0 || spec->qo.sig0_specified)) {
        fprintf(stderr, "error: TSIG (-k/-y) and SIG(0) (+sig0-pkey) cannot be combined in this version of dag\n");
        return 1;
    }
    if (spec->qo.want_sig0 || spec->qo.sig0_specified) {
        if (!spec->qo.sig0_key.pkey) {
            fprintf(stderr, "error: SIG(0) requested (+sig0) but no private key specified (+sig0-pkey=file)\n");
            return 1;
        }
        if (!spec->qo.sig0_key.signer_name) {
            fprintf(stderr, "error: SIG(0) requires a signer name (+sig0-name=name)\n");
            return 1;
        }
    }

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
                                    spec->no_hexdump_query, spec->no_hexdump_response, &spec->qo, spec->hex_payload, &spec->dopt);
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

#if defined(main) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
#ifndef _WIN32
__attribute__((weak))
#endif
int run_replay_mode(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return 1;
}
#endif

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
    if (argc >= 2 && strcmp(argv[1], "--replay") == 0) {
        return run_replay_mode(argc, argv);
    }
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
            } else if (is_qtype_syntax_or_known(arg)) {
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
        free_query_opts(&global_spec.qo);
        return 1;
    }

    // -f バッチファイルモードの処理
    if (global_spec.batch_file) {
        int batch_rc = execute_batch_spec(&global_spec);
        print_multi_server_summary(global_spec.use_ldnsz, global_spec.dopt.yaml);
#ifndef _WIN32
        if (global_spec.qo.mem_debug) {
            struct rusage ru;
            getrusage(RUSAGE_SELF, &ru);
            fprintf(stderr, ";; Memory usage: maxrss=%ld KB\n", (long)ru.ru_maxrss);
        }
#endif
        close_cached_tcp();
        zone_arena_destroy(&g_dag_arena);
        free_query_opts(&global_spec.qo);
        if (g_results) free(g_results);
        return batch_rc;
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
        deep_copy_query_opts(&local_spec.qo, &global_spec.qo);
        if (queries[q].start < queries[q].end) {
            if (parse_arg_slice(queries[q].start, queries[q].end, argc, argv, &local_spec) < 0) {
                last_exit_code = 1;
                free_query_opts(&local_spec.qo);
                continue;
            }
        }

        // タプル内で -f が指定された場合
        if (local_spec.batch_file) {
            int batch_rc = execute_batch_spec(&local_spec);
            if (batch_rc != 0) last_exit_code = batch_rc;
            free_query_opts(&local_spec.qo);
            continue;
        }

        if (local_spec.qo.mem_debug) global_spec.qo.mem_debug = true;
        if (local_spec.use_ldnsz) global_spec.use_ldnsz = true;
        int rc = execute_query_spec(&local_spec);
        if (rc != 0) last_exit_code = rc;
        free_query_opts(&local_spec.qo);

        if (query_count > 1) {
            bool used_nofail = local_spec.qo.nofail && (!local_spec.test_all) && (!local_spec.do_trace) && (!local_spec.do_nssearch) && (!local_spec.batch_file) && (local_spec.server_arg && strchr(local_spec.server_arg, ',') != NULL);
            if (!used_nofail) {
                print_multi_server_summary(local_spec.use_ldnsz, local_spec.dopt.yaml);
            }
            g_server_count = 0;
        }
    }

    if (query_count <= 1) {
        bool used_nofail_failover = global_spec.qo.nofail && (!global_spec.test_all) && (!global_spec.do_trace) && (!global_spec.do_nssearch) && (!global_spec.batch_file) && (global_spec.server_arg && strchr(global_spec.server_arg, ',') != NULL);
        if (!used_nofail_failover) {
            print_multi_server_summary(global_spec.use_ldnsz, global_spec.dopt.yaml);
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
    free_query_opts(&global_spec.qo);
    if (g_results) free(g_results);
#ifdef _WIN32
    WSACleanup();
#endif
    return last_exit_code;
}

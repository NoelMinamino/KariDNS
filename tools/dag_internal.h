#ifndef DAG_INTERNAL_H
#define DAG_INTERNAL_H

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
#include <stdarg.h>

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
#include <sys/wait.h>
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
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#ifdef HAVE_LIBIDN2
#include <idn2.h>
#endif

#include "../dns_wire.h"
#include "../dns_utils.h"
#include "../dns_zone_parser.h"
#include "dag_replay.h"

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

extern bool g_dag_suppress_stdout;
#define printf(...) do { if (!g_dag_suppress_stdout) { fprintf(stdout, __VA_ARGS__); } } while(0)

extern zone_arena_t g_dag_arena;
extern char g_last_server_ip[INET6_ADDRSTRLEN + 1];
extern int g_last_socket_family;

/* Types */
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
    bool tsig_specified;
    tsig_key_t tsig_key;

    bool want_sig0;
    bool sig0_specified;
    sig0_key_t sig0_key;

    struct {
        update_op_kind_t kind;
        char *raw;
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
    bool use_glue;

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
    bool explicit_ttlid;
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

extern tcp_conn_cache_t g_cached_conn;

/* Functions shared between dag modules */
const char *format_ttl_units(uint32_t ttl, char *buf, size_t buf_size);
const char *format_class_name(uint16_t klass, char *buf, size_t buf_size);
const char *opcode_name(uint8_t opcode);
const char *rcode_name(uint16_t rcode);
const char *get_ede_error_string(uint16_t code);
void format_rdata_for_display(const uint8_t *pkt, size_t pkt_len, uint16_t type,
                             size_t abs_offset, uint16_t rdlen,
                             char *out, size_t out_cap, const display_opts_t *dopt);
void decode_and_print_edns_option(const uint8_t *pkt, size_t p,
                                  uint16_t code, uint16_t olen,
                                  const char *indent,
                                  const display_opts_t *dopt);
void init_query_spec(query_spec_t *spec);
void deep_copy_query_opts(query_opts_t *dst, const query_opts_t *src);
void free_query_opts(query_opts_t *qo);
void prescan_always_global_options(int argc, char **argv, query_spec_t *global_spec);
int parse_arg_slice(int start, int end, int argc, char **argv, query_spec_t *spec);
int execute_query_spec(query_spec_t *spec);

ssize_t do_tcp_recv_response(int sock, uint8_t *resp, size_t resp_cap);
ssize_t do_tls_recv_response(SSL *ssl, uint8_t *resp, size_t resp_cap);

#endif /* DAG_INTERNAL_H */
